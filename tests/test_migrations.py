from __future__ import annotations

import json
import hashlib
from importlib import resources
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from agentic_os import DB_AUTHORITY_ENABLED
from agentic_os.migrations import (
    MigrationError,
    MigrationHashDrift,
    _allow_next_slo_audit_write,
    _connect,
    _register_migration_functions,
    apply_migrations,
    load_migrations,
    repository_root,
    verify_database,
)
from agentic_os.openclaw_adapter import MetadataObservation
from agentic_os.reconciliation import reconcile_unknown_metadata
from agentic_os.runtime_dispatch import (
    DispatchRequest,
    dispatch_with_metadata,
    lease_metadata,
    release_metadata,
    spawn_metadata,
    stable_json,
)
from agentic_os.slo_contracts import (
    SLO_QUERY_CONTRACTS,
    SLO_QUERY_COUNT,
    slo_query_contracts_for_schema_version,
    slo_query_hash,
)


def _shadow_projection_id(run_id: str, path: str, digest: str) -> str:
    payload = f"{run_id}\0{path}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _clock_hash(now_epoch_ms: int, bound_by: str) -> str:
    payload = json.dumps(
        {
            "bound_by": bound_by,
            "now_epoch_ms": now_epoch_ms,
            "source": "pass-gate-writer-local-wall-clock-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _apply_v1_migration_only(self, directory_name: str) -> None:
        migration_dir = Path(self.temporary.name) / directory_name
        migration_dir.mkdir()
        shutil.copy(
            repository_root() / "migrations/0001_minimum_contract.sql",
            migration_dir / "0001_minimum_contract.sql",
        )
        v1_hash = hashlib.sha256(
            (migration_dir / "0001_minimum_contract.sql").read_bytes()
        ).hexdigest()
        (migration_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "migrations": [
                        {
                            "version": 1,
                            "name": "minimum_contract",
                            "file": "0001_minimum_contract.sql",
                            "sha256": v1_hash,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(apply_migrations(self.database, migration_dir=migration_dir), (1,))

    def _apply_migrations_through(self, version: int, directory_name: str) -> None:
        source_dir = repository_root() / "migrations"
        migration_dir = Path(self.temporary.name) / directory_name
        migration_dir.mkdir()
        manifest = json.loads((source_dir / "manifest.json").read_text(encoding="utf-8"))
        selected = [
            migration
            for migration in manifest["migrations"]
            if migration["version"] <= version
        ]
        for migration in selected:
            shutil.copy(source_dir / migration["file"], migration_dir / migration["file"])
        (migration_dir / "manifest.json").write_text(
            json.dumps({"migrations": selected}, indent=2) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            apply_migrations(self.database, migration_dir=migration_dir),
            tuple(migration["version"] for migration in selected),
        )

    def _seed_v9_dispatch(
        self,
        connection: sqlite3.Connection,
        suffix: str,
        *,
        spawn_state: str,
        requested_at_epoch_ms: int,
    ) -> DispatchRequest:
        request = DispatchRequest(
            run_id=f"run-{suffix}",
            transition_id=f"transition-{suffix}",
            phase="phase",
            agent_id="agent",
            requester_agent_id="requester",
            task_digest=f"task-{suffix}",
            spawn_request_id=f"spawn-{suffix}",
            reserve_budget_event_id=f"reserve-{suffix}",
            client_lease_id=f"client-lease-{suffix}",
            acquire_idempotency_key=f"acquire-idem-{suffix}",
            release_idempotency_key=f"release-idem-{suffix}",
            ttl_ms=60_000,
            spawn_client_request_id=f"client-{suffix}",
            spawn_idempotency_key=f"spawn-idem-{suffix}",
        )
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) VALUES(?,"
            "'file_authority','now')",
            (f"workflow-{suffix}",),
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,?,"
            "'file_authority','candidate','R1','R1','now','now')",
            (request.run_id, f"prepare-{suffix}", f"workflow-{suffix}"),
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES(?,?,'before','after','dispatch',"
            "'spawn','R1',?,0,'now')",
            (request.transition_id, request.run_id, f"transition-idem-{suffix}"),
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES(?,?,?,'endpoint','capability',100,200,'known','effective',?)",
            (
                f"cost-row-{suffix}",
                "provider",
                f"model-{suffix}",
                f"cost-hash-{suffix}",
            ),
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?, 'pending','now','now')",
            (
                request.spawn_request_id,
                request.run_id,
                request.phase,
                request.agent_id,
                request.transition_id,
                request.spawn_client_request_id,
                request.spawn_idempotency_key,
                request.task_digest,
            ),
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,usage_confidence,updated_at) VALUES(?,?, 'capability',"
            "'provider',?,'endpoint',?,'effective',?,'known',?,100,100,100,1000,"
            "1,1,1,'known','now')",
            (
                request.run_id,
                f"workflow-{suffix}",
                f"model-{suffix}",
                f"cost-row-{suffix}",
                f"cost-hash-{suffix}",
                request.transition_id,
            ),
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,provider,model,spawn_request_id,"
            "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
            "cost_registry_hash,cost_confidence,event_type,input_tokens,usage_confidence,"
            "source,created_at,created_at_epoch_ms) VALUES(?,?,?,1,?,?,'provider',?,"
            "?,'endpoint','capability',?,'effective',?,'known','reserve',1,'known','test',"
            "'now',?)",
            (
                request.reserve_budget_event_id,
                f"reserve-idem-{suffix}",
                f"reserve-dedupe-{suffix}",
                request.run_id,
                request.transition_id,
                f"model-{suffix}",
                request.spawn_request_id,
                f"cost-row-{suffix}",
                f"cost-hash-{suffix}",
                requested_at_epoch_ms - 1,
            ),
        )
        acquire = lease_metadata(request, f"gateway-{suffix}")
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,"
            "metadata_contract_version,metadata_json,external_metadata_json,external_run_id,"
            "external_transition_id,external_client_request_id,external_idempotency_key,"
            "external_phase,external_agent_id,external_requester_agent_id,external_ttl_ms,"
            "state,external_id,requested_at,requested_at_epoch_ms,accepted_at,"
            "accepted_at_epoch_ms) VALUES(?,?,?,'allow_lease_acquire',?,?,?,?,?,?, 'v1',"
            "?,?,?,?,?,?,?,?,?,?, 'accepted',?,'request-time',?,'accept-time',?)",
            (
                f"acquire:{request.acquire_idempotency_key}",
                request.run_id,
                request.transition_id,
                request.client_lease_id,
                request.acquire_idempotency_key,
                request.phase,
                request.agent_id,
                request.requester_agent_id,
                request.ttl_ms,
                stable_json(lease_metadata(request, "pending")),
                stable_json(acquire),
                request.run_id,
                request.transition_id,
                request.client_lease_id,
                request.acquire_idempotency_key,
                request.phase,
                request.agent_id,
                request.requester_agent_id,
                request.ttl_ms,
                f"gateway-{suffix}",
                requested_at_epoch_ms,
                requested_at_epoch_ms + 1,
            ),
        )
        connection.execute(
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,requester_agent_id,"
            "state,gateway_lease_id,client_lease_id,acquire_idempotency_key,"
            "release_idempotency_key,ttl_ms,metadata_contract_version,metadata_observed_at,"
            "external_metadata_json,external_client_lease_id,external_idempotency_key,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,acquire_requested_at,acquired_at,"
            "expires_at,expires_at_epoch_ms) VALUES(?,?,?,?,?,?,'acquired',?,?,?,?,?,'v1',"
            "'observed',?,?,?,?,?,?,?,?,?,'request-time','acquired','later',?)",
            (
                request.client_lease_id,
                request.run_id,
                request.phase,
                request.transition_id,
                request.agent_id,
                request.requester_agent_id,
                f"gateway-{suffix}",
                request.client_lease_id,
                request.acquire_idempotency_key,
                request.release_idempotency_key,
                request.ttl_ms,
                stable_json(acquire),
                request.client_lease_id,
                request.acquire_idempotency_key,
                request.run_id,
                request.phase,
                request.transition_id,
                request.agent_id,
                request.requester_agent_id,
                request.ttl_ms,
                requested_at_epoch_ms + request.ttl_ms,
            ),
        )
        spawn = spawn_metadata(request)
        accepted = spawn_state == "accepted"
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES(?,?,?,"
            "'sessions_spawn',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'request-time',?,?,?)",
            (
                f"spawn:{request.spawn_idempotency_key}",
                request.run_id,
                request.transition_id,
                request.spawn_request_id,
                request.reserve_budget_event_id,
                request.spawn_client_request_id,
                request.spawn_idempotency_key,
                request.phase,
                request.agent_id,
                request.task_digest,
                "v1" if accepted else None,
                stable_json(spawn),
                stable_json(spawn) if accepted else None,
                request.run_id if accepted else None,
                request.transition_id if accepted else None,
                request.spawn_client_request_id if accepted else None,
                request.spawn_idempotency_key if accepted else None,
                request.phase if accepted else None,
                request.agent_id if accepted else None,
                request.task_digest if accepted else None,
                spawn_state,
                f"session-{suffix}" if accepted else None,
                requested_at_epoch_ms,
                "accept-time" if accepted else None,
                requested_at_epoch_ms + 1 if accepted else None,
            ),
        )
        if accepted:
            connection.execute(
                "UPDATE spawn_requests SET session_key=?,dispatch_run_id=?,"
                "metadata_contract_version='v1',metadata_observed_at='observed',"
                "external_metadata_json=? WHERE spawn_request_id=?",
                (
                    f"session-{suffix}",
                    f"session-{suffix}",
                    stable_json(spawn),
                    request.spawn_request_id,
                ),
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,phase,"
                "agent_id,client_request_id,spawn_idempotency_key,session_key,task_digest,"
                "state,spawned_at) VALUES(?,?,?,?,?,?,?,?,?,?, 'running','now')",
                (
                    f"session:{suffix}",
                    request.spawn_request_id,
                    request.run_id,
                    request.transition_id,
                    request.phase,
                    request.agent_id,
                    request.spawn_client_request_id,
                    request.spawn_idempotency_key,
                    f"session-{suffix}",
                    request.task_digest,
                ),
            )
            connection.execute(
                "UPDATE spawn_requests SET state='accepted' WHERE spawn_request_id=?",
                (request.spawn_request_id,),
            )
        return request

    def _seed_runtime_dispatch_binding(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        transition_id: str,
        phase: str,
        agent_id: str,
        task_digest: str,
        spawn_request_id: str,
        spawn_client_request_id: str,
        spawn_idempotency_key: str,
        requester_agent_id: str = "requester",
        lease_id: str = "lease",
        client_lease_id: str = "client-lease",
        acquire_idempotency_key: str = "acquire-idem",
        release_idempotency_key: str = "release-idem",
        reserve_budget_event_id: str = "reserve",
    ) -> None:
        connection.execute(
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
            "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
            "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
            "expires_at_epoch_ms) VALUES(?,?,?,?,?,?,'acquire_pending',?,?,?,?,"
            "'now','later',1800000060000)",
            (
                lease_id,
                run_id,
                phase,
                transition_id,
                agent_id,
                requester_agent_id,
                client_lease_id,
                acquire_idempotency_key,
                release_idempotency_key,
                60_000,
            ),
        )
        connection.execute(
            "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
            "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
            "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
            "spawn_idempotency_key,reserve_budget_event_id,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                spawn_request_id,
                lease_id,
                run_id,
                transition_id,
                phase,
                agent_id,
                requester_agent_id,
                task_digest,
                client_lease_id,
                acquire_idempotency_key,
                release_idempotency_key,
                spawn_client_request_id,
                spawn_idempotency_key,
                reserve_budget_event_id,
                "now",
            ),
        )

    def _insert_gate_bound_evidence(
        self,
        connection: sqlite3.Connection,
        evidence_hash: str,
        suffix: str,
        decision: str = "pass",
    ) -> tuple[str, str, str]:
        workflow = f"slo-workflow-{suffix}"
        run_id = f"slo-run-{suffix}"
        transition_id = f"slo-transition-{suffix}"
        verifier_id = f"slo-verifier-{suffix}"
        gate_id = f"slo-gate-{suffix}"
        clock_id = f"slo-clock-{suffix}"
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES(?,'file_authority','now')",
            (workflow,),
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
            "?,'file_authority','candidate','R1','R1','now','now')",
            (run_id, f"slo-prepare-{suffix}", workflow),
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES(?,?,"
            "'before','after','gate','check','R1',?,0,'now')",
            (transition_id, run_id, f"slo-transition-idem-{suffix}"),
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES(?,?,?,?,"
            "'provider','model',?,?,?,'independent','{\"reviewer_session\":\"fixture\"}','now')",
            (
                verifier_id,
                run_id,
                f"worker-{suffix}",
                f"verifier-{suffix}",
                f"prompt-{suffix}",
                f"context-{suffix}",
                evidence_hash,
            ),
        )
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES(?,?,?,?,?,?,'now',1000,'v1',?,?,?,'R1','now')",
            (
                gate_id,
                run_id,
                transition_id,
                clock_id,
                verifier_id,
                decision,
                f"query-{suffix}",
                f"migration-{suffix}",
                evidence_hash,
            ),
        )
        connection.execute(
            "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
            "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
            "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
            "VALUES(?,?,?,?,?,?,1000,1000,'clock',?,1000)",
            (
                clock_id,
                gate_id,
                gate_id,
                run_id,
                transition_id,
                f"nonce-{suffix}",
                f"source-{suffix}",
            ),
        )
        connection.execute(
            "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,size_bytes,"
            "content_type,redaction_status,producer_run_id,verifier_run_id,gate_run_id,"
            "captured_at) VALUES(?,?,?,?,1,'application/json','none',?,?,?,'now')",
            (
                evidence_hash,
                run_id,
                f"slo-{suffix}.json",
                f"sha-{suffix}",
                run_id,
                verifier_id,
                gate_id,
            ),
        )
        return run_id, verifier_id, gate_id

    def test_authority_remains_disabled(self) -> None:
        self.assertIs(DB_AUTHORITY_ENABLED, False)

    def test_complete_schema_and_idempotent_apply(self) -> None:
        migrations = load_migrations(repository_root() / "migrations")
        self.assertEqual(
            apply_migrations(self.database), tuple(migration.version for migration in migrations)
        )
        self.assertEqual(apply_migrations(self.database), ())
        with sqlite3.connect(self.database) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            self.assertEqual(len(tables), 35)
            self.assertIn(("db_authority_canary_rollback_proofs",), tables)
            rows = connection.execute(
                "SELECT version,name,sha256 FROM schema_migrations ORDER BY version"
            ).fetchall()
            self.assertEqual(
                rows,
                [
                    (migration.version, migration.name, migration.sha256)
                    for migration in migrations
                ],
            )
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM slo_queries").fetchone(),
                (SLO_QUERY_COUNT * len(migrations),),
            )

    def test_legacy_slo_fixture_metadata_upgrades_to_current_contract(self) -> None:
        self._apply_migrations_through(12, "legacy-slo-fixture-metadata")
        for version in range(1, 13):
            meta_contract = next(
                contract
                for contract in slo_query_contracts_for_schema_version(version)
                if contract.query_name == "SLO query fixture status"
            )
            self.assertEqual(meta_contract.empty_db_expected_status, "pass")
        current_meta_contract = next(
            contract
            for contract in slo_query_contracts_for_schema_version(14)
            if contract.query_name == "SLO query fixture status"
        )
        self.assertEqual(
            current_meta_contract.empty_db_expected_status,
            "self_bootstrap_empty",
        )

        self.assertEqual(apply_migrations(self.database), (13, 14, 15, 16))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT DISTINCT empty_db_expected_status FROM slo_queries "
                    "WHERE query_name='SLO query fixture status' "
                    "AND schema_version BETWEEN 1 AND 12"
                ).fetchall(),
                [("pass",)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT empty_db_expected_status FROM slo_queries "
                    "WHERE query_name='SLO query fixture status' "
                    "AND schema_version IN (13,14) ORDER BY schema_version"
                ).fetchall(),
                [("self_bootstrap_empty",), ("self_bootstrap_empty",)],
            )

    def test_v10_backfills_exact_v9_dispatches_for_replay_and_reconciliation(self) -> None:
        self._apply_migrations_through(9, "v9-exact")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            accepted = self._seed_v9_dispatch(
                connection,
                "accepted",
                spawn_state="accepted",
                requested_at_epoch_ms=1_800_000_000_100,
            )
            pending = self._seed_v9_dispatch(
                connection,
                "pending",
                spawn_state="pending",
                requested_at_epoch_ms=2,
            )

        self.assertEqual(apply_migrations(self.database), (10, 11, 12, 13, 14, 15, 16))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT spawn_request_id,client_lease_id FROM runtime_dispatch_bindings "
                    "ORDER BY spawn_request_id"
                ).fetchall(),
                [
                    (accepted.spawn_request_id, accepted.client_lease_id),
                    (pending.spawn_request_id, pending.client_lease_id),
                ],
            )

        class NoCallAdapter:
            def __getattr__(self, name):
                raise AssertionError(f"accepted replay called adapter method {name}")

        replay = dispatch_with_metadata(self.database, NoCallAdapter(), accepted)
        self.assertEqual(replay.status, "replayed")
        self.assertEqual(replay.session_key, "session-accepted")

        class ReconcileAdapter:
            def sessions_list(self):
                return []

            def allow_lease_list(self):
                return []

            def allow_lease_release(self, params):
                raise AssertionError("zero session observation must retain the lease")

        summary = reconcile_unknown_metadata(self.database, ReconcileAdapter())
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM leases WHERE client_lease_id=?",
                    (pending.client_lease_id,),
                ).fetchone(),
                ("acquired",),
            )

    def test_v10_rejects_post_migration_spawn_intent_without_binding(self) -> None:
        self.assertEqual(
            apply_migrations(self.database),
            tuple(migration.version for migration in load_migrations()),
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "runtime dispatch binding"):
                self._seed_v9_dispatch(
                    connection,
                    "unbound-post-v10",
                    spawn_state="pending",
                    requested_at_epoch_ms=1_800_000_000_250,
                )

    def test_v10_upgrade_refuses_ambiguous_v9_dispatch_binding(self) -> None:
        self._apply_migrations_through(9, "v9-ambiguous")
        requested_ms = 1_800_000_000_300
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            request = self._seed_v9_dispatch(
                connection,
                "ambiguous",
                spawn_state="pending",
                requested_at_epoch_ms=requested_ms,
            )
            other = DispatchRequest(
                **{
                    **request.__dict__,
                    "client_lease_id": "client-lease-ambiguous-other",
                    "acquire_idempotency_key": "acquire-idem-ambiguous-other",
                    "release_idempotency_key": "release-idem-ambiguous-other",
                    "lease_id": "lease-ambiguous-other",
                }
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,"
                "metadata_json,state,requested_at,requested_at_epoch_ms) VALUES(?,?,?,"
                "'allow_lease_acquire',?,?,?,?,?,?,?,'pending','request-time',?)",
                (
                    f"acquire:{other.acquire_idempotency_key}",
                    other.run_id,
                    other.transition_id,
                    other.client_lease_id,
                    other.acquire_idempotency_key,
                    other.phase,
                    other.agent_id,
                    other.requester_agent_id,
                    other.ttl_ms,
                    stable_json(lease_metadata(other, "pending")),
                    requested_ms,
                ),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES(?,?,?,?,?,?,'acquire_pending',?,?,?,?,"
                "'request-time','later',?)",
                (
                    other.lease_id,
                    other.run_id,
                    other.phase,
                    other.transition_id,
                    other.agent_id,
                    other.requester_agent_id,
                    other.client_lease_id,
                    other.acquire_idempotency_key,
                    other.release_idempotency_key,
                    other.ttl_ms,
                    requested_ms + other.ttl_ms,
                ),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "valid=1"):
            apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone(),
                (9,),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='runtime_dispatch_bindings'"
                ).fetchone()
            )

    def test_v10_upgrade_refuses_unbound_v9_dispatch(self) -> None:
        self._apply_migrations_through(9, "v9-unbound")
        with sqlite3.connect(self.database) as connection:
            request = self._seed_v9_dispatch(
                connection,
                "unbound",
                spawn_state="pending",
                requested_at_epoch_ms=1_800_000_000_400,
            )
            connection.execute(
                "UPDATE external_rpc_intents SET requested_at='different-time',"
                "requested_at_epoch_ms=requested_at_epoch_ms+1 "
                "WHERE rpc_kind='allow_lease_acquire' AND idempotency_key=?",
                (request.acquire_idempotency_key,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "valid=1"):
            apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone(),
                (9,),
            )

    def test_legacy_money_import_evidence_children_match_completed_batch_counts(
        self,
    ) -> None:
        apply_migrations(self.database)
        digest_a = "a" * 64
        digest_b = "b" * 64
        digest_c = "c" * 64
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO legacy_money_import_quarantine("
                "quarantine_id,batch_id,source_row_ordinal,legacy_row_id,"
                "source_column,source_type,source_unit,source_value_text,"
                "reason_code,reason_detail,row_payload_hash,created_at) VALUES("
                "'quarantine-a','quarantine-batch',1,'row-a','actual_cost_usd',"
                "'text','usd_decimal','bad','invalid_money','bad money',?,"
                "'now')",
                (digest_b,),
            )
            connection.execute(
                "INSERT INTO legacy_money_import_batches("
                "batch_id,source_schema_version,source_table,source_unit,"
                "payload_hash,status,row_count,quarantine_count,promoted_count,"
                "created_at,completed_at,failure_reason) VALUES("
                "'quarantine-batch','legacy_budget_terminal_usage_v1',"
                "'legacy_budget_terminal_usage_v1','usd_decimal',?,"
                "'quarantined',1,1,0,'now','now','failed')",
                (digest_a,),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "quarantine evidence"):
                connection.execute(
                    "INSERT INTO legacy_money_import_quarantine("
                    "quarantine_id,batch_id,source_row_ordinal,legacy_row_id,"
                    "source_column,source_type,source_unit,source_value_text,"
                    "reason_code,reason_detail,row_payload_hash,created_at) VALUES("
                    "'quarantine-extra','quarantine-batch',2,'row-b',"
                    "'actual_cost_usd','text','usd_decimal','bad',"
                    "'invalid_money','bad money',?,'now')",
                    (digest_c,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "promotion evidence"):
                connection.execute(
                    "INSERT INTO legacy_money_import_promotions("
                    "batch_id,legacy_row_id,row_payload_hash,settlement_id,promoted_at"
                    ") VALUES('quarantine-batch','row-a',?,'missing-settlement','now')",
                    (digest_b,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "count mismatch"):
                connection.execute(
                    "INSERT INTO legacy_money_import_batches("
                    "batch_id,source_schema_version,source_table,source_unit,"
                    "payload_hash,status,row_count,quarantine_count,promoted_count,"
                    "created_at,completed_at,failure_reason) VALUES("
                    "'missing-quarantine-evidence','legacy_budget_terminal_usage_v1',"
                    "'legacy_budget_terminal_usage_v1','usd_decimal',?,"
                    "'quarantined',2,2,0,'now','now','failed')",
                    (digest_a,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "count mismatch"):
                connection.execute(
                    "INSERT INTO legacy_money_import_batches("
                    "batch_id,source_schema_version,source_table,source_unit,"
                    "payload_hash,status,row_count,quarantine_count,promoted_count,"
                    "created_at,completed_at,failure_reason) VALUES("
                    "'missing-promotion-evidence','legacy_budget_terminal_usage_v1',"
                    "'legacy_budget_terminal_usage_v1','usd_decimal',?,"
                    "'promoted',1,0,1,'now','now',NULL)",
                    (digest_b,),
                )

            connection.execute(
                "INSERT INTO legacy_money_import_promotions("
                "batch_id,legacy_row_id,row_payload_hash,settlement_id,promoted_at"
                ") VALUES('promotion-batch','row-a',?,'missing-settlement-a','now')",
                (digest_b,),
            )
            connection.execute(
                "INSERT INTO legacy_money_import_batches("
                "batch_id,source_schema_version,source_table,source_unit,"
                "payload_hash,status,row_count,quarantine_count,promoted_count,"
                "created_at,completed_at,failure_reason) VALUES("
                "'promotion-batch','legacy_budget_terminal_usage_v1',"
                "'legacy_budget_terminal_usage_v1','usd_decimal',?,"
                "'promoted',1,0,1,'now','now',NULL)",
                (digest_b,),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "promotion evidence"):
                connection.execute(
                    "INSERT INTO legacy_money_import_promotions("
                    "batch_id,legacy_row_id,row_payload_hash,settlement_id,promoted_at"
                    ") VALUES('promotion-batch','row-b',?,'missing-settlement-b','now')",
                    (digest_c,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "quarantine evidence"):
                connection.execute(
                    "INSERT INTO legacy_money_import_quarantine("
                    "quarantine_id,batch_id,source_row_ordinal,legacy_row_id,"
                    "source_column,source_type,source_unit,source_value_text,"
                    "reason_code,reason_detail,row_payload_hash,created_at) VALUES("
                    "'quarantine-wrong-status','promotion-batch',1,'row-a',"
                    "'actual_cost_usd','text','usd_decimal','bad',"
                    "'invalid_money','bad money',?,'now')",
                    (digest_c,),
                )

    def test_legacy_money_import_batch_source_identity_is_constrained(self) -> None:
        apply_migrations(self.database)
        digest = "a" * 64
        insert_sql = (
            "INSERT INTO legacy_money_import_batches("
            "batch_id,source_schema_version,source_table,source_unit,payload_hash,"
            "status,row_count,quarantine_count,promoted_count,created_at,completed_at,"
            "failure_reason) VALUES(?,?,?,?,?,'promoted',0,0,0,'now','now',NULL)"
        )
        with sqlite3.connect(self.database) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "legacy_money_import_source_schema_version",
            ):
                connection.execute(
                    insert_sql,
                    (
                        "bad-schema-version",
                        "legacy_budget_terminal_usage_v0",
                        "legacy_budget_terminal_usage_v1",
                        "usd_decimal",
                        digest,
                    ),
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "legacy_money_import_source_table",
            ):
                connection.execute(
                    insert_sql,
                    (
                        "bad-source-table",
                        "legacy_budget_terminal_usage_v1",
                        "other_table",
                        "usd_decimal",
                        digest,
                    ),
                )

    def test_existing_version_1_database_upgrades_to_shadow_projection_identity(self) -> None:
        migration_dir = Path(self.temporary.name) / "v1-migrations"
        migration_dir.mkdir()
        shutil.copy(
            repository_root() / "migrations/0001_minimum_contract.sql",
            migration_dir / "0001_minimum_contract.sql",
        )
        v1_hash = hashlib.sha256(
            (migration_dir / "0001_minimum_contract.sql").read_bytes()
        ).hexdigest()
        (migration_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "migrations": [
                        {
                            "version": 1,
                            "name": "minimum_contract",
                            "file": "0001_minimum_contract.sql",
                            "sha256": v1_hash,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(apply_migrations(self.database, migration_dir=migration_dir), (1,))

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('shadow','file_authority_shadow','now')"
            )
            for run_id in ("run-a", "run-b"):
                connection.execute(
                    "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                    "authority_mode,state,risk_class,risk_dominance,created_at,"
                    "updated_at,finalized_at,finalized_at_epoch_ms) VALUES(?,?,"
                    "'shadow','file_authority_shadow','finalized','R1','R1',"
                    "'now','now','now',1)",
                    (run_id, f"prepare-{run_id}"),
                )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-a-stale','run-a',"
                "'reports/summary.json',?,'file_authority_shadow',"
                "'2026-01-01T00:00:00+00:00')",
                ("b" * 64,),
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-a-middle','run-a',"
                "'reports/summary.json',?,'file_authority_shadow',"
                "'2026-01-01T12:00:00+00:00')",
                ("c" * 64,),
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-a-current','run-a',"
                "'reports/summary.json',?,'file_authority_shadow',"
                "'2026-01-02T00:00:00+00:00')",
                ("a" * 64,),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                    "source_authority,generated_at) VALUES('projection-b','run-b',"
                    "'reports/summary.json',?,'file_authority_shadow','now')",
                    ("a" * 64,),
                )

        self.assertEqual(
            apply_migrations(self.database),
            (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        )
        retained_projection_id = _shadow_projection_id(
            "run-a", "reports/summary.json", "a" * 64
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT projection_id,sha256 FROM artifact_projections "
                    "WHERE run_id='run-a' AND path='reports/summary.json'"
                ).fetchone(),
                (retained_projection_id, "a" * 64),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT projection_id,sha256,retained_projection_id,archive_reason "
                    "FROM artifact_projection_history WHERE run_id='run-a' "
                    "ORDER BY projection_id"
                ).fetchall(),
                [
                    (
                        "projection-a-middle",
                        "c" * 64,
                        retained_projection_id,
                        "v1_identity_collapse",
                    ),
                    (
                        "projection-a-stale",
                        "b" * 64,
                        retained_projection_id,
                        "v1_identity_collapse",
                    ),
                ],
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-b','run-b',"
                "'reports/summary.json',?,'file_authority_shadow','now')",
                ("a" * 64,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE path='reports/summary.json' AND sha256=?",
                    ("a" * 64,),
                ).fetchone(),
                (2,),
            )

    def test_existing_version_2_database_upgrades_to_budget_ledger_slo_identity(self) -> None:
        migration_dir = Path(self.temporary.name) / "v2-migrations"
        migration_dir.mkdir()
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        v1_v2_migrations = manifest["migrations"][:2]
        for row in v1_v2_migrations:
            shutil.copy(
                repository_root() / "migrations" / row["file"],
                migration_dir / row["file"],
            )
        (migration_dir / "manifest.json").write_text(
            json.dumps({"migrations": v1_v2_migrations}),
            encoding="utf-8",
        )

        self.assertEqual(apply_migrations(self.database, migration_dir=migration_dir), (1, 2))
        query_name = "Budget ledger reconciles to counters and budgets"
        legacy_contract = next(
            contract
            for contract in slo_query_contracts_for_schema_version(2)
            if contract.query_name == query_name
        )
        current_contract = next(
            contract for contract in SLO_QUERY_CONTRACTS if contract.query_name == query_name
        )
        v3_contract = next(
            contract
            for contract in slo_query_contracts_for_schema_version(3)
            if contract.query_name == query_name
        )
        legacy_hash = slo_query_hash(legacy_contract.sql_text)
        v3_hash = slo_query_hash(v3_contract.sql_text)
        current_hash = slo_query_hash(current_contract.sql_text)
        self.assertNotEqual(legacy_hash, current_hash)
        self.assertNotEqual(v3_hash, current_hash)

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version,query_hash FROM slo_queries "
                    "WHERE query_name=? ORDER BY schema_version",
                    (query_name,),
                ).fetchall(),
                [(1, legacy_hash), (2, legacy_hash)],
            )

        self.assertEqual(
            apply_migrations(self.database),
            (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version,query_hash FROM slo_queries "
                    "WHERE query_name=? ORDER BY schema_version",
                    (query_name,),
                ).fetchall(),
                [
                    (1, legacy_hash),
                    (2, legacy_hash),
                    (3, v3_hash),
                    (4, current_hash),
                    (5, current_hash),
                    (6, current_hash),
                    (7, current_hash),
                    (8, current_hash),
                    (9, current_hash),
                    (10, current_hash),
                    (11, current_hash),
                    (12, current_hash),
                    (13, current_hash),
                    (14, current_hash),
                    (15, current_hash),
                    (16, current_hash),
                ],
            )

    def test_strict_prior_reserve_slo_hash_is_versioned_for_existing_v14_databases(
        self,
    ) -> None:
        migration_dir = Path(self.temporary.name) / "v14-migrations"
        migration_dir.mkdir()
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        v14_migrations = manifest["migrations"][:14]
        for row in v14_migrations:
            shutil.copy(
                repository_root() / "migrations" / row["file"],
                migration_dir / row["file"],
            )
        (migration_dir / "manifest.json").write_text(
            json.dumps({"migrations": v14_migrations}),
            encoding="utf-8",
        )

        query_name = "`sessions_spawn` intent without exact strict prior reserve"
        v14_contract = next(
            contract
            for contract in slo_query_contracts_for_schema_version(14)
            if contract.query_name == query_name
        )
        current_contract = next(
            contract for contract in SLO_QUERY_CONTRACTS if contract.query_name == query_name
        )
        v14_hash = slo_query_hash(v14_contract.sql_text)
        current_hash = slo_query_hash(current_contract.sql_text)
        self.assertNotEqual(v14_hash, current_hash)
        self.assertNotIn(
            "be.transition_id IS NOT rb.selected_reserve_transition_id",
            v14_contract.sql_text,
        )
        self.assertIn(
            "be.transition_id IS NOT rb.selected_reserve_transition_id",
            current_contract.sql_text,
        )

        self.assertEqual(
            apply_migrations(self.database, migration_dir=migration_dir),
            tuple(range(1, 15)),
        )
        snapshot = Path(self.temporary.name) / "control-v14-snapshot.db"
        with sqlite3.connect(self.database) as source:
            with sqlite3.connect(snapshot) as target:
                source.backup(target)
        self.assertEqual(
            verify_database(snapshot, migration_dir=migration_dir),
            tuple(range(1, 15)),
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version,query_hash FROM slo_queries "
                    "WHERE query_name=? ORDER BY schema_version DESC LIMIT 1",
                    (query_name,),
                ).fetchone(),
                (14, v14_hash),
            )

        self.assertEqual(apply_migrations(self.database), (15, 16))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version,query_hash FROM slo_queries "
                    "WHERE query_name=? ORDER BY schema_version",
                    (query_name,),
                ).fetchall()[-2:],
                [(15, current_hash), (16, current_hash)],
            )

    def test_strict_prior_reserve_migration_aborts_on_active_trust(self) -> None:
        self._apply_migrations_through(14, "v14-active-trust-migrations")
        with sqlite3.connect(self.database) as connection:
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trust_observations_validate_bound_insert'"
            ).fetchone()[0]
            connection.execute("DROP TRIGGER trust_observations_validate_bound_insert")
            connection.execute(
                "INSERT INTO trust_observations("
                "observation_id,scope,severity,status,effective_group_id,"
                "usage_confidence,created_at"
                ") VALUES('active-trust','workflow','R1','promoted','group',"
                "'known','now')"
            )
            connection.execute(trigger_sql)

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "strict_prior_reserve_active_trust"
        ):
            apply_migrations(self.database)

    def test_release_owner_migration_aborts_on_existing_terminal_lease_mismatch(
        self,
    ) -> None:
        self._apply_migrations_through(14, "v14-release-owner-mismatch")
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('workflow','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('run','prepare','workflow','file_authority','candidate','R1',"
                "'R1','now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('transition','run','before',"
                "'after','dispatch','allow_lease','R1','transition-idem',0,'now')"
            )
            release_metadata = json.dumps(
                {
                    "client_lease_id": "other-client",
                    "run_id": "run",
                    "phase": "other-phase",
                    "transition_id": "transition",
                    "agent_id": "other-agent",
                    "requester_agent_id": "other-requester",
                    "idempotency_key": "release-idem",
                    "release_idempotency_key": "release-idem",
                    "gateway_lease_id": "gateway",
                }
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,phase,agent_id,requester_agent_id,client_request_id,"
                "idempotency_key,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_client_request_id,external_idempotency_key,state,external_id,"
                "requested_at,requested_at_epoch_ms) VALUES('release-intent','run',"
                "'transition','allow_lease_release','other-phase','other-agent',"
                "'other-requester','other-client','release-idem','v1','{}',?,"
                "'run','other-phase','transition','other-agent','other-requester',"
                "'other-client','release-idem','accepted','gateway','now',1000)",
                (release_metadata,),
            )
            acquire_metadata = {
                "client_lease_id": "client",
                "idempotency_key": "acquire-idem",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway",
            }
            lease_values = (
                "lease",
                "run",
                "phase",
                "transition",
                "agent",
                "requester",
                "released",
                "gateway",
                "client",
                "acquire-idem",
                60000,
                "v1",
                "now",
                json.dumps(acquire_metadata),
                "client",
                "acquire-idem",
                "run",
                "phase",
                "transition",
                "agent",
                "requester",
                60000,
                "expires",
                2000000000000,
                "release-idem",
                "release-requested",
                "released-at",
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms,"
                "release_idempotency_key,release_requested_at,released_at) VALUES("
                + ",".join("?" for _ in lease_values)
                + ")",
                lease_values,
            )

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "__no_release_owner_metadata_violations__"
        ):
            apply_migrations(self.database)

    def test_strict_prior_reserve_trigger_stays_active_with_cross_workflow_trust(
        self,
    ) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        for workflow in ("trusted-workflow", "other-workflow"):
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES(?,'file_authority','now')",
                (workflow,),
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'trusted-run','trusted-prepare','trusted-workflow','file_authority',"
            "'finalized','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'r','prepare','other-workflow','file_authority','candidate','R1','R1',"
            "'now','now')"
        )
        for transition_id in ("t", "t-other"):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?, 'r', 'before', 'after',"
                "'dispatch','spawn','R1', ?, 0,'now')",
                (transition_id, f"{transition_id}-idem"),
            )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','r','phase','agent','t','client',"
            "'spawn-idem','task','pending','now','now')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,usage_confidence,updated_at) VALUES('r',"
            "'other-workflow','capability','provider','model','endpoint','cost-row',"
            "'effective','cost-hash','known','t-other',10,10,10,10,1,1,1,"
            "'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
            "VALUES('reserve','reserve-idem','reserve-dedupe',1,'r','t','spawn',"
            "'provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,'known','test','now',1000)"
        )
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='trust_observations_validate_bound_insert'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER trust_observations_validate_bound_insert")
        connection.execute(
            "INSERT INTO trust_observations(observation_id,scope,severity,status,"
            "effective_group_id,usage_confidence,created_at,run_id) VALUES("
            "'active-trust','workflow','R1','promoted','group','known','now',"
            "'trusted-run')"
        )
        connection.execute(trigger_sql)
        external_metadata = json.dumps(
            {
                "run_id": "r",
                "transition_id": "t",
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "phase": "phase",
                "agent_id": "agent",
                "task_digest": "task",
            }
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "strict prior reserve"):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_contract_version,"
                "metadata_json,external_metadata_json,external_run_id,"
                "external_transition_id,external_client_request_id,"
                "external_idempotency_key,external_phase,external_agent_id,"
                "external_task_digest,state,external_id,requested_at,"
                "requested_at_epoch_ms) VALUES('intent-cross-workflow','r','t',"
                "'sessions_spawn','spawn','reserve','client','spawn-idem','phase',"
                "'agent','task','v1','{}',?,'r','t','client','spawn-idem','phase',"
                "'agent','task','accepted','bad-session','now',1001)",
                (external_metadata,),
            )

    def test_v1_projection_identity_upgrade_rejects_ambiguous_timestamps(self) -> None:
        self._apply_v1_migration_only("v1-migrations")

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('shadow','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                "'run-a','prepare-run-a','shadow','file_authority_shadow',"
                "'finalized','R1','R1','now','now','now',1)"
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-a-old','run-a',"
                "'reports/summary.json',?,'file_authority_shadow','9')",
                ("a" * 64,),
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection-a-new','run-a',"
                "'reports/summary.json',?,'file_authority_shadow','10')",
                ("b" * 64,),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_v1_projection_identity_upgrade_rejects_duplicate_timestamp(self) -> None:
        self._apply_v1_migration_only("v1-duplicate-timestamp")

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('shadow','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                "'run-a','prepare-run-a','shadow','file_authority_shadow',"
                "'finalized','R1','R1','now','now','now',1)"
            )
            for projection_id, digest in (
                ("projection-a-old", "a" * 64),
                ("projection-a-new", "b" * 64),
            ):
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                    "source_authority,generated_at) VALUES(?,?,"
                    "'reports/summary.json',?,'file_authority_shadow',"
                    "'2026-01-01T00:00:00+00:00')",
                    (projection_id, "run-a", digest),
                )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_v1_projection_identity_upgrade_rejects_tied_max_timestamp(self) -> None:
        self._apply_v1_migration_only("v1-tied-max-timestamp")

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('shadow','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                "'run-a','prepare-run-a','shadow','file_authority_shadow',"
                "'finalized','R1','R1','now','now','now',1)"
            )
            for projection_id, digest, generated_at in (
                (
                    "projection-a-old",
                    "a" * 64,
                    "2026-01-01T00:00:00+00:00",
                ),
                (
                    "projection-a-current-left",
                    "b" * 64,
                    "2026-01-02T00:00:00+00:00",
                ),
                (
                    "projection-a-current-right",
                    "c" * 64,
                    "2026-01-02T00:00:00+00:00",
                ),
            ):
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                    "source_authority,generated_at) VALUES(?,?,"
                    "'reports/summary.json',?,'file_authority_shadow',?)",
                    (projection_id, "run-a", digest, generated_at),
                )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_connect_fails_closed_when_wal_is_unavailable(self) -> None:
        connection = mock.Mock()

        def execute(statement: str) -> mock.Mock:
            cursor = mock.Mock()
            if statement == "PRAGMA journal_mode=WAL":
                cursor.fetchone.return_value = ("delete",)
            elif statement == "PRAGMA foreign_keys":
                cursor.fetchone.return_value = (1,)
            else:
                cursor.fetchone.return_value = None
            return cursor

        connection.execute.side_effect = execute
        with mock.patch("agentic_os.migrations.sqlite3.connect", return_value=connection):
            with self.assertRaisesRegex(MigrationError, "WAL journal mode is unavailable"):
                _connect(self.database)
        connection.close.assert_called_once_with()

    def test_packaged_migration_assets_match_repository_assets(self) -> None:
        asset_root = resources.files("agentic_os.migration_assets")
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        for filename in ("manifest.json", *(row["file"] for row in manifest["migrations"])):
            with self.subTest(filename=filename):
                self.assertEqual(
                    (asset_root / filename).read_bytes(),
                    (repository_root() / "migrations" / filename).read_bytes(),
                )
        self.assertEqual(
            [migration.sha256 for migration in load_migrations()],
            [
                migration.sha256
                for migration in load_migrations(repository_root() / "migrations")
            ],
        )

    def test_default_migration_loader_uses_package_resources(self) -> None:
        asset_root = resources.files("agentic_os.migration_assets")
        with mock.patch(
            "agentic_os.migrations.repository_root",
            side_effect=AssertionError("source-tree migrations must not be required"),
        ):
            migrations = load_migrations()
        self.assertEqual(
            [migration.name for migration in migrations],
            [
                "minimum_contract",
                "shadow_projection_identity",
                "budget_ledger_slo_identity",
                "budget_post_dispatch_mutations",
                "budget_retry_prefix_spawn_scope",
                "budget_post_dispatch_slo_guards",
                "budget_post_dispatch_clock_identity",
                "budget_atomic_final_settlement",
                "legacy_money_import_quarantine",
                "runtime_dispatch_binding",
                "gate_authority_snapshot",
                "goal_run_evidence_binding",
                "trust_promotion_binding",
                "db_authority_canary_binding",
                "strict_prior_reserve_slo_identity",
                "expired_lease_spawn_guard",
            ],
        )
        for migration in migrations:
            with self.subTest(migration=migration.name):
                self.assertEqual(
                    migration.sha256,
                    hashlib.sha256((asset_root / migration.path.name).read_bytes()).hexdigest(),
                )

    def test_verify_is_read_only_and_creates_no_sidecars(self) -> None:
        apply_migrations(self.database)
        verify_target = Path(self.temporary.name) / "readonly.db"
        # SQLite backup establishes a migrated, checkpointed baseline with no
        # sidecars. verify_database must not change it or create any.
        with sqlite3.connect(self.database) as source, sqlite3.connect(verify_target) as target:
            source.backup(target)
        wal = Path(f"{verify_target}-wal")
        shm = Path(f"{verify_target}-shm")
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        before = hashlib.sha256(verify_target.read_bytes()).hexdigest()
        before_mtime = verify_target.stat().st_mtime_ns
        self.assertEqual(
            verify_database(verify_target),
            (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        )
        self.assertEqual(hashlib.sha256(verify_target.read_bytes()).hexdigest(), before)
        self.assertEqual(verify_target.stat().st_mtime_ns, before_mtime)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())

    def test_verify_refuses_sidecar_without_changing_any_file(self) -> None:
        apply_migrations(self.database)
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                verify_target = Path(self.temporary.name) / f"sidecar{suffix}.db"
                with sqlite3.connect(self.database) as source, sqlite3.connect(
                    verify_target
                ) as target:
                    source.backup(target)
                sidecar = Path(f"{verify_target}{suffix}")
                sidecar.write_bytes(b"sidecar-sentinel")
                database_before = (
                    hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                    verify_target.stat().st_mtime_ns,
                )
                sidecar_before = (sidecar.read_bytes(), sidecar.stat().st_mtime_ns)
                with self.assertRaisesRegex(
                    MigrationError, "requires an offline checkpointed snapshot"
                ):
                    verify_database(verify_target)
                self.assertEqual(
                    (
                        hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                        verify_target.stat().st_mtime_ns,
                    ),
                    database_before,
                )
                self.assertEqual(
                    (sidecar.read_bytes(), sidecar.stat().st_mtime_ns), sidecar_before
                )
                for other_suffix in ("-wal", "-shm", "-journal"):
                    other = Path(f"{verify_target}{other_suffix}")
                    self.assertEqual(other.exists(), other_suffix == suffix)

    def test_foreign_keys_are_enforced(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('r','p','missing','file_authority','candidate','R0','R0','t','t')"
            )

    def test_migration_file_hash_drift_is_refused_before_database_creation(self) -> None:
        migration_dir = Path(self.temporary.name) / "migrations"
        shutil.copytree(repository_root() / "migrations", migration_dir)
        migration = migration_dir / "0001_minimum_contract.sql"
        migration.write_text(migration.read_text() + "\n-- drift\n", encoding="utf-8")
        drift_database = Path(self.temporary.name) / "drift.db"
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(drift_database, migration_dir=migration_dir)
        self.assertFalse(drift_database.exists())

    def test_recorded_hash_drift_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE schema_migrations SET sha256=?", ("0" * 64,))
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(self.database)

    def test_forged_migration_ledger_without_schema_is_refused(self) -> None:
        migration = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )["migrations"][0]
        for operation in (verify_database, apply_migrations):
            database = Path(self.temporary.name) / f"forged-{operation.__name__}.db"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE schema_migrations (version ANY PRIMARY KEY,name TEXT NOT NULL,"
                    "sha256 TEXT NOT NULL,applied_at TEXT NOT NULL,"
                    "CHECK(typeof(version)='integer' AND version>0)) STRICT"
                )
                connection.execute(
                    "INSERT INTO schema_migrations VALUES(?,?,?,?)",
                    (migration["version"], migration["name"], migration["sha256"], "now"),
                )
            with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                MigrationHashDrift, "schema differs"
            ):
                operation(database)

    def test_schema_object_definition_drift_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE workflow_authority ADD COLUMN forged TEXT")
        verify_target = Path(self.temporary.name) / "schema-drift-readonly.db"
        with sqlite3.connect(self.database) as source, sqlite3.connect(verify_target) as target:
            source.backup(target)
        with self.assertRaisesRegex(MigrationHashDrift, "schema differs"):
            verify_database(verify_target)
        with self.assertRaisesRegex(MigrationHashDrift, "schema differs"):
            apply_migrations(self.database)

    def test_database_authority_requires_cutover_evidence(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        for mode in ("db_authority_canary", "db_authority"):
            with self.subTest(mode=mode), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO workflow_authority(workflow,mode,updated_at) VALUES(?,?,?)",
                    (mode, mode, "now"),
                )
            with self.subTest(mode=f"{mode}-undrained"), self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                    "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                    "open_file_authority_runs,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (f"{mode}-undrained", mode, "river", "evidence", "deadline", "parity", 1, "now"),
                )
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
            "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,updated_at) "
            "VALUES('valid','db_authority','river','evidence','deadline','parity','now')"
        )

    def test_db_authority_run_requires_current_cutover_but_history_survives(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('file-run','prepare-file','w','file_authority','candidate','R1','R1',"
            "'now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('bad-db-run','prepare-bad','w','db_authority','candidate','R1',"
                "'R1','now','now')"
            )
        connection.execute(
            "UPDATE workflow_authority SET open_file_authority_runs=1 WHERE workflow='w'"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE workflow_authority SET mode='db_authority_canary',"
                "cutover_approved_by='river',cutover_evidence_hash='evidence',"
                "rollback_deadline='deadline',last_parity_audit_hash='parity',"
                "updated_at='later' WHERE workflow='w'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "drained"):
            connection.execute(
                "UPDATE workflow_authority SET mode='db_authority_canary',"
                "cutover_approved_by='river',cutover_evidence_hash='evidence',"
                "rollback_deadline='deadline',last_parity_audit_hash='parity',"
                "open_file_authority_runs=0,updated_at='later' WHERE workflow='w'"
            )
        connection.execute(
            "UPDATE runs SET state='finalized' WHERE run_id='file-run'"
        )
        connection.execute(
            "UPDATE workflow_authority SET mode='db_authority_canary',"
            "cutover_approved_by='river',cutover_evidence_hash='evidence',"
            "rollback_deadline='deadline',last_parity_audit_hash='parity',"
            "open_file_authority_runs=0,updated_at='later' WHERE workflow='w'"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('db-run','prepare-db','w','db_authority_canary','candidate','R1',"
            "'R1','now','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "active db authority"):
            connection.execute(
                "UPDATE workflow_authority SET mode='rollback_to_file_authority',"
                "updated_at='rollback' WHERE workflow='w'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "conflicts"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('late-file-run','prepare-late-file','w','file_authority',"
                "'candidate','R1','R1','now','now')"
            )
        connection.execute("UPDATE runs SET state='finalized' WHERE run_id='db-run'")
        connection.execute(
            "UPDATE workflow_authority SET mode='rollback_to_file_authority',"
            "updated_at='rollback' WHERE workflow='w'"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "active workflow cutover"):
            connection.execute(
                "UPDATE runs SET authority_mode='db_authority',updated_at='terminal-db-claim' "
                "WHERE run_id='file-run'"
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('file-terminal-swap','prepare-terminal-swap','w','file_authority',"
            "'candidate','R1','R1','now','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "active workflow cutover"):
            connection.execute(
                "UPDATE runs SET authority_mode='db_authority',state='finalized',"
                "updated_at='terminal-swap' WHERE run_id='file-terminal-swap'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "active workflow cutover"):
            connection.execute(
                "UPDATE runs SET state='candidate',updated_at='reopened' "
                "WHERE run_id='db-run'"
            )
        self.assertEqual(
            connection.execute(
                "SELECT authority_mode FROM runs WHERE run_id='file-run'"
            ).fetchone(),
            ("file_authority",),
        )

    def test_canary_projection_freezes_run_authority_binding(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        for workflow in ("canary-a", "canary-b"):
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES(?,'db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                (workflow, "c" * 64, "p" * 64),
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
            "finalized_at_epoch_ms) VALUES('canary-run','prepare-canary','canary-a',"
            "'db_authority_canary','finalized','R1','R1','now','now',"
            "'2099-01-01T00:00:00+00:00',4070908800000)"
        )
        digest = "d" * 64
        connection.execute(
            "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
            "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
            (
                _shadow_projection_id("canary-run", "tmp/canary.json", digest),
                "canary-run",
                "tmp/canary.json",
                digest,
                "db_authority_canary",
                "2099-01-01T00:00:00+00:00",
            ),
        )

        for statement in (
            "UPDATE artifact_projections SET source_authority='file_authority' "
            "WHERE run_id='canary-run'",
            "UPDATE artifact_projections SET run_id='missing' "
            "WHERE run_id='canary-run'",
            "UPDATE artifact_projections SET path='tmp/other.json' "
            "WHERE run_id='canary-run'",
            "UPDATE artifact_projections SET sha256='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' WHERE run_id='canary-run'",
            "DELETE FROM artifact_projections WHERE run_id='canary-run'",
        ):
            with self.subTest(statement=statement), self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection identity is immutable"
            ):
                connection.execute(statement)
        for statement in (
            "UPDATE runs SET workflow='canary-b' WHERE run_id='canary-run'",
            "UPDATE runs SET authority_mode='db_authority' WHERE run_id='canary-run'",
            "UPDATE runs SET state='prepared' WHERE run_id='canary-run'",
            "UPDATE runs SET risk_class='R2' WHERE run_id='canary-run'",
            "UPDATE runs SET risk_dominance='R2' WHERE run_id='canary-run'",
            "UPDATE runs SET prepare_idempotency_key='prepare-other' "
            "WHERE run_id='canary-run'",
            "UPDATE runs SET finalized_at='tampered' WHERE run_id='canary-run'",
            "DELETE FROM runs WHERE run_id='canary-run'",
        ):
            with self.subTest(statement=statement), self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection binding is immutable"
            ):
                connection.execute(statement)
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary projection identity is immutable"
        ):
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('non-canary-extra',"
                "'canary-run','tmp/extra.json',?,'file_authority','now')",
                ("f" * 64,),
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
            "finalized_at_epoch_ms) VALUES('canary-run-duplicate-path',"
            "'prepare-canary-duplicate-path','canary-a','db_authority_canary',"
            "'finalized','R1','R1','now','now','2099-01-01T00:00:00+00:00',"
            "4070908800000)"
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary projection identity is immutable"
        ):
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    _shadow_projection_id(
                        "canary-run-duplicate-path",
                        "tmp/canary.json",
                        "f" * 64,
                    ),
                    "canary-run-duplicate-path",
                    "tmp/canary.json",
                    "f" * 64,
                    "db_authority_canary",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary workflow binding is immutable"
        ):
            connection.execute(
                "UPDATE workflow_authority SET mode='file_authority' "
                "WHERE workflow='canary-a'"
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary workflow binding is immutable"
        ):
            connection.execute(
                "UPDATE workflow_authority SET mode='rollback_to_file_authority' "
                "WHERE workflow='canary-a'"
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary workflow binding is immutable"
        ):
            connection.execute(
                "UPDATE workflow_authority SET cutover_evidence_hash=? "
                "WHERE workflow='canary-a'",
                ("f" * 64,),
            )
        self.assertEqual(
            connection.execute(
                "SELECT workflow,authority_mode FROM runs WHERE run_id='canary-run'"
            ).fetchone(),
            ("canary-a", "db_authority_canary"),
        )

    def test_canary_projection_insert_requires_valid_canary_binding(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('file-workflow','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('file-run','prepare-file','file-workflow','file_authority',"
            "'prepared','R1','R1','now','now')"
        )
        digest = "d" * 64
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "canary projection identity is immutable"
        ):
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    _shadow_projection_id("file-run", "tmp/forged.json", digest),
                    "file-run",
                    "tmp/forged.json",
                    digest,
                    "db_authority_canary",
                    "now",
                ),
            )

    def test_canary_binding_migration_rejects_existing_authority_drift(self) -> None:
        self._apply_migrations_through(13, "through-v13-canary-binding")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                ("c" * 64, "e" * 64),
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
                "finalized_at_epoch_ms) VALUES('canary-run','prepare-canary','canary',"
                "'db_authority_canary','finalized','R1','R1','now','now',"
                "'2099-01-01T00:00:00+00:00',4070908800000)"
            )
            digest = "d" * 64
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    _shadow_projection_id("canary-run", "tmp/canary.json", digest),
                    "canary-run",
                    "tmp/canary.json",
                    digest,
                    "db_authority_canary",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            connection.execute(
                "UPDATE runs SET authority_mode='file_authority' "
                "WHERE run_id='canary-run'"
            )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_canary_binding_migration_rejects_malformed_cutover_metadata(self) -> None:
        self._apply_migrations_through(13, "through-v13-canary-bad-cutover")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',"
                "'notsha','not-a-deadline','also-notsha','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
                "finalized_at_epoch_ms) VALUES('canary-run','prepare-canary','canary',"
                "'db_authority_canary','finalized','R1','R1','now','now',"
                "'2099-01-01T00:00:00+00:00',4070908800000)"
            )
            digest = "d" * 64
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    _shadow_projection_id("canary-run", "tmp/canary.json", digest),
                    "canary-run",
                    "tmp/canary.json",
                    digest,
                    "db_authority_canary",
                    "2099-01-01T00:00:00+00:00",
                ),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_canary_binding_migration_counts_every_projection_for_canary_runs(self) -> None:
        self._apply_migrations_through(13, "through-v13-canary-extra-projection")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                ("c" * 64, "e" * 64),
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
                "finalized_at_epoch_ms) VALUES('canary-run','prepare-canary','canary',"
                "'db_authority_canary','finalized','R1','R1','now','now',"
                "'2099-01-01T00:00:00+00:00',4070908800000)"
            )
            canary_digest = "d" * 64
            file_digest = "f" * 64
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    _shadow_projection_id("canary-run", "tmp/canary.json", canary_digest),
                    "canary-run",
                    "tmp/canary.json",
                    canary_digest,
                    "db_authority_canary",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                (
                    "legacy-file-authority-extra",
                    "canary-run",
                    "tmp/extra.json",
                    file_digest,
                    "file_authority",
                    "2099-01-01T00:00:00+00:00",
                ),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_canary_binding_migration_rejects_duplicate_canary_paths(self) -> None:
        self._apply_migrations_through(13, "through-v13-canary-duplicate-path")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                ("c" * 64, "e" * 64),
            )
            for run_id, digest in (("canary-run-a", "a" * 64), ("canary-run-b", "b" * 64)):
                connection.execute(
                    "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                    "authority_mode,state,risk_class,risk_dominance,created_at,"
                    "updated_at,finalized_at,finalized_at_epoch_ms) VALUES(?,?,'canary',"
                    "'db_authority_canary','finalized','R1','R1','now','now',"
                    "'2099-01-01T00:00:00+00:00',4070908800000)",
                    (run_id, f"prepare-{run_id}"),
                )
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                    "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                    (
                        _shadow_projection_id(run_id, "tmp/canary.json", digest),
                        run_id,
                        "tmp/canary.json",
                        digest,
                        "db_authority_canary",
                        "2099-01-01T00:00:00+00:00",
                    ),
                )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)

    def test_canary_binding_migration_rejects_candidate_projection_atomically(self) -> None:
        self._apply_migrations_through(13, "through-v13-candidate-canary")
        projection_id = _shadow_projection_id(
            "candidate-run", "tmp/candidate.json", "d" * 64
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                ("c" * 64, "e" * 64),
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'candidate-run','prepare-candidate','canary','db_authority_canary',"
                "'candidate','R1','R1','now','now')"
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES(?, 'candidate-run',"
                "'tmp/candidate.json',?,'db_authority_canary','now')",
                (projection_id, "d" * 64),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone(),
                (13,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='candidate-run'"
                ).fetchone(),
                ("candidate",),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='trigger' AND "
                    "name='artifact_projections_preserve_db_authority_canary_delete'"
                ).fetchone()
            )

    def test_canary_binding_migration_accepts_valid_prepared_and_finalized_runs(self) -> None:
        self._apply_migrations_through(13, "through-v13-valid-canary-lifecycle")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "updated_at) VALUES('canary','db_authority_canary','local-fixture',?,"
                "'2099-01-01T00:00:00+00:00',?,'now')",
                ("c" * 64, "e" * 64),
            )
            for run_id, state, finalized_at, finalized_epoch_ms in (
                ("prepared-run", "prepared", None, None),
                (
                    "finalized-run",
                    "finalized",
                    "2099-01-01T00:00:00+00:00",
                    4070908800000,
                ),
            ):
                connection.execute(
                    "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                    "authority_mode,state,risk_class,risk_dominance,created_at,updated_at,"
                    "finalized_at,finalized_at_epoch_ms) VALUES(?,?,'canary',"
                    "'db_authority_canary',?,'R1','R1','now','now',?,?)",
                    (run_id, f"prepare-{run_id}", state, finalized_at, finalized_epoch_ms),
                )
                path = f"tmp/{run_id}.json"
                digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                    "source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                    (
                        _shadow_projection_id(run_id, path, digest),
                        run_id,
                        path,
                        digest,
                        "db_authority_canary",
                        "2099-01-01T00:00:00+00:00",
                    ),
                )

        self.assertEqual(apply_migrations(self.database), (14, 15, 16))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT run_id,state FROM runs ORDER BY run_id"
                ).fetchall(),
                [("finalized-run", "finalized"), ("prepared-run", "prepared")],
            )

    def test_run_risk_dominance_is_allowlisted(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('run','prepare','w','file_authority','candidate','R1','HIGH',"
                "'now','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('bad-state','prepare-state','w','file_authority','gate-passsed',"
                "'R1','R1','now','now')"
            )

    def test_run_state_is_allowlisted(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('ok','prepare-ok','w','file_authority','gate_passed','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('triaged','prepare-triaged','w','file_authority','triaged','R1','R1',"
            "'now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('bad','prepare-bad','w','file_authority','gate_pased','R1','R1',"
                "'now','now')"
            )

    def test_approval_transition_requires_bound_gate_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('r','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        values = (
            "t", "r", "before", "after", "mutate", "write", "file", "id", "hash",
            "scope", 1, "approval", "channel", "source", "text", "R1", "idem", 0, None,
            "now",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
                "approval_required,approval_id,approval_channel,approval_source_digest,"
                "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
                "gate_run_id,created_at) VALUES(" + ",".join("?" for _ in values) + ")",
                values,
            )

    def test_high_risk_transition_requires_approval(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('r','prepare','w','file_authority','candidate','R4','R4','now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES("
                "'t','r','before','after','mutate','write','R4','idem',0,'now')"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "run risk dominance"):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES("
                "'low-copy','r','before','after','mutate','write','R1','low-idem',0,'now')"
            )

    def test_approval_transition_must_match_authorized_run_and_target(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
        connection.commit()
        connection.execute("BEGIN")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run-b','river',"
            "'telegram','source','text','write','file','id','hash','scope','R1',"
            "2000,'approval-hash','transition','gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "authorize transition"):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,approval_required,approval_id,approval_channel,"
                "approval_source_digest,approval_text_digest,risk_dominance,"
                "idempotency_key,guard_version_before,gate_run_id,created_at) VALUES("
                "'transition','run-a','before','after','mutate','write','file','id',"
                "'hash','scope',1,'approval','telegram','source','text','R1',"
                "'idem',0,'gate','now')"
            )
        connection.rollback()
        connection.execute("BEGIN")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('expired-approval','run-a',"
            "'river','telegram','source','text','write','file','id','hash','scope',"
            "'R1',1000,'expired-approval-hash','expired-transition','expired-gate','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
            "approval_required,approval_id,approval_channel,approval_source_digest,"
            "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
            "gate_run_id,created_at) VALUES('expired-transition','run-a','before',"
            "'after','mutate','write','file','id','hash','scope',1,'expired-approval',"
            "'telegram','source','text','R1','expired-idem',0,'expired-gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "expired"):
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
                "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
                "VALUES('expired-clock','expired-gate','expired-gate','run-a',"
                "'expired-transition','expired-nonce',1000,1000,'clock','source',1000)"
            )
        connection.rollback()

    def test_transition_approval_must_be_single_use(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.commit()
        connection.execute("BEGIN")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,single_use,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run','river',"
            "'telegram','source','text','write','file','id','hash','scope','R1',"
            "2000,0,'approval-hash','transition','gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "authorize transition"):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
                "approval_required,approval_id,approval_channel,approval_source_digest,"
                "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
                "gate_run_id,created_at) VALUES('transition','run','before','after',"
                "'mutate','write','file','id','hash','scope',1,'approval','telegram',"
                "'source','text','R1','idem',0,'gate','now')"
            )
        connection.rollback()

    def test_approval_id_must_be_non_empty(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                "source_message_digest,approval_text_digest,approved_action_type,"
                "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
                "expires_at_epoch_ms,approval_hash,approved_at) VALUES('',"
                "'run','river','telegram','source','text','write','file','id','hash',"
                "'scope','R1',2000,'approval-hash','now')"
            )
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
                "approval_required,approval_id,approval_channel,approval_source_digest,"
                "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
                "gate_run_id,created_at) VALUES('transition','run','before','after',"
                "'mutate','write','file','id','hash','scope',1,'','telegram',"
                "'source','text','R1','idem',0,'gate','now')"
            )

    def test_consumed_transition_approval_ceiling_cannot_be_weakened(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R4','R4','now','now')"
        )
        connection.commit()
        connection.execute("BEGIN")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,single_use,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run','river',"
            "'telegram','source','text','write','file','id','hash','scope','R4',"
            "2000,1,'approval-hash','transition','gate','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
            "approval_required,approval_id,approval_channel,approval_source_digest,"
            "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
            "gate_run_id,created_at) VALUES('transition','run','before','after',"
            "'mutate','write','file','id','hash','scope',1,'approval','telegram',"
            "'source','text','R4','idem',0,'gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "exact approval binding"):
            connection.execute(
                "UPDATE approvals SET approved_risk_ceiling='R0' "
                "WHERE approval_id='approval'"
            )
        connection.rollback()

    def test_exact_mutating_approval_slo_rejects_reusable_consumed_approval(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,single_use,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run','river',"
            "'telegram','source','text','write','file','id','hash','scope','R1',"
            "2000,1,'approval-hash','transition','gate','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
            "approval_required,approval_id,approval_channel,approval_source_digest,"
            "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
            "gate_run_id,created_at) VALUES('transition','run','before','after',"
            "'mutate','write','file','id','hash','scope',1,'approval','telegram',"
            "'source','text','R1','idem',0,'gate','now')"
        )
        connection.execute(
            "INSERT INTO risk_assessments(assessment_id,run_id,transition_id,action_risk,"
            "target_risk,data_risk,side_effect_risk,permission_risk,"
            "irreversibility_risk,risk_dominance,assessed_at) VALUES("
            "'risk','run','transition','R1','R1','R1','R1','R1','R1','R1','now')"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier','run','worker','verifier','provider','model','prompt','context',"
            "'evidence','independent','{\"reviewer_session\":\"fixture\"}','now')"
        )
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES('gate','run','transition','clock','verifier','pass','now',1000,"
            "'v1','query','migration','evidence','R1','now')"
        )
        connection.execute(
            "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
            "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
            "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
            "VALUES('clock','gate','gate','run','transition','nonce',1000,1000,"
            "'clock','source',1000)"
        )
        connection.execute(
            "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,size_bytes,"
            "content_type,redaction_status,producer_run_id,verifier_run_id,gate_run_id,"
            "captured_at) VALUES('evidence','run','evidence.json','sha',1,"
            "'application/json','none','run','verifier','gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "pass-gated transition"):
            connection.execute(
                "UPDATE transitions SET approval_required=0,approval_id=NULL,"
                "approval_channel=NULL,approval_source_digest=NULL,"
                "approval_text_digest=NULL WHERE transition_id='transition'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "exact approval binding"):
            connection.execute("UPDATE approvals SET single_use=0 WHERE approval_id='approval'")

    def test_approval_consumption_target_is_exclusive(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)

        def insert_approval(
            approval_id: str,
            transition_id: str | None,
            gate_run_id: str | None,
            goal_run_id: str | None,
        ) -> None:
            connection.execute(
                "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                "source_message_digest,approval_text_digest,approved_action_type,"
                "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
                "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
                "consumed_by_gate_run_id,consumed_by_goal_run_id,approved_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    approval_id,
                    f"run-{approval_id}",
                    "river",
                    "telegram",
                    f"source-{approval_id}",
                    f"text-{approval_id}",
                    "action",
                    "target",
                    f"target-{approval_id}",
                    f"hash-{approval_id}",
                    "scope",
                    "R1",
                    2000,
                    f"approval-hash-{approval_id}",
                    transition_id,
                    gate_run_id,
                    goal_run_id,
                    "now",
                ),
            )

        insert_approval("unconsumed", None, None, None)
        insert_approval("transition-gate", "transition", "gate", None)
        insert_approval("goal-run", None, None, "goal")
        for approval_id, transition_id, gate_run_id, goal_run_id in (
            ("transition-only", "transition", None, None),
            ("gate-only", None, "gate", None),
            ("transition-goal", "transition", None, "goal"),
            ("gate-goal", None, "gate", "goal"),
            ("transition-gate-goal", "transition", "gate", "goal"),
        ):
            with self.subTest(approval_id=approval_id), self.assertRaises(
                sqlite3.IntegrityError
            ):
                insert_approval(approval_id, transition_id, gate_run_id, goal_run_id)

    def test_lease_external_metadata_is_required_and_exact(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        base = (
            "lease", "run", "phase", "transition", "agent", "requester", "acquired",
            "gateway", "client", "idem", 60000, "expires", 2000000000000,
        )
        statement = (
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,requester_agent_id,"
            "state,gateway_lease_id,client_lease_id,acquire_idempotency_key,ttl_ms,expires_at,"
            "expires_at_epoch_ms) VALUES(" + ",".join("?" for _ in base) + ")"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(statement, base)
        metadata = {
            "client_lease_id": "client",
            "idempotency_key": "idem-valid",
            "run_id": "run",
            "phase": "phase",
            "transition_id": "transition",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "ttl_ms": 60000,
        }
        missing_acquire_proof = (
            "lease-no-proof", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway-no-proof", "client-no-proof", "idem-no-proof", 60000,
            "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-no-proof",
                    "idempotency_key": "idem-no-proof",
                    "gateway_lease_id": "gateway-no-proof",
                }
            ),
            "client-no-proof", "idem-no-proof", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "acquire intent proof"):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in missing_acquire_proof) + ")",
                missing_acquire_proof,
            )
        acquire_metadata = json.dumps(
            {
                "client_lease_id": "client-valid",
                "idempotency_key": "idem-valid",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,"
            "external_id,requested_at,requested_at_epoch_ms) VALUES('acquire-valid','run',"
            "'transition','allow_lease_acquire','phase','agent','requester',60000,"
            "'client-valid','idem-valid','v1','{}',?,'run','phase','transition','agent',"
            "'requester',60000,"
            "'client-valid','idem-valid','accepted','gateway','now',1000)",
            (acquire_metadata,),
        )
        valid = (
            "lease-valid", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway", "client-valid", "idem-valid", 60000, "v1", "now",
            json.dumps({**metadata, "client_lease_id": "client-valid"}),
            "client-valid", "idem-valid", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in valid)
                + ")",
                valid,
            )
        mismatched_gateway_metadata = (
            "lease-mismatched-gateway", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway", "client-valid", "idem-valid", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-valid",
                    "gateway_lease_id": "other-gateway",
                }
            ),
            "client-valid", "idem-valid", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in mismatched_gateway_metadata)
                + ")",
                mismatched_gateway_metadata,
            )
        valid = (
            "lease-valid", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway", "client-valid", "idem-valid", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-valid",
                    "gateway_lease_id": "gateway",
                }
            ),
            "client-valid", "idem-valid", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        connection.execute(
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
            "requester_agent_id,state,gateway_lease_id,client_lease_id,"
            "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
            "metadata_observed_at,external_metadata_json,external_client_lease_id,"
            "external_idempotency_key,external_run_id,external_phase,"
            "external_transition_id,external_agent_id,external_requester_agent_id,"
            "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
            + ",".join("?" for _ in valid) + ")",
            valid,
        )
        numeric_identity = (
            "lease-numeric", "1", "phase", "transition", "agent", "requester",
            "acquired", "gateway-numeric", "1", "idem-numeric", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": 1,
                    "idempotency_key": "idem-numeric",
                    "run_id": 1,
                    "gateway_lease_id": "gateway-numeric",
                }
            ),
            "1", "idem-numeric", "1", "phase", "transition", "agent", "requester",
            60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in numeric_identity) + ")",
                numeric_identity,
            )
        empty_identity = (
            "lease-empty", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway-empty", "", "idem-empty", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "",
                    "idempotency_key": "idem-empty",
                    "gateway_lease_id": "gateway-empty",
                }
            ),
            "", "idem-empty", "run", "phase", "transition", "agent", "requester",
            60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in empty_identity) + ")",
                empty_identity,
            )
        duplicate_gateway = (
            "lease-valid-2", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway", "client-valid-2", "idem-valid-2", 60000,
            "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-valid-2",
                    "idempotency_key": "idem-valid-2",
                    "gateway_lease_id": "gateway",
                }
            ),
            "client-valid-2", "idem-valid-2", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in duplicate_gateway) + ")",
                duplicate_gateway,
            )

    def test_live_lease_release_states_require_release_proof(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        metadata = {
            "client_lease_id": "client",
            "idempotency_key": "idem",
            "run_id": "run",
            "phase": "phase",
            "transition_id": "transition",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "ttl_ms": 60000,
        }
        acquire_fields = (
            "lease_id,run_id,phase,transition_id,agent_id,requester_agent_id,state,"
            "gateway_lease_id,client_lease_id,acquire_idempotency_key,ttl_ms,"
            "metadata_contract_version,metadata_observed_at,external_metadata_json,"
            "external_client_lease_id,external_idempotency_key,external_run_id,"
            "external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,expires_at,expires_at_epoch_ms"
        )
        released_without_proof = (
            "released-no-proof", "run", "phase", "transition", "agent", "requester",
            "released", "gateway-released", "client", "idem", 60000, "v1", "now",
            json.dumps(metadata), "client", "idem", "run", "phase", "transition",
            "agent", "requester", 60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                f"INSERT INTO leases({acquire_fields}) VALUES("
                + ",".join("?" for _ in released_without_proof)
                + ")",
                released_without_proof,
            )
        expired_without_proof = (
            "expired-no-proof", "run", "phase", "transition", "agent", "requester",
            "expired", "gateway-expired-no-proof", "client-expired-no-proof",
            "idem-expired-no-proof", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-expired-no-proof",
                    "idempotency_key": "idem-expired-no-proof",
                    "gateway_lease_id": "gateway-expired-no-proof",
                }
            ),
            "client-expired-no-proof", "idem-expired-no-proof", "run", "phase",
            "transition", "agent", "requester", 60000, "past", 1,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release intent proof"):
            connection.execute(
                f"INSERT INTO leases({acquire_fields}) VALUES("
                + ",".join("?" for _ in expired_without_proof)
                + ")",
                expired_without_proof,
            )
        released_fields = (
            f"{acquire_fields},release_idempotency_key,release_requested_at,released_at"
        )
        released_with_fake_local_proof = (
            "released-fake-proof", "run", "phase", "transition", "agent", "requester",
            "released", "gateway-fake", "client-fake", "idem-fake", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-fake",
                    "idempotency_key": "idem-fake",
                    "gateway_lease_id": "gateway-fake",
                }
            ),
            "client-fake", "idem-fake", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000, "release-idem-fake",
            "release-requested", "released-at",
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release intent proof"):
            connection.execute(
                f"INSERT INTO leases({released_fields}) VALUES("
                + ",".join("?" for _ in released_with_fake_local_proof)
                + ")",
                released_with_fake_local_proof,
            )
        bad_release_metadata = json.dumps(
            {
                "run_id": "other",
                "transition_id": "transition",
                "release_idempotency_key": "release-idem-bad",
                "gateway_lease_id": "gateway-bad",
            }
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_transition_id,"
                "external_idempotency_key,state,external_id,requested_at,requested_at_epoch_ms) "
                "VALUES('release-intent-bad','run','transition','allow_lease_release',"
                "'release-client-bad','release-idem-bad','v1','{}',?,'run','transition',"
                "'release-idem-bad','accepted','gateway-bad','now',1000)",
                (bad_release_metadata,),
            )
        missing_owner_metadata = json.dumps(
            {
                "run_id": "run",
                "transition_id": "transition",
                "idempotency_key": "release-idem-missing-owner",
                "release_idempotency_key": "release-idem-missing-owner",
                "gateway_lease_id": "gateway-released-ok",
            }
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "owner metadata proof"):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "phase,agent_id,requester_agent_id,client_request_id,idempotency_key,"
                "metadata_contract_version,metadata_json,external_metadata_json,"
                "external_run_id,external_phase,external_transition_id,external_agent_id,"
                "external_requester_agent_id,external_client_request_id,external_idempotency_key,"
                "state,external_id,requested_at,requested_at_epoch_ms) "
                "VALUES('release-intent-missing-owner','run','transition',"
                "'allow_lease_release','phase','agent','requester','client-ok',"
                "'release-idem-missing-owner','v1','{}',?,'run','phase','transition',"
                "'agent','requester','client-ok','release-idem-missing-owner',"
                "'accepted','gateway-released-ok','now',1000)",
                (missing_owner_metadata,),
            )
        release_metadata = json.dumps(
            {
                "client_lease_id": "client-ok",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "idempotency_key": "release-idem",
                "release_idempotency_key": "release-idem",
                "gateway_lease_id": "gateway-released-ok",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_client_request_id,external_idempotency_key,"
            "state,external_id,requested_at,requested_at_epoch_ms) "
            "VALUES('release-intent','run','transition','allow_lease_release',"
            "'phase','agent','requester','client-ok','release-idem','v1','{}',?,"
            "'run','phase','transition','agent','requester','client-ok','release-idem',"
            "'accepted','gateway-released-ok','now',1000)",
            (release_metadata,),
        )
        released_with_external_proof = (
            "released-ok", "run", "phase", "transition", "agent", "requester",
            "released", "gateway-released-ok", "client-ok", "idem-ok", 60000, "v1",
            "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-ok",
                    "idempotency_key": "idem-ok",
                    "gateway_lease_id": "gateway-released-ok",
                }
            ),
            "client-ok", "idem-ok", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000, "release-idem",
            "release-requested", "released-at",
        )
        connection.execute(
            f"INSERT INTO leases({released_fields}) VALUES("
            + ",".join("?" for _ in released_with_external_proof)
            + ")",
            released_with_external_proof,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release intent proof"):
            connection.execute(
                "UPDATE leases SET gateway_lease_id='gateway-released-other', "
                "external_metadata_json=? WHERE lease_id='released-ok'",
                (
                    json.dumps(
                        {
                            **metadata,
                            "client_lease_id": "client-ok",
                            "idempotency_key": "idem-ok",
                            "gateway_lease_id": "gateway-released-other",
                        }
                    ),
                ),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release intent proof"):
            connection.execute(
                "UPDATE external_rpc_intents SET external_id='other-gateway' "
                "WHERE intent_id='release-intent'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release intent proof"):
            connection.execute("DELETE FROM external_rpc_intents WHERE intent_id='release-intent'")
        acquire_live_metadata = json.dumps(
            {
                "client_lease_id": "client-live",
                "idempotency_key": "idem-live",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway-live",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,"
            "external_id,requested_at,requested_at_epoch_ms) VALUES('acquire-live','run',"
            "'transition','allow_lease_acquire','phase','agent','requester',60000,"
            "'client-live','idem-live','v1','{}',?,'run','phase','transition','agent',"
            "'requester',60000,"
            "'client-live','idem-live','accepted','gateway-live','now',1000)",
            (acquire_live_metadata,),
        )
        acquired_live = (
            "acquired-live", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway-live", "client-live", "idem-live", 60000, "v1", "now",
            json.dumps(
                {
                    **metadata,
                    "client_lease_id": "client-live",
                    "idempotency_key": "idem-live",
                    "gateway_lease_id": "gateway-live",
                }
            ),
            "client-live", "idem-live", "run", "phase", "transition", "agent",
            "requester", 60000, "expires", 2000000000000,
        )
        connection.execute(
            f"INSERT INTO leases({acquire_fields}) VALUES("
            + ",".join("?" for _ in acquired_live)
            + ")",
            acquired_live,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release proof before deletion"):
            connection.execute("DELETE FROM leases WHERE lease_id='acquired-live'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving live state"):
            connection.execute(
                "UPDATE leases SET state='acquire_pending' "
                "WHERE lease_id='acquired-live'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "acquire intent proof"):
            connection.execute(
                "UPDATE external_rpc_intents SET external_id='gateway-other' "
                "WHERE intent_id='acquire-live'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "acquire intent proof"):
            connection.execute("DELETE FROM external_rpc_intents WHERE intent_id='acquire-live'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "live lease"):
            connection.execute(
                "UPDATE leases SET state='release_not_required', gateway_lease_id=NULL "
                "WHERE lease_id='acquired-live'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "expiry is immutable"):
            connection.execute(
                "UPDATE leases SET expires_at_epoch_ms=1 WHERE lease_id='acquired-live'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "expiry is immutable"):
            connection.execute(
                "UPDATE leases SET expires_at='past', expires_at_epoch_ms=1 "
                "WHERE lease_id='acquired-live'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving live state"):
            connection.execute(
                "UPDATE leases SET state='expired' WHERE lease_id='acquired-live'"
            )
        acquire_expired_metadata = json.dumps(
            {
                "client_lease_id": "client-expired",
                "idempotency_key": "idem-expired",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway-expired",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,"
            "external_id,requested_at,requested_at_epoch_ms) VALUES('acquire-expired','run',"
            "'transition','allow_lease_acquire','phase','agent','requester',60000,"
            "'client-expired','idem-expired','v1','{}',?,'run','phase','transition','agent',"
            "'requester',60000,"
            "'client-expired','idem-expired','accepted','gateway-expired','now',1000)",
            (acquire_expired_metadata,),
        )
        acquired_expired = (
            "acquired-expired", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway-expired", "client-expired", "idem-expired", 60000,
            "v1", "now", acquire_expired_metadata, "client-expired", "idem-expired",
            "run", "phase", "transition", "agent", "requester", 60000, "past", 1,
        )
        connection.execute(
            f"INSERT INTO leases({acquire_fields}) VALUES("
            + ",".join("?" for _ in acquired_expired)
            + ")",
            acquired_expired,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving live state"):
            connection.execute(
                "UPDATE leases SET state='expired', ttl_ms=1, "
                "metadata_contract_version=NULL, external_metadata_json=NULL "
                "WHERE lease_id='acquired-expired'"
            )
        connection.execute(
            "UPDATE leases SET state='expired' WHERE lease_id='acquired-expired'"
        )
        self.assertEqual(
            connection.execute(
                "SELECT state,ttl_ms,metadata_contract_version,external_metadata_json "
                "FROM leases WHERE lease_id='acquired-expired'"
            ).fetchone(),
            ("expired", 60000, "v1", acquire_expired_metadata),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving live state"):
            connection.execute(
                "UPDATE leases SET state='human_review_required', gateway_lease_id=NULL "
                "WHERE lease_id='acquired-live'"
            )
        release_not_required_with_gateway = (
            "release-not-required", "run", "phase", "transition", "agent", "requester",
            "release_not_required", "gateway-hidden", "client-hidden", "idem-hidden",
            60000, "expires", 2000000000000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in release_not_required_with_gateway)
                + ")",
                release_not_required_with_gateway,
            )
        pending_acquire_metadata = json.dumps(
            {
                "client_lease_id": "client-pending",
                "idempotency_key": "idem-pending",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway-pending",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,external_id,requested_at,requested_at_epoch_ms) "
            "VALUES('acquire-pending','run','transition','allow_lease_acquire','phase',"
            "'agent','requester',60000,'client-pending','idem-pending','v1','{}',?,"
            "'run','phase','transition','agent','requester',60000,'client-pending',"
            "'idem-pending','accepted','gateway-pending','now',1000)",
            (pending_acquire_metadata,),
        )
        pending_lease = (
            "acquire-pending", "run", "phase", "transition", "agent", "requester",
            "acquire_pending", None, "client-pending", "idem-pending", 60000, "v1",
            "now", pending_acquire_metadata, "client-pending", "idem-pending", "run",
            "phase", "transition", "agent", "requester", 60000, "expires",
            2000000000000,
        )
        connection.execute(
            f"INSERT INTO leases({acquire_fields}) VALUES("
            + ",".join("?" for _ in pending_lease)
            + ")",
            pending_lease,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release proof before deletion"):
            connection.execute("DELETE FROM leases WHERE lease_id='acquire-pending'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving pending ownership"):
            connection.execute(
                "UPDATE leases SET state='expired' WHERE lease_id='acquire-pending'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving pending ownership"):
            connection.execute(
                "UPDATE leases SET state='human_review_required' "
                "WHERE lease_id='acquire-pending'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving pending ownership"):
            connection.execute(
                "UPDATE leases SET state='release_not_required' "
                "WHERE lease_id='acquire-pending'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "leaving pending ownership"):
            connection.execute(
                "UPDATE leases SET client_lease_id='client-other' "
                "WHERE lease_id='acquire-pending'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "acquire intent proof"):
            connection.execute(
                "UPDATE external_rpc_intents SET state='pending' "
                "WHERE intent_id='acquire-pending'"
            )
        connection.execute(
            "UPDATE leases SET state='acquired', gateway_lease_id='gateway-pending' "
            "WHERE lease_id='acquire-pending'"
        )
        self.assertEqual(
            connection.execute(
                "SELECT state,gateway_lease_id FROM leases WHERE lease_id='acquire-pending'"
            ).fetchone(),
            ("acquired", "gateway-pending"),
        )
        hidden_acquire_metadata = json.dumps(
            {
                "client_lease_id": "client-hidden",
                "idempotency_key": "idem-hidden",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway-hidden",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,external_id,requested_at,requested_at_epoch_ms) "
            "VALUES('acquire-hidden','run','transition','allow_lease_acquire','phase',"
            "'agent','requester',60000,'client-hidden','idem-hidden','v1','{}',?,"
            "'run','phase','transition','agent','requester',60000,'client-hidden',"
            "'idem-hidden','accepted','gateway-hidden','now',1000)",
            (hidden_acquire_metadata,),
        )
        release_not_required_with_hidden_acquire = (
            "release-not-required-hidden", "run", "phase", "transition", "agent",
            "requester", "release_not_required", None, "client-hidden", "idem-hidden",
            60000, "expires", 2000000000000,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "release_not_required"):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                + ",".join("?" for _ in release_not_required_with_hidden_acquire)
                + ")",
                release_not_required_with_hidden_acquire,
            )

    def test_sqlite_boundary_rejects_duplicate_raw_metadata_keys(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        duplicate = '{"run_id":"expected","run_id":"other"}'
        with self.assertRaisesRegex(sqlite3.IntegrityError, "duplicate external metadata"):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_json,external_metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'intent','run','transition','allow_lease_acquire','client','idem','{}',?,"
                "'pending','now',1)",
                (duplicate,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "duplicate external metadata"):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,ttl_ms,"
                "external_metadata_json,expires_at,expires_at_epoch_ms) VALUES("
                "'lease','run','phase','transition','agent','requester','acquire_pending',"
                "'client-lease','lease-idem',60000,?,'expires',2000000000000)",
                (duplicate,),
            )

    def test_session_key_must_match_accepted_spawn_request(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('r','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'t','r','before','after','dispatch','spawn','R1','transition-idem',0,'now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'t-other','r','before','after','budget','reserve','R1',"
            "'transition-other-idem',0,'now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "accepted spawn request"):
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "session_key,created_at,updated_at) VALUES('spawn-bad','r','phase',"
                "'agent','t','client-bad','spawn-idem-bad','task','accepted',"
                "'accepted-session','now','now')"
            )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,transition_id,"
            "client_request_id,spawn_idempotency_key,task_digest,state,session_key,created_at,"
            "updated_at) VALUES('spawn','r','phase','agent','t','client','spawn-idem','task',"
            "'pending','accepted-session','now','now')"
        )
        self._seed_runtime_dispatch_binding(
            connection,
            run_id="r",
            transition_id="t",
            phase="phase",
            agent_id="agent",
            task_digest="task",
            spawn_request_id="spawn",
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
            reserve_budget_event_id="reserve",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,phase,"
                "agent_id,client_request_id,spawn_idempotency_key,session_key,task_digest,state) "
                "VALUES('session','spawn','r','t','phase','agent','client','spawn-idem',"
                "'wrong-session','task','running')"
            )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,usage_confidence,updated_at) VALUES('r','w','capability','provider','model',"
            "'endpoint','cost-row','effective','cost-hash','known','t',10,10,10,10,1,1,"
            "1,'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('reserve','reserve-idem','reserve-dedupe',1,'r',"
            "'t','spawn','provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,'known','test','now',1000)"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('consume','consume-idem','consume-dedupe',2,'r',"
            "'t','spawn','provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','consume',1,'known','test','now',1000)"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('over-budget','over-budget-idem','over-budget-dedupe',"
            "3,'r','t','spawn','provider','model','endpoint','capability','cost-row',"
            "'effective','cost-hash','known','reserve',11,'known','test','now',1000)"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-forged','other-provider','model','endpoint','capability',1,1,"
            "'known','effective','forged-hash')"
        )
        connection.execute(
            "UPDATE run_budgets SET selected_cost_registry_id='cost-forged',"
            "selected_cost_registry_hash='forged-hash' WHERE run_id='r'"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('forged-cost-row','forged-cost-row-idem',"
            "'forged-cost-row-dedupe',4,'r','t','spawn','provider','model','endpoint',"
            "'capability','cost-forged','effective','forged-hash','known','reserve',1,"
            "'known','test','now',1000)"
        )
        external_metadata = json.dumps(
            {
                "run_id": "r",
                "transition_id": "t",
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "phase": "phase",
                "agent_id": "agent",
                "task_digest": "task",
            }
        )
        for identifier, reserve_id, requested_at_epoch_ms in (
            ("intent-consume", "consume", 1001),
            ("intent-late-reserve", "reserve", 1000),
            ("intent-over-budget", "over-budget", 1001),
            ("intent-forged-cost-row", "forged-cost-row", 1001),
        ):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(
                sqlite3.IntegrityError, "strict prior reserve"
            ):
                connection.execute(
                    "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                    "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                    "idempotency_key,phase,agent_id,task_digest,metadata_contract_version,"
                    "metadata_json,external_metadata_json,external_run_id,"
                    "external_transition_id,external_client_request_id,"
                    "external_idempotency_key,external_phase,external_agent_id,"
                    "external_task_digest,state,external_id,requested_at,"
                    "requested_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'r','t',"
                    "?,?,?,?,?,'accepted','bad-session','now',?)",
                    (
                        identifier,
                        "r",
                        "t",
                        "sessions_spawn",
                        "spawn",
                        reserve_id,
                        "client",
                        "spawn-idem",
                        "phase",
                        "agent",
                        "task",
                        "v1",
                        "{}",
                        external_metadata,
                        "client",
                        "spawn-idem",
                        "phase",
                        "agent",
                        "task",
                        requested_at_epoch_ms,
                    ),
                )
        connection.execute(
            "UPDATE run_budgets SET selected_cost_registry_id='cost-row',"
            "selected_cost_registry_hash='cost-hash' WHERE run_id='r'"
        )
        connection.execute(
            "UPDATE run_budgets SET selected_reserve_transition_id='t-other' "
            "WHERE run_id='r'"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "strict prior reserve"):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
                "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_transition_id,"
                "external_client_request_id,external_idempotency_key,external_phase,"
                "external_agent_id,external_task_digest,state,external_id,requested_at,"
                "requested_at_epoch_ms) VALUES('intent-selected-drift','r','t',"
                "'sessions_spawn','spawn','reserve','client','spawn-idem','phase',"
                "'agent','task','v1','{}',?,'r','t','client','spawn-idem','phase',"
                "'agent','task','accepted','bad-session','now',1001)",
                (external_metadata,),
            )
        connection.execute(
            "UPDATE run_budgets SET selected_reserve_transition_id='t' WHERE run_id='r'"
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "client_request_id,idempotency_key,metadata_json,state,requested_at,"
            "requested_at_epoch_ms) "
            "VALUES('intent-update-selected-drift','r','t','allow_lease_acquire',"
            "'client-update','spawn-idem-update','{}','pending','now',1001)"
        )
        connection.execute(
            "UPDATE run_budgets SET selected_reserve_transition_id='t-other' "
            "WHERE run_id='r'"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "strict prior reserve"):
            connection.execute(
                "UPDATE external_rpc_intents SET rpc_kind='sessions_spawn',"
                "spawn_request_id='spawn',reserve_budget_event_id='reserve',"
                "client_request_id='client',idempotency_key='spawn-idem',"
                "phase='phase',agent_id='agent',task_digest='task' "
                "WHERE intent_id='intent-update-selected-drift'"
            )
        connection.execute(
            "UPDATE run_budgets SET selected_reserve_transition_id='t' WHERE run_id='r'"
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms) VALUES('intent','r','t','sessions_spawn','spawn',"
            "'reserve','client','spawn-idem','phase','agent','task','v1','{}',?,"
            "'r','t','client','spawn-idem','phase','agent','task','accepted',"
            "'accepted-session','now',1001)",
            (external_metadata,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "reserve/release"):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,input_tokens,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('release-after-intent',"
                "'release-after-intent-idem','release-after-intent-dedupe',5,'r','t',"
                "'spawn','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','release',1,'known','test','now',1002)"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "budget row is immutable"):
            connection.execute("DELETE FROM run_budgets WHERE run_id='r'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "budget row is immutable"):
            connection.execute("UPDATE run_budgets SET run_id='other' WHERE run_id='r'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "ledger-backed"):
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=0 WHERE run_id='r'"
            )
        self.assertEqual(
            connection.execute(
                "SELECT reserved_input_tokens FROM run_budgets WHERE run_id='r'"
            ).fetchone(),
            (1,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "selection is immutable"):
            connection.execute(
                "UPDATE run_budgets SET input_token_budget=0 WHERE run_id='r'"
            )
        for assignment in ("input_tokens=2", "event_sequence=99"):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable"
            ):
                connection.execute(
                    f"UPDATE budget_events SET {assignment} "
                    "WHERE budget_event_id='reserve'"
                )
        connection.execute(
            "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,phase,"
            "agent_id,client_request_id,spawn_idempotency_key,session_key,task_digest,state) "
            "VALUES('session-good','spawn','r','t','phase','agent','client','spawn-idem',"
            "'accepted-session','task','running')"
        )
        connection.execute(
            "UPDATE spawn_requests SET state='accepted' WHERE spawn_request_id='spawn'"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "session proof"):
            connection.execute(
                "UPDATE sessions SET session_key='other-session' "
                "WHERE session_id='session-good'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "session proof"):
            connection.execute("DELETE FROM sessions WHERE session_id='session-good'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "external intent proof"):
            connection.execute(
                "UPDATE external_rpc_intents SET external_id='other-session' "
                "WHERE intent_id='intent'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "external intent proof"):
            connection.execute("DELETE FROM external_rpc_intents WHERE intent_id='intent'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "accepted spawn request"):
            connection.execute(
                "UPDATE spawn_requests SET session_key='other-session' "
                "WHERE spawn_request_id='spawn'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "state is immutable"):
            connection.execute(
                "UPDATE spawn_requests SET state='pending' WHERE spawn_request_id='spawn'"
            )
        connection.execute("UPDATE spawn_requests SET state='completed' WHERE spawn_request_id='spawn'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "state is immutable"):
            connection.execute(
                "UPDATE spawn_requests SET state='accepted' WHERE spawn_request_id='spawn'"
            )

    def test_v4_preserves_accepted_post_dispatch_events_before_counter_rewrite(self) -> None:
        self._apply_migrations_through(4, "through-v4")
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        external_metadata = (
            '{"run_id":"v4-run","transition_id":"v4-transition",'
            '"client_request_id":"v4-client","idempotency_key":"v4-spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        with connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('w','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,"
                "registry_row_hash) VALUES('cost-row','provider','model','endpoint',"
                "'capability',1,1,'known','effective','cost-hash')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('v4-run','prepare-v4','w','file_authority','child_completed',"
                "'R1','R1','now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('v4-transition','v4-run',"
                "'before','after','budget','consume','R1','idem-v4',0,'now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('v4-other-transition','v4-run',"
                "'before','after','budget','consume','R1','idem-v4-other',0,'now')"
            )
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,"
                "state,session_key,created_at,updated_at) VALUES('v4-spawn','v4-run',"
                "'phase','agent','v4-transition','v4-client','v4-spawn-idem','task',"
                "'pending','session-key','now','now')"
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,"
                "selected_provider,selected_model,selected_endpoint_binding_id,"
                "selected_cost_registry_id,selected_cost_effective_at,"
                "selected_cost_registry_hash,selected_cost_confidence,"
                "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
                "output_token_budget,cost_budget_microusd,retry_budget,"
                "human_attention_budget,reserved_input_tokens,reserved_cost_microusd,"
                "consumed_input_tokens,consumed_cost_microusd,usage_confidence,updated_at) "
                "VALUES('v4-run','w','capability','provider','model','endpoint',"
                "'cost-row','effective','cost-hash','known','v4-transition',10,10,"
                "10,10,1,1,1,1,0,0,'known','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,input_tokens,cost_microusd,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES('v4-reserve','idem-v4-reserve',"
                "'dedupe-v4-reserve',1,'v4-run','v4-transition','v4-spawn',"
                "'provider','model','endpoint','capability','cost-row','effective',"
                "'cost-hash','known','reserve',1,1,'known','test','now',800)"
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_contract_version,"
                "metadata_json,external_metadata_json,external_run_id,"
                "external_transition_id,external_client_request_id,"
                "external_idempotency_key,external_phase,external_agent_id,"
                "external_task_digest,state,external_id,requested_at,"
                "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
                "'intent-v4','v4-run','v4-transition','sessions_spawn','v4-spawn',"
                "'v4-reserve','v4-client','v4-spawn-idem','phase','agent','task',"
                "'v1',?,?,'v4-run','v4-transition','v4-client','v4-spawn-idem',"
                "'phase','agent','task','accepted','session-key','now',900,'now',1000)",
                (external_metadata, external_metadata),
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,"
                "transition_id,phase,agent_id,client_request_id,"
                "spawn_idempotency_key,session_key,task_digest,state) VALUES("
                "'v4-session','v4-spawn','v4-run','v4-transition','phase','agent',"
                "'v4-client','v4-spawn-idem','session-key','task','running')"
            )
            connection.execute(
                "UPDATE spawn_requests SET state='accepted' "
                "WHERE spawn_request_id='v4-spawn'"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,input_tokens,cost_microusd,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES('v4-consume','idem-v4-consume',"
                "'dedupe-v4-consume',2,'v4-run','v4-transition','v4-spawn',"
                "'provider','model','endpoint','capability','cost-row','effective',"
                "'cost-hash','known','consume',1,1,'known','test','now',1100)"
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=0,"
                "reserved_cost_microusd=0,consumed_input_tokens=1,"
                "consumed_cost_microusd=1 WHERE run_id='v4-run'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with connection:
                connection.execute(
                    "UPDATE budget_events SET source='repair' "
                    "WHERE budget_event_id='v4-consume'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with connection:
                connection.execute(
                    "UPDATE budget_events SET event_idempotency_key='rewritten-v4-key' "
                    "WHERE budget_event_id='v4-consume'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with connection:
                connection.execute(
                    "UPDATE budget_events SET event_dedupe_hash='rewritten-v4-hash' "
                    "WHERE budget_event_id='v4-consume'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with connection:
                connection.execute(
                    "DELETE FROM budget_events WHERE budget_event_id='v4-consume'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "selection is immutable"):
            with connection:
                connection.execute(
                    "UPDATE run_budgets "
                    "SET selected_reserve_transition_id='v4-other-transition' "
                    "WHERE run_id='v4-run'"
                )

    def test_spawn_request_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','dispatch','spawn','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES("
                "'spawn','run-a','phase','agent','transition-run-b','client','spawn-idem',"
                "'task','pending','now','now')"
            )

    def test_lease_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','lease','acquire','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,ttl_ms,"
                "expires_at,expires_at_epoch_ms) VALUES("
                "'lease','run-a','phase','transition-run-b','agent','requester',"
                "'acquire_pending','client','lease-idem',60000,'expires',2000000000000)"
            )

    def test_external_intent_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','lease','acquire','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_json,state,requested_at,"
                "requested_at_epoch_ms) VALUES("
                "'intent','run-a','transition-run-b','allow_lease_acquire','client',"
                "'idem','{}','pending','now',1000)"
            )

    def test_external_intent_rpc_identity_must_be_non_empty(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','lease','acquire','R1','transition-idem',"
            "0,'now')"
        )
        for intent_id, client_request_id, idempotency_key in (
            ("empty-client", "", "idem"),
            ("empty-idempotency", "client", ""),
        ):
            with self.subTest(intent_id=intent_id), self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                    "rpc_kind,client_request_id,idempotency_key,metadata_json,state,"
                    "requested_at,requested_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        intent_id,
                        "run",
                        "transition",
                        "allow_lease_acquire",
                        client_request_id,
                        idempotency_key,
                        "{}",
                        "pending",
                        "now",
                        1000,
                    ),
                )

    def test_accepted_allow_lease_acquire_requires_exact_metadata(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','lease','acquire','R1','transition-idem',"
            "0,'now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_json,state,external_id,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'missing','run','transition','allow_lease_acquire','client','idem',"
                "'{}','accepted','gateway','now',1000)"
            )
        bad_metadata = json.dumps(
            {
                "run_id": "other",
                "transition_id": "transition",
                "client_lease_id": "client-bad",
                "idempotency_key": "idem-bad",
                "gateway_lease_id": "gateway-bad",
            }
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_transition_id,"
                "external_client_request_id,external_idempotency_key,state,external_id,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'bad','run','transition','allow_lease_acquire','client-bad','idem-bad',"
                "'v1','{}',?,'run','transition','client-bad','idem-bad','accepted',"
                "'gateway-bad','now',1000)",
                (bad_metadata,),
            )
        partial_metadata = json.dumps(
            {
                "run_id": "run",
                "transition_id": "transition",
                "client_request_id": "client-partial",
                "idempotency_key": "idem-partial",
                "gateway_lease_id": "gateway-partial",
            }
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_transition_id,"
                "external_client_request_id,external_idempotency_key,state,external_id,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'partial','run','transition','allow_lease_acquire','client-partial',"
                "'idem-partial','v1','{}',?,'run','transition','client-partial',"
                "'idem-partial','accepted','gateway-partial','now',1000)",
                (partial_metadata,),
            )
        metadata = json.dumps(
            {
                "client_lease_id": "client-ok",
                "idempotency_key": "idem-ok",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "gateway-ok",
            }
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "phase,agent_id,requester_agent_id,ttl_ms,client_request_id,idempotency_key,"
            "metadata_contract_version,metadata_json,external_metadata_json,"
            "external_run_id,external_phase,external_transition_id,external_agent_id,"
            "external_requester_agent_id,external_ttl_ms,external_client_request_id,"
            "external_idempotency_key,state,"
            "external_id,requested_at,requested_at_epoch_ms) VALUES("
            "'ok','run','transition','allow_lease_acquire','phase','agent','requester',"
            "60000,'client-ok','idem-ok','v1','{}',?,'run','phase','transition','agent',"
            "'requester',60000,'client-ok','idem-ok','accepted','gateway-ok','now',1000)",
            (metadata,),
        )

    def test_budget_event_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','budget','reserve','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,capability_class,"
                "event_type,human_attention_units,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES("
                "'event','event-idem','event-dedupe',1,'run-a','transition-run-b',"
                "'capability','human_attention',1,'known','test','now',1000)"
            )

    def test_pass_gate_requires_same_run_transition_and_verifier_evidence(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','gate','check','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier-b','run-b','worker','verifier','provider','model','prompt','context',"
            "'evidence-b','independent','{\"reviewer_session\":\"fixture-b\"}','now')"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier-a','run-a','worker','verifier','provider','model','prompt','context',"
            "'evidence-a','independent','{\"reviewer_session\":\"fixture-a\"}','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('gate-verifier','run-a','transition-run-a','clock-verifier',"
                "'verifier-b','pass','now',1000,'v1','query','migration','evidence-b','R1','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "decision,completed_at,completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,risk_dominance,created_at) VALUES("
                "'gate-transition','run-a','transition-run-b','clock-transition','fail','now',"
                "1000,'v1','query','migration','R1','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('pass-bad-risk','run-a','transition-run-a','clock-pass-bad-risk',"
                "'verifier-a','pass','now',1000,'v1','query','migration','evidence-a',"
                "'NOT_A_RISK','now')"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "risk dominance"):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('pass-low-risk','run-a','transition-run-a','clock-pass-low-risk',"
                "'verifier-a','pass','now',1000,'v1','query','migration','evidence-a',"
                "'R2','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "decision,completed_at,completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,risk_dominance,created_at) VALUES("
                "'gate-bad-risk','run-a','transition-run-a','clock-bad-risk','fail','now',"
                "1000,'v1','query','migration','NOT_A_RISK','now')"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "risk dominance"):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "decision,completed_at,completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,risk_dominance,created_at) VALUES("
                "'gate-low-risk','run-a','transition-run-a','clock-low-risk','fail','now',"
                "1000,'v1','query','migration','R2','now')"
            )

    def test_verifier_independence_proof_must_be_valid_json_object(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        for suffix, proof in (
            ("empty", ""),
            ("invalid", "not-json"),
            ("array", "[]"),
            ("empty-object", "{}"),
            ("empty-spaced-object", "{ }"),
        ):
            with self.subTest(proof=suffix), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                    "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
                    "context_hash,evidence_hash,independence_class,"
                    "independence_proof_json,completed_at) VALUES(?,?,?,?,"
                    "'provider','model',?,?,?,'independent',?,'now')",
                    (
                        f"verifier-{suffix}",
                        "run",
                        "worker",
                        "verifier",
                        f"prompt-{suffix}",
                        f"context-{suffix}",
                        f"evidence-{suffix}",
                        proof,
                    ),
                )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
            "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
            "context_hash,evidence_hash,independence_class,independence_proof_json,"
            "completed_at) VALUES('verifier-valid','run','worker','verifier',"
            "'provider','model','prompt','context','evidence','independent',"
            "'{\"reviewer_session\":\"session-a\"}','now')"
        )

    def test_pass_gate_requires_gate_bound_evidence_row(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','gate','check','R1','transition-idem',"
            "0,'now')"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier','run','worker','verifier','provider','model','prompt','context',"
            "'evidence','independent','{\"reviewer_session\":\"fixture\"}','now')"
        )
        connection.commit()
        connection.execute("BEGIN")
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES('gate','run','transition','clock','verifier','pass','now',1000,"
            "'v1','query','migration','evidence','R1','now')"
        )
        connection.execute(
            "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
            "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
            "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
            "VALUES('clock','gate','gate','run','transition','nonce',1000,1000,"
            "'clock','source',1000)"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.commit()
        connection.rollback()

    def test_gate_clock_and_evidence_hash_must_match_exactly(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','gate','check','R1','transition-idem',"
            "0,'now')"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier','run','worker','verifier','provider','model','prompt','context',"
            "'evidence-good','independent','{\"reviewer_session\":\"fixture-good\"}','now')"
        )
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES('gate','run','transition','clock','verifier','pass','now',1000,"
            "'v1','query','migration','evidence-good','R1','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "clock context"):
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
                "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
                "VALUES('clock','gate','gate','run','transition','nonce',999,999,"
                "'clock','source',999)"
            )
        connection.execute(
            "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
            "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
            "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
            "VALUES('clock','gate','gate','run','transition','nonce',1000,1000,"
            "'clock','source',1000)"
        )
        for statement in (
            "UPDATE gate_runs SET completed_at_epoch_ms=1001 WHERE gate_run_id='gate'",
            "UPDATE gate_runs SET decision='fail' WHERE gate_run_id='gate'",
            "DELETE FROM gate_runs WHERE gate_run_id='gate'",
        ):
            with self.subTest(statement=statement), self.assertRaisesRegex(
                sqlite3.IntegrityError, "pass gate is immutable"
            ):
                connection.execute(statement)
        for statement in (
            "UPDATE transitions SET action_type='rewrite' WHERE transition_id='transition'",
            "DELETE FROM transitions WHERE transition_id='transition'",
        ):
            with self.subTest(statement=statement), self.assertRaisesRegex(
                sqlite3.IntegrityError, "pass-gated transition is immutable"
            ):
                connection.execute(statement)
        for assignment in (
            "gate_nonce='nonce-rewritten'",
            "trusted_clock_source_hash='source-rewritten'",
        ):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable"
            ):
                connection.execute(
                    f"UPDATE gate_clock_context SET {assignment} "
                    "WHERE clock_context_id='clock'"
                )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,size_bytes,"
                "content_type,redaction_status,producer_run_id,verifier_run_id,gate_run_id,"
                "captured_at) VALUES('other','run','other.json','sha',1,'application/json',"
                "'none','run','verifier','gate','now')"
            )
        connection.execute(
            "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,size_bytes,"
            "content_type,redaction_status,producer_run_id,verifier_run_id,gate_run_id,"
            "captured_at) VALUES('evidence-good','run','evidence.json','sha-good',1,"
            "'application/json','none','run','verifier','gate','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE evidence_hashes SET sha256='sha-rewritten' "
                "WHERE evidence_hash='evidence-good'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "DELETE FROM evidence_hashes WHERE evidence_hash='evidence-good'"
            )

    def test_gate_evidence_slo_requires_claimed_evidence_hash(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','gate','check','R1','transition-idem',"
            "0,'now')"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier','run','worker','verifier','provider','model','prompt','context',"
            "'claimed','independent','{\"reviewer_session\":\"fixture-claimed\"}','now')"
        )
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES('gate','run','transition','clock','verifier','pass','now',1000,"
            "'v1','query','migration','claimed','R1','now')"
        )
        connection.execute(
            "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,size_bytes,"
            "content_type,redaction_status,producer_run_id,verifier_run_id,gate_run_id,"
            "captured_at) VALUES('other','run','other.json','sha-other',1,"
            "'application/json','none','run','verifier','gate','now')"
        )
        query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Gate evidence bound to same run"
        )
        self.assertEqual(connection.execute(query).fetchall(), [("gate",)])

    def test_risk_assessment_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','risk','assess','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO risk_assessments(assessment_id,run_id,transition_id,"
                "action_risk,target_risk,data_risk,side_effect_risk,permission_risk,"
                "irreversibility_risk,risk_dominance,assessed_at) VALUES("
                "'assessment','run-a','transition-run-b','R1','R1','R1','R1','R1','R1',"
                "'R1','now')"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "risk assessment"):
            connection.execute(
                "INSERT INTO risk_assessments(assessment_id,run_id,transition_id,"
                "action_risk,target_risk,data_risk,side_effect_risk,permission_risk,"
                "irreversibility_risk,risk_dominance,assessed_at) VALUES("
                "'high-assessment','run-a','transition-run-a','R4','R4','R4','R4',"
                "'R4','R4','R4','now')"
            )
        connection.execute(
            "INSERT INTO risk_assessments(assessment_id,run_id,transition_id,"
            "action_risk,target_risk,data_risk,side_effect_risk,permission_risk,"
            "irreversibility_risk,risk_dominance,assessed_at) VALUES("
            "'matched-assessment','run-a','transition-run-a','R1','R1','R1','R1',"
            "'R1','R1','R1','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "transition risk"):
            connection.execute(
                "UPDATE transitions SET risk_dominance='R2' "
                "WHERE transition_id='transition-run-a'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "run risk dominance"):
            connection.execute(
                "UPDATE runs SET risk_dominance='R2' WHERE run_id='run-a'"
            )

    def test_predicate_backend_is_allowlisted(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
                "schema_hash,sandbox_required,sandbox_enforced,created_at) "
                "VALUES('plugin','unsafe','1','shell','schema',0,0,'now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
                "schema_hash,sandbox_required,sandbox_enforced,created_at) "
                "VALUES('sandbox-missing','unsafe','1','agentic_predicate_inproc_v1',"
                "'schema',1,0,'now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
                "schema_hash,sandbox_required,sandbox_enforced,sensitive,created_at) "
                "VALUES('sensitive-unapproved','unsafe','1','agentic_predicate_inproc_v1',"
                "'schema',0,1,1,'now')"
            )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'safe-plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,sensitive,approved_at,created_at) "
            "VALUES('approved-sensitive','safe','1','agentic_predicate_inproc_v1','schema',"
            "0,1,1,'approved','now')"
        )

    def test_goal_run_predicate_must_match_manifest(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        for plugin in ("manifest-plugin", "other-plugin"):
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
                "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES(?,?,"
                "'1','agentic_predicate_inproc_v1','schema',0,1,'now')",
                (plugin, plugin),
            )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('goal','owner','R1','manifest','manifest-plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,created_at,"
                "created_at_epoch_ms) VALUES("
                "'goal-run','goal','R1','open','other-plugin',"
                "'agentic_predicate_inproc_v1',1,'now',1000)"
            )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'sandbox-plugin','sandboxed','1','agentic_predicate_inproc_v1','schema',1,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('sandbox-goal','owner','R1','manifest-sandbox','sandbox-plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        for goal_run_id, enforced, proof in (
            ("sandbox-not-enforced", 0, None),
            ("sandbox-no-proof", 1, None),
        ):
            with self.subTest(goal_run_id=goal_run_id), self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
                    "predicate_plugin_hash,backend,sandbox_enforced,sandbox_proof_hash,"
                    "created_at,created_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        goal_run_id,
                        "sandbox-goal",
                        "R1",
                        "open",
                        "sandbox-plugin",
                        "agentic_predicate_inproc_v1",
                        enforced,
                        proof,
                        "now",
                        1000,
                    ),
                )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,sandbox_proof_hash,created_at,"
            "created_at_epoch_ms) "
            "VALUES('sandbox-ok','sandbox-goal','R1','open','sandbox-plugin',"
            "'agentic_predicate_inproc_v1',1,'sandbox-proof','now',1000)"
        )
        for assignment in (
            "enabled=0",
            "severity='R2'",
        ):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "referenced goal runs|goal manifest identity"
            ):
                connection.execute(
                    f"UPDATE goal_manifests SET {assignment} WHERE goal_id='sandbox-goal'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "referenced predicate plugin"):
            connection.execute(
                "UPDATE predicate_plugins SET disabled_at='now' "
                "WHERE predicate_plugin_hash='sandbox-plugin'"
            )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,disabled_at,created_at) "
            "VALUES('disabled-plugin','disabled','1','agentic_predicate_inproc_v1',"
            "'schema',0,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('disabled-plugin-goal','owner','R1','manifest-disabled-plugin',"
            "'disabled-plugin','agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "enabled manifest"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,created_at,"
                "created_at_epoch_ms) VALUES('disabled-plugin-run','disabled-plugin-goal',"
                "'R1','open','disabled-plugin','agentic_predicate_inproc_v1',1,'now',1000)"
            )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('disabled-goal','owner','R1','manifest-disabled','manifest-plugin',"
            "'agentic_predicate_inproc_v1',0,0,'now','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "enabled manifest"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,created_at,"
                "created_at_epoch_ms) VALUES('disabled-goal-run','disabled-goal',"
                "'R1','open','manifest-plugin','agentic_predicate_inproc_v1',1,'now',1000)"
            )

    def test_approval_required_goal_run_requires_exact_approval(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('goal','owner','R1','manifest','plugin','agentic_predicate_inproc_v1',"
            "1,1,'now','now')"
        )
        source_digest = hashlib.sha256(b"goal-source").hexdigest()
        text_digest = hashlib.sha256(b"goal-text").hexdigest()
        approval_hash = hashlib.sha256(b"goal-approval").hexdigest()
        far_future_epoch_ms = 253402300799999
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,created_at,"
                "created_at_epoch_ms) VALUES("
                "'missing-approval','goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'now',1000)"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
                "created_at_epoch_ms) "
                "VALUES('fake-approval','goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'missing','now',1000)"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                "source_message_digest,approval_text_digest,approved_action_type,"
                "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
                "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
                "consumed_by_gate_run_id,consumed_by_goal_run_id,approved_at) "
                "VALUES('double-consume','run','river','telegram','source-double',"
                "'text-double','goal_run','goal','goal','manifest','owner','R1',"
                "2000,'double-consume-hash','transition','gate','goal-run','now')"
            )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('wrong-approval','run','river','telegram','source-wrong',"
            "'text-wrong','other_action','goal','other-goal','manifest','owner','R1',"
            "2000,'wrong-approval-hash','wrong-approved','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
                "created_at_epoch_ms) "
                "VALUES('wrong-approved','goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'wrong-approval','now',1000)"
            )
        connection.execute("DELETE FROM approvals WHERE approval_id='wrong-approval'")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('expired-approval','run',"
            "'river','telegram',?,?,'goal_run','goal','goal','manifest','owner',"
            "'R1',1000,?,'expired','now')",
            (
                hashlib.sha256(b"expired-source").hexdigest(),
                hashlib.sha256(b"expired-text").hexdigest(),
                hashlib.sha256(b"expired-approval").hexdigest(),
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "unexpired"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
                "created_at_epoch_ms) "
                "VALUES('expired','goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'expired-approval','backdated',1)"
            )
        connection.execute("DELETE FROM approvals WHERE approval_id='expired-approval'")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('malformed-approval','run',"
            "'river','telegram','x','y','goal_run','goal','goal','manifest',"
            "'owner','R1',?,'not-a-sha','malformed','now')",
            (far_future_epoch_ms,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "SHA-256"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
                "created_at_epoch_ms) "
                "VALUES('malformed','goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'malformed-approval','now',1000)"
            )
        connection.execute("DELETE FROM approvals WHERE approval_id='malformed-approval'")
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('approval','run',"
            "'river','telegram',?,?,'goal_run','goal','goal','manifest',"
            "'owner','R1',?,?, 'approved','now')",
            (source_digest, text_digest, far_future_epoch_ms, approval_hash),
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
            "created_at_epoch_ms) "
            "VALUES('approved','goal','run','R1','open','plugin',"
            "'agentic_predicate_inproc_v1',1,'approval','now',1000)"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "UPDATE goal_runs SET approval_id=NULL WHERE goal_run_id='approved'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "enabled manifest"):
            connection.execute(
                "UPDATE goal_runs SET severity='R2' WHERE goal_run_id='approved'"
            )
        for assignment in (
            "severity='R2'",
            "manifest_hash='new-manifest'",
            "owner='new-owner'",
        ):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "referenced goal runs|current SHA-256|goal manifest identity"
            ):
                connection.execute(
                    f"UPDATE goal_manifests SET {assignment} WHERE goal_id='goal'"
                )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,updated_at) "
            "VALUES('late-approval-goal','owner','R1','late-manifest','plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,created_at,created_at_epoch_ms) "
            "VALUES('late-approval-run','late-approval-goal','run','R1','open','plugin',"
            "'agentic_predicate_inproc_v1',1,'now',1000)"
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "referenced goal runs|current SHA-256|goal manifest identity"
        ):
            connection.execute(
                "UPDATE goal_manifests SET approval_required=1 "
                "WHERE goal_id='late-approval-goal'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "UPDATE approvals SET expires_at_epoch_ms=1999 "
                "WHERE approval_id='approval'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute("DELETE FROM approvals WHERE approval_id='approval'")

    def test_goal_run_evidence_requires_same_run_independent_pass_gate(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('forged','goal','run','R1',"
                "'open','plugin','agentic_predicate_inproc_v1',1,?,"
                "'now',1000)",
                (hashlib.sha256(b"forged").hexdigest(),),
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('wrong-run','goal','other-run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,"
                "'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('bound','goal','run','R1',"
            "'open','plugin','agentic_predicate_inproc_v1',1,?,"
            "'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE goal_runs SET evidence_hash=? WHERE goal_run_id='bound'",
                (hashlib.sha256(b"other").hexdigest(),),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE goal_runs SET run_id='other-run' WHERE goal_run_id='bound'"
            )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('other-goal','owner','R1','other-manifest','plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE goal_runs SET goal_id='other-goal' WHERE goal_run_id='bound'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
            connection.execute("DELETE FROM goal_runs WHERE goal_run_id='bound'")

    def test_goal_run_evidence_migration_rejects_invalid_legacy_rows(self) -> None:
        self._apply_migrations_through(11, "through-11")
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('goal','owner','R1','manifest','plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('legacy-forged','goal','R1',"
            "'open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
            (hashlib.sha256(b"forged").hexdigest(),),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "goal_run_evidence_binding_legacy_invalid"
        ):
            apply_migrations(self.database)

    def test_goal_run_required_approval_migration_rejects_invalid_legacy_rows(
        self,
    ) -> None:
        self._apply_migrations_through(11, "through-11")
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES('run',"
            "'prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('goal','owner','R1','manifest','plugin',"
            "'agentic_predicate_inproc_v1',1,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('legacy-approval','run','river','telegram','x','y','goal_run',"
            "'goal','goal','manifest','owner','R1',1000,'not-a-sha',"
            "'legacy-required','now')"
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
            "created_at_epoch_ms) VALUES('legacy-required','goal','run','R1','open',"
            "'plugin','agentic_predicate_inproc_v1',1,'legacy-approval','backdated',1)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "goal_run_required_approval_legacy_invalid"
        ):
            apply_migrations(self.database)

    def test_goal_run_evidence_requires_artifact_digest_match(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            evidence_sha256=hashlib.sha256(b"different-artifact").hexdigest(),
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('digest-mismatch','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_requires_sha256_shape(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            evidence_hash="not-a-sha",
            evidence_sha256="not-a-sha",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('malformed-sha','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,"
                "'not-a-sha','now',1000)"
            )

    def test_goal_run_evidence_rejects_database_authority_gate_snapshot(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            authority_mode="db_authority_canary",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('db-authority','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_rejects_malformed_gate_authority_snapshot(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "authority snapshot"
        ):
            self._seed_goal_run_evidence_binding_fixture(
                connection,
                gate_run_authority_mode="restored-file-later",
                gate_workflow_authority_mode="file_authority",
            )

    def test_goal_run_evidence_rejects_spoofed_file_authority_snapshot(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "authority snapshot"
        ):
            self._seed_goal_run_evidence_binding_fixture(
                connection,
                authority_mode="db_authority_canary",
                gate_run_authority_mode="file_authority",
                gate_workflow_authority_mode="file_authority",
            )

    def test_goal_run_evidence_rejects_self_verifier_run_id(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            verifier_run_id="run",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('self-verifier-goal','goal',"
                "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,"
                "'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_requires_current_gate_identity(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            gate_query_hash=hashlib.sha256(b"stale-gate-query").hexdigest(),
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('stale-gate-identity','goal',"
                "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,"
                "'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_requires_complete_metadata(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            evidence_content_type="",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('incomplete-evidence','goal',"
                "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,"
                "'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_rejects_cutover_after_gate_snapshot(
        self,
    ) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "UPDATE runs SET state='finalized',finalized_at='now',"
            "finalized_at_epoch_ms=1001 WHERE run_id IN ('run','other-run')"
        )
        connection.execute(
            "UPDATE workflow_authority SET mode='db_authority_canary',"
            "cutover_approved_by='river',cutover_evidence_hash=?,"
            "rollback_deadline='deadline',last_parity_audit_hash=?,"
            "open_file_authority_runs=0 WHERE workflow='w'",
            (
                hashlib.sha256(b"cutover").hexdigest(),
                hashlib.sha256(b"parity").hexdigest(),
            ),
        )
        connection.execute(
            "UPDATE runs SET authority_mode='db_authority_canary' "
            "WHERE run_id='run'"
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('after-cutover','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_migration_rejects_finalized_snapshot_mismatch(
        self,
    ) -> None:
        self._apply_migrations_through(11, "through-11")
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "UPDATE runs SET state='finalized',finalized_at='now',"
            "finalized_at_epoch_ms=1001 WHERE run_id IN ('run','other-run')"
        )
        connection.execute(
            "UPDATE workflow_authority SET mode='db_authority_canary',"
            "cutover_approved_by='river',cutover_evidence_hash=?,"
            "rollback_deadline='deadline',last_parity_audit_hash=?,"
            "open_file_authority_runs=0 WHERE workflow='w'",
            (
                hashlib.sha256(b"cutover").hexdigest(),
                hashlib.sha256(b"parity").hexdigest(),
            ),
        )
        connection.execute(
            "UPDATE runs SET authority_mode='db_authority_canary' "
            "WHERE run_id='run'"
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('legacy-after-cutover','goal',"
            "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,"
            "'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "gate_authority_snapshot_invalid"
        ):
            apply_migrations(self.database)

    def test_goal_run_evidence_requires_derived_trusted_gate_clock(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            trusted_clock_source_hash="a" * 64,
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('forged-clock','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )

    def test_goal_run_evidence_requires_exact_unexpired_transition_approval(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(
            connection,
            transition_approval_required=False,
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "same-run independent pass-gate evidence"
        ):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
                "created_at,created_at_epoch_ms) VALUES('approval-bypass','goal','run',"
                "'R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
                (hashlib.sha256(b"pass-evidence").hexdigest(),),
            )
        migration_sql = (
            repository_root() / "migrations/0012_goal_run_evidence_binding.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("a.expires_at_epoch_ms > c.now_epoch_ms", migration_sql)
        self.assertNotIn("strftime('%s','now')", migration_sql)

    def test_goal_run_evidence_freezes_transition_approval_digest_after_binding(
        self,
    ) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('bound-approval-freeze','goal',"
            "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "UPDATE approvals SET approval_hash=? WHERE approval_id='approval'",
                (hashlib.sha256(b"rewritten-approval").hexdigest(),),
            )
        for assignment in ("approver=''", "approved_at=''"):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "approval"
            ):
                connection.execute(
                    f"UPDATE approvals SET {assignment} WHERE approval_id='approval'"
                )

    def test_goal_run_evidence_freezes_gate_clock_signer_after_binding(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('bound-clock-freeze','goal',"
            "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "clock signer"):
            connection.execute(
                "UPDATE gate_clock_context SET bound_by='other' "
                "WHERE clock_context_id='clock'"
            )

    def test_goal_run_evidence_freezes_verifier_proof_after_binding(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('bound-verifier-freeze','goal',"
            "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "verifier proof"):
            connection.execute(
                "UPDATE judge_verifier_runs SET independence_proof_json=? "
                "WHERE verifier_run_id='verifier'",
                ('{"review":"rewritten"}',),
            )
        for assignment in ("model_version='other'", "completed_at='later'"):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "verifier proof"
            ):
                connection.execute(
                    f"UPDATE judge_verifier_runs SET {assignment} "
                    "WHERE verifier_run_id='verifier'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "verifier proof"):
            connection.execute(
                "DELETE FROM judge_verifier_runs WHERE verifier_run_id='verifier'"
            )

    def test_goal_run_evidence_blocks_authority_cutover_after_binding(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self._seed_goal_run_evidence_binding_fixture(connection)
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,evidence_hash,"
            "created_at,created_at_epoch_ms) VALUES('bound-authority-freeze','goal',"
            "'run','R1','open','plugin','agentic_predicate_inproc_v1',1,?,'now',1000)",
            (hashlib.sha256(b"pass-evidence").hexdigest(),),
        )
        connection.execute(
            "UPDATE runs SET state='finalized',finalized_at='now',"
            "finalized_at_epoch_ms=1001 WHERE run_id IN ('run','other-run')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "file-authority workflow"):
            connection.execute(
                "UPDATE workflow_authority SET mode='db_authority_canary',"
                "cutover_approved_by='river',cutover_evidence_hash=?,"
                "rollback_deadline='deadline',last_parity_audit_hash=?,"
                "open_file_authority_runs=0 WHERE workflow='w'",
                (
                    hashlib.sha256(b"cutover").hexdigest(),
                    hashlib.sha256(b"parity").hexdigest(),
                ),
            )

    def test_goal_manifest_required_flip_rechecks_current_approval_clock_and_shape(
        self,
    ) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES('run',"
            "'prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('flip-goal','owner','R1','manifest','plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('flip-approval','run','river','telegram',?,?,'goal_run','goal',"
            "'flip-goal','manifest','owner','R1',1000,?,'flip-run','now')",
            (
                hashlib.sha256(b"flip-source").hexdigest(),
                hashlib.sha256(b"flip-text").hexdigest(),
                hashlib.sha256(b"flip-approval").hexdigest(),
            ),
        )
        connection.execute(
            "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
            "predicate_plugin_hash,backend,sandbox_enforced,approval_id,created_at,"
            "created_at_epoch_ms) VALUES('flip-run','flip-goal','run','R1','open',"
            "'plugin','agentic_predicate_inproc_v1',1,'flip-approval','backdated',1)"
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "current SHA-256|goal manifest identity"
        ):
            connection.execute(
                "UPDATE goal_manifests SET approval_required=1 "
                "WHERE goal_id='flip-goal'"
            )

    def test_goal_run_required_approval_rejects_missing_approval_identity(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES('run',"
            "'prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('identity-goal','owner','R1','manifest','plugin',"
            "'agentic_predicate_inproc_v1',1,1,'now','now')"
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_goal_run_id,approved_at) "
            "VALUES('identity-approval','run','','telegram',?,?,'goal_run','goal',"
            "'identity-goal','manifest','owner','R1',253402300799999,?,"
            "'identity-run','now')",
            (
                hashlib.sha256(b"identity-source").hexdigest(),
                hashlib.sha256(b"identity-text").hexdigest(),
                hashlib.sha256(b"identity-approval").hexdigest(),
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "approval"):
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "predicate_plugin_hash,backend,sandbox_enforced,approval_id,"
                "created_at,created_at_epoch_ms) VALUES('identity-run',"
                "'identity-goal','run','R1','open','plugin',"
                "'agentic_predicate_inproc_v1',1,'identity-approval','now',1000)"
            )

    def _seed_goal_run_evidence_binding_fixture(
        self,
        connection: sqlite3.Connection,
        *,
        authority_mode: str = "file_authority",
        gate_run_authority_mode: str | None = None,
        gate_workflow_authority_mode: str | None = None,
        evidence_hash: str | None = None,
        evidence_sha256: str | None = None,
        transition_approval_required: bool = True,
        approval_expires_at_epoch_ms: int = 2000,
        verifier_run_id: str = "verifier",
        trusted_clock_source_hash: str | None = None,
        gate_query_hash: str | None = None,
        migration_sha256: str | None = None,
        evidence_path: str = "artifacts/evidence.json",
        evidence_content_type: str = "application/json",
        evidence_redaction_status: str = "none",
        evidence_captured_at: str = "now",
    ) -> None:
        _register_migration_functions(connection)
        evidence_hash = evidence_hash or hashlib.sha256(b"pass-evidence").hexdigest()
        gate_run_authority_mode = gate_run_authority_mode or authority_mode
        gate_workflow_authority_mode = gate_workflow_authority_mode or authority_mode
        evidence_sha256 = evidence_sha256 or evidence_hash
        trusted_clock_source_hash = trusted_clock_source_hash or _clock_hash(1000, "writer")
        current_gate_query_hash, current_migration_sha256 = self._current_gate_identity(
            connection
        )
        gate_query_hash = gate_query_hash or current_gate_query_hash
        migration_sha256 = migration_sha256 or current_migration_sha256
        target_hash = hashlib.sha256(b"target").hexdigest()
        source_digest = hashlib.sha256(b"source").hexdigest()
        text_digest = hashlib.sha256(b"text").hexdigest()
        approval_hash = hashlib.sha256(b"approval").hexdigest()
        if authority_mode in ("db_authority_canary", "db_authority"):
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "open_file_authority_runs,updated_at) VALUES('w',?,'river',?,"
                "'deadline',?,0,'now')",
                (
                    authority_mode,
                    hashlib.sha256(b"cutover").hexdigest(),
                    hashlib.sha256(b"parity").hexdigest(),
                ),
            )
        else:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('w',?,'now')",
                (authority_mode,),
            )
        for run_id in ("run", "other-run"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES(?,?, 'w',?,'candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}", authority_mode),
            )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,target_type,target_id,target_hash,"
            "target_scope,risk_dominance,idempotency_key,guard_version_before,"
            "created_at) VALUES('transition','run','prepared','gate_passed','gate',"
            "'mutate','artifact','artifact-1',?,'repo','R1','idem',0,'now')",
            (target_hash,),
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run','river',"
            "'telegram',?,?,'mutate','artifact','artifact-1',?,'repo','R1',"
            "?,?,'transition','gate','now')",
            (
                source_digest,
                text_digest,
                target_hash,
                approval_expires_at_epoch_ms,
                approval_hash,
            ),
        )
        if transition_approval_required:
            connection.execute(
                "UPDATE transitions SET approval_required=1,approval_id='approval',"
                "approval_channel='telegram',approval_source_digest=?,"
                "approval_text_digest=?,gate_run_id='gate',evidence_hash=? "
                "WHERE transition_id='transition'",
                (source_digest, text_digest, evidence_hash),
            )
        else:
            connection.execute(
                "UPDATE transitions SET gate_run_id='gate',evidence_hash=? "
                "WHERE transition_id='transition'",
                (evidence_hash,),
            )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
            "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
            "context_hash,evidence_hash,independence_class,independence_proof_json,"
            "completed_at) VALUES(?,'run','writer','security','openai',"
            "'gpt-5','prompt','context',?,'independent',?, 'now')",
            (verifier_run_id, evidence_hash, '{"review":"independent"}'),
        )
        try:
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,requires_same_run,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,"
                "created_at,run_authority_mode,workflow_authority_mode) "
                "VALUES('gate','run','transition','clock',?,"
                "'pass','now',1000,1,'v1',?,?,?,'R1','now',?,?)",
                (
                    verifier_run_id,
                    gate_query_hash,
                    migration_sha256,
                    evidence_hash,
                    gate_run_authority_mode,
                    gate_workflow_authority_mode,
                ),
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES('clock','gate','gate','run',"
                "'transition','nonce',1000,1000,'writer',?,1000)",
                (trusted_clock_source_hash,),
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES(?, 'run',"
                "?,?,13,?,?,'run',?,'gate',?)",
                (
                    evidence_hash,
                    evidence_path,
                    evidence_sha256,
                    evidence_content_type,
                    evidence_redaction_status,
                    verifier_run_id,
                    evidence_captured_at,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )
        connection.execute(
            "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
            "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
            "updated_at) VALUES('goal','owner','R1','manifest','plugin',"
            "'agentic_predicate_inproc_v1',0,1,'now','now')"
        )

    def _current_gate_identity(
        self, connection: sqlite3.Connection
    ) -> tuple[str, str]:
        row = connection.execute(
            "SELECT q.query_hash,q.migration_sha256 FROM schema_migrations m "
            "JOIN slo_queries q ON q.schema_version=m.version "
            "AND q.migration_sha256=m.sha256 "
            "WHERE q.query_name='Completion gate before done for R2+' "
            "ORDER BY m.version DESC LIMIT 1"
        ).fetchone()
        self.assertIsNotNone(row)
        return str(row[0]), str(row[1])

    def test_verifier_independence_class_is_allowlisted(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,context_hash,"
                "evidence_hash,independence_class,independence_proof_json,completed_at) "
                "VALUES('verifier','run','worker','verifier','provider','model','prompt',"
                "'context','evidence','bogus','{}','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,context_hash,"
                "evidence_hash,independence_class,independence_proof_json,completed_at) "
                "VALUES('self-verifier','run','worker','worker','provider','model',"
                "'prompt','context','evidence-self','independent','{}','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,context_hash,"
                "evidence_hash,independence_class,independence_proof_json,"
                "same_worker_context,completed_at) VALUES('same-context','run','worker',"
                "'verifier','provider','model','prompt','context','evidence-context',"
                "'independent','{}',1,'now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,context_hash,"
                "evidence_hash,independence_class,independence_proof_json,completed_at) "
                "VALUES('same-prompt-context','run','worker','verifier','provider','model',"
                "'same','same','evidence-same','independent','{}','now')"
            )

    def test_zero_reserve_policy_minima_are_enforced_at_sqlite_boundary(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO endpoint_zero_reserve_policies(zero_reserve_policy_id,"
            "endpoint_binding_id,capability_class,policy_hash,min_retry_units,"
            "effective_from_epoch_ms,effective_until_epoch_ms) "
            "VALUES('policy','endpoint','capability','policy-hash',1,1,2000)"
        )

        def insert_event(
            identifier: str, retry_units: int, sequence: int, created_at_epoch_ms: int = 1000
        ) -> None:
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,zero_reserve_policy_id,"
                "zero_reserve_policy_hash,event_type,retry_units,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'run','transition','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','policy','policy-hash','reserve',?,'known',"
                "'test','now',?)",
                (
                    identifier,
                    f"idem-{identifier}",
                    f"dedupe-{identifier}",
                    sequence,
                    retry_units,
                    created_at_epoch_ms,
                ),
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "minima not met"):
            insert_event("bad", 0, 1)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,retry_units,usage_confidence,"
                "source,created_at,created_at_epoch_ms) VALUES('no-policy','idem-no-policy',"
                "'dedupe-no-policy',99,'run','transition','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known','reserve',1,"
                "'known','test','now',1000)"
            )
        insert_event("good", 1, 2)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "mismatch"):
            insert_event("expired-boundary", 1, 3, 2000)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "mismatch"):
            connection.execute(
                "UPDATE budget_events SET created_at_epoch_ms=2000 "
                "WHERE budget_event_id='good'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE endpoint_zero_reserve_policies SET min_retry_units=2 "
                "WHERE zero_reserve_policy_id='policy'"
            )

    def test_budget_slos_count_reserved_plus_consumed_against_budget(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        for run_id in ("counter-run", "ledger-run"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES(?, ?, "
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?, ?, 'before','after',"
                "'budget','reserve','R1', ?, 0,'now')",
                (f"transition-{run_id}", run_id, f"idem-{run_id}"),
            )
        statement = (
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,consumed_input_tokens,usage_confidence,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                statement,
                (
                    "counter-run",
                    "w",
                    "capability",
                    "provider",
                    "model",
                    "endpoint",
                    "cost-row",
                    "effective",
                    "cost-hash",
                    "known",
                    "transition-counter-run",
                    10,
                    10,
                    10,
                    10,
                    1,
                    1,
                    6,
                    5,
                    "known",
                    "now",
                ),
            )
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            statement,
            (
                "counter-run",
                "w",
                "capability",
                "provider",
                "model",
                "endpoint",
                "cost-row",
                "effective",
                "cost-hash",
                "known",
                "transition-counter-run",
                10,
                10,
                10,
                10,
                1,
                1,
                6,
                5,
                "known",
                "now",
            ),
        )
        connection.execute(
            statement,
            (
                "ledger-run",
                "w",
                "capability",
                "provider",
                "model",
                "endpoint",
                "cost-row",
                "effective",
                "cost-hash",
                "known",
                "transition-ledger-run",
                10,
                10,
                10,
                10,
                1,
                1,
                10,
                10,
                "known",
                "now",
            ),
        )
        for event_id, sequence, event_type, amount in (
            ("ledger-reserve-1", 1, "reserve", 10),
            ("ledger-consume", 2, "consume", 10),
            ("ledger-reserve-2", 3, "reserve", 10),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'ledger-run','transition-ledger-run','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known',?,?,'known',"
                "'test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    event_type,
                    amount,
                    1000 + sequence,
                ),
            )
        connection.execute("PRAGMA ignore_check_constraints=OFF")
        counters_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget counters outside selected budget"
        )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        self.assertIn(("counter-run",), connection.execute(counters_query).fetchall())
        self.assertIn(("ledger-run",), connection.execute(ledger_query).fetchall())

    def test_budget_prefix_slo_bounds_retry_consumption_before_restore(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'retry-run','prepare-retry','w','file_authority','candidate','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-retry','retry-run',"
            "'before','after','budget','retry','R1','idem-retry',0,'now')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,consumed_retries,"
            "usage_confidence,updated_at) VALUES('retry-run','w','capability','provider',"
            "'model','endpoint','cost-row','effective','cost-hash','known',"
            "'transition-retry',10,10,10,10,1,1,1,'known','now')"
        )
        connection.execute(
            "INSERT INTO endpoint_zero_reserve_policies("
            "zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,"
            "enabled,min_retry_units,min_time_seconds,min_human_attention_units,"
            "effective_from_epoch_ms,effective_until_epoch_ms) VALUES("
            "'zero-retry','endpoint','capability','zero-hash',1,1,0,0,1,"
            "253402300799999)"
        )
        for event_id, sequence, event_type, retry_units in (
            ("retry-reserve", 1, "reserve", 1),
            ("retry-burst", 2, "retry_decrement", 2),
            ("retry-restore", 3, "retry_restore", 1),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,zero_reserve_policy_id,"
                "zero_reserve_policy_hash,event_type,retry_units,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'retry-run','transition-retry','provider','model','endpoint','capability',"
                "'cost-row','effective','cost-hash','known',?,?,?,?,'known','test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    "zero-retry" if event_type == "reserve" else None,
                    "zero-hash" if event_type == "reserve" else None,
                    event_type,
                    retry_units,
                    1000 + sequence,
                ),
            )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(prefix_query).fetchall(), [("retry-burst",)])

    def test_budget_prefix_slo_partitions_retry_consumption_by_spawn(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'retry-scope-run','prepare-retry-scope','w','file_authority','candidate',"
            "'R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-retry-scope',"
            "'retry-scope-run','before','after','budget','retry','R1',"
            "'idem-retry-scope',0,'now')"
        )
        for spawn_id, client_id, idem in (
            ("spawn-a", "client-a", "spawn-idem-a"),
            ("spawn-b", "client-b", "spawn-idem-b"),
        ):
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES(?,'retry-scope-run','phase','agent',"
                "'transition-retry-scope',?,?,'task','pending','now','now')",
                (spawn_id, client_id, idem),
            )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_retries,consumed_retries,usage_confidence,updated_at) "
            "VALUES('retry-scope-run','w','capability','provider','model','endpoint',"
            "'cost-row','effective','cost-hash','known','transition-retry-scope',"
            "10,10,10,10,1,1,0,1,'known','now')"
        )
        connection.execute(
            "INSERT INTO endpoint_zero_reserve_policies("
            "zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,"
            "enabled,min_retry_units,min_time_seconds,min_human_attention_units,"
            "effective_from_epoch_ms,effective_until_epoch_ms) VALUES("
            "'zero-retry','endpoint','capability','zero-hash',1,1,0,0,1,"
            "253402300799999)"
        )
        for event_id, sequence, spawn_id, event_type in (
            ("retry-a-reserve", 1, "spawn-a", "reserve"),
            ("retry-b-decrement", 2, "spawn-b", "retry_decrement"),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "zero_reserve_policy_id,zero_reserve_policy_hash,event_type,retry_units,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'retry-scope-run','transition-retry-scope',?,'provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash','known',"
                "?,?,?,1,'known','test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    spawn_id,
                    "zero-retry" if event_type == "reserve" else None,
                    "zero-hash" if event_type == "reserve" else None,
                    event_type,
                    1000 + sequence,
                ),
            )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        current_prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        v4_prefix_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(4)
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(v4_prefix_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_prefix_query).fetchall(),
            [("retry-b-decrement",)],
        )

    def test_budget_prefix_slo_partitions_token_consumption_by_spawn(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'token-scope-run','prepare-token-scope','w','file_authority','candidate',"
            "'R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-token-scope',"
            "'token-scope-run','before','after','budget','consume','R1',"
            "'idem-token-scope',0,'now')"
        )
        for spawn_id, client_id, idem in (
            ("spawn-a", "client-a", "spawn-idem-a"),
            ("spawn-b", "client-b", "spawn-idem-b"),
        ):
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES(?,'token-scope-run','phase','agent',"
                "'transition-token-scope',?,?,'task','pending','now','now')",
                (spawn_id, client_id, idem),
            )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,consumed_input_tokens,"
            "consumed_cost_microusd,usage_confidence,updated_at) VALUES("
            "'token-scope-run','w','capability','provider','model','endpoint',"
            "'cost-row','effective','cost-hash','known','transition-token-scope',"
            "10,10,10,10,1,1,0,0,1,1,'known','now')"
        )
        for event_id, sequence, spawn_id, event_type in (
            ("input-a-reserve", 1, "spawn-a", "reserve"),
            ("input-b-consume", 2, "spawn-b", "consume"),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,input_tokens,cost_microusd,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'token-scope-run','transition-token-scope',?,'provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash','known',"
                "?,1,1,'known','test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    spawn_id,
                    event_type,
                    1000 + sequence,
                ),
            )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        current_prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        v4_prefix_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(4)
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(v4_prefix_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_prefix_query).fetchall(),
            [("input-b-consume",)],
        )

    def test_post_dispatch_budget_slo_requires_accepted_session_proof(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'proof-run','prepare-proof','w','file_authority','child_completed','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-proof','proof-run',"
            "'before','after','budget','consume','R1','idem-proof',0,'now')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','proof-run','phase','agent',"
            "'transition-proof','client','spawn-idem','task','pending','now','now')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,consumed_input_tokens,"
            "consumed_cost_microusd,usage_confidence,updated_at) VALUES("
            "'proof-run','w','capability','provider','model','endpoint','cost-row',"
            "'effective','cost-hash','known','transition-proof',10,10,10,10,1,1,"
            "0,0,1,1,'known','now')"
        )
        for event_id, sequence, event_type in (
            ("proof-reserve", 1, "reserve"),
            ("proof-consume", 2, "consume"),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,input_tokens,cost_microusd,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'proof-run','transition-proof','spawn','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known',?,1,1,"
                "'known','test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    event_type,
                    1000 + sequence,
                ),
            )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        proof_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(prefix_query).fetchall(), [])
        self.assertEqual(connection.execute(proof_query).fetchall(), [("proof-consume",)])

    def test_post_dispatch_budget_slo_requires_accepted_request_order(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'clock-run','prepare-clock','w','file_authority','child_completed','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-clock','clock-run',"
            "'before','after','budget','consume','R1','idem-clock',0,'now')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','clock-run','phase','agent',"
            "'transition-clock','client','spawn-idem','task','pending','now','now')"
        )
        self._seed_runtime_dispatch_binding(
            connection,
            run_id="clock-run",
            transition_id="transition-clock",
            phase="phase",
            agent_id="agent",
            task_digest="task",
            spawn_request_id="spawn",
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
            reserve_budget_event_id="clock-reserve",
        )
        external_metadata = (
            '{"run_id":"clock-run","transition_id":"transition-clock",'
            '"client_request_id":"client","idempotency_key":"spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,usage_confidence,updated_at) "
            "VALUES('clock-run','w','capability','provider','model','endpoint','cost-row',"
            "'effective','cost-hash','known','transition-clock',10,10,10,10,1,1,1,1,"
            "'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('clock-reserve','idem-clock-reserve',"
            "'dedupe-clock-reserve',1,'clock-run','transition-clock','spawn',"
            "'provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,1,'known','test','now',800)"
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
            "'intent-clock','clock-run','transition-clock','sessions_spawn','spawn',"
            "'clock-reserve','client','spawn-idem','phase','agent','task','v1',?,?,'clock-run',"
            "'transition-clock','client','spawn-idem','phase','agent','task','accepted',"
            "'session-key','now',1000,'now',900)",
            (external_metadata, external_metadata),
        )
        connection.execute(
            "UPDATE spawn_requests SET session_key='session-key' "
            "WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
            "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
            "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
            "'clock-run','transition-clock','phase','agent','client','spawn-idem',"
            "'session-key','task','completed','now','now')"
        )
        connection.execute(
            "UPDATE spawn_requests SET state='completed' WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('clock-consume','idem-clock-consume',"
            "'dedupe-clock-consume',2,'clock-run','transition-clock','spawn',"
            "'provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','consume',1,1,'known','test','now',1100)"
        )
        connection.execute(
            "UPDATE run_budgets SET reserved_input_tokens=0,reserved_cost_microusd=0,"
            "consumed_input_tokens=1,consumed_cost_microusd=1 WHERE run_id='clock-run'"
        )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        current_proof_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        v5_proof_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(5)
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(prefix_query).fetchall(), [])
        self.assertEqual(connection.execute(v5_proof_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_proof_query).fetchall(),
            [("clock-consume",)],
        )

    def test_post_dispatch_budget_slo_requires_selected_cost_row(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for cost_id, effective_at, row_hash in (
            ("cost-row", "effective", "cost-hash"),
            ("cost-alt", "effective-alt", "cost-alt-hash"),
        ):
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
                "VALUES(?,'provider','model','endpoint','capability',1,1,'known',?,?)",
                (cost_id, effective_at, row_hash),
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'cost-run','prepare-cost','w','file_authority','child_completed','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-cost','cost-run',"
            "'before','after','budget','consume','R1','idem-cost',0,'now')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','cost-run','phase','agent',"
            "'transition-cost','client','spawn-idem','task','pending','now','now')"
        )
        self._seed_runtime_dispatch_binding(
            connection,
            run_id="cost-run",
            transition_id="transition-cost",
            phase="phase",
            agent_id="agent",
            task_digest="task",
            spawn_request_id="spawn",
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
            reserve_budget_event_id="cost-reserve",
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,usage_confidence,updated_at) "
            "VALUES('cost-run','w','capability','provider','model','endpoint','cost-row',"
            "'effective','cost-hash','known','transition-cost',10,10,10,10,1,1,1,1,"
            "'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('cost-reserve','idem-cost-reserve',"
            "'dedupe-cost-reserve',1,'cost-run','transition-cost','spawn',"
            "'provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,1,'known','test','now',800)"
        )
        external_metadata = (
            '{"run_id":"cost-run","transition_id":"transition-cost",'
            '"client_request_id":"client","idempotency_key":"spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
            "'intent-cost','cost-run','transition-cost','sessions_spawn','spawn',"
            "'cost-reserve','client','spawn-idem','phase','agent','task','v1',?,?,'cost-run',"
            "'transition-cost','client','spawn-idem','phase','agent','task','accepted',"
            "'session-key','now',900,'now',1000)",
            (external_metadata, external_metadata),
        )
        connection.execute(
            "UPDATE spawn_requests SET session_key='session-key' "
            "WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
            "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
            "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
            "'cost-run','transition-cost','phase','agent','client','spawn-idem',"
            "'session-key','task','completed','now','now')"
        )
        connection.execute(
            "UPDATE spawn_requests SET state='completed' WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('cost-consume','idem-cost-consume',"
            "'dedupe-cost-consume',2,'cost-run','transition-cost','spawn',"
            "'provider','model','endpoint','capability','cost-alt','effective-alt',"
            "'cost-alt-hash','known','consume',1,1,'known','test','now',1100)"
        )
        connection.execute(
            "UPDATE run_budgets SET reserved_input_tokens=0,reserved_cost_microusd=0,"
            "consumed_input_tokens=1,consumed_cost_microusd=1 WHERE run_id='cost-run'"
        )
        endpoint_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Endpoint-bound budget event cost row blocks dispatch"
        )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        prefix_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget prefix over-release or over-restore"
        )
        current_proof_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        v5_proof_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(5)
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        self.assertEqual(connection.execute(endpoint_query).fetchall(), [])
        self.assertEqual(connection.execute(ledger_query).fetchall(), [])
        self.assertEqual(connection.execute(prefix_query).fetchall(), [])
        self.assertEqual(connection.execute(v5_proof_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_proof_query).fetchall(),
            [("cost-consume",)],
        )

    def test_post_dispatch_budget_slo_requires_trusted_clock_context(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'clockless-run','prepare-clockless','w','file_authority','child_completed',"
            "'R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-clockless',"
            "'clockless-run','before','after','budget','consume','R1',"
            "'idem-clockless',0,'now')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','clockless-run','phase','agent',"
            "'transition-clockless','client','spawn-idem','task','pending','now','now')"
        )
        self._seed_runtime_dispatch_binding(
            connection,
            run_id="clockless-run",
            transition_id="transition-clockless",
            phase="phase",
            agent_id="agent",
            task_digest="task",
            spawn_request_id="spawn",
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
            reserve_budget_event_id="clockless-reserve",
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,usage_confidence,updated_at) "
            "VALUES('clockless-run','w','capability','provider','model','endpoint',"
            "'cost-row','effective','cost-hash','known','transition-clockless',10,10,"
            "10,10,1,1,1,1,'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('clockless-reserve','idem-clockless-reserve',"
            "'dedupe-clockless-reserve',1,'clockless-run','transition-clockless',"
            "'spawn','provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,1,'known','test','now',800)"
        )
        external_metadata = (
            '{"run_id":"clockless-run","transition_id":"transition-clockless",'
            '"client_request_id":"client","idempotency_key":"spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
            "'intent-clockless','clockless-run','transition-clockless','sessions_spawn',"
            "'spawn','clockless-reserve','client','spawn-idem','phase','agent','task',"
            "'v1',?,?,'clockless-run','transition-clockless','client','spawn-idem',"
            "'phase','agent','task','accepted','session-key','now',900,'now',1000)",
            (external_metadata, external_metadata),
        )
        connection.execute(
            "UPDATE spawn_requests SET session_key='session-key' "
            "WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
            "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
            "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
            "'clockless-run','transition-clockless','phase','agent','client',"
            "'spawn-idem','session-key','task','completed','now','now')"
        )
        connection.execute(
            "UPDATE spawn_requests SET state='completed' WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('clockless-consume','idem-clockless-consume',"
            "'dedupe-clockless-consume',2,'clockless-run','transition-clockless',"
            "'spawn','provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','consume',1,1,'known','test','now',1100)"
        )
        connection.execute(
            "UPDATE run_budgets SET reserved_input_tokens=0,reserved_cost_microusd=0,"
            "consumed_input_tokens=1,consumed_cost_microusd=1 "
            "WHERE run_id='clockless-run'"
        )
        current_proof_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        v6_proof_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(6)
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        self.assertEqual(connection.execute(v6_proof_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_proof_query).fetchall(),
            [("clockless-consume",)],
        )

    def test_post_dispatch_budget_slo_requires_selected_transition(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'transition-run','prepare-transition','w','file_authority','child_completed',"
            "'R1','R1','now','now')"
        )
        for transition_id in ("transition-selected", "transition-event"):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,'transition-run','before',"
                "'after','budget','consume','R1',?,0,'now')",
                (transition_id, f"idem-{transition_id}"),
            )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
            "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
            "created_at,updated_at) VALUES('spawn','transition-run','phase','agent',"
            "'transition-event','client','spawn-idem','task','pending','now','now')"
        )
        self._seed_runtime_dispatch_binding(
            connection,
            run_id="transition-run",
            transition_id="transition-event",
            phase="phase",
            agent_id="agent",
            task_digest="task",
            spawn_request_id="spawn",
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
            reserve_budget_event_id="transition-reserve",
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "reserved_input_tokens,reserved_cost_microusd,usage_confidence,updated_at) "
            "VALUES('transition-run','w','capability','provider','model','endpoint',"
            "'cost-row','effective','cost-hash','known','transition-event',10,10,"
            "10,10,1,1,1,1,'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('transition-reserve','idem-transition-reserve',"
            "'dedupe-transition-reserve',1,'transition-run','transition-event','spawn',"
            "'provider','model','endpoint','capability','cost-row','effective',"
            "'cost-hash','known','reserve',1,1,'known','test','now',800)"
        )
        external_metadata = (
            '{"run_id":"transition-run","transition_id":"transition-event",'
            '"client_request_id":"client","idempotency_key":"spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        connection.execute(
            "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
            "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
            "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
            "external_metadata_json,external_run_id,external_transition_id,"
            "external_client_request_id,external_idempotency_key,external_phase,"
            "external_agent_id,external_task_digest,state,external_id,requested_at,"
            "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
            "'intent-transition','transition-run','transition-event','sessions_spawn',"
            "'spawn','transition-reserve','client','spawn-idem','phase','agent','task',"
            "'v1',?,?,'transition-run','transition-event','client','spawn-idem',"
            "'phase','agent','task','accepted','session-key','now',900,'now',1000)",
            (external_metadata, external_metadata),
        )
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='run_budgets_preserve_spawn_prior_reserve_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER run_budgets_preserve_spawn_prior_reserve_update")
        connection.execute(
            "UPDATE run_budgets SET selected_reserve_transition_id='transition-selected' "
            "WHERE run_id='transition-run'"
        )
        connection.execute(trigger_sql)
        connection.execute(
            "UPDATE spawn_requests SET session_key='session-key' "
            "WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
            "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
            "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
            "'transition-run','transition-event','phase','agent','client',"
            "'spawn-idem','session-key','task','completed','now','now')"
        )
        connection.execute(
            "UPDATE spawn_requests SET state='completed' WHERE spawn_request_id='spawn'"
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
            "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
            "context_hash,evidence_hash,independence_class,"
            "independence_proof_json,completed_at) VALUES('verifier-transition',"
            "'transition-run','worker','verifier','provider','model','prompt',"
            "'context','evidence-transition','independent','{\"reviewer\":\"slo\"}',"
            "'now')"
        )
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,"
            "gate_version,gate_query_hash,migration_sha256,evidence_hash,"
            "risk_dominance,created_at) VALUES('gate-transition','transition-run',"
            "'transition-event','clock-transition','verifier-transition','pass','now',"
            "1100,'v1','query','migration','evidence-transition','R1','now')"
        )
        connection.execute(
            "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
            "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,now_epoch_ms,"
            "bound_at_epoch_ms,bound_by,trusted_clock_source_hash,consumed_at_epoch_ms) "
            "VALUES('clock-transition','gate-transition','gate-transition',"
            "'transition-run','transition-event','nonce',1100,1100,'test',"
            "'trusted-clock',1100)"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
            "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
            "input_tokens,cost_microusd,usage_confidence,source,created_at,"
            "created_at_epoch_ms,clock_context_id) VALUES('transition-consume',"
            "'idem-transition-consume','dedupe-transition-consume',2,'transition-run',"
            "'transition-event','spawn','provider','model','endpoint','capability',"
            "'cost-row','effective','cost-hash','known','consume',1,1,'known','test',"
            "'now',1100,'clock-transition')"
        )
        connection.execute(
            "UPDATE run_budgets SET reserved_input_tokens=0,reserved_cost_microusd=0,"
            "consumed_input_tokens=1,consumed_cost_microusd=1 "
            "WHERE run_id='transition-run'"
        )
        current_proof_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        v6_proof_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(6)
            if (
                contract.query_name
                == "Accepted `sessions_spawn` without exact accepted session identity"
            )
        )
        self.assertEqual(connection.execute(v6_proof_query).fetchall(), [])
        self.assertEqual(
            connection.execute(current_proof_query).fetchall(),
            [("transition-consume",)],
        )

    def test_consume_confidence_amount_slo_matches_runtime_pairing(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'amount-run','prepare-amount','w','file_authority','child_completed','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-amount','amount-run',"
            "'before','after','budget','consume','R1','idem-amount',0,'now')"
        )
        for event_id, sequence, confidence, input_tokens, cost in (
            ("known-zero-consume", 1, "known", 0, 0),
            ("estimated-zero-consume", 2, "estimated", 0, 0),
            ("unknown-nonzero-consume", 3, "unknown", 1, 1),
        ):
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,input_tokens,cost_microusd,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'amount-run','transition-amount','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known','consume',?,"
                "?,?, 'test','now',?)",
                (
                    event_id,
                    f"idem-{event_id}",
                    f"dedupe-{event_id}",
                    sequence,
                    input_tokens,
                    cost,
                    confidence,
                    1000 + sequence,
                ),
            )
        current_amount_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget event amount malformed or out of range"
        )
        v5_amount_query = next(
            contract.sql_text
            for contract in slo_query_contracts_for_schema_version(5)
            if contract.query_name == "Budget event amount malformed or out of range"
        )
        self.assertEqual(connection.execute(v5_amount_query).fetchall(), [])
        self.assertEqual(
            set(connection.execute(current_amount_query).fetchall()),
            {
                ("known-zero-consume",),
                ("estimated-zero-consume",),
                ("unknown-nonzero-consume",),
            },
        )

    def test_budget_ledger_slo_rejects_events_without_run_budget(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'missing-budget','prepare','w','file_authority','candidate','R1','R1',"
            "'now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition','missing-budget',"
            "'before','after','budget','reserve','R1','transition-idem',0,'now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,capability_class,"
            "event_type,human_attention_units,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('event','event-idem','event-dedupe',1,"
            "'missing-budget','transition','capability','human_attention',1,'known',"
            "'test','now',1000)"
        )
        ledger_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Budget ledger reconciles to counters and budgets"
        )
        self.assertEqual(connection.execute(ledger_query).fetchall(), [("missing-budget",)])

    def test_p1_budget_sql_fixture_pack_exercises_blocking_slos(self) -> None:
        fixture_root = repository_root() / "tests/fixtures"
        expectations = {
            "budgets/ledger_reconciliation.sql": {
                "Budget ledger reconciles to counters and budgets": {
                    ("fixture-ledger-drift",),
                    ("fixture-consume-over-budget",),
                },
                "Budget prefix over-release or over-restore": {
                    ("fixture-consume-over-budget-event",),
                },
                "Duplicate or replayed budget events": {
                    ("fixture-duplicate-replay-dedupe",),
                },
            },
            "budgets/human_attention_cross_dimension_payload.sql": {
                "Budget event amount malformed or out of range": {
                    ("fixture-human-cross-payload",),
                    ("fixture-consume-carries-human-attention",),
                },
            },
            "budgets/retry_cross_dimension_payload.sql": {
                "Budget event amount malformed or out of range": {
                    ("fixture-consume-carries-retry",),
                    ("fixture-retry-decrement-cross-payload",),
                    ("fixture-retry-restore-cross-payload",),
                },
            },
            "budgets/non_negative_budget_accounting.sql": {
                "Budget ledger reconciles to counters and budgets": {
                    ("fixture-negative-net-reserve",)
                },
                "Budget prefix over-release or over-restore": {
                    ("fixture-over-release",)
                },
            },
            "budgets/zero_reserve_policy.sql": {
                "Invalid zero-reserve policy": {
                    ("fixture-invalid-zero-policy",)
                },
            },
            "budgets/selected_model_registry_binding.sql": {
                "Run budget selected cost row mismatch": {
                    ("fixture-selected-run-budget-mismatch",),
                    ("fixture-selected-missing-cost-row",),
                    ("fixture-selected-unknown-cost-row",),
                },
                "Endpoint-bound budget event cost row blocks dispatch": {
                    ("fixture-selected-event-model-mismatch-event",),
                    ("fixture-selected-event-missing-cost-row-event",),
                    ("fixture-selected-event-unknown-cost-row-event",),
                },
            },
            "budgets/strict_prior_reserve_binding.sql": {
                "`sessions_spawn` intent without exact strict prior reserve": {
                    ("fixture-prior-absent-reserve-intent",),
                    ("fixture-prior-same-ms-intent",),
                    ("fixture-prior-wrong-endpoint-intent",),
                    ("fixture-prior-wrong-hash-intent",),
                    ("fixture-prior-wrong-transition-intent",),
                    ("fixture-prior-selected-transition-drift-intent",),
                },
            },
            "sqlite_type_affinity_h1_h4.sql": {
                "Model cost registry numeric bounds": {
                    ("fixture-numeric-text-cost",),
                    ("fixture-integral-real-cost",),
                    ("fixture-max-plus-one-cost",),
                },
            },
        }
        budget_fixture_paths = {
            str(path.relative_to(fixture_root))
            for path in (fixture_root / "budgets").glob("*.sql")
        }
        type_affinity_fixture = fixture_root / "sqlite_type_affinity_h1_h4.sql"
        fixture_paths = {
            *budget_fixture_paths,
            str(type_affinity_fixture.relative_to(fixture_root)),
        }
        self.assertEqual(fixture_paths, set(expectations))
        contracts = {contract.query_name: contract.sql_text for contract in SLO_QUERY_CONTRACTS}

        for index, (fixture, expected_by_query) in enumerate(expectations.items()):
            with self.subTest(fixture=fixture):
                database = Path(self.temporary.name) / f"fixture-{index}.db"
                apply_migrations(database)
                connection = sqlite3.connect(database)
                _register_migration_functions(connection)
                self.addCleanup(connection.close)
                connection.executescript(
                    (fixture_root / fixture).read_text(encoding="utf-8")
                )
                for query_name, expected_rows in expected_by_query.items():
                    rows = set(connection.execute(contracts[query_name]).fetchall())
                    self.assertLessEqual(expected_rows, rows)
                if fixture == "budgets/non_negative_budget_accounting.sql":
                    row = connection.execute(
                        """
                        WITH event_sums AS (
                          SELECT run_id,
                                 SUM(
                                   CASE
                                     WHEN event_type='reserve' THEN input_tokens
                                     WHEN event_type IN ('release','consume')
                                       THEN -input_tokens
                                     ELSE 0
                                   END
                                 ) AS net_reserved_input
                          FROM budget_events
                          GROUP BY run_id
                        )
                        SELECT s.net_reserved_input, rb.reserved_input_tokens
                        FROM event_sums s
                        JOIN run_budgets rb USING(run_id)
                        WHERE s.run_id='fixture-negative-net-reserve'
                        """
                    ).fetchone()
                    self.assertEqual(row, (-3, 0))
                    counter_rows = set(
                        connection.execute(
                            contracts["Budget counters outside selected budget"]
                        ).fetchall()
                    )
                    self.assertNotIn(("fixture-negative-net-reserve",), counter_rows)
                    ledger_without_negative_net = contracts[
                        "Budget ledger reconciles to counters and budgets"
                    ].replace(
                        "COALESCE(s.net_reserved_time,0)<0 OR "
                        "COALESCE(s.net_reserved_input,0)<0 OR "
                        "COALESCE(s.net_reserved_output,0)<0 OR "
                        "COALESCE(s.net_reserved_cost,0)<0 OR "
                        "COALESCE(s.net_reserved_retries,0)<0 OR "
                        "COALESCE(s.net_reserved_human,0)<0 OR ",
                        "",
                    )
                    self.assertNotIn(
                        ("fixture-negative-net-reserve",),
                        set(connection.execute(ledger_without_negative_net).fetchall()),
                    )
                if fixture == "budgets/ledger_reconciliation.sql":
                    row = connection.execute(
                        """
                        SELECT
                          SUM(CASE WHEN event_type='reserve' THEN input_tokens ELSE 0 END),
                          SUM(CASE WHEN event_type='consume' THEN input_tokens ELSE 0 END),
                          input_token_budget,
                          consumed_input_tokens
                        FROM budget_events
                        JOIN run_budgets USING(run_id)
                        WHERE run_id='fixture-consume-over-budget'
                        GROUP BY run_id
                        """
                    ).fetchone()
                    self.assertEqual(row, (5, 6, 5, 6))
                    ledger_query = contracts[
                        "Budget ledger reconciles to counters and budgets"
                    ]
                    ledger_without_negative_net = ledger_query.replace(
                        "COALESCE(s.net_reserved_time,0)<0 OR "
                        "COALESCE(s.net_reserved_input,0)<0 OR "
                        "COALESCE(s.net_reserved_output,0)<0 OR "
                        "COALESCE(s.net_reserved_cost,0)<0 OR "
                        "COALESCE(s.net_reserved_retries,0)<0 OR "
                        "COALESCE(s.net_reserved_human,0)<0 OR ",
                        "",
                    )
                    self.assertIn(
                        ("fixture-consume-over-budget",),
                        set(connection.execute(ledger_without_negative_net).fetchall()),
                    )
                if fixture == "budgets/human_attention_cross_dimension_payload.sql":
                    amount_query = contracts[
                        "Budget event amount malformed or out of range"
                    ]
                    amount_without_consume_cross_dimension = amount_query.replace(
                        " OR (event_type='consume' "
                        "AND (retry_units<>0 OR human_attention_units<>0))",
                        "",
                    )
                    self.assertNotIn(
                        ("fixture-consume-carries-human-attention",),
                        set(
                            connection.execute(
                                amount_without_consume_cross_dimension
                            ).fetchall()
                        ),
                    )
                if fixture == "sqlite_type_affinity_h1_h4.sql":
                    rows = set(
                        connection.execute(
                            contracts["Model cost registry numeric bounds"]
                        ).fetchall()
                    )
                    self.assertNotIn(("fixture-exact-max-cost",), rows)
                if fixture == "budgets/selected_model_registry_binding.sql":
                    selected_rows = set(
                        connection.execute(
                            contracts["Run budget selected cost row mismatch"]
                        ).fetchall()
                    )
                    self.assertNotIn(("fixture-selected-positive",), selected_rows)
                    endpoint_rows = set(
                        connection.execute(
                            contracts[
                                "Endpoint-bound budget event cost row blocks dispatch"
                            ]
                        ).fetchall()
                    )
                    self.assertNotIn(
                        ("fixture-selected-event-positive-event",), endpoint_rows
                    )
                if fixture == "budgets/strict_prior_reserve_binding.sql":
                    prior_rows = set(
                        connection.execute(
                            contracts[
                                "`sessions_spawn` intent without exact strict prior reserve"
                            ]
                        ).fetchall()
                    )
                    self.assertNotIn(("fixture-prior-positive-intent",), prior_rows)

    def test_unknown_usage_blocks_promoted_run_states(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        for state in ("gate_passed", "release_pending", "finalized"):
            run_id = f"run-{state}"
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES(?, ?, "
                "'w','file_authority',?,'R1','R1','now','now')",
                (run_id, f"prepare-{state}", state),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?, ?, 'before','after',"
                "'budget','reserve','R1', ?, 0,'now')",
                (f"transition-{state}", run_id, f"idem-{state}"),
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
                "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
                "selected_cost_effective_at,selected_cost_registry_hash,"
                "selected_cost_confidence,selected_reserve_transition_id,"
                "time_budget_seconds,input_token_budget,output_token_budget,"
                "cost_budget_microusd,retry_budget,human_attention_budget,"
                "usage_confidence,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    "w",
                    "capability",
                    "provider",
                    "model",
                    "endpoint",
                    "cost-row",
                    "effective",
                    "cost-hash",
                    "known",
                    f"transition-{state}",
                    10,
                    10,
                    10,
                    10,
                    1,
                    1,
                    "unknown",
                    "now",
                ),
            )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run-event-unknown','prepare-event-unknown','w','file_authority',"
            "'release_pending','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES('transition-event-unknown',"
            "'run-event-unknown','before','after','budget','reserve','R1',"
            "'idem-event-unknown',0,'now')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,"
            "selected_cost_confidence,selected_reserve_transition_id,"
            "time_budget_seconds,input_token_budget,output_token_budget,"
            "cost_budget_microusd,retry_budget,human_attention_budget,"
            "usage_confidence,updated_at) VALUES('run-event-unknown','w','capability',"
            "'provider','model','endpoint','cost-row','effective','cost-hash','known',"
            "'transition-event-unknown',10,10,10,10,1,1,'known','now')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
            "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
            "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
            "cost_registry_hash,cost_confidence,event_type,input_tokens,usage_confidence,"
            "source,created_at,created_at_epoch_ms) VALUES('unknown-event','idem-unknown',"
            "'dedupe-unknown',1,'run-event-unknown','transition-event-unknown','provider',"
            "'model','endpoint','capability','cost-row','effective','cost-hash','known',"
            "'reserve',1,'unknown','test','now',1000)"
        )
        query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Unknown usage blocks auto-local"
        )
        self.assertEqual(
            {row[0] for row in connection.execute(query).fetchall()},
            {
                "run-gate_passed",
                "run-release_pending",
                "run-finalized",
                "run-event-unknown",
            },
        )

    def test_completion_gate_slo_blocks_finalized_r2_without_finalized_time(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'finalized-r2','prepare','w','file_authority','finalized','R2','R2',"
            "'now','now')"
        )
        query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Completion gate before done for R2+"
        )
        self.assertEqual(connection.execute(query).fetchall(), [("finalized-r2",)])
        design = (
            repository_root() / "docs/agentic-os-production-adaptation.md"
        ).read_text(encoding="utf-8")
        self.assertIn(f"| Completion gate before done for R2+ | `{query}` |", design)

    def test_completion_gate_slo_requires_pass_gate_on_finalizing_transition(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,finalized_at,finalized_at_epoch_ms,"
            "created_at,updated_at) VALUES('finalized-r2','prepare','w',"
            "'file_authority','finalized','R2','R2','done',1000,'now','now')"
        )
        for transition_id, state_after, gate_id, completed_at_epoch_ms in (
            ("old-transition", "gate_passed", "old-gate", 900),
            ("final-transition", "finalized", None, None),
        ):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,?,?,"
                "'gate','check','R2',?,0,'now')",
                (
                    transition_id,
                    "finalized-r2",
                    "candidate",
                    state_after,
                    f"idem-{transition_id}",
                ),
            )
            if gate_id is not None:
                connection.execute(
                    "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                    "clock_context_id,verifier_run_id,decision,completed_at,"
                    "completed_at_epoch_ms,gate_version,gate_query_hash,"
                    "migration_sha256,evidence_hash,risk_dominance,created_at) "
                    "VALUES(?,?,?,?,?,'pass','now',?,'v1','query','migration',"
                    "?,'R2','now')",
                    (
                        gate_id,
                        "finalized-r2",
                        transition_id,
                        f"clock-{gate_id}",
                        f"verifier-{gate_id}",
                        completed_at_epoch_ms,
                        f"evidence-{gate_id}",
                    ),
                )
        query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "Completion gate before done for R2+"
        )
        self.assertEqual(connection.execute(query).fetchall(), [("finalized-r2",)])
        connection.execute(
            "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
            "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
            "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
            "VALUES('final-gate','finalized-r2','final-transition','clock-final',"
            "'verifier-final','pass','now',999,'v1','query','migration',"
            "'evidence-final','R2','now')"
        )
        self.assertEqual(connection.execute(query).fetchall(), [])

    def test_readme_migration_example_uses_private_test_database(self) -> None:
        readme = (repository_root() / "README.md").read_text(encoding="utf-8")
        self.assertIn("agentic_os.cli migrate --test-db", readme)
        self.assertNotIn("agentic_os.cli migrate --db /tmp", readme)

    def test_slo_registry_is_seeded_and_audit_must_match_current_query_identity(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        status_query = next(
            contract.sql_text
            for contract in SLO_QUERY_CONTRACTS
            if contract.query_name == "SLO query fixture status"
        )
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        current_migration = manifest["migrations"][-1]
        schema_version = current_migration["version"]
        migration_hash = current_migration["sha256"]
        rows = connection.execute(
            "SELECT query_name,schema_version,migration_sha256,query_hash,sql_text,"
            "empty_db_expected_status,fixture_db_expected_status FROM slo_queries "
            "WHERE schema_version=? AND migration_sha256=?",
            (schema_version, migration_hash),
        ).fetchall()
        actual = {row[0]: row[1:] for row in rows}
        expected = {
            contract.query_name: (
                schema_version,
                migration_hash,
                slo_query_hash(contract.sql_text),
                contract.sql_text,
                contract.empty_db_expected_status,
                contract.fixture_db_expected_status,
            )
            for contract in SLO_QUERY_CONTRACTS
        }
        self.assertEqual(len(actual), SLO_QUERY_COUNT)
        self.assertEqual(actual, expected)
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM slo_queries").fetchone(),
            (SLO_QUERY_COUNT * len(manifest["migrations"]),),
        )
        initial_blockers = {row[0] for row in connection.execute(status_query).fetchall()}
        self.assertEqual(
            initial_blockers,
            {
                contract.query_name
                for contract in SLO_QUERY_CONTRACTS
                if contract.query_name != "SLO query fixture status"
            },
        )
        self.assertNotIn("SLO query fixture status", initial_blockers)
        contract = SLO_QUERY_CONTRACTS[0]
        query_hash = slo_query_hash(contract.sql_text)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,evidence_hash,run_at,run_at_epoch_ms) VALUES("
                "'a',?,?,?,?,0,'pass','pass','pass',?,'now',1000)",
                (contract.query_name, schema_version, migration_hash, "d" * 64, "e" * 64),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,evidence_hash,run_at,run_at_epoch_ms) VALUES("
                "'a-nonzero',?,?,?,?,1,'pass','pass','pass',?,'now',1000)",
                (contract.query_name, schema_version, migration_hash, query_hash, "e" * 64),
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "evidence|writer provenance"
        ):
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
                "gate_run_id,run_at,run_at_epoch_ms) VALUES("
                "'a-synthetic-pass',?,?,?,?,0,'pass','pass','pass',?,?,?,?,"
                "'now',1000)",
                (
                    contract.query_name,
                    schema_version,
                    migration_hash,
                    query_hash,
                    "synthetic-evidence",
                    "synthetic-run",
                    "synthetic-verifier",
                    "synthetic-gate",
                ),
            )
        stale_run_id, stale_verifier_id, stale_gate_id = self._insert_gate_bound_evidence(
            connection,
            evidence_hash="slo-evidence-stale",
            suffix="stale",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "evidence|writer provenance"
        ):
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
                "gate_run_id,run_at,run_at_epoch_ms) VALUES("
                "'a-wrong-evidence-binding',?,?,?,?,0,'pass','pass','pass',?,?,?,?,"
                "'now',1000)",
                (
                    contract.query_name,
                    schema_version,
                    migration_hash,
                    query_hash,
                    "slo-evidence-stale",
                    stale_run_id,
                    stale_verifier_id,
                    "wrong-gate",
                ),
            )
        for decision in ("fail", "human_review_required"):
            (
                non_pass_run_id,
                non_pass_verifier_id,
                non_pass_gate_id,
            ) = self._insert_gate_bound_evidence(
                connection,
                evidence_hash=f"slo-evidence-{decision}",
                suffix=f"non-pass-{decision}",
                decision=decision,
            )
            with self.subTest(decision=decision), self.assertRaisesRegex(
                sqlite3.IntegrityError, "pass-gate evidence|writer provenance"
            ):
                connection.execute(
                    "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                    "migration_sha256,query_hash,result_count,status,empty_db_status,"
                    "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
                    "gate_run_id,run_at,run_at_epoch_ms) VALUES("
                    f"'a-non-pass-{decision}',?,?,?,?,0,'pass','pass','pass',?,?,?,?,"
                    "'now',1000)",
                    (
                        contract.query_name,
                        schema_version,
                        migration_hash,
                        query_hash,
                        f"slo-evidence-{decision}",
                        non_pass_run_id,
                        non_pass_verifier_id,
                        non_pass_gate_id,
                    ),
                )
        _allow_next_slo_audit_write(connection, "a-stale-pass")
        connection.execute(
            "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
            "migration_sha256,query_hash,result_count,status,empty_db_status,"
            "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
            "gate_run_id,run_at,run_at_epoch_ms) VALUES("
            "'a-stale-pass',?,?,?,?,0,'pass','pass','pass',?,?,?,?,"
            "'zzzz',1000)",
            (
                contract.query_name,
                schema_version,
                migration_hash,
                query_hash,
                "slo-evidence-stale",
                stale_run_id,
                stale_verifier_id,
                stale_gate_id,
            ),
        )
        _allow_next_slo_audit_write(connection, "a-valid")
        connection.execute(
            "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
            "migration_sha256,query_hash,result_count,status,empty_db_status,"
            "fixture_db_status,evidence_hash,run_at,run_at_epoch_ms) VALUES("
            "'a-fresh-fail',?,?,?,?,1,'fail','pass','pass',NULL,'aaaa',2000)",
            (contract.query_name, schema_version, migration_hash, query_hash),
        )
        self.assertIn(
            (contract.query_name,),
            connection.execute(status_query).fetchall(),
        )
        valid_run_id, valid_verifier_id, valid_gate_id = self._insert_gate_bound_evidence(
            connection,
            evidence_hash="slo-evidence-valid",
            suffix="valid",
        )
        connection.execute(
            "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
            "migration_sha256,query_hash,result_count,status,empty_db_status,"
            "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
            "gate_run_id,run_at,run_at_epoch_ms) VALUES("
            "'a-valid',?,?,?,?,0,'pass','pass','pass',?,?,?,?,"
            "'now',3000)",
            (
                contract.query_name,
                schema_version,
                migration_hash,
                query_hash,
                "slo-evidence-valid",
                valid_run_id,
                valid_verifier_id,
                valid_gate_id,
            ),
        )
        for assignment in (
            "query_hash='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            "run_at_epoch_ms=4000",
            "status='fail'",
        ):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(
                sqlite3.IntegrityError, "SLO audit row is immutable"
            ):
                connection.execute(
                    f"UPDATE slo_audits SET {assignment} "
                    "WHERE slo_audit_id='a-valid'"
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "SLO audit row is immutable"):
            connection.execute("DELETE FROM slo_audits WHERE slo_audit_id='a-valid'")
        self.assertNotIn(
            (contract.query_name,),
            connection.execute(status_query).fetchall(),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "pass gate is immutable"):
            connection.execute(
                "UPDATE gate_runs SET decision='fail' WHERE gate_run_id=?",
                (valid_gate_id,),
            )
        self.assertNotIn(
            (contract.query_name,),
            connection.execute(status_query).fetchall(),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE slo_queries SET sql_text='SELECT 2' WHERE query_name=?",
                (contract.query_name,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE slo_queries SET query_hash=? WHERE query_name=?",
                ("f" * 64, contract.query_name),
            )

    def test_sessions_spawn_metadata_slo_uses_null_safe_json_type_checks(self) -> None:
        contract = next(
            item
            for item in SLO_QUERY_CONTRACTS
            if item.query_name == "`sessions_spawn` external metadata exact match"
        )
        self.assertIn(
            "json_type(external_metadata_json,'$.run_id') IS NOT 'text'",
            contract.sql_text,
        )
        self.assertNotIn(
            "json_type(external_metadata_json,'$.run_id')<>'text'",
            contract.sql_text,
        )

    def test_slo_registry_allows_same_query_name_for_new_schema_version(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        contract = SLO_QUERY_CONTRACTS[0]
        future_version = max(migration.version for migration in load_migrations()) + 1
        migration_sha = "9" * 64
        query_hash = "9" * 64
        connection.execute(
            "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
            "VALUES(?,'future_contract',?,'now')",
            (future_version, migration_sha),
        )
        connection.execute(
            "INSERT INTO slo_queries(query_name,schema_version,migration_sha256,"
            "query_hash,sql_text,empty_db_expected_status,fixture_db_expected_status,"
            "created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                contract.query_name,
                future_version,
                migration_sha,
                query_hash,
                "SELECT 1;",
                "pass",
                "pass",
                "now",
            ),
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM slo_queries WHERE query_name=?",
                (contract.query_name,),
            ).fetchone(),
            (future_version,),
        )

    def test_slo_registry_delete_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "DELETE FROM slo_queries WHERE query_name=?",
                    (SLO_QUERY_CONTRACTS[0].query_name,),
                )

    def test_type_preserving_money_bounds(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        base = ("p", "m", "e", "c", "known", "2026-01-01", "h")

        def insert(identifier: str, input_price: object, output_price: object) -> None:
            connection.execute(
                "INSERT INTO model_cost_registry("
                "cost_registry_id,provider,model,endpoint_binding_id,capability_class,"
                "input_cost_microusd_per_million,output_cost_microusd_per_million,"
                "confidence,effective_at,registry_row_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (identifier, *base[:4], input_price, output_price, *base[4:6], identifier),
            )

        insert("max", 100_000_000_000, 100_000_000_000)
        for identifier, value in (
            ("max-plus-one", 100_000_000_001),
            ("numeric-text", "1500"),
            ("integral-real", 1500.0),
            ("negative", -1),
        ):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError):
                insert(identifier, value, 0)

    def test_referenced_model_cost_registry_is_immutable(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','dispatch','spawn','R1','transition-idem',"
            "0,'now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "usage_confidence,updated_at) VALUES("
            "'run','w','capability','provider','model','endpoint','cost-row','effective',"
            "'cost-hash','known','transition',10,10,10,10,1,1,'known','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE model_cost_registry SET input_cost_microusd_per_million=2 "
                "WHERE cost_registry_id='cost-row'"
            )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row-event','provider','model','endpoint','capability',1,1,'known',"
            "'effective-2','cost-hash-event')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('event','event-idem','event-dedupe',1,'run',"
            "'transition','provider','model','endpoint','capability','cost-row-event',"
            "'effective-2','cost-hash-event','known','consume',1,'known','test','now',1000)"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE model_cost_registry SET output_cost_microusd_per_million=2 "
                "WHERE cost_registry_id='cost-row-event'"
            )

    def test_run_budget_reserve_transition_must_match_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES(?, ?, "
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?, ?, 'before','after',"
                "'dispatch','spawn','R1', ?, 0,'now')",
                (f"transition-{run_id}", run_id, f"idem-{run_id}"),
            )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        statement = (
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "usage_confidence,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                statement,
                (
                    "run-a",
                    "w",
                    "capability",
                    "provider",
                    "model",
                    "endpoint",
                    "cost-row",
                    "effective",
                    "cost-hash",
                    "known",
                    "transition-run-b",
                    10,
                    10,
                    10,
                    10,
                    1,
                    1,
                    "known",
                    "now",
                ),
            )
        connection.execute(
            statement,
            (
                "run-a",
                "w",
                "capability",
                "provider",
                "model",
                "endpoint",
                "cost-row",
                "effective",
                "cost-hash",
                "known",
                "transition-run-a",
                10,
                10,
                10,
                10,
                1,
                1,
                "known",
                "now",
            ),
        )

    def test_manifest_is_machine_readable_and_has_pinned_migrations(self) -> None:
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [(row["version"], row["name"]) for row in manifest["migrations"]],
            [
                (1, "minimum_contract"),
                (2, "shadow_projection_identity"),
                (3, "budget_ledger_slo_identity"),
                (4, "budget_post_dispatch_mutations"),
                (5, "budget_retry_prefix_spawn_scope"),
                (6, "budget_post_dispatch_slo_guards"),
                (7, "budget_post_dispatch_clock_identity"),
                (8, "budget_atomic_final_settlement"),
                (9, "legacy_money_import_quarantine"),
                (10, "runtime_dispatch_binding"),
                (11, "gate_authority_snapshot"),
                (12, "goal_run_evidence_binding"),
                (13, "trust_promotion_binding"),
                (14, "db_authority_canary_binding"),
                (15, "strict_prior_reserve_slo_identity"),
                (16, "expired_lease_spawn_guard"),
            ],
        )

    def test_readme_digests_match_current_design_and_migration(self) -> None:
        readme = (repository_root() / "README.md").read_text(encoding="utf-8")
        design_digest = hashlib.sha256(
            (repository_root() / "docs/agentic-os-production-adaptation.md").read_bytes()
        ).hexdigest()
        manifest_path = repository_root() / "migrations/manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        base_migration_digest = hashlib.sha256(
            (repository_root() / "migrations/0001_minimum_contract.sql").read_bytes()
        ).hexdigest()
        latest_migration_digest = hashlib.sha256(
            (repository_root() / "migrations" / manifest["migrations"][-1]["file"]).read_bytes()
        ).hexdigest()
        project_status = json.loads(
            (repository_root() / "docs/project-status.json").read_text(encoding="utf-8")
        )
        acceptance = project_status["repository_artifact_acceptance"]
        accepted_design_digest = acceptance["accepted_head_design_artifact"]["sha256"]
        current_design_digest = acceptance["current_corrected_design_artifact"]["sha256"]
        self.assertEqual(set(project_status), {
            "repository_artifact_acceptance",
            "live_runtime_evidence",
            "production_authority",
        })
        self.assertEqual(
            project_status["repository_artifact_acceptance"]["status"],
            "accepted_and_merged",
        )
        self.assertEqual(
            project_status["live_runtime_evidence"]["status"],
            "pending_current_evidence",
        )
        self.assertEqual(project_status["production_authority"]["status"], "disabled")
        self.assertFalse(DB_AUTHORITY_ENABLED)
        self.assertIn("accepted repository state", readme)
        self.assertIn("passed exact-head Phase C", readme)
        self.assertIn("clean Codex review", readme)
        self.assertIn("no current-head GitHub Codex review binding", readme)
        self.assertIn(
            "historical candidate invocations and reviews must not be counted",
            readme,
        )
        self.assertIn(
            "docs/runtime-evidence/phase-b-revalidation-20260809.json", readme
        )
        self.assertIn("docs/project-status.json", readme)
        self.assertNotIn(
            "The current Issue #44 persistent-lifecycle candidate proof is intentionally disabled",
            readme,
        )
        self.assertNotIn("has **not** yet passed fresh independent", readme)
        self.assertNotIn("Draft PR successor", readme)
        self.assertNotIn("still required before it can be", readme)
        self.assertIn(
            "Accepted-head repository design artifact SHA-256: "
            f"`{accepted_design_digest}`",
            readme,
        )
        self.assertIn(
            "Current corrected design artifact SHA-256: "
            f"`{current_design_digest}`",
            readme,
        )
        self.assertEqual(current_design_digest, design_digest)
        self.assertNotEqual(accepted_design_digest, current_design_digest)
        self.assertIn(f"Base DDL migration SHA-256: `{base_migration_digest}`", readme)
        self.assertIn(
            f"Current latest migration SHA-256: `{latest_migration_digest}`", readme
        )
        self.assertIn(f"Current migration manifest SHA-256: `{manifest_digest}`", readme)

    def test_design_contract_primary_ddl_is_current_projection_schema(self) -> None:
        design = (repository_root() / "docs/agentic-os-production-adaptation.md").read_text(
            encoding="utf-8"
        )
        contract = design.split("## Minimum Database Contracts", 1)[1]
        ddl = contract.split("```sql\n", 1)[1].split("\n```", 1)[0] + "\n"
        projection_ddl = ddl.split(
            "CREATE TEMP TABLE goal_run_evidence_binding_migration_guard", 1
        )[0]
        with sqlite3.connect(":memory:") as connection:
            _register_migration_functions(connection)
            connection.executescript(projection_ddl)
        projection_contract = ddl.split("CREATE TABLE artifact_projections (", 1)[1].split(
            "CREATE TABLE evidence_hashes", 1
        )[0]
        self.assertIn("UNIQUE(run_id, path, source_authority)", projection_contract)
        self.assertIn("CREATE TABLE artifact_projection_history", projection_contract)
        self.assertNotIn("UNIQUE(path, sha256)", projection_contract)

    def test_design_contract_includes_shadow_projection_v2_overlay(self) -> None:
        design = (repository_root() / "docs/agentic-os-production-adaptation.md").read_text(
            encoding="utf-8"
        )
        overlay = design.split("Current migration v2 shadow projection identity:", 1)[1]
        self.assertIn("CREATE TABLE artifact_projection_history", overlay)
        self.assertIn("UNIQUE(run_id, path, source_authority)", overlay)

    def test_schema_migration_version_preserves_numeric_type(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        for version in ("2", 2.0):
            with self.subTest(version=version), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                    "VALUES(?,?,?,?)",
                    (version, "bad", "0" * 64, "now"),
                )


if __name__ == "__main__":
    unittest.main()
