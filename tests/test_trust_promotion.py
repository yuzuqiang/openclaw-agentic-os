from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

from agentic_os.goal_runs import record_goal_run
from agentic_os.migrations import (
    _register_migration_functions,
    _trust_binding_hash,
    apply_migrations,
    repository_root,
)
from agentic_os.pass_gates import (
    ApprovalGrant,
    GateEvidence,
    VerifierProof,
    record_approval_pass_gate,
)
from agentic_os.slo_contracts import SLO_QUERY_CONTRACTS, slo_query_hash
from agentic_os.trust_promotion import TrustPromotionError, promote_trust


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


class TrustPromotionWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.artifact_root = repository_root() / "artifacts/trust-promotion-test"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_artifact_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.evidence_directory = tempfile.TemporaryDirectory(dir=self.artifact_root)
        self.addCleanup(self.evidence_directory.cleanup)
        self.database = Path(self.temporary.name) / "control.db"
        self.evidence_path = Path(self.evidence_directory.name) / "evidence.json"
        self.evidence_content = b'{"trust":true}\n'
        self.evidence_path.write_bytes(self.evidence_content)
        self.evidence_hash = _sha_bytes(self.evidence_content)

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _cleanup_artifact_root(self) -> None:
        try:
            self.artifact_root.rmdir()
            self.artifact_root.parent.rmdir()
        except OSError:
            pass

    def test_promote_trust_records_bound_observation(self) -> None:
        self._seed_valid_fixture()

        result = self._promote()

        self.assertEqual(result.run_id, "run")
        self.assertEqual(result.goal_run_id, "goal-run")
        self.assertEqual(result.blocking_slo_query_count, len(SLO_QUERY_CONTRACTS))
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT status,usage_confidence,cost_confidence,blocking_slo_bundle_hash "
                "FROM trust_observations WHERE observation_id='trust'"
            ).fetchone()
        self.assertEqual(row, ("promoted", "known", "known", result.blocking_slo_bundle_hash))

    def test_unknown_or_estimated_budget_confidence_fails_without_write(self) -> None:
        for column, value in (
            ("usage_confidence", "unknown"),
            ("usage_confidence", "estimated"),
            ("selected_cost_confidence", "estimated"),
        ):
            with self.subTest(column=column, value=value):
                self._reset_database()
                if column == "selected_cost_confidence":
                    self._seed_valid_fixture(cost_confidence=value)
                else:
                    self._seed_valid_fixture()
                    with closing(sqlite3.connect(self.database)) as connection, connection:
                        connection.execute(
                            f"UPDATE run_budgets SET {column}=? WHERE run_id='run'",
                            (value,),
                        )
                self._assert_promotion_fails_without_write(
                    "current blocking SLO pass|complete bound evidence"
                )

    def test_unknown_or_estimated_budget_event_confidence_fails_without_write(self) -> None:
        for usage_confidence, cost_confidence in (
            ("unknown", "known"),
            ("estimated", "known"),
            ("known", "estimated"),
            ("known", "unknown"),
        ):
            with self.subTest(usage=usage_confidence, cost=cost_confidence):
                self._reset_database()
                self._seed_valid_fixture()
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    if cost_confidence == "unknown":
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(
                                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                                "model,endpoint_binding_id,capability_class,cost_registry_id,"
                                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                                "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                                "VALUES('budget-event','budget-event-idem','budget-event-dedupe',"
                                "1,'run','transition','provider','model','endpoint','capability',"
                                "'cost-row','effective','cost-hash',?,'consume',1,?,'test',"
                                "'now',2000)",
                                (cost_confidence, usage_confidence),
                            )
                    else:
                        connection.execute(
                            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                            "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                            "model,endpoint_binding_id,capability_class,cost_registry_id,"
                            "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                            "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                            "VALUES('budget-event','budget-event-idem','budget-event-dedupe',"
                            "1,'run','transition','provider','model','endpoint','capability',"
                            "'cost-row','effective','cost-hash',?,'consume',1,?,'test',"
                            "'now',2000)",
                            (cost_confidence, usage_confidence),
                        )
                if cost_confidence == "unknown":
                    self._promote(observation_id="schema-blocked-unknown-cost")
                else:
                    self._assert_promotion_fails_without_write(
                        "current blocking SLO pass|complete bound evidence"
                    )

    def test_unknown_or_estimated_final_settlement_confidence_fails_without_write(self) -> None:
        for usage_confidence, cost_confidence in (
            ("unknown", "known"),
            ("estimated", "known"),
            ("known", "estimated"),
        ):
            with self.subTest(usage=usage_confidence, cost=cost_confidence):
                self._reset_database()
                self._seed_valid_fixture(cost_confidence=cost_confidence)
                if usage_confidence == "unknown":
                    with self.assertRaises(sqlite3.IntegrityError):
                        self._seed_completed_spawn_and_settlement(
                            usage_confidence=usage_confidence,
                            cost_confidence=cost_confidence,
                        )
                    self._promote(observation_id="schema-blocked-unknown-settlement")
                else:
                    self._seed_completed_spawn_and_settlement(
                        usage_confidence=usage_confidence,
                        cost_confidence=cost_confidence,
                    )
                    self._assert_promotion_fails_without_write(
                        "current blocking SLO pass|complete bound evidence"
                    )

    def test_estimated_model_cost_registry_confidence_fails_without_write(self) -> None:
        self._seed_valid_fixture(cost_confidence="estimated")
        self._assert_promotion_fails_without_write(
            "current blocking SLO pass|complete bound evidence"
        )

    def test_missing_or_stale_slo_audit_fails_without_write(self) -> None:
        for statement in (
            "DELETE FROM slo_audits WHERE query_name='Duplicate live dispatch blocked'",
            "UPDATE slo_audits SET gate_run_id='wrong-gate' "
            "WHERE query_name='Duplicate live dispatch blocked'",
        ):
            with self.subTest(statement=statement):
                self._reset_database()
                self._seed_valid_fixture()
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    with self.assertRaises(sqlite3.Error):
                        connection.execute(statement)
                # The immutable audit row blocks stale mutation directly; prove promotion
                # still succeeds after the failed tamper, then remove a non-pass row by
                # rebuilding without SLOs below.
                self._promote(observation_id="tamper-proof")

        self._reset_database()
        self._seed_valid_fixture(seed_slo_audits=False)
        self._assert_promotion_fails_without_write(
            "current blocking SLO pass|complete bound evidence"
        )

    def test_later_failing_slo_audit_blocks_stale_pass_promotion(self) -> None:
        self._seed_valid_fixture()
        schema_version, migration_sha256 = self._current_schema_identity()
        contract = SLO_QUERY_CONTRACTS[0]
        with closing(sqlite3.connect(self.database)) as connection, connection:
            latest_epoch = connection.execute(
                "SELECT MAX(run_at_epoch_ms) FROM slo_audits WHERE query_name=?",
                (contract.query_name,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,run_at,run_at_epoch_ms) VALUES("
                "'slo-latest-fail',?,?,?,?,1,'fail','fail','fail','audit-later',?)",
                (
                    contract.query_name,
                    schema_version,
                    migration_sha256,
                    slo_query_hash(contract.sql_text),
                    int(latest_epoch) + 1000,
                ),
            )

        self._assert_promotion_fails_without_write(
            "current blocking SLO pass|complete bound evidence"
        )

    def test_current_slo_failure_after_cached_audits_blocks_promotion(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            latest_epoch = connection.execute(
                "SELECT MAX(run_at_epoch_ms) FROM slo_audits"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                "model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('post-audit-consume',"
                "'post-audit-consume-idem','post-audit-consume-dedupe',1,'run',"
                "'transition','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','consume',999,999,'known','test',"
                "'now',?)",
                (int(latest_epoch) + 1000,),
            )

        self._assert_promotion_fails_without_write("current blocking SLO pass")

    def test_current_external_rpc_slo_failure_after_cached_audits_blocks_promotion(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            latest_epoch = connection.execute(
                "SELECT MAX(run_at_epoch_ms) FROM slo_audits"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,client_request_id,idempotency_key,metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'post-audit-intent','run','transition','allow_lease_release',"
                "'post-audit-client','post-audit-idem','{}','pending','later',?)",
                (int(latest_epoch) + 1000,),
            )

        self._assert_promotion_fails_without_write("current blocking SLO pass")

    def test_predicate_plugin_metadata_is_frozen_before_trust_promotion(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "predicate plugin metadata"):
                connection.execute(
                    "UPDATE predicate_plugins SET schema_hash='mutated-schema' "
                    "WHERE predicate_plugin_hash='plugin'"
                )

        self._promote()

    def test_fake_later_schema_or_slo_identity_blocks_trust_promotion(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                "VALUES(99,'fake_future',?,'now')",
                (_sha("fake-future-migration"),),
            )
            connection.execute(
                "INSERT INTO slo_queries(query_name,schema_version,migration_sha256,"
                "query_hash,sql_text,empty_db_expected_status,fixture_db_expected_status,"
                "created_at) VALUES('fake-slo',99,?,?,?, 'pass','pass','now')",
                (_sha("fake-future-migration"), _sha("fake-slo"), "SELECT 1 WHERE 0"),
            )

        self._assert_promotion_fails_without_write(
            "database schema verification failed|current blocking SLO pass|complete bound evidence"
        )

    def test_trust_scope_and_severity_must_match_bound_evidence(self) -> None:
        for field, value in (("scope", "global"), ("severity", "R2")):
            with self.subTest(field=field):
                self._reset_database()
                self._seed_valid_fixture()
                self._assert_promotion_fails_without_write(
                    "complete bound evidence", **{field: value}
                )

    def test_effective_group_must_match_bound_evidence(self) -> None:
        self._seed_valid_fixture()
        with self.assertRaisesRegex(TrustPromotionError, "effective_group_id"):
            promote_trust(
                self.database,
                observation_id="wrong-group",
                scope="workflow",
                severity="R1",
                effective_group_id="workflow:group",
                run_id="run",
                goal_run_id="goal-run",
                evidence_hash=self.evidence_hash,
                bounded_at="bounded-now",
                created_at="created-now",
            )
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(self._trust_count(connection), 0)

    def test_active_trust_can_only_be_invalidated_fail_closed(self) -> None:
        self._seed_valid_fixture()
        self._promote()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "active trust"):
                connection.execute(
                    "UPDATE trust_observations SET status='stale' "
                    "WHERE observation_id='trust'"
                )
            connection.execute(
                "UPDATE trust_observations SET invalidated_at='invalid-now' "
                "WHERE observation_id='trust'"
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_observations "
                    "WHERE observation_id='trust' AND invalidated_at IS NULL"
                ).fetchone()[0],
                0,
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "reactivated"):
                connection.execute(
                    "UPDATE trust_observations SET invalidated_at=NULL "
                    "WHERE observation_id='trust'"
            )

    def test_post_promotion_slo_schema_and_registry_changes_require_invalidation(self) -> None:
        self._seed_valid_fixture()
        self._seed_bound_runtime_rows()
        self._promote()
        schema_version, migration_sha256 = self._current_schema_identity()
        contract = SLO_QUERY_CONTRACTS[0]
        with closing(sqlite3.connect(self.database)) as connection, connection:
            latest_epoch = connection.execute(
                "SELECT MAX(run_at_epoch_ms) FROM slo_audits"
            ).fetchone()[0]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "SLO audit changes"):
                connection.execute(
                    "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                    "migration_sha256,query_hash,result_count,status,empty_db_status,"
                    "fixture_db_status,run_at,run_at_epoch_ms) VALUES("
                    "'post-trust-slo-fail',?,?,?,?,1,'fail','fail','fail','later',?)",
                    (
                        contract.query_name,
                        schema_version,
                        migration_sha256,
                        slo_query_hash(contract.sql_text),
                        int(latest_epoch) + 1000,
                    ),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "schema changes"):
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                    "VALUES(99,'future',?,'now')",
                    (_sha("future-migration"),),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "SLO registry changes"):
                connection.execute(
                    "INSERT INTO slo_queries(query_name,schema_version,migration_sha256,"
                    "query_hash,sql_text,empty_db_expected_status,"
                    "fixture_db_expected_status,created_at) VALUES("
                    "'future-slo',?,?,?,?,?,?,?)",
                    (
                        schema_version,
                        migration_sha256,
                        _sha("future-slo"),
                        "SELECT 1 WHERE 0",
                        "pass",
                        "pass",
                        "now",
                    ),
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "external RPC intent changes"
            ):
                connection.execute(
                    "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                    "rpc_kind,client_request_id,idempotency_key,metadata_json,state,"
                    "requested_at,requested_at_epoch_ms) VALUES("
                    "'post-trust-intent','run','transition','allow_lease_release',"
                    "'post-trust-client','post-trust-idem','{}','pending','later',2000)"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "external RPC intent changes"
            ):
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute(
                    "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                    "rpc_kind,client_request_id,idempotency_key,metadata_json,state,"
                    "requested_at,requested_at_epoch_ms) VALUES("
                    "'post-trust-unbound-intent','missing-run','transition',"
                    "'allow_lease_release','post-trust-unbound-client',"
                    "'post-trust-unbound-idem','{}','pending','later',2000)"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "session changes"):
                connection.execute(
                    "INSERT INTO sessions(session_id,spawn_request_id,run_id,"
                    "transition_id,phase,agent_id,client_request_id,"
                    "spawn_idempotency_key,session_key,task_digest,state,"
                    "spawned_at) VALUES('post-trust-orphan-session',"
                    "'missing-spawn','missing-run','transition','phase','agent',"
                    "'post-trust-orphan-client','post-trust-orphan-idem',"
                    "'post-trust-orphan-session-key','task','completed','later')"
                )
            connection.execute("PRAGMA foreign_keys=ON")
            self._assert_integrity_error_without_authority_or_trust_write(
                connection,
                "lease changes",
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                "'post-trust-lease','run','phase','transition','agent','requester',"
                "'acquire_pending','post-trust-lease-client','post-trust-acquire',"
                "60000,'later',2000)",
            )
            connection.execute("PRAGMA foreign_keys=OFF")
            for label, statement, message in (
                (
                    "unbound lease insert",
                    "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                    "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                    "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                    "'post-trust-unbound-lease','missing-run','phase','transition',"
                    "'agent','requester','acquire_pending','post-trust-unbound-lease-client',"
                    "'post-trust-unbound-acquire',60000,'later',2000)",
                    "lease changes",
                ),
                (
                    "unbound spawn request insert",
                    "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                    "transition_id,client_request_id,spawn_idempotency_key,task_digest,"
                    "state,created_at,updated_at) VALUES('post-trust-unbound-spawn',"
                    "'missing-run','phase','agent','transition','client','spawn-idem',"
                    "'task','pending','now','now')",
                    "spawn request changes",
                ),
                (
                    "unbound session insert",
                    "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
                    "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
                    "task_digest,state,spawned_at,completed_at) VALUES("
                    "'post-trust-unbound-session','spawn','missing-run','transition',"
                    "'phase','agent','client','spawn-idem','session-key','task',"
                    "'completed','spawned-now','completed-now')",
                    "session changes",
                ),
                (
                    "unbound lease update",
                    "UPDATE leases SET run_id='missing-run' WHERE lease_id='pretrust-lease'",
                    "lease changes",
                ),
                (
                    "unbound spawn request update",
                    "UPDATE spawn_requests SET run_id='missing-run' "
                    "WHERE spawn_request_id='pretrust-spawn'",
                    "spawn request changes",
                ),
                (
                    "unbound session update",
                    "UPDATE sessions SET run_id='missing-run' WHERE session_id='pretrust-session'",
                    "session changes",
                ),
            ):
                with self.subTest(label=label):
                    self._assert_integrity_error_without_authority_or_trust_write(
                        connection, message, statement
                    )
            connection.execute("PRAGMA foreign_keys=ON")
            self._assert_integrity_error_without_authority_or_trust_write(
                connection,
                "run changes",
                "UPDATE runs SET state='gate_passed' WHERE run_id='run'",
            )
            self._assert_integrity_error_without_authority_or_trust_write(
                connection,
                "run changes",
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at) VALUES('post-trust-run','post-trust-prepare',"
                "'workflow','file_authority','finalized','R2','R2','now','now')",
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "predicate plugin metadata"
            ):
                connection.execute(
                    "UPDATE predicate_plugins SET schema_hash='mutated-after-trust' "
                    "WHERE predicate_plugin_hash='plugin'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "predicate plugin metadata"
            ):
                connection.execute(
                    "UPDATE predicate_plugins SET predicate_plugin_hash='plugin-mutated' "
                    "WHERE predicate_plugin_hash='plugin'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "goal manifest changes"
            ):
                connection.execute(
                    "UPDATE goal_manifests SET goal_id='goal-mutated' "
                    "WHERE goal_id='goal'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "risk assessment changes"
            ):
                connection.execute(
                    "DELETE FROM risk_assessments WHERE transition_id='transition'"
                )
            connection.execute(
                "UPDATE trust_observations SET invalidated_at='invalid-now' "
                "WHERE observation_id='trust'"
            )
            connection.execute(
                "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                "migration_sha256,query_hash,result_count,status,empty_db_status,"
                "fixture_db_status,run_at,run_at_epoch_ms) VALUES("
                "'post-invalidated-slo-fail',?,?,?,?,1,'fail','fail','fail','later',?)",
                (
                    contract.query_name,
                    schema_version,
                    migration_sha256,
                    slo_query_hash(contract.sql_text),
                    int(latest_epoch) + 1000,
                ),
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,client_request_id,idempotency_key,metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'post-invalidated-intent','run','transition','allow_lease_release',"
                "'post-invalidated-client','post-invalidated-idem','{}','pending',"
                "'later',2000)"
            )

    def test_post_promotion_budget_evidence_changes_require_invalidation(self) -> None:
        self._seed_valid_fixture()
        self._seed_sibling_run()
        self._promote()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "budget event changes"):
                connection.execute(
                    "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                    "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                    "model,endpoint_binding_id,capability_class,cost_registry_id,"
                    "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                    "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                    "VALUES('post-trust-unknown','post-trust-unknown-idem',"
                    "'post-trust-unknown-dedupe',"
                    "1,'run','transition','provider','model','endpoint','capability',"
                    "'cost-row','effective','cost-hash','known','consume',1,'unknown',"
                    "'test','now',2000)"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "budget event changes"):
                connection.execute(
                    "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                    "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                    "model,endpoint_binding_id,capability_class,cost_registry_id,"
                    "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                    "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                    "VALUES('post-trust-known','post-trust-known-idem',"
                    "'post-trust-known-dedupe',"
                    "1,'run','transition','provider','model','endpoint','capability',"
                    "'cost-row','effective','cost-hash','known','consume',1,'known',"
                    "'test','now',2000)"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "budget event changes"):
                connection.execute(
                    "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                    "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                    "model,endpoint_binding_id,capability_class,cost_registry_id,"
                    "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                    "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                    "VALUES('post-trust-sibling-known','post-trust-sibling-known-idem',"
                    "'post-trust-sibling-known-dedupe',"
                    "1,'sibling-run','sibling-transition','provider','model','endpoint',"
                    "'capability','cost-row','effective','cost-hash','known','consume',"
                    "1,'known','test','now',2000)"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "selected budget changes"):
                connection.execute(
                    "INSERT INTO run_budgets(run_id,workflow,capability_class,"
                    "selected_provider,selected_model,selected_endpoint_binding_id,"
                    "selected_cost_registry_id,selected_cost_effective_at,"
                    "selected_cost_registry_hash,selected_cost_confidence,"
                    "selected_reserve_transition_id,time_budget_seconds,"
                    "input_token_budget,output_token_budget,cost_budget_microusd,"
                    "retry_budget,human_attention_budget,usage_confidence,updated_at) "
                    "VALUES('sibling-run','workflow','capability','provider','model',"
                    "'endpoint','cost-row','effective','cost-hash','known',"
                    "'sibling-transition',10,10,10,10,1,1,'known','now')"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "selected budget changes"):
                connection.execute(
                    "UPDATE run_budgets SET selected_provider='other-provider' "
                    "WHERE run_id='run'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "settlement changes"):
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute(
                    "INSERT INTO budget_settlements(settlement_id,"
                    "settlement_idempotency_key,settlement_dedupe_hash,run_id,"
                    "transition_id,spawn_request_id,provider,model,"
                    "endpoint_binding_id,capability_class,cost_registry_id,"
                    "cost_effective_at,cost_registry_hash,cost_confidence,"
                    "actual_time_seconds,actual_input_tokens,actual_output_tokens,"
                    "actual_cost_microusd,actual_retry_units,"
                    "actual_human_attention_units,released_time_seconds,"
                    "released_input_tokens,released_output_tokens,"
                    "released_cost_microusd,released_retry_units,"
                    "released_human_attention_units,usage_confidence,source,"
                    "created_at,created_at_epoch_ms,clock_context_id) VALUES("
                    "'post-trust-sibling-settlement','post-trust-sibling-settlement-idem',"
                    "'post-trust-sibling-settlement-dedupe','sibling-run',"
                    "'sibling-transition','missing-spawn','provider','model','endpoint',"
                    "'capability','cost-row','effective','cost-hash','known',"
                    "0,0,0,0,0,0,0,0,0,0,0,0,'known','test','now',2000,'clock')"
                )
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "UPDATE trust_observations SET invalidated_at='invalid-now' "
                "WHERE observation_id='trust'"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                "model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,usage_confidence,source,created_at,created_at_epoch_ms) "
                "VALUES('post-invalidated-unknown','post-invalidated-unknown-idem',"
                "'post-invalidated-unknown-dedupe',"
                "1,'run','transition','provider','model','endpoint','capability',"
                "'cost-row','effective','cost-hash','known','consume',1,'unknown',"
                "'test','now',2000)"
            )
            self.assertEqual(
                connection.execute(
                    "SELECT usage_confidence FROM budget_events "
                    "WHERE budget_event_id='post-invalidated-unknown'"
                ).fetchone()[0],
                "unknown",
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,"
                "selected_provider,selected_model,selected_endpoint_binding_id,"
                "selected_cost_registry_id,selected_cost_effective_at,"
                "selected_cost_registry_hash,selected_cost_confidence,"
                "selected_reserve_transition_id,time_budget_seconds,"
                "input_token_budget,output_token_budget,cost_budget_microusd,"
                "retry_budget,human_attention_budget,usage_confidence,updated_at) "
                "VALUES('sibling-run','workflow','capability','provider','model',"
                "'endpoint','cost-row','effective','cost-hash','known',"
                "'sibling-transition',10,10,10,10,1,1,'known','now')"
            )

    def test_wrong_run_self_verifier_db_authority_and_stale_clock_fail(self) -> None:
        mutations = (
            ("wrong run", "UPDATE goal_runs SET run_id='other-run' WHERE goal_run_id='goal-run'"),
            ("self verifier", "UPDATE judge_verifier_runs SET verifier_run_id='run' WHERE verifier_run_id='verifier'"),
            ("db authority", "UPDATE workflow_authority SET mode='db_authority_canary',cutover_approved_by='a',cutover_evidence_hash=?,rollback_deadline='d',last_parity_audit_hash=?,open_file_authority_runs=0 WHERE workflow='workflow'"),
            ("stale clock", "UPDATE gate_clock_context SET trusted_clock_source_hash=? WHERE clock_context_id='clock'"),
        )
        for label, statement in mutations:
            with self.subTest(label=label):
                self._reset_database()
                self._seed_valid_fixture()
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    if label == "db authority":
                        with self.assertRaises(sqlite3.Error):
                            connection.execute(statement, (_sha("cutover"), _sha("parity")))
                    elif label == "stale clock":
                        with self.assertRaises(sqlite3.Error):
                            connection.execute(statement, ("a" * 64,))
                    else:
                        with self.assertRaises(sqlite3.Error):
                            connection.execute(statement)
                self._promote(observation_id=f"tamper-proof-{label.replace(' ', '-')}")

    def test_changed_evidence_artifact_fails_without_write(self) -> None:
        self._seed_valid_fixture()
        self.evidence_path.write_bytes(b'{"trust":false}\n')

        self._assert_promotion_fails_without_write("evidence artifact")

    def test_direct_sql_bypass_and_malformed_bundle_hash_are_rejected(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            before = self._trust_count(connection)
            with self.assertRaises(sqlite3.Error):
                connection.execute(
                    "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                    "effective_group_id,usage_confidence,bounded_at,created_at) "
                    "VALUES('direct','workflow','R1','promoted','group','known','now','now')"
                )
            _register_migration_functions(connection)
            row = connection.execute(
                "SELECT * FROM trust_promotion_bound_evidence WHERE run_id='run'"
            ).fetchone()
            columns = [item[0] for item in connection.execute(
                "SELECT * FROM trust_promotion_bound_evidence WHERE 0"
            ).description]
            binding = dict(zip(columns, row))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "complete bound evidence"):
                connection.execute(
                    "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                    "effective_group_id,verifier_run_id,gate_run_id,usage_confidence,"
                    "bounded_at,created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
                    "transition_id,approval_id,approval_hash,schema_version,migration_sha256,"
                    "blocking_slo_query_count,blocking_slo_pass_audit_count,"
                    "blocking_slo_bundle_hash,clock_context_id,gate_clock_epoch_ms,"
                    "trusted_clock_source_hash,run_authority_mode,workflow_authority_mode,"
                    "selected_cost_registry_id,selected_cost_registry_hash,cost_confidence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "direct-shaped",
                        "workflow",
                        "R1",
                        "promoted",
                        "group",
                        binding["verifier_run_id"],
                        binding["gate_run_id"],
                        "known",
                        "now",
                        "now",
                        "run",
                        "goal-run",
                        self.evidence_hash,
                        "run",
                        binding["transition_id"],
                        binding["approval_id"],
                        binding["approval_hash"],
                        binding["schema_version"],
                        binding["migration_sha256"],
                        binding["current_slo_query_count"],
                        binding["current_slo_query_count"],
                        "f" * 64,
                        binding["clock_context_id"],
                        binding["gate_clock_epoch_ms"],
                        binding["trusted_clock_source_hash"],
                        binding["run_authority_mode"],
                        binding["workflow_authority_mode"],
                        binding["selected_cost_registry_id"],
                        binding["selected_cost_registry_hash"],
                        "known",
                    ),
                )
            bundle_hash = _trust_binding_hash(
                "run",
                "goal-run",
                self.evidence_hash,
                binding["verifier_run_id"],
                binding["gate_run_id"],
                binding["schema_version"],
                binding["migration_sha256"],
                binding["current_slo_query_count"],
            )
            connection.execute(
                "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                "VALUES(99,'fake_future',?,'now')",
                (_sha("fake-future-migration"),),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "complete bound evidence"):
                connection.execute(
                    "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                    "effective_group_id,verifier_run_id,gate_run_id,usage_confidence,"
                    "bounded_at,created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
                    "transition_id,approval_id,approval_hash,schema_version,migration_sha256,"
                    "blocking_slo_query_count,blocking_slo_pass_audit_count,"
                    "blocking_slo_bundle_hash,clock_context_id,gate_clock_epoch_ms,"
                    "trusted_clock_source_hash,run_authority_mode,workflow_authority_mode,"
                    "selected_cost_registry_id,selected_cost_registry_hash,cost_confidence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "direct-fake-schema",
                        "workflow",
                        "R1",
                        "promoted",
                        bundle_hash,
                        binding["verifier_run_id"],
                        binding["gate_run_id"],
                        "known",
                        "now",
                        "now",
                        "run",
                        "goal-run",
                        self.evidence_hash,
                        "run",
                        binding["transition_id"],
                        binding["approval_id"],
                        binding["approval_hash"],
                        binding["schema_version"],
                        binding["migration_sha256"],
                        binding["current_slo_query_count"],
                        binding["current_slo_query_count"],
                        bundle_hash,
                        binding["clock_context_id"],
                        binding["gate_clock_epoch_ms"],
                        binding["trusted_clock_source_hash"],
                        binding["run_authority_mode"],
                        binding["workflow_authority_mode"],
                        binding["selected_cost_registry_id"],
                        binding["selected_cost_registry_hash"],
                        "known",
                    ),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "complete bound evidence"):
                connection.execute(
                    "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                    "effective_group_id,verifier_run_id,gate_run_id,usage_confidence,"
                    "bounded_at,created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
                    "transition_id,approval_id,approval_hash,schema_version,migration_sha256,"
                    "blocking_slo_query_count,blocking_slo_pass_audit_count,"
                    "blocking_slo_bundle_hash,clock_context_id,gate_clock_epoch_ms,"
                    "trusted_clock_source_hash,run_authority_mode,workflow_authority_mode,"
                    "selected_cost_registry_id,selected_cost_registry_hash,cost_confidence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "direct-wrong-group",
                        "workflow",
                        "R1",
                        "promoted",
                        "other-group",
                        binding["verifier_run_id"],
                        binding["gate_run_id"],
                        "known",
                        "now",
                        "now",
                        "run",
                        "goal-run",
                        self.evidence_hash,
                        "run",
                        binding["transition_id"],
                        binding["approval_id"],
                        binding["approval_hash"],
                        binding["schema_version"],
                        binding["migration_sha256"],
                        binding["current_slo_query_count"],
                        binding["current_slo_query_count"],
                        bundle_hash,
                        binding["clock_context_id"],
                        binding["gate_clock_epoch_ms"],
                        binding["trusted_clock_source_hash"],
                        binding["run_authority_mode"],
                        binding["workflow_authority_mode"],
                        binding["selected_cost_registry_id"],
                        binding["selected_cost_registry_hash"],
                        "known",
                    ),
                )
            self.evidence_path.write_bytes(b'{"trust":"tampered"}\n')
            with self.assertRaisesRegex(sqlite3.IntegrityError, "complete bound evidence"):
                connection.execute(
                    "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                    "effective_group_id,verifier_run_id,gate_run_id,usage_confidence,"
                    "bounded_at,created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
                    "transition_id,approval_id,approval_hash,schema_version,migration_sha256,"
                    "blocking_slo_query_count,blocking_slo_pass_audit_count,"
                    "blocking_slo_bundle_hash,clock_context_id,gate_clock_epoch_ms,"
                    "trusted_clock_source_hash,run_authority_mode,workflow_authority_mode,"
                    "selected_cost_registry_id,selected_cost_registry_hash,cost_confidence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "direct-stale-artifact",
                        "workflow",
                        "R1",
                        "promoted",
                        bundle_hash,
                        binding["verifier_run_id"],
                        binding["gate_run_id"],
                        "known",
                        "now",
                        "now",
                        "run",
                        "goal-run",
                        self.evidence_hash,
                        "run",
                        binding["transition_id"],
                        binding["approval_id"],
                        binding["approval_hash"],
                        binding["schema_version"],
                        binding["migration_sha256"],
                        binding["current_slo_query_count"],
                        binding["current_slo_query_count"],
                        bundle_hash,
                        binding["clock_context_id"],
                        binding["gate_clock_epoch_ms"],
                        binding["trusted_clock_source_hash"],
                        binding["run_authority_mode"],
                        binding["workflow_authority_mode"],
                        binding["selected_cost_registry_id"],
                        binding["selected_cost_registry_hash"],
                        "known",
                    ),
                )
            self.assertEqual(self._trust_count(connection), before)

    def test_direct_sql_rejects_stale_budget_audits_after_budget_input_drift(self) -> None:
        self._seed_valid_fixture()
        with closing(sqlite3.connect(self.database)) as connection:
            _register_migration_functions(connection)
            binding = self._trust_binding(connection)
            latest_epoch = connection.execute(
                "SELECT MAX(run_at_epoch_ms) FROM slo_audits"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,"
                "model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('post-audit-reserve',"
                "'post-audit-reserve-idem','post-audit-reserve-dedupe',1,'run',"
                "'transition','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','reserve',1,1,'known','test','now',?)",
                (int(latest_epoch) + 1000,),
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=1,"
                "reserved_cost_microusd=1 WHERE run_id='run'"
            )
            bundle_hash = _trust_binding_hash(
                "run",
                "goal-run",
                self.evidence_hash,
                binding["verifier_run_id"],
                binding["gate_run_id"],
                binding["schema_version"],
                binding["migration_sha256"],
                binding["current_slo_query_count"],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "complete bound evidence"):
                self._insert_direct_trust(connection, "direct-stale-budget", binding, bundle_hash)

    def test_migration_aborts_on_active_legacy_trust_rows(self) -> None:
        legacy = Path(self.temporary.name) / "legacy-minimal.db"
        with closing(sqlite3.connect(legacy)) as connection:
            connection.execute(
                "CREATE TABLE trust_observations ("
                "observation_id TEXT PRIMARY KEY,scope TEXT NOT NULL,"
                "severity TEXT NOT NULL,status TEXT NOT NULL,"
                "effective_group_id TEXT NOT NULL,verifier_run_id TEXT,"
                "gate_run_id TEXT,usage_confidence TEXT NOT NULL,"
                "bounded_at TEXT,invalidated_at TEXT,created_at TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO trust_observations(observation_id,scope,severity,status,"
                "effective_group_id,usage_confidence,created_at) VALUES("
                "'legacy','workflow','R1','promoted','group','known','now')"
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "legacy_active_unbound"):
                connection.executescript(
                    (repository_root() / "migrations/0013_trust_promotion_binding.sql")
                    .read_text(encoding="utf-8")
                )

    def _seed_valid_fixture(
        self, *, seed_slo_audits: bool = True, cost_confidence: str = "known"
    ) -> None:
        apply_migrations(self.database)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('workflow','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'run','prepare','workflow','file_authority','candidate','R1','R1',"
                "'now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,risk_dominance,idempotency_key,guard_version_before,"
                "created_at) VALUES('transition','run','prepared','gate_passed','gate',"
                "'mutate','artifact','artifact-1',?,'repo','R1','transition-idem',"
                "0,'now')",
                (_sha("artifact"),),
            )
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,"
                "registry_row_hash) VALUES('cost-row','provider','model','endpoint',"
                "'capability',1,1,?,'effective','cost-hash')",
                (cost_confidence,),
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,"
                "selected_provider,selected_model,selected_endpoint_binding_id,"
                "selected_cost_registry_id,selected_cost_effective_at,"
                "selected_cost_registry_hash,selected_cost_confidence,"
                "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
                "output_token_budget,cost_budget_microusd,retry_budget,"
                "human_attention_budget,usage_confidence,updated_at) VALUES("
                "'run','workflow','capability','provider','model','endpoint',"
                "'cost-row','effective','cost-hash',?,'transition',10,10,10,"
                "10,1,1,'known','now')",
                (cost_confidence,),
            )
        self._record_pass_gate()
        record_goal_run(
            self.database,
            goal_run_id="goal-run",
            goal_id="goal",
            run_id="run",
            severity="R1",
            state="open",
            predicate_plugin_hash="plugin",
            evidence_hash=self.evidence_hash,
            created_at="now",
            created_at_epoch_ms=int(time.time() * 1000),
        )
        if seed_slo_audits:
            self._seed_slo_pass_audits()
        self._chmod_database_private(self.database)

    def _record_pass_gate(self) -> None:
        gate_query_hash, migration_sha256 = self._current_gate_identity()
        now_epoch_ms = int(time.time() * 1000)
        bound_by = "trust-pass-gate"
        record_approval_pass_gate(
            self.database,
            run_id="run",
            transition_id="transition",
            gate_run_id="gate",
            clock_context_id="clock",
            gate_nonce="nonce",
            now_epoch_ms=now_epoch_ms,
            bound_by=bound_by,
            trusted_clock_source_hash=_clock_hash(now_epoch_ms, bound_by),
            gate_version="pass-gate-v1",
            gate_query_hash=gate_query_hash,
            migration_sha256=migration_sha256,
            approval=ApprovalGrant(
                approval_id="approval",
                approver="erwin",
                channel="telegram",
                source_message_digest=_sha("source"),
                approval_text_digest=_sha("text"),
                approved_risk_ceiling="R1",
                expires_at_epoch_ms=now_epoch_ms + 3_600_000,
                approved_at="approved-now",
            ),
            verifier=VerifierProof(
                verifier_run_id="verifier",
                worker_agent_id="writer",
                verifier_agent_id="security",
                provider="openai",
                model="gpt-5",
                prompt_hash=_sha("prompt"),
                context_hash=_sha("context"),
                independence_proof={"reviewer_session": "phase-c"},
                completed_at="verified-now",
            ),
            evidence=GateEvidence(
                path=self.evidence_path.relative_to(repository_root()).as_posix(),
                sha256=self.evidence_hash,
                size_bytes=len(self.evidence_content),
                content_type="application/json",
                redaction_status="none",
                captured_at="captured-now",
            ),
            completed_at="completed-now",
            created_at="created-now",
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,"
                "backend,schema_hash,sandbox_required,sandbox_enforced,created_at) "
                "VALUES('plugin','safe','1','agentic_predicate_inproc_v1','schema',"
                "0,1,'now')"
            )
            connection.execute(
                "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
                "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
                "updated_at) VALUES('goal','owner','R1','manifest','plugin',"
                "'agentic_predicate_inproc_v1',0,1,'now','now')"
            )

    def _seed_slo_pass_audits(self) -> None:
        schema_version, migration_sha256 = self._current_schema_identity()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            for index, contract in enumerate(SLO_QUERY_CONTRACTS, start=1):
                connection.execute(
                    "INSERT INTO slo_audits(slo_audit_id,query_name,schema_version,"
                    "migration_sha256,query_hash,result_count,status,empty_db_status,"
                    "fixture_db_status,evidence_hash,evidence_run_id,verifier_run_id,"
                    "gate_run_id,run_at,run_at_epoch_ms) VALUES(?,?,?,?,?,0,'pass',"
                    "'pass','pass',?,?,?,?,?,?)",
                    (
                        f"slo-{index}",
                        contract.query_name,
                        schema_version,
                        migration_sha256,
                        slo_query_hash(contract.sql_text),
                        self.evidence_hash,
                        "run",
                        "verifier",
                        "gate",
                        "audit-now",
                        int(time.time() * 1000) + index,
                    ),
                )

    def _seed_sibling_run(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('sibling-run','sibling-prepare','workflow','file_authority',"
                "'candidate','R1','R1','now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,risk_dominance,idempotency_key,guard_version_before,"
                "created_at) VALUES('sibling-transition','sibling-run','prepared',"
                "'candidate','noop','observe','artifact','artifact-2',?,'repo','R1',"
                "'sibling-transition-idem',0,'now')",
                (_sha("sibling-artifact"),),
            )

    def _seed_bound_runtime_rows(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('pretrust-spawn','run','phase','agent',"
                "'transition','client','spawn-idem','task','pending','now','now')"
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES('pretrust-lease','run',"
                "'phase','transition','agent','requester','acquire_pending',"
                "'pretrust-lease-client','pretrust-acquire',60000,'later',2000)"
            )
            connection.execute(
                "UPDATE spawn_requests SET session_key='session-key' "
                "WHERE spawn_request_id='pretrust-spawn'"
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
                "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
                "task_digest,state,spawned_at,completed_at) VALUES('pretrust-session',"
                "'pretrust-spawn','run','transition','phase','agent','client',"
                "'spawn-idem','session-key','task','completed','spawned-now',"
                "'completed-now')"
            )

    def _seed_completed_spawn_and_settlement(
        self, *, usage_confidence: str, cost_confidence: str
    ) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            gate_epoch_ms = int(
                connection.execute(
                    "SELECT now_epoch_ms FROM gate_clock_context "
                    "WHERE clock_context_id='clock'"
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn','run','phase','agent','transition',"
                "'client','spawn-idem','task','pending','now','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES('reserve','reserve-idem',"
                "'reserve-dedupe',1,'run','transition','spawn','provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash',?,"
                "'reserve',1,1,'known','test','now',?)",
                (cost_confidence, gate_epoch_ms - 3),
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=1,"
                "reserved_cost_microusd=1 WHERE run_id='run'"
            )
            connection.execute(
                "UPDATE runs SET state='child_completed' WHERE run_id='run'"
            )
            connection.execute(
                "UPDATE spawn_requests SET session_key='session-key' "
                "WHERE spawn_request_id='spawn'"
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
                "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
                "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
                "'run','transition','phase','agent','client','spawn-idem','session-key',"
                "'task','completed','spawned-now','completed-now')"
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES('lease','run','phase','transition','agent',"
                "'requester','acquire_pending','client-lease','acquire-idem',"
                "'release-idem',60000,'now','later',?)",
                (gate_epoch_ms + 60000,),
            )
            connection.execute(
                "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
                "transition_id,phase,agent_id,requester_agent_id,task_digest,"
                "client_lease_id,acquire_idempotency_key,release_idempotency_key,"
                "spawn_client_request_id,spawn_idempotency_key,reserve_budget_event_id,"
                "created_at) VALUES('spawn','lease','run','transition','phase','agent',"
                "'requester','task','client-lease','acquire-idem','release-idem',"
                "'client','spawn-idem','reserve','now')"
            )
            metadata = (
                '{"run_id":"run","transition_id":"transition",'
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
                "'intent','run','transition','sessions_spawn','spawn','reserve','client',"
                "'spawn-idem','phase','agent','task','v1',?,?,'run','transition',"
                "'client','spawn-idem','phase','agent','task','accepted','session-key',"
                "'requested-now',?,'accepted-now',?)",
                (metadata, metadata, gate_epoch_ms - 2, gate_epoch_ms - 1),
            )
            connection.execute(
                "UPDATE spawn_requests SET state='completed' "
                "WHERE spawn_request_id='spawn'"
            )
            connection.execute(
                "INSERT INTO budget_settlements(settlement_id,"
                "settlement_idempotency_key,settlement_dedupe_hash,run_id,"
                "transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
                "cost_confidence,actual_time_seconds,actual_input_tokens,"
                "actual_output_tokens,actual_cost_microusd,actual_retry_units,"
                "actual_human_attention_units,released_time_seconds,"
                "released_input_tokens,released_output_tokens,released_cost_microusd,"
                "released_retry_units,released_human_attention_units,usage_confidence,"
                "source,created_at,created_at_epoch_ms,clock_context_id) VALUES("
                "'settlement','settlement-idem','settlement-dedupe','run','transition',"
                "'spawn','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash',?,0,0,0,0,0,0,0,1,0,1,0,0,?,"
                "'terminal-usage-import','settled-now',?,'clock')",
                (cost_confidence, usage_confidence, gate_epoch_ms),
            )

    def _current_gate_identity(self) -> tuple[str, str]:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT q.query_hash,q.migration_sha256 FROM schema_migrations m "
                "JOIN slo_queries q ON q.schema_version=m.version "
                "AND q.migration_sha256=m.sha256 "
                "WHERE q.query_name='Completion gate before done for R2+' "
                "ORDER BY m.version DESC LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        return str(row[0]), str(row[1])

    def _current_schema_identity(self) -> tuple[int, str]:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT version,sha256 FROM schema_migrations "
                "ORDER BY version DESC LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        return int(row[0]), str(row[1])

    def _promote(
        self,
        *,
        observation_id: str = "trust",
        scope: str = "workflow",
        severity: str = "R1",
    ):
        return promote_trust(
            self.database,
            observation_id=observation_id,
            scope=scope,
            severity=severity,
            effective_group_id=self._expected_effective_group_id(),
            run_id="run",
            goal_run_id="goal-run",
            evidence_hash=self.evidence_hash,
            bounded_at="bounded-now",
            created_at="created-now",
        )

    def _expected_effective_group_id(self) -> str:
        schema_version, migration_sha256 = self._current_schema_identity()
        return _trust_binding_hash(
            "run",
            "goal-run",
            self.evidence_hash,
            "verifier",
            "gate",
            schema_version,
            migration_sha256,
            len(SLO_QUERY_CONTRACTS),
        )

    def _trust_binding(self, connection: sqlite3.Connection) -> dict[str, object]:
        row = connection.execute(
            "SELECT * FROM trust_promotion_bound_evidence WHERE run_id='run'"
        ).fetchone()
        self.assertIsNotNone(row)
        columns = [
            item[0]
            for item in connection.execute(
                "SELECT * FROM trust_promotion_bound_evidence WHERE 0"
            ).description
        ]
        return dict(zip(columns, row))

    def _insert_direct_trust(
        self,
        connection: sqlite3.Connection,
        observation_id: str,
        binding: dict[str, object],
        bundle_hash: str,
    ) -> None:
        connection.execute(
            "INSERT INTO trust_observations(observation_id,scope,severity,status,"
            "effective_group_id,verifier_run_id,gate_run_id,usage_confidence,"
            "bounded_at,created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
            "transition_id,approval_id,approval_hash,schema_version,migration_sha256,"
            "blocking_slo_query_count,blocking_slo_pass_audit_count,"
            "blocking_slo_bundle_hash,clock_context_id,gate_clock_epoch_ms,"
            "trusted_clock_source_hash,run_authority_mode,workflow_authority_mode,"
            "selected_cost_registry_id,selected_cost_registry_hash,cost_confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation_id,
                "workflow",
                "R1",
                "promoted",
                bundle_hash,
                binding["verifier_run_id"],
                binding["gate_run_id"],
                "known",
                "now",
                "now",
                "run",
                "goal-run",
                self.evidence_hash,
                "run",
                binding["transition_id"],
                binding["approval_id"],
                binding["approval_hash"],
                binding["schema_version"],
                binding["migration_sha256"],
                binding["current_slo_query_count"],
                binding["current_slo_query_count"],
                bundle_hash,
                binding["clock_context_id"],
                binding["gate_clock_epoch_ms"],
                binding["trusted_clock_source_hash"],
                binding["run_authority_mode"],
                binding["workflow_authority_mode"],
                binding["selected_cost_registry_id"],
                binding["selected_cost_registry_hash"],
                "known",
            ),
        )

    def _assert_promotion_fails_without_write(self, message: str, **overrides: str) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            before = self._trust_count(connection)
        with self.assertRaisesRegex(TrustPromotionError, message):
            self._promote(**overrides)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(self._trust_count(connection), before)

    def _assert_integrity_error_without_authority_or_trust_write(
        self, connection: sqlite3.Connection, message: str, statement: str
    ) -> None:
        before = self._authority_and_trust_state(connection)
        with self.assertRaisesRegex(sqlite3.IntegrityError, message):
            connection.execute(statement)
        self.assertEqual(self._authority_and_trust_state(connection), before)

    def _authority_and_trust_state(self, connection: sqlite3.Connection) -> tuple[int, int, int]:
        return (
            int(connection.execute("SELECT COUNT(*) FROM trust_observations").fetchone()[0]),
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_observations WHERE invalidated_at IS NULL"
                ).fetchone()[0]
            ),
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM runs WHERE authority_mode<>'file_authority'"
                ).fetchone()[0]
            )
            + int(
                connection.execute(
                    "SELECT COUNT(*) FROM workflow_authority WHERE mode<>'file_authority'"
                ).fetchone()[0]
            ),
        )

    def _trust_count(self, connection: sqlite3.Connection) -> int:
        return int(connection.execute("SELECT COUNT(*) FROM trust_observations").fetchone()[0])

    def _reset_database(self) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = Path(f"{self.database}{suffix}")
            if path.exists():
                path.unlink()
        self.evidence_path.write_bytes(self.evidence_content)

    def _chmod_database_private(self, database: Path) -> None:
        os.chmod(database.parent, 0o700)
        if database.exists():
            os.chmod(database, 0o600)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{database}{suffix}")
            if sidecar.exists():
                os.chmod(sidecar, 0o600)

    def test_writer_refuses_unsafe_database_paths(self) -> None:
        self._seed_valid_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            unsafe = Path(temporary) / "control.db"
            shutil.copy2(self.database, unsafe)
            os.chmod(unsafe, 0o666)
            with self.assertRaisesRegex(TrustPromotionError, "privacy preflight"):
                promote_trust(
                    unsafe,
                    observation_id="unsafe",
                    scope="workflow",
                    severity="R1",
                    effective_group_id="group",
                    run_id="run",
                    goal_run_id="goal-run",
                    evidence_hash=self.evidence_hash,
                    bounded_at="now",
                    created_at="now",
                )


class TrustBindingHashTests(unittest.TestCase):
    def test_binding_hash_is_shape_checked(self) -> None:
        digest = _trust_binding_hash("run", "goal", "a" * 64, "verifier", "gate", 13, "b" * 64, 30)
        self.assertEqual(len(digest), 64)
        self.assertEqual(_trust_binding_hash("run", "goal", "a" * 64, "verifier", "gate", "13", "b" * 64, 30), "")


if __name__ == "__main__":
    unittest.main()
