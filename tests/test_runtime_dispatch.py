from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from agentic_os.migrations import apply_migrations
from agentic_os.openclaw_adapter import AdapterContractError, MetadataObservation
from agentic_os.reconciliation import reconcile_unknown_metadata
from agentic_os.runtime_dispatch import (
    DispatchRequest,
    RuntimeDispatchError,
    dispatch_with_metadata,
    lease_metadata,
    spawn_metadata,
    stable_json,
)


class ScriptedAdapter:
    def __init__(
        self,
        *,
        acquire: list[MetadataObservation] | None = None,
        spawn: list[MetadataObservation] | None = None,
        release: list[MetadataObservation] | None = None,
        leases: list[MetadataObservation] | None = None,
        sessions: list[MetadataObservation] | None = None,
    ) -> None:
        self.acquire = list(acquire or [])
        self.spawn = list(spawn or [])
        self.release = list(release or [])
        self.leases = list(leases or [])
        self.sessions = list(sessions or [])
        self.calls: list[str] = []

    def allow_lease_acquire(self, params):
        self.calls.append("allow_lease_acquire")
        return self.acquire.pop(0)

    def allow_lease_list(self):
        self.calls.append("allow_lease_list")
        return list(self.leases)

    def allow_lease_release(self, params):
        self.calls.append("allow_lease_release")
        return self.release.pop(0)

    def sessions_spawn(self, params):
        self.calls.append("sessions_spawn")
        return self.spawn.pop(0)

    def sessions_list(self):
        self.calls.append("sessions_list")
        return list(self.sessions)

    def session_status(self, session_key):
        self.calls.append("session_status")
        return self.sessions[0]


class ContractFailingAdapter(ScriptedAdapter):
    def __init__(self, fail_on: set[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.fail_on = fail_on

    def _maybe_fail(self, call: str) -> None:
        if call in self.fail_on:
            self.calls.append(call)
            raise AdapterContractError(f"{call} response missing metadata")

    def allow_lease_acquire(self, params):
        self._maybe_fail("allow_lease_acquire")
        return super().allow_lease_acquire(params)

    def allow_lease_release(self, params):
        self._maybe_fail("allow_lease_release")
        return super().allow_lease_release(params)

    def sessions_spawn(self, params):
        self._maybe_fail("sessions_spawn")
        return super().sessions_spawn(params)


class TransportFailingAdapter(ScriptedAdapter):
    def __init__(self, fail_on: dict[str, BaseException], **kwargs) -> None:
        super().__init__(**kwargs)
        self.fail_on = fail_on

    def _maybe_fail(self, call: str) -> None:
        error = self.fail_on.get(call)
        if error is not None:
            self.calls.append(call)
            raise error

    def allow_lease_acquire(self, params):
        self._maybe_fail("allow_lease_acquire")
        return super().allow_lease_acquire(params)

    def allow_lease_release(self, params):
        self._maybe_fail("allow_lease_release")
        return super().allow_lease_release(params)

    def sessions_spawn(self, params):
        self._maybe_fail("sessions_spawn")
        return super().sessions_spawn(params)


def observation(metadata: dict[str, object], *, external_id: str) -> MetadataObservation:
    return MetadataObservation(
        metadata_contract_version="v1",
        normalized=dict(metadata),
        raw_json=stable_json(dict(metadata)),
        external_id=external_id,
        spawn_request_session_key=external_id,
        session_key=external_id,
    )


class RuntimeDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.database = Path(self.tmp.name) / "control.db"
        apply_migrations(self.database)
        self.request = DispatchRequest(
            run_id="run",
            transition_id="transition",
            phase="phase",
            agent_id="agent",
            requester_agent_id="requester",
            task_digest="task",
            spawn_request_id="spawn",
            reserve_budget_event_id="reserve",
            client_lease_id="client-lease",
            acquire_idempotency_key="acquire-idem",
            release_idempotency_key="release-idem",
            ttl_ms=60_000,
            spawn_client_request_id="client",
            spawn_idempotency_key="spawn-idem",
        )
        self._seed_run_and_budget()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _seed_run_and_budget(self) -> None:
        with self._connect() as connection:
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
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('transition','run','before',"
                "'after','dispatch','spawn','R1','transition-idem',0,'now')"
            )
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
                "VALUES('cost-row','provider','model','endpoint','capability',100,200,"
                "'known','effective','cost-hash')"
            )
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn','run','phase','agent','transition',"
                "'client','spawn-idem','task','pending','now','now')"
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
                "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
                "selected_cost_effective_at,selected_cost_registry_hash,"
                "selected_cost_confidence,selected_reserve_transition_id,time_budget_seconds,"
                "input_token_budget,output_token_budget,cost_budget_microusd,retry_budget,"
                "human_attention_budget,reserved_input_tokens,usage_confidence,updated_at) "
                "VALUES('run','workflow','capability','provider','model','endpoint',"
                "'cost-row','effective','cost-hash','known','transition',100,100,100,"
                "1000,1,1,1,'known','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "spawn_request_id,endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES("
                "'reserve','reserve-idem','reserve-dedupe',1,'run','transition',"
                "'provider','model','spawn','endpoint','capability','cost-row','effective',"
                "'cost-hash','known','reserve',1,'known','test','now',1)"
            )

    def _accepted_adapter(self) -> ScriptedAdapter:
        return ScriptedAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(spawn_metadata(self.request), external_id="session-key")],
        )

    def _release_observation(self) -> MetadataObservation:
        metadata = {
            "client_lease_id": self.request.client_lease_id,
            "idempotency_key": self.request.release_idempotency_key,
            "run_id": self.request.run_id,
            "phase": self.request.phase,
            "transition_id": self.request.transition_id,
            "agent_id": self.request.agent_id,
            "requester_agent_id": self.request.requester_agent_id,
            "gateway_lease_id": "lease-gateway",
        }
        return observation(metadata, external_id="lease-gateway")

    def test_dispatch_persists_exact_lease_spawn_and_session_identity(self) -> None:
        result = dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        self.assertEqual(result.session_key, "session-key")
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,external_id,external_run_id,external_ttl_ms "
                    "FROM external_rpc_intents WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone(),
                ("accepted", "lease-gateway", "run", 60000),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,external_id,external_client_request_id "
                    "FROM external_rpc_intents WHERE rpc_kind='sessions_spawn'"
                ).fetchone(),
                ("accepted", "session-key", "client"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,session_key FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone(),
                ("accepted", "session-key"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT session_key,state FROM sessions WHERE spawn_request_id='spawn'"
                ).fetchone(),
                ("session-key", "running"),
            )

    def test_missing_lease_metadata_fails_closed_before_spawn(self) -> None:
        adapter = ScriptedAdapter(
            acquire=[
                MetadataObservation(
                    metadata_contract_version="v1",
                    normalized=None,
                    raw_json=None,
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(spawn_metadata(self.request), external_id="session-key")],
        )
        with self.assertRaises(RuntimeDispatchError):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, ["allow_lease_acquire"])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_adapter_contract_error_on_acquire_fails_closed_before_spawn(self) -> None:
        adapter = ContractFailingAdapter(
            {"allow_lease_acquire"},
            spawn=[observation(spawn_metadata(self.request), external_id="session-key")],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "allow lease"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, ["allow_lease_acquire"])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_adapter_contract_error_on_spawn_releases_owned_lease(self) -> None:
        adapter = ContractFailingAdapter(
            {"sessions_spawn"},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            release=[self._release_observation()],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "owned lease released"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(
            adapter.calls,
            ["allow_lease_acquire", "sessions_spawn", "allow_lease_release"],
        )
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("released", "release-idem"),
            )

    def test_spawn_metadata_mismatch_releases_only_owned_lease(self) -> None:
        wrong = dict(spawn_metadata(self.request))
        wrong["task_digest"] = "other-task"
        adapter = ScriptedAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(wrong, external_id="session-key")],
            release=[self._release_observation()],
        )
        with self.assertRaises(RuntimeDispatchError):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(Counter(adapter.calls)["allow_lease_release"], 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("released", "release-idem"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_release_contract_error_after_spawn_failure_keeps_human_review_state(
        self,
    ) -> None:
        wrong = dict(spawn_metadata(self.request))
        wrong["task_digest"] = "other-task"
        adapter = ContractFailingAdapter(
            {"allow_lease_release"},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(wrong, external_id="session-key")],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "release requires human review"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(
            adapter.calls,
            ["allow_lease_acquire", "sessions_spawn", "allow_lease_release"],
        )
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key,reconciliation_status FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                (
                    "acquired",
                    "release-idem",
                    "allow_lease_release response missing metadata",
                ),
            )

    def test_identical_dispatch_replay_skips_adapter_and_conflicting_reuse_fails(self) -> None:
        first = self._accepted_adapter()
        dispatch_with_metadata(self.database, first, self.request)
        replay = ScriptedAdapter()
        result = dispatch_with_metadata(self.database, replay, self.request)
        self.assertEqual(result.status, "replayed")
        self.assertEqual(replay.calls, [])
        conflicting = DispatchRequest(
            **{**self.request.__dict__, "task_digest": "other-task"}
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "conflicting reuse"):
            dispatch_with_metadata(self.database, ScriptedAdapter(), conflicting)

    def test_failed_spawn_replay_preserves_review_state_without_adapter_call(self) -> None:
        for state in ("unknown", "failed", "human_review_required"):
            with self.subTest(state=state):
                self.tearDown()
                self.setUp()
                self._seed_unknown_spawn()
                with self._connect() as connection:
                    connection.execute(
                        "UPDATE external_rpc_intents SET state=? "
                        "WHERE rpc_kind='sessions_spawn'",
                        (state,),
                    )
                    connection.execute(
                        "UPDATE spawn_requests SET state=?,ambiguity_reason='prior failure' "
                        "WHERE spawn_request_id='spawn'",
                        (state,),
                    )
                adapter = self._accepted_adapter()
                with self.assertRaisesRegex(RuntimeDispatchError, "will not be retried"):
                    dispatch_with_metadata(self.database, adapter, self.request)
                self.assertEqual(adapter.calls, [])

    def test_allow_lease_transport_failure_marks_unknown_before_spawn(self) -> None:
        adapter = TransportFailingAdapter(
            {"allow_lease_acquire": OSError("network timeout")}
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "transport outcome unknown"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, ["allow_lease_acquire"])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "unknown",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_sessions_spawn_transport_failure_marks_unknown_without_releasing_lease(
        self,
    ) -> None:
        adapter = TransportFailingAdapter(
            {"sessions_spawn": TimeoutError("spawn timed out")},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "reconciliation required"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, ["allow_lease_acquire", "sessions_spawn"])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone()[0],
                "unknown",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "unknown",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("acquired", None),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                0,
            )

    def test_runtime_database_privacy_preflight_runs_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            database = Path(outside) / "control.db"
            adapter = self._accepted_adapter()
            with self.assertRaisesRegex(RuntimeDispatchError, "privacy preflight"):
                dispatch_with_metadata(database, adapter, self.request)
            self.assertFalse(database.exists())
            self.assertEqual(adapter.calls, [])

    def _seed_unknown_spawn(self) -> None:
        with self._connect() as connection:
            acquire = lease_metadata(self.request, "lease-gateway")
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,"
                "metadata_contract_version,metadata_json,external_metadata_json,"
                "external_run_id,external_transition_id,external_client_request_id,"
                "external_idempotency_key,external_phase,external_agent_id,"
                "external_requester_agent_id,external_ttl_ms,state,external_id,"
                "requested_at,requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) "
                "VALUES('acquire:acquire-idem','run','transition','allow_lease_acquire',"
                "'client-lease','acquire-idem','phase','agent','requester',60000,'v1',?,"
                "?, 'run','transition','client-lease','acquire-idem','phase','agent',"
                "'requester',60000,'accepted','lease-gateway','now',1800000000001,"
                "'now',1800000000002)",
                (stable_json(acquire), stable_json(acquire)),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,gateway_lease_id,client_lease_id,"
                "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,acquire_requested_at,acquired_at,expires_at,"
                "expires_at_epoch_ms) VALUES('client-lease','run','phase','transition',"
                "'agent','requester','acquired','lease-gateway','client-lease',"
                "'acquire-idem',60000,'v1','now',?,'client-lease','acquire-idem',"
                "'run','phase','transition','agent','requester',60000,'now','now',"
                "'later',1800000060000)",
                (stable_json(acquire),),
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
                "phase,agent_id,task_digest,metadata_json,state,requested_at,"
                "requested_at_epoch_ms) VALUES('spawn:spawn-idem','run','transition',"
                "'sessions_spawn','spawn','reserve','client','spawn-idem','phase','agent',"
                "'task',?,'unknown','now',1800000000003)",
                (stable_json(spawn_metadata(self.request)),),
            )

    def test_reconcile_unknown_spawn_from_session_list_without_retry(self) -> None:
        self._seed_unknown_spawn()
        adapter = ScriptedAdapter(
            sessions=[observation(spawn_metadata(self.request), external_id="session-key")]
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.reconciled, 1)
        self.assertNotIn("sessions_spawn", adapter.calls)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,external_id FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone(),
                ("reconciled", "session-key"),
            )

    def test_reconcile_unknown_spawn_requires_full_session_identity(self) -> None:
        self._seed_unknown_spawn()
        adapter = ScriptedAdapter(
            sessions=[
                MetadataObservation(
                    metadata_contract_version="v1",
                    normalized=spawn_metadata(self.request),
                    raw_json=stable_json(spawn_metadata(self.request)),
                    external_id="session-key",
                    spawn_request_session_key=None,
                    session_key="session-key",
                )
            ]
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_reconcile_ambiguous_session_discovery_requires_human_review(self) -> None:
        self._seed_unknown_spawn()
        adapter = ScriptedAdapter(
            sessions=[
                observation(spawn_metadata(self.request), external_id="session-a"),
                observation(spawn_metadata(self.request), external_id="session-b"),
            ]
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )


if __name__ == "__main__":
    unittest.main()
