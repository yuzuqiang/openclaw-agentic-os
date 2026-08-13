from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import agentic_os.runtime_dispatch as runtime_dispatch
import agentic_os.reconciliation as reconciliation_module
from agentic_os.migrations import apply_migrations
from agentic_os.openclaw_adapter import (
    AdapterContractError,
    MetadataObservation,
    OpenClawAdapter,
)
from agentic_os.reconciliation import reconcile_unknown_metadata
from agentic_os.runtime_dispatch import (
    DispatchRequest,
    RuntimeDispatchError,
    dispatch_with_metadata,
    lease_metadata,
    release_metadata,
    spawn_metadata,
    stable_json,
)
from tests.openclaw_adapter_test_harness import CannedOpenClawAdapter


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
        self.params: list[tuple[str, dict[str, object]]] = []

    def allow_lease_acquire(self, params):
        self.calls.append("allow_lease_acquire")
        self.params.append(("allow_lease_acquire", dict(params)))
        return self.acquire.pop(0)

    def allow_lease_list(self):
        self.calls.append("allow_lease_list")
        return list(self.leases)

    def allow_lease_release(self, params):
        self.calls.append("allow_lease_release")
        self.params.append(("allow_lease_release", dict(params)))
        return self.release.pop(0)

    def sessions_spawn(self, params):
        self.calls.append("sessions_spawn")
        self.params.append(("sessions_spawn", dict(params)))
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

    def _maybe_fail(self, call: str, params=None) -> None:
        if call in self.fail_on:
            self.calls.append(call)
            if params is not None:
                self.params.append((call, dict(params)))
            raise AdapterContractError(f"{call} response missing metadata")

    def allow_lease_acquire(self, params):
        self._maybe_fail("allow_lease_acquire", params)
        return super().allow_lease_acquire(params)

    def allow_lease_release(self, params):
        self._maybe_fail("allow_lease_release", params)
        return super().allow_lease_release(params)

    def sessions_spawn(self, params):
        self._maybe_fail("sessions_spawn", params)
        return super().sessions_spawn(params)


class TransportFailingAdapter(ScriptedAdapter):
    def __init__(self, fail_on: dict[str, BaseException], **kwargs) -> None:
        super().__init__(**kwargs)
        self.fail_on = fail_on

    def _maybe_fail(self, call: str, params=None) -> None:
        error = self.fail_on.get(call)
        if error is not None:
            self.calls.append(call)
            if params is not None:
                self.params.append((call, dict(params)))
            raise error

    def allow_lease_acquire(self, params):
        self._maybe_fail("allow_lease_acquire", params)
        return super().allow_lease_acquire(params)

    def allow_lease_release(self, params):
        self._maybe_fail("allow_lease_release", params)
        return super().allow_lease_release(params)

    def sessions_spawn(self, params):
        self._maybe_fail("sessions_spawn", params)
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
        return self._release_observation_for(self.request, "lease-gateway")

    def _release_observation_for(
        self, request: DispatchRequest, gateway_lease_id: str
    ) -> MetadataObservation:
        metadata = {
            "client_lease_id": request.client_lease_id,
            "release_idempotency_key": request.release_idempotency_key,
            "run_id": request.run_id,
            "phase": request.phase,
            "transition_id": request.transition_id,
            "agent_id": request.agent_id,
            "requester_agent_id": request.requester_agent_id,
            "gateway_lease_id": gateway_lease_id,
        }
        return observation(metadata, external_id=gateway_lease_id)

    def _additional_request(self, suffix: str, *, agent_id: str) -> DispatchRequest:
        request = DispatchRequest(
            **{
                **self.request.__dict__,
                "agent_id": agent_id,
                "task_digest": f"task-{suffix}",
                "spawn_request_id": f"spawn-{suffix}",
                "reserve_budget_event_id": f"reserve-{suffix}",
                "client_lease_id": f"client-lease-{suffix}",
                "acquire_idempotency_key": f"acquire-idem-{suffix}",
                "release_idempotency_key": f"release-idem-{suffix}",
                "spawn_client_request_id": f"client-{suffix}",
                "spawn_idempotency_key": f"spawn-idem-{suffix}",
            }
        )
        with self._connect() as connection:
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
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "spawn_request_id,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'run','transition','provider','model',?,'endpoint','capability','cost-row',"
                "'effective','cost-hash','known','reserve',1,'known','test','now',2)",
                (
                    request.reserve_budget_event_id,
                    f"reserve-idem-{suffix}",
                    f"reserve-dedupe-{suffix}",
                    2,
                    request.spawn_request_id,
                ),
            )
        return request

    def test_dispatch_persists_exact_lease_spawn_and_session_identity(self) -> None:
        adapter = self._accepted_adapter()
        result = dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(result.session_key, "session-key")
        spawn_params = [
            params for call, params in adapter.params if call == "sessions_spawn"
        ]
        self.assertEqual(
            spawn_params,
            [
                {
                    "metadata": spawn_metadata(self.request),
                    "gateway_lease_id": "lease-gateway",
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                }
            ],
        )
        self.assertNotIn("gateway_lease_id", spawn_params[0]["metadata"])
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

    def test_dispatch_acceptance_timestamps_are_strictly_after_request(self) -> None:
        original_now = runtime_dispatch.now_utc
        runtime_dispatch.now_utc = lambda: ("1970-01-01T00:00:01Z", 1000)
        try:
            dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        finally:
            runtime_dispatch.now_utc = original_now
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT rpc_kind,requested_at_epoch_ms,accepted_at_epoch_ms "
                    "FROM external_rpc_intents "
                    "WHERE rpc_kind IN ('allow_lease_acquire','sessions_spawn') "
                    "ORDER BY rpc_kind"
                ).fetchall(),
                [
                    ("allow_lease_acquire", 1000, 1001),
                    ("sessions_spawn", 1000, 1001),
                ],
            )

    def test_spawn_intent_time_strictly_follows_same_millisecond_reserve(self) -> None:
        original_now = runtime_dispatch.now_utc
        runtime_dispatch.now_utc = lambda: ("1970-01-01T00:00:01Z", 1000)
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE budget_events SET created_at_epoch_ms=1000 "
                    "WHERE budget_event_id='reserve'"
                )
            dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        finally:
            runtime_dispatch.now_utc = original_now
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT requested_at_epoch_ms,accepted_at_epoch_ms "
                    "FROM external_rpc_intents WHERE rpc_kind='sessions_spawn'"
                ).fetchone(),
                (1001, 1002),
            )

    def test_runtime_schema_verification_runs_before_adapter_call(self) -> None:
        bad_dir = Path(self.tmp.name) / "bad"
        bad_dir.mkdir()
        bad_database = bad_dir / "control.db"
        with sqlite3.connect(bad_database) as connection:
            connection.execute("CREATE TABLE schema_migrations(version INTEGER)")
        adapter = self._accepted_adapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "schema verification"):
            dispatch_with_metadata(bad_database, adapter, self.request)
        self.assertEqual(adapter.calls, [])

    def test_invalid_ttl_fails_before_database_or_adapter_call(self) -> None:
        request = DispatchRequest(**{**self.request.__dict__, "ttl_ms": True})
        adapter = self._accepted_adapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "ttl_ms"):
            dispatch_with_metadata(self.database, adapter, request)
        self.assertEqual(adapter.calls, [])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM external_rpc_intents"
                ).fetchone()[0],
                0,
            )

    def test_dispatch_closes_runtime_database_connection(self) -> None:
        original_connect = runtime_dispatch.connect_runtime_db
        proxies = []

        class ConnectionProxy:
            def __init__(self, inner):
                self.inner = inner
                self.closed = False

            def execute(self, *args, **kwargs):
                return self.inner.execute(*args, **kwargs)

            def close(self):
                self.closed = True
                self.inner.close()

        def tracking_connect(path):
            proxy = ConnectionProxy(original_connect(path))
            proxies.append(proxy)
            return proxy

        runtime_dispatch.connect_runtime_db = tracking_connect
        try:
            dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        finally:
            runtime_dispatch.connect_runtime_db = original_connect
        self.assertEqual(len(proxies), 1)
        self.assertTrue(proxies[0].closed)

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

    def test_adapter_audit_serialization_error_fails_closed_before_spawn(self) -> None:
        request = self.request

        class NonSerializableTransport:
            def call(self, method, params):
                metadata = lease_metadata(request, "lease-gateway")
                return {
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": stable_json(metadata),
                    },
                    "external_id": "lease-gateway",
                    "diagnostic": object(),
                }

        adapter = CannedOpenClawAdapter(NonSerializableTransport())
        with self.assertRaisesRegex(RuntimeDispatchError, "allow lease"):
            dispatch_with_metadata(self.database, adapter, self.request)
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
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                "accepted",
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
        self.assertEqual(
            [params for call, params in adapter.params if call == "allow_lease_release"],
            [release_metadata(self.request, "lease-gateway")],
        )
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
                    "release_pending",
                    "release-idem",
                    "allow_lease_release response missing metadata",
                ),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_release_raw_metadata_conflicting_idempotency_alias_requires_review(
        self,
    ) -> None:
        wrong = dict(spawn_metadata(self.request))
        wrong["task_digest"] = "other-task"
        release_metadata_payload = release_metadata(self.request, "lease-gateway")
        raw_release_metadata = dict(release_metadata_payload)
        raw_release_metadata["idempotency_key"] = "other-release-idem"
        adapter = ScriptedAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(wrong, external_id="session-key")],
            release=[
                MetadataObservation(
                    metadata_contract_version="v1",
                    normalized=release_metadata_payload,
                    raw_json=stable_json(raw_release_metadata),
                    external_id="lease-gateway",
                    spawn_request_session_key="lease-gateway",
                    session_key="lease-gateway",
                )
            ],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "release requires human review"):
            dispatch_with_metadata(self.database, adapter, self.request)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone(),
                ("human_review_required",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,reconciliation_status FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                (
                    "release_pending",
                    "raw external metadata.idempotency_key conflicts "
                    "with release_idempotency_key",
                ),
            )

    def test_release_transport_failure_keeps_pending_release_intent_unknown(self) -> None:
        wrong = dict(spawn_metadata(self.request))
        wrong["task_digest"] = "other-task"
        adapter = TransportFailingAdapter(
            {"allow_lease_release": TimeoutError("release timed out")},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(wrong, external_id="session-key")],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "release outcome unknown"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(
            [params for call, params in adapter.params if call == "allow_lease_release"],
            [release_metadata(self.request, "lease-gateway")],
        )
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key,reconciliation_status "
                    "FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("release_pending", "release-idem", "release timed out"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                "unknown",
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
        for field in ("spawn_request_id", "reserve_budget_event_id"):
            with self.subTest(field=field):
                changed = DispatchRequest(
                    **{**self.request.__dict__, field: f"other-{field}"}
                )
                adapter = ScriptedAdapter()
                with self.assertRaisesRegex(RuntimeDispatchError, "conflicting reuse"):
                    dispatch_with_metadata(self.database, adapter, changed)
                self.assertEqual(adapter.calls, [])
        for field in ("client_lease_id", "acquire_idempotency_key"):
            with self.subTest(field=field):
                changed = DispatchRequest(
                    **{**self.request.__dict__, field: f"other-{field}"}
                )
                adapter = ScriptedAdapter()
                with self.assertRaisesRegex(RuntimeDispatchError, "allow lease identity"):
                    dispatch_with_metadata(self.database, adapter, changed)
                self.assertEqual(adapter.calls, [])

    def test_accepted_spawn_replay_requires_local_session_proof(self) -> None:
        self._seed_unknown_spawn()
        spawn = spawn_metadata(self.request)
        with self._connect() as connection:
            connection.execute(
                "UPDATE external_rpc_intents SET state='accepted',"
                "metadata_contract_version='v1',external_metadata_json=?,"
                "external_run_id='run',external_transition_id='transition',"
                "external_client_request_id='client',external_idempotency_key='spawn-idem',"
                "external_phase='phase',external_agent_id='agent',external_task_digest='task',"
                "external_id='session-key',accepted_at='now',accepted_at_epoch_ms=1800000000004 "
                "WHERE rpc_kind='sessions_spawn'",
                (stable_json(spawn),),
            )
        adapter = ScriptedAdapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "local session proof"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, [])

    def test_conflicting_acquire_intent_reuse_fails_before_adapter_call(self) -> None:
        with self._connect() as connection:
            conflict = dict(lease_metadata(self.request, "pending"))
            conflict["idempotency_key"] = "other-acquire-idem"
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,"
                "metadata_json,state,requested_at,requested_at_epoch_ms) VALUES("
                "'acquire:other','run','transition','allow_lease_acquire','client-lease',"
                "'other-acquire-idem','phase','agent','requester',60000,?,'pending','now',10)",
                (stable_json(conflict),),
            )
        adapter = self._accepted_adapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "allow_lease_acquire identity"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, [])

    def test_release_key_collision_fails_before_acquire(self) -> None:
        for field in (
            "client_lease_id",
            "acquire_idempotency_key",
            "spawn_client_request_id",
            "spawn_idempotency_key",
        ):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                request = DispatchRequest(
                    **{
                        **self.request.__dict__,
                        "release_idempotency_key": getattr(self.request, field),
                    }
                )
                adapter = self._accepted_adapter()
                with self.assertRaisesRegex(RuntimeDispatchError, "allow_lease_release"):
                    dispatch_with_metadata(self.database, adapter, request)
                self.assertEqual(adapter.calls, [])
                with self._connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM external_rpc_intents"
                        ).fetchone()[0],
                        0,
                    )

    def test_failed_spawn_replay_preserves_review_state_without_adapter_call(self) -> None:
        for state in ("pending", "unknown", "failed", "human_review_required"):
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

    def test_sessions_spawn_transport_failure_requires_human_review_without_retrying_or_releasing_lease(
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
        with self.assertRaisesRegex(RuntimeDispatchError, "human review required"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(adapter.calls, ["allow_lease_acquire", "sessions_spawn"])
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
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT ambiguity_reason FROM spawn_requests "
                    "WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "spawn timed out",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,release_idempotency_key FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("acquired", "release-idem"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                0,
            )
        replay = ScriptedAdapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "will not be retried"):
            dispatch_with_metadata(self.database, replay, self.request)
        self.assertEqual(replay.calls, [])

    def test_late_acquire_acceptance_cannot_override_human_review(self) -> None:
        database = self.database

        class LateAcquireAdapter(ScriptedAdapter):
            def allow_lease_acquire(inner_self, params):
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "UPDATE external_rpc_intents SET state='human_review_required' "
                        "WHERE rpc_kind='allow_lease_acquire'"
                    )
                    connection.execute(
                        "UPDATE leases SET state='human_review_required',"
                        "reconciliation_status='manual-review' "
                        "WHERE client_lease_id='client-lease'"
                    )
                return super().allow_lease_acquire(params)

        adapter = LateAcquireAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ]
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "allow lease metadata"):
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
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_late_spawn_acceptance_cannot_override_human_review(self) -> None:
        database = self.database

        class LateSpawnAdapter(ScriptedAdapter):
            def sessions_spawn(inner_self, params):
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "UPDATE external_rpc_intents SET state='human_review_required' "
                        "WHERE rpc_kind='sessions_spawn'"
                    )
                    connection.execute(
                        "UPDATE spawn_requests SET state='human_review_required',"
                        "ambiguity_reason='manual-review' "
                        "WHERE spawn_request_id='spawn'"
                    )
                return super().sessions_spawn(params)

        adapter = LateSpawnAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(spawn_metadata(self.request), external_id="session-key")],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "local persistence"):
            dispatch_with_metadata(self.database, adapter, self.request)
        self.assertEqual(
            adapter.calls,
            ["allow_lease_acquire", "sessions_spawn"],
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
                    "SELECT state,session_key FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone(),
                ("human_review_required", None),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "acquired",
            )

    def test_local_spawn_persistence_error_keeps_owned_lease_for_review(self) -> None:
        original_persist = runtime_dispatch.persist_spawn_acceptance

        def fail_persistence(*args, **kwargs):
            raise sqlite3.IntegrityError("local write failed")

        runtime_dispatch.persist_spawn_acceptance = fail_persistence
        adapter = self._accepted_adapter()
        try:
            with self.assertRaisesRegex(RuntimeDispatchError, "local persistence"):
                dispatch_with_metadata(self.database, adapter, self.request)
        finally:
            runtime_dispatch.persist_spawn_acceptance = original_persist
        self.assertEqual(adapter.calls, ["allow_lease_acquire", "sessions_spawn"])
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
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "acquired",
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
                "acquire_idempotency_key,release_idempotency_key,ttl_ms,metadata_contract_version,"
                "metadata_observed_at,external_metadata_json,external_client_lease_id,"
                "external_idempotency_key,external_run_id,external_phase,"
                "external_transition_id,external_agent_id,external_requester_agent_id,"
                "external_ttl_ms,acquire_requested_at,acquired_at,expires_at,"
                "expires_at_epoch_ms) VALUES('client-lease','run','phase','transition',"
                "'agent','requester','acquired','lease-gateway','client-lease',"
                "'acquire-idem','release-idem',60000,'v1','now',?,'client-lease','acquire-idem',"
                "'run','phase','transition','agent','requester',60000,'now','now',"
                "'later',1800000060000)",
                (stable_json(acquire),),
            )
            connection.execute(
                "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
                "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
                "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
                "spawn_idempotency_key,reserve_budget_event_id,created_at) VALUES('spawn','client-lease','run',"
                "'transition','phase','agent','requester','task','client-lease',"
                "'acquire-idem','release-idem','client','spawn-idem','reserve','now')"
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

    def test_reconcile_pending_spawn_from_session_list_after_crash(self) -> None:
        self._seed_unknown_spawn()
        with self._connect() as connection:
            connection.execute(
                "UPDATE external_rpc_intents SET state='pending',resolved_at=NULL,"
                "resolved_at_epoch_ms=NULL,requested_at='old',requested_at_epoch_ms=2 "
                "WHERE rpc_kind='sessions_spawn'"
            )
            connection.execute(
                "UPDATE spawn_requests SET state='pending',ambiguity_reason=NULL "
                "WHERE spawn_request_id='spawn'"
            )
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

    def test_reconcile_fresh_pending_spawn_does_not_race_in_flight_dispatch(self) -> None:
        self._seed_unknown_spawn()
        original_now = reconciliation_module.now_utc
        reconciliation_module.now_utc = lambda: ("2026-07-16T00:00:00Z", 2_000_000)
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE external_rpc_intents SET state='pending',resolved_at=NULL,"
                    "resolved_at_epoch_ms=NULL,requested_at='now',requested_at_epoch_ms=? "
                    "WHERE rpc_kind='sessions_spawn'",
                    (2_000_000,),
                )
                connection.execute(
                    "UPDATE spawn_requests SET state='pending',ambiguity_reason=NULL "
                    "WHERE spawn_request_id='spawn'"
                )
            adapter = ScriptedAdapter(
                sessions=[
                    observation(spawn_metadata(self.request), external_id="session-key")
                ]
            )
            summary = reconcile_unknown_metadata(self.database, adapter)
        finally:
            reconciliation_module.now_utc = original_now
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 0)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,external_id FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone(),
                ("pending", None),
            )

    def test_reconcile_spawn_requires_acquired_allow_lease_proof(self) -> None:
        with self._connect() as connection:
            runtime_dispatch.insert_pending_dispatch(connection, self.request)
            connection.execute(
                "UPDATE external_rpc_intents SET requested_at='old',requested_at_epoch_ms=2 "
                "WHERE rpc_kind IN ('allow_lease_acquire','sessions_spawn')"
            )
        adapter = ScriptedAdapter(
            sessions=[observation(spawn_metadata(self.request), external_id="session-key")]
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 2)
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
                    "SELECT state,external_id FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn'"
                ).fetchone(),
                ("human_review_required", None),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,session_key FROM spawn_requests "
                    "WHERE spawn_request_id='spawn'"
                ).fetchone(),
                ("human_review_required", None),
            )

    def test_reconcile_release_pending_from_release_metadata(self) -> None:
        wrong = dict(spawn_metadata(self.request))
        wrong["task_digest"] = "other-task"
        adapter = TransportFailingAdapter(
            {"allow_lease_release": TimeoutError("release timed out")},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            spawn=[observation(wrong, external_id="session-key")],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "release outcome unknown"):
            dispatch_with_metadata(self.database, adapter, self.request)

        reconcile_adapter = ScriptedAdapter(leases=[self._release_observation()])
        summary = reconcile_unknown_metadata(self.database, reconcile_adapter)
        self.assertEqual(summary.reconciled, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state,external_id FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone(),
                ("reconciled", "lease-gateway"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state,reconciliation_status FROM leases "
                    "WHERE client_lease_id='client-lease'"
                ).fetchone(),
                ("released", "not_needed"),
            )

    def test_reconcile_acquire_only_lease_releases_after_blocked_spawn(self) -> None:
        adapter = TransportFailingAdapter(
            {"allow_lease_acquire": OSError("network timeout")}
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "transport outcome unknown"):
            dispatch_with_metadata(self.database, adapter, self.request)

        reconcile_adapter = ScriptedAdapter(
            leases=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
            release=[self._release_observation()],
        )
        summary = reconcile_unknown_metadata(self.database, reconcile_adapter)
        self.assertEqual(summary.reconciled, 2)
        self.assertIn("allow_lease_release", reconcile_adapter.calls)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "reconciled",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_release'"
                ).fetchone()[0],
                "accepted",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "released",
            )

    def test_reconcile_keeps_crash_left_acquired_lease_after_zero_session(self) -> None:
        class CrashAfterAcquireAdapter(ScriptedAdapter):
            def sessions_spawn(self, params):
                self.calls.append("sessions_spawn")
                self.params.append(("sessions_spawn", dict(params)))
                raise SystemExit("simulated process crash")

        crash_adapter = CrashAfterAcquireAdapter(
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ]
        )
        with self.assertRaisesRegex(SystemExit, "simulated process crash"):
            dispatch_with_metadata(self.database, crash_adapter, self.request)
        with self._connect() as connection:
            connection.execute(
                "UPDATE external_rpc_intents SET requested_at='old',requested_at_epoch_ms=2 "
                "WHERE rpc_kind='sessions_spawn'"
            )

        reconcile_adapter = ScriptedAdapter(release=[self._release_observation()])
        summary = reconcile_unknown_metadata(self.database, reconcile_adapter)
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        self.assertNotIn("allow_lease_release", reconcile_adapter.calls)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "acquired",
            )

    def test_cleanup_binding_never_releases_other_same_transition_lease(self) -> None:
        dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        blocked = self._additional_request("blocked", agent_id="agent-blocked")
        with self.assertRaisesRegex(RuntimeDispatchError, "transport outcome unknown"):
            dispatch_with_metadata(
                self.database,
                TransportFailingAdapter(
                    {"allow_lease_acquire": TimeoutError("acquire timed out")}
                ),
                blocked,
            )
        blocked_gateway_id = "lease-gateway-blocked"
        reconcile_adapter = ScriptedAdapter(
            leases=[
                observation(
                    lease_metadata(blocked, blocked_gateway_id),
                    external_id=blocked_gateway_id,
                )
            ],
            sessions=[
                observation(spawn_metadata(self.request), external_id="session-key")
            ],
            release=[self._release_observation_for(blocked, blocked_gateway_id)],
        )
        summary = reconcile_unknown_metadata(self.database, reconcile_adapter)
        self.assertEqual(summary.reconciled, 2)
        self.assertEqual(
            [params for call, params in reconcile_adapter.params if call == "allow_lease_release"],
            [release_metadata(blocked, blocked_gateway_id)],
        )
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT client_lease_id,state FROM leases ORDER BY client_lease_id"
                ).fetchall(),
                [
                    ("client-lease", "acquired"),
                    ("client-lease-blocked", "released"),
                ],
            )

    def test_duplicate_live_dispatch_is_blocked_before_second_spawn(self) -> None:
        duplicate = self._additional_request("duplicate", agent_id=self.request.agent_id)
        dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        duplicate_gateway_id = "lease-gateway-duplicate"
        adapter = ScriptedAdapter(
            acquire=[
                observation(
                    lease_metadata(duplicate, duplicate_gateway_id),
                    external_id=duplicate_gateway_id,
                )
            ],
            spawn=[observation(spawn_metadata(duplicate), external_id="session-duplicate")],
            release=[self._release_observation_for(duplicate, duplicate_gateway_id)],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "duplicate live dispatch"):
            dispatch_with_metadata(self.database, adapter, duplicate)
        self.assertEqual(adapter.calls, [])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT spawn_request_id,state FROM spawn_requests ORDER BY spawn_request_id"
                ).fetchall(),
                [("spawn", "accepted"), ("spawn-duplicate", "pending")],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM spawn_requests WHERE run_id='run' AND phase='phase' "
                    "AND agent_id='agent' AND state IN ('accepted','completed')"
                ).fetchone()[0],
                1,
            )

    def test_ambiguous_first_spawn_blocks_second_before_any_adapter_call(self) -> None:
        duplicate = self._additional_request("after-unknown", agent_id=self.request.agent_id)
        first = TransportFailingAdapter(
            {"sessions_spawn": TimeoutError("spawn outcome unknown")},
            acquire=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ],
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "human review required"):
            dispatch_with_metadata(self.database, first, self.request)
        self.assertEqual(first.calls, ["allow_lease_acquire", "sessions_spawn"])

        second = self._accepted_adapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "duplicate live dispatch"):
            dispatch_with_metadata(self.database, second, duplicate)
        self.assertEqual(second.calls, [])
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn' AND spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT client_lease_id,state FROM leases ORDER BY client_lease_id"
                ).fetchall(),
                [("client-lease", "acquired")],
            )

    def test_unverified_acquire_review_state_blocks_new_slot_attempt(self) -> None:
        with self.assertRaisesRegex(RuntimeDispatchError, "allow lease"):
            dispatch_with_metadata(
                self.database,
                ContractFailingAdapter({"allow_lease_acquire"}),
                self.request,
            )
        replacement = self._additional_request("replacement", agent_id=self.request.agent_id)
        adapter = self._accepted_adapter()
        with self.assertRaisesRegex(RuntimeDispatchError, "duplicate live dispatch"):
            dispatch_with_metadata(self.database, adapter, replacement)
        self.assertEqual(adapter.calls, [])

    def test_preflight_failure_without_external_intent_does_not_block_new_slot(self) -> None:
        invalid = DispatchRequest(**{**self.request.__dict__, "ttl_ms": True})
        with self.assertRaisesRegex(RuntimeDispatchError, "ttl_ms"):
            dispatch_with_metadata(self.database, ScriptedAdapter(), invalid)
        replacement = self._additional_request("replacement", agent_id=self.request.agent_id)
        gateway_id = "lease-gateway-replacement"
        adapter = ScriptedAdapter(
            acquire=[
                observation(
                    lease_metadata(replacement, gateway_id), external_id=gateway_id
                )
            ],
            spawn=[
                observation(spawn_metadata(replacement), external_id="session-replacement")
            ],
        )
        result = dispatch_with_metadata(self.database, adapter, replacement)
        self.assertEqual(result.session_key, "session-replacement")
        self.assertEqual(adapter.calls, ["allow_lease_acquire", "sessions_spawn"])

    def test_runtime_dispatch_binding_is_exact_and_immutable(self) -> None:
        dispatch_with_metadata(self.database, self._accepted_adapter(), self.request)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT spawn_request_id,lease_id,client_lease_id,"
                    "acquire_idempotency_key,release_idempotency_key "
                    "FROM runtime_dispatch_bindings"
                ).fetchone(),
                ("spawn", "client-lease", "client-lease", "acquire-idem", "release-idem"),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE runtime_dispatch_bindings SET lease_id='other' "
                    "WHERE spawn_request_id='spawn'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "DELETE FROM runtime_dispatch_bindings WHERE spawn_request_id='spawn'"
                )

    def test_post_v10_spawn_intent_requires_exact_reserve_binding(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "spawn_request_id,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "usage_confidence,source,created_at,created_at_epoch_ms) VALUES("
                "'other-reserve','other-reserve-idem','other-reserve-dedupe',2,'run',"
                "'transition','provider','model','spawn','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','reserve',1,'known','test','old',1)"
            )
            runtime_dispatch.insert_pending_dispatch(connection, self.request)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "runtime dispatch binding"):
                connection.execute(
                    "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                    "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                    "idempotency_key,phase,agent_id,task_digest,metadata_json,state,"
                    "requested_at,requested_at_epoch_ms) VALUES("
                    "'spawn:other-reserve','run','transition','sessions_spawn','spawn',"
                    "'other-reserve','client-other','spawn-idem-other','phase','agent','task',"
                    "'{}','pending','now',2)"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "runtime dispatch binding"):
                connection.execute(
                    "UPDATE external_rpc_intents SET reserve_budget_event_id='other-reserve' "
                    "WHERE rpc_kind='sessions_spawn' AND idempotency_key='spawn-idem'"
                )

    def test_reconcile_unknown_acquire_requires_local_lease_row(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,"
                "metadata_json,state,requested_at,requested_at_epoch_ms) VALUES("
                "'acquire:acquire-idem','run','transition','allow_lease_acquire',"
                "'client-lease','acquire-idem','phase','agent','requester',60000,?,"
                "'unknown','now',1800000000001)",
                (stable_json(lease_metadata(self.request, "pending")),),
            )
        adapter = ScriptedAdapter(
            leases=[
                observation(
                    lease_metadata(self.request, "lease-gateway"),
                    external_id="lease-gateway",
                )
            ]
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "human_review_required",
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
            ],
            release=[self._release_observation()],
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
            ],
            release=[self._release_observation()],
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        self.assertNotIn("allow_lease_release", adapter.calls)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM leases WHERE client_lease_id='client-lease'"
                ).fetchone()[0],
                "acquired",
            )

    def test_reconcile_matching_malformed_session_observation_requires_review(self) -> None:
        self._seed_unknown_spawn()
        adapter = ScriptedAdapter(
            sessions=[
                observation(spawn_metadata(self.request), external_id="session-key"),
                MetadataObservation(
                    metadata_contract_version="v1",
                    normalized=spawn_metadata(self.request),
                    raw_json=None,
                    external_id="session-key-2",
                    spawn_request_session_key="session-key-2",
                    session_key="session-key-2",
                ),
            ],
            release=[self._release_observation()],
        )
        summary = reconcile_unknown_metadata(self.database, adapter)
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_reconcile_contract_failed_matching_session_item_requires_review(self) -> None:
        self._seed_unknown_spawn()

        class ListTransport:
            def call(self, method, params):
                if method == "sessions_list":
                    metadata = spawn_metadata(self_request)
                    return {
                        "sessions": [
                            {
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": metadata,
                                    "raw_json": stable_json(metadata),
                                },
                                "external_id": "session-key",
                                "session_key": "session-key",
                                "spawn_request_session_key": "session-key",
                            },
                            {
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": metadata,
                                    "raw_json": stable_json(metadata),
                                },
                                "external_id": "session-key-2",
                                "session_key": "session-key-2",
                                "spawn_request_session_key": "session-key-2",
                                "session": {"session_key": "conflicting-session"},
                            },
                        ]
                    }
                if method == "subagents.allowLease.status":
                    return {"leases": []}
                raise AssertionError(method)

        self_request = self.request
        summary = reconcile_unknown_metadata(
            self.database,
            CannedOpenClawAdapter(ListTransport()),
        )
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM spawn_requests WHERE spawn_request_id='spawn'"
                ).fetchone()[0],
                "human_review_required",
            )

    def test_reconcile_gatewayless_matching_lease_observation_requires_review(self) -> None:
        adapter = TransportFailingAdapter(
            {"allow_lease_acquire": TimeoutError("acquire timed out")}
        )
        with self.assertRaisesRegex(RuntimeDispatchError, "transport outcome unknown"):
            dispatch_with_metadata(self.database, adapter, self.request)
        with self._connect() as connection:
            connection.execute(
                "UPDATE external_rpc_intents SET requested_at='old',requested_at_epoch_ms=2 "
                "WHERE rpc_kind='allow_lease_acquire'"
            )
        valid = observation(
            lease_metadata(self.request, "lease-gateway"),
            external_id="lease-gateway",
        )
        gatewayless_normalized = dict(lease_metadata(self.request, "lease-gateway"))
        gatewayless_normalized.pop("gateway_lease_id")
        summary = reconcile_unknown_metadata(
            self.database,
            ScriptedAdapter(
                leases=[
                    valid,
                    MetadataObservation(
                        metadata_contract_version="v1",
                        normalized=gatewayless_normalized,
                        raw_json=stable_json(gatewayless_normalized),
                        external_id=None,
                    ),
                ]
            ),
        )
        self.assertEqual(summary.reconciled, 0)
        self.assertEqual(summary.human_review_required, 1)
        with self._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM external_rpc_intents "
                    "WHERE rpc_kind='allow_lease_acquire'"
                ).fetchone()[0],
                "human_review_required",
            )


if __name__ == "__main__":
    unittest.main()
