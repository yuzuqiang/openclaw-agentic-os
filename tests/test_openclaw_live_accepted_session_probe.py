from __future__ import annotations

import argparse
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from agentic_os.migrations import repository_root


SCRIPT = repository_root() / "scripts/openclaw-live-accepted-session-probe.py"


def load_probe_module():
    spec = importlib.util.spec_from_file_location("openclaw_live_probe", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load live probe script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args(**overrides):
    values = {
        "probe_id": "unit",
        "agent_id": "technical-writer",
        "requester_agent_id": "main",
        "ttl_ms": 60_000,
        "gateway_timeout_ms": 10_000,
        "agent_timeout_seconds": 120,
        "execute_session_spawn": False,
        "evidence_file": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def acquire_owner(**overrides):
    values = {
        "client_lease_id": "issue35-unit",
        "idempotency_key": "issue35-acquire-unit",
        "run_id": "issue35-run-unit",
        "phase": "B",
        "transition_id": "issue35-transition-unit",
        "agent_id": "technical-writer",
        "requester_agent_id": "main",
        "ttl_ms": 60_000,
    }
    values.update(overrides)
    return values


def status_lease(gateway_lease_id="lease-unit", **overrides):
    return {**acquire_owner(), "gateway_lease_id": gateway_lease_id, **overrides}


def release_response(params, *, released=True, **overrides):
    return {"released": released, **dict(params), **overrides}


def spawn_response(params, *, session_key="session-unit"):
    return {
        "session": {
            "session_key": session_key,
            "spawn_request_session_key": session_key,
            "metadata_echo": dict(params["metadata"]),
        },
        "external_id": session_key,
    }


class OpenClawLiveAcceptedSessionProbeTests(unittest.TestCase):
    def test_preflight_failure_fails_closed_before_any_rpc(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            return_value=(False, {"status": "fail", "error": "missing metadata"}),
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_failed")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        self.assertEqual(payload["rpc_attempted"], [])
        gateway.assert_not_called()

    def test_db_authority_enabled_fails_closed_before_preflight(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module.agentic_os, "DB_AUTHORITY_ENABLED", True
        ), mock.patch.object(module, "_preflight") as preflight, mock.patch.object(
            module, "_gateway_call"
        ) as gateway:
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "db_authority_enabled")
        self.assertTrue(payload["db_authority_enabled"])
        self.assertEqual(payload["released"], "not_required")
        preflight.assert_not_called()
        gateway.assert_not_called()

    def test_preflight_timeout_writes_fail_closed_probe_payload(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            side_effect=subprocess.TimeoutExpired(cmd=["preflight"], timeout=30),
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_timed_out")
        self.assertEqual(payload["preflight"]["status"], "fail")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        gateway.assert_not_called()

    def test_acquired_lease_is_released_when_session_execution_is_disabled(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_gateway(method, params, *, timeout_ms):
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "session_spawn_execution_disabled")
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "subagents.allowLease.release",
            ],
        )

    def test_duplicate_acquire_failure_still_releases_first_acquired_lease(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []
        acquire_calls = 0

        def fake_gateway(method, params, *, timeout_ms):
            nonlocal acquire_calls
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                if acquire_calls == 1:
                    return {"gateway_lease_id": "lease-unit"}
                raise RuntimeError("duplicate acquire timed out")
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["allow_lease"]["gateway_lease_id"], "lease-unit")
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.release",
            ],
        )

    def test_non_idempotent_duplicate_acquire_releases_both_observed_leases(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []
        acquire_calls = 0

        def fake_gateway(method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                return {
                    "gateway_lease_id": "lease-unit"
                    if acquire_calls == 1
                    else "lease-duplicate"
                }
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("different lease identity", payload["error"])
        self.assertEqual(released_ids, ["lease-unit", "lease-duplicate"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_cleanup_attempts_every_observed_lease(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []
        acquire_calls = 0

        def fake_gateway(method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                return {
                    "gateway_lease_id": "lease-unit"
                    if acquire_calls == 1
                    else "lease-duplicate"
                }
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                if params["gateway_lease_id"] == "lease-unit":
                    raise RuntimeError("first release failed")
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertEqual(payload["prior_reason"], "live_probe_contract_failed")
        self.assertEqual(released_ids, ["lease-unit", "lease-duplicate"])
        self.assertFalse(payload["released"])

    def test_status_must_observe_acquired_lease_before_probe_can_pass(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [{"gateway_lease_id": "other-lease"}]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("status did not observe", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_status_must_echo_owner_metadata_for_acquired_lease(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease(run_id="other-run")]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("status proof did not echo expected metadata", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_status_metadata_must_belong_to_observed_lease_object(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {
                    "request_echo": status_lease(),
                    "leases": [{"gateway_lease_id": "lease-unit"}],
                }
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("status proof did not echo expected metadata", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_must_report_lease_identity(self) -> None:
        module = load_probe_module()
        acquire_calls = 0

        def fake_gateway(method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                if acquire_calls == 1:
                    return {"gateway_lease_id": "lease-unit"}
                return {"status": "already_acquired"}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("duplicate allowLease acquire did not report", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_release_false_fails_closed_even_when_identity_matches(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params, released=False)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn("release did not report success", payload["release_error"])

    def test_release_must_echo_owner_metadata(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params, run_id="other-run")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn(
            "release proof did not echo expected metadata",
            payload["release_error"],
        )

    def test_release_metadata_must_belong_to_released_lease_object(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return {
                    **dict(params),
                    "lease": {
                        "gateway_lease_id": params["gateway_lease_id"],
                        "released": True,
                    },
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn(
            "release proof did not echo expected metadata",
            payload["release_error"],
        )

    def test_spawn_timeout_is_recorded_as_attempted_and_releases_lease(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                raise RuntimeError("spawn timed out")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["spawn_attempted"])
        self.assertIn("sessions_spawn", payload["rpc_attempted"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_session_identity_mismatch_fails_closed_and_releases(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []
        spawn_calls = 0

        def fake_gateway(method, params, *, timeout_ms):
            nonlocal spawn_calls
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                session = "session-a" if spawn_calls == 0 else "session-b"
                spawn_calls += 1
                return spawn_response(params, session_key=session)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["spawn_attempted"])
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["released"], True)
        self.assertIn("duplicate spawn", payload["error"])
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "sessions_spawn",
                "sessions_spawn",
                "subagents.allowLease.release",
            ],
        )

    def test_duplicate_session_identity_pass_binds_structured_spawn_responses(
        self,
    ) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_gateway(method, params, *, timeout_ms):
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {**spawn_response(params), "accepted": True}
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["accepted_session_identity"], "session-unit")
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            set(payload["accepted_session_identity_parity"].values()),
            {"session-unit"},
        )
        structured = payload["sessions_spawn_structured_evidence"]
        self.assertEqual(
            structured["first"]["identity"]["session_key"], "session-unit"
        )
        self.assertEqual(
            structured["first"]["metadata_echo"]["run_id"],
            "issue35-run-unit",
        )
        self.assertIn("raw_response_sha256", structured["first"])
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "sessions_spawn",
                "sessions_spawn",
                "subagents.allowLease.release",
            ],
        )

    def test_release_failure_downgrades_otherwise_passing_probe(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                raise RuntimeError("release refused")
            if method == "sessions_spawn":
                return spawn_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn("release refused", payload["release_error"])
        self.assertEqual(payload["accepted_session_identity"], "session-unit")

    def test_spawn_response_must_echo_request_metadata(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                        "metadata_echo": {**params["metadata"], "run_id": "other-run"},
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "sessions_spawn response did not echo expected metadata",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_spawn_response_rejects_conflicting_session_identity_aliases(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "external_id": "session-unit",
                    "session_key": "session-unit",
                    "spawn_request_session_key": "session-unit",
                    "session": {
                        "session_key": "other-session",
                        "metadata_echo": dict(params["metadata"]),
                    },
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting session identity aliases", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_spawn_metadata_echo_must_be_bound_to_created_session(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "request_echo": {"metadata": dict(params["metadata"])},
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "sessions_spawn response did not echo expected metadata",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_top_level_spawn_metadata_echo_is_not_session_proof(self) -> None:
        module = load_probe_module()

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "metadata_echo": dict(params["metadata"]),
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "sessions_spawn response did not echo expected metadata",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_missing_openclaw_cli_fails_closed_instead_of_traceback(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(
            module.subprocess,
            "run",
            side_effect=FileNotFoundError("openclaw missing"),
        ):
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        self.assertIn("openclaw missing", payload["error"])


if __name__ == "__main__":
    unittest.main()
