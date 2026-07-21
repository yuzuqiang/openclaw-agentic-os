from __future__ import annotations

import argparse
import importlib.util
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

    def test_acquired_lease_is_released_when_session_execution_is_disabled(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_gateway(method, params, *, timeout_ms):
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [{"gateway_lease_id": "lease-unit"}]}
            if method == "subagents.allowLease.release":
                return {
                    "released": True,
                    "gateway_lease_id": params["gateway_lease_id"],
                }
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
                return {"leases": [{"gateway_lease_id": "lease-unit"}]}
            if method == "subagents.allowLease.release":
                return {"released": True, "gateway_lease_id": params["gateway_lease_id"]}
            if method == "sessions_spawn":
                session = "session-a" if spawn_calls == 0 else "session-b"
                spawn_calls += 1
                return {
                    "session": {
                        "session_key": session,
                        "spawn_request_session_key": session,
                    },
                    "external_id": session,
                }
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
                return {"leases": [{"gateway_lease_id": "lease-unit"}]}
            if method == "subagents.allowLease.release":
                return {"released": True, "gateway_lease_id": params["gateway_lease_id"]}
            if method == "sessions_spawn":
                return {
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                    },
                    "external_id": "session-unit",
                    "accepted": True,
                }
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
                return {"leases": [{"gateway_lease_id": "lease-unit"}]}
            if method == "subagents.allowLease.release":
                raise RuntimeError("release refused")
            if method == "sessions_spawn":
                return {
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
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn("release refused", payload["release_error"])
        self.assertEqual(payload["accepted_session_identity"], "session-unit")


if __name__ == "__main__":
    unittest.main()
