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
                return {"released": True, "gateway_lease_id": params["gateway_lease_id"]}
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

        def fake_gateway(method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.status":
                return {"leases": [{"gateway_lease_id": "lease-unit"}]}
            if method == "subagents.allowLease.release":
                return {"released": True}
            raise AssertionError(method)

        spawn_results = [
            {
                "externalId": "session-a",
                "spawnRequestSessionKey": "session-a",
                "sessionKey": "session-a",
                "probeId": "unit",
            },
            {
                "externalId": "session-b",
                "spawnRequestSessionKey": "session-b",
                "sessionKey": "session-b",
                "probeId": "unit",
            },
        ]

        with mock.patch.object(
            module, "_preflight", return_value=(True, {"status": "pass"})
        ), mock.patch.object(
            module, "_gateway_call", side_effect=fake_gateway
        ), mock.patch.object(
            module, "_agent_spawn_once", side_effect=spawn_results
        ):
            payload = module.run_probe(args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["spawn_attempted"])
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["released"], True)
        self.assertIn("duplicate spawn", payload["error"])


if __name__ == "__main__":
    unittest.main()
