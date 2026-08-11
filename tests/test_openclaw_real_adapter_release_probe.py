from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "openclaw-real-adapter-release-probe.py"
)
SPEC = importlib.util.spec_from_file_location("real_adapter_release_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real adapter release probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


CATALOG = {
    "tools": [
        {
            "name": "subagents.allowLease.acquire",
            "parameters": [
                "client_lease_id",
                "idempotency_key",
                "run_id",
                "phase",
                "transition_id",
                "agent_id",
                "requester_agent_id",
                "ttl_ms",
            ],
        },
        {"name": "subagents.allowLease.status", "parameters": []},
        {
            "name": "subagents.allowLease.release",
            "parameters": [
                "client_lease_id",
                "release_idempotency_key",
                "run_id",
                "phase",
                "transition_id",
                "agent_id",
                "requester_agent_id",
                "gateway_lease_id",
            ],
        },
        {
            "name": "sessions_spawn",
            "parameters": ["client_request_id", "idempotency_key", "metadata"],
        },
        {"name": "sessions_list", "parameters": []},
        {"name": "sessions_status", "parameters": ["session_key"]},
        {
            "name": "sessions_history",
            "parameters": ["sessionKey", "limit", "includeTools"],
        },
    ]
}
RELEASE_PARAMS = {
    "client_lease_id": "client-lease:test",
    "release_idempotency_key": "release-key",
    "run_id": "run:test",
    "phase": "phase-b",
    "transition_id": "transition:test",
    "agent_id": "agent:worker",
    "requester_agent_id": "agent:main",
}


class FakeTransport:
    def __init__(self) -> None:
        self.active = False
        self.release_calls: list[dict[str, Any]] = []
        self.release_response: dict[str, Any] | None = None
        self.status_response: dict[str, Any] | None = None

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        if method == "subagents.allowLease.acquire":
            self.active = True
            return self._response(params, "gateway-lease:test")
        if method == "subagents.allowLease.release":
            self.release_calls.append(dict(params))
            self.active = False
            if self.release_response is None:
                self.release_response = self._response(
                    params, "gateway-lease:test", released=True
                )
            return self.release_response
        if method == "subagents.allowLease.status":
            if self.status_response is not None:
                return self.status_response
            return {
                "leases": [self._response({}, "gateway-lease:test")]
                if self.active
                else []
            }
        raise AssertionError(f"unexpected method: {method}")

    @staticmethod
    def _response(
        params: Mapping[str, Any], external_id: str, *, released: bool | None = None
    ) -> dict[str, Any]:
        normalized = dict(params)
        response: dict[str, Any] = {
            "external_id": external_id,
            "metadata": {
                "metadata_contract_version": "v1",
                "normalized": normalized,
                "raw_json": json.dumps(normalized, sort_keys=True),
            },
        }
        if released is not None:
            response["released"] = released
        return response


class RealAdapterReleaseProbeTests(unittest.TestCase):
    def test_unverified_factory_is_confined_to_explicit_test_path(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        production_prefix, test_suffix = source.split(
            "def run_release_probe_for_offline_tests", 1
        )
        main_source = test_suffix.split("def main", 1)[1]

        self.assertNotIn("_from_unverified_transport_for_tests", production_prefix)
        self.assertNotIn("_from_unverified_transport_for_tests", main_source)
        root = SCRIPT.parents[1]
        for path in (root / "src" / "agentic_os").rglob("*.py"):
            if path.name == "openclaw_adapter.py":
                continue
            with self.subTest(path=path.relative_to(root)):
                self.assertNotIn(
                    "_from_unverified_transport_for_tests",
                    path.read_text(encoding="utf-8"),
                )

    def test_unverified_in_process_adapter_refuses_before_any_rpc(self) -> None:
        transport = FakeTransport()
        adapter = MODULE.OpenClawAdapter._from_unverified_transport_for_tests(transport)

        with self.assertRaisesRegex(MODULE.ProbeError, "verified in-process"):
            MODULE.run_release_probe(
                adapter=adapter,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

        self.assertFalse(transport.active)
        self.assertEqual(transport.release_calls, [])

    def test_cross_process_unsigned_catalog_refuses_before_any_rpc(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(
                {
                    "acquire_params": {"idempotency_key": "acquire-key"},
                    "catalog": CATALOG,
                    "release_params": RELEASE_PARAMS,
                },
                sort_keys=True,
            )
            + "\n",
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        messages = [json.loads(line) for line in result.stdout.splitlines() if line]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["type"], "error")
        self.assertIn("unsigned cross-process catalog", messages[0]["error"])
        self.assertNotIn('"type": "rpc"', result.stdout)

    def test_canonical_release_replays_and_disappears(self) -> None:
        transport = FakeTransport()
        result = MODULE.run_release_probe_for_offline_tests(
            transport=transport,
            acquire_params={"idempotency_key": "acquire-key"},
            release_params=RELEASE_PARAMS,
        )

        self.assertTrue(all(result.values()))
        self.assertEqual(len(transport.release_calls), 2)
        self.assertEqual(
            transport.release_calls[0]["release_idempotency_key"], "release-key"
        )
        self.assertNotIn("idempotency_key", transport.release_calls[0])
        self.assertEqual(
            transport.release_calls[0]["gateway_lease_id"], "gateway-lease:test"
        )

    def test_rejects_legacy_release_metadata(self) -> None:
        transport = FakeTransport()
        transport.release_response = transport._response(
            {"idempotency_key": "legacy"}, "gateway-lease:test"
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "legacy idempotency_key"):
            MODULE.run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_release_metadata_that_does_not_match_request(self) -> None:
        transport = FakeTransport()
        wrong = dict(RELEASE_PARAMS)
        wrong["agent_id"] = "agent:other"
        wrong["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(
            wrong, "gateway-lease:test", released=True
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "does not match request"):
            MODULE.run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_explicit_unsuccessful_release_response(self) -> None:
        transport = FakeTransport()
        release = dict(RELEASE_PARAMS)
        release["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(
            release, "gateway-lease:test", released=False
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "did not report success"):
            MODULE.run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_release_response_without_success_confirmation(self) -> None:
        transport = FakeTransport()
        release = dict(RELEASE_PARAMS)
        release["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(release, "gateway-lease:test")
        with self.assertRaisesRegex(MODULE.ProbeError, "lacks success confirmation"):
            MODULE.run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_visible_post_release_lease_with_incomplete_metadata(self) -> None:
        transport = FakeTransport()
        transport.status_response = {
            "leases": [
                {
                    "gateway_lease_id": "gateway-lease:test",
                }
            ]
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "incomplete metadata"):
            MODULE.run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )


if __name__ == "__main__":
    unittest.main()
