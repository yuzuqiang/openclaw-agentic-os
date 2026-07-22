from __future__ import annotations

import importlib.util
import json
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
                self.release_response = self._response(params, "gateway-lease:test")
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
    def _response(params: Mapping[str, Any], external_id: str) -> dict[str, Any]:
        normalized = dict(params)
        return {
            "external_id": external_id,
            "metadata": {
                "metadata_contract_version": "v1",
                "normalized": normalized,
                "raw_json": json.dumps(normalized, sort_keys=True),
            },
        }


class RealAdapterReleaseProbeTests(unittest.TestCase):
    def test_canonical_release_replays_and_disappears(self) -> None:
        transport = FakeTransport()
        result = MODULE.run_release_probe(
            transport=transport,
            catalog=CATALOG,
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
            MODULE.run_release_probe(
                transport=transport,
                catalog=CATALOG,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_release_metadata_that_does_not_match_request(self) -> None:
        transport = FakeTransport()
        wrong = dict(RELEASE_PARAMS)
        wrong["agent_id"] = "agent:other"
        wrong["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(wrong, "gateway-lease:test")
        with self.assertRaisesRegex(MODULE.ProbeError, "does not match request"):
            MODULE.run_release_probe(
                transport=transport,
                catalog=CATALOG,
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
            MODULE.run_release_probe(
                transport=transport,
                catalog=CATALOG,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )


if __name__ == "__main__":
    unittest.main()
