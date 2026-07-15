from __future__ import annotations

import json
import unittest

from agentic_os.openclaw_adapter import AdapterContractError, OpenClawAdapter


class CannedTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, method, params):
        self.calls.append((method, dict(params)))
        if method == "subagents.allowLease.acquire":
            metadata = {
                "client_lease_id": "client-lease",
                "idempotency_key": "acquire-idem",
                "run_id": "run",
                "phase": "phase",
                "transition_id": "transition",
                "agent_id": "agent",
                "requester_agent_id": "requester",
                "ttl_ms": 60000,
                "gateway_lease_id": "lease-gateway",
            }
            return {
                "lease": {"lease_id": "lease-gateway"},
                "metadata": {
                    "metadata_contract_version": "v1",
                    "normalized": metadata,
                    "raw_json": json.dumps(
                        metadata, sort_keys=True, separators=(",", ":")
                    ),
                },
            }
        if method == "sessions_spawn":
            metadata = {
                "run_id": "run",
                "transition_id": "transition",
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "phase": "phase",
                "agent_id": "agent",
                "task_digest": "task",
            }
            return {
                "session": {
                    "session_key": "session-key",
                    "spawn_request_session_key": "session-key",
                },
                "metadata": {
                    "contract_version": "v1",
                    "normalized_metadata": metadata,
                    "raw_metadata_json": json.dumps(metadata),
                },
            }
        if method == "sessions_list":
            return {
                "sessions": [
                    {
                        "session_key": "session-key",
                        "metadata": {
                            "metadata_contract_version": "v1",
                            "external_metadata": {
                                "run_id": "run",
                                "transition_id": "transition",
                                "client_request_id": "client",
                                "idempotency_key": "spawn-idem",
                                "phase": "phase",
                                "agent_id": "agent",
                                "task_digest": "task",
                            },
                            "raw_metadata_json": json.dumps(
                                {
                                    "run_id": "run",
                                    "transition_id": "transition",
                                    "client_request_id": "client",
                                    "idempotency_key": "spawn-idem",
                                    "phase": "phase",
                                    "agent_id": "agent",
                                    "task_digest": "task",
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                    }
                ]
            }
        raise AssertionError(method)


class OpenClawAdapterTests(unittest.TestCase):
    def test_canned_allow_lease_and_spawn_responses_extract_metadata(self) -> None:
        transport = CannedTransport()
        adapter = OpenClawAdapter(transport)
        lease = adapter.allow_lease_acquire({"client_lease_id": "client-lease"})
        self.assertEqual(lease.external_id, "lease-gateway")
        self.assertEqual(lease.metadata_contract_version, "v1")
        self.assertIn('"gateway_lease_id":"lease-gateway"', lease.raw_json)

        session = adapter.sessions_spawn({"client_request_id": "client"})
        self.assertEqual(session.external_id, "session-key")
        self.assertEqual(session.session_key, "session-key")
        self.assertEqual(session.spawn_request_session_key, "session-key")

        listed = adapter.sessions_list()
        self.assertEqual(listed[0].external_id, "session-key")

    def test_missing_metadata_fails_contract(self) -> None:
        class BadTransport:
            def call(self, method, params):
                return {"ok": True}

        with self.assertRaises(AdapterContractError):
            OpenClawAdapter(BadTransport()).sessions_spawn({})

    def test_normalized_metadata_without_raw_json_fails_contract(self) -> None:
        class MissingRawTransport:
            def call(self, method, params):
                return {
                    "session": {
                        "session_key": "session-key",
                        "spawn_request_session_key": "session-key",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": {
                            "run_id": "run",
                            "transition_id": "transition",
                            "client_request_id": "client",
                            "idempotency_key": "spawn-idem",
                            "phase": "phase",
                            "agent_id": "agent",
                            "task_digest": "task",
                        },
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "raw metadata JSON"):
            OpenClawAdapter(MissingRawTransport()).sessions_spawn({})


if __name__ == "__main__":
    unittest.main()
