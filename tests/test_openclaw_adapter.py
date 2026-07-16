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
        if method == "session_status":
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
                "sessionKey": params["sessionKey"],
                "session": {
                    "sessionKey": params["sessionKey"],
                    "spawnRequestSessionKey": params["sessionKey"],
                },
                "metadata": {
                    "metadata_contract_version": "v1",
                    "normalized": metadata,
                    "raw_json": json.dumps(
                        metadata, sort_keys=True, separators=(",", ":")
                    ),
                },
            }
        if method == "sessions_history":
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
                "sessionKey": params["sessionKey"],
                "spawnRequestSessionKey": params["sessionKey"],
                "messages": [{"role": "assistant", "content": "done"}],
                "metadata": {
                    "metadata_contract_version": "v1",
                    "normalized": metadata,
                    "raw_json": json.dumps(
                        metadata, sort_keys=True, separators=(",", ":")
                    ),
                },
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

        status = adapter.session_status("session-key")
        self.assertEqual(status.external_id, "session-key")
        self.assertEqual(status.session_key, "session-key")
        self.assertEqual(
            transport.calls[-1], ("session_status", {"sessionKey": "session-key"})
        )

        result = adapter.session_result("session-key")
        self.assertEqual(result.external_id, "session-key")
        self.assertEqual(result.session_key, "session-key")
        self.assertEqual(result.spawn_request_session_key, "session-key")
        self.assertIn('"messages":[{"content":"done"', result.raw_response_json)
        self.assertEqual(
            transport.calls[-1],
            (
                "sessions_history",
                {"sessionKey": "session-key", "limit": 1, "includeTools": True},
            ),
        )

    def test_session_result_missing_raw_json_fails_contract(self) -> None:
        class MissingRawResultTransport:
            def call(self, method, params):
                return {
                    "sessionKey": params["sessionKey"],
                    "spawnRequestSessionKey": params["sessionKey"],
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
            OpenClawAdapter(MissingRawResultTransport()).session_result("session-key")

    def test_session_result_missing_accepted_identity_fails_contract(self) -> None:
        class MissingIdentityResultTransport:
            def call(self, method, params):
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
                    "sessionKey": params["sessionKey"],
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(
            AdapterContractError, "accepted session identity"
        ):
            OpenClawAdapter(MissingIdentityResultTransport()).session_result(
                "session-key"
            )

    def test_session_result_conflicting_top_level_and_nested_aliases_fail_contract(
        self,
    ) -> None:
        class ConflictingResultTransport:
            def call(self, method, params):
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
                    "session_key": "session-top",
                    "session": {
                        "session_key": "session-nested",
                        "spawn_request_session_key": "session-top",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "conflicting session key"):
            OpenClawAdapter(ConflictingResultTransport()).session_result("session-key")

    def test_session_result_malformed_response_fails_contract(self) -> None:
        class MalformedResultTransport:
            def call(self, method, params):
                return ["not", "an", "object"]

        with self.assertRaisesRegex(AdapterContractError, "sessions_history response"):
            OpenClawAdapter(MalformedResultTransport()).session_result("session-key")

    def test_session_result_audit_serialization_failure_fails_contract(self) -> None:
        class NonSerializableResultTransport:
            def call(self, method, params):
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
                    "sessionKey": params["sessionKey"],
                    "spawnRequestSessionKey": params["sessionKey"],
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                    "diagnostic": object(),
                }

        with self.assertRaisesRegex(AdapterContractError, "JSON serializable"):
            OpenClawAdapter(NonSerializableResultTransport()).session_result(
                "session-key"
            )

    def test_session_result_transport_failure_is_not_swallowed(self) -> None:
        class FailingResultTransport:
            def call(self, method, params):
                raise TimeoutError("result timed out")

        with self.assertRaisesRegex(TimeoutError, "result timed out"):
            OpenClawAdapter(FailingResultTransport()).session_result("session-key")

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

    def test_conflicting_top_level_and_nested_session_key_fails_contract(self) -> None:
        class ConflictingSessionTransport:
            def call(self, method, params):
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
                    "session_key": "session-top",
                    "spawn_request_session_key": "session-top",
                    "session": {
                        "session_key": "session-nested",
                        "spawn_request_session_key": "session-top",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "conflicting session key"):
            OpenClawAdapter(ConflictingSessionTransport()).sessions_spawn({})

    def test_conflicting_nested_session_aliases_fail_contract(self) -> None:
        class ConflictingNestedAliasTransport:
            def call(self, method, params):
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
                        "session_key": "session-a",
                        "key": "session-b",
                        "spawn_request_session_key": "session-a",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "conflicting session key"):
            OpenClawAdapter(ConflictingNestedAliasTransport()).sessions_spawn({})

    def test_conflicting_spawn_request_session_aliases_fail_contract(self) -> None:
        class ConflictingSpawnRequestAliasTransport:
            def call(self, method, params):
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
                        "spawn_request_session_key": "session-a",
                        "request_session_key": "session-b",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(
            AdapterContractError, "conflicting spawn request session key"
        ):
            OpenClawAdapter(ConflictingSpawnRequestAliasTransport()).sessions_spawn({})

    def test_gateway_lease_id_is_not_a_session_identity_alias(self) -> None:
        class GatewayEchoSessionTransport:
            def call(self, method, params):
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
                    "session_key": "session-key",
                    "spawn_request_session_key": "session-key",
                    "gateway_lease_id": "lease-gateway",
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        observation = OpenClawAdapter(GatewayEchoSessionTransport()).sessions_spawn({})
        self.assertEqual(observation.external_id, "session-key")
        self.assertEqual(observation.session_key, "session-key")

    def test_list_responses_skip_malformed_unrelated_entries(self) -> None:
        class LegacyListTransport:
            def call(self, method, params):
                lease_metadata = {
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
                session_metadata = {
                    "run_id": "run",
                    "transition_id": "transition",
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                    "phase": "phase",
                    "agent_id": "agent",
                    "task_digest": "task",
                }
                if method == "subagents.allowLease.status":
                    return {
                        "leases": [
                            {"legacy": True},
                            {
                                "gateway_lease_id": "lease-gateway",
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": lease_metadata,
                                    "raw_json": json.dumps(
                                        lease_metadata,
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    ),
                                },
                            },
                        ]
                    }
                if method == "sessions_list":
                    return {
                        "sessions": [
                            {"legacy": True},
                            {
                                "session_key": "session-key",
                                "spawn_request_session_key": "session-key",
                                "gateway_lease_id": "lease-gateway",
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": session_metadata,
                                    "raw_json": json.dumps(
                                        session_metadata,
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    ),
                                },
                            },
                        ]
                    }
                raise AssertionError(method)

        adapter = OpenClawAdapter(LegacyListTransport())
        self.assertEqual(
            [observation.external_id for observation in adapter.allow_lease_list()],
            ["lease-gateway"],
        )
        self.assertEqual(
            [observation.external_id for observation in adapter.sessions_list()],
            ["session-key"],
        )

    def test_list_responses_reject_malformed_top_level_containers(self) -> None:
        class MalformedListTransport:
            def call(self, method, params):
                if method == "subagents.allowLease.status":
                    return {"leases": "not-an-array"}
                if method == "sessions_list":
                    return {"sessions": {"legacy": True}}
                raise AssertionError(method)

        adapter = OpenClawAdapter(MalformedListTransport())
        with self.assertRaisesRegex(AdapterContractError, "lease response"):
            adapter.allow_lease_list()
        with self.assertRaisesRegex(AdapterContractError, "session response"):
            adapter.sessions_list()


if __name__ == "__main__":
    unittest.main()
