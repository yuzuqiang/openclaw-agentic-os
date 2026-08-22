from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from agentic_os.openclaw_adapter import (
    AdapterContractError,
    MetadataObservation,
    OpenClawAdapter,
    assert_installed_runtime_tools,
    assert_installed_session_tools,
)
from tests.openclaw_adapter_test_harness import CannedOpenClawAdapter


TASK = "task body"
TASK_DIGEST = hashlib.sha256(TASK.encode("utf-8")).hexdigest()
SPAWN_RPC_PROPERTIES = {
    "task": {"type": "string"},
    "taskName": {"type": "string"},
    "runtime": {"type": "string"},
    "mode": {"type": "string"},
    "agentId": {"type": "string"},
    "cleanup": {"type": "string"},
    "context": {"type": "string"},
    "lightContext": {"type": "boolean"},
    "client_request_id": {"type": "string"},
    "idempotency_key": {"type": "string"},
    "gateway_lease_id": {"type": "string"},
    "metadata": {"type": "object"},
}


INSTALLED_SESSION_TOOL_CATALOG = {
    "tools": [
        {
            "name": "sessions_spawn",
            "inputSchema": {
                "properties": dict(SPAWN_RPC_PROPERTIES)
            },
        },
        {"name": "sessions_list", "inputSchema": {"properties": {}}},
        {
            "name": "session_status",
            "inputSchema": {"properties": {"sessionKey": {"type": "string"}}},
        },
        {
            "name": "sessions_history",
            "inputSchema": {
                "properties": {
                    "sessionKey": {"type": "string"},
                    "limit": {"type": "integer"},
                    "includeTools": {"type": "boolean"},
                }
            },
        },
    ]
}

INSTALLED_RUNTIME_TOOL_CATALOG = {
    "tools": [
        {
            "name": "subagents.allowLease.acquire",
            "inputSchema": {
                "properties": {
                    "client_lease_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "run_id": {"type": "string"},
                    "phase": {"type": "string"},
                    "transition_id": {"type": "string"},
                    "agent_id": {"type": "string"},
                    "requester_agent_id": {"type": "string"},
                    "ttl_ms": {"type": "integer"},
                }
            },
        },
        {
            "name": "subagents.allowLease.status",
            "inputSchema": {"properties": {}},
        },
        {
            "name": "subagents.allowLease.release",
            "inputSchema": {
                "properties": {
                    "client_lease_id": {"type": "string"},
                    "release_idempotency_key": {"type": "string"},
                    "run_id": {"type": "string"},
                    "phase": {"type": "string"},
                    "transition_id": {"type": "string"},
                    "agent_id": {"type": "string"},
                    "requester_agent_id": {"type": "string"},
                    "gateway_lease_id": {"type": "string"},
                }
            },
        },
        *INSTALLED_SESSION_TOOL_CATALOG["tools"],
    ]
}


def verified_runtime_envelope() -> dict[str, Any]:
    catalog = json.loads(json.dumps(INSTALLED_RUNTIME_TOOL_CATALOG))
    model_tools = json.loads(
        json.dumps(
            [
                tool
                for tool in catalog["tools"]
                if tool["name"]
                in {
                    "sessions_spawn",
                    "sessions_list",
                    "session_status",
                    "sessions_history",
                }
            ]
        )
    )
    gateway_tools = json.loads(
        json.dumps(
            [
                tool
                for tool in catalog["tools"]
                if tool["name"].startswith("subagents.allowLease.")
            ]
        )
    )
    catalog.update(
        {
            "active_executable_sha256": "c" * 64,
            "catalog_kind": "sanitized_openclaw_runtime",
            "connected_gateway_build_evidence": {
                "connected_executable_sha256": "c" * 64,
                "status": "proven",
                "verification_method": "gateway_reported_executable_sha256",
            },
            "connected_gateway_build_identity": "proven",
            "gateway_rpc_catalog": {
                "authority": "installed_runtime_sources",
                "catalog_kind": "source_bound_gateway_rpc_catalog",
                "rpc_evidence": [
                    {
                        "disk_source_declaration": "observed",
                        "live_reachability": "reachable",
                        "live_probe": {
                            "live_reachability": "reachable",
                            "method": name,
                            "raw_response_sha256": (
                                "b" * 64
                                if name == "subagents.allowLease.status"
                                else "d" * 64
                            ),
                            "request_semantics": (
                                "read_only_request"
                                if name == "subagents.allowLease.status"
                                else "bounded_contract_probe"
                            ),
                            "status": "ok",
                        },
                        "name": name,
                    }
                    for name in (
                        "subagents.allowLease.acquire",
                        "subagents.allowLease.status",
                        "subagents.allowLease.release",
                    )
                ],
                "source_bound_rpc_names": [
                    "subagents.allowLease.acquire",
                    "subagents.allowLease.release",
                    "subagents.allowLease.status",
                ],
                "status": "disk_source_declarations_complete",
                "status_corroboration": {
                    "live_reachability": "reachable",
                    "method": "subagents.allowLease.status",
                    "raw_response_sha256": "b" * 64,
                    "request_semantics": "read_only_request",
                    "status": "ok",
                },
                "tools": gateway_tools,
            },
            "model_tool_catalog": {
                "authority": "tools.catalog",
                "catalog_kind": "model_callable_tools_catalog",
                "raw_response_sha256": "a" * 64,
                "tools": model_tools,
            },
            "runtime_target": "live_installed_openclaw",
        }
    )
    return {"catalog": catalog, "runtime_ready": True, "status": "pass"}


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
                "task_digest": TASK_DIGEST,
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
                                "task_digest": TASK_DIGEST,
                            },
                            "raw_metadata_json": json.dumps(
                                {
                                    "run_id": "run",
                                    "transition_id": "transition",
                                    "client_request_id": "client",
                                    "idempotency_key": "spawn-idem",
                                    "phase": "phase",
                                    "agent_id": "agent",
                                    "task_digest": TASK_DIGEST,
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
                "task_digest": TASK_DIGEST,
            }
            return {
                "session_key": params["sessionKey"],
                "session": {
                    "session_key": params["sessionKey"],
                    "spawn_request_session_key": params["sessionKey"],
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
                "task_digest": TASK_DIGEST,
            }
            return {
                "sessionKey": params["sessionKey"],
                "spawnRequestSessionKey": params["sessionKey"],
                "messages": [
                    {
                        "role": "assistant",
                        "content": "done",
                        "sessionKey": params["sessionKey"],
                        "spawnRequestSessionKey": params["sessionKey"],
                    }
                ],
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
        adapter = CannedOpenClawAdapter(transport)
        self.assertFalse(adapter.runtime_authority_verified)
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

    def test_history_messages_without_item_identity_fail_contract(self) -> None:
        class MessageOnlyHistoryTransport(CannedTransport):
            def call(self, method, params):
                if method == "sessions_history":
                    metadata = {
                        "run_id": "run",
                        "transition_id": "transition",
                        "client_request_id": "client",
                        "idempotency_key": "spawn-idem",
                        "phase": "phase",
                        "agent_id": "agent",
                        "task_digest": TASK_DIGEST,
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
                return super().call(method, params)

        adapter = CannedOpenClawAdapter(MessageOnlyHistoryTransport())
        with self.assertRaisesRegex(
            AdapterContractError, "messages\\[0\\] must include requested session identity"
        ):
            adapter.session_result("session-key")

    def test_fully_forged_valid_envelope_cannot_mint_runtime_authority(self) -> None:
        with self.assertRaisesRegex(AdapterContractError, "unsigned preflight mapping"):
            OpenClawAdapter.from_preflighted_catalog(
                CannedTransport(), verified_runtime_envelope()
            )

    def test_preflighted_adapter_rejects_plain_schema_catalog(self) -> None:
        assert_installed_runtime_tools(INSTALLED_RUNTIME_TOOL_CATALOG)

        with self.assertRaisesRegex(
            AdapterContractError, "envelope status must be pass"
        ):
            OpenClawAdapter.from_preflighted_catalog(
                CannedTransport(), INSTALLED_RUNTIME_TOOL_CATALOG
            )

    def test_direct_constructor_is_inert(self) -> None:
        with self.assertRaisesRegex(AdapterContractError, "transport-bound.*attestor"):
            OpenClawAdapter(CannedTransport())

    def test_object_new_and_injected_state_cannot_reach_transport(self) -> None:
        class RecordingTransport:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, Any]]] = []

            def call(self, method, params):
                self.calls.append((method, dict(params)))
                return {}

        transport = RecordingTransport()
        adapter = object.__new__(OpenClawAdapter)
        adapter.__dict__.update(
            {
                "_transport": transport,
                "_authority_mode": "verified_runtime",
                "_authority_capability": object(),
                "_runtime_authority_verified": True,
                "_verified_runtime_authority": True,
            }
        )
        calls = (
            lambda: adapter.allow_lease_acquire({}),
            adapter.allow_lease_list,
            lambda: adapter.allow_lease_release({}),
            lambda: adapter.sessions_spawn({}),
            adapter.sessions_list,
            lambda: adapter.session_status("session-key"),
            lambda: adapter.session_result("session-key"),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaisesRegex(
                    AdapterContractError, "no verified transport-bound"
                ):
                    call()
                self.assertEqual(transport.calls, [])

    def test_duplicate_sessions_spawn_changed_descriptor_rejected_before_rpc(
        self,
    ) -> None:
        metadata = {
            "run_id": "run",
            "transition_id": "transition",
            "client_request_id": "client",
            "idempotency_key": "spawn-idem",
            "phase": "phase",
            "agent_id": "agent",
            "task_digest": TASK_DIGEST,
        }

        def spawn_request(gateway_lease_id: str) -> dict[str, Any]:
            return {
                "task": TASK,
                "taskName": "task-name",
                "runtime": "subagent",
                "mode": "run",
                "agentId": "agent",
                "cleanup": "delete",
                "context": "isolated",
                "lightContext": False,
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "gateway_lease_id": gateway_lease_id,
                "metadata": dict(metadata),
            }

        calls: list[tuple[str, dict[str, Any]]] = []

        def call(logical_name, params):
            calls.append((logical_name, dict(params)))
            return (
                "sessions_spawn",
                {
                    "session": {
                        "session_key": "session-key",
                        "spawn_request_session_key": "session-key",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": dict(metadata),
                        "raw_json": json.dumps(
                            metadata,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                },
            )

        adapter = object.__new__(OpenClawAdapter)
        adapter._require_verified_runtime_authority = lambda: SimpleNamespace(
            attestation=SimpleNamespace(
                method_bindings={
                    "sessions_spawn": SimpleNamespace(
                        parameter_names=tuple(SPAWN_RPC_PROPERTIES)
                    )
                }
            )
        )
        adapter._call = call
        adapter._lease_metadata_by_external_id = {
            "lease-one": {**metadata, "gateway_lease_id": "lease-one"},
            "lease-two": {**metadata, "gateway_lease_id": "lease-two"},
        }
        adapter._session_metadata_by_key = {}
        adapter._session_identity_by_request = {}
        adapter._session_spawn_request_by_request_identity = {}

        observation = adapter.sessions_spawn(spawn_request("lease-one"))
        self.assertEqual(observation.session_key, "session-key")
        with self.assertRaisesRegex(
            AdapterContractError,
            "duplicate sessions_spawn request changed execution descriptor",
        ):
            adapter.sessions_spawn(spawn_request("lease-two"))
        self.assertEqual(len(calls), 1)

    def test_changed_sessions_spawn_duplicate_after_malformed_response_rejected_before_rpc(
        self,
    ) -> None:
        metadata = {
            "run_id": "run",
            "transition_id": "transition",
            "client_request_id": "client",
            "idempotency_key": "spawn-idem",
            "phase": "phase",
            "agent_id": "agent",
            "task_digest": TASK_DIGEST,
        }

        def spawn_request(gateway_lease_id: str) -> dict[str, Any]:
            return {
                "task": TASK,
                "taskName": "task-name",
                "runtime": "subagent",
                "mode": "run",
                "agentId": "agent",
                "cleanup": "delete",
                "context": "isolated",
                "lightContext": False,
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "gateway_lease_id": gateway_lease_id,
                "metadata": dict(metadata),
            }

        calls: list[tuple[str, dict[str, Any]]] = []

        def call(logical_name, params):
            calls.append((logical_name, dict(params)))
            raw_metadata = dict(metadata)
            raw_metadata.pop("task_digest")
            return (
                "sessions_spawn",
                {
                    "session": {
                        "session_key": "session-key",
                        "spawn_request_session_key": "session-key",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": dict(metadata),
                        "raw_json": json.dumps(
                            raw_metadata,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                },
            )

        adapter = object.__new__(OpenClawAdapter)
        adapter._require_verified_runtime_authority = lambda: SimpleNamespace(
            attestation=SimpleNamespace(
                method_bindings={
                    "sessions_spawn": SimpleNamespace(
                        parameter_names=tuple(SPAWN_RPC_PROPERTIES)
                    )
                }
            )
        )
        adapter._call = call
        adapter._lease_metadata_by_external_id = {
            "lease-one": {**metadata, "gateway_lease_id": "lease-one"},
            "lease-two": {**metadata, "gateway_lease_id": "lease-two"},
        }
        adapter._session_metadata_by_key = {}
        adapter._session_identity_by_request = {}
        adapter._session_spawn_request_by_request_identity = {}

        with self.assertRaisesRegex(
            AdapterContractError, "raw external metadata is missing required fields"
        ):
            adapter.sessions_spawn(spawn_request("lease-one"))
        with self.assertRaisesRegex(
            AdapterContractError,
            "duplicate sessions_spawn request changed execution descriptor",
        ):
            adapter.sessions_spawn(spawn_request("lease-two"))
        self.assertEqual(len(calls), 1)

    def test_sessions_spawn_rejects_session_key_cached_for_another_request(
        self,
    ) -> None:
        metadata_one = {
            "run_id": "run",
            "transition_id": "transition",
            "client_request_id": "client-one",
            "idempotency_key": "spawn-idem-one",
            "phase": "phase",
            "agent_id": "agent",
            "task_digest": TASK_DIGEST,
        }
        metadata_two = {
            **metadata_one,
            "client_request_id": "client-two",
            "idempotency_key": "spawn-idem-two",
        }
        metadata_by_lease = {
            "lease-one": metadata_one,
            "lease-two": metadata_two,
        }

        def spawn_request(gateway_lease_id: str) -> dict[str, Any]:
            metadata = metadata_by_lease[gateway_lease_id]
            return {
                "task": TASK,
                "taskName": f"task-name-{gateway_lease_id}",
                "runtime": "subagent",
                "mode": "run",
                "agentId": "agent",
                "cleanup": "delete",
                "context": "isolated",
                "lightContext": False,
                "client_request_id": metadata["client_request_id"],
                "idempotency_key": metadata["idempotency_key"],
                "gateway_lease_id": gateway_lease_id,
                "metadata": dict(metadata),
            }

        def call(logical_name, params):
            metadata = metadata_by_lease[params["gateway_lease_id"]]
            return (
                "sessions_spawn",
                {
                    "session": {
                        "session_key": "shared-session-key",
                        "spawn_request_session_key": "shared-session-key",
                    },
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": dict(metadata),
                        "raw_json": json.dumps(
                            metadata,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                },
            )

        adapter = object.__new__(OpenClawAdapter)
        adapter._require_verified_runtime_authority = lambda: SimpleNamespace(
            attestation=SimpleNamespace(
                method_bindings={
                    "sessions_spawn": SimpleNamespace(
                        parameter_names=tuple(SPAWN_RPC_PROPERTIES)
                    )
                }
            )
        )
        adapter._call = call
        adapter._lease_metadata_by_external_id = {
            lease: {**metadata, "gateway_lease_id": lease}
            for lease, metadata in metadata_by_lease.items()
        }
        adapter._session_metadata_by_key = {}
        adapter._session_identity_by_request = {}
        adapter._session_spawn_request_by_request_identity = {}

        observation = adapter.sessions_spawn(spawn_request("lease-one"))
        self.assertEqual(observation.session_key, "shared-session-key")
        with self.assertRaisesRegex(
            AdapterContractError,
            "session identity is already cached for different request metadata",
        ):
            adapter.sessions_spawn(spawn_request("lease-two"))
        self.assertEqual(
            adapter._session_metadata_by_key["shared-session-key"], metadata_one
        )

    def test_verified_lease_adoption_restores_release_ownership(self) -> None:
        acquire_metadata = {
            "run_id": "run",
            "transition_id": "transition",
            "phase": "phase",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "client_lease_id": "client-lease",
            "idempotency_key": "acquire-idem",
            "ttl_ms": 60000,
            "gateway_lease_id": "lease-gateway",
        }
        release_metadata = {
            "client_lease_id": "client-lease",
            "release_idempotency_key": "release-idem",
            "run_id": "run",
            "phase": "phase",
            "transition_id": "transition",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "gateway_lease_id": "lease-gateway",
        }
        calls: list[tuple[str, dict[str, Any]]] = []

        def call(logical_name, params):
            calls.append((logical_name, dict(params)))
            return (
                "allow_lease_release",
                {
                    "gateway_lease_id": "lease-gateway",
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": dict(release_metadata),
                        "raw_json": json.dumps(
                            release_metadata,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                },
            )

        adapter = object.__new__(OpenClawAdapter)
        adapter._require_verified_runtime_authority = lambda: SimpleNamespace()
        adapter._call = call
        adapter._lease_metadata_by_external_id = {}
        adapter.adopt_verified_lease_ownership(
            dict(acquire_metadata),
            MetadataObservation(
                metadata_contract_version="v1",
                normalized=dict(acquire_metadata),
                raw_json=json.dumps(
                    acquire_metadata, sort_keys=True, separators=(",", ":")
                ),
                external_id="lease-gateway",
            ),
        )
        observation = adapter.allow_lease_release(dict(release_metadata))

        self.assertEqual(observation.external_id, "lease-gateway")
        self.assertEqual(calls, [("allow_lease_release", release_metadata)])

    def test_production_tree_has_no_authority_token_or_test_transport_factory(self) -> None:
        root = Path(__file__).resolve().parents[1]
        production = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in (root / "src", root / "scripts")
            for path in directory.rglob("*.py")
        )
        for forbidden in (
            "_AdapterConstructionCapability",
            "_RUNTIME_AUTHORITY_CAPABILITY_GUARD",
            "_UNVERIFIED_TEST_CAPABILITY_GUARD",
            "_from_verified_runtime_authority",
            "_from_unverified_transport_for_tests",
            "run_release_probe_for_offline_tests",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, production)

    def test_preflighted_adapter_rejects_unproven_connected_build(self) -> None:
        payload = verified_runtime_envelope()
        payload["catalog"]["connected_gateway_build_identity"] = "unproven"

        with self.assertRaisesRegex(AdapterContractError, "build identity is not proven"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_non_pass_or_offline_envelope(self) -> None:
        payload = verified_runtime_envelope()
        payload["status"] = "declared_schema_validated"
        payload["runtime_ready"] = False

        with self.assertRaisesRegex(
            AdapterContractError, "status must be pass.*runtime_ready=true"
        ):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_aggregate_nested_mismatch(self) -> None:
        payload = verified_runtime_envelope()
        spawn = next(
            item
            for item in payload["catalog"]["model_tool_catalog"]["tools"]
            if item["name"] == "sessions_spawn"
        )
        spawn["inputSchema"]["properties"]["unexpected"] = {"type": "string"}

        with self.assertRaisesRegex(AdapterContractError, "aggregate.*disagree"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_alternate_rpc_evidence_shape(self) -> None:
        payload = verified_runtime_envelope()
        payload["catalog"]["gateway_rpc_catalog"]["rpc_evidence"] = {
            "subagents.allowLease.status": {"live_reachability": "reachable"}
        }

        with self.assertRaisesRegex(AdapterContractError, "evidence must be a list"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_runtime_tool_catalog_preflight_rejects_missing_allow_lease_tool(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            AdapterContractError, "subagents\\.allowLease\\.acquire"
        ):
            assert_installed_runtime_tools(INSTALLED_SESSION_TOOL_CATALOG)

    def test_runtime_tool_catalog_preflight_rejects_missing_release_owner_parameter(
        self,
    ) -> None:
        catalog = json.loads(json.dumps(INSTALLED_RUNTIME_TOOL_CATALOG))
        release_tool = next(
            tool
            for tool in catalog["tools"]
            if tool["name"] == "subagents.allowLease.release"
        )
        del release_tool["inputSchema"]["properties"]["gateway_lease_id"]

        with self.assertRaisesRegex(AdapterContractError, "gateway_lease_id"):
            assert_installed_runtime_tools(catalog)

    def test_preflighted_adapter_rejects_source_only_gateway_rpc_authority(self) -> None:
        payload = verified_runtime_envelope()
        rpc_evidence = payload["catalog"]["gateway_rpc_catalog"]["rpc_evidence"]
        for item in rpc_evidence:
            if item["name"] != "subagents.allowLease.status":
                item["live_reachability"] = "unproven"

        with self.assertRaisesRegex(
            AdapterContractError,
            "acquire live reachability is unproven.*release live reachability is unproven",
        ):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_duplicate_gateway_rpc_evidence(self) -> None:
        payload = verified_runtime_envelope()
        rpc_evidence = payload["catalog"]["gateway_rpc_catalog"]["rpc_evidence"]
        rpc_evidence.append(json.loads(json.dumps(rpc_evidence[0])))

        with self.assertRaisesRegex(AdapterContractError, "duplicates.*acquire"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_bare_reachability_claim(self) -> None:
        payload = verified_runtime_envelope()
        rpc_evidence = payload["catalog"]["gateway_rpc_catalog"]["rpc_evidence"]
        status = next(
            item
            for item in rpc_evidence
            if item["name"] == "subagents.allowLease.status"
        )
        del status["live_probe"]

        with self.assertRaisesRegex(AdapterContractError, "method-bound live probe"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_preflighted_adapter_rejects_status_corroboration_probe_mismatch(
        self,
    ) -> None:
        payload = verified_runtime_envelope()
        payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"][
            "raw_response_sha256"
        ] = "e" * 64

        with self.assertRaisesRegex(AdapterContractError, "must exactly match"):
            OpenClawAdapter.from_preflighted_catalog(CannedTransport(), payload)

    def test_session_tool_catalog_preflight_rejects_missing_history_parameter(self) -> None:
        catalog = {
            "tools": {
                "sessions_spawn": {
                    "parameters": {
                        **{key: {} for key in SPAWN_RPC_PROPERTIES},
                    }
                },
                "sessions_list": {"parameters": {}},
                "session_status": {"parameters": {"sessionKey": {}}},
                "sessions_history": {
                    "parameters": {"sessionKey": {}, "limit": {}}
                },
            }
        }

        with self.assertRaisesRegex(AdapterContractError, "includeTools"):
            assert_installed_session_tools(catalog)

    def test_session_tool_catalog_preflight_rejects_missing_spawn_metadata_parameter(
        self,
    ) -> None:
        catalog = {
            "tools": {
                "sessions_spawn": {
                    "parameters": {"client_request_id": {}, "idempotency_key": {}}
                },
                "sessions_list": {"parameters": {}},
                "session_status": {"parameters": {"sessionKey": {}}},
                "sessions_history": {
                    "parameters": {
                        "sessionKey": {},
                        "limit": {},
                        "includeTools": {},
                    }
                },
            }
        }

        with self.assertRaisesRegex(AdapterContractError, "metadata"):
            assert_installed_session_tools(catalog)

    def test_session_tool_catalog_preflight_rejects_duplicate_required_tool_names(
        self,
    ) -> None:
        catalog = {
            "tools": [
                {
                    "name": "sessions_spawn",
                    "inputSchema": {
                        "properties": {
                            "client_request_id": {"type": "string"},
                            "idempotency_key": {"type": "string"},
                        }
                    },
                },
                {
                    "name": "sessions_spawn",
                    "inputSchema": {
                        "properties": {
                            **SPAWN_RPC_PROPERTIES,
                        }
                    },
                },
                {"name": "sessions_list", "inputSchema": {"properties": {}}},
                {
                    "name": "session_status",
                    "inputSchema": {
                        "properties": {"sessionKey": {"type": "string"}}
                    },
                },
                {
                    "name": "sessions_history",
                    "inputSchema": {
                        "properties": {
                            "sessionKey": {"type": "string"},
                            "limit": {"type": "integer"},
                            "includeTools": {"type": "boolean"},
                        }
                    },
                },
            ]
        }

        with self.assertRaisesRegex(AdapterContractError, "duplicate sessions_spawn"):
            assert_installed_session_tools(catalog)

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
            CannedOpenClawAdapter(
                MissingRawResultTransport()
            ).session_result("session-key")

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
            CannedOpenClawAdapter(
                MissingIdentityResultTransport()
            ).session_result("session-key")

    def test_session_result_different_history_session_fails_contract(self) -> None:
        class DifferentSessionResultTransport:
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
                    "sessionKey": "other-session",
                    "spawnRequestSessionKey": "other-session",
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "requested session"):
            CannedOpenClawAdapter(
                DifferentSessionResultTransport()
            ).session_result("session-key")

    def test_session_result_different_history_item_session_fails_contract(self) -> None:
        class DifferentHistoryItemResultTransport:
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
                    "messages": [
                        {
                            "role": "assistant",
                            "content": "done",
                            "sessionKey": "other-session",
                            "spawnRequestSessionKey": "other-session",
                        }
                    ],
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "messages\\[0\\]"):
            CannedOpenClawAdapter(
                DifferentHistoryItemResultTransport()
            ).session_result("session-key")

    def test_session_result_accepts_history_item_top_level_key_alias(self) -> None:
        class TopLevelKeyHistoryItemTransport:
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
                    "messages": [
                        {
                            "role": "assistant",
                            "content": "done",
                            "key": params["sessionKey"],
                        }
                    ],
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        result = CannedOpenClawAdapter(
            TopLevelKeyHistoryItemTransport()
        ).session_result("session-key")

        self.assertEqual(result.session_key, "session-key")

    def test_session_result_different_history_item_external_id_fails_contract(
        self,
    ) -> None:
        class DifferentHistoryItemExternalIdTransport:
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
                    "messages": [
                        {
                            "role": "assistant",
                            "content": "done",
                            "external_id": "other-session",
                        }
                    ],
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "messages\\[0\\]"):
            CannedOpenClawAdapter(
                DifferentHistoryItemExternalIdTransport()
            ).session_result("session-key")

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
            CannedOpenClawAdapter(
                ConflictingResultTransport()
            ).session_result("session-key")

    def test_session_result_malformed_response_fails_contract(self) -> None:
        class MalformedResultTransport:
            def call(self, method, params):
                return ["not", "an", "object"]

        with self.assertRaisesRegex(AdapterContractError, "sessions_history response"):
            CannedOpenClawAdapter(
                MalformedResultTransport()
            ).session_result("session-key")

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
            CannedOpenClawAdapter(
                NonSerializableResultTransport()
            ).session_result("session-key")

    def test_session_result_transport_failure_is_not_swallowed(self) -> None:
        class FailingResultTransport:
            def call(self, method, params):
                raise TimeoutError("result timed out")

        with self.assertRaisesRegex(TimeoutError, "result timed out"):
            CannedOpenClawAdapter(
                FailingResultTransport()
            ).session_result("session-key")

    def test_missing_metadata_fails_contract(self) -> None:
        class BadTransport:
            def call(self, method, params):
                return {"ok": True}

        with self.assertRaises(AdapterContractError):
            CannedOpenClawAdapter(
                BadTransport()
            ).sessions_spawn({})

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
            CannedOpenClawAdapter(
                MissingRawTransport()
            ).sessions_spawn({})

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
            CannedOpenClawAdapter(
                ConflictingSessionTransport()
            ).sessions_spawn({})

    def test_conflicting_nested_session_external_id_fails_contract(self) -> None:
        class ConflictingExternalAliasTransport:
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
                    "sessionKey": "session-key",
                    "spawnRequestSessionKey": "session-key",
                    "session": {"external_id": "other-session"},
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": metadata,
                        "raw_json": json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "conflicting session external identity"):
            CannedOpenClawAdapter(
                ConflictingExternalAliasTransport()
            ).sessions_spawn({})

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
            CannedOpenClawAdapter(
                ConflictingNestedAliasTransport()
            ).sessions_spawn({})

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
            CannedOpenClawAdapter(
                ConflictingSpawnRequestAliasTransport()
            ).sessions_spawn({})

    def test_conflicting_top_level_and_nested_metadata_aliases_fail_contract(self) -> None:
        class ConflictingMetadataContainerTransport:
            def call(self, method, params):
                nested_metadata = {
                    "run_id": "run",
                    "transition_id": "transition",
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                    "phase": "phase",
                    "agent_id": "agent",
                    "task_digest": "task",
                }
                top_level_metadata = dict(nested_metadata)
                top_level_metadata["run_id"] = "other-run"
                return {
                    "session_key": "session-key",
                    "spawn_request_session_key": "session-key",
                    "external_metadata": top_level_metadata,
                    "raw_metadata_json": json.dumps(
                        top_level_metadata, sort_keys=True, separators=(",", ":")
                    ),
                    "metadata": {
                        "metadata_contract_version": "v1",
                        "normalized": nested_metadata,
                        "raw_json": json.dumps(
                            nested_metadata, sort_keys=True, separators=(",", ":")
                        ),
                    },
                }

        with self.assertRaisesRegex(AdapterContractError, "conflicting normalized metadata"):
            CannedOpenClawAdapter(
                ConflictingMetadataContainerTransport()
            ).sessions_spawn({})

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

        observation = CannedOpenClawAdapter(
            GatewayEchoSessionTransport()
        ).sessions_spawn({})
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

        adapter = CannedOpenClawAdapter(
            LegacyListTransport()
        )
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

        adapter = CannedOpenClawAdapter(
            MalformedListTransport()
        )
        with self.assertRaisesRegex(AdapterContractError, "lease response"):
            adapter.allow_lease_list()
        with self.assertRaisesRegex(AdapterContractError, "session response"):
            adapter.sessions_list()

    def test_list_responses_reject_malformed_items_even_with_one_match(self) -> None:
        class MalformedItemTransport:
            def call(self, method, params):
                if method == "subagents.allowLease.status":
                    return {
                        "leases": [
                            {
                                "gateway_lease_id": "lease-gateway",
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": {
                                        "gateway_lease_id": "lease-gateway"
                                    },
                                    "raw_json": json.dumps(
                                        {"gateway_lease_id": "lease-gateway"},
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    ),
                                },
                            },
                            "not-an-object",
                        ]
                    }
                if method == "sessions_list":
                    return {
                        "sessions": [
                            {
                                "session_key": "session-key",
                                "spawn_request_session_key": "session-key",
                                "metadata": {
                                    "metadata_contract_version": "v1",
                                    "normalized": {"session_key": "session-key"},
                                    "raw_json": json.dumps(
                                        {"session_key": "session-key"},
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    ),
                                },
                            },
                            7,
                        ]
                    }
                raise AssertionError(method)

        adapter = CannedOpenClawAdapter(MalformedItemTransport())
        with self.assertRaisesRegex(AdapterContractError, "malformed lease item"):
            adapter.allow_lease_list()
        with self.assertRaisesRegex(AdapterContractError, "malformed session item"):
            adapter.sessions_list()


if __name__ == "__main__":
    unittest.main()
