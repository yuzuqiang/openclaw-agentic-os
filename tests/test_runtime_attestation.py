from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from agentic_os.openclaw_adapter import AdapterContractError, OpenClawAdapter
from agentic_os.runtime_attestation import (
    GatewayCliAttestedTransport,
    RuntimeAttestationError,
    canonical_json_bytes,
)
from tests.test_openclaw_adapter import verified_runtime_envelope


NOW_MS = 1_800_000_000_000


def method_bindings() -> dict[str, dict[str, object]]:
    return {
        "allow_lease_acquire": {
            "method": "subagents.allowLease.acquire",
            "parameter_names": [
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
        "allow_lease_status": {
            "method": "subagents.allowLease.status",
            "parameter_names": [],
        },
        "allow_lease_release": {
            "method": "subagents.allowLease.release",
            "parameter_names": [
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
        "sessions_spawn": {
            "method": "sessions_spawn",
            "parameter_names": ["client_request_id", "idempotency_key", "metadata"],
        },
        "sessions_list": {"method": "sessions_list", "parameter_names": []},
        "session_status": {
            "method": "session_status",
            "parameter_names": ["sessionKey"],
        },
        "sessions_history": {
            "method": "sessions_history",
            "parameter_names": ["sessionKey", "limit", "includeTools"],
        },
    }


def binding() -> dict[str, object]:
    return {
        "executable": {"path_sha256": "0" * 64, "content_sha256": "1" * 64},
        "install": {
            "root_sha256": "6" * 64,
            "package_json_sha256": "2" * 64,
            "package_name": "openclaw",
            "version": "2026.7.1",
        },
        "sources": [
            {"path": "dist/openclaw-tools.js", "sha256": "3" * 64},
            {"path": "dist/server-methods.js", "sha256": "4" * 64},
        ],
        "catalog": {"authority": "tools.catalog", "sha256": "5" * 64},
        "gateway": {
            "endpoint": "ws://127.0.0.1:18789",
            "version": "2026.7.1",
            "build_id": "2d2ddc4",
            "process_identity": "gateway-pid:start-token",
        },
        "transport": {"kind": "gateway-websocket", "identity": "socket-identity"},
    }


class DigestVerifier:
    def verify(self, *, payload: bytes, signature: str, algorithm: str) -> bool:
        return algorithm == "ed25519" and signature == hashlib.sha256(
            b"test-verifier:" + payload
        ).hexdigest()


class FakeAttestedTransport:
    def __init__(self) -> None:
        self.binding = binding()
        self.methods = method_bindings()
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.identity_reads = 0
        self.envelope_overrides: dict[str, object] = {}
        self.mutate_signed_payload = None
        self.spawn_error: Exception | None = None
        self.spawn_session_key = "session-1"
        self.spawn_normalized_override: dict[str, object] | None = None
        self.spawn_raw_override: str | None = None

    def runtime_identity_snapshot(self):
        self.identity_reads += 1
        return {
            "binding": deepcopy(self.binding),
            "method_bindings": deepcopy(self.methods),
        }

    def request_runtime_attestation(self, *, challenge, client_process_id):
        payload = {
            "schema_version": "agentic-os.openclaw-attestation.v1",
            "online": True,
            "challenge": challenge,
            "nonce": challenge,
            "issued_at_epoch_ms": NOW_MS - 1_000,
            "expires_at_epoch_ms": NOW_MS + 60_000,
            "client_process_id": client_process_id,
            "binding": deepcopy(self.binding),
            "method_bindings": deepcopy(self.methods),
        }
        payload.update(deepcopy(self.envelope_overrides))
        signature = hashlib.sha256(
            b"test-verifier:" + canonical_json_bytes(payload)
        ).hexdigest()
        if self.mutate_signed_payload is not None:
            self.mutate_signed_payload(payload)
        return {
            "signature_algorithm": "ed25519",
            "signature": signature,
            "signed_payload": payload,
        }

    @staticmethod
    def _metadata(payload):
        return {
            "metadata_contract_version": "v1",
            "normalized": payload,
            "raw_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }

    def call(self, method, params):
        self.calls.append((method, dict(params)))
        if method == "subagents.allowLease.acquire":
            metadata = {**dict(params), "gateway_lease_id": "lease-1"}
            return {
                "gateway_lease_id": "lease-1",
                "metadata": self._metadata(metadata),
            }
        if method == "subagents.allowLease.status":
            return {"leases": []}
        if method == "subagents.allowLease.release":
            return {
                "gateway_lease_id": params["gateway_lease_id"],
                "metadata": self._metadata(dict(params)),
            }
        if method == "sessions_spawn":
            if self.spawn_error is not None:
                raise self.spawn_error
            metadata = dict(params["metadata"])
            normalized = (
                self.spawn_normalized_override
                if self.spawn_normalized_override is not None
                else metadata
            )
            raw = self.spawn_raw_override
            return {
                "session_key": self.spawn_session_key,
                "spawn_request_session_key": self.spawn_session_key,
                "metadata": {
                    "metadata_contract_version": "v1",
                    "normalized": normalized,
                    "raw_json": raw
                    if raw is not None
                    else json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                },
            }
        if method == "sessions_list":
            return {"sessions": []}
        if method == "session_status":
            metadata = session_metadata()
            return {
                "session_key": params["sessionKey"],
                "spawn_request_session_key": params["sessionKey"],
                "metadata": self._metadata(metadata),
            }
        if method == "sessions_history":
            metadata = session_metadata()
            return {
                "sessionKey": params["sessionKey"],
                "spawnRequestSessionKey": params["sessionKey"],
                "messages": [],
                "metadata": self._metadata(metadata),
            }
        raise AssertionError(method)


def session_metadata() -> dict[str, str]:
    return {
        "run_id": "run",
        "transition_id": "transition",
        "client_request_id": "client",
        "idempotency_key": "spawn-idem",
        "phase": "phase",
        "agent_id": "agent",
        "task_digest": "task",
    }


def lease_params() -> dict[str, object]:
    return {
        "client_lease_id": "client-lease",
        "idempotency_key": "lease-idem",
        "run_id": "run",
        "phase": "phase",
        "transition_id": "transition",
        "agent_id": "agent",
        "requester_agent_id": "requester",
        "ttl_ms": 60_000,
    }


class RuntimeAttestationTests(unittest.TestCase):
    def _adapter(self, transport: FakeAttestedTransport) -> OpenClawAdapter:
        from agentic_os.runtime_attestation import TransportBoundRuntimeAttestor

        return OpenClawAdapter.from_attested_transport(
            transport,
            TransportBoundRuntimeAttestor(
                DigestVerifier(),
                clock_ms=lambda: NOW_MS,
                nonce_factory=lambda: "challenge-1",
            ),
        )

    def test_positive_attestation_and_exact_singular_status_binding(self) -> None:
        transport = FakeAttestedTransport()
        adapter = self._adapter(transport)
        self.assertTrue(adapter.runtime_authority_verified)
        lease = adapter.allow_lease_acquire(lease_params())
        self.assertEqual(lease.external_id, "lease-1")
        metadata = session_metadata()
        session = adapter.sessions_spawn(
            {
                "client_request_id": metadata["client_request_id"],
                "idempotency_key": metadata["idempotency_key"],
                "metadata": metadata,
                "gateway_lease_id": "lease-1",
            }
        )
        self.assertEqual(session.external_id, "session-1")
        adapter.session_status("session-1")
        self.assertEqual(
            transport.calls[-1], ("session_status", {"sessionKey": "session-1"})
        )
        self.assertNotIn("sessions_status", [method for method, _params in transport.calls])

    def test_unsigned_mapping_and_offline_attestation_are_rejected(self) -> None:
        transport = FakeAttestedTransport()
        with self.assertRaisesRegex(AdapterContractError, "unsigned preflight mapping"):
            # A shape-valid mapping still has no live challenge or signature authority.
            OpenClawAdapter.from_preflighted_catalog(
                transport,
                verified_runtime_envelope(),
            )

        offline = FakeAttestedTransport()
        offline.envelope_overrides["online"] = False
        with self.assertRaisesRegex(AdapterContractError, "offline"):
            self._adapter(offline)

    def test_stale_attestation_is_rejected_before_application_transport(self) -> None:
        transport = FakeAttestedTransport()
        transport.envelope_overrides.update(
            {"issued_at_epoch_ms": NOW_MS - 120_000, "expires_at_epoch_ms": NOW_MS - 1}
        )
        with self.assertRaisesRegex(AdapterContractError, "stale or expired"):
            self._adapter(transport)
        self.assertEqual(transport.calls, [])

    def test_unsigned_status_alias_injection_is_rejected(self) -> None:
        transport = FakeAttestedTransport()

        def mutate(payload):
            payload["method_bindings"]["session_status"]["method"] = "sessions_status"

        transport.mutate_signed_payload = mutate
        with self.assertRaisesRegex(AdapterContractError, "signature is invalid"):
            self._adapter(transport)
        self.assertEqual(transport.calls, [])

    def test_source_endpoint_and_build_drift_fail_before_application_rpc(self) -> None:
        mutations = (
            lambda value: value["sources"][0].__setitem__("sha256", "9" * 64),
            lambda value: value["catalog"].__setitem__("sha256", "8" * 64),
            lambda value: value["gateway"].__setitem__(
                "endpoint", "ws://127.0.0.1:9999"
            ),
            lambda value: value["gateway"].__setitem__("build_id", "other-build"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                transport = FakeAttestedTransport()
                adapter = self._adapter(transport)
                mutate(transport.binding)
                self.assertFalse(adapter.runtime_authority_verified)
                with self.assertRaisesRegex(AdapterContractError, "identity drifted"):
                    adapter.allow_lease_acquire(lease_params())
                self.assertEqual(transport.calls, [])

    def test_cross_process_replay_fails_before_identity_read_or_rpc(self) -> None:
        transport = FakeAttestedTransport()
        adapter = self._adapter(transport)
        reads = transport.identity_reads
        with patch("agentic_os.runtime_attestation.os.getpid", return_value=999999):
            with self.assertRaisesRegex(AdapterContractError, "cross-process"):
                adapter.allow_lease_acquire(lease_params())
        self.assertEqual(transport.identity_reads, reads)
        self.assertEqual(transport.calls, [])

    def test_missing_and_raw_normalized_mismatched_metadata_fail_closed(self) -> None:
        metadata = session_metadata()
        for normalized, raw, message in (
            ({}, None, "normalized metadata"),
            (
                metadata,
                json.dumps({**metadata, "task_digest": "other"}),
                "do not match",
            ),
        ):
            with self.subTest(message=message):
                transport = FakeAttestedTransport()
                transport.spawn_normalized_override = normalized
                transport.spawn_raw_override = raw
                adapter = self._adapter(transport)
                with self.assertRaisesRegex(AdapterContractError, message):
                    adapter.sessions_spawn(
                        {
                            "client_request_id": "client",
                            "idempotency_key": "spawn-idem",
                            "metadata": metadata,
                        }
                    )

    def test_unknown_spawn_outcome_is_never_retried(self) -> None:
        transport = FakeAttestedTransport()
        transport.spawn_error = TimeoutError("unknown outcome")
        adapter = self._adapter(transport)
        with self.assertRaisesRegex(TimeoutError, "unknown outcome"):
            adapter.sessions_spawn(
                {
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                    "metadata": session_metadata(),
                }
            )
        self.assertEqual(
            [method for method, _params in transport.calls], ["sessions_spawn"]
        )

    def test_invalid_requests_fail_before_transport(self) -> None:
        transport = FakeAttestedTransport()
        adapter = self._adapter(transport)
        with self.assertRaisesRegex(AdapterContractError, "ttl_ms"):
            adapter.allow_lease_acquire({**lease_params(), "ttl_ms": 0})
        with self.assertRaisesRegex(AdapterContractError, "local intent"):
            adapter.sessions_spawn(
                {
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                    "metadata": {**session_metadata(), "unexpected": "field"},
                }
            )
        self.assertEqual(transport.calls, [])

    def test_duplicate_request_identity_must_return_same_external_identity(self) -> None:
        transport = FakeAttestedTransport()
        adapter = self._adapter(transport)
        first = adapter.sessions_spawn(
            {
                "client_request_id": "client",
                "idempotency_key": "spawn-idem",
                "metadata": session_metadata(),
            }
        )
        self.assertEqual(first.external_id, "session-1")
        transport.spawn_session_key = "session-2"
        with self.assertRaisesRegex(AdapterContractError, "different session identity"):
            adapter.sessions_spawn(
                {
                    "client_request_id": "client",
                    "idempotency_key": "spawn-idem",
                    "metadata": session_metadata(),
                }
            )

    def test_cli_transport_binds_signed_payload_to_local_executable_and_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "openclaw"
            executable.write_bytes(b"candidate")
            executable.chmod(0o755)
            executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            catalog_sha = "5" * 64
            transport = GatewayCliAttestedTransport(
                str(executable),
                executable_sha256=executable_sha,
                catalog_sha256=catalog_sha,
            )
            candidate_binding = binding()
            candidate_binding["executable"] = {
                "path_sha256": transport.executable_path_sha256,
                "content_sha256": executable_sha,
            }
            candidate_binding["catalog"] = {
                "authority": "tools.catalog",
                "sha256": catalog_sha,
            }
            transport._gateway_call = lambda method, params: {
                "signed_payload": {
                    "binding": candidate_binding,
                    "method_bindings": method_bindings(),
                }
            }
            transport.request_runtime_attestation(
                challenge="challenge", client_process_id="1"
            )
            self.assertEqual(
                transport.runtime_identity_snapshot()["binding"], candidate_binding
            )
            executable.write_bytes(b"drift")
            with self.assertRaisesRegex(RuntimeAttestationError, "drifted"):
                transport.runtime_identity_snapshot()


if __name__ == "__main__":
    unittest.main()
