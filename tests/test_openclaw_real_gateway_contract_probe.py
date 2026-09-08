from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import get_type_hints
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("real_gateway_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real Gateway probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ATTESTATION_HMAC_SECRET = hashlib.sha256(
    b"attestation-verification-domain-for-pr45-review-tests"
).digest()
ATTESTATION_HMAC_SECRET_HEX = ATTESTATION_HMAC_SECRET.hex()
VALIDATION_ANCHOR_HMAC_SECRET = hashlib.sha256(
    b"validation-anchor-domain-for-pr45-review-tests"
).digest()
VALIDATION_ANCHOR_HMAC_SECRET_HEX = VALIDATION_ANCHOR_HMAC_SECRET.hex()
VALID_RUNTIME_HEAD = "06e6e3f" + "a" * 33


class RealGatewayProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_validation_anchor = os.environ.get(
            MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV
        )
        os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
            VALIDATION_ANCHOR_HMAC_SECRET_HEX
        )
        self._original_runtime_launch_bindings = MODULE._runtime_launch_bindings
        MODULE._runtime_launch_bindings = lambda _root, _env: (
            Path("/bound/node"),
            "file:///bound/node_modules/tsx/dist/loader.mjs",
            self._valid_runtime_launch_sources(),
        )
        self._original_assert_loopback_port_available_before_launch = (
            MODULE._assert_loopback_port_available_before_launch
        )
        MODULE._assert_loopback_port_available_before_launch = lambda _port: None
        self._original_require_trusted_persistent_lifecycle_boundary = (
            MODULE._require_trusted_persistent_lifecycle_boundary
        )
        MODULE._require_trusted_persistent_lifecycle_boundary = lambda: None
        self._original_statvfs = MODULE.os.statvfs
        MODULE.os.statvfs = lambda _path: type(
            "StatVFS",
            (),
            {"f_flag": getattr(MODULE.os, "ST_RDONLY", 1)},
        )()

    def tearDown(self) -> None:
        MODULE._runtime_launch_bindings = self._original_runtime_launch_bindings
        MODULE._assert_loopback_port_available_before_launch = (
            self._original_assert_loopback_port_available_before_launch
        )
        MODULE._require_trusted_persistent_lifecycle_boundary = (
            self._original_require_trusted_persistent_lifecycle_boundary
        )
        MODULE.os.statvfs = self._original_statvfs
        if self._previous_validation_anchor is None:
            os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
        else:
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                self._previous_validation_anchor
            )

    def test_persistent_status_negative_rejection_requires_invalid_params(
        self,
    ) -> None:
        valid = {
            "method": "subagents.allowLease.status",
            "request_params": dict(MODULE.STATUS_NON_EMPTY_PARAMS_REJECTION_REQUEST),
            "response": {
                "ok": False,
                "error": {
                    "code": "invalid_params",
                    "message": "unexpected params: requesterAgentId",
                },
            },
        }
        valid["raw_response_sha256"] = MODULE._canonical_sha256(valid["response"])
        self.assertEqual(
            MODULE._validate_allow_lease_status_rejects_non_empty_params(valid),
            valid["raw_response_sha256"],
        )

        cases = {
            "top_level_success": {
                "ok": True,
                "result": {"error": "parameter cache unavailable"},
            },
            "string_error": {"ok": False, "error": "parameter backend unavailable"},
            "wrong_code": {
                "ok": False,
                "error": {"code": "unavailable", "message": "param"},
            },
            "missing_field": {
                "ok": False,
                "error": {"code": "invalid_params", "message": "param"},
            },
        }
        for name, response in cases.items():
            record = {
                "method": "subagents.allowLease.status",
                "request_params": dict(
                    MODULE.STATUS_NON_EMPTY_PARAMS_REJECTION_REQUEST
                ),
                "response": response,
                "raw_response_sha256": MODULE._canonical_sha256(response),
            }
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ProbeError,
                "accepted non-empty parameters|structured invalid_params|requesterAgentId",
            ):
                MODULE._validate_allow_lease_status_rejects_non_empty_params(record)

    def _validator_env_for_path(
        self,
        run_root: Path,
        validation_anchor_key: bytes,
        attestation_verification_key: bytes = ATTESTATION_HMAC_SECRET,
    ) -> dict[str, str]:
        pinned = MODULE._pin_prepared_run_root(run_root.resolve())
        try:
            return MODULE._validator_env(
                run_root=pinned,
                validation_anchor_key=validation_anchor_key,
                attestation_verification_key=attestation_verification_key,
            )
        finally:
            pinned.close()

    def _agentic_source_bindings(self, *relatives: str) -> list[dict[str, str]]:
        if not relatives:
            relatives = (
                "scripts/openclaw-real-gateway-contract-probe.py",
                MODULE.RUNTIME_SOURCE_CONTRACT_HELPER,
            )
        return [
            {
                "path": relative,
                "sha256": MODULE._sha256_bytes((MODULE.ROOT / relative).read_bytes()),
            }
            for relative in relatives
        ]

    def _launcher_boundary(
        self,
        *,
        pid: int = 1234,
        root_identity: dict | None = None,
        cleanup_marker_sha256: str = "a" * 64,
        teardown_status: str = "confirmed",
        boundary_type: str = "external-container",
        os_boundary_type: str | None = None,
    ) -> dict:
        os_boundary_type = os_boundary_type or boundary_type
        root_identity = root_identity or {
            "pid": pid,
            "uid": os.getuid(),
            "start_id": f"root-{pid}",
        }
        boundary = {
            "schema_version": MODULE.LAUNCHER_BOUNDARY_SCHEMA_VERSION,
            "boundary_type": boundary_type,
            "boundary_nonce_sha256": "c" * 64,
            "teardown_status": teardown_status,
            "authority": MODULE.LAUNCHER_BOUNDARY_AUTHORITY,
            "evidence_authority": MODULE.LAUNCHER_BOUNDARY_EVIDENCE_AUTHORITY,
            "os_boundary_type": os_boundary_type,
            "root_pid": pid,
            "root_identity": dict(root_identity),
            "root_process_group_id": pid,
            "root_session_id": pid,
            "cleanup_marker_sha256": cleanup_marker_sha256,
            "command_sha256": "d" * 64,
            "cwd_sha256": "e" * 64,
            "launcher_pid": os.getpid(),
            "launcher_uid": os.getuid(),
            "launcher_parent_pid": os.getppid(),
            "host_os": os.name,
            "host_platform": sys.platform,
            "created_at_epoch_ms": int(time.time() * 1000),
        }
        boundary["boundary_id_sha256"] = MODULE._canonical_sha256(
            {
                key: value
                for key, value in boundary.items()
                if key not in {"boundary_id_sha256", "teardown_status"}
            }
        )
        self.assertEqual(sorted(boundary), sorted(MODULE.LAUNCHER_BOUNDARY_KEYS))
        return boundary

    def _attach_valid_process_cleanup(self, proc, *, pid: int = 1234):
        root_identity = {"pid": pid, "uid": os.getuid(), "start_id": f"root-{pid}"}
        proc._agentic_os_process_cleanup = {
            "tracking_status": "available",
            "root_pid": pid,
            "root_identity": root_identity,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [],
            "launcher_owned_boundary": self._launcher_boundary(
                pid=pid,
                root_identity=root_identity,
                boundary_type=MODULE.LAUNCHER_BOUNDARY_OS_TYPE,
            ),
        }
        return proc

    def _is_environmental_cleanup_tracking_unavailable(self, cleanup: dict) -> bool:
        if cleanup.get("tracking_status") != "unavailable":
            return False
        error = str(cleanup.get("tracking_error") or "")
        return any(
            message in error
            for message in (
                "process table scan is unavailable",
                "candidate cleanup marker scan is unavailable",
                "unattributed same-UID process appeared without candidate cleanup marker",
            )
        )

    def _valid_persistent_receipt(self) -> dict:
        now_ms = int(time.time() * 1000)
        production_health = {"reachable": False}
        production_health_sha256 = MODULE._canonical_sha256(production_health)
        contract_vector_sha256 = MODULE._expected_persistent_contract_vector_sha256()
        return {
            "status": "pass",
            "immutable_inputs": {
                "runtime_head": VALID_RUNTIME_HEAD,
                "agentic_os_head": "agentic-head",
                "contract_vector_sha256": contract_vector_sha256,
                "run_id": "run-id",
                "transition_id": "transition-id",
            },
            "production_before": {
                "config_sha256": "0" * 64,
                "health": production_health,
            },
            "production_after": {
                "config_sha256": "0" * 64,
                "health": production_health,
            },
            "candidate": {
                "port": MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                "env": {"unexpected_provider_key_count": 0},
                "logs": {"stdout_sha256": "1" * 64, "stderr_sha256": "2" * 64},
            },
            "preflight": {
                "status": "pass",
                "runtime_ready": True,
                "required_tool_names": list(MODULE.PERSISTENT_REQUIRED_TOOL_NAMES),
                "evidence_sha256": "3" * 64,
                "persistent_evidence_sha256": "4" * 64,
                "stdout_sha256": "5" * 64,
                "stderr_sha256": "6" * 64,
                "hello": {
                    "status": "pass",
                    "required_methods": list(MODULE.PERSISTENT_REQUIRED_TOOL_NAMES),
                },
            },
            "attestation": {
                "status": "pass",
                "gateway_endpoint": "ws://127.0.0.1:20189",
                "gateway_build_id": VALID_RUNTIME_HEAD,
                "executable_content_sha256": "7" * 64,
                "catalog_sha256": "8" * 64,
                "contract_vector_sha256": contract_vector_sha256,
                "rpc_transcript_sha256": "a" * 64,
                "runtime_authored_rpc_evidence_sha256": "b" * 64,
                "signed_payload_sha256": "c" * 64,
                "runtime_identity_token_sha256": "d" * 64,
                "expires_at_epoch_ms": now_ms + 60_000,
                "captured_at_epoch_ms": now_ms,
            },
            "lifecycle": {
                "status": "pass",
                "run_id": "run-id",
                "transition_id": "transition-id",
                "duplicate_acquire_same_lease": True,
                "first_spawn_status": "accepted",
                "duplicate_spawn_same_session": True,
                "pre_release_status": "visible",
                "pre_release_lease_count": 1,
                "pre_release_gateway_lease_id_sha256": "e" * 64,
                "post_release_lease_count": 0,
                "gateway_lease_id_sha256": "e" * 64,
                "session_key_sha256": "f" * 64,
                "child_run_id_sha256": "0" * 64,
                "session_status_sha256": "1" * 64,
                "sessions_history_sha256": "2" * 64,
                "release_status": "released",
                "duplicate_release_status": "released",
                "primary_release_sha256": "3" * 64,
                "duplicate_release_sha256": "3" * 64,
                "release_gateway_lease_id_sha256": "e" * 64,
                "duplicate_release_gateway_lease_id_sha256": "e" * 64,
                "release_owner_metadata_sha256": "4" * 64,
                "duplicate_release_owner_metadata_sha256": "4" * 64,
                "release_idempotency_key_sha256": "5" * 64,
                "duplicate_release_idempotency_key_sha256": "5" * 64,
                "expected_release_idempotency_key_sha256": "5" * 64,
                "release_client_lease_id_sha256": MODULE._text_sha256(
                    "client-lease"
                ),
                "duplicate_release_client_lease_id_sha256": MODULE._text_sha256(
                    "client-lease"
                ),
                "expected_release_client_lease_id_sha256": MODULE._text_sha256(
                    "client-lease"
                ),
                "release_run_id_sha256": MODULE._text_sha256("run-id"),
                "duplicate_release_run_id_sha256": MODULE._text_sha256("run-id"),
                "release_phase_sha256": MODULE._text_sha256("phase-b"),
                "duplicate_release_phase_sha256": MODULE._text_sha256("phase-b"),
                "expected_release_phase_sha256": MODULE._text_sha256("phase-b"),
                "release_transition_id_sha256": MODULE._text_sha256("transition-id"),
                "duplicate_release_transition_id_sha256": MODULE._text_sha256(
                    "transition-id"
                ),
                "release_agent_id_sha256": MODULE._text_sha256("agent"),
                "duplicate_release_agent_id_sha256": MODULE._text_sha256("agent"),
                "expected_release_agent_id_sha256": MODULE._text_sha256("agent"),
                "release_requester_agent_id_sha256": MODULE._text_sha256("requester"),
                "duplicate_release_requester_agent_id_sha256": MODULE._text_sha256(
                    "requester"
                ),
                "expected_release_requester_agent_id_sha256": MODULE._text_sha256(
                    "requester"
                ),
                "wrong_owner_release_status": "rejected",
                "wrong_owner_release_sha256": "6" * 64,
                "wrong_owner_release_gateway_lease_id_sha256": "e" * 64,
                "wrong_owner_release_owner_metadata_sha256": "7" * 64,
                "wrong_owner_release_idempotency_key_sha256": "8" * 64,
                "listener_owner_status": "verified_before_lifecycle",
                "listener_process_identity_sha256": MODULE._text_sha256(
                    "1234:gateway-process:test"
                ),
                "sessions_list_count": 1,
                "matching_session_count": 1,
            },
            "rollback": {
                "status": "pass",
                "candidate_port_closed": True,
                "production_config_hash_unchanged": True,
                "production_health_before_sha256": production_health_sha256,
                "production_health_after_sha256": production_health_sha256,
                "db_authority": {"DB_AUTHORITY_ENABLED": False},
                "candidate_shutdown": {"port_closed": True},
            },
            "runtime_launch": {
                "token_sha256": "d" * 64,
                "executable_sha256": "7" * 64,
            },
            "paths": {
                "run_root": {"realpath_sha256": "7" * 64},
                "key_path": {"realpath_sha256": "8" * 64},
            },
            "soak": {"status": "prepared_not_started", "started": False},
            "historical_probe_audit": {
                "verdict": "not_authority_for_phase_b",
                "sha256": "9" * 64,
            },
        }

    def _valid_runtime_sources(
        self, relatives: tuple[str, ...] | None = None
    ) -> list[dict[str, str]]:
        selected = relatives or MODULE.PERSISTENT_RUNTIME_SOURCE_PATHS
        return [
            {
                "path": relative,
                "sha256": "7" * 64
                if relative == "openclaw.mjs"
                else hashlib.sha256(relative.encode()).hexdigest(),
            }
            for relative in selected
        ]

    def _valid_runtime_launch_sources(self) -> list[dict[str, str]]:
        return [
            {
                "path": label,
                "sha256": hashlib.sha256(f"content:{label}".encode()).hexdigest(),
                "realpath_sha256": hashlib.sha256(f"path:{label}".encode()).hexdigest(),
            }
            for index, label in enumerate(MODULE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS)
        ]

    def _write_runtime_source_fixture(self, root: Path, files: dict[str, str]) -> None:
        base_files = {
            "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
            "openclaw.mjs": "export const openclaw = true;\n",
            MODULE.PERSISTENT_LIFECYCLE_RUNNER: "export const runner = true;\n",
            "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
            "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
            "src/gateway/client.ts": "export const c = 1;\n",
            "src/utils/message-channel.ts": "export const m = 1;\n",
        }
        base_files.update(files)
        for relative, content in base_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def _resign_attestation_response(self, response: dict) -> None:
        signed_payload = response["signed_payload"]
        response["signature"] = hmac.new(
            ATTESTATION_HMAC_SECRET,
            MODULE._canonical_json_bytes(signed_payload),
            hashlib.sha256,
        ).hexdigest()

    def _write_persistent_receipts(
        self,
        run_root: Path,
        receipt: dict,
        validation: dict | None = None,
        tools_catalog_response: dict | None = None,
        persistent_evidence_transform=None,
        preflight_evidence_transform=None,
        lifecycle_transcript_transform=None,
        runtime_sources: list[dict[str, str]] | None = None,
    ) -> tuple[Path, Path]:
        receipts = run_root / "receipts"
        receipts.mkdir(parents=True)
        candidate_root = run_root.parent
        package_json = candidate_root / "package.json"
        if not package_json.exists():
            package_json.write_text(
                '{"name":"openclaw","version":"0.0.0-test"}\n',
                encoding="utf-8",
            )
        now_ms = int(time.time() * 1000)
        source_records = runtime_sources or self._valid_runtime_sources()
        request_params = {
            "challenge": "challenge-1",
            "client_process_id": "persistent-runner:1234:unit-test",
            "expected_executable_sha256": "7" * 64,
            "expected_catalog_sha256": "8" * 64,
            "expected_runtime_identity_token_sha256": "d" * 64,
        }
        signed_payload = {
            "schema_version": "agentic-os.openclaw-attestation.v1",
            "online": True,
            "challenge": request_params["challenge"],
            "nonce": request_params["challenge"],
            "issued_at_epoch_ms": now_ms - 1_000,
            "expires_at_epoch_ms": receipt["attestation"]["expires_at_epoch_ms"],
            "client_process_id": request_params["client_process_id"],
            "runtime_identity_token_sha256": "d" * 64,
            "owner_scope_id": "e" * 64,
            "rpc_transcript_sha256": "a" * 64,
            "binding": {
                "executable": {
                    "path_sha256": MODULE.runtime_source_contract.path_sha256(
                        candidate_root / "openclaw.mjs"
                    ),
                    "content_sha256": "7" * 64,
                },
                "install": {
                    "root_sha256": MODULE.runtime_source_contract.path_sha256(
                        candidate_root
                    ),
                    "package_json_sha256": MODULE._sha256_bytes(
                        package_json.read_bytes()
                    ),
                    "package_name": "openclaw",
                    "version": "0.0.0-test",
                },
                "sources": source_records,
                "sources_sha256": MODULE._canonical_sha256(source_records),
                "catalog": {
                    "authority": "tools.catalog.runtimeMethods",
                    "sha256": "8" * 64,
                    "contract_vector_sha256": receipt["attestation"].get(
                        "contract_vector_sha256",
                        MODULE._expected_persistent_contract_vector_sha256(),
                    ),
                },
                "gateway": {
                    "endpoint": f"ws://127.0.0.1:{MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT}",
                    "version": "0.0.0-test",
                    "build_id": receipt["attestation"].get(
                        "gateway_build_id", VALID_RUNTIME_HEAD
                    ),
                    "process_identity": "1234:gateway-process:test",
                },
                "transport": {
                    "kind": "gateway-websocket",
                    "identity": "gateway-websocket:test",
                },
            },
            "method_bindings": MODULE._expected_method_bindings_payload(),
        }
        if tools_catalog_response is None:
            tools_catalog_response = {
                "runtimeMethods": MODULE._expected_runtime_methods_catalog(),
                "groups": [
                    {
                        "id": "agentic-os-runtime",
                        "tools": [
                            {"name": name}
                            for name in MODULE.PERSISTENT_REQUIRED_TOOL_NAMES
                        ],
                    }
                ]
            }
        rpc_evidence = {
            "tools_catalog": {
                "method": "tools.catalog",
                "request_params": {},
                "response": tools_catalog_response,
                "raw_response_sha256": MODULE._canonical_sha256(tools_catalog_response),
            },
            "allow_lease_status": {
                "method": "subagents.allowLease.status",
                "request_params": {},
                "response": {"status": "ok", "leases": []},
                "raw_response_sha256": MODULE._canonical_sha256(
                    {"status": "ok", "leases": []}
                ),
            },
            "allow_lease_status_rejects_non_empty_params": {
                "method": "subagents.allowLease.status",
                "request_params": dict(
                    MODULE.STATUS_NON_EMPTY_PARAMS_REJECTION_REQUEST
                ),
                "response": {
                    "ok": False,
                    "error": {
                        "code": "invalid_params",
                        "message": "unexpected params: requesterAgentId",
                    },
                },
                "raw_response_sha256": MODULE._canonical_sha256(
                    {
                        "ok": False,
                        "error": {
                            "code": "invalid_params",
                            "message": "unexpected params: requesterAgentId",
                        },
                    }
                ),
            },
        }
        expected_transcript_sha256 = MODULE._canonical_sha256(
            {
                "schema_version": MODULE.PERSISTENT_RPC_TRANSCRIPT_SCHEMA_VERSION,
                "records": [
                    {
                        "key": key,
                        "method": rpc_evidence[key]["method"],
                        "request_params": dict(rpc_evidence[key]["request_params"]),
                        "raw_response_sha256": rpc_evidence[key]["raw_response_sha256"],
                    }
                    for key, _method in MODULE.PERSISTENT_RPC_TRANSCRIPT_RECORDS
                ],
            }
        )
        signed_payload["rpc_transcript_sha256"] = expected_transcript_sha256
        attestation_response = {
            "signature_algorithm": "hmac-sha256",
            "signature": hmac.new(
                ATTESTATION_HMAC_SECRET,
                MODULE._canonical_json_bytes(signed_payload),
                hashlib.sha256,
            ).hexdigest(),
            "signed_payload": signed_payload,
        }
        persistent_evidence = {
            "schema_version": MODULE.PERSISTENT_ATTESTATION_SCHEMA_VERSION,
            "expected_runtime_head": VALID_RUNTIME_HEAD,
            "expected_agentic_os_head": "agentic-head",
            "runtime": {
                "executable_sha256": "7" * 64,
                "expected_catalog_sha256": "8" * 64,
            },
            "attestation": {
                "request_params": request_params,
                "response": attestation_response,
                "runtime_identity_token_sha256": "d" * 64,
            },
            "rpc_evidence": rpc_evidence,
        }
        if persistent_evidence_transform is not None:
            persistent_evidence_transform(persistent_evidence)
        lease_id = "gateway-lease:unit-test"
        session_key = "agent:unit-test:session"
        child_run_id = "child-run:unit-test"
        release_owner_metadata = "owner-metadata:unit-test"
        release_idempotency_key = "release-idempotency:unit-test"
        wrong_owner_metadata = "wrong-owner-metadata:unit-test"
        wrong_owner_idempotency_key = "wrong-owner-idempotency:unit-test"
        lifecycle_metadata = {
            "run_id": "run-id",
            "transition_id": "transition-id",
            "phase": "phase-b",
            "agent_id": "agent",
            "requester_agent_id": "requester",
        }
        acquire_request = {
            "client_lease_id": "client-lease",
            "idempotency_key": "acquire-idempotency:unit-test",
            "run_id": "run-id",
            "phase": "phase-b",
            "transition_id": "transition-id",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "ttl_ms": 60000,
        }
        spawn_request = {
            "task": "unit-test lifecycle child",
            "taskName": "unit_test_lifecycle_child",
            "runtime": "subagent",
            "mode": "run",
            "agentId": "agent",
            "cleanup": "delete",
            "context": "isolated",
            "lightContext": True,
            "client_request_id": "spawn-client-request:unit-test",
            "idempotency_key": "spawn-idempotency:unit-test",
            "gateway_lease_id": lease_id,
            "metadata": lifecycle_metadata,
        }
        release_request = {
            "client_lease_id": "client-lease",
            "release_idempotency_key": release_idempotency_key,
            "run_id": "run-id",
            "phase": "phase-b",
            "transition_id": "transition-id",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "gateway_lease_id": lease_id,
        }
        wrong_owner_release_request = {
            **release_request,
            "requester_agent_id": "wrong-requester",
            "release_idempotency_key": wrong_owner_idempotency_key,
        }
        release_response = {
            "status": "released",
            "gateway_lease_id": lease_id,
            "owner_metadata": release_owner_metadata,
            "release_idempotency_key": release_idempotency_key,
            "client_lease_id": "client-lease",
            "run_id": "run-id",
            "phase": "phase-b",
            "transition_id": "transition-id",
            "agent_id": "agent",
            "requester_agent_id": "requester",
        }
        lifecycle_rpc_responses = {
            "acquire": {"status": "accepted", "gateway_lease_id": lease_id},
            "duplicate_acquire": {"status": "accepted", "gateway_lease_id": lease_id},
            "first_spawn": {
                "status": "accepted",
                "session_key": session_key,
                "child_run_id": child_run_id,
            },
            "duplicate_spawn": {
                "status": "accepted",
                "session_key": session_key,
                "child_run_id": child_run_id,
            },
            "pre_release_status": {
                "status": "ok",
                "leases": [{"gateway_lease_id": lease_id}],
            },
            "session_status": {
                "status": "completed",
                "session_key": session_key,
                "child_run_id": child_run_id,
                "metadata": lifecycle_metadata,
                "child_result": {"status": "ok"},
            },
            "sessions_history": {
                "items": [
                    {
                        "session_key": session_key,
                        "child_run_id": child_run_id,
                        "metadata": lifecycle_metadata,
                        "child_result": {"status": "ok"},
                    }
                ]
            },
            "sessions_list": {"sessions": [{"session_key": session_key}]},
            "wrong_owner_release": {
                "status": "rejected",
                "gateway_lease_id": lease_id,
                "owner_metadata": wrong_owner_metadata,
                "release_idempotency_key": wrong_owner_idempotency_key,
            },
            "release": release_response,
            "duplicate_release": dict(release_response),
            "post_release_status": {"status": "ok", "leases": []},
        }
        lifecycle_rpc_records = {
            key: {
                "method": method,
                "request_params": {
                    "acquire": acquire_request,
                    "duplicate_acquire": acquire_request,
                    "first_spawn": spawn_request,
                    "duplicate_spawn": spawn_request,
                    "pre_release_status": {},
                    "session_status": {"sessionKey": session_key},
                    "sessions_history": {
                        "sessionKey": session_key,
                        "limit": 20,
                        "includeTools": True,
                    },
                    "sessions_list": {},
                    "wrong_owner_release": wrong_owner_release_request,
                    "release": release_request,
                    "duplicate_release": release_request,
                    "post_release_status": {},
                }[key],
                "response": lifecycle_rpc_responses[key],
                "raw_response_sha256": MODULE._canonical_sha256(
                    lifecycle_rpc_responses[key]
                ),
            }
            for key, method in MODULE.PERSISTENT_LIFECYCLE_RPC_TRANSCRIPT_RECORDS
        }
        lifecycle_rpc_transcript = {
            "schema_version": MODULE.PERSISTENT_LIFECYCLE_RPC_TRANSCRIPT_SCHEMA_VERSION,
            "record_authority": MODULE.PERSISTENT_LIFECYCLE_RPC_TRANSCRIPT_RECORD_AUTHORITY,
            "capture_authority": MODULE.PERSISTENT_LIFECYCLE_RPC_TRANSCRIPT_CAPTURE_AUTHORITY,
            "captured_after_runner_exit": True,
            "captured_with_pinned_receipts_fd": True,
            "capture_parent_process_id": os.getpid(),
            "run_id": "run-id",
            "transition_id": "transition-id",
            "records": lifecycle_rpc_records,
        }
        if lifecycle_transcript_transform is not None:
            lifecycle_transcript_transform(lifecycle_rpc_transcript)
        lifecycle = receipt["lifecycle"]
        lifecycle_defaults = {
            "pre_release_gateway_lease_id_sha256": "e" * 64,
            "gateway_lease_id_sha256": "e" * 64,
            "session_key_sha256": "f" * 64,
            "child_run_id_sha256": "0" * 64,
            "session_status_sha256": "1" * 64,
            "sessions_history_sha256": "2" * 64,
            "primary_release_sha256": "3" * 64,
            "duplicate_release_sha256": "3" * 64,
            "release_gateway_lease_id_sha256": "e" * 64,
            "duplicate_release_gateway_lease_id_sha256": "e" * 64,
            "release_owner_metadata_sha256": "4" * 64,
            "duplicate_release_owner_metadata_sha256": "4" * 64,
            "release_idempotency_key_sha256": "5" * 64,
            "duplicate_release_idempotency_key_sha256": "5" * 64,
            "expected_release_idempotency_key_sha256": "5" * 64,
            "wrong_owner_release_sha256": "6" * 64,
            "wrong_owner_release_gateway_lease_id_sha256": "e" * 64,
            "wrong_owner_release_owner_metadata_sha256": "7" * 64,
            "wrong_owner_release_idempotency_key_sha256": "8" * 64,
        }
        lifecycle_derived = {
            "pre_release_gateway_lease_id_sha256": MODULE._text_sha256(lease_id),
            "gateway_lease_id_sha256": MODULE._text_sha256(lease_id),
            "session_key_sha256": MODULE._text_sha256(session_key),
            "child_run_id_sha256": MODULE._text_sha256(child_run_id),
            "session_status_sha256": lifecycle_rpc_records["session_status"][
                "raw_response_sha256"
            ],
            "sessions_history_sha256": lifecycle_rpc_records["sessions_history"][
                "raw_response_sha256"
            ],
            "primary_release_sha256": lifecycle_rpc_records["release"][
                "raw_response_sha256"
            ],
            "duplicate_release_sha256": lifecycle_rpc_records["duplicate_release"][
                "raw_response_sha256"
            ],
            "release_gateway_lease_id_sha256": MODULE._text_sha256(lease_id),
            "duplicate_release_gateway_lease_id_sha256": MODULE._text_sha256(lease_id),
            "release_owner_metadata_sha256": MODULE._text_sha256(release_owner_metadata),
            "duplicate_release_owner_metadata_sha256": MODULE._text_sha256(
                release_owner_metadata
            ),
            "release_idempotency_key_sha256": MODULE._text_sha256(
                release_idempotency_key
            ),
            "duplicate_release_idempotency_key_sha256": MODULE._text_sha256(
                release_idempotency_key
            ),
            "expected_release_idempotency_key_sha256": MODULE._text_sha256(
                release_idempotency_key
            ),
            "wrong_owner_release_sha256": lifecycle_rpc_records["wrong_owner_release"][
                "raw_response_sha256"
            ],
            "wrong_owner_release_gateway_lease_id_sha256": MODULE._text_sha256(lease_id),
            "wrong_owner_release_owner_metadata_sha256": MODULE._text_sha256(
                wrong_owner_metadata
            ),
            "wrong_owner_release_idempotency_key_sha256": MODULE._text_sha256(
                wrong_owner_idempotency_key
            ),
        }
        for key, value in lifecycle_derived.items():
            if lifecycle.get(key) == lifecycle_defaults[key]:
                lifecycle[key] = value
        lifecycle_transcript_file = (
            receipts / MODULE.PERSISTENT_LIFECYCLE_RPC_TRANSCRIPT_FILE
        )
        lifecycle_transcript_file.write_text(
            json.dumps(lifecycle_rpc_transcript), encoding="utf-8"
        )
        lifecycle["gateway_rpc_transcript_file"] = str(lifecycle_transcript_file)
        lifecycle["gateway_rpc_transcript_sha256"] = MODULE._sha256_bytes(
            lifecycle_transcript_file.read_bytes()
        )
        preflight = receipt["preflight"]
        preflight_required_tool_names = preflight.get("required_tool_names")
        if not isinstance(preflight_required_tool_names, list):
            preflight_required_tool_names = []
        hello_required_methods = preflight.get("hello", {}).get("required_methods")
        if not isinstance(hello_required_methods, list):
            hello_required_methods = []
        preflight_evidence = {
            "status": "pass",
            "runtime_ready": True,
            "required_tool_names": list(preflight_required_tool_names),
            "hello": {
                "status": "pass",
                "required_methods": list(hello_required_methods),
            },
        }
        if preflight_evidence_transform is not None:
            preflight_evidence_transform(preflight_evidence)
        preflight_evidence_file = receipts / "capability-preflight-attempt-1.json"
        preflight_evidence_file.write_text(
            json.dumps(preflight_evidence), encoding="utf-8"
        )
        receipt["preflight"]["evidence_file"] = str(preflight_evidence_file)
        receipt["preflight"]["evidence_sha256"] = MODULE._sha256_bytes(
            preflight_evidence_file.read_bytes()
        )
        persistent_evidence_file = receipts / "persistent-attested-preflight-input-attempt-1.json"
        persistent_evidence_file.write_text(json.dumps(persistent_evidence), encoding="utf-8")
        receipt["preflight"]["persistent_evidence_file"] = str(persistent_evidence_file)
        receipt["preflight"]["persistent_evidence_sha256"] = MODULE._sha256_bytes(
            persistent_evidence_file.read_bytes()
        )
        if receipt["attestation"].get("signed_payload_sha256") == "c" * 64:
            receipt["attestation"]["signed_payload_sha256"] = MODULE._canonical_sha256(
                signed_payload
            )
        if receipt["attestation"].get("runtime_authored_rpc_evidence_sha256") == "b" * 64:
            receipt["attestation"]["runtime_authored_rpc_evidence_sha256"] = (
                MODULE._canonical_sha256(rpc_evidence)
            )
        if receipt["attestation"].get("rpc_transcript_sha256") == "a" * 64:
            receipt["attestation"]["rpc_transcript_sha256"] = expected_transcript_sha256
        receipt_file = receipts / "lifecycle-receipt.json"
        validation_file = receipts / "independent-validation.json"
        receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
        if validation is None:
            lifecycle_rpc_transcript = MODULE._validate_lifecycle_gateway_rpc_transcript(
                run_root=run_root,
                lifecycle=receipt["lifecycle"],
                expected_run_id="run-id",
                expected_transition_id="transition-id",
            )
            lifecycle_attestation = MODULE._lifecycle_attestation_record(
                receipt["lifecycle"]
            )
            validation = {
                "schema_version": MODULE.PERSISTENT_VALIDATION_SCHEMA_VERSION,
                "status": "pass",
                "receipt_sha256": MODULE._sha256_bytes(receipt_file.read_bytes()),
                "attestation_response_sha256": MODULE._canonical_sha256(
                    attestation_response
                ),
                "tools_catalog_response_sha256": MODULE._canonical_sha256(
                    tools_catalog_response
                ),
                "lifecycle_rpc_transcript_sha256": lifecycle_rpc_transcript["sha256"],
                "lifecycle_attestation_sha256": MODULE._canonical_sha256(
                    lifecycle_attestation
                ),
                "lifecycle_attestation": lifecycle_attestation,
                "attestation_signature_verified": True,
                "attestation_verification": {
                    "schema_version": MODULE.PERSISTENT_ATTESTATION_VERIFICATION_SCHEMA_VERSION,
                    "signature_algorithm": "hmac-sha256",
                    "signature_sha256": MODULE._text_sha256(
                        str(attestation_response.get("signature", ""))
                    ),
                    "signed_payload_sha256": MODULE._canonical_sha256(signed_payload),
                    "verified": True,
                },
                "validator_authority": "independent-phase-c-verifier",
                "validator_identity": "phase-c-verifier:unit-test",
                "validator_identity_sha256": MODULE._text_sha256(
                    "phase-c-verifier:unit-test"
                ),
                "lifecycle_rpc_transcript": {
                    "schema_version": lifecycle_rpc_transcript["schema_version"],
                    "sha256": lifecycle_rpc_transcript["sha256"],
                    "response_digests": lifecycle_rpc_transcript["response_digests"],
                },
            }
            validation["authentication"] = {
                "scheme": "hmac-sha256-env",
                "key_env": MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
                "signature": hmac.new(
                    VALIDATION_ANCHOR_HMAC_SECRET,
                    MODULE._canonical_json_bytes(
                        MODULE._authentication_payload(validation)
                    ),
                    hashlib.sha256,
                ).hexdigest(),
            }
        validation_file.write_text(json.dumps(validation), encoding="utf-8")
        return receipt_file, validation_file

    def _call_persistent_summary(
        self,
        root: Path,
        receipt: dict,
        validation: dict | None = None,
        tools_catalog_response: dict | None = None,
        persistent_evidence_transform=None,
        preflight_evidence_transform=None,
        lifecycle_transcript_transform=None,
        runtime_sources: list[dict[str, str]] | None = None,
    ):
        run_root = root / "run"
        runtime_sources = runtime_sources or self._valid_runtime_sources()
        receipt_file, validation_file = self._write_persistent_receipts(
            run_root,
            receipt,
            validation,
            tools_catalog_response=tools_catalog_response,
            persistent_evidence_transform=persistent_evidence_transform,
            preflight_evidence_transform=preflight_evidence_transform,
            lifecycle_transcript_transform=lifecycle_transcript_transform,
            runtime_sources=runtime_sources,
        )
        original_git = MODULE._git

        class Proc:
            stdout = "runner stdout"
            stderr = "runner stderr"
            returncode = 0

        proc = self._attach_valid_process_cleanup(Proc())

        previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
        os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
            VALIDATION_ANCHOR_HMAC_SECRET_HEX
        )
        try:
            MODULE._git = lambda git_root, *args: "agentic-head"
            return MODULE._persistent_lifecycle_summary(
                openclaw_root=root,
                run_root=run_root,
                receipt_file=receipt_file,
                validation_file=validation_file,
                head=VALID_RUNTIME_HEAD,
                agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                runtime_sources=runtime_sources,
                runtime_launch_sources=self._valid_runtime_launch_sources(),
                command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                proc=proc,
                port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                expected_run_id="run-id",
                expected_transition_id="transition-id",
                validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
            )
        finally:
            MODULE._git = original_git
            if previous_secret is None:
                os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
            else:
                os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_runtime_annotations_resolve(self) -> None:
        self.assertEqual(
            get_type_hints(MODULE._validate_sha256_field)["payload"],
            MODULE.Mapping[str, MODULE.Any],
        )

    def test_requires_running_and_completed_lifecycle_proofs(self) -> None:
        self.assertIn("lifecycle_running_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("lifecycle_completed_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("lifecycle_failure_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("duplicate_release_identity_parity", MODULE.REQUIRED_RUNTIME_PROOFS)

    def test_disabled_adapter_probe_is_not_an_authoritative_requirement(self) -> None:
        for proof in MODULE.DISABLED_FUTURE_RUNTIME_PROOFS:
            self.assertNotIn(proof, MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn(
            "agentic_adapter_release_succeeded",
            MODULE.DISABLED_FUTURE_RUNTIME_PROOFS,
        )

    def test_binds_current_gateway_and_adapter_sources_without_disabled_probe(self) -> None:
        self.assertIn(
            "scripts/agentic_os_runtime_source_contract.py",
            MODULE.AGENTIC_SOURCE_PATHS,
        )
        self.assertIn("src/agentic_os/openclaw_adapter.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/runtime_attestation.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/metadata.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/__init__.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertFalse(hasattr(MODULE, "ADAPTER_PROBE"))

    def test_parent_probe_rejects_external_probe_root_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ)
            env[MODULE.PROBE_ROOT_ENV] = directory
            proc = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import importlib.util, pathlib; "
                        f"path = pathlib.Path({str(SCRIPT)!r}); "
                        "spec = importlib.util.spec_from_file_location('probe', path); "
                        "module = importlib.util.module_from_spec(spec); "
                        "spec.loader.exec_module(module)"
                    ),
                ],
                cwd=SCRIPT.parents[1],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(MODULE.PROBE_ROOT_ENV, proc.stderr + proc.stdout)

    def test_rejects_raw_session_identity(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw field"):
            MODULE._walk_evidence({"child_session_key": "agent:worker:subagent:raw"})

    def test_rejects_camel_case_raw_identity_aliases(self) -> None:
        for key in ("sessionKey", "gatewayLeaseId", "childRunId", "taskMarker", "authToken"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw field"):
                    MODULE._walk_evidence({key: "raw-runtime-identity"})

    def test_rejects_raw_child_result_aliases(self) -> None:
        for key in (
            "child_result",
            "childResult",
            "child_result_raw",
            "childResultRaw",
            "raw_child_result",
            "rawChildResult",
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw field"):
                    MODULE._walk_evidence(
                        {
                            key: {"status": "raw-child-output"},
                            "child_result_sha256": "0" * 64,
                        }
                    )

    def test_probe_does_not_overwrite_final_evidence_before_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            output.write_text('{"status":"previous"}\n', encoding="utf-8")
            original_run = MODULE._run
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_source_binding = MODULE._source_binding
            original_validate_sources = MODULE._validate_sources
            original_git = MODULE._git
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                self.assertIs(start_new_session, True)
                self.assertIsNotNone(env)
                temp_path = Path(env["AGENTIC_OS_REAL_GATEWAY_EVIDENCE_FILE"])
                self.assertNotEqual(temp_path, output)
                temp_path.write_text(json.dumps({"status": "pass"}), encoding="utf-8")
                return self._attach_valid_process_cleanup(Proc())

            try:
                MODULE._run = fake_run
                MODULE.validate_candidate_root = lambda root: "openclaw-head"
                MODULE._candidate_probe_mode = lambda root: "legacy_e2e"
                MODULE._source_binding = lambda root, relative: {
                    "path": relative,
                    "sha256": "0" * 64,
                }
                MODULE._git = lambda root, *args: "agentic-head"
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                with self.assertRaisesRegex(MODULE.ProbeError, "head binding"):
                    MODULE.run_probe(Path(directory), output, timeout=1)
                self.assertEqual(output.read_text(encoding="utf-8"), '{"status":"previous"}\n')
                self.assertEqual(list(Path(directory).glob(".evidence.json.*.tmp")), [])
            finally:
                MODULE._run = original_run
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._source_binding = original_source_binding
                MODULE._validate_sources = original_validate_sources
                MODULE._git = original_git
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

    def test_rejects_local_absolute_path_value(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw value"):
            MODULE._walk_evidence({"error": "/Users/example/private"})

    def test_rejects_windows_absolute_path_value(self) -> None:
        for value in (r"C:\Users\example\private", r"\\server\share\private"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw value"):
                    MODULE._walk_evidence({"error": value})

    def test_evidence_requires_current_agentic_head_binding(self) -> None:
        head = MODULE._git(MODULE.ROOT, "rev-parse", "HEAD")
        payload = {
            "status": "pass",
            "openclaw_head_sha": "openclaw-head",
            "agentic_os_head_sha": "stale-head",
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "Agentic OS head binding"):
            MODULE.validate_evidence(
                payload,
                openclaw_root=MODULE.ROOT,
                agentic_root=MODULE.ROOT,
                head="openclaw-head",
            )
        self.assertNotEqual(head, "stale-head")

    def test_committed_runtime_evidence_does_not_claim_stale_pass(self) -> None:
        evidence = MODULE.ROOT / "docs" / "runtime-evidence" / "openclaw-real-gateway-contract.json"
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        agentic_head = MODULE._git(MODULE.ROOT, "rev-parse", "HEAD")
        if payload.get("status") == "pass":
            self.assertEqual(payload.get("agentic_os_head_sha"), agentic_head)
            expected_sources = {
                item.get("path"): item.get("sha256")
                for item in payload.get("agentic_sources", [])
                if isinstance(item, dict)
            }
            for relative in MODULE.AGENTIC_SOURCE_PATHS:
                source = MODULE.ROOT / relative
                self.assertEqual(
                    expected_sources.get(relative),
                    MODULE._sha256_bytes(source.read_bytes()),
                )
        else:
            self.assertEqual(
                payload.get("committed_snapshot_authority"),
                "non_authoritative_last_run_snapshot",
            )

    def test_post_runner_validator_rebind_rejects_agentic_source_drift(self) -> None:
        initial = [
            {
                "path": "scripts/openclaw-real-gateway-contract-probe.py",
                "sha256": "0" * 64,
            }
        ]
        current = [
            {
                "path": "scripts/openclaw-real-gateway-contract-probe.py",
                "sha256": "1" * 64,
            }
        ]
        with mock.patch.object(MODULE, "_source_bindings", return_value=current):
            with self.assertRaisesRegex(MODULE.ProbeError, "source binding changed"):
                MODULE._assert_agentic_sources_still_bound(initial)

    def test_post_runner_validator_rebind_rejects_runtime_source_contract_drift(
        self,
    ) -> None:
        initial = self._agentic_source_bindings()
        current = [
            dict(source)
            for source in initial
        ]
        for source in current:
            if source["path"] == MODULE.RUNTIME_SOURCE_CONTRACT_HELPER:
                source["sha256"] = "1" * 64
        with mock.patch.object(MODULE, "_source_bindings", return_value=current):
            with self.assertRaisesRegex(MODULE.ProbeError, "source binding changed"):
                MODULE._assert_agentic_sources_still_bound(initial)

    def test_legacy_runner_uses_scrubbed_allowlisted_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            original_run = MODULE._run
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_source_binding = MODULE._source_binding
            original_validate_sources = MODULE._validate_sources
            original_git = MODULE._git
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                self.assertIs(start_new_session, True)
                self.assertIsNotNone(env)
                self.assertNotIn("AGENTIC_OS_REAL_ADAPTER_PROBE_SCRIPT", env)
                self.assertNotIn("OPENAI_API_KEY", env)
                self.assertNotIn("ANTHROPIC_API_KEY", env)
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("NODE_OPTIONS", env)
                self.assertEqual(env["AGENTIC_OS_EXPECTED_OPENCLAW_HEAD"], "openclaw-head")
                temp_path = Path(env["AGENTIC_OS_REAL_GATEWAY_EVIDENCE_FILE"])
                payload = {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "authenticated_gateway": True,
                    "effective_allow_lease": True,
                    "runtime_catalog_discovered": True,
                    "read_only_acquire_rejected": True,
                    "wrong_lease_rejected": True,
                    "cross_principal_lease_hidden": True,
                    "cross_principal_spawn_rejected": True,
                    "cross_principal_sessions_hidden": True,
                    "cross_principal_status_rejected": True,
                    "released_lease_spawn_rejected": True,
                    "canonical_session_observed": True,
                    "lifecycle_running_observed": True,
                    "lifecycle_completed_observed": True,
                    "lifecycle_failure_observed": True,
                    "duplicate_lease_identity_parity": True,
                    "duplicate_spawn_identity_parity": True,
                    "duplicate_release_identity_parity": True,
                    "child_completed": True,
                    "child_result_sha256": "0" * 64,
                    "child_run_id_sha256": "1" * 64,
                    "child_session_key_sha256": "2" * 64,
                    "task_marker_sha256": "3" * 64,
                    "static_allow_agents_wildcard": False,
                    "model_request_count": 2,
                    "sources": [],
                }
                temp_path.write_text(json.dumps(payload), encoding="utf-8")
                return self._attach_valid_process_cleanup(Proc())

            try:
                MODULE._run = fake_run
                MODULE.validate_candidate_root = lambda root: "openclaw-head"
                MODULE._candidate_probe_mode = lambda root: "legacy_e2e"
                MODULE._source_binding = lambda root, relative: {
                    "path": relative,
                    "sha256": "0" * 64,
                }
                MODULE._validate_sources = lambda value, *, root, label: None
                MODULE._git = lambda root, *args: "agentic-head"
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                with mock.patch.dict(
                    os.environ,
                    {
                        "OPENAI_API_KEY": "sk-live-secret",
                        "ANTHROPIC_API_KEY": "anthropic-secret",
                        "GITHUB_TOKEN": "github-secret",
                        "NODE_OPTIONS": "--require malicious-preload",
                    },
                    clear=False,
                ):
                    payload = MODULE.run_probe(Path(directory), output, timeout=1)
                self.assertEqual(payload["status"], "pass")
                self.assertEqual(payload["agentic_os_head_sha"], "agentic-head")
            finally:
                MODULE._run = original_run
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._source_binding = original_source_binding
                MODULE._validate_sources = original_validate_sources
                MODULE._git = original_git
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

    def test_legacy_runner_timeout_requires_process_group_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            original_run = MODULE._run
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_source_binding = MODULE._source_binding
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )
            cleanup = {
                "tracking_status": "available",
                "descendant_identities": [
                    {
                        "pid": 234567,
                        "uid": os.getuid(),
                        "start_id": "detached-start",
                    }
                ],
            }
            captured = {}

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                self.assertIs(start_new_session, True)
                exc = MODULE.subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output="runner stdout",
                    stderr="runner stderr",
                )
                exc.pid = 123456
                exc._agentic_os_process_cleanup = cleanup
                raise exc

            def fake_terminate_and_verify(proc):
                captured["cleanup"] = MODULE._tracked_cleanup_from_process(proc)
                return True, False

            try:
                MODULE._run = fake_run
                MODULE.validate_candidate_root = lambda root: "openclaw-head"
                MODULE._candidate_probe_mode = lambda root: "legacy_e2e"
                MODULE._source_binding = lambda root, relative: {
                    "path": relative,
                    "sha256": "0" * 64,
                }
                MODULE._terminate_and_verify_process_group = fake_terminate_and_verify
                with self.assertRaisesRegex(MODULE.ProbeError, "process group remained alive"):
                    MODULE.run_probe(Path(directory), output, timeout=1)
                self.assertEqual(captured["cleanup"], cleanup)
            finally:
                MODULE._run = original_run
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._source_binding = original_source_binding
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

    def test_evidence_requires_non_authoritative_snapshot_annotations(self) -> None:
        payload = {
            "status": "pass",
            "openclaw_head_sha": "openclaw-head",
            "agentic_os_head_sha": MODULE._git(MODULE.ROOT, "rev-parse", "HEAD"),
            "static_allow_agents_wildcard": False,
            "model_request_count": 2,
        }
        for proof in MODULE.REQUIRED_RUNTIME_PROOFS:
            payload[proof] = True
        with self.assertRaisesRegex(MODULE.ProbeError, "non-authoritative"):
            MODULE.validate_evidence(
                payload,
                openclaw_root=MODULE.ROOT,
                agentic_root=MODULE.ROOT,
                head="openclaw-head",
            )

    def test_disabled_future_adapter_proofs_are_rejected_as_authoritative(self) -> None:
        payload = {
            "status": "pass",
            "openclaw_head_sha": "openclaw-head",
            "agentic_os_head_sha": MODULE._git(MODULE.ROOT, "rev-parse", "HEAD"),
            "static_allow_agents_wildcard": False,
            "model_request_count": 2,
            "committed_snapshot_authority": "non_authoritative_last_run_snapshot",
            "current_head_evidence_required": True,
            "child_completed": False,
            "agentic_adapter_release_succeeded": True,
        }
        for proof in MODULE.REQUIRED_RUNTIME_PROOFS:
            payload[proof] = True
        with self.assertRaisesRegex(MODULE.ProbeError, "disabled future runtime proofs"):
            MODULE.validate_evidence(
                payload,
                openclaw_root=MODULE.ROOT,
                agentic_root=MODULE.ROOT,
                head="openclaw-head",
            )

    def test_child_completion_requires_hash_only_proofs(self) -> None:
        payload = {
            "status": "pass",
            "openclaw_head_sha": "openclaw-head",
            "agentic_os_head_sha": MODULE._git(MODULE.ROOT, "rev-parse", "HEAD"),
            "static_allow_agents_wildcard": False,
            "model_request_count": 2,
            "committed_snapshot_authority": "non_authoritative_last_run_snapshot",
            "current_head_evidence_required": True,
        }
        for proof in MODULE.REQUIRED_RUNTIME_PROOFS:
            payload[proof] = True
        with self.assertRaisesRegex(MODULE.ProbeError, "child_result_sha256"):
            MODULE.validate_evidence(
                payload,
                openclaw_root=MODULE.ROOT,
                agentic_root=MODULE.ROOT,
                head="openclaw-head",
            )

    def test_candidate_validation_requires_clean_exact_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"openclaw"}\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ProbeError, "git rev-parse HEAD failed"):
                MODULE.validate_candidate_root(root)

    def test_candidate_probe_mode_uses_persistent_runner_without_legacy_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")

            self.assertEqual(MODULE._candidate_probe_mode(root), "persistent_lifecycle_runner")

    def test_candidate_probe_mode_prefers_persistent_runner_over_legacy_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            legacy = root / MODULE.E2E_TEST
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("// legacy\n", encoding="utf-8")

            self.assertEqual(MODULE._candidate_probe_mode(root), "persistent_lifecycle_runner")

    def test_candidate_probe_mode_fails_without_supported_harness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODULE.ProbeError, "neither"):
                MODULE._candidate_probe_mode(Path(directory))

    def test_persistent_runtime_source_closure_binds_transitive_local_imports(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "import 'node:fs';\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: "\n".join(
                    (
                        "import { canonicalJson } from '../src/gateway/agentic-os-canonical-json.js';",
                        "import { GatewayClient } from '../src/gateway/client.js';",
                        "import { GATEWAY_CLIENT_MODES } from '../src/utils/message-channel.js';",
                    )
                )
                + "\n",
                "src/gateway/agentic-os-runtime-attestation.ts": "\n".join(
                    (
                        "import { resolveCommitHash } from '../infra/git-commit.js';",
                        "import { resolveOpenClawPackageRootSync } from '../infra/openclaw-root.js';",
                        "import { VERSION } from '../version.js';",
                        "import { canonicalJson } from './agentic-os-canonical-json.js';",
                        "import { agenticOsRuntimeContractVector } from './agentic-os-runtime-contract-descriptors.js';",
                    )
                )
                + "\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const methods = [];\n",
                "src/gateway/client.ts": (
                    "import { GatewayClient as BaseGatewayClient } "
                    "from '../../packages/gateway-client/src/index.js';\n"
                    "import { packageRuntime } from 'fixture-runtime';\n"
                ),
                "src/utils/message-channel.ts": (
                    "export { normalizeMessageChannel } "
                    "from './message-channel-normalize.js';\n"
                ),
                "src/gateway/agentic-os-canonical-json.ts": "export function canonicalJson(v: unknown) { return JSON.stringify(v); }\n",
                "src/infra/git-commit.ts": "export function resolveCommitHash() { return 'head'; }\n",
                "src/infra/openclaw-root.ts": "export function resolveOpenClawPackageRootSync() { return null; }\n",
                "src/version.ts": "export const VERSION = '0.0.0-test';\n",
                "packages/gateway-client/src/index.ts": "export class GatewayClient {}\n",
                "src/utils/message-channel-normalize.ts": "export function normalizeMessageChannel() { return 'internal'; }\n",
                "node_modules/fixture-runtime/package.json": (
                    '{"name":"fixture-runtime","main":"index.cjs"}\n'
                ),
                "node_modules/fixture-runtime/index.cjs": (
                    "const implPath = require /* bound */ . /* hidden */ resolve /* target */ ('./impl.cjs');\n"
                    "const dep = require('fixture-runtime-dep');\n"
                    "module.exports = { packageRuntime() { return Boolean(implPath) && dep.ok; } };\n"
                ),
                "node_modules/fixture-runtime/impl.cjs": (
                    "module.exports = { packageRuntime() { return true; } };\n"
                ),
                "node_modules/fixture-runtime-dep/package.json": (
                    '{"name":"fixture-runtime-dep","main":"index.js"}\n'
                ),
                "node_modules/fixture-runtime-dep/index.js": (
                    "module.exports = { ok: true };\n"
                ),
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Agentic OS Test",
                "GIT_AUTHOR_EMAIL": "agentic-os-test@example.invalid",
                "GIT_COMMITTER_NAME": "Agentic OS Test",
                "GIT_COMMITTER_EMAIL": "agentic-os-test@example.invalid",
            }
            subprocess.run(["git", "init"], cwd=root, env=env, check=True, stdout=subprocess.PIPE)
            subprocess.run(["git", "add", "."], cwd=root, env=env, check=True, stdout=subprocess.PIPE)
            subprocess.run(
                ["git", "commit", "-m", "runtime source closure fixture"],
                cwd=root,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
            )

            paths = MODULE._persistent_runtime_source_paths(root)
            expected_transitive = {
                "src/gateway/agentic-os-canonical-json.ts",
                "src/infra/git-commit.ts",
                "src/infra/openclaw-root.ts",
                "src/version.ts",
                "packages/gateway-client/src/index.ts",
                "src/utils/message-channel-normalize.ts",
                "node_modules/fixture-runtime/package.json",
                "node_modules/fixture-runtime/index.cjs",
                "node_modules/fixture-runtime/impl.cjs",
                "node_modules/fixture-runtime-dep/package.json",
                "node_modules/fixture-runtime-dep/index.js",
            }
            self.assertTrue(expected_transitive.issubset(set(paths)))
            self.assertNotIn("node:fs", paths)
            bindings = MODULE._persistent_runtime_source_bindings(root)
            by_path = {item["path"]: item["sha256"] for item in bindings}
            transitive_source = root / "src/gateway/agentic-os-canonical-json.ts"
            self.assertEqual(
                by_path["src/gateway/agentic-os-canonical-json.ts"],
                MODULE._sha256_bytes(transitive_source.read_bytes()),
            )

            transitive_source.write_text("export const evil = true;\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ProbeError, "source closure"):
                MODULE._persistent_runtime_source_bindings(root)

    def test_persistent_runtime_source_closure_fails_on_unbound_package_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "import 'missing-runtime-package';\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: "export const runner = true;\n",
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "package import"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_commonjs_require(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "const name = './runner-impl.cjs';\nrequire /* hidden */ (name);\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "scripts/runner-impl.cjs": "module.exports = {};\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "dynamic CommonJS require"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_require_resolve_with_trivia(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "const name = './runner-impl.cjs';\n"
                    "require . /* hidden */ resolve(name);\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "scripts/runner-impl.cjs": "module.exports = {};\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "dynamic CommonJS require"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_computed_dynamic_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "const name = './runner-impl.mjs';\nawait import /* hidden */ (name);\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "scripts/runner-impl.mjs": "export const dynamic = true;\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "dynamic import"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_template_dynamic_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "const name = 'runner-impl';\nawait import /* hidden */ (`./${name}.mjs`);\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "scripts/runner-impl.mjs": "export const dynamic = true;\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "dynamic import"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_accepts_dynamic_import_attributes(
        self,
    ) -> None:
        for attribute_key in ("with", "assert"):
            with self.subTest(attribute_key=attribute_key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            "const config = await import("
                            f"'./config.json', {{ {attribute_key}: {{ type: 'json' }} }});\n"
                            "export { config };\n"
                        ),
                        "scripts/config.json": '{"runtime": true}\n',
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

                self.assertIn("scripts/config.json", paths)

    def test_persistent_runtime_source_closure_binds_commonjs_callable_variants(
        self,
    ) -> None:
        variants = (
            "require?.('./runner-impl.cjs');\n",
            "require?.resolve('./runner-impl.cjs');\n",
            "require.resolve?.('./runner-impl.cjs');\n",
            "require?.['resolve']('./runner-impl.cjs');\n",
            "require['resolve']('./runner-impl.cjs');\n",
            "require['resolve']?.('./runner-impl.cjs');\n",
            "module.require('./runner-impl.cjs');\n",
            "module['require']('./runner-impl.cjs');\n",
            "module?.['require']?.('./runner-impl.cjs');\n",
            "(require)('./runner-impl.cjs');\n",
            "(require.resolve)('./runner-impl.cjs');\n",
            "`${require('./runner-impl.cjs')}`;\n",
        )
        for runner_source in variants:
            with self.subTest(runner_source=runner_source):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    files = {
                        "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                        "openclaw.mjs": "export const openclaw = true;\n",
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: runner_source,
                        "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                        "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                        "src/gateway/client.ts": "export const c = 1;\n",
                        "src/utils/message-channel.ts": "export const m = 1;\n",
                        "scripts/runner-impl.cjs": "module.exports = {};\n",
                    }
                    for relative, content in files.items():
                        path = root / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(content, encoding="utf-8")

                    paths = MODULE._persistent_runtime_source_paths(root)
                    self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_indirect_bare_commonjs_require(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "(0, require)('./hidden.cjs');\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "indirect CommonJS require",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_commonjs_require_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const load = require;\n"
                        "load('./runner-impl.cjs');\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = {};\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_commonjs_require_alias_non_call(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const load = require;\n"
                        "const later = load;\n"
                        "later('./runner-impl.cjs');\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = {};\n",
                },
            )

            with self.assertRaisesRegex(
                RuntimeError, "unsupported CommonJS require alias usage"
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_create_require_loader(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = createRequire(import.meta.url);\n"
                        "load('./runner-impl.cjs');\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = {};\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_binds_create_require_loader_in_template_expression(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = createRequire(import.meta.url);\n"
                        "const value = `${load('./runner-impl.cjs')}`;\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = {};\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_unsupported_create_require_loader_usage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = createRequire(import.meta.url);\n"
                        "const alias = load;\n"
                        "alias('./runner-impl.cjs');\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = {};\n",
                },
            )

            with self.assertRaisesRegex(
                RuntimeError, "unsupported createRequire loader usage"
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_resolves_node_export_entry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: "export const runner = true;\n",
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": (
                    "import { packageRuntime } from 'fixture-runtime';\n"
                ),
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "node_modules/fixture-runtime/package.json": json.dumps(
                    {
                        "name": "fixture-runtime",
                        "main": "legacy-main.cjs",
                        "module": "bundler-entry.mjs",
                        "types": "index.d.ts",
                        "exports": {
                            ".": {
                                "types": "./index.d.ts",
                                "import": "./runtime-entry.js",
                                "require": "./runtime-entry.cjs",
                                "default": "./default-entry.js",
                            }
                        },
                    }
                )
                + "\n",
                "node_modules/fixture-runtime/legacy-main.cjs": (
                    "module.exports = { legacy: true };\n"
                ),
                "node_modules/fixture-runtime/bundler-entry.mjs": (
                    "export const bundler = true;\n"
                ),
                "node_modules/fixture-runtime/index.d.ts": (
                    "export declare const onlyTypes: boolean;\n"
                ),
                "node_modules/fixture-runtime/runtime-entry.js": (
                    "export const packageRuntime = true;\n"
                ),
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/package.json", paths)
        self.assertIn("node_modules/fixture-runtime/runtime-entry.js", paths)
        self.assertNotIn("node_modules/fixture-runtime/legacy-main.cjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/bundler-entry.mjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/index.d.ts", paths)

    def test_persistent_runtime_source_closure_prefers_node_addons_export_condition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "src/gateway/client.ts": "import addon from 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": {
                                ".": {
                                    "node-addons": "./addon-entry.js",
                                    "node": "./node-entry.js",
                                    "default": "./default-entry.js",
                                }
                            },
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/addon-entry.js": (
                        "export default 'node-addons';\n"
                    ),
                    "node_modules/fixture-runtime/node-entry.js": (
                        "export default 'node';\n"
                    ),
                    "node_modules/fixture-runtime/default-entry.js": (
                        "export default 'default';\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/addon-entry.js", paths)
        self.assertNotIn("node_modules/fixture-runtime/node-entry.js", paths)
        self.assertNotIn("node_modules/fixture-runtime/default-entry.js", paths)

    def test_persistent_runtime_source_closure_uses_node_legacy_package_index_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "src/gateway/client.ts": "import runtime from 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": (
                        '{"name":"fixture-runtime"}\n'
                    ),
                    "node_modules/fixture-runtime/index.ts": (
                        "export default 'typescript-decoy';\n"
                    ),
                    "node_modules/fixture-runtime/index.js": (
                        "export default 'node-runtime';\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/index.js", paths)
        self.assertNotIn("node_modules/fixture-runtime/index.ts", paths)

    def test_persistent_runtime_source_closure_uses_commonjs_directory_package_main(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "require('./lib');\n",
                    "scripts/lib/package.json": json.dumps(
                        {"name": "runner-lib", "main": "actual.cjs"}
                    )
                    + "\n",
                    "scripts/lib/actual.cjs": "module.exports = { actual: true };\n",
                    "scripts/lib/index.js": "module.exports = { decoy: true };\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/lib/package.json", paths)
        self.assertIn("scripts/lib/actual.cjs", paths)
        self.assertNotIn("scripts/lib/index.js", paths)

    def test_persistent_runtime_source_closure_rejects_native_addons(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "require('fixture-native-addon');\n",
                    "node_modules/fixture-native-addon/package.json": json.dumps(
                        {"name": "fixture-native-addon", "main": "native-addon"}
                    )
                    + "\n",
                    "node_modules/fixture-native-addon/native-addon.node": "native fixture\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "native add-on"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_preserves_commonjs_query_filename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "require('./runner-impl?prod');\n"
                    ),
                    "scripts/runner-impl.js": "module.exports = { decoy: true };\n",
                    "scripts/runner-impl?prod.js": (
                        "module.exports = { actual: true };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl?prod.js", paths)
        self.assertNotIn("scripts/runner-impl.js", paths)

    def test_persistent_runtime_source_closure_parses_commonjs_after_regex_literal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const r = /'/;\n"
                        "require('./runner-impl.cjs');\n"
                    ),
                    "scripts/runner-impl.cjs": "module.exports = { actual: true };\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_fails_closed_on_ambiguous_slash(
        self,
    ) -> None:
        cases = {
            "control_header": "if (enabled) /'/.test(value);\n",
            "loop_header": "while (enabled) /'/.test(value);\n",
            "closing_block": "{} /'/.test(value);\n",
        }
        for name, prefix in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            prefix + "require('./runner-impl.cjs');\n"
                        ),
                        "scripts/runner-impl.cjs": (
                            "module.exports = { actual: true };\n"
                        ),
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "ambiguous JavaScript slash token",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_child_process_node_entrypoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawn, execFile } from 'node:child_process';\n"
                        "spawn(process.execPath, ['./spawn-worker.mjs']);\n"
                        "execFile(process.execPath, ['./exec-worker.mjs']);\n"
                    ),
                    "spawn-worker.mjs": "export const spawnWorker = true;\n",
                    "exec-worker.mjs": "export const execWorker = true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("spawn-worker.mjs", paths)
        self.assertIn("exec-worker.mjs", paths)

    def test_persistent_runtime_source_closure_binds_sync_child_process_node_entrypoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawnSync, execFileSync } from 'node:child_process';\n"
                        "spawnSync(process.execPath, ['./spawn-sync-worker.mjs']);\n"
                        "execFileSync(process.execPath, ['./exec-file-sync-worker.mjs']);\n"
                    ),
                    "spawn-sync-worker.mjs": "export const spawnSyncWorker = true;\n",
                    "exec-file-sync-worker.mjs": (
                        "export const execFileSyncWorker = true;\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("spawn-sync-worker.mjs", paths)
        self.assertIn("exec-file-sync-worker.mjs", paths)

    def test_persistent_runtime_source_closure_binds_aliased_sync_child_process_node_entrypoints(
        self,
    ) -> None:
        cases = {
            "esm_renamed_spawn_sync": (
                "import { spawnSync as launchNode } from 'node:child_process';\n"
                "launchNode(process.execPath, ['./esm-spawn-alias.mjs']);\n",
                "esm-spawn-alias.mjs",
            ),
            "esm_renamed_exec_file_sync": (
                "import { execFileSync as launchFile } from 'child_process';\n"
                "launchFile(process.execPath, ['./esm-exec-file-alias.mjs']);\n",
                "esm-exec-file-alias.mjs",
            ),
            "cjs_destructured_spawn_sync": (
                "const { spawnSync: runNodeNow } = require('node:child_process');\n"
                "runNodeNow(process.execPath, ['./cjs-spawn-alias.cjs']);\n",
                "cjs-spawn-alias.cjs",
            ),
            "cjs_destructured_exec_file_sync": (
                "const { execFileSync: runFileNow } = require('child_process');\n"
                "runFileNow(process.execPath, ['./cjs-exec-file-alias.cjs']);\n",
                "cjs-exec-file-alias.cjs",
            ),
        }
        for name, (source, worker) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        worker: "module.exports = { worker: true };\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn(worker, paths)

    def test_persistent_runtime_source_closure_rejects_aliased_exec_sync(
        self,
    ) -> None:
        cases = {
            "esm_renamed_exec_sync": (
                "import { execSync as shellNow } from 'node:child_process';\n"
                "shellNow(process.execPath + ' ./hidden.mjs');\n"
            ),
            "cjs_destructured_exec_sync": (
                "const { execSync: shellNow } = require('child_process');\n"
                "shellNow(process.execPath + ' ./hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.mjs": "export const hidden = true;\n",
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "shell child-process entrypoint",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_async_shell_exec(
        self,
    ) -> None:
        cases = {
            "direct_import": (
                "import { exec } from 'node:child_process';\n"
                "exec(process.execPath + ' ./hidden.mjs');\n"
            ),
            "aliased_import": (
                "import { exec as shellLater } from 'child_process';\n"
                "shellLater(process.execPath + ' ./hidden.mjs');\n"
            ),
            "cjs_destructured_alias": (
                "const { exec: shellLater } = require('node:child_process');\n"
                "shellLater(process.execPath + ' ./hidden.cjs');\n"
            ),
            "namespace_call": (
                "const child_process = require('child_process');\n"
                "child_process.exec(process.execPath + ' ./hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.mjs": "export const hidden = true;\n",
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "shell child-process entrypoint",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_unbound_exec_sync(
        self,
    ) -> None:
        cases = (
            (
                "import { execSync } from 'node:child_process';\n"
                "execSync(process.execPath + ' ./hidden.mjs');\n"
            ),
            (
                "import * as cp from 'node:child_process';\n"
                "cp.spawnSync(process.execPath, ['./hidden.mjs']);\n"
            ),
            (
                "import * as cp from 'node:child_process';\n"
                "(0, cp.spawnSync)(process.execPath, ['./hidden.mjs']);\n"
            ),
            (
                "import { spawnSync } from 'node:child_process';\n"
                "(0, spawnSync)(process.execPath, ['./hidden.mjs']);\n"
            ),
            (
                "const cp = require('node:child_process');\n"
                "cp['spawnSync'](process.execPath, ['./hidden.mjs']);\n"
            ),
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.mjs": "export const hidden = true;\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "shell child-process entrypoint|child-process Node entrypoint",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_run_main(
        self,
    ) -> None:
        cases = (
            "require('module').runMain('./hidden.cjs');\n",
            "const moduleApi = require('node:module');\nmoduleApi.runMain('./hidden.cjs');\n",
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "CommonJS runtime loader",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_inline_create_require_invocation(
        self,
    ) -> None:
        cases = {
            "commonjs_inline": (
                "require('module').createRequire(__filename)('./hidden.cjs');\n"
            ),
            "namespace_inline": (
                "const moduleApi = require('node:module');\n"
                "moduleApi.createRequire(__filename)('./hidden.cjs');\n"
            ),
            "one_character_namespace_inline": (
                "const m = require('node:module');\n"
                "m.createRequire(__filename)('./hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("scripts/hidden.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_nonlocal_create_require_base(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = createRequire("
                        "new URL('../alternate/base.mjs', import.meta.url));\n"
                        "load('./hidden.cjs');\n"
                    ),
                    "alternate/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported non-local createRequire base",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_native_addon_entrypoint(
        self,
    ) -> None:
        variants = (
            "process.dlopen(module, './runtime-addon.node');\n",
            "process.dlopen?.(module, './runtime-addon.node');\n",
            "process?.dlopen(module, './runtime-addon.node');\n",
            "process['dlopen'](module, './runtime-addon.node');\n",
            "process?.['dlopen']?.(module, './runtime-addon.node');\n",
            "(process.dlopen)(module, './runtime-addon.node');\n",
            "((process.dlopen))(module, './runtime-addon.node');\n",
            "(process['dlopen'])(module, './runtime-addon.node');\n",
            "(process).dlopen(module, './runtime-addon.node');\n",
            "globalThis.process.dlopen(module, './runtime-addon.node');\n",
            "globalThis['process'].dlopen(module, './runtime-addon.node');\n",
            "(globalThis).process.dlopen(module, './runtime-addon.node');\n",
            "globalThis?.process.dlopen(module, './runtime-addon.node');\n",
            "globalThis?.['process'].dlopen(module, './runtime-addon.node');\n",
            "global.process.dlopen(module, './runtime-addon.node');\n",
            "process.dl\\u006fpen(module, './runtime-addon.node');\n",
            "pro\\u0063ess.dlopen(module, './runtime-addon.node');\n",
            "globalThis.pro\\u0063ess.dl\\u006fpen(module, './runtime-addon.node');\n",
            "`${process.dlopen(module, './runtime-addon.node')}`;\n",
        )
        for source in variants:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/runtime-addon.node": "native-addon-placeholder\n",
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "native add-on"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_native_addon_entrypoint(
        self,
    ) -> None:
        cases = {
            "dynamic": (
                "const addon = './runtime-addon.node';\n"
                "process.dlopen(module, addon);\n"
            ),
            "transferred": (
                "const loadAddon = process.dlopen;\n"
                "loadAddon(module, './runtime-addon.node');\n"
            ),
            "process-alias": (
                "const p = process;\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "process-alias-asi": (
                "const p = (process)\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "destructured": (
                "const { dlopen } = process;\n"
                "dlopen(module, './runtime-addon.node');\n"
            ),
            "dynamic-key": (
                "const key = 'dlopen';\n"
                "process[key](module, './runtime-addon.node');\n"
            ),
            "computed-key": (
                "process['dlo' + 'pen'](module, './runtime-addon.node');\n"
            ),
            "concatenated-path": (
                "process.dlopen(module, './runtime-addon' + '.node');\n"
            ),
            "sequence-transfer": (
                "const p = (0, process);\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "conditional-transfer": (
                "const p = true ? process : null;\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "container-transfer": (
                "const holder = { p: process };\n"
                "holder.p.dlopen(module, './runtime-addon.node');\n"
            ),
            "global-destructuring": (
                "const { process: p } = globalThis;\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "global-reflection": (
                "Reflect.get(globalThis, 'process').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "process-module-require-direct": (
                "require('node:process').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "process-module-require-alias": (
                "const p = require('node:process');\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "process-module-import": (
                "import p from 'node:process';\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "process-get-builtin-module": (
                "process.getBuiltinModule('node:process').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "process-get-builtin-module-alias": (
                "const p = process.getBuiltinModule('node:process');\n"
                "p.dlopen(module, './runtime-addon.node');\n"
            ),
            "module-constructor-load": (
                "module.constructor._load('node:process').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "non-strict-this-process": (
                "this.process.dlopen(module, './runtime-addon.node');\n"
            ),
            "computed-this-process": (
                "(function () { return this['pro' + 'cess']; })().dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "template-this-process": (
                "(function () { return this[`process`]; })().dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "computed-module-constructor-load": (
                "module.constructor['_load']('node:' + 'pro' + 'cess').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "reflect-computed-this-process": (
                "(function () { return Reflect.get("
                "this, 'pro' + 'cess'); })().dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "sequence-this-container-computed-process": (
                "const obj = (0, this);\n"
                "obj['pro' + 'cess'].dlopen(module, './runtime-addon.node');\n"
            ),
            "sequence-this-container-template-process": (
                "const obj = (0, this);\n"
                "obj[`process`].dlopen(module, './runtime-addon.node');\n"
            ),
            "sequence-reflect-transfer": (
                "const R = (0, Reflect);\n"
                "R.get(this, 'pro' + 'cess').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "reflect-container-transfer": (
                "const holder = { R: Reflect };\n"
                "holder.R.get(this, 'pro' + 'cess').dlopen("
                "module, './runtime-addon.node');\n"
            ),
            "conditional-module-transfer": (
                "const M = true ? module : null;\n"
                "M.constructor['_lo' + 'ad']('node:' + 'pro' + 'cess').dlopen("
                "module, './runtime-addon.node');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/runtime-addon.node": "native-addon-placeholder\n",
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "native add-on"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_ignores_native_addon_text_literals(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const quoted = \"process.dlopen(module, './runtime-addon.node')\";\n"
                        "const raw = `process.dlopen(module, './runtime-addon.node')`;\n"
                        "const pattern = /process\\.dlopen\\(module/;\n"
                        "const env = process.env;\n"
                        "const version = globalThis['process'].version;\n"
                        "const legacyVersion = global.process.version;\n"
                        "const labels = { process: 'runtime' };\n"
                        "const processLabel = 'process';\n"
                        "const processLabels = ['process'];\n"
                        "export { quoted, raw, pattern, env, version, legacyVersion, labels };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertNotIn("scripts/runtime-addon.node", paths)

    def test_persistent_runtime_source_closure_rejects_dynamic_child_process_node_entrypoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawn } from 'node:child_process';\n"
                        "const worker = './spawn-worker.mjs';\n"
                        "spawn(process.execPath, [worker]);\n"
                    ),
                    "spawn-worker.mjs": "export const spawnWorker = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "child-process Node"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_evaluated_loader_calls(
        self,
    ) -> None:
        cases = {
            "eval_require": 'eval("require(\\\'./runner-impl.cjs\\\')");\n',
            "function_import": 'new Function("return import(\\\'./runner-impl.mjs\\\')")();\n',
            "property_eval": 'globalThis.eval("require(\\\'./runner-impl.cjs\\\')");\n',
            "indirect_eval": '(0, eval)("require(\\\'./runner-impl.cjs\\\')");\n',
            "function_reference": (
                'Reflect.construct(Function, ["return import(\\\'./runner-impl.mjs\\\')"])();\n'
            ),
            "vm_run_in_this_context": (
                "import vm from 'node:vm';\n"
                "import fs from 'node:fs';\n"
                "vm.runInThisContext(fs.readFileSync("
                "new URL('./runner-impl.mjs', import.meta.url), 'utf8'));\n"
            ),
            "vm_bracket_run_in_this_context": (
                "import vm from 'node:vm';\n"
                "vm['runIn' + 'ThisContext']('require(\\'./runner-impl.cjs\\')');\n"
            ),
            "vm_script": (
                "import { Script } from 'node:vm';\n"
                "new Script('require(\\'./runner-impl.cjs\\')').runInThisContext();\n"
            ),
            "inspector_runtime_evaluate": (
                "import inspector from 'node:inspector';\n"
                "const session = new inspector.Session();\n"
                "session.connect();\n"
                "session.post('Runtime.evaluate', {"
                " expression: \"process.getBuiltinModule('module')"
                ".createRequire(process.cwd() + '/x')('./hidden.cjs')\""
                "});\n"
            ),
            "repl_source_load": (
                "import repl from 'node:repl';\n"
                "const server = repl.start({ prompt: '', terminal: false });\n"
                "server.commands.load.action.call(server, './hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/runner-impl.cjs": "module.exports = { actual: true };\n",
                        "scripts/runner-impl.mjs": "export const actual = true;\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "evaluated loader|inspector evaluation|REPL",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_compile(
        self,
    ) -> None:
        cases = {
            "direct_module_compile": (
                "module._compile(\"require('./hidden.cjs')\", __filename);\n"
            ),
            "constructed_node_module_compile": (
                "new (require('node:module'))(__filename)"
                "._compile(\"require('./hidden.cjs')\", __filename);\n"
            ),
            "constructed_node_module_member_compile": (
                "new (require('node:module').Module)(__filename)"
                "._compile(\"require('./hidden.cjs')\", __filename);\n"
            ),
            "grouped_constructed_node_module_member_compile": (
                "(new (require('node:module').Module)(__filename))"
                "['_com' + 'pile'](\"require('./hidden.cjs')\", __filename);\n"
            ),
            "destructured_node_module_constructor_compile": (
                "const { Module: RuntimeModule } = require('node:module');\n"
                "new RuntimeModule(__filename)"
                "._compile(\"require('./hidden.cjs')\", __filename);\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "runtime compiler"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_custom_commonjs_extensions(
        self,
    ) -> None:
        cases = {
            "require_extensions": (
                "require.extensions['.foo'] = require.extensions['.js'];\n"
                "require('./impl.foo');\n"
            ),
            "module_extensions": (
                "module._extensions['.foo'] = module._extensions['.js'];\n"
                "require('./impl.foo');\n"
            ),
            "require_node_module_extensions": (
                "require('node:module')._extensions['.foo'] = () => {};\n"
                "require('./impl.foo');\n"
            ),
            "require_node_module_legacy_extensions": (
                "require('node:module').extensions['.foo'] = () => {};\n"
                "require('./impl.foo');\n"
            ),
            "require_node_module_member_extensions": (
                "require('node:module').Module['_ext' + 'ensions']['.foo'] = () => {};\n"
                "require('./impl.foo');\n"
            ),
            "aliased_node_module_extensions": (
                "const runtimeModule = require('node:module');\n"
                "runtimeModule.extensions['.foo'] = () => {};\n"
                "require('./impl.foo');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/impl.foo": "require('./hidden.cjs');\n",
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "CommonJS extension"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_webassembly_evaluation(
        self,
    ) -> None:
        cases = {
            "instantiate_read_file": (
                "import fs from 'node:fs';\n"
                "WebAssembly.instantiate(fs.readFileSync('./impl.wasm'));\n"
            ),
            "compile_static_member": (
                "const wasm = globalThis['Web' + 'Assembly'];\n"
                "wasm.compile(new Uint8Array());\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/impl.wasm": "unbound binary payload",
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "WebAssembly"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_register_hooks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { register as registerHook } from 'node:module';\n"
                        "registerHook('./hooks.mjs', import.meta.url);\n"
                    ),
                    "scripts/hooks.mjs": "export async function resolve() { return {}; }\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "module.register hook"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_register_hook_in_template_expression(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { register as registerHook } from 'node:module';\n"
                        "`${registerHook('./hooks.mjs', import.meta.url)}`;\n"
                    ),
                    "scripts/hooks.mjs": "export async function resolve() { return {}; }\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "module.register hook"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_register_hooks_source_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { registerHooks } from 'node:module';\n"
                        "registerHooks({ load() {} });\n"
                    ),
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "evaluated loader"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_unbound_execution_capabilities(
        self,
    ) -> None:
        cases = {
            "node_test": (
                "import { run } from 'node:test';\n"
                "run({ files: ['./hidden.cjs'] });\n"
            ),
            "node_vm": (
                "import vm from 'node:vm';\n"
                "const member = ['run', 'InThis', 'Context'].join('');\n"
                "vm[member]('hidden source');\n"
            ),
            "node_sqlite": (
                "import { DatabaseSync } from 'node:sqlite';\n"
                "new DatabaseSync(':memory:', { allowExtension: true })"
                ".loadExtension('./hidden.so');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {MODULE.PERSISTENT_LIFECYCLE_RUNNER: source},
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError, "unbound execution capability"
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_callable_constructor_evaluation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import fs from 'node:fs';\n"
                        "[].filter.constructor("
                        "fs.readFileSync('./hidden.txt', 'utf8'))();\n"
                    ),
                    "scripts/hidden.txt": "globalThis.hidden = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "evaluated loader"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_indirect_fork_aliases(
        self,
    ) -> None:
        cases = (
            "import { fork as launch } from 'node:child_process';\n"
            "(0, launch)('./hidden.cjs');\n",
            "import { fork as launch } from 'node:child_process';\n"
            "Reflect.apply(launch, null, ['./hidden.cjs']);\n",
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = {};\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError, "indirect child-process fork entrypoint"
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_escaped_constructor_and_execve(
        self,
    ) -> None:
        cases = {
            "escaped_constructor": (
                "import fs from 'node:fs';\n"
                "[].filter.constr\\u0075ctor("
                "fs.readFileSync('./hidden.txt', 'utf8'))();\n"
            ),
            "brace_escaped_constructor": (
                "import fs from 'node:fs';\n"
                "[].filter.constr\\u{75}ctor("
                "fs.readFileSync('./hidden.txt', 'utf8'))();\n"
            ),
            "process_execve": (
                "process.execve(process.execPath, "
                "[process.execPath, './hidden.cjs'], process.env);\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {MODULE.PERSISTENT_LIFECYCLE_RUNNER: source},
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "unsupported"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_indirect_worker_constructor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { Worker } from 'node:worker_threads';\n"
                        "new (0, Worker)(new URL('./hidden.mjs', import.meta.url));\n"
                    ),
                    "scripts/hidden.mjs": "export const hidden = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "indirect Worker"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_module_register_hook(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { register } from 'node:module';\n"
                        "const hook = './hooks.mjs';\n"
                        "register(hook, import.meta.url);\n"
                    ),
                    "scripts/hooks.mjs": "export async function resolve() { return {}; }\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "module.register hook"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_register_parent_or_transfer(
        self,
    ) -> None:
        cases = {
            "dynamic_parent": (
                "import { register } from 'node:module';\n"
                "register('./hooks.mjs', parentURL);\n"
            ),
            "wrong_parent": (
                "import { register } from 'node:module';\n"
                "register('./hooks.mjs', 'file:///tmp/elsewhere.mjs');\n"
            ),
            "loader_transfer": (
                "import { register as registerHook } from 'node:module';\n"
                "const delegated = registerHook;\n"
                "delegated('./hooks.mjs', import.meta.url);\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hooks.mjs": (
                            "export async function resolve() { return {}; }\n"
                        ),
                    },
                )

                with self.assertRaisesRegex(MODULE.ProbeError, "module.register hook"):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_commonjs_alias_in_template_expression(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const load = require;\n"
                        "`${load('./runner-impl.cjs')}`;\n"
                    ),
                    "scripts/runner-impl.cjs": (
                        "module.exports = { actual: true };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-impl.cjs", paths)

    def test_persistent_runtime_source_closure_binds_quoted_static_import_clause(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "src/gateway/client.ts": (
                        'import { "a;b" as value } from "./quoted-dep.mjs";\n'
                        "export const c = value;\n"
                    ),
                    "src/gateway/quoted-dep.mjs": 'export const "a;b" = true;\n',
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("src/gateway/quoted-dep.mjs", paths)

    def test_persistent_runtime_source_closure_resolves_nested_importer_dependency(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "src/gateway/client.ts": "import { packageRuntime } from 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": (
                        '{"name":"fixture-runtime","main":"index.cjs"}\n'
                    ),
                    "node_modules/fixture-runtime/index.cjs": (
                        "const dep = require('fixture-runtime-dep');\n"
                        "module.exports = { packageRuntime() { return dep.source; } };\n"
                    ),
                    "node_modules/fixture-runtime/node_modules/fixture-runtime-dep/package.json": (
                        '{"name":"fixture-runtime-dep","main":"index.js"}\n'
                    ),
                    "node_modules/fixture-runtime/node_modules/fixture-runtime-dep/index.js": (
                        "module.exports = { source: 'nested' };\n"
                    ),
                    "node_modules/fixture-runtime-dep/package.json": (
                        '{"name":"fixture-runtime-dep","main":"index.js"}\n'
                    ),
                    "node_modules/fixture-runtime-dep/index.js": (
                        "module.exports = { source: 'root' };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn(
            "node_modules/fixture-runtime/node_modules/fixture-runtime-dep/index.js",
            paths,
        )
        self.assertNotIn("node_modules/fixture-runtime-dep/index.js", paths)

    def test_persistent_runtime_source_closure_resolves_wildcard_package_exports(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "src/gateway/client.ts": (
                        "import { feature } from 'fixture-runtime/feature/x';\n"
                    ),
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": {"./feature/*": "./dist/feature/*.js"},
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/dist/feature/x.js": (
                        "export const feature = true;\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/dist/feature/x.js", paths)

    def test_persistent_runtime_source_closure_resolves_package_self_reference_before_node_modules(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "package.json": json.dumps(
                        {
                            "name": "demo",
                            "version": "0.0.0-test",
                            "exports": {"./feature": "./real.js"},
                        }
                    )
                    + "\n",
                    "src/gateway/client.ts": "import { feature } from 'demo/feature';\n",
                    "real.js": "export const feature = 'root';\n",
                    "node_modules/demo/package.json": json.dumps(
                        {
                            "name": "demo",
                            "exports": {"./feature": "./decoy.js"},
                        }
                    )
                    + "\n",
                    "node_modules/demo/decoy.js": "export const feature = 'decoy';\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("real.js", paths)
        self.assertNotIn("node_modules/demo/decoy.js", paths)

    def test_persistent_runtime_source_closure_resolves_package_imports_map(
        self,
    ) -> None:
        cases = {
            "esm": (
                "src/gateway/client.ts",
                "import { impl } from '#impl';\nexport const c = impl;\n",
                "impl.mjs",
            ),
            "commonjs": (
                MODULE.PERSISTENT_LIFECYCLE_RUNNER,
                "const impl = require('#impl');\n",
                "impl.cjs",
            ),
        }
        for name, (relative, source, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        "package.json": json.dumps(
                            {
                                "name": "openclaw",
                                "version": "0.0.0-test",
                                "imports": {
                                    "#impl": {
                                        "import": "./impl.mjs",
                                        "require": "./impl.cjs",
                                    }
                                },
                            }
                        )
                        + "\n",
                        relative: source,
                        "impl.mjs": "export const impl = true;\n",
                        "impl.cjs": "module.exports = { impl: true };\n",
                        "node_modules/#impl/package.json": '{"name":"#impl"}\n',
                        "node_modules/#impl/index.js": "export const decoy = true;\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn(expected, paths)
            self.assertIn("package.json", paths)
            self.assertNotIn("node_modules/#impl/index.js", paths)

    def test_persistent_runtime_source_closure_treats_core_subpath_overlap_as_package(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "openclaw.mjs": "import extra from 'fs/extra';\n",
                    "node_modules/fs/package.json": (
                        '{"name":"fs","exports":{"./extra":"./extra.js"}}\n'
                    ),
                    "node_modules/fs/extra.js": "export default true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fs/package.json", paths)
        self.assertIn("node_modules/fs/extra.js", paths)

    def test_persistent_runtime_source_closure_accepts_complete_node_builtins(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "openclaw.mjs": (
                        "import 'node:async_hooks';\n"
                        "import 'node:readline';\n"
                        "import 'node:zlib';\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertNotIn("node:async_hooks", paths)
        self.assertNotIn("node:readline", paths)
        self.assertNotIn("node:zlib", paths)

    def test_persistent_runtime_source_closure_rejects_escaped_specifiers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        'require("./f\\\\u006fo.js");\n'
                    ),
                    "scripts/foo.js": "module.exports = { real: true };\n",
                    "scripts/fu006fo.js": "module.exports = { decoy: true };\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "JavaScript escape"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_decodes_esm_file_url_escapes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import './%68idden.mjs';\n"
                    ),
                    "scripts/hidden.mjs": "import './transitive.mjs';\n",
                    "scripts/transitive.mjs": "export const real = true;\n",
                    "scripts/%68idden.mjs": "export const decoy = true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/hidden.mjs", paths)
        self.assertIn("scripts/transitive.mjs", paths)
        self.assertNotIn("scripts/%68idden.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_esm_encoded_separators(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import './safe%2fhidden.mjs';\n"
                    ),
                    "scripts/safe/hidden.mjs": "export const real = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "encoded path separator"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_commonjs_callable_variants(
        self,
    ) -> None:
        variants = (
            "const name = './runner-impl.cjs';\nrequire?.resolve(name);\n",
            "const name = './runner-impl.cjs';\nrequire.resolve?.(name);\n",
            "const name = './runner-impl.cjs';\nrequire?.['resolve'](name);\n",
            "const name = './runner-impl.cjs';\nrequire['resolve']?.(name);\n",
            "const name = './runner-impl.cjs';\n(require.resolve)(name);\n",
        )
        for runner_source in variants:
            with self.subTest(runner_source=runner_source):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    files = {
                        "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                        "openclaw.mjs": "export const openclaw = true;\n",
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: runner_source,
                        "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                        "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                        "src/gateway/client.ts": "export const c = 1;\n",
                        "src/utils/message-channel.ts": "export const m = 1;\n",
                        "scripts/runner-impl.cjs": "module.exports = {};\n",
                    }
                    for relative, content in files.items():
                        path = root / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(content, encoding="utf-8")

                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "dynamic CommonJS require"
                    ):
                        MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_detects_template_import_expression(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "`${await import('./runner-impl.mjs')}`;\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
                "scripts/runner-impl.mjs": "export const dynamic = true;\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            paths = MODULE._persistent_runtime_source_paths(root)
            self.assertIn("scripts/runner-impl.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_unresolved_literal_dynamic_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "package.json": '{"name":"openclaw","version":"0.0.0-test"}\n',
                "openclaw.mjs": "export const openclaw = true;\n",
                MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                    "await import /* source closure */ ('./runner-impl.mjs');\n"
                ),
                "src/gateway/agentic-os-runtime-attestation.ts": "export const a = 1;\n",
                "src/gateway/agentic-os-runtime-contract-descriptors.ts": "export const d = [];\n",
                "src/gateway/client.ts": "export const c = 1;\n",
                "src/utils/message-channel.ts": "export const m = 1;\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(MODULE.ProbeError, "could not be resolved"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_worker_and_fork_entrypoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        'new Worker(new URL("./runner-worker.mjs", import.meta.url));\n'
                        'child_process.fork("./runner-child.cjs");\n'
                    ),
                    "scripts/runner-worker.mjs": "export const worker = true;\n",
                    "runner-child.cjs": "module.exports = { child: true };\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/runner-worker.mjs", paths)
        self.assertIn("runner-child.cjs", paths)

    def test_persistent_runtime_source_closure_binds_aliased_fork_entrypoints(
        self,
    ) -> None:
        cases = {
            "esm_renamed_fork": (
                "import { fork as launch } from 'node:child_process';\n"
                "launch('./hidden.cjs');\n"
            ),
            "cjs_destructured_fork": (
                "const { fork: launch } = require('child_process');\n"
                "launch('./hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("hidden.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_cluster_entrypoints(
        self,
    ) -> None:
        cases = {
            "esm_cluster": (
                "import cluster from 'node:cluster';\n"
                "cluster.setupPrimary({ exec: './hidden.cjs' });\n"
                "Reflect.apply(cluster.fork, cluster, []);\n"
            ),
            "cjs_cluster": (
                "const cluster = require('cluster');\n"
                "cluster.setupPrimary({ exec: './hidden.cjs' });\n"
                "cluster.fork();\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "cluster execution capability",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_qualified_worker_entrypoints(
        self,
    ) -> None:
        variants = (
            (
                "import * as wt from 'node:worker_threads';\n"
                "new wt.Worker(new URL('./runner-worker.mjs', import.meta.url));\n"
            ),
            (
                "import { Worker as ThreadWorker } from 'worker_threads';\n"
                "new ThreadWorker(new URL('./runner-worker.mjs', import.meta.url));\n"
            ),
            (
                "const wt = require('node:worker_threads');\n"
                "new wt['Worker'](new URL('./runner-worker.mjs', import.meta.url));\n"
            ),
            (
                "const { Worker: ThreadWorker } = require('worker_threads');\n"
                "new ThreadWorker(new URL('./runner-worker.mjs', import.meta.url));\n"
            ),
        )
        for source in variants:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/runner-worker.mjs": "export const worker = true;\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("scripts/runner-worker.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_dynamic_qualified_worker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import * as wt from 'node:worker_threads';\n"
                        "const workerUrl = new URL('./runner-worker.mjs', import.meta.url);\n"
                        "new wt.Worker(workerUrl);\n"
                    ),
                    "scripts/runner-worker.mjs": "export const worker = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "Worker entrypoint"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_worker_entrypoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const workerUrl = new URL('./runner-worker.mjs', import.meta.url);\n"
                        "new Worker(workerUrl);\n"
                    ),
                    "scripts/runner-worker.mjs": "export const worker = true;\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "Worker entrypoint"):
                MODULE._persistent_runtime_source_paths(root)

    def test_runtime_launch_bindings_resolve_node_and_tsx_preload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            node = bin_dir / "node"
            node.write_text("#!/bin/sh\n", encoding="utf-8")
            node.chmod(0o755)
            tsx_root = root / "node_modules" / "tsx"
            loader = tsx_root / "dist" / "loader.mjs"
            loader.parent.mkdir(parents=True)
            (tsx_root / "package.json").write_text('{"name":"tsx"}\n', encoding="utf-8")
            loader.write_text("export default null;\n", encoding="utf-8")

            class Proc:
                returncode = 0
                stdout = loader.resolve().as_uri() + "\n"
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240, **_kwargs):
                self.assertEqual(Path(command[0]), node.resolve())
                self.assertEqual(cwd, root)
                self.assertEqual(env["PATH"], str(bin_dir))
                return self._attach_valid_process_cleanup(Proc())

            with mock.patch.object(
                MODULE, "_runtime_launch_bindings", self._original_runtime_launch_bindings
            ), mock.patch.object(MODULE, "_run", side_effect=fake_run):
                resolved_node, tsx_import, bindings = MODULE._runtime_launch_bindings(
                    root,
                    {"PATH": str(bin_dir)},
                )

            self.assertEqual(resolved_node, node.resolve())
            self.assertEqual(tsx_import, loader.resolve().as_uri())
            by_path = {item["path"]: item for item in bindings}
            self.assertEqual(
                by_path["runtime-launcher:node"]["sha256"],
                MODULE._sha256_bytes(node.resolve().read_bytes()),
            )
            self.assertEqual(
                by_path["runtime-preload:tsx"]["sha256"],
                MODULE._sha256_bytes(loader.resolve().read_bytes()),
            )
            self.assertIn("runtime-preload-package:tsx", by_path)
            serialized = json.dumps(bindings, sort_keys=True)
            self.assertNotIn(str(root), serialized)

    def test_runtime_launch_revalidation_rejects_changed_source_digest(self) -> None:
        expected_sources = self._valid_runtime_launch_sources()
        changed_sources = [dict(item) for item in expected_sources]
        changed_sources[0]["sha256"] = "0" * 64

        with mock.patch.object(
            MODULE,
            "_runtime_launch_bindings",
            return_value=(
                Path("/bound/node"),
                "file:///bound/node_modules/tsx/dist/loader.mjs",
                changed_sources,
            ),
        ):
            with self.assertRaisesRegex(MODULE.ProbeError, "source binding changed"):
                MODULE._assert_runtime_launch_sources_still_bound(
                    openclaw_root=Path("/unused"),
                    runner_env={},
                    expected_node_executable=Path("/bound/node"),
                    expected_tsx_preload_specifier=(
                        "file:///bound/node_modules/tsx/dist/loader.mjs"
                    ),
                    expected_sources=expected_sources,
                )

    def test_runtime_launch_revalidation_rejects_changed_launcher_path(self) -> None:
        with mock.patch.object(
            MODULE,
            "_runtime_launch_bindings",
            return_value=(
                Path("/other/node"),
                "file:///bound/node_modules/tsx/dist/loader.mjs",
                self._valid_runtime_launch_sources(),
            ),
        ):
            with self.assertRaisesRegex(MODULE.ProbeError, "Node launcher binding changed"):
                MODULE._assert_runtime_launch_sources_still_bound(
                    openclaw_root=Path("/unused"),
                    runner_env={},
                    expected_node_executable=Path("/bound/node"),
                    expected_tsx_preload_specifier=(
                        "file:///bound/node_modules/tsx/dist/loader.mjs"
                    ),
                    expected_sources=self._valid_runtime_launch_sources(),
                )

    def test_runtime_source_revalidation_rejects_changed_post_run_closure(self) -> None:
        expected_sources = self._valid_runtime_sources()
        changed_sources = [dict(item) for item in expected_sources]
        changed_sources[0]["sha256"] = "0" * 64

        with mock.patch.object(
            MODULE,
            "_persistent_runtime_source_bindings",
            return_value=changed_sources,
        ):
            with self.assertRaisesRegex(MODULE.ProbeError, "runtime source closure changed"):
                MODULE._assert_runtime_sources_still_bound(
                    Path("/unused"),
                    expected_sources,
                )

    def test_runtime_evidence_json_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(
                '{"status":"fail","nested":{"status":"fail","status":"pass"}}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "duplicate JSON key: status"):
                MODULE._read_json_file(path, "persistent lifecycle receipt")

    def test_persistent_summary_rejects_validation_receipt_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            validation = {"status": "pass", "receipt_sha256": "a" * 64}
            with self.assertRaisesRegex(MODULE.ProbeError, "not bound"):
                self._call_persistent_summary(Path(directory), receipt, validation)

    def test_persistent_summary_rejects_validation_lifecycle_attestation_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._valid_persistent_receipt()
            run_root = root / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root,
                receipt,
            )
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation["lifecycle_attestation_sha256"] = "0" * 64
            validation["authentication"] = {
                "scheme": "hmac-sha256-env",
                "key_env": MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
                "signature": hmac.new(
                    VALIDATION_ANCHOR_HMAC_SECRET,
                    MODULE._canonical_json_bytes(
                        MODULE._authentication_payload(validation)
                    ),
                    hashlib.sha256,
                ).hexdigest(),
            }
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                VALIDATION_ANCHOR_HMAC_SECRET_HEX
            )
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "lifecycle attestation"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=root,
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type(
                            "Proc",
                            (),
                            {"stdout": "", "stderr": "", "returncode": 0},
                        )(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_runner_authored_lifecycle_attestation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._valid_persistent_receipt()
            run_root = root / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root,
                receipt,
            )
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation["lifecycle_attestation"]["record_authority"] = (
                "agentic-os-persistent-lifecycle-runner-receipt"
            )
            validation["lifecycle_attestation"]["record_transport"] = (
                "non_rpc_pinned_run_root_receipt"
            )
            validation["lifecycle_attestation_sha256"] = MODULE._canonical_sha256(
                validation["lifecycle_attestation"]
            )
            validation["authentication"] = {
                "scheme": "hmac-sha256-env",
                "key_env": MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
                "signature": hmac.new(
                    VALIDATION_ANCHOR_HMAC_SECRET,
                    MODULE._canonical_json_bytes(
                        MODULE._authentication_payload(validation)
                    ),
                    hashlib.sha256,
                ).hexdigest(),
            }
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                VALIDATION_ANCHOR_HMAC_SECRET_HEX
            )
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "lifecycle attestation"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=root,
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type(
                            "Proc",
                            (),
                            {"stdout": "", "stderr": "", "returncode": 0},
                        )(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_missing_signed_lifecycle_attestation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._valid_persistent_receipt()
            run_root = root / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root,
                receipt,
            )
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation.pop("lifecycle_attestation")
            validation["authentication"]["signature"] = hmac.new(
                VALIDATION_ANCHOR_HMAC_SECRET,
                MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
                hashlib.sha256,
            ).hexdigest()
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                VALIDATION_ANCHOR_HMAC_SECRET_HEX
            )
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "lifecycle attestation"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=root,
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type(
                            "Proc",
                            (),
                            {"stdout": "", "stderr": "", "returncode": 0},
                        )(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_fake_gateway_lifecycle_observation_rpc(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def add_lifecycle_observations(evidence: dict) -> None:
                lifecycle_observations_response = {
                    "schema_version": MODULE.PERSISTENT_LIFECYCLE_OBSERVATIONS_SCHEMA_VERSION,
                    "lifecycle_sha256": MODULE._canonical_sha256(
                        MODULE._lifecycle_observation_snapshot(receipt["lifecycle"])
                    ),
                    "observations": MODULE._lifecycle_observation_snapshot(
                        receipt["lifecycle"]
                    ),
                }
                evidence["rpc_evidence"]["lifecycle_observations"] = {
                    "method": "agenticOs.lifecycle.observations",
                    "request_params": {},
                    "response": lifecycle_observations_response,
                    "raw_response_sha256": MODULE._canonical_sha256(
                        lifecycle_observations_response
                    ),
                }

            with self.assertRaisesRegex(MODULE.ProbeError, "unsupported non-Gateway"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=add_lifecycle_observations,
                )

    def test_persistent_summary_requires_private_lifecycle_rpc_transcript(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root,
                self._valid_persistent_receipt(),
            )
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
            Path(receipt["lifecycle"]["gateway_rpc_transcript_file"]).unlink()
            original_git = MODULE._git
            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "Gateway RPC transcript",
            ):
                try:
                    MODULE._git = lambda git_root, *args: "agentic-head"
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=root,
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=self._attach_valid_process_cleanup(
                            type(
                                "Proc",
                                (),
                                {"stdout": "", "stderr": "", "returncode": 0},
                            )()
                        ),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
                finally:
                    MODULE._git = original_git

    def test_persistent_summary_rejects_lifecycle_values_not_bound_to_rpc_transcript(
        self,
    ) -> None:
        def fabricate_spawn(transcript: dict) -> None:
            response = transcript["records"]["first_spawn"]["response"]
            response["status"] = "rejected"
            transcript["records"]["first_spawn"]["raw_response_sha256"] = (
                MODULE._canonical_sha256(response)
            )

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "first spawn response|response-bound",
            ):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=fabricate_spawn,
                )

    def test_persistent_summary_rejects_runner_copied_lifecycle_transcript(
        self,
    ) -> None:
        def mark_as_copied(transcript: dict) -> None:
            transcript["source_transcript_sha256"] = "9" * 64

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(MODULE.ProbeError, "copied from runner"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=mark_as_copied,
                )

    def test_persistent_summary_rejects_unsuccessful_acquire_response_status(
        self,
    ) -> None:
        def reject_acquire(transcript: dict) -> None:
            response = transcript["records"]["acquire"]["response"]
            response["status"] = "rejected"
            transcript["records"]["acquire"]["raw_response_sha256"] = (
                MODULE._canonical_sha256(response)
            )

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(MODULE.ProbeError, "acquire response was not accepted"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=reject_acquire,
                )

    def test_persistent_summary_rejects_empty_lifecycle_request_payloads(
        self,
    ) -> None:
        def empty_request(transcript: dict) -> None:
            transcript["records"]["first_spawn"]["request_params"] = {}

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(MODULE.ProbeError, "request does not match method schema"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=empty_request,
                )

    def test_persistent_summary_rejects_empty_session_read_responses(
        self,
    ) -> None:
        def empty_session_reads(transcript: dict) -> None:
            for key in ("session_status", "sessions_history"):
                response = transcript["records"][key]["response"]
                response.clear()
                transcript["records"][key]["raw_response_sha256"] = (
                    MODULE._canonical_sha256(response)
                )

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(MODULE.ProbeError, "session_status"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=empty_session_reads,
                )

    def test_persistent_summary_rejects_lifecycle_transcript_without_parent_capture(
        self,
    ) -> None:
        def remove_parent_capture(transcript: dict) -> None:
            transcript.pop("capture_authority", None)

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "probe-parent capture",
            ):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=remove_parent_capture,
                )

    def test_persistent_summary_rejects_live_lease_after_release_transcript_status(
        self,
    ) -> None:
        def leave_release_live(transcript: dict) -> None:
            response = transcript["records"]["post_release_status"]["response"]
            response["leases"] = [{"gateway_lease_id": "gateway-lease:unit-test"}]
            transcript["records"]["post_release_status"]["raw_response_sha256"] = (
                MODULE._canonical_sha256(response)
            )

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "post-release status",
            ):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    lifecycle_transcript_transform=leave_release_live,
                )

    def test_persistent_summary_rejects_validation_without_lifecycle_rpc_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root,
                self._valid_persistent_receipt(),
            )
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation.pop("lifecycle_rpc_transcript_sha256")
            validation["authentication"]["signature"] = hmac.new(
                VALIDATION_ANCHOR_HMAC_SECRET,
                MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
                hashlib.sha256,
            ).hexdigest()
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "Gateway lifecycle RPC transcript",
                ):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=Path(directory),
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=self._attach_valid_process_cleanup(
                            type(
                                "Proc",
                                (),
                                {"stdout": "", "stderr": "", "returncode": 0},
                            )()
                        ),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git

    def test_persistent_summary_rejects_malformed_allow_lease_status_response(
        self,
    ) -> None:
        for response in (
            {"leases": []},
            {"status": "error", "leases": []},
            {"status": "ok", "leases": "none"},
            {"status": "ok", "leases": [{}]},
            {"status": "ok", "leases": [{"metadata": {}}]},
            {"status": "ok", "leases": [{"gateway_lease_id": "lease-1"}]},
        ):
            with self.subTest(response=response):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()

                    def replace_allow_lease_status(payload: dict) -> None:
                        record = payload["rpc_evidence"]["allow_lease_status"]
                        record["response"] = response
                        record["raw_response_sha256"] = MODULE._canonical_sha256(response)
                        payload["attestation"]["response"]["signed_payload"][
                            "rpc_transcript_sha256"
                        ] = MODULE._canonical_sha256(
                            {
                                "schema_version": MODULE.PERSISTENT_RPC_TRANSCRIPT_SCHEMA_VERSION,
                                "records": [
                                    {
                                        "key": key,
                                        "method": payload["rpc_evidence"][key]["method"],
                                        "request_params": dict(
                                            payload["rpc_evidence"][key]["request_params"]
                                        ),
                                        "raw_response_sha256": payload["rpc_evidence"][key][
                                            "raw_response_sha256"
                                        ],
                                    }
                                    for key, _method in MODULE.PERSISTENT_RPC_TRANSCRIPT_RECORDS
                                ],
                            }
                        )
                        signed_payload = payload["attestation"]["response"]["signed_payload"]
                        payload["attestation"]["response"]["signature"] = hmac.new(
                            ATTESTATION_HMAC_SECRET,
                            MODULE._canonical_json_bytes(signed_payload),
                            hashlib.sha256,
                        ).hexdigest()

                    with self.assertRaisesRegex(MODULE.ProbeError, "allowLease status"):
                        self._call_persistent_summary(
                            Path(directory),
                            receipt,
                            persistent_evidence_transform=replace_allow_lease_status,
                        )

    def test_persistent_summary_requires_status_non_empty_params_rejection(
        self,
    ) -> None:
        cases = {
            "missing": lambda evidence: evidence["rpc_evidence"].pop(
                "allow_lease_status_rejects_non_empty_params"
            ),
            "accepted": lambda evidence: evidence["rpc_evidence"][
                "allow_lease_status_rejects_non_empty_params"
            ].update(
                {
                    "response": {"status": "ok", "leases": []},
                    "raw_response_sha256": MODULE._canonical_sha256(
                        {"status": "ok", "leases": []}
                    ),
                }
            ),
        }
        for name, transform in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                receipt = self._valid_persistent_receipt()

                def mutate_status_negative_proof(payload: dict) -> None:
                    transform(payload)

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "allowLease status|allow_lease_status_rejects_non_empty_params|accepted non-empty parameters|negative",
                ):
                    self._call_persistent_summary(
                        Path(directory),
                        receipt,
                        persistent_evidence_transform=mutate_status_negative_proof,
                    )

    def test_persistent_summary_rejects_missing_required_tool_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            del receipt["preflight"]["required_tool_names"]
            del receipt["preflight"]["hello"]["required_methods"]
            with self.assertRaisesRegex(MODULE.ProbeError, "required tool names"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_malformed_required_tool_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["preflight"]["required_tool_names"] = ["sessions_spawn", 7]
            with self.assertRaisesRegex(MODULE.ProbeError, "non-empty strings"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_session_identity_digests(self) -> None:
        for key in ("session_key_sha256", "child_run_id_sha256"):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    del receipt["lifecycle"][key]
                    with self.assertRaisesRegex(MODULE.ProbeError, key):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_session_read_digests(self) -> None:
        for key in ("session_status_sha256", "sessions_history_sha256"):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    del receipt["lifecycle"][key]
                    with self.assertRaisesRegex(MODULE.ProbeError, key):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_lease_identity_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            del receipt["lifecycle"]["gateway_lease_id_sha256"]
            with self.assertRaisesRegex(MODULE.ProbeError, "gateway_lease_id_sha256"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_duplicate_acquire_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["duplicate_acquire_same_lease"] = False
            with self.assertRaisesRegex(MODULE.ProbeError, "duplicate acquire"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_duplicate_release_identity_digest(self) -> None:
        for value in (None, "not-a-sha"):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["lifecycle"]["duplicate_release_sha256"]
                    else:
                        receipt["lifecycle"]["duplicate_release_sha256"] = value
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "duplicate_release_sha256"
                    ):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_failed_primary_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["release_status"] = "rejected"
            with self.assertRaisesRegex(MODULE.ProbeError, "primary release status|release_status"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_arbitrary_duplicate_release_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["duplicate_release_sha256"] = "4" * 64
            with self.assertRaisesRegex(
                MODULE.ProbeError, "duplicate release response|duplicate_release_sha256"
            ):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_mismatched_duplicate_release_identity(self) -> None:
        for key, message in (
            ("duplicate_release_gateway_lease_id_sha256", "Gateway lease id|duplicate_release_gateway_lease_id_sha256"),
            ("duplicate_release_owner_metadata_sha256", "owner metadata|duplicate_release_owner_metadata_sha256"),
            ("duplicate_release_idempotency_key_sha256", "idempotency key|duplicate_release_idempotency_key_sha256"),
        ):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    receipt["lifecycle"][key] = "6" * 64
                    with self.assertRaisesRegex(MODULE.ProbeError, message):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_release_owner_echo_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            del receipt["lifecycle"]["release_client_lease_id_sha256"]
            with self.assertRaisesRegex(MODULE.ProbeError, "release_client_lease_id_sha256"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_release_owner_echo_not_request_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["release_agent_id_sha256"] = MODULE._text_sha256(
                "another-agent"
            )
            receipt["lifecycle"]["duplicate_release_agent_id_sha256"] = (
                receipt["lifecycle"]["release_agent_id_sha256"]
            )
            with self.assertRaisesRegex(
                MODULE.ProbeError, "release_agent_id_sha256"
            ):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_release_identity_not_acquired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["release_gateway_lease_id_sha256"] = "6" * 64
            receipt["lifecycle"]["duplicate_release_gateway_lease_id_sha256"] = "6" * 64
            with self.assertRaisesRegex(
                MODULE.ProbeError, "acquired lease|release_gateway_lease_id_sha256"
            ):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_non_integer_lifecycle_counts(self) -> None:
        for value in (None, 0, True, 1.0):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["lifecycle"]["matching_session_count"]
                    else:
                        receipt["lifecycle"]["matching_session_count"] = value
                    with self.assertRaisesRegex(
                        MODULE.ProbeError,
                        "matching accepted session|sessions list counts",
                    ):
                        self._call_persistent_summary(Path(directory), receipt)
        for value in (None, False, 0.0, 1):
            with self.subTest(post_release_lease_count=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["lifecycle"]["post_release_lease_count"]
                    else:
                        receipt["lifecycle"]["post_release_lease_count"] = value
                    with self.assertRaisesRegex(MODULE.ProbeError, "release cleanup"):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_inconsistent_session_list_count(self) -> None:
        for value in (None, 0, True, 1.0, 2):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["lifecycle"]["sessions_list_count"]
                    else:
                        receipt["lifecycle"]["sessions_list_count"] = value
                    with self.assertRaisesRegex(MODULE.ProbeError, "sessions list count"):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_pre_release_live_status(self) -> None:
        for key, value in (
            ("pre_release_status", "missing"),
            ("pre_release_lease_count", 0),
            ("pre_release_gateway_lease_id_sha256", "f" * 64),
        ):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                receipt = self._valid_persistent_receipt()
                if value == "missing":
                    del receipt["lifecycle"][key]
                else:
                    receipt["lifecycle"][key] = value
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "status did not expose|pre_release"
                ):
                    self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_changed_production_config_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["production_after"]["config_sha256"] = "1" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "production config hashes changed"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_production_config_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            del receipt["production_after"]["config_sha256"]
            with self.assertRaisesRegex(MODULE.ProbeError, "production_after.config_sha256"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_production_health_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["rollback"]["production_health_before_sha256"] = "f" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "health before digest mismatch"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_changed_production_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            after_health = {"reachable": True}
            receipt["production_after"]["health"] = after_health
            receipt["rollback"]["production_health_after_sha256"] = MODULE._canonical_sha256(
                after_health
            )
            with self.assertRaisesRegex(MODULE.ProbeError, "production health changed"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_non_loopback_gateway_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["gateway_endpoint"] = "ws://192.168.50.90:20189"
            with self.assertRaisesRegex(MODULE.ProbeError, "loopback listener"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_wrong_gateway_endpoint_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["gateway_endpoint"] = "ws://127.0.0.1:20190"
            with self.assertRaisesRegex(MODULE.ProbeError, "loopback listener"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_localhost_gateway_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["gateway_endpoint"] = "ws://localhost:20189"
            with self.assertRaisesRegex(MODULE.ProbeError, "loopback listener"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_gateway_endpoint_credentials_or_query(self) -> None:
        for endpoint in (
            "ws://secret@127.0.0.1:20189",
            "ws://127.0.0.1:20189/?token=raw-secret",
            "wss://127.0.0.1:20189",
        ):
            with self.subTest(endpoint=endpoint):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    receipt["attestation"]["gateway_endpoint"] = endpoint
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "canonical|credentials"
                    ):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_provider_secret_leak_count(self) -> None:
        for value in (None, False, 0.0, 1):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["candidate"]["env"]["unexpected_provider_key_count"]
                    else:
                        receipt["candidate"]["env"]["unexpected_provider_key_count"] = value
                    with self.assertRaisesRegex(MODULE.ProbeError, "provider secrets"):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_incomplete_attested_runtime_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def strip_sources(evidence):
                response = evidence["attestation"]["response"]
                signed_payload = response["signed_payload"]
                sources = [{"path": "openclaw.mjs", "sha256": "7" * 64}]
                signed_payload["binding"]["sources"] = sources
                signed_payload["binding"]["sources_sha256"] = MODULE._canonical_sha256(
                    sources
                )
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "runtime sources"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=strip_sources,
                )

    def test_persistent_summary_rejects_attestation_missing_transitive_runtime_source(
        self,
    ) -> None:
        transitive_path = "src/gateway/agentic-os-canonical-json.ts"
        runtime_sources = self._valid_runtime_sources(
            (*MODULE.PERSISTENT_RUNTIME_SOURCE_PATHS, transitive_path)
        )
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def strip_transitive_source(evidence):
                response = evidence["attestation"]["response"]
                signed_payload = response["signed_payload"]
                sources = [
                    source
                    for source in signed_payload["binding"]["sources"]
                    if source["path"] != transitive_path
                ]
                signed_payload["binding"]["sources"] = sources
                signed_payload["binding"]["sources_sha256"] = MODULE._canonical_sha256(
                    sources
                )
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "source-bound"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=strip_transitive_source,
                    runtime_sources=runtime_sources,
                )

    def test_persistent_summary_rejects_fabricated_install_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def fabricate_install_digests(evidence):
                response = evidence["attestation"]["response"]
                install = response["signed_payload"]["binding"]["install"]
                install["root_sha256"] = "5" * 64
                install["package_json_sha256"] = "4" * 64
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "candidate-bound"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=fabricate_install_digests,
                )

    def test_persistent_summary_rejects_fabricated_executable_path_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def fabricate_executable_path_digest(evidence):
                response = evidence["attestation"]["response"]
                executable = response["signed_payload"]["binding"]["executable"]
                executable["path_sha256"] = "6" * 64
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "executable path digest"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=fabricate_executable_path_digest,
                )

    def test_persistent_summary_rejects_gateway_build_id_not_bound_to_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["gateway_build_id"] = "deadbee"

            def stale_build_id(evidence):
                response = evidence["attestation"]["response"]
                response["signed_payload"]["binding"]["gateway"]["build_id"] = "deadbee"
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "runtime-head bound"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=stale_build_id,
                )

    def test_persistent_summary_rejects_gateway_build_id_short_head_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["gateway_build_id"] = VALID_RUNTIME_HEAD[:7]

            def short_build_id(evidence):
                response = evidence["attestation"]["response"]
                response["signed_payload"]["binding"]["gateway"]["build_id"] = (
                    VALID_RUNTIME_HEAD[:7]
                )
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "runtime-head bound"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=short_build_id,
                )

    def test_persistent_summary_rejects_requested_identity_mismatch(self) -> None:
        cases = (
            ("immutable_inputs", "run_id"),
            ("immutable_inputs", "transition_id"),
            ("lifecycle", "run_id"),
            ("lifecycle", "transition_id"),
        )
        for section, key in cases:
            with self.subTest(section=section, key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    receipt[section][key] = "stale-identity"
                    with self.assertRaisesRegex(MODULE.ProbeError, "requested lifecycle"):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_gateway_token_not_bound_to_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["runtime_launch"]["token_sha256"] = "0" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "Gateway token"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_stale_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            old_ms = int(time.time() * 1000) - 120_000
            receipt["attestation"]["captured_at_epoch_ms"] = old_ms
            receipt["attestation"]["expires_at_epoch_ms"] = old_ms + 1_000
            with self.assertRaisesRegex(MODULE.ProbeError, "fresh|capture time"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_overlong_attestation_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["attestation"]["expires_at_epoch_ms"] = (
                int(time.time() * 1000)
                + MODULE.PERSISTENT_ATTESTATION_MAX_LIFETIME_MS
                + 120_000
            )
            with self.assertRaisesRegex(MODULE.ProbeError, "lifetime"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_signed_attestation_contract_drift(self) -> None:
        cases = (
            ("missing_schema", lambda payload: payload.pop("schema_version")),
            ("offline", lambda payload: payload.__setitem__("online", False)),
            (
                "wrong_challenge",
                lambda payload: payload.__setitem__("challenge", "other-challenge"),
            ),
            (
                "wrong_client_process",
                lambda payload: payload.__setitem__(
                    "client_process_id", "other-process"
                ),
            ),
            (
                "missing_method_binding",
                lambda payload: payload["method_bindings"].pop("session_status"),
            ),
            (
                "missing_transport_binding",
                lambda payload: payload["binding"].pop("transport"),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()

                    def drift(payload: dict) -> None:
                        response = payload["attestation"]["response"]
                        signed_payload = response["signed_payload"]
                        mutate(signed_payload)
                        self._resign_attestation_response(response)

                    with self.assertRaisesRegex(
                        MODULE.ProbeError,
                        "signed payload|online|challenge|client process|method bindings|binding|transport",
                    ):
                        self._call_persistent_summary(
                            Path(directory),
                            receipt,
                            persistent_evidence_transform=drift,
                        )

    def test_persistent_summary_rejects_missing_wrong_owner_release_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"].pop("wrong_owner_release_status")
            with self.assertRaisesRegex(
                MODULE.ProbeError, "wrong_owner_release_status|wrong-owner"
            ):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_wrong_owner_release_using_owner_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["wrong_owner_release_owner_metadata_sha256"] = (
                receipt["lifecycle"]["release_owner_metadata_sha256"]
            )
            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "wrong-owner release|wrong_owner_release_owner_metadata_sha256",
            ):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_attestation_client_not_launched_runner_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def drift(evidence: dict) -> None:
                raw_attestation = evidence["attestation"]
                raw_attestation["request_params"]["client_process_id"] = (
                    "persistent-runner:9999:unit-test"
                )
                response = raw_attestation["response"]
                response["signed_payload"]["client_process_id"] = (
                    "persistent-runner:9999:unit-test"
                )
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "launched-runner"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=drift,
                )

    def test_persistent_summary_rejects_listener_process_outside_candidate_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()

            def drift(evidence: dict) -> None:
                response = evidence["attestation"]["response"]
                response["signed_payload"]["binding"]["gateway"][
                    "process_identity"
                ] = "9999:external-gateway"
                self._resign_attestation_response(response)

            with self.assertRaisesRegex(MODULE.ProbeError, "listener process"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=drift,
                )

    def test_persistent_summary_rejects_missing_preflight_artifact_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt = self._valid_persistent_receipt()
            receipt_file, validation_file = self._write_persistent_receipts(run_root, receipt)
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
            del receipt["preflight"]["evidence_file"]
            receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation["receipt_sha256"] = MODULE._sha256_bytes(receipt_file.read_bytes())
            validation["authentication"]["signature"] = hmac.new(
                VALIDATION_ANCHOR_HMAC_SECRET,
                MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
                hashlib.sha256,
            ).hexdigest()
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = VALIDATION_ANCHOR_HMAC_SECRET_HEX
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "capability preflight"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=Path(directory),
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_preflight_artifact_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt = self._valid_persistent_receipt()
            receipt_file, validation_file = self._write_persistent_receipts(run_root, receipt)
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
            receipt["preflight"]["evidence_sha256"] = "0" * 64
            receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            validation["receipt_sha256"] = MODULE._sha256_bytes(receipt_file.read_bytes())
            validation["authentication"]["signature"] = hmac.new(
                VALIDATION_ANCHOR_HMAC_SECRET,
                MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
                hashlib.sha256,
            ).hexdigest()
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = VALIDATION_ANCHOR_HMAC_SECRET_HEX
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "preflight evidence digest"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=Path(directory),
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_missing_attestation_identity_fields(self) -> None:
        required_keys = (
            "gateway_build_id",
            "executable_content_sha256",
            "catalog_sha256",
            "contract_vector_sha256",
            "rpc_transcript_sha256",
            "runtime_authored_rpc_evidence_sha256",
            "signed_payload_sha256",
            "runtime_identity_token_sha256",
        )
        for key in required_keys:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    del receipt["attestation"][key]
                    with self.assertRaisesRegex(MODULE.ProbeError, key):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_corrupt_attestation_bindings(self) -> None:
        cases = {
            "gateway_build_id": "unrelated-build",
            "executable_content_sha256": "0" * 64,
            "catalog_sha256": "0" * 64,
            "contract_vector_sha256": "0" * 64,
            "rpc_transcript_sha256": "0" * 64,
            "runtime_authored_rpc_evidence_sha256": "0" * 64,
            "signed_payload_sha256": "0" * 64,
            "runtime_identity_token_sha256": "0" * 64,
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    receipt["attestation"][key] = value
                    with self.assertRaises(MODULE.ProbeError):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_launch_executable_attestation_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["runtime_launch"]["executable_sha256"] = "6" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "runtime launch executable"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_missing_attestation_signature(self) -> None:
        def remove_signature(evidence):
            response = evidence["attestation"]["response"]
            del response["signature"]

        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            with self.assertRaisesRegex(MODULE.ProbeError, "signature"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    persistent_evidence_transform=remove_signature,
                )

    def test_persistent_summary_rejects_missing_attestation_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt = self._valid_persistent_receipt()
            receipt_file, validation_file = self._write_persistent_receipts(run_root, receipt)
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            del validation["attestation_verification"]
            validation["authentication"]["signature"] = hmac.new(
                VALIDATION_ANCHOR_HMAC_SECRET,
                MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
                hashlib.sha256,
            ).hexdigest()
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = VALIDATION_ANCHOR_HMAC_SECRET_HEX
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "attestation verification"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=Path(directory),
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_summary_rejects_catalog_without_required_runtime_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            with self.assertRaisesRegex(MODULE.ProbeError, "tools.catalog"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    tools_catalog_response={"tools": []},
                )

    def test_persistent_summary_accepts_runtime_methods_catalog_for_gateway_rpc_names(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            payload = self._call_persistent_summary(
                Path(directory),
                receipt,
                tools_catalog_response={
                    "groups": [],
                    "runtimeMethods": MODULE._expected_runtime_methods_catalog(),
                },
            )
            self.assertTrue(payload["runtime_catalog_discovered"])
            self.assertEqual(
                sorted(payload["required_tool_names"]),
                sorted(MODULE.PERSISTENT_REQUIRED_TOOL_NAMES),
            )
            self.assertEqual(
                payload["lifecycle_attestation"]["record_transport"],
                "validator_pinned_gateway_rpc_transcript_reverification",
            )
            self.assertEqual(
                payload["lifecycle_attestation"]["signed_by"],
                "independent_validation_hmac",
            )

    def test_persistent_summary_rejects_runtime_method_parameter_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            runtime_methods = MODULE._expected_runtime_methods_catalog()
            runtime_methods[0] = {
                "name": runtime_methods[0]["name"],
                "parameters": ["wrong_parameter"],
            }
            with self.assertRaisesRegex(MODULE.ProbeError, "runtimeMethods"):
                self._call_persistent_summary(
                    Path(directory),
                    receipt,
                    tools_catalog_response={
                        "groups": [
                            {
                                "id": "agentic-os-runtime",
                                "tools": [
                                    {"name": name}
                                    for name in MODULE.PERSISTENT_REQUIRED_TOOL_NAMES
                                ],
                            }
                        ],
                        "runtimeMethods": runtime_methods,
                    },
                )

    def test_persistent_summary_accepts_source_bound_preflight_catalog_without_legacy_hello(
        self,
    ) -> None:
        gateway_names = [
            name
            for name in MODULE.PERSISTENT_REQUIRED_TOOL_NAMES
            if name.startswith("subagents.")
        ]
        model_names = [
            name
            for name in MODULE.PERSISTENT_REQUIRED_TOOL_NAMES
            if name.startswith("sessions_") or name == "session_status"
        ]

        def use_source_bound_catalog(preflight_evidence: dict) -> None:
            preflight_evidence.pop("required_tool_names")
            preflight_evidence.pop("hello")
            preflight_evidence["catalog"] = {
                "model_tool_catalog": {"required_tool_names": model_names},
                "gateway_rpc_catalog": {"source_bound_rpc_names": gateway_names},
                "attestation_rpc_catalog": {"method": "agenticOs.runtime.attest"},
            }

        with tempfile.TemporaryDirectory() as directory:
            payload = self._call_persistent_summary(
                Path(directory),
                self._valid_persistent_receipt(),
                preflight_evidence_transform=use_source_bound_catalog,
            )

        self.assertEqual(
            sorted(payload["required_tool_names"]),
            sorted(MODULE.PERSISTENT_REQUIRED_TOOL_NAMES),
        )

    def test_persistent_summary_rejects_unauthenticated_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt = self._valid_persistent_receipt()
            receipt_file, validation_file = self._write_persistent_receipts(run_root, receipt)
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            del validation["authentication"]
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git
            previous_secret = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = VALIDATION_ANCHOR_HMAC_SECRET_HEX
            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                with self.assertRaisesRegex(MODULE.ProbeError, "authentication"):
                    MODULE._persistent_lifecycle_summary(
                        openclaw_root=Path(directory),
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=self._valid_runtime_sources(),
                        runtime_launch_sources=self._valid_runtime_launch_sources(),
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                    )
            finally:
                MODULE._git = original_git
                if previous_secret is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_secret

    def test_persistent_lifecycle_summary_is_phase_b_snapshot_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = self._call_persistent_summary(
                Path(directory),
                self._valid_persistent_receipt(),
            )

        self.assertEqual(payload["status"], "pass")
        self.assertFalse(payload["runtime_ready"])
        self.assertTrue(payload["runtime_ready_candidate_evidence"])
        self.assertTrue(payload["runtime_ready_blocked_until_phase_c"])
        self.assertTrue(payload["duplicate_release_identity_parity"])
        self.assertEqual(payload["lifecycle"]["release_status"], "released")
        self.assertEqual(
            payload["lifecycle"]["primary_release_sha256"],
            payload["lifecycle"]["duplicate_release_sha256"],
        )
        self.assertEqual(
            payload["lifecycle"]["release_gateway_lease_id_sha256"],
            payload["lifecycle"]["duplicate_release_gateway_lease_id_sha256"],
        )
        self.assertEqual(
            [item["path"] for item in payload["runtime_launch_sources"]],
            list(MODULE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS),
        )
        self.assertFalse(payload["db_authority_enabled"])
        self.assertNotIn("/private", json.dumps(payload, sort_keys=True))
        self.assertNotIn("runner stdout", json.dumps(payload, sort_keys=True))

    def test_persistent_runner_invocation_uses_isolated_runner_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            output = root / "evidence.json"
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_runtime_launch_bindings = MODULE._runtime_launch_bindings
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )
            captured_command = {}
            captured_env = {}
            captured_validator = {}
            captured_modes = {}
            previous_openai_key = os.environ.get("OPENAI_API_KEY")
            previous_node_options = os.environ.get("NODE_OPTIONS")
            previous_validation_key = os.environ.get(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV)
            previous_attestation_key = os.environ.get(
                MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV
            )
            os.environ["OPENAI_API_KEY"] = "sk-test-provider-secret"
            os.environ["NODE_OPTIONS"] = "--require=/tmp/hook.cjs"
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = VALIDATION_ANCHOR_HMAC_SECRET_HEX
            os.environ[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV] = (
                ATTESTATION_HMAC_SECRET_HEX
            )

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(
                command,
                *,
                cwd,
                env=None,
                timeout=240,
                start_new_session=False,
                pass_fds=(),
            ):
                self.assertIsNotNone(env)
                self.assertIs(start_new_session, True)
                captured_command["command"] = list(command)
                captured_env.update(env)
                captured_env["candidate_pass_fds"] = pass_fds
                return self._attach_valid_process_cleanup(Proc())

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._persistent_lifecycle_summary = lambda **kwargs: {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "agentic_os_head_sha": "agentic-head",
                    "runtime_ready": False,
                    "runtime_ready_candidate_evidence": True,
                    "isolated_non_production_gateway": {},
                }
                MODULE._run_independent_validator = lambda **kwargs: captured_validator.update(
                    kwargs
                )
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                MODULE._runtime_launch_bindings = lambda _root, _env: (
                    Path("/bound/node"),
                    "file:///bound/node_modules/tsx/dist/loader.mjs",
                    self._valid_runtime_launch_sources(),
                )
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                payload = MODULE._run_persistent_lifecycle_probe(
                    root,
                    output,
                    timeout=1,
                    head=VALID_RUNTIME_HEAD,
                    agentic_sources=[],
                    runtime_sources=[],
                    run_root=run_root,
                    port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                    run_id="run-id",
                    transition_id="transition-id",
                )
                for directory_path in (
                    run_root,
                    run_root / "runner-home",
                    run_root / "runner-state",
                    run_root / "runner-tmp",
                ):
                    captured_modes[directory_path.name] = directory_path.stat().st_mode & 0o777
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._runtime_launch_bindings = original_runtime_launch_bindings
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )
                if previous_openai_key is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = previous_openai_key
                if previous_node_options is None:
                    os.environ.pop("NODE_OPTIONS", None)
                else:
                    os.environ["NODE_OPTIONS"] = previous_node_options
                if previous_validation_key is None:
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                else:
                    os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = previous_validation_key
                if previous_attestation_key is None:
                    os.environ.pop(
                        MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, None
                    )
                else:
                    os.environ[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV] = (
                        previous_attestation_key
                    )

        self.assertEqual(payload["status"], "pass")
        command = captured_command["command"]
        self.assertEqual(command[0], "/bound/node")
        self.assertEqual(
            command[1:3],
            ["--import", "file:///bound/node_modules/tsx/dist/loader.mjs"],
        )
        self.assertNotEqual(command[2], "tsx")
        self.assertNotIn("OPENAI_API_KEY", captured_env)
        self.assertNotIn("NODE_OPTIONS", captured_env)
        self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, captured_env)
        self.assertEqual(
            captured_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
            ATTESTATION_HMAC_SECRET_HEX,
        )
        self.assertEqual(captured_env["candidate_pass_fds"], ())
        self.assertEqual(
            captured_validator["pinned_run_root"].original_path,
            run_root.resolve(),
        )
        self.assertEqual(captured_env["OPENCLAW_HOME"], str((run_root / "runner-home").resolve()))
        self.assertEqual(
            captured_env["OPENCLAW_STATE_DIR"],
            str((run_root / "runner-state").resolve()),
        )
        self.assertNotEqual(
            captured_env["OPENCLAW_STATE_DIR"],
            "/Users/zuqiangyu/.openclaw/state",
        )
        self.assertEqual(captured_modes["run"], 0o700)
        self.assertEqual(captured_modes["runner-home"], 0o700)
        self.assertEqual(captured_modes["runner-state"], 0o700)
        self.assertEqual(captured_modes["runner-tmp"], 0o700)

    def test_documented_cli_clean_environment_generates_anchor_and_launches_validator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            evidence_file = root / "evidence.json"
            captured: dict[str, object] = {}

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["runner_command"] = list(command)
                captured["runner_env"] = dict(env or {})
                key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(key_path.parent, 0o700)
                key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                os.chmod(key_path, 0o600)
                return self._attach_valid_process_cleanup(Proc())

            def fake_validator(**kwargs):
                captured["validator_calls"] = int(captured.get("validator_calls", 0)) + 1
                captured["validation_anchor_key"] = kwargs["validation_anchor_key"]
                captured["attestation_verification_key"] = kwargs[
                    "attestation_verification_key"
                ]
                captured["validator_env"] = MODULE._validator_env(
                    run_root=kwargs["pinned_run_root"],
                    validation_anchor_key=kwargs["validation_anchor_key"],
                    attestation_verification_key=kwargs["attestation_verification_key"],
                )

            def fake_summary(**kwargs):
                captured["summary_validation_anchor_key"] = kwargs[
                    "validation_anchor_key"
                ]
                return {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "agentic_os_head_sha": "agentic-head",
                    "runtime_ready": False,
                    "runtime_ready_candidate_evidence": True,
                    "isolated_non_production_gateway": {},
                }

            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PROCESS_CONTAINMENT_BOUNDARY_ENV: (
                        MODULE.LAUNCHER_BOUNDARY_OS_TYPE
                    )
                },
                clear=True,
            ), mock.patch.object(
                MODULE.secrets,
                "token_bytes",
                side_effect=[VALIDATION_ANCHOR_HMAC_SECRET, ATTESTATION_HMAC_SECRET],
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE, "_candidate_probe_mode", return_value="persistent_lifecycle"
            ), mock.patch.object(
                MODULE, "_source_bindings", return_value=[]
            ), mock.patch.object(
                MODULE, "_persistent_runtime_source_bindings", return_value=[]
            ), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "_run", side_effect=fake_run
            ), mock.patch.object(
                MODULE,
                "_runtime_launch_bindings",
                return_value=(
                    Path("/bound/node"),
                    "file:///bound/node_modules/tsx/dist/loader.mjs",
                    self._valid_runtime_launch_sources(),
                ),
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=fake_validator
            ), mock.patch.object(
                MODULE,
                "_bind_probe_parent_lifecycle_gateway_rpc_transcript",
                return_value=None,
            ), mock.patch.object(
                MODULE, "_persistent_lifecycle_summary", side_effect=fake_summary
            ), mock.patch.object(
                MODULE, "_terminate_and_verify_process_group", return_value=(True, True)
            ), mock.patch("builtins.print"):
                exit_code = MODULE.main(
                    [
                        "--openclaw-root",
                        str(root),
                        "--evidence-file",
                        str(evidence_file),
                        "--run-root",
                        str(run_root),
                    ]
                )

                self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, os.environ)
                self.assertNotIn(
                    MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, os.environ
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["validator_calls"], 1)
            self.assertEqual(
                captured["validation_anchor_key"], VALIDATION_ANCHOR_HMAC_SECRET
            )
            self.assertEqual(
                captured["summary_validation_anchor_key"],
                VALIDATION_ANCHOR_HMAC_SECRET,
            )
            self.assertEqual(
                captured["attestation_verification_key"], ATTESTATION_HMAC_SECRET
            )
            runner_env = captured["runner_env"]
            self.assertIsInstance(runner_env, dict)
            self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, runner_env)
            self.assertEqual(
                runner_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
                ATTESTATION_HMAC_SECRET_HEX,
            )
            runner_command = captured["runner_command"]
            self.assertIsInstance(runner_command, list)
            self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, "\0".join(runner_command))
            validator_env = captured["validator_env"]
            self.assertIsInstance(validator_env, dict)
            self.assertEqual(
                validator_env[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV],
                VALIDATION_ANCHOR_HMAC_SECRET_HEX,
            )
            self.assertEqual(
                validator_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
                ATTESTATION_HMAC_SECRET_HEX,
            )
            self.assertFalse(
                (run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).exists()
            )
            evidence_serialized = evidence_file.read_text(encoding="utf-8")
            self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, evidence_serialized)
            self.assertNotIn(ATTESTATION_HMAC_SECRET_HEX, evidence_serialized)
            for path in run_root.rglob("*"):
                if path.is_file():
                    serialized = path.read_text(encoding="utf-8")
                    self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, serialized)
                    self.assertNotIn(ATTESTATION_HMAC_SECRET_HEX, serialized)

    def test_default_persistent_runner_state_is_private_unique_and_outside_evidence_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "docs" / "runtime-evidence" / "probe.json"
            captured = {"run_roots": []}
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_persistent_runtime_source_bindings = (
                MODULE._persistent_runtime_source_bindings
            )
            original_run_persistent = MODULE._run_persistent_lifecycle_probe

            def fake_run_persistent(*args, **kwargs):
                captured["run_roots"].append(kwargs["run_root"])
                return {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "agentic_os_head_sha": "agentic-head",
                    "runtime_ready": False,
                    "runtime_ready_candidate_evidence": True,
                }

            try:
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._candidate_probe_mode = lambda candidate_root: "persistent_lifecycle_runner"
                MODULE._persistent_runtime_source_bindings = lambda *args, **kwargs: []
                MODULE._run_persistent_lifecycle_probe = fake_run_persistent
                with mock.patch.dict(
                    os.environ,
                    {
                        MODULE.PROCESS_CONTAINMENT_BOUNDARY_ENV: "external-container",
                    },
                    clear=False,
                ):
                    MODULE.run_probe(root, evidence_file, timeout=1)
                    MODULE.run_probe(root, evidence_file, timeout=1)
            finally:
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._persistent_runtime_source_bindings = (
                    original_persistent_runtime_source_bindings
                )
                MODULE._run_persistent_lifecycle_probe = original_run_persistent

        self.assertEqual(len(captured["run_roots"]), 2)
        self.assertNotEqual(captured["run_roots"][0], captured["run_roots"][1])
        for run_root in captured["run_roots"]:
            run_root = run_root.resolve()
            self.assertNotIn("runtime-evidence", run_root.parts)
            self.assertFalse(str(run_root).startswith(str(root.resolve())))
            self.assertEqual(run_root.stat().st_mode & 0o777, 0o700)

    def test_persistent_runner_requires_process_containment_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "evidence.json"
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_persistent_runtime_source_bindings = (
                MODULE._persistent_runtime_source_bindings
            )
            original_run_persistent = MODULE._run_persistent_lifecycle_probe
            launched = False

            def fake_run_persistent(*_args, **_kwargs):
                nonlocal launched
                launched = True
                return {"status": "pass"}

            try:
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._candidate_probe_mode = lambda candidate_root: "persistent_lifecycle_runner"
                MODULE._persistent_runtime_source_bindings = lambda *args, **kwargs: []
                MODULE._run_persistent_lifecycle_probe = fake_run_persistent
                with mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(MODULE.ProbeError, "containment boundary"):
                        MODULE.run_probe(root, evidence_file, timeout=1)
            finally:
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._persistent_runtime_source_bindings = (
                    original_persistent_runtime_source_bindings
                )
                MODULE._run_persistent_lifecycle_probe = original_run_persistent

            self.assertFalse(launched)
            self.assertTrue(evidence_file.is_file())
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "fail_closed")
            self.assertEqual(
                evidence["classification"],
                "persistent_lifecycle_prelaunch_blocked",
            )
            self.assertEqual(
                evidence["reason"], "process_containment_boundary_required"
            )
            self.assertEqual(evidence["openclaw_head_sha"], VALID_RUNTIME_HEAD)
            self.assertFalse(evidence["runtime_ready_candidate_evidence"])
            self.assertFalse(evidence["production_authority_enabled"])
            self.assertFalse(
                evidence["isolated_non_production_gateway"][
                    "production_gateway_restart_attempted"
                ]
            )
            self.assertFalse(
                evidence["isolated_non_production_gateway"][
                    "production_session_mutation_attempted"
                ]
            )
            self.assertFalse(
                evidence["isolated_non_production_gateway"][
                    "production_lease_mutation_attempted"
                ]
            )
            self.assertFalse(
                evidence["isolated_non_production_gateway"]["candidate_process_started"]
            )

    def test_persistent_runner_writes_fail_closed_evidence_on_source_closure_rejection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "evidence.json"
            auto_run_root = root / "auto-run-root"
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_persistent_runtime_source_bindings = (
                MODULE._persistent_runtime_source_bindings
            )
            original_run_persistent = MODULE._run_persistent_lifecycle_probe
            original_default_private_run_root = MODULE._default_private_run_root
            launched = False
            private_error = "runtime source import escapes to /home/alice/private-secret.mjs"

            def fake_source_bindings(*_args, **_kwargs):
                raise MODULE.ProbeError(private_error)

            def fake_default_private_run_root(_head):
                auto_run_root.mkdir(mode=0o700)
                return auto_run_root

            def fake_run_persistent(*_args, **_kwargs):
                nonlocal launched
                launched = True
                return {"status": "pass"}

            try:
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._candidate_probe_mode = lambda candidate_root: "persistent_lifecycle_runner"
                MODULE._persistent_runtime_source_bindings = fake_source_bindings
                MODULE._default_private_run_root = fake_default_private_run_root
                MODULE._run_persistent_lifecycle_probe = fake_run_persistent
                with self.assertRaisesRegex(MODULE.ProbeError, "private-secret"):
                    MODULE.run_probe(root, evidence_file, timeout=1)
            finally:
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._persistent_runtime_source_bindings = (
                    original_persistent_runtime_source_bindings
                )
                MODULE._default_private_run_root = original_default_private_run_root
                MODULE._run_persistent_lifecycle_probe = original_run_persistent

            self.assertFalse(launched)
            self.assertFalse(auto_run_root.exists())
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "fail_closed")
            self.assertEqual(evidence["reason"], "runtime_source_closure_failed")
            self.assertEqual(evidence["error"], "prelaunch validation failed")
            self.assertEqual(evidence["error_class"], "ProbeError")
            self.assertEqual(
                evidence["error_message_sha256"],
                MODULE._text_sha256(private_error),
            )
            self.assertNotIn("private-secret", evidence_file.read_text(encoding="utf-8"))
            self.assertNotIn("/home/alice", evidence_file.read_text(encoding="utf-8"))
            self.assertFalse(evidence["runtime_ready_candidate_evidence"])
            self.assertFalse(
                evidence["isolated_non_production_gateway"]["candidate_process_started"]
            )

    def test_persistent_runner_revalidates_agentic_sources_before_source_closure_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "evidence.json"
            auto_run_root = root / "auto-run-root"
            launched = False

            def fake_run_persistent(*_args, **_kwargs):
                nonlocal launched
                launched = True
                return {"status": "pass"}

            def fake_default_private_run_root(_head):
                auto_run_root.mkdir(mode=0o700)
                return auto_run_root

            with mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE,
                "_candidate_probe_mode",
                return_value="persistent_lifecycle_runner",
            ), mock.patch.object(
                MODULE,
                "_persistent_runtime_source_bindings",
                side_effect=MODULE.ProbeError("runtime source blocked"),
            ), mock.patch.object(
                MODULE,
                "_default_private_run_root",
                side_effect=fake_default_private_run_root,
            ), mock.patch.object(
                MODULE, "_run_persistent_lifecycle_probe", side_effect=fake_run_persistent
            ), mock.patch.object(
                MODULE,
                "_assert_agentic_sources_still_bound",
                side_effect=MODULE.ProbeError("source binding changed"),
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "source binding changed"):
                    MODULE.run_probe(root, evidence_file, timeout=1)

            self.assertFalse(launched)
            self.assertFalse(auto_run_root.exists())
            self.assertFalse(evidence_file.exists())

    def test_persistent_runner_revalidates_agentic_sources_before_boundary_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "evidence.json"
            auto_run_root = root / "auto-run-root"
            launched = False

            def fake_run_persistent(*_args, **_kwargs):
                nonlocal launched
                launched = True
                return {"status": "pass"}

            def fake_default_private_run_root(_head):
                auto_run_root.mkdir(mode=0o700)
                return auto_run_root

            with mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE,
                "_candidate_probe_mode",
                return_value="persistent_lifecycle_runner",
            ), mock.patch.object(
                MODULE, "_persistent_runtime_source_bindings", return_value=[]
            ), mock.patch.object(
                MODULE,
                "_default_private_run_root",
                side_effect=fake_default_private_run_root,
            ), mock.patch.object(
                MODULE, "_run_persistent_lifecycle_probe", side_effect=fake_run_persistent
            ), mock.patch.object(
                MODULE,
                "_require_process_containment_boundary_request",
                side_effect=MODULE.ProbeError("containment boundary required"),
            ), mock.patch.object(
                MODULE,
                "_assert_agentic_sources_still_bound",
                side_effect=MODULE.ProbeError("source binding changed"),
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "source binding changed"):
                    MODULE.run_probe(root, evidence_file, timeout=1)

            self.assertFalse(launched)
            self.assertFalse(auto_run_root.exists())
            self.assertFalse(evidence_file.exists())

    def test_persistent_runner_preserves_explicit_run_root_on_prelaunch_rejection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            explicit_run_root = root / "explicit-run-root"
            explicit_run_root.mkdir(mode=0o700)
            evidence_file = root / "evidence.json"
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_persistent_runtime_source_bindings = (
                MODULE._persistent_runtime_source_bindings
            )
            try:
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._candidate_probe_mode = lambda candidate_root: "persistent_lifecycle_runner"
                MODULE._persistent_runtime_source_bindings = lambda *_args, **_kwargs: (
                    (_ for _ in ()).throw(MODULE.ProbeError("runtime source blocked"))
                )
                with self.assertRaisesRegex(MODULE.ProbeError, "runtime source blocked"):
                    MODULE.run_probe(
                        root,
                        evidence_file,
                        timeout=1,
                        run_root=explicit_run_root,
                    )
            finally:
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._persistent_runtime_source_bindings = (
                    original_persistent_runtime_source_bindings
                )

            self.assertTrue(explicit_run_root.is_dir())

    def test_persistent_runner_accepts_boundary_env_only_as_launch_request(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                MODULE.PROCESS_CONTAINMENT_BOUNDARY_ENV: (
                    MODULE.LAUNCHER_BOUNDARY_OS_TYPE
                )
            },
            clear=True,
        ):
            self.assertEqual(
                MODULE._require_process_containment_boundary_request(),
                MODULE.LAUNCHER_BOUNDARY_OS_TYPE,
            )

    def test_process_containment_receipt_rejects_caller_only_boundary_without_cleanup(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "cleanup receipt"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=None,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_process_containment_receipt_rejects_unavailable_cleanup_tracking(self) -> None:
        cleanup = {
            "tracking_status": "unavailable",
            "tracking_error": "process table scan is unavailable",
            "root_pid": 1234,
            "root_identity": None,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": False,
            "descendant_identities": [],
            "unattributed_process_identities": [],
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "cleanup tracking"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=False,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_process_containment_receipt_rejects_marker_cleared_unattributed_descendant(self) -> None:
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": {"pid": 1234, "uid": os.getuid(), "start_id": "root"},
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [
                {"pid": 4321, "uid": os.getuid(), "start_id": "escaped"}
            ],
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "marker-cleared detached"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_process_containment_receipt_rejects_unverified_cleanup_marker(self) -> None:
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": {"pid": 1234, "uid": os.getuid(), "start_id": "root"},
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": False,
            "descendant_identities": [],
            "unattributed_process_identities": [],
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "marker"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_process_containment_receipt_rejects_env_only_external_boundary(self) -> None:
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": {"pid": 1234, "uid": os.getuid(), "start_id": "root"},
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [],
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "launcher-owned boundary"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_process_containment_receipt_rejects_posix_only_boundary_for_external_container(
        self,
    ) -> None:
        root_identity = {"pid": 1234, "uid": os.getuid(), "start_id": "root"}
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": root_identity,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [],
            "launcher_owned_boundary": self._launcher_boundary(
                root_identity=root_identity,
                os_boundary_type=MODULE.LAUNCHER_BOUNDARY_OS_TYPE,
            ),
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "requested OS boundary"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def _assert_launcher_owned_boundary_cleanup_receipt(
        self,
        proc,
        *,
        attempted: bool,
        reaped: bool,
        cleanup: dict | None,
    ) -> None:
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(reaped)
        self.assertFalse(attempted)
        self.assertIsNotNone(cleanup)
        assert cleanup is not None
        self.assertEqual(cleanup["tracking_status"], "available")
        boundary = cleanup["launcher_owned_boundary"]
        self.assertEqual(boundary["schema_version"], MODULE.LAUNCHER_BOUNDARY_SCHEMA_VERSION)
        self.assertEqual(boundary["authority"], MODULE.LAUNCHER_BOUNDARY_AUTHORITY)
        self.assertEqual(boundary["boundary_type"], MODULE.LAUNCHER_BOUNDARY_OS_TYPE)
        self.assertEqual(
            boundary["os_boundary_type"], MODULE.LAUNCHER_BOUNDARY_OS_TYPE
        )
        self.assertEqual(boundary["teardown_status"], "confirmed")
        self.assertEqual(boundary["root_pid"], cleanup["root_pid"])
        self.assertEqual(boundary["root_identity"], cleanup["root_identity"])
        self.assertEqual(
            boundary["cleanup_marker_sha256"],
            cleanup["cleanup_marker_sha256"],
        )
        self.assertRegex(boundary["boundary_id_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(boundary["command_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(
            MODULE.INTERNAL_PROCESS_CONTAINMENT_BOUNDARY_ENV,
            proc.stdout + proc.stderr,
        )

    def _run_launcher_owned_boundary_cleanup_probe_once(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {
                MODULE.INTERNAL_PROCESS_CONTAINMENT_BOUNDARY_ENV: (
                    MODULE.LAUNCHER_BOUNDARY_OS_TYPE
                ),
            }
            proc = MODULE._run(
                [
                    sys.executable,
                    "-c",
                    "import os, time; "
                    f"print(os.environ.get({MODULE.INTERNAL_PROCESS_CONTAINMENT_BOUNDARY_ENV!r}, ''), end=''); "
                    "time.sleep(0.25)",
                ],
                cwd=Path(directory),
                env=env,
                timeout=5,
                start_new_session=True,
            )
            attempted, reaped = MODULE._terminate_and_verify_process_group(proc)
            cleanup = MODULE._tracked_cleanup_from_process(proc)
        return proc, attempted, reaped, cleanup

    def test_real_run_emits_launcher_owned_boundary_cleanup_receipt(self) -> None:
        ambient_failures: list[dict] = []
        for _attempt in range(5):
            proc, attempted, reaped, cleanup = (
                self._run_launcher_owned_boundary_cleanup_probe_once()
            )
            if cleanup is not None and self._is_environmental_cleanup_tracking_unavailable(
                cleanup
            ):
                tracking_error = str(cleanup.get("tracking_error") or "")
                if "unattributed same-UID process appeared" in tracking_error:
                    ambient_failures.append(cleanup)
                    continue
                self.skipTest(
                    "launcher-owned cleanup receipt requires host process-table and "
                    "marker inspection capability; observed "
                    f"{cleanup.get('tracking_error')}"
                )

            self._assert_launcher_owned_boundary_cleanup_receipt(
                proc,
                attempted=attempted,
                reaped=reaped,
                cleanup=cleanup,
            )
            return

        self.skipTest(
            "ambient same-UID process activity prevented a positive cleanup receipt "
            f"in {len(ambient_failures)} attempts"
        )

    def test_process_containment_receipt_binds_launcher_cleanup_evidence(self) -> None:
        root_identity = {"pid": 1234, "uid": os.getuid(), "start_id": "root"}
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": root_identity,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [
                {"pid": 2345, "uid": os.getuid(), "start_id": "child"}
            ],
            "unattributed_process_identities": [],
            "launcher_owned_boundary": self._launcher_boundary(
                root_identity=root_identity,
            ),
        }
        receipt = MODULE._process_containment_boundary_receipt(
            requested_boundary="external-container",
            cleanup=cleanup,
            process_group_cleanup_attempted=True,
            process_group_reaped=True,
            port_closed=True,
        )

        self.assertEqual(
            receipt["schema_version"],
            "agentic-os.process-containment-boundary-receipt.v1",
        )
        self.assertEqual(receipt["receipt_authority"], "agentic-os-probe-launcher")
        self.assertEqual(receipt["requested_boundary"], "external-container")
        self.assertEqual(receipt["root_pid"], 1234)
        self.assertEqual(receipt["descendant_identity_count"], 1)
        self.assertEqual(
            receipt["launcher_owned_boundary"]["boundary_id_sha256"],
            cleanup["launcher_owned_boundary"]["boundary_id_sha256"],
        )
        self.assertEqual(receipt["cleanup_receipt_sha256"], MODULE._canonical_sha256(cleanup))

    def test_process_containment_receipt_accepts_realizable_posix_boundary(
        self,
    ) -> None:
        root_identity = {"pid": 1234, "uid": os.getuid(), "start_id": "root"}
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": root_identity,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [],
            "launcher_owned_boundary": self._launcher_boundary(
                root_identity=root_identity,
                boundary_type=MODULE.LAUNCHER_BOUNDARY_OS_TYPE,
            ),
        }
        receipt = MODULE._process_containment_boundary_receipt(
            requested_boundary=MODULE.LAUNCHER_BOUNDARY_OS_TYPE,
            cleanup=cleanup,
            process_group_cleanup_attempted=True,
            process_group_reaped=True,
            port_closed=True,
        )

        self.assertEqual(receipt["requested_boundary"], MODULE.LAUNCHER_BOUNDARY_OS_TYPE)
        self.assertEqual(receipt["proven_os_boundary"], MODULE.LAUNCHER_BOUNDARY_OS_TYPE)

    def test_process_containment_receipt_rejects_replayed_launcher_boundary(self) -> None:
        root_identity = {"pid": 1234, "uid": os.getuid(), "start_id": "root"}
        cleanup = {
            "tracking_status": "available",
            "root_pid": 1234,
            "root_identity": root_identity,
            "cleanup_marker_sha256": "a" * 64,
            "cleanup_marker_verified": True,
            "descendant_identities": [],
            "unattributed_process_identities": [],
            "launcher_owned_boundary": self._launcher_boundary(
                root_identity=root_identity,
                cleanup_marker_sha256="f" * 64,
            ),
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "marker"):
            MODULE._process_containment_boundary_receipt(
                requested_boundary="external-container",
                cleanup=cleanup,
                process_group_cleanup_attempted=True,
                process_group_reaped=True,
                port_closed=True,
            )

    def test_independent_validator_writes_fresh_authenticated_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            receipt = self._valid_persistent_receipt()
            receipt_file, validation_file = self._write_persistent_receipts(run_root, receipt)
            validation_file.unlink()
            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV: (
                        ATTESTATION_HMAC_SECRET_HEX
                    ),
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    ),
                },
            ):
                MODULE._write_independent_validation_file(
                    run_root=run_root,
                    receipt_file=receipt_file,
                    validation_file=validation_file,
                )

            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            receipt_payload = json.loads(receipt_file.read_text(encoding="utf-8"))
            persistent_evidence = json.loads(
                Path(receipt_payload["preflight"]["persistent_evidence_file"]).read_text(
                    encoding="utf-8"
                )
            )
            response = persistent_evidence["attestation"]["response"]
            tools_catalog = persistent_evidence["rpc_evidence"]["tools_catalog"]["response"]
            self.assertEqual(
                sorted(persistent_evidence["rpc_evidence"]),
                [
                    "allow_lease_status",
                    "allow_lease_status_rejects_non_empty_params",
                    "tools_catalog",
                ],
            )
            self.assertEqual(validation["status"], "pass")
            self.assertEqual(
                validation["receipt_sha256"], MODULE._sha256_bytes(receipt_file.read_bytes())
            )
            self.assertEqual(
                validation["attestation_response_sha256"], MODULE._canonical_sha256(response)
            )
            self.assertEqual(
                validation["tools_catalog_response_sha256"],
                MODULE._canonical_sha256(tools_catalog),
            )
            self.assertEqual(
                validation["lifecycle_attestation"],
                MODULE._lifecycle_attestation_record(receipt_payload["lifecycle"]),
            )
            self.assertEqual(
                validation["lifecycle_attestation_sha256"],
                MODULE._canonical_sha256(validation["lifecycle_attestation"]),
            )
            self.assertEqual(
                validation["lifecycle_attestation"]["record_transport"],
                "validator_pinned_gateway_rpc_transcript_reverification",
            )
            self.assertEqual(
                validation["lifecycle_rpc_transcript_sha256"],
                receipt_payload["lifecycle"]["gateway_rpc_transcript_sha256"],
            )
            self.assertEqual(validation_file.stat().st_mode & 0o777, 0o600)

    def test_independent_validator_subprocess_receives_keys_without_persisting_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root, self._valid_persistent_receipt()
            )
            os.chmod(run_root, 0o700)
            validation_file.unlink()
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(exist_ok=True, mode=0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            pinned = MODULE._pin_prepared_run_root(run_root.resolve())
            source_binding = self._agentic_source_bindings()
            try:
                with mock.patch.object(
                    MODULE,
                    "_source_bindings",
                    return_value=source_binding,
                ):
                    MODULE._run_independent_validator(
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                        pinned_run_root=pinned,
                        agentic_sources=source_binding,
                        timeout=5,
                    )
            finally:
                pinned.close()

            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            self.assertTrue(validation["attestation_signature_verified"])
            self.assertTrue(validation["attestation_verification"]["verified"])
            self.assertTrue(key_path.exists())
            serialized = validation_file.read_text(encoding="utf-8")
            self.assertNotIn(ATTESTATION_HMAC_SECRET_HEX, serialized)
            self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, serialized)

    def test_independent_validator_rejects_arbitrary_64_hex_attestation_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root, self._valid_persistent_receipt()
            )
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
            evidence_file = Path(receipt["preflight"]["persistent_evidence_file"])
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
            evidence["attestation"]["response"]["signature"] = "f" * 64
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV: (
                        ATTESTATION_HMAC_SECRET_HEX
                    ),
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    ),
                },
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "signature mismatch"):
                    MODULE._write_independent_validation_file(
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                    )

    def test_independent_validator_rejects_wrong_attestation_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root, self._valid_persistent_receipt()
            )
            wrong_key_hex = hashlib.sha256(b"wrong-attestation-verification-domain").hexdigest()
            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV: wrong_key_hex,
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    ),
                },
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "signature mismatch"):
                    MODULE._write_independent_validation_file(
                        run_root=run_root,
                        receipt_file=receipt_file,
                        validation_file=validation_file,
                    )

    def test_hmac_env_keys_fail_closed_when_missing_weak_or_unsafe(self) -> None:
        cases = {
            "missing": None,
            "weak": "00" * 32,
            "unsafe": "A" * 64,
        }
        for env_name in (
            MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV,
            MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
        ):
            for label, value in cases.items():
                with self.subTest(env_name=env_name, case=label):
                    with mock.patch.dict(os.environ, {}, clear=False):
                        os.environ.pop(env_name, None)
                        if value is not None:
                            os.environ[env_name] = value
                        with self.assertRaisesRegex(
                            MODULE.ProbeError, "unavailable|weak|unsafe"
                        ):
                            MODULE._hmac_secret_from_env(env_name, "test")

    def test_validation_anchor_is_generated_only_when_not_supplied(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            MODULE.secrets,
            "token_bytes",
            return_value=VALIDATION_ANCHOR_HMAC_SECRET,
        ) as token_bytes:
            self.assertEqual(
                MODULE._select_validation_anchor_key(),
                VALIDATION_ANCHOR_HMAC_SECRET,
            )
            token_bytes.assert_called_once_with(32)
            self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, os.environ)

        with mock.patch.dict(
            os.environ,
            {
                MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                    VALIDATION_ANCHOR_HMAC_SECRET_HEX
                )
            },
            clear=True,
        ), mock.patch.object(MODULE.secrets, "token_bytes") as token_bytes:
            self.assertEqual(
                MODULE._select_validation_anchor_key(),
                VALIDATION_ANCHOR_HMAC_SECRET,
            )
            token_bytes.assert_not_called()
            self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, os.environ)

    def test_attestation_verification_key_is_parent_selected_before_candidate_launch(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            MODULE.secrets,
            "token_bytes",
            return_value=ATTESTATION_HMAC_SECRET,
        ) as token_bytes:
            self.assertEqual(
                MODULE._select_attestation_verification_key(),
                ATTESTATION_HMAC_SECRET,
            )
            token_bytes.assert_called_once_with(32)
            self.assertNotIn(MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, os.environ)

        with mock.patch.dict(
            os.environ,
            {
                MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV: (
                    ATTESTATION_HMAC_SECRET_HEX
                )
            },
            clear=True,
        ), mock.patch.object(MODULE.secrets, "token_bytes") as token_bytes:
            self.assertEqual(
                MODULE._select_attestation_verification_key(),
                ATTESTATION_HMAC_SECRET,
            )
            token_bytes.assert_not_called()
            self.assertNotIn(MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, os.environ)

    def test_parent_environment_is_sanitized_before_candidate_launch(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "OPENAI_API_KEY": "sk-secret",
                "CUSTOM_TOKEN": "secret",
                MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                    VALIDATION_ANCHOR_HMAC_SECRET_HEX
                ),
                MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV: (
                    ATTESTATION_HMAC_SECRET_HEX
                ),
            },
            clear=True,
        ):
            self.assertEqual(
                MODULE._select_validation_anchor_key(),
                VALIDATION_ANCHOR_HMAC_SECRET,
            )
            self.assertEqual(
                MODULE._select_attestation_verification_key(),
                ATTESTATION_HMAC_SECRET,
            )
            MODULE._sanitize_parent_environment_before_candidate_launch()

            self.assertEqual(os.environ["PATH"], "/usr/bin")
            self.assertNotIn("OPENAI_API_KEY", os.environ)
            self.assertNotIn("CUSTOM_TOKEN", os.environ)
            self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, os.environ)
            self.assertNotIn(MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, os.environ)

    def test_validator_env_uses_parent_attestation_key_and_separates_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    )
                },
            ):
                validator_env = self._validator_env_for_path(
                    run_root,
                    validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                )

            self.assertEqual(
                validator_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
                ATTESTATION_HMAC_SECRET_HEX,
            )
            self.assertEqual(
                validator_env[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV],
                VALIDATION_ANCHOR_HMAC_SECRET_HEX,
            )
            self.assertTrue(key_path.exists())

    def test_validator_env_ignores_candidate_authored_attestation_key_files(self) -> None:
        for case in ("symlink", "mode", "weak"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run_root = root / "run"
                key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(run_root, 0o700)
                os.chmod(key_path.parent, 0o700)
                if case == "symlink":
                    target = root / "target.key"
                    target.write_bytes(ATTESTATION_HMAC_SECRET)
                    os.chmod(target, 0o600)
                    key_path.symlink_to(target)
                else:
                    key_path.write_bytes(
                        b"short" if case == "weak" else ATTESTATION_HMAC_SECRET
                    )
                    os.chmod(key_path, 0o644 if case == "mode" else 0o600)
                with mock.patch.dict(
                    os.environ,
                    {
                        MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                            VALIDATION_ANCHOR_HMAC_SECRET_HEX
                        )
                    },
                ):
                    validator_env = self._validator_env_for_path(
                        run_root,
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                    )
                self.assertEqual(
                    validator_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
                    ATTESTATION_HMAC_SECRET_HEX,
                )

    def test_validator_env_does_not_open_candidate_authored_attestation_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            original_open = MODULE.os.open
            key_open_attempted = False

            def fail_if_key_opened(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal key_open_attempted
                if (
                    path == MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH.name
                    and dir_fd is not None
                ):
                    key_open_attempted = True
                    raise AssertionError("candidate-authored key must not be opened")
                return original_open(path, flags, mode, dir_fd=dir_fd)

            pinned = MODULE._pin_prepared_run_root(run_root.resolve())
            with mock.patch.object(MODULE.os, "open", fail_if_key_opened), mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    )
                },
            ):
                try:
                    validator_env = MODULE._validator_env(
                        run_root=pinned,
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                    )
                finally:
                    pinned.close()
            self.assertFalse(key_open_attempted)
            self.assertEqual(
                validator_env[MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV],
                ATTESTATION_HMAC_SECRET_HEX,
            )

    def test_validator_env_fails_explicitly_when_validation_anchor_is_weak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            with self.assertRaisesRegex(
                MODULE.ProbeError, "validation anchor.*weak"
            ):
                self._validator_env_for_path(
                    run_root,
                    validation_anchor_key=b"weak",
                )
            self.assertTrue(key_path.exists())

    def test_validator_env_rejects_reused_key_material_across_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            with mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        ATTESTATION_HMAC_SECRET_HEX
                    )
                },
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "domain separated"):
                    self._validator_env_for_path(
                        run_root,
                        validation_anchor_key=ATTESTATION_HMAC_SECRET,
                    )

    def test_explicit_run_root_rejects_symlink_unsafe_or_nonempty_tree(self) -> None:
        for case in ("symlink", "mode", "nonempty"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run_root = root / "run"
                if case == "symlink":
                    target = root / "target"
                    target.mkdir(mode=0o700)
                    run_root.symlink_to(target, target_is_directory=True)
                else:
                    run_root.mkdir(mode=0o700)
                    if case == "mode":
                        os.chmod(run_root, 0o755)
                    else:
                        (run_root / "stale").write_text("stale", encoding="utf-8")
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "symlink|owner-owned|empty"
                ):
                    MODULE._prepare_private_run_root(run_root)

    def test_persistent_runner_fails_before_launch_when_supplied_validation_anchor_is_weak(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            original_run = MODULE._run
            launched = False

            def fake_run(*args, **kwargs):
                nonlocal launched
                launched = True
                raise AssertionError("runner must not launch without validation anchor")

            try:
                MODULE._run = fake_run
                with mock.patch.dict(
                    os.environ,
                    {MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: "00" * 32},
                ):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "validation anchor.*weak"
                    ):
                        MODULE._run_persistent_lifecycle_probe(
                            root,
                            root / "evidence.json",
                            timeout=1,
                            head=VALID_RUNTIME_HEAD,
                            agentic_sources=[],
                            runtime_sources=[],
                            run_root=run_root,
                            port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                            run_id="run-id",
                            transition_id="transition-id",
                        )
            finally:
                MODULE._run = original_run

            self.assertFalse(launched)
            self.assertFalse(run_root.exists())

    def test_persistent_runner_fails_before_launch_when_loopback_port_is_occupied(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            output = root / "evidence.json"
            launched = False

            class OccupiedSocket:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def bind(self, address):
                    raise OSError(MODULE.errno.EADDRINUSE, "occupied")

            def fake_run(*args, **kwargs):
                nonlocal launched
                launched = True
                raise AssertionError("runner must not launch on an occupied port")

            with mock.patch.object(MODULE, "_git", return_value="agentic-head"), mock.patch.object(
                MODULE,
                "_assert_loopback_port_available_before_launch",
                self._original_assert_loopback_port_available_before_launch,
            ), mock.patch.object(
                MODULE.socket, "socket", return_value=OccupiedSocket()
            ), mock.patch.object(MODULE, "_run", side_effect=fake_run):
                with self.assertRaisesRegex(MODULE.ProbeError, "already occupied"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=20190,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(launched)

    def test_persistent_runner_timeout_writes_fail_closed_cleanup_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            captured = {}
            original_run = MODULE._run
            original_git = MODULE._git
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )
            cleanup = {
                "tracking_status": "available",
                "descendant_identities": [
                    {
                        "pid": 234567,
                        "uid": os.getuid(),
                        "start_id": "detached-start",
                    }
                ],
            }

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["start_new_session"] = start_new_session
                key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(key_path.parent, 0o700)
                key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                os.chmod(key_path, 0o600)
                exc = MODULE.subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output="runner stdout",
                    stderr="runner stderr",
                )
                exc.pid = 123456
                exc._agentic_os_process_cleanup = cleanup
                raise exc

            def fake_terminate_and_verify(proc):
                captured["cleanup"] = MODULE._tracked_cleanup_from_process(proc)
                return True, True

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: True
                MODULE._terminate_and_verify_process_group = fake_terminate_and_verify
                with self.assertRaisesRegex(MODULE.ProbeError, "timed out"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIs(captured["start_new_session"], True)
            self.assertEqual(captured["cleanup"], cleanup)
            self.assertEqual(payload["status"], "fail_closed")
            self.assertIs(
                payload["isolated_non_production_gateway"]["candidate_port_closed"],
                True,
            )
            self.assertIn("timeout_process_group_cleanup", json.dumps(payload, sort_keys=True))
            self.assertFalse(
                (run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).exists()
            )

    def test_persistent_runner_failure_writes_fail_closed_cleanup_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            captured = {}
            original_run = MODULE._run
            original_git = MODULE._git
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_wait_for_process_group_reaped = MODULE._wait_for_process_group_reaped

            class Proc:
                returncode = 1
                stdout = "runner stdout"
                stderr = "runner stderr"

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["start_new_session"] = start_new_session
                key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(key_path.parent, 0o700)
                key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                os.chmod(key_path, 0o600)
                return self._attach_valid_process_cleanup(Proc())

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: True
                MODULE._terminate_process_group = lambda proc: True
                with self.assertRaisesRegex(MODULE.ProbeError, "runner failed"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIs(captured["start_new_session"], True)
            self.assertEqual(payload["status"], "fail_closed")
            self.assertIs(
                payload["isolated_non_production_gateway"]["candidate_port_closed"],
                True,
            )
            self.assertIn("failure_process_group_cleanup", json.dumps(payload, sort_keys=True))
            self.assertFalse(
                (run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).exists()
            )

    def test_pre_validator_exception_removes_attestation_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            validator_called = False

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(key_path.parent, 0o700)
                key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                os.chmod(key_path, 0o600)
                return self._attach_valid_process_cleanup(Proc())

            def unexpected_validator(**kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(MODULE, "_run", side_effect=fake_run), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value="changed-head"
            ), mock.patch.object(
                MODULE, "_wait_for_loopback_port_closed", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_process_group", return_value=True
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "evidence was rejected"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            self.assertFalse(
                (run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).exists()
            )

    def test_persistent_runner_reaps_process_group_before_validator_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            validator_called = False

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(MODULE, "_run", return_value=Proc()), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE, "_wait_for_loopback_port_closed", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_and_verify_process_group", return_value=(True, False)
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "process group alive before validator"
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "pre_validator_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertFalse(cleanup["process_group_reaped"])

    def test_cleanup_tracker_marks_marker_matched_detached_same_uid_child(self) -> None:
        root_pid = 123456
        escaped_pid = 234567
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = False
        tracker.root_identity = None
        tracker.descendants = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            root_pid: {
                "pid": root_pid,
                "ppid": 1,
                "pgid": root_pid,
                "uid": os.getuid(),
                "start_id": "root-start",
            },
            escaped_pid: {
                "pid": escaped_pid,
                "ppid": 1,
                "pgid": escaped_pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            },
        }

        def has_marker(pid, observed_marker):
            self.assertEqual(observed_marker, marker)
            return pid in {root_pid, escaped_pid}

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", side_effect=has_marker
        ):
            tracker._poll_once()

        self.assertTrue(tracker.cleanup_marker_verified)
        self.assertIn(escaped_pid, tracker.descendants)
        self.assertEqual(tracker.descendants[escaped_pid]["start_id"], "escaped-start")

    def test_cleanup_tracker_fails_closed_on_unmarked_candidate_era_process(
        self,
    ) -> None:
        root_pid = 123456
        escaped_pid = 234567
        baseline_pid = 345678
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = False
        tracker.baseline_identities = {
            baseline_pid: {
                "pid": baseline_pid,
                "uid": os.getuid(),
                "start_id": "baseline-start",
            }
        }
        tracker.root_identity = None
        tracker.descendants = {}
        tracker.unattributed_identities = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            root_pid: {
                "pid": root_pid,
                "ppid": 1,
                "pgid": root_pid,
                "uid": os.getuid(),
                "start_id": "root-start",
            },
            escaped_pid: {
                "pid": escaped_pid,
                "ppid": 1,
                "pgid": escaped_pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            },
            baseline_pid: {
                "pid": baseline_pid,
                "ppid": 1,
                "pgid": baseline_pid,
                "uid": os.getuid(),
                "start_id": "baseline-start",
            },
        }

        def has_marker(pid, observed_marker):
            self.assertEqual(observed_marker, marker)
            return pid == root_pid

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", side_effect=has_marker
        ):
            tracker._poll_once()
            tracker._poll_once()

        snapshot = tracker.snapshot()
        self.assertTrue(snapshot["cleanup_marker_verified"])
        self.assertEqual(snapshot["tracking_status"], "unavailable")
        self.assertIn("without candidate cleanup marker", snapshot["tracking_error"])
        self.assertNotIn(escaped_pid, tracker.descendants)
        self.assertEqual(
            snapshot["unattributed_process_identities"],
            [
                {
                    "pid": escaped_pid,
                    "uid": os.getuid(),
                    "start_id": "escaped-start",
                }
            ],
        )

    def test_cleanup_tracker_keeps_single_unattributed_sample_diagnostic(
        self,
    ) -> None:
        root_pid = 123456
        unrelated_pid = 234567
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = False
        tracker.baseline_identities = {}
        tracker.root_identity = None
        tracker.descendants = {}
        tracker.unattributed_identities = {}
        tracker._pending_unattributed_identities = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            root_pid: {
                "pid": root_pid,
                "ppid": 1,
                "pgid": root_pid,
                "uid": os.getuid(),
                "start_id": "root-start",
            },
            unrelated_pid: {
                "pid": unrelated_pid,
                "ppid": 1,
                "pgid": unrelated_pid,
                "uid": os.getuid(),
                "start_id": "unrelated-start",
            },
        }

        def has_marker(pid, observed_marker):
            self.assertEqual(observed_marker, marker)
            return pid == root_pid

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", side_effect=has_marker
        ):
            tracker._poll_once()

        snapshot = tracker.snapshot()
        self.assertTrue(snapshot["cleanup_marker_verified"])
        self.assertEqual(snapshot["tracking_status"], "available")
        self.assertEqual(snapshot["unattributed_process_identities"], [])
        self.assertNotIn(unrelated_pid, tracker.descendants)

    def test_cleanup_tracker_records_unmarked_process_when_root_exits_first(
        self,
    ) -> None:
        root_pid = 123456
        escaped_pid = 234567
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = False
        tracker.baseline_identities = {}
        tracker.root_identity = None
        tracker.descendants = {}
        tracker.unattributed_identities = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            escaped_pid: {
                "pid": escaped_pid,
                "ppid": 1,
                "pgid": escaped_pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            }
        }

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", return_value=False
        ):
            tracker._poll_once()

        snapshot = tracker.snapshot()
        self.assertIsNone(snapshot["root_identity"])
        self.assertEqual(snapshot["tracking_status"], "unavailable")
        self.assertIn("candidate process identity", snapshot["tracking_error"])
        self.assertEqual(
            snapshot["unattributed_process_identities"],
            [
                {
                    "pid": escaped_pid,
                    "uid": os.getuid(),
                    "start_id": "escaped-start",
                }
            ],
        )

    def test_cleanup_tracker_rejects_first_seen_detached_child_after_root_exit(
        self,
    ) -> None:
        root_pid = 123456
        escaped_pid = 234567
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = True
        tracker.baseline_identities = {}
        tracker.root_identity = {
            "pid": root_pid,
            "uid": os.getuid(),
            "start_id": "root-start",
        }
        tracker.descendants = {}
        tracker.unattributed_identities = {}
        tracker._pending_unattributed_identities = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            escaped_pid: {
                "pid": escaped_pid,
                "ppid": 1,
                "pgid": escaped_pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            }
        }

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", return_value=False
        ):
            tracker._poll_once()

        snapshot = tracker.snapshot()
        self.assertEqual(snapshot["tracking_status"], "unavailable")
        self.assertIn("without candidate cleanup marker", snapshot["tracking_error"])
        self.assertEqual(
            snapshot["unattributed_process_identities"],
            [
                {
                    "pid": escaped_pid,
                    "uid": os.getuid(),
                    "start_id": "escaped-start",
                }
            ],
        )

    def test_cleanup_tracker_fails_closed_when_root_marker_scan_is_unavailable(
        self,
    ) -> None:
        root_pid = 123456
        marker = "unit-cleanup-marker"
        tracker = MODULE._ProcessCleanupTracker.__new__(MODULE._ProcessCleanupTracker)
        tracker.root_pid = root_pid
        tracker.uid = os.getuid()
        tracker.cleanup_marker = marker
        tracker.cleanup_marker_verified = False
        tracker.root_identity = None
        tracker.descendants = {}
        tracker.unavailable_error = None
        tracker._lock = MODULE.threading.Lock()
        records = {
            root_pid: {
                "pid": root_pid,
                "ppid": 1,
                "pgid": root_pid,
                "uid": os.getuid(),
                "start_id": "root-start",
            }
        }

        with mock.patch.object(MODULE, "_process_table", return_value=records), mock.patch.object(
            MODULE, "_process_has_cleanup_marker", return_value=None
        ):
            tracker._poll_once()

        snapshot = tracker.snapshot()
        self.assertFalse(snapshot["cleanup_marker_verified"])
        self.assertEqual(snapshot["tracking_status"], "unavailable")

    def test_process_group_cleanup_rejects_tracked_detached_descendant_survival(
        self,
    ) -> None:
        class Proc:
            pid = 123456

        proc = Proc()
        proc._agentic_os_process_cleanup = {
            "tracking_status": "available",
            "descendant_identities": [
                {
                    "pid": 234567,
                    "uid": os.getuid(),
                    "start_id": "detached-start",
                }
            ],
        }

        with mock.patch.object(
            MODULE, "_terminate_process_group", return_value=True
        ), mock.patch.object(
            MODULE, "_wait_for_process_group_reaped", return_value=True
        ), mock.patch.object(
            MODULE, "_terminate_tracked_process_identities", return_value=True
        ), mock.patch.object(
            MODULE, "_wait_for_tracked_processes_reaped", return_value=False
        ):
            attempted, reaped = MODULE._terminate_and_verify_process_group(proc)

        self.assertTrue(attempted)
        self.assertFalse(reaped)

    def test_unattributed_candidate_era_process_is_diagnostic_only(
        self,
    ) -> None:
        pid = 234567
        cleanup = {
            "tracking_status": "unavailable",
            "tracking_error": (
                "unattributed same-UID process appeared without candidate cleanup marker"
            ),
            "descendant_identities": [],
            "unattributed_process_identities": [
                {
                    "pid": pid,
                    "uid": os.getuid(),
                    "start_id": "escaped-start",
                }
            ],
        }
        live_unattributed_process = {
            pid: {
                "pid": pid,
                "ppid": 1,
                "pgid": pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            }
        }

        with mock.patch.object(
            MODULE, "_process_table", return_value=live_unattributed_process
        ), mock.patch.object(MODULE.os, "kill") as kill:
            self.assertFalse(MODULE._terminate_tracked_process_identities(cleanup))
            self.assertFalse(
                MODULE._wait_for_tracked_processes_reaped(
                    cleanup, timeout_seconds=0.0
                )
            )

        kill.assert_not_called()

    def test_cleanup_signals_only_proven_descendant_not_unattributed_sentinel(
        self,
    ) -> None:
        descendant_pid = 234567
        sentinel_pid = 345678
        descendant_identity = {
            "pid": descendant_pid,
            "uid": os.getuid(),
            "start_id": "detached-start",
        }
        sentinel_identity = {
            "pid": sentinel_pid,
            "uid": os.getuid(),
            "start_id": "unrelated-sentinel-start",
        }
        cleanup = {
            "tracking_status": "unavailable",
            "tracking_error": (
                "unattributed same-UID process appeared without candidate cleanup marker"
            ),
            "descendant_identities": [descendant_identity],
            "unattributed_process_identities": [sentinel_identity],
        }
        live_processes = {
            descendant_pid: {
                "pid": descendant_pid,
                "ppid": 1,
                "pgid": descendant_pid,
                "uid": os.getuid(),
                "start_id": "detached-start",
            },
            sentinel_pid: {
                "pid": sentinel_pid,
                "ppid": 1,
                "pgid": sentinel_pid,
                "uid": os.getuid(),
                "start_id": "unrelated-sentinel-start",
            },
        }

        with mock.patch.object(
            MODULE, "_process_table", return_value=live_processes
        ), mock.patch.object(MODULE.os, "kill") as kill:
            self.assertTrue(MODULE._terminate_tracked_process_identities(cleanup))

        kill.assert_called_once_with(descendant_pid, MODULE.signal.SIGKILL)

    def test_tracked_descendant_cleanup_skips_reused_pid_identity(self) -> None:
        pid = 234567
        old_identity = {
            "pid": pid,
            "uid": os.getuid(),
            "start_id": "old-process-start",
        }
        cleanup = {
            "tracking_status": "available",
            "descendant_identities": [old_identity],
        }
        reused_pid_table = {
            pid: {
                "pid": pid,
                "ppid": 1,
                "pgid": pid,
                "uid": os.getuid(),
                "start_id": "new-process-start",
            }
        }

        with mock.patch.object(
            MODULE, "_process_table", return_value=reused_pid_table
        ), mock.patch.object(MODULE.os, "kill") as kill:
            self.assertFalse(MODULE._process_identity_alive(old_identity))
            self.assertFalse(MODULE._terminate_tracked_process_identities(cleanup))
            self.assertTrue(
                MODULE._wait_for_tracked_processes_reaped(
                    cleanup, timeout_seconds=0.0
                )
            )

        kill.assert_not_called()

    def test_persistent_runner_success_blocks_validator_on_tracked_detached_descendant(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            validator_called = False

            class Proc:
                pid = 123456
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"
                _agentic_os_process_cleanup = {
                    "tracking_status": "available",
                    "descendant_identities": [
                        {
                            "pid": 234567,
                            "uid": os.getuid(),
                            "start_id": "detached-start",
                        }
                    ],
                }

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(MODULE, "_run", return_value=Proc()), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE, "_wait_for_loopback_port_closed", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_process_group", return_value=True
            ), mock.patch.object(
                MODULE, "_wait_for_process_group_reaped", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_tracked_process_identities", return_value=True
            ), mock.patch.object(
                MODULE, "_wait_for_tracked_processes_reaped", return_value=False
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "process group alive before validator"
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "pre_validator_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertFalse(cleanup["process_group_reaped"])

    def test_persistent_runner_blocks_validator_on_unattributed_process_without_kill(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            run_root = root / "run"
            output = root / "evidence.json"
            validator_called = False
            unattributed_pid = 234567

            class Proc:
                pid = 123456
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"
                _agentic_os_process_cleanup = {
                    "tracking_status": "unavailable",
                    "tracking_error": "candidate process identity is unavailable",
                    "descendant_identities": [],
                    "unattributed_process_identities": [
                        {
                            "pid": unattributed_pid,
                            "uid": os.getuid(),
                            "start_id": "unrelated-sentinel-start",
                        }
                    ],
                }

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(MODULE, "_run", return_value=Proc()), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE, "_wait_for_loopback_port_closed", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_process_group", return_value=True
            ), mock.patch.object(
                MODULE, "_wait_for_process_group_reaped", return_value=True
            ), mock.patch.object(
                MODULE.os, "kill"
            ) as kill, mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "process group alive before validator"
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            kill.assert_not_called()
            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "pre_validator_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertFalse(cleanup["process_group_reaped"])

    def test_whole_run_root_replacement_is_rejected_and_cleanup_targets_original_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            moved_root = root / "run-original"
            replacement_key = b"replacement key must survive"
            validator_called = False

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                original_key_path = (
                    run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                )
                original_key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                os.chmod(original_key_path, 0o600)
                run_root.rename(moved_root)
                run_root.mkdir(mode=0o700)
                for name in MODULE.PINNED_RUN_SUBDIRECTORIES:
                    (run_root / name).mkdir(mode=0o700)
                replacement_key_path = (
                    run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                )
                replacement_key_path.write_bytes(replacement_key)
                os.chmod(replacement_key_path, 0o600)
                return self._attach_valid_process_cleanup(Proc())

            def unexpected_validator(**kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(MODULE, "_run", side_effect=fake_run), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "run-root pathname identity changed"
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        root / "evidence.json",
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=run_root,
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            self.assertFalse(
                (moved_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).exists()
            )
            self.assertEqual(
                (run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH).read_bytes(),
                replacement_key,
            )

    def test_pinned_subtree_replacement_is_rejected_and_cleanup_uses_original_keys(
        self,
    ) -> None:
        for swapped_subtree in MODULE.PINNED_RUN_SUBDIRECTORIES:
            with self.subTest(subtree=swapped_subtree), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run_root = root / "run"
                moved_subtree = run_root / f"{swapped_subtree}-original"
                marker = b"replacement subtree marker"
                validator_called = False

                class Proc:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                def fake_run(
                    command, *, cwd, env=None, timeout=240, start_new_session=False
                ):
                    key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                    key_path.write_bytes(ATTESTATION_HMAC_SECRET)
                    os.chmod(key_path, 0o600)
                    subtree = run_root / swapped_subtree
                    subtree.rename(moved_subtree)
                    subtree.mkdir(mode=0o700)
                    (subtree / "replacement-marker").write_bytes(marker)
                    if swapped_subtree == "keys":
                        replacement_key_path = (
                            run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                        )
                        replacement_key_path.write_bytes(b"replacement key")
                        os.chmod(replacement_key_path, 0o600)
                    return self._attach_valid_process_cleanup(Proc())

                def unexpected_validator(**kwargs):
                    nonlocal validator_called
                    validator_called = True

                with mock.patch.object(
                    MODULE, "_run", side_effect=fake_run
                ), mock.patch.object(
                    MODULE, "_git", return_value="agentic-head"
                ), mock.patch.object(
                    MODULE, "_run_independent_validator", side_effect=unexpected_validator
                ):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError,
                        f"pinned {swapped_subtree} subtree identity changed",
                    ):
                        MODULE._run_persistent_lifecycle_probe(
                            root,
                            root / "evidence.json",
                            timeout=1,
                            head=VALID_RUNTIME_HEAD,
                            agentic_sources=[],
                            runtime_sources=[],
                            run_root=run_root,
                            port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                            run_id="run-id",
                            transition_id="transition-id",
                        )

                self.assertFalse(validator_called)
                original_keys = (
                    moved_subtree
                    if swapped_subtree == "keys"
                    else run_root / "keys"
                )
                self.assertFalse(
                    (original_keys / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH.name).exists()
                )
                self.assertEqual(
                    (run_root / swapped_subtree / "replacement-marker").read_bytes(),
                    marker,
                )
                if swapped_subtree == "keys":
                    self.assertEqual(
                        (
                            run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
                        ).read_bytes(),
                        b"replacement key",
                    )

    def test_pinned_artifact_file_replacement_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = MODULE._prepare_private_run_root(Path(directory) / "run")
            pinned = MODULE._pin_prepared_run_root(run_root)
            artifact = run_root / "evidence" / "artifact.json"
            original_artifact = artifact.with_name("artifact-original.json")
            artifact.write_text('{"status":"pass"}', encoding="utf-8")
            original_read = MODULE.os.read
            swapped = False

            def swap_after_open(descriptor, size):
                nonlocal swapped
                chunk = original_read(descriptor, size)
                if not swapped:
                    artifact.rename(original_artifact)
                    artifact.write_text('{"status":"replacement"}', encoding="utf-8")
                    swapped = True
                return chunk

            try:
                with mock.patch.object(MODULE.os, "read", side_effect=swap_after_open):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "file changed during pinned access"
                    ):
                        MODULE._read_pinned_artifact_bytes(
                            pinned,
                            "evidence/artifact.json",
                            "test artifact",
                        )
            finally:
                pinned.close()

            self.assertTrue(swapped)
            self.assertEqual(
                json.loads(artifact.read_text(encoding="utf-8"))["status"],
                "replacement",
            )

    def _assert_same_inode_artifact_mutation_during_read_is_rejected(
        self,
        mutate,
        expected_final_status: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = MODULE._prepare_private_run_root(Path(directory) / "run")
            pinned = MODULE._pin_prepared_run_root(run_root)
            artifact = run_root / "evidence" / "artifact.json"
            artifact.write_text('{"status":"pass"}', encoding="utf-8")
            before = artifact.stat()
            original_read = MODULE.os.read
            mutated = False

            def mutate_same_inode_after_open(descriptor, size):
                nonlocal mutated
                chunk = original_read(descriptor, size)
                if not mutated:
                    mutate(artifact)
                    mutated = True
                return chunk

            try:
                with mock.patch.object(
                    MODULE.os, "read", side_effect=mutate_same_inode_after_open
                ):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "file changed during pinned access"
                    ):
                        MODULE._read_pinned_artifact_bytes(
                            pinned,
                            "evidence/artifact.json",
                            "test artifact",
                        )
            finally:
                pinned.close()

            after = artifact.stat()
            self.assertTrue(mutated)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertEqual(
                json.loads(artifact.read_text(encoding="utf-8"))["status"],
                expected_final_status,
            )

    def test_pinned_artifact_equal_length_same_inode_overwrite_is_rejected(self) -> None:
        def mutate(artifact: Path) -> None:
            with artifact.open("r+b") as handle:
                handle.write(b'{"status":"evil"}')
                handle.flush()
                os.fsync(handle.fileno())

        self._assert_same_inode_artifact_mutation_during_read_is_rejected(
            mutate,
            "evil",
        )

    def test_pinned_artifact_same_inode_truncate_rewrite_is_rejected(self) -> None:
        def mutate(artifact: Path) -> None:
            with artifact.open("r+b") as handle:
                handle.truncate(0)
                handle.write(b'{"status":"evil"}')
                handle.flush()
                os.fsync(handle.fileno())

        self._assert_same_inode_artifact_mutation_during_read_is_rejected(
            mutate,
            "evil",
        )

    def test_pinned_artifact_same_inode_aba_mutation_is_rejected(self) -> None:
        def mutate(artifact: Path) -> None:
            with artifact.open("r+b") as handle:
                handle.write(b'{"status":"evil"}')
                handle.flush()
                os.fsync(handle.fileno())
                handle.seek(0)
                handle.write(b'{"status":"pass"}')
                handle.flush()
                os.fsync(handle.fileno())

        self._assert_same_inode_artifact_mutation_during_read_is_rejected(
            mutate,
            "pass",
        )

    def test_pinned_run_root_rejects_post_pin_permission_widening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = MODULE._prepare_private_run_root(Path(directory) / "run")
            pinned = MODULE._pin_prepared_run_root(run_root)
            os.chmod(run_root, 0o755)
            try:
                with self.assertRaisesRegex(MODULE.ProbeError, "run root is unsafe"):
                    MODULE._assert_pinned_run_root_identity(pinned)
            finally:
                os.chmod(run_root, 0o700)
                pinned.close()

    def test_pinned_validator_receives_only_explicit_run_capability_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = MODULE._prepare_private_run_root(Path(directory) / "run")
            pinned = MODULE._pin_prepared_run_root(run_root)
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            captured = {}

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(
                command,
                *,
                cwd,
                env=None,
                timeout=240,
                start_new_session=False,
                pass_fds=(),
                input_bytes=None,
            ):
                captured["command"] = list(command)
                captured["cwd"] = cwd
                captured["pass_fds"] = pass_fds
                captured["input_bytes"] = input_bytes
                captured["copy_path_exists_during_launch"] = (
                    run_root / "keys" / "bound-independent-validator.py"
                ).exists()
                (run_root / "receipts" / "independent-validation.json").write_text(
                    json.dumps({"status": "pass"}),
                    encoding="utf-8",
                )
                return self._attach_valid_process_cleanup(Proc())

            try:
                source_binding = self._agentic_source_bindings()
                with mock.patch.object(
                    MODULE,
                    "_run",
                    side_effect=fake_run,
                ), mock.patch.object(
                    MODULE,
                    "_source_bindings",
                    return_value=source_binding,
                ):
                    MODULE._run_independent_validator(
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                        pinned_run_root=pinned,
                        agentic_sources=source_binding,
                    )
            finally:
                pinned.close()

            pinned_fds = pinned.validator_fds()
            self.assertEqual(captured["pass_fds"], pinned_fds)
            command = captured["command"]
            self.assertEqual(captured["cwd"], pinned.original_path)
            self.assertEqual(command[1:4], ["-I", "-S", "-c"])
            self.assertEqual(command[4], MODULE.STDIN_VALIDATOR_BOOTSTRAP)
            self.assertEqual(
                command[5],
                str(
                    (
                        MODULE.ROOT
                        / "scripts/openclaw-real-gateway-contract-probe.py"
                    ).resolve()
                ),
            )
            self.assertEqual(
                MODULE._sha256_bytes(captured["input_bytes"]),
                command[6],
            )
            bundle = json.loads(captured["input_bytes"].decode("utf-8"))
            self.assertEqual(
                bundle["modules"]["agentic_os_runtime_source_contract"]["path"],
                str((MODULE.ROOT / MODULE.RUNTIME_SOURCE_CONTRACT_HELPER).resolve()),
            )
            self.assertEqual(command[7], "__persistent-validator")
            self.assertNotIn("bound-independent-validator.py", command[5])
            self.assertFalse(captured["copy_path_exists_during_launch"])
            for name in ("root", *MODULE.PINNED_RUN_SUBDIRECTORIES):
                self.assertIn(f"--{name}-fd", command)
                self.assertIn(f"--{name}-device", command)
                self.assertIn(f"--{name}-inode", command)

    def test_validator_stdin_bootstrap_uses_bundled_source_contract_helper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir()
            helper_path = scripts_dir / "agentic_os_runtime_source_contract.py"
            marker = root / "helper-marker.txt"
            helper_path.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('disk', encoding='utf-8')\nVALUE = 'disk'\n",
                encoding="utf-8",
            )
            validator_path = scripts_dir / "openclaw-real-gateway-contract-probe.py"
            validator_source = (
                "import sys\n"
                "from pathlib import Path\n"
                f"sys.path.insert(0, {str(scripts_dir)!r})\n"
                "import agentic_os_runtime_source_contract as helper\n"
                f"Path({str(marker)!r}).write_text(helper.VALUE, encoding='utf-8')\n"
            ).encode("utf-8")
            helper_source = b"VALUE = 'bundled'\n"
            bundle = MODULE._validator_source_bundle(
                validator_source=validator_source,
                validator_digest=MODULE._sha256_bytes(validator_source),
                validator_path=str(validator_path),
                helper_source=helper_source,
                helper_digest=MODULE._sha256_bytes(helper_source),
                helper_path=str(helper_path),
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    MODULE.STDIN_VALIDATOR_BOOTSTRAP,
                    str(validator_path),
                    MODULE._sha256_bytes(bundle),
                    "__persistent-validator",
                ],
                input=bundle,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8"))
            self.assertEqual(marker.read_text(encoding="utf-8"), "bundled")

    def test_validator_stdin_launch_ignores_post_verification_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root, self._valid_persistent_receipt()
            )
            os.chmod(run_root, 0o700)
            validation_file.unlink()
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(exist_ok=True, mode=0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            pinned = MODULE._pin_prepared_run_root(run_root.resolve())
            source_binding = self._agentic_source_bindings()
            original_run = MODULE._run
            tampered_script = run_root / "keys" / "bound-independent-validator.py"
            tampered_marker = run_root / "receipts" / "tampered-validator-ran.json"
            malicious_source = "\n".join(
                (
                    "import json, os",
                    f"marker = {str(tampered_marker)!r}",
                    "visible_fds = []",
                    "for fd in range(3, 64):",
                    "    try:",
                    "        os.fstat(fd)",
                    "    except OSError:",
                    "        continue",
                    "    visible_fds.append(fd)",
                    "payload = {",
                    f"    'attestation_key': os.environ.get({MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV!r}),",
                    f"    'validation_key': os.environ.get({MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV!r}),",
                    "    'visible_fds': visible_fds,",
                    "}",
                    "with open(marker, 'w', encoding='utf-8') as handle:",
                    "    json.dump(payload, handle, sort_keys=True)",
                )
            )

            def replace_then_run(
                command,
                *,
                cwd,
                env=None,
                timeout=240,
                start_new_session=False,
                pass_fds=(),
                input_bytes=None,
            ):
                tampered_script.write_text(malicious_source, encoding="utf-8")
                os.chmod(tampered_script, 0o700)
                return original_run(
                    command,
                    cwd=cwd,
                    env=env,
                    timeout=timeout,
                    start_new_session=start_new_session,
                    pass_fds=pass_fds,
                    input_bytes=input_bytes,
                )

            try:
                with mock.patch.object(
                    MODULE,
                    "_run",
                    side_effect=replace_then_run,
                ), mock.patch.object(
                    MODULE,
                    "_source_bindings",
                    return_value=source_binding,
                ):
                    MODULE._run_independent_validator(
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                        pinned_run_root=pinned,
                        agentic_sources=source_binding,
                        timeout=5,
                    )
            finally:
                pinned.close()

            self.assertTrue(tampered_script.exists())
            self.assertFalse(tampered_marker.exists())
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            self.assertEqual(validation["status"], "pass")
            serialized = validation_file.read_text(encoding="utf-8")
            self.assertNotIn(ATTESTATION_HMAC_SECRET_HEX, serialized)
            self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, serialized)

    def test_validator_stdin_launch_ignores_retained_writable_copy_fd_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            receipt_file, validation_file = self._write_persistent_receipts(
                run_root, self._valid_persistent_receipt()
            )
            os.chmod(run_root, 0o700)
            validation_file.unlink()
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(exist_ok=True, mode=0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            pinned = MODULE._pin_prepared_run_root(run_root.resolve())
            source_binding = self._agentic_source_bindings()
            original_bound_source = MODULE._bound_validator_script_source
            original_run = MODULE._run
            retained_fd = -1
            tampered_marker = run_root / "receipts" / "retained-fd-tampered-ran.json"
            malicious_source = "\n".join(
                (
                    "import json, os",
                    f"marker = {str(tampered_marker)!r}",
                    "visible_fds = []",
                    "for fd in range(3, 64):",
                    "    try:",
                    "        os.fstat(fd)",
                    "    except OSError:",
                    "        continue",
                    "    visible_fds.append(fd)",
                    "payload = {",
                    f"    'attestation_key': os.environ.get({MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV!r}),",
                    f"    'validation_key': os.environ.get({MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV!r}),",
                    "    'visible_fds': visible_fds,",
                    "}",
                    "with open(marker, 'w', encoding='utf-8') as handle:",
                    "    json.dump(payload, handle, sort_keys=True)",
                )
            ).encode()

            def bind_then_retain_writable_copy_fd(**kwargs):
                nonlocal retained_fd
                source_bytes, digest, path = original_bound_source(**kwargs)
                retained_fd = os.open(
                    "bound-independent-validator.py",
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=pinned.keys.fd,
                )
                offset = 0
                while offset < len(source_bytes):
                    offset += os.write(retained_fd, source_bytes[offset:])
                os.fsync(retained_fd)
                self.assertEqual(MODULE._sha256_bytes(source_bytes), digest)
                return source_bytes, digest, path

            def mutate_retained_fd_then_run(
                command,
                *,
                cwd,
                env=None,
                timeout=240,
                start_new_session=False,
                pass_fds=(),
                input_bytes=None,
            ):
                self.assertGreaterEqual(retained_fd, 0)
                os.lseek(retained_fd, 0, os.SEEK_SET)
                os.ftruncate(retained_fd, 0)
                offset = 0
                while offset < len(malicious_source):
                    offset += os.write(retained_fd, malicious_source[offset:])
                os.fsync(retained_fd)
                return original_run(
                    command,
                    cwd=cwd,
                    env=env,
                    timeout=timeout,
                    start_new_session=start_new_session,
                    pass_fds=pass_fds,
                    input_bytes=input_bytes,
                )

            try:
                with mock.patch.object(
                    MODULE,
                    "_bound_validator_script_source",
                    side_effect=bind_then_retain_writable_copy_fd,
                ), mock.patch.object(
                    MODULE,
                    "_run",
                    side_effect=mutate_retained_fd_then_run,
                ), mock.patch.object(
                    MODULE,
                    "_source_bindings",
                    return_value=source_binding,
                ):
                    MODULE._run_independent_validator(
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        attestation_verification_key=ATTESTATION_HMAC_SECRET,
                        pinned_run_root=pinned,
                        agentic_sources=source_binding,
                        timeout=5,
                    )
            finally:
                if retained_fd >= 0:
                    os.close(retained_fd)
                pinned.close()

            self.assertFalse(tampered_marker.exists())
            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            self.assertEqual(validation["status"], "pass")
            serialized = validation_file.read_text(encoding="utf-8")
            self.assertNotIn(ATTESTATION_HMAC_SECRET_HEX, serialized)
            self.assertNotIn(VALIDATION_ANCHOR_HMAC_SECRET_HEX, serialized)

    def test_candidate_subprocess_does_not_inherit_pinned_run_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = MODULE._prepare_private_run_root(root / "run")
            pinned = MODULE._pin_prepared_run_root(run_root)
            descriptors = pinned.validator_fds()
            child_code = (
                "import json, os, sys\n"
                "visible = []\n"
                "for raw in sys.argv[1:]:\n"
                "    try:\n"
                "        os.fstat(int(raw))\n"
                "    except OSError:\n"
                "        continue\n"
                "    visible.append(int(raw))\n"
                "print(json.dumps(visible))\n"
            )
            try:
                proc = MODULE._run(
                    [sys.executable, "-c", child_code, *map(str, descriptors)],
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", "")},
                    timeout=5,
                )
            finally:
                pinned.close()

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), [])

    def test_run_reaps_child_when_communicate_is_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            class FakePopen:
                pid = 4321
                returncode = None

                def __init__(self) -> None:
                    self.calls = 0
                    self.killed = False

                def communicate(self, *args, **kwargs):
                    self.calls += 1
                    if self.calls == 1:
                        raise KeyboardInterrupt("operator interruption")
                    return "cleanup stdout", "cleanup stderr"

                def poll(self):
                    return None if not self.killed else -9

                def kill(self) -> None:
                    self.killed = True
                    self.returncode = -9

            fake_proc = FakePopen()
            with mock.patch.object(MODULE.subprocess, "Popen", return_value=fake_proc):
                with self.assertRaises(KeyboardInterrupt) as captured:
                    MODULE._run(["candidate"], cwd=Path(directory), timeout=5)

            self.assertTrue(fake_proc.killed)
            self.assertEqual(fake_proc.calls, 2)
            self.assertEqual(getattr(captured.exception, "pid"), 4321)

    def test_attestation_key_cleanup_failure_retains_primary_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            primary = MODULE.ProbeError("primary runner timeout marker")
            with mock.patch.object(
                MODULE, "_run_persistent_lifecycle_probe_once", side_effect=primary
            ), mock.patch.object(
                MODULE,
                "_remove_attestation_verification_key",
                side_effect=MODULE.ProbeError("cleanup marker"),
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "primary runner timeout marker;.*cleanup marker",
                ) as captured:
                    MODULE._run_persistent_lifecycle_probe(
                        Path(directory),
                        Path(directory) / "evidence.json",
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=Path(directory) / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertIs(captured.exception.__cause__, primary)

    def test_persistent_runner_failure_rejects_unverified_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            original_run = MODULE._run
            original_git = MODULE._git
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_wait_for_process_group_reaped = MODULE._wait_for_process_group_reaped

            class Proc:
                returncode = 1
                stdout = "runner stdout"
                stderr = "runner stderr"

            try:
                MODULE._run = lambda *args, **kwargs: self._attach_valid_process_cleanup(Proc())
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: False
                MODULE._terminate_process_group = lambda proc: True
                MODULE._wait_for_process_group_reaped = lambda proc: True
                with self.assertRaisesRegex(MODULE.ProbeError, "port remained open"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group
                MODULE._wait_for_process_group_reaped = original_wait_for_process_group_reaped

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(
                payload["isolated_non_production_gateway"]["candidate_port_closed"]
            )
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "failure_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")

    def test_persistent_runner_success_rejects_unclosed_candidate_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            try:
                MODULE._run = lambda *args, **kwargs: self._attach_valid_process_cleanup(Proc())
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "agentic_os_head_sha": "agentic-head",
                    "runtime_ready": False,
                    "runtime_ready_candidate_evidence": True,
                    "isolated_non_production_gateway": {"candidate_port_closed": True},
                }
                MODULE._wait_for_loopback_port_closed = lambda port: False
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                MODULE._terminate_process_group = lambda proc: True
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                with self.assertRaisesRegex(MODULE.ProbeError, "candidate port remained open"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_port_closure"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertIs(cleanup["candidate_port_closed"], False)

    def test_persistent_runner_success_revalidates_runtime_launch_bindings_before_validator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            validator_called = False
            bindings = [
                (
                    Path("/bound/node"),
                    "file:///bound/node_modules/tsx/dist/loader.mjs",
                    self._valid_runtime_launch_sources(),
                ),
                (
                    Path("/bound/node"),
                    "file:///bound/node_modules/tsx/dist/loader.mjs",
                    [
                        {
                            **item,
                            "sha256": (
                                "0" * 64
                                if item["path"] == "runtime-launcher:node"
                                else item["sha256"]
                            ),
                        }
                        for item in self._valid_runtime_launch_sources()
                    ],
                ),
            ]

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            try:
                with mock.patch.object(MODULE, "_run", return_value=self._attach_valid_process_cleanup(Proc())), mock.patch.object(
                    MODULE, "_git", return_value="agentic-head"
                ), mock.patch.object(
                    MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
                ), mock.patch.object(
                    MODULE, "_runtime_launch_bindings", side_effect=bindings
                ), mock.patch.object(
                    MODULE, "_run_independent_validator", side_effect=unexpected_validator
                ), mock.patch.object(
                    MODULE, "_wait_for_loopback_port_closed", return_value=True
                ), mock.patch.object(
                    MODULE, "_terminate_and_verify_process_group", return_value=(True, True)
                ), mock.patch.object(
                    MODULE, "_terminate_process_group", return_value=True
                ):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError,
                        "evidence was rejected after successful runner exit",
                    ):
                        MODULE._run_persistent_lifecycle_probe(
                            root,
                            output,
                            timeout=1,
                            head=VALID_RUNTIME_HEAD,
                            agentic_sources=[],
                            runtime_sources=[],
                            run_root=root / "run",
                            port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                            run_id="run-id",
                            transition_id="transition-id",
                        )
            finally:
                self.assertFalse(validator_called)

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "fail_closed")
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "pass")

    def test_persistent_runner_success_revalidates_runtime_sources_before_validator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            validator_called = False

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            try:
                with mock.patch.object(
                    MODULE,
                    "_run",
                    return_value=self._attach_valid_process_cleanup(Proc()),
                ), mock.patch.object(
                    MODULE, "_git", return_value="agentic-head"
                ), mock.patch.object(
                    MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
                ), mock.patch.object(
                    MODULE,
                    "_assert_runtime_sources_still_bound",
                    side_effect=MODULE.ProbeError("runtime source closure changed"),
                ), mock.patch.object(
                    MODULE, "_run_independent_validator", side_effect=unexpected_validator
                ), mock.patch.object(
                    MODULE, "_wait_for_loopback_port_closed", return_value=True
                ), mock.patch.object(
                    MODULE, "_terminate_and_verify_process_group", return_value=(True, True)
                ), mock.patch.object(
                    MODULE, "_terminate_process_group", return_value=True
                ):
                    with self.assertRaisesRegex(
                        MODULE.ProbeError,
                        "evidence was rejected after successful runner exit",
                    ):
                        MODULE._run_persistent_lifecycle_probe(
                            root,
                            output,
                            timeout=1,
                            head=VALID_RUNTIME_HEAD,
                            agentic_sources=[],
                            runtime_sources=[],
                            run_root=root / "run",
                            port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                            run_id="run-id",
                            transition_id="transition-id",
                        )
            finally:
                self.assertFalse(validator_called)

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "fail_closed")
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "pass")

    def test_validator_python_runtime_binds_loaded_module_file_closure(self) -> None:
        previous_closure = MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES
        module_name = "validator_startup_closure_fixture"
        previous_module = sys.modules.get(module_name)
        try:
            with tempfile.TemporaryDirectory() as directory:
                module_path = Path(directory) / "startup_dependency.py"
                module_path.write_text("VALUE = 'before'\n", encoding="utf-8")
                module = types.ModuleType(module_name)
                module.__file__ = str(module_path)
                sys.modules[module_name] = module
                MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES = None

                before = MODULE._validator_python_runtime_bindings()
                by_path = {item["path"]: item["sha256"] for item in before}
                self.assertIn(f"validator-runtime:module:{module_name}", by_path)
                self.assertIn("validator-runtime:module:encodings", by_path)

                module_path.write_text("VALUE = 'after'\n", encoding="utf-8")
                after = MODULE._validator_python_runtime_bindings()
                after_by_path = {item["path"]: item["sha256"] for item in after}
                self.assertNotEqual(
                    by_path[f"validator-runtime:module:{module_name}"],
                    after_by_path[f"validator-runtime:module:{module_name}"],
                )
        finally:
            MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES = previous_closure
            if previous_module is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous_module

    def test_validator_python_runtime_binds_available_bytecode_cache(self) -> None:
        previous_closure = MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES
        module_name = "validator_startup_cache_fixture"
        previous_module = sys.modules.get(module_name)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_path = root / "cached_dependency.py"
                cache_path = root / "__pycache__" / "cached_dependency.cpython-test.pyc"
                cache_path.parent.mkdir()
                source_path.write_text("VALUE = 'source'\n", encoding="utf-8")
                cache_path.write_bytes(b"bytecode-before")
                module = types.ModuleType(module_name)
                module.__file__ = str(source_path)
                module.__cached__ = str(cache_path)
                sys.modules[module_name] = module
                MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES = None

                before = MODULE._validator_python_runtime_bindings()
                by_path = {item["path"]: item["sha256"] for item in before}
                self.assertIn(f"validator-runtime:module:{module_name}", by_path)
                cache_label = f"validator-runtime:module:{module_name}:artifact:1"
                self.assertIn(cache_label, by_path)

                cache_path.write_bytes(b"bytecode-after")
                after = MODULE._validator_python_runtime_bindings()
                after_by_path = {item["path"]: item["sha256"] for item in after}
                self.assertNotEqual(by_path[cache_label], after_by_path[cache_label])
                self.assertEqual(
                    by_path[f"validator-runtime:module:{module_name}"],
                    after_by_path[f"validator-runtime:module:{module_name}"],
                )
        finally:
            MODULE._VALIDATOR_PYTHON_RUNTIME_CLOSURE_MODULES = previous_closure
            if previous_module is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous_module

    def test_persistent_runner_success_revalidates_validator_python_runtime_before_validator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            validator_called = False
            expected_sources = [
                {
                    "path": "validator-runtime:python",
                    "sha256": "a" * 64,
                    "realpath_sha256": "b" * 64,
                }
            ]
            changed_sources = [{**expected_sources[0], "sha256": "c" * 64}]

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def unexpected_validator(**_kwargs):
                nonlocal validator_called
                validator_called = True

            with mock.patch.object(
                MODULE,
                "_run",
                return_value=self._attach_valid_process_cleanup(Proc()),
            ), mock.patch.object(
                MODULE, "_git", return_value="agentic-head"
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value=VALID_RUNTIME_HEAD
            ), mock.patch.object(
                MODULE,
                "_validator_python_runtime_bindings",
                side_effect=[expected_sources, changed_sources],
            ), mock.patch.object(
                MODULE, "_run_independent_validator", side_effect=unexpected_validator
            ), mock.patch.object(
                MODULE, "_wait_for_loopback_port_closed", return_value=True
            ), mock.patch.object(
                MODULE, "_terminate_and_verify_process_group", return_value=(True, True)
            ), mock.patch.object(
                MODULE, "_terminate_process_group", return_value=True
            ):
                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "evidence was rejected after successful runner exit",
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )

            self.assertFalse(validator_called)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "fail_closed")
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "pass")

    def test_persistent_runner_success_rejects_port_closed_only_by_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            waits = iter([False, True])
            captured = {}
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            try:
                MODULE._run = lambda *args, **kwargs: self._attach_valid_process_cleanup(Proc())
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: {
                    "status": "pass",
                    "openclaw_head_sha": "openclaw-head",
                    "agentic_os_head_sha": "agentic-head",
                    "runtime_ready": False,
                    "runtime_ready_candidate_evidence": True,
                    "isolated_non_production_gateway": {"candidate_port_closed": True},
                }
                MODULE._wait_for_loopback_port_closed = lambda port: next(waits)
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                MODULE._terminate_process_group = lambda proc: captured.setdefault(
                    "cleanup_attempted", True
                )
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                with self.assertRaisesRegex(MODULE.ProbeError, "remained open before cleanup"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_port_closure"
            )
            self.assertEqual(payload["status"], "fail_closed")
            self.assertEqual(cleanup["status"], "fail")
            self.assertIs(cleanup["process_group_cleanup_attempted"], True)
            self.assertIs(cleanup["candidate_port_closed"], True)
            self.assertIs(captured["cleanup_attempted"], True)

    def test_persistent_runner_success_rejection_cleans_candidate_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            captured = {}
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["start_new_session"] = start_new_session
                return self._attach_valid_process_cleanup(Proc())

            def fake_terminate(proc):
                captured["cleanup_attempted"] = True
                return True

            def fake_terminate_and_verify(proc):
                captured["cleanup_attempted"] = True
                return (True, True)

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: (_ for _ in ()).throw(
                    MODULE.ProbeError("contradictory receipt")
                )
                MODULE._wait_for_loopback_port_closed = lambda port: True
                MODULE._terminate_and_verify_process_group = fake_terminate_and_verify
                MODULE._terminate_process_group = fake_terminate
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                with self.assertRaisesRegex(MODULE.ProbeError, "evidence was rejected"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIs(captured["start_new_session"], True)
            self.assertIs(captured["cleanup_attempted"], True)
            self.assertEqual(payload["status"], "fail_closed")
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "pass")
            self.assertIs(cleanup["candidate_port_closed"], True)

    def test_persistent_runner_success_rejection_fails_when_candidate_gateway_remains_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_process_group = MODULE._terminate_process_group
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            try:
                MODULE._run = lambda *args, **kwargs: self._attach_valid_process_cleanup(Proc())
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: (_ for _ in ()).throw(
                    MODULE.ProbeError("contradictory receipt")
                )
                MODULE._wait_for_loopback_port_closed = lambda port: False
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                MODULE._terminate_process_group = lambda proc: True
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "candidate process cleanup remained incomplete",
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertIs(cleanup["candidate_port_closed"], False)

    def test_persistent_runner_success_rejection_fails_on_tracked_descendant_survival(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / MODULE.PERSISTENT_LIFECYCLE_RUNNER
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("// runner\n", encoding="utf-8")
            output = root / "evidence.json"
            original_run = MODULE._run
            original_git = MODULE._git
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_persistent_lifecycle_summary = MODULE._persistent_lifecycle_summary
            original_run_independent_validator = MODULE._run_independent_validator
            original_bind_parent_transcript = (
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript
            )
            original_wait_for_loopback_port_closed = MODULE._wait_for_loopback_port_closed
            original_terminate_and_verify_process_group = (
                MODULE._terminate_and_verify_process_group
            )

            class Proc:
                returncode = 0
                stdout = "runner stdout"
                stderr = "runner stderr"

            proc = self._attach_valid_process_cleanup(Proc())
            proc._agentic_os_process_cleanup["descendant_identities"] = [
                {
                    "pid": 234567,
                    "uid": os.getuid(),
                    "start_id": "detached-start",
                }
            ]

            try:
                MODULE._run = lambda *args, **kwargs: proc
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: VALID_RUNTIME_HEAD
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: (_ for _ in ()).throw(
                    MODULE.ProbeError("contradictory receipt")
                )
                MODULE._wait_for_loopback_port_closed = lambda port: True
                cleanup_results = iter(((True, True), (True, False)))
                MODULE._terminate_and_verify_process_group = lambda proc: next(
                    cleanup_results
                )
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    lambda **kwargs: None
                )
                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "candidate process cleanup remained incomplete",
                ):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head=VALID_RUNTIME_HEAD,
                        agentic_sources=[],
                        runtime_sources=[],
                        run_root=root / "run",
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        run_id="run-id",
                        transition_id="transition-id",
                    )
            finally:
                MODULE._run = original_run
                MODULE._git = original_git
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._persistent_lifecycle_summary = original_persistent_lifecycle_summary
                MODULE._run_independent_validator = original_run_independent_validator
                MODULE._bind_probe_parent_lifecycle_gateway_rpc_transcript = (
                    original_bind_parent_transcript
                )
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_and_verify_process_group = (
                    original_terminate_and_verify_process_group
                )

            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_validation_process_group_cleanup"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertIs(cleanup["candidate_port_closed"], True)
            self.assertIs(cleanup["tracked_cleanup_available"], True)
            self.assertIs(cleanup["all_candidate_processes_reaped"], False)

    def test_immutable_runtime_source_root_preserves_package_symlink_topology(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_root = root / "node_modules/.pnpm/pkg@1/node_modules/pkg"
            package_root.mkdir(parents=True)
            package_link = root / "node_modules/pkg"
            package_link.symlink_to(".pnpm/pkg@1/node_modules/pkg", target_is_directory=True)
            execution_root = MODULE._require_immutable_runtime_source_root(root, [])

            self.assertEqual(execution_root, root)
            self.assertTrue((execution_root / "node_modules/pkg").is_symlink())
            self.assertEqual(
                (execution_root / "node_modules/pkg").resolve(), package_root.resolve()
            )

    def test_immutable_runtime_source_root_rejects_hardlinked_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.mjs"
            source.write_text("export const value = 1;\n", encoding="utf-8")
            os.link(source, root / "outside-alias.mjs")

            with self.assertRaisesRegex(MODULE.ProbeError, "hardlink"):
                MODULE._require_immutable_runtime_source_root(
                    root,
                    [{"path": "main.mjs", "sha256": "a" * 64}],
                )

    def test_persistent_runtime_source_root_requires_external_read_only_mount(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            simulated_statvfs = MODULE.os.statvfs
            MODULE.os.statvfs = self._original_statvfs
            try:
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "externally enforced read-only runtime source mount"
                ):
                    MODULE._require_immutable_runtime_source_root(root, [])
            finally:
                MODULE.os.statvfs = simulated_statvfs

    def test_persistent_lifecycle_requires_external_trusted_boundary(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ProbeError,
            "persistent lifecycle authority is disabled",
        ):
            self._original_require_trusted_persistent_lifecycle_boundary()

    def test_persistent_runtime_source_closure_uses_module_sync_require_condition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "require('fixture-runtime');\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": {
                                ".": {
                                    "module-sync": "./module-sync.cjs",
                                    "require": "./require.cjs",
                                }
                            },
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/module-sync.cjs": (
                        "module.exports = { selected: 'module-sync' };\n"
                    ),
                    "node_modules/fixture-runtime/require.cjs": (
                        "module.exports = { selected: 'require' };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/module-sync.cjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/require.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_inline_require_child_process(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "require('node:child_process').execFileSync("
                        "process.execPath, ['./hidden.cjs']);\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "inline require child-process",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_bracketed_inline_require_child_process(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "require('node:child_process')['execFileSync']("
                        "process.execPath, ['./hidden.cjs']);\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "inline require child-process",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_template_inline_require_child_process(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "require('node:child_process')[`execFileSync`]("
                        "process.execPath, ['./hidden.cjs']);\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "computed inline require child-process",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_bracketed_inline_create_require(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "require('node:module')['createRequire'](__filename)"
                        "('./hidden.cjs');\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "computed inline require module member",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_binds_whitespace_free_static_imports(
        self,
    ) -> None:
        for source in (
            "import'./hidden.mjs';\n",
            "import*as hidden from'./hidden.mjs';\n",
            "export*from'./hidden.mjs';\n",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.mjs": "export const hidden = true;\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("scripts/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_ignores_static_import_text_in_data(
        self,
    ) -> None:
        for source in (
            "const grammar = /import'not-a-package'/;\n",
            "const grammar = \"import'not-a-package'\";\n",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {MODULE.PERSISTENT_LIFECYCLE_RUNNER: source},
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertNotIn("node_modules/not-a-package", paths)

    def test_persistent_runtime_source_closure_preserves_regex_before_static_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const grammar = /[/*]/; import './hidden.mjs';\n"
                    ),
                    "scripts/hidden.mjs": "export const hidden = true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_uses_module_sync_import_condition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import runtime from 'fixture-runtime';\n"
                    ),
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": {
                                ".": {
                                    "module-sync": "./module-sync.mjs",
                                    "import": "./import.mjs",
                                }
                            },
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/module-sync.mjs": (
                        "export default 'module-sync';\n"
                    ),
                    "node_modules/fixture-runtime/import.mjs": (
                        "export default 'import';\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/module-sync.mjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/import.mjs", paths)


    def test_persistent_runtime_source_closure_rejects_indirect_create_require_factory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = (createRequire)("
                        "new URL('../alternate/base.mjs', import.meta.url));\n"
                        "load('./hidden.cjs');\n"
                    ),
                    "alternate/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "indirect createRequire factory invocation",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_import_after_postfix_operator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "let x = 1; x++ / import('fixture-runtime') / 2;\n"
                    ),
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {"name": "fixture-runtime", "exports": "./hidden.mjs"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/hidden.mjs": "export default true;\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "ambiguous JavaScript slash token",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_ignores_computed_require_in_string_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        'const doc = "require(\'node:module\')[\'createRequire\']";\n'
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn(MODULE.PERSISTENT_LIFECYCLE_RUNNER, paths)

    def test_persistent_runtime_source_closure_recognizes_all_line_comment_terminators(
        self,
    ) -> None:
        for terminator in ("\r", "\u2028", "\u2029"):
            with self.subTest(terminator=repr(terminator)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            f"// comment{terminator}import('fixture-runtime');\n"
                        ),
                        "node_modules/fixture-runtime/package.json": json.dumps(
                            {"name": "fixture-runtime", "exports": "./hidden.mjs"}
                        )
                        + "\n",
                        "node_modules/fixture-runtime/hidden.mjs": "export default true;\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("node_modules/fixture-runtime/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_uses_node_package_pattern_precedence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "package.json": json.dumps(
                        {
                            "name": "fixture-root",
                            "imports": {
                                "#*/bar": "./root-a.mjs",
                                "#foo/*": "./root-b.mjs",
                            },
                        }
                    )
                    + "\n",
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import 'fixture-runtime/foo/bar';\nimport '#foo/bar';\n"
                    ),
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": {
                                "./*/bar": "./external-a.mjs",
                                "./foo/*": "./external-b.mjs",
                            },
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/external-a.mjs": "export default 'a';\n",
                    "node_modules/fixture-runtime/external-b.mjs": "export default 'b';\n",
                    "root-a.mjs": "export default 'a';\n",
                    "root-b.mjs": "export default 'b';\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/external-b.mjs", paths)
        self.assertIn("root-b.mjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/external-a.mjs", paths)
        self.assertNotIn("root-a.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_encoded_package_export_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "import 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {"name": "fixture-runtime", "exports": "./%68idden.mjs"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/%68idden.mjs": "export default 'decoy';\n",
                    "node_modules/fixture-runtime/hidden.mjs": "export default 'real';\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported percent-encoded path",
            ):
                MODULE._persistent_runtime_source_paths(root)


    def test_persistent_runtime_source_closure_recognizes_trivia_comment_terminators(
        self,
    ) -> None:
        for terminator in ("\r", "\u2028", "\u2029"):
            with self.subTest(terminator=repr(terminator)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            f"import// comment{terminator}('./hidden.mjs');\n"
                        ),
                        "scripts/hidden.mjs": "export default true;\n",
                    },
                )

                paths = MODULE._persistent_runtime_source_paths(root)

            self.assertIn("scripts/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_nested_indirect_create_require_factory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { createRequire } from 'node:module';\n"
                        "const load = ((createRequire))("
                        "new URL('../alternate/base.mjs', import.meta.url));\n"
                        "load('./hidden.cjs');\n"
                    ),
                    "alternate/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "indirect createRequire factory invocation",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_encoded_package_import_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    "package.json": json.dumps(
                        {
                            "name": "fixture-root",
                            "imports": {"#x": "./%68idden.mjs"},
                        }
                    )
                    + "\n",
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "import '#x';\n",
                    "%68idden.mjs": "export default 'decoy';\n",
                    "hidden.mjs": "export default 'real';\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported percent-encoded path",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_ignores_inline_child_process_in_string_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        'const doc = "require(\'node:child_process\').execFileSync(";\n'
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn(MODULE.PERSISTENT_LIFECYCLE_RUNNER, paths)

    def test_persistent_runtime_source_closure_rejects_named_non_node_child_process_executable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawnSync } from 'node:child_process';\n"
                        "spawnSync('./hidden.sh');\n"
                    ),
                    "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported child-process Node entrypoint",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_named_run_main_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { runMain } from 'node:module';\n"
                        "runMain('./hidden.cjs');\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported CommonJS runtime loader",
            ):
                MODULE._persistent_runtime_source_paths(root)


    def test_persistent_runtime_source_closure_rejects_optional_and_grouped_run_main(
        self,
    ) -> None:
        cases = (
            "runMain?.('./hidden.cjs');\n",
            "(runMain)('./hidden.cjs');\n",
        )
        for invocation in cases:
            with self.subTest(invocation=invocation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            "import { runMain } from 'node:module';\n" + invocation
                        ),
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "unsupported CommonJS runtime loader",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_optional_and_grouped_child_process_aliases(
        self,
    ) -> None:
        cases = (
            "go?.('./hidden.sh');\n",
            "(go)('./hidden.sh');\n",
        )
        for invocation in cases:
            with self.subTest(invocation=invocation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            "import { spawnSync as go } from 'node:child_process';\n"
                            + invocation
                        ),
                        "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "unsupported child-process Node entrypoint",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_transferred_child_process_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawnSync } from 'node:child_process';\n"
                        "const go = spawnSync;\n"
                        "go('./hidden.sh');\n"
                    ),
                    "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported child-process Node entrypoint",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_indirect_child_process_alias_call(
        self,
    ) -> None:
        cases = {
            "call": "go.call(null, './hidden.sh');\n",
            "apply": "go.apply(null, ['./hidden.sh']);\n",
            "reflect_apply": "Reflect.apply(go, null, ['./hidden.sh']);\n",
        }
        for name, invocation in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                            "import { spawnSync as go } from 'node:child_process';\n"
                            + invocation
                        ),
                        "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "unsupported child-process Node entrypoint",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_tracks_default_worker_threads_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import wt from 'node:worker_threads';\n"
                        "new wt.Worker(new URL('./hidden.mjs', import.meta.url));\n"
                    ),
                    "scripts/hidden.mjs": "export default true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_url_suffixed_package_export_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "import 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {"name": "fixture-runtime", "exports": "./real.mjs?x"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/real.mjs": "export default 'real';\n",
                    "node_modules/fixture-runtime/real.mjs?x": "export default 'decoy';\n",
                },
            )

            with self.assertRaisesRegex(MODULE.ProbeError, "unsupported URL suffix"):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_non_relative_package_export_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "import 'fixture-runtime';\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {
                            "name": "fixture-runtime",
                            "exports": ["not-relative", "./hidden.mjs"],
                        }
                    )
                    + "\n",
                    "node_modules/fixture-runtime/not-relative": "export default 'decoy';\n",
                    "node_modules/fixture-runtime/hidden.mjs": "export default 'real';\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "package export target is unsupported",
            ):
                MODULE._persistent_runtime_source_paths(root)


    def test_persistent_runtime_source_closure_tracks_combined_default_worker_threads_import(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import wt, { Worker } from 'node:worker_threads';\n"
                        "new wt.Worker(new URL('./hidden.mjs', import.meta.url));\n"
                    ),
                    "scripts/hidden.mjs": "export default true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/hidden.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_nested_grouped_child_process_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawnSync as go } from 'node:child_process';\n"
                        "((go))('./hidden.sh');\n"
                    ),
                    "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported child-process Node entrypoint",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_escaped_child_process_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import { spawnSync as g\\u006f } from 'node:child_process';\n"
                        "g\\u006f('./hidden.sh');\n"
                    ),
                    "scripts/hidden.sh": "#!/bin/sh\nexit 0\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported child-process Node entrypoint",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_preserves_unicode_escapes_in_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "// \\u000a[].filter.constructor('hidden')();\n"
                        "const quoted = \"\\u0022; [].filter.constructor('hidden')();//\";\n"
                        "const raw = `\\u0060; [].filter.constructor('hidden')();//`;\n"
                        "const pattern = /\\u002f [].filter.constructor('hidden')/;\n"
                        "export { quoted, raw, pattern };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn(MODULE.PERSISTENT_LIFECYCLE_RUNNER, paths)

    def test_persistent_runtime_source_closure_handles_combined_child_process_imports(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import cp, { spawnSync as runNode } from 'node:child_process';\n"
                        "runNode(process.execPath, ['./combined-child.mjs']);\n"
                    ),
                    "combined-child.mjs": "export const child = true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("combined-child.mjs", paths)

    def test_persistent_runtime_source_closure_rejects_combined_child_process_default(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import cp, { spawnSync } from 'node:child_process';\n"
                        "cp.execSync(process.execPath + ' ./hidden.cjs');\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "shell child-process entrypoint",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_combined_node_module_imports(
        self,
    ) -> None:
        cases = {
            "named_run_main": (
                "import moduleApi, { runMain } from 'node:module';\n"
                "runMain('./hidden.cjs');\n"
            ),
            "default_run_main": (
                "import moduleApi, { createRequire } from 'node:module';\n"
                "moduleApi.runMain('./hidden.cjs');\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "CommonJS runtime loader",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_module_instance_load(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import M from 'node:module';\n"
                        "new M().load('./hidden.cjs');\n"
                    ),
                    "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "CommonJS runtime loader",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_dynamic_execution_builtins(
        self,
    ) -> None:
        cases = {
            "child_process": "await import('node:child_process');\n",
            "node_module": "await import('node:module');\n",
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {MODULE.PERSISTENT_LIFECYCLE_RUNNER: source},
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "dynamic .*execution capability|dynamic CommonJS runtime loader",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_handles_string_named_child_process(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "const { 'spawnSync': runNode } = require('node:child_process');\n"
                        "runNode(process.execPath, ['./string-named-child.cjs']);\n"
                    ),
                    "string-named-child.cjs": (
                        "module.exports = { child: true };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("string-named-child.cjs", paths)

    def test_persistent_runtime_source_closure_rejects_indirect_commonjs_require(
        self,
    ) -> None:
        cases = {
            "require_call": "require.call(null, './hidden.cjs');\n",
            "reflect_apply": "Reflect.apply(require, null, ['./hidden.cjs']);\n",
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_runtime_source_fixture(
                    root,
                    {
                        MODULE.PERSISTENT_LIFECYCLE_RUNNER: source,
                        "scripts/hidden.cjs": "module.exports = { hidden: true };\n",
                    },
                )

                with self.assertRaisesRegex(
                    MODULE.ProbeError,
                    "indirect CommonJS require invocation",
                ):
                    MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_rejects_encoded_bare_package_subpath(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: (
                        "import 'fixture-runtime/%68idden.mjs';\n"
                    ),
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {"name": "fixture-runtime"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/%68idden.mjs": (
                        "export default 'decoy';\n"
                    ),
                    "node_modules/fixture-runtime/hidden.mjs": (
                        "export default 'real';\n"
                    ),
                },
            )

            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "unsupported percent-encoded path",
            ):
                MODULE._persistent_runtime_source_paths(root)

    def test_persistent_runtime_source_closure_resolves_commonjs_package_subdirectory_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "require('fixture-runtime/subdir');\n",
                    "node_modules/fixture-runtime/package.json": json.dumps(
                        {"name": "fixture-runtime"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/subdir/package.json": json.dumps(
                        {"main": "hidden.cjs"}
                    )
                    + "\n",
                    "node_modules/fixture-runtime/subdir/index.js": (
                        "module.exports = { decoy: true };\n"
                    ),
                    "node_modules/fixture-runtime/subdir/hidden.cjs": (
                        "module.exports = { real: true };\n"
                    ),
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("node_modules/fixture-runtime/subdir/package.json", paths)
        self.assertIn("node_modules/fixture-runtime/subdir/hidden.cjs", paths)
        self.assertNotIn("node_modules/fixture-runtime/subdir/index.js", paths)

    def test_persistent_runtime_source_closure_recurses_into_jsx_dependencies(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_runtime_source_fixture(
                root,
                {
                    MODULE.PERSISTENT_LIFECYCLE_RUNNER: "import './view.jsx';\n",
                    "scripts/view.jsx": (
                        "import './view-model.mjs';\n"
                        "export const View = () => <div />;\n"
                    ),
                    "scripts/view-model.mjs": "export const model = true;\n",
                },
            )

            paths = MODULE._persistent_runtime_source_paths(root)

        self.assertIn("scripts/view.jsx", paths)
        self.assertIn("scripts/view-model.mjs", paths)


if __name__ == "__main__":
    unittest.main()
