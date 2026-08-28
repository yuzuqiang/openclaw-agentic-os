from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import time
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

    def tearDown(self) -> None:
        MODULE._runtime_launch_bindings = self._original_runtime_launch_bindings
        if self._previous_validation_anchor is None:
            os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
        else:
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                self._previous_validation_anchor
            )

    def _validator_env_for_path(
        self,
        run_root: Path,
        validation_anchor_key: bytes,
    ) -> dict[str, str]:
        pinned = MODULE._pin_prepared_run_root(run_root.resolve())
        try:
            return MODULE._validator_env(
                run_root=pinned,
                validation_anchor_key=validation_anchor_key,
            )
        finally:
            pinned.close()

    def _valid_persistent_receipt(self) -> dict:
        now_ms = int(time.time() * 1000)
        production_health = {"reachable": False}
        production_health_sha256 = MODULE._canonical_sha256(production_health)
        contract_vector_sha256 = MODULE._expected_persistent_contract_vector_sha256()
        return {
            "status": "pass",
            "immutable_inputs": {
                "runtime_head": "openclaw-head",
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
                "gateway_build_id": "06e6e3f",
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

    def _valid_runtime_launch_sources(self) -> list[dict[str, str]]:
        return [
            {
                "path": label,
                "sha256": format(index + 10, "x") * 64,
                "realpath_sha256": format(index + 13, "x") * 64,
            }
            for index, label in enumerate(MODULE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS)
        ]

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
    ) -> tuple[Path, Path]:
        receipts = run_root / "receipts"
        receipts.mkdir(parents=True)
        now_ms = int(time.time() * 1000)
        source_records = [{"path": "openclaw.mjs", "sha256": "7" * 64}]
        request_params = {
            "challenge": "challenge-1",
            "client_process_id": "persistent-runner:unit-test",
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
                    "path_sha256": "6" * 64,
                    "content_sha256": "7" * 64,
                },
                "install": {
                    "root_sha256": "5" * 64,
                    "package_json_sha256": "4" * 64,
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
                    "build_id": "06e6e3f",
                    "process_identity": "gateway-process:test",
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
        }
        expected_transcript_sha256 = MODULE._canonical_sha256(
            {
                "schema_version": MODULE.PERSISTENT_RPC_TRANSCRIPT_SCHEMA_VERSION,
                "records": [
                    {
                        "key": key,
                        "method": rpc_evidence[key]["method"],
                        "request_params": {},
                        "raw_response_sha256": rpc_evidence[key]["raw_response_sha256"],
                    }
                    for key in (
                        "tools_catalog",
                        "allow_lease_status",
                    )
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
            "expected_runtime_head": "openclaw-head",
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
            }
            validation["authentication"] = {
                "scheme": "hmac-sha256-env",
                "key_env": MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
                "signature": hmac.new(
                    VALIDATION_ANCHOR_HMAC_SECRET,
                    MODULE._canonical_json_bytes(MODULE._authentication_payload(validation)),
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
    ):
        run_root = root / "run"
        receipt_file, validation_file = self._write_persistent_receipts(
            run_root,
            receipt,
            validation,
            tools_catalog_response=tools_catalog_response,
            persistent_evidence_transform=persistent_evidence_transform,
            preflight_evidence_transform=preflight_evidence_transform,
        )
        original_git = MODULE._git

        class Proc:
            stdout = "runner stdout"
            stderr = "runner stderr"
            returncode = 0

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
                head="openclaw-head",
                agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
                runtime_launch_sources=self._valid_runtime_launch_sources(),
                command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                proc=Proc(),
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
        self.assertIn("src/agentic_os/openclaw_adapter.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/runtime_attestation.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/metadata.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/__init__.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertFalse(hasattr(MODULE, "ADAPTER_PROBE"))

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
                return Proc()

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
                return Proc()

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
                return Proc()

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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                                        "request_params": {},
                                        "raw_response_sha256": payload["rpc_evidence"][key][
                                            "raw_response_sha256"
                                        ],
                                    }
                                    for key in ("tools_catalog", "allow_lease_status")
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
            with self.assertRaisesRegex(MODULE.ProbeError, "duplicate acquire lease"):
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
            with self.assertRaisesRegex(MODULE.ProbeError, "primary release status"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_arbitrary_duplicate_release_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["duplicate_release_sha256"] = "4" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "duplicate release response"):
                self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_mismatched_duplicate_release_identity(self) -> None:
        for key, message in (
            ("duplicate_release_gateway_lease_id_sha256", "Gateway lease id"),
            ("duplicate_release_owner_metadata_sha256", "owner metadata"),
            ("duplicate_release_idempotency_key_sha256", "idempotency key"),
        ):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    receipt["lifecycle"][key] = "6" * 64
                    with self.assertRaisesRegex(MODULE.ProbeError, message):
                        self._call_persistent_summary(Path(directory), receipt)

    def test_persistent_summary_rejects_release_identity_not_acquired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["release_gateway_lease_id_sha256"] = "6" * 64
            receipt["lifecycle"]["duplicate_release_gateway_lease_id_sha256"] = "6" * 64
            with self.assertRaisesRegex(MODULE.ProbeError, "acquired lease"):
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
                    with self.assertRaisesRegex(MODULE.ProbeError, "matching accepted session"):
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
        for value in (None, 0, True, 1.0):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    receipt = self._valid_persistent_receipt()
                    if value is None:
                        del receipt["lifecycle"]["sessions_list_count"]
                    else:
                        receipt["lifecycle"]["sessions_list_count"] = value
                    with self.assertRaisesRegex(MODULE.ProbeError, "sessions list count"):
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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                    "runtimeMethods": [
                        {"name": name}
                        for name in MODULE.PERSISTENT_REQUIRED_TOOL_NAMES
                        if name != "agenticOs.runtime.attest"
                    ],
                },
            )
            self.assertTrue(payload["runtime_catalog_discovered"])
            self.assertEqual(
                sorted(payload["required_tool_names"]),
                sorted(MODULE.PERSISTENT_REQUIRED_TOOL_NAMES),
            )
            self.assertEqual(
                payload["lifecycle_attestation"]["record_transport"],
                "non_rpc_pinned_run_root_receipt",
            )
            self.assertEqual(
                payload["lifecycle_attestation"]["signed_by"],
                "independent_validation_hmac",
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
                        head="openclaw-head",
                        agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                        runtime_sources=[{"path": "openclaw.mjs", "sha256": "7" * 64}],
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
                return Proc()

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
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
                    head="openclaw-head",
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
        self.assertNotIn(
            MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, captured_env
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
                return Proc()

            def fake_validator(**kwargs):
                captured["validator_calls"] = int(captured.get("validator_calls", 0)) + 1
                captured["validation_anchor_key"] = kwargs["validation_anchor_key"]
                captured["validator_env"] = MODULE._validator_env(
                    run_root=kwargs["pinned_run_root"],
                    validation_anchor_key=kwargs["validation_anchor_key"],
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

            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                MODULE.secrets,
                "token_bytes",
                return_value=VALIDATION_ANCHOR_HMAC_SECRET,
            ), mock.patch.object(
                MODULE, "validate_candidate_root", return_value="openclaw-head"
            ), mock.patch.object(
                MODULE, "_candidate_probe_mode", return_value="persistent_lifecycle"
            ), mock.patch.object(
                MODULE, "_source_bindings", return_value=[]
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
            runner_env = captured["runner_env"]
            self.assertIsInstance(runner_env, dict)
            self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, runner_env)
            self.assertNotIn(
                MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, runner_env
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
            original_source_bindings = MODULE._source_bindings
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
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
                MODULE._candidate_probe_mode = lambda candidate_root: "persistent_lifecycle_runner"
                MODULE._source_bindings = lambda *args, **kwargs: []
                MODULE._run_persistent_lifecycle_probe = fake_run_persistent
                MODULE.run_probe(root, evidence_file, timeout=1)
                MODULE.run_probe(root, evidence_file, timeout=1)
            finally:
                MODULE.validate_candidate_root = original_validate_candidate_root
                MODULE._candidate_probe_mode = original_candidate_probe_mode
                MODULE._source_bindings = original_source_bindings
                MODULE._run_persistent_lifecycle_probe = original_run_persistent

        self.assertEqual(len(captured["run_roots"]), 2)
        self.assertNotEqual(captured["run_roots"][0], captured["run_roots"][1])
        for run_root in captured["run_roots"]:
            run_root = run_root.resolve()
            self.assertNotIn("runtime-evidence", run_root.parts)
            self.assertFalse(str(run_root).startswith(str(root.resolve())))
            self.assertEqual(run_root.stat().st_mode & 0o777, 0o700)

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
                ["allow_lease_status", "tools_catalog"],
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
                "non_rpc_pinned_run_root_receipt",
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
            source_binding = [
                {
                    "path": "scripts/openclaw-real-gateway-contract-probe.py",
                    "sha256": MODULE._sha256_bytes(MODULE.SCRIPT.read_bytes())
                    if hasattr(MODULE, "SCRIPT")
                    else MODULE._sha256_bytes(
                        (
                            MODULE.ROOT
                            / "scripts/openclaw-real-gateway-contract-probe.py"
                        ).read_bytes()
                    ),
                }
            ]
            try:
                with mock.patch.object(
                    MODULE,
                    "_source_bindings",
                    return_value=source_binding,
                ):
                    MODULE._run_independent_validator(
                        validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        pinned_run_root=pinned,
                        agentic_sources=source_binding,
                        timeout=5,
                    )
            finally:
                pinned.close()

            validation = json.loads(validation_file.read_text(encoding="utf-8"))
            self.assertTrue(validation["attestation_signature_verified"])
            self.assertTrue(validation["attestation_verification"]["verified"])
            self.assertFalse(key_path.exists())
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

    def test_validator_env_consumes_private_attestation_key_and_separates_domains(self) -> None:
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
            self.assertFalse(key_path.exists())

    def test_validator_env_rejects_unsafe_attestation_key_files(self) -> None:
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
                    with self.assertRaisesRegex(MODULE.ProbeError, "unsafe|weak"):
                        self._validator_env_for_path(
                            run_root,
                            validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        )

    def test_validator_env_rejects_key_swapped_to_symlink_before_no_follow_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            replacement = root / "replacement.key"
            replacement.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(replacement, 0o600)
            original_open = MODULE.os.open
            swapped = False

            def swap_before_key_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if (
                    not swapped
                    and path == MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH.name
                    and dir_fd is not None
                ):
                    key_path.unlink()
                    key_path.symlink_to(replacement)
                    swapped = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            pinned = MODULE._pin_prepared_run_root(run_root.resolve())
            with mock.patch.object(MODULE.os, "open", swap_before_key_open), mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    )
                },
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "unsafe|unavailable"):
                    try:
                        MODULE._validator_env(
                            run_root=pinned,
                            validation_anchor_key=VALIDATION_ANCHOR_HMAC_SECRET,
                        )
                    finally:
                        pinned.close()
            self.assertTrue(swapped)

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
            self.assertFalse(key_path.exists())

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
                            head="openclaw-head",
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
                        head="openclaw-head",
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
                return Proc()

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
                        head="openclaw-head",
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
                return Proc()

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
                        head="openclaw-head",
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
                MODULE, "validate_candidate_root", return_value="openclaw-head"
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
                        head="openclaw-head",
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

    def test_unattributed_candidate_era_process_is_killed_but_fails_closed(
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
        process_table_before = {
            pid: {
                "pid": pid,
                "ppid": 1,
                "pgid": pid,
                "uid": os.getuid(),
                "start_id": "escaped-start",
            }
        }

        with mock.patch.object(
            MODULE, "_process_table", side_effect=[process_table_before, {}]
        ), mock.patch.object(MODULE.os, "kill") as kill:
            self.assertTrue(MODULE._terminate_tracked_process_identities(cleanup))
            self.assertFalse(
                MODULE._wait_for_tracked_processes_reaped(
                    cleanup, timeout_seconds=0.0
                )
            )

        kill.assert_called_once_with(pid, MODULE.signal.SIGKILL)

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
                MODULE, "validate_candidate_root", return_value="openclaw-head"
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
                        head="openclaw-head",
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
                return Proc()

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
                        head="openclaw-head",
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
                    return Proc()

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
                            head="openclaw-head",
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
                return Proc()

            try:
                source_binding = [
                    {
                        "path": "scripts/openclaw-real-gateway-contract-probe.py",
                        "sha256": MODULE._sha256_bytes(
                            (
                                MODULE.ROOT
                                / "scripts/openclaw-real-gateway-contract-probe.py"
                            ).read_bytes()
                        ),
                    }
                ]
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
            self.assertEqual(command[7], "__persistent-validator")
            self.assertNotIn("bound-independent-validator.py", command[5])
            self.assertFalse(captured["copy_path_exists_during_launch"])
            for name in ("root", *MODULE.PINNED_RUN_SUBDIRECTORIES):
                self.assertIn(f"--{name}-fd", command)
                self.assertIn(f"--{name}-device", command)
                self.assertIn(f"--{name}-inode", command)

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
            source_binding = [
                {
                    "path": "scripts/openclaw-real-gateway-contract-probe.py",
                    "sha256": MODULE._sha256_bytes(
                        (
                            MODULE.ROOT
                            / "scripts/openclaw-real-gateway-contract-probe.py"
                        ).read_bytes()
                    ),
                }
            ]
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
            source_binding = [
                {
                    "path": "scripts/openclaw-real-gateway-contract-probe.py",
                    "sha256": MODULE._sha256_bytes(
                        (
                            MODULE.ROOT
                            / "scripts/openclaw-real-gateway-contract-probe.py"
                        ).read_bytes()
                    ),
                }
            ]
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
                        head="openclaw-head",
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
                MODULE._run = lambda *args, **kwargs: Proc()
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: False
                MODULE._terminate_process_group = lambda proc: True
                MODULE._wait_for_process_group_reaped = lambda proc: True
                with self.assertRaisesRegex(MODULE.ProbeError, "port remained open"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head="openclaw-head",
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
                MODULE._run = lambda *args, **kwargs: Proc()
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
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
                with self.assertRaisesRegex(MODULE.ProbeError, "candidate port remained open"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head="openclaw-head",
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
                with mock.patch.object(MODULE, "_run", return_value=Proc()), mock.patch.object(
                    MODULE, "_git", return_value="agentic-head"
                ), mock.patch.object(
                    MODULE, "validate_candidate_root", return_value="openclaw-head"
                ), mock.patch.object(
                    MODULE, "_runtime_launch_bindings", side_effect=bindings
                ), mock.patch.object(
                    MODULE, "_run_independent_validator", side_effect=unexpected_validator
                ), mock.patch.object(
                    MODULE, "_wait_for_loopback_port_closed", return_value=True
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
                            head="openclaw-head",
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
                MODULE._run = lambda *args, **kwargs: Proc()
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
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
                with self.assertRaisesRegex(MODULE.ProbeError, "remained open before cleanup"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head="openclaw-head",
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
                return Proc()

            def fake_terminate(proc):
                captured["cleanup_attempted"] = True
                return True

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: (_ for _ in ()).throw(
                    MODULE.ProbeError("contradictory receipt")
                )
                MODULE._wait_for_loopback_port_closed = lambda port: True
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                MODULE._terminate_process_group = fake_terminate
                with self.assertRaisesRegex(MODULE.ProbeError, "evidence was rejected"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head="openclaw-head",
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
                MODULE._run = lambda *args, **kwargs: Proc()
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE.validate_candidate_root = lambda candidate_root: "openclaw-head"
                MODULE._run_independent_validator = lambda **kwargs: None
                MODULE._persistent_lifecycle_summary = lambda **kwargs: (_ for _ in ()).throw(
                    MODULE.ProbeError("contradictory receipt")
                )
                MODULE._wait_for_loopback_port_closed = lambda port: False
                MODULE._terminate_and_verify_process_group = lambda proc: (True, True)
                MODULE._terminate_process_group = lambda proc: True
                with self.assertRaisesRegex(MODULE.ProbeError, "port remained open"):
                    MODULE._run_persistent_lifecycle_probe(
                        root,
                        output,
                        timeout=1,
                        head="openclaw-head",
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


if __name__ == "__main__":
    unittest.main()
