from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
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

    def tearDown(self) -> None:
        if self._previous_validation_anchor is None:
            os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
        else:
            os.environ[MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = (
                self._previous_validation_anchor
            )

    def _valid_persistent_receipt(self) -> dict:
        now_ms = int(time.time() * 1000)
        return {
            "status": "pass",
            "immutable_inputs": {
                "runtime_head": "openclaw-head",
                "agentic_os_head": "agentic-head",
                "contract_vector_sha256": "9" * 64,
                "run_id": "run-id",
                "transition_id": "transition-id",
            },
            "production_before": {
                "config_sha256": "0" * 64,
                "health": {"reachable": False},
            },
            "production_after": {
                "config_sha256": "0" * 64,
                "health": {"reachable": False},
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
                "contract_vector_sha256": "9" * 64,
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
                "duplicate_release_sha256": "3" * 64,
                "sessions_list_count": 1,
                "matching_session_count": 1,
            },
            "rollback": {
                "status": "pass",
                "candidate_port_closed": True,
                "production_config_hash_unchanged": True,
                "production_health_before_sha256": "4" * 64,
                "production_health_after_sha256": "5" * 64,
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

    def _write_persistent_receipts(
        self,
        run_root: Path,
        receipt: dict,
        validation: dict | None = None,
        tools_catalog_response: dict | None = None,
        persistent_evidence_transform=None,
    ) -> tuple[Path, Path]:
        receipts = run_root / "receipts"
        receipts.mkdir(parents=True)
        now_ms = int(time.time() * 1000)
        signed_payload = {
            "issued_at_epoch_ms": now_ms - 1_000,
            "expires_at_epoch_ms": receipt["attestation"]["expires_at_epoch_ms"],
            "runtime_identity_token_sha256": "d" * 64,
            "rpc_transcript_sha256": "a" * 64,
            "binding": {
                "executable": {"content_sha256": "7" * 64},
                "catalog": {
                    "sha256": "8" * 64,
                    "contract_vector_sha256": "9" * 64,
                },
                "gateway": {
                    "endpoint": f"ws://127.0.0.1:{MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT}",
                    "build_id": "06e6e3f",
                },
            },
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
                "response": {"leases": []},
                "raw_response_sha256": MODULE._canonical_sha256({"leases": []}),
            },
        }
        expected_transcript_sha256 = MODULE._canonical_sha256(
            {
                "schema_version": "agentic-os.persistent-rpc-transcript.v1",
                "records": [
                    {
                        "key": key,
                        "method": rpc_evidence[key]["method"],
                        "request_params": {},
                        "raw_response_sha256": rpc_evidence[key]["raw_response_sha256"],
                    }
                    for key in ("tools_catalog", "allow_lease_status")
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
                "request_params": {
                    "expected_executable_sha256": "7" * 64,
                    "expected_catalog_sha256": "8" * 64,
                },
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
    ):
        run_root = root / "run"
        receipt_file, validation_file = self._write_persistent_receipts(
            run_root,
            receipt,
            validation,
            tools_catalog_response=tools_catalog_response,
            persistent_evidence_transform=persistent_evidence_transform,
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
                command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                proc=Proc(),
                port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                expected_run_id="run-id",
                expected_transition_id="transition-id",
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

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240):
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

    def test_runner_does_not_advertise_disabled_adapter_probe_to_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            original_run = MODULE._run
            original_validate_candidate_root = MODULE.validate_candidate_root
            original_candidate_probe_mode = MODULE._candidate_probe_mode
            original_source_binding = MODULE._source_binding
            original_validate_sources = MODULE._validate_sources
            original_git = MODULE._git

            class Proc:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(command, *, cwd, env=None, timeout=240):
                self.assertIsNotNone(env)
                self.assertNotIn("AGENTIC_OS_REAL_ADAPTER_PROBE_SCRIPT", env)
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

    def test_candidate_probe_mode_fails_without_supported_harness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODULE.ProbeError, "neither"):
                MODULE._candidate_probe_mode(Path(directory))

    def test_persistent_summary_rejects_validation_receipt_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            validation = {"status": "pass", "receipt_sha256": "a" * 64}
            with self.assertRaisesRegex(MODULE.ProbeError, "not bound"):
                self._call_persistent_summary(Path(directory), receipt, validation)

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

    def test_persistent_summary_rejects_missing_matching_session_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = self._valid_persistent_receipt()
            receipt["lifecycle"]["matching_session_count"] = 0
            with self.assertRaisesRegex(MODULE.ProbeError, "matching accepted session"):
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
        for value in (None, 1):
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
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
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
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
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
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
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
                        command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                        proc=type("Proc", (), {"stdout": "", "stderr": "", "returncode": 0})(),
                        port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                        expected_run_id="run-id",
                        expected_transition_id="transition-id",
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

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                self.assertIsNotNone(env)
                self.assertIs(start_new_session, True)
                captured_env.update(env)
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
        self.assertNotIn("OPENAI_API_KEY", captured_env)
        self.assertNotIn("NODE_OPTIONS", captured_env)
        self.assertNotIn(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, captured_env)
        self.assertNotIn(
            MODULE.PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV, captured_env
        )
        self.assertEqual(
            captured_validator["validation_file"],
            run_root.resolve() / "receipts" / "independent-validation.json",
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
            key_path.parent.mkdir(mode=0o700)
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
                MODULE._run_independent_validator(
                    run_root=run_root,
                    receipt_file=receipt_file,
                    validation_file=validation_file,
                    timeout=5,
                )

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

    def test_validator_env_consumes_private_attestation_key_and_separates_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, mode=0o700)
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
                validator_env = MODULE._validator_env(run_root=run_root)

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
                key_path.parent.mkdir(parents=True, mode=0o700)
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
                        MODULE._validator_env(run_root=run_root)

    def test_validator_env_rejects_key_swapped_to_symlink_before_no_follow_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, mode=0o700)
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

            with mock.patch.object(MODULE.os, "open", swap_before_key_open), mock.patch.dict(
                os.environ,
                {
                    MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV: (
                        VALIDATION_ANCHOR_HMAC_SECRET_HEX
                    )
                },
            ):
                with self.assertRaisesRegex(MODULE.ProbeError, "unsafe|unavailable"):
                    MODULE._validator_env(run_root=run_root)
            self.assertTrue(swapped)

    def test_validator_env_fails_explicitly_when_validation_anchor_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, mode=0o700)
            os.chmod(run_root, 0o700)
            os.chmod(key_path.parent, 0o700)
            key_path.write_bytes(ATTESTATION_HMAC_SECRET)
            os.chmod(key_path, 0o600)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                with self.assertRaisesRegex(
                    MODULE.ProbeError, "validation anchor.*unavailable"
                ):
                    MODULE._validator_env(run_root=run_root)
            self.assertFalse(key_path.exists())

    def test_validator_env_rejects_reused_key_material_across_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_root = Path(directory) / "run"
            key_path = run_root / MODULE.PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH
            key_path.parent.mkdir(parents=True, mode=0o700)
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
                    MODULE._validator_env(run_root=run_root)

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

    def test_persistent_runner_fails_before_launch_when_validation_anchor_is_missing(
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
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop(MODULE.PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV, None)
                    with self.assertRaisesRegex(
                        MODULE.ProbeError, "validation anchor.*unavailable"
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

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["start_new_session"] = start_new_session
                raise MODULE.subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output="runner stdout",
                    stderr="runner stderr",
                )

            try:
                MODULE._run = fake_run
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: True
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

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIs(captured["start_new_session"], True)
            self.assertEqual(payload["status"], "fail_closed")
            self.assertIs(
                payload["isolated_non_production_gateway"]["candidate_port_closed"],
                True,
            )
            self.assertIn("timeout_process_group_cleanup", json.dumps(payload, sort_keys=True))

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

            class Proc:
                returncode = 1
                stdout = "runner stdout"
                stderr = "runner stderr"

            def fake_run(command, *, cwd, env=None, timeout=240, start_new_session=False):
                captured["start_new_session"] = start_new_session
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

            class Proc:
                returncode = 1
                stdout = "runner stdout"
                stderr = "runner stderr"

            try:
                MODULE._run = lambda *args, **kwargs: Proc()
                MODULE._git = lambda git_root, *args: "agentic-head"
                MODULE._wait_for_loopback_port_closed = lambda port: False
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
                MODULE._wait_for_loopback_port_closed = original_wait_for_loopback_port_closed
                MODULE._terminate_process_group = original_terminate_process_group

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

            payload = json.loads(output.read_text(encoding="utf-8"))
            cleanup = next(
                item
                for item in payload["fail_closed_matrix"]
                if item["check"] == "post_success_port_closure"
            )
            self.assertEqual(cleanup["status"], "fail")
            self.assertIs(cleanup["candidate_port_closed"], False)

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
