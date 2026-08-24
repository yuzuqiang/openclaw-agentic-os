from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import get_type_hints


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("real_gateway_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real Gateway probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RealGatewayProbeTests(unittest.TestCase):
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

    def test_persistent_lifecycle_summary_is_phase_b_snapshot_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            receipts = run_root / "receipts"
            receipts.mkdir(parents=True)
            receipt_file = receipts / "lifecycle-receipt.json"
            validation_file = receipts / "independent-validation.json"
            receipt = {
                "status": "pass",
                "immutable_inputs": {
                    "runtime_head": "openclaw-head",
                    "agentic_os_head": "agentic-head",
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
                },
                "lifecycle": {
                    "status": "pass",
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
                "runtime_launch": {"token_sha256": "6" * 64},
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
            validation = {"status": "pass", "receipt_sha256": "a" * 64}
            receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
            validation_file.write_text(json.dumps(validation), encoding="utf-8")
            original_git = MODULE._git

            class Proc:
                stdout = "runner stdout"
                stderr = "runner stderr"
                returncode = 0

            try:
                MODULE._git = lambda git_root, *args: "agentic-head"
                payload = MODULE._persistent_lifecycle_summary(
                    openclaw_root=root,
                    run_root=run_root,
                    receipt_file=receipt_file,
                    validation_file=validation_file,
                    head="openclaw-head",
                    agentic_sources=[{"path": "agentic.py", "sha256": "0" * 64}],
                    runtime_sources=[{"path": "runtime.ts", "sha256": "1" * 64}],
                    command=["node", MODULE.PERSISTENT_LIFECYCLE_RUNNER],
                    proc=Proc(),
                    port=MODULE.PERSISTENT_LIFECYCLE_DEFAULT_PORT,
                )
            finally:
                MODULE._git = original_git

        self.assertEqual(payload["status"], "pass")
        self.assertFalse(payload["runtime_ready"])
        self.assertTrue(payload["runtime_ready_candidate_evidence"])
        self.assertTrue(payload["runtime_ready_blocked_until_phase_c"])
        self.assertFalse(payload["db_authority_enabled"])
        self.assertNotIn("/private", json.dumps(payload, sort_keys=True))
        self.assertNotIn("runner stdout", json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
