from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("real_gateway_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real Gateway probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RealGatewayProbeTests(unittest.TestCase):
    def test_requires_running_and_completed_lifecycle_proofs(self) -> None:
        self.assertIn("lifecycle_running_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("lifecycle_completed_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("lifecycle_failure_observed", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("duplicate_release_identity_parity", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn("agentic_adapter_live_catalog", MODULE.REQUIRED_RUNTIME_PROOFS)
        self.assertIn(
            "agentic_adapter_duplicate_release_parity", MODULE.REQUIRED_RUNTIME_PROOFS
        )
        self.assertIn(
            "agentic_adapter_release_metadata_parity", MODULE.REQUIRED_RUNTIME_PROOFS
        )
        self.assertIn(
            "agentic_adapter_post_release_absent", MODULE.REQUIRED_RUNTIME_PROOFS
        )

    def test_binds_merged_adapter_and_composed_probe_sources(self) -> None:
        self.assertIn(
            "scripts/openclaw-real-adapter-release-probe.py",
            MODULE.AGENTIC_SOURCE_PATHS,
        )
        self.assertIn("src/agentic_os/openclaw_adapter.py", MODULE.AGENTIC_SOURCE_PATHS)
        self.assertIn("src/agentic_os/metadata.py", MODULE.AGENTIC_SOURCE_PATHS)

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
            original_source_binding = MODULE._source_binding
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
                MODULE._source_binding = original_source_binding
                MODULE._git = original_git

    def test_rejects_local_absolute_path_value(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw value"):
            MODULE._walk_evidence({"error": "/Users/example/private"})

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
            with self.assertRaisesRegex(MODULE.ProbeError, "real Gateway E2E"):
                MODULE.validate_candidate_root(root)


if __name__ == "__main__":
    unittest.main()
