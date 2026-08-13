from __future__ import annotations

import json
import re
import unittest

import agentic_os
from agentic_os.migrations import repository_root


EVIDENCE_PATH = (
    "docs/runtime-evidence/phase-b-20260813-local-openclaw-tsgo-evidence-reuse.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PhaseBOpenClawEvidenceContractTests(unittest.TestCase):
    def _payload(self) -> dict:
        root = repository_root()
        return json.loads((root / EVIDENCE_PATH).read_text(encoding="utf-8"))

    def test_project_status_and_readme_point_to_contract(self) -> None:
        root = repository_root()
        status = json.loads((root / "docs/project-status.json").read_text(encoding="utf-8"))
        readme = (root / "README.md").read_text(encoding="utf-8")

        evidence = status["live_runtime_evidence"]["local_openclaw_dependency_evidence"]
        self.assertEqual(evidence["path"], EVIDENCE_PATH)
        self.assertEqual(
            evidence["status"],
            "local_deterministic_harness_pass_live_blacksmith_not_applicable",
        )
        self.assertEqual(evidence["implementation_focused_tests"], "pass")
        self.assertEqual(evidence["deterministic_production_path_proof"], "pass")
        self.assertEqual(evidence["live_blacksmith_status"], "unavailable_personal_repository")
        self.assertFalse(evidence["production_authority_enabled"])
        self.assertIn(EVIDENCE_PATH, readme)

    def test_contract_keeps_three_validation_outcomes_distinct(self) -> None:
        payload = self._payload()

        self.assertEqual(payload["schemaVersion"], 1)
        self.assertEqual(payload["repository"], "yuzuqiang/openclaw-agentic-os")
        self.assertEqual(
            payload["implementation_focused_tests"]["status"],
            "pass",
        )
        self.assertEqual(
            payload["deterministic_production_path_proof"]["status"],
            "pass",
        )
        self.assertEqual(
            payload["live_blacksmith"]["live_blacksmith_status"],
            "unavailable_personal_repository",
        )
        self.assertEqual(
            payload["live_blacksmith"]["classification"],
            "not_applicable_environment_limit_not_validation_pass",
        )
        self.assertFalse(payload["live_blacksmith"]["claimed_live_testbox_run"])
        self.assertFalse(payload["live_blacksmith"]["claimed_live_blacksmith_pass"])
        self.assertNotEqual(payload["live_blacksmith"]["live_blacksmith_status"], "pass")
        self.assertNotEqual(payload["live_blacksmith"]["live_blacksmith_status"], "fail")
        self.assertNotEqual(payload["live_blacksmith"]["live_blacksmith_status"], "mocked")

    def test_contract_binds_local_openclaw_patch_without_remote_authority(self) -> None:
        dependency = self._payload()["local_openclaw_dependency"]

        self.assertEqual(dependency["source_repository"], "openclaw/openclaw")
        self.assertTrue(dependency["local_only"])
        self.assertEqual(
            dependency["branch"],
            "local/agentic-os-tsgo-evidence-reuse-20260812",
        )
        self.assertEqual(
            dependency["head_sha"],
            "5ed61193b685e6d038621ed8985b67c5eaf6718d",
        )
        self.assertEqual(
            dependency["archive_head_sha"],
            "45cd11b118d1db353d6c5d4c5200bf9a43994ec7",
        )
        self.assertFalse(dependency["upstream_configured"])
        self.assertFalse(dependency["remote_push_allowed"])
        self.assertRegex(dependency["sync_payload_manifest_sha256"], SHA256_RE)

    def test_deterministic_proof_names_receipt_reuse_and_affected_rerun(self) -> None:
        proof = self._payload()["deterministic_production_path_proof"]

        self.assertEqual(
            proof["mechanism"],
            "production check-changed code path -> deterministic fake Crabbox remote-clone harness -> receipt import/reuse -> affected descendant rerun",
        )
        self.assertEqual(proof["harness"], "deterministic_test_harness_not_live_blacksmith")
        self.assertEqual(proof["remote_executor"], "fake_crabbox_runner")
        self.assertFalse(proof["live_remote_execution_claimed"])
        self.assertIn("receipt import/reuse", proof["mechanism"])
        self.assertIn("affected descendant rerun", proof["mechanism"])
        self.assertIn(
            "second fresh invocation launches zero duplicate native heavy children",
            proof["asserted_behaviors"],
        )
        self.assertIn(
            "affected descendant commit reruns the correct native lane",
            proof["asserted_behaviors"],
        )
        self.assertRegex(self._payload()["implementation_focused_tests"]["log_sha256"], SHA256_RE)
        self.assertRegex(self._payload()["implementation_focused_tests"]["timing_sha256"], SHA256_RE)

    def test_live_blacksmith_limitation_and_authority_boundary_fail_closed(self) -> None:
        payload = self._payload()
        live = payload["live_blacksmith"]
        authority = payload["authority_boundary"]

        self.assertEqual(
            live["official_limitation_statement"],
            "Blacksmith is limited to GitHub organizations and is not available for personal repositories.",
        )
        self.assertRegex(live["official_limitation_sha256"], SHA256_RE)
        for value in live["attempt_artifacts"].values():
            self.assertRegex(value, SHA256_RE)

        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        self.assertFalse(authority["db_authority_enabled"])
        self.assertFalse(authority["production_authority_enabled"])
        self.assertFalse(authority["runtime_ready"])
        self.assertFalse(authority["production_openclaw_write"])
        self.assertFalse(authority["official_openclaw_repository_write"])
        self.assertFalse(authority["openclaw_remote_push"])
        self.assertFalse(authority["mocked_live_testbox_substitute"])


if __name__ == "__main__":
    unittest.main()
