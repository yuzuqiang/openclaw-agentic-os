from __future__ import annotations

import hashlib
import json
import re
import unittest

from agentic_os.migrations import repository_root


class CurrentStatusTests(unittest.TestCase):
    def test_readme_current_design_hash_matches_design_document(self) -> None:
        root = repository_root()
        readme = (root / "README.md").read_text(encoding="utf-8")
        design = root / "docs/agentic-os-production-adaptation.md"
        digest = hashlib.sha256(design.read_bytes()).hexdigest()
        match = re.search(r"Current design artifact SHA-256: `([0-9a-f]{64})`", readme)

        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), digest)

    def test_current_status_keeps_revalidation_status_consistent(self) -> None:
        root = repository_root()
        readme_status = (root / "README.md").read_text(encoding="utf-8").split(
            "## Foundation commands", 1
        )[0]
        design_current_status = (
            root / "docs/agentic-os-production-adaptation.md"
        ).read_text(encoding="utf-8")

        current_required_claim = (
            "current Draft successor head still requires final exact-head Phase C "
            "revalidation"
        )
        self.assertIn("final exact-head", readme_status)
        self.assertIn("Phase C revalidation", readme_status)
        self.assertIn(current_required_claim, design_current_status)

        stale_claims = (
            "has **not** yet passed fresh independent revalidation",
            "still requires fresh independent revalidation",
            "Runtime behavior remains unproven and fresh independent revalidation is required.",
        )
        for claim in stale_claims:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, readme_status)
                self.assertNotIn(claim, design_current_status)

    def test_phase_b_revalidation_evidence_preserves_runtime_boundaries(self) -> None:
        root = repository_root()
        payload = json.loads(
            (
                root / "docs/runtime-evidence/phase-b-revalidation-20260809.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(payload["status"], "superseded")
        self.assertEqual(
            payload["design_status"],
            "historical_revalidation_superseded_by_current_draft_remediation",
        )
        self.assertTrue(
            payload["current_successor_revalidation"][
                "required_before_independent_acceptance"
            ]
        )
        self.assertEqual(
            payload["historical_origin_main_sha"],
            "fa79a7ea4235a2c822e51052649f982f61c962e7",
        )
        self.assertEqual(
            payload["audited_github_review_binding"]["reviewed_head_sha"],
            "7f1453769fddee1ea482c6f32ef506b4d16b9733",
        )
        self.assertEqual(
            payload["audited_github_review_binding"]["reviewed_head_tree_sha"],
            "30f122ae32335c51de8eb23740497468307f3fdd",
        )
        self.assertEqual(
            payload["completion_gate_receipt"]["run_id"],
            "phase-20260809-053538-phase-b-software-architect-completion-final",
        )
        self.assertEqual(payload["completion_gate_receipt"]["status"], "PASS")
        self.assertRegex(payload["completion_gate_receipt"]["report_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn(
            3743656102,
            payload["audited_github_review_binding"]["review_comment_ids"],
        )
        self.assertFalse(payload["production_behavior_proven"])
        self.assertFalse(payload["db_authority_enabled"])
        self.assertEqual(
            payload["runtime_evidence"]["real_gateway_contract"]["status"],
            "stale_snapshot",
        )
        self.assertEqual(
            payload["runtime_evidence"]["fresh_installed_negative_preflight"]["status"],
            "fail",
        )

    def test_installed_negative_baseline_preserves_runtime_provenance(self) -> None:
        root = repository_root()
        payload = json.loads(
            (
                root
                / "docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(
            payload["catalog"]["runtime_target"],
            "installed_openclaw_negative_baseline",
        )
        self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
        self.assertEqual(
            payload["catalog"]["active_catalog"]["method"],
            "tools.catalog",
        )
        self.assertEqual(
            payload["catalog"]["active_catalog"]["status"],
            "failed_before_contract_validation",
        )
        self.assertTrue(payload["catalog_failure"]["runtime_provenance_preserved"])
        self.assertEqual(payload["catalog_failure"]["returncode"], 1)
        for key in (
            "install_root_path_sha256",
            "active_executable_path_sha256",
            "active_executable_sha256",
        ):
            self.assertRegex(payload["catalog"][key], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
