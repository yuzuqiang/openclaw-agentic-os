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

    def test_current_status_no_longer_claims_revalidation_is_pending(self) -> None:
        root = repository_root()
        readme_status = (root / "README.md").read_text(encoding="utf-8").split(
            "## Foundation commands", 1
        )[0]
        design_current_status = (
            (root / "docs/agentic-os-production-adaptation.md")
            .read_text(encoding="utf-8")
            .split("## Unified Target Architecture", 1)[0]
        )

        stale_claims = (
            "has **not** yet passed fresh independent revalidation",
            "still requires fresh independent revalidation",
            "fresh independent revalidation is still required",
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

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(
            payload["audited_origin_main_sha"],
            "fa79a7ea4235a2c822e51052649f982f61c962e7",
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


if __name__ == "__main__":
    unittest.main()
