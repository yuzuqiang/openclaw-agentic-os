from __future__ import annotations

import hashlib
import json
import re
import subprocess
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

    def test_current_vs_proposed_truth_claims_are_independently_present(self) -> None:
        root = repository_root()
        design_current_status = (
            root / "docs/agentic-os-production-adaptation.md"
        ).read_text(encoding="utf-8").split("## Test and Acceptance Matrix", 1)[0]

        required_claims = (
            "Current file artifacts remain operational authority.",
            "Current production OpenClaw is not proven to satisfy",
            "Current bounded local/synthetic implementation slices include",
            "Runtime production behavior remains unproven.",
            "agentic_os.DB_AUTHORITY_ENABLED",
            "False",
        )
        for claim in required_claims:
            with self.subTest(claim=claim):
                self.assertIn(claim, design_current_status)

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
            payload["historical_github_review_binding"]["historical_candidate_sha"],
            "7f1453769fddee1ea482c6f32ef506b4d16b9733",
        )
        self.assertEqual(
            payload["historical_github_review_binding"]["historical_candidate_tree_sha"],
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
            payload["historical_github_review_binding"]["review_comment_ids"],
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
        negative_preflight = payload["runtime_evidence"]["fresh_installed_negative_preflight"]
        negative_preflight_path = root / negative_preflight["path"]
        self.assertEqual(
            negative_preflight["sha256"],
            hashlib.sha256(negative_preflight_path.read_bytes()).hexdigest(),
        )
        self.assertNotIn("live_split_catalog_preflight", payload["runtime_evidence"])
        self.assertEqual(
            hashlib.sha256(
                (root / "docs/runtime-evidence/phase-b-revalidation-20260809.json").read_bytes()
            ).hexdigest(),
            "e178fe8244a332f64836714b8fbac0b6c57d27f6005d2358957e52709bca7aa3",
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
        self.assertNotIn("original_status", payload)
        self.assertNotIn("retraction_reason", payload)
        self.assertNotIn("superseded_by", payload)
        self.assertEqual(
            payload["catalog"]["runtime_target"],
            "installed_openclaw_negative_baseline",
        )
        self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
        self.assertEqual(
            payload["catalog"]["catalog_capture"]["method"],
            "tools.catalog",
        )
        self.assertEqual(
            payload["catalog"]["catalog_capture"]["status"],
            "catalog_unavailable_before_contract_validation",
        )
        self.assertEqual(
            payload["catalog"]["catalog_capture"]["validation_stage"],
            "catalog_capture",
        )
        self.assertTrue(payload["catalog_failure"]["runtime_provenance_preserved"])
        self.assertEqual(payload["catalog_failure"]["returncode"], 1)
        binding = payload["preflight_evidence_binding"]
        self.assertRegex(binding["agentic_os_head_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(binding["agentic_os_tree_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(binding["preflight_script_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            binding["invocation"]["script"],
            "scripts/openclaw-tool-capability-preflight.py",
        )
        self.assertIn("--installed-openclaw-negative-baseline", binding["invocation"]["argv"])
        self.assertIn(
            "docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json",
            binding["invocation"]["argv"],
        )
        for key in (
            "install_root_path_sha256",
            "active_executable_path_sha256",
            "active_executable_sha256",
        ):
            self.assertRegex(payload["catalog"][key], r"^[0-9a-f]{64}$")
        self.assertEqual(
            hashlib.sha256(
                (
                    root
                    / "docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json"
                ).read_bytes()
            ).hexdigest(),
            "92a199248f743b643e96e1b1adee00b4d0d16700160a12e03fa8edb9f88a6342",
        )

    def test_evidence_index_preserves_history_and_current_epoch_boundary(self) -> None:
        root = repository_root()
        index = json.loads(
            (
                root
                / "docs/runtime-evidence/phase-b-20260811-evidence-index.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(index["classification"], "evidence_lineage_correction")
        self.assertIn("byte-for-byte immutable", index["mutation_policy"])
        historical = {item["path"]: item for item in index["historical_artifacts"]}
        negative = historical[
            "docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json"
        ]
        self.assertEqual(
            negative["binding_assessment"]["status"],
            "invalid_mixed_revision_binding",
        )
        self.assertNotEqual(
            negative["binding_assessment"]["stored_script_sha256"],
            negative["binding_assessment"]["actual_script_sha256_at_bound_head"],
        )
        historical_script = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{negative['binding_assessment']['bound_head']}:scripts/openclaw-tool-capability-preflight.py",
            ],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(
            hashlib.sha256(historical_script).hexdigest(),
            negative["binding_assessment"]["actual_script_sha256_at_bound_head"],
        )
        for path, record in historical.items():
            self.assertTrue(record["immutable_historical_bytes"])
            self.assertEqual(
                record["sha256"], hashlib.sha256((root / path).read_bytes()).hexdigest()
            )

    def test_live_split_catalog_preflight_preserves_dual_catalog_boundary(self) -> None:
        root = repository_root()
        index = json.loads(
            (root / "docs/runtime-evidence/phase-b-20260811-evidence-index.json").read_text(
                encoding="utf-8"
            )
        )
        current = index["current_evidence"]
        evidence_path = root / current["path"]
        if current["status"] == "pending_clean_generator_revision_capture":
            self.assertEqual(index["status"], "pending_current_evidence")
            self.assertFalse(evidence_path.exists())
            return
        self.assertEqual(current["status"], "captured_from_clean_generator_revision")
        self.assertEqual(index["status"], "current_evidence_captured")
        self.assertEqual(
            current["sha256"], hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        )
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["classification"], "fail_closed_future_contract")
        self.assertFalse(payload["runtime_ready"])
        self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
        self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
        self.assertEqual(payload["catalog"]["openclaw_version"], "2026.7.1")
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["authority"],
            "tools.catalog",
        )
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["required_tool_names"],
            ["session_status", "sessions_history", "sessions_list", "sessions_spawn"],
        )
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"][
                "parameter_schema_unavailable_tool_names"
            ],
            ["session_status", "sessions_history", "sessions_list", "sessions_spawn"],
        )
        model_tools = {
            item["name"]: item
            for item in payload["catalog"]["model_tool_catalog"]["tools"]
        }
        self.assertEqual(
            model_tools["sessions_spawn"]["parameter_evidence"]["status"],
            "installed_source_bound_catalog_schema_unavailable",
        )
        self.assertEqual(
            model_tools["sessions_history"]["parameter_evidence"]["status"],
            "unproven_from_catalog_and_installed_sources",
        )
        self.assertEqual(
            payload["catalog"]["gateway_rpc_catalog"]["source_bound_rpc_names"],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.release",
                "subagents.allowLease.status",
            ],
        )
        self.assertEqual(
            payload["catalog"]["gateway_rpc_catalog"]["status"],
            "disk_source_declarations_complete",
        )
        rpc_evidence = {
            item["name"]: item
            for item in payload["catalog"]["gateway_rpc_catalog"]["rpc_evidence"]
        }
        self.assertEqual(
            rpc_evidence["subagents.allowLease.status"]["live_reachability"],
            "reachable",
        )
        status_probe = rpc_evidence["subagents.allowLease.status"]["live_probe"]
        self.assertEqual(status_probe["method"], "subagents.allowLease.status")
        self.assertEqual(status_probe["status"], "ok")
        self.assertEqual(status_probe["live_reachability"], "reachable")
        self.assertRegex(status_probe["raw_response_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(status_probe["request_semantics"], "read_only_request")
        self.assertFalse(status_probe["requested_mutation"])
        self.assertGreaterEqual(len(status_probe["incidental_mutations_possible"]), 2)
        for method in (
            "subagents.allowLease.acquire",
            "subagents.allowLease.release",
        ):
            with self.subTest(method=method):
                self.assertEqual(
                    rpc_evidence[method]["disk_source_declaration"], "observed"
                )
                self.assertEqual(rpc_evidence[method]["live_reachability"], "unproven")
                self.assertNotIn("live_probe", rpc_evidence[method])
        self.assertEqual(
            payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"][
                "method"
            ],
            "subagents.allowLease.status",
        )
        self.assertFalse(
            payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"][
                "requested_mutation"
            ]
        )
        self.assertNotIn(
            "non_mutating",
            payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"],
        )
        self.assertEqual(
            payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"][
                "request_semantics"
            ],
            "read_only_request",
        )
        self.assertGreaterEqual(
            len(payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"]["incidental_mutations_possible"]),
            2,
        )
        self.assertEqual(payload["catalog"]["connected_gateway_build_identity"], "unproven")
        self.assertEqual(
            payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"][
                "status"
            ],
            "ok",
        )
        self.assertEqual(
            payload["catalog"]["status_alias_requirement"][
                "future_canonical_status_method"
            ],
            "sessions_status",
        )
        self.assertFalse(
            payload["catalog"]["status_alias_requirement"][
                "future_canonical_status_alias_available"
            ]
        )
        self.assertEqual(
            payload["catalog"]["status_alias_requirement"][
                "future_canonical_status_method_status"
            ],
            "missing_from_model_callable_tools_catalog",
        )
        self.assertFalse(
            payload["catalog"]["future_db_authority_contract"]["db_authority_enabled"]
        )
        self.assertIn(
            "accepted_session_identity_requirement",
            payload["catalog"]["future_db_authority_contract"],
        )
        self.assertIn("runtime tool catalog is missing sessions_status", payload["error"])
        self.assertIn("live reachability is unproven", payload["error"])
        self.assertNotIn("sessions_history is missing parameters", payload["error"])
        self.assertNotIn(
            "runtime authority envelope must declare runtime_ready=true",
            payload["error"],
        )
        binding = payload["preflight_evidence_binding"]
        self.assertEqual(binding["binding_kind"], "generator_revision")
        self.assertFalse(binding["containing_commit_self_binding"])
        self.assertEqual(
            current["generator_revision"],
            {
                "head_sha": binding["agentic_os_head_sha"],
                "script_sha256": binding["preflight_script_sha256"],
                "tree_sha": binding["agentic_os_tree_sha"],
            },
        )
        bound_head = binding["agentic_os_head_sha"]
        bound_tree = subprocess.run(
            ["git", "-C", str(root), "rev-parse", f"{bound_head}^{{tree}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(bound_tree, binding["agentic_os_tree_sha"])
        script_blob = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{bound_head}:scripts/openclaw-tool-capability-preflight.py",
            ],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(
            hashlib.sha256(script_blob).hexdigest(),
            binding["preflight_script_sha256"],
        )
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", bound_head, "HEAD"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "diff",
                "--exit-code",
                f"{bound_head}..HEAD",
                "--",
                *binding["capability_source_paths"],
            ],
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
