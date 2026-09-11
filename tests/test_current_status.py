from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest

import agentic_os
from agentic_os.migrations import repository_root


STATUS_DOMAINS = {
    "repository_artifact_acceptance",
    "live_runtime_evidence",
    "production_authority",
}


def _git_output(root, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_bytes(root, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
    ).stdout


class CurrentStatusTests(unittest.TestCase):
    def test_project_status_binds_accepted_repository_design(self) -> None:
        root = repository_root()
        status = json.loads((root / "docs/project-status.json").read_text(encoding="utf-8"))
        self.assertEqual(set(status), STATUS_DOMAINS)

        repository = status["repository_artifact_acceptance"]
        accepted_head = "53c9555cacb8e1906bc7cb6e252c0b91a73a8141"
        merge_commit = "b48a7cba8c6671b5dd33a369fb4f59f57d159739"
        accepted_tree = "609ea2995b6d1113b1952a34f26bbc35f82e1592"

        self.assertEqual(repository["status"], "accepted_and_merged")
        self.assertEqual(repository["repository"], "yuzuqiang/openclaw-agentic-os")
        self.assertEqual(repository["pull_request_number"], 39)
        self.assertEqual(
            repository["pull_request_url"],
            "https://github.com/yuzuqiang/openclaw-agentic-os/pull/39",
        )
        self.assertEqual(repository["accepted_head_sha"], accepted_head)
        self.assertEqual(repository["merge_commit_sha"], merge_commit)
        self.assertEqual(repository["base_start_sha"], merge_commit)
        self.assertEqual(repository["accepted_head_tree_sha"], accepted_tree)
        self.assertEqual(repository["merge_commit_tree_sha"], accepted_tree)
        self.assertEqual(repository["merged_at"], "2026-08-12T10:59:18Z")
        self.assertEqual(repository["phase_c"]["verdict"], "PASS")
        self.assertEqual(repository["phase_c"]["reviewed_head_sha"], accepted_head)
        self.assertEqual(repository["codex_review"]["verdict"], "clean")
        self.assertEqual(repository["codex_review"]["reviewed_head_sha"], accepted_head)
        self.assertTrue(
            accepted_head.startswith(
                repository["codex_review"]["reviewed_head_prefix_from_comment"]
            )
        )
        self.assertEqual(repository["status_check"]["name"], "agentic-os-ci")
        self.assertEqual(repository["status_check"]["status"], "SUCCESS")
        self.assertEqual(repository["status_check"]["head_sha"], accepted_head)

        self.assertEqual(_git_output(root, "rev-parse", f"{accepted_head}^{{tree}}"), accepted_tree)
        self.assertEqual(_git_output(root, "rev-parse", f"{merge_commit}^{{tree}}"), accepted_tree)
        self.assertIn(accepted_head, _git_output(root, "show", "-s", "--format=%P", merge_commit))
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", accepted_head, merge_commit],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", merge_commit, "HEAD"],
            check=True,
        )

        accepted_artifact = repository["accepted_head_design_artifact"]
        self.assertEqual(accepted_artifact["path"], "docs/agentic-os-production-adaptation.md")
        self.assertEqual(accepted_artifact["head_sha"], accepted_head)
        accepted_design = _git_bytes(
            root,
            "show",
            f"{accepted_head}:{accepted_artifact['path']}",
        )
        self.assertEqual(
            accepted_artifact["sha256"],
            hashlib.sha256(accepted_design).hexdigest(),
        )

        current_artifact = repository["current_corrected_design_artifact"]
        self.assertEqual(current_artifact["path"], accepted_artifact["path"])
        self.assertEqual(
            current_artifact["status"],
            "current_successor_artifact_not_pr39_acceptance",
        )
        self.assertEqual(
            current_artifact["sha256"],
            hashlib.sha256((root / current_artifact["path"]).read_bytes()).hexdigest(),
        )
        self.assertNotEqual(
            current_artifact["sha256"],
            accepted_artifact["sha256"],
        )

    def test_readme_current_design_hash_matches_status_contract(self) -> None:
        root = repository_root()
        status = json.loads((root / "docs/project-status.json").read_text(encoding="utf-8"))
        readme = (root / "README.md").read_text(encoding="utf-8")
        repository = status["repository_artifact_acceptance"]
        accepted_digest = repository["accepted_head_design_artifact"]["sha256"]
        current_digest = repository["current_corrected_design_artifact"]["sha256"]
        accepted_match = re.search(
            r"Accepted-head repository design artifact SHA-256: `([0-9a-f]{64})`",
            readme,
        )
        current_match = re.search(
            r"Current corrected design artifact SHA-256: `([0-9a-f]{64})`",
            readme,
        )

        self.assertIsNotNone(accepted_match)
        self.assertIsNotNone(current_match)
        self.assertEqual(accepted_match.group(1), accepted_digest)
        self.assertEqual(current_match.group(1), current_digest)
        self.assertEqual(
            current_digest,
            hashlib.sha256(
                (root / "docs/agentic-os-production-adaptation.md").read_bytes()
            ).hexdigest(),
        )
        self.assertNotEqual(current_digest, accepted_digest)
        self.assertIn("docs/project-status.json", readme)

    def test_current_status_keeps_revalidation_status_consistent(self) -> None:
        root = repository_root()
        readme_status = (root / "README.md").read_text(encoding="utf-8").split(
            "## Foundation commands", 1
        )[0]
        design_current_status = (
            root / "docs/agentic-os-production-adaptation.md"
        ).read_text(encoding="utf-8")
        normalized_readme_status = re.sub(r"\s+", " ", readme_status)
        normalized_design_current_status = re.sub(r"\s+", " ", design_current_status)

        accepted_claims = (
            "accepted repository state",
            "passed exact-head Phase C",
            "clean Codex review",
            "This is repository/design acceptance only",
        )
        for claim in accepted_claims:
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_readme_status)
                self.assertIn(claim, normalized_design_current_status)

        current_runtime_review_claims = (
            "Current installed-runtime evidence lineage and Issue #44 downstream persistent-lifecycle recapture",
            "no runtime-ready persistent-lifecycle proof exists",
            "no current-head GitHub Codex review binding exists",
            "candidate_process_started=false",
            "historical candidate invocations and reviews must not be counted as current exact-head runtime evidence",
        )
        for claim in current_runtime_review_claims:
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_readme_status)

        stale_claims = (
            "Draft PR successor",
            "current Draft remediation",
            "current Draft successor head",
            "there is no current Issue #44 persistent-lifecycle candidate proof",
            "The current Issue #44 persistent-lifecycle candidate proof is intentionally disabled",
            "final exact-head Phase C revalidation",
            "still required before it can be treated as independently accepted",
            "Phase C must replay against the exact PR head",
            "has **not** yet passed fresh independent revalidation",
            "still requires fresh independent revalidation",
            "Runtime behavior remains unproven and fresh independent revalidation is required.",
        )
        for claim in stale_claims:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, normalized_readme_status)
                self.assertNotIn(claim, normalized_design_current_status)

    def test_project_status_keeps_runtime_and_authority_boundaries_separate(self) -> None:
        root = repository_root()
        status = json.loads((root / "docs/project-status.json").read_text(encoding="utf-8"))
        self.assertEqual(set(status), STATUS_DOMAINS)

        live = status["live_runtime_evidence"]
        self.assertIn(
            live["status"],
            {
                "current_fail_closed_runtime_evidence_pending_phase_c",
                "pending_current_evidence",
            },
        )
        self.assertFalse(live["runtime_ready"])
        self.assertFalse(live["production_behavior_proven"])
        local_p03 = live["local_p03_runtime_heartbeat_shadow"]
        self.assertEqual(local_p03["status"], "local_only_non_authoritative")
        self.assertEqual(
            local_p03["ambiguous_sessions_spawn"],
            "human_review_required_no_retry",
        )
        self.assertEqual(
            local_p03["agentic_os_runtime_attest_rpc"],
            "candidate_source_bound_unproven_live_gateway",
        )
        self.assertEqual(
            local_p03["agentic_os_runtime_identity_rpc"],
            "not_required_nonexistent_removed_current_enforcement_is_connection_bound_attestation",
        )
        self.assertEqual(
            local_p03["signed_json_contract"],
            "canonical_json_utf8_escaped_cross_language_validated",
        )
        self.assertFalse(local_p03["live_gateway_session_or_lease_mutation"])
        self.assertFalse(local_p03["production_authority_enabled"])
        source_bound = live["local_p03_source_bound_candidate_preflight"]
        source_bound_path = root / source_bound["path"]
        self.assertEqual(
            source_bound["sha256"],
            hashlib.sha256(source_bound_path.read_bytes()).hexdigest(),
        )
        source_bound_payload = json.loads(source_bound_path.read_text(encoding="utf-8"))
        self.assertEqual(source_bound_payload["status"], "fail")
        self.assertFalse(source_bound_payload["runtime_ready"])
        self.assertEqual(
            source_bound_payload["catalog"]["attestation_rpc_catalog"]["status"],
            "source_bound_exact",
        )
        spawn_tool = next(
            tool
            for tool in source_bound_payload["catalog"]["model_tool_catalog"]["tools"]
            if tool["name"] == "sessions_spawn"
        )
        self.assertEqual(len(spawn_tool["parameters"]), 12)

        index = json.loads((root / live["evidence_index"]["path"]).read_text(encoding="utf-8"))
        self.assertEqual(live["evidence_index"]["status"], index["status"])
        self.assertIn(
            index["status"],
            {
                "current_fail_closed_runtime_evidence_pending_phase_c",
                "pending_current_evidence",
            },
        )
        self.assertEqual(
            live["evidence_index"]["current_evidence_status"],
            index["current_evidence"]["status"],
        )
        self.assertEqual(
            live["evidence_index"]["downstream_candidate_status"],
            index["downstream_candidate_evidence"]["status"],
        )
        self.assertIn(
            index["current_evidence"]["status"],
            {
                "captured_from_clean_generator_revision",
                "pending_clean_generator_revision_capture",
            },
        )
        current_evidence_path = root / index["current_evidence"]["path"]
        if index["current_evidence"]["status"] == "pending_clean_generator_revision_capture":
            self.assertEqual(index["status"], "pending_current_evidence")
            self.assertFalse(current_evidence_path.exists())
        else:
            self.assertTrue(current_evidence_path.exists())
            self.assertEqual(
                index["current_evidence"]["sha256"],
                hashlib.sha256(current_evidence_path.read_bytes()).hexdigest(),
            )

        issue44_installed = live["issue44_live_installed_preflight"]
        issue44_installed_path = root / issue44_installed["path"]
        self.assertIn(
            issue44_installed["status"],
            {
                "captured_from_clean_generator_revision",
                "pending_clean_generator_revision_capture",
            },
        )
        if issue44_installed["status"] == "pending_clean_generator_revision_capture":
            self.assertFalse(issue44_installed_path.exists())
            self.assertEqual(issue44_installed["sha256"], "")
        else:
            self.assertTrue(issue44_installed_path.exists())
            self.assertEqual(
                issue44_installed["sha256"],
                hashlib.sha256(issue44_installed_path.read_bytes()).hexdigest(),
            )
        self.assertFalse(issue44_installed["runtime_ready"])

        issue44_candidate = live["issue44_downstream_persistent_lifecycle_probe"]
        issue44_candidate_path = root / issue44_candidate["path"]
        self.assertEqual(
            issue44_candidate["sha256"],
            hashlib.sha256(issue44_candidate_path.read_bytes()).hexdigest(),
        )
        issue44_candidate_payload = json.loads(
            issue44_candidate_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            issue44_candidate["status"],
            "fail_closed_runtime_source_closure_pending_phase_c",
        )
        self.assertFalse(issue44_candidate["runtime_ready_candidate_evidence"])
        self.assertFalse(issue44_candidate["validation_receipt_bound"])
        self.assertFalse(issue44_candidate["duplicate_release_identity_parity"])
        self.assertEqual(issue44_candidate_payload["status"], "fail_closed")
        self.assertFalse(issue44_candidate_payload["runtime_ready"])
        self.assertFalse(issue44_candidate_payload["runtime_ready_candidate_evidence"])
        self.assertTrue(issue44_candidate_payload["phase_c_exact_head_required_before_review"])
        self.assertFalse(issue44_candidate_payload["isolated_non_production_gateway"]["candidate_process_started"])
        self.assertFalse(issue44_candidate_payload["isolated_non_production_gateway"]["production_gateway_restart_attempted"])
        self.assertEqual(
            issue44_candidate_payload["openclaw_head_sha"],
            issue44_candidate["openclaw_head_sha"],
        )
        self.assertEqual(
            index["downstream_candidate_evidence"]["isolated_non_production_gateway"][
                "run_root_sha256"
            ],
            issue44_candidate_payload["isolated_non_production_gateway"][
                "run_root_sha256"
            ],
        )
        matrix = live["issue44_downstream_incompatibility_matrix"]
        matrix_path = root / matrix["path"]
        self.assertTrue(matrix_path.exists())
        self.assertEqual(
            matrix["sha256"],
            hashlib.sha256(matrix_path.read_bytes()).hexdigest(),
        )
        matrix_payload = json.loads(matrix_path.read_text(encoding="utf-8"))
        self.assertFalse(matrix_payload["runtime_ready"])
        self.assertFalse(matrix_payload["production_authority_enabled"])
        self.assertIn("literal_helper_call_dynamic_import", matrix["accounted_boundaries"])
        self.assertIn("source_closure_computed_dynamic_import", matrix["blockers"])
        self.assertIn("source_closure_compile_cache_respawn_child_process", matrix["blockers"])
        self.assertEqual(
            index["downstream_local_remediation_boundary"]["sha256"],
            matrix["sha256"],
        )
        self.assertEqual(
            index["downstream_local_remediation_boundary"]["source_closure_blockers"],
            [
                "openclaw.mjs:357",
                "openclaw.mjs:373",
                "openclaw.mjs:769",
                "openclaw.mjs:141",
                "openclaw.mjs:266",
                "openclaw.mjs:293",
            ],
        )
        self.assertEqual(
            index["downstream_local_remediation_boundary"]["accounted_dynamic_import_locations"],
            [],
        )
        self.assertEqual(
            index["downstream_local_remediation_boundary"]["dynamic_import_blocker_locations"],
            ["openclaw.mjs:357", "openclaw.mjs:373", "openclaw.mjs:769"],
        )
        dist_blocker = next(
            item
            for item in matrix_payload["blockers"]
            if item["id"] == "missing_committed_dist_entrypoints"
        )
        self.assertIn(
            {"path": "dist/entry.js", "tracked": False, "exists": False},
            dist_blocker["paths"],
        )

        authority = status["production_authority"]
        self.assertEqual(authority["status"], "disabled")
        self.assertTrue(authority["file_artifacts_remain_authority"])
        self.assertFalse(authority["db_authority_enabled"])
        self.assertFalse(authority["production_agentic_os_control_db_authority"])
        self.assertFalse(authority["production_agentic_os_daemon"])
        self.assertFalse(authority["production_session_authority"])
        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)

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
        first_downstream = historical[
            "docs/runtime-evidence/phase-b-issue44-downstream-persistent-lifecycle-20260824.json"
        ]
        self.assertEqual(
            first_downstream["status"],
            "invalidated_historical_downstream_snapshot",
        )
        self.assertTrue(first_downstream["raw_runtime_ready_candidate_evidence"])
        self.assertFalse(first_downstream["runtime_ready_candidate_evidence"])
        round3_downstream = historical[
            "docs/runtime-evidence/phase-b-issue44-downstream-persistent-lifecycle-20260826-round3.json"
        ]
        self.assertEqual(
            round3_downstream["status"],
            "invalid_capability_source_drift_pending_recapture",
        )
        self.assertEqual(round3_downstream["raw_status"], "pass")
        self.assertTrue(round3_downstream["raw_runtime_ready_candidate_evidence"])
        self.assertFalse(round3_downstream["runtime_ready_candidate_evidence"])
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
        self.assertEqual(index["status"], "current_fail_closed_runtime_evidence_pending_phase_c")
        expected_no_source_drift = current["generator_binding_requirements"][
            "no_capability_source_drift_after_bound_head"
        ]
        self.assertTrue(expected_no_source_drift)
        reviewed_head = current["reviewed_head_sha"]
        self.assertRegex(reviewed_head, r"^[0-9a-f]{40}$")
        self.assertEqual(
            current["generator_binding_requirements"]["containing_revision_sha"],
            reviewed_head,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                reviewed_head,
                "HEAD",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                current["generator_revision"]["head_sha"],
                reviewed_head,
            ],
            check=True,
            capture_output=True,
        )
        self.assertEqual(
            current["sha256"], hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        )
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["classification"], "fail_closed_future_contract")
        self.assertFalse(payload["runtime_ready"])
        self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
        self.assertTrue(current["no_production_lease_mutation"])
        candidate = index["downstream_candidate_evidence"]
        candidate_path = root / candidate["path"]
        self.assertEqual(
            candidate["sha256"], hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        )
        candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
        self.assertEqual(candidate["status"], "fail_closed_runtime_source_closure_pending_phase_c")
        self.assertFalse(candidate["runtime_ready_candidate_evidence"])
        self.assertIn("compile-cache respawn child-process entrypoint", candidate["status_reason"])
        self.assertFalse(candidate["validation_receipt_bound"])
        self.assertFalse(candidate["duplicate_release_identity_parity"])
        self.assertEqual(candidate_payload["status"], "fail_closed")
        self.assertFalse(candidate_payload["runtime_ready"])
        self.assertFalse(candidate_payload["runtime_ready_candidate_evidence"])
        self.assertEqual(candidate_payload["reason"], "runtime_source_closure_failed")
        self.assertFalse(
            candidate_payload["isolated_non_production_gateway"]["candidate_process_started"]
        )
        self.assertEqual(
            candidate["isolated_non_production_gateway"]["run_root_sha256"],
            candidate_payload["isolated_non_production_gateway"]["run_root_sha256"],
        )
        matrix = index["downstream_local_remediation_boundary"]
        matrix_path = root / matrix["path"]
        self.assertEqual(
            matrix["sha256"], hashlib.sha256(matrix_path.read_bytes()).hexdigest()
        )
        self.assertFalse(matrix["runtime_ready"])
        self.assertEqual(
            matrix["source_closure_blockers"],
            [
                "openclaw.mjs:357",
                "openclaw.mjs:373",
                "openclaw.mjs:769",
                "openclaw.mjs:141",
                "openclaw.mjs:266",
                "openclaw.mjs:293",
            ],
        )
        self.assertEqual(
            matrix["accounted_dynamic_import_locations"],
            [],
        )
        self.assertEqual(
            matrix["dynamic_import_blocker_locations"],
            ["openclaw.mjs:357", "openclaw.mjs:373", "openclaw.mjs:769"],
        )
        self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
        self.assertEqual(payload["catalog"]["openclaw_version"], "2026.7.1")
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["authority"],
            "tools.catalog",
        )
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["required_tool_names"],
            [],
        )
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["source_declared_tool_names"],
            ["session_status", "sessions_history", "sessions_list", "sessions_spawn"],
        )
        self.assertEqual(
            payload["catalog"]["model_tool_catalog"]["status"],
            "catalog_unavailable_before_contract_validation",
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
            "skipped_no_production_lease_mutation",
        )
        status_probe = payload["catalog"]["gateway_rpc_catalog"]["status_corroboration"]
        self.assertEqual(status_probe["method"], "subagents.allowLease.status")
        self.assertEqual(status_probe["status"], "skipped_no_production_lease_mutation")
        self.assertEqual(
            status_probe["live_reachability"],
            "skipped_no_production_lease_mutation",
        )
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
            "skipped_no_production_lease_mutation",
        )
        self.assertEqual(
            payload["catalog"]["status_alias_requirement"][
                "canonical_status_method"
            ],
            "session_status",
        )
        self.assertFalse(
            payload["catalog"]["status_alias_requirement"][
                "canonical_status_method_available"
            ]
        )
        self.assertEqual(
            payload["catalog"]["status_alias_requirement"][
                "canonical_status_method_status"
            ],
            "unproven_model_catalog_unavailable",
        )
        self.assertFalse(
            payload["catalog"]["future_db_authority_contract"]["db_authority_enabled"]
        )
        self.assertIn(
            "accepted_session_identity_requirement",
            payload["catalog"]["future_db_authority_contract"],
        )
        self.assertNotIn("runtime tool catalog is missing session_status", payload["error"])
        self.assertIn("model-callable tools.catalog is unavailable", payload["error"])
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
        self.assertRegex(bound_head, r"^[0-9a-f]{40}$")
        reviewed_head = current["reviewed_head_sha"]
        self.assertRegex(reviewed_head, r"^[0-9a-f]{40}$")
        self.assertEqual(current["reviewed_head_sha"], reviewed_head)
        self.assertEqual(
            current["generator_binding_requirements"]["containing_revision_sha"],
            reviewed_head,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                reviewed_head,
                "HEAD",
            ],
            check=True,
            capture_output=True,
        )
        ancestry_check = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                bound_head,
                reviewed_head,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
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
        drift_check = subprocess.run(
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
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(ancestry_check.returncode, 0)
        self.assertEqual(drift_check.returncode, 0)


if __name__ == "__main__":
    unittest.main()
