from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import signal
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts/heartbeat-shadow-soak-monitor.py"
)
SPEC = importlib.util.spec_from_file_location("heartbeat_shadow_soak_monitor", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


def _write_json(path: Path, value: dict[str, object]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _signed_anchor(value: dict[str, object], key: str) -> dict[str, object]:
    signature = hmac.new(
        key.encode("utf-8"),
        monitor._anchor_signature_payload(value),
        hashlib.sha256,
    ).hexdigest()
    return {
        **value,
        "authentication": {
            "scheme": "hmac-sha256-env",
            "key_env": monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV,
            "signature": signature,
        },
    }


def _pass_sample(
    sampled_at_epoch_ms: int,
    digest: str,
    sampled_at_monotonic_ms: int | None = None,
) -> dict[str, object]:
    if sampled_at_monotonic_ms is None:
        sampled_at_monotonic_ms = sampled_at_epoch_ms
    return {
        "sampled_at_epoch_ms": sampled_at_epoch_ms,
        "sampled_at_monotonic_ms": sampled_at_monotonic_ms,
        "status": "pass",
        "authority_mode": "file_authority_shadow",
        "expected_authority_input_digest": digest,
        "observed_authority_input_digest": digest,
        "parity_status": "pass",
        "parity_percent": 100,
        "db_authority_enabled": False,
        "runtime_authority_counts": {
            "lease_rows": 0,
            "spawn_request_rows": 0,
            "session_rows": 0,
            "lifecycle_rpc_intent_rows": 0,
            "duplicate_spawn_identity_groups": 0,
        },
        "runtime_authority_counts_observed": True,
        "observation_error": None,
        "counters": {
            "duplicate_spawn": 0,
            "orphan_lease": 0,
            "unknown_or_unowned_session": 0,
            "privacy_violation": 0,
            "projection_drift": 0,
        },
    }


class HeartbeatShadowSoakMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.state_dir = self.root / "docs/runtime-evidence/soak"
        self.heartbeat = self.root / "docs/runtime-evidence/soak/HEARTBEAT.md"
        self.heartbeat.parent.mkdir(parents=True, exist_ok=True)
        self.heartbeat.write_text("# Heartbeat\n\nNo active periodic tasks.\n", encoding="utf-8")
        self.live_config = self.root / "openclaw.json"
        self.live_config.write_text(
            json.dumps(
                {"agents": {"defaults": {"heartbeat": {"every": "30m", "target": "main"}}}},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.baseline = self.root / "docs/runtime-evidence/soak/baseline.json"
        self.baseline.write_text("{}", encoding="utf-8")
        self.lifecycle = self.root / "docs/runtime-evidence/lifecycle.json"
        self.validation = self.root / "docs/runtime-evidence/validation.json"
        self.anchor_key = "phase-c-anchor-test-key"
        env_patch = mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: self.anchor_key},
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        lifecycle = {
            "status": "pass",
            "immutable_inputs": {
                "runtime_head": monitor.EXPECTED_RUNTIME_HEAD,
                "db_authority_enabled_required": False,
            },
            "rollback": {
                "status": "pass",
                "db_authority": {"DB_AUTHORITY_ENABLED": False},
            },
            "soak": {"production_cron_mutated": False},
        }
        lifecycle_sha = _write_json(self.lifecycle, lifecycle)
        self.validation_anchor = self.root / "docs/runtime-evidence/validation-anchor.json"
        anchor = _signed_anchor(
            {
                "schema_version": "agentic-os.independent-validation-anchor.v1",
                "record_authority": "phase_c_terminal_checkpoint",
                "validation_verdict": "pass",
                "receipt_sha256": lifecycle_sha,
                "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                "verifier": {
                    "identity": "security-engineer-phase-c",
                    "role": "independent_verifier",
                    "session_key": "phase-c-session",
                },
            },
            self.anchor_key,
        )
        anchor_sha = _write_json(self.validation_anchor, anchor)
        validation_sha = _write_json(
            self.validation,
            {
                "status": "pass",
                "receipt_sha256": lifecycle_sha,
                "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                "verifier": {
                    "identity": "security-engineer-phase-c",
                    "role": "independent_verifier",
                    "session_key": "phase-c-session",
                },
                "invocation": {
                    "command": "python -m unittest tests.test_heartbeat_shadow_soak_monitor",
                    "completed_at": "2026-08-15T00:00:00Z",
                },
                "authenticated_record": {
                    "path": str(self.validation_anchor.relative_to(self.root)),
                    "sha256": anchor_sha,
                },
            },
        )
        self.args = Namespace(
            state_dir=self.state_dir,
            run_id="phase-b-test-soak",
            baseline_path=self.baseline,
            heartbeat_file=self.heartbeat,
            live_config_path=self.live_config,
            lifecycle_receipt_path=self.lifecycle,
            independent_validation_path=self.validation,
            runtime_head=monitor.EXPECTED_RUNTIME_HEAD,
            agentic_os_evidence_head=monitor.EXPECTED_AGENTIC_OS_EVIDENCE_HEAD,
            implementation_base=monitor.EXPECTED_IMPLEMENTATION_BASE,
            monitor_implementation_head="b" * 40,
            expected_lifecycle_sha256=lifecycle_sha,
            expected_independent_validation_sha256=validation_sha,
            duration_hours=24,
            interval_seconds=300,
            no_daemon=True,
        )

    def test_first_sample_writes_core_receipt_and_sanitized_envelope(self) -> None:
        digest = "a" * 64

        def sample_side_effect(**kwargs: object) -> dict[str, object]:
            return _pass_sample(
                int(kwargs["sampled_at_epoch_ms"]),
                digest,
                int(kwargs["sampled_at_monotonic_ms"]),
            )

        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            with mock.patch.object(
                monitor,
                "run_heartbeat_file_shadow_cycle",
                return_value={
                    "schema_version": "p03-heartbeat-shadow-cycle-receipt.v1",
                    "status": "pass",
                    "authority_input_digest": digest,
                },
            ), mock.patch.object(
                monitor,
                "snapshot_heartbeat_runtime_authority_database",
                return_value={
                    "schema_version": "p03-heartbeat-runtime-authority-snapshot.v1",
                    "status": "pass",
                    "authority": "file_artifacts",
                    "db_authority_enabled": False,
                    "source_database": "state/agentic-os/control.db",
                    "source_sidecars_observed": ["control.db-wal"],
                    "snapshot_database": "state/agentic-os/backups/test/sample.db",
                    "snapshot_sha256": "b" * 64,
                    "snapshot_sidecars_present": False,
                    "local_recovery_only": True,
                    "packaging_retrieval_denied": True,
                    "runtime_authority_counts": {
                        "lease_rows": 0,
                        "spawn_request_rows": 0,
                        "session_rows": 0,
                        "lifecycle_rpc_intent_rows": 0,
                        "duplicate_spawn_identity_groups": 0,
                    },
                },
            ), mock.patch.object(
                monitor, "heartbeat_parity_sample", side_effect=sample_side_effect
            ):
                first = monitor._first_sample(config)
            monitor._persist_envelope(
                config,
                status="running",
                sample=first,
                note="unit-test",
            )

        core = json.loads(
            (self.state_dir / "core-soak-receipt.json").read_text(encoding="utf-8")
        )
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(core["status"], "in_progress")
        self.assertEqual(len(core["samples"]), 1)
        self.assertEqual(envelope["status"], "running")
        self.assertEqual(envelope["first_sample"]["status"], "pass")
        self.assertEqual(envelope["runtime_snapshots"]["snapshots_count"], 1)
        self.assertIs(envelope["runtime_snapshots"]["local_recovery_only"], True)
        self.assertEqual(
            envelope["stop_rollback_contract"]["pre_phase_c_contract"],
            "command_availability_only_while_soak_running",
        )
        self.assertFalse(
            json.dumps(envelope, sort_keys=True).lower().count("token")
            and "token_material_copied\":true" in json.dumps(envelope, sort_keys=True).lower()
        )
        self.assertIn(" stop ", envelope["monitor"]["stop_command"])
        self.assertIn(" rollback ", envelope["monitor"]["rollback_command"])

    def test_predecessor_validation_requires_independent_provenance(self) -> None:
        lifecycle_sha = hashlib.sha256(self.lifecycle.read_bytes()).hexdigest()
        weak_validation_sha = _write_json(
            self.validation,
            {"status": "pass", "receipt_sha256": lifecycle_sha},
        )
        self.args.expected_independent_validation_sha256 = weak_validation_sha
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "verifier provenance"):
                monitor._build_config(self.args)

    def test_predecessor_validation_requires_authenticated_record_hash(self) -> None:
        lifecycle_sha = hashlib.sha256(self.lifecycle.read_bytes()).hexdigest()
        validation_sha = _write_json(
            self.validation,
            {
                "status": "pass",
                "receipt_sha256": lifecycle_sha,
                "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                "verifier": {
                    "identity": "security-engineer-phase-c",
                    "role": "independent_verifier",
                    "session_key": "phase-c-session",
                },
                "invocation": {
                    "command": "python -m unittest tests.test_heartbeat_shadow_soak_monitor",
                    "completed_at": "2026-08-15T00:00:00Z",
                },
                "authenticated_record": {
                    "path": str(self.validation_anchor.relative_to(self.root)),
                    "sha256": "0" * 64,
                },
            },
        )
        self.args.expected_independent_validation_sha256 = validation_sha
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "authenticated record hash"):
                monitor._build_config(self.args)

    def test_predecessor_validation_rejects_unsigned_authenticated_record(self) -> None:
        lifecycle_sha = hashlib.sha256(self.lifecycle.read_bytes()).hexdigest()
        unsigned_anchor_sha = _write_json(
            self.validation_anchor,
            {
                "schema_version": "agentic-os.independent-validation-anchor.v1",
                "record_authority": "phase_c_terminal_checkpoint",
                "validation_verdict": "pass",
                "receipt_sha256": lifecycle_sha,
                "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                "verifier": {
                    "identity": "security-engineer-phase-c",
                    "role": "independent_verifier",
                    "session_key": "phase-c-session",
                },
            },
        )
        validation_sha = _write_json(
            self.validation,
            {
                "status": "pass",
                "receipt_sha256": lifecycle_sha,
                "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                "verifier": {
                    "identity": "security-engineer-phase-c",
                    "role": "independent_verifier",
                    "session_key": "phase-c-session",
                },
                "invocation": {
                    "command": "python -m unittest tests.test_heartbeat_shadow_soak_monitor",
                    "completed_at": "2026-08-15T00:00:00Z",
                },
                "authenticated_record": {
                    "path": str(self.validation_anchor.relative_to(self.root)),
                    "sha256": unsigned_anchor_sha,
                },
            },
        )
        self.args.expected_independent_validation_sha256 = validation_sha

        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "signature is missing"):
                monitor._build_config(self.args)

    def test_committed_default_validation_anchor_is_signed_and_bound(self) -> None:
        repo_root = SCRIPT_PATH.parents[1]
        validation_path = (
            repo_root
            / "docs/runtime-evidence/phase-b-p03-independent-validation-20260814T032902Z.json"
        )
        anchor_path = (
            repo_root
            / "docs/runtime-evidence/phase-b-p03-independent-validation-anchor-20260814T032914Z.json"
        )
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        public_fixture_key = "phase-c-terminal-checkpoint-anchor-20260814T032914Z"

        with mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: public_fixture_key},
        ):
            self.assertEqual(
                monitor._sha256_file(validation_path),
                monitor.EXPECTED_INDEPENDENT_VALIDATION_SHA256,
            )
            self.assertEqual(
                validation["authenticated_record"]["sha256"],
                monitor._sha256_file(anchor_path),
            )
            monitor._validate_independent_validation_anchor(
                {"exact_heads": {"implementation_base": monitor.EXPECTED_IMPLEMENTATION_BASE}},
                validation,
            )
            args = Namespace(
                state_dir=repo_root / "docs/runtime-evidence/soak/default-anchor-smoke",
                run_id="default-anchor-smoke",
                baseline_path=repo_root / "docs/runtime-evidence/soak/baseline.json",
                heartbeat_file=repo_root / "HEARTBEAT.md",
                live_config_path=repo_root / "openclaw.json",
                lifecycle_receipt_path=repo_root
                / "docs/runtime-evidence/phase-b-p03-isolated-candidate-lifecycle-20260814T032902Z.json",
                independent_validation_path=validation_path,
                runtime_head=monitor.EXPECTED_RUNTIME_HEAD,
                agentic_os_evidence_head=monitor.EXPECTED_AGENTIC_OS_EVIDENCE_HEAD,
                implementation_base=monitor.EXPECTED_IMPLEMENTATION_BASE,
                monitor_implementation_head="b" * 40,
                expected_lifecycle_sha256=monitor.EXPECTED_LIFECYCLE_SHA256,
                expected_independent_validation_sha256=(
                    monitor.EXPECTED_INDEPENDENT_VALIDATION_SHA256
                ),
                duration_hours=24,
                interval_seconds=300,
                no_daemon=True,
            )
            with mock.patch.object(monitor, "REPO_ROOT", repo_root):
                config = monitor._build_config(args)
            self.assertEqual(
                config["predecessor_receipts"]["independent_validation"]["sha256"],
                monitor.EXPECTED_INDEPENDENT_VALIDATION_SHA256,
            )

    def test_coverage_gap_uses_failed_closed_monitor_envelope(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            receipt = monitor.append_heartbeat_soak_sample(
                receipt,
                _pass_sample(1_700_000_000_000, digest),
            )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._persist_envelope(
                config,
                status="failed_closed",
                violation="coverage_gap",
            )

        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        core = json.loads(
            (self.state_dir / "core-soak-receipt.json").read_text(encoding="utf-8")
        )
        self.assertEqual(core["status"], "in_progress")
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["coverage_gap"])
        self.assertIs(envelope["coverage"]["coverage_gap_detected"], True)

    def test_run_uses_monotonic_deadline_when_wall_clock_stalls(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            receipt = monitor.append_heartbeat_soak_sample(
                receipt,
                _pass_sample(
                    1_700_000_000_000,
                    digest,
                    sampled_at_monotonic_ms=1_000_000,
                ),
            )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            with mock.patch.object(
                monitor, "_epoch_ms", return_value=1_700_000_000_000
            ), mock.patch.object(
                monitor.time,
                "monotonic_ns",
                return_value=1_600_001 * 1_000_000,
            ):
                result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["coverage_gap"])

    def test_interval_bounds_fail_closed_before_start(self) -> None:
        self.args.interval_seconds = 59
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "interval"):
                monitor._build_config(self.args)
        self.args.interval_seconds = 3601
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "interval"):
                monitor._build_config(self.args)

    def test_snapshot_failure_becomes_failed_runtime_observation_sample(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            with mock.patch.object(
                monitor,
                "snapshot_heartbeat_runtime_authority_database",
                side_effect=monitor.HeartbeatShadowError("snapshot unavailable"),
            ):
                sample = monitor._sample(config, 1_700_000_000_000)

        self.assertEqual(sample["status"], "fail")
        self.assertIs(sample["runtime_authority_counts_observed"], False)
        self.assertEqual(sample["observation_error"], "runtime_authority_audit_error")
        self.assertEqual(sample["counters"]["unknown_or_unowned_session"], 1)

    def test_start_git_contract_requires_clean_worktree_and_exact_head(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
        heads = config["exact_heads"]
        clean_calls: list[list[str]] = []

        def clean_git(_repo_root: Path, argv: list[str], _label: str) -> str:
            clean_calls.append(argv)
            if argv == ["status", "--porcelain=v1"]:
                return ""
            if argv == ["rev-parse", "HEAD"]:
                return str(heads["monitor_implementation_head"])
            return ""

        with mock.patch.object(monitor, "_git_text", side_effect=clean_git):
            monitor._assert_start_git_contract(config)

        self.assertIn(
            [
                "cat-file",
                "-e",
                f"{heads['monitor_implementation_head']}^{{commit}}",
            ],
            clean_calls,
        )
        self.assertIn(
            [
                "merge-base",
                "--is-ancestor",
                heads["implementation_base"],
                heads["monitor_implementation_head"],
            ],
            clean_calls,
        )

        with mock.patch.object(monitor, "_git_text", return_value=" M changed.py"):
            with self.assertRaisesRegex(monitor.MonitorError, "clean"):
                monitor._assert_start_git_contract(config)

        def mismatch_git(_repo_root: Path, argv: list[str], _label: str) -> str:
            if argv == ["status", "--porcelain=v1"]:
                return ""
            if argv == ["rev-parse", "HEAD"]:
                return "0" * 40
            return ""

        with mock.patch.object(monitor, "_git_text", side_effect=mismatch_git):
            with self.assertRaisesRegex(monitor.MonitorError, "does not match"):
                monitor._assert_start_git_contract(config)

    def test_no_daemon_start_persists_first_sample_without_running_process(self) -> None:
        digest = "a" * 64
        first = _pass_sample(1_700_000_000_000, digest)
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(
            monitor, "_first_sample", return_value=first
        ):
            result = monitor.start(self.args)

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "first_sample_pass")
        self.assertNotIn("process_alive", envelope["monitor"])

    def test_daemon_readiness_accepts_child_running_envelope(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.state_dir / "monitor-envelope.json",
            {"status": "running", "monitor": {"pid": 12345}},
        )
        process = mock.Mock(pid=12345)
        process.poll.return_value = None

        monitor._wait_for_daemon_ready(config, process)

    def test_daemon_readiness_rejects_child_failed_envelope(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.state_dir / "monitor-envelope.json",
            {"status": "failed_closed", "monitor": {"pid": 12345}},
        )
        process = mock.Mock(pid=12345)
        process.poll.return_value = None

        with self.assertRaisesRegex(monitor.MonitorError, "failed closed"):
            monitor._wait_for_daemon_ready(config, process)

    def test_daemon_readiness_rejects_early_process_exit(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
        process = mock.Mock(pid=12345)
        process.poll.return_value = 2

        with self.assertRaisesRegex(monitor.MonitorError, "exited before readiness"):
            monitor._wait_for_daemon_ready(config, process)

    def test_run_validation_abort_persists_failed_closed_envelope(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            monitor._atomic_write_json(
                self.state_dir / "core-soak-receipt.json",
                {"schema_version": "broken"},
            )
            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["core_receipt_invalid"])

    def test_run_revalidates_git_contract_before_resuming(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            with mock.patch.object(
                monitor,
                "_assert_start_git_contract",
                side_effect=monitor.MonitorError("dirty monitor"),
            ):
                result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["monitor_git_identity_invalid"])
        self.assertEqual(envelope["note"], "dirty monitor")

    def test_unreadable_core_receipt_persists_failed_closed_envelope(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = "a" * 64
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            (self.state_dir / "core-soak-receipt.json").write_text(
                "{broken", encoding="utf-8"
            )
            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["core_receipt_invalid"])
        self.assertIn("unreadable JSON", envelope["note"])

    def test_failed_closed_persists_despite_corrupt_snapshot_ledger(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = "a" * 64
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            (self.state_dir / "runtime-snapshot-receipts.json").write_text(
                "{broken", encoding="utf-8"
            )
            monitor._persist_envelope(
                config,
                status="failed_closed",
                violation="snapshot_ledger_corrupt",
                note="sample failed",
            )

        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["snapshot_ledger_corrupt"])
        self.assertEqual(envelope["runtime_snapshots"]["snapshots_count"], 0)

    def test_run_rejects_core_receipt_from_other_monitor_config(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id="other-run",
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["core_receipt_invalid"])
        self.assertIn("run_id", envelope["note"])

    def test_status_refresh_preserves_failed_closed_audit_fields(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            sample = _pass_sample(1_700_000_000_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, sample)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._persist_envelope(
                config,
                status="failed_closed",
                violation="coverage_gap",
                sample=sample,
                note="gap detected",
            )
            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["coverage_gap"])
        self.assertEqual(envelope["note"], "gap detected")
        self.assertIs(envelope["coverage"]["coverage_gap_detected"], True)

    def test_status_refresh_fails_closed_when_running_pid_is_dead(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            sample = _pass_sample(1_700_000_000_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, sample)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "running", "violations": [], "latest_sample": sample},
            )
            (self.state_dir / "monitor.pid").write_text("12345\n", encoding="utf-8")
            with mock.patch.object(monitor, "_pid_alive", return_value=False):
                result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["monitor_process_dead"])
        self.assertIs(envelope["monitor"]["process_alive"], False)
        self.assertEqual(envelope["note"], "running monitor process is not alive")

    def test_status_refresh_fails_closed_when_running_config_is_unreadable(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        monitor._atomic_write_json(
            self.state_dir / "monitor-envelope.json",
            {"status": "running", "violations": [], "latest_sample": {}},
        )
        (self.state_dir / "monitor-config.json").write_text("{", encoding="utf-8")

        result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["monitor_state_unreadable"])
        self.assertIn("running monitor state is unreadable", envelope["note"])

    def test_status_refresh_fails_closed_when_running_core_receipt_contract_invalid(
        self,
    ) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            monitor._atomic_write_json(
                self.state_dir / "core-soak-receipt.json",
                {
                    "schema_version": "p03-heartbeat-shadow-soak-receipt.v1",
                    "run_id": config["run_id"],
                },
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "running", "violations": [], "latest_sample": {}},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["monitor_state_unreadable"])
        self.assertIn("running monitor state is unreadable", envelope["note"])

    def test_status_refresh_fails_closed_when_running_sample_is_overdue(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            sample = _pass_sample(1_700_000_000_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, sample)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "running", "violations": [], "latest_sample": sample},
            )
            (self.state_dir / "monitor.pid").write_text("12345\n", encoding="utf-8")
            with mock.patch.object(monitor, "_pid_alive", return_value=True), mock.patch.object(
                monitor, "_epoch_ms", return_value=1_700_000_601_000
            ):
                result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["coverage_gap"])
        self.assertIs(envelope["coverage"]["coverage_gap_detected"], True)
        self.assertEqual(envelope["note"], "running monitor sample window is overdue")

    def test_status_refresh_checks_monotonic_sample_deadline(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=10_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            sample = _pass_sample(
                1_700_000_000_000,
                digest,
                sampled_at_monotonic_ms=10_000,
            )
            receipt = monitor.append_heartbeat_soak_sample(receipt, sample)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "running", "violations": [], "latest_sample": sample},
            )
            (self.state_dir / "monitor.pid").write_text("12345\n", encoding="utf-8")
            with mock.patch.object(monitor, "_pid_alive", return_value=True), mock.patch.object(
                monitor, "_epoch_ms", return_value=1_700_000_001_000
            ), mock.patch.object(
                monitor.time,
                "monotonic_ns",
                return_value=611_000 * 1_000_000,
            ):
                result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["coverage_gap"])
        self.assertEqual(
            envelope["note"],
            "running monitor sample monotonic window is overdue",
        )

    def test_rollback_refuses_active_monitor_before_receipt_or_mutation(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            (self.state_dir / "monitor.pid").write_text("12345\n", encoding="utf-8")
            with mock.patch.object(monitor, "_pid_alive", return_value=True):
                with mock.patch.object(
                    monitor, "force_heartbeat_file_authority_rollback"
                ) as rollback:
                    with self.assertRaisesRegex(monitor.MonitorError, "active"):
                        monitor.rollback(
                            Namespace(
                                state_dir=self.state_dir,
                                rollback_id="active-monitor",
                                allow_running=False,
                            )
                        )

        rollback.assert_not_called()

    def test_unrequested_signal_exits_nonzero_after_failed_closed_envelope(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HEARTBEAT_SHADOW_MONITOR_STATE_DIR": str(self.state_dir)},
        ), mock.patch.object(
            monitor, "_load_config", return_value={"state_dir": str(self.state_dir)}
        ), mock.patch.object(
            monitor, "_stop_requested", return_value=False
        ), mock.patch.object(
            monitor, "_persist_envelope"
        ) as persist:
            with self.assertRaises(SystemExit) as raised:
                monitor._handle_signal(signal.SIGTERM, None)

        self.assertEqual(raised.exception.code, 2)
        persist.assert_called_once_with(
            {"state_dir": str(self.state_dir)},
            status="failed_closed",
            violation=f"signal_{signal.SIGTERM}",
        )

    def test_requested_signal_exits_zero_after_stopped_envelope(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HEARTBEAT_SHADOW_MONITOR_STATE_DIR": str(self.state_dir)},
        ), mock.patch.object(
            monitor, "_load_config", return_value={"state_dir": str(self.state_dir)}
        ), mock.patch.object(
            monitor, "_stop_requested", return_value=True
        ), mock.patch.object(
            monitor, "_persist_envelope"
        ) as persist:
            with self.assertRaises(SystemExit) as raised:
                monitor._handle_signal(signal.SIGINT, None)

        self.assertEqual(raised.exception.code, 0)
        persist.assert_called_once_with(
            {"state_dir": str(self.state_dir)},
            status="stopped",
            violation=None,
        )


if __name__ == "__main__":
    unittest.main()
