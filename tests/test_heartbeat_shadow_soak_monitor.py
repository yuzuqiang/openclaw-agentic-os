from __future__ import annotations

import hashlib
import importlib.util
import json
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


def _pass_sample(sampled_at_epoch_ms: int, digest: str) -> dict[str, object]:
    return {
        "sampled_at_epoch_ms": sampled_at_epoch_ms,
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
        self.baseline = self.root / "docs/runtime-evidence/soak/baseline.json"
        self.baseline.write_text("{}", encoding="utf-8")
        self.lifecycle = self.root / "docs/runtime-evidence/lifecycle.json"
        self.validation = self.root / "docs/runtime-evidence/validation.json"
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
        validation_sha = _write_json(
            self.validation,
            {"status": "pass", "receipt_sha256": lifecycle_sha},
        )
        self.args = Namespace(
            state_dir=self.state_dir,
            run_id="phase-b-test-soak",
            baseline_path=self.baseline,
            heartbeat_file=self.heartbeat,
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
            return _pass_sample(int(kwargs["sampled_at_epoch_ms"]), digest)

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
        self.assertFalse(
            json.dumps(envelope, sort_keys=True).lower().count("token")
            and "token_material_copied\":true" in json.dumps(envelope, sort_keys=True).lower()
        )
        self.assertIn(" stop ", envelope["monitor"]["stop_command"])
        self.assertIn(" rollback ", envelope["monitor"]["rollback_command"])

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

    def test_interval_bounds_fail_closed_before_start(self) -> None:
        self.args.interval_seconds = 59
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "interval"):
                monitor._build_config(self.args)
        self.args.interval_seconds = 3601
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "interval"):
                monitor._build_config(self.args)


if __name__ == "__main__":
    unittest.main()
