from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import signal
import subprocess
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime
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


def _snapshot_entry(root: Path, snapshot_database: Path, payload: bytes = b"runtime snapshot") -> dict[str, object]:
    snapshot_database.parent.mkdir(parents=True, exist_ok=True)
    snapshot_database.write_bytes(payload)
    return {
        "schema_version": "p03-heartbeat-runtime-authority-snapshot.v1",
        "status": "pass",
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "source_database": "state/agentic-os/control.db",
        "source_sidecars_observed": ["control.db-wal"],
        "snapshot_database": snapshot_database.relative_to(root).as_posix(),
        "snapshot_sha256": hashlib.sha256(payload).hexdigest(),
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
    }


class HeartbeatShadowSoakMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        monitor._ACTIVE_SIGNAL_CONFIG = None
        self.addCleanup(setattr, monitor, "_ACTIVE_SIGNAL_CONFIG", None)
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
        self.anchor_key = "phase-c-anchor-test-key-with-32-byte-floor"
        env_patch = mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: self.anchor_key},
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.verifier_session_key_sha256 = hashlib.sha256(
            b"phase-c-session"
        ).hexdigest()
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
                    "session_key_sha256": self.verifier_session_key_sha256,
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
                    "session_key_sha256": self.verifier_session_key_sha256,
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

        def snapshot_side_effect(**kwargs: object) -> dict[str, object]:
            return _snapshot_entry(self.root, Path(kwargs["snapshot_database"]))

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
                side_effect=snapshot_side_effect,
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

    def test_runtime_snapshot_trailing_receipt_is_reconciled_with_core_samples(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=str(config["run_id"]),
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            sample = _pass_sample(1_700_000_300_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, sample)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            first_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000300000.db",
            )
            trailing_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000600000.db",
                b"trailing snapshot",
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [first_snapshot, trailing_snapshot],
                },
            )

            envelope = monitor._envelope(config=config, status="running")

        self.assertEqual(envelope["runtime_snapshots"]["snapshots_count"], 1)

    def test_runtime_snapshot_trailing_receipt_is_archived_before_next_append(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=str(config["run_id"]),
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            first_sample = _pass_sample(1_700_000_300_000, digest)
            next_sample = _pass_sample(1_700_000_900_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, first_sample)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            first_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000300000.db",
            )
            orphan_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000600000.db",
                b"orphan snapshot",
            )
            new_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000900000.db",
                b"new snapshot",
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [first_snapshot, orphan_snapshot],
                },
            )

            monitor._append_runtime_snapshot_receipt(config, new_snapshot)

            ledger = json.loads(
                (self.state_dir / "runtime-snapshot-receipts.json").read_text(
                    encoding="utf-8"
                )
            )
            archive = json.loads(
                (self.state_dir / "runtime-snapshot-orphans.json").read_text(
                    encoding="utf-8"
                )
            )
            validated = monitor._validate_runtime_snapshot_receipts(
                config,
                ledger,
                samples=[first_sample, next_sample],
            )

        self.assertEqual(
            [item["snapshot_database"] for item in ledger["snapshots"]],
            [first_snapshot["snapshot_database"], new_snapshot["snapshot_database"]],
        )
        self.assertEqual(len(archive["orphans"]), 1)
        self.assertEqual(
            archive["orphans"][0]["reason"],
            "unmatched_trailing_before_append",
        )
        self.assertEqual(
            archive["orphans"][0]["snapshot"]["snapshot_database"],
            orphan_snapshot["snapshot_database"],
        )
        self.assertEqual(len(validated), 2)

    def test_runtime_snapshot_orphan_archive_rejects_symlink(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=str(config["run_id"]),
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=300,
            )
            first_sample = _pass_sample(1_700_000_300_000, digest)
            receipt = monitor.append_heartbeat_soak_sample(receipt, first_sample)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            first_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000300000.db",
            )
            orphan_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000600000.db",
                b"orphan snapshot",
            )
            new_snapshot = _snapshot_entry(
                self.root,
                snapshot_root / "sample-1700000900000.db",
                b"new snapshot",
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [first_snapshot, orphan_snapshot],
                },
            )
            external_archive = self.root / "outside-orphan-archive.json"
            monitor._atomic_write_json(
                external_archive,
                {
                    "schema_version": f"{monitor.SCHEMA_SNAPSHOTS}.orphans",
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "orphans": [],
                },
            )
            external_before = external_archive.read_text(encoding="utf-8")
            (self.state_dir / "runtime-snapshot-orphans.json").symlink_to(
                external_archive
            )

            with self.assertRaisesRegex(
                monitor.MonitorError,
                "orphan archive path must not be a symlink",
            ):
                monitor._append_runtime_snapshot_receipt(config, new_snapshot)

        self.assertEqual(external_archive.read_text(encoding="utf-8"), external_before)

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
                    "session_key_sha256": self.verifier_session_key_sha256,
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

    def test_predecessor_validation_rejects_plaintext_verifier_session_key(self) -> None:
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
                    "sha256": hashlib.sha256(b"irrelevant").hexdigest(),
                },
            },
        )
        self.args.expected_independent_validation_sha256 = validation_sha
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "must redact session_key"):
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
                    "session_key_sha256": self.verifier_session_key_sha256,
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
                    "session_key_sha256": self.verifier_session_key_sha256,
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

    def test_predecessor_validation_rejects_weak_anchor_hmac_key(self) -> None:
        lifecycle_sha = hashlib.sha256(self.lifecycle.read_bytes()).hexdigest()
        weak_key = "x"
        anchor_sha = _write_json(
            self.validation_anchor,
            _signed_anchor(
                {
                    "schema_version": "agentic-os.independent-validation-anchor.v1",
                    "record_authority": "phase_c_terminal_checkpoint",
                    "validation_verdict": "pass",
                    "receipt_sha256": lifecycle_sha,
                    "implementation_head": monitor.EXPECTED_IMPLEMENTATION_BASE,
                    "verifier": {
                        "identity": "security-engineer-phase-c",
                        "role": "independent_verifier",
                        "session_key_sha256": self.verifier_session_key_sha256,
                    },
                },
                weak_key,
            ),
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
                    "session_key_sha256": self.verifier_session_key_sha256,
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
        self.args.expected_independent_validation_sha256 = validation_sha

        with mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: weak_key},
        ), mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "signature key is too weak"):
                monitor._build_config(self.args)

    def test_committed_default_validation_anchor_is_externally_signed_and_bound(
        self,
    ) -> None:
        repo_root = SCRIPT_PATH.parents[1]
        validation_path = (
            repo_root
            / "docs/runtime-evidence/phase-b-p03-independent-validation-20260821T065433Z.json"
        )
        anchor_path = (
            repo_root
            / "docs/runtime-evidence/phase-b-p03-independent-validation-anchor-20260821T065433Z.json"
        )
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        invalid_hmac_key = "not-the-independent-validation-anchor-signature-key"
        completed_at = datetime.fromisoformat(
            validation["validated_at_utc"].replace("Z", "+00:00")
        )
        implementation_committed_at = datetime.fromisoformat(
            validation["invocation"]["implementation_commit_committed_at"]
        )

        self.assertGreaterEqual(completed_at, implementation_committed_at)
        for head_key in ("reviewed_head", "review_merge_head"):
            self.assertEqual(
                subprocess.run(
                    [
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        monitor.EXPECTED_IMPLEMENTATION_BASE,
                        validation["invocation"][head_key],
                    ],
                    cwd=repo_root,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode,
                0,
            )
        self.assertEqual(
            monitor._sha256_file(validation_path),
            monitor.EXPECTED_INDEPENDENT_VALIDATION_SHA256,
        )
        self.assertEqual(
            validation["authenticated_record"]["sha256"],
            monitor._sha256_file(anchor_path),
        )
        with mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: invalid_hmac_key},
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "signature mismatch"):
                monitor._validate_independent_validation_anchor(
                    {
                        "exact_heads": {
                            "implementation_base": monitor.EXPECTED_IMPLEMENTATION_BASE
                        }
                    },
                    validation,
                )
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                monitor.MonitorError, "signature key is unavailable"
            ):
                monitor._validate_independent_validation_anchor(
                    {
                        "exact_heads": {
                            "implementation_base": monitor.EXPECTED_IMPLEMENTATION_BASE
                        }
                    },
                    validation,
                )
        with mock.patch.dict(
            os.environ,
            {monitor.INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV: invalid_hmac_key},
        ):
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
                with self.assertRaisesRegex(monitor.MonitorError, "signature mismatch"):
                    monitor._build_config(args)

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

    def test_run_revalidates_saved_predecessor_receipts_before_resuming(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(
            monitor, "_write_pidfile", side_effect=AssertionError("must not resume")
        ):
            config = monitor._build_config(self.args)
            config["predecessor_receipts"]["lifecycle"]["sha256"] = "0" * 64
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["monitor_resume_identity_invalid"])
        self.assertIn("predecessor receipt summary mismatch", envelope["note"])

    def test_run_rejects_tampered_resume_paths_before_pidfile_write(self) -> None:
        attacker_pidfile = self.root.parent / "attacker-monitor.pid"
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract", side_effect=AssertionError("must not git")
        ), mock.patch.object(
            monitor, "_write_pidfile", side_effect=AssertionError("must not write pid")
        ):
            config = monitor._build_config(self.args)
            config["pidfile_path"] = str(attacker_pidfile)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        self.assertFalse(attacker_pidfile.exists())

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

        with mock.patch.object(monitor, "_git_text", side_effect=clean_git), mock.patch.object(
            monitor, "_git_check", return_value=True
        ) as git_check:
            monitor._assert_start_git_contract(config)

        self.assertIn(
            [
                "cat-file",
                "-e",
                f"{heads['monitor_implementation_head']}^{{commit}}",
            ],
            clean_calls,
        )
        git_check.assert_called_with(
            self.root,
            [
                "merge-base",
                "--is-ancestor",
                heads["implementation_base"],
                heads["monitor_implementation_head"],
            ],
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

    def test_start_git_contract_rejects_non_ancestor_despite_valid_predecessor_receipts(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
        heads = config["exact_heads"]

        def non_ancestor_git(_repo_root: Path, argv: list[str], _label: str) -> str:
            if argv == ["status", "--porcelain=v1"]:
                return ""
            if argv == ["rev-parse", "HEAD"]:
                return str(heads["monitor_implementation_head"])
            if argv == [
                "cat-file",
                "-e",
                f"{heads['monitor_implementation_head']}^{{commit}}",
            ]:
                return ""
            raise AssertionError(f"unexpected git text call: {argv}")

        with mock.patch.object(
            monitor, "_git_text", side_effect=non_ancestor_git
        ), mock.patch.object(
            monitor, "_git_check", return_value=False
        ), mock.patch.object(
            monitor,
            "_verified_predecessor_summary",
            side_effect=AssertionError("predecessor receipt fallback is unsafe"),
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "must be an ancestor"):
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

    def test_start_rejects_stale_stop_request_before_first_sample(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.state_dir / "stop-request.json",
            {"schema_version": monitor.SCHEMA_STOP, "requested_at": "stale"},
        )
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(
            monitor, "_first_sample", side_effect=AssertionError("must not sample")
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "stale stop request"):
                monitor.start(self.args)

    def test_start_rejects_existing_state_reservation_before_first_sample(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.state_dir / "monitor-start-reservation.json",
            {"schema_version": monitor.SCHEMA_START_RESERVATION, "status": "reserved"},
        )
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(
            monitor, "_first_sample", side_effect=AssertionError("must not sample")
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "start reservation"):
                monitor.start(self.args)

    def test_start_rejects_symlinked_state_dir_before_reservation_write(self) -> None:
        outside_parent = tempfile.TemporaryDirectory()
        self.addCleanup(outside_parent.cleanup)
        outside_state_dir = Path(outside_parent.name) / "outside-state"
        state_link = self.root / "docs/runtime-evidence/soak-link"
        state_link.symlink_to(outside_state_dir, target_is_directory=True)
        args = Namespace(**{**self.args.__dict__, "state_dir": state_link})

        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_first_sample", side_effect=AssertionError("must not sample")
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "state_dir.*symlink"):
                monitor.start(args)

        self.assertFalse(outside_state_dir.exists())
        self.assertFalse((outside_state_dir / "monitor-start-reservation.json").exists())

    def test_start_reserves_state_before_first_sample_and_releases_after_no_daemon(
        self,
    ) -> None:
        digest = "a" * 64
        first = _pass_sample(1_700_000_000_000, digest)
        reservation = self.state_dir / "monitor-start-reservation.json"

        def first_sample(config: dict[str, object]) -> dict[str, object]:
            self.assertTrue(reservation.exists())
            self.assertEqual(
                json.loads(reservation.read_text(encoding="utf-8"))["schema_version"],
                monitor.SCHEMA_START_RESERVATION,
            )
            return first

        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(monitor, "_first_sample", side_effect=first_sample):
            result = monitor.start(self.args)

        self.assertEqual(result, 0)
        self.assertFalse(reservation.exists())

    def test_start_releases_state_reservation_when_git_contract_fails(self) -> None:
        reservation = self.state_dir / "monitor-start-reservation.json"
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor,
            "_assert_start_git_contract",
            side_effect=monitor.MonitorError("dirty worktree"),
        ), mock.patch.object(
            monitor, "_first_sample", side_effect=AssertionError("must not sample")
        ):
            with self.assertRaisesRegex(monitor.MonitorError, "dirty worktree"):
                monitor.start(self.args)

        self.assertFalse(reservation.exists())

    def test_start_terminates_daemon_when_pidfile_publication_fails(self) -> None:
        digest = "a" * 64
        first = _pass_sample(1_700_000_000_000, digest)
        args = Namespace(**{**self.args.__dict__, "no_daemon": False})
        process = mock.Mock(pid=12345)
        process.poll.return_value = None
        process.wait.return_value = 0

        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ), mock.patch.object(
            monitor, "_first_sample", return_value=first
        ), mock.patch.object(
            monitor.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            Path, "write_text", side_effect=OSError("pid write failed")
        ), mock.patch.object(
            monitor, "_wait_for_daemon_ready", side_effect=AssertionError("not ready")
        ):
            with self.assertRaisesRegex(OSError, "pid write failed"):
                monitor.start(args)

        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=monitor.DAEMON_READY_TIMEOUT_SECONDS)
        self.assertFalse((self.state_dir / "monitor-start-reservation.json").exists())

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

    def test_runtime_snapshot_ledger_is_bound_to_run_file_hash_and_sample(self) -> None:
        digest = "a" * 64
        epoch = 1_700_000_000_123
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            snapshot_path = monitor._runtime_snapshot_path(config, epoch)
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot_path.write_bytes(b"snapshot-ledger")
            entry = {
                "schema_version": "p03-heartbeat-runtime-authority-snapshot.v1",
                "status": "pass",
                "authority": "file_artifacts",
                "db_authority_enabled": False,
                "source_database": "state/agentic-os/control.db",
                "source_sidecars_observed": [],
                "snapshot_database": snapshot_path.relative_to(self.root).as_posix(),
                "snapshot_sha256": hashlib.sha256(b"snapshot-ledger").hexdigest(),
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
            }
            ledger_path = Path(config["runtime_snapshot_receipts_path"])
            _write_json(
                ledger_path,
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": "other-run",
                    "scope": "local_recovery_only",
                    "snapshots": [entry],
                },
            )
            with self.assertRaisesRegex(monitor.MonitorError, "run_id mismatch"):
                monitor._append_runtime_snapshot_receipt(config, entry)

            drifted = {**entry, "snapshot_sha256": "b" * 64}
            _write_json(
                ledger_path,
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [drifted],
                },
            )
            with self.assertRaisesRegex(monitor.MonitorError, "hash mismatch"):
                monitor._append_runtime_snapshot_receipt(config, entry)

            document = {
                "schema_version": monitor.SCHEMA_SNAPSHOTS,
                "run_id": config["run_id"],
                "scope": "local_recovery_only",
                "snapshots": [entry],
            }
            with self.assertRaisesRegex(monitor.MonitorError, "does not match its sample"):
                monitor._validate_runtime_snapshot_receipts(
                    config,
                    document,
                    samples=[_pass_sample(epoch + 1, digest)],
                )

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

    def test_run_recovers_missing_complete_core_receipt_authentication(self) -> None:
        digest = "a" * 64
        args = Namespace(**{**self.args.__dict__, "interval_seconds": 3600})
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "_assert_start_git_contract"
        ):
            config = monitor._build_config(args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=3600,
            )
            snapshots = []
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            for index in range(25):
                sampled_at = 1_700_000_000_000 + index * 3_600_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
                snapshots.append(
                    _snapshot_entry(
                        self.root,
                        snapshot_root / f"sample-{sampled_at}.db",
                        f"snapshot-{index}".encode("utf-8"),
                    )
                )
            self.assertEqual(receipt["status"], "complete")
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": snapshots,
                },
            )

            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        self.assertTrue(
            (self.state_dir / "core-soak-receipt-authentication.json").exists()
        )
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "complete")
        self.assertEqual(envelope["violations"], [])

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

        with mock.patch.object(monitor, "REPO_ROOT", self.root):
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

    def test_status_requires_core_receipt_for_complete_envelope(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("terminal monitor status requires core receipt", envelope["note"])

    def test_status_requires_complete_core_receipt_for_complete_envelope(self) -> None:
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
            self.assertEqual(receipt["status"], "in_progress")
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [],
                },
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("requires complete core receipt", envelope["note"])

    def test_status_requires_snapshot_ledger_for_complete_envelope(self) -> None:
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
            for index in range(289):
                sampled_at = 1_700_000_000_000 + index * 300_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
            self.assertEqual(receipt["status"], "complete")
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("requires runtime snapshot ledger", envelope["note"])

    def test_status_rejects_trailing_snapshot_on_complete_envelope(self) -> None:
        digest = "a" * 64
        args = Namespace(**{**self.args.__dict__, "interval_seconds": 3600})
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=3600,
            )
            snapshots = []
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            for index in range(25):
                sampled_at = 1_700_000_000_000 + index * 3_600_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
                snapshots.append(
                    _snapshot_entry(
                        self.root,
                        snapshot_root / f"sample-{sampled_at}.db",
                        f"snapshot-{index}".encode("utf-8"),
                    )
                )
            self.assertEqual(receipt["status"], "complete")
            trailing_epoch = 1_700_000_000_000 + 25 * 3_600_000
            trailing = _snapshot_entry(
                self.root,
                snapshot_root / f"sample-{trailing_epoch}.db",
                b"unmatched terminal trailing snapshot",
            )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": [*snapshots, trailing],
                },
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("trailing receipt is unreconciled", envelope["note"])

    def test_status_requires_authenticated_complete_core_receipt(self) -> None:
        digest = "a" * 64
        args = Namespace(**{**self.args.__dict__, "interval_seconds": 3600})
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=3600,
            )
            snapshots = []
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            for index in range(25):
                sampled_at = 1_700_000_000_000 + index * 3_600_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
                snapshots.append(
                    _snapshot_entry(
                        self.root,
                        snapshot_root / f"sample-{sampled_at}.db",
                        f"snapshot-{index}".encode("utf-8"),
                    )
                )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": snapshots,
                },
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("terminal signature", envelope["note"])

    def test_status_accepts_authenticated_complete_core_receipt(self) -> None:
        digest = "a" * 64
        args = Namespace(**{**self.args.__dict__, "interval_seconds": 3600})
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            receipt = monitor.new_heartbeat_soak_receipt(
                run_id=config["run_id"],
                authority_input_digest=digest,
                started_at_epoch_ms=1_700_000_000_000,
                started_at_monotonic_ms=1_700_000_000_000,
                duration_hours=24,
                sample_interval_seconds=3600,
            )
            snapshots = []
            snapshot_root = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/phase-b-test-soak"
            )
            for index in range(25):
                sampled_at = 1_700_000_000_000 + index * 3_600_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
                snapshots.append(
                    _snapshot_entry(
                        self.root,
                        snapshot_root / f"sample-{sampled_at}.db",
                        f"snapshot-{index}".encode("utf-8"),
                    )
                )
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "runtime-snapshot-receipts.json",
                {
                    "schema_version": monitor.SCHEMA_SNAPSHOTS,
                    "run_id": config["run_id"],
                    "scope": "local_recovery_only",
                    "snapshots": snapshots,
                },
            )
            monitor._write_core_receipt_authentication(config)
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 0)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "complete")
        self.assertEqual(envelope["violations"], [])

    def test_status_rejects_symlinked_envelope_before_read_or_write(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        outside = self.root / "outside-envelope.json"
        outside.write_text('{"status":"running"}', encoding="utf-8")
        try:
            (self.state_dir / "monitor-envelope.json").symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")

        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            with self.assertRaisesRegex(monitor.MonitorError, "must not be a symlink"):
                monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(outside.read_text(encoding="utf-8"), '{"status":"running"}')

    def test_status_rejects_terminal_receipt_from_other_monitor_config(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
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
                sample_interval_seconds=3600,
            )
            for index in range(25):
                sampled_at = 1_700_000_000_000 + index * 3_600_000
                receipt = monitor.append_heartbeat_soak_sample(
                    receipt,
                    _pass_sample(sampled_at, digest, sampled_at),
                )
            self.assertEqual(receipt["status"], "complete")
            monitor.persist_heartbeat_soak_receipt(
                self.state_dir / "core-soak-receipt.json",
                receipt,
                repo_root_path=self.root,
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "complete", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_core_receipt_invalid"])
        self.assertIn("run_id", envelope["note"])

    def test_status_requires_rollback_receipt_for_rolled_back_envelope(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "rolled_back", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_rollback_receipt_invalid"])
        self.assertIn("terminal monitor status requires rollback receipt", envelope["note"])

    def test_status_rejects_forged_rollback_receipt_for_rolled_back_envelope(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            monitor._atomic_write_json(
                self.state_dir / "rollback-receipt.json",
                {
                    "schema_version": "p03-heartbeat-forced-rollback-receipt.v1",
                    "status": "pass",
                    "workflow": "heartbeat",
                    "authority": "file_artifacts",
                    "db_authority_enabled": False,
                    "authority_input_digest": "b" * 64,
                    "file_authority_view_recreated": True,
                    "shadow_database_removed": True,
                    "recoverable_local_backup_created": True,
                    "parity_percent": 100,
                    "parity": {"status": "pass", "percent": 100, "mismatch_count": 0},
                },
            )
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "rolled_back", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_rollback_receipt_invalid"])
        self.assertIn("authority digest", envelope["note"])

    def test_status_rejects_rolled_back_when_shadow_database_reappears(self) -> None:
        digest = "a" * 64
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            config["authority_input_digest"] = digest
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)
            backup = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-rollback/recreated/control.db"
            )
            snapshot = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-rollback/recreated/audit.db"
            )
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(b"backup")
            snapshot.write_bytes(b"snapshot")
            monitor._atomic_write_json(
                self.state_dir / "rollback-receipt.json",
                {
                    "schema_version": "p03-heartbeat-forced-rollback-receipt.v1",
                    "status": "pass",
                    "workflow": "heartbeat",
                    "authority": "file_artifacts",
                    "db_authority_enabled": False,
                    "authority_input_digest": digest,
                    "file_authority_view_recreated": True,
                    "shadow_database_removed": True,
                    "recoverable_local_backup_created": True,
                    "recoverable_local_backup_path": backup.relative_to(self.root).as_posix(),
                    "recoverable_local_backup_sha256": hashlib.sha256(b"backup").hexdigest(),
                    "audit_snapshot_database": snapshot.relative_to(self.root).as_posix(),
                    "audit_snapshot_sha256": hashlib.sha256(b"snapshot").hexdigest(),
                    "parity_percent": 100,
                    "parity": {"status": "pass", "percent": 100, "mismatch_count": 0},
                },
            )
            (self.root / "state/agentic-os").mkdir(parents=True, exist_ok=True)
            (self.root / "state/agentic-os/control.db").write_bytes(b"recreated")
            monitor._atomic_write_json(
                self.state_dir / "monitor-envelope.json",
                {"status": "rolled_back", "violations": []},
            )

            result = monitor.status(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        envelope = json.loads(
            (self.state_dir / "monitor-envelope.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["status"], "failed_closed")
        self.assertEqual(envelope["violations"], ["terminal_rollback_receipt_invalid"])
        self.assertIn("shadow database exists", envelope["note"])

    def test_resume_rejects_tampered_authority_input_paths_before_sampling(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            stale_config = self.root / "docs/runtime-evidence/soak/stale-openclaw.json"
            stale_config.write_text(self.live_config.read_text(encoding="utf-8"), encoding="utf-8")
            config["live_config_path"] = str(stale_config)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)

            result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        self.assertFalse((self.state_dir / "monitor.pid").exists())

    def test_resume_rejects_self_consistent_authority_path_tamper_before_sampling(
        self,
    ) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            stale_config = self.root / "docs/runtime-evidence/soak/stale-openclaw.json"
            stale_config.write_text(
                self.live_config.read_text(encoding="utf-8"), encoding="utf-8"
            )
            config["live_config_path"] = str(stale_config.resolve())
            config["authority_input_paths"] = monitor._authority_input_path_identities(
                baseline_path=self.baseline,
                heartbeat_file=self.heartbeat,
                live_config_path=stale_config,
            )
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)

            with mock.patch.object(
                monitor, "_assert_start_git_contract"
            ) as git_contract, mock.patch.object(
                monitor, "_sample", side_effect=AssertionError("must not sample")
            ) as sample:
                result = monitor.run(Namespace(state_dir=self.state_dir))

        self.assertEqual(result, 2)
        git_contract.assert_not_called()
        sample.assert_not_called()
        self.assertFalse((self.state_dir / "monitor.pid").exists())

    def test_start_rejects_symlinked_output_before_first_sample(self) -> None:
        outside = self.root / "outside-monitor-config.json"
        with mock.patch.object(monitor, "REPO_ROOT", self.root), mock.patch.object(
            monitor, "run_heartbeat_file_shadow_cycle"
        ) as first_sample:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            (self.state_dir / "monitor-config.json").symlink_to(outside)

            with self.assertRaisesRegex(monitor.MonitorError, "monitor_config_path"):
                monitor.start(self.args)

        first_sample.assert_not_called()
        self.assertFalse(outside.exists())

    def test_stop_revalidates_saved_paths_before_writing_request(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            tampered_stop_path = self.root / "outside-stop-request.json"
            config["stop_request_path"] = str(tampered_stop_path)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)

            with self.assertRaisesRegex(monitor.MonitorError, "stop_request_path"):
                monitor.stop(
                    Namespace(
                        state_dir=self.state_dir,
                        reason="test",
                        wait_seconds=0,
                    )
                )

        self.assertFalse(tampered_stop_path.exists())

    def test_rollback_revalidates_saved_paths_before_receipt_or_mutation(self) -> None:
        with mock.patch.object(monitor, "REPO_ROOT", self.root):
            config = monitor._build_config(self.args)
            tampered_envelope = self.root / "outside-monitor-envelope.json"
            config["monitor_envelope_path"] = str(tampered_envelope)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            monitor._atomic_write_json(self.state_dir / "monitor-config.json", config)

            with mock.patch.object(
                monitor, "force_heartbeat_file_authority_rollback"
            ) as rollback:
                with self.assertRaisesRegex(monitor.MonitorError, "monitor_envelope_path"):
                    monitor.rollback(
                        Namespace(
                            state_dir=self.state_dir,
                            rollback_id="tampered-config",
                            allow_running=True,
                        )
                    )

        rollback.assert_not_called()
        self.assertFalse(tampered_envelope.exists())

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
            monitor,
            "_load_validated_resume_config",
            return_value={"state_dir": str(self.state_dir)},
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
            monitor,
            "_load_validated_resume_config",
            return_value={"state_dir": str(self.state_dir)},
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

    def test_signal_uses_active_validated_config_when_disk_config_is_tampered(self) -> None:
        active_config = {
            "state_dir": str(self.state_dir),
            "stop_request_path": str(self.state_dir / "stop-request.json"),
        }
        with mock.patch.dict(
            os.environ,
            {"HEARTBEAT_SHADOW_MONITOR_STATE_DIR": str(self.state_dir)},
        ), mock.patch.object(
            monitor, "_ACTIVE_SIGNAL_CONFIG", active_config
        ), mock.patch.object(
            monitor, "_load_validated_resume_config"
        ) as load_config, mock.patch.object(
            monitor, "_stop_requested", return_value=False
        ), mock.patch.object(
            monitor, "_persist_envelope"
        ) as persist:
            with self.assertRaises(SystemExit) as raised:
                monitor._handle_signal(signal.SIGTERM, None)

        self.assertEqual(raised.exception.code, 2)
        load_config.assert_not_called()
        persist.assert_called_once_with(
            active_config,
            status="failed_closed",
            violation=f"signal_{signal.SIGTERM}",
        )


if __name__ == "__main__":
    unittest.main()
