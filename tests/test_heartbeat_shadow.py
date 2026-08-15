from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import agentic_os
import agentic_os.heartbeat_shadow as heartbeat_shadow_module
from agentic_os.heartbeat_shadow import (
    HeartbeatShadowError,
    append_heartbeat_soak_sample,
    force_heartbeat_file_authority_rollback,
    heartbeat_authority_manifest,
    heartbeat_parity_sample,
    new_heartbeat_soak_receipt,
    persist_heartbeat_soak_receipt,
    run_heartbeat_dual_write_projection,
    run_heartbeat_file_shadow_cycle,
    snapshot_heartbeat_runtime_authority_database,
    validate_heartbeat_soak_receipt,
)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class HeartbeatShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        subprocess.run(
            ["git", "init", "-q"],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (self.root / ".gitignore").write_text(
            "state/agentic-os/\n", encoding="utf-8"
        )
        self.heartbeat_file = self.root / "HEARTBEAT.md"
        self.heartbeat_file.write_text(
            "# Heartbeat\n\n- Check one bounded maintenance item.\n",
            encoding="utf-8",
        )
        self.live_config_path = self.root / "openclaw.json"
        self.baseline_path = self.root / "evidence/heartbeat-baseline.json"
        self.manifest_path = self.root / "artifacts/heartbeat-authority.json"
        self.projection_path = self.root / "artifacts/heartbeat-dual-write.json"
        self.database = self.root / "state/agentic-os/control.db"
        self._write_baseline()

    def _baseline(self, *, every: str = "30m") -> dict[str, object]:
        scheduler = {"every": every, "target": "main"}
        scheduler_digest = hashlib.sha256(
            _canonical_json(scheduler).rstrip(b"\n")
        ).hexdigest()
        return {
            "schema_version": "p03-heartbeat-authority-baseline.v1",
            "captured_at": "2026-08-13T07:00:00Z",
            "classification": "sanitized_read_only_projection",
            "file_authority": {
                "path": str(self.heartbeat_file),
                "sha256": hashlib.sha256(self.heartbeat_file.read_bytes()).hexdigest(),
                "active_periodic_tasks": 1,
            },
            "scheduler_projection": {
                "source": "agents.defaults.heartbeat",
                "value": scheduler,
                "canonical_json_sha256": scheduler_digest,
            },
            "privacy_boundary": {
                "allowed_config_path": "agents.defaults.heartbeat",
                "full_openclaw_config_persisted": False,
                "secrets_persisted": False,
            },
            "runtime_interpretation": {
                "db_authority_enabled": False,
                "file_artifacts_remain_authority": True,
                "production_dispatch_controlled_by_shadow_db": False,
            },
        }

    def _write_baseline(self, *, every: str = "30m") -> None:
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.live_config_path.write_bytes(
            _canonical_json(
                {"agents": {"defaults": {"heartbeat": {"every": every, "target": "main"}}}}
            )
        )
        self.baseline_path.write_bytes(_canonical_json(self._baseline(every=every)))

    def _file_shadow_cycle(self, run_id: str = "heartbeat-file-shadow") -> dict[str, object]:
        return run_heartbeat_file_shadow_cycle(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            manifest_path=self.manifest_path,
            run_id=run_id,
            database=self.database,
            repo_root_path=self.root,
            observed_at_epoch_ms=1_700_000_000_000,
        )

    def _insert_runtime_authority_lease(self, run_id: str) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "runtime-authority-transition",
                    run_id,
                    "before",
                    "after",
                    "dispatch",
                    "allow_lease_acquire",
                    "R1",
                    "runtime-authority-transition-key",
                    1,
                    "now",
                ),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "runtime-authority-lease",
                    run_id,
                    "phase",
                    "runtime-authority-transition",
                    "worker",
                    "requester",
                    "acquire_pending",
                    "runtime-authority-client-lease",
                    "runtime-authority-acquire-key",
                    "runtime-authority-release-key",
                    60_000,
                    "now",
                    "later",
                    1_700_000_000_000,
                ),
            )

    def test_file_authority_cycle_projects_only_shadow_and_receipts_100_percent(self) -> None:
        receipt = self._file_shadow_cycle()

        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        self.assertEqual(receipt["authority"], "file_artifacts")
        self.assertIs(receipt["db_authority_enabled"], False)
        self.assertEqual(receipt["parity"]["percent"], 100)
        self.assertEqual(receipt["parity"]["mismatch_count"], 0)
        self.assertEqual(set(receipt["runtime_authority_counts"].values()), {0})
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM leases").fetchone(), (0,)
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM spawn_requests").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM sessions").fetchone(), (0,)
            )

    def test_manifest_rejects_authority_drift_privacy_weakening_and_db_authority(self) -> None:
        self.heartbeat_file.write_text("# drift\n", encoding="utf-8")
        with self.assertRaisesRegex(HeartbeatShadowError, "drifted"):
            heartbeat_authority_manifest(
                self.baseline_path, self.heartbeat_file, self.live_config_path
            )

        self.heartbeat_file.write_text(
            "# Heartbeat\n\n- Check one bounded maintenance item.\n",
            encoding="utf-8",
        )
        unsafe = self._baseline()
        unsafe["privacy_boundary"]["secrets_persisted"] = True
        self.baseline_path.write_bytes(_canonical_json(unsafe))
        with self.assertRaisesRegex(HeartbeatShadowError, "privacy boundary"):
            heartbeat_authority_manifest(
                self.baseline_path, self.heartbeat_file, self.live_config_path
            )

        self._write_baseline()
        with mock.patch.object(agentic_os, "DB_AUTHORITY_ENABLED", True):
            with self.assertRaisesRegex(HeartbeatShadowError, "authority must remain disabled"):
                heartbeat_authority_manifest(
                    self.baseline_path, self.heartbeat_file, self.live_config_path
                )

    def test_manifest_rejects_unsafe_scheduler_projection_and_live_config_drift(self) -> None:
        unsafe = self._baseline()
        unsafe["scheduler_projection"]["value"]["token"] = "not-safe"
        self.baseline_path.write_bytes(_canonical_json(unsafe))
        with self.assertRaisesRegex(HeartbeatShadowError, "unsupported scheduler fields"):
            heartbeat_authority_manifest(
                self.baseline_path, self.heartbeat_file, self.live_config_path
            )

        self._write_baseline()
        self.live_config_path.write_bytes(
            _canonical_json(
                {"agents": {"defaults": {"heartbeat": {"every": "5m", "target": "main"}}}}
            )
        )
        with self.assertRaisesRegex(HeartbeatShadowError, "live Heartbeat scheduler"):
            heartbeat_authority_manifest(
                self.baseline_path, self.heartbeat_file, self.live_config_path
            )

    def test_cycle_rejects_artifacts_and_database_outside_checked_root(self) -> None:
        outside = Path(self.temporary.name).parent / "heartbeat-outside.json"
        self.addCleanup(outside.unlink, missing_ok=True)
        with self.assertRaisesRegex(HeartbeatShadowError, "inside the checked worktree"):
            run_heartbeat_file_shadow_cycle(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                manifest_path=outside,
                run_id="outside-manifest",
                database=self.database,
                repo_root_path=self.root,
            )
        self.assertFalse(outside.exists())

        wrong_database = self.root / "state/agentic-os/not-control.db"
        with self.assertRaisesRegex(HeartbeatShadowError, "must use ignored"):
            run_heartbeat_file_shadow_cycle(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                manifest_path=self.manifest_path,
                run_id="wrong-db",
                database=wrong_database,
                repo_root_path=self.root,
            )

    def test_dual_write_requires_exact_prior_parity_and_remains_non_authoritative(self) -> None:
        prior = self._file_shadow_cycle()
        receipt = run_heartbeat_dual_write_projection(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projection_receipt_path=self.projection_path,
            run_id="heartbeat-dual-write",
            prior_file_shadow_receipt=prior,
            database=self.database,
            repo_root_path=self.root,
            observed_at_epoch_ms=1_700_000_060_000,
        )

        self.assertEqual(receipt["parity"]["percent"], 100)
        self.assertIs(receipt["db_authority_enabled"], False)
        self.assertEqual(set(receipt["runtime_authority_counts"].values()), {0})
        projection = json.loads(self.projection_path.read_text(encoding="utf-8"))
        self.assertEqual(projection["authority"], "file_artifacts")
        self.assertIs(projection["db_authority_enabled"], False)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("dual_write_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM workflow_authority "
                    "WHERE mode IN ('db_authority_canary','db_authority')"
                ).fetchone(),
                (0,),
            )

        tampered = {**prior, "parity": {**prior["parity"], "percent": 99}}
        with self.assertRaisesRegex(HeartbeatShadowError, "100% parity PASS"):
            run_heartbeat_dual_write_projection(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                projection_receipt_path=self.root / "artifacts/rejected.json",
                run_id="heartbeat-rejected",
                prior_file_shadow_receipt=tampered,
                database=self.database,
                repo_root_path=self.root,
            )

    def test_parity_samples_complete_only_after_bounded_24_hour_window(self) -> None:
        prior = self._file_shadow_cycle()
        started = 1_700_000_000_000
        receipt = new_heartbeat_soak_receipt(
            run_id="heartbeat-soak",
            authority_input_digest=prior["authority_input_digest"],
            started_at_epoch_ms=started,
            started_at_monotonic_ms=started,
            duration_hours=24,
            sample_interval_seconds=3600,
        )
        first = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=started,
            sampled_at_monotonic_ms=started,
            repo_root_path=self.root,
        )
        self.assertEqual(first["parity_percent"], 100)
        receipt = append_heartbeat_soak_sample(receipt, first)
        self.assertEqual(receipt["status"], "in_progress")

        final = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=started + 3_600_000,
            sampled_at_monotonic_ms=started + 3_600_000,
            repo_root_path=self.root,
        )
        receipt = append_heartbeat_soak_sample(receipt, final)
        for sampled_at in range(
            started + 7_200_000,
            receipt["deadline_epoch_ms"] + 1,
            3_600_000,
        ):
            receipt = append_heartbeat_soak_sample(
                receipt,
                heartbeat_parity_sample(
                    baseline_path=self.baseline_path,
                    heartbeat_file=self.heartbeat_file,
                    live_config_path=self.live_config_path,
                    projected_artifact=self.manifest_path,
                    run_id=prior["run_id"],
                    authority_input_digest=prior["authority_input_digest"],
                    authority_mode="file_authority_shadow",
                    database=self.database,
                    sampled_at_epoch_ms=sampled_at,
                    sampled_at_monotonic_ms=sampled_at,
                    repo_root_path=self.root,
                ),
            )
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(set(receipt["aggregate_counters"].values()), {0})

        receipt_path = self.root / "artifacts/heartbeat-soak.json"
        digest = persist_heartbeat_soak_receipt(
            receipt_path, receipt, repo_root_path=self.root
        )
        self.assertEqual(digest, hashlib.sha256(receipt_path.read_bytes()).hexdigest())
        validate_heartbeat_soak_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )

    def test_parity_sample_can_audit_sidecar_free_runtime_snapshot(self) -> None:
        prior = self._file_shadow_cycle()
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "UPDATE workflow_authority SET updated_at=updated_at WHERE workflow='heartbeat'"
            )
            connection.commit()
            self.assertTrue(
                self.database.with_name("control.db-wal").exists()
                or self.database.with_name("control.db-shm").exists()
            )
            direct = heartbeat_parity_sample(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                projected_artifact=self.manifest_path,
                run_id=prior["run_id"],
                authority_input_digest=prior["authority_input_digest"],
                authority_mode="file_authority_shadow",
                database=self.database,
                sampled_at_epoch_ms=1_700_000_060_000,
                sampled_at_monotonic_ms=1_700_000_060_000,
                repo_root_path=self.root,
            )
            self.assertEqual(direct["status"], "fail")
            self.assertEqual(direct["observation_error"], "runtime_authority_audit_error")

            snapshot_path = (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-soak/test/sample.db"
            )
            snapshot = snapshot_heartbeat_runtime_authority_database(
                source_database=self.database,
                snapshot_database=snapshot_path,
                repo_root_path=self.root,
            )

        self.assertTrue(snapshot_path.is_file())
        self.assertFalse(snapshot_path.with_name("sample.db-wal").exists())
        self.assertFalse(snapshot_path.with_name("sample.db-shm").exists())
        self.assertIs(snapshot["local_recovery_only"], True)
        self.assertIs(snapshot["packaging_retrieval_denied"], True)
        self.assertEqual(set(snapshot["runtime_authority_counts"].values()), {0})
        sample = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            runtime_audit_database=snapshot_path,
            sampled_at_epoch_ms=1_700_000_060_000,
            sampled_at_monotonic_ms=1_700_000_060_000,
            repo_root_path=self.root,
        )
        self.assertEqual(sample["status"], "pass")
        self.assertIs(sample["runtime_authority_counts_observed"], True)

    def test_parity_sample_records_file_drift_as_failed_sample(self) -> None:
        prior = self._file_shadow_cycle()
        self.heartbeat_file.write_text("# changed authority\n", encoding="utf-8")
        sample = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=1_700_000_060_000,
            sampled_at_monotonic_ms=1_700_000_060_000,
            repo_root_path=self.root,
        )

        self.assertEqual(sample["status"], "fail")
        self.assertEqual(sample["observation_error"], "authority_manifest_invalid")
        self.assertEqual(sample["counters"]["projection_drift"], 1)
        receipt = new_heartbeat_soak_receipt(
            run_id="heartbeat-soak-fail",
            authority_input_digest=prior["authority_input_digest"],
            started_at_epoch_ms=1_700_000_000_000,
            started_at_monotonic_ms=1_700_000_000_000,
            duration_hours=24,
            sample_interval_seconds=60,
        )
        receipt = append_heartbeat_soak_sample(receipt, sample)
        self.assertEqual(receipt["status"], "failed")

    def test_parity_sample_observes_fresh_live_heartbeat_config_drift(self) -> None:
        prior = self._file_shadow_cycle()
        self.live_config_path.write_bytes(
            _canonical_json(
                {"agents": {"defaults": {"heartbeat": {"every": "5m", "target": "main"}}}}
            )
        )
        sample = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=1_700_000_060_000,
            sampled_at_monotonic_ms=1_700_000_060_000,
            repo_root_path=self.root,
        )

        self.assertEqual(sample["status"], "fail")
        self.assertEqual(sample["observation_error"], "authority_manifest_invalid")
        self.assertEqual(sample["counters"]["projection_drift"], 1)

    def test_soak_rejects_tampered_samples_aggregates_and_early_completion(self) -> None:
        prior = self._file_shadow_cycle()
        started = 1_700_000_000_000
        receipt = new_heartbeat_soak_receipt(
            run_id="heartbeat-soak",
            authority_input_digest=prior["authority_input_digest"],
            started_at_epoch_ms=started,
            started_at_monotonic_ms=started,
            duration_hours=24,
            sample_interval_seconds=60,
        )
        sample = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=started,
            sampled_at_monotonic_ms=started,
            repo_root_path=self.root,
        )
        tampered_sample = {
            **sample,
            "expected_authority_input_digest": "0" * 64,
        }
        with self.assertRaisesRegex(HeartbeatShadowError, "sample contract"):
            append_heartbeat_soak_sample(receipt, tampered_sample)

        receipt = append_heartbeat_soak_sample(receipt, sample)
        tampered_receipt = {
            **receipt,
            "aggregate_counters": {
                **receipt["aggregate_counters"],
                "projection_drift": 1,
            },
        }
        with self.assertRaisesRegex(HeartbeatShadowError, "do not match samples"):
            validate_heartbeat_soak_receipt(tampered_receipt)

        early_complete = {**receipt, "status": "complete"}
        with self.assertRaisesRegex(HeartbeatShadowError, "cannot complete before"):
            validate_heartbeat_soak_receipt(early_complete)

        wall_clock_fast_forward = {
            **sample,
            "sampled_at_epoch_ms": started + 60_000,
            "sampled_at_monotonic_ms": started,
        }
        with self.assertRaisesRegex(HeartbeatShadowError, "monotonic"):
            append_heartbeat_soak_sample(receipt, wall_clock_fast_forward)

        gap = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=started + 180_000,
            sampled_at_monotonic_ms=started + 180_000,
            repo_root_path=self.root,
        )
        with self.assertRaisesRegex(HeartbeatShadowError, "coverage gap"):
            append_heartbeat_soak_sample(receipt, gap)

    def test_soak_classifies_privacy_and_runtime_observation_failures(self) -> None:
        prior = self._file_shadow_cycle()
        unsafe = self._baseline()
        unsafe["privacy_boundary"]["secrets_persisted"] = True
        self.baseline_path.write_bytes(_canonical_json(unsafe))
        privacy = heartbeat_parity_sample(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            projected_artifact=self.manifest_path,
            run_id=prior["run_id"],
            authority_input_digest=prior["authority_input_digest"],
            authority_mode="file_authority_shadow",
            database=self.database,
            sampled_at_epoch_ms=1_700_000_060_000,
            sampled_at_monotonic_ms=1_700_000_060_000,
            repo_root_path=self.root,
        )
        self.assertEqual(privacy["counters"]["privacy_violation"], 1)
        self.assertEqual(
            privacy["observation_error"],
            "authority_manifest_privacy_violation",
        )

        self._write_baseline()
        with mock.patch(
            "agentic_os.heartbeat_shadow._runtime_authority_counts",
            side_effect=HeartbeatShadowError("unreadable"),
        ):
            unknown = heartbeat_parity_sample(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                projected_artifact=self.manifest_path,
                run_id=prior["run_id"],
                authority_input_digest=prior["authority_input_digest"],
                authority_mode="file_authority_shadow",
                database=self.database,
                sampled_at_epoch_ms=1_700_000_060_000,
                sampled_at_monotonic_ms=1_700_000_060_000,
                repo_root_path=self.root,
            )
        self.assertIs(unknown["runtime_authority_counts_observed"], False)
        self.assertEqual(unknown["observation_error"], "runtime_authority_audit_error")
        self.assertEqual(unknown["counters"]["unknown_or_unowned_session"], 1)

    def test_forced_rollback_handles_zero_wal_shm_and_preserves_file_view(self) -> None:
        prior = self._file_shadow_cycle()
        heartbeat_digest = hashlib.sha256(self.heartbeat_file.read_bytes()).hexdigest()
        receipt_path = self.root / "artifacts/heartbeat-rollback.json"
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "UPDATE workflow_authority SET updated_at=updated_at WHERE workflow='heartbeat'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.assertTrue(self.database.with_name("control.db-wal").exists())
            self.assertTrue(self.database.with_name("control.db-shm").exists())
        receipt = force_heartbeat_file_authority_rollback(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            database=self.database,
            authority_input_digest=prior["authority_input_digest"],
            rollback_id="drill-1",
            receipt_path=receipt_path,
            observed_at_epoch_ms=1_700_000_120_000,
            repo_root_path=self.root,
        )

        backup = (
            self.root
            / "state/agentic-os/backups/heartbeat-shadow-rollback/drill-1/control.db"
        )
        self.assertFalse(self.database.exists())
        self.assertTrue(backup.is_file())
        self.assertTrue(backup.with_name("control.db-wal").is_file())
        self.assertTrue(backup.with_name("control.db-shm").is_file())
        self.assertEqual(receipt["parity_percent"], 100)
        self.assertEqual(receipt["parity"]["status"], "pass")
        self.assertEqual(receipt["recoverable_local_backup_path"], backup.relative_to(self.root).as_posix())
        self.assertEqual(receipt["recoverable_local_backup_sha256"], hashlib.sha256(backup.read_bytes()).hexdigest())
        self.assertTrue(
            (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-rollback/drill-1/audit-snapshot.db"
            ).is_file()
        )
        self.assertIs(receipt["file_authority_view_recreated"], True)
        self.assertIs(receipt["production_session_or_lease_authority_left"], False)
        self.assertIs(receipt["production_gateway_mutated"], False)
        self.assertIs(receipt["production_config_mutated"], False)
        self.assertIs(receipt["production_service_mutated"], False)
        self.assertIs(receipt["production_cron_mutated"], False)
        self.assertIs(receipt["production_authority_mutated"], False)
        self.assertEqual(
            hashlib.sha256(self.heartbeat_file.read_bytes()).hexdigest(),
            heartbeat_digest,
        )
        self.assertTrue(receipt_path.is_file())

    def test_forced_rollback_compensates_partial_sidecar_backup_move(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/partial-rollback.json"
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "UPDATE workflow_authority SET updated_at='partial-move' "
                "WHERE workflow='heartbeat'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.assertTrue(self.database.with_name("control.db-wal").exists())
        original_replace = heartbeat_shadow_module.os.replace

        def fail_wal_move(source: Path, destination: Path) -> None:
            if str(destination).endswith("control.db-wal"):
                raise OSError("simulated wal move failure")
            original_replace(source, destination)

        with mock.patch.object(
            heartbeat_shadow_module.os,
            "replace",
            side_effect=fail_wal_move,
        ):
            with self.assertRaisesRegex(HeartbeatShadowError, "failed atomically"):
                force_heartbeat_file_authority_rollback(
                    baseline_path=self.baseline_path,
                    heartbeat_file=self.heartbeat_file,
                    live_config_path=self.live_config_path,
                    database=self.database,
                    authority_input_digest=prior["authority_input_digest"],
                    rollback_id="partial-sidecar",
                    receipt_path=receipt_path,
                    repo_root_path=self.root,
                )

        backup = (
            self.root
            / "state/agentic-os/backups/heartbeat-shadow-rollback/partial-sidecar/control.db"
        )
        self.assertTrue(self.database.is_file())
        self.assertTrue(self.database.with_name("control.db-wal").exists())
        self.assertFalse(backup.exists())
        self.assertFalse(receipt_path.exists())

    def test_forced_rollback_fails_closed_on_runtime_authority_rows(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/rejected-rollback.json"
        self._insert_runtime_authority_lease(str(prior["run_id"]))
        with self.assertRaisesRegex(HeartbeatShadowError, "runtime authority rows"):
            force_heartbeat_file_authority_rollback(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                database=self.database,
                authority_input_digest=prior["authority_input_digest"],
                rollback_id="blocked",
                receipt_path=receipt_path,
                repo_root_path=self.root,
            )
        self.assertTrue(self.database.is_file())
        self.assertFalse(receipt_path.exists())

    def test_forced_rollback_holds_exclusive_lock_across_final_snapshot_and_move(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/heartbeat-rollback-lock.json"
        original_snapshot = heartbeat_shadow_module._locked_rollback_audit_snapshot
        writer_result: list[str] = []

        def racing_snapshot(source: Path, target: Path, root: Path) -> dict[str, object]:
            def writer() -> None:
                connection = sqlite3.connect(self.database, timeout=0.1)
                try:
                    connection.execute("CREATE TABLE rollback_writer_race(value TEXT)")
                    connection.commit()
                    writer_result.append("write_succeeded")
                except sqlite3.Error:
                    writer_result.append("write_blocked")
                finally:
                    connection.close()

            thread = threading.Thread(target=writer)
            thread.start()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            return original_snapshot(source, target, root)

        with mock.patch.object(
            heartbeat_shadow_module,
            "_locked_rollback_audit_snapshot",
            side_effect=racing_snapshot,
        ):
            receipt = force_heartbeat_file_authority_rollback(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                database=self.database,
                authority_input_digest=prior["authority_input_digest"],
                rollback_id="lock-race",
                receipt_path=receipt_path,
                repo_root_path=self.root,
            )

        self.assertEqual(writer_result, ["write_blocked"])
        self.assertEqual(receipt["status"], "pass")
        self.assertFalse(self.database.exists())

    def test_forced_rollback_checkpoints_committed_wal_under_final_lock(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/committed-wal-rollback.json"
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "UPDATE workflow_authority SET updated_at='committed-wal' WHERE workflow='heartbeat'"
            )
            connection.commit()
            self.assertGreater(self.database.with_name("control.db-wal").stat().st_size, 0)
        receipt = force_heartbeat_file_authority_rollback(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            database=self.database,
            authority_input_digest=prior["authority_input_digest"],
            rollback_id="committed-wal",
            receipt_path=receipt_path,
            repo_root_path=self.root,
        )
        self.assertEqual(receipt["status"], "pass")
        self.assertFalse(self.database.exists())
        self.assertTrue(receipt_path.exists())

    def test_forced_rollback_selects_parity_run_bound_to_requested_digest(self) -> None:
        prior = run_heartbeat_file_shadow_cycle(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            manifest_path=self.root / "artifacts/old-heartbeat-authority.json",
            run_id="heartbeat-file-shadow-old",
            database=self.database,
            repo_root_path=self.root,
            observed_at_epoch_ms=1_700_000_000_000,
        )
        self._write_baseline(every="45m")
        newer = run_heartbeat_file_shadow_cycle(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            manifest_path=self.root / "artifacts/new-heartbeat-authority.json",
            run_id="heartbeat-file-shadow-new",
            database=self.database,
            repo_root_path=self.root,
            observed_at_epoch_ms=1_700_000_060_000,
        )
        self._write_baseline(every="30m")
        receipt_path = self.root / "artifacts/digest-bound-rollback.json"

        receipt = force_heartbeat_file_authority_rollback(
            baseline_path=self.baseline_path,
            heartbeat_file=self.heartbeat_file,
            live_config_path=self.live_config_path,
            database=self.database,
            authority_input_digest=prior["authority_input_digest"],
            rollback_id="digest-bound",
            receipt_path=receipt_path,
            repo_root_path=self.root,
        )
        self.assertNotEqual(
            prior["authority_input_digest"], newer["authority_input_digest"]
        )
        self.assertEqual(receipt["parity"]["run_id"], "heartbeat-file-shadow-old")
        self.assertFalse(self.database.exists())
        self.assertTrue(receipt_path.exists())

    def test_forced_rollback_rejects_busy_source_before_source_mutation(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/rejected-busy.json"
        locker = sqlite3.connect(self.database, timeout=0.1)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            with self.assertRaisesRegex(
                HeartbeatShadowError,
                "checkpoint is busy|snapshot could not be created|idle/checkpointable",
            ):
                force_heartbeat_file_authority_rollback(
                    baseline_path=self.baseline_path,
                    heartbeat_file=self.heartbeat_file,
                    live_config_path=self.live_config_path,
                    database=self.database,
                    authority_input_digest=prior["authority_input_digest"],
                    rollback_id="busy-source",
                    receipt_path=receipt_path,
                    repo_root_path=self.root,
                )
        finally:
            locker.rollback()
            locker.close()
        self.assertTrue(self.database.is_file())
        self.assertFalse(receipt_path.exists())
        self.assertFalse(
            (
                self.root
                / "state/agentic-os/backups/heartbeat-shadow-rollback/busy-source/control.db"
            ).exists()
        )

    def test_forced_rollback_rejects_shadow_parity_drift(self) -> None:
        prior = self._file_shadow_cycle()
        receipt_path = self.root / "artifacts/rejected-parity.json"
        self.manifest_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(HeartbeatShadowError, "parity"):
            force_heartbeat_file_authority_rollback(
                baseline_path=self.baseline_path,
                heartbeat_file=self.heartbeat_file,
                live_config_path=self.live_config_path,
                database=self.database,
                authority_input_digest=prior["authority_input_digest"],
                rollback_id="parity-drift",
                receipt_path=receipt_path,
                repo_root_path=self.root,
            )
        self.assertTrue(self.database.is_file())
        self.assertFalse(receipt_path.exists())


if __name__ == "__main__":
    unittest.main()
