from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from agentic_os.migrations import apply_migrations, repository_root
from agentic_os.privacy import PrivacyPreflightError
from agentic_os.shadow import (
    ShadowBackfillError,
    _projection_rows_by_path,
    audit_file_authority_shadow,
    backfill_file_authority_shadow,
)


class ShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "shadow-control.db"

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _artifact(self, name: str = "summary.json", content: bytes = b'{"ok": true}\n') -> Path:
        path = Path(self.temporary.name) / "reports" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def _checkpoint_and_remove_sidecars(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{self.database}{suffix}").unlink(missing_ok=True)

    def test_backfill_file_authority_shadow_and_audit_pass(self) -> None:
        artifact = self._artifact()
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        result = backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(result.workflow, "heartbeat")
        self.assertEqual(result.run_id, "shadow-run")
        self.assertEqual(len(result.projections), 1)
        self.assertEqual(result.projections[0].sha256, digest)

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT authority_mode,state FROM runs WHERE run_id='shadow-run'"
                ).fetchone(),
                ("file_authority_shadow", "finalized"),
            )
            finalized_at, finalized_epoch_ms = connection.execute(
                "SELECT finalized_at,finalized_at_epoch_ms FROM runs "
                "WHERE run_id='shadow-run'"
            ).fetchone()
            self.assertIsInstance(finalized_at, str)
            self.assertEqual(
                finalized_epoch_ms,
                int(datetime.fromisoformat(finalized_at).timestamp() * 1000),
            )
            self.assertGreater(finalized_epoch_ms, 1_600_000_000_000)
            self.assertEqual(
                connection.execute(
                    "SELECT sha256,source_authority FROM artifact_projections "
                    "WHERE run_id='shadow-run'"
                ).fetchone(),
                (digest, "file_authority_shadow"),
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "pass")
        self.assertEqual(audit.issues, ())

        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections WHERE run_id='shadow-run'"
                ).fetchone(),
                (1,),
            )

    def test_shadow_audit_detects_artifact_drift(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        artifact.write_bytes(b'{"ok": false}\n')

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertEqual(len(audit.issues), 1)
        self.assertEqual(audit.issues[0].reason, "sha256_mismatch")

        with self.assertRaisesRegex(ShadowBackfillError, "projection drift"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_normalizes_workflow_and_run_id(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow=" heartbeat ",
            run_id=" shadow-run ",
        )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT workflow,authority_mode FROM runs WHERE run_id='shadow-run'"
                ).fetchone(),
                ("heartbeat", "file_authority_shadow"),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT run_id FROM runs WHERE run_id=' shadow-run '"
                ).fetchone()
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow=" heartbeat ",
            run_id=" shadow-run ",
        )
        self.assertEqual(audit.status, "pass")

    def test_shadow_rejects_empty_prepare_key_before_migration(self) -> None:
        artifact = self._artifact()
        with self.assertRaisesRegex(ShadowBackfillError, "prepare_idempotency_key"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
                prepare_idempotency_key=" ",
            )
        self.assertFalse(self.database.exists())
        self.assertFalse(Path(f"{self.database}-wal").exists())
        self.assertFalse(Path(f"{self.database}-shm").exists())

    def test_shadow_backfill_rejects_prepare_key_mismatch_for_existing_run(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
            prepare_idempotency_key="prepare-one",
        )

        with self.assertRaisesRegex(ShadowBackfillError, "matching shadow run"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
                prepare_idempotency_key="prepare-two",
            )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT prepare_idempotency_key FROM runs WHERE run_id='shadow-run'"
                ).fetchone(),
                ("prepare-one",),
            )

    def test_shadow_audit_rejects_prepare_key_mismatch(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
            prepare_idempotency_key="prepare-one",
        )

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
            prepare_idempotency_key="prepare-one",
        )
        self.assertEqual(audit.status, "pass")

        for prepare_key in (None, "prepare-two"):
            with self.subTest(prepare_key=prepare_key):
                audit = audit_file_authority_shadow(
                    self.database,
                    [artifact],
                    workflow="heartbeat",
                    run_id="shadow-run",
                    prepare_idempotency_key=prepare_key,
                )
                self.assertEqual(audit.status, "fail")
                self.assertIn("missing_shadow_run", {issue.reason for issue in audit.issues})

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE runs SET prepare_idempotency_key='prepare-tampered' "
                "WHERE run_id='shadow-run'"
            )
        self._checkpoint_and_remove_sidecars()

        tampered_audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
            prepare_idempotency_key="prepare-one",
        )
        self.assertEqual(tampered_audit.status, "fail")
        self.assertIn(
            "missing_shadow_run", {issue.reason for issue in tampered_audit.issues}
        )

    def test_shadow_backfill_rejects_nonterminal_existing_run(self) -> None:
        artifact = self._artifact()
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'shadow-run','file-shadow:shadow-run','heartbeat','file_authority_shadow',"
                "'running','R1','R1','now','now')"
            )

        with self.assertRaisesRegex(ShadowBackfillError, "matching shadow run"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
            )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM artifact_projections").fetchone(),
                (0,),
            )

    def test_shadow_backfill_records_same_artifact_for_each_run(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run-one",
        )
        result = backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run-two",
        )
        self.assertEqual(len(result.projections), 1)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections WHERE path=?",
                    (result.projections[0].path,),
                ).fetchone(),
                (2,),
            )

    def test_shadow_schema_blocks_conflicting_projection_rows(self) -> None:
        artifact = self._artifact()
        result = backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO artifact_projections("
                    "projection_id,run_id,path,sha256,source_authority,generated_at"
                    ") VALUES(?,?,?,?,?,?)",
                    (
                        "manual-conflicting-projection",
                        "shadow-run",
                        result.projections[0].path,
                        "0" * 64,
                        "file_authority_shadow",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )

    def test_shadow_audit_rejects_duplicate_projection_rows(self) -> None:
        projected, issues = _projection_rows_by_path(
            (
                ("projection-a", "reports/summary.json", "a" * 64),
                ("projection-b", "reports/summary.json", "b" * 64),
            ),
            run_id="shadow-run",
        )

        self.assertEqual(projected, {})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].path, "reports/summary.json")
        self.assertEqual(issues[0].reason, "duplicate_projection")

    def test_shadow_audit_verifies_deterministic_projection_id(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE artifact_projections SET projection_id='manual-projection' "
                "WHERE run_id='shadow-run'"
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertIn("projection_id_mismatch", {issue.reason for issue in audit.issues})

    def test_shadow_backfill_rejects_raw_state_artifact(self) -> None:
        raw = Path(self.temporary.name) / "control.db.old"
        with self.assertRaises(PrivacyPreflightError):
            backfill_file_authority_shadow(
                self.database,
                [raw],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_backfill_rejects_resolved_raw_state_symlink(self) -> None:
        raw = Path(self.temporary.name) / "control.db"
        raw.write_bytes(b"raw")
        artifact = Path(self.temporary.name) / "reports" / "summary.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.symlink_to(raw)
        with self.assertRaises(PrivacyPreflightError):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_audit_rejects_resolved_raw_state_symlink(self) -> None:
        raw = Path(self.temporary.name) / "control.db"
        raw.write_bytes(b"raw")
        artifact = Path(self.temporary.name) / "reports" / "summary.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.symlink_to(raw)
        with self.assertRaises(PrivacyPreflightError):
            audit_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_rejects_empty_workflow_and_run_id(self) -> None:
        artifact = self._artifact()
        with self.assertRaisesRegex(ShadowBackfillError, "workflow"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow=" ",
                run_id="shadow-run",
            )
        with self.assertRaisesRegex(ShadowBackfillError, "run_id"):
            audit_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="",
            )

    def test_shadow_audit_rejects_unpinned_schema(self) -> None:
        artifact = self._artifact()
        relative = artifact.resolve().relative_to(repository_root()).as_posix()
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        handbuilt = Path(self.temporary.name) / "handbuilt-control.db"
        with sqlite3.connect(handbuilt) as connection:
            connection.execute(
                "CREATE TABLE runs (run_id TEXT, workflow TEXT, authority_mode TEXT)"
            )
            connection.execute(
                "CREATE TABLE artifact_projections ("
                "run_id TEXT,path TEXT,sha256 TEXT,source_authority TEXT)"
            )
            connection.execute(
                "INSERT INTO runs VALUES(?,?,?)",
                ("shadow-run", "heartbeat", "file_authority_shadow"),
            )
            connection.execute(
                "INSERT INTO artifact_projections VALUES(?,?,?,?)",
                ("shadow-run", relative, digest, "file_authority_shadow"),
            )

        audit = audit_file_authority_shadow(
            handbuilt,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertEqual(audit.issues[0].reason, "invalid_schema")

    def test_shadow_audit_returns_invalid_schema_for_corrupt_sqlite(self) -> None:
        artifact = self._artifact()
        self.database.write_bytes(b"not sqlite")

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertEqual(audit.issues[0].reason, "invalid_schema")

    def test_shadow_audit_rejects_nonterminal_shadow_run(self) -> None:
        artifact = self._artifact()
        relative = artifact.resolve().relative_to(repository_root()).as_posix()
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'shadow-run','file-shadow:shadow-run','heartbeat','file_authority_shadow',"
                "'running','R1','R1','now','now')"
            )
            connection.execute(
                "INSERT INTO artifact_projections(projection_id,run_id,path,sha256,"
                "source_authority,generated_at) VALUES('projection','shadow-run',?,?,"
                "'file_authority_shadow','now')",
                (relative, digest),
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertIn("missing_shadow_run", {issue.reason for issue in audit.issues})

    def test_shadow_audit_rejects_live_sqlite_sidecars(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        sidecar = Path(f"{self.database}-wal")
        sidecar.write_bytes(b"sidecar-sentinel")
        sidecar_before = (sidecar.read_bytes(), sidecar.stat().st_mtime_ns)

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertEqual(audit.issues[0].reason, "invalid_schema")
        self.assertEqual(
            (sidecar.read_bytes(), sidecar.stat().st_mtime_ns), sidecar_before
        )

    def test_shadow_audit_requires_current_workflow_shadow_mode(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE workflow_authority SET mode='file_authority' WHERE workflow='heartbeat'"
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertIn("workflow_not_shadow", {issue.reason for issue in audit.issues})

    def test_shadow_backfill_rejects_artifact_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            artifact = Path(outside) / "summary.json"
            artifact.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ShadowBackfillError, "outside repository root"):
                backfill_file_authority_shadow(
                    self.database,
                    [artifact],
                    workflow="heartbeat",
                    run_id="shadow-run",
                )


if __name__ == "__main__":
    unittest.main()
