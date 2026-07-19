from __future__ import annotations

import contextlib
import hashlib
import io
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import agentic_os
import agentic_os.shadow as shadow_module
from agentic_os.cli import main as cli_main
from agentic_os.migrations import (
    MigrationError,
    _register_migration_functions,
    apply_migrations,
    repository_root,
)
from agentic_os.privacy import PrivacyPreflightError
from agentic_os.shadow import (
    ShadowBackfillError,
    _projection_rows_by_path,
    audit_dual_write_shadow,
    audit_file_authority_shadow,
    backfill_file_authority_shadow,
    dual_write_shadow_artifact,
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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

    def test_shadow_audit_rejects_default_prepare_key_tamper(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "UPDATE runs SET prepare_idempotency_key='prepare-tampered' "
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
        self.assertIn("missing_shadow_run", {issue.reason for issue in audit.issues})

    def test_shadow_audit_rejects_finalization_timestamp_tamper(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )

        for finalized_at in ("not-a-date", "1970-01-01T00:00:00+00:00"):
            with self.subTest(finalized_at=finalized_at):
                with sqlite3.connect(self.database) as connection:
                    _register_migration_functions(connection)
                    connection.execute(
                        "UPDATE runs SET finalized_at=? WHERE run_id='shadow-run'",
                        (finalized_at,),
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

    def test_shadow_audit_rejects_finalization_epoch_tamper(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "UPDATE runs SET finalized_at_epoch_ms=1 WHERE run_id='shadow-run'"
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

    def test_shadow_backfill_rejects_nonterminal_existing_run(self) -> None:
        artifact = self._artifact()
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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
            _register_migration_functions(connection)
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

    def test_shadow_preserves_explicit_symlink_artifact_paths(self) -> None:
        target = self._artifact("target.json", b'{"target": true}\n')
        reports = target.parent
        link_a = reports / "link-a.json"
        link_b = reports / "link-b.json"
        link_a.symlink_to(target)
        link_b.symlink_to(target)
        expected_paths = {
            link_a.relative_to(repository_root()).as_posix(),
            link_b.relative_to(repository_root()).as_posix(),
        }

        result = backfill_file_authority_shadow(
            self.database,
            [link_a, link_b],
            workflow="heartbeat",
            run_id="shadow-run",
        )

        self.assertEqual({projection.path for projection in result.projections}, expected_paths)
        self.assertEqual(len({projection.projection_id for projection in result.projections}), 2)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                {
                    row[0]
                    for row in connection.execute(
                        "SELECT path FROM artifact_projections WHERE run_id='shadow-run'"
                    ).fetchall()
                },
                expected_paths,
            )
        self._checkpoint_and_remove_sidecars()
        audit = audit_file_authority_shadow(
            self.database,
            [link_a, link_b],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "pass", audit.issues)

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

    def test_dual_write_shadow_first_write_replay_and_authority_disabled(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'

        result = dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )

        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        self.assertEqual(result.status, "written")
        self.assertEqual(artifact.read_bytes(), payload)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("dual_write_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT authority_mode,state FROM runs WHERE run_id='dual-run'"
                ).fetchone(),
                ("dual_write_shadow", "finalized"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT sha256,source_authority FROM artifact_projections "
                    "WHERE run_id='dual-run'"
                ).fetchone(),
                (hashlib.sha256(payload).hexdigest(), "dual_write_shadow"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM workflow_authority "
                    "WHERE mode IN ('db_authority_canary','db_authority')"
                ).fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM runs "
                    "WHERE authority_mode IN ('db_authority_canary','db_authority')"
                ).fetchone(),
                (0,),
            )

        replay = dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        self.assertEqual(replay.status, "replayed")
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE run_id='dual-run' AND source_authority='dual_write_shadow'"
                ).fetchone(),
                (1,),
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_dual_write_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="dual-run",
        )
        self.assertEqual(audit.status, "pass", audit.issues)

    def test_dual_write_shadow_requires_explicit_new_workflow_proof(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "new-workflow proof"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM workflow_authority "
                    "WHERE workflow='heartbeat'"
                ).fetchone(),
                (0,),
            )

    def test_dual_write_shadow_rejects_prior_run_without_workflow_metadata(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'file-run','prepare-file','heartbeat','file_authority',"
                "'running','R1','R1','now','now')"
            )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(MigrationError, "foreign_key_check failed"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
                new_workflow=True,
            )

        self.assertFalse(artifact.exists())

    def test_dual_write_shadow_rejects_file_authority_without_backfill(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority','now')"
            )

        with self.assertRaisesRegex(ShadowBackfillError, "backfill first"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections WHERE run_id='dual-run'"
                ).fetchone(),
                (0,),
            )

    def test_dual_write_shadow_promotes_only_backfilled_workflow(self) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority','now')"
            )
        backfill_file_authority_shadow(
            self.database,
            [backfilled],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        result = dual_write_shadow_artifact(
            self.database,
            artifact,
            b'{"dual": true}\n',
            workflow="heartbeat",
            run_id="dual-run",
            risk_class="R1",
            risk_dominance="R1",
        )

        self.assertEqual(result.status, "written")
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("dual_write_shadow",),
            )

    def test_dual_write_shadow_blocks_promotion_with_open_file_authority_run(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'file-run','prepare-file','heartbeat','file_authority',"
                "'running','R1','R1','now','now')"
            )
        backfill_file_authority_shadow(
            self.database,
            [backfilled],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "open file-authority run"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )

    def test_dual_write_shadow_honors_open_file_authority_run_counter(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority','now')"
            )
        backfill_file_authority_shadow(
            self.database,
            [backfilled],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "UPDATE workflow_authority SET open_file_authority_runs=1 "
                "WHERE workflow='heartbeat'"
            )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "open file-authority run"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )

    def test_dual_write_shadow_requires_current_shadow_parity_before_promotion(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority','now')"
            )
        backfill_file_authority_shadow(
            self.database,
            [backfilled],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        backfilled.write_bytes(b'{"shadow": "stale"}\n')
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "shadow parity audit failed"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE source_authority='dual_write_shadow'"
                ).fetchone(),
                (0,),
            )

    def test_dual_write_shadow_rejects_empty_shadow_prepare_key_before_promotion(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        relative = backfilled.resolve().relative_to(repository_root()).as_posix()
        digest = hashlib.sha256(backfilled.read_bytes()).hexdigest()
        created_at, finalized_at_epoch_ms = shadow_module._utc_now()
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
                "finalized_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "shadow-run",
                    " ",
                    "heartbeat",
                    "file_authority_shadow",
                    "finalized",
                    "R1",
                    "R1",
                    created_at,
                    created_at,
                    created_at,
                    finalized_at_epoch_ms,
                ),
            )
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,?)",
                (
                    shadow_module._projection_id("shadow-run", relative, digest),
                    "shadow-run",
                    relative,
                    digest,
                    "file_authority_shadow",
                    created_at,
                ),
            )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "prepare identity"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE source_authority='dual_write_shadow'"
                ).fetchone(),
                (0,),
            )

    def test_dual_write_shadow_rejects_non_r1_shadow_risk_before_promotion(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        relative = backfilled.resolve().relative_to(repository_root()).as_posix()
        digest = hashlib.sha256(backfilled.read_bytes()).hexdigest()
        created_at, finalized_at_epoch_ms = shadow_module._utc_now()
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('heartbeat','file_authority_shadow','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
                "finalized_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "shadow-run",
                    "prepare-shadow",
                    "heartbeat",
                    "file_authority_shadow",
                    "finalized",
                    "R2",
                    "R2",
                    created_at,
                    created_at,
                    created_at,
                    finalized_at_epoch_ms,
                ),
            )
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,?)",
                (
                    shadow_module._projection_id("shadow-run", relative, digest),
                    "shadow-run",
                    relative,
                    digest,
                    "file_authority_shadow",
                    created_at,
                ),
            )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "non-R1 shadow parity"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())

    def test_dual_write_shadow_rejects_contaminated_shadow_baseline_before_promotion(
        self,
    ) -> None:
        backfilled = self._artifact("backfilled.json", b'{"shadow": true}\n')
        contaminant = self._artifact("contaminant.json", b'{"dual": false}\n')
        contaminant_relative = contaminant.resolve().relative_to(repository_root()).as_posix()
        contaminant_digest = hashlib.sha256(contaminant.read_bytes()).hexdigest()
        backfill_file_authority_shadow(
            self.database,
            [backfilled],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,'now')",
                (
                    shadow_module._projection_id(
                        "shadow-run", contaminant_relative, contaminant_digest
                    ),
                    "shadow-run",
                    contaminant_relative,
                    contaminant_digest,
                    "dual_write_shadow",
                ),
            )
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "unexpected shadow parity"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(artifact.exists())

    def test_dual_write_shadow_replay_fails_on_workflow_mode_drift(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "UPDATE workflow_authority SET mode='file_authority_shadow' "
                "WHERE workflow='heartbeat'"
            )

        with self.assertRaisesRegex(ShadowBackfillError, "backfill first"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                payload,
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )

    def test_dual_write_shadow_rejects_non_r1_risk(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"

        with self.assertRaisesRegex(ShadowBackfillError, "only explicit R1"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R2",
                risk_dominance="R2",
            )

        self.assertFalse(self.database.exists())
        self.assertFalse(artifact.exists())

    def test_dual_write_shadow_rejects_preexisting_artifact_without_projection(
        self,
    ) -> None:
        artifact = self._artifact("dual.json", b'{"dual": true}\n')

        with self.assertRaisesRegex(ShadowBackfillError, "pre-existing artifact"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": true}\n',
                workflow="heartbeat",
                run_id="dual-run",
                risk_class="R1",
                risk_dominance="R1",
            )

        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE run_id='dual-run'"
                ).fetchone(),
                (0,),
            )

    def test_dual_write_shadow_changed_replay_fails_before_overwrite(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        original = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            original,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )

        with self.assertRaisesRegex(ShadowBackfillError, "refusing to overwrite"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                b'{"dual": false}\n',
                workflow="heartbeat",
                run_id="dual-run",
                prepare_idempotency_key="prepare-dual",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertEqual(artifact.read_bytes(), original)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT sha256 FROM artifact_projections "
                    "WHERE run_id='dual-run' AND source_authority='dual_write_shadow'"
                ).fetchone(),
                (hashlib.sha256(original).hexdigest(),),
            )

    def test_dual_write_shadow_changed_path_replay_fails_before_append(
        self,
    ) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        changed_path = Path(self.temporary.name) / "reports" / "renamed.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )

        with self.assertRaisesRegex(ShadowBackfillError, "different artifact path"):
            dual_write_shadow_artifact(
                self.database,
                changed_path,
                payload,
                workflow="heartbeat",
                run_id="dual-run",
                prepare_idempotency_key="prepare-dual",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertFalse(changed_path.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE run_id='dual-run' AND source_authority='dual_write_shadow'"
                ).fetchone(),
                (1,),
            )

    def test_dual_write_shadow_replay_rejects_extra_run_projection(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        extra_path = "reports/extra.json"
        extra_digest = "e" * 64
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,'now')",
                (
                    shadow_module._projection_id("dual-run", extra_path, extra_digest),
                    "dual-run",
                    extra_path,
                    extra_digest,
                    "dual_write_shadow",
                ),
            )

        with self.assertRaisesRegex(ShadowBackfillError, "extra projections"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                payload,
                workflow="heartbeat",
                run_id="dual-run",
                prepare_idempotency_key="prepare-dual",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertEqual(artifact.read_bytes(), payload)

    def test_dual_write_shadow_audit_rejects_extra_dual_write_projection(
        self,
    ) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        extra_artifact = self._artifact("extra-dual.json", b'{"extra": true}\n')
        extra_relative = extra_artifact.resolve().relative_to(repository_root()).as_posix()
        extra_digest = hashlib.sha256(extra_artifact.read_bytes()).hexdigest()
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,'now')",
                (
                    shadow_module._projection_id("dual-run", extra_relative, extra_digest),
                    "dual-run",
                    extra_relative,
                    extra_digest,
                    "dual_write_shadow",
                ),
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_dual_write_shadow(
            self.database,
            [artifact, extra_artifact],
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
        )

        self.assertEqual(audit.status, "fail")
        self.assertIn("unexpected_projection", {issue.reason for issue in audit.issues})

    def test_dual_write_shadow_replay_rejects_cross_authority_projection(
        self,
    ) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        extra_path = "reports/extra-shadow.json"
        extra_digest = "f" * 64
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute(
                "INSERT INTO artifact_projections("
                "projection_id,run_id,path,sha256,source_authority,generated_at"
                ") VALUES(?,?,?,?,?,'now')",
                (
                    shadow_module._projection_id("dual-run", extra_path, extra_digest),
                    "dual-run",
                    extra_path,
                    extra_digest,
                    "file_authority_shadow",
                ),
            )
        self._checkpoint_and_remove_sidecars()

        with self.assertRaisesRegex(ShadowBackfillError, "extra projections"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                payload,
                workflow="heartbeat",
                run_id="dual-run",
                prepare_idempotency_key="prepare-dual",
                risk_class="R1",
                risk_dominance="R1",
            )
        self._checkpoint_and_remove_sidecars()

        audit = audit_dual_write_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-dual",
        )
        self.assertEqual(audit.status, "fail")
        self.assertIn("unexpected_projection", {issue.reason for issue in audit.issues})

    def test_dual_write_shadow_rejects_prepare_key_mismatch_on_replay(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        payload = b'{"dual": true}\n'
        dual_write_shadow_artifact(
            self.database,
            artifact,
            payload,
            workflow="heartbeat",
            run_id="dual-run",
            prepare_idempotency_key="prepare-one",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )

        with self.assertRaisesRegex(ShadowBackfillError, "matching shadow run"):
            dual_write_shadow_artifact(
                self.database,
                artifact,
                payload,
                workflow="heartbeat",
                run_id="dual-run",
                prepare_idempotency_key="prepare-two",
                risk_class="R1",
                risk_dominance="R1",
            )
        self.assertEqual(artifact.read_bytes(), payload)

    def test_dual_write_shadow_audit_detects_file_db_drift(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "dual.json"
        dual_write_shadow_artifact(
            self.database,
            artifact,
            b'{"dual": true}\n',
            workflow="heartbeat",
            run_id="dual-run",
            risk_class="R1",
            risk_dominance="R1",
            new_workflow=True,
        )
        artifact.write_bytes(b'{"dual": "drift"}\n')
        self._checkpoint_and_remove_sidecars()

        audit = audit_dual_write_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="dual-run",
        )

        self.assertEqual(audit.status, "fail")
        self.assertEqual({issue.reason for issue in audit.issues}, {"sha256_mismatch"})

    def test_dual_write_shadow_cleans_created_file_after_write_failure(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "partial.json"
        original_open = Path.open
        temp_paths: list[Path] = []

        class FailingDestination:
            def __init__(self, path: Path) -> None:
                self.path = path

            def __enter__(self) -> "FailingDestination":
                with original_open(self.path, "xb") as handle:
                    handle.write(b"partial")
                return self

            def write(self, _content: bytes) -> int:
                raise OSError("disk full")

            def __exit__(self, *_exc: object) -> bool:
                return False

        def flaky_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
            if (
                path.parent == artifact.parent
                and path.name.startswith(f".{artifact.name}.tmp-")
                and mode == "xb"
            ):
                temp_paths.append(path)
                return FailingDestination(path)
            return original_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, "open", flaky_open):
            with self.assertRaisesRegex(OSError, "disk full"):
                dual_write_shadow_artifact(
                    self.database,
                    artifact,
                    b'{"partial": true}\n',
                    workflow="heartbeat",
                    run_id="write-failed",
                    risk_class="R1",
                    risk_dominance="R1",
                    new_workflow=True,
                )

        self.assertFalse(artifact.exists())
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs "
                    "WHERE run_id='write-failed'"
                ).fetchone(),
                ("prepared",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections "
                    "WHERE run_id='write-failed'"
                ).fetchone(),
                (1,),
            )
        self.assertTrue(temp_paths)
        self.assertTrue(all(not path.exists() for path in temp_paths))

        recovered = dual_write_shadow_artifact(
            self.database,
            artifact,
            b'{"partial": true}\n',
            workflow="heartbeat",
            run_id="write-failed",
            risk_class="R1",
            risk_dominance="R1",
        )

        self.assertEqual(recovered.status, "recovered")
        self.assertEqual(artifact.read_bytes(), b'{"partial": true}\n')
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='write-failed'"
                ).fetchone(),
                ("finalized",),
            )

    def test_dual_write_shadow_recovers_prepared_file_after_finalize_failure(
        self,
    ) -> None:
        artifact = Path(self.temporary.name) / "reports" / "finalize.json"
        payload = b'{"finalize": true}\n'
        original_finalize = shadow_module._finalize_prepared_shadow_run

        with mock.patch.object(
            shadow_module,
            "_finalize_prepared_shadow_run",
            side_effect=ShadowBackfillError("finalize interrupted"),
        ):
            with self.assertRaisesRegex(ShadowBackfillError, "finalize interrupted"):
                dual_write_shadow_artifact(
                    self.database,
                    artifact,
                    payload,
                    workflow="heartbeat",
                    run_id="finalize-failed",
                    risk_class="R1",
                    risk_dominance="R1",
                    new_workflow=True,
                )

        self.assertEqual(artifact.read_bytes(), payload)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='finalize-failed'"
                ).fetchone(),
                ("prepared",),
            )

        with mock.patch.object(
            shadow_module,
            "_finalize_prepared_shadow_run",
            side_effect=original_finalize,
        ):
            recovered = dual_write_shadow_artifact(
                self.database,
                artifact,
                payload,
                workflow="heartbeat",
                run_id="finalize-failed",
                risk_class="R1",
                risk_dominance="R1",
            )

        self.assertEqual(recovered.status, "recovered")
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='finalize-failed'"
                ).fetchone(),
                ("finalized",),
            )

    def test_dual_write_shadow_preserves_committed_file_after_checkpoint_failure(
        self,
    ) -> None:
        artifact = Path(self.temporary.name) / "reports" / "checkpoint.json"
        payload = b'{"checkpoint": true}\n'

        with mock.patch.object(
            shadow_module,
            "_checkpoint_offline_snapshot",
            side_effect=ShadowBackfillError("checkpoint busy"),
        ):
            with self.assertRaisesRegex(ShadowBackfillError, "checkpoint busy"):
                dual_write_shadow_artifact(
                    self.database,
                    artifact,
                    payload,
                    workflow="heartbeat",
                    run_id="checkpoint-busy",
                    risk_class="R1",
                    risk_dominance="R1",
                    new_workflow=True,
                )

        self.assertEqual(artifact.read_bytes(), payload)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            self.assertEqual(
                connection.execute(
                    "SELECT sha256,source_authority FROM artifact_projections "
                    "WHERE run_id='checkpoint-busy'"
                ).fetchone(),
                (hashlib.sha256(payload).hexdigest(), "dual_write_shadow"),
            )

    def test_cli_dual_write_shadow_positive_and_negative_paths(self) -> None:
        artifact = Path(self.temporary.name) / "reports" / "cli-dual.json"
        payload = '{"cli": true}\n'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = cli_main(
                [
                    "dual-write-shadow",
                    "--db",
                    str(self.database),
                    "--workflow",
                    "heartbeat",
                    "--run-id",
                    "cli-dual",
                    "--risk-class",
                    "R1",
                    "--risk-dominance",
                    "R1",
                    "--artifact",
                    str(artifact),
                    "--content",
                    payload,
                    "--new-workflow",
                    "--repo-root",
                    str(repository_root()),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("dual-write shadow written", output.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = cli_main(
                [
                    "dual-write-shadow-audit",
                    "--db",
                    str(self.database),
                    "--workflow",
                    "heartbeat",
                    "--run-id",
                    "cli-dual",
                    "--artifact",
                    str(artifact),
                    "--repo-root",
                    str(repository_root()),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("shadow audit pass", output.getvalue())

        artifact.write_text('{"cli": false}\n', encoding="utf-8")
        self._checkpoint_and_remove_sidecars()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = cli_main(
                [
                    "dual-write-shadow-audit",
                    "--db",
                    str(self.database),
                    "--workflow",
                    "heartbeat",
                    "--run-id",
                    "cli-dual",
                    "--artifact",
                    str(artifact),
                    "--repo-root",
                    str(repository_root()),
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("sha256_mismatch", output.getvalue())

    def test_cli_dual_write_shadow_rejects_raw_state_content_file_before_copying(
        self,
    ) -> None:
        raw_state = self.state_root / "control.db"
        raw_state.write_bytes(b"raw sqlite bytes")
        self.addCleanup(raw_state.unlink, missing_ok=True)
        artifact = Path(self.temporary.name) / "reports" / "copied.json"

        with self.assertRaisesRegex(PrivacyPreflightError, "raw database state"):
            cli_main(
                [
                    "dual-write-shadow",
                    "--db",
                    str(self.database),
                    "--workflow",
                    "heartbeat",
                    "--run-id",
                    "raw-state-copy",
                    "--risk-class",
                    "R1",
                    "--risk-dominance",
                    "R1",
                    "--artifact",
                    str(artifact),
                    "--content-file",
                    str(raw_state),
                    "--repo-root",
                    str(repository_root()),
                ]
            )

        self.assertFalse(artifact.exists())


if __name__ == "__main__":
    unittest.main()
