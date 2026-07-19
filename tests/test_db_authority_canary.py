from __future__ import annotations

import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentic_os
import agentic_os.db_authority_canary as canary_module
from agentic_os.cli import main as cli_main
from agentic_os.db_authority_canary import (
    DbAuthorityCanaryError,
    db_authority_canary_artifact,
    rollback_db_authority_canary,
)
from agentic_os.migrations import apply_migrations, repository_root


class DbAuthorityCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "canary-control.db"
        self.artifact = Path(self.temporary.name) / "reports" / "canary.json"
        self.payload = b'{"workflow":"heartbeat","synthetic":true}\n'
        self.cutover_hash = hashlib.sha256(b"synthetic-cutover").hexdigest()
        self.parity_hash = hashlib.sha256(b"synthetic-parity").hexdigest()

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def test_canary_writes_only_local_artifact_and_synthetic_db_proof(self) -> None:
        result = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        self.assertEqual(result.status, "written")
        self.assertEqual(self.artifact.read_bytes(), self.payload)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode,cutover_approved_by,rollback_deadline "
                    "FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                (
                    "db_authority_canary",
                    "local-fixture",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT authority_mode,state,risk_class,risk_dominance "
                    "FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("db_authority_canary", "finalized", "R1", "R1"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT source_authority,sha256 FROM artifact_projections "
                    "WHERE run_id='canary-run'"
                ).fetchone(),
                ("db_authority_canary", hashlib.sha256(self.payload).hexdigest()),
            )
            for table in (
                "external_rpc_intents",
                "leases",
                "spawn_requests",
                "sessions",
            ):
                self.assertEqual(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE run_id='canary-run'"
                    ).fetchone(),
                    (0,),
                )

        replay = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        self.assertEqual(replay.status, "replayed")

    def test_canary_recovers_after_local_crash_fixture(self) -> None:
        with self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )
        self.assertFalse(self.artifact.exists())
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("prepared",),
            )

        recovered = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertEqual(recovered.status, "recovered")
        self.assertEqual(self.artifact.read_bytes(), self.payload)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("finalized",),
            )

    def test_rollback_proves_projection_regeneration(self) -> None:
        written = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )

        self.assertEqual(rollback.status, "rolled_back")
        self.assertEqual(rollback.regenerated, (written.projection,))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("rollback_to_file_authority",),
            )

    def test_canary_refuses_real_session_control_rows_on_replay(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,risk_dominance,idempotency_key,guard_version_before,"
                "created_at) VALUES("
                "'t','canary-run','prepared','spawn_pending','dispatch','spawn',"
                "'session','s',?,'local','R1','transition-idem',0,'now')",
                (hashlib.sha256(b"target").hexdigest(),),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                "'lease','canary-run','B','t','ai-engineer','main',"
                "'release_not_required','client-lease','acquire-idem',1000,"
                "'2099-01-01T00:00:00+00:00',4070908800000)"
            )

        with self.assertRaisesRegex(
            DbAuthorityCanaryError, "real session-control rows"
        ):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        with self.assertRaisesRegex(
            DbAuthorityCanaryError, "real session-control rows"
        ):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_rollback_rejects_cross_workflow_projection(self) -> None:
        other_artifact = Path(self.temporary.name) / "reports" / "other.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            other_artifact,
            b'{"workflow":"other","synthetic":true}\n',
            workflow="other",
            run_id="other-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "exactly match"):
            rollback_db_authority_canary(
                self.database,
                (other_artifact,),
                workflow="heartbeat",
            )

    def test_rollback_requires_complete_projection_set(self) -> None:
        second_artifact = Path(self.temporary.name) / "reports" / "second.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            second_artifact,
            b'{"workflow":"heartbeat","sequence":2}\n',
            workflow="heartbeat",
            run_id="canary-run-2",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "exactly match"):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_rollback_requires_one_projection_for_every_finalized_run(self) -> None:
        second_artifact = Path(self.temporary.name) / "reports" / "second.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            second_artifact,
            b'{"workflow":"heartbeat","sequence":2}\n',
            workflow="heartbeat",
            run_id="canary-run-2",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM artifact_projections WHERE run_id='canary-run-2'"
            )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "one projection"):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_second_canary_run_cannot_reuse_artifact_path(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with self.assertRaisesRegex(DbAuthorityCanaryError, "already belongs"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run-2",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_expired_prepared_canary_can_exact_recover_and_rollback(self) -> None:
        deadline = "2027-01-01T00:00:00+00:00"
        with mock.patch.object(
            canary_module,
            "_utc_now",
            return_value=("2026-01-01T00:00:00+00:00", 1767225600000),
        ), self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline=deadline,
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )

        with mock.patch.object(
            canary_module,
            "_utc_now",
            side_effect=[
                ("2028-01-01T00:00:00+00:00", 1830297600000),
                ("2028-01-01T00:00:01+00:00", 1830297601000),
            ],
        ):
            recovered = db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline=deadline,
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertEqual(recovered.status, "recovered")
        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_rollback_rejects_outside_and_nonexistent_databases(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with tempfile.TemporaryDirectory() as outside:
            outside_db = Path(outside) / "canary.db"
            shutil.copy2(self.database, outside_db)
            with self.assertRaisesRegex(DbAuthorityCanaryError, "privacy preflight"):
                rollback_db_authority_canary(
                    outside_db,
                    (self.artifact,),
                    workflow="heartbeat",
                )
            missing_db = Path(outside) / "missing.db"
            with self.assertRaisesRegex(DbAuthorityCanaryError, "privacy preflight"):
                rollback_db_authority_canary(
                    missing_db,
                    (self.artifact,),
                    workflow="heartbeat",
                )
            self.assertFalse(missing_db.exists())

    def test_canary_rejects_malformed_and_past_deadlines(self) -> None:
        for deadline in ("not-a-time", "2000-01-01T00:00:00+00:00"):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(
                DbAuthorityCanaryError, "rollback_deadline"
            ):
                db_authority_canary_artifact(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="heartbeat",
                    run_id="canary-run",
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline=deadline,
                    last_parity_audit_hash=self.parity_hash,
                )

    def test_replay_rejects_corrupted_finalization_metadata(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE runs SET finalized_at='tampered' WHERE run_id='canary-run'"
            )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "invalid canary state"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_canary_reads_authority_disable_flag_at_call_time(self) -> None:
        original = agentic_os.DB_AUTHORITY_ENABLED
        agentic_os.DB_AUTHORITY_ENABLED = True
        try:
            with self.assertRaisesRegex(
                DbAuthorityCanaryError, "production DB authority must remain disabled"
            ):
                db_authority_canary_artifact(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="heartbeat",
                    run_id="canary-run",
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline="2099-01-01T00:00:00+00:00",
                    last_parity_audit_hash=self.parity_hash,
                )
        finally:
            agentic_os.DB_AUTHORITY_ENABLED = original

    def test_canary_cli_write_and_rollback(self) -> None:
        status = cli_main(
            [
                "db-authority-canary",
                "--db",
                str(self.database),
                "--workflow",
                "heartbeat",
                "--run-id",
                "canary-run",
                "--cutover-approved-by",
                "local-fixture",
                "--cutover-evidence-hash",
                self.cutover_hash,
                "--rollback-deadline",
                "2099-01-01T00:00:00+00:00",
                "--last-parity-audit-hash",
                self.parity_hash,
                "--artifact",
                str(self.artifact),
                "--content",
                self.payload.decode("utf-8"),
            ]
        )
        self.assertEqual(status, 0)

        rollback_status = cli_main(
            [
                "db-authority-canary-rollback",
                "--db",
                str(self.database),
                "--workflow",
                "heartbeat",
                "--artifact",
                str(self.artifact),
            ]
        )
        self.assertEqual(rollback_status, 0)


if __name__ == "__main__":
    unittest.main()
