from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from agentic_os.goal_runs import GoalRunError, record_goal_run
from agentic_os.migrations import apply_migrations, load_migrations, repository_root


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _shadow_projection_id(run_id: str, relative_path: str, digest: str) -> str:
    payload = f"{run_id}\0{relative_path}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class GoalRunWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"
        apply_migrations(self.database)
        self.evidence_hash = _sha(b"pass-evidence")
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            self._seed_valid_goal_run_fixture(connection)
        self._chmod_database_private(self.database)

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def test_record_goal_run_binds_existing_pass_gate_evidence(self) -> None:
        result = record_goal_run(
            self.database,
            goal_run_id="goal-run",
            goal_id="goal",
            run_id="run",
            severity="R1",
            state="open",
            predicate_plugin_hash="plugin",
            evidence_hash=self.evidence_hash,
            created_at="now",
            created_at_epoch_ms=1000,
        )
        self.assertEqual(result.evidence_hash, self.evidence_hash)
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT run_id,evidence_hash FROM goal_runs WHERE goal_run_id='goal-run'"
            ).fetchone()
        self.assertEqual(row, ("run", self.evidence_hash))

    def test_record_goal_run_consumes_required_approval_in_transaction(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "UPDATE goal_manifests SET approval_required=1 WHERE goal_id='goal'"
            )
            connection.execute(
                "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                "source_message_digest,approval_text_digest,approved_action_type,"
                "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
                "expires_at_epoch_ms,approval_hash,approved_at) VALUES("
                "'goal-approval','run','river','telegram','goal-source','goal-text',"
                "'goal_run','goal','goal','manifest','owner','R1',2000,"
                "'goal-approval-hash','now')"
            )
        result = record_goal_run(
            self.database,
            goal_run_id="approval-bound",
            goal_id="goal",
            run_id="run",
            severity="R1",
            state="open",
            predicate_plugin_hash="plugin",
            approval_id="goal-approval",
            created_at="now",
            created_at_epoch_ms=1000,
        )
        self.assertEqual(result.goal_run_id, "approval-bound")
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT consumed_by_goal_run_id FROM approvals "
                "WHERE approval_id='goal-approval'"
            ).fetchone()
        self.assertEqual(row, ("approval-bound",))

    def test_forged_goal_run_evidence_fails_without_partial_write(self) -> None:
        with self.assertRaisesRegex(
            GoalRunError, "same-run independent pass-gate evidence"
        ):
            record_goal_run(
                self.database,
                goal_run_id="forged",
                goal_id="goal",
                run_id="run",
                severity="R1",
                state="open",
                predicate_plugin_hash="plugin",
                evidence_hash=_sha(b"forged"),
                created_at="now",
                created_at_epoch_ms=1000,
            )
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM goal_runs WHERE goal_run_id='forged'"
                ).fetchone()[0],
                0,
            )

    def test_writer_refuses_database_authority_runs(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "open_file_authority_runs,updated_at) VALUES('db-workflow',"
                "'db_authority_canary','erwin',?,'deadline',?,0,'now')",
                (_sha(b"cutover"), _sha(b"parity")),
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('db-run','prepare-db','db-workflow','db_authority_canary',"
                "'candidate','R1','R1','now','now')"
            )
        with self.assertRaisesRegex(GoalRunError, "database-authority"):
            record_goal_run(
                self.database,
                goal_run_id="db-authority-goal-run",
                goal_id="goal",
                run_id="db-run",
                severity="R1",
                state="open",
                predicate_plugin_hash="plugin",
                created_at="now",
                created_at_epoch_ms=1000,
            )

    def test_writer_refuses_unsafe_database_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unsafe = Path(temporary) / "control.db"
            shutil.copy2(self.database, unsafe)
            os.chmod(unsafe, 0o666)
            with self.assertRaisesRegex(GoalRunError, "privacy preflight"):
                record_goal_run(
                    unsafe,
                    goal_run_id="unsafe-path",
                    goal_id="goal",
                    severity="R1",
                    state="open",
                    predicate_plugin_hash="plugin",
                    created_at="now",
                    created_at_epoch_ms=1000,
                )

    def test_writer_requires_recorded_migrations_and_slo_contracts(self) -> None:
        handmade = Path(self.temporary.name) / "handmade.db"
        with closing(sqlite3.connect(handmade)) as connection:
            connection.create_function(
                "agentic_shadow_projection_id",
                3,
                _shadow_projection_id,
                deterministic=True,
            )
            connection.execute("PRAGMA foreign_keys=ON")
            for migration in load_migrations():
                connection.executescript(migration.path.read_text(encoding="utf-8"))
        self._chmod_database_private(handmade)
        with self.assertRaisesRegex(GoalRunError, "schema verification"):
            record_goal_run(
                handmade,
                goal_run_id="unrecorded",
                goal_id="goal",
                severity="R1",
                state="open",
                predicate_plugin_hash="plugin",
                created_at="now",
                created_at_epoch_ms=1000,
            )

    def _chmod_database_private(self, database: Path) -> None:
        os.chmod(database.parent, 0o700)
        if database.exists():
            os.chmod(database, 0o600)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{database}{suffix}")
            if sidecar.exists():
                os.chmod(sidecar, 0o600)

    def _seed_valid_goal_run_fixture(self, connection: sqlite3.Connection) -> None:
        target_hash = _sha(b"target")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) VALUES('run',"
            "'prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,target_type,target_id,target_hash,"
            "target_scope,risk_dominance,idempotency_key,guard_version_before,"
            "created_at) VALUES('transition','run','prepared','gate_passed','gate',"
            "'mutate','artifact','artifact-1',?,'repo','R1','idem',0,'now')",
            (target_hash,),
        )
        connection.execute(
            "INSERT INTO approvals(approval_id,run_id,approver,channel,"
            "source_message_digest,approval_text_digest,approved_action_type,"
            "target_type,target_id,target_hash,target_scope,approved_risk_ceiling,"
            "expires_at_epoch_ms,approval_hash,consumed_by_transition_id,"
            "consumed_by_gate_run_id,approved_at) VALUES('approval','run','river',"
            "'telegram','source','text','mutate','artifact','artifact-1',?,"
            "'repo','R1',2000,'approval-hash','transition','gate','now')",
            (target_hash,),
        )
        connection.execute(
            "UPDATE transitions SET approval_required=1,approval_id='approval',"
            "approval_channel='telegram',approval_source_digest='source',"
            "approval_text_digest='text',gate_run_id='gate',evidence_hash=? "
            "WHERE transition_id='transition'",
            (self.evidence_hash,),
        )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
            "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
            "context_hash,evidence_hash,independence_class,independence_proof_json,"
            "completed_at) VALUES('verifier','run','writer','security','openai',"
            "'gpt-5','prompt','context',?,'independent',?, 'now')",
            (self.evidence_hash, '{"review":"independent"}'),
        )
        try:
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,requires_same_run,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,"
                "created_at,run_authority_mode,workflow_authority_mode) "
                "VALUES('gate','run','transition','clock','verifier',"
                "'pass','now',1000,1,'v1',?,?,?,'R1','now','file_authority',"
                "'file_authority')",
                (_sha(b"gate-query"), _sha(b"migration"), self.evidence_hash),
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES('clock','gate','gate','run',"
                "'transition','nonce',1000,1000,'writer',?,1000)",
                (_sha(b"clock"),),
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES(?, 'run',"
                "'artifacts/evidence.json',?,13,'application/json','none','run',"
                "'verifier','gate','now')",
                (self.evidence_hash, self.evidence_hash),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        with connection:
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,"
                "backend,schema_hash,sandbox_required,sandbox_enforced,created_at) "
                "VALUES('plugin','safe','1','agentic_predicate_inproc_v1','schema',"
                "0,1,'now')"
            )
            connection.execute(
                "INSERT INTO goal_manifests(goal_id,owner,severity,manifest_hash,"
                "predicate_plugin_hash,backend,approval_required,enabled,created_at,"
                "updated_at) VALUES('goal','owner','R1','manifest','plugin',"
                "'agentic_predicate_inproc_v1',0,1,'now','now')"
            )


if __name__ == "__main__":
    unittest.main()
