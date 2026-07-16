from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from agentic_os.migrations import apply_migrations, repository_root
from agentic_os.pass_gates import (
    ApprovalGrant,
    GateEvidence,
    PassGateError,
    VerifierProof,
    record_approval_pass_gate,
)
from agentic_os.slo_contracts import SLO_QUERY_CONTRACTS


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class PassGateWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"
        apply_migrations(self.database)
        self._seed_transition()

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _seed_transition(self, *, authority_mode: str = "file_authority") -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            if authority_mode in {"db_authority_canary", "db_authority"}:
                connection.execute(
                    "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                    "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                    "open_file_authority_runs,updated_at) VALUES('workflow',?,"
                    "'approver',?,'deadline',?,0,'now')",
                    (authority_mode, _sha("cutover"), _sha("parity")),
                )
            else:
                connection.execute(
                    "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                    "VALUES('workflow',?,'now')",
                    (authority_mode,),
                )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('run','prepare','workflow',?,'candidate','R2','R2','now','now')",
                (authority_mode,),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,risk_dominance,idempotency_key,guard_version_before,"
                "created_at) VALUES('transition','run','prepared','gate_passed',"
                "'gate','mutate','artifact','artifact-1',?,'repo','R2',"
                "'transition-idem',0,'now')",
                (_sha("artifact"),),
            )

    def _approval(self, *, expires_at_epoch_ms: int = 1_800_000_100_000) -> ApprovalGrant:
        return ApprovalGrant(
            approval_id="approval",
            approver="erwin",
            channel="telegram",
            source_message_digest=_sha("source-message"),
            approval_text_digest=_sha("approval-text"),
            approved_risk_ceiling="R2",
            expires_at_epoch_ms=expires_at_epoch_ms,
            approved_at="approved-now",
            source_message_id="message-1",
        )

    def _verifier(self, *, worker_agent_id: str = "writer") -> VerifierProof:
        return VerifierProof(
            verifier_run_id="verifier",
            worker_agent_id=worker_agent_id,
            verifier_agent_id="security-reviewer",
            provider="openai",
            model="gpt-5",
            prompt_hash=_sha("prompt"),
            context_hash=_sha("context"),
            independence_proof={"reviewer_session": "phase-c", "head": _sha("head")},
            completed_at="verified-now",
        )

    def _evidence(self) -> GateEvidence:
        return GateEvidence(
            path="artifacts/pass-gate/evidence.json",
            sha256=_sha("evidence"),
            size_bytes=17,
            content_type="application/json",
            redaction_status="none",
            captured_at="captured-now",
        )

    def _record(self, **overrides: object) -> None:
        kwargs = {
            "run_id": "run",
            "transition_id": "transition",
            "gate_run_id": "gate",
            "clock_context_id": "clock",
            "gate_nonce": "nonce",
            "now_epoch_ms": 1_800_000_000_000,
            "bound_by": "pass-gate-writer",
            "trusted_clock_source_hash": _sha("trusted-clock"),
            "gate_version": "pass-gate-v1",
            "gate_query_hash": _sha("gate-query"),
            "migration_sha256": _sha("migration"),
            "approval": self._approval(),
            "verifier": self._verifier(),
            "evidence": self._evidence(),
            "completed_at": "completed-now",
            "created_at": "created-now",
        }
        kwargs.update(overrides)
        record_approval_pass_gate(self.database, **kwargs)

    def test_records_exact_approval_clock_verifier_pass_gate_bundle(self) -> None:
        self._record()

        with closing(sqlite3.connect(self.database)) as connection:
            transition = connection.execute(
                "SELECT approval_required,approval_id,gate_run_id,evidence_hash "
                "FROM transitions WHERE transition_id='transition'"
            ).fetchone()
            self.assertEqual(
                transition,
                (1, "approval", "gate", _sha("evidence")),
            )
            gate = connection.execute(
                "SELECT decision,clock_context_id,verifier_run_id,completed_at_epoch_ms "
                "FROM gate_runs WHERE gate_run_id='gate'"
            ).fetchone()
            self.assertEqual(gate, ("pass", "clock", "verifier", 1_800_000_000_000))
            clock = connection.execute(
                "SELECT gate_run_id,consumed_by_gate_run_id,now_epoch_ms,"
                "bound_at_epoch_ms,consumed_at_epoch_ms FROM gate_clock_context "
                "WHERE clock_context_id='clock'"
            ).fetchone()
            self.assertEqual(
                clock,
                ("gate", "gate", 1_800_000_000_000, 1_800_000_000_000, 1_800_000_000_000),
            )
            for query_name in (
                "Passing gate without verifier row",
                "Passing gate wrong-run or non-independent verifier",
                "Gate evidence bound to same run",
                "Gate clock context exact one-use binding",
                "Broad or expired approvals",
                "Exact mutating approval binding",
                "Reused approval id",
                "Non-independent verifier row",
            ):
                sql = next(
                    item.sql_text
                    for item in SLO_QUERY_CONTRACTS
                    if item.query_name == query_name
                )
                self.assertIsNone(
                    connection.execute(sql).fetchone(),
                    query_name,
                )

    def test_expired_approval_is_rejected_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "expire after"):
            self._record(approval=self._approval(expires_at_epoch_ms=1_800_000_000_000))

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_runs").fetchone()[0], 0)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM judge_verifier_runs").fetchone()[0],
                0,
            )

    def test_same_worker_verifier_is_rejected(self) -> None:
        with self.assertRaisesRegex(PassGateError, "independent"):
            self._record(
                verifier=VerifierProof(
                    verifier_run_id="verifier",
                    worker_agent_id="same",
                    verifier_agent_id="same",
                    provider="openai",
                    model="gpt-5",
                    prompt_hash=_sha("prompt"),
                    context_hash=_sha("context"),
                    independence_proof={"reviewer_session": "phase-c"},
                    completed_at="verified-now",
                )
            )

    def test_database_authority_run_is_rejected_without_writes(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM transitions")
            connection.execute("DELETE FROM runs")
            connection.execute("DELETE FROM workflow_authority")
        self._seed_transition(authority_mode="db_authority_canary")

        with self.assertRaisesRegex(PassGateError, "database-authority"):
            self._record()

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_runs").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
