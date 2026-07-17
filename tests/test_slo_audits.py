from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import agentic_os
from agentic_os.migrations import apply_migrations, repository_root
from agentic_os.pass_gates import (
    ApprovalGrant,
    GateEvidence,
    VerifierProof,
    record_approval_pass_gate,
)
from agentic_os.slo_audits import SloAuditError, record_slo_audit


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _clock_hash(now_epoch_ms: int, bound_by: str) -> str:
    return hashlib.sha256(
        (
            '{"bound_by":"'
            + bound_by
            + '","now_epoch_ms":'
            + str(now_epoch_ms)
            + ',"source":"pass-gate-writer-local-wall-clock-v1"}'
        ).encode("utf-8")
    ).hexdigest()


class SloAuditWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.artifact_root = repository_root() / "artifacts/slo-audit-test"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.evidence_directory = tempfile.TemporaryDirectory(dir=self.artifact_root)
        self.addCleanup(self.evidence_directory.cleanup)
        self.addCleanup(self._cleanup_artifact_root)
        self.database = Path(self.temporary.name) / "control.db"
        apply_migrations(self.database)
        self._seed_transition()

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _cleanup_artifact_root(self) -> None:
        try:
            self.artifact_root.rmdir()
            self.artifact_root.parent.rmdir()
        except OSError:
            pass

    def _seed_transition(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('workflow','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('run','prepare','workflow','file_authority','candidate',"
                "'R2','R2','now','now')"
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

    def _current_gate_identity(self) -> tuple[str, str]:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT q.query_hash, q.migration_sha256 FROM schema_migrations m "
                "JOIN slo_queries q ON q.schema_version=m.version "
                "AND q.migration_sha256=m.sha256 "
                "WHERE q.query_name='Completion gate before done for R2+' "
                "ORDER BY m.version DESC LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def _approval(self) -> ApprovalGrant:
        return ApprovalGrant(
            approval_id="approval",
            approver="erwin",
            channel="telegram",
            source_message_digest=_sha("source-message"),
            approval_text_digest=_sha("approval-text"),
            approved_risk_ceiling="R2",
            expires_at_epoch_ms=int(time.time() * 1000) + 3_600_000,
            approved_at="approved-now",
            source_message_id="message-1",
        )

    def _verifier(self) -> VerifierProof:
        return VerifierProof(
            verifier_run_id="verifier",
            worker_agent_id="writer",
            verifier_agent_id="security-reviewer",
            provider="openai",
            model="gpt-5",
            prompt_hash=_sha("prompt"),
            context_hash=_sha("context"),
            independence_proof={"reviewer_session": "phase-c", "head": _sha("head")},
            completed_at="verified-now",
        )

    def _evidence(
        self,
        *,
        name: str = "evidence.json",
        content: bytes = b'{"ok":true}\n',
    ) -> GateEvidence:
        path = Path(self.evidence_directory.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return GateEvidence(
            path=path.relative_to(repository_root()).as_posix(),
            sha256=_sha_bytes(content),
            size_bytes=len(content),
            content_type="application/json",
            redaction_status="none",
            captured_at="captured-now",
        )

    def _record_pass_gate(self) -> GateEvidence:
        gate_query_hash, migration_sha256 = self._current_gate_identity()
        now_epoch_ms = int(time.time() * 1000)
        bound_by = "pass-gate-writer"
        evidence = self._evidence()
        record_approval_pass_gate(
            self.database,
            run_id="run",
            transition_id="transition",
            gate_run_id="gate",
            clock_context_id="clock",
            gate_nonce="nonce",
            now_epoch_ms=now_epoch_ms,
            bound_by=bound_by,
            trusted_clock_source_hash=_clock_hash(now_epoch_ms, bound_by),
            gate_version="pass-gate-v1",
            gate_query_hash=gate_query_hash,
            migration_sha256=migration_sha256,
            approval=self._approval(),
            verifier=self._verifier(),
            evidence=evidence,
            completed_at="completed-now",
            created_at="created-now",
        )
        return evidence

    def _insert_malformed_pass_gate(
        self,
        *,
        evidence: GateEvidence,
        verifier_run_id: str = "verifier",
        gate_query_hash: str | None = None,
        migration_sha256: str | None = None,
        authority_mode: str = "file_authority",
        stored_evidence_hash: str | None = None,
        approval_bound: bool = True,
        restore_current_authority: bool = False,
    ) -> None:
        current_gate_query_hash, current_migration_sha256 = self._current_gate_identity()
        if gate_query_hash is None:
            gate_query_hash = current_gate_query_hash
        if migration_sha256 is None:
            migration_sha256 = current_migration_sha256
        if stored_evidence_hash is None:
            stored_evidence_hash = evidence.sha256
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            if authority_mode in {"db_authority_canary", "db_authority"}:
                connection.execute(
                    "UPDATE runs SET state='finalized',finalized_at='done',"
                    "finalized_at_epoch_ms=1 WHERE run_id='run'"
                )
                connection.execute(
                    "UPDATE workflow_authority SET mode=?,cutover_approved_by='approver',"
                    "cutover_evidence_hash=?,rollback_deadline='deadline',"
                    "last_parity_audit_hash=?,open_file_authority_runs=0 "
                    "WHERE workflow='workflow'",
                    (authority_mode, _sha("cutover"), _sha("parity")),
                )
                connection.execute(
                    "UPDATE runs SET authority_mode=? WHERE run_id='run'",
                    (authority_mode,),
                )
            if approval_bound:
                connection.execute(
                    "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                    "source_message_id,source_message_digest,approval_text_digest,"
                    "approved_action_type,target_type,target_id,target_hash,target_scope,"
                    "approved_risk_ceiling,expires_at_epoch_ms,expires_at_display,"
                    "single_use,approval_hash,consumed_by_transition_id,"
                    "consumed_by_gate_run_id,approved_at) VALUES('approval','run',"
                    "'erwin','telegram','message-1',?,?,'mutate','artifact',"
                    "'artifact-1',?,'repo','R2',?,NULL,1,?,'transition','gate',"
                    "'approved-now')",
                    (
                        _sha("source-message"),
                        _sha("approval-text"),
                        _sha("artifact"),
                        int(time.time() * 1000) + 3_600_000,
                        _sha("approval:gate"),
                    ),
                )
                connection.execute(
                    "UPDATE transitions SET approval_required=1,approval_id='approval',"
                    "approval_channel='telegram',approval_source_digest=?,"
                    "approval_text_digest=?,gate_run_id='gate',evidence_hash=? "
                    "WHERE run_id='run' AND transition_id='transition'",
                    (
                        _sha("source-message"),
                        _sha("approval-text"),
                        stored_evidence_hash,
                    ),
                )
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
                "context_hash,evidence_hash,independence_class,"
                "independence_proof_json,same_worker_context,completed_at) "
                "VALUES(?,'run','writer','security-reviewer','openai','gpt-5',"
                "?,?,?,'independent','{\"reviewer_session\":\"phase-c\"}',0,"
                "'verified-now')",
                (verifier_run_id, _sha("prompt"), _sha("context"), stored_evidence_hash),
            )
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,requires_same_run,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,"
                "created_at,run_authority_mode,workflow_authority_mode) "
                "VALUES('gate','run','transition','clock',?,'pass','completed-now',"
                "1,1,'pass-gate-v1',?,?,?,'R2','created-now',?,?)",
                (
                    verifier_run_id,
                    gate_query_hash,
                    migration_sha256,
                    stored_evidence_hash,
                    authority_mode,
                    authority_mode,
                ),
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES('clock','gate','gate','run',"
                "'transition','nonce',1,1,'test',?,1)",
                (_sha("clock"),),
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES(?,?,?,?,?,"
                "?,?,?,?,'gate',?)",
                (
                    stored_evidence_hash,
                    "run",
                    evidence.path,
                    evidence.sha256,
                    evidence.size_bytes,
                    evidence.content_type,
                    evidence.redaction_status,
                    "run",
                    verifier_run_id,
                    evidence.captured_at,
                ),
            )
            if restore_current_authority:
                connection.execute(
                    "UPDATE workflow_authority SET mode='rollback_to_file_authority',"
                    "updated_at='rollback' WHERE workflow='workflow'"
                )
                connection.execute(
                    "UPDATE runs SET authority_mode='file_authority',"
                    "updated_at='restored-file' WHERE run_id='run'"
                )

    def _assert_no_slo_audit_rows(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM slo_audits").fetchone()[0],
                0,
            )

    def _record_slo(self, **overrides: object):
        kwargs = {
            "slo_audit_id": "slo-audit",
            "query_name": "Duplicate live dispatch blocked",
            "run_at": "audit-now",
            "run_at_epoch_ms": int(time.time() * 1000),
        }
        kwargs.update(overrides)
        return record_slo_audit(self.database, **kwargs)

    def test_records_passing_named_slo_with_existing_pass_gate_evidence(self) -> None:
        evidence = self._record_pass_gate()
        record = self._record_slo(
            evidence_hash=evidence.sha256,
            evidence_run_id="run",
            verifier_run_id="verifier",
            gate_run_id="gate",
        )

        self.assertEqual(record.status, "pass")
        self.assertEqual(record.result_count, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT a.status,a.result_count,a.query_hash,q.query_hash,"
                "a.evidence_hash,a.evidence_run_id,a.verifier_run_id,a.gate_run_id "
                "FROM slo_audits a JOIN slo_queries q "
                "ON q.query_name=a.query_name "
                "AND q.schema_version=a.schema_version "
                "AND q.migration_sha256=a.migration_sha256 "
                "AND q.query_hash=a.query_hash "
                "WHERE a.slo_audit_id='slo-audit'"
            ).fetchone()
        self.assertEqual(
            row,
            (
                "pass",
                0,
                record.query_hash,
                record.query_hash,
                evidence.sha256,
                "run",
                "verifier",
                "gate",
            ),
        )

    def test_pass_status_requires_existing_pass_gate_evidence(self) -> None:
        with self.assertRaisesRegex(SloAuditError, "pass-gate evidence"):
            self._record_slo(
                evidence_hash="a" * 64,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_same_run_verifier_without_write(self) -> None:
        evidence = self._evidence()
        self._insert_malformed_pass_gate(evidence=evidence, verifier_run_id="run")

        with self.assertRaisesRegex(SloAuditError, "independent verifier run id"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="run",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_rejects_future_audit_clock_without_write(self) -> None:
        evidence = self._record_pass_gate()

        with self.assertRaisesRegex(SloAuditError, "clock cannot be in the future"):
            self._record_slo(
                run_at_epoch_ms=253_402_300_799_999,
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_evidence_hash_digest_mismatch_without_write(self) -> None:
        evidence = self._evidence()
        stored_evidence_hash = _sha("not-the-artifact-digest")
        self._insert_malformed_pass_gate(
            evidence=evidence,
            stored_evidence_hash=stored_evidence_hash,
        )

        with self.assertRaisesRegex(SloAuditError, "pass-gate evidence"):
            self._record_slo(
                evidence_hash=stored_evidence_hash,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_unapproved_pass_gate_without_write(self) -> None:
        evidence = self._evidence()
        self._insert_malformed_pass_gate(evidence=evidence, approval_bound=False)

        with self.assertRaisesRegex(SloAuditError, "pass-gate evidence"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_gate_time_db_authority_without_write(self) -> None:
        evidence = self._evidence()
        self._insert_malformed_pass_gate(
            evidence=evidence,
            authority_mode="db_authority_canary",
            restore_current_authority=True,
        )

        with self.assertRaisesRegex(SloAuditError, "database-authority pass gates"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_private_state_evidence_without_write(self) -> None:
        content = self.database.read_bytes()
        evidence = GateEvidence(
            path=self.database.relative_to(repository_root()).as_posix(),
            sha256=_sha_bytes(content),
            size_bytes=len(content),
            content_type="application/octet-stream",
            redaction_status="none",
            captured_at="captured-now",
        )
        self._insert_malformed_pass_gate(evidence=evidence)

        with self.assertRaisesRegex(SloAuditError, "safely retrievable"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_credential_evidence_without_write(self) -> None:
        evidence = self._evidence(name="config/credentials.json")
        self._insert_malformed_pass_gate(evidence=evidence)

        with self.assertRaisesRegex(SloAuditError, "safely retrievable"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_symlink_evidence_without_write(self) -> None:
        target = Path(self.evidence_directory.name) / "target.json"
        target.write_bytes(b'{"ok":true}\n')
        link = Path(self.evidence_directory.name) / "link.json"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        evidence = GateEvidence(
            path=link.relative_to(repository_root()).as_posix(),
            sha256=_sha_bytes(target.read_bytes()),
            size_bytes=target.stat().st_size,
            content_type="application/json",
            redaction_status="none",
            captured_at="captured-now",
        )
        self._insert_malformed_pass_gate(evidence=evidence)

        with self.assertRaisesRegex(SloAuditError, "safely retrievable"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_hard_linked_evidence_without_write(self) -> None:
        target = Path(self.evidence_directory.name) / "target.json"
        target.write_bytes(b'{"ok":true}\n')
        alias = Path(self.evidence_directory.name) / "alias.json"
        try:
            os.link(target, alias)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard link creation unavailable: {exc}")
        evidence = GateEvidence(
            path=alias.relative_to(repository_root()).as_posix(),
            sha256=_sha_bytes(alias.read_bytes()),
            size_bytes=alias.stat().st_size,
            content_type="application/json",
            redaction_status="none",
            captured_at="captured-now",
        )
        self._insert_malformed_pass_gate(evidence=evidence)

        with self.assertRaisesRegex(SloAuditError, "safely retrievable"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_rejects_stale_gate_identity_without_write(self) -> None:
        evidence = self._evidence()
        self._insert_malformed_pass_gate(evidence=evidence, gate_query_hash="a" * 64)

        with self.assertRaisesRegex(SloAuditError, "SLO identity is stale"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_pass_audit_refuses_database_authority_evidence_without_write(self) -> None:
        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        evidence = self._evidence()
        self._insert_malformed_pass_gate(
            evidence=evidence,
            authority_mode="db_authority_canary",
        )

        with self.assertRaisesRegex(SloAuditError, "database-authority"):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self._assert_no_slo_audit_rows()

    def test_failing_named_slo_records_result_count_without_pass_evidence(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,"
                "registry_row_hash) VALUES('cost','provider','model','endpoint',"
                "'capability',1,1,'known','now',?)",
                (_sha("cost-row"),),
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,"
                "selected_provider,selected_model,selected_endpoint_binding_id,"
                "selected_cost_registry_id,selected_cost_effective_at,"
                "selected_cost_registry_hash,selected_cost_confidence,"
                "selected_reserve_transition_id,time_budget_seconds,"
                "input_token_budget,output_token_budget,cost_budget_microusd,"
                "retry_budget,human_attention_budget,usage_confidence,updated_at) "
                "VALUES('run','workflow','capability','provider','model',"
                "'endpoint','cost','now',?,'known','transition',1,1,1,1,1,1,"
                "'unknown','now')",
                (_sha("cost-row"),),
            )
            connection.execute(
                "UPDATE runs SET state='gate_passed' WHERE run_id='run'"
            )

        record = self._record_slo(query_name="Unknown usage blocks auto-local")

        self.assertEqual(record.status, "fail")
        self.assertEqual(record.result_count, 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,result_count,evidence_hash FROM slo_audits "
                    "WHERE slo_audit_id='slo-audit'"
                ).fetchone(),
                ("fail", 1, None),
            )

    def test_schema_identity_is_verified_under_write_lock(self) -> None:
        evidence = self._record_pass_gate()
        from agentic_os import slo_audits

        original_verify = slo_audits._verify_schema_identity
        observed_transactions: list[bool] = []

        def assert_write_transaction(connection: sqlite3.Connection) -> None:
            observed_transactions.append(connection.in_transaction)
            self.assertTrue(connection.in_transaction)
            original_verify(connection)

        with mock.patch(
            "agentic_os.slo_audits._verify_schema_identity",
            side_effect=assert_write_transaction,
        ):
            self._record_slo(
                evidence_hash=evidence.sha256,
                evidence_run_id="run",
                verifier_run_id="verifier",
                gate_run_id="gate",
            )

        self.assertEqual(observed_transactions, [True])

    def test_unknown_query_name_is_rejected_without_audit_row(self) -> None:
        with self.assertRaisesRegex(SloAuditError, "identity is missing"):
            self._record_slo(query_name="not a pinned query")

        self._assert_no_slo_audit_rows()


if __name__ == "__main__":
    unittest.main()
