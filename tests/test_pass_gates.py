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

from agentic_os.migrations import apply_migrations, repository_root
from agentic_os.pass_gates import (
    ApprovalGrant,
    GateEvidence,
    PassGateError,
    VerifierProof,
    record_approval_pass_gate,
)
from agentic_os.predicates import MAX_FILE_EVIDENCE_BYTES
from agentic_os.slo_contracts import SLO_QUERY_CONTRACTS


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


class PassGateWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.artifact_root = repository_root() / "artifacts/pass-gate-test"
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

    def _approval(self, *, expires_at_epoch_ms: int | None = None) -> ApprovalGrant:
        expires_at_epoch_ms = expires_at_epoch_ms or int(time.time() * 1000) + 3_600_000
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

    def _evidence(
        self,
        *,
        name: str = "evidence.json",
        content: bytes = b'{"ok":true}\n',
        sha256: str | None = None,
        size_bytes: int | None = None,
    ) -> GateEvidence:
        path = Path(self.evidence_directory.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        relative = path.relative_to(repository_root()).as_posix()
        return GateEvidence(
            path=relative,
            sha256=sha256 or _sha_bytes(content),
            size_bytes=len(content) if size_bytes is None else size_bytes,
            content_type="application/json",
            redaction_status="none",
            captured_at="captured-now",
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

    def _record(self, **overrides: object) -> None:
        if "gate_query_hash" in overrides and "migration_sha256" in overrides:
            gate_query_hash = str(overrides["gate_query_hash"])
            migration_sha256 = str(overrides["migration_sha256"])
        else:
            gate_query_hash, migration_sha256 = self._current_gate_identity()
        bound_by = str(overrides.get("bound_by", "pass-gate-writer"))
        if "now_epoch_ms" in overrides:
            now_epoch_ms = int(overrides["now_epoch_ms"])
        else:
            now_epoch_ms = int(time.time() * 1000)
        approval = overrides["approval"] if "approval" in overrides else self._approval()
        verifier = overrides["verifier"] if "verifier" in overrides else self._verifier()
        evidence = overrides["evidence"] if "evidence" in overrides else self._evidence()
        kwargs = {
            "run_id": "run",
            "transition_id": "transition",
            "gate_run_id": "gate",
            "clock_context_id": "clock",
            "gate_nonce": "nonce",
            "now_epoch_ms": now_epoch_ms,
            "bound_by": bound_by,
            "trusted_clock_source_hash": _clock_hash(now_epoch_ms, bound_by),
            "gate_version": "pass-gate-v1",
            "gate_query_hash": gate_query_hash,
            "migration_sha256": migration_sha256,
            "approval": approval,
            "verifier": verifier,
            "evidence": evidence,
            "completed_at": "completed-now",
            "created_at": "created-now",
        }
        kwargs.update(overrides)
        record_approval_pass_gate(self.database, **kwargs)

    def _assert_no_bundle_rows(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            for table in (
                "approvals",
                "gate_runs",
                "gate_clock_context",
                "judge_verifier_runs",
                "evidence_hashes",
            ):
                self.assertEqual(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                    table,
                )

    def test_records_exact_approval_clock_verifier_pass_gate_bundle(self) -> None:
        self._record()

        with closing(sqlite3.connect(self.database)) as connection:
            transition = connection.execute(
                "SELECT approval_required,approval_id,gate_run_id,evidence_hash "
                "FROM transitions WHERE transition_id='transition'"
            ).fetchone()
            self.assertEqual(
                transition,
                (1, "approval", "gate", self._evidence().sha256),
            )
            gate = connection.execute(
                "SELECT decision,clock_context_id,verifier_run_id,completed_at_epoch_ms "
                "FROM gate_runs WHERE gate_run_id='gate'"
            ).fetchone()
            self.assertEqual(gate[:3], ("pass", "clock", "verifier"))
            clock = connection.execute(
                "SELECT gate_run_id,consumed_by_gate_run_id,now_epoch_ms,"
                "bound_at_epoch_ms,consumed_at_epoch_ms FROM gate_clock_context "
                "WHERE clock_context_id='clock'"
            ).fetchone()
            self.assertEqual(clock[0:2], ("gate", "gate"))
            self.assertEqual((clock[2], clock[3], clock[4]), (gate[3], gate[3], gate[3]))
            for query_name in (
                item.query_name
                for item in SLO_QUERY_CONTRACTS
                if item.query_name != "SLO query fixture status"
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

    def test_absolute_evidence_path_is_stored_as_repo_relative_path(self) -> None:
        evidence = self._evidence()
        self._record(
            evidence=GateEvidence(
                path=str(repository_root() / evidence.path),
                sha256=evidence.sha256,
                size_bytes=evidence.size_bytes,
                content_type=evidence.content_type,
                redaction_status=evidence.redaction_status,
                captured_at=evidence.captured_at,
            )
        )

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT path FROM evidence_hashes WHERE evidence_hash=?",
                    (evidence.sha256,),
                ).fetchone(),
                (evidence.path,),
            )

    def test_expired_approval_is_rejected_before_any_bundle_rows(self) -> None:
        now_epoch_ms = int(time.time() * 1000)
        with self.assertRaisesRegex(PassGateError, "expire after"):
            self._record(
                now_epoch_ms=now_epoch_ms,
                approval=self._approval(expires_at_epoch_ms=now_epoch_ms),
            )

        self._assert_no_bundle_rows()

    def test_trusted_clock_source_hash_must_be_derived_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "derived gate clock"):
            self._record(trusted_clock_source_hash="a" * 64)

        self._assert_no_bundle_rows()

    def test_stale_trusted_clock_is_rejected_before_any_bundle_rows(self) -> None:
        stale_now_epoch_ms = 1000
        with self.assertRaisesRegex(PassGateError, "outside local wall-clock skew"):
            self._record(
                now_epoch_ms=stale_now_epoch_ms,
                trusted_clock_source_hash=_clock_hash(
                    stale_now_epoch_ms,
                    "pass-gate-writer",
                ),
            )

        self._assert_no_bundle_rows()

    def test_caller_stale_clock_cannot_keep_recently_expired_approval_alive(self) -> None:
        caller_now_epoch_ms = 10_000_000
        local_now_epoch_ms = caller_now_epoch_ms + 90_000
        with mock.patch(
            "agentic_os.pass_gates.time.time",
            return_value=local_now_epoch_ms / 1000,
        ):
            with self.assertRaisesRegex(PassGateError, "expire after"):
                self._record(
                    now_epoch_ms=caller_now_epoch_ms,
                    trusted_clock_source_hash=_clock_hash(
                        caller_now_epoch_ms,
                        "pass-gate-writer",
                    ),
                    approval=self._approval(
                        expires_at_epoch_ms=caller_now_epoch_ms + 1_000
                    ),
                )

        self._assert_no_bundle_rows()

    def test_gate_clock_is_resampled_inside_transaction_for_expiry(self) -> None:
        caller_now_epoch_ms = 10_000_000
        transaction_now_epoch_ms = caller_now_epoch_ms + 2_000
        with mock.patch(
            "agentic_os.pass_gates.time.time",
            side_effect=[
                caller_now_epoch_ms / 1000,
                transaction_now_epoch_ms / 1000,
            ],
        ):
            with self.assertRaisesRegex(PassGateError, "expire after"):
                self._record(
                    now_epoch_ms=caller_now_epoch_ms,
                    trusted_clock_source_hash=_clock_hash(
                        caller_now_epoch_ms,
                        "pass-gate-writer",
                    ),
                    approval=self._approval(
                        expires_at_epoch_ms=caller_now_epoch_ms + 1_000
                    ),
                )

        self._assert_no_bundle_rows()

    def test_schema_identity_is_verified_under_write_lock(self) -> None:
        from agentic_os import pass_gates

        original_verify = pass_gates._verify_schema_identity
        observed_transactions: list[bool] = []

        def assert_write_transaction(connection: sqlite3.Connection) -> None:
            observed_transactions.append(connection.in_transaction)
            self.assertTrue(connection.in_transaction)
            original_verify(connection)

        with mock.patch(
            "agentic_os.pass_gates._verify_schema_identity",
            side_effect=assert_write_transaction,
        ):
            self._record()

        self.assertEqual(observed_transactions, [True])

    def test_malformed_gate_identity_hashes_are_rejected_before_any_bundle_rows(self) -> None:
        for field_name in (
            "trusted_clock_source_hash",
            "gate_query_hash",
            "migration_sha256",
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(PassGateError, field_name):
                    self._record(**{field_name: "not-a-sha256"})
                self._assert_no_bundle_rows()

    def test_fictional_gate_identity_hashes_are_rejected_before_any_bundle_rows(self) -> None:
        for field_name in ("gate_query_hash", "migration_sha256"):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(PassGateError, "SLO identity"):
                    self._record(**{field_name: "a" * 64})
                self._assert_no_bundle_rows()

    def test_finalized_run_cannot_receive_backdated_pass_gate(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE runs SET state='finalized',finalized_at='done',"
                "finalized_at_epoch_ms=2000 WHERE run_id='run'"
            )
            connection.execute(
                "UPDATE transitions SET state_after='finalized' "
                "WHERE transition_id='transition'"
            )

        with self.assertRaisesRegex(PassGateError, "retroactive"):
            self._record()

        self._assert_no_bundle_rows()

    def test_malformed_transition_target_hash_is_rejected_before_any_bundle_rows(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE transitions SET target_hash='not-a-digest' "
                "WHERE transition_id='transition'"
            )

        with self.assertRaisesRegex(PassGateError, "transition target_hash"):
            self._record()

        self._assert_no_bundle_rows()

    def test_pending_external_rpc_blocks_pass_gate_before_commit(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO external_rpc_intents("
                "intent_id,run_id,transition_id,rpc_kind,client_request_id,"
                "idempotency_key,metadata_json,state,requested_at,"
                "requested_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "intent",
                    "run",
                    "transition",
                    "allow_lease_acquire",
                    "client-request",
                    "lease-idempotency",
                    "{}",
                    "pending",
                    "requested-now",
                    1,
                ),
            )

        with self.assertRaisesRegex(PassGateError, "Metadata-missing external RPC"):
            self._record()

        self._assert_no_bundle_rows()

    def test_raw_state_evidence_path_is_rejected_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "evidence path"):
            self._record(
                evidence=GateEvidence(
                    path="state/agentic-os/control.db",
                    sha256=_sha("evidence"),
                    size_bytes=17,
                    content_type="application/json",
                    redaction_status="none",
                    captured_at="captured-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_private_credential_evidence_path_is_rejected_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "private credentials"):
            self._record(evidence=self._evidence(name="config/credentials.json"))

        self._assert_no_bundle_rows()

    def test_symlink_evidence_path_is_rejected_before_any_bundle_rows(self) -> None:
        target = Path(self.evidence_directory.name) / "target.json"
        target.write_bytes(b'{"ok":true}\n')
        link = Path(self.evidence_directory.name) / "link.json"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

        with self.assertRaisesRegex(PassGateError, "symlink evidence"):
            self._record(
                evidence=GateEvidence(
                    path=link.relative_to(repository_root()).as_posix(),
                    sha256=_sha_bytes(target.read_bytes()),
                    size_bytes=target.stat().st_size,
                    content_type="application/json",
                    redaction_status="none",
                    captured_at="captured-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_hard_linked_evidence_path_is_rejected_before_any_bundle_rows(self) -> None:
        target = Path(self.evidence_directory.name) / "target.json"
        target.write_bytes(b'{"ok":true}\n')
        alias = Path(self.evidence_directory.name) / "alias.json"
        try:
            os.link(target, alias)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard link creation unavailable: {exc}")

        with self.assertRaisesRegex(PassGateError, "hard-linked"):
            self._record(
                evidence=GateEvidence(
                    path=alias.relative_to(repository_root()).as_posix(),
                    sha256=_sha_bytes(alias.read_bytes()),
                    size_bytes=alias.stat().st_size,
                    content_type="application/json",
                    redaction_status="none",
                    captured_at="captured-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_missing_evidence_artifact_is_rejected_before_any_bundle_rows(self) -> None:
        missing = Path(self.evidence_directory.name) / "missing.json"
        with self.assertRaisesRegex(PassGateError, "artifact is not readable"):
            self._record(
                evidence=GateEvidence(
                    path=missing.relative_to(repository_root()).as_posix(),
                    sha256=_sha_bytes(b"missing"),
                    size_bytes=len(b"missing"),
                    content_type="application/json",
                    redaction_status="none",
                    captured_at="captured-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_evidence_changed_before_commit_is_rejected_and_rolled_back(self) -> None:
        evidence = self._evidence()
        path = repository_root() / evidence.path

        from agentic_os import pass_gates

        original = pass_gates._assert_blocking_slos_clear

        def mutate_after_slos(connection: sqlite3.Connection) -> None:
            original(connection)
            path.write_bytes(b'{"ok":false}\n')

        with mock.patch(
            "agentic_os.pass_gates._assert_blocking_slos_clear",
            side_effect=mutate_after_slos,
        ):
            with self.assertRaisesRegex(PassGateError, "changed before commit"):
                self._record(evidence=evidence)

        self._assert_no_bundle_rows()

    def test_evidence_swapped_to_symlink_before_commit_is_rejected(self) -> None:
        evidence = self._evidence()
        path = repository_root() / evidence.path
        moved = path.with_name("moved-evidence.json")

        from agentic_os import pass_gates

        original = pass_gates._assert_blocking_slos_clear

        def swap_to_symlink_after_slos(connection: sqlite3.Connection) -> None:
            original(connection)
            path.rename(moved)
            try:
                os.symlink(moved, path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

        with mock.patch(
            "agentic_os.pass_gates._assert_blocking_slos_clear",
            side_effect=swap_to_symlink_after_slos,
        ):
            with self.assertRaisesRegex(PassGateError, "changed before commit"):
                self._record(evidence=evidence)

        self._assert_no_bundle_rows()

    def test_stale_evidence_hash_is_rejected_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "sha256 does not match"):
            self._record(evidence=self._evidence(sha256=_sha("stale")))

        self._assert_no_bundle_rows()

    def test_stale_evidence_size_is_rejected_before_any_bundle_rows(self) -> None:
        with self.assertRaisesRegex(PassGateError, "size does not match"):
            self._record(evidence=self._evidence(size_bytes=999))

        self._assert_no_bundle_rows()

    def test_malformed_verifier_hashes_are_rejected_before_any_bundle_rows(self) -> None:
        for field_name in ("prompt_hash", "context_hash"):
            with self.subTest(field_name=field_name):
                values = {
                    "prompt_hash": _sha("prompt"),
                    "context_hash": _sha("context"),
                }
                values[field_name] = "ABCDEF"
                with self.assertRaisesRegex(PassGateError, field_name):
                    self._record(
                        verifier=VerifierProof(
                            verifier_run_id="verifier",
                            worker_agent_id="writer",
                            verifier_agent_id="security-reviewer",
                            provider="openai",
                            model="gpt-5",
                            prompt_hash=values["prompt_hash"],
                            context_hash=values["context_hash"],
                            independence_proof={"reviewer_session": "phase-c"},
                            completed_at="verified-now",
                        )
                    )
                self._assert_no_bundle_rows()

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

        self._assert_no_bundle_rows()

    def test_verifier_run_id_cannot_reuse_worker_run_id(self) -> None:
        with self.assertRaisesRegex(PassGateError, "verifier run id"):
            self._record(
                verifier=VerifierProof(
                    verifier_run_id="run",
                    worker_agent_id="writer",
                    verifier_agent_id="security-reviewer",
                    provider="openai",
                    model="gpt-5",
                    prompt_hash=_sha("prompt"),
                    context_hash=_sha("context"),
                    independence_proof={"reviewer_session": "phase-c"},
                    completed_at="verified-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_database_authority_run_is_rejected_without_writes(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM transitions")
            connection.execute("DELETE FROM runs")
            connection.execute("DELETE FROM workflow_authority")
        self._seed_transition(authority_mode="db_authority_canary")

        with self.assertRaisesRegex(PassGateError, "database-authority"):
            self._record()

        self._assert_no_bundle_rows()

    def test_lax_sqlite_sidecar_is_rejected_before_any_bundle_rows(self) -> None:
        gate_query_hash, migration_sha256 = self._current_gate_identity()
        sidecar = Path(f"{self.database}-wal")
        sidecar.write_bytes(b"wal")
        sidecar.chmod(0o644)

        with self.assertRaisesRegex(PassGateError, "sidecar requires 0600"):
            self._record(
                gate_query_hash=gate_query_hash,
                migration_sha256=migration_sha256,
            )

        self._assert_no_bundle_rows()

    def test_symlink_sqlite_sidecar_is_rejected_before_opening_wal(self) -> None:
        gate_query_hash, migration_sha256 = self._current_gate_identity()
        target = Path(self.temporary.name) / "external-wal-target"
        target.write_bytes(b"wal")
        target.chmod(0o600)
        sidecar = Path(f"{self.database}-wal")
        try:
            os.symlink(target, sidecar)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

        with self.assertRaisesRegex(PassGateError, "sidecar must be a regular"):
            self._record(
                gate_query_hash=gate_query_hash,
                migration_sha256=migration_sha256,
            )

        self._assert_no_bundle_rows()

    def test_hard_linked_sqlite_sidecar_is_rejected_before_opening_wal(self) -> None:
        gate_query_hash, migration_sha256 = self._current_gate_identity()
        target = Path(self.temporary.name) / "external-wal-target"
        target.write_bytes(b"wal")
        target.chmod(0o600)
        sidecar = Path(f"{self.database}-wal")
        try:
            os.link(target, sidecar)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard link creation unavailable: {exc}")

        with self.assertRaisesRegex(PassGateError, "sidecar cannot use hard-linked"):
            self._record(
                gate_query_hash=gate_query_hash,
                migration_sha256=migration_sha256,
            )

        self._assert_no_bundle_rows()

    def test_hard_linked_database_is_rejected_before_opening_wal(self) -> None:
        alias = Path(self.temporary.name) / "control-alias.db"
        try:
            os.link(self.database, alias)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard link creation unavailable: {exc}")

        with self.assertRaisesRegex(PassGateError, "database cannot use hard-linked"):
            self._record()

        self._assert_no_bundle_rows()

    def test_oversized_evidence_is_rejected_before_any_bundle_rows(self) -> None:
        path = Path(self.evidence_directory.name) / "large-evidence.bin"
        with path.open("wb") as handle:
            handle.seek(MAX_FILE_EVIDENCE_BYTES)
            handle.write(b"x")

        with self.assertRaisesRegex(PassGateError, "exceeds safe size"):
            self._record(
                evidence=GateEvidence(
                    path=path.relative_to(repository_root()).as_posix(),
                    sha256=_sha_bytes(b"x"),
                    size_bytes=MAX_FILE_EVIDENCE_BYTES + 1,
                    content_type="application/octet-stream",
                    redaction_status="none",
                    captured_at="captured-now",
                )
            )

        self._assert_no_bundle_rows()

    def test_sqlite_sidecars_are_private_after_successful_write(self) -> None:
        self._record()

        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{self.database}{suffix}")
            if sidecar.exists():
                self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600, sidecar)


if __name__ == "__main__":
    unittest.main()
