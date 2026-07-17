"""Local-only writer for executable SLO audit rows."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .migrations import (
    MigrationError,
    _database_checks,
    _verify_schema,
    _verify_slo_queries,
    load_migrations,
)
from .pass_gates import (
    _EvidenceSnapshot,
    GateEvidence,
    PassGateError,
    _assert_evidence_snapshot_current,
    _connect,
    _derived_trusted_clock_source_hash,
    _validate_evidence,
)
from .slo_contracts import SLO_QUERY_CONTRACTS, slo_query_hash


class SloAuditError(RuntimeError):
    """An executable SLO audit row could not be recorded safely."""


@dataclass(frozen=True)
class SloAuditRecord:
    slo_audit_id: str
    query_name: str
    schema_version: int
    migration_sha256: str
    query_hash: str
    result_count: int
    status: str


@dataclass(frozen=True)
class _CurrentSloQuery:
    query_name: str
    schema_version: int
    migration_sha256: str
    query_hash: str
    sql_text: str
    empty_db_expected_status: str
    fixture_db_expected_status: str


@dataclass(frozen=True)
class _PassEvidenceBinding:
    evidence_hash: str
    evidence_run_id: str
    verifier_run_id: str
    gate_run_id: str
    evidence_snapshot: _EvidenceSnapshot


_MAX_EPOCH_MS = 253_402_300_799_999
_REFUSED_AUTHORITY_MODES = {"db_authority_canary", "db_authority"}
_PASS_GATE_QUERY_NAME = "Completion gate before done for R2+"
_FILE_AUTHORITY_MODE = "file_authority"


def record_slo_audit(
    database: Path,
    *,
    slo_audit_id: str,
    query_name: str,
    run_at: str,
    run_at_epoch_ms: int,
    evidence_hash: str | None = None,
    evidence_run_id: str | None = None,
    verifier_run_id: str | None = None,
    gate_run_id: str | None = None,
) -> SloAuditRecord:
    """Execute one pinned SLO query and persist its audit result.

    This writer is intentionally local-only. It requires a pre-existing migrated
    SQLite database, runs under ``BEGIN IMMEDIATE``, resolves the current
    ``slo_queries`` identity from the database, and never calls OpenClaw,
    Gateway, Cron, or production authority surfaces.
    """

    slo_audit_id = _required_text("slo_audit_id", slo_audit_id)
    query_name = _required_text("query_name", query_name)
    run_at = _required_text("run_at", run_at)
    _epoch_ms("run_at_epoch_ms", run_at_epoch_ms)

    connection = _connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            query = _current_slo_query(connection, query_name)
            result_count = _execute_pinned_slo(connection, query.sql_text)
            status = "pass" if result_count == 0 else "fail"
            evidence_fields: tuple[str | None, str | None, str | None, str | None]
            pass_evidence: _PassEvidenceBinding | None = None
            if status == "pass":
                pass_evidence = _require_pass_evidence(
                    connection,
                    evidence_hash=evidence_hash,
                    evidence_run_id=evidence_run_id,
                    verifier_run_id=verifier_run_id,
                    gate_run_id=gate_run_id,
                )
                evidence_fields = (
                    pass_evidence.evidence_hash,
                    pass_evidence.evidence_run_id,
                    pass_evidence.verifier_run_id,
                    pass_evidence.gate_run_id,
                )
                raise SloAuditError(
                    "passing SLO audit requires fixture execution evidence"
                )
            else:
                evidence_fields = (None, None, None, None)
            writer_run_at_epoch_ms = _writer_audit_epoch_ms()
            connection.execute(
                "INSERT INTO slo_audits("
                "slo_audit_id,query_name,schema_version,migration_sha256,"
                "query_hash,result_count,status,empty_db_status,fixture_db_status,"
                "evidence_hash,evidence_run_id,verifier_run_id,gate_run_id,"
                "run_at,run_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    slo_audit_id,
                    query.query_name,
                    query.schema_version,
                    query.migration_sha256,
                    query.query_hash,
                    result_count,
                    status,
                    "not_run",
                    "not_run",
                    evidence_fields[0],
                    evidence_fields[1],
                    evidence_fields[2],
                    evidence_fields[3],
                    run_at,
                    writer_run_at_epoch_ms,
                ),
            )
            if pass_evidence is not None:
                _assert_safe_pass_evidence_current(pass_evidence)
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    except sqlite3.Error as exc:
        raise SloAuditError(f"SLO audit database write failed: {exc}") from exc
    finally:
        connection.close()
    return SloAuditRecord(
        slo_audit_id=slo_audit_id,
        query_name=query.query_name,
        schema_version=query.schema_version,
        migration_sha256=query.migration_sha256,
        query_hash=query.query_hash,
        result_count=result_count,
        status=status,
    )


def _verify_schema_identity(connection: sqlite3.Connection) -> None:
    migrations = load_migrations()
    expected = [(item.version, item.name, item.sha256) for item in migrations]
    try:
        actual = connection.execute(
            "SELECT version,name,sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
        if actual != expected:
            raise SloAuditError("SLO audit database migration identity mismatch")
        _verify_schema(connection, migrations)
        _verify_slo_queries(connection, migrations)
        _database_checks(connection)
    except (MigrationError, sqlite3.Error) as exc:
        raise SloAuditError("SLO audit database schema verification failed") from exc


def _current_slo_query(
    connection: sqlite3.Connection, query_name: str
) -> _CurrentSloQuery:
    row = connection.execute(
        "SELECT q.query_name,q.schema_version,q.migration_sha256,q.query_hash,"
        "q.sql_text,q.empty_db_expected_status,q.fixture_db_expected_status "
        "FROM schema_migrations m "
        "JOIN slo_queries q ON q.schema_version=m.version "
        "AND q.migration_sha256=m.sha256 "
        "WHERE q.query_name=? "
        "ORDER BY m.version DESC LIMIT 1",
        (query_name,),
    ).fetchone()
    if row is None:
        raise SloAuditError("current SLO query identity is missing")
    contract = next(
        (item for item in SLO_QUERY_CONTRACTS if item.query_name == query_name),
        None,
    )
    if contract is None:
        raise SloAuditError("SLO query is not in the pinned local contract")
    if row[4] != contract.sql_text or row[3] != slo_query_hash(contract.sql_text):
        raise SloAuditError("current SLO query does not match the pinned SQL contract")
    return _CurrentSloQuery(
        query_name=row[0],
        schema_version=row[1],
        migration_sha256=row[2],
        query_hash=row[3],
        sql_text=row[4],
        empty_db_expected_status=row[5],
        fixture_db_expected_status=row[6],
    )


def _execute_pinned_slo(connection: sqlite3.Connection, sql_text: str) -> int:
    try:
        cursor = connection.execute(sql_text)
        return sum(1 for _row in cursor)
    except sqlite3.Error as exc:
        raise SloAuditError("pinned SLO SQL failed to execute") from exc


def _require_pass_evidence(
    connection: sqlite3.Connection,
    *,
    evidence_hash: str | None,
    evidence_run_id: str | None,
    verifier_run_id: str | None,
    gate_run_id: str | None,
) -> _PassEvidenceBinding:
    evidence_hash = _sha256_text("evidence_hash", evidence_hash)
    evidence_run_id = _required_text("evidence_run_id", evidence_run_id)
    verifier_run_id = _required_text("verifier_run_id", verifier_run_id)
    gate_run_id = _required_text("gate_run_id", gate_run_id)
    if verifier_run_id == evidence_run_id:
        raise SloAuditError("passing SLO audit requires independent verifier run id")
    row = connection.execute(
        "SELECT r.authority_mode,e.path,e.sha256,e.size_bytes,e.content_type,"
        "e.redaction_status,e.captured_at,g.gate_query_hash,g.migration_sha256,"
        "v.worker_run_id,g.run_authority_mode,g.workflow_authority_mode,w.mode,"
        "c.now_epoch_ms,c.bound_by,c.trusted_clock_source_hash "
        "FROM evidence_hashes e "
        "JOIN gate_runs g ON g.gate_run_id=e.gate_run_id "
        "AND g.evidence_hash=e.evidence_hash "
        "AND g.run_id=e.run_id "
        "AND g.verifier_run_id=e.verifier_run_id "
        "AND g.evidence_hash=e.sha256 "
        "JOIN judge_verifier_runs v ON v.verifier_run_id=e.verifier_run_id "
        "AND v.worker_run_id=e.run_id "
        "AND v.evidence_hash=e.evidence_hash "
        "JOIN runs r ON r.run_id=e.run_id "
        "JOIN workflow_authority w ON w.workflow=r.workflow "
        "JOIN transitions t ON t.transition_id=g.transition_id "
        "AND t.run_id=g.run_id "
        "AND t.approval_required=1 "
        "AND t.gate_run_id=g.gate_run_id "
        "AND t.evidence_hash=e.evidence_hash "
        "JOIN approvals a ON a.approval_id=t.approval_id "
        "AND a.run_id=t.run_id "
        "AND a.approved_action_type=t.action_type "
        "AND a.target_type=t.target_type "
        "AND a.target_id=t.target_id "
        "AND a.target_hash=t.target_hash "
        "AND a.target_scope=t.target_scope "
        "AND a.channel=t.approval_channel "
        "AND a.source_message_digest=t.approval_source_digest "
        "AND a.approval_text_digest=t.approval_text_digest "
        "AND a.single_use=1 "
        "AND a.consumed_by_transition_id=t.transition_id "
        "AND a.consumed_by_gate_run_id=g.gate_run_id "
        "JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id "
        "AND c.gate_run_id=g.gate_run_id "
        "AND c.consumed_by_gate_run_id=g.gate_run_id "
        "AND c.run_id=g.run_id "
        "AND c.transition_id=g.transition_id "
        "AND c.now_epoch_ms=g.completed_at_epoch_ms "
        "AND c.bound_at_epoch_ms=c.now_epoch_ms "
        "AND c.consumed_at_epoch_ms=c.now_epoch_ms "
        "WHERE e.gate_run_id=? "
        "AND e.evidence_hash=? "
        "AND e.sha256=? "
        "AND e.run_id=? "
        "AND e.producer_run_id=? "
        "AND e.verifier_run_id=? "
        "AND g.decision='pass' "
        "AND g.requires_same_run=1 "
        "AND v.independence_class='independent' "
        "AND v.same_worker_context=0 "
        "AND v.worker_agent_id<>v.verifier_agent_id "
        "AND a.expires_at_epoch_ms > c.now_epoch_ms",
        (
            gate_run_id,
            evidence_hash,
            evidence_hash,
            evidence_run_id,
            evidence_run_id,
            verifier_run_id,
        ),
    ).fetchone()
    if row is None:
        raise SloAuditError("passing SLO audit requires pass-gate evidence")
    if row[0] in _REFUSED_AUTHORITY_MODES:
        raise SloAuditError("SLO audit writer refuses database-authority runs")
    _assert_file_authority_gate_snapshot(
        run_authority_mode=row[10],
        workflow_authority_mode=row[11],
    )
    if row[12] in _REFUSED_AUTHORITY_MODES:
        raise SloAuditError("SLO audit writer refuses database-authority workflows")
    _assert_bound_gate_clock(
        now_epoch_ms=row[13],
        bound_by=row[14],
        trusted_clock_source_hash=row[15],
    )
    if verifier_run_id == row[9]:
        raise SloAuditError("passing SLO audit requires independent verifier run id")
    _assert_current_pass_gate_identity(
        connection,
        gate_query_hash=row[7],
        migration_sha256=row[8],
    )
    snapshot = _validate_bound_pass_evidence(
        path=row[1],
        sha256=row[2],
        size_bytes=row[3],
        content_type=row[4],
        redaction_status=row[5],
        captured_at=row[6],
    )
    return _PassEvidenceBinding(
        evidence_hash=evidence_hash,
        evidence_run_id=evidence_run_id,
        verifier_run_id=verifier_run_id,
        gate_run_id=gate_run_id,
        evidence_snapshot=snapshot,
    )


def _assert_current_pass_gate_identity(
    connection: sqlite3.Connection, *, gate_query_hash: str, migration_sha256: str
) -> None:
    row = connection.execute(
        "SELECT q.query_hash, q.migration_sha256 FROM schema_migrations m "
        "JOIN slo_queries q ON q.schema_version=m.version "
        "AND q.migration_sha256=m.sha256 "
        "WHERE q.query_name=? ORDER BY m.version DESC LIMIT 1",
        (_PASS_GATE_QUERY_NAME,),
    ).fetchone()
    if row is None:
        raise SloAuditError("current PASS gate SLO identity is missing")
    if (gate_query_hash, migration_sha256) != (row[0], row[1]):
        raise SloAuditError("bound PASS gate SLO identity is stale")


def _validate_bound_pass_evidence(
    *,
    path: object,
    sha256: object,
    size_bytes: object,
    content_type: object,
    redaction_status: object,
    captured_at: object,
) -> _EvidenceSnapshot:
    if not isinstance(path, str) or not isinstance(sha256, str):
        raise SloAuditError("passing SLO audit requires pass-gate evidence")
    if not isinstance(content_type, str) or not isinstance(redaction_status, str):
        raise SloAuditError("passing SLO audit requires pass-gate evidence")
    if not isinstance(captured_at, str):
        raise SloAuditError("passing SLO audit requires pass-gate evidence")
    try:
        return _validate_evidence(
            GateEvidence(
                path=path,
                sha256=sha256,
                size_bytes=size_bytes,
                content_type=content_type,
                redaction_status=redaction_status,
                captured_at=captured_at,
            )
        )
    except PassGateError as exc:
        raise SloAuditError(
            "passing SLO audit requires safely retrievable pass-gate evidence"
        ) from exc


def _assert_safe_pass_evidence_current(binding: _PassEvidenceBinding) -> None:
    try:
        _assert_evidence_snapshot_current(binding.evidence_snapshot)
    except PassGateError as exc:
        raise SloAuditError("passing SLO audit pass-gate evidence changed") from exc


def _writer_audit_epoch_ms() -> int:
    return int(time.time() * 1000)


def _assert_file_authority_gate_snapshot(
    *, run_authority_mode: object, workflow_authority_mode: object
) -> None:
    if (
        run_authority_mode != _FILE_AUTHORITY_MODE
        or workflow_authority_mode != _FILE_AUTHORITY_MODE
    ):
        raise SloAuditError("SLO audit writer requires file-authority pass gates")


def _assert_bound_gate_clock(
    *, now_epoch_ms: object, bound_by: object, trusted_clock_source_hash: object
) -> None:
    if type(now_epoch_ms) is not int or not isinstance(bound_by, str):
        raise SloAuditError("passing SLO audit requires trusted gate clock evidence")
    if not isinstance(trusted_clock_source_hash, str):
        raise SloAuditError("passing SLO audit requires trusted gate clock evidence")
    expected = _derived_trusted_clock_source_hash(
        now_epoch_ms=now_epoch_ms,
        bound_by=bound_by,
    )
    if trusted_clock_source_hash != expected:
        raise SloAuditError("passing SLO audit requires trusted gate clock evidence")


def _required_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SloAuditError(f"{name} must be a non-empty string")
    return value


def _epoch_ms(name: str, value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_EPOCH_MS:
        raise SloAuditError(f"{name} must be an integer epoch millisecond")
    return value


def _sha256_text(name: str, value: object) -> str:
    value = _required_text(name, value)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise SloAuditError(f"{name} must be a lowercase SHA-256 digest")
    return value
