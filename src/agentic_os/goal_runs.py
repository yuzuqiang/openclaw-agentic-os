"""Local-only Standing Goal run writer with evidence binding checks."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .migrations import MigrationError, repository_root, verify_database_connection
from .predicates import INPROC_PREDICATE_BACKEND
from .privacy import PrivacyPreflightError, assert_privacy_preflight


class GoalRunError(RuntimeError):
    """A goal run could not be recorded with safe evidence bindings."""


_MAX_EPOCH_MS = 253_402_300_799_999
_DB_AUTHORITY_MODES = {"db_authority_canary", "db_authority"}
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True)
class GoalRunRecord:
    goal_run_id: str
    goal_id: str
    run_id: str | None
    severity: str
    state: str
    evidence_hash: str | None


def record_goal_run(
    database: Path,
    *,
    goal_run_id: str,
    goal_id: str,
    severity: str,
    state: str,
    predicate_plugin_hash: str,
    created_at: str,
    created_at_epoch_ms: int,
    run_id: str | None = None,
    backend: str = INPROC_PREDICATE_BACKEND,
    sandbox_enforced: bool = True,
    sandbox_proof_hash: str | None = None,
    approval_id: str | None = None,
    evidence_hash: str | None = None,
    triaged_at: str | None = None,
) -> GoalRunRecord:
    """Record a goal run without calling OpenClaw/Gateway/Cron.

    If ``evidence_hash`` is supplied, it must already name same-run,
    approval-bound PASS-gate evidence with an independent verifier. Production
    database-authority runs are rejected even if the schema would accept them.
    """

    goal_run_id = _required_text("goal_run_id", goal_run_id)
    goal_id = _required_text("goal_id", goal_id)
    severity = _required_text("severity", severity)
    state = _required_text("state", state)
    predicate_plugin_hash = _required_text("predicate_plugin_hash", predicate_plugin_hash)
    backend = _required_text("backend", backend)
    created_at = _required_text("created_at", created_at)
    created_at_epoch_ms = _epoch_ms("created_at_epoch_ms", created_at_epoch_ms)
    run_id = _optional_text("run_id", run_id)
    sandbox_proof_hash = _optional_text("sandbox_proof_hash", sandbox_proof_hash)
    approval_id = _optional_text("approval_id", approval_id)
    evidence_hash = _optional_sha256("evidence_hash", evidence_hash)
    triaged_at = _optional_text("triaged_at", triaged_at)
    sandbox_enforced_value = _bool_int("sandbox_enforced", sandbox_enforced)

    connection = _connect_goal_run_database(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            if run_id is not None:
                _reject_database_authority_run(connection, run_id)
            if evidence_hash is not None:
                if run_id is None:
                    raise GoalRunError("goal run evidence requires a bound run_id")
                _assert_evidence_binding(connection, run_id=run_id, evidence_hash=evidence_hash)
            if approval_id is not None:
                _consume_goal_approval(
                    connection,
                    approval_id=approval_id,
                    goal_run_id=goal_run_id,
                    goal_id=goal_id,
                    run_id=run_id,
                    predicate_plugin_hash=predicate_plugin_hash,
                    backend=backend,
                )
            connection.execute(
                "INSERT INTO goal_runs(goal_run_id,goal_id,run_id,severity,state,"
                "triaged_at,predicate_plugin_hash,backend,sandbox_enforced,"
                "sandbox_proof_hash,approval_id,evidence_hash,created_at,"
                "created_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    goal_run_id,
                    goal_id,
                    run_id,
                    severity,
                    state,
                    triaged_at,
                    predicate_plugin_hash,
                    backend,
                    sandbox_enforced_value,
                    sandbox_proof_hash,
                    approval_id,
                    evidence_hash,
                    created_at,
                    created_at_epoch_ms,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise GoalRunError(str(exc)) from exc
    finally:
        connection.close()
    return GoalRunRecord(
        goal_run_id=goal_run_id,
        goal_id=goal_id,
        run_id=run_id,
        severity=severity,
        state=state,
        evidence_hash=evidence_hash,
    )


def _verify_schema_identity(connection: sqlite3.Connection) -> None:
    try:
        verify_database_connection(connection)
    except (MigrationError, sqlite3.Error) as exc:
        raise GoalRunError("goal run database schema verification failed") from exc


def _connect_goal_run_database(database: Path) -> sqlite3.Connection:
    path = Path(database).expanduser().resolve()
    try:
        assert_privacy_preflight(repository_root(), database_paths=(path,))
    except PrivacyPreflightError as exc:
        raise GoalRunError("goal run database privacy preflight failed") from exc
    if not path.is_file():
        raise GoalRunError("goal run database must already exist")
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    database_stat = os.stat(path, follow_symlinks=False)
    file_mode = stat.S_IMODE(database_stat.st_mode)
    if not stat.S_ISREG(database_stat.st_mode):
        raise GoalRunError("goal run database must be a regular private file")
    if parent_mode != 0o700 or file_mode != 0o600:
        raise GoalRunError("goal run database requires 0700 directory and 0600 file")
    if int(getattr(database_stat, "st_nlink", 1) or 1) > 1:
        raise GoalRunError("goal run database cannot use hard-linked file aliases")
    _refuse_lax_sqlite_sidecars(path)
    database_uri = path.as_uri() + "?mode=rw"
    connection: sqlite3.Connection | None = None
    old_umask = os.umask(0o177)
    try:
        connection = sqlite3.connect(database_uri, uri=True, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=10000")
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise GoalRunError("goal run database open failed") from exc
    finally:
        os.umask(old_umask)
    actual_journal_mode = journal_mode[0] if journal_mode else None
    if str(actual_journal_mode).casefold() != "wal":
        connection.close()
        raise GoalRunError(
            "SQLite WAL journal mode is unavailable: "
            f"requested WAL, got {actual_journal_mode!r}"
        )
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
        connection.close()
        raise GoalRunError("SQLite foreign key enforcement is unavailable")
    try:
        _chmod_private_sqlite_sidecars(path)
    except GoalRunError:
        connection.close()
        raise
    return connection


def _sqlite_sidecar_paths(database: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{database}{suffix}") for suffix in _SQLITE_SIDECAR_SUFFIXES)


def _stat_existing_path_nofollow(path: Path) -> os.stat_result | None:
    try:
        return os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _refuse_lax_sqlite_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecar_paths(database):
        sidecar_stat = _stat_existing_path_nofollow(sidecar)
        if sidecar_stat is None:
            continue
        if not stat.S_ISREG(sidecar_stat.st_mode):
            raise GoalRunError("SQLite sidecar must be a regular private file")
        if int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1:
            raise GoalRunError("SQLite sidecar cannot use hard-linked file aliases")
        if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
            raise GoalRunError("SQLite sidecar requires 0600 file mode")


def _chmod_private_sqlite_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecar_paths(database):
        sidecar_stat = _stat_existing_path_nofollow(sidecar)
        if sidecar_stat is None:
            continue
        if not stat.S_ISREG(sidecar_stat.st_mode):
            raise GoalRunError("SQLite sidecar must be a regular private file")
        if int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1:
            raise GoalRunError("SQLite sidecar cannot use hard-linked file aliases")
        if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
            sidecar.chmod(0o600)
            sidecar_stat = os.stat(sidecar, follow_symlinks=False)
            if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
                raise GoalRunError("SQLite sidecar requires 0600 file mode")


def _reject_database_authority_run(connection: sqlite3.Connection, run_id: str) -> None:
    row = connection.execute(
        "SELECT r.authority_mode, w.mode FROM runs r "
        "JOIN workflow_authority w ON w.workflow=r.workflow "
        "WHERE r.run_id=?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise GoalRunError("goal run requires an existing run")
    if row[0] in _DB_AUTHORITY_MODES or row[1] in _DB_AUTHORITY_MODES:
        raise GoalRunError("goal run writer refuses database-authority runs")


def _assert_evidence_binding(
    connection: sqlite3.Connection, *, run_id: str, evidence_hash: str
) -> None:
    row = connection.execute(
        "SELECT e.evidence_hash FROM evidence_hashes e "
        "JOIN judge_verifier_runs j ON j.verifier_run_id=e.verifier_run_id "
        " AND j.worker_run_id=e.run_id AND j.evidence_hash=e.evidence_hash "
        "JOIN gate_runs g ON g.gate_run_id=e.gate_run_id "
        " AND g.evidence_hash=e.evidence_hash AND g.run_id=e.run_id "
        " AND g.verifier_run_id=e.verifier_run_id "
        "JOIN transitions t ON t.transition_id=g.transition_id "
        " AND t.run_id=g.run_id AND t.gate_run_id=g.gate_run_id "
        " AND t.evidence_hash=g.evidence_hash "
        "JOIN gate_clock_context c ON c.gate_run_id=g.gate_run_id "
        " AND c.consumed_by_gate_run_id=g.gate_run_id AND c.run_id=g.run_id "
        " AND c.transition_id=t.transition_id "
        "JOIN approvals a ON a.approval_id=t.approval_id "
        " AND a.run_id=t.run_id AND a.approved_action_type=t.action_type "
        " AND a.target_type=t.target_type AND a.target_id=t.target_id "
        " AND a.target_hash=t.target_hash AND a.target_scope=t.target_scope "
        " AND a.channel=t.approval_channel "
        " AND a.source_message_digest=t.approval_source_digest "
        " AND a.approval_text_digest=t.approval_text_digest "
        " AND a.consumed_by_transition_id=t.transition_id "
        " AND a.consumed_by_gate_run_id=g.gate_run_id "
        "WHERE e.evidence_hash=? AND e.sha256=e.evidence_hash "
        "AND length(e.evidence_hash)=64 "
        "AND e.evidence_hash NOT GLOB '*[^0-9a-f]*' "
        "AND e.run_id=? AND e.producer_run_id=? "
        "AND e.verifier_run_id IS NOT NULL AND e.gate_run_id IS NOT NULL "
        "AND g.run_authority_mode='file_authority' "
        "AND g.workflow_authority_mode='file_authority' "
        "AND g.decision='pass' AND g.requires_same_run=1 "
        "AND t.approval_required=1 "
        "AND j.independence_class='independent' "
        "AND j.verifier_run_id<>j.worker_run_id "
        "AND j.verifier_run_id<>e.run_id "
        "AND j.worker_agent_id<>j.verifier_agent_id AND j.same_worker_context=0 "
        "AND a.single_use=1 "
        "AND CASE a.approved_risk_ceiling "
        "WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 "
        "WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1 END >= "
        "CASE t.risk_dominance "
        "WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 "
        "WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99 END "
        "AND a.expires_at_epoch_ms > c.now_epoch_ms",
        (evidence_hash, run_id, run_id),
    ).fetchone()
    if row is None:
        raise GoalRunError(
            "goal run evidence requires same-run independent pass-gate evidence"
        )


def _consume_goal_approval(
    connection: sqlite3.Connection,
    *,
    approval_id: str,
    goal_run_id: str,
    goal_id: str,
    run_id: str | None,
    predicate_plugin_hash: str,
    backend: str,
) -> None:
    if run_id is None:
        raise GoalRunError("goal run approval requires a bound run_id")
    trusted_now_epoch_ms = int(time.time() * 1000)
    cursor = connection.execute(
        "UPDATE approvals SET consumed_by_goal_run_id=? "
        "WHERE approval_id=? "
        "AND consumed_by_transition_id IS NULL "
        "AND consumed_by_gate_run_id IS NULL "
        "AND (consumed_by_goal_run_id IS NULL OR consumed_by_goal_run_id=?) "
        "AND run_id=? "
        "AND approved_action_type='goal_run' "
        "AND target_type='goal' "
        "AND target_id=? "
        "AND single_use=1 "
        "AND length(source_message_digest)=64 "
        "AND source_message_digest NOT GLOB '*[^0-9a-f]*' "
        "AND length(approval_text_digest)=64 "
        "AND approval_text_digest NOT GLOB '*[^0-9a-f]*' "
        "AND length(approval_hash)=64 "
        "AND approval_hash NOT GLOB '*[^0-9a-f]*' "
        "AND expires_at_epoch_ms > ? "
        "AND EXISTS ("
        "SELECT 1 FROM goal_manifests gm "
        "WHERE gm.goal_id=? "
        "AND gm.predicate_plugin_hash=? "
        "AND gm.backend=? "
        "AND gm.approval_required=1 "
        "AND gm.enabled=1 "
        "AND approvals.target_hash=gm.manifest_hash "
        "AND approvals.target_scope=gm.owner "
        "AND CASE approvals.approved_risk_ceiling "
        "WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 "
        "WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1 END >= "
        "CASE gm.severity "
        "WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 "
        "WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99 END"
        ")",
        (
            goal_run_id,
            approval_id,
            goal_run_id,
            run_id,
            goal_id,
            trusted_now_epoch_ms,
            goal_id,
            predicate_plugin_hash,
            backend,
        ),
    )
    if cursor.rowcount != 1:
        raise GoalRunError("goal run approval could not be consumed")


def _required_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise GoalRunError(f"{name} must be non-empty text")
    return value


def _optional_text(name: str, value: object | None) -> str | None:
    if value is None:
        return None
    return _required_text(name, value)


def _optional_sha256(name: str, value: object | None) -> str | None:
    if value is None:
        return None
    text = _required_text(name, value)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise GoalRunError(f"{name} must be lowercase SHA-256")
    return text


def _epoch_ms(name: str, value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_EPOCH_MS:
        raise GoalRunError(f"{name} must be a valid epoch millisecond integer")
    return value


def _bool_int(name: str, value: object) -> int:
    if type(value) is not bool:
        raise GoalRunError(f"{name} must be a boolean")
    return 1 if value else 0
