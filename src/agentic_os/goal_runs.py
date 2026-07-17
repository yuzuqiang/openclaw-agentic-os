"""Local-only Standing Goal run writer with evidence binding checks."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .migrations import _connect, _verify_schema, load_migrations
from .predicates import INPROC_PREDICATE_BACKEND


class GoalRunError(RuntimeError):
    """A goal run could not be recorded with safe evidence bindings."""


_MAX_EPOCH_MS = 253_402_300_799_999
_DB_AUTHORITY_MODES = {"db_authority_canary", "db_authority"}


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

    connection = _connect(database)
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
    _verify_schema(connection, load_migrations())


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
        "JOIN approvals a ON a.run_id=g.run_id "
        " AND a.consumed_by_gate_run_id=g.gate_run_id "
        "WHERE e.evidence_hash=? AND e.run_id=? AND e.producer_run_id=? "
        "AND e.verifier_run_id IS NOT NULL AND e.gate_run_id IS NOT NULL "
        "AND g.decision='pass' AND g.requires_same_run=1 "
        "AND j.independence_class='independent' "
        "AND j.worker_agent_id<>j.verifier_agent_id AND j.same_worker_context=0 "
        "AND a.single_use=1",
        (evidence_hash, run_id, run_id),
    ).fetchone()
    if row is None:
        raise GoalRunError(
            "goal run evidence requires same-run independent pass-gate evidence"
        )


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
