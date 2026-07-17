"""Atomic approval, verifier, clock, and PASS-gate prerequisite writer."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .migrations import (
    MigrationError,
    _database_checks,
    _verify_schema,
    _verify_slo_queries,
    load_migrations,
    repository_root,
)
from .privacy import (
    PrivacyPreflightError,
    assert_paths_retrievable,
    assert_privacy_preflight,
)
from .predicates import (
    MAX_FILE_EVIDENCE_BYTES,
    PredicateContractError,
    _is_credential_path_denied,
    _reject_symlink_evidence_path,
)
from .slo_contracts import SLO_QUERY_CONTRACTS


class PassGateError(RuntimeError):
    """A PASS gate prerequisite bundle could not be proven safe."""


_MAX_EPOCH_MS = 253_402_300_799_999
_RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
_COMPLETION_GATE_QUERY_NAME = "Completion gate before done for R2+"
_SLO_FIXTURE_STATUS_QUERY_NAME = "SLO query fixture status"
_TERMINAL_RUN_STATES = {"finalized", "rolled_back", "rejected"}
_TRUSTED_CLOCK_SOURCE = "pass-gate-writer-local-wall-clock-v1"
_TRUSTED_CLOCK_MAX_SKEW_MS = 5 * 60 * 1000
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True)
class ApprovalGrant:
    approval_id: str
    approver: str
    channel: str
    source_message_digest: str
    approval_text_digest: str
    approved_risk_ceiling: str
    expires_at_epoch_ms: int
    approved_at: str
    source_message_id: str | None = None
    expires_at_display: str | None = None


@dataclass(frozen=True)
class VerifierProof:
    verifier_run_id: str
    worker_agent_id: str
    verifier_agent_id: str
    provider: str
    model: str
    prompt_hash: str
    context_hash: str
    independence_proof: Mapping[str, object]
    completed_at: str
    model_version: str | None = None


@dataclass(frozen=True)
class GateEvidence:
    path: str
    sha256: str
    size_bytes: int
    content_type: str
    redaction_status: str
    captured_at: str


@dataclass(frozen=True)
class PassGateBundle:
    gate_run_id: str
    clock_context_id: str
    approval_id: str
    verifier_run_id: str
    evidence_hash: str
    status: str


@dataclass(frozen=True)
class _TrustedClock:
    now_epoch_ms: int
    source_hash: str


@dataclass(frozen=True)
class _EvidenceSnapshot:
    relative_path: str
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int]


def record_approval_pass_gate(
    database: Path,
    *,
    run_id: str,
    transition_id: str,
    gate_run_id: str,
    clock_context_id: str,
    gate_nonce: str,
    now_epoch_ms: int,
    bound_by: str,
    trusted_clock_source_hash: str,
    gate_version: str,
    gate_query_hash: str,
    migration_sha256: str,
    approval: ApprovalGrant,
    verifier: VerifierProof,
    evidence: GateEvidence,
    completed_at: str,
    created_at: str,
    assessment_id: str | None = None,
) -> PassGateBundle:
    """Persist an exact approval-bound PASS gate bundle in one transaction.

    The writer is intentionally local-only: it updates an already migrated
    SQLite control database, refuses database-authority runs, and does not call
    OpenClaw, Gateway, Cron, or any production authority surface.
    """

    run_id = _required_text("run_id", run_id)
    transition_id = _required_text("transition_id", transition_id)
    gate_run_id = _required_text("gate_run_id", gate_run_id)
    clock_context_id = _required_text("clock_context_id", clock_context_id)
    gate_nonce = _required_text("gate_nonce", gate_nonce)
    bound_by = _required_text("bound_by", bound_by)
    trusted_clock_source_hash = _sha256_text(
        "trusted_clock_source_hash", trusted_clock_source_hash
    )
    gate_version = _required_text("gate_version", gate_version)
    gate_query_hash = _sha256_text("gate_query_hash", gate_query_hash)
    migration_sha256 = _sha256_text("migration_sha256", migration_sha256)
    completed_at = _required_text("completed_at", completed_at)
    created_at = _required_text("created_at", created_at)
    now_epoch_ms = _epoch_ms("now_epoch_ms", now_epoch_ms)
    _assert_trusted_clock(
        now_epoch_ms=now_epoch_ms,
        bound_by=bound_by,
        trusted_clock_source_hash=trusted_clock_source_hash,
    )
    _validate_verifier(verifier, worker_run_id=run_id)
    evidence_snapshot = _validate_evidence(evidence)
    evidence_hash = evidence.sha256
    assessment_id = _required_text(
        "assessment_id", assessment_id or f"{transition_id}:{gate_run_id}:risk"
    )

    connection = _connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            transition = _transition_for_gate(
                connection, run_id=run_id, transition_id=transition_id
            )
            if transition["authority_mode"] in {"db_authority_canary", "db_authority"}:
                raise PassGateError("PASS gate writer refuses database-authority runs")
            _reject_terminal_run(transition)
            _assert_gate_identity(
                connection,
                gate_query_hash=gate_query_hash,
                migration_sha256=migration_sha256,
            )
            action_type = _transition_text(transition, "action_type")
            target_type = _transition_text(transition, "target_type")
            target_id = _transition_text(transition, "target_id")
            target_hash = _sha256_text(
                "transition target_hash",
                _transition_text(transition, "target_hash"),
            )
            target_scope = _transition_text(transition, "target_scope")
            risk_dominance = _transition_text(transition, "risk_dominance")
            if _pass_gate_exists(
                connection, run_id=run_id, transition_id=transition_id
            ):
                raise PassGateError("transition already has an immutable PASS gate")
            trusted_clock = _assert_trusted_clock(
                now_epoch_ms=now_epoch_ms,
                bound_by=bound_by,
                trusted_clock_source_hash=trusted_clock_source_hash,
            )
            now_epoch_ms = trusted_clock.now_epoch_ms
            trusted_clock_source_hash = trusted_clock.source_hash
            _validate_approval(approval, now_epoch_ms=now_epoch_ms)
            if _RISK_ORDER[approval.approved_risk_ceiling] < _RISK_ORDER[risk_dominance]:
                raise PassGateError("approval risk ceiling is below transition risk")

            approval_hash = _approval_hash(
                approval,
                run_id=run_id,
                transition_id=transition_id,
                gate_run_id=gate_run_id,
                action_type=action_type,
                target_type=target_type,
                target_id=target_id,
                target_hash=target_hash,
                target_scope=target_scope,
            )
            connection.execute(
                "INSERT INTO approvals(approval_id,run_id,approver,channel,"
                "source_message_id,source_message_digest,approval_text_digest,"
                "approved_action_type,target_type,target_id,target_hash,target_scope,"
                "approved_risk_ceiling,expires_at_epoch_ms,expires_at_display,"
                "single_use,approval_hash,consumed_by_transition_id,"
                "consumed_by_gate_run_id,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?,?,?,?,?,?)",
                (
                    approval.approval_id,
                    run_id,
                    approval.approver,
                    approval.channel,
                    approval.source_message_id,
                    approval.source_message_digest,
                    approval.approval_text_digest,
                    action_type,
                    target_type,
                    target_id,
                    target_hash,
                    target_scope,
                    approval.approved_risk_ceiling,
                    approval.expires_at_epoch_ms,
                    approval.expires_at_display,
                    1,
                    approval_hash,
                    transition_id,
                    gate_run_id,
                    approval.approved_at,
                ),
            )
            connection.execute(
                "INSERT INTO risk_assessments(assessment_id,run_id,transition_id,"
                "action_risk,target_risk,data_risk,side_effect_risk,"
                "permission_risk,irreversibility_risk,risk_dominance,assessed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    assessment_id,
                    run_id,
                    transition_id,
                    risk_dominance,
                    risk_dominance,
                    risk_dominance,
                    risk_dominance,
                    risk_dominance,
                    risk_dominance,
                    risk_dominance,
                    created_at,
                ),
            )
            connection.execute(
                "UPDATE transitions SET approval_required=1,approval_id=?,"
                "approval_channel=?,approval_source_digest=?,approval_text_digest=?,"
                "gate_run_id=?,evidence_hash=? WHERE run_id=? AND transition_id=?",
                (
                    approval.approval_id,
                    approval.channel,
                    approval.source_message_digest,
                    approval.approval_text_digest,
                    gate_run_id,
                    evidence_hash,
                    run_id,
                    transition_id,
                ),
            )
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,model_version,"
                "prompt_hash,context_hash,evidence_hash,independence_class,"
                "independence_proof_json,same_worker_context,completed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                (
                    verifier.verifier_run_id,
                    run_id,
                    verifier.worker_agent_id,
                    verifier.verifier_agent_id,
                    verifier.provider,
                    verifier.model,
                    verifier.model_version,
                    verifier.prompt_hash,
                    verifier.context_hash,
                    evidence_hash,
                    "independent",
                    _canonical_json(verifier.independence_proof),
                    verifier.completed_at,
                ),
            )
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,requires_same_run,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,"
                "created_at) VALUES(?,?,?,?,?,'pass',?,?,1,?,?,?,?,?,?)",
                (
                    gate_run_id,
                    run_id,
                    transition_id,
                    clock_context_id,
                    verifier.verifier_run_id,
                    completed_at,
                    now_epoch_ms,
                    gate_version,
                    gate_query_hash,
                    migration_sha256,
                    evidence_hash,
                    risk_dominance,
                    created_at,
                ),
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    clock_context_id,
                    gate_run_id,
                    gate_run_id,
                    run_id,
                    transition_id,
                    gate_nonce,
                    now_epoch_ms,
                    now_epoch_ms,
                    bound_by,
                    trusted_clock_source_hash,
                    now_epoch_ms,
                ),
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    evidence_hash,
                    run_id,
                    evidence_snapshot.relative_path,
                    evidence.sha256,
                    evidence.size_bytes,
                    evidence.content_type,
                    evidence.redaction_status,
                    run_id,
                    verifier.verifier_run_id,
                    gate_run_id,
                    evidence.captured_at,
                ),
            )
            _assert_blocking_slos_clear(connection)
            _assert_evidence_snapshot_current(evidence_snapshot)
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    except sqlite3.Error as exc:
        raise PassGateError(f"PASS gate database write failed: {exc}") from exc
    finally:
        connection.close()
    return PassGateBundle(
        gate_run_id=gate_run_id,
        clock_context_id=clock_context_id,
        approval_id=approval.approval_id,
        verifier_run_id=verifier.verifier_run_id,
        evidence_hash=evidence_hash,
        status="created",
    )


def _connect(database: Path) -> sqlite3.Connection:
    path = Path(database).expanduser().resolve()
    try:
        assert_privacy_preflight(repository_root(), database_paths=(path,))
    except PrivacyPreflightError as exc:
        raise PassGateError("PASS gate database privacy preflight failed") from exc
    if not path.is_file():
        raise PassGateError("PASS gate database must already exist")
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    database_stat = os.stat(path, follow_symlinks=False)
    file_mode = stat.S_IMODE(database_stat.st_mode)
    if not stat.S_ISREG(database_stat.st_mode):
        raise PassGateError("PASS gate database must be a regular private file")
    if parent_mode != 0o700 or file_mode != 0o600:
        raise PassGateError("PASS gate database requires 0700 directory and 0600 file")
    if int(getattr(database_stat, "st_nlink", 1) or 1) > 1:
        raise PassGateError("PASS gate database cannot use hard-linked file aliases")
    _refuse_lax_sqlite_sidecars(path)
    database_uri = path.as_uri() + "?mode=rw"
    old_umask = os.umask(0o177)
    try:
        connection = sqlite3.connect(database_uri, uri=True, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=10000")
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    finally:
        os.umask(old_umask)
    actual_journal_mode = journal_mode[0] if journal_mode else None
    if str(actual_journal_mode).casefold() != "wal":
        connection.close()
        raise PassGateError(
            "SQLite WAL journal mode is unavailable: "
            f"requested WAL, got {actual_journal_mode!r}"
        )
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
        connection.close()
        raise PassGateError("SQLite foreign key enforcement is unavailable")
    try:
        _chmod_private_sqlite_sidecars(path)
    except PassGateError:
        connection.close()
        raise
    return connection


def _verify_schema_identity(connection: sqlite3.Connection) -> None:
    migrations = load_migrations()
    expected = [(item.version, item.name, item.sha256) for item in migrations]
    try:
        actual = connection.execute(
            "SELECT version,name,sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
        if actual != expected:
            raise PassGateError("PASS gate database migration identity mismatch")
        _verify_schema(connection, migrations)
        _verify_slo_queries(connection, migrations)
        _database_checks(connection)
    except (MigrationError, sqlite3.Error) as exc:
        raise PassGateError("PASS gate database schema verification failed") from exc


def _transition_for_gate(
    connection: sqlite3.Connection, *, run_id: str, transition_id: str
) -> dict[str, str | None]:
    row = connection.execute(
        "SELECT t.action_type,t.target_type,t.target_id,t.target_hash,"
        "t.target_scope,t.risk_dominance,r.authority_mode,r.risk_dominance,"
        "r.state,r.finalized_at_epoch_ms "
        "FROM transitions t JOIN runs r ON r.run_id=t.run_id "
        "WHERE t.run_id=? AND t.transition_id=?",
        (run_id, transition_id),
    ).fetchone()
    if row is None:
        raise PassGateError("transition does not exist for PASS gate")
    if row[5] != row[7]:
        raise PassGateError("transition risk does not match run risk")
    return {
        "action_type": row[0],
        "target_type": row[1],
        "target_id": row[2],
        "target_hash": row[3],
        "target_scope": row[4],
        "risk_dominance": row[5],
        "authority_mode": row[6],
        "run_risk_dominance": row[7],
        "run_state": row[8],
        "finalized_at_epoch_ms": row[9],
    }


def _pass_gate_exists(
    connection: sqlite3.Connection, *, run_id: str, transition_id: str
) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM gate_runs WHERE run_id=? AND transition_id=? "
            "AND decision='pass' LIMIT 1",
            (run_id, transition_id),
        ).fetchone()
        is not None
    )


def _reject_terminal_run(transition: Mapping[str, object]) -> None:
    run_state = transition.get("run_state")
    finalized_at_epoch_ms = transition.get("finalized_at_epoch_ms")
    if run_state in _TERMINAL_RUN_STATES or finalized_at_epoch_ms is not None:
        raise PassGateError("terminal run cannot receive a retroactive PASS gate")


def _assert_gate_identity(
    connection: sqlite3.Connection, *, gate_query_hash: str, migration_sha256: str
) -> None:
    row = connection.execute(
        "SELECT q.query_hash, q.migration_sha256 FROM schema_migrations m "
        "JOIN slo_queries q ON q.schema_version=m.version "
        "AND q.migration_sha256=m.sha256 "
        "WHERE q.query_name=? ORDER BY m.version DESC LIMIT 1",
        (_COMPLETION_GATE_QUERY_NAME,),
    ).fetchone()
    if row is None:
        raise PassGateError("current PASS gate SLO identity is missing")
    if (gate_query_hash, migration_sha256) != (row[0], row[1]):
        raise PassGateError("PASS gate SLO identity does not match current database")


def _assert_blocking_slos_clear(connection: sqlite3.Connection) -> None:
    contracts = {
        item.query_name: item.sql_text
        for item in SLO_QUERY_CONTRACTS
        if item.query_name != _SLO_FIXTURE_STATUS_QUERY_NAME
    }
    for query_name in sorted(contracts):
        if connection.execute(contracts[query_name]).fetchone() is not None:
            raise PassGateError(f"blocking SLO failed before PASS gate commit: {query_name}")


def _approval_hash(
    approval: ApprovalGrant,
    *,
    run_id: str,
    transition_id: str,
    gate_run_id: str,
    action_type: str,
    target_type: str,
    target_id: str,
    target_hash: str,
    target_scope: str,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "approval_id": approval.approval_id,
                "run_id": run_id,
                "transition_id": transition_id,
                "gate_run_id": gate_run_id,
                "action_type": action_type,
                "target_type": target_type,
                "target_id": target_id,
                "target_hash": target_hash,
                "target_scope": target_scope,
                "channel": approval.channel,
                "source_message_digest": approval.source_message_digest,
                "approval_text_digest": approval.approval_text_digest,
                "approved_risk_ceiling": approval.approved_risk_ceiling,
                "expires_at_epoch_ms": approval.expires_at_epoch_ms,
            }
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _required_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise PassGateError(f"{name} must be a non-empty string")
    return value


def _transition_text(row: Mapping[str, object], name: str) -> str:
    try:
        value = row[name]
    except KeyError as exc:
        raise PassGateError(f"transition is missing {name}") from exc
    if not isinstance(value, str) or not value:
        raise PassGateError("approval-bound transition requires exact target fields")
    return value


def _epoch_ms(name: str, value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_EPOCH_MS:
        raise PassGateError(f"{name} must be an integer epoch millisecond")
    return value


def _sha256_text(name: str, value: str) -> str:
    value = _required_text(name, value)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise PassGateError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _derived_trusted_clock_source_hash(*, now_epoch_ms: int, bound_by: str) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "bound_by": bound_by,
                "now_epoch_ms": now_epoch_ms,
                "source": _TRUSTED_CLOCK_SOURCE,
            }
        ).encode("utf-8")
    ).hexdigest()


def _assert_trusted_clock(
    *,
    now_epoch_ms: int,
    bound_by: str,
    trusted_clock_source_hash: str,
) -> _TrustedClock:
    local_now_epoch_ms = int(time.time() * 1000)
    if abs(local_now_epoch_ms - now_epoch_ms) > _TRUSTED_CLOCK_MAX_SKEW_MS:
        raise PassGateError("trusted gate clock is outside local wall-clock skew")
    caller_expected = _derived_trusted_clock_source_hash(
        now_epoch_ms=now_epoch_ms,
        bound_by=bound_by,
    )
    if trusted_clock_source_hash != caller_expected:
        raise PassGateError("trusted_clock_source_hash does not match derived gate clock")
    local_source_hash = _derived_trusted_clock_source_hash(
        now_epoch_ms=local_now_epoch_ms,
        bound_by=bound_by,
    )
    return _TrustedClock(
        now_epoch_ms=local_now_epoch_ms,
        source_hash=local_source_hash,
    )


def _validate_approval(approval: ApprovalGrant, *, now_epoch_ms: int) -> None:
    _required_text("approval_id", approval.approval_id)
    _required_text("approver", approval.approver)
    _required_text("channel", approval.channel)
    _sha256_text("source_message_digest", approval.source_message_digest)
    _sha256_text("approval_text_digest", approval.approval_text_digest)
    if approval.approved_risk_ceiling not in _RISK_ORDER:
        raise PassGateError("approved_risk_ceiling must be R0, R1, R2, R3, or R4")
    expires_at = _epoch_ms("expires_at_epoch_ms", approval.expires_at_epoch_ms)
    if expires_at <= now_epoch_ms:
        raise PassGateError("approval must expire after the trusted gate clock")
    _required_text("approved_at", approval.approved_at)


def _validate_verifier(verifier: VerifierProof, *, worker_run_id: str) -> None:
    _required_text("verifier_run_id", verifier.verifier_run_id)
    if verifier.verifier_run_id == worker_run_id:
        raise PassGateError("verifier run id must be independent from worker run")
    _required_text("worker_agent_id", verifier.worker_agent_id)
    _required_text("verifier_agent_id", verifier.verifier_agent_id)
    if verifier.worker_agent_id == verifier.verifier_agent_id:
        raise PassGateError("verifier must be independent from worker")
    _required_text("provider", verifier.provider)
    _required_text("model", verifier.model)
    _sha256_text("prompt_hash", verifier.prompt_hash)
    _sha256_text("context_hash", verifier.context_hash)
    if verifier.prompt_hash == verifier.context_hash:
        raise PassGateError("verifier prompt and context hashes must differ")
    if not verifier.independence_proof:
        raise PassGateError("verifier independence proof must be a non-empty object")
    _canonical_json(verifier.independence_proof)
    _required_text("completed_at", verifier.completed_at)


def _validate_evidence(evidence: GateEvidence) -> _EvidenceSnapshot:
    path_text = _required_text("evidence path", evidence.path)
    try:
        assert_paths_retrievable(path_text)
    except PrivacyPreflightError as exc:
        raise PassGateError("gate evidence path is not safely retrievable") from exc
    expected_sha256 = _sha256_text("evidence sha256", evidence.sha256)
    if type(evidence.size_bytes) is not int or evidence.size_bytes < 0:
        raise PassGateError("evidence size must be a non-negative integer")
    if evidence.size_bytes > MAX_FILE_EVIDENCE_BYTES:
        raise PassGateError("gate evidence exceeds safe size limit")
    repo_root = repository_root().resolve()
    candidate = Path(path_text).expanduser()
    if candidate.is_absolute():
        try:
            input_relative = candidate.relative_to(repo_root)
        except ValueError:
            raise PassGateError("gate evidence artifact must stay inside the worktree") from None
    else:
        input_relative = candidate
    if ".." in input_relative.parts or not input_relative.parts:
        raise PassGateError("gate evidence path must name repo evidence")
    try:
        _reject_symlink_evidence_path(repo_root, input_relative)
    except PredicateContractError as exc:
        raise PassGateError("gate evidence cannot use symlink evidence") from exc
    if _is_credential_path_denied(path_text) or _is_credential_path_denied(
        input_relative.as_posix()
    ):
        raise PassGateError("gate evidence targets private credentials or artifacts")
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PassGateError("gate evidence artifact is not readable") from exc
    try:
        relative = resolved.relative_to(repo_root).as_posix()
    except ValueError:
        raise PassGateError("gate evidence artifact must stay inside the worktree") from None
    if _is_credential_path_denied(relative):
        raise PassGateError("gate evidence targets private credentials or artifacts")
    try:
        assert_paths_retrievable((path_text, relative))
    except PrivacyPreflightError as exc:
        raise PassGateError("gate evidence path is not safely retrievable") from exc
    actual_sha256, file_stat = _hash_evidence_file(resolved)
    if file_stat.st_size != evidence.size_bytes:
        raise PassGateError("gate evidence size does not match artifact")
    if actual_sha256 != expected_sha256:
        raise PassGateError("gate evidence sha256 does not match artifact")
    _required_text("evidence content_type", evidence.content_type)
    _required_text("evidence redaction_status", evidence.redaction_status)
    _required_text("evidence captured_at", evidence.captured_at)
    return _EvidenceSnapshot(
        relative_path=relative,
        sha256=expected_sha256,
        size_bytes=evidence.size_bytes,
        identity=_stat_identity(file_stat),
    )


def _assert_evidence_snapshot_current(snapshot: _EvidenceSnapshot) -> None:
    repo_root = repository_root().resolve()
    relative_path = Path(snapshot.relative_path)
    path = repository_root().resolve() / snapshot.relative_path
    try:
        _reject_symlink_evidence_path(repo_root, relative_path)
        actual_sha256, file_stat = _hash_evidence_file(path, checked_stat=None)
        if _stat_identity(file_stat) != snapshot.identity:
            raise PassGateError("gate evidence artifact changed before commit")
        if file_stat.st_size != snapshot.size_bytes:
            raise PassGateError("gate evidence artifact changed before commit")
    except (OSError, PredicateContractError) as exc:
        raise PassGateError("gate evidence artifact changed before commit") from exc
    if actual_sha256 != snapshot.sha256:
        raise PassGateError("gate evidence artifact changed before commit")


def _hash_evidence_file(
    path: Path, *, checked_stat: os.stat_result | None = None
) -> tuple[str, os.stat_result]:
    digest = hashlib.sha256()
    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise PassGateError("gate evidence artifact must be a regular file")
        if int(getattr(opened_stat, "st_nlink", 1) or 1) > 1:
            raise PassGateError("gate evidence cannot use hard-linked file aliases")
        if checked_stat is not None and _stat_identity(opened_stat) != _stat_identity(
            checked_stat
        ):
            raise PassGateError("gate evidence artifact changed during read")
        size = int(getattr(opened_stat, "st_size", 0) or 0)
        if size > MAX_FILE_EVIDENCE_BYTES:
            raise PassGateError("gate evidence exceeds safe size limit")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            total_read = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total_read += len(chunk)
                if total_read > MAX_FILE_EVIDENCE_BYTES:
                    raise PassGateError("gate evidence exceeds safe size limit")
                digest.update(chunk)
        return digest.hexdigest(), opened_stat
    except PassGateError:
        raise
    except OSError as exc:
        raise PassGateError("gate evidence artifact is not readable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _stat_identity(path_stat: os.stat_result) -> tuple[int, int, int]:
    return (
        int(getattr(path_stat, "st_dev", -1)),
        int(getattr(path_stat, "st_ino", -1)),
        int(getattr(path_stat, "st_mode", -1)),
    )


def _sqlite_sidecar_paths(database: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{database}{suffix}") for suffix in _SQLITE_SIDECAR_SUFFIXES)


def _refuse_lax_sqlite_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecar_paths(database):
        sidecar_stat = _stat_existing_path_nofollow(sidecar)
        if sidecar_stat is None:
            continue
        if not stat.S_ISREG(sidecar_stat.st_mode):
            raise PassGateError("SQLite sidecar must be a regular private file")
        if int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1:
            raise PassGateError("SQLite sidecar cannot use hard-linked file aliases")
        if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
            raise PassGateError("SQLite sidecar requires 0600 file mode")


def _chmod_private_sqlite_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecar_paths(database):
        sidecar_stat = _stat_existing_path_nofollow(sidecar)
        if sidecar_stat is None:
            continue
        if not stat.S_ISREG(sidecar_stat.st_mode):
            raise PassGateError("SQLite sidecar must be a regular private file")
        if int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1:
            raise PassGateError("SQLite sidecar cannot use hard-linked file aliases")
        if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
            sidecar.chmod(0o600)
            sidecar_stat = os.stat(sidecar, follow_symlinks=False)
            if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
                raise PassGateError("SQLite sidecar requires 0600 file mode")


def _stat_existing_path_nofollow(path: Path) -> os.stat_result | None:
    try:
        return os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
