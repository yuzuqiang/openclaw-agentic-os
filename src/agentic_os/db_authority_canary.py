"""Synthetic local-only database-authority canary artifact workflow."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import DB_AUTHORITY_ENABLED
from .migrations import apply_migrations, verify_database_connection
from .shadow import (
    ShadowBackfillError,
    ShadowProjection,
    _atomic_create_file,
    _checkpoint_offline_snapshot,
    _connect,
    _normalize_artifact_target,
    _normalize_required_identity,
    _projection_id,
    _remove_checkpointed_sidecars,
    _repo_relative,
    _sha256,
    _utc_now,
)


class DbAuthorityCanaryError(RuntimeError):
    """The local synthetic canary could not be proven artifact-only."""


@dataclass(frozen=True)
class DbAuthorityCanaryResult:
    workflow: str
    run_id: str
    projection: ShadowProjection
    status: str
    rollback_deadline: str


@dataclass(frozen=True)
class DbAuthorityRollbackResult:
    workflow: str
    status: str
    regenerated: tuple[ShadowProjection, ...]


_REAL_SESSION_TABLES = (
    "external_rpc_intents",
    "leases",
    "spawn_requests",
    "sessions",
)


def db_authority_canary_artifact(
    database: Path,
    artifact: str | Path,
    content: bytes,
    *,
    workflow: str,
    run_id: str,
    cutover_approved_by: str,
    cutover_evidence_hash: str,
    rollback_deadline: str,
    last_parity_audit_hash: str,
    prepare_idempotency_key: str | None = None,
    repo_root_path: Path | None = None,
    crash_after_prepare: bool = False,
) -> DbAuthorityCanaryResult:
    """Record one synthetic/local artifact-only ``db_authority_canary`` run.

    This writer deliberately does not call OpenClaw, Gateway, Cron, or real
    session-control tools. It only writes a private SQLite proof and a local
    artifact under the repository root. ``DB_AUTHORITY_ENABLED`` remains false;
    this is canary fixture evidence, not production DB authority.
    """

    if DB_AUTHORITY_ENABLED:
        raise DbAuthorityCanaryError("production DB authority must remain disabled")
    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    cutover_approved_by = _normalize_required_identity(
        "cutover_approved_by", cutover_approved_by
    )
    cutover_evidence_hash = _sha256_text(
        "cutover_evidence_hash", cutover_evidence_hash
    )
    rollback_deadline = _normalize_required_identity(
        "rollback_deadline", rollback_deadline
    )
    last_parity_audit_hash = _sha256_text(
        "last_parity_audit_hash", last_parity_audit_hash
    )
    if not content:
        raise DbAuthorityCanaryError("content must be non-empty")
    prepare_key = (
        _normalize_required_identity("prepare_idempotency_key", prepare_idempotency_key)
        if prepare_idempotency_key is not None
        else f"db-authority-canary:{run_id}"
    )
    root = Path(repo_root_path or Path(__file__).resolve().parents[2]).resolve()
    target, relative = _normalize_artifact_target(artifact, repo_root_path=root)
    digest = hashlib.sha256(content).hexdigest()
    projection = ShadowProjection(
        path=relative,
        sha256=digest,
        projection_id=_projection_id(run_id, relative, digest),
    )
    database_path = Path(database).expanduser().resolve()
    apply_migrations(database_path, repo_root=root)
    created_at, created_epoch_ms = _utc_now()
    connection = _connect(database_path)
    checkpointed = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            verify_database_connection(connection)
            _assert_no_real_session_control(connection, run_id=run_id)
            _ensure_canary_workflow(
                connection,
                workflow=workflow,
                cutover_approved_by=cutover_approved_by,
                cutover_evidence_hash=cutover_evidence_hash,
                rollback_deadline=rollback_deadline,
                last_parity_audit_hash=last_parity_audit_hash,
                updated_at=created_at,
            )
            run_state = _canary_run_state(
                connection,
                workflow=workflow,
                run_id=run_id,
                prepare_idempotency_key=prepare_key,
            )
            if run_state == "finalized":
                _assert_artifact_matches(target, digest, relative)
                _assert_projection_matches(
                    connection, run_id=run_id, projection=projection
                )
                connection.execute("COMMIT")
                _checkpoint_offline_snapshot(connection)
                checkpointed = True
                return DbAuthorityCanaryResult(
                    workflow=workflow,
                    run_id=run_id,
                    projection=projection,
                    status="replayed",
                    rollback_deadline=rollback_deadline,
                )
            if run_state is None:
                _insert_prepared_canary_run(
                    connection,
                    workflow=workflow,
                    run_id=run_id,
                    prepare_idempotency_key=prepare_key,
                    created_at=created_at,
                )
                connection.execute(
                    "INSERT INTO artifact_projections("
                    "projection_id,run_id,path,sha256,source_authority,generated_at"
                    ") VALUES(?,?,?,?,?,?)",
                    (
                        projection.projection_id,
                        run_id,
                        relative,
                        digest,
                        "db_authority_canary",
                        created_at,
                    ),
                )
            else:
                _assert_projection_matches(
                    connection, run_id=run_id, projection=projection
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        if crash_after_prepare:
            raise DbAuthorityCanaryError("simulated crash after canary DB prepare")
        if target.exists():
            _assert_artifact_matches(target, digest, relative)
        else:
            _atomic_create_file(target, content)
        finalized_at, finalized_epoch_ms = _utc_now()
        connection.execute("BEGIN IMMEDIATE")
        try:
            _assert_no_real_session_control(connection, run_id=run_id)
            _assert_artifact_matches(target, digest, relative)
            updated = connection.execute(
                "UPDATE runs SET state='finalized',updated_at=?,finalized_at=?,"
                "finalized_at_epoch_ms=? WHERE run_id=? AND state='prepared'",
                (finalized_at, finalized_at, finalized_epoch_ms, run_id),
            ).rowcount
            if updated != 1:
                raise DbAuthorityCanaryError("canary run could not be finalized")
            connection.execute("COMMIT")
            _checkpoint_offline_snapshot(connection)
            checkpointed = True
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    except ShadowBackfillError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    finally:
        connection.close()
        if checkpointed:
            _remove_checkpointed_sidecars(database_path)
    return DbAuthorityCanaryResult(
        workflow=workflow,
        run_id=run_id,
        projection=projection,
        status="recovered" if run_state == "prepared" else "written",
        rollback_deadline=rollback_deadline,
    )


def rollback_db_authority_canary(
    database: Path,
    artifacts: tuple[str | Path, ...],
    *,
    workflow: str,
    repo_root_path: Path | None = None,
) -> DbAuthorityRollbackResult:
    """Rollback the synthetic canary workflow and prove projection regeneration."""

    workflow = _normalize_required_identity("workflow", workflow)
    if not artifacts:
        raise DbAuthorityCanaryError("at least one artifact is required")
    root = Path(repo_root_path or Path(__file__).resolve().parents[2]).resolve()
    database_path = Path(database).expanduser().resolve()
    connection = _connect(database_path)
    regenerated: list[ShadowProjection] = []
    checkpointed = False
    rolled_back_at, _epoch_ms = _utc_now()
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            verify_database_connection(connection)
            row = connection.execute(
                "SELECT mode FROM workflow_authority WHERE workflow=?", (workflow,)
            ).fetchone()
            if row is None or row[0] != "db_authority_canary":
                raise DbAuthorityCanaryError(
                    "rollback requires an active db_authority_canary workflow"
                )
            open_canary = connection.execute(
                "SELECT run_id FROM runs WHERE workflow=? "
                "AND authority_mode='db_authority_canary' "
                "AND state NOT IN ('finalized','rolled_back','rejected') LIMIT 1",
                (workflow,),
            ).fetchone()
            if open_canary is not None:
                raise DbAuthorityCanaryError("cannot rollback an open canary run")
            for artifact in artifacts:
                path = Path(artifact)
                relative = _repo_relative(root, path, resolve=False)
                absolute = (path if path.is_absolute() else root / path).resolve()
                if not absolute.is_file():
                    raise DbAuthorityCanaryError(
                        f"rollback artifact is missing: {relative}"
                    )
                digest = _sha256(absolute)
                row = connection.execute(
                    "SELECT projection_id,run_id,sha256 FROM artifact_projections "
                    "WHERE path=? AND source_authority='db_authority_canary'",
                    (relative,),
                ).fetchone()
                if row is None or row[2] != digest:
                    raise DbAuthorityCanaryError(
                        f"canary projection cannot be regenerated for {relative}"
                    )
                regenerated.append(
                    ShadowProjection(
                        path=relative,
                        sha256=digest,
                        projection_id=_projection_id(row[1], relative, digest),
                    )
                )
                if regenerated[-1].projection_id != row[0]:
                    raise DbAuthorityCanaryError(
                        f"canary projection id drift for {relative}"
                    )
            connection.execute(
                "UPDATE workflow_authority SET mode='rollback_to_file_authority',"
                "updated_at=? WHERE workflow=? AND mode='db_authority_canary'",
                (rolled_back_at, workflow),
            )
            connection.execute("COMMIT")
            _checkpoint_offline_snapshot(connection)
            checkpointed = True
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    except ShadowBackfillError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    finally:
        connection.close()
        if checkpointed:
            _remove_checkpointed_sidecars(database_path)
    return DbAuthorityRollbackResult(
        workflow=workflow,
        status="rolled_back",
        regenerated=tuple(regenerated),
    )


def _sha256_text(name: str, value: str) -> str:
    normalized = _normalize_required_identity(name, value)
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise DbAuthorityCanaryError(f"{name} must be a lowercase SHA-256 digest")
    return normalized


def _assert_no_real_session_control(
    connection: sqlite3.Connection, *, run_id: str
) -> None:
    for table in _REAL_SESSION_TABLES:
        count = connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (run_id,)
        ).fetchone()[0]
        if count:
            raise DbAuthorityCanaryError(
                "db_authority_canary is synthetic/local artifact-only; "
                f"real session-control rows exist in {table}"
            )


def _ensure_canary_workflow(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    cutover_approved_by: str,
    cutover_evidence_hash: str,
    rollback_deadline: str,
    last_parity_audit_hash: str,
    updated_at: str,
) -> None:
    row = connection.execute(
        "SELECT mode,cutover_approved_by,cutover_evidence_hash,rollback_deadline,"
        "last_parity_audit_hash,open_file_authority_runs FROM workflow_authority "
        "WHERE workflow=?",
        (workflow,),
    ).fetchone()
    expected = (
        "db_authority_canary",
        cutover_approved_by,
        cutover_evidence_hash,
        rollback_deadline,
        last_parity_audit_hash,
        0,
    )
    if row == expected:
        return
    if row is not None:
        raise DbAuthorityCanaryError(
            f"workflow {workflow!r} is not the matching synthetic canary"
        )
    connection.execute(
        "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
        "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
        "open_file_authority_runs,updated_at) VALUES(?,?,?,?,?,?,0,?)",
        (
            workflow,
            "db_authority_canary",
            cutover_approved_by,
            cutover_evidence_hash,
            rollback_deadline,
            last_parity_audit_hash,
            updated_at,
        ),
    )


def _canary_run_state(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str,
) -> str | None:
    row = connection.execute(
        "SELECT workflow,authority_mode,prepare_idempotency_key,state,"
        "risk_class,risk_dominance,finalized_at,finalized_at_epoch_ms "
        "FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    if row[:6] != (
        workflow,
        "db_authority_canary",
        prepare_idempotency_key,
        row[3],
        "R1",
        "R1",
    ):
        raise DbAuthorityCanaryError(f"run {run_id!r} is not a matching canary run")
    if row[3] == "prepared" and row[6] is None and row[7] is None:
        return "prepared"
    if row[3] == "finalized" and isinstance(row[6], str) and type(row[7]) is int:
        return "finalized"
    raise DbAuthorityCanaryError(f"run {run_id!r} has invalid canary state")


def _insert_prepared_canary_run(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str,
    created_at: str,
) -> None:
    connection.execute(
        "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
        "state,risk_class,risk_dominance,created_at,updated_at) "
        "VALUES(?,?,?,'db_authority_canary','prepared','R1','R1',?,?)",
        (run_id, prepare_idempotency_key, workflow, created_at, created_at),
    )


def _assert_projection_matches(
    connection: sqlite3.Connection, *, run_id: str, projection: ShadowProjection
) -> None:
    row = connection.execute(
        "SELECT projection_id,sha256,source_authority FROM artifact_projections "
        "WHERE run_id=? AND path=?",
        (run_id, projection.path),
    ).fetchone()
    if row != (projection.projection_id, projection.sha256, "db_authority_canary"):
        raise DbAuthorityCanaryError(
            f"canary projection drift for {projection.path}"
        )


def _assert_artifact_matches(target: Path, digest: str, relative: str) -> None:
    if not target.exists() or not target.is_file():
        raise DbAuthorityCanaryError(f"canary artifact is missing: {relative}")
    if _sha256(target) != digest:
        raise DbAuthorityCanaryError(
            f"canary artifact drift for {relative}; refusing to finalize"
        )
