"""Synthetic local-only database-authority canary artifact workflow."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import agentic_os
from .migrations import (
    _allow_next_db_authority_canary_rollback,
    _register_migration_functions,
    apply_migrations,
    verify_database_connection,
)
from .privacy import PrivacyPreflightError, assert_privacy_preflight
from .shadow import (
    ShadowBackfillError,
    ShadowProjection,
    _atomic_create_file,
    _checkpoint_offline_snapshot,
    _connect,
    _normalize_artifact_target,
    _normalize_artifacts,
    _normalize_required_identity,
    _projection_id,
    _repo_relative,
    _sha256,
    _utc_iso_epoch_ms,
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
CONTROLLED_DB_AUTHORITY_CANARY_WORKFLOWS = frozenset(("local-artifact-canary",))


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

    return _db_authority_canary_artifact_impl(
        database,
        artifact,
        content,
        workflow=workflow,
        run_id=run_id,
        cutover_approved_by=cutover_approved_by,
        cutover_evidence_hash=cutover_evidence_hash,
        rollback_deadline=rollback_deadline,
        last_parity_audit_hash=last_parity_audit_hash,
        prepare_idempotency_key=prepare_idempotency_key,
        repo_root_path=repo_root_path,
        crash_after_prepare=crash_after_prepare,
    )


def _controlled_db_authority_canary_artifact(
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
    return _db_authority_canary_artifact_impl(
        database,
        artifact,
        content,
        workflow=workflow,
        run_id=run_id,
        cutover_approved_by=cutover_approved_by,
        cutover_evidence_hash=cutover_evidence_hash,
        rollback_deadline=rollback_deadline,
        last_parity_audit_hash=last_parity_audit_hash,
        prepare_idempotency_key=prepare_idempotency_key,
        repo_root_path=repo_root_path,
        crash_after_prepare=crash_after_prepare,
        _allow_controlled_workflow=True,
        _require_single_workflow_projection_set=True,
        _require_workflow_no_real_session_control=True,
    )


def _db_authority_canary_artifact_impl(
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
    _allow_controlled_workflow: bool = False,
    _require_single_workflow_projection_set: bool = False,
    _require_workflow_no_real_session_control: bool = False,
) -> DbAuthorityCanaryResult:
    if agentic_os.DB_AUTHORITY_ENABLED:
        raise DbAuthorityCanaryError("production DB authority must remain disabled")
    workflow = _normalize_required_identity("workflow", workflow)
    if (
        workflow in CONTROLLED_DB_AUTHORITY_CANARY_WORKFLOWS
        and not _allow_controlled_workflow
    ):
        raise DbAuthorityCanaryError(
            f"workflow {workflow!r} must use the DB-authority expansion controller"
        )
    run_id = _normalize_required_identity("run_id", run_id)
    cutover_approved_by = _normalize_required_identity(
        "cutover_approved_by", cutover_approved_by
    )
    cutover_evidence_hash = _sha256_text(
        "cutover_evidence_hash", cutover_evidence_hash
    )
    rollback_deadline, rollback_deadline_epoch_ms = _normalize_deadline(
        rollback_deadline
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
    database_input = Path(database).expanduser()
    if database_input.is_symlink():
        raise DbAuthorityCanaryError("canary database cannot be a symlink")
    database_path = database_input.resolve()
    pre_migration_identity = _validate_canary_database_path(
        database_path, root=root, must_exist=False
    )
    apply_migrations(database_path, repo_root=root)
    post_migration_identity = _validate_canary_database_path(
        database_path, root=root, must_exist=True
    )
    if (
        pre_migration_identity is not None
        and post_migration_identity != pre_migration_identity
    ):
        raise DbAuthorityCanaryError(
            "canary database identity changed while applying migrations"
        )
    created_at, created_epoch_ms = _utc_now()
    connection = _connect_existing_canary_database(
        database_path,
        root=root,
        expected_identity=post_migration_identity,
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            verify_database_connection(connection)
            if _require_workflow_no_real_session_control:
                _assert_no_real_session_control_for_workflow(
                    connection, workflow=workflow
                )
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
            if _require_single_workflow_projection_set:
                _assert_single_workflow_projection_set(
                    connection,
                    workflow=workflow,
                    run_id=run_id,
                    projection=projection,
                )
            if run_state is None and rollback_deadline_epoch_ms <= created_epoch_ms:
                raise DbAuthorityCanaryError(
                    "rollback_deadline must be later than the canary preparation clock"
                )
            if run_state == "finalized":
                _assert_artifact_matches(target, digest, relative)
                _assert_projection_matches(
                    connection, run_id=run_id, projection=projection
                )
                connection.execute("COMMIT")
                _checkpoint_offline_snapshot(connection)
                return DbAuthorityCanaryResult(
                    workflow=workflow,
                    run_id=run_id,
                    projection=projection,
                    status="replayed",
                    rollback_deadline=rollback_deadline,
                )
            if run_state is None:
                existing_path = connection.execute(
                    "SELECT p.run_id FROM artifact_projections p "
                    "WHERE p.path=? AND p.source_authority='db_authority_canary' "
                    "AND p.run_id<>? LIMIT 1",
                    (relative, run_id),
                ).fetchone()
                if existing_path is not None:
                    raise DbAuthorityCanaryError(
                        f"canary artifact path already belongs to run {existing_path[0]!r}"
                    )
                if target.exists():
                    raise DbAuthorityCanaryError(
                        "canary artifact must not already exist for a first write"
                    )
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
        finalized_at = datetime.fromtimestamp(
            finalized_epoch_ms / 1000, tz=timezone.utc
        ).isoformat()
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
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    except ShadowBackfillError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    finally:
        try:
            _harden_canary_sidecars(database_path)
        finally:
            connection.close()
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

    return _rollback_db_authority_canary_impl(
        database,
        artifacts,
        workflow=workflow,
        repo_root_path=repo_root_path,
    )


def _controlled_rollback_db_authority_canary(
    database: Path,
    artifacts: tuple[str | Path, ...],
    *,
    workflow: str,
    repo_root_path: Path | None = None,
) -> DbAuthorityRollbackResult:
    return _rollback_db_authority_canary_impl(
        database,
        artifacts,
        workflow=workflow,
        repo_root_path=repo_root_path,
        _allow_controlled_workflow=True,
    )


def _rollback_db_authority_canary_impl(
    database: Path,
    artifacts: tuple[str | Path, ...],
    *,
    workflow: str,
    repo_root_path: Path | None = None,
    _allow_controlled_workflow: bool = False,
) -> DbAuthorityRollbackResult:
    workflow = _normalize_required_identity("workflow", workflow)
    if (
        workflow in CONTROLLED_DB_AUTHORITY_CANARY_WORKFLOWS
        and not _allow_controlled_workflow
    ):
        raise DbAuthorityCanaryError(
            f"workflow {workflow!r} must use the DB-authority expansion controller"
        )
    if not artifacts:
        raise DbAuthorityCanaryError("at least one artifact is required")
    root = Path(repo_root_path or Path(__file__).resolve().parents[2]).resolve()
    database_input = Path(database).expanduser()
    if database_input.is_symlink():
        raise DbAuthorityCanaryError("canary database cannot be a symlink")
    database_path = database_input.resolve()
    connection = _connect_existing_canary_database(database_path, root=root)
    regenerated: list[ShadowProjection] = []
    rolled_back_at, _epoch_ms = _utc_now()
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            verify_database_connection(connection)
            row = connection.execute(
                "SELECT mode,cutover_approved_by,cutover_evidence_hash,"
                "rollback_deadline,last_parity_audit_hash,open_file_authority_runs "
                "FROM workflow_authority WHERE workflow=?",
                (workflow,),
            ).fetchone()
            if row is None or row[0] != "db_authority_canary":
                raise DbAuthorityCanaryError(
                    "rollback requires an active db_authority_canary workflow"
                )
            if (
                not row[1]
                or row[5] != 0
                or _sha256_text("cutover_evidence_hash", row[2]) != row[2]
                or _normalize_deadline(row[3])[0] != row[3]
                or _sha256_text("last_parity_audit_hash", row[4]) != row[4]
            ):
                raise DbAuthorityCanaryError(
                    "rollback requires intact db_authority_canary cutover evidence"
                )
            projection_bindings = connection.execute(
                "SELECT p.projection_id,p.run_id,p.path,p.sha256,"
                "r.workflow,r.authority_mode,r.state,w.mode "
                "FROM artifact_projections p "
                "JOIN runs r ON r.run_id=p.run_id "
                "LEFT JOIN workflow_authority w ON w.workflow=r.workflow "
                "WHERE p.source_authority='db_authority_canary' "
                "AND r.workflow=?",
                (workflow,),
            ).fetchall()
            for (
                _projection_id_value,
                projection_run_id,
                _path,
                _digest,
                run_workflow,
                run_authority_mode,
                _run_state,
                workflow_mode,
            ) in projection_bindings:
                if (
                    run_workflow is None
                    or run_authority_mode != "db_authority_canary"
                    or _run_state != "finalized"
                    or workflow_mode
                    not in {"db_authority_canary", "rollback_to_file_authority"}
                ):
                    raise DbAuthorityCanaryError(
                        "db_authority_canary projection has workflow/run/authority binding drift: "
                        f"{projection_run_id}"
                    )

            canary_runs = connection.execute(
                "SELECT run_id,state,finalized_at,finalized_at_epoch_ms FROM runs "
                "WHERE workflow=? AND authority_mode='db_authority_canary'",
                (workflow,),
            ).fetchall()
            if not canary_runs:
                raise DbAuthorityCanaryError("rollback requires finalized canary runs")
            for run_id, state, finalized_at, finalized_epoch_ms in canary_runs:
                if (
                    state != "finalized"
                    or type(finalized_epoch_ms) is not int
                    or _utc_iso_epoch_ms(finalized_at) != finalized_epoch_ms
                ):
                    raise DbAuthorityCanaryError("cannot rollback an open or invalid canary run")
                _assert_no_real_session_control(connection, run_id=run_id)

            expected_rows = [
                (projection_id, projection_run_id, path, digest)
                for (
                    projection_id,
                    projection_run_id,
                    path,
                    digest,
                    run_workflow,
                    run_authority_mode,
                    run_state,
                    _workflow_mode,
                ) in projection_bindings
                if run_workflow == workflow
                and run_authority_mode == "db_authority_canary"
                and run_state == "finalized"
            ]
            canary_run_ids = {run_id for run_id, *_rest in canary_runs}
            projection_counts = {run_id: 0 for run_id in canary_run_ids}
            all_projection_counts = {
                row[0]: row[1]
                for row in connection.execute(
                    "SELECT run_id,COUNT(*) FROM artifact_projections "
                    "WHERE run_id IN ("
                    + ",".join("?" for _run_id in canary_run_ids)
                    + ") GROUP BY run_id",
                    tuple(canary_run_ids),
                ).fetchall()
            }
            if any(
                all_projection_counts.get(run_id, 0) != 1
                for run_id in canary_run_ids
            ):
                raise DbAuthorityCanaryError(
                    "rollback requires exactly one projection per finalized canary run"
                )
            expected_by_path: dict[str, tuple[str, str, str]] = {}
            for projection_id, run_id, path, digest in expected_rows:
                if run_id not in projection_counts:
                    raise DbAuthorityCanaryError(
                        f"projection references an unexpected canary run: {run_id}"
                    )
                projection_counts[run_id] += 1
                if path in expected_by_path:
                    raise DbAuthorityCanaryError(
                        f"ambiguous canary projection path for workflow {workflow!r}: {path}"
                    )
                expected_by_path[path] = (projection_id, run_id, digest)
            if any(count != 1 for count in projection_counts.values()):
                raise DbAuthorityCanaryError(
                    "rollback requires exactly one projection per finalized canary run"
                )

            supplied = _normalize_artifacts(artifacts, repo_root_path=root)
            supplied_by_path = {
                relative: (absolute, digest)
                for absolute, relative, digest in supplied
            }
            if set(supplied_by_path) != set(expected_by_path):
                raise DbAuthorityCanaryError(
                    "rollback artifacts must exactly match the workflow canary projection set"
                )
            for relative in sorted(expected_by_path):
                projection_id, run_id, expected_digest = expected_by_path[relative]
                absolute, _cached_digest = supplied_by_path[relative]
                actual_digest = _sha256(absolute)
                regenerated_projection = ShadowProjection(
                    path=relative,
                    sha256=actual_digest,
                    projection_id=_projection_id(run_id, relative, actual_digest),
                )
                if (
                    actual_digest != expected_digest
                    or regenerated_projection.projection_id != projection_id
                ):
                    raise DbAuthorityCanaryError(
                        f"canary projection cannot be regenerated for {relative}"
                    )
                regenerated.append(regenerated_projection)
            proof_hash = _canary_rollback_proof_hash(workflow, tuple(regenerated))
            _allow_next_db_authority_canary_rollback(
                connection, workflow, proof_hash
            )
            connection.execute(
                "INSERT INTO db_authority_canary_rollback_proofs("
                "workflow,proof_hash,created_at) VALUES(?,?,?)",
                (workflow, proof_hash, rolled_back_at),
            )
            updated = connection.execute(
                "UPDATE workflow_authority SET mode='rollback_to_file_authority',"
                "updated_at=? WHERE workflow=? AND mode='db_authority_canary'",
                (rolled_back_at, workflow),
            ).rowcount
            if updated != 1:
                raise DbAuthorityCanaryError("canary workflow could not be rolled back")
            connection.execute("COMMIT")
            _checkpoint_offline_snapshot(connection)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    except ShadowBackfillError as exc:
        raise DbAuthorityCanaryError(str(exc)) from exc
    finally:
        try:
            _harden_canary_sidecars(database_path)
        finally:
            connection.close()
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


def _canary_rollback_proof_hash(
    workflow: str, projections: tuple[ShadowProjection, ...]
) -> str:
    payload = json.dumps(
        {
            "projections": [
                {
                    "path": projection.path,
                    "projection_id": projection.projection_id,
                    "sha256": projection.sha256,
                }
                for projection in projections
            ],
            "source": "db-authority-canary-rollback-proof-v1",
            "workflow": workflow,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_deadline(value: str) -> tuple[str, int]:
    value = _normalize_required_identity("rollback_deadline", value)
    deadline_epoch_ms = _utc_iso_epoch_ms(value)
    if deadline_epoch_ms is None:
        raise DbAuthorityCanaryError(
            "rollback_deadline must be a timezone-aware ISO-8601 timestamp"
        )
    normalized = datetime.fromtimestamp(
        deadline_epoch_ms / 1000, tz=timezone.utc
    ).isoformat()
    return normalized, deadline_epoch_ms


def _connect_existing_canary_database(
    database: Path,
    *,
    root: Path,
    expected_identity: tuple[int, int] | None = None,
) -> sqlite3.Connection:
    database_identity = _validate_canary_database_path(
        database, root=root, must_exist=True
    )
    if expected_identity is not None and database_identity != expected_identity:
        raise DbAuthorityCanaryError("canary database identity changed before open")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=rw", uri=True, isolation_level=None
        )
        _register_migration_functions(connection)
        opened_identity = _validate_canary_database_path(
            database, root=root, must_exist=True, check_sidecars=False
        )
        if opened_identity != database_identity:
            raise DbAuthorityCanaryError("canary database identity changed while opening")
        connection.execute("PRAGMA busy_timeout=10000")
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if str(journal_mode[0] if journal_mode else "").casefold() != "wal":
            raise DbAuthorityCanaryError("SQLite WAL journal mode is unavailable")
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise DbAuthorityCanaryError("SQLite foreign key enforcement is unavailable")
        verify_database_connection(connection)
        return connection
    except Exception:
        if connection is not None:
            connection.close()
        raise


def _validate_canary_database_path(
    database: Path,
    *,
    root: Path,
    must_exist: bool,
    check_sidecars: bool = True,
) -> tuple[int, int] | None:
    try:
        assert_privacy_preflight(root, database_paths=(database,))
    except PrivacyPreflightError as exc:
        raise DbAuthorityCanaryError("canary database privacy preflight failed") from exc
    try:
        database_stat = os.lstat(database)
    except FileNotFoundError:
        if must_exist:
            raise DbAuthorityCanaryError("canary database must already exist") from None
        return None
    parent_mode = stat.S_IMODE(database.parent.stat().st_mode)
    file_mode = stat.S_IMODE(database_stat.st_mode)
    if not stat.S_ISREG(database_stat.st_mode):
        raise DbAuthorityCanaryError("canary database must be a regular private file")
    if parent_mode != 0o700 or file_mode != 0o600:
        raise DbAuthorityCanaryError(
            "canary database requires 0700 directory and 0600 file"
        )
    if int(getattr(database_stat, "st_nlink", 1) or 1) > 1:
        raise DbAuthorityCanaryError("canary database cannot use hard-linked aliases")
    if not check_sidecars:
        return database_stat.st_dev, database_stat.st_ino
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database}{suffix}")
        try:
            sidecar_stat = os.lstat(sidecar)
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(sidecar_stat.st_mode)
            or stat.S_IMODE(sidecar_stat.st_mode) != 0o600
            or int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1
        ):
            raise DbAuthorityCanaryError(
                f"canary database sidecar must be a private regular file: {sidecar}"
            )
    return database_stat.st_dev, database_stat.st_ino


def _harden_canary_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database}{suffix}")
        try:
            sidecar_stat = os.lstat(sidecar)
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(sidecar_stat.st_mode)
            or int(getattr(sidecar_stat, "st_nlink", 1) or 1) > 1
        ):
            raise DbAuthorityCanaryError(
                f"canary database sidecar must be a private regular file: {sidecar}"
            )
        if stat.S_IMODE(sidecar_stat.st_mode) != 0o600:
            os.chmod(sidecar, 0o600, follow_symlinks=False)
            hardened = os.stat(sidecar, follow_symlinks=False)
            if stat.S_IMODE(hardened.st_mode) != 0o600:
                raise DbAuthorityCanaryError(
                    f"canary database sidecar must have mode 0600: {sidecar}"
                )


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


def _assert_no_real_session_control_for_workflow(
    connection: sqlite3.Connection, *, workflow: str
) -> None:
    for table in _REAL_SESSION_TABLES:
        count = connection.execute(
            f"SELECT COUNT(*) FROM {table} rpc "
            "JOIN runs r ON r.run_id=rpc.run_id WHERE r.workflow=?",
            (workflow,),
        ).fetchone()[0]
        if count:
            raise DbAuthorityCanaryError(
                "synthetic expansion eligibility proof must cover the whole "
                f"workflow; real session-control rows exist in {table}"
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
    if (
        row[3] == "finalized"
        and type(row[7]) is int
        and _utc_iso_epoch_ms(row[6]) == row[7]
    ):
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


def _assert_single_workflow_projection_set(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    projection: ShadowProjection,
) -> None:
    canary_runs = connection.execute(
        "SELECT run_id,state FROM runs "
        "WHERE workflow=? AND authority_mode='db_authority_canary'",
        (workflow,),
    ).fetchall()
    if not canary_runs:
        return
    if len(canary_runs) != 1:
        raise DbAuthorityCanaryError(
            "synthetic expansion eligibility proof must bind the full workflow "
            "canary projection set"
        )
    existing_run_id, existing_state = canary_runs[0]
    projection_rows = connection.execute(
        "SELECT projection_id,path,sha256,source_authority "
        "FROM artifact_projections WHERE run_id=?",
        (existing_run_id,),
    ).fetchall()
    expected_projection = (
        projection.projection_id,
        projection.path,
        projection.sha256,
        "db_authority_canary",
    )
    if (
        existing_run_id == run_id
        and existing_state in {"prepared", "finalized"}
        and projection_rows == [expected_projection]
    ):
        return
    raise DbAuthorityCanaryError(
        "synthetic expansion eligibility proof must bind the full workflow "
        "canary projection set"
    )


def _assert_artifact_matches(target: Path, digest: str, relative: str) -> None:
    if not target.exists() or not target.is_file():
        raise DbAuthorityCanaryError(f"canary artifact is missing: {relative}")
    if _sha256(target) != digest:
        raise DbAuthorityCanaryError(
            f"canary artifact drift for {relative}; refusing to finalize"
        )
