"""Offline file-authority shadow projection and parity checks."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .migrations import (
    MigrationError,
    apply_migrations,
    repository_root,
    verify_database,
)
from .privacy import assert_paths_retrievable


class ShadowBackfillError(RuntimeError):
    """File-authority shadow backfill or parity audit failed closed."""


@dataclass(frozen=True)
class ShadowProjection:
    path: str
    sha256: str
    projection_id: str


@dataclass(frozen=True)
class ShadowBackfillResult:
    workflow: str
    run_id: str
    projections: tuple[ShadowProjection, ...]


@dataclass(frozen=True)
class ShadowAuditIssue:
    path: str
    reason: str
    expected_sha256: str | None = None
    actual_sha256: str | None = None


@dataclass(frozen=True)
class ShadowAuditResult:
    workflow: str
    run_id: str
    status: str
    checked_count: int
    issues: tuple[ShadowAuditIssue, ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_relative(root: Path, path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        raise ShadowBackfillError(
            f"shadow artifact is outside repository root: {resolved}"
        ) from None


def _projection_id(run_id: str, relative_path: str, digest: str) -> str:
    payload = f"{run_id}\0{relative_path}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_required_identity(name: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ShadowBackfillError(f"{name} must be a non-empty identity")
    return normalized


def _run_is_finalized_shadow(
    row: tuple[object, ...] | None,
    *,
    workflow: str,
    prepare_idempotency_key: str | None = None,
) -> bool:
    if row is None:
        return False
    if prepare_idempotency_key is None:
        expected = (workflow, "file_authority_shadow", "finalized", "R1", "R1")
        identity = row[:5]
        finalized_at = row[5]
        finalized_epoch_ms = row[6]
    else:
        expected = (
            workflow,
            "file_authority_shadow",
            prepare_idempotency_key,
            "finalized",
            "R1",
            "R1",
        )
        identity = row[:6]
        finalized_at = row[6]
        finalized_epoch_ms = row[7]
    return (
        identity == expected
        and isinstance(finalized_at, str)
        and finalized_at.strip() != ""
        and type(finalized_epoch_ms) is int
        and finalized_epoch_ms > 0
    )


def _normalize_artifacts(
    artifacts: Iterable[str | Path], *, repo_root_path: Path
) -> tuple[tuple[Path, str, str], ...]:
    paths = tuple(Path(artifact).expanduser() for artifact in artifacts)
    if not paths:
        raise ShadowBackfillError("at least one artifact path is required")
    normalized: list[tuple[Path, str, str]] = []
    seen: set[str] = set()
    for path in paths:
        resolved = path.resolve()
        relative = _repo_relative(repo_root_path, resolved)
        assert_paths_retrievable((path, resolved, relative))
        if not resolved.is_file():
            raise ShadowBackfillError(f"shadow artifact is not a file: {resolved}")
        if relative in seen:
            continue
        seen.add(relative)
        normalized.append((resolved, relative, _sha256(resolved)))
    return tuple(normalized)


def _connect(database: Path, *, existing: bool = False) -> sqlite3.Connection:
    if existing:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro&immutable=1", uri=True, isolation_level=None
        )
        connection.execute("PRAGMA query_only=ON")
    else:
        connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        connection.close()
        raise ShadowBackfillError("SQLite foreign key enforcement is unavailable")
    return connection


def _checkpoint_offline_snapshot(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if result is not None and result[0] != 0:
        raise ShadowBackfillError("shadow database checkpoint failed")


def _remove_checkpointed_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database}{suffix}")
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass


def _ensure_shadow_run(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str,
    created_at: str,
) -> None:
    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    prepare_idempotency_key = _normalize_required_identity(
        "prepare_idempotency_key", prepare_idempotency_key
    )
    existing_workflow = connection.execute(
        "SELECT mode FROM workflow_authority WHERE workflow=?", (workflow,)
    ).fetchone()
    if existing_workflow is None:
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES(?,'file_authority_shadow',?)",
            (workflow, created_at),
        )
    elif existing_workflow[0] == "file_authority":
        connection.execute(
            "UPDATE workflow_authority SET mode='file_authority_shadow',updated_at=? "
            "WHERE workflow=?",
            (created_at, workflow),
        )
    elif existing_workflow[0] != "file_authority_shadow":
        raise ShadowBackfillError(
            f"workflow {workflow!r} is not in file-authority shadow mode"
        )

    existing_run = connection.execute(
        "SELECT workflow,authority_mode,prepare_idempotency_key,state,risk_class,"
        "risk_dominance,finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if existing_run is not None:
        if not _run_is_finalized_shadow(
            existing_run,
            workflow=workflow,
            prepare_idempotency_key=prepare_idempotency_key,
        ):
            raise ShadowBackfillError(f"run {run_id!r} is not a matching shadow run")
        return

    connection.execute(
        "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
        "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
        "finalized_at_epoch_ms) VALUES(?,?,?,'file_authority_shadow','finalized',"
        "'R1','R1',?,?,?,1)",
        (run_id, prepare_idempotency_key, workflow, created_at, created_at, created_at),
    )


def backfill_file_authority_shadow(
    database: Path,
    artifacts: Iterable[str | Path],
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str | None = None,
    repo_root_path: Path | None = None,
) -> ShadowBackfillResult:
    """Backfill explicit file artifacts as shadow evidence, never authority."""

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    prepare_key = (
        _normalize_required_identity("prepare_idempotency_key", prepare_idempotency_key)
        if prepare_idempotency_key is not None
        else f"file-shadow:{run_id}"
    )
    root = Path(repo_root_path or repository_root()).resolve()
    normalized = _normalize_artifacts(artifacts, repo_root_path=root)
    apply_migrations(database, repo_root=root)
    created_at = _utc_now()
    database_path = Path(database).expanduser().resolve()
    connection = _connect(database_path)
    checkpointed = False
    projections: list[ShadowProjection] = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _ensure_shadow_run(
                connection,
                workflow=workflow,
                run_id=run_id,
                prepare_idempotency_key=prepare_key,
                created_at=created_at,
            )
            for _path, relative, digest in normalized:
                rows = connection.execute(
                    "SELECT projection_id,sha256 FROM artifact_projections "
                    "WHERE run_id=? AND path=? AND source_authority='file_authority_shadow'",
                    (run_id, relative),
                ).fetchall()
                projection = ShadowProjection(
                    path=relative,
                    sha256=digest,
                    projection_id=_projection_id(run_id, relative, digest),
                )
                if rows:
                    existing_ids = {row[0] for row in rows}
                    existing_digests = {row[1] for row in rows}
                    if existing_ids != {projection.projection_id} or existing_digests != {
                        digest
                    }:
                        raise ShadowBackfillError(
                            "shadow projection drift for "
                            f"{relative}; use a new run_id for a new snapshot"
                        )
                    projections.append(projection)
                    continue
                try:
                    connection.execute(
                        "INSERT INTO artifact_projections("
                        "projection_id,run_id,path,sha256,source_authority,"
                        "generated_at) VALUES(?,?,?,?,?,?)",
                        (
                            projection.projection_id,
                            run_id,
                            relative,
                            digest,
                            "file_authority_shadow",
                            created_at,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ShadowBackfillError(
                        f"shadow projection insert conflict for {relative}"
                    ) from exc
                projections.append(projection)
            connection.execute("COMMIT")
            _checkpoint_offline_snapshot(connection)
            checkpointed = True
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    finally:
        connection.close()
        if checkpointed:
            _remove_checkpointed_sidecars(database_path)
    return ShadowBackfillResult(workflow=workflow, run_id=run_id, projections=tuple(projections))


def _projection_rows_by_path(
    rows: Iterable[tuple[str, str]]
) -> tuple[dict[str, str], tuple[ShadowAuditIssue, ...]]:
    projected: dict[str, str] = {}
    grouped: dict[str, list[str]] = {}
    issues: list[ShadowAuditIssue] = []
    for path, digest in rows:
        grouped.setdefault(path, []).append(digest)
    for path, digests in grouped.items():
        unique_digests = tuple(dict.fromkeys(digests))
        if len(digests) != 1 or len(unique_digests) != 1:
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="duplicate_projection",
                    actual_sha256=",".join(unique_digests),
                )
            )
            continue
        projected[path] = unique_digests[0]
    return projected, tuple(issues)


def audit_file_authority_shadow(
    database: Path,
    artifacts: Iterable[str | Path],
    *,
    workflow: str,
    run_id: str,
    repo_root_path: Path | None = None,
) -> ShadowAuditResult:
    """Compare current artifact files with their shadow projections."""

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    root = Path(repo_root_path or repository_root()).resolve()
    normalized = _normalize_artifacts(artifacts, repo_root_path=root)
    expected = {relative: digest for _path, relative, digest in normalized}
    database_path = Path(database).expanduser().resolve()
    issues: list[ShadowAuditIssue] = []
    if not database_path.is_file():
        issues.append(ShadowAuditIssue(path=str(database_path), reason="invalid_schema"))
        return ShadowAuditResult(
            workflow=workflow,
            run_id=run_id,
            status="fail",
            checked_count=len(expected),
            issues=tuple(issues),
        )
    try:
        verify_database(database_path)
    except (MigrationError, sqlite3.DatabaseError):
        issues.append(ShadowAuditIssue(path=str(database_path), reason="invalid_schema"))
        return ShadowAuditResult(
            workflow=workflow,
            run_id=run_id,
            status="fail",
            checked_count=len(expected),
            issues=tuple(issues),
        )

    connection = _connect(database_path, existing=True)
    try:
        run = connection.execute(
            "SELECT workflow,authority_mode,state,risk_class,risk_dominance,"
            "finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if not _run_is_finalized_shadow(run, workflow=workflow):
            issues.append(ShadowAuditIssue(path="", reason="missing_shadow_run"))
        workflow_mode = connection.execute(
            "SELECT mode FROM workflow_authority WHERE workflow=?", (workflow,)
        ).fetchone()
        if workflow_mode != ("file_authority_shadow",):
            issues.append(ShadowAuditIssue(path="", reason="workflow_not_shadow"))
        rows = connection.execute(
            "SELECT path,sha256 FROM artifact_projections "
            "WHERE run_id=? AND source_authority='file_authority_shadow'",
            (run_id,),
        ).fetchall()
    finally:
        connection.close()

    projected, projection_issues = _projection_rows_by_path(rows)
    issues.extend(projection_issues)
    for path, digest in expected.items():
        if any(issue.path == path and issue.reason == "duplicate_projection" for issue in issues):
            continue
        actual = projected.get(path)
        if actual is None:
            issues.append(
                ShadowAuditIssue(path=path, reason="missing_projection", expected_sha256=digest)
            )
        elif actual != digest:
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="sha256_mismatch",
                    expected_sha256=digest,
                    actual_sha256=actual,
                )
            )
    for path, digest in projected.items():
        if path not in expected:
            issues.append(
                ShadowAuditIssue(path=path, reason="unexpected_projection", actual_sha256=digest)
            )
    return ShadowAuditResult(
        workflow=workflow,
        run_id=run_id,
        status="pass" if not issues else "fail",
        checked_count=len(expected),
        issues=tuple(issues),
    )
