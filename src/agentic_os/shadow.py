"""Offline file-authority shadow projection and parity checks."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import uuid
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
class DualWriteShadowResult:
    workflow: str
    run_id: str
    projection: ShadowProjection
    status: str


@dataclass(frozen=True)
class ShadowAuditIssue:
    path: str
    reason: str
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    expected_projection_id: str | None = None
    actual_projection_id: str | None = None


@dataclass(frozen=True)
class ShadowAuditResult:
    workflow: str
    run_id: str
    status: str
    checked_count: int
    issues: tuple[ShadowAuditIssue, ...]


def _utc_now() -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    return now.isoformat(), int(now.timestamp() * 1000)


def _utc_iso_epoch_ms(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_relative(root: Path, path: Path, *, resolve: bool = True) -> str:
    expanded = path.expanduser()
    candidate = expanded if expanded.is_absolute() else root / expanded
    normalized = candidate.resolve() if resolve else Path(os.path.abspath(candidate))
    try:
        return normalized.relative_to(root).as_posix()
    except ValueError:
        raise ShadowBackfillError(
            f"shadow artifact is outside repository root: {normalized}"
        ) from None


def _projection_id(run_id: str, relative_path: str, digest: str) -> str:
    payload = f"{run_id}\0{relative_path}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_required_identity(name: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ShadowBackfillError(f"{name} must be a non-empty identity")
    return normalized


def _normalize_dual_write_risk(risk_class: str, risk_dominance: str) -> tuple[str, str]:
    normalized_class = _normalize_required_identity("risk_class", risk_class)
    normalized_dominance = _normalize_required_identity("risk_dominance", risk_dominance)
    if (normalized_class, normalized_dominance) != ("R1", "R1"):
        raise ShadowBackfillError(
            "dual-write shadow supports only explicit R1 risk; "
            "run higher-risk work through the completion gate before shadowing"
        )
    return normalized_class, normalized_dominance


def _run_is_finalized_shadow(
    row: tuple[object, ...] | None,
    *,
    workflow: str,
    authority_mode: str = "file_authority_shadow",
    prepare_idempotency_key: str | None = None,
    risk_class: str = "R1",
    risk_dominance: str = "R1",
) -> bool:
    if row is None:
        return False
    if prepare_idempotency_key is None:
        expected = (workflow, authority_mode, "finalized", risk_class, risk_dominance)
        identity = row[:5]
        finalized_at = row[5]
        finalized_epoch_ms = row[6]
    else:
        expected = (
            workflow,
            authority_mode,
            prepare_idempotency_key,
            "finalized",
            risk_class,
            risk_dominance,
        )
        identity = row[:6]
        finalized_at = row[6]
        finalized_epoch_ms = row[7]
    if (
        identity != expected
        or type(finalized_epoch_ms) is not int
        or finalized_epoch_ms <= 0
    ):
        return False
    return _utc_iso_epoch_ms(finalized_at) == finalized_epoch_ms


def _matching_shadow_run_state(
    row: tuple[object, ...] | None,
    *,
    workflow: str,
    authority_mode: str,
    prepare_idempotency_key: str,
    risk_class: str,
    risk_dominance: str,
) -> str | None:
    if row is None:
        return None
    expected = (
        workflow,
        authority_mode,
        prepare_idempotency_key,
        risk_class,
        risk_dominance,
    )
    identity = (row[0], row[1], row[2], row[4], row[5])
    if identity != expected:
        return None
    state = row[3]
    finalized_at = row[6]
    finalized_epoch_ms = row[7]
    if state == "prepared":
        return "prepared" if finalized_at is None and finalized_epoch_ms is None else None
    if state == "finalized" and type(finalized_epoch_ms) is int and finalized_epoch_ms > 0:
        return "finalized" if _utc_iso_epoch_ms(finalized_at) == finalized_epoch_ms else None
    return None


def _normalize_artifacts(
    artifacts: Iterable[str | Path], *, repo_root_path: Path
) -> tuple[tuple[Path, str, str], ...]:
    paths = tuple(Path(artifact).expanduser() for artifact in artifacts)
    if not paths:
        raise ShadowBackfillError("at least one artifact path is required")
    normalized: list[tuple[Path, str, str]] = []
    seen: set[str] = set()
    for path in paths:
        explicit_relative = _repo_relative(repo_root_path, path, resolve=False)
        resolved = (path if path.is_absolute() else repo_root_path / path).resolve()
        resolved_relative = _repo_relative(repo_root_path, resolved)
        assert_paths_retrievable((path, explicit_relative, resolved, resolved_relative))
        if not resolved.is_file():
            raise ShadowBackfillError(f"shadow artifact is not a file: {resolved}")
        if explicit_relative in seen:
            continue
        seen.add(explicit_relative)
        normalized.append((resolved, explicit_relative, _sha256(resolved)))
    return tuple(normalized)


def _normalize_artifact_target(
    artifact: str | Path, *, repo_root_path: Path
) -> tuple[Path, str]:
    path = Path(artifact).expanduser()
    explicit_relative = _repo_relative(repo_root_path, path, resolve=False)
    absolute = path if path.is_absolute() else repo_root_path / path
    if absolute.exists():
        resolved = absolute.resolve()
        resolved_relative = _repo_relative(repo_root_path, resolved)
        assert_paths_retrievable(
            (path, explicit_relative, resolved, resolved_relative)
        )
    else:
        parent = absolute.parent.resolve()
        parent_relative = _repo_relative(repo_root_path, parent)
        assert_paths_retrievable((path, explicit_relative, parent, parent_relative))
    return absolute, explicit_relative


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


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_create_file(target: Path, content: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(
        f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )
    linked = False
    try:
        with temporary.open("xb") as destination:
            written = destination.write(content)
            if written != len(content):
                raise OSError("short write")
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.link(temporary, target)
            linked = True
        except FileExistsError as exc:
            raise ShadowBackfillError(
                f"existing artifact appeared during atomic write: {target}"
            ) from exc
        _fsync_directory(target.parent)
    except Exception:
        if linked:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        try:
            temporary.unlink()
        except Exception:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            raise


def _remove_checkpointed_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database}{suffix}")
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass


def _assert_workflow_shadow_parity(
    connection: sqlite3.Connection, *, workflow: str, repo_root_path: Path
) -> None:
    workflow_counters = connection.execute(
        "SELECT open_file_authority_runs FROM workflow_authority WHERE workflow=?",
        (workflow,),
    ).fetchone()
    if workflow_counters is not None:
        open_file_authority_runs = workflow_counters[0]
        if type(open_file_authority_runs) is not int or open_file_authority_runs > 0:
            raise ShadowBackfillError(
                f"workflow {workflow!r} has an open file-authority run"
            )
    open_file_run = connection.execute(
        "SELECT run_id,state FROM runs WHERE workflow=? AND authority_mode='file_authority' "
        "AND state NOT IN ('finalized','rolled_back','rejected') LIMIT 1",
        (workflow,),
    ).fetchone()
    if open_file_run is not None:
        raise ShadowBackfillError(
            f"workflow {workflow!r} has an open file-authority run"
        )
    runs = connection.execute(
        "SELECT run_id,workflow,authority_mode,prepare_idempotency_key,state,"
        "risk_class,risk_dominance,finalized_at,finalized_at_epoch_ms "
        "FROM runs WHERE workflow=? AND authority_mode='file_authority_shadow'",
        (workflow,),
    ).fetchall()
    if not runs:
        raise ShadowBackfillError(
            f"workflow {workflow!r} has no file-authority shadow parity baseline"
        )
    for (
        run_id,
        run_workflow,
        authority_mode,
        prepare_key,
        state,
        risk_class,
        risk_dominance,
        finalized_at,
        finalized_at_epoch_ms,
    ) in runs:
        if (
            not isinstance(prepare_key, str)
            or prepare_key != prepare_key.strip()
            or not prepare_key
        ):
            raise ShadowBackfillError(
                f"workflow {workflow!r} has incomplete shadow prepare identity"
            )
        if risk_class != "R1" or risk_dominance != "R1":
            raise ShadowBackfillError(
                f"workflow {workflow!r} has non-R1 shadow parity evidence"
            )
        run_identity = (
            run_workflow,
            authority_mode,
            prepare_key,
            state,
            risk_class,
            risk_dominance,
            finalized_at,
            finalized_at_epoch_ms,
        )
        if not _run_is_finalized_shadow(
            run_identity,
            workflow=workflow,
            prepare_idempotency_key=prepare_key,
            risk_class="R1",
            risk_dominance="R1",
        ):
            raise ShadowBackfillError(
                f"workflow {workflow!r} has non-finalized shadow parity evidence"
            )
        all_projections = connection.execute(
            "SELECT projection_id,path,sha256,source_authority FROM artifact_projections "
            "WHERE run_id=?",
            (run_id,),
        ).fetchall()
        if any(source != "file_authority_shadow" for *_fields, source in all_projections):
            raise ShadowBackfillError(
                f"workflow {workflow!r} has unexpected shadow parity projection"
            )
        projections = [
            (projection_id, path, digest)
            for projection_id, path, digest, _source in all_projections
        ]
        if not projections:
            raise ShadowBackfillError(
                f"workflow {workflow!r} has a shadow run with no parity projections"
            )
        for projection_id, path, digest in projections:
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or not isinstance(projection_id, str)
                or Path(path).is_absolute()
            ):
                raise ShadowBackfillError(
                    f"workflow {workflow!r} has invalid shadow parity evidence"
                )
            expected_projection_id = _projection_id(run_id, path, digest)
            if projection_id != expected_projection_id:
                raise ShadowBackfillError(
                    f"workflow {workflow!r} has stale shadow parity evidence"
                )
            artifact = repo_root_path / path
            try:
                explicit_relative = _repo_relative(
                    repo_root_path, artifact, resolve=False
                )
                resolved = artifact.resolve(strict=True)
                resolved_relative = _repo_relative(repo_root_path, resolved)
                assert_paths_retrievable(
                    (path, explicit_relative, artifact, resolved, resolved_relative)
                )
            except (OSError, ShadowBackfillError) as exc:
                raise ShadowBackfillError(
                    f"workflow {workflow!r} shadow parity is missing or unsafe"
                ) from exc
            if not resolved.is_file() or _sha256(resolved) != digest:
                raise ShadowBackfillError(
                    f"workflow {workflow!r} shadow parity audit failed"
                )


def _ensure_shadow_run(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str,
    authority_mode: str = "file_authority_shadow",
    risk_class: str = "R1",
    risk_dominance: str = "R1",
    created_at: str,
    finalized_at_epoch_ms: int,
    allow_workflow_promotion: bool = True,
    allow_new_dual_write_workflow: bool = False,
    repo_root_path: Path | None = None,
    insert_state: str = "finalized",
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
        if authority_mode == "dual_write_shadow":
            if not allow_new_dual_write_workflow:
                raise ShadowBackfillError(
                    f"workflow {workflow!r} requires explicit new-workflow proof"
                )
            existing_run = connection.execute(
                "SELECT run_id,authority_mode FROM runs WHERE workflow=? LIMIT 1",
                (workflow,),
            ).fetchone()
            if existing_run is not None:
                raise ShadowBackfillError(
                    f"workflow {workflow!r} has prior run evidence without workflow metadata"
                )
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES(?,?,?)",
            (workflow, authority_mode, created_at),
        )
    elif existing_workflow[0] == authority_mode:
        pass
    elif (
        allow_workflow_promotion
        and authority_mode == "file_authority_shadow"
        and existing_workflow[0] == "file_authority"
    ):
        connection.execute(
            "UPDATE workflow_authority SET mode=?,updated_at=? "
            "WHERE workflow=?",
            (authority_mode, created_at, workflow),
        )
    elif (
        allow_workflow_promotion
        and authority_mode == "dual_write_shadow"
        and existing_workflow[0] == "file_authority_shadow"
    ):
        if repo_root_path is None:
            raise ShadowBackfillError(
                "dual-write promotion requires shadow parity evidence"
            )
        _assert_workflow_shadow_parity(
            connection, workflow=workflow, repo_root_path=repo_root_path
        )
        connection.execute(
            "UPDATE workflow_authority SET mode=?,updated_at=? "
            "WHERE workflow=?",
            (authority_mode, created_at, workflow),
        )
    else:
        raise ShadowBackfillError(
            f"workflow {workflow!r} is not in {authority_mode} mode; "
            "run file-authority shadow backfill first"
        )

    existing_run = connection.execute(
        "SELECT workflow,authority_mode,prepare_idempotency_key,state,risk_class,"
        "risk_dominance,finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if existing_run is not None:
        existing_state = _matching_shadow_run_state(
            existing_run,
            workflow=workflow,
            authority_mode=authority_mode,
            prepare_idempotency_key=prepare_idempotency_key,
            risk_class=risk_class,
            risk_dominance=risk_dominance,
        )
        if existing_state == "finalized" or (
            insert_state == "prepared" and existing_state == "prepared"
        ):
            return
        raise ShadowBackfillError(f"run {run_id!r} is not a matching shadow run")

    if insert_state == "finalized":
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at,finalized_at,"
            "finalized_at_epoch_ms) VALUES(?,?,?,?,'finalized',?,?,?, ?,?,?)",
            (
                run_id,
                prepare_idempotency_key,
                workflow,
                authority_mode,
                risk_class,
                risk_dominance,
                created_at,
                created_at,
                created_at,
                finalized_at_epoch_ms,
            ),
        )
    elif insert_state == "prepared":
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
            "state,risk_class,risk_dominance,created_at,updated_at) "
            "VALUES(?,?,?,?,'prepared',?,?,?,?)",
            (
                run_id,
                prepare_idempotency_key,
                workflow,
                authority_mode,
                risk_class,
                risk_dominance,
                created_at,
                created_at,
            ),
        )
    else:
        raise ShadowBackfillError(f"unsupported shadow run state: {insert_state}")


def _finalize_prepared_shadow_run(
    connection: sqlite3.Connection,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str,
    authority_mode: str,
    risk_class: str,
    risk_dominance: str,
    finalized_at: str,
    finalized_at_epoch_ms: int,
) -> None:
    existing_run = connection.execute(
        "SELECT workflow,authority_mode,prepare_idempotency_key,state,risk_class,"
        "risk_dominance,finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if (
        _matching_shadow_run_state(
            existing_run,
            workflow=workflow,
            authority_mode=authority_mode,
            prepare_idempotency_key=prepare_idempotency_key,
            risk_class=risk_class,
            risk_dominance=risk_dominance,
        )
        != "prepared"
    ):
        raise ShadowBackfillError(f"run {run_id!r} is not a prepared shadow run")
    updated = connection.execute(
        "UPDATE runs SET state='finalized',updated_at=?,finalized_at=?,"
        "finalized_at_epoch_ms=? WHERE run_id=? AND state='prepared'",
        (finalized_at, finalized_at, finalized_at_epoch_ms, run_id),
    ).rowcount
    if updated != 1:
        raise ShadowBackfillError(f"run {run_id!r} could not be finalized")


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
    created_at, finalized_at_epoch_ms = _utc_now()
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
                finalized_at_epoch_ms=finalized_at_epoch_ms,
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


def dual_write_shadow_artifact(
    database: Path,
    artifact: str | Path,
    content: bytes,
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str | None = None,
    risk_class: str,
    risk_dominance: str,
    new_workflow: bool = False,
    repo_root_path: Path | None = None,
) -> DualWriteShadowResult:
    """Write one file-authority artifact plus SQLite parity evidence.

    File content remains the operational artifact. SQLite receives only
    `dual_write_shadow` parity evidence and never becomes dispatch authority.
    """

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    if not content:
        raise ShadowBackfillError("content must be non-empty")
    prepare_key = (
        _normalize_required_identity("prepare_idempotency_key", prepare_idempotency_key)
        if prepare_idempotency_key is not None
        else f"dual-write-shadow:{run_id}"
    )
    risk_class, risk_dominance = _normalize_dual_write_risk(risk_class, risk_dominance)
    root = Path(repo_root_path or repository_root()).resolve()
    target, relative = _normalize_artifact_target(artifact, repo_root_path=root)
    digest = hashlib.sha256(content).hexdigest()
    projection = ShadowProjection(
        path=relative,
        sha256=digest,
        projection_id=_projection_id(run_id, relative, digest),
    )
    database_path = Path(database).expanduser().resolve()
    apply_migrations(database_path, repo_root=root)
    created_at, created_at_epoch_ms = _utc_now()
    connection = _connect(database_path)
    checkpointed = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            run_projections = connection.execute(
                "SELECT projection_id,path,sha256,source_authority "
                "FROM artifact_projections WHERE run_id=?",
                (run_id,),
            ).fetchall()
            rows = [
                row
                for row in run_projections
                if row[1] == relative and row[3] == "dual_write_shadow"
            ]
            if rows:
                existing_ids = {row[0] for row in rows}
                existing_digests = {row[2] for row in rows}
                run_projection_paths = {path for _id, path, _digest, _source in run_projections}
                run_projection_sources = {
                    source for _id, _path, _digest, source in run_projections
                }
                if len(run_projections) != 1 or run_projection_paths != {relative}:
                    raise ShadowBackfillError(
                        "dual-write shadow replay drift for "
                        f"{run_id}; refusing extra projections"
                    )
                if run_projection_sources != {"dual_write_shadow"}:
                    raise ShadowBackfillError(
                        "dual-write shadow replay drift for "
                        f"{run_id}; refusing extra projections"
                    )
                if existing_ids != {projection.projection_id} or existing_digests != {
                    digest
                }:
                    raise ShadowBackfillError(
                        "dual-write shadow replay drift for "
                        f"{relative}; refusing to overwrite file authority"
                    )
                existing_run = connection.execute(
                    "SELECT workflow,authority_mode,prepare_idempotency_key,state,"
                    "risk_class,risk_dominance,finalized_at,finalized_at_epoch_ms "
                    "FROM runs WHERE run_id=?",
                    (run_id,),
                ).fetchone()
                run_state = _matching_shadow_run_state(
                    existing_run,
                    workflow=workflow,
                    authority_mode="dual_write_shadow",
                    prepare_idempotency_key=prepare_key,
                    risk_class=risk_class,
                    risk_dominance=risk_dominance,
                )
                if run_state is None:
                    raise ShadowBackfillError(
                        f"run {run_id!r} is not a matching shadow run"
                    )
                _ensure_shadow_run(
                    connection,
                    workflow=workflow,
                    run_id=run_id,
                    prepare_idempotency_key=prepare_key,
                    authority_mode="dual_write_shadow",
                    risk_class=risk_class,
                    risk_dominance=risk_dominance,
                    created_at=created_at,
                    finalized_at_epoch_ms=created_at_epoch_ms,
                    allow_workflow_promotion=False,
                    insert_state=run_state,
                )
                if target.exists():
                    actual_digest = _sha256(target)
                    if actual_digest != digest:
                        raise ShadowBackfillError(
                            "dual-write shadow artifact drift for "
                            f"{relative}; refusing to overwrite file authority"
                        )
                elif run_state == "prepared":
                    _atomic_create_file(target, content)
                else:
                    raise ShadowBackfillError(
                        f"dual-write shadow artifact is missing: {relative}"
                    )
                if run_state == "prepared":
                    finalized_at, finalized_at_epoch_ms = _utc_now()
                    _finalize_prepared_shadow_run(
                        connection,
                        workflow=workflow,
                        run_id=run_id,
                        prepare_idempotency_key=prepare_key,
                        authority_mode="dual_write_shadow",
                        risk_class=risk_class,
                        risk_dominance=risk_dominance,
                        finalized_at=finalized_at,
                        finalized_at_epoch_ms=finalized_at_epoch_ms,
                    )
                connection.execute("COMMIT")
                _checkpoint_offline_snapshot(connection)
                checkpointed = True
                return DualWriteShadowResult(
                    workflow=workflow,
                    run_id=run_id,
                    projection=projection,
                    status="replayed" if run_state == "finalized" else "recovered",
                )

            if run_projections:
                raise ShadowBackfillError(
                    "dual-write shadow replay drift for "
                    f"{run_id}; refusing to add a different artifact path"
                )
            if target.exists():
                raise ShadowBackfillError(
                    f"pre-existing artifact has no dual-write projection: {relative}"
                )
            _ensure_shadow_run(
                connection,
                workflow=workflow,
                run_id=run_id,
                prepare_idempotency_key=prepare_key,
                authority_mode="dual_write_shadow",
                risk_class=risk_class,
                risk_dominance=risk_dominance,
                created_at=created_at,
                finalized_at_epoch_ms=created_at_epoch_ms,
                allow_new_dual_write_workflow=new_workflow,
                repo_root_path=root,
                insert_state="prepared",
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
                    "dual_write_shadow",
                    created_at,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

        _atomic_create_file(target, content)

        connection.execute("BEGIN IMMEDIATE")
        try:
            if not target.exists() or _sha256(target) != digest:
                raise ShadowBackfillError(
                    "dual-write shadow artifact drift for "
                    f"{relative}; refusing to finalize file authority"
                )
            finalized_at, finalized_at_epoch_ms = _utc_now()
            _finalize_prepared_shadow_run(
                connection,
                workflow=workflow,
                run_id=run_id,
                prepare_idempotency_key=prepare_key,
                authority_mode="dual_write_shadow",
                risk_class=risk_class,
                risk_dominance=risk_dominance,
                finalized_at=finalized_at,
                finalized_at_epoch_ms=finalized_at_epoch_ms,
            )
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
    return DualWriteShadowResult(
        workflow=workflow,
        run_id=run_id,
        projection=projection,
        status="written",
    )


def _projection_rows_by_path(
    rows: Iterable[tuple[str, str, str]], *, run_id: str
) -> tuple[dict[str, str], tuple[ShadowAuditIssue, ...]]:
    projected: dict[str, str] = {}
    grouped: dict[str, list[tuple[str, str]]] = {}
    issues: list[ShadowAuditIssue] = []
    for projection_id, path, digest in rows:
        grouped.setdefault(path, []).append((projection_id, digest))
    for path, projections in grouped.items():
        unique_digests = tuple(dict.fromkeys(digest for _projection_id, digest in projections))
        if len(projections) != 1 or len(unique_digests) != 1:
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="duplicate_projection",
                    actual_sha256=",".join(unique_digests),
                )
            )
            continue
        projection_id, digest = projections[0]
        expected_projection_id = _projection_id(run_id, path, digest)
        if projection_id != expected_projection_id:
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="projection_id_mismatch",
                    expected_sha256=digest,
                    actual_sha256=digest,
                    expected_projection_id=expected_projection_id,
                    actual_projection_id=projection_id,
                )
            )
        projected[path] = digest
    return projected, tuple(issues)


def audit_file_authority_shadow(
    database: Path,
    artifacts: Iterable[str | Path],
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str | None = None,
    repo_root_path: Path | None = None,
) -> ShadowAuditResult:
    """Compare current artifact files with their shadow projections."""

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    prepare_key = (
        _normalize_required_identity("prepare_idempotency_key", prepare_idempotency_key)
        if prepare_idempotency_key is not None
        else f"file-shadow:{run_id}"
    )
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
            "SELECT workflow,authority_mode,prepare_idempotency_key,state,"
            "risk_class,risk_dominance,"
            "finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if not _run_is_finalized_shadow(
            run, workflow=workflow, prepare_idempotency_key=prepare_key
        ):
            issues.append(ShadowAuditIssue(path="", reason="missing_shadow_run"))
        workflow_mode = connection.execute(
            "SELECT mode FROM workflow_authority WHERE workflow=?", (workflow,)
        ).fetchone()
        if workflow_mode != ("file_authority_shadow",):
            issues.append(ShadowAuditIssue(path="", reason="workflow_not_shadow"))
        rows = connection.execute(
            "SELECT projection_id,path,sha256 FROM artifact_projections "
            "WHERE run_id=? AND source_authority='file_authority_shadow'",
            (run_id,),
        ).fetchall()
    finally:
        connection.close()

    projected, projection_issues = _projection_rows_by_path(rows, run_id=run_id)
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


def audit_dual_write_shadow(
    database: Path,
    artifacts: Iterable[str | Path],
    *,
    workflow: str,
    run_id: str,
    prepare_idempotency_key: str | None = None,
    repo_root_path: Path | None = None,
) -> ShadowAuditResult:
    """Compare current file artifacts with `dual_write_shadow` parity evidence."""

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    prepare_key = (
        _normalize_required_identity("prepare_idempotency_key", prepare_idempotency_key)
        if prepare_idempotency_key is not None
        else f"dual-write-shadow:{run_id}"
    )
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
            "SELECT workflow,authority_mode,prepare_idempotency_key,state,"
            "risk_class,risk_dominance,"
            "finalized_at,finalized_at_epoch_ms FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if not _run_is_finalized_shadow(
            run,
            workflow=workflow,
            authority_mode="dual_write_shadow",
            prepare_idempotency_key=prepare_key,
        ):
            issues.append(ShadowAuditIssue(path="", reason="missing_shadow_run"))
        workflow_mode = connection.execute(
            "SELECT mode FROM workflow_authority WHERE workflow=?", (workflow,)
        ).fetchone()
        if workflow_mode != ("dual_write_shadow",):
            issues.append(ShadowAuditIssue(path="", reason="workflow_not_shadow"))
        run_projection_rows = connection.execute(
            "SELECT projection_id,path,sha256,source_authority FROM artifact_projections "
            "WHERE run_id=?",
            (run_id,),
        ).fetchall()
    finally:
        connection.close()

    if len(run_projection_rows) > 1:
        for _projection_id, path, digest, _source_authority in run_projection_rows:
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="unexpected_projection",
                    actual_sha256=digest,
                )
            )
    rows = [
        (projection_id, path, digest)
        for projection_id, path, digest, source_authority in run_projection_rows
        if source_authority == "dual_write_shadow"
    ]
    for _projection_id, path, digest, source_authority in run_projection_rows:
        if source_authority != "dual_write_shadow":
            issues.append(
                ShadowAuditIssue(
                    path=path,
                    reason="unexpected_projection",
                    actual_sha256=digest,
                )
            )
    projected, projection_issues = _projection_rows_by_path(rows, run_id=run_id)
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
