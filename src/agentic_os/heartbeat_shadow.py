"""Heartbeat-only file-authority shadow pilot and bounded soak receipts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import agentic_os
from agentic_os.migrations import repository_root
from agentic_os.privacy import (
    PrivacyPreflightError,
    assert_paths_retrievable,
    assert_privacy_preflight,
    is_raw_state_denied,
)
from agentic_os.shadow import (
    ShadowBackfillError,
    audit_dual_write_shadow,
    audit_file_authority_shadow,
    backfill_file_authority_shadow,
    dual_write_shadow_artifact,
)


class HeartbeatShadowError(RuntimeError):
    """Heartbeat shadow authority, parity, rollback, or soak failed closed."""


HEARTBEAT_WORKFLOW = "heartbeat"
HEARTBEAT_CONTROL_DB = Path("state/agentic-os/control.db")
MIN_SOAK_HOURS = 24
MAX_SOAK_HOURS = 72
SOAK_COUNTER_KEYS = (
    "duplicate_spawn",
    "orphan_lease",
    "unknown_or_unowned_session",
    "privacy_violation",
    "projection_drift",
)
RUNTIME_AUTHORITY_COUNT_KEYS = (
    "lease_rows",
    "spawn_request_rows",
    "session_rows",
    "lifecycle_rpc_intent_rows",
    "duplicate_spawn_identity_groups",
)
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
SAFE_SCHEDULER_FIELDS = {
    "every": str,
    "target": str,
}
SOAK_SAMPLE_FIELDS = {
    "authority_mode",
    "counters",
    "db_authority_enabled",
    "expected_authority_input_digest",
    "observation_error",
    "observed_authority_input_digest",
    "parity_percent",
    "parity_status",
    "runtime_authority_counts",
    "runtime_authority_counts_observed",
    "sampled_at_epoch_ms",
    "sampled_at_monotonic_ms",
    "status",
}


def _canonical_json(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise HeartbeatShadowError("Heartbeat receipt must be canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _required_identity(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HeartbeatShadowError(f"{label} must be non-empty text")
    return value.strip()


def _repo_artifact_path(root: Path, path: Path, label: str) -> Path:
    target = path.expanduser().resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HeartbeatShadowError(f"{label} must stay inside the checked worktree") from None
    try:
        assert_paths_retrievable(target.relative_to(root))
    except PrivacyPreflightError as exc:
        raise HeartbeatShadowError(f"{label} cannot be raw database state") from exc
    return target


def _repo_local_recovery_database_path(root: Path, path: Path, label: str) -> Path:
    target = path.expanduser().resolve()
    try:
        relative = target.relative_to(root)
    except ValueError:
        raise HeartbeatShadowError(f"{label} must stay inside the checked worktree") from None
    parts = relative.parts
    if parts[:3] != ("state", "agentic-os", "backups"):
        raise HeartbeatShadowError(f"{label} must stay under state/agentic-os/backups")
    assert_paths_retrievable((relative, target), local_recovery=True)
    if not is_raw_state_denied(relative):
        raise HeartbeatShadowError(f"{label} must remain denied to packaging/retrieval")
    return target


def _assert_db_authority_disabled() -> None:
    if agentic_os.DB_AUTHORITY_ENABLED:
        raise HeartbeatShadowError("database authority must remain disabled")


def _contains_sensitive_key(value: object) -> bool:
    denied_fragments = (
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
    )
    if isinstance(value, Mapping):
        return any(
            any(fragment in str(key).casefold() for fragment in denied_fragments)
            or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _safe_scheduler_projection(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise HeartbeatShadowError(f"{label} must be an object")
    if set(value) != set(SAFE_SCHEDULER_FIELDS):
        raise HeartbeatShadowError(f"{label} contains unsupported scheduler fields")
    result: dict[str, str] = {}
    for key, expected_type in SAFE_SCHEDULER_FIELDS.items():
        item = value.get(key)
        if (
            type(item) is not expected_type
            or item != item.strip()
            or not item
            or len(item) > 200
        ):
            raise HeartbeatShadowError(f"{label}.{key} must be bounded non-empty text")
        result[key] = item
    if _contains_sensitive_key(result):
        raise HeartbeatShadowError(f"{label} contains sensitive keys")
    return result


def _live_scheduler_projection(live_config_path: Path) -> dict[str, str]:
    config = _json_file(live_config_path.expanduser().resolve(), "live OpenClaw config")
    agents = config.get("agents")
    defaults = agents.get("defaults") if isinstance(agents, Mapping) else None
    heartbeat = defaults.get("heartbeat") if isinstance(defaults, Mapping) else None
    return _safe_scheduler_projection(heartbeat, "live Heartbeat scheduler projection")


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> str:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    content = (_canonical_json(value) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return _sha256_bytes(content)


def _json_file(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HeartbeatShadowError(f"{label} is not readable JSON") from exc
    if not isinstance(value, Mapping):
        raise HeartbeatShadowError(f"{label} must be a JSON object")
    return value


def heartbeat_control_database(repo_root_path: Path | None = None) -> Path:
    root = Path(repo_root_path or repository_root()).resolve()
    _assert_db_authority_disabled()
    database = (root / HEARTBEAT_CONTROL_DB).resolve()
    assert_privacy_preflight(root, database_paths=(database,))
    return database


def _validate_baseline(
    baseline: Mapping[str, Any], heartbeat_file: Path, live_config_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(baseline) != {
        "captured_at",
        "classification",
        "file_authority",
        "privacy_boundary",
        "runtime_interpretation",
        "scheduler_projection",
        "schema_version",
    }:
        raise HeartbeatShadowError("Heartbeat authority baseline has unexpected fields")
    if baseline.get("schema_version") != "p03-heartbeat-authority-baseline.v1":
        raise HeartbeatShadowError("Heartbeat authority baseline schema is unsupported")
    if baseline.get("classification") != "sanitized_read_only_projection":
        raise HeartbeatShadowError("Heartbeat baseline is not a sanitized projection")
    if not isinstance(baseline.get("captured_at"), str) or not baseline["captured_at"].strip():
        raise HeartbeatShadowError("Heartbeat baseline capture time is missing")

    privacy_boundary = baseline.get("privacy_boundary")
    if not isinstance(privacy_boundary, Mapping) or set(privacy_boundary) != {
        "allowed_config_path",
        "full_openclaw_config_persisted",
        "secrets_persisted",
    }:
        raise HeartbeatShadowError("Heartbeat baseline privacy boundary is invalid")
    if (
        privacy_boundary.get("allowed_config_path") != "agents.defaults.heartbeat"
        or privacy_boundary.get("full_openclaw_config_persisted") is not False
        or privacy_boundary.get("secrets_persisted") is not False
    ):
        raise HeartbeatShadowError("Heartbeat baseline privacy boundary is unsafe")

    file_authority = baseline.get("file_authority")
    if not isinstance(file_authority, Mapping) or set(file_authority) != {
        "active_periodic_tasks",
        "path",
        "sha256",
    }:
        raise HeartbeatShadowError("Heartbeat file-authority baseline is invalid")
    supplied_heartbeat_file = heartbeat_file.expanduser()
    if supplied_heartbeat_file.is_symlink():
        raise HeartbeatShadowError("Heartbeat file must not be a symlink")
    resolved = supplied_heartbeat_file.resolve()
    if Path(str(file_authority["path"])).expanduser().resolve() != resolved:
        raise HeartbeatShadowError("Heartbeat file path does not match authority baseline")
    if not resolved.is_file() or resolved.is_symlink():
        raise HeartbeatShadowError("Heartbeat file must be a regular non-symlink file")
    file_digest = _sha256_file(resolved)
    if file_digest != file_authority.get("sha256"):
        raise HeartbeatShadowError("HEARTBEAT.md drifted from the authority baseline")
    active_periodic_tasks = file_authority.get("active_periodic_tasks")
    if type(active_periodic_tasks) is not int or active_periodic_tasks < 0:
        raise HeartbeatShadowError("Heartbeat active task count must be non-negative")

    scheduler = baseline.get("scheduler_projection")
    if not isinstance(scheduler, Mapping) or set(scheduler) != {
        "canonical_json_sha256",
        "source",
        "value",
    }:
        raise HeartbeatShadowError("sanitized Heartbeat scheduler projection is invalid")
    if scheduler.get("source") != "agents.defaults.heartbeat":
        raise HeartbeatShadowError("Heartbeat scheduler source is not authoritative")
    scheduler_value = scheduler.get("value")
    safe_scheduler = _safe_scheduler_projection(
        scheduler_value, "sanitized Heartbeat scheduler projection"
    )
    scheduler_digest = _sha256_bytes(_canonical_json(safe_scheduler).encode("utf-8"))
    if scheduler_digest != scheduler.get("canonical_json_sha256"):
        raise HeartbeatShadowError("Heartbeat scheduler subtree digest does not match")
    if _live_scheduler_projection(live_config_path) != safe_scheduler:
        raise HeartbeatShadowError("live Heartbeat scheduler config drifted from baseline")

    interpretation = baseline.get("runtime_interpretation")
    if not isinstance(interpretation, Mapping) or set(interpretation) != {
        "db_authority_enabled",
        "file_artifacts_remain_authority",
        "production_dispatch_controlled_by_shadow_db",
    }:
        raise HeartbeatShadowError("Heartbeat runtime interpretation is invalid")
    if (
        interpretation.get("db_authority_enabled") is not False
        or interpretation.get("file_artifacts_remain_authority") is not True
        or interpretation.get("production_dispatch_controlled_by_shadow_db") is not False
    ):
        raise HeartbeatShadowError("Heartbeat baseline does not preserve file authority")
    _assert_db_authority_disabled()
    return dict(file_authority), {
        "source": scheduler["source"],
        "value": safe_scheduler,
        "canonical_json_sha256": _sha256_bytes(
            _canonical_json(safe_scheduler).encode("utf-8")
        ),
    }


def heartbeat_authority_manifest(
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
    *,
    observed_at_epoch_ms: int | None = None,
) -> dict[str, Any]:
    """Build the exact two-input authority manifest; no full config is accepted."""

    baseline = _json_file(baseline_path.expanduser().resolve(), "Heartbeat baseline")
    file_authority, scheduler = _validate_baseline(
        baseline, heartbeat_file, live_config_path
    )
    observed = (
        time.time_ns() // 1_000_000
        if observed_at_epoch_ms is None
        else observed_at_epoch_ms
    )
    if type(observed) is not int or observed <= 0:
        raise HeartbeatShadowError("observed_at_epoch_ms must be a positive integer")
    return {
        "schema_version": "p03-heartbeat-authority-manifest.v1",
        "workflow": HEARTBEAT_WORKFLOW,
        "observed_at_epoch_ms": observed,
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "inputs": [
            {
                "kind": "file",
                "authority_path": file_authority["path"],
                "sha256": file_authority["sha256"],
                "active_periodic_tasks": file_authority["active_periodic_tasks"],
            },
            {
                "kind": "sanitized_config_subtree",
                "source": scheduler["source"],
                "canonical_json_sha256": scheduler["canonical_json_sha256"],
                "value": scheduler["value"],
            },
        ],
        "excluded_inputs": "all OpenClaw config outside agents.defaults.heartbeat",
    }


def _manifest_authority_digest(manifest: Mapping[str, Any]) -> str:
    authority_view = dict(manifest)
    authority_view.pop("observed_at_epoch_ms", None)
    return _sha256_bytes(_canonical_json(authority_view).encode("utf-8"))


def _sqlite_sidecars(database: Path) -> list[Path]:
    return [
        Path(f"{database}{suffix}")
        for suffix in SQLITE_SIDECAR_SUFFIXES
        if Path(f"{database}{suffix}").exists()
    ]


def _remove_checkpointed_snapshot_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecars(database):
        if sidecar.name.endswith("-wal") and sidecar.stat().st_size != 0:
            raise HeartbeatShadowError("Heartbeat runtime snapshot has live WAL content")
        sidecar.unlink()


def _runtime_authority_counts(database: Path) -> dict[str, int]:
    _assert_db_authority_disabled()
    database_path = database.expanduser().resolve()
    if _sqlite_sidecars(database_path):
        raise HeartbeatShadowError("Heartbeat shadow DB is not an offline snapshot")
    with sqlite3.connect(
        f"{database_path.as_uri()}?mode=ro&immutable=1", uri=True
    ) as connection:
        lease_rows = connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
        spawn_request_rows = connection.execute(
            "SELECT COUNT(*) FROM spawn_requests"
        ).fetchone()[0]
        session_rows = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        lifecycle_rpc_intent_rows = connection.execute(
            "SELECT COUNT(*) FROM external_rpc_intents WHERE rpc_kind IN "
            "('allow_lease_acquire','allow_lease_release','sessions_spawn')"
        ).fetchone()[0]
        duplicate_spawn_identity_groups = connection.execute(
            "SELECT COUNT(*) FROM ("
            "SELECT external_id FROM external_rpc_intents "
            "WHERE rpc_kind='sessions_spawn' AND external_id IS NOT NULL "
            "GROUP BY external_id HAVING COUNT(*)>1)"
        ).fetchone()[0]
        heartbeat_modes = connection.execute(
            "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
        ).fetchall()
    modes = [row[0] for row in heartbeat_modes]
    if modes not in [["file_authority_shadow"], ["dual_write_shadow"]]:
        raise HeartbeatShadowError("Heartbeat workflow has non-shadow DB authority")
    counts = {
        "lease_rows": lease_rows,
        "spawn_request_rows": spawn_request_rows,
        "session_rows": session_rows,
        "lifecycle_rpc_intent_rows": lifecycle_rpc_intent_rows,
        "duplicate_spawn_identity_groups": duplicate_spawn_identity_groups,
    }
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise HeartbeatShadowError("Heartbeat runtime authority counts are invalid")
    return counts


def snapshot_heartbeat_runtime_authority_database(
    *,
    source_database: Path,
    snapshot_database: Path,
    repo_root_path: Path | None = None,
) -> dict[str, Any]:
    """Create a sidecar-free local-only SQLite snapshot for immutable sampling."""

    _assert_db_authority_disabled()
    root = Path(repo_root_path or repository_root()).resolve()
    expected_database = heartbeat_control_database(root)
    source = source_database.expanduser().resolve()
    if source != expected_database:
        raise HeartbeatShadowError("Heartbeat snapshot source is not the ignored control DB")
    if not source.is_file() or source.is_symlink():
        raise HeartbeatShadowError("Heartbeat snapshot source DB is missing or unsafe")
    target = _repo_local_recovery_database_path(
        root, snapshot_database, "Heartbeat runtime authority snapshot"
    )
    if target.exists() or any(Path(f"{target}{suffix}").exists() for suffix in SQLITE_SIDECAR_SUFFIXES):
        raise HeartbeatShadowError("Heartbeat runtime authority snapshot target already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    source_sidecars = _sqlite_sidecars(source)
    try:
        with sqlite3.connect(source, isolation_level=None) as source_connection:
            source_connection.execute("PRAGMA query_only=ON")
            with sqlite3.connect(target) as target_connection:
                source_connection.backup(target_connection)
                target_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                target_connection.execute("PRAGMA journal_mode=DELETE")
                quick_check = target_connection.execute("PRAGMA quick_check").fetchone()
                if quick_check != ("ok",):
                    raise HeartbeatShadowError("Heartbeat runtime snapshot failed integrity check")
    except HeartbeatShadowError:
        target.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(f"{target}{suffix}").unlink(missing_ok=True)
        raise
    except sqlite3.Error as exc:
        target.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(f"{target}{suffix}").unlink(missing_ok=True)
        raise HeartbeatShadowError("Heartbeat runtime snapshot could not be created") from exc
    target.chmod(0o600)
    _remove_checkpointed_snapshot_sidecars(target)
    if _sqlite_sidecars(target):
        raise HeartbeatShadowError("Heartbeat runtime snapshot is not sidecar-free")
    with sqlite3.connect(f"{target.as_uri()}?mode=ro&immutable=1", uri=True) as connection:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
        if quick_check != ("ok",):
            raise HeartbeatShadowError("Heartbeat runtime snapshot immutable check failed")
    counts = _runtime_authority_counts(target)
    return {
        "schema_version": "p03-heartbeat-runtime-authority-snapshot.v1",
        "status": "pass",
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "source_database": source.relative_to(root).as_posix(),
        "source_sidecars_observed": [sidecar.name for sidecar in source_sidecars],
        "snapshot_database": target.relative_to(root).as_posix(),
        "snapshot_sha256": _sha256_file(target),
        "snapshot_sidecars_present": False,
        "local_recovery_only": True,
        "packaging_retrieval_denied": True,
        "runtime_authority_counts": counts,
    }


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rollback_recovery_database(root: Path, rollback_id: str, name: str) -> Path:
    return _repo_local_recovery_database_path(
        root,
        root
        / "state/agentic-os/backups/heartbeat-shadow-rollback"
        / rollback_id
        / name,
        "Heartbeat rollback local recovery database",
    )


def _sidecar_receipts(database: Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for sidecar in _sqlite_sidecars(database):
        receipts.append(
            {
                "name": sidecar.name,
                "size_bytes": sidecar.stat().st_size,
                "sha256": _sha256_file(sidecar),
            }
        )
    return receipts


def _assert_no_live_rollback_sidecars(database: Path) -> None:
    for sidecar in _sqlite_sidecars(database):
        size = sidecar.stat().st_size
        if sidecar.name.endswith("-wal") and size != 0:
            raise HeartbeatShadowError("Heartbeat shadow DB has live WAL content")
        if sidecar.name.endswith("-journal") and size != 0:
            raise HeartbeatShadowError(
                "Heartbeat shadow DB has live rollback journal content"
            )


def _lock_rollback_source_idle(database: Path) -> tuple[sqlite3.Connection, dict[str, Any]]:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(database, isolation_level=None, timeout=0.1)
        connection.execute("PRAGMA busy_timeout=100")
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if not checkpoint or checkpoint[0] != 0:
            raise HeartbeatShadowError("Heartbeat shadow DB checkpoint is busy")
        connection.execute("BEGIN EXCLUSIVE")
        _assert_no_live_rollback_sidecars(database)
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
    except HeartbeatShadowError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise HeartbeatShadowError(
            "Heartbeat shadow DB is not idle/checkpointable"
        ) from exc
    if quick_check != ("ok",):
        connection.close()
        raise HeartbeatShadowError("Heartbeat shadow DB failed read-only integrity check")
    return connection, {
        "quick_check": "ok",
        "checkpoint": list(checkpoint),
        "source_sidecars": _sidecar_receipts(database),
    }


def _locked_rollback_audit_snapshot(
    source: Path, target: Path, root: Path
) -> dict[str, Any]:
    if target.exists() or any(Path(f"{target}{suffix}").exists() for suffix in SQLITE_SIDECAR_SUFFIXES):
        raise HeartbeatShadowError("Heartbeat runtime authority snapshot target already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(source, target)
        target.chmod(0o600)
        _remove_checkpointed_snapshot_sidecars(target)
        if _sqlite_sidecars(target):
            raise HeartbeatShadowError("Heartbeat runtime snapshot is not sidecar-free")
        with sqlite3.connect(f"{target.as_uri()}?mode=ro&immutable=1", uri=True) as connection:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check != ("ok",):
                raise HeartbeatShadowError("Heartbeat runtime snapshot immutable check failed")
        counts = _runtime_authority_counts(target)
    except HeartbeatShadowError:
        target.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(f"{target}{suffix}").unlink(missing_ok=True)
        raise
    except (OSError, sqlite3.Error) as exc:
        target.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(f"{target}{suffix}").unlink(missing_ok=True)
        raise HeartbeatShadowError("Heartbeat runtime snapshot could not be created") from exc
    return {
        "schema_version": "p03-heartbeat-runtime-authority-snapshot.v1",
        "status": "pass",
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "source_database": source.relative_to(root).as_posix(),
        "source_sidecars_observed": [sidecar.name for sidecar in _sqlite_sidecars(source)],
        "snapshot_database": target.relative_to(root).as_posix(),
        "snapshot_sha256": _sha256_file(target),
        "snapshot_sidecars_present": False,
        "local_recovery_only": True,
        "packaging_retrieval_denied": True,
        "runtime_authority_counts": counts,
    }


def _artifact_projection_set_binds_authority_digest(
    artifact_paths: list[Path], authority_input_digest: object
) -> bool:
    if not _is_sha256(authority_input_digest):
        return False
    for path in artifact_paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(document, Mapping):
            return False
        try:
            projection_digest = document.get("authority_input_digest")
            if projection_digest is None:
                projection_digest = _manifest_authority_digest(document)
        except HeartbeatShadowError:
            return False
        if projection_digest != authority_input_digest:
            return False
    return True


def _rollback_shadow_parity(
    audit_database: Path,
    *,
    repo_root_path: Path,
    authority_input_digest: str,
) -> dict[str, Any]:
    mode_to_audit = {
        "file_authority_shadow": (audit_file_authority_shadow, "file_authority_shadow"),
        "dual_write_shadow": (audit_dual_write_shadow, "dual_write_shadow"),
    }
    with sqlite3.connect(
        f"{audit_database.as_uri()}?mode=ro&immutable=1", uri=True
    ) as connection:
        modes = connection.execute(
            "SELECT mode FROM workflow_authority WHERE workflow=?",
            (HEARTBEAT_WORKFLOW,),
        ).fetchall()
        if len(modes) != 1 or modes[0][0] not in mode_to_audit:
            raise HeartbeatShadowError("Heartbeat rollback lacks shadow parity mode")
        mode = modes[0][0]
        candidates = connection.execute(
            "SELECT run_id FROM runs WHERE workflow=? AND authority_mode=? "
            "AND state='finalized' ORDER BY finalized_at_epoch_ms DESC, run_id DESC",
            (HEARTBEAT_WORKFLOW, mode),
        ).fetchall()
        if not candidates:
            raise HeartbeatShadowError("Heartbeat rollback lacks finalized parity run")
        run_id = None
        projections: list[tuple[Any, ...]] = []
        for candidate in candidates:
            candidate_run_id = candidate[0]
            candidate_projections = connection.execute(
                "SELECT path FROM artifact_projections WHERE run_id=? "
                "AND source_authority=? ORDER BY path",
                (candidate_run_id, mode_to_audit[mode][1]),
            ).fetchall()
            if not candidate_projections:
                continue
            candidate_paths = [repo_root_path / str(row[0]) for row in candidate_projections]
            if not _artifact_projection_set_binds_authority_digest(
                candidate_paths, authority_input_digest
            ):
                continue
            run_id = candidate_run_id
            projections = candidate_projections
            break
        if run_id is None:
            raise HeartbeatShadowError(
                "Heartbeat rollback lacks parity run bound to authority digest"
            )
    if not isinstance(run_id, str) or not run_id:
        raise HeartbeatShadowError("Heartbeat rollback parity run is invalid")
    artifact_paths = [repo_root_path / str(row[0]) for row in projections]
    if not artifact_paths:
        raise HeartbeatShadowError("Heartbeat rollback lacks parity projections")
    audit_function = mode_to_audit[mode][0]
    try:
        audit = audit_function(
            audit_database,
            artifact_paths,
            workflow=HEARTBEAT_WORKFLOW,
            run_id=run_id,
            repo_root_path=repo_root_path,
        )
    except (ShadowBackfillError, sqlite3.Error) as exc:
        raise HeartbeatShadowError("Heartbeat rollback parity audit failed") from exc
    mismatch_count = len(audit.issues)
    if (
        audit.status != "pass"
        or audit.checked_count != len(artifact_paths)
        or mismatch_count != 0
    ):
        raise HeartbeatShadowError("Heartbeat rollback parity is not 100%")
    return {
        "status": "pass",
        "authority_mode": mode,
        "run_id": run_id,
        "checked_count": audit.checked_count,
        "matched_count": len(artifact_paths),
        "mismatch_count": 0,
        "percent": 100,
        "artifact_paths": [
            path.relative_to(repo_root_path).as_posix() for path in artifact_paths
        ],
    }


def _move_database_to_local_backup(source: Path, backup: Path) -> list[str]:
    if backup.exists() or any(Path(f"{backup}{suffix}").exists() for suffix in SQLITE_SIDECAR_SUFFIXES):
        raise HeartbeatShadowError("Heartbeat rollback backup already exists")
    backup.parent.mkdir(parents=True, exist_ok=True)
    sidecars = _sqlite_sidecars(source)
    moved: list[str] = []
    moved_paths: list[tuple[Path, Path]] = []
    try:
        os.replace(source, backup)
        moved_paths.append((backup, source))
        for sidecar in sidecars:
            destination = Path(f"{backup}{sidecar.name.removeprefix(source.name)}")
            os.replace(sidecar, destination)
            moved_paths.append((destination, sidecar))
            moved.append(destination.name)
    except OSError as exc:
        for destination, original in reversed(moved_paths):
            if destination.exists() and not original.exists():
                os.replace(destination, original)
        raise HeartbeatShadowError("Heartbeat rollback backup move failed atomically") from exc
    finally:
        _fsync_directory(backup.parent)
        _fsync_directory(source.parent)
    return moved


def _create_rollback_source_path_guard(source: Path) -> int:
    try:
        source.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise HeartbeatShadowError(
            "Heartbeat shadow DB path was recreated during rollback"
        ) from exc
    except OSError as exc:
        raise HeartbeatShadowError(
            "Heartbeat rollback source path guard could not be created"
        ) from exc
    try:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        try:
            source.rmdir()
        except OSError:
            pass
        raise HeartbeatShadowError(
            "Heartbeat rollback source path guard could not be opened"
        ) from exc
    return descriptor


def _release_rollback_source_path_guard(source: Path, descriptor: int) -> None:
    try:
        descriptor_stat = os.fstat(descriptor)
        try:
            source_stat = source.stat()
        except FileNotFoundError:
            source_stat = None
        os.close(descriptor)
        descriptor = -1
        try:
            if (
                source_stat is not None
                and source_stat.st_dev == descriptor_stat.st_dev
                and source_stat.st_ino == descriptor_stat.st_ino
            ):
                source.rmdir()
            elif source_stat is not None:
                raise HeartbeatShadowError(
                    "Heartbeat rollback source path was replaced before guard removal"
                )
        except OSError as exc:
            raise HeartbeatShadowError(
                "Heartbeat rollback source path guard could not be removed"
            ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remove_recreated_rollback_source_path(source: Path) -> None:
    try:
        if source.is_dir():
            source.rmdir()
        elif source.exists():
            source.unlink()
    except OSError as exc:
        raise HeartbeatShadowError(
            "Heartbeat rollback recreated source path could not be removed"
        ) from exc


def _restore_database_from_local_backup(source: Path, backup: Path) -> None:
    if source.exists():
        raise HeartbeatShadowError("Heartbeat rollback source path blocks restore")
    try:
        os.replace(backup, source)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            backup_sidecar = Path(f"{backup}{suffix}")
            source_sidecar = Path(f"{source}{suffix}")
            if backup_sidecar.exists():
                if source_sidecar.exists():
                    raise HeartbeatShadowError(
                        "Heartbeat rollback sidecar path blocks restore"
                    )
                os.replace(backup_sidecar, source_sidecar)
    except OSError as exc:
        raise HeartbeatShadowError(
            "Heartbeat rollback backup restore failed"
        ) from exc
    finally:
        _fsync_directory(backup.parent)
        _fsync_directory(source.parent)


def run_heartbeat_file_shadow_cycle(
    *,
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
    manifest_path: Path,
    run_id: str,
    database: Path | None = None,
    repo_root_path: Path | None = None,
    observed_at_epoch_ms: int | None = None,
) -> dict[str, Any]:
    root = Path(repo_root_path or repository_root()).resolve()
    expected_database = heartbeat_control_database(root)
    target_database = Path(database or expected_database).expanduser().resolve()
    if target_database != expected_database:
        raise HeartbeatShadowError(
            "Heartbeat shadow DB must use ignored state/agentic-os/control.db"
        )
    target_manifest = _repo_artifact_path(root, manifest_path, "Heartbeat manifest")
    authority_inputs = {
        _repo_artifact_path(root, baseline_path, "Heartbeat baseline"),
        _repo_artifact_path(root, heartbeat_file, "Heartbeat file"),
        _repo_artifact_path(root, live_config_path, "Heartbeat live config"),
    }
    if target_manifest in authority_inputs:
        raise HeartbeatShadowError(
            "Heartbeat manifest output must not overwrite authority inputs"
        )
    manifest = heartbeat_authority_manifest(
        baseline_path,
        heartbeat_file,
        live_config_path,
        observed_at_epoch_ms=observed_at_epoch_ms,
    )
    manifest_sha256 = _atomic_write_json(target_manifest, manifest)
    try:
        backfill = backfill_file_authority_shadow(
            target_database,
            (target_manifest,),
            workflow=HEARTBEAT_WORKFLOW,
            run_id=run_id,
            repo_root_path=root,
        )
        audit = audit_file_authority_shadow(
            target_database,
            (target_manifest,),
            workflow=HEARTBEAT_WORKFLOW,
            run_id=run_id,
            repo_root_path=root,
        )
    except ShadowBackfillError as exc:
        raise HeartbeatShadowError(str(exc)) from exc
    live_manifest = heartbeat_authority_manifest(
        baseline_path,
        heartbeat_file,
        live_config_path,
        observed_at_epoch_ms=observed_at_epoch_ms,
    )
    authority_digest = _manifest_authority_digest(manifest)
    if _manifest_authority_digest(live_manifest) != authority_digest:
        raise HeartbeatShadowError("Heartbeat authority changed during shadow projection")
    counts = _runtime_authority_counts(target_database)
    if any(counts.values()):
        raise HeartbeatShadowError("Heartbeat shadow DB contains runtime authority rows")
    projection_count = len(backfill.projections)
    mismatch_count = len(audit.issues)
    if (
        audit.status != "pass"
        or projection_count != 1
        or audit.checked_count != projection_count
        or mismatch_count != 0
    ):
        raise HeartbeatShadowError("Heartbeat file-authority shadow parity failed")
    return {
        "schema_version": "p03-heartbeat-shadow-cycle-receipt.v1",
        "status": "pass",
        "workflow": HEARTBEAT_WORKFLOW,
        "run_id": run_id,
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "control_db_ignored": True,
        "manifest_path": target_manifest.relative_to(root).as_posix(),
        "manifest_sha256": manifest_sha256,
        "authority_input_digest": authority_digest,
        "projection_count": projection_count,
        "parity": {
            "checked_count": audit.checked_count,
            "matched_count": projection_count,
            "mismatch_count": mismatch_count,
            "percent": 100,
            "status": "pass",
        },
        "runtime_authority_counts": counts,
    }


def _validate_file_shadow_receipt(receipt: Mapping[str, Any]) -> None:
    if set(receipt) != {
        "authority",
        "authority_input_digest",
        "control_db_ignored",
        "db_authority_enabled",
        "manifest_path",
        "manifest_sha256",
        "parity",
        "projection_count",
        "run_id",
        "runtime_authority_counts",
        "schema_version",
        "status",
        "workflow",
    }:
        raise HeartbeatShadowError("file-shadow receipt fields are invalid")
    parity = receipt.get("parity")
    counts = receipt.get("runtime_authority_counts")
    if (
        receipt.get("schema_version") != "p03-heartbeat-shadow-cycle-receipt.v1"
        or receipt.get("status") != "pass"
        or receipt.get("workflow") != HEARTBEAT_WORKFLOW
        or receipt.get("authority") != "file_artifacts"
        or receipt.get("db_authority_enabled") is not False
        or receipt.get("control_db_ignored") is not True
        or not _is_sha256(receipt.get("manifest_sha256"))
        or not _is_sha256(receipt.get("authority_input_digest"))
        or type(receipt.get("projection_count")) is not int
        or receipt.get("projection_count") != 1
        or not isinstance(parity, Mapping)
        or dict(parity)
        != {
            "checked_count": 1,
            "matched_count": 1,
            "mismatch_count": 0,
            "percent": 100,
            "status": "pass",
        }
        or not isinstance(counts, Mapping)
        or set(counts) != set(RUNTIME_AUTHORITY_COUNT_KEYS)
        or any(type(value) is not int or value != 0 for value in counts.values())
    ):
        raise HeartbeatShadowError("file-shadow receipt is not an exact 100% parity PASS")
    _required_identity("file-shadow run_id", receipt.get("run_id"))
    _required_identity("file-shadow manifest_path", receipt.get("manifest_path"))


def run_heartbeat_dual_write_projection(
    *,
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
    projection_receipt_path: Path,
    run_id: str,
    prior_file_shadow_receipt: Mapping[str, Any],
    database: Path | None = None,
    repo_root_path: Path | None = None,
    observed_at_epoch_ms: int | None = None,
) -> dict[str, Any]:
    """Project one derived parity receipt after a file-shadow PASS.

    The derived receipt is never an input to Heartbeat dispatch or decisions.
    """

    _validate_file_shadow_receipt(prior_file_shadow_receipt)
    root = Path(repo_root_path or repository_root()).resolve()
    expected_database = heartbeat_control_database(root)
    target_database = Path(database or expected_database).expanduser().resolve()
    if target_database != expected_database:
        raise HeartbeatShadowError("Heartbeat dual-write DB placement is invalid")
    target_projection = _repo_artifact_path(
        root, projection_receipt_path, "Heartbeat dual-write projection"
    )
    prior_manifest = _repo_artifact_path(
        root,
        root / str(prior_file_shadow_receipt["manifest_path"]),
        "Heartbeat prior file-shadow manifest",
    )
    if (
        not prior_manifest.is_file()
        or _sha256_file(prior_manifest)
        != prior_file_shadow_receipt["manifest_sha256"]
    ):
        raise HeartbeatShadowError(
            "Heartbeat file-shadow preflight manifest is missing or drifted"
        )
    try:
        prior_audit = audit_file_authority_shadow(
            target_database,
            (prior_manifest,),
            workflow=HEARTBEAT_WORKFLOW,
            run_id=str(prior_file_shadow_receipt["run_id"]),
            repo_root_path=root,
        )
    except (ShadowBackfillError, sqlite3.Error) as exc:
        raise HeartbeatShadowError(
            "Heartbeat file-shadow preflight DB projection is not auditable"
        ) from exc
    if prior_audit.status != "pass" or prior_audit.checked_count != 1:
        raise HeartbeatShadowError(
            "Heartbeat file-shadow preflight DB projection is not an exact PASS"
        )
    manifest = heartbeat_authority_manifest(
        baseline_path,
        heartbeat_file,
        live_config_path,
        observed_at_epoch_ms=observed_at_epoch_ms,
    )
    authority_digest = _manifest_authority_digest(manifest)
    if authority_digest != prior_file_shadow_receipt.get("authority_input_digest"):
        raise HeartbeatShadowError("Heartbeat authority drifted after file-shadow preflight")
    content = {
        "schema_version": "p03-heartbeat-dual-write-projection.v1",
        "workflow": HEARTBEAT_WORKFLOW,
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "authority_input_digest": authority_digest,
        "source_file_shadow_run_id": prior_file_shadow_receipt.get("run_id"),
    }
    result = dual_write_shadow_artifact(
        target_database,
        target_projection,
        (_canonical_json(content) + "\n").encode("utf-8"),
        workflow=HEARTBEAT_WORKFLOW,
        run_id=run_id,
        risk_class="R1",
        risk_dominance="R1",
        repo_root_path=root,
    )
    audit = audit_dual_write_shadow(
        target_database,
        (target_projection,),
        workflow=HEARTBEAT_WORKFLOW,
        run_id=run_id,
        repo_root_path=root,
    )
    counts = _runtime_authority_counts(target_database)
    mismatch_count = len(audit.issues)
    if (
        audit.status != "pass"
        or audit.checked_count != 1
        or mismatch_count != 0
        or any(counts.values())
    ):
        raise HeartbeatShadowError("Heartbeat dual-write projection parity failed")
    return {
        **content,
        "status": "pass",
        "run_id": run_id,
        "projection_sha256": result.projection.sha256,
        "projection_path": target_projection.relative_to(root).as_posix(),
        "parity": {
            "checked_count": audit.checked_count,
            "matched_count": 1,
            "mismatch_count": mismatch_count,
            "percent": 100,
            "status": "pass",
        },
        "runtime_authority_counts": counts,
    }


def heartbeat_parity_sample(
    *,
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
    projected_artifact: Path,
    run_id: str,
    authority_input_digest: str,
    authority_mode: str,
    database: Path,
    runtime_audit_database: Path | None = None,
    sampled_at_epoch_ms: int,
    sampled_at_monotonic_ms: int | None = None,
    repo_root_path: Path | None = None,
) -> dict[str, Any]:
    if type(sampled_at_epoch_ms) is not int or sampled_at_epoch_ms <= 0:
        raise HeartbeatShadowError("sample time must be a positive integer")
    if sampled_at_monotonic_ms is None:
        sampled_at_monotonic_ms = time.monotonic_ns() // 1_000_000
    if type(sampled_at_monotonic_ms) is not int or sampled_at_monotonic_ms <= 0:
        raise HeartbeatShadowError("sample monotonic time must be a positive integer")
    if not _is_sha256(authority_input_digest):
        raise HeartbeatShadowError("sample authority input digest must be SHA-256")
    _required_identity("sample run_id", run_id)
    root = Path(repo_root_path or repository_root()).resolve()
    expected_database = heartbeat_control_database(root)
    target_database = database.expanduser().resolve()
    if target_database != expected_database:
        raise HeartbeatShadowError("Heartbeat sample DB placement is invalid")
    audit_database = target_database
    if runtime_audit_database is not None:
        audit_database = _repo_local_recovery_database_path(
            root,
            runtime_audit_database,
            "Heartbeat sample runtime audit database",
        )
    audit_function = (
        audit_file_authority_shadow
        if authority_mode == "file_authority_shadow"
        else audit_dual_write_shadow
        if authority_mode == "dual_write_shadow"
        else None
    )
    if audit_function is None:
        raise HeartbeatShadowError("Heartbeat sample authority mode is not shadow-only")
    target_projection = _repo_artifact_path(
        root, projected_artifact, "Heartbeat sampled projection"
    )
    current_digest: str | None = None
    observation_error: str | None = None
    privacy_violation = False
    try:
        manifest = heartbeat_authority_manifest(
            baseline_path,
            heartbeat_file,
            live_config_path,
            observed_at_epoch_ms=sampled_at_epoch_ms,
        )
        current_digest = _manifest_authority_digest(manifest)
    except HeartbeatShadowError as exc:
        privacy_violation = any(
            marker in str(exc).casefold() for marker in ("privacy", "sensitive")
        )
        observation_error = (
            "authority_manifest_privacy_violation"
            if privacy_violation
            else "authority_manifest_invalid"
        )
    try:
        audit = audit_function(
            audit_database,
            (target_projection,),
            workflow=HEARTBEAT_WORKFLOW,
            run_id=run_id,
            repo_root_path=root,
        )
        audit_status = audit.status
    except (ShadowBackfillError, sqlite3.Error):
        audit_status = "fail"
        observation_error = observation_error or "projection_audit_error"
    counts_observed = True
    try:
        counts = _runtime_authority_counts(audit_database)
    except (HeartbeatShadowError, sqlite3.Error):
        counts_observed = False
        counts = {key: 0 for key in RUNTIME_AUTHORITY_COUNT_KEYS}
        observation_error = observation_error or "runtime_authority_audit_error"
    counters = {key: 0 for key in SOAK_COUNTER_KEYS}
    if current_digest != authority_input_digest or audit_status != "pass":
        counters["projection_drift"] = 1
    counters["duplicate_spawn"] = counts["duplicate_spawn_identity_groups"]
    counters["orphan_lease"] = counts["lease_rows"]
    counters["unknown_or_unowned_session"] = (
        counts["spawn_request_rows"]
        + counts["session_rows"]
        + counts["lifecycle_rpc_intent_rows"]
    )
    if not counts_observed:
        counters["unknown_or_unowned_session"] += 1
    if privacy_violation:
        counters["privacy_violation"] = 1
    passed = not any(counters.values()) and observation_error is None
    return {
        "sampled_at_epoch_ms": sampled_at_epoch_ms,
        "sampled_at_monotonic_ms": sampled_at_monotonic_ms,
        "status": "pass" if passed else "fail",
        "authority_mode": authority_mode,
        "expected_authority_input_digest": authority_input_digest,
        "observed_authority_input_digest": current_digest,
        "parity_status": "pass" if passed else "fail",
        "parity_percent": 100 if passed else 0,
        "db_authority_enabled": False,
        "runtime_authority_counts": counts,
        "runtime_authority_counts_observed": counts_observed,
        "observation_error": observation_error,
        "counters": counters,
    }


def new_heartbeat_soak_receipt(
    *,
    run_id: str,
    authority_input_digest: str,
    started_at_epoch_ms: int,
    duration_hours: int,
    sample_interval_seconds: int,
    started_at_monotonic_ms: int | None = None,
) -> dict[str, Any]:
    _assert_db_authority_disabled()
    normalized_run_id = _required_identity("Heartbeat soak run_id", run_id)
    if not _is_sha256(authority_input_digest):
        raise HeartbeatShadowError("Heartbeat soak authority digest must be SHA-256")
    if (
        type(duration_hours) is not int
        or not MIN_SOAK_HOURS <= duration_hours <= MAX_SOAK_HOURS
    ):
        raise HeartbeatShadowError("Heartbeat soak duration must be in [24,72] hours")
    if (
        type(sample_interval_seconds) is not int
        or not 60 <= sample_interval_seconds <= 3600
    ):
        raise HeartbeatShadowError(
            "Heartbeat soak sample interval must be in [60,3600] seconds"
        )
    if type(started_at_epoch_ms) is not int or started_at_epoch_ms <= 0:
        raise HeartbeatShadowError("Heartbeat soak start must be positive epoch ms")
    if started_at_monotonic_ms is None:
        started_at_monotonic_ms = time.monotonic_ns() // 1_000_000
    if type(started_at_monotonic_ms) is not int or started_at_monotonic_ms <= 0:
        raise HeartbeatShadowError("Heartbeat soak start must be positive monotonic ms")
    return {
        "schema_version": "p03-heartbeat-soak-receipt.v1",
        "status": "in_progress",
        "workflow": HEARTBEAT_WORKFLOW,
        "run_id": normalized_run_id,
        "authority": "file_artifacts",
        "db_authority_enabled": False,
        "authority_input_digest": authority_input_digest,
        "started_at_epoch_ms": started_at_epoch_ms,
        "deadline_epoch_ms": started_at_epoch_ms + duration_hours * 3_600_000,
        "started_at_monotonic_ms": started_at_monotonic_ms,
        "deadline_monotonic_ms": started_at_monotonic_ms + duration_hours * 3_600_000,
        "duration_hours": duration_hours,
        "sample_interval_seconds": sample_interval_seconds,
        "samples": [],
        "aggregate_counters": {key: 0 for key in SOAK_COUNTER_KEYS},
    }


def _validate_heartbeat_soak_sample(
    sample: Mapping[str, Any], *, expected_authority_input_digest: str
) -> None:
    if set(sample) != SOAK_SAMPLE_FIELDS:
        raise HeartbeatShadowError("Heartbeat soak sample fields are invalid")
    sampled_at = sample.get("sampled_at_epoch_ms")
    sampled_monotonic = sample.get("sampled_at_monotonic_ms")
    counters = sample.get("counters")
    counts = sample.get("runtime_authority_counts")
    observed_digest = sample.get("observed_authority_input_digest")
    if (
        type(sampled_at) is not int
        or sampled_at <= 0
        or type(sampled_monotonic) is not int
        or sampled_monotonic <= 0
        or sample.get("status") not in {"pass", "fail"}
        or sample.get("authority_mode")
        not in {"file_authority_shadow", "dual_write_shadow"}
        or sample.get("expected_authority_input_digest")
        != expected_authority_input_digest
        or (observed_digest is not None and not _is_sha256(observed_digest))
        or sample.get("parity_status") not in {"pass", "fail"}
        or sample.get("parity_percent") not in {0, 100}
        or sample.get("db_authority_enabled") is not False
        or sample.get("observation_error")
        not in {
            None,
            "authority_manifest_invalid",
            "authority_manifest_privacy_violation",
            "projection_audit_error",
            "runtime_authority_audit_error",
        }
        or type(sample.get("runtime_authority_counts_observed")) is not bool
    ):
        raise HeartbeatShadowError("Heartbeat soak sample contract is invalid")
    if not isinstance(counters, Mapping) or set(counters) != set(SOAK_COUNTER_KEYS):
        raise HeartbeatShadowError("Heartbeat soak sample counters are invalid")
    if any(type(value) is not int or value < 0 for value in counters.values()):
        raise HeartbeatShadowError("Heartbeat soak sample counters must be non-negative")
    if not isinstance(counts, Mapping) or set(counts) != set(RUNTIME_AUTHORITY_COUNT_KEYS):
        raise HeartbeatShadowError("Heartbeat soak runtime authority counts are invalid")
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise HeartbeatShadowError("Heartbeat soak runtime authority counts are invalid")
    if not sample["runtime_authority_counts_observed"] and (
        sample.get("observation_error") != "runtime_authority_audit_error"
        or counters.get("unknown_or_unowned_session", 0) < 1
    ):
        raise HeartbeatShadowError(
            "Heartbeat soak unobserved runtime authority must fail closed"
        )
    passed = (
        observed_digest == expected_authority_input_digest
        and sample.get("parity_status") == "pass"
        and sample.get("parity_percent") == 100
        and sample.get("observation_error") is None
        and not any(counters.values())
        and not any(counts.values())
    )
    if (sample.get("status") == "pass") is not passed:
        raise HeartbeatShadowError("Heartbeat soak sample status is inconsistent")
    if not passed and sample.get("parity_status") != "fail":
        raise HeartbeatShadowError("Heartbeat soak failed sample must fail parity")


def append_heartbeat_soak_sample(
    receipt: Mapping[str, Any], sample: Mapping[str, Any]
) -> dict[str, Any]:
    _assert_db_authority_disabled()
    validate_heartbeat_soak_receipt(receipt)
    if receipt["status"] != "in_progress":
        raise HeartbeatShadowError("completed/failed Heartbeat soak cannot accept samples")
    _validate_heartbeat_soak_sample(
        sample,
        expected_authority_input_digest=receipt["authority_input_digest"],
    )
    sampled_at = sample.get("sampled_at_epoch_ms")
    sampled_monotonic = sample.get("sampled_at_monotonic_ms")
    if type(sampled_at) is not int:
        raise HeartbeatShadowError("Heartbeat soak sample time is invalid")
    if type(sampled_monotonic) is not int:
        raise HeartbeatShadowError("Heartbeat soak monotonic sample time is invalid")
    samples = [dict(item) for item in receipt["samples"]]
    if samples:
        minimum = samples[-1]["sampled_at_epoch_ms"] + receipt["sample_interval_seconds"] * 1000
        minimum_monotonic = (
            samples[-1]["sampled_at_monotonic_ms"]
            + receipt["sample_interval_seconds"] * 1000
        )
        if sampled_at < minimum:
            raise HeartbeatShadowError("Heartbeat soak sample interval is too short")
        if sampled_monotonic < minimum_monotonic:
            raise HeartbeatShadowError("Heartbeat soak monotonic interval is too short")
        maximum = samples[-1]["sampled_at_epoch_ms"] + receipt["sample_interval_seconds"] * 2000
        maximum_monotonic = (
            samples[-1]["sampled_at_monotonic_ms"]
            + receipt["sample_interval_seconds"] * 2000
        )
        if sampled_at > maximum:
            raise HeartbeatShadowError("Heartbeat soak sample interval has a coverage gap")
        if sampled_monotonic > maximum_monotonic:
            raise HeartbeatShadowError("Heartbeat soak monotonic interval has a coverage gap")
    elif sampled_at < receipt["started_at_epoch_ms"]:
        raise HeartbeatShadowError("Heartbeat soak sample precedes start")
    elif sampled_monotonic < receipt["started_at_monotonic_ms"]:
        raise HeartbeatShadowError("Heartbeat soak monotonic sample precedes start")
    elif sampled_at > receipt["started_at_epoch_ms"] + receipt["sample_interval_seconds"] * 1000:
        raise HeartbeatShadowError("Heartbeat soak first sample missed its coverage window")
    elif sampled_monotonic > receipt["started_at_monotonic_ms"] + receipt["sample_interval_seconds"] * 1000:
        raise HeartbeatShadowError(
            "Heartbeat soak first monotonic sample missed its coverage window"
        )
    if sampled_at > receipt["deadline_epoch_ms"] + receipt["sample_interval_seconds"] * 1000:
        raise HeartbeatShadowError("Heartbeat soak sample exceeds bounded deadline")
    if sampled_monotonic > receipt["deadline_monotonic_ms"] + receipt["sample_interval_seconds"] * 1000:
        raise HeartbeatShadowError("Heartbeat soak monotonic sample exceeds bounded deadline")
    samples.append(dict(sample))
    maximum_samples = (
        receipt["duration_hours"] * 3_600 // receipt["sample_interval_seconds"] + 2
    )
    if len(samples) > maximum_samples:
        raise HeartbeatShadowError("Heartbeat soak sample count exceeds its bounded window")
    aggregate = {
        key: sum(item["counters"][key] for item in samples) for key in SOAK_COUNTER_KEYS
    }
    status = (
        "failed"
        if sample.get("status") != "pass" or any(aggregate.values())
        else "in_progress"
    )
    if (
        status == "in_progress"
        and sampled_at >= receipt["deadline_epoch_ms"]
        and sampled_monotonic >= receipt["deadline_monotonic_ms"]
    ):
        status = "complete"
    result = {
        **dict(receipt),
        "samples": samples,
        "aggregate_counters": aggregate,
        "status": status,
    }
    validate_heartbeat_soak_receipt(result)
    return result


def validate_heartbeat_soak_receipt(receipt: Mapping[str, Any]) -> None:
    _assert_db_authority_disabled()
    expected = {
        "schema_version",
        "status",
        "workflow",
        "run_id",
        "authority",
        "db_authority_enabled",
        "authority_input_digest",
        "started_at_epoch_ms",
        "deadline_epoch_ms",
        "started_at_monotonic_ms",
        "deadline_monotonic_ms",
        "duration_hours",
        "sample_interval_seconds",
        "samples",
        "aggregate_counters",
    }
    if set(receipt) != expected:
        raise HeartbeatShadowError("Heartbeat soak receipt fields are invalid")
    if (
        receipt.get("schema_version") != "p03-heartbeat-soak-receipt.v1"
        or receipt.get("workflow") != HEARTBEAT_WORKFLOW
        or receipt.get("authority") != "file_artifacts"
        or receipt.get("db_authority_enabled") is not False
        or receipt.get("status") not in {"in_progress", "complete", "failed"}
    ):
        raise HeartbeatShadowError("Heartbeat soak receipt authority contract is invalid")
    _required_identity("Heartbeat soak run_id", receipt.get("run_id"))
    authority_digest = receipt.get("authority_input_digest")
    if not _is_sha256(authority_digest):
        raise HeartbeatShadowError("Heartbeat soak authority digest is invalid")
    duration = receipt.get("duration_hours")
    interval = receipt.get("sample_interval_seconds")
    if type(duration) is not int or not MIN_SOAK_HOURS <= duration <= MAX_SOAK_HOURS:
        raise HeartbeatShadowError("Heartbeat soak duration is invalid")
    if type(interval) is not int or not 60 <= interval <= 3600:
        raise HeartbeatShadowError("Heartbeat soak interval is invalid")
    started = receipt.get("started_at_epoch_ms")
    deadline = receipt.get("deadline_epoch_ms")
    started_monotonic = receipt.get("started_at_monotonic_ms")
    deadline_monotonic = receipt.get("deadline_monotonic_ms")
    if (
        type(started) is not int
        or type(deadline) is not int
        or deadline != started + duration * 3_600_000
        or type(started_monotonic) is not int
        or started_monotonic <= 0
        or type(deadline_monotonic) is not int
        or deadline_monotonic != started_monotonic + duration * 3_600_000
    ):
        raise HeartbeatShadowError("Heartbeat soak deadline is invalid")
    samples = receipt.get("samples")
    if not isinstance(samples, list):
        raise HeartbeatShadowError("Heartbeat soak samples must be a list")
    aggregate = receipt.get("aggregate_counters")
    if not isinstance(aggregate, Mapping) or set(aggregate) != set(SOAK_COUNTER_KEYS):
        raise HeartbeatShadowError("Heartbeat soak aggregate counters are invalid")
    if any(type(value) is not int or value < 0 for value in aggregate.values()):
        raise HeartbeatShadowError("Heartbeat soak aggregate counters are invalid")
    maximum_samples = duration * 3_600 // interval + 2
    if len(samples) > maximum_samples:
        raise HeartbeatShadowError("Heartbeat soak sample count exceeds its bounded window")
    previous_sampled_at: int | None = None
    previous_sampled_monotonic: int | None = None
    recomputed = {key: 0 for key in SOAK_COUNTER_KEYS}
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise HeartbeatShadowError("Heartbeat soak sample must be an object")
        _validate_heartbeat_soak_sample(
            sample,
            expected_authority_input_digest=authority_digest,
        )
        sampled_at = sample["sampled_at_epoch_ms"]
        sampled_monotonic = sample["sampled_at_monotonic_ms"]
        if sampled_at < started:
            raise HeartbeatShadowError("Heartbeat soak sample precedes start")
        if sampled_monotonic < started_monotonic:
            raise HeartbeatShadowError("Heartbeat soak monotonic sample precedes start")
        if sampled_at > deadline + interval * 1000:
            raise HeartbeatShadowError("Heartbeat soak sample exceeds bounded deadline")
        if sampled_monotonic > deadline_monotonic + interval * 1000:
            raise HeartbeatShadowError("Heartbeat soak monotonic sample exceeds bounded deadline")
        if previous_sampled_at is not None and (
            sampled_at < previous_sampled_at + interval * 1000
        ):
            raise HeartbeatShadowError("Heartbeat soak sample interval is too short")
        if previous_sampled_monotonic is not None and (
            sampled_monotonic < previous_sampled_monotonic + interval * 1000
        ):
            raise HeartbeatShadowError("Heartbeat soak monotonic interval is too short")
        if previous_sampled_at is not None and (
            sampled_at > previous_sampled_at + interval * 2000
        ):
            raise HeartbeatShadowError("Heartbeat soak sample interval has a coverage gap")
        if previous_sampled_monotonic is not None and (
            sampled_monotonic > previous_sampled_monotonic + interval * 2000
        ):
            raise HeartbeatShadowError(
                "Heartbeat soak monotonic interval has a coverage gap"
            )
        if previous_sampled_at is None and sampled_at > started + interval * 1000:
            raise HeartbeatShadowError("Heartbeat soak first sample missed its coverage window")
        if (
            previous_sampled_monotonic is None
            and sampled_monotonic > started_monotonic + interval * 1000
        ):
            raise HeartbeatShadowError(
                "Heartbeat soak first monotonic sample missed its coverage window"
            )
        previous_sampled_at = sampled_at
        previous_sampled_monotonic = sampled_monotonic
        for key in SOAK_COUNTER_KEYS:
            recomputed[key] += sample["counters"][key]
    if dict(aggregate) != recomputed:
        raise HeartbeatShadowError("Heartbeat soak aggregate counters do not match samples")
    if receipt["status"] == "complete":
        if not samples or samples[-1].get("sampled_at_epoch_ms", 0) < deadline:
            raise HeartbeatShadowError("Heartbeat soak cannot complete before 24-72h deadline")
        if not samples or samples[-1].get("sampled_at_monotonic_ms", 0) < deadline_monotonic:
            raise HeartbeatShadowError(
                "Heartbeat soak cannot complete before monotonic 24-72h deadline"
            )
        if any(aggregate.values()) or any(item.get("status") != "pass" for item in samples):
            raise HeartbeatShadowError("Heartbeat soak completion contains violations")
    elif receipt["status"] == "failed":
        if not samples or samples[-1].get("status") != "fail":
            raise HeartbeatShadowError("Heartbeat soak failed status lacks a failed sample")
    else:
        if any(sample.get("status") != "pass" for sample in samples):
            raise HeartbeatShadowError("Heartbeat soak in-progress state contains a failure")
        if samples and samples[-1].get("sampled_at_epoch_ms", 0) >= deadline:
            raise HeartbeatShadowError("Heartbeat soak remained in progress after its deadline")
        if samples and samples[-1].get("sampled_at_monotonic_ms", 0) >= deadline_monotonic:
            raise HeartbeatShadowError(
                "Heartbeat soak remained in progress after its monotonic deadline"
            )


def persist_heartbeat_soak_receipt(
    receipt_path: Path,
    receipt: Mapping[str, Any],
    *,
    repo_root_path: Path | None = None,
) -> str:
    """Atomically persist one sanitized bounded-soak receipt inside the worktree."""

    _assert_db_authority_disabled()
    validate_heartbeat_soak_receipt(receipt)
    root = Path(repo_root_path or repository_root()).resolve()
    target = _repo_artifact_path(root, receipt_path, "Heartbeat soak receipt")
    return _atomic_write_json(target, receipt)


def force_heartbeat_file_authority_rollback(
    *,
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
    database: Path,
    authority_input_digest: str,
    rollback_id: str,
    receipt_path: Path,
    observed_at_epoch_ms: int | None = None,
    repo_root_path: Path | None = None,
) -> dict[str, Any]:
    """Recoverably remove the shadow DB and prove the file view is unchanged."""

    if not rollback_id or any(
        character
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in rollback_id
    ):
        raise HeartbeatShadowError("rollback_id contains unsafe characters")
    if not _is_sha256(authority_input_digest):
        raise HeartbeatShadowError("Heartbeat rollback authority digest is invalid")
    root = Path(repo_root_path or repository_root()).resolve()
    target_receipt = _repo_artifact_path(root, receipt_path, "Heartbeat rollback receipt")
    target = database.expanduser().resolve()
    expected = heartbeat_control_database(root)
    if target != expected:
        raise HeartbeatShadowError("Heartbeat rollback target is not the ignored control DB")
    if not target.is_file():
        raise HeartbeatShadowError("Heartbeat shadow DB is missing")
    if target_receipt.exists():
        raise HeartbeatShadowError("Heartbeat rollback receipt already exists")
    audit_snapshot = _rollback_recovery_database(root, rollback_id, "audit-snapshot.db")
    backup = _rollback_recovery_database(root, rollback_id, target.name)
    if backup.exists() or any(Path(f"{backup}{suffix}").exists() for suffix in SQLITE_SIDECAR_SUFFIXES):
        raise HeartbeatShadowError("Heartbeat rollback backup already exists")
    assert_privacy_preflight(root, database_paths=(target, audit_snapshot, backup))
    lock_connection, source_idle = _lock_rollback_source_idle(target)
    source_path_guard: int | None = None
    backup_created = False
    receipt_written = False
    try:
        snapshot = _locked_rollback_audit_snapshot(target, audit_snapshot, root)
        counts = dict(snapshot["runtime_authority_counts"])
        if any(counts.values()):
            raise HeartbeatShadowError("Heartbeat rollback found runtime authority rows")
        manifest = heartbeat_authority_manifest(
            baseline_path,
            heartbeat_file,
            live_config_path,
            observed_at_epoch_ms=observed_at_epoch_ms,
        )
        if _manifest_authority_digest(manifest) != authority_input_digest:
            raise HeartbeatShadowError("Heartbeat file authority drifted before rollback")
        parity = _rollback_shadow_parity(
            audit_snapshot,
            repo_root_path=root,
            authority_input_digest=authority_input_digest,
        )
        source_sha256 = _sha256_file(target)
        moved_sidecars = _move_database_to_local_backup(target, backup)
        backup_created = True
        source_path_guard = _create_rollback_source_path_guard(target)
        backup_sha256 = _sha256_file(backup)
        if backup_sha256 != source_sha256:
            raise HeartbeatShadowError("Heartbeat rollback backup hash mismatch")
        recreated = heartbeat_authority_manifest(
            baseline_path,
            heartbeat_file,
            live_config_path,
            observed_at_epoch_ms=observed_at_epoch_ms,
        )
        recreated_digest = _manifest_authority_digest(recreated)
        if recreated_digest != authority_input_digest:
            raise HeartbeatShadowError(
                "Heartbeat file-authority view was not recreated exactly"
            )
        receipt = {
            "schema_version": "p03-heartbeat-forced-rollback-receipt.v1",
            "status": "pass",
            "workflow": HEARTBEAT_WORKFLOW,
            "authority": "file_artifacts",
            "db_authority_enabled": False,
            "authority_input_digest": recreated_digest,
            "rollback_id": rollback_id,
            "file_authority_view_recreated": True,
            "parity": parity,
            "parity_percent": 100,
            "shadow_database_removed": True,
            "recoverable_local_backup_created": True,
            "recoverable_local_backup_path": backup.relative_to(root).as_posix(),
            "recoverable_local_backup_sha256": backup_sha256,
            "source_database_sha256_before_rollback": source_sha256,
            "source_sidecars_before_rollback": source_idle["source_sidecars"],
            "source_sidecars_moved_to_backup": moved_sidecars,
            "backup_sidecars": _sidecar_receipts(backup),
            "audit_snapshot_database": audit_snapshot.relative_to(root).as_posix(),
            "audit_snapshot_sha256": snapshot["snapshot_sha256"],
            "audit_snapshot_sidecars_present": False,
            "runtime_authority_counts_before_rollback": counts,
            "source_database_idle_check": source_idle["quick_check"],
            "local_recovery_only": True,
            "packaging_retrieval_denied": True,
            "production_gateway_mutated": False,
            "production_config_mutated": False,
            "production_service_mutated": False,
            "production_cron_mutated": False,
            "production_authority_mutated": False,
            "production_session_or_lease_authority_left": False,
        }
        _atomic_write_json(target_receipt, receipt)
        receipt_written = True
    finally:
        active_error = sys.exc_info()[1]
        release_error: BaseException | None = None
        restore_error: BaseException | None = None
        try:
            if source_path_guard is not None:
                _release_rollback_source_path_guard(target, source_path_guard)
                source_path_guard = None
        except BaseException as exc:
            release_error = exc
        finally:
            if backup_created and not receipt_written:
                if target.exists():
                    _remove_recreated_rollback_source_path(target)
                try:
                    _restore_database_from_local_backup(target, backup)
                except BaseException as exc:
                    restore_error = exc
        if restore_error is not None:
            raise restore_error
        if release_error is not None and active_error is None:
            raise release_error
        try:
            lock_connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        lock_connection.close()
    if target.exists():
        raise HeartbeatShadowError("Heartbeat shadow DB remains after rollback")
    return receipt
