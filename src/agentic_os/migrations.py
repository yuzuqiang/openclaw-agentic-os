"""Versioned, hash-pinned SQLite migration runner."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

from .privacy import assert_privacy_preflight
from .predicates import (
    MAX_FILE_EVIDENCE_BYTES,
    PredicateContractError,
    _assert_predicate_path_allowed,
    _is_credential_path_denied,
    _reject_symlink_evidence_path,
)
from .slo_contracts import (
    SLO_QUERY_COUNT,
    slo_query_contracts_for_schema_version,
    slo_query_hash,
)

try:
    from importlib.resources.abc import Traversable
except ImportError:  # pragma: no cover - local Python 3.9 runners only.
    Traversable = Any


class MigrationError(RuntimeError):
    """Base migration failure."""


class MigrationHashDrift(MigrationError):
    """A migration differs from its pinned or recorded digest."""


_MIGRATION_CONNECTION_STATES: dict[int, dict[str, set[tuple[str, ...]]]] = {}


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path | Traversable
    sha256: str


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_migration_dir() -> Traversable:
    return resources.files("agentic_os.migration_assets")


def _sha256(path: Path | Traversable) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _shadow_projection_id(run_id: object, relative_path: object, digest: object) -> str:
    if not all(isinstance(item, str) and item for item in (run_id, relative_path, digest)):
        raise sqlite3.OperationalError("shadow projection id inputs must be non-empty text")
    payload = f"{run_id}\0{relative_path}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _utc_iso_epoch_ms(value: object) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def _trusted_clock_source_hash(now_epoch_ms: object, bound_by: object) -> str:
    if type(now_epoch_ms) is not int or not isinstance(bound_by, str) or not bound_by:
        return ""
    payload = json.dumps(
        {
            "bound_by": bound_by,
            "now_epoch_ms": now_epoch_ms,
            "source": "pass-gate-writer-local-wall-clock-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _trust_binding_hash(
    run_id: object,
    goal_run_id: object,
    evidence_hash: object,
    verifier_run_id: object,
    gate_run_id: object,
    schema_version: object,
    migration_sha256: object,
    blocking_slo_query_count: object,
) -> str:
    if not all(
        isinstance(item, str) and item
        for item in (
            run_id,
            goal_run_id,
            evidence_hash,
            verifier_run_id,
            gate_run_id,
            migration_sha256,
        )
    ):
        return ""
    if type(schema_version) is not int or type(blocking_slo_query_count) is not int:
        return ""
    payload = json.dumps(
        {
            "blocking_slo_query_count": blocking_slo_query_count,
            "evidence_hash": evidence_hash,
            "gate_run_id": gate_run_id,
            "goal_run_id": goal_run_id,
            "migration_sha256": migration_sha256,
            "run_id": run_id,
            "schema_version": schema_version,
            "source": "trust-promotion-binding-v1",
            "verifier_run_id": verifier_run_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _approval_hash_sql(
    approval_id: object,
    run_id: object,
    transition_id: object,
    gate_run_id: object,
    action_type: object,
    target_type: object,
    target_id: object,
    target_hash: object,
    target_scope: object,
    channel: object,
    source_message_digest: object,
    approval_text_digest: object,
    approved_risk_ceiling: object,
    expires_at_epoch_ms: object,
) -> str:
    text_fields = (
        approval_id,
        run_id,
        transition_id,
        gate_run_id,
        action_type,
        target_type,
        target_id,
        target_hash,
        target_scope,
        channel,
        source_message_digest,
        approval_text_digest,
        approved_risk_ceiling,
    )
    if not all(isinstance(item, str) and item for item in text_fields):
        return ""
    if type(expires_at_epoch_ms) is not int:
        return ""
    payload = json.dumps(
        {
            "approval_id": approval_id,
            "run_id": run_id,
            "transition_id": transition_id,
            "gate_run_id": gate_run_id,
            "action_type": action_type,
            "target_type": target_type,
            "target_id": target_id,
            "target_hash": target_hash,
            "target_scope": target_scope,
            "channel": channel,
            "source_message_digest": source_message_digest,
            "approval_text_digest": approval_text_digest,
            "approved_risk_ceiling": approved_risk_ceiling,
            "expires_at_epoch_ms": expires_at_epoch_ms,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _slo_audit_writer_hash(
    slo_audit_id: object,
    query_name: object,
    schema_version: object,
    migration_sha256: object,
    query_hash: object,
    result_count: object,
    status: object,
    empty_db_status: object,
    fixture_db_status: object,
    evidence_hash: object,
    evidence_run_id: object,
    verifier_run_id: object,
    gate_run_id: object,
    run_at_epoch_ms: object,
) -> str:
    text_fields = (
        slo_audit_id,
        query_name,
        migration_sha256,
        query_hash,
        status,
        empty_db_status,
        fixture_db_status,
        evidence_hash,
        evidence_run_id,
        verifier_run_id,
        gate_run_id,
    )
    if not all(isinstance(item, str) and item for item in text_fields):
        return ""
    if type(schema_version) is not int or type(result_count) is not int:
        return ""
    if type(run_at_epoch_ms) is not int:
        return ""
    payload = json.dumps(
        {
            "empty_db_status": empty_db_status,
            "evidence_hash": evidence_hash,
            "evidence_run_id": evidence_run_id,
            "fixture_db_status": fixture_db_status,
            "gate_run_id": gate_run_id,
            "migration_sha256": migration_sha256,
            "query_hash": query_hash,
            "query_name": query_name,
            "result_count": result_count,
            "run_at_epoch_ms": run_at_epoch_ms,
            "schema_version": schema_version,
            "slo_audit_id": slo_audit_id,
            "source": "agentic-os-slo-audit-writer-v1",
            "status": status,
            "verifier_run_id": verifier_run_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _migration_state(connection: sqlite3.Connection) -> dict[str, set[tuple[str, ...]]]:
    return _MIGRATION_CONNECTION_STATES.setdefault(
        id(connection),
        {
            "slo_audit_writes": set(),
        },
    )


def _allow_next_slo_audit_write(
    connection: sqlite3.Connection, slo_audit_id: str
) -> None:
    if not isinstance(slo_audit_id, str) or not slo_audit_id:
        raise MigrationError("SLO audit writer guard requires a non-empty audit id")
    _migration_state(connection)["slo_audit_writes"].add((slo_audit_id,))


def _consume_guard(
    state: dict[str, set[tuple[str, ...]]], guard_name: str, key: tuple[str, ...]
) -> int:
    guard = state[guard_name]
    if key not in guard:
        return 0
    guard.remove(key)
    return 1


def _evidence_snapshot_current(
    path: object,
    sha256: object,
    size_bytes: object,
    content_type: object,
    redaction_status: object,
    captured_at: object,
) -> int:
    if not all(
        isinstance(item, str) and item
        for item in (path, sha256, content_type, redaction_status, captured_at)
    ):
        return 0
    if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
        return 0
    if type(size_bytes) is not int or size_bytes < 0:
        return 0
    repo_root = repository_root().resolve()
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(repo_root)
        except ValueError:
            return 0
    else:
        relative = candidate
        candidate = repo_root / relative
    if ".." in relative.parts or not relative.parts:
        return 0
    try:
        _assert_predicate_path_allowed(relative.as_posix())
    except PredicateContractError:
        return 0
    if _is_credential_path_denied(path) or _is_credential_path_denied(
        relative.as_posix()
    ):
        return 0
    try:
        _reject_symlink_evidence_path(repo_root, relative)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repo_root)
    except (OSError, PredicateContractError):
        return 0
    except ValueError:
        return 0
    resolved_relative = resolved.relative_to(repo_root).as_posix()
    try:
        _assert_predicate_path_allowed(resolved_relative)
    except PredicateContractError:
        return 0
    if _is_credential_path_denied(resolved_relative):
        return 0
    digest = hashlib.sha256()
    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
        stat_result = os.fstat(fd)
        if stat_result.st_size > MAX_FILE_EVIDENCE_BYTES:
            return 0
        if stat_result.st_size != size_bytes:
            return 0
        with os.fdopen(fd, "rb") as handle:
            fd = None
            total_read = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total_read += len(chunk)
                if total_read > MAX_FILE_EVIDENCE_BYTES:
                    return 0
                digest.update(chunk)
    except OSError:
        return 0
    finally:
        if fd is not None:
            os.close(fd)
    if not stat.S_ISREG(stat_result.st_mode):
        return 0
    if int(getattr(stat_result, "st_nlink", 1) or 1) > 1:
        return 0
    return 1 if digest.hexdigest() == sha256 else 0


def _current_slos_pass(
    connection: sqlite3.Connection, schema_version: object, migration_sha256: object
) -> int:
    if type(schema_version) is not int or not isinstance(migration_sha256, str):
        return 0
    if len(migration_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in migration_sha256
    ):
        return 0
    try:
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            return 0
        current = connection.execute(
            "SELECT version,sha256 FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if current != (schema_version, migration_sha256):
            return 0
        query_count = connection.execute(
            "SELECT COUNT(*) FROM slo_queries WHERE schema_version=? AND migration_sha256=?",
            (schema_version, migration_sha256),
        ).fetchone()[0]
        if query_count != SLO_QUERY_COUNT:
            return 0
        for contract in slo_query_contracts_for_schema_version(schema_version):
            query = connection.execute(
                "SELECT query_hash FROM slo_queries "
                "WHERE query_name=? AND schema_version=? AND migration_sha256=?",
                (contract.query_name, schema_version, migration_sha256),
            ).fetchone()
            if query is None or query[0] != slo_query_hash(contract.sql_text):
                return 0
            if connection.execute(contract.sql_text).fetchone() is not None:
                return 0
    except sqlite3.Error:
        return 0
    return 1


def _register_migration_functions(connection: sqlite3.Connection) -> None:
    state = _migration_state(connection)
    connection.create_function(
        "agentic_shadow_projection_id",
        3,
        _shadow_projection_id,
        deterministic=True,
    )
    connection.create_function(
        "agentic_utc_iso_epoch_ms",
        1,
        _utc_iso_epoch_ms,
        deterministic=True,
    )
    connection.create_function(
        "agentic_trusted_clock_source_hash",
        2,
        _trusted_clock_source_hash,
        deterministic=True,
    )
    connection.create_function(
        "agentic_trust_binding_hash",
        8,
        _trust_binding_hash,
        deterministic=True,
    )
    connection.create_function(
        "agentic_approval_hash",
        14,
        _approval_hash_sql,
        deterministic=True,
    )
    connection.create_function(
        "agentic_slo_audit_writer_hash",
        14,
        _slo_audit_writer_hash,
        deterministic=True,
    )
    connection.create_function(
        "agentic_slo_audit_write_allowed",
        1,
        lambda slo_audit_id: _consume_guard(
            state,
            "slo_audit_writes",
            (slo_audit_id,) if isinstance(slo_audit_id, str) else ("",),
        ),
    )
    connection.create_function(
        "agentic_evidence_snapshot_current",
        6,
        _evidence_snapshot_current,
    )
    connection.create_function(
        "agentic_trust_promotion_current_slos_pass",
        2,
        lambda schema_version, migration_sha256: _current_slos_pass(
            connection, schema_version, migration_sha256
        ),
    )


def load_migrations(migration_dir: Path | None = None) -> tuple[Migration, ...]:
    directory: Path | Traversable
    if migration_dir is None:
        directory = _default_migration_dir()
    else:
        directory = Path(migration_dir)
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        rows = manifest["migrations"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise MigrationError(f"invalid migration manifest: {exc}") from exc

    migrations: list[Migration] = []
    seen_versions: set[int] = set()
    for row in rows:
        try:
            version = row["version"]
            name = row["name"]
            filename = row["file"]
            expected = row["sha256"]
        except (KeyError, TypeError) as exc:
            raise MigrationError("malformed migration manifest entry") from exc
        if type(version) is not int or version <= 0 or version in seen_versions:
            raise MigrationError(f"invalid or duplicate migration version: {version!r}")
        if not isinstance(name, str) or not name or not isinstance(filename, str):
            raise MigrationError("migration name and file must be non-empty strings")
        if not isinstance(expected, str) or len(expected) != 64:
            raise MigrationError(f"invalid pinned SHA-256 for migration {version}")
        path = directory / filename
        actual = _sha256(path)
        if actual != expected:
            raise MigrationHashDrift(
                f"migration {version} hash drift: expected {expected}, found {actual}"
            )
        migrations.append(Migration(version, name, path, expected))
        seen_versions.add(version)
    return tuple(sorted(migrations, key=lambda item: item.version))


def _statements(sql: str) -> Iterator[str]:
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                yield statement
            buffer = ""
    if buffer.strip():
        raise MigrationError("migration ends with an incomplete SQL statement")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    _register_migration_functions(connection)
    connection.execute("PRAGMA busy_timeout=10000")
    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    actual_journal_mode = journal_mode[0] if journal_mode else None
    if str(actual_journal_mode).casefold() != "wal":
        connection.close()
        raise MigrationError(
            "SQLite WAL journal mode is unavailable: "
            f"requested WAL, got {actual_journal_mode!r}"
        )
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        connection.close()
        raise MigrationError("SQLite foreign key enforcement is unavailable")
    return connection


def _connect_read_only(path: Path) -> sqlite3.Connection:
    """Open an existing database without changing journal mode or sidecars."""

    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True, isolation_level=None
    )
    _register_migration_functions(connection)
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        connection.close()
        raise MigrationError("SQLite foreign key enforcement is unavailable")
    return connection


def _recorded(connection: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if not exists:
        return {}
    rows = connection.execute(
        "SELECT version, name, sha256 FROM schema_migrations ORDER BY version"
    ).fetchall()
    return {row[0]: (row[1], row[2]) for row in rows}


def _verify_recorded(
    recorded: dict[int, tuple[str, str]], migrations: tuple[Migration, ...]
) -> None:
    known = {migration.version: migration for migration in migrations}
    unknown = sorted(set(recorded) - set(known))
    if unknown:
        raise MigrationHashDrift(f"database contains unknown migration versions: {unknown}")
    for version, (name, digest) in recorded.items():
        expected = known[version]
        if (name, digest) != (expected.name, expected.sha256):
            raise MigrationHashDrift(
                f"recorded migration {version} differs from pinned name/hash"
            )


def _database_checks(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if integrity != [("ok",)]:
        raise MigrationError(f"integrity_check failed: {integrity!r}")
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_keys:
        raise MigrationError(f"foreign_key_check failed: {foreign_keys!r}")


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[str, str, str, str | None]]:
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
    ).fetchall()


def _expected_schema(migrations: tuple[Migration, ...]) -> list[tuple[str, str, str, str | None]]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _register_migration_functions(connection)
        connection.execute("PRAGMA foreign_keys=ON")
        for migration in migrations:
            for statement in _statements(migration.path.read_text(encoding="utf-8")):
                connection.execute(statement)
        return _schema_rows(connection)
    finally:
        connection.close()


def _verify_schema(
    connection: sqlite3.Connection, migrations: tuple[Migration, ...]
) -> None:
    actual = _schema_rows(connection)
    expected = _expected_schema(migrations)
    if actual != expected:
        actual_keys = {(row[0], row[1]) for row in actual}
        expected_keys = {(row[0], row[1]) for row in expected}
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        changed = sorted(
            (row[0], row[1])
            for row in expected
            if (row[0], row[1]) in actual_keys
            and row != next(item for item in actual if item[0:2] == row[0:2])
        )
        raise MigrationHashDrift(
            "database schema differs from pinned migrations: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def _expected_slo_rows(migration: Migration) -> dict[tuple[object, ...], tuple[object, ...]]:
    contracts = slo_query_contracts_for_schema_version(migration.version)
    if len(contracts) != SLO_QUERY_COUNT or SLO_QUERY_COUNT != 30:
        raise MigrationError(f"expected 30 required SLO queries, found {len(contracts)}")
    return {
        (
            contract.query_name,
            migration.version,
            migration.sha256,
            slo_query_hash(contract.sql_text),
        ): (
            contract.sql_text,
            contract.empty_db_expected_status,
            contract.fixture_db_expected_status,
        )
        for contract in contracts
    }


def _seed_slo_queries(connection: sqlite3.Connection, migration: Migration) -> None:
    for contract in slo_query_contracts_for_schema_version(migration.version):
        connection.execute(
            "INSERT INTO slo_queries("
            "query_name,schema_version,migration_sha256,query_hash,sql_text,"
            "empty_db_expected_status,fixture_db_expected_status,created_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                contract.query_name,
                migration.version,
                migration.sha256,
                slo_query_hash(contract.sql_text),
                contract.sql_text,
                contract.empty_db_expected_status,
                contract.fixture_db_expected_status,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def _verify_slo_queries(
    connection: sqlite3.Connection, migrations: tuple[Migration, ...]
) -> None:
    if not migrations:
        return
    expected: dict[tuple[object, ...], tuple[object, ...]] = {}
    for migration in migrations:
        expected.update(_expected_slo_rows(migration))
    rows = connection.execute(
        "SELECT query_name,schema_version,migration_sha256,query_hash,sql_text,"
        "empty_db_expected_status,fixture_db_expected_status FROM slo_queries "
        "ORDER BY query_name,schema_version,migration_sha256,query_hash"
    ).fetchall()
    actual = {row[0:4]: row[4:] for row in rows}
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(
            name
            for name in set(expected) & set(actual)
            if expected[name] != actual[name]
        )
        raise MigrationHashDrift(
            "SLO registry differs from pinned query contracts: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def apply_migrations(
    database: Path,
    *,
    repo_root: Path | None = None,
    migration_dir: Path | None = None,
) -> tuple[int, ...]:
    """Apply pinned migrations and return versions applied by this call.

    Privacy checks run before SQLite can create the database. This function is
    schema tooling; it does not enable database authority.
    """

    root = Path(repo_root or repository_root()).resolve()
    path = Path(database).expanduser().resolve()
    assert_privacy_preflight(root, database_paths=(path,))
    migrations = load_migrations(migration_dir)
    parent_existed = path.parent.exists()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Never chmod a caller-owned shared directory such as /tmp. Directories
    # created for Agentic OS state are private from their first creation.
    if not parent_existed:
        os.chmod(path.parent, 0o700)
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if parent_mode != 0o700:
        raise MigrationError(
            f"database directory must have mode 0700, found {parent_mode:04o}: {path.parent}"
        )

    applied: list[int] = []
    connection = _connect(path)
    try:
        recorded = _recorded(connection)
        _verify_recorded(recorded, migrations)
        if recorded:
            recorded_migrations = tuple(
                migration for migration in migrations if migration.version in recorded
            )
            _verify_schema(connection, recorded_migrations)
            _verify_slo_queries(connection, recorded_migrations)
            _database_checks(connection)
        for migration in migrations:
            if migration.version in recorded:
                continue
            connection.execute("BEGIN IMMEDIATE")
            try:
                sql = migration.path.read_text(encoding="utf-8")
                for statement in _statements(sql):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                    "VALUES(?,?,?,?)",
                    (
                        migration.version,
                        migration.name,
                        migration.sha256,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                _seed_slo_queries(connection, migration)
                _database_checks(connection)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            applied.append(migration.version)
        _verify_recorded(_recorded(connection), migrations)
        _verify_schema(connection, migrations)
        _verify_slo_queries(connection, migrations)
        _database_checks(connection)
    finally:
        connection.close()
        if path.exists():
            os.chmod(path, 0o600)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{path}{suffix}")
            if sidecar.exists():
                os.chmod(sidecar, 0o600)
    return tuple(applied)


def verify_database(
    database: Path, *, migration_dir: Path | None = None
) -> tuple[int, ...]:
    """Verify an offline checkpointed database without mutating it."""

    migrations = load_migrations(migration_dir)
    path = Path(database).expanduser().resolve()
    if not path.is_file():
        raise MigrationError(f"database does not exist: {path}")
    present_sidecars = [
        sidecar
        for sidecar in (
            Path(f"{path}-wal"),
            Path(f"{path}-shm"),
            Path(f"{path}-journal"),
        )
        if sidecar.exists()
    ]
    if present_sidecars:
        names = ", ".join(str(sidecar) for sidecar in present_sidecars)
        raise MigrationError(
            "verification requires an offline checkpointed snapshot; "
            f"refusing database with SQLite sidecars: {names}"
        )
    connection = _connect_read_only(path)
    try:
        return verify_database_connection(connection, migrations=migrations)
    finally:
        connection.close()


def verify_database_connection(
    connection: sqlite3.Connection,
    *,
    migrations: tuple[Migration, ...] | None = None,
    migration_dir: Path | None = None,
) -> tuple[int, ...]:
    """Verify a live database connection against the pinned migration contract."""

    expected_migrations = migrations or load_migrations(migration_dir)
    recorded = _recorded(connection)
    _verify_recorded(recorded, expected_migrations)
    if recorded:
        recorded_migrations = tuple(
            migration for migration in expected_migrations if migration.version in recorded
        )
        _verify_schema(connection, recorded_migrations)
        _verify_slo_queries(connection, recorded_migrations)
        _database_checks(connection)
    expected = {migration.version for migration in expected_migrations}
    if set(recorded) != expected:
        missing = sorted(expected - set(recorded))
        raise MigrationError(f"database is missing migrations: {missing}")
    _verify_schema(connection, expected_migrations)
    _verify_slo_queries(connection, expected_migrations)
    _database_checks(connection)
    return tuple(sorted(recorded))
