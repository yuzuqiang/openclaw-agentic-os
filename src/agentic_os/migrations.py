"""Versioned, hash-pinned SQLite migration runner."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .privacy import assert_privacy_preflight
from .slo_contracts import SLO_QUERY_CONTRACTS, SLO_QUERY_COUNT, slo_query_hash


class MigrationError(RuntimeError):
    """Base migration failure."""


class MigrationHashDrift(MigrationError):
    """A migration differs from its pinned or recorded digest."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sha256: str


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_migrations(migration_dir: Path | None = None) -> tuple[Migration, ...]:
    directory = Path(migration_dir or repository_root() / "migrations")
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
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA journal_mode=WAL")
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


def _expected_slo_rows(migration: Migration) -> dict[str, tuple[object, ...]]:
    if SLO_QUERY_COUNT != 30:
        raise MigrationError(f"expected 30 required SLO queries, found {SLO_QUERY_COUNT}")
    return {
        contract.query_name: (
            migration.version,
            migration.sha256,
            slo_query_hash(contract.sql_text),
            contract.sql_text,
            contract.empty_db_expected_status,
            contract.fixture_db_expected_status,
        )
        for contract in SLO_QUERY_CONTRACTS
    }


def _seed_slo_queries(connection: sqlite3.Connection, migration: Migration) -> None:
    for contract in SLO_QUERY_CONTRACTS:
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
    migration = migrations[0]
    expected = _expected_slo_rows(migration)
    rows = connection.execute(
        "SELECT query_name,schema_version,migration_sha256,query_hash,sql_text,"
        "empty_db_expected_status,fixture_db_expected_status FROM slo_queries "
        "ORDER BY query_name"
    ).fetchall()
    actual = {row[0]: row[1:] for row in rows}
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
        recorded = _recorded(connection)
        _verify_recorded(recorded, migrations)
        expected = {migration.version for migration in migrations}
        if set(recorded) != expected:
            missing = sorted(expected - set(recorded))
            raise MigrationError(f"database is missing migrations: {missing}")
        _verify_schema(connection, migrations)
        _verify_slo_queries(connection, migrations)
        _database_checks(connection)
        return tuple(sorted(recorded))
    finally:
        connection.close()
