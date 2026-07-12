from __future__ import annotations

import json
import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentic_os import DB_AUTHORITY_ENABLED
from agentic_os.migrations import (
    MigrationError,
    MigrationHashDrift,
    apply_migrations,
    repository_root,
    verify_database,
)


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"

    def test_authority_remains_disabled(self) -> None:
        self.assertIs(DB_AUTHORITY_ENABLED, False)

    def test_complete_schema_and_idempotent_apply(self) -> None:
        self.assertEqual(apply_migrations(self.database), (1,))
        self.assertEqual(apply_migrations(self.database), ())
        with sqlite3.connect(self.database) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            self.assertEqual(len(tables), 27)
            row = connection.execute(
                "SELECT version,name,sha256 FROM schema_migrations"
            ).fetchone()
            self.assertEqual(row[0:2], (1, "minimum_contract"))
            self.assertEqual(
                row[2], "4d74e68c0b82af1156a7d414059c0c278ae129e173eac8c04af2c9d2b571fbab"
            )
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_verify_is_read_only_and_creates_no_sidecars(self) -> None:
        apply_migrations(self.database)
        verify_target = Path(self.temporary.name) / "readonly.db"
        # SQLite backup establishes a migrated, checkpointed baseline with no
        # sidecars. verify_database must not change it or create any.
        with sqlite3.connect(self.database) as source, sqlite3.connect(verify_target) as target:
            source.backup(target)
        wal = Path(f"{verify_target}-wal")
        shm = Path(f"{verify_target}-shm")
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        before = hashlib.sha256(verify_target.read_bytes()).hexdigest()
        before_mtime = verify_target.stat().st_mtime_ns
        self.assertEqual(verify_database(verify_target), (1,))
        self.assertEqual(hashlib.sha256(verify_target.read_bytes()).hexdigest(), before)
        self.assertEqual(verify_target.stat().st_mtime_ns, before_mtime)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())

    def test_verify_refuses_sidecar_without_changing_any_file(self) -> None:
        apply_migrations(self.database)
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                verify_target = Path(self.temporary.name) / f"sidecar{suffix}.db"
                with sqlite3.connect(self.database) as source, sqlite3.connect(
                    verify_target
                ) as target:
                    source.backup(target)
                sidecar = Path(f"{verify_target}{suffix}")
                sidecar.write_bytes(b"sidecar-sentinel")
                database_before = (
                    hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                    verify_target.stat().st_mtime_ns,
                )
                sidecar_before = (sidecar.read_bytes(), sidecar.stat().st_mtime_ns)
                with self.assertRaisesRegex(
                    MigrationError, "requires an offline checkpointed snapshot"
                ):
                    verify_database(verify_target)
                self.assertEqual(
                    (
                        hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                        verify_target.stat().st_mtime_ns,
                    ),
                    database_before,
                )
                self.assertEqual(
                    (sidecar.read_bytes(), sidecar.stat().st_mtime_ns), sidecar_before
                )
                for other_suffix in ("-wal", "-shm", "-journal"):
                    other = Path(f"{verify_target}{other_suffix}")
                    self.assertEqual(other.exists(), other_suffix == suffix)

    def test_foreign_keys_are_enforced(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('r','p','missing','file_authority','candidate','R0','R0','t','t')"
            )

    def test_migration_file_hash_drift_is_refused_before_database_creation(self) -> None:
        migration_dir = Path(self.temporary.name) / "migrations"
        shutil.copytree(repository_root() / "migrations", migration_dir)
        migration = migration_dir / "0001_minimum_contract.sql"
        migration.write_text(migration.read_text() + "\n-- drift\n", encoding="utf-8")
        drift_database = Path(self.temporary.name) / "drift.db"
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(drift_database, migration_dir=migration_dir)
        self.assertFalse(drift_database.exists())

    def test_recorded_hash_drift_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE schema_migrations SET sha256=?", ("0" * 64,))
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(self.database)

    def test_type_preserving_money_bounds(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        base = ("p", "m", "e", "c", "known", "2026-01-01", "h")

        def insert(identifier: str, input_price: object, output_price: object) -> None:
            connection.execute(
                "INSERT INTO model_cost_registry("
                "cost_registry_id,provider,model,endpoint_binding_id,capability_class,"
                "input_cost_microusd_per_million,output_cost_microusd_per_million,"
                "confidence,effective_at,registry_row_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (identifier, *base[:4], input_price, output_price, *base[4:6], identifier),
            )

        insert("max", 100_000_000_000, 100_000_000_000)
        for identifier, value in (
            ("max-plus-one", 100_000_000_001),
            ("numeric-text", "1500"),
            ("integral-real", 1500.0),
            ("negative", -1),
        ):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError):
                insert(identifier, value, 0)

    def test_manifest_is_machine_readable_and_has_one_pinned_migration(self) -> None:
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["migrations"]), 1)
        self.assertEqual(manifest["migrations"][0]["version"], 1)

    def test_migration_is_exact_accepted_ddl_block(self) -> None:
        design = (repository_root() / "docs/agentic-os-production-adaptation.md").read_text(
            encoding="utf-8"
        )
        contract = design.split("## Minimum Database Contracts", 1)[1]
        ddl = contract.split("```sql\n", 1)[1].split("\n```", 1)[0] + "\n"
        migration = (repository_root() / "migrations/0001_minimum_contract.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(migration, ddl)

    def test_schema_migration_version_preserves_numeric_type(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        for version in ("2", 2.0):
            with self.subTest(version=version), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                    "VALUES(?,?,?,?)",
                    (version, "bad", "0" * 64, "now"),
                )


if __name__ == "__main__":
    unittest.main()
