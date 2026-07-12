from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agentic_os.migrations import MigrationError, apply_migrations, repository_root
from agentic_os.privacy import (
    PREFLIGHT_PATHS,
    PrivacyPreflightError,
    assert_paths_retrievable,
    assert_privacy_preflight,
    is_raw_state_denied,
)


class PrivacyTests(unittest.TestCase):
    def test_repository_preflight_proves_all_required_paths_ignored(self) -> None:
        result = assert_privacy_preflight(repository_root())
        self.assertEqual(result.ignored_paths, PREFLIGHT_PATHS)

    def test_preflight_fails_closed_when_rules_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
            with self.assertRaises(PrivacyPreflightError):
                assert_privacy_preflight(root)

    def test_migration_does_not_create_database_after_failed_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            target = root / "outside.db"
            with self.assertRaises(PrivacyPreflightError):
                apply_migrations(target, repo_root=root)
            self.assertFalse(target.exists())

    def test_unignored_database_target_inside_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(
                (repository_root() / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            target = root / "custom.db"
            with self.assertRaisesRegex(PrivacyPreflightError, "not ignored"):
                apply_migrations(target, repo_root=root)
            self.assertFalse(target.exists())

    def test_database_target_outside_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as other:
            root = Path(repo)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(
                (repository_root() / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            target = Path(other) / "control.db"
            with self.assertRaisesRegex(PrivacyPreflightError, "outside checked worktree"):
                apply_migrations(target, repo_root=root)
            self.assertFalse(target.exists())

    def test_tracked_runtime_database_is_rejected_even_when_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(
                (repository_root() / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            tracked = root / "state/agentic-os/control.db"
            tracked.parent.mkdir(parents=True)
            tracked.write_bytes(b"tracked")
            subprocess.run(["git", "add", "-f", str(tracked)], cwd=root, check=True)
            with self.assertRaisesRegex(PrivacyPreflightError, "tracked runtime paths"):
                assert_privacy_preflight(root)

    def test_any_tracked_raw_state_path_is_rejected_even_outside_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(
                (repository_root() / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            tracked = root / "state/agentic-os/secret.db"
            tracked.parent.mkdir(parents=True)
            tracked.write_bytes(b"tracked")
            subprocess.run(["git", "add", "-f", str(tracked)], cwd=root, check=True)
            with self.assertRaisesRegex(PrivacyPreflightError, "secret.db"):
                assert_privacy_preflight(root)

    def test_existing_database_directory_must_be_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(
                (repository_root() / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            state = root / "state/agentic-os"
            state.mkdir(parents=True)
            os.chmod(state, 0o755)
            target = state / "control.db"
            with self.assertRaisesRegex(PrivacyPreflightError, "not ignored"):
                # The actual target is ignored, so this assertion protects
                # against accidentally weakening the test setup.
                apply_migrations(root / "custom.db", repo_root=root)
            with self.assertRaisesRegex(MigrationError, "mode 0700"):
                apply_migrations(target, repo_root=root)
            self.assertFalse(target.exists())

    def test_packaging_and_retrieval_denylist(self) -> None:
        denied = (
            "export/control.db",
            "control.db-wal",
            "control.db-shm",
            "control.db-journal",
            "state/agentic-os/control.db.gz",
            "dump.sqlite.zip",
            "cache.sqlite3.zst",
            "control.db-wal.xz",
            "control.db.backup.zst",
            "state/agentic-os/control.db.backup123",
            "state/agentic-os/control.db.bak1",
            "cache.sqlite",
            "cache.sqlite-backup",
            "cache.sqlite.backup",
            "cache.sqlite.bak",
            "cache.sqlite3",
            "cache.sqlite3-wal",
            "cache.sqlite3-shm",
            "cache.sqlite3.backup",
            "state/agentic-os/backups/redacted.txt",
        )
        for path in denied:
            with self.subTest(path=path):
                self.assertTrue(is_raw_state_denied(path))
        self.assertFalse(is_raw_state_denied("reports/summary.json"))
        with self.assertRaises(PrivacyPreflightError):
            assert_paths_retrievable(denied)
        assert_paths_retrievable(denied, local_recovery=True)


if __name__ == "__main__":
    unittest.main()
