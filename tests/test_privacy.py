from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from agentic_os.migrations import apply_migrations, repository_root
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

    def test_packaging_and_retrieval_denylist(self) -> None:
        denied = (
            "export/control.db",
            "control.db-wal",
            "control.db-shm",
            "state/agentic-os/control.db.backup123",
            "state/agentic-os/control.db.bak1",
            "cache.sqlite",
            "cache.sqlite-backup",
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
