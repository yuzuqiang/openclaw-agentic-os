from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentic_os.migrations import repository_root
from agentic_os.privacy import PrivacyPreflightError
from agentic_os.shadow import (
    ShadowBackfillError,
    audit_file_authority_shadow,
    backfill_file_authority_shadow,
)


class ShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "shadow-control.db"

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _artifact(self, name: str = "summary.json", content: bytes = b'{"ok": true}\n') -> Path:
        path = Path(self.temporary.name) / "reports" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_backfill_file_authority_shadow_and_audit_pass(self) -> None:
        artifact = self._artifact()
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        result = backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(result.workflow, "heartbeat")
        self.assertEqual(result.run_id, "shadow-run")
        self.assertEqual(len(result.projections), 1)
        self.assertEqual(result.projections[0].sha256, digest)

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("file_authority_shadow",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT authority_mode,state FROM runs WHERE run_id='shadow-run'"
                ).fetchone(),
                ("file_authority_shadow", "finalized"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT sha256,source_authority FROM artifact_projections "
                    "WHERE run_id='shadow-run'"
                ).fetchone(),
                (digest, "file_authority_shadow"),
            )

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "pass")
        self.assertEqual(audit.issues, ())

        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM artifact_projections WHERE run_id='shadow-run'"
                ).fetchone(),
                (1,),
            )

    def test_shadow_audit_detects_artifact_drift(self) -> None:
        artifact = self._artifact()
        backfill_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        artifact.write_bytes(b'{"ok": false}\n')

        audit = audit_file_authority_shadow(
            self.database,
            [artifact],
            workflow="heartbeat",
            run_id="shadow-run",
        )
        self.assertEqual(audit.status, "fail")
        self.assertEqual(len(audit.issues), 1)
        self.assertEqual(audit.issues[0].reason, "sha256_mismatch")

        with self.assertRaisesRegex(ShadowBackfillError, "projection drift"):
            backfill_file_authority_shadow(
                self.database,
                [artifact],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_backfill_rejects_raw_state_artifact(self) -> None:
        raw = Path(self.temporary.name) / "control.db.old"
        with self.assertRaises(PrivacyPreflightError):
            backfill_file_authority_shadow(
                self.database,
                [raw],
                workflow="heartbeat",
                run_id="shadow-run",
            )

    def test_shadow_backfill_rejects_artifact_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            artifact = Path(outside) / "summary.json"
            artifact.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ShadowBackfillError, "outside repository root"):
                backfill_file_authority_shadow(
                    self.database,
                    [artifact],
                    workflow="heartbeat",
                    run_id="shadow-run",
                )


if __name__ == "__main__":
    unittest.main()
