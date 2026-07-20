from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import agentic_os
import agentic_os.db_authority_canary as canary_module
from agentic_os.cli import main as cli_main
from agentic_os.db_authority_canary import (
    DbAuthorityCanaryError,
    db_authority_canary_artifact,
    rollback_db_authority_canary,
)
from agentic_os.db_authority_controller import (
    DbAuthorityControllerError,
    expected_synthetic_expansion_eligibility_proof,
    rollback_synthetic_db_authority_expansion,
    run_synthetic_db_authority_expansion,
)
from agentic_os.migrations import (
    _register_migration_functions,
    apply_migrations,
    repository_root,
)


class DbAuthorityCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "canary-control.db"
        self.artifact = Path(self.temporary.name) / "reports" / "canary.json"
        self.payload = b'{"workflow":"heartbeat","synthetic":true}\n'
        self.cutover_hash = hashlib.sha256(b"synthetic-cutover").hexdigest()
        self.parity_hash = hashlib.sha256(b"synthetic-parity").hexdigest()

    def _eligibility_proof(
        self,
        *,
        workflow: str = "local-artifact-canary",
        run_id: str = "canary-run",
        artifact: Path | None = None,
        content: bytes | None = None,
        prepare_idempotency_key: str | None = None,
        verifier_run_id: str = "phase-a-boundary-review",
        persist_verifier_evidence: bool = True,
    ) -> dict[str, object]:
        proof = expected_synthetic_expansion_eligibility_proof(
            artifact or self.artifact,
            content or self.payload,
            workflow=workflow,
            run_id=run_id,
            risk_class="R1",
            risk_dominance="R1",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id=verifier_run_id,
            prepare_idempotency_key=prepare_idempotency_key,
        )
        if persist_verifier_evidence:
            self._persist_verifier_evidence(proof)
        return proof

    def _persist_verifier_evidence(self, proof: dict[str, object]) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT OR IGNORE INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('synthetic-verifier-proof','file_authority',"
                "'2026-01-01T00:00:00+00:00')"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at,"
                "finalized_at,finalized_at_epoch_ms) VALUES("
                "'phase-b-worker-evidence','phase-b-worker-evidence-prepare',"
                "'synthetic-verifier-proof','file_authority','finalized','R1','R1',"
                "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',"
                "'2026-01-01T00:00:00+00:00',1767225600000)"
            )
            connection.execute(
                "INSERT OR REPLACE INTO judge_verifier_runs(verifier_run_id,"
                "worker_run_id,worker_agent_id,verifier_agent_id,provider,model,"
                "model_version,prompt_hash,context_hash,evidence_hash,"
                "independence_class,independence_proof_json,same_worker_context,"
                "completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                (
                    proof["verifier_run_id"],
                    "phase-b-worker-evidence",
                    proof["worker_agent_id"],
                    proof["verifier_agent_id"],
                    "local",
                    "codex-review",
                    "test",
                    hashlib.sha256(b"prompt").hexdigest(),
                    hashlib.sha256(b"context").hexdigest(),
                    proof["gate_evidence_hash"],
                    "independent",
                    json.dumps(
                        {"review": "independent verifier evidence persisted"},
                        sort_keys=True,
                    ),
                    "2026-01-01T00:00:00+00:00",
                ),
            )

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def test_canary_writes_only_local_artifact_and_synthetic_db_proof(self) -> None:
        result = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertFalse(agentic_os.DB_AUTHORITY_ENABLED)
        self.assertEqual(result.status, "written")
        self.assertEqual(self.artifact.read_bytes(), self.payload)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode,cutover_approved_by,rollback_deadline "
                    "FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                (
                    "db_authority_canary",
                    "local-fixture",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT authority_mode,state,risk_class,risk_dominance "
                    "FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("db_authority_canary", "finalized", "R1", "R1"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT source_authority,sha256 FROM artifact_projections "
                    "WHERE run_id='canary-run'"
                ).fetchone(),
                ("db_authority_canary", hashlib.sha256(self.payload).hexdigest()),
            )
            for table in (
                "external_rpc_intents",
                "leases",
                "spawn_requests",
                "sessions",
            ):
                self.assertEqual(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE run_id='canary-run'"
                    ).fetchone(),
                    (0,),
                )

        replay = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        self.assertEqual(replay.status, "replayed")

    def test_expansion_controller_admits_only_fixed_low_risk_workflow(self) -> None:
        result = run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertFalse(result.db_authority_enabled)
        self.assertEqual(result.controller_status, "artifact_only_canary_recorded")
        self.assertTrue(result.proof["artifact_only"])
        self.assertFalse(result.proof["real_openclaw_rpc"])
        self.assertFalse(result.proof["real_gateway_rpc"])
        self.assertFalse(result.proof["real_cron_rpc"])
        self.assertFalse(result.proof["real_session_rpc"])
        self.assertEqual(
            result.proof["eligibility_proof"],
            self._eligibility_proof(),
        )
        eligibility = result.proof["eligibility_proof"]
        self.assertIsInstance(eligibility, dict)
        self.assertEqual(eligibility["gate_decision"], "not_required")
        self.assertEqual(eligibility["projection_count"], 1)
        self.assertEqual(
            result.proof["rollback_proof_hash"],
            eligibility["rollback_proof_hash"],
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT workflow,authority_mode,risk_class,risk_dominance "
                    "FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("local-artifact-canary", "db_authority_canary", "R1", "R1"),
            )

    def test_expansion_controller_normalizes_identities_in_emitted_proof(self) -> None:
        result = run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow=" local-artifact-canary ",
            run_id=" canary-run ",
            risk_class=" R1 ",
            risk_dominance=" R1 ",
            worker_agent_id=" phase-b-ai-engineer ",
            verifier_agent_id=" phase-a-security-engineer ",
            verifier_run_id=" phase-a-boundary-review ",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by=" local-fixture ",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertEqual(result.workflow, "local-artifact-canary")
        self.assertEqual(result.run_id, "canary-run")
        self.assertEqual(result.proof["workflow"], "local-artifact-canary")
        self.assertEqual(result.proof["run_id"], "canary-run")
        self.assertTrue(result.proof["workflow_isolation"])
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT workflow,run_id FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("local-artifact-canary", "canary-run"),
            )

    def test_expansion_controller_rejects_cross_workflow_and_r3_r4(self) -> None:
        with self.assertRaisesRegex(DbAuthorityControllerError, "only"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof={},
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        with self.assertRaisesRegex(DbAuthorityControllerError, "human-required"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R3",
                risk_dominance="R3",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof={},
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_expansion_controller_requires_exact_eligibility_proof(self) -> None:
        base = self._eligibility_proof()
        drifted_projection = dict(base)
        drifted_projection["projection"] = {
            **base["projection"],
            "sha256": hashlib.sha256(b"drifted").hexdigest(),
        }
        cases = {
            "missing": {},
            "stale-parity": {
                **base,
                "parity_audit_hash": hashlib.sha256(b"stale").hexdigest(),
            },
            "cross-workflow-proof": {**base, "workflow": "other"},
            "duplicated-projection": {**base, "projection_count": 2},
            "malformed-gate": {**base, "gate_decision": "pass"},
            "json-bool-int-drift": {**base, "real_session_rpc": 0},
            "drifted-projection": drifted_projection,
        }
        for name, proof in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                DbAuthorityControllerError,
                "eligibility proof|exact synthetic expansion boundary",
            ):
                run_synthetic_db_authority_expansion(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="local-artifact-canary",
                    run_id="canary-run",
                    risk_class="R1",
                    risk_dominance="R1",
                    worker_agent_id="phase-b-ai-engineer",
                    verifier_agent_id="phase-a-security-engineer",
                    verifier_run_id="phase-a-boundary-review",
                    eligibility_proof=proof,
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline="2099-01-01T00:00:00+00:00",
                    last_parity_audit_hash=self.parity_hash,
                )
            self.assertFalse(self.artifact.exists())
            with sqlite3.connect(self.database) as connection:
                if connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='runs'"
                ).fetchone():
                    self.assertIsNone(
                        connection.execute(
                            "SELECT 1 FROM runs WHERE run_id='canary-run'"
                        ).fetchone()
                    )

    def test_expansion_controller_requires_supplied_api_eligibility_proof(self) -> None:
        with self.assertRaisesRegex(DbAuthorityControllerError, "eligibility proof"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=None,  # type: ignore[arg-type]
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_expansion_controller_requires_persisted_verifier_evidence(self) -> None:
        proof = self._eligibility_proof(persist_verifier_evidence=False)

        with self.assertRaisesRegex(
            DbAuthorityControllerError, "persisted verifier evidence"
        ):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=proof,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_expansion_controller_validates_database_alias_before_migration(
        self,
    ) -> None:
        real_database = Path(self.temporary.name) / "real-control.db"
        alias_database = Path(self.temporary.name) / "alias-control.db"
        try:
            os.symlink(real_database, alias_database)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        self.database = alias_database
        proof = self._eligibility_proof(persist_verifier_evidence=False)

        with self.assertRaisesRegex(DbAuthorityControllerError, "symlink"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=proof,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

        self.assertFalse(real_database.exists())
        self.assertFalse(self.artifact.exists())

    def test_expansion_controller_rejects_verifier_reusing_worker_run_id(
        self,
    ) -> None:
        verifier_run_id = "phase-b-worker-evidence"
        proof = self._eligibility_proof(verifier_run_id=verifier_run_id)

        with self.assertRaisesRegex(DbAuthorityControllerError, "exact gate"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id=verifier_run_id,
                eligibility_proof=proof,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_expansion_controller_binds_prepare_idempotency_key(self) -> None:
        prepare_key = "review-trigger-prepare-key"
        proof = self._eligibility_proof(prepare_idempotency_key=prepare_key)
        default_proof = self._eligibility_proof(persist_verifier_evidence=False)
        self.assertEqual(proof["prepare_idempotency_key"], prepare_key)
        self.assertNotEqual(
            proof["canary_evidence_hash"],
            default_proof["canary_evidence_hash"],
        )
        self.assertNotEqual(
            proof["gate_evidence_hash"],
            default_proof["gate_evidence_hash"],
        )

        with self.assertRaisesRegex(
            DbAuthorityControllerError, "exact synthetic expansion boundary"
        ):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=default_proof,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                prepare_idempotency_key=prepare_key,
            )
        self.assertFalse(self.artifact.exists())

        result = run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=proof,
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
            prepare_idempotency_key=prepare_key,
        )

        self.assertEqual(
            result.proof["eligibility_proof"]["prepare_idempotency_key"],
            prepare_key,
        )
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT prepare_idempotency_key FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                (prepare_key,),
            )

    def test_expansion_controller_rejects_self_attested_verifier_identity(self) -> None:
        forged = expected_synthetic_expansion_eligibility_proof(
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
            worker_agent_id="forged-worker",
            verifier_agent_id="forged-verifier",
            verifier_run_id="forged-verifier-run",
        )

        with self.assertRaisesRegex(
            DbAuthorityControllerError, "exact synthetic expansion boundary"
        ):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=forged,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_expansion_controller_rejects_replayed_controlled_canary_proof(self) -> None:
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityControllerError, "retroactive"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_expansion_controller_rejects_non_independent_gate_proof(self) -> None:
        with self.assertRaisesRegex(DbAuthorityControllerError, "independent"):
            expected_synthetic_expansion_eligibility_proof(
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-b-ai-engineer",
                verifier_run_id="canary-run",
            )

    def test_expansion_controller_rollback_requires_disabled_db_authority(self) -> None:
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with mock.patch.object(
            agentic_os, "DB_AUTHORITY_ENABLED", True
        ), self.assertRaisesRegex(
            DbAuthorityControllerError, "production DB authority must remain disabled"
        ):
            rollback_synthetic_db_authority_expansion(
                self.database,
                (self.artifact,),
                workflow="local-artifact-canary",
            )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority "
                    "WHERE workflow='local-artifact-canary'"
                ).fetchone(),
                ("db_authority_canary",),
            )

        rollback = rollback_synthetic_db_authority_expansion(
            self.database,
            (self.artifact,),
            workflow="local-artifact-canary",
        )
        self.assertFalse(rollback.db_authority_enabled)
        self.assertFalse(rollback.proof["db_authority_enabled"])
        self.assertEqual(rollback.controller_status, "artifact_only_canary_rolled_back")

    def test_expansion_controller_rejects_preexisting_canary_projection_set(self) -> None:
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        next_artifact = Path(self.temporary.name) / "reports" / "canary-2.json"
        next_payload = b'{"workflow":"heartbeat","synthetic":true,"next":true}\n'

        with self.assertRaisesRegex(DbAuthorityCanaryError, "projection set"):
            run_synthetic_db_authority_expansion(
                self.database,
                next_artifact,
                next_payload,
                workflow="local-artifact-canary",
                run_id="canary-run-2",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(
                    run_id="canary-run-2",
                    artifact=next_artifact,
                    content=next_payload,
                ),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(next_artifact.exists())

    def test_expansion_controller_rejects_unprojected_canary_run(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "open_file_authority_runs,updated_at) VALUES(?,?,?,?,?,?,0,?)",
                (
                    "local-artifact-canary",
                    "db_authority_canary",
                    "local-fixture",
                    self.cutover_hash,
                    "2099-01-01T00:00:00+00:00",
                    self.parity_hash,
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('orphan-canary','orphan-prepare','local-artifact-canary',"
                "'db_authority_canary','prepared','R1','R1',"
                "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')"
            )
            connection.commit()

        with self.assertRaisesRegex(DbAuthorityCanaryError, "projection set"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_raw_canary_rejects_controlled_expansion_workflow(self) -> None:
        with self.assertRaisesRegex(DbAuthorityCanaryError, "expansion controller"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_raw_canary_api_does_not_expose_controlled_workflow_escape_hatch(
        self,
    ) -> None:
        with self.assertRaises(TypeError):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                _allow_controlled_workflow=True,  # type: ignore[call-arg]
            )
        self.assertFalse(self.artifact.exists())

    def test_raw_canary_rollback_rejects_controlled_expansion_workflow(self) -> None:
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "expansion controller"):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="local-artifact-canary",
            )

        rollback = rollback_synthetic_db_authority_expansion(
            self.database,
            (self.artifact,),
            workflow="local-artifact-canary",
        )
        self.assertEqual(rollback.rollback.status, "rolled_back")

    def test_expansion_controller_recovers_prepared_projection_set(self) -> None:
        with self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )
        self.assertFalse(self.artifact.exists())

        recovered = run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertEqual(recovered.canary.status, "recovered")
        self.assertEqual(self.artifact.read_bytes(), self.payload)

    def test_expansion_controller_revalidates_projection_set_before_finalize(
        self,
    ) -> None:
        original_create = canary_module._atomic_create_file

        def contaminate_workflow(target: Path, content: bytes) -> None:
            original_create(target, content)
            digest = hashlib.sha256(b'{"workflow":"extra"}\n').hexdigest()
            with sqlite3.connect(self.database) as connection:
                _register_migration_functions(connection)
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute(
                    "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                    "authority_mode,state,risk_class,risk_dominance,created_at,"
                    "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                    "'canary-run-2','canary-run-2-prepare','local-artifact-canary',"
                    "'db_authority_canary','finalized','R1','R1',"
                    "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',"
                    "'2026-01-01T00:00:00+00:00',1767225600000)"
                )
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,"
                    "sha256,source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                    (
                        canary_module._projection_id(
                            "canary-run-2", "reports/extra.json", digest
                        ),
                        "canary-run-2",
                        "reports/extra.json",
                        digest,
                        "db_authority_canary",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )

        with mock.patch.object(
            canary_module, "_atomic_create_file", side_effect=contaminate_workflow
        ), self.assertRaisesRegex(DbAuthorityCanaryError, "projection set"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("prepared",),
            )

    def test_expansion_controller_revalidates_verifier_evidence_before_finalize(
        self,
    ) -> None:
        proof = self._eligibility_proof()
        original_create = canary_module._atomic_create_file

        def drift_verifier_evidence(target: Path, content: bytes) -> None:
            original_create(target, content)
            with sqlite3.connect(self.database) as connection:
                connection.execute(
                    "UPDATE judge_verifier_runs SET evidence_hash=? "
                    "WHERE verifier_run_id=?",
                    (
                        hashlib.sha256(b"drifted-gate").hexdigest(),
                        proof["verifier_run_id"],
                    ),
                )

        with mock.patch.object(
            canary_module, "_atomic_create_file", side_effect=drift_verifier_evidence
        ), self.assertRaisesRegex(DbAuthorityControllerError, "exact gate"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=proof,
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("prepared",),
            )

    def test_expansion_controller_rejects_workflow_real_session_rows(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('local-artifact-canary','file_authority',"
                "'2026-01-01T00:00:00+00:00')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                "'prior-file-run','prior-file-prepare','local-artifact-canary',"
                "'file_authority','finalized','R1','R1',"
                "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',"
                "'2026-01-01T00:00:00+00:00',1767225600000)"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,"
                "state_after,transition_type,action_type,target_type,target_id,"
                "target_hash,target_scope,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES("
                "'prior-transition','prior-file-run','prepared','spawn_pending',"
                "'dispatch','spawn','session','prior-session',?,'local','R1',"
                "'prior-transition-idem',0,'2026-01-01T00:00:00+00:00')",
                (hashlib.sha256(b"prior-session").hexdigest(),),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                "'prior-lease','prior-file-run','B','prior-transition',"
                "'ai-engineer','main','release_not_required','prior-client-lease',"
                "'prior-acquire-idem',1000,'2099-01-01T00:00:00+00:00',"
                "4070908800000)"
            )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "whole workflow"):
            run_synthetic_db_authority_expansion(
                self.database,
                self.artifact,
                self.payload,
                workflow="local-artifact-canary",
                run_id="canary-run",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(self.artifact.exists())

    def test_expansion_controller_projection_set_guard_handles_uri_database_path(
        self,
    ) -> None:
        self.database = Path(self.temporary.name) / "canary#control?.db"
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        next_artifact = Path(self.temporary.name) / "reports" / "canary-2.json"
        next_payload = b'{"workflow":"heartbeat","synthetic":true,"next":true}\n'

        with self.assertRaisesRegex(DbAuthorityCanaryError, "projection set"):
            run_synthetic_db_authority_expansion(
                self.database,
                next_artifact,
                next_payload,
                workflow="local-artifact-canary",
                run_id="canary-run-2",
                risk_class="R1",
                risk_dominance="R1",
                worker_agent_id="phase-b-ai-engineer",
                verifier_agent_id="phase-a-security-engineer",
                verifier_run_id="phase-a-boundary-review",
                eligibility_proof=self._eligibility_proof(
                    run_id="canary-run-2",
                    artifact=next_artifact,
                    content=next_payload,
                ),
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertFalse(next_artifact.exists())

    def test_expansion_controller_rollback_proof_uses_normalized_workflow(self) -> None:
        result = run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        rollback = rollback_synthetic_db_authority_expansion(
            self.database,
            (self.artifact,),
            workflow=" local-artifact-canary ",
        )

        self.assertEqual(rollback.workflow, "local-artifact-canary")
        self.assertTrue(rollback.proof["workflow_isolation"])
        self.assertEqual(
            rollback.proof["rollback_proof_hash"],
            result.proof["rollback_proof_hash"],
        )

    def test_expansion_controller_rollback_rejects_multi_projection_set(self) -> None:
        apply_migrations(self.database)
        artifacts = (
            self.artifact,
            Path(self.temporary.name) / "reports" / "canary-2.json",
        )
        payloads = (
            self.payload,
            b'{"workflow":"heartbeat","synthetic":true,"second":true}\n',
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
                "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,"
                "open_file_authority_runs,updated_at) VALUES(?,?,?,?,?,?,0,?)",
                (
                    "local-artifact-canary",
                    "db_authority_canary",
                    "local-fixture",
                    self.cutover_hash,
                    "2099-01-01T00:00:00+00:00",
                    self.parity_hash,
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            for index, (artifact, payload) in enumerate(zip(artifacts, payloads), 1):
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(payload)
                _target, relative = canary_module._normalize_artifact_target(
                    artifact,
                    repo_root_path=repository_root(),
                )
                digest = hashlib.sha256(payload).hexdigest()
                run_id = f"legacy-canary-{index}"
                connection.execute(
                    "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                    "authority_mode,state,risk_class,risk_dominance,created_at,"
                    "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                    "?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        f"{run_id}-prepare",
                        "local-artifact-canary",
                        "db_authority_canary",
                        "finalized",
                        "R1",
                        "R1",
                        "2026-01-01T00:00:00+00:00",
                        "2026-01-01T00:00:00+00:00",
                        "2026-01-01T00:00:00+00:00",
                        1767225600000,
                    ),
                )
                connection.execute(
                    "INSERT INTO artifact_projections(projection_id,run_id,path,"
                    "sha256,source_authority,generated_at) VALUES(?,?,?,?,?,?)",
                    (
                        canary_module._projection_id(run_id, relative, digest),
                        run_id,
                        relative,
                        digest,
                        "db_authority_canary",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "projection set"):
            rollback_synthetic_db_authority_expansion(
                self.database,
                artifacts,
                workflow="local-artifact-canary",
            )

    def test_expansion_controller_rollback_rechecks_workflow_rpc_rows(self) -> None:
        run_synthetic_db_authority_expansion(
            self.database,
            self.artifact,
            self.payload,
            workflow="local-artifact-canary",
            run_id="canary-run",
            risk_class="R1",
            risk_dominance="R1",
            worker_agent_id="phase-b-ai-engineer",
            verifier_agent_id="phase-a-security-engineer",
            verifier_run_id="phase-a-boundary-review",
            eligibility_proof=self._eligibility_proof(),
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,"
                "authority_mode,state,risk_class,risk_dominance,created_at,"
                "updated_at,finalized_at,finalized_at_epoch_ms) VALUES("
                "'prior-file-run','prior-file-prepare','local-artifact-canary',"
                "'file_authority','finalized','R1','R1',"
                "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',"
                "'2026-01-01T00:00:00+00:00',1767225600000)"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,"
                "state_after,transition_type,action_type,target_type,target_id,"
                "target_hash,target_scope,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES("
                "'prior-transition','prior-file-run','prepared','spawn_pending',"
                "'dispatch','spawn','session','prior-session',?,'local','R1',"
                "'prior-transition-idem',0,'2026-01-01T00:00:00+00:00')",
                (hashlib.sha256(b"prior-session").hexdigest(),),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                "'prior-lease','prior-file-run','B','prior-transition',"
                "'ai-engineer','main','release_not_required','prior-client-lease',"
                "'prior-acquire-idem',1000,'2099-01-01T00:00:00+00:00',"
                "4070908800000)"
            )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "whole workflow"):
            rollback_synthetic_db_authority_expansion(
                self.database,
                (self.artifact,),
                workflow="local-artifact-canary",
            )

    def test_canary_recovers_after_local_crash_fixture(self) -> None:
        with self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )
        self.assertFalse(self.artifact.exists())
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("prepared",),
            )
            _register_migration_functions(connection)
            for statement, parameters in (
                (
                    "UPDATE workflow_authority SET cutover_evidence_hash=? "
                    "WHERE workflow='heartbeat'",
                    ("f" * 64,),
                ),
                (
                    "UPDATE workflow_authority SET mode='rollback_to_file_authority' "
                    "WHERE workflow='heartbeat'",
                    (),
                ),
                (
                    "UPDATE runs SET state='finalized',"
                    "finalized_at='2099-01-01T00:00:00+00:00',"
                    "finalized_at_epoch_ms=1 WHERE run_id='canary-run'",
                    (),
                ),
            ):
                with self.subTest(statement=statement), self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "canary workflow binding|canary projection binding",
                ):
                    connection.execute(statement, parameters)

        recovered = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        self.assertEqual(recovered.status, "recovered")
        self.assertEqual(self.artifact.read_bytes(), self.payload)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM runs WHERE run_id='canary-run'"
                ).fetchone(),
                ("finalized",),
            )

    def test_first_canary_write_rejects_preexisting_artifact(self) -> None:
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.artifact.write_bytes(self.payload)

        with self.assertRaisesRegex(DbAuthorityCanaryError, "must not already exist"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        with sqlite3.connect(self.database) as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id='canary-run'"
                ).fetchone()
            )

    def test_rollback_proves_projection_regeneration(self) -> None:
        written = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )

        self.assertEqual(rollback.status, "rolled_back")
        self.assertEqual(rollback.regenerated, (written.projection,))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT mode FROM workflow_authority WHERE workflow='heartbeat'"
                ).fetchone(),
                ("rollback_to_file_authority",),
            )

    def test_canary_refuses_real_session_control_rows_on_replay(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,"
                "target_scope,risk_dominance,idempotency_key,guard_version_before,"
                "created_at) VALUES("
                "'t','canary-run','prepared','spawn_pending','dispatch','spawn',"
                "'session','s',?,'local','R1','transition-idem',0,'now')",
                (hashlib.sha256(b"target").hexdigest(),),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
                "'lease','canary-run','B','t','ai-engineer','main',"
                "'release_not_required','client-lease','acquire-idem',1000,"
                "'2099-01-01T00:00:00+00:00',4070908800000)"
            )

        with self.assertRaisesRegex(
            DbAuthorityCanaryError, "real session-control rows"
        ):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )
        with self.assertRaisesRegex(
            DbAuthorityCanaryError, "real session-control rows"
        ):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_rollback_rejects_cross_workflow_projection(self) -> None:
        other_artifact = Path(self.temporary.name) / "reports" / "other.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            other_artifact,
            b'{"workflow":"other","synthetic":true}\n',
            workflow="other",
            run_id="other-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "exactly match"):
            rollback_db_authority_canary(
                self.database,
                (other_artifact,),
                workflow="heartbeat",
            )

    def test_rollback_ignores_unrelated_prepared_canary(self) -> None:
        other_artifact = Path(self.temporary.name) / "reports" / "other.json"
        written = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            db_authority_canary_artifact(
                self.database,
                other_artifact,
                b'{"workflow":"other","synthetic":true}\n',
                workflow="other",
                run_id="other-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.regenerated, (written.projection,))

    def test_rollback_rejects_corrupted_cutover_metadata(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary workflow binding is immutable"
            ):
                connection.execute(
                    "UPDATE workflow_authority SET cutover_evidence_hash='bad' "
                    "WHERE workflow='heartbeat'"
                )
        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_rollback_rehashes_artifact_immediately_before_commit(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        original_normalize = canary_module._normalize_artifacts

        def stale_normalize(*args, **kwargs):
            normalized = original_normalize(*args, **kwargs)
            self.artifact.write_bytes(b'{"workflow":"heartbeat","stale":true}\n')
            return normalized

        with mock.patch.object(
            canary_module, "_normalize_artifacts", side_effect=stale_normalize
        ), self.assertRaisesRegex(
            DbAuthorityCanaryError, "cannot be regenerated"
        ):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_rollback_requires_complete_projection_set(self) -> None:
        second_artifact = Path(self.temporary.name) / "reports" / "second.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            second_artifact,
            b'{"workflow":"heartbeat","sequence":2}\n',
            workflow="heartbeat",
            run_id="canary-run-2",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with self.assertRaisesRegex(DbAuthorityCanaryError, "exactly match"):
            rollback_db_authority_canary(
                self.database,
                (self.artifact,),
                workflow="heartbeat",
            )

    def test_projection_delete_cannot_hide_finalized_run_from_rollback(self) -> None:
        second_artifact = Path(self.temporary.name) / "reports" / "second.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            second_artifact,
            b'{"workflow":"heartbeat","sequence":2}\n',
            workflow="heartbeat",
            run_id="canary-run-2",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection identity is immutable"
            ):
                connection.execute(
                    "DELETE FROM artifact_projections WHERE run_id='canary-run-2'"
                )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact, second_artifact),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_second_canary_run_cannot_reuse_artifact_path(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with self.assertRaisesRegex(DbAuthorityCanaryError, "already belongs"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run-2",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

    def test_expired_prepared_canary_can_exact_recover_and_rollback(self) -> None:
        deadline = "2027-01-01T00:00:00+00:00"
        with mock.patch.object(
            canary_module,
            "_utc_now",
            return_value=("2026-01-01T00:00:00+00:00", 1767225600000),
        ), self.assertRaisesRegex(DbAuthorityCanaryError, "simulated crash"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline=deadline,
                last_parity_audit_hash=self.parity_hash,
                crash_after_prepare=True,
            )

        with mock.patch.object(
            canary_module,
            "_utc_now",
            side_effect=[
                ("2028-01-01T00:00:00+00:00", 1830297600000),
                ("2028-01-01T00:00:01+00:00", 1830297601000),
            ],
        ):
            recovered = db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline=deadline,
                last_parity_audit_hash=self.parity_hash,
            )
        self.assertEqual(recovered.status, "recovered")
        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_rollback_rejects_outside_and_nonexistent_databases(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with tempfile.TemporaryDirectory() as outside:
            outside_db = Path(outside) / "canary.db"
            shutil.copy2(self.database, outside_db)
            with self.assertRaisesRegex(DbAuthorityCanaryError, "privacy preflight"):
                rollback_db_authority_canary(
                    outside_db,
                    (self.artifact,),
                    workflow="heartbeat",
                )
            missing_db = Path(outside) / "missing.db"
            with self.assertRaisesRegex(DbAuthorityCanaryError, "privacy preflight"):
                rollback_db_authority_canary(
                    missing_db,
                    (self.artifact,),
                    workflow="heartbeat",
                )
            self.assertFalse(missing_db.exists())

    def test_canary_writer_rejects_preexisting_hard_link_before_migration(self) -> None:
        self.database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
            connection.execute("INSERT INTO sentinel VALUES('unchanged')")
        self.database.chmod(0o600)
        with tempfile.TemporaryDirectory() as outside:
            alias = Path(outside) / "external-hard-link.db"
            os.link(self.database, alias)
            before = alias.read_bytes()

            with self.assertRaisesRegex(DbAuthorityCanaryError, "hard-linked"):
                db_authority_canary_artifact(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="heartbeat",
                    run_id="canary-run",
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline="2099-01-01T00:00:00+00:00",
                    last_parity_audit_hash=self.parity_hash,
                )

            self.assertEqual(alias.read_bytes(), before)
            with sqlite3.connect(alias) as connection:
                self.assertEqual(
                    connection.execute("SELECT value FROM sentinel").fetchone(),
                    ("unchanged",),
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='schema_migrations'"
                    ).fetchone()
                )

    def test_canary_writer_rejects_unsafe_sidecar_before_migration(self) -> None:
        self.database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
            connection.execute("INSERT INTO sentinel VALUES('unchanged')")
        self.database.chmod(0o600)
        sidecar = Path(f"{self.database}-wal")
        sidecar.symlink_to(self.database.parent / "missing-sidecar-target")

        with self.assertRaisesRegex(DbAuthorityCanaryError, "sidecar"):
            db_authority_canary_artifact(
                self.database,
                self.artifact,
                self.payload,
                workflow="heartbeat",
                run_id="canary-run",
                cutover_approved_by="local-fixture",
                cutover_evidence_hash=self.cutover_hash,
                rollback_deadline="2099-01-01T00:00:00+00:00",
                last_parity_audit_hash=self.parity_hash,
            )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT value FROM sentinel").fetchone(),
                ("unchanged",),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='schema_migrations'"
                ).fetchone()
            )

    def test_canary_projection_prevents_run_binding_tampering(self) -> None:
        second_artifact = Path(self.temporary.name) / "reports" / "second.json"
        other_artifact = Path(self.temporary.name) / "reports" / "other.json"
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            second_artifact,
            b'{"workflow":"heartbeat","sequence":2}\n',
            workflow="heartbeat",
            run_id="canary-run-2",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        db_authority_canary_artifact(
            self.database,
            other_artifact,
            b'{"workflow":"other","synthetic":true}\n',
            workflow="other",
            run_id="other-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )

        with sqlite3.connect(self.database, isolation_level=None) as connection:
            _register_migration_functions(connection)
            for statement in (
                "UPDATE artifact_projections SET source_authority='file_authority' "
                "WHERE run_id='canary-run-2'",
                "UPDATE artifact_projections SET run_id='other-run' "
                "WHERE run_id='canary-run-2'",
                "UPDATE artifact_projections SET path='tmp/tampered.json' "
                "WHERE run_id='canary-run-2'",
                "UPDATE artifact_projections SET sha256=? "
                "WHERE run_id='canary-run-2'",
                "DELETE FROM artifact_projections WHERE run_id='canary-run-2'",
            ):
                parameters = ("f" * 64,) if "sha256=?" in statement else ()
                with self.subTest(statement=statement), self.assertRaisesRegex(
                    sqlite3.IntegrityError, "canary projection identity is immutable"
                ):
                    connection.execute(statement, parameters)
            for statement in (
                "UPDATE runs SET authority_mode='file_authority' "
                "WHERE run_id='canary-run-2'",
                "UPDATE runs SET workflow='other' WHERE run_id='canary-run-2'",
                "UPDATE runs SET state='prepared' WHERE run_id='canary-run-2'",
                "UPDATE runs SET risk_dominance='R2' WHERE run_id='canary-run-2'",
                "UPDATE runs SET prepare_idempotency_key='other-prepare' "
                "WHERE run_id='canary-run-2'",
                "UPDATE runs SET finalized_at='tampered' "
                "WHERE run_id='canary-run-2'",
            ):
                with self.subTest(statement=statement), self.assertRaisesRegex(
                    sqlite3.IntegrityError, "canary projection binding is immutable"
                ):
                    connection.execute(statement)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection identity is immutable"
            ):
                connection.execute(
                    "INSERT INTO artifact_projections("
                    "projection_id,run_id,path,sha256,source_authority,generated_at) "
                    "VALUES('non-canary-extra','canary-run-2','tmp/extra.json',?,"
                    "'file_authority','now')",
                    ("f" * 64,),
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary workflow binding is immutable"
            ):
                connection.execute(
                    "UPDATE workflow_authority SET mode='file_authority' "
                    "WHERE workflow='heartbeat'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary workflow binding is immutable"
            ):
                connection.execute(
                    "UPDATE workflow_authority SET mode='rollback_to_file_authority' "
                    "WHERE workflow='heartbeat'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary workflow binding is immutable"
            ):
                connection.execute(
                    "UPDATE workflow_authority SET cutover_evidence_hash=? "
                    "WHERE workflow='heartbeat'",
                    ("f" * 64,),
                )
            self.assertEqual(
                connection.execute(
                    "SELECT workflow,authority_mode FROM runs "
                    "WHERE run_id='canary-run-2'"
                ).fetchone(),
                ("heartbeat", "db_authority_canary"),
            )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact, second_artifact),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_insert_or_replace_cannot_remove_canary_projection(self) -> None:
        written = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        original = (
            written.projection.projection_id,
            "canary-run",
            written.projection.path,
            written.projection.sha256,
            "db_authority_canary",
        )

        with sqlite3.connect(self.database, isolation_level=None) as connection:
            _register_migration_functions(connection)
            replacements = (
                (
                    written.projection.projection_id,
                    "canary-run",
                    "tmp/replacement-primary.json",
                    "f" * 64,
                    "file_authority",
                    "now",
                ),
                (
                    "non-canary-replacement",
                    "canary-run",
                    written.projection.path,
                    written.projection.sha256,
                    "file_authority",
                    "now",
                ),
            )
            for replacement in replacements:
                with self.subTest(replacement=replacement), self.assertRaisesRegex(
                    sqlite3.IntegrityError, "canary projection identity is immutable"
                ):
                    connection.execute(
                        "INSERT OR REPLACE INTO artifact_projections("
                        "projection_id,run_id,path,sha256,source_authority,generated_at) "
                        "VALUES(?,?,?,?,?,?)",
                        replacement,
                    )
            self.assertEqual(
                connection.execute(
                    "SELECT projection_id,run_id,path,sha256,source_authority "
                    "FROM artifact_projections WHERE run_id='canary-run'"
                ).fetchone(),
                original,
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection binding is immutable"
            ):
                connection.execute(
                    "UPDATE runs SET authority_mode='file_authority' "
                    "WHERE run_id='canary-run'"
                )

        rollback = rollback_db_authority_canary(
            self.database,
            (self.artifact,),
            workflow="heartbeat",
        )
        self.assertEqual(rollback.status, "rolled_back")

    def test_canary_rejects_malformed_and_past_deadlines(self) -> None:
        for deadline in ("not-a-time", "2000-01-01T00:00:00+00:00"):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(
                DbAuthorityCanaryError, "rollback_deadline"
            ):
                db_authority_canary_artifact(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="heartbeat",
                    run_id="canary-run",
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline=deadline,
                    last_parity_audit_hash=self.parity_hash,
                )

    def test_replay_rejects_corrupted_finalization_metadata(self) -> None:
        db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        with sqlite3.connect(self.database) as connection:
            _register_migration_functions(connection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "canary projection binding is immutable"
            ):
                connection.execute(
                    "UPDATE runs SET finalized_at='tampered' WHERE run_id='canary-run'"
                )

        replay = db_authority_canary_artifact(
            self.database,
            self.artifact,
            self.payload,
            workflow="heartbeat",
            run_id="canary-run",
            cutover_approved_by="local-fixture",
            cutover_evidence_hash=self.cutover_hash,
            rollback_deadline="2099-01-01T00:00:00+00:00",
            last_parity_audit_hash=self.parity_hash,
        )
        self.assertEqual(replay.status, "replayed")

    def test_canary_reads_authority_disable_flag_at_call_time(self) -> None:
        original = agentic_os.DB_AUTHORITY_ENABLED
        agentic_os.DB_AUTHORITY_ENABLED = True
        try:
            with self.assertRaisesRegex(
                DbAuthorityCanaryError, "production DB authority must remain disabled"
            ):
                db_authority_canary_artifact(
                    self.database,
                    self.artifact,
                    self.payload,
                    workflow="heartbeat",
                    run_id="canary-run",
                    cutover_approved_by="local-fixture",
                    cutover_evidence_hash=self.cutover_hash,
                    rollback_deadline="2099-01-01T00:00:00+00:00",
                    last_parity_audit_hash=self.parity_hash,
                )
        finally:
            agentic_os.DB_AUTHORITY_ENABLED = original

    def test_canary_cli_write_and_rollback(self) -> None:
        status = cli_main(
            [
                "db-authority-canary",
                "--db",
                str(self.database),
                "--workflow",
                "heartbeat",
                "--run-id",
                "canary-run",
                "--cutover-approved-by",
                "local-fixture",
                "--cutover-evidence-hash",
                self.cutover_hash,
                "--rollback-deadline",
                "2099-01-01T00:00:00+00:00",
                "--last-parity-audit-hash",
                self.parity_hash,
                "--artifact",
                str(self.artifact),
                "--content",
                self.payload.decode("utf-8"),
            ]
        )
        self.assertEqual(status, 0)

        rollback_status = cli_main(
            [
                "db-authority-canary-rollback",
                "--db",
                str(self.database),
                "--workflow",
                "heartbeat",
                "--artifact",
                str(self.artifact),
            ]
        )
        self.assertEqual(rollback_status, 0)

    def test_expansion_controller_cli_emits_artifact_only_proof(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli_main(
                [
                    "db-authority-expansion",
                    "--db",
                    str(self.database),
                    "--workflow",
                    "local-artifact-canary",
                    "--run-id",
                    "canary-run",
                    "--risk-class",
                    "R1",
                    "--risk-dominance",
                    "R1",
                    "--worker-agent-id",
                    "phase-b-ai-engineer",
                    "--verifier-agent-id",
                    "phase-a-security-engineer",
                    "--verifier-run-id",
                    "phase-a-boundary-review",
                    "--eligibility-proof-json",
                    json.dumps(self._eligibility_proof(), sort_keys=True),
                    "--cutover-approved-by",
                    "local-fixture",
                    "--cutover-evidence-hash",
                    self.cutover_hash,
                    "--rollback-deadline",
                    "2099-01-01T00:00:00+00:00",
                    "--last-parity-audit-hash",
                    self.parity_hash,
                    "--artifact",
                    str(self.artifact),
                    "--content",
                    self.payload.decode("utf-8"),
                ]
            )

        self.assertEqual(status, 0)
        emitted = output.getvalue()
        self.assertIn("db-authority expansion written", emitted)
        self.assertIn('"artifact_only":true', emitted)
        self.assertIn('"db_authority_enabled":false', emitted)
        self.assertIn('"real_session_rpc":false', emitted)


if __name__ == "__main__":
    unittest.main()
