"""Per-workflow synthetic DB-authority expansion controller."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import agentic_os
from .db_authority_canary import (
    DbAuthorityCanaryError,
    DbAuthorityCanaryResult,
    DbAuthorityRollbackResult,
    db_authority_canary_artifact,
    rollback_db_authority_canary,
)
from .shadow import _normalize_required_identity


SYNTHETIC_WORKFLOW = "local-artifact-canary"
SUPPORTED_RISK_CLASS = "R1"
SUPPORTED_RISK_DOMINANCE = "R1"
HUMAN_REQUIRED_RISKS = frozenset(("R3", "R4"))


class DbAuthorityControllerError(DbAuthorityCanaryError):
    """The per-workflow DB-authority controller rejected the expansion."""


@dataclass(frozen=True)
class DbAuthorityControllerResult:
    workflow: str
    run_id: str
    canary: DbAuthorityCanaryResult
    controller_status: str
    db_authority_enabled: bool
    proof: dict[str, object]


@dataclass(frozen=True)
class DbAuthorityControllerRollbackResult:
    workflow: str
    rollback: DbAuthorityRollbackResult
    controller_status: str
    db_authority_enabled: bool
    proof: dict[str, object]


def run_synthetic_db_authority_expansion(
    database: Path,
    artifact: str | Path,
    content: bytes,
    *,
    workflow: str,
    run_id: str,
    risk_class: str,
    risk_dominance: str,
    cutover_approved_by: str,
    cutover_evidence_hash: str,
    rollback_deadline: str,
    last_parity_audit_hash: str,
    prepare_idempotency_key: str | None = None,
    repo_root_path: Path | None = None,
    crash_after_prepare: bool = False,
) -> DbAuthorityControllerResult:
    """Run the one allowed artifact-only DB-authority expansion slice.

    This is a controller for P2.0 readiness evidence, not production authority.
    It deliberately admits only the fixed synthetic workflow and R1/R1 risk.
    R3/R4 remain human-required and are rejected instead of being downcast.
    """

    _assert_controller_boundary(
        workflow=workflow,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
    )
    canary = db_authority_canary_artifact(
        database,
        artifact,
        content,
        workflow=workflow,
        run_id=run_id,
        cutover_approved_by=cutover_approved_by,
        cutover_evidence_hash=cutover_evidence_hash,
        rollback_deadline=rollback_deadline,
        last_parity_audit_hash=last_parity_audit_hash,
        prepare_idempotency_key=prepare_idempotency_key,
        repo_root_path=repo_root_path,
        crash_after_prepare=crash_after_prepare,
    )
    proof = _controller_proof(
        workflow=workflow,
        run_id=run_id,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
        canary_status=canary.status,
        rollback_status=None,
        projection_count=1,
    )
    return DbAuthorityControllerResult(
        workflow=workflow,
        run_id=run_id,
        canary=canary,
        controller_status="artifact_only_canary_recorded",
        db_authority_enabled=agentic_os.DB_AUTHORITY_ENABLED,
        proof=proof,
    )


def rollback_synthetic_db_authority_expansion(
    database: Path,
    artifacts: tuple[str | Path, ...],
    *,
    workflow: str,
    repo_root_path: Path | None = None,
) -> DbAuthorityControllerRollbackResult:
    """Rollback the one allowed synthetic DB-authority expansion workflow."""

    _assert_supported_workflow(workflow)
    rollback = rollback_db_authority_canary(
        database,
        artifacts,
        workflow=workflow,
        repo_root_path=repo_root_path,
    )
    proof = _controller_proof(
        workflow=workflow,
        run_id="",
        risk_class=SUPPORTED_RISK_CLASS,
        risk_dominance=SUPPORTED_RISK_DOMINANCE,
        canary_status=None,
        rollback_status=rollback.status,
        projection_count=len(rollback.regenerated),
    )
    return DbAuthorityControllerRollbackResult(
        workflow=workflow,
        rollback=rollback,
        controller_status="artifact_only_canary_rolled_back",
        db_authority_enabled=agentic_os.DB_AUTHORITY_ENABLED,
        proof=proof,
    )


def proof_json(proof: dict[str, object]) -> str:
    """Return deterministic controller proof for CLI/log artifacts."""

    return json.dumps(proof, sort_keys=True, separators=(",", ":"))


def _assert_controller_boundary(
    *, workflow: str, risk_class: str, risk_dominance: str
) -> None:
    _assert_supported_workflow(workflow)
    risk_class = _normalize_required_identity("risk_class", risk_class)
    risk_dominance = _normalize_required_identity("risk_dominance", risk_dominance)
    if risk_class in HUMAN_REQUIRED_RISKS or risk_dominance in HUMAN_REQUIRED_RISKS:
        raise DbAuthorityControllerError(
            "R3/R4 DB-authority expansion remains human-required"
        )
    if (risk_class, risk_dominance) != (
        SUPPORTED_RISK_CLASS,
        SUPPORTED_RISK_DOMINANCE,
    ):
        raise DbAuthorityControllerError(
            "synthetic DB-authority expansion admits only R1/R1"
        )


def _assert_supported_workflow(workflow: str) -> None:
    workflow = _normalize_required_identity("workflow", workflow)
    if workflow != SYNTHETIC_WORKFLOW:
        raise DbAuthorityControllerError(
            f"unsupported DB-authority expansion workflow {workflow!r}; "
            f"only {SYNTHETIC_WORKFLOW!r} is enabled"
        )


def _controller_proof(
    *,
    workflow: str,
    run_id: str,
    risk_class: str,
    risk_dominance: str,
    canary_status: str | None,
    rollback_status: str | None,
    projection_count: int,
) -> dict[str, object]:
    return {
        "controller": "per_workflow_db_authority_expansion_v1",
        "workflow": workflow,
        "run_id": run_id,
        "risk_class": risk_class,
        "risk_dominance": risk_dominance,
        "canary_status": canary_status,
        "rollback_status": rollback_status,
        "projection_count": projection_count,
        "workflow_isolation": workflow == SYNTHETIC_WORKFLOW,
        "artifact_only": True,
        "real_openclaw_rpc": False,
        "real_gateway_rpc": False,
        "real_cron_rpc": False,
        "real_session_rpc": False,
        "db_authority_enabled": agentic_os.DB_AUTHORITY_ENABLED,
        "r3_r4_human_required": True,
    }
