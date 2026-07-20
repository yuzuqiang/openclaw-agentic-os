"""Per-workflow synthetic DB-authority expansion controller."""

from __future__ import annotations

import json
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import agentic_os
from .db_authority_canary import (
    DbAuthorityCanaryError,
    DbAuthorityCanaryResult,
    DbAuthorityRollbackResult,
    _canary_rollback_proof_hash,
    _normalize_deadline,
    _sha256_text,
    db_authority_canary_artifact,
    rollback_db_authority_canary,
)
from .shadow import (
    ShadowProjection,
    _normalize_artifact_target,
    _normalize_required_identity,
    _projection_id,
)


SYNTHETIC_WORKFLOW = "local-artifact-canary"
SUPPORTED_RISK_CLASS = "R1"
SUPPORTED_RISK_DOMINANCE = "R1"
HUMAN_REQUIRED_RISKS = frozenset(("R3", "R4"))
ELIGIBILITY_PROOF_VERSION = "synthetic_db_authority_expansion_eligibility_v1"
CANARY_EVIDENCE_VERSION = "synthetic_db_authority_expansion_canary_v1"
GATE_EVIDENCE_VERSION = "synthetic_db_authority_expansion_gate_v1"


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
    eligibility_proof: Mapping[str, object],
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

    _assert_db_authority_disabled()
    _assert_controller_boundary(
        workflow=workflow,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
    )
    expected_proof = expected_synthetic_expansion_eligibility_proof(
        artifact,
        content,
        workflow=workflow,
        run_id=run_id,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
        cutover_approved_by=cutover_approved_by,
        cutover_evidence_hash=cutover_evidence_hash,
        rollback_deadline=rollback_deadline,
        last_parity_audit_hash=last_parity_audit_hash,
        eligibility_proof=eligibility_proof,
        repo_root_path=repo_root_path,
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
    _assert_canary_matches_eligibility(canary, expected_proof)
    db_authority_enabled = _assert_db_authority_disabled()
    proof = _controller_proof(
        workflow=workflow,
        run_id=run_id,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
        canary_status=canary.status,
        rollback_status=None,
        projections=(canary.projection,),
        eligibility_proof=expected_proof,
        db_authority_enabled=db_authority_enabled,
    )
    return DbAuthorityControllerResult(
        workflow=workflow,
        run_id=run_id,
        canary=canary,
        controller_status="artifact_only_canary_recorded",
        db_authority_enabled=db_authority_enabled,
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

    _assert_db_authority_disabled()
    _assert_supported_workflow(workflow)
    rollback = rollback_db_authority_canary(
        database,
        artifacts,
        workflow=workflow,
        repo_root_path=repo_root_path,
    )
    db_authority_enabled = _assert_db_authority_disabled()
    proof = _controller_proof(
        workflow=workflow,
        run_id="",
        risk_class=SUPPORTED_RISK_CLASS,
        risk_dominance=SUPPORTED_RISK_DOMINANCE,
        canary_status=None,
        rollback_status=rollback.status,
        projections=rollback.regenerated,
        eligibility_proof=None,
        db_authority_enabled=db_authority_enabled,
    )
    return DbAuthorityControllerRollbackResult(
        workflow=workflow,
        rollback=rollback,
        controller_status="artifact_only_canary_rolled_back",
        db_authority_enabled=db_authority_enabled,
        proof=proof,
    )


def proof_json(proof: dict[str, object]) -> str:
    """Return deterministic controller proof for CLI/log artifacts."""

    return json.dumps(proof, sort_keys=True, separators=(",", ":"))


def expected_synthetic_expansion_eligibility_proof(
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
    worker_agent_id: str | None = None,
    verifier_agent_id: str | None = None,
    verifier_run_id: str | None = None,
    eligibility_proof: Mapping[str, object] | None = None,
    repo_root_path: Path | None = None,
) -> dict[str, object]:
    """Build or validate the exact local proof required before canary authority.

    R1 does not require a production PASS-gate row, but this controller still
    requires a local independent proof bundle bound to the exact workflow, run,
    parity hash, projection identity, and deterministic rollback regeneration
    hash. The proof is artifact-only and carries explicit no-RPC boundaries.
    """

    workflow = _normalize_required_identity("workflow", workflow)
    run_id = _normalize_required_identity("run_id", run_id)
    risk_class = _normalize_required_identity("risk_class", risk_class)
    risk_dominance = _normalize_required_identity("risk_dominance", risk_dominance)
    cutover_approved_by = _normalize_required_identity(
        "cutover_approved_by", cutover_approved_by
    )
    cutover_evidence_hash = _sha256_text(
        "cutover_evidence_hash", cutover_evidence_hash
    )
    rollback_deadline, _rollback_deadline_epoch_ms = _normalize_deadline(
        rollback_deadline
    )
    last_parity_audit_hash = _sha256_text(
        "last_parity_audit_hash", last_parity_audit_hash
    )
    if not content:
        raise DbAuthorityControllerError("content must be non-empty")
    _assert_controller_boundary(
        workflow=workflow,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
    )

    if eligibility_proof is not None:
        worker_agent_id = _required_proof_text(
            eligibility_proof, "worker_agent_id"
        )
        verifier_agent_id = _required_proof_text(
            eligibility_proof, "verifier_agent_id"
        )
        verifier_run_id = _required_proof_text(eligibility_proof, "verifier_run_id")
    else:
        worker_agent_id = _normalize_required_identity(
            "worker_agent_id", worker_agent_id
        )
        verifier_agent_id = _normalize_required_identity(
            "verifier_agent_id", verifier_agent_id
        )
        verifier_run_id = _normalize_required_identity(
            "verifier_run_id", verifier_run_id
        )
    if worker_agent_id == verifier_agent_id or verifier_run_id == run_id:
        raise DbAuthorityControllerError(
            "synthetic expansion gate proof must be independent"
        )

    projection = _expected_projection(
        artifact, content, run_id=run_id, repo_root_path=repo_root_path
    )
    rollback_proof_hash = _canary_rollback_proof_hash(workflow, (projection,))
    canary_evidence_hash = _synthetic_canary_evidence_hash(
        workflow=workflow,
        run_id=run_id,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
        cutover_approved_by=cutover_approved_by,
        cutover_evidence_hash=cutover_evidence_hash,
        rollback_deadline=rollback_deadline,
        last_parity_audit_hash=last_parity_audit_hash,
        projection=projection,
    )
    gate_evidence_hash = _synthetic_gate_evidence_hash(
        workflow=workflow,
        run_id=run_id,
        risk_class=risk_class,
        risk_dominance=risk_dominance,
        worker_agent_id=worker_agent_id,
        verifier_agent_id=verifier_agent_id,
        verifier_run_id=verifier_run_id,
        canary_evidence_hash=canary_evidence_hash,
        rollback_proof_hash=rollback_proof_hash,
    )
    expected: dict[str, object] = {
        "version": ELIGIBILITY_PROOF_VERSION,
        "workflow": workflow,
        "run_id": run_id,
        "risk_class": risk_class,
        "risk_dominance": risk_dominance,
        "gate_decision": "not_required",
        "gate_requirement": "R1 local synthetic artifact-only slice",
        "worker_agent_id": worker_agent_id,
        "verifier_agent_id": verifier_agent_id,
        "verifier_run_id": verifier_run_id,
        "canary_status": "eligible",
        "canary_evidence_hash": canary_evidence_hash,
        "rollback_status": "regenerable",
        "rollback_proof_hash": rollback_proof_hash,
        "parity_audit_hash": last_parity_audit_hash,
        "projection": {
            "path": projection.path,
            "projection_id": projection.projection_id,
            "sha256": projection.sha256,
            "source_authority": "db_authority_canary",
        },
        "projection_count": 1,
        "gate_evidence_hash": gate_evidence_hash,
        "workflow_isolation": workflow == SYNTHETIC_WORKFLOW,
        "artifact_only": True,
        "real_openclaw_rpc": False,
        "real_gateway_rpc": False,
        "real_cron_rpc": False,
        "real_session_rpc": False,
        "db_authority_enabled": False,
        "r3_r4_human_required": True,
    }
    expected["eligibility_hash"] = _proof_hash(expected)
    if eligibility_proof is not None:
        _assert_exact_proof(eligibility_proof, expected)
    return expected


def _assert_db_authority_disabled() -> bool:
    if agentic_os.DB_AUTHORITY_ENABLED:
        raise DbAuthorityControllerError("production DB authority must remain disabled")
    return False


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


def _required_proof_text(proof: Mapping[str, object], key: str) -> str:
    value = proof.get(key)
    if not isinstance(value, str):
        raise DbAuthorityControllerError(f"eligibility proof {key} must be text")
    return _normalize_required_identity(key, value)


def _expected_projection(
    artifact: str | Path,
    content: bytes,
    *,
    run_id: str,
    repo_root_path: Path | None,
) -> ShadowProjection:
    root = Path(repo_root_path or Path(__file__).resolve().parents[2]).resolve()
    _target, relative = _normalize_artifact_target(artifact, repo_root_path=root)
    digest = hashlib.sha256(content).hexdigest()
    return ShadowProjection(
        path=relative,
        sha256=digest,
        projection_id=_projection_id(run_id, relative, digest),
    )


def _synthetic_canary_evidence_hash(
    *,
    workflow: str,
    run_id: str,
    risk_class: str,
    risk_dominance: str,
    cutover_approved_by: str,
    cutover_evidence_hash: str,
    rollback_deadline: str,
    last_parity_audit_hash: str,
    projection: ShadowProjection,
) -> str:
    return _digest(
        {
            "source": CANARY_EVIDENCE_VERSION,
            "workflow": workflow,
            "run_id": run_id,
            "risk_class": risk_class,
            "risk_dominance": risk_dominance,
            "cutover_approved_by": cutover_approved_by,
            "cutover_evidence_hash": cutover_evidence_hash,
            "rollback_deadline": rollback_deadline,
            "last_parity_audit_hash": last_parity_audit_hash,
            "projection": {
                "path": projection.path,
                "projection_id": projection.projection_id,
                "sha256": projection.sha256,
                "source_authority": "db_authority_canary",
            },
        }
    )


def _synthetic_gate_evidence_hash(
    *,
    workflow: str,
    run_id: str,
    risk_class: str,
    risk_dominance: str,
    worker_agent_id: str,
    verifier_agent_id: str,
    verifier_run_id: str,
    canary_evidence_hash: str,
    rollback_proof_hash: str,
) -> str:
    return _digest(
        {
            "source": GATE_EVIDENCE_VERSION,
            "workflow": workflow,
            "run_id": run_id,
            "risk_class": risk_class,
            "risk_dominance": risk_dominance,
            "gate_decision": "not_required",
            "worker_agent_id": worker_agent_id,
            "verifier_agent_id": verifier_agent_id,
            "verifier_run_id": verifier_run_id,
            "canary_evidence_hash": canary_evidence_hash,
            "rollback_proof_hash": rollback_proof_hash,
        }
    )


def _assert_exact_proof(
    proof: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    if not isinstance(proof, Mapping):
        raise DbAuthorityControllerError("eligibility proof must be an object")
    if set(proof) != set(expected):
        raise DbAuthorityControllerError(
            "eligibility proof must contain exactly the required keys"
        )
    if proof != expected:
        raise DbAuthorityControllerError(
            "eligibility proof does not match the exact synthetic expansion boundary"
        )


def _assert_canary_matches_eligibility(
    canary: DbAuthorityCanaryResult, proof: Mapping[str, object]
) -> None:
    projection = proof["projection"]
    if not isinstance(projection, Mapping):
        raise DbAuthorityControllerError("eligibility proof projection must be an object")
    if (
        canary.workflow != proof["workflow"]
        or canary.run_id != proof["run_id"]
        or canary.projection.path != projection.get("path")
        or canary.projection.projection_id != projection.get("projection_id")
        or canary.projection.sha256 != projection.get("sha256")
    ):
        raise DbAuthorityControllerError(
            "canary result drifted from the exact eligibility proof"
        )


def _digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _proof_hash(proof: Mapping[str, object]) -> str:
    payload = {key: value for key, value in proof.items() if key != "eligibility_hash"}
    return _digest(payload)


def _projection_proof(projection: ShadowProjection) -> dict[str, object]:
    return {
        "path": projection.path,
        "projection_id": projection.projection_id,
        "sha256": projection.sha256,
        "source_authority": "db_authority_canary",
    }


def _controller_proof(
    *,
    workflow: str,
    run_id: str,
    risk_class: str,
    risk_dominance: str,
    canary_status: str | None,
    rollback_status: str | None,
    projections: tuple[ShadowProjection, ...],
    eligibility_proof: Mapping[str, object] | None,
    db_authority_enabled: bool,
) -> dict[str, object]:
    projection_proofs = [_projection_proof(projection) for projection in projections]
    return {
        "controller": "per_workflow_db_authority_expansion_v1",
        "workflow": workflow,
        "run_id": run_id,
        "risk_class": risk_class,
        "risk_dominance": risk_dominance,
        "canary_status": canary_status,
        "rollback_status": rollback_status,
        "projection_count": len(projection_proofs),
        "projections": projection_proofs,
        "eligibility_proof": dict(eligibility_proof) if eligibility_proof else None,
        "rollback_proof_hash": (
            _canary_rollback_proof_hash(workflow, projections)
            if projections
            else None
        ),
        "workflow_isolation": workflow == SYNTHETIC_WORKFLOW,
        "artifact_only": True,
        "real_openclaw_rpc": False,
        "real_gateway_rpc": False,
        "real_cron_rpc": False,
        "real_session_rpc": False,
        "db_authority_enabled": db_authority_enabled,
        "r3_r4_human_required": True,
    }
