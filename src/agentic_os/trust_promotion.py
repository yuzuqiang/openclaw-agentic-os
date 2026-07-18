"""Local-only trust promotion writer with fail-closed evidence binding."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .migrations import (
    MigrationError,
    _register_migration_functions,
    _trust_binding_hash,
    verify_database_connection,
)
from .pass_gates import (
    GateEvidence,
    PassGateError,
    _assert_evidence_snapshot_current,
    _connect,
    _validate_evidence,
)
from .slo_contracts import SLO_QUERY_CONTRACTS


class TrustPromotionError(RuntimeError):
    """Trust promotion evidence could not be proven safe."""


@dataclass(frozen=True)
class TrustObservationRecord:
    observation_id: str
    run_id: str
    goal_run_id: str
    evidence_hash: str
    gate_run_id: str
    verifier_run_id: str
    schema_version: int
    migration_sha256: str
    blocking_slo_query_count: int
    blocking_slo_bundle_hash: str


def promote_trust(
    database: Path,
    *,
    observation_id: str,
    scope: str,
    severity: str,
    effective_group_id: str,
    run_id: str,
    goal_run_id: str,
    evidence_hash: str,
    bounded_at: str,
    created_at: str,
) -> TrustObservationRecord:
    """Persist one active trust observation only after all local gates bind.

    The writer opens an already migrated private SQLite database, uses
    ``BEGIN IMMEDIATE``, re-verifies the full migration/schema/SLO identity,
    derives all authority fields from the database, rechecks the evidence
    artifact just before commit, and never calls OpenClaw/Gateway/Cron or any
    production authority surface.
    """

    observation_id = _required_text("observation_id", observation_id)
    scope = _required_text("scope", scope)
    severity = _required_text("severity", severity)
    effective_group_id = _required_text("effective_group_id", effective_group_id)
    run_id = _required_text("run_id", run_id)
    goal_run_id = _required_text("goal_run_id", goal_run_id)
    evidence_hash = _sha256_text("evidence_hash", evidence_hash)
    bounded_at = _required_text("bounded_at", bounded_at)
    created_at = _required_text("created_at", created_at)

    try:
        connection = _connect(database)
    except PassGateError as exc:
        raise TrustPromotionError(str(exc)) from exc
    try:
        _register_migration_functions(connection)
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            _verify_current_blocking_slos(connection)
            binding = _bound_evidence(
                connection,
                run_id=run_id,
                goal_run_id=goal_run_id,
                evidence_hash=evidence_hash,
            )
            evidence_snapshot = _safe_current_evidence_snapshot(
                connection,
                run_id=run_id,
                evidence_hash=evidence_hash,
                verifier_run_id=binding["verifier_run_id"],
                gate_run_id=binding["gate_run_id"],
            )
            bundle_hash = _trust_binding_hash(
                run_id,
                goal_run_id,
                evidence_hash,
                binding["verifier_run_id"],
                binding["gate_run_id"],
                binding["schema_version"],
                binding["migration_sha256"],
                binding["current_slo_query_count"],
            )
            if not bundle_hash:
                raise TrustPromotionError("trust promotion binding hash could not be derived")
            if effective_group_id != bundle_hash:
                raise TrustPromotionError("effective_group_id must match bound evidence")
            connection.execute(
                "INSERT INTO trust_observations("
                "observation_id,scope,severity,status,effective_group_id,"
                "verifier_run_id,gate_run_id,usage_confidence,bounded_at,"
                "created_at,run_id,goal_run_id,evidence_hash,evidence_run_id,"
                "transition_id,approval_id,approval_hash,schema_version,"
                "migration_sha256,blocking_slo_query_count,"
                "blocking_slo_pass_audit_count,blocking_slo_bundle_hash,"
                "clock_context_id,gate_clock_epoch_ms,trusted_clock_source_hash,"
                "run_authority_mode,workflow_authority_mode,"
                "selected_cost_registry_id,selected_cost_registry_hash,"
                "cost_confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?,?,?,?,?,?,?,?)",
                (
                    observation_id,
                    scope,
                    severity,
                    "promoted",
                    effective_group_id,
                    binding["verifier_run_id"],
                    binding["gate_run_id"],
                    "known",
                    bounded_at,
                    created_at,
                    run_id,
                    goal_run_id,
                    evidence_hash,
                    binding["evidence_run_id"],
                    binding["transition_id"],
                    binding["approval_id"],
                    binding["approval_hash"],
                    binding["schema_version"],
                    binding["migration_sha256"],
                    binding["current_slo_query_count"],
                    binding["current_slo_query_count"],
                    bundle_hash,
                    binding["clock_context_id"],
                    binding["gate_clock_epoch_ms"],
                    binding["trusted_clock_source_hash"],
                    binding["run_authority_mode"],
                    binding["workflow_authority_mode"],
                    binding["selected_cost_registry_id"],
                    binding["selected_cost_registry_hash"],
                    "known",
                ),
            )
            _assert_evidence_snapshot_current(evidence_snapshot)
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise TrustPromotionError(str(exc)) from exc
    finally:
        connection.close()

    return TrustObservationRecord(
        observation_id=observation_id,
        run_id=run_id,
        goal_run_id=goal_run_id,
        evidence_hash=evidence_hash,
        gate_run_id=binding["gate_run_id"],
        verifier_run_id=binding["verifier_run_id"],
        schema_version=binding["schema_version"],
        migration_sha256=binding["migration_sha256"],
        blocking_slo_query_count=binding["current_slo_query_count"],
        blocking_slo_bundle_hash=bundle_hash,
    )


def _verify_schema_identity(connection: sqlite3.Connection) -> None:
    try:
        verify_database_connection(connection)
    except (MigrationError, sqlite3.Error) as exc:
        raise TrustPromotionError("trust promotion database schema verification failed") from exc


def _verify_current_blocking_slos(connection: sqlite3.Connection) -> None:
    for contract in SLO_QUERY_CONTRACTS:
        try:
            row = connection.execute(contract.sql_text).fetchone()
        except sqlite3.Error as exc:
            raise TrustPromotionError("trust promotion SLO recheck failed") from exc
        if row is not None:
            raise TrustPromotionError("trust promotion requires current blocking SLO pass")


def _bound_evidence(
    connection: sqlite3.Connection, *, run_id: str, goal_run_id: str, evidence_hash: str
) -> dict[str, object]:
    row = connection.execute(
        "SELECT evidence_run_id,verifier_run_id,gate_run_id,transition_id,"
        "approval_id,approval_hash,clock_context_id,gate_clock_epoch_ms,"
        "trusted_clock_source_hash,schema_version,migration_sha256,"
        "run_authority_mode,workflow_authority_mode,selected_cost_registry_id,"
        "selected_cost_registry_hash,current_slo_query_count "
        "FROM trust_promotion_bound_evidence "
        "WHERE run_id=? AND goal_run_id=? AND evidence_hash=?",
        (run_id, goal_run_id, evidence_hash),
    ).fetchone()
    if row is None:
        raise TrustPromotionError("trust promotion requires complete bound evidence")
    keys = (
        "evidence_run_id",
        "verifier_run_id",
        "gate_run_id",
        "transition_id",
        "approval_id",
        "approval_hash",
        "clock_context_id",
        "gate_clock_epoch_ms",
        "trusted_clock_source_hash",
        "schema_version",
        "migration_sha256",
        "run_authority_mode",
        "workflow_authority_mode",
        "selected_cost_registry_id",
        "selected_cost_registry_hash",
        "current_slo_query_count",
    )
    return dict(zip(keys, row))


def _safe_current_evidence_snapshot(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    evidence_hash: str,
    verifier_run_id: object,
    gate_run_id: object,
) -> object:
    row = connection.execute(
        "SELECT path,sha256,size_bytes,content_type,redaction_status,captured_at "
        "FROM evidence_hashes WHERE run_id=? AND evidence_hash=? "
        "AND sha256=? AND producer_run_id=? AND verifier_run_id=? "
        "AND gate_run_id=?",
        (run_id, evidence_hash, evidence_hash, run_id, verifier_run_id, gate_run_id),
    ).fetchone()
    if row is None:
        raise TrustPromotionError("trust promotion evidence artifact binding is missing")
    try:
        snapshot = _validate_evidence(
            GateEvidence(
                path=row[0],
                sha256=row[1],
                size_bytes=row[2],
                content_type=row[3],
                redaction_status=row[4],
                captured_at=row[5],
            )
        )
        _assert_evidence_snapshot_current(snapshot)
        return snapshot
    except PassGateError as exc:
        raise TrustPromotionError("trust promotion evidence artifact changed") from exc


def _required_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TrustPromotionError(f"{name} must be non-empty text")
    return value


def _sha256_text(name: str, value: object) -> str:
    text = _required_text(name, value)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise TrustPromotionError(f"{name} must be lowercase SHA-256")
    return text
