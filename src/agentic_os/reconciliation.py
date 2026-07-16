"""Fail-closed reconciliation scanner for unknown metadata outcomes."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from agentic_os.metadata import (
    MetadataContractError,
    validate_accepted_session_identity,
    validate_allow_lease_observation,
    validate_allow_lease_release_observation,
    validate_session_observation,
)
from agentic_os.openclaw_adapter import MetadataCapableOpenClawAdapter, MetadataObservation
from agentic_os.runtime_dispatch import (
    AMBIGUOUS_TRANSPORT_ERRORS,
    DispatchRequest,
    RELEASE_FAILURE_ERRORS,
    RuntimeDispatchError,
    connect_runtime_db,
    immediate_transaction,
    lease_metadata,
    mark_human_review,
    mark_owned_lease_release_review,
    mark_owned_lease_release_unknown,
    persist_acquired_lease,
    persist_released_lease,
    persist_spawn_acceptance,
    release_metadata,
    release_owned_lease,
    spawn_metadata,
)


@dataclass(frozen=True)
class ReconciliationSummary:
    reconciled: int
    human_review_required: int


@dataclass(frozen=True)
class ReleasePendingRequest:
    request: DispatchRequest
    gateway_lease_id: str


def _unknown_spawn_requests(connection: sqlite3.Connection) -> list[DispatchRequest]:
    rows = connection.execute(
        "SELECT i.run_id,i.transition_id,i.phase,i.agent_id,l.requester_agent_id,"
        "i.task_digest,i.spawn_request_id,i.reserve_budget_event_id,l.client_lease_id,"
        "l.acquire_idempotency_key,COALESCE(l.release_idempotency_key,''),l.ttl_ms,"
        "i.client_request_id,i.idempotency_key,l.lease_id FROM external_rpc_intents i "
        "JOIN runtime_dispatch_bindings b ON b.spawn_request_id=i.spawn_request_id "
        "AND b.run_id=i.run_id AND b.transition_id=i.transition_id "
        "AND b.phase=i.phase AND b.agent_id=i.agent_id "
        "AND b.task_digest=i.task_digest "
        "AND b.spawn_client_request_id=i.client_request_id "
        "AND b.spawn_idempotency_key=i.idempotency_key "
        "JOIN leases l ON l.lease_id=b.lease_id AND l.run_id=b.run_id "
        "AND l.transition_id=b.transition_id AND l.phase=b.phase "
        "AND l.agent_id=b.agent_id AND l.requester_agent_id=b.requester_agent_id "
        "AND l.client_lease_id=b.client_lease_id "
        "AND l.acquire_idempotency_key=b.acquire_idempotency_key "
        "AND l.release_idempotency_key=b.release_idempotency_key "
        "WHERE i.rpc_kind='sessions_spawn' AND i.state IN ('pending','unknown')"
    ).fetchall()
    return [
        DispatchRequest(
            run_id=row[0],
            transition_id=row[1],
            phase=row[2],
            agent_id=row[3],
            requester_agent_id=row[4],
            task_digest=row[5],
            spawn_request_id=row[6],
            reserve_budget_event_id=row[7],
            client_lease_id=row[8],
            acquire_idempotency_key=row[9],
            release_idempotency_key=row[10] or f"reconcile-release:{row[8]}",
            ttl_ms=row[11],
            spawn_client_request_id=row[12],
            spawn_idempotency_key=row[13],
            lease_id=row[14],
        )
        for row in rows
    ]


def _unknown_lease_requests(connection: sqlite3.Connection) -> list[DispatchRequest]:
    rows = connection.execute(
        "SELECT i.run_id,i.transition_id,i.phase,i.agent_id,i.requester_agent_id,"
        "COALESCE(sr.task_digest,'unknown-task'),COALESCE(sr.spawn_request_id,'unknown-spawn'),"
        "COALESCE(i.reserve_budget_event_id,''),i.client_request_id,i.idempotency_key,"
        "COALESCE(l.release_idempotency_key,''),i.ttl_ms,COALESCE(sr.client_request_id,'unknown-client'),"
        "COALESCE(sr.spawn_idempotency_key,'unknown-spawn-idem'),l.lease_id "
        "FROM external_rpc_intents i "
        "JOIN runtime_dispatch_bindings b ON b.run_id=i.run_id "
        "AND b.transition_id=i.transition_id AND b.phase=i.phase "
        "AND b.agent_id=i.agent_id AND b.requester_agent_id=i.requester_agent_id "
        "AND b.client_lease_id=i.client_request_id "
        "AND b.acquire_idempotency_key=i.idempotency_key "
        "JOIN leases l ON l.lease_id=b.lease_id AND l.run_id=b.run_id "
        "AND l.transition_id=b.transition_id AND l.phase=b.phase "
        "AND l.agent_id=b.agent_id AND l.requester_agent_id=b.requester_agent_id "
        "AND l.client_lease_id=b.client_lease_id "
        "AND l.acquire_idempotency_key=b.acquire_idempotency_key "
        "AND l.release_idempotency_key=b.release_idempotency_key "
        "AND l.ttl_ms=i.ttl_ms "
        "JOIN spawn_requests sr ON sr.spawn_request_id=b.spawn_request_id "
        "AND sr.run_id=b.run_id AND sr.transition_id=b.transition_id "
        "AND sr.phase=b.phase AND sr.agent_id=b.agent_id "
        "AND sr.task_digest=b.task_digest "
        "AND sr.client_request_id=b.spawn_client_request_id "
        "AND sr.spawn_idempotency_key=b.spawn_idempotency_key "
        "WHERE i.rpc_kind='allow_lease_acquire' AND i.state IN ('pending','unknown')"
    ).fetchall()
    return [
        DispatchRequest(
            run_id=row[0],
            transition_id=row[1],
            phase=row[2],
            agent_id=row[3],
            requester_agent_id=row[4],
            task_digest=row[5],
            spawn_request_id=row[6],
            reserve_budget_event_id=row[7],
            client_lease_id=row[8],
            acquire_idempotency_key=row[9],
            release_idempotency_key=row[10] or f"reconcile-release:{row[8]}",
            ttl_ms=row[11],
            spawn_client_request_id=row[12],
            spawn_idempotency_key=row[13],
            lease_id=row[14],
        )
        for row in rows
    ]


def _orphan_unknown_lease_requests(connection: sqlite3.Connection) -> list[DispatchRequest]:
    rows = connection.execute(
        "SELECT i.run_id,i.transition_id,i.phase,i.agent_id,i.requester_agent_id,"
        "COALESCE(sr.task_digest,'unknown-task'),COALESCE(sr.spawn_request_id,'unknown-spawn'),"
        "COALESCE(i.reserve_budget_event_id,''),i.client_request_id,i.idempotency_key,"
        "i.ttl_ms,COALESCE(sr.client_request_id,'unknown-client'),"
        "COALESCE(sr.spawn_idempotency_key,'unknown-spawn-idem') "
        "FROM external_rpc_intents i "
        "LEFT JOIN spawn_requests sr ON sr.run_id=i.run_id AND sr.transition_id=i.transition_id "
        "WHERE i.rpc_kind='allow_lease_acquire' AND i.state IN ('pending','unknown') "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM leases l "
        "  WHERE l.run_id=i.run_id AND l.transition_id=i.transition_id "
        "  AND l.phase=i.phase AND l.agent_id=i.agent_id "
        "  AND l.requester_agent_id=i.requester_agent_id "
        "  AND l.client_lease_id=i.client_request_id "
        "  AND l.acquire_idempotency_key=i.idempotency_key "
        "  AND l.ttl_ms=i.ttl_ms"
        ")"
    ).fetchall()
    return [
        DispatchRequest(
            run_id=row[0],
            transition_id=row[1],
            phase=row[2],
            agent_id=row[3],
            requester_agent_id=row[4],
            task_digest=row[5],
            spawn_request_id=row[6],
            reserve_budget_event_id=row[7],
            client_lease_id=row[8],
            acquire_idempotency_key=row[9],
            release_idempotency_key=f"reconcile-release:{row[8]}",
            ttl_ms=row[10],
            spawn_client_request_id=row[11],
            spawn_idempotency_key=row[12],
        )
        for row in rows
    ]


def _release_pending_requests(connection: sqlite3.Connection) -> list[ReleasePendingRequest]:
    rows = connection.execute(
        "SELECT i.run_id,i.transition_id,i.phase,i.agent_id,i.requester_agent_id,"
        "COALESCE(sr.task_digest,'unknown-task'),COALESCE(sr.spawn_request_id,'unknown-spawn'),"
        "'',l.client_lease_id,"
        "l.acquire_idempotency_key,i.idempotency_key,l.ttl_ms,"
        "COALESCE(sr.client_request_id,'unknown-client'),"
        "COALESCE(sr.spawn_idempotency_key,'unknown-spawn-idem'),"
        "l.lease_id,l.gateway_lease_id "
        "FROM external_rpc_intents i "
        "JOIN leases l ON l.run_id=i.run_id AND l.transition_id=i.transition_id "
        "AND l.release_idempotency_key=i.idempotency_key "
        "AND l.gateway_lease_id IS NOT NULL AND l.gateway_lease_id<>'' "
        "AND l.state='release_pending' "
        "JOIN runtime_dispatch_bindings b ON b.lease_id=l.lease_id "
        "AND b.run_id=l.run_id AND b.transition_id=l.transition_id "
        "AND b.phase=l.phase AND b.agent_id=l.agent_id "
        "AND b.requester_agent_id=l.requester_agent_id "
        "AND b.client_lease_id=l.client_lease_id "
        "AND b.acquire_idempotency_key=l.acquire_idempotency_key "
        "AND b.release_idempotency_key=l.release_idempotency_key "
        "JOIN spawn_requests sr ON sr.spawn_request_id=b.spawn_request_id "
        "AND sr.run_id=b.run_id AND sr.transition_id=b.transition_id "
        "AND sr.phase=b.phase AND sr.agent_id=b.agent_id "
        "AND sr.task_digest=b.task_digest "
        "AND sr.client_request_id=b.spawn_client_request_id "
        "AND sr.spawn_idempotency_key=b.spawn_idempotency_key "
        "WHERE i.rpc_kind='allow_lease_release' AND i.state IN ('pending','unknown')"
    ).fetchall()
    return [
        ReleasePendingRequest(
            request=DispatchRequest(
                run_id=row[0],
                transition_id=row[1],
                phase=row[2],
                agent_id=row[3],
                requester_agent_id=row[4],
                task_digest=row[5],
                spawn_request_id=row[6],
                reserve_budget_event_id=row[7],
                client_lease_id=row[8],
                acquire_idempotency_key=row[9],
                release_idempotency_key=row[10],
                ttl_ms=row[11],
                spawn_client_request_id=row[12],
                spawn_idempotency_key=row[13],
                lease_id=row[14],
            ),
            gateway_lease_id=row[15],
        )
        for row in rows
    ]


def _acquire_only_cleanup_requests(
    connection: sqlite3.Connection,
) -> list[ReleasePendingRequest]:
    rows = connection.execute(
        "SELECT l.run_id,l.transition_id,l.phase,l.agent_id,l.requester_agent_id,"
        "sr.task_digest,sr.spawn_request_id,COALESCE(i.reserve_budget_event_id,''),"
        "l.client_lease_id,l.acquire_idempotency_key,"
        "COALESCE(l.release_idempotency_key,'reconcile-release:' || l.client_lease_id),"
        "l.ttl_ms,sr.client_request_id,sr.spawn_idempotency_key,l.lease_id,l.gateway_lease_id "
        "FROM leases l "
        "JOIN runtime_dispatch_bindings b ON b.lease_id=l.lease_id "
        "AND b.run_id=l.run_id AND b.transition_id=l.transition_id "
        "AND b.phase=l.phase AND b.agent_id=l.agent_id "
        "AND b.requester_agent_id=l.requester_agent_id "
        "AND b.client_lease_id=l.client_lease_id "
        "AND b.acquire_idempotency_key=l.acquire_idempotency_key "
        "AND b.release_idempotency_key=l.release_idempotency_key "
        "JOIN spawn_requests sr ON sr.spawn_request_id=b.spawn_request_id "
        "AND sr.run_id=b.run_id AND sr.transition_id=b.transition_id "
        "AND sr.phase=b.phase AND sr.agent_id=b.agent_id "
        "AND sr.task_digest=b.task_digest "
        "AND sr.client_request_id=b.spawn_client_request_id "
        "AND sr.spawn_idempotency_key=b.spawn_idempotency_key "
        "JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' "
        "AND i.run_id=b.run_id AND i.transition_id=b.transition_id "
        "AND i.phase=b.phase AND i.agent_id=b.agent_id "
        "AND i.task_digest=b.task_digest "
        "AND i.spawn_request_id=b.spawn_request_id "
        "AND i.client_request_id=b.spawn_client_request_id "
        "AND i.idempotency_key=b.spawn_idempotency_key "
        "WHERE l.state='acquired' AND l.gateway_lease_id IS NOT NULL "
        "AND l.gateway_lease_id<>'' "
        "AND i.state IN ('failed','human_review_required') "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM external_rpc_intents release "
        "  WHERE release.rpc_kind='allow_lease_release' "
        "  AND release.idempotency_key=COALESCE(l.release_idempotency_key,'reconcile-release:' || l.client_lease_id)"
        ")"
    ).fetchall()
    return [
        ReleasePendingRequest(
            request=DispatchRequest(
                run_id=row[0],
                transition_id=row[1],
                phase=row[2],
                agent_id=row[3],
                requester_agent_id=row[4],
                task_digest=row[5],
                spawn_request_id=row[6],
                reserve_budget_event_id=row[7],
                client_lease_id=row[8],
                acquire_idempotency_key=row[9],
                release_idempotency_key=row[10],
                ttl_ms=row[11],
                spawn_client_request_id=row[12],
                spawn_idempotency_key=row[13],
                lease_id=row[14],
            ),
            gateway_lease_id=row[15],
        )
        for row in rows
    ]


def _matching_sessions(
    request: DispatchRequest, observations: list[MetadataObservation]
) -> list[tuple[MetadataObservation, str]]:
    matches: list[tuple[MetadataObservation, str]] = []
    for observation in observations:
        try:
            validate_session_observation(
                local=spawn_metadata(request),
                normalized=observation.normalized,
                raw_json=observation.raw_json,
                metadata_contract_version=observation.metadata_contract_version,
            )
            session_key = validate_accepted_session_identity(
                external_id=observation.external_id,
                spawn_request_session_key=observation.spawn_request_session_key,
                session_key=observation.session_key,
            )
        except MetadataContractError:
            continue
        matches.append((observation, session_key))
    return matches


def _matching_leases(
    request: DispatchRequest, observations: list[MetadataObservation]
) -> list[tuple[MetadataObservation, str]]:
    matches: list[tuple[MetadataObservation, str]] = []
    for observation in observations:
        if not observation.external_id:
            continue
        try:
            validate_allow_lease_observation(
                local=lease_metadata(request, observation.external_id),
                normalized=observation.normalized,
                raw_json=observation.raw_json,
                metadata_contract_version=observation.metadata_contract_version,
            )
        except MetadataContractError:
            continue
        matches.append((observation, observation.external_id))
    return matches


def _matching_releases(
    request: DispatchRequest,
    gateway_lease_id: str,
    observations: list[MetadataObservation],
) -> list[MetadataObservation]:
    matches: list[MetadataObservation] = []
    for observation in observations:
        try:
            validate_allow_lease_release_observation(
                local=release_metadata(request, gateway_lease_id),
                normalized=observation.normalized,
                raw_json=observation.raw_json,
                metadata_contract_version=observation.metadata_contract_version,
            )
        except MetadataContractError:
            continue
        matches.append(observation)
    return matches


def reconcile_unknown_metadata(
    database: Path, adapter: MetadataCapableOpenClawAdapter
) -> ReconciliationSummary:
    reconciled = 0
    human_review = 0
    with connect_runtime_db(database) as connection:
        session_observations = list(adapter.sessions_list())
        lease_observations = list(adapter.allow_lease_list())
        for request in _orphan_unknown_lease_requests(connection):
            with immediate_transaction(connection):
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="allow_lease_acquire",
                    reason="missing-local-lease-row",
                )
                human_review += 1

        for item in _release_pending_requests(connection):
            matches = _matching_releases(
                item.request, item.gateway_lease_id, lease_observations
            )
            with immediate_transaction(connection):
                if len(matches) != 1:
                    mark_owned_lease_release_review(
                        connection,
                        item.request,
                        item.gateway_lease_id,
                        reason="zero-or-ambiguous-release-observation",
                    )
                    human_review += 1
                    continue
                persist_released_lease(
                    connection,
                    item.request,
                    matches[0],
                    item.gateway_lease_id,
                    reconciled=True,
                )
                reconciled += 1

        for request in _unknown_lease_requests(connection):
            matches = _matching_leases(request, lease_observations)
            with immediate_transaction(connection):
                if len(matches) != 1:
                    mark_human_review(
                        connection,
                        request,
                        rpc_kind="allow_lease_acquire",
                        reason="zero-or-ambiguous-lease-observation",
                    )
                    human_review += 1
                    continue
                observation, gateway_lease_id = matches[0]
                persist_acquired_lease(
                    connection,
                    request,
                    observation,
                    gateway_lease_id,
                    reconciled=True,
                )
                reconciled += 1

        for request in _unknown_spawn_requests(connection):
            matches = _matching_sessions(request, session_observations)
            with immediate_transaction(connection):
                if len(matches) != 1:
                    mark_human_review(
                        connection,
                        request,
                        rpc_kind="sessions_spawn",
                        reason="zero-or-ambiguous-session-observation",
                    )
                    human_review += 1
                    continue
                observation, session_key = matches[0]
                try:
                    persist_spawn_acceptance(
                        connection,
                        request,
                        observation,
                        session_key,
                        reconciled=True,
                    )
                    reconciled += 1
                except RuntimeDispatchError as exc:
                    mark_human_review(
                        connection,
                        request,
                        rpc_kind="sessions_spawn",
                        reason=str(exc),
                    )
                    human_review += 1

        for item in _acquire_only_cleanup_requests(connection):
            try:
                release_owned_lease(
                    connection, adapter, item.request, item.gateway_lease_id
                )
                reconciled += 1
            except AMBIGUOUS_TRANSPORT_ERRORS as exc:
                with immediate_transaction(connection):
                    mark_owned_lease_release_unknown(
                        connection,
                        item.request,
                        item.gateway_lease_id,
                        reason=str(exc),
                    )
                human_review += 1
            except RELEASE_FAILURE_ERRORS as exc:
                with immediate_transaction(connection):
                    mark_owned_lease_release_review(
                        connection,
                        item.request,
                        item.gateway_lease_id,
                        reason=str(exc),
                    )
                human_review += 1

    return ReconciliationSummary(
        reconciled=reconciled, human_review_required=human_review
    )
