"""Fail-closed reconciliation scanner for unknown metadata outcomes."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from agentic_os.metadata import (
    MetadataContractError,
    validate_allow_lease_observation,
    validate_session_observation,
)
from agentic_os.openclaw_adapter import MetadataCapableOpenClawAdapter, MetadataObservation
from agentic_os.runtime_dispatch import (
    DispatchRequest,
    connect_runtime_db,
    immediate_transaction,
    lease_metadata,
    mark_human_review,
    persist_acquired_lease,
    persist_spawn_acceptance,
    spawn_metadata,
)


@dataclass(frozen=True)
class ReconciliationSummary:
    reconciled: int
    human_review_required: int


def _unknown_spawn_requests(connection: sqlite3.Connection) -> list[DispatchRequest]:
    rows = connection.execute(
        "SELECT i.run_id,i.transition_id,i.phase,i.agent_id,l.requester_agent_id,"
        "i.task_digest,i.spawn_request_id,i.reserve_budget_event_id,l.client_lease_id,"
        "l.acquire_idempotency_key,COALESCE(l.release_idempotency_key,''),l.ttl_ms,"
        "i.client_request_id,i.idempotency_key,l.lease_id FROM external_rpc_intents i "
        "JOIN leases l ON l.run_id=i.run_id AND l.transition_id=i.transition_id "
        "WHERE i.rpc_kind='sessions_spawn' AND i.state='unknown'"
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
        "LEFT JOIN leases l ON l.client_lease_id=i.client_request_id "
        "LEFT JOIN spawn_requests sr ON sr.run_id=i.run_id AND sr.transition_id=i.transition_id "
        "WHERE i.rpc_kind='allow_lease_acquire' AND i.state='unknown'"
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


def _matching_sessions(
    request: DispatchRequest, observations: list[MetadataObservation]
) -> list[MetadataObservation]:
    matches: list[MetadataObservation] = []
    for observation in observations:
        try:
            validate_session_observation(
                local=spawn_metadata(request),
                normalized=observation.normalized,
                raw_json=observation.raw_json,
                metadata_contract_version=observation.metadata_contract_version,
            )
        except MetadataContractError:
            continue
        matches.append(observation)
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


def reconcile_unknown_metadata(
    database: Path, adapter: MetadataCapableOpenClawAdapter
) -> ReconciliationSummary:
    reconciled = 0
    human_review = 0
    with connect_runtime_db(database) as connection:
        session_observations = list(adapter.sessions_list())
        lease_observations = list(adapter.allow_lease_list())
        with immediate_transaction(connection):
            for request in _unknown_lease_requests(connection):
                matches = _matching_leases(request, lease_observations)
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
                if len(matches) != 1 or not matches[0].external_id:
                    mark_human_review(
                        connection,
                        request,
                        rpc_kind="sessions_spawn",
                        reason="zero-or-ambiguous-session-observation",
                    )
                    human_review += 1
                    continue
                persist_spawn_acceptance(
                    connection,
                    request,
                    matches[0],
                    matches[0].external_id,
                    reconciled=True,
                )
                reconciled += 1

    return ReconciliationSummary(
        reconciled=reconciled, human_review_required=human_review
    )
