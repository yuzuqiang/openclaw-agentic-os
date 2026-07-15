"""DB-persisted metadata runtime dispatcher."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from agentic_os.metadata import (
    MetadataContractError,
    validate_accepted_lease_identity,
    validate_accepted_session_identity,
    validate_allow_lease_observation,
    validate_allow_lease_release_observation,
    validate_session_observation,
)
from agentic_os.openclaw_adapter import (
    AdapterContractError,
    MetadataCapableOpenClawAdapter,
    MetadataObservation,
)


class RuntimeDispatchError(RuntimeError):
    """Runtime dispatch failed closed before accepting external authority."""


METADATA_RUNTIME_ERRORS = (
    AdapterContractError,
    MetadataContractError,
    RuntimeDispatchError,
    sqlite3.Error,
)


@dataclass(frozen=True)
class DispatchRequest:
    run_id: str
    transition_id: str
    phase: str
    agent_id: str
    requester_agent_id: str
    task_digest: str
    spawn_request_id: str
    reserve_budget_event_id: str
    client_lease_id: str
    acquire_idempotency_key: str
    release_idempotency_key: str
    ttl_ms: int
    spawn_client_request_id: str
    spawn_idempotency_key: str
    lease_id: str | None = None


@dataclass(frozen=True)
class DispatchResult:
    session_key: str
    gateway_lease_id: str
    status: str


def now_utc() -> tuple[str, int]:
    epoch_ms = int(time.time() * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_ms / 1000)), epoch_ms


def stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def connect_runtime_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA busy_timeout=10000")
    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    if str(journal_mode[0] if journal_mode else "").casefold() != "wal":
        connection.close()
        raise RuntimeDispatchError("SQLite WAL journal mode is unavailable")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def immediate_transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except Exception:
        connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")


def lease_metadata(request: DispatchRequest, gateway_lease_id: str) -> dict[str, Any]:
    return {
        "client_lease_id": request.client_lease_id,
        "idempotency_key": request.acquire_idempotency_key,
        "run_id": request.run_id,
        "phase": request.phase,
        "transition_id": request.transition_id,
        "agent_id": request.agent_id,
        "requester_agent_id": request.requester_agent_id,
        "ttl_ms": request.ttl_ms,
        "gateway_lease_id": gateway_lease_id,
    }


def release_metadata(request: DispatchRequest, gateway_lease_id: str) -> dict[str, str]:
    return {
        "client_lease_id": request.client_lease_id,
        "idempotency_key": request.release_idempotency_key,
        "run_id": request.run_id,
        "phase": request.phase,
        "transition_id": request.transition_id,
        "agent_id": request.agent_id,
        "requester_agent_id": request.requester_agent_id,
        "gateway_lease_id": gateway_lease_id,
    }


def spawn_metadata(request: DispatchRequest) -> dict[str, str]:
    return {
        "run_id": request.run_id,
        "transition_id": request.transition_id,
        "client_request_id": request.spawn_client_request_id,
        "idempotency_key": request.spawn_idempotency_key,
        "phase": request.phase,
        "agent_id": request.agent_id,
        "task_digest": request.task_digest,
    }


def _existing_external_id(
    connection: sqlite3.Connection, *, rpc_kind: str, idempotency_key: str
) -> str | None:
    row = connection.execute(
        "SELECT external_id FROM external_rpc_intents "
        "WHERE rpc_kind=? AND idempotency_key=? AND state IN ('accepted','reconciled')",
        (rpc_kind, idempotency_key),
    ).fetchone()
    return row[0] if row else None


def _assert_no_conflicting_spawn_replay(
    connection: sqlite3.Connection, request: DispatchRequest
) -> None:
    row = connection.execute(
        "SELECT run_id,transition_id,client_request_id,phase,agent_id,task_digest "
        "FROM external_rpc_intents WHERE rpc_kind='sessions_spawn' AND idempotency_key=?",
        (request.spawn_idempotency_key,),
    ).fetchone()
    if row is None:
        return
    expected = (
        request.run_id,
        request.transition_id,
        request.spawn_client_request_id,
        request.phase,
        request.agent_id,
        request.task_digest,
    )
    if row != expected:
        raise RuntimeDispatchError("conflicting reuse of sessions_spawn idempotency key")


def insert_pending_dispatch(connection: sqlite3.Connection, request: DispatchRequest) -> None:
    _assert_no_conflicting_spawn_replay(connection, request)
    now, now_ms = now_utc()
    expires_ms = now_ms + request.ttl_ms
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ms / 1000))
    lease_id = request.lease_id or request.client_lease_id

    connection.execute(
        "INSERT OR IGNORE INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
        "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
        "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            request.spawn_request_id,
            request.run_id,
            request.phase,
            request.agent_id,
            request.transition_id,
            request.spawn_client_request_id,
            request.spawn_idempotency_key,
            request.task_digest,
            "pending",
            now,
            now,
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
        "requester_agent_id,state,client_lease_id,acquire_idempotency_key,ttl_ms,"
        "acquire_requested_at,expires_at,expires_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            lease_id,
            request.run_id,
            request.phase,
            request.transition_id,
            request.agent_id,
            request.requester_agent_id,
            "acquire_pending",
            request.client_lease_id,
            request.acquire_idempotency_key,
            request.ttl_ms,
            now,
            expires,
            expires_ms,
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO external_rpc_intents(intent_id,run_id,transition_id,"
        "rpc_kind,client_request_id,idempotency_key,phase,agent_id,requester_agent_id,"
        "ttl_ms,metadata_json,state,requested_at,requested_at_epoch_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"acquire:{request.acquire_idempotency_key}",
            request.run_id,
            request.transition_id,
            "allow_lease_acquire",
            request.client_lease_id,
            request.acquire_idempotency_key,
            request.phase,
            request.agent_id,
            request.requester_agent_id,
            request.ttl_ms,
            stable_json(lease_metadata(request, "pending")),
            "pending",
            now,
            now_ms,
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO external_rpc_intents(intent_id,run_id,transition_id,"
        "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
        "idempotency_key,phase,agent_id,task_digest,metadata_json,state,requested_at,"
        "requested_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"spawn:{request.spawn_idempotency_key}",
            request.run_id,
            request.transition_id,
            "sessions_spawn",
            request.spawn_request_id,
            request.reserve_budget_event_id,
            request.spawn_client_request_id,
            request.spawn_idempotency_key,
            request.phase,
            request.agent_id,
            request.task_digest,
            stable_json(spawn_metadata(request)),
            "pending",
            now,
            now_ms,
        ),
    )


def persist_acquired_lease(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    observation: MetadataObservation,
    gateway_lease_id: str,
    *,
    reconciled: bool = False,
) -> None:
    now, now_ms = now_utc()
    observed = validate_allow_lease_observation(
        local=lease_metadata(request, gateway_lease_id),
        normalized=observation.normalized,
        raw_json=observation.raw_json,
        metadata_contract_version=observation.metadata_contract_version,
    )
    state = "reconciled" if reconciled else "accepted"
    connection.execute(
        "UPDATE external_rpc_intents SET state=?,metadata_contract_version=?,"
        "external_metadata_json=?,external_run_id=?,external_transition_id=?,"
        "external_client_request_id=?,external_idempotency_key=?,external_phase=?,"
        "external_agent_id=?,external_requester_agent_id=?,external_ttl_ms=?,"
        "external_id=?,accepted_at=COALESCE(accepted_at,?),accepted_at_epoch_ms="
        "COALESCE(accepted_at_epoch_ms,?) WHERE rpc_kind='allow_lease_acquire' "
        "AND idempotency_key=?",
        (
            state,
            observation.metadata_contract_version,
            observation.raw_json,
            observed["run_id"],
            observed["transition_id"],
            observed["client_lease_id"],
            observed["idempotency_key"],
            observed["phase"],
            observed["agent_id"],
            observed["requester_agent_id"],
            observed["ttl_ms"],
            gateway_lease_id,
            now,
            now_ms,
            request.acquire_idempotency_key,
        ),
    )
    connection.execute(
        "UPDATE leases SET state='acquired',gateway_lease_id=?,metadata_contract_version=?,"
        "metadata_observed_at=?,external_metadata_json=?,external_client_lease_id=?,"
        "external_idempotency_key=?,external_run_id=?,external_phase=?,external_transition_id=?,"
        "external_agent_id=?,external_requester_agent_id=?,external_ttl_ms=?,acquired_at=? "
        "WHERE client_lease_id=?",
        (
            gateway_lease_id,
            observation.metadata_contract_version,
            now,
            observation.raw_json,
            observed["client_lease_id"],
            observed["idempotency_key"],
            observed["run_id"],
            observed["phase"],
            observed["transition_id"],
            observed["agent_id"],
            observed["requester_agent_id"],
            observed["ttl_ms"],
            now,
            request.client_lease_id,
        ),
    )


def persist_spawn_acceptance(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    observation: MetadataObservation,
    session_key: str,
    *,
    reconciled: bool = False,
) -> None:
    now, now_ms = now_utc()
    observed = validate_session_observation(
        local=spawn_metadata(request),
        normalized=observation.normalized,
        raw_json=observation.raw_json,
        metadata_contract_version=observation.metadata_contract_version,
    )
    state = "reconciled" if reconciled else "accepted"
    connection.execute(
        "UPDATE external_rpc_intents SET state=?,metadata_contract_version=?,"
        "external_metadata_json=?,external_run_id=?,external_transition_id=?,"
        "external_client_request_id=?,external_idempotency_key=?,external_phase=?,"
        "external_agent_id=?,external_task_digest=?,external_id=?,accepted_at="
        "COALESCE(accepted_at,?),accepted_at_epoch_ms=COALESCE(accepted_at_epoch_ms,?) "
        "WHERE rpc_kind='sessions_spawn' AND idempotency_key=?",
        (
            state,
            observation.metadata_contract_version,
            observation.raw_json,
            observed["run_id"],
            observed["transition_id"],
            observed["client_request_id"],
            observed["idempotency_key"],
            observed["phase"],
            observed["agent_id"],
            observed["task_digest"],
            session_key,
            now,
            now_ms,
            request.spawn_idempotency_key,
        ),
    )
    connection.execute(
        "UPDATE spawn_requests SET session_key=?,dispatch_run_id=?,metadata_contract_version=?,"
        "metadata_observed_at=?,external_metadata_json=?,updated_at=? WHERE spawn_request_id=?",
        (
            session_key,
            session_key,
            observation.metadata_contract_version,
            now,
            observation.raw_json,
            now,
            request.spawn_request_id,
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
        "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,task_digest,"
        "status_metadata_json,state,spawned_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"session:{session_key}",
            request.spawn_request_id,
            request.run_id,
            request.transition_id,
            request.phase,
            request.agent_id,
            request.spawn_client_request_id,
            request.spawn_idempotency_key,
            session_key,
            request.task_digest,
            observation.status_metadata_json,
            "running",
            now,
        ),
    )
    connection.execute(
        "UPDATE spawn_requests SET state='accepted',updated_at=? WHERE spawn_request_id=?",
        (now, request.spawn_request_id),
    )


def mark_human_review(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    *,
    rpc_kind: str,
    reason: str,
) -> None:
    now, now_ms = now_utc()
    key = (
        request.acquire_idempotency_key
        if rpc_kind == "allow_lease_acquire"
        else request.spawn_idempotency_key
    )
    connection.execute(
        "UPDATE external_rpc_intents SET state='human_review_required',resolved_at=?,"
        "resolved_at_epoch_ms=? WHERE rpc_kind=? AND idempotency_key=?",
        (now, now_ms, rpc_kind, key),
    )
    if rpc_kind == "sessions_spawn":
        connection.execute(
            "UPDATE spawn_requests SET state='human_review_required',ambiguity_reason=?,"
            "updated_at=? WHERE spawn_request_id=?",
            (reason, now, request.spawn_request_id),
        )
    else:
        connection.execute(
            "UPDATE leases SET state='human_review_required',reconciliation_status=? "
            "WHERE client_lease_id=? AND gateway_lease_id IS NULL",
            (reason, request.client_lease_id),
        )


def mark_owned_lease_release_review(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    gateway_lease_id: str,
    *,
    reason: str,
) -> None:
    now, _ = now_utc()
    connection.execute(
        "UPDATE leases SET release_idempotency_key=?,release_requested_at=?,"
        "reconciliation_status=? "
        "WHERE client_lease_id=? AND run_id=? AND transition_id=? "
        "AND gateway_lease_id=?",
        (
            request.release_idempotency_key,
            now,
            reason,
            request.client_lease_id,
            request.run_id,
            request.transition_id,
            gateway_lease_id,
        ),
    )


def release_owned_lease(
    connection: sqlite3.Connection,
    adapter: MetadataCapableOpenClawAdapter,
    request: DispatchRequest,
    gateway_lease_id: str,
) -> None:
    row = connection.execute(
        "SELECT state,gateway_lease_id FROM leases WHERE client_lease_id=? AND run_id=? "
        "AND transition_id=?",
        (request.client_lease_id, request.run_id, request.transition_id),
    ).fetchone()
    if row != ("acquired", gateway_lease_id):
        raise RuntimeDispatchError("refusing to release a lease not exactly owned by this run")
    observation = adapter.allow_lease_release(
        {
            "run_id": request.run_id,
            "transition_id": request.transition_id,
            "gateway_lease_id": gateway_lease_id,
            "idempotency_key": request.release_idempotency_key,
        }
    )
    observed = validate_allow_lease_release_observation(
        local=release_metadata(request, gateway_lease_id),
        normalized=observation.normalized,
        raw_json=observation.raw_json,
        metadata_contract_version=observation.metadata_contract_version,
    )
    now, now_ms = now_utc()
    connection.execute(
        "UPDATE leases SET release_idempotency_key=?,release_requested_at=? "
        "WHERE client_lease_id=?",
        (request.release_idempotency_key, now, request.client_lease_id),
    )
    connection.execute(
        "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
        "client_request_id,idempotency_key,metadata_contract_version,metadata_json,"
        "external_metadata_json,external_run_id,external_transition_id,"
        "external_idempotency_key,state,external_id,requested_at,requested_at_epoch_ms,"
        "accepted_at,accepted_at_epoch_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"release:{request.release_idempotency_key}",
            request.run_id,
            request.transition_id,
            "allow_lease_release",
            request.release_idempotency_key,
            request.release_idempotency_key,
            observation.metadata_contract_version,
            stable_json(release_metadata(request, gateway_lease_id)),
            observation.raw_json,
            observed["run_id"],
            observed["transition_id"],
            observed["idempotency_key"],
            "accepted",
            observed["gateway_lease_id"],
            now,
            now_ms,
            now,
            now_ms,
        ),
    )
    connection.execute(
        "UPDATE leases SET state='released',released_at=? WHERE client_lease_id=?",
        (now, request.client_lease_id),
    )


def dispatch_with_metadata(
    database: Path, adapter: MetadataCapableOpenClawAdapter, request: DispatchRequest
) -> DispatchResult:
    with connect_runtime_db(database) as connection:
        with immediate_transaction(connection):
            insert_pending_dispatch(connection, request)
            existing = _existing_external_id(
                connection,
                rpc_kind="sessions_spawn",
                idempotency_key=request.spawn_idempotency_key,
            )
            if existing:
                lease = connection.execute(
                    "SELECT gateway_lease_id FROM leases WHERE client_lease_id=?",
                    (request.client_lease_id,),
                ).fetchone()
                return DispatchResult(
                    session_key=existing,
                    gateway_lease_id=lease[0] if lease else "",
                    status="replayed",
                )

        try:
            acquire_observation = adapter.allow_lease_acquire(
                {
                    "run_id": request.run_id,
                    "transition_id": request.transition_id,
                    "phase": request.phase,
                    "agent_id": request.agent_id,
                    "requester_agent_id": request.requester_agent_id,
                    "client_lease_id": request.client_lease_id,
                    "idempotency_key": request.acquire_idempotency_key,
                    "ttl_ms": request.ttl_ms,
                }
            )
            gateway_lease_id = validate_accepted_lease_identity(
                gateway_lease_id=acquire_observation.external_id
            )
            with immediate_transaction(connection):
                persist_acquired_lease(
                    connection, request, acquire_observation, gateway_lease_id
                )
        except METADATA_RUNTIME_ERRORS as exc:
            with immediate_transaction(connection):
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="allow_lease_acquire",
                    reason=str(exc),
                )
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="sessions_spawn",
                    reason="spawn blocked by allow lease metadata failure",
                )
            raise RuntimeDispatchError("allow lease metadata validation failed") from exc

        try:
            spawn_observation = adapter.sessions_spawn(
                {
                    "run_id": request.run_id,
                    "transition_id": request.transition_id,
                    "phase": request.phase,
                    "agent_id": request.agent_id,
                    "task_digest": request.task_digest,
                    "client_request_id": request.spawn_client_request_id,
                    "idempotency_key": request.spawn_idempotency_key,
                    "gateway_lease_id": gateway_lease_id,
                }
            )
            session_key = validate_accepted_session_identity(
                external_id=spawn_observation.external_id,
                spawn_request_session_key=spawn_observation.spawn_request_session_key,
                session_key=spawn_observation.session_key,
            )
            with immediate_transaction(connection):
                persist_spawn_acceptance(connection, request, spawn_observation, session_key)
        except METADATA_RUNTIME_ERRORS as exc:
            with immediate_transaction(connection):
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="sessions_spawn",
                    reason=str(exc),
                )
            try:
                with immediate_transaction(connection):
                    release_owned_lease(connection, adapter, request, gateway_lease_id)
            except METADATA_RUNTIME_ERRORS as release_exc:
                with immediate_transaction(connection):
                    mark_owned_lease_release_review(
                        connection,
                        request,
                        gateway_lease_id,
                        reason=str(release_exc),
                    )
                raise RuntimeDispatchError(
                    "sessions_spawn metadata validation failed; "
                    "owned lease release requires human review"
                ) from exc
            raise RuntimeDispatchError(
                "sessions_spawn metadata validation failed; owned lease released"
            ) from exc

        return DispatchResult(
            session_key=session_key, gateway_lease_id=gateway_lease_id, status="accepted"
        )
