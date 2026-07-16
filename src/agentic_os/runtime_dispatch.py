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
from agentic_os.migrations import MigrationError, repository_root, verify_database_connection
from agentic_os.openclaw_adapter import (
    AdapterContractError,
    MetadataCapableOpenClawAdapter,
    MetadataObservation,
)
from agentic_os.privacy import PrivacyPreflightError, assert_privacy_preflight


class RuntimeDispatchError(RuntimeError):
    """Runtime dispatch failed closed before accepting external authority."""


METADATA_RUNTIME_ERRORS = (
    AdapterContractError,
    MetadataContractError,
    RuntimeDispatchError,
    sqlite3.Error,
)

AMBIGUOUS_TRANSPORT_ERRORS = (TimeoutError, OSError)
RELEASE_FAILURE_ERRORS = METADATA_RUNTIME_ERRORS + AMBIGUOUS_TRANSPORT_ERRORS


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
    return utc_from_epoch_ms(epoch_ms), epoch_ms


def utc_from_epoch_ms(epoch_ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_ms / 1000))


def stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def connect_runtime_db(path: Path) -> sqlite3.Connection:
    database = Path(path).expanduser().resolve()
    try:
        assert_privacy_preflight(repository_root(), database_paths=(database,))
    except PrivacyPreflightError as exc:
        raise RuntimeDispatchError("runtime dispatch database privacy preflight failed") from exc
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=rw", uri=True, isolation_level=None
        )
    except sqlite3.Error as exc:
        raise RuntimeDispatchError("runtime dispatch database open failed") from exc
    connection.execute("PRAGMA busy_timeout=10000")
    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    if str(journal_mode[0] if journal_mode else "").casefold() != "wal":
        connection.close()
        raise RuntimeDispatchError("SQLite WAL journal mode is unavailable")
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        connection.close()
        raise RuntimeDispatchError("SQLite foreign key enforcement is unavailable")
    try:
        verify_database_connection(connection)
    except (MigrationError, sqlite3.Error) as exc:
        connection.close()
        raise RuntimeDispatchError("runtime dispatch database schema verification failed") from exc
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


def _existing_spawn_replay_result(
    connection: sqlite3.Connection, request: DispatchRequest
) -> DispatchResult | None:
    row = connection.execute(
        "SELECT run_id,transition_id,spawn_request_id,reserve_budget_event_id,"
        "client_request_id,phase,agent_id,task_digest,state,external_id "
        "FROM external_rpc_intents "
        "WHERE rpc_kind='sessions_spawn' AND idempotency_key=?",
        (request.spawn_idempotency_key,),
    ).fetchone()
    if row is None:
        return None
    expected = (
        request.run_id,
        request.transition_id,
        request.spawn_request_id,
        request.reserve_budget_event_id,
        request.spawn_client_request_id,
        request.phase,
        request.agent_id,
        request.task_digest,
    )
    if row[:8] != expected:
        raise RuntimeDispatchError("conflicting reuse of sessions_spawn idempotency key")
    state = row[8]
    external_id = row[9]
    if state in ("accepted", "reconciled"):
        binding = connection.execute(
            "SELECT spawn_request_id,lease_id,run_id,transition_id,phase,agent_id,"
            "requester_agent_id,task_digest,client_lease_id,acquire_idempotency_key,"
            "release_idempotency_key,spawn_client_request_id,spawn_idempotency_key "
            "FROM runtime_dispatch_bindings WHERE spawn_request_id=?",
            (request.spawn_request_id,),
        ).fetchone()
        expected_binding = (
            request.spawn_request_id,
            request.lease_id or request.client_lease_id,
            request.run_id,
            request.transition_id,
            request.phase,
            request.agent_id,
            request.requester_agent_id,
            request.task_digest,
            request.client_lease_id,
            request.acquire_idempotency_key,
            request.release_idempotency_key,
            request.spawn_client_request_id,
            request.spawn_idempotency_key,
        )
        if binding != expected_binding:
            raise RuntimeDispatchError(
                "conflicting reuse of sessions_spawn allow lease identity binding"
            )
        session_key = validate_accepted_session_identity(
            external_id=external_id,
            spawn_request_session_key=external_id,
            session_key=external_id,
        )
        lease = connection.execute(
            "SELECT gateway_lease_id FROM leases WHERE run_id=? AND transition_id=? "
            "AND phase=? AND agent_id=? AND requester_agent_id=? "
            "AND client_lease_id=? AND acquire_idempotency_key=? "
            "AND release_idempotency_key=? "
            "AND gateway_lease_id IS NOT NULL AND gateway_lease_id<>''",
            (
                request.run_id,
                request.transition_id,
                request.phase,
                request.agent_id,
                request.requester_agent_id,
                request.client_lease_id,
                request.acquire_idempotency_key,
                request.release_idempotency_key,
            ),
        ).fetchone()
        if lease is None:
            raise RuntimeDispatchError(
                "conflicting reuse of sessions_spawn allow lease identity"
            )
        return DispatchResult(
            session_key=session_key,
            gateway_lease_id=lease[0],
            status="replayed",
        )
    if state in ("pending", "unknown", "failed", "human_review_required"):
        raise RuntimeDispatchError(
            f"sessions_spawn replay is already {state}; external RPC will not be retried"
        )
    return None


def _assert_no_conflicting_spawn_replay(
    connection: sqlite3.Connection, request: DispatchRequest
) -> None:
    rows = connection.execute(
        "SELECT run_id,transition_id,spawn_request_id,reserve_budget_event_id,"
        "client_request_id,idempotency_key,phase,agent_id,task_digest "
        "FROM external_rpc_intents WHERE rpc_kind='sessions_spawn' "
        "AND (client_request_id=? OR idempotency_key=?)",
        (request.spawn_client_request_id, request.spawn_idempotency_key),
    ).fetchall()
    expected = (
        request.run_id,
        request.transition_id,
        request.spawn_request_id,
        request.reserve_budget_event_id,
        request.spawn_client_request_id,
        request.spawn_idempotency_key,
        request.phase,
        request.agent_id,
        request.task_digest,
    )
    if any(row != expected for row in rows):
        raise RuntimeDispatchError("conflicting reuse of sessions_spawn idempotency key")


def _assert_or_insert_spawn_request(
    connection: sqlite3.Connection, request: DispatchRequest, now: str
) -> None:
    row = connection.execute(
        "SELECT run_id,phase,agent_id,transition_id,client_request_id,"
        "spawn_idempotency_key,task_digest,state FROM spawn_requests "
        "WHERE spawn_request_id=?",
        (request.spawn_request_id,),
    ).fetchone()
    expected = (
        request.run_id,
        request.phase,
        request.agent_id,
        request.transition_id,
        request.spawn_client_request_id,
        request.spawn_idempotency_key,
        request.task_digest,
        "pending",
    )
    if row is not None:
        if row != expected:
            raise RuntimeDispatchError("conflicting reuse of spawn_request_id")
        return
    connection.execute(
        "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
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


def _assert_or_insert_lease(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    *,
    now: str,
    expires: str,
    expires_ms: int,
    lease_id: str,
) -> None:
    rows = connection.execute(
        "SELECT lease_id,run_id,phase,transition_id,agent_id,requester_agent_id,"
        "state,client_lease_id,acquire_idempotency_key,release_idempotency_key,ttl_ms FROM leases "
        "WHERE lease_id=? OR client_lease_id=? OR acquire_idempotency_key=?",
        (lease_id, request.client_lease_id, request.acquire_idempotency_key),
    ).fetchall()
    expected = (
        lease_id,
        request.run_id,
        request.phase,
        request.transition_id,
        request.agent_id,
        request.requester_agent_id,
        "acquire_pending",
        request.client_lease_id,
        request.acquire_idempotency_key,
        request.release_idempotency_key,
        request.ttl_ms,
    )
    if rows:
        if len(rows) != 1 or rows[0] != expected:
            raise RuntimeDispatchError("conflicting reuse of allow lease identity")
        return
    connection.execute(
        "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
        "requester_agent_id,state,client_lease_id,acquire_idempotency_key,ttl_ms,"
        "release_idempotency_key,acquire_requested_at,expires_at,expires_at_epoch_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
            request.release_idempotency_key,
            now,
            expires,
            expires_ms,
        ),
    )


def _assert_or_insert_acquire_intent(
    connection: sqlite3.Connection, request: DispatchRequest, *, now: str, now_ms: int
) -> None:
    rows = connection.execute(
        "SELECT intent_id,run_id,transition_id,rpc_kind,client_request_id,"
        "idempotency_key,phase,agent_id,requester_agent_id,ttl_ms,metadata_json,state "
        "FROM external_rpc_intents WHERE rpc_kind='allow_lease_acquire' "
        "AND (client_request_id=? OR idempotency_key=?)",
        (request.client_lease_id, request.acquire_idempotency_key),
    ).fetchall()
    metadata = stable_json(lease_metadata(request, "pending"))
    expected = (
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
        metadata,
        "pending",
    )
    if rows:
        if len(rows) != 1 or rows[0] != expected:
            raise RuntimeDispatchError("conflicting reuse of allow_lease_acquire identity")
        return
    connection.execute(
        "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
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
            metadata,
            "pending",
            now,
            now_ms,
        ),
    )


def _assert_or_insert_dispatch_binding(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    *,
    now: str,
) -> None:
    lease_id = request.lease_id or request.client_lease_id
    rows = connection.execute(
        "SELECT spawn_request_id,lease_id,run_id,transition_id,phase,agent_id,"
        "requester_agent_id,task_digest,client_lease_id,acquire_idempotency_key,"
        "release_idempotency_key,spawn_client_request_id,spawn_idempotency_key "
        "FROM runtime_dispatch_bindings WHERE spawn_request_id=? OR lease_id=? "
        "OR client_lease_id=? OR acquire_idempotency_key=? "
        "OR release_idempotency_key=? OR spawn_client_request_id=? "
        "OR spawn_idempotency_key=?",
        (
            request.spawn_request_id,
            lease_id,
            request.client_lease_id,
            request.acquire_idempotency_key,
            request.release_idempotency_key,
            request.spawn_client_request_id,
            request.spawn_idempotency_key,
        ),
    ).fetchall()
    expected = (
        request.spawn_request_id,
        lease_id,
        request.run_id,
        request.transition_id,
        request.phase,
        request.agent_id,
        request.requester_agent_id,
        request.task_digest,
        request.client_lease_id,
        request.acquire_idempotency_key,
        request.release_idempotency_key,
        request.spawn_client_request_id,
        request.spawn_idempotency_key,
    )
    if rows:
        if len(rows) != 1 or rows[0] != expected:
            raise RuntimeDispatchError("conflicting reuse of runtime dispatch binding")
        return
    connection.execute(
        "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
        "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
        "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
        "spawn_idempotency_key,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (*expected, now),
    )


def _strictly_after_requested_time(
    connection: sqlite3.Connection, *, rpc_kind: str, idempotency_key: str
) -> tuple[str, int]:
    requested = connection.execute(
        "SELECT requested_at_epoch_ms FROM external_rpc_intents "
        "WHERE rpc_kind=? AND idempotency_key=?",
        (rpc_kind, idempotency_key),
    ).fetchone()
    if requested is None or type(requested[0]) is not int:
        raise RuntimeDispatchError("missing requested timestamp for accepted RPC")
    _, now_ms = now_utc()
    accepted_ms = max(now_ms, requested[0] + 1)
    return utc_from_epoch_ms(accepted_ms), accepted_ms


def insert_pending_dispatch(connection: sqlite3.Connection, request: DispatchRequest) -> None:
    _assert_no_conflicting_spawn_replay(connection, request)
    assert_no_potentially_live_dispatch(connection, request)
    now, now_ms = now_utc()
    expires_ms = now_ms + request.ttl_ms
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ms / 1000))
    lease_id = request.lease_id or request.client_lease_id

    _assert_or_insert_spawn_request(connection, request, now)
    _assert_or_insert_lease(
        connection,
        request,
        now=now,
        expires=expires,
        expires_ms=expires_ms,
        lease_id=lease_id,
    )
    _assert_or_insert_acquire_intent(connection, request, now=now, now_ms=now_ms)
    _assert_or_insert_dispatch_binding(connection, request, now=now)
    connection.execute(
        "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
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


def assert_no_potentially_live_dispatch(
    connection: sqlite3.Connection, request: DispatchRequest
) -> None:
    duplicate = connection.execute(
        "SELECT i.spawn_request_id FROM external_rpc_intents i "
        "JOIN spawn_requests sr ON sr.spawn_request_id=i.spawn_request_id "
        "AND sr.run_id=i.run_id AND sr.transition_id=i.transition_id "
        "AND sr.phase=i.phase AND sr.agent_id=i.agent_id "
        "AND sr.task_digest=i.task_digest AND sr.client_request_id=i.client_request_id "
        "AND sr.spawn_idempotency_key=i.idempotency_key "
        "JOIN runtime_dispatch_bindings b ON b.spawn_request_id=sr.spawn_request_id "
        "AND b.run_id=sr.run_id AND b.transition_id=sr.transition_id "
        "AND b.phase=sr.phase AND b.agent_id=sr.agent_id "
        "AND b.task_digest=sr.task_digest "
        "AND b.spawn_client_request_id=sr.client_request_id "
        "AND b.spawn_idempotency_key=sr.spawn_idempotency_key "
        "JOIN leases l ON l.lease_id=b.lease_id AND l.run_id=b.run_id "
        "AND l.transition_id=b.transition_id AND l.phase=b.phase "
        "AND l.agent_id=b.agent_id AND l.requester_agent_id=b.requester_agent_id "
        "AND l.client_lease_id=b.client_lease_id "
        "AND l.acquire_idempotency_key=b.acquire_idempotency_key "
        "AND l.release_idempotency_key=b.release_idempotency_key "
        "WHERE i.rpc_kind='sessions_spawn' AND i.run_id=? AND i.phase=? AND i.agent_id=? "
        "AND i.spawn_request_id<>? AND ("
        "i.state IN ('pending','unknown','accepted','reconciled') OR ("
        "i.state='human_review_required' AND NOT ("
        "sr.state='human_review_required' "
        "AND sr.ambiguity_reason LIKE 'spawn blocked by allow lease%' "
        "AND l.state IN ('released','release_not_required','expired','human_review_required')"
        "))) ORDER BY i.requested_at_epoch_ms,i.intent_id LIMIT 1",
        (request.run_id, request.phase, request.agent_id, request.spawn_request_id),
    ).fetchone()
    if duplicate is not None:
        raise RuntimeDispatchError(
            "duplicate live dispatch for run, phase, and agent is blocked"
        )


def persist_acquired_lease(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    observation: MetadataObservation,
    gateway_lease_id: str,
    *,
    reconciled: bool = False,
) -> None:
    now, now_ms = _strictly_after_requested_time(
        connection,
        rpc_kind="allow_lease_acquire",
        idempotency_key=request.acquire_idempotency_key,
    )
    observed = validate_allow_lease_observation(
        local=lease_metadata(request, gateway_lease_id),
        normalized=observation.normalized,
        raw_json=observation.raw_json,
        metadata_contract_version=observation.metadata_contract_version,
    )
    state = "reconciled" if reconciled else "accepted"
    intent_cursor = connection.execute(
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
    if intent_cursor.rowcount != 1:
        raise RuntimeDispatchError("allow_lease_acquire intent update did not match exactly one row")
    lease_cursor = connection.execute(
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
    if lease_cursor.rowcount != 1:
        raise RuntimeDispatchError("allow_lease_acquire lease update did not match exactly one row")


def persist_spawn_acceptance(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    observation: MetadataObservation,
    session_key: str,
    *,
    reconciled: bool = False,
) -> None:
    assert_no_potentially_live_dispatch(connection, request)
    now, now_ms = _strictly_after_requested_time(
        connection,
        rpc_kind="sessions_spawn",
        idempotency_key=request.spawn_idempotency_key,
    )
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


def mark_unknown(
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
        "UPDATE external_rpc_intents SET state='unknown',resolved_at=?,"
        "resolved_at_epoch_ms=? WHERE rpc_kind=? AND idempotency_key=? "
        "AND state NOT IN ('accepted','reconciled','human_review_required','failed')",
        (now, now_ms, rpc_kind, key),
    )
    if rpc_kind == "sessions_spawn":
        connection.execute(
            "UPDATE spawn_requests SET state='unknown',ambiguity_reason=?,"
            "updated_at=? WHERE spawn_request_id=? "
            "AND state NOT IN ('accepted','completed','human_review_required','failed')",
            (reason, now, request.spawn_request_id),
        )
    else:
        connection.execute(
            "UPDATE leases SET reconciliation_status=? "
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
    now, now_ms = now_utc()
    connection.execute(
        "UPDATE external_rpc_intents SET state='human_review_required',resolved_at=?,"
        "resolved_at_epoch_ms=? WHERE rpc_kind='allow_lease_release' AND idempotency_key=? "
        "AND state NOT IN ('accepted','reconciled')",
        (now, now_ms, request.release_idempotency_key),
    )
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


def mark_owned_lease_release_unknown(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    gateway_lease_id: str,
    *,
    reason: str,
) -> None:
    now, now_ms = now_utc()
    connection.execute(
        "UPDATE external_rpc_intents SET state='unknown',resolved_at=?,"
        "resolved_at_epoch_ms=? WHERE rpc_kind='allow_lease_release' AND idempotency_key=? "
        "AND state NOT IN ('accepted','reconciled','human_review_required','failed')",
        (now, now_ms, request.release_idempotency_key),
    )
    connection.execute(
        "UPDATE leases SET state='release_pending',release_idempotency_key=?,"
        "release_requested_at=COALESCE(release_requested_at,?),reconciliation_status=? "
        "WHERE client_lease_id=? AND run_id=? AND transition_id=? "
        "AND gateway_lease_id=? AND state IN ('acquired','release_pending')",
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


def prepare_owned_lease_release(
    connection: sqlite3.Connection,
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
    now, now_ms = now_utc()
    metadata = stable_json(release_metadata(request, gateway_lease_id))
    lease_cursor = connection.execute(
        "UPDATE leases SET state='release_pending',release_idempotency_key=?,"
        "release_requested_at=?,reconciliation_status='release_pending' "
        "WHERE client_lease_id=? AND run_id=? AND transition_id=? "
        "AND gateway_lease_id=? AND state='acquired'",
        (
            request.release_idempotency_key,
            now,
            request.client_lease_id,
            request.run_id,
            request.transition_id,
            gateway_lease_id,
        ),
    )
    if lease_cursor.rowcount != 1:
        raise RuntimeDispatchError("release_pending lease update did not match exactly one row")
    connection.execute(
        "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
        "client_request_id,idempotency_key,phase,agent_id,requester_agent_id,"
        "metadata_json,state,requested_at,requested_at_epoch_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"release:{request.release_idempotency_key}",
            request.run_id,
            request.transition_id,
            "allow_lease_release",
            request.release_idempotency_key,
            request.release_idempotency_key,
            request.phase,
            request.agent_id,
            request.requester_agent_id,
            metadata,
            "pending",
            now,
            now_ms,
        ),
    )


def persist_released_lease(
    connection: sqlite3.Connection,
    request: DispatchRequest,
    observation: MetadataObservation,
    gateway_lease_id: str,
    *,
    reconciled: bool = False,
) -> None:
    observed = validate_allow_lease_release_observation(
        local=release_metadata(request, gateway_lease_id),
        normalized=observation.normalized,
        raw_json=observation.raw_json,
        metadata_contract_version=observation.metadata_contract_version,
    )
    now, now_ms = _strictly_after_requested_time(
        connection,
        rpc_kind="allow_lease_release",
        idempotency_key=request.release_idempotency_key,
    )
    state = "reconciled" if reconciled else "accepted"
    intent_cursor = connection.execute(
        "UPDATE external_rpc_intents SET state=?,metadata_contract_version=?,"
        "external_metadata_json=?,external_run_id=?,external_transition_id=?,"
        "external_client_request_id=?,external_idempotency_key=?,external_phase=?,"
        "external_agent_id=?,external_requester_agent_id=?,external_id=?,"
        "accepted_at=?,accepted_at_epoch_ms=? "
        "WHERE rpc_kind='allow_lease_release' AND idempotency_key=? "
        "AND state IN ('pending','unknown')",
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
            observed["gateway_lease_id"],
            now,
            now_ms,
            request.release_idempotency_key,
        ),
    )
    if intent_cursor.rowcount != 1:
        raise RuntimeDispatchError("allow_lease_release intent update did not match exactly one row")
    lease_cursor = connection.execute(
        "UPDATE leases SET state='released',released_at=?,reconciliation_status='not_needed' "
        "WHERE client_lease_id=? AND run_id=? AND transition_id=? "
        "AND gateway_lease_id=? AND state='release_pending'",
        (
            now,
            request.client_lease_id,
            request.run_id,
            request.transition_id,
            gateway_lease_id,
        ),
    )
    if lease_cursor.rowcount != 1:
        raise RuntimeDispatchError("released lease update did not match exactly one row")


def release_owned_lease(
    connection: sqlite3.Connection,
    adapter: MetadataCapableOpenClawAdapter,
    request: DispatchRequest,
    gateway_lease_id: str,
) -> None:
    with immediate_transaction(connection):
        prepare_owned_lease_release(connection, request, gateway_lease_id)
    observation = adapter.allow_lease_release(release_metadata(request, gateway_lease_id))
    with immediate_transaction(connection):
        persist_released_lease(connection, request, observation, gateway_lease_id)


def dispatch_with_metadata(
    database: Path, adapter: MetadataCapableOpenClawAdapter, request: DispatchRequest
) -> DispatchResult:
    with connect_runtime_db(database) as connection:
        with immediate_transaction(connection):
            existing = _existing_spawn_replay_result(connection, request)
            if existing is not None:
                return existing
            insert_pending_dispatch(connection, request)

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
        except AMBIGUOUS_TRANSPORT_ERRORS as exc:
            with immediate_transaction(connection):
                mark_unknown(
                    connection,
                    request,
                    rpc_kind="allow_lease_acquire",
                    reason=str(exc),
                )
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="sessions_spawn",
                    reason="spawn blocked by allow lease transport uncertainty",
                )
            raise RuntimeDispatchError("allow lease transport outcome unknown") from exc
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
        except AMBIGUOUS_TRANSPORT_ERRORS as exc:
            with immediate_transaction(connection):
                mark_unknown(
                    connection,
                    request,
                    rpc_kind="sessions_spawn",
                    reason=str(exc),
                )
            raise RuntimeDispatchError(
                "sessions_spawn transport outcome unknown; reconciliation required"
            ) from exc
        except METADATA_RUNTIME_ERRORS as exc:
            with immediate_transaction(connection):
                mark_human_review(
                    connection,
                    request,
                    rpc_kind="sessions_spawn",
                    reason=str(exc),
                )
            try:
                release_owned_lease(connection, adapter, request, gateway_lease_id)
            except AMBIGUOUS_TRANSPORT_ERRORS as release_exc:
                with immediate_transaction(connection):
                    mark_owned_lease_release_unknown(
                        connection,
                        request,
                        gateway_lease_id,
                        reason=str(release_exc),
                    )
                raise RuntimeDispatchError(
                    "sessions_spawn metadata validation failed; "
                    "owned lease release outcome unknown"
                ) from exc
            except RELEASE_FAILURE_ERRORS as release_exc:
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
                f"sessions_spawn failed closed ({exc}); owned lease released"
            ) from exc

        return DispatchResult(
            session_key=session_key, gateway_lease_id=gateway_lease_id, status="accepted"
        )
