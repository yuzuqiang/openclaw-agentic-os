"""Metadata-capable OpenClaw adapter contracts."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class AdapterContractError(ValueError):
    """An OpenClaw response did not expose the required metadata contract."""


@dataclass(frozen=True)
class MetadataObservation:
    metadata_contract_version: str | None
    normalized: Mapping[str, Any] | None
    raw_json: str | None
    external_id: str | None = None
    spawn_request_session_key: str | None = None
    session_key: str | None = None
    status_metadata_json: str | None = None
    raw_response_json: str | None = None


class MetadataCapableOpenClawAdapter(Protocol):
    def allow_lease_acquire(self, params: Mapping[str, Any]) -> MetadataObservation:
        ...

    def allow_lease_list(self) -> Sequence[MetadataObservation]:
        ...

    def allow_lease_release(self, params: Mapping[str, Any]) -> MetadataObservation:
        ...

    def sessions_spawn(self, params: Mapping[str, Any]) -> MetadataObservation:
        ...

    def sessions_list(self) -> Sequence[MetadataObservation]:
        ...

    def session_status(self, session_key: str) -> MetadataObservation:
        ...


class OpenClawTransport(Protocol):
    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


def _json_object(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterContractError(f"{label} must be an object")
    return value


def observation_from_openclaw_response(response: Mapping[str, Any]) -> MetadataObservation:
    """Extract normalized/raw metadata from OpenClaw-shaped raw responses."""

    container: Mapping[str, Any] = response
    if isinstance(response.get("metadata"), Mapping):
        container = _mapping(response["metadata"], "metadata")

    normalized = (
        container.get("normalized")
        or container.get("normalized_metadata")
        or container.get("external_metadata")
    )
    normalized = _mapping(normalized, "normalized metadata")

    raw_json = container.get("raw_json") or container.get("raw_metadata_json")
    if not isinstance(raw_json, str) or not raw_json:
        raise AdapterContractError("raw metadata JSON is required")

    version = container.get("metadata_contract_version") or container.get(
        "contract_version"
    )
    if not isinstance(version, str) or not version:
        raise AdapterContractError("metadata contract version is required")

    external_id = response.get("external_id")
    if external_id is None:
        external_id = response.get("gateway_lease_id") or response.get("session_key")
    if external_id is None and isinstance(response.get("lease"), Mapping):
        lease = _mapping(response["lease"], "lease")
        external_id = lease.get("gateway_lease_id") or lease.get("lease_id")
    if external_id is None and isinstance(response.get("session"), Mapping):
        session = _mapping(response["session"], "session")
        external_id = session.get("session_key") or session.get("key")

    session_key = response.get("session_key")
    spawn_request_session_key = response.get("spawn_request_session_key")
    if isinstance(response.get("session"), Mapping):
        session = _mapping(response["session"], "session")
        session_key = session_key or session.get("session_key") or session.get("key")
        spawn_request_session_key = (
            spawn_request_session_key
            or session.get("spawn_request_session_key")
            or session.get("request_session_key")
        )

    status_metadata_json = response.get("status_metadata_json")
    if status_metadata_json is not None and not isinstance(status_metadata_json, str):
        raise AdapterContractError("status_metadata_json must be a string")

    return MetadataObservation(
        metadata_contract_version=version,
        normalized=normalized,
        raw_json=raw_json,
        external_id=external_id if isinstance(external_id, str) else None,
        spawn_request_session_key=(
            spawn_request_session_key if isinstance(spawn_request_session_key, str) else None
        ),
        session_key=session_key if isinstance(session_key, str) else None,
        status_metadata_json=status_metadata_json,
        raw_response_json=_json_object(response),
    )


class OpenClawAdapter:
    """Thin adapter over an RPC transport using canned OpenClaw response shapes."""

    def __init__(self, transport: OpenClawTransport) -> None:
        self._transport = transport

    def allow_lease_acquire(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            self._transport.call("subagents.allowLease.acquire", params)
        )

    def allow_lease_list(self) -> Sequence[MetadataObservation]:
        response = self._transport.call("subagents.allowLease.status", {})
        leases = response.get("leases")
        if not isinstance(leases, Iterable):
            raise AdapterContractError("allow lease status response must include leases")
        return tuple(observation_from_openclaw_response(_mapping(item, "lease")) for item in leases)

    def allow_lease_release(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            self._transport.call("subagents.allowLease.release", params)
        )

    def sessions_spawn(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            self._transport.call("sessions_spawn", params)
        )

    def sessions_list(self) -> Sequence[MetadataObservation]:
        response = self._transport.call("sessions_list", {})
        sessions = response.get("sessions")
        if not isinstance(sessions, Iterable):
            raise AdapterContractError("sessions_list response must include sessions")
        return tuple(
            observation_from_openclaw_response(_mapping(item, "session"))
            for item in sessions
        )

    def session_status(self, session_key: str) -> MetadataObservation:
        return observation_from_openclaw_response(
            self._transport.call("sessions_status", {"session_key": session_key})
        )
