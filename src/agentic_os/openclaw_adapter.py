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


def _identity_alias(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterContractError(f"{label} must be a string")
    return value


def _consistent_identity(label: str, aliases: Iterable[tuple[str, Any]]) -> str | None:
    selected: tuple[str, str] | None = None
    for alias_label, raw_value in aliases:
        value = _identity_alias(raw_value, alias_label)
        if value is None:
            continue
        if selected is None:
            selected = (alias_label, value)
            continue
        selected_label, selected_value = selected
        if value != selected_value:
            raise AdapterContractError(
                f"conflicting {label} aliases: {selected_label}="
                f"{selected_value!r}, {alias_label}={value!r}"
            )
    return selected[1] if selected is not None else None


def _observations_from_items(items: Any, label: str) -> tuple[MetadataObservation, ...]:
    if not isinstance(items, Iterable):
        raise AdapterContractError(f"{label} response must include {label}")
    observations: list[MetadataObservation] = []
    for item in items:
        try:
            observations.append(observation_from_openclaw_response(_mapping(item, label)))
        except AdapterContractError:
            continue
    return tuple(observations)


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

    lease: Mapping[str, Any] | None = None
    if isinstance(response.get("lease"), Mapping):
        lease = _mapping(response["lease"], "lease")
    session: Mapping[str, Any] | None = None
    if isinstance(response.get("session"), Mapping):
        session = _mapping(response["session"], "session")

    session_key = _consistent_identity(
        "session key",
        (
            ("session_key", response.get("session_key")),
            (
                "session.session_key",
                session.get("session_key") if session is not None else None,
            ),
            ("session.key", session.get("key") if session is not None else None),
        ),
    )
    spawn_request_session_key = _consistent_identity(
        "spawn request session key",
        (
            ("spawn_request_session_key", response.get("spawn_request_session_key")),
            (
                "session.spawn_request_session_key",
                session.get("spawn_request_session_key") if session is not None else None,
            ),
            (
                "session.request_session_key",
                session.get("request_session_key") if session is not None else None,
            ),
        ),
    )
    if session_key is not None or spawn_request_session_key is not None:
        external_id = _consistent_identity(
            "session external identity",
            (
                ("external_id", response.get("external_id")),
                ("session_key", session_key),
            ),
        )
    else:
        external_id = _consistent_identity(
            "lease external identity",
            (
                ("external_id", response.get("external_id")),
                ("gateway_lease_id", response.get("gateway_lease_id")),
                (
                    "lease.gateway_lease_id",
                    lease.get("gateway_lease_id") if lease is not None else None,
                ),
                ("lease.lease_id", lease.get("lease_id") if lease is not None else None),
            ),
        )

    status_metadata_json = response.get("status_metadata_json")
    if status_metadata_json is not None and not isinstance(status_metadata_json, str):
        raise AdapterContractError("status_metadata_json must be a string")

    return MetadataObservation(
        metadata_contract_version=version,
        normalized=normalized,
        raw_json=raw_json,
        external_id=external_id,
        spawn_request_session_key=spawn_request_session_key,
        session_key=session_key,
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
        return _observations_from_items(response.get("leases"), "lease")

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
        return _observations_from_items(response.get("sessions"), "session")

    def session_status(self, session_key: str) -> MetadataObservation:
        return observation_from_openclaw_response(
            self._transport.call("sessions_status", {"session_key": session_key})
        )
