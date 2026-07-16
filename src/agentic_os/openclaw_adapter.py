"""Metadata-capable OpenClaw adapter contracts."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
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

    def session_result(self, session_key: str) -> MetadataObservation:
        ...


class OpenClawTransport(Protocol):
    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


_REQUIRED_SESSION_TOOL_PARAMS: Mapping[str, frozenset[str]] = {
    "sessions_spawn": frozenset(("client_request_id", "idempotency_key")),
    "sessions_list": frozenset(),
    "sessions_status": frozenset(("session_key",)),
    "sessions_history": frozenset(("sessionKey", "limit", "includeTools")),
}


def _json_object(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise AdapterContractError("raw OpenClaw response must be JSON serializable") from exc


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterContractError(f"{label} must be an object")
    return value


def _transport_response(value: Any, method: str) -> Mapping[str, Any]:
    return _mapping(value, f"{method} response")


def _tool_name(entry: Mapping[str, Any]) -> str | None:
    for key in ("name", "method", "id"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _parameter_names(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            return frozenset(str(key) for key in properties)
        return frozenset(str(key) for key in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        names: set[str] = set()
        for item in value:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, Mapping):
                name = item.get("name")
                if isinstance(name, str) and name:
                    names.add(name)
        return frozenset(names)
    raise AdapterContractError("runtime tool catalog parameters must be inspectable")


def _tool_parameters(entry: Mapping[str, Any]) -> frozenset[str]:
    if "parameters" in entry:
        return _parameter_names(entry["parameters"])
    if "input_schema" in entry:
        return _parameter_names(entry["input_schema"])
    if "inputSchema" in entry:
        return _parameter_names(entry["inputSchema"])
    return frozenset()


def _tool_entries(catalog: Mapping[str, Any]) -> Mapping[str, frozenset[str]]:
    tools = catalog.get("tools", catalog)
    entries: dict[str, frozenset[str]] = {}
    if isinstance(tools, Mapping):
        for name, value in tools.items():
            if isinstance(value, Mapping):
                entries[str(name)] = _tool_parameters(value)
            else:
                entries[str(name)] = frozenset()
        return entries
    if isinstance(tools, Sequence) and not isinstance(tools, (str, bytes, bytearray)):
        for item in tools:
            entry = _mapping(item, "runtime tool catalog entry")
            name = _tool_name(entry)
            if name is not None:
                entries[name] = _tool_parameters(entry)
        return entries
    raise AdapterContractError("runtime tool catalog must expose tools")


def assert_installed_session_tools(catalog: Mapping[str, Any]) -> None:
    """Fail closed unless the runtime exposes the session tools this adapter calls."""

    entries = _tool_entries(catalog)
    for method, required_params in _REQUIRED_SESSION_TOOL_PARAMS.items():
        if method not in entries:
            raise AdapterContractError(f"runtime tool catalog is missing {method}")
        missing_params = sorted(required_params - entries[method])
        if missing_params:
            missing = ", ".join(missing_params)
            raise AdapterContractError(
                f"runtime tool catalog {method} is missing parameters: {missing}"
            )


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
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise AdapterContractError(f"{label} response must include {label}")
    observations: list[MetadataObservation] = []
    for item in items:
        try:
            mapped = _mapping(item, label)
        except AdapterContractError:
            continue
        try:
            observations.append(observation_from_openclaw_response(mapped))
        except AdapterContractError:
            partial = partial_observation_from_openclaw_response(mapped)
            if partial is not None:
                observations.append(
                    replace(partial, metadata_contract_version=None, raw_json=None)
                )
    return tuple(observations)


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def partial_observation_from_openclaw_response(
    response: Mapping[str, Any],
) -> MetadataObservation | None:
    """Keep malformed matching list observations visible to reconciliation."""

    container: Mapping[str, Any] = response
    if isinstance(response.get("metadata"), Mapping):
        container = _mapping(response["metadata"], "metadata")
    normalized = (
        container.get("normalized")
        or container.get("normalized_metadata")
        or container.get("external_metadata")
    )
    if not isinstance(normalized, Mapping):
        return None
    version = container.get("metadata_contract_version") or container.get(
        "contract_version"
    )
    raw_json = container.get("raw_json") or container.get("raw_metadata_json")
    lease = response.get("lease") if isinstance(response.get("lease"), Mapping) else {}
    session = response.get("session") if isinstance(response.get("session"), Mapping) else {}
    raw_response_json: str | None
    try:
        raw_response_json = _json_object(response)
    except AdapterContractError:
        raw_response_json = None
    session_key = _string_or_none(response.get("session_key")) or _string_or_none(
        response.get("sessionKey")
    ) or _string_or_none(session.get("session_key")) or _string_or_none(
        session.get("sessionKey")
    )
    spawn_request_session_key = _string_or_none(
        response.get("spawn_request_session_key")
    ) or _string_or_none(response.get("spawnRequestSessionKey")) or _string_or_none(
        session.get("spawn_request_session_key")
    ) or _string_or_none(session.get("spawnRequestSessionKey"))
    external_id = (
        _string_or_none(response.get("external_id"))
        or session_key
        or _string_or_none(response.get("gateway_lease_id"))
        or _string_or_none(lease.get("gateway_lease_id"))
        or _string_or_none(lease.get("lease_id"))
    )
    status_metadata_json = response.get("status_metadata_json")
    return MetadataObservation(
        metadata_contract_version=version if isinstance(version, str) else None,
        normalized=normalized,
        raw_json=raw_json if isinstance(raw_json, str) else None,
        external_id=external_id,
        spawn_request_session_key=spawn_request_session_key,
        session_key=session_key,
        status_metadata_json=status_metadata_json
        if isinstance(status_metadata_json, str)
        else None,
        raw_response_json=raw_response_json,
    )


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
            ("sessionKey", response.get("sessionKey")),
            (
                "session.session_key",
                session.get("session_key") if session is not None else None,
            ),
            (
                "session.sessionKey",
                session.get("sessionKey") if session is not None else None,
            ),
            ("session.key", session.get("key") if session is not None else None),
        ),
    )
    spawn_request_session_key = _consistent_identity(
        "spawn request session key",
        (
            ("spawn_request_session_key", response.get("spawn_request_session_key")),
            ("spawnRequestSessionKey", response.get("spawnRequestSessionKey")),
            (
                "session.spawn_request_session_key",
                session.get("spawn_request_session_key") if session is not None else None,
            ),
            (
                "session.spawnRequestSessionKey",
                session.get("spawnRequestSessionKey") if session is not None else None,
            ),
            (
                "session.request_session_key",
                session.get("request_session_key") if session is not None else None,
            ),
            (
                "session.requestSessionKey",
                session.get("requestSessionKey") if session is not None else None,
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

    @classmethod
    def from_preflighted_catalog(
        cls, transport: OpenClawTransport, catalog: Mapping[str, Any]
    ) -> "OpenClawAdapter":
        assert_installed_session_tools(catalog)
        return cls(transport)

    def allow_lease_acquire(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("subagents.allowLease.acquire", params),
                "subagents.allowLease.acquire",
            )
        )

    def allow_lease_list(self) -> Sequence[MetadataObservation]:
        response = _transport_response(
            self._transport.call("subagents.allowLease.status", {}),
            "subagents.allowLease.status",
        )
        return _observations_from_items(response.get("leases"), "lease")

    def allow_lease_release(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("subagents.allowLease.release", params),
                "subagents.allowLease.release",
            )
        )

    def sessions_spawn(self, params: Mapping[str, Any]) -> MetadataObservation:
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("sessions_spawn", params), "sessions_spawn"
            )
        )

    def sessions_list(self) -> Sequence[MetadataObservation]:
        response = _transport_response(
            self._transport.call("sessions_list", {}), "sessions_list"
        )
        return _observations_from_items(response.get("sessions"), "session")

    def session_status(self, session_key: str) -> MetadataObservation:
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("sessions_status", {"session_key": session_key}),
                "sessions_status",
            )
        )

    def session_result(self, session_key: str) -> MetadataObservation:
        response = _transport_response(
            self._transport.call(
                "sessions_history",
                {"sessionKey": session_key, "limit": 1, "includeTools": True},
            ),
            "sessions_history",
        )
        observation = observation_from_openclaw_response(response)
        if (
            not observation.external_id
            or not observation.session_key
            or not observation.spawn_request_session_key
        ):
            raise AdapterContractError(
                "sessions_history response must include accepted session identity"
            )
        if (
            observation.external_id != session_key
            or observation.session_key != session_key
            or observation.spawn_request_session_key != session_key
        ):
            raise AdapterContractError(
                "sessions_history response identity must match requested session"
            )
        return observation
