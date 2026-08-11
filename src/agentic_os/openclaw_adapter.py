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
    "sessions_spawn": frozenset(("client_request_id", "idempotency_key", "metadata")),
    "sessions_list": frozenset(),
    "sessions_status": frozenset(("session_key",)),
    "sessions_history": frozenset(("sessionKey", "limit", "includeTools")),
}

_REQUIRED_ALLOW_LEASE_TOOL_PARAMS: Mapping[str, frozenset[str]] = {
    "subagents.allowLease.acquire": frozenset(
        (
            "client_lease_id",
            "idempotency_key",
            "run_id",
            "phase",
            "transition_id",
            "agent_id",
            "requester_agent_id",
            "ttl_ms",
        )
    ),
    "subagents.allowLease.status": frozenset(),
    "subagents.allowLease.release": frozenset(
        (
            "client_lease_id",
            "release_idempotency_key",
            "run_id",
            "phase",
            "transition_id",
            "agent_id",
            "requester_agent_id",
            "gateway_lease_id",
        )
    ),
}

_REQUIRED_RUNTIME_TOOL_PARAMS: Mapping[str, frozenset[str]] = {
    **_REQUIRED_ALLOW_LEASE_TOOL_PARAMS,
    **_REQUIRED_SESSION_TOOL_PARAMS,
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
                if name in entries and name in _REQUIRED_RUNTIME_TOOL_PARAMS:
                    raise AdapterContractError(
                        f"runtime tool catalog has duplicate {name} entries"
                    )
                entries[name] = _tool_parameters(entry)
        return entries
    raise AdapterContractError("runtime tool catalog must expose tools")


def _split_evidence_authority_errors(
    catalog: Mapping[str, Any], required_tools: Mapping[str, frozenset[str]]
) -> tuple[list[str], frozenset[str]]:
    """Reject split evidence that promotes source declarations into live authority."""

    errors: list[str] = []
    unproven_parameter_methods: set[str] = set()
    tools = catalog.get("tools")
    if isinstance(tools, Sequence) and not isinstance(tools, (str, bytes, bytearray)):
        for value in tools:
            if not isinstance(value, Mapping):
                continue
            name = _tool_name(value)
            parameter_evidence = value.get("parameter_evidence")
            if (
                name in required_tools
                and required_tools[name]
                and isinstance(parameter_evidence, Mapping)
                and parameter_evidence.get("status")
                == "unproven_from_catalog_and_installed_sources"
            ):
                unproven_parameter_methods.add(name)

    gateway_catalog = catalog.get("gateway_rpc_catalog")
    if isinstance(gateway_catalog, Mapping):
        raw_rpc_evidence = gateway_catalog.get("rpc_evidence")
        rpc_evidence: dict[str, Mapping[str, Any]] = {}
        if not isinstance(raw_rpc_evidence, Sequence) or isinstance(
            raw_rpc_evidence, (str, bytes, bytearray)
        ):
            errors.append("runtime Gateway RPC evidence must be a list")
        else:
            for item in raw_rpc_evidence:
                if not isinstance(item, Mapping):
                    errors.append("runtime Gateway RPC evidence entry must be an object")
                    continue
                name = item.get("name")
                if not isinstance(name, str) or name not in _REQUIRED_ALLOW_LEASE_TOOL_PARAMS:
                    errors.append("runtime Gateway RPC evidence has an unexpected method")
                    continue
                if name in rpc_evidence:
                    errors.append(f"runtime Gateway RPC evidence duplicates {name}")
                    continue
                rpc_evidence[name] = item
        for method in _REQUIRED_ALLOW_LEASE_TOOL_PARAMS:
            if method not in required_tools:
                continue
            evidence = rpc_evidence.get(method)
            if not isinstance(evidence, Mapping):
                errors.append(
                    f"runtime Gateway RPC {method} is missing authority-aware live "
                    "reachability evidence"
                )
            elif evidence.get("live_reachability") != "reachable":
                errors.append(
                    f"runtime Gateway RPC {method} live reachability is unproven; "
                    "installed source declaration is not runtime reachability proof"
                )
            else:
                live_probe = evidence.get("live_probe")
                if (
                    not isinstance(live_probe, Mapping)
                    or live_probe.get("method") != method
                    or live_probe.get("status") != "ok"
                    or live_probe.get("live_reachability") != "reachable"
                    or not _is_sha256(live_probe.get("raw_response_sha256"))
                    or not isinstance(live_probe.get("request_semantics"), str)
                    or not live_probe.get("request_semantics")
                ):
                    errors.append(
                        f"runtime Gateway RPC {method} reachable claim lacks a valid "
                        "method-bound live probe"
                    )
    return errors, frozenset(unproven_parameter_methods)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def assert_preflighted_runtime_authority(payload: Mapping[str, Any]) -> None:
    """Require a complete, live-proven envelope before constructing an online adapter."""

    errors: list[str] = []
    if payload.get("status") != "pass":
        errors.append("runtime authority envelope status must be pass")
    if payload.get("runtime_ready") is not True:
        errors.append("runtime authority envelope must declare runtime_ready=true")
    catalog = payload.get("catalog")
    if not isinstance(catalog, Mapping):
        raise AdapterContractError(
            "; ".join((*errors, "runtime authority envelope must include catalog"))
        )

    try:
        assert_installed_runtime_tools(catalog)
    except AdapterContractError as exc:
        errors.append(str(exc))

    if catalog.get("catalog_kind") != "sanitized_openclaw_runtime":
        errors.append("runtime authority catalog kind is invalid")
    if catalog.get("runtime_target") not in {
        "live_installed_openclaw",
        "isolated_candidate",
    }:
        errors.append("runtime authority target is not an online OpenClaw runtime")

    model_catalog = catalog.get("model_tool_catalog")
    gateway_catalog = catalog.get("gateway_rpc_catalog")
    model_entries: Mapping[str, frozenset[str]] = {}
    gateway_entries: Mapping[str, frozenset[str]] = {}
    if not isinstance(model_catalog, Mapping):
        errors.append("runtime authority requires model_tool_catalog")
    else:
        if model_catalog.get("catalog_kind") != "model_callable_tools_catalog":
            errors.append("runtime model tool catalog kind is invalid")
        if model_catalog.get("authority") != "tools.catalog":
            errors.append("runtime model tool catalog authority must be tools.catalog")
        if not _is_sha256(model_catalog.get("raw_response_sha256")):
            errors.append("runtime model tool catalog response digest is invalid")
        try:
            model_entries = _tool_entries({"tools": model_catalog.get("tools")})
            _assert_installed_tools(
                {"tools": model_catalog.get("tools")},
                _REQUIRED_SESSION_TOOL_PARAMS,
            )
        except AdapterContractError as exc:
            errors.append(f"runtime model tool authority is incomplete: {exc}")

    if not isinstance(gateway_catalog, Mapping):
        errors.append("runtime authority requires gateway_rpc_catalog")
    else:
        if gateway_catalog.get("catalog_kind") != "source_bound_gateway_rpc_catalog":
            errors.append("runtime Gateway RPC catalog kind is invalid")
        if gateway_catalog.get("authority") != "installed_runtime_dist_sources":
            errors.append(
                "runtime Gateway RPC catalog authority must be installed runtime sources"
            )
        source_bound_rpc_names = gateway_catalog.get("source_bound_rpc_names")
        if (
            gateway_catalog.get("status") != "disk_source_declarations_complete"
            or not isinstance(source_bound_rpc_names, Sequence)
            or isinstance(source_bound_rpc_names, (str, bytes, bytearray))
            or any(not isinstance(name, str) for name in source_bound_rpc_names)
            or set(source_bound_rpc_names) != set(_REQUIRED_ALLOW_LEASE_TOOL_PARAMS)
        ):
            errors.append("runtime Gateway RPC source declarations are incomplete")
        try:
            gateway_entries = _tool_entries({"tools": gateway_catalog.get("tools")})
            _assert_installed_tools(
                {"tools": gateway_catalog.get("tools")},
                _REQUIRED_ALLOW_LEASE_TOOL_PARAMS,
            )
        except AdapterContractError as exc:
            errors.append(f"runtime Gateway RPC source authority is incomplete: {exc}")
        status_corroboration = gateway_catalog.get("status_corroboration")
        if not isinstance(status_corroboration, Mapping):
            errors.append("runtime Gateway status corroboration is missing")
        elif (
            status_corroboration.get("method") != "subagents.allowLease.status"
            or status_corroboration.get("status") != "ok"
            or status_corroboration.get("live_reachability") != "reachable"
            or not _is_sha256(status_corroboration.get("raw_response_sha256"))
        ):
            errors.append("runtime Gateway status corroboration is not live-proven")

    try:
        aggregate_entries = _tool_entries(catalog)
    except AdapterContractError as exc:
        errors.append(str(exc))
        aggregate_entries = {}
    if model_entries and gateway_entries:
        for method in _REQUIRED_RUNTIME_TOOL_PARAMS:
            nested = (
                gateway_entries
                if method in _REQUIRED_ALLOW_LEASE_TOOL_PARAMS
                else model_entries
            )
            if aggregate_entries.get(method) != nested.get(method):
                errors.append(
                    f"runtime aggregate and authority catalog disagree for {method}"
                )

    if catalog.get("connected_gateway_build_identity") != "proven":
        errors.append("connected Gateway build identity is not proven")
    build_evidence = catalog.get("connected_gateway_build_evidence")
    active_executable_sha256 = catalog.get("active_executable_sha256")
    if not isinstance(build_evidence, Mapping):
        errors.append("connected Gateway build evidence is missing")
    elif (
        build_evidence.get("status") != "proven"
        or build_evidence.get("verification_method")
        != "gateway_reported_executable_sha256"
        or not _is_sha256(active_executable_sha256)
        or build_evidence.get("connected_executable_sha256")
        != active_executable_sha256
    ):
        errors.append("connected Gateway build evidence is invalid")

    if errors:
        raise AdapterContractError("; ".join(errors))


def assert_installed_session_tools(catalog: Mapping[str, Any]) -> None:
    """Fail closed unless the runtime exposes the session tools this adapter calls."""

    _assert_installed_tools(catalog, _REQUIRED_SESSION_TOOL_PARAMS)


def assert_installed_runtime_tools(catalog: Mapping[str, Any]) -> None:
    """Fail closed unless the runtime exposes all dispatch tools this adapter calls."""

    _assert_installed_tools(catalog, _REQUIRED_RUNTIME_TOOL_PARAMS)


def _assert_installed_tools(
    catalog: Mapping[str, Any], required_tools: Mapping[str, frozenset[str]]
) -> None:
    entries = _tool_entries(catalog)
    errors, unproven_parameter_methods = _split_evidence_authority_errors(
        catalog, required_tools
    )
    for method, required_params in required_tools.items():
        if method not in entries:
            errors.append(f"runtime tool catalog is missing {method}")
            continue
        if method in unproven_parameter_methods:
            errors.append(
                f"runtime tool catalog {method} required parameter schema is unproven "
                "by tools.catalog and installed runtime source evidence"
            )
            continue
        missing_params = sorted(required_params - entries[method])
        if missing_params:
            missing = ", ".join(missing_params)
            errors.append(
                f"runtime tool catalog {method} is missing parameters: {missing}"
            )
    if errors:
        raise AdapterContractError("; ".join(errors))


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


def _history_item_session_keys(
    response: Mapping[str, Any],
) -> tuple[tuple[str, str | None, str | None, str | None], ...]:
    """Return item-level session identities from a history response."""

    identities: list[tuple[str, str | None, str | None, str | None]] = []
    for container_name in ("messages", "history", "items", "events"):
        items = response.get(container_name)
        if not isinstance(items, Sequence) or isinstance(
            items, (str, bytes, bytearray)
        ):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            session = (
                item.get("session") if isinstance(item.get("session"), Mapping) else {}
            )
            label = f"{container_name}[{index}]"
            session_key = _consistent_identity(
                f"{label} session key",
                (
                    (f"{label}.session_key", item.get("session_key")),
                    (f"{label}.sessionKey", item.get("sessionKey")),
                    (f"{label}.session.session_key", session.get("session_key")),
                    (f"{label}.session.sessionKey", session.get("sessionKey")),
                    (f"{label}.session.key", session.get("key")),
                ),
            )
            spawn_request_session_key = _consistent_identity(
                f"{label} spawn request session key",
                (
                    (
                        f"{label}.spawn_request_session_key",
                        item.get("spawn_request_session_key"),
                    ),
                    (
                        f"{label}.spawnRequestSessionKey",
                        item.get("spawnRequestSessionKey"),
                    ),
                    (
                        f"{label}.session.spawn_request_session_key",
                        session.get("spawn_request_session_key"),
                    ),
                    (
                        f"{label}.session.spawnRequestSessionKey",
                        session.get("spawnRequestSessionKey"),
                    ),
                    (
                        f"{label}.session.request_session_key",
                        session.get("request_session_key"),
                    ),
                    (
                        f"{label}.session.requestSessionKey",
                        session.get("requestSessionKey"),
                    ),
                ),
            )
            external_id = _consistent_identity(
                f"{label} external identity",
                (
                    (f"{label}.external_id", item.get("external_id")),
                    (f"{label}.externalId", item.get("externalId")),
                    (
                        f"{label}.session.external_id",
                        session.get("external_id"),
                    ),
                    (
                        f"{label}.session.externalId",
                        session.get("externalId"),
                    ),
                ),
            )
            if (
                session_key is not None
                or spawn_request_session_key is not None
                or external_id is not None
            ):
                identities.append(
                    (label, session_key, spawn_request_session_key, external_id)
                )
    return tuple(identities)


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
        normalized = None
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
    if (
        normalized is None
        and external_id is None
        and session_key is None
        and spawn_request_session_key is None
    ):
        return None
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
    """Fail-closed RPC adapter pending a transport-bound runtime attestor."""

    def __init__(self, transport: OpenClawTransport) -> None:
        del transport
        raise AdapterContractError(
            "OpenClawAdapter construction is disabled until a transport-bound "
            "runtime attestor is implemented"
        )

    def _require_verified_runtime_authority(self) -> None:
        """Reject until a real attestor can bind authority to this exact instance."""

        raise AdapterContractError(
            "OpenClawAdapter has no verified transport-bound runtime authority"
        )

    @property
    def runtime_authority_verified(self) -> bool:
        return False

    @classmethod
    def from_preflighted_catalog(
        cls, transport: OpenClawTransport, payload: Mapping[str, Any]
    ) -> "OpenClawAdapter":
        assert_preflighted_runtime_authority(payload)
        raise AdapterContractError(
            "unsigned preflight mapping cannot mint verified runtime authority"
        )

    def allow_lease_acquire(self, params: Mapping[str, Any]) -> MetadataObservation:
        OpenClawAdapter._require_verified_runtime_authority(self)
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("subagents.allowLease.acquire", params),
                "subagents.allowLease.acquire",
            )
        )

    def allow_lease_list(self) -> Sequence[MetadataObservation]:
        OpenClawAdapter._require_verified_runtime_authority(self)
        response = _transport_response(
            self._transport.call("subagents.allowLease.status", {}),
            "subagents.allowLease.status",
        )
        return _observations_from_items(response.get("leases"), "lease")

    def allow_lease_release(self, params: Mapping[str, Any]) -> MetadataObservation:
        OpenClawAdapter._require_verified_runtime_authority(self)
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("subagents.allowLease.release", params),
                "subagents.allowLease.release",
            )
        )

    def sessions_spawn(self, params: Mapping[str, Any]) -> MetadataObservation:
        OpenClawAdapter._require_verified_runtime_authority(self)
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("sessions_spawn", params), "sessions_spawn"
            )
        )

    def sessions_list(self) -> Sequence[MetadataObservation]:
        OpenClawAdapter._require_verified_runtime_authority(self)
        response = _transport_response(
            self._transport.call("sessions_list", {}), "sessions_list"
        )
        return _observations_from_items(response.get("sessions"), "session")

    def session_status(self, session_key: str) -> MetadataObservation:
        OpenClawAdapter._require_verified_runtime_authority(self)
        return observation_from_openclaw_response(
            _transport_response(
                self._transport.call("sessions_status", {"session_key": session_key}),
                "sessions_status",
            )
        )

    def session_result(self, session_key: str) -> MetadataObservation:
        OpenClawAdapter._require_verified_runtime_authority(self)
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
        for (
            label,
            item_session_key,
            item_spawn_request_session_key,
            item_external_id,
        ) in (
            _history_item_session_keys(response)
        ):
            if item_session_key is not None and item_session_key != session_key:
                raise AdapterContractError(
                    f"sessions_history {label} identity must match requested session"
                )
            if (
                item_spawn_request_session_key is not None
                and item_spawn_request_session_key != session_key
            ):
                raise AdapterContractError(
                    f"sessions_history {label} identity must match requested session"
                )
            if item_external_id is not None and item_external_id != session_key:
                raise AdapterContractError(
                    f"sessions_history {label} identity must match requested session"
                )
        return observation
