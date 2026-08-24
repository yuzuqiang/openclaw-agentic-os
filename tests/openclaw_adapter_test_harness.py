"""Test-only canned transport adapter.

This module deliberately lives outside the production package.  It exercises the
response parsers and dispatch semantics without creating runtime authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agentic_os.openclaw_adapter import (
    AdapterContractError,
    MetadataObservation,
    OpenClawTransport,
    _history_item_session_keys,
    _observations_from_items,
    _transport_response,
    observation_from_openclaw_response,
)


class CannedOpenClawAdapter:
    """Test-local protocol implementation over an arbitrary canned transport."""

    runtime_authority_verified = False

    def __init__(self, transport: OpenClawTransport) -> None:
        self._transport = transport

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
                self._transport.call("session_status", {"sessionKey": session_key}),
                "session_status",
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
        for (
            label,
            item_session_key,
            item_spawn_request_session_key,
            item_external_id,
        ) in _history_item_session_keys(response):
            if (
                item_session_key is None
                and item_spawn_request_session_key is None
                and item_external_id is None
            ):
                raise AdapterContractError(
                    f"sessions_history {label} must include requested session identity"
                )
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
