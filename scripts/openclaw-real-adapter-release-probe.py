#!/usr/bin/env python3
"""Exercise the merged Agentic adapter against a JSON-line Gateway bridge."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_os.openclaw_adapter import (  # noqa: E402
    AdapterContractError,
    MetadataObservation,
    OpenClawAdapter,
)
from agentic_os.metadata import (  # noqa: E402
    MetadataContractError,
    validate_allow_lease_release_observation,
)


class ProbeError(RuntimeError):
    pass


class JsonLineTransport:
    """Synchronous adapter transport backed by a supervising JSON-line process."""

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        print(
            json.dumps(
                {"type": "rpc", "method": method, "params": dict(params)},
                sort_keys=True,
            ),
            flush=True,
        )
        line = sys.stdin.readline()
        if not line:
            raise ProbeError("Gateway bridge closed before replying")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProbeError("Gateway bridge returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise ProbeError("Gateway bridge response must be an object")
        if response.get("ok") is not True:
            error = response.get("error")
            raise ProbeError(error if isinstance(error, str) else "Gateway RPC failed")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise ProbeError("Gateway bridge payload must be an object")
        return payload


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProbeError(f"{label} must be an object")
    return value


def _validated_release_metadata(
    observation: MetadataObservation, expected: Mapping[str, Any]
) -> Mapping[str, Any]:
    try:
        return validate_allow_lease_release_observation(
            local=expected,
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
    except MetadataContractError as exc:
        raise ProbeError("release response metadata does not match request") from exc


def _matches_released_lease(
    observation: MetadataObservation,
    *,
    acquired_external_id: str,
    release_params: Mapping[str, Any],
) -> bool:
    if observation.external_id == acquired_external_id:
        return True
    normalized = observation.normalized
    if not isinstance(normalized, Mapping):
        return False
    gateway_lease_id = normalized.get("gateway_lease_id")
    client_lease_id = normalized.get("client_lease_id")
    return (
        gateway_lease_id == acquired_external_id
        or client_lease_id == release_params.get("client_lease_id")
    )


def _reject_visible_post_release_lease(
    observation: MetadataObservation,
    *,
    acquired_external_id: str,
    release_params: Mapping[str, Any],
) -> None:
    if not _matches_released_lease(
        observation,
        acquired_external_id=acquired_external_id,
        release_params=release_params,
    ):
        return
    if (
        observation.metadata_contract_version is None
        or observation.raw_json is None
        or observation.external_id is None
    ):
        raise ProbeError("released lease remains visible with incomplete metadata")
    raise ProbeError("released lease remains visible")


def _require_release_request_fields(release_params: Mapping[str, Any]) -> None:
    required = (
        "client_lease_id",
        "release_idempotency_key",
        "run_id",
        "phase",
        "transition_id",
        "agent_id",
        "requester_agent_id",
        "gateway_lease_id",
    )
    missing = [
        field
        for field in required
        if not isinstance(release_params.get(field), str) or not release_params.get(field)
    ]
    if missing:
        raise ProbeError(f"release request is missing required fields: {missing}")


def _release_metadata(observation: MetadataObservation) -> Mapping[str, Any]:
    normalized = observation.normalized
    if not isinstance(normalized, Mapping):
        raise ProbeError("release response lacks normalized metadata")
    if "idempotency_key" in normalized:
        raise ProbeError("release response exposes legacy idempotency_key metadata")
    key = normalized.get("release_idempotency_key")
    if not isinstance(key, str) or not key:
        raise ProbeError("release response lacks release_idempotency_key metadata")
    return normalized


def run_release_probe(
    *,
    transport: Any,
    catalog: Mapping[str, Any],
    acquire_params: Mapping[str, Any],
    release_params: Mapping[str, Any],
) -> dict[str, bool]:
    """Preflight the live catalog and prove canonical release replay semantics."""

    adapter = OpenClawAdapter.from_preflighted_catalog(transport, catalog)
    acquired = adapter.allow_lease_acquire(acquire_params)
    if not acquired.external_id:
        raise ProbeError("acquire response lacks an external lease identity")

    canonical_release = dict(release_params)
    canonical_release["gateway_lease_id"] = acquired.external_id
    _require_release_request_fields(canonical_release)
    first = adapter.allow_lease_release(canonical_release)
    second = adapter.allow_lease_release(canonical_release)
    _release_metadata(first)
    _release_metadata(second)
    first_metadata = _validated_release_metadata(first, canonical_release)
    second_metadata = _validated_release_metadata(second, canonical_release)
    if (
        first.external_id != acquired.external_id
        or second.external_id != acquired.external_id
    ):
        raise ProbeError("release response lease identity does not match acquire")
    if first_metadata != second_metadata:
        raise ProbeError("duplicate release metadata differs")
    if first.raw_response_json != second.raw_response_json:
        raise ProbeError("duplicate release response differs")
    for lease in adapter.allow_lease_list():
        _reject_visible_post_release_lease(
            lease,
            acquired_external_id=acquired.external_id,
            release_params=canonical_release,
        )
    return {
        "agentic_adapter_live_catalog": True,
        "agentic_adapter_release_succeeded": True,
        "agentic_adapter_duplicate_release_parity": True,
        "agentic_adapter_release_metadata_parity": True,
        "agentic_adapter_post_release_absent": True,
    }


def main() -> int:
    line = sys.stdin.readline()
    if not line:
        raise ProbeError("missing probe initialization")
    try:
        request = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProbeError("probe initialization is invalid JSON") from exc
    request = _object(request, "probe initialization")
    result = run_release_probe(
        transport=JsonLineTransport(),
        catalog=_object(request.get("catalog"), "catalog"),
        acquire_params=_object(request.get("acquire_params"), "acquire_params"),
        release_params=_object(request.get("release_params"), "release_params"),
    )
    print(json.dumps({"type": "result", **result}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AdapterContractError, ProbeError) as exc:
        print(
            json.dumps({"type": "error", "error": str(exc)}, sort_keys=True),
            flush=True,
        )
        raise SystemExit(1) from exc
