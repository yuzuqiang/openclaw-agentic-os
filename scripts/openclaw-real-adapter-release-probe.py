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
    first = adapter.allow_lease_release(canonical_release)
    second = adapter.allow_lease_release(canonical_release)
    first_metadata = _release_metadata(first)
    second_metadata = _release_metadata(second)
    if (
        first.external_id != acquired.external_id
        or second.external_id != acquired.external_id
    ):
        raise ProbeError("release response lease identity does not match acquire")
    if first_metadata != second_metadata:
        raise ProbeError("duplicate release metadata differs")
    if first.raw_response_json != second.raw_response_json:
        raise ProbeError("duplicate release response differs")
    if any(
        lease.external_id == acquired.external_id
        for lease in adapter.allow_lease_list()
    ):
        raise ProbeError("released lease remains visible")
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
