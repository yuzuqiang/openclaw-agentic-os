#!/usr/bin/env python3
"""Disabled future-contract release probe pending runtime attestation.

This entry point is deliberately not an authoritative proof source until a
verified in-process adapter handoff exists.
"""

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
    OpenClawAdapter,
)


class ProbeError(RuntimeError):
    pass


DISABLED_PROOF_STATUS = "disabled_future_contract_not_authoritative"


def run_release_probe(
    *,
    adapter: OpenClawAdapter,
    acquire_params: Mapping[str, Any],
    release_params: Mapping[str, Any],
) -> dict[str, bool]:
    """Refuse before transport until an exact-instance attestor exists."""

    del acquire_params, release_params
    if type(adapter) is not OpenClawAdapter:
        raise ProbeError("release probe requires an exact OpenClawAdapter instance")
    try:
        OpenClawAdapter._require_verified_runtime_authority(adapter)
    except AdapterContractError as exc:
        raise ProbeError(
            "release probe requires verified in-process runtime authority"
        ) from exc
    raise ProbeError(
        "adapter release proof is disabled_future_contract_not_authoritative"
    )


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProbeError(f"{label} must be an object")
    return value


def main() -> int:
    line = sys.stdin.readline()
    if not line:
        raise ProbeError("missing probe initialization")
    try:
        request = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProbeError("probe initialization is invalid JSON") from exc
    request = _object(request, "probe initialization")
    if "catalog" in request:
        raise ProbeError(
            "unsigned cross-process catalog cannot create live adapter authority; "
            "adapter release proof is disabled_future_contract_not_authoritative"
        )
    raise ProbeError(
        "cross-process release probe requires a verified in-process adapter "
        "capability; adapter release proof is disabled_future_contract_not_authoritative"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AdapterContractError, ProbeError) as exc:
        print(
            json.dumps({"type": "error", "error": str(exc)}, sort_keys=True),
            flush=True,
        )
        raise SystemExit(1) from exc
