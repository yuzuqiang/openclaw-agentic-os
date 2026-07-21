#!/usr/bin/env python3
"""Bounded live OpenClaw accepted-session identity/idempotency probe.

The probe refuses to call mutating OpenClaw RPCs unless the installed runtime
catalog first passes ``openclaw-tool-capability-preflight.py`` for the exact
Agentic OS allowLease/session metadata contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import agentic_os  # noqa: E402
from agentic_os.metadata import (  # noqa: E402
    MetadataContractError,
    validate_accepted_lease_identity,
    validate_accepted_session_identity,
)


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "openclaw-tool-capability-preflight.py"


def _json_dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _write_evidence(path: str | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_json(cmd: list[str], *, timeout: int) -> tuple[int, dict[str, Any]]:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    try:
        payload = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        payload = {
            "status": "error",
            "error": "command returned non-JSON output",
            "stdout_prefix": (proc.stdout or "")[:500],
        }
    if proc.returncode != 0 and "error" not in payload:
        payload["error"] = (proc.stderr or proc.stdout or "command failed").strip()
    return proc.returncode, payload


def _preflight() -> tuple[bool, dict[str, Any]]:
    code, payload = _run_json(
        [
            sys.executable,
            str(PREFLIGHT),
            "--live-installed-openclaw",
            "--json",
        ],
        timeout=30,
    )
    return code == 0 and payload.get("status") == "pass", payload


def _gateway_call(method: str, params: dict[str, Any], *, timeout_ms: int) -> dict[str, Any]:
    code, payload = _run_json(
        [
            "openclaw",
            "gateway",
            "call",
            method,
            "--json",
            "--timeout",
            str(timeout_ms),
            "--params",
            _json_dump(params),
        ],
        timeout=max(5, timeout_ms // 1000 + 5),
    )
    if code != 0:
        raise RuntimeError(f"gateway call {method} failed: {payload.get('error') or payload}")
    return payload


def _path_value(payload: Any, path: tuple[str, ...]) -> Any:
    value = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _string_path(payload: Any, *paths: tuple[str, ...], label: str = "identity") -> str | None:
    selected: tuple[tuple[str, ...], str] | None = None
    for path in paths:
        value = _path_value(payload, path)
        if isinstance(value, str) and value:
            if selected is None:
                selected = (path, value)
            elif value != selected[1]:
                first_path = ".".join(selected[0])
                second_path = ".".join(path)
                raise MetadataContractError(
                    f"conflicting {label} aliases: {first_path}={selected[1]!r}, "
                    f"{second_path}={value!r}"
                )
    return selected[1] if selected is not None else None


def _raw_response_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_json_dump(payload).encode("utf-8")).hexdigest()


def _lease_id_from_response(response: dict[str, Any]) -> str | None:
    return _string_path(
        response,
        ("gateway_lease_id",),
        ("lease", "gateway_lease_id"),
        ("leaseId",),
        ("id",),
        label="gateway lease identity",
    )


def _iter_mappings(value: Any) -> tuple[Mapping[str, Any], ...]:
    found: list[Mapping[str, Any]] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            found.append(item)
            stack.extend(item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            stack.extend(item)
    return tuple(found)


def _mapping_path(payload: dict[str, Any], path: tuple[str, ...]) -> Mapping[str, Any] | None:
    value = _path_value(payload, path)
    return value if isinstance(value, Mapping) else None


def _require_expected_metadata_from_paths(
    payload: dict[str, Any],
    *,
    expected: dict[str, Any],
    label: str,
    paths: tuple[tuple[str, ...], ...],
) -> dict[str, Any]:
    for path in paths:
        item = payload if not path else _mapping_path(payload, path)
        if item is not None and all(item.get(key) == value for key, value in expected.items()):
            return {key: item[key] for key in expected}
    missing = ", ".join(sorted(expected))
    raise MetadataContractError(f"{label} did not echo expected metadata: {missing}")


def _validate_status_observes_lease(
    status: dict[str, Any], *, expected_metadata: dict[str, Any]
) -> dict[str, Any]:
    expected_gateway_lease_id = expected_metadata["gateway_lease_id"]
    for item in _iter_mappings(status):
        mapped = dict(item)
        if _lease_id_from_response(mapped) == expected_gateway_lease_id:
            owner_metadata = _require_expected_metadata_from_paths(
                mapped,
                expected=expected_metadata,
                label="allowLease status proof",
                paths=((), ("owner_metadata",), ("metadata",), ("lease", "owner_metadata"), ("lease", "metadata")),
            )
            return {
                "gateway_lease_id": expected_gateway_lease_id,
                "owner_metadata": owner_metadata,
                "raw_response_sha256": _raw_response_sha256(status),
                "response_top_level_keys": sorted(status),
            }
    raise MetadataContractError("allowLease status did not observe acquired lease identity")


def _validate_release_succeeded(response: dict[str, Any]) -> None:
    for path in (("released",), ("lease", "released")):
        value: Any = response
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value is not None:
            if value is True:
                return
            raise MetadataContractError("allowLease release did not report success")
    for path in (("status",), ("result",), ("lease", "status")):
        value = response
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if isinstance(value, str) and value.lower() in {"released", "success", "ok", "pass"}:
            return
    raise MetadataContractError("allowLease release response lacks success confirmation")


def _session_identity_from_spawn_response(response: dict[str, Any]) -> dict[str, str | None]:
    return {
        "external_id": _string_path(
            response,
            ("external_id",),
            ("externalId",),
            ("session", "external_id"),
            ("session", "externalId"),
            ("output", "external_id"),
            ("output", "externalId"),
            ("output", "session", "external_id"),
            ("output", "session", "externalId"),
            label="session external identity",
        ),
        "spawn_request_session_key": _string_path(
            response,
            ("spawn_request_session_key",),
            ("spawnRequestSessionKey",),
            ("request_session_key",),
            ("requestSessionKey",),
            ("session", "spawn_request_session_key"),
            ("session", "spawnRequestSessionKey"),
            ("session", "request_session_key"),
            ("session", "requestSessionKey"),
            ("output", "spawn_request_session_key"),
            ("output", "spawnRequestSessionKey"),
            ("output", "request_session_key"),
            ("output", "requestSessionKey"),
            ("output", "session", "spawn_request_session_key"),
            ("output", "session", "spawnRequestSessionKey"),
            ("output", "session", "request_session_key"),
            ("output", "session", "requestSessionKey"),
            label="spawn request session identity",
        ),
        "session_key": _string_path(
            response,
            ("session_key",),
            ("sessionKey",),
            ("session", "session_key"),
            ("session", "sessionKey"),
            ("session", "key"),
            ("output", "session_key"),
            ("output", "sessionKey"),
            ("output", "session", "session_key"),
            ("output", "session", "sessionKey"),
            ("output", "session", "key"),
            label="session identity",
        ),
    }


def _session_spawn_once(
    spawn_args: dict[str, Any],
    *,
    expected_metadata: dict[str, Any],
    timeout_seconds: int,
    timeout_ms: int,
) -> dict[str, Any]:
    response = _gateway_call(
        "sessions_spawn",
        spawn_args,
        timeout_ms=max(timeout_ms, timeout_seconds * 1000),
    )
    identity = _session_identity_from_spawn_response(response)
    accepted = validate_accepted_session_identity(
        external_id=identity["external_id"],
        spawn_request_session_key=identity["spawn_request_session_key"],
        session_key=identity["session_key"],
    )
    metadata_echo = _require_expected_metadata_from_paths(
        response,
        expected=expected_metadata,
        label="sessions_spawn response",
        paths=(
            ("session", "metadata"),
            ("session", "metadata_echo"),
            ("metadata_echo",),
            ("metadata",),
            ("output", "session", "metadata"),
            ("output", "session", "metadata_echo"),
            ("output", "metadata_echo"),
            ("output", "metadata"),
        ),
    )
    return {
        "accepted_session_identity": accepted,
        "identity": identity,
        "metadata_echo": metadata_echo,
        "raw_response_sha256": _raw_response_sha256(response),
        "response_top_level_keys": sorted(response),
    }


def _release_lease(
    release_params: dict[str, Any],
    *,
    expected_metadata: dict[str, Any],
    timeout_ms: int,
) -> dict[str, Any]:
    response = _gateway_call(
        "subagents.allowLease.release",
        release_params,
        timeout_ms=timeout_ms,
    )
    expected_gateway_lease_id = expected_metadata["gateway_lease_id"]
    released_gateway_lease_id = _lease_id_from_response(response)
    validate_accepted_lease_identity(
        gateway_lease_id=released_gateway_lease_id,
        duplicate_acquire_lease_id=expected_gateway_lease_id,
    )
    _validate_release_succeeded(response)
    owner_metadata = _require_expected_metadata_from_paths(
        response,
        expected=expected_metadata,
        label="allowLease release proof",
        paths=((), ("owner_metadata",), ("metadata",), ("lease", "owner_metadata"), ("lease", "metadata")),
    )
    return {
        "gateway_lease_id": released_gateway_lease_id,
        "owner_metadata": owner_metadata,
        "raw_response_sha256": _raw_response_sha256(response),
        "response_top_level_keys": sorted(response),
    }


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    started = int(time.time() * 1000)
    evidence: dict[str, Any] = {
        "probe": "openclaw-live-accepted-session-identity",
        "started_epoch_ms": started,
        "db_authority_enabled": bool(agentic_os.DB_AUTHORITY_ENABLED),
        "rpc_attempted": [],
        "released": None,
    }
    if evidence["db_authority_enabled"]:
        evidence.update(
            {
                "status": "fail_closed",
                "reason": "db_authority_enabled",
                "spawn_attempted": False,
                "lease_acquired": False,
                "released": "not_required",
            }
        )
        return evidence
    try:
        preflight_ok, preflight_payload = _preflight()
    except subprocess.TimeoutExpired as exc:
        evidence.update(
            {
                "status": "fail_closed",
                "reason": "capability_preflight_timed_out",
                "error": str(exc),
                "preflight": {"status": "fail", "error": "capability preflight timed out"},
                "spawn_attempted": False,
                "lease_acquired": False,
                "released": "not_required",
            }
        )
        return evidence
    evidence["preflight"] = preflight_payload
    if not preflight_ok:
        evidence.update(
            {
                "status": "fail_closed",
                "reason": "capability_preflight_failed",
                "spawn_attempted": False,
                "lease_acquired": False,
                "released": "not_required",
            }
        )
        return evidence

    lease_id: str | None = None
    gateway_lease_id: str | None = None
    lease_ids_to_release: list[str] = []
    try:
        acquire_params = {
            "client_lease_id": f"issue35-{args.probe_id}",
            "idempotency_key": f"issue35-acquire-{args.probe_id}",
            "run_id": f"issue35-run-{args.probe_id}",
            "phase": "B",
            "transition_id": f"issue35-transition-{args.probe_id}",
            "agent_id": args.agent_id,
            "requester_agent_id": args.requester_agent_id,
            "ttl_ms": args.ttl_ms,
        }
        evidence["rpc_attempted"].append("subagents.allowLease.acquire")
        first = _gateway_call(
            "subagents.allowLease.acquire", acquire_params, timeout_ms=args.gateway_timeout_ms
        )
        gateway_lease_id = _lease_id_from_response(first)
        lease_id = validate_accepted_lease_identity(gateway_lease_id=gateway_lease_id)
        lease_ids_to_release.append(lease_id)
        evidence["allow_lease"] = {
            "gateway_lease_id": gateway_lease_id,
            "raw_acquire_response_sha256": _raw_response_sha256(first),
        }
        evidence["lease_acquired"] = True
        evidence["rpc_attempted"].append("subagents.allowLease.acquire:duplicate")
        second = _gateway_call(
            "subagents.allowLease.acquire", acquire_params, timeout_ms=args.gateway_timeout_ms
        )
        duplicate_gateway_lease_id = _lease_id_from_response(second)
        if duplicate_gateway_lease_id is None:
            raise MetadataContractError(
                "duplicate allowLease acquire did not report lease identity"
            )
        if duplicate_gateway_lease_id not in lease_ids_to_release:
            lease_ids_to_release.append(duplicate_gateway_lease_id)
        validate_accepted_lease_identity(
            gateway_lease_id=gateway_lease_id,
            duplicate_acquire_lease_id=duplicate_gateway_lease_id,
        )
        evidence["allow_lease"]["duplicate_gateway_lease_id"] = duplicate_gateway_lease_id
        evidence["allow_lease"]["raw_duplicate_response_sha256"] = _raw_response_sha256(second)
        evidence["rpc_attempted"].append("subagents.allowLease.status")
        status = _gateway_call(
            "subagents.allowLease.status", {}, timeout_ms=args.gateway_timeout_ms
        )
        evidence["allow_lease"]["status_observed_lease"] = _validate_status_observes_lease(
            status,
            expected_metadata={**acquire_params, "gateway_lease_id": gateway_lease_id},
        )
        if not args.execute_session_spawn:
            evidence.update(
                {
                    "status": "fail_closed",
                    "reason": "session_spawn_execution_disabled",
                    "spawn_attempted": False,
                    "lease_acquired": True,
                }
            )
            return evidence

        spawn_args = {
            "task": "Return exactly: issue35 identity probe complete",
            "taskName": f"issue35probe{args.probe_id.replace('-', '')[:24]}",
            "runtime": "subagent",
            "mode": "run",
            "agentId": args.agent_id,
            "client_request_id": f"issue35-client-{args.probe_id}",
            "idempotency_key": f"issue35-spawn-{args.probe_id}",
            "metadata": {
                "run_id": f"issue35-run-{args.probe_id}",
                "transition_id": f"issue35-transition-{args.probe_id}",
                "client_request_id": f"issue35-client-{args.probe_id}",
                "idempotency_key": f"issue35-spawn-{args.probe_id}",
                "phase": "B",
                "agent_id": args.agent_id,
                "task_digest": f"issue35-task-{args.probe_id}",
            },
        }
        evidence["rpc_attempted"].append("sessions_spawn")
        accepted_one = _session_spawn_once(
            spawn_args,
            expected_metadata=spawn_args["metadata"],
            timeout_seconds=args.agent_timeout_seconds,
            timeout_ms=args.gateway_timeout_ms,
        )
        evidence["rpc_attempted"].append("sessions_spawn:duplicate")
        accepted_two = _session_spawn_once(
            spawn_args,
            expected_metadata=spawn_args["metadata"],
            timeout_seconds=args.agent_timeout_seconds,
            timeout_ms=args.gateway_timeout_ms,
        )
        session_identity = validate_accepted_session_identity(
            external_id=accepted_one["identity"]["external_id"],
            spawn_request_session_key=accepted_one["identity"]["spawn_request_session_key"],
            session_key=accepted_one["identity"]["session_key"],
            duplicate_spawn_session_key=accepted_two["accepted_session_identity"],
        )
        evidence.update(
            {
                "status": "pass",
                "spawn_attempted": True,
                "lease_acquired": True,
                "accepted_session_identity": session_identity,
                "accepted_session_identity_parity": {
                    "external_rpc_intents.external_id": session_identity,
                    "spawn_requests.session_key": session_identity,
                    "sessions.session_key": session_identity,
                },
                "sessions_spawn_structured_evidence": {
                    "first": accepted_one,
                    "duplicate": accepted_two,
                },
            }
        )
        return evidence
    except (MetadataContractError, RuntimeError, subprocess.TimeoutExpired) as exc:
        evidence.update(
            {
                "status": "fail_closed",
                "reason": "live_probe_contract_failed",
                "error": str(exc),
                "spawn_attempted": any("sessions_spawn" in item for item in evidence["rpc_attempted"]),
                "lease_acquired": bool(gateway_lease_id),
            }
        )
        return evidence
    finally:
        if lease_ids_to_release:
            release_errors: list[str] = []
            releases: list[dict[str, Any]] = []
            for index, acquired_lease_id in enumerate(lease_ids_to_release):
                release_params = {
                    "client_lease_id": f"issue35-{args.probe_id}",
                    "idempotency_key": f"issue35-release-{args.probe_id}-{index}",
                    "run_id": f"issue35-run-{args.probe_id}",
                    "phase": "B",
                    "transition_id": f"issue35-transition-{args.probe_id}",
                    "agent_id": args.agent_id,
                    "requester_agent_id": args.requester_agent_id,
                    "gateway_lease_id": acquired_lease_id,
                }
                evidence["rpc_attempted"].append("subagents.allowLease.release")
                try:
                    release = _release_lease(
                        release_params,
                        expected_metadata=release_params,
                        timeout_ms=args.gateway_timeout_ms,
                    )
                    releases.append(release)
                    if "allow_lease_release" not in evidence:
                        evidence["allow_lease_release"] = release
                except BaseException as exc:  # pragma: no cover - defensive live cleanup path
                    release_errors.append(f"{acquired_lease_id}: {exc}")
            if releases:
                evidence["allow_lease_releases"] = releases
            if release_errors:
                prior_reason = evidence.get("reason")
                evidence["status"] = "fail_closed"
                evidence["reason"] = "lease_release_failed"
                if prior_reason is not None:
                    evidence["prior_reason"] = prior_reason
                evidence["released"] = False
                evidence["release_error"] = "; ".join(release_errors)
            else:
                evidence["released"] = True
        elif evidence.get("released") is None:
            evidence["released"] = "not_required"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-id", default="local", help="Stable suffix for duplicate probe keys.")
    parser.add_argument("--agent-id", default="technical-writer")
    parser.add_argument("--requester-agent-id", default="main")
    parser.add_argument("--ttl-ms", type=int, default=60_000)
    parser.add_argument("--gateway-timeout-ms", type=int, default=10_000)
    parser.add_argument(
        "--agent-timeout-seconds",
        type=int,
        default=120,
        help="Upper bound for each direct structured sessions_spawn RPC.",
    )
    parser.add_argument(
        "--execute-session-spawn",
        action="store_true",
        help="Actually spawn duplicate accepted-session probes after exact preflight and allowLease proof pass.",
    )
    parser.add_argument("--evidence-file", help="Path for sanitized JSON evidence.")
    args = parser.parse_args(argv)

    payload = run_probe(args)
    _write_evidence(args.evidence_file, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
