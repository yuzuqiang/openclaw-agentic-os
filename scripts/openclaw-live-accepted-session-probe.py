#!/usr/bin/env python3
"""Bounded live OpenClaw accepted-session identity/idempotency probe.

The probe refuses to call mutating OpenClaw RPCs unless the installed runtime
catalog first passes ``openclaw-tool-capability-preflight.py`` for the exact
Agentic OS allowLease/session metadata contract.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

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


def _string_path(payload: Any, *paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value = payload
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _agent_tool_prompt(spawn_args: dict[str, Any], probe_id: str) -> str:
    return (
        "Call the `sessions_spawn` tool exactly once with this JSON object:\n"
        f"{json.dumps(spawn_args, sort_keys=True)}\n\n"
        "After the tool returns, reply with JSON only using keys "
        '{"status","sessionKey","spawnRequestSessionKey","externalId","probeId"}. '
        f'Set "probeId" to "{probe_id}". Do not invent identities.'
    )


def _agent_spawn_once(spawn_args: dict[str, Any], probe_id: str, timeout_seconds: int) -> dict[str, Any]:
    session_key = f"agent:main:issue35-identity-probe-{probe_id}"
    code, payload = _run_json(
        [
            "openclaw",
            "agent",
            "--agent",
            "main",
            "--session-key",
            session_key,
            "--message",
            _agent_tool_prompt(spawn_args, probe_id),
            "--json",
            "--thinking",
            "low",
            "--timeout",
            str(timeout_seconds),
        ],
        timeout=timeout_seconds + 20,
    )
    if code != 0:
        raise RuntimeError(f"agent sessions_spawn bridge failed: {payload.get('error') or payload}")
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    summary = meta.get("toolSummary") if isinstance(meta.get("toolSummary"), dict) else {}
    tools = summary.get("tools") if isinstance(summary.get("tools"), list) else []
    if not (summary.get("calls") == 1 and summary.get("failures") == 0 and tools == ["sessions_spawn"]):
        raise RuntimeError("sessions_spawn was not called exactly once without tool failure")
    text = ""
    for item in result.get("payloads") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            text = item["text"].strip()
            break
    try:
        accepted = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("agent bridge did not return JSON identity evidence") from exc
    if not isinstance(accepted, dict) or accepted.get("probeId") != probe_id:
        raise RuntimeError("agent bridge returned mismatched probe identity")
    return accepted


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    started = int(time.time() * 1000)
    preflight_ok, preflight_payload = _preflight()
    evidence: dict[str, Any] = {
        "probe": "openclaw-live-accepted-session-identity",
        "started_epoch_ms": started,
        "db_authority_enabled": False,
        "preflight": preflight_payload,
        "rpc_attempted": [],
        "released": None,
    }
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
        first = _gateway_call(
            "subagents.allowLease.acquire", acquire_params, timeout_ms=args.gateway_timeout_ms
        )
        evidence["rpc_attempted"].append("subagents.allowLease.acquire")
        second = _gateway_call(
            "subagents.allowLease.acquire", acquire_params, timeout_ms=args.gateway_timeout_ms
        )
        evidence["rpc_attempted"].append("subagents.allowLease.acquire:duplicate")
        status = _gateway_call(
            "subagents.allowLease.status", {}, timeout_ms=args.gateway_timeout_ms
        )
        evidence["rpc_attempted"].append("subagents.allowLease.status")
        gateway_lease_id = _string_path(
            first,
            ("gateway_lease_id",),
            ("lease", "gateway_lease_id"),
            ("leaseId",),
            ("id",),
        )
        duplicate_gateway_lease_id = _string_path(
            second,
            ("gateway_lease_id",),
            ("lease", "gateway_lease_id"),
            ("leaseId",),
            ("id",),
        )
        lease_id = gateway_lease_id
        validate_accepted_lease_identity(
            gateway_lease_id=gateway_lease_id,
            duplicate_acquire_lease_id=duplicate_gateway_lease_id,
        )
        evidence["allow_lease"] = {
            "gateway_lease_id": gateway_lease_id,
            "duplicate_gateway_lease_id": duplicate_gateway_lease_id,
            "status_observed": bool(status),
        }
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
        accepted_one = _agent_spawn_once(spawn_args, args.probe_id, args.agent_timeout_seconds)
        evidence["rpc_attempted"].append("sessions_spawn")
        accepted_two = _agent_spawn_once(spawn_args, args.probe_id, args.agent_timeout_seconds)
        evidence["rpc_attempted"].append("sessions_spawn:duplicate")
        session_identity = validate_accepted_session_identity(
            external_id=accepted_one.get("externalId"),
            spawn_request_session_key=accepted_one.get("spawnRequestSessionKey"),
            session_key=accepted_one.get("sessionKey"),
            duplicate_spawn_session_key=accepted_two.get("sessionKey"),
        )
        evidence.update(
            {
                "status": "pass",
                "spawn_attempted": True,
                "lease_acquired": True,
                "accepted_session_identity": session_identity,
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
        if lease_id:
            try:
                release_params = {
                    "client_lease_id": f"issue35-{args.probe_id}",
                    "idempotency_key": f"issue35-release-{args.probe_id}",
                    "run_id": f"issue35-run-{args.probe_id}",
                    "phase": "B",
                    "transition_id": f"issue35-transition-{args.probe_id}",
                    "agent_id": args.agent_id,
                    "requester_agent_id": args.requester_agent_id,
                    "gateway_lease_id": lease_id,
                }
                _gateway_call(
                    "subagents.allowLease.release",
                    release_params,
                    timeout_ms=args.gateway_timeout_ms,
                )
                evidence["rpc_attempted"].append("subagents.allowLease.release")
                evidence["released"] = True
            except BaseException as exc:  # pragma: no cover - defensive live cleanup path
                evidence["released"] = False
                evidence["release_error"] = str(exc)
        elif evidence.get("released") is None:
            evidence["released"] = "not_required"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-id", default="local", help="Stable suffix for duplicate probe keys.")
    parser.add_argument("--agent-id", default="technical-writer")
    parser.add_argument("--requester-agent-id", default="main")
    parser.add_argument("--ttl-ms", type=int, default=60_000)
    parser.add_argument("--gateway-timeout-ms", type=int, default=10_000)
    parser.add_argument("--agent-timeout-seconds", type=int, default=120)
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
