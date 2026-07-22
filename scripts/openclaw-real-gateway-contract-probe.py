#!/usr/bin/env python3
"""Run the Agentic OS contract against an isolated, real OpenClaw Gateway."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
E2E_TEST = "test/agentic-os-runtime-contract.e2e.test.ts"
FORBIDDEN_EVIDENCE_KEYS = {
    "child_session_key",
    "child_run_id",
    "gateway_lease_id",
    "session_key",
    "task_marker",
    "token",
}
FORBIDDEN_EVIDENCE_FRAGMENTS = (
    "gateway-lease:",
    "agent:",
    "test-token-placeholder",
)


class ProbeError(RuntimeError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _git(root: Path, *args: str) -> str:
    proc = _run(["git", *args], cwd=root, timeout=30)
    if proc.returncode != 0:
        raise ProbeError(f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def validate_candidate_root(root: Path) -> str:
    root = root.resolve()
    package_path = root / "package.json"
    test_path = root / E2E_TEST
    if not package_path.is_file() or not test_path.is_file():
        raise ProbeError("OpenClaw candidate is missing package.json or the real Gateway E2E")
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError("OpenClaw candidate package.json is invalid") from exc
    if package.get("name") != "openclaw":
        raise ProbeError("candidate package name is not openclaw")
    head = _git(root, "rev-parse", "HEAD")
    if len(head) != 40:
        raise ProbeError("candidate HEAD is not a full git SHA")
    dirty = _git(root, "status", "--porcelain", "--untracked-files=normal")
    if dirty:
        raise ProbeError("candidate worktree is dirty; exact-head evidence is not authoritative")
    return head


def _walk_evidence(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_EVIDENCE_KEYS:
                raise ProbeError(f"evidence contains forbidden raw field: {'.'.join((*path, key))}")
            _walk_evidence(item, (*path, key))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_evidence(item, (*path, str(index)))
        return
    if isinstance(value, str):
        if Path(value).is_absolute() or any(
            fragment in value for fragment in FORBIDDEN_EVIDENCE_FRAGMENTS
        ):
            raise ProbeError(f"evidence contains forbidden raw value at {'.'.join(path)}")


def validate_evidence(payload: dict[str, Any], *, openclaw_root: Path, head: str) -> None:
    if payload.get("status") != "pass" or payload.get("openclaw_head_sha") != head:
        raise ProbeError("evidence status or OpenClaw head binding is invalid")
    required_true = (
        "authenticated_gateway",
        "effective_allow_lease",
        "runtime_catalog_discovered",
        "read_only_acquire_rejected",
        "wrong_lease_rejected",
        "cross_principal_lease_hidden",
        "cross_principal_spawn_rejected",
        "cross_principal_sessions_hidden",
        "cross_principal_status_rejected",
        "released_lease_spawn_rejected",
        "canonical_session_observed",
        "duplicate_lease_identity_parity",
        "duplicate_spawn_identity_parity",
        "child_completed",
    )
    if not all(payload.get(key) is True for key in required_true):
        raise ProbeError("evidence is missing a required runtime proof")
    if payload.get("static_allow_agents_wildcard") is not False:
        raise ProbeError("evidence does not prove a non-wildcard static allowlist")
    if payload.get("model_request_count") != 1:
        raise ProbeError("evidence does not prove exactly one real child model request")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ProbeError("evidence source binding is missing")
    for source in sources:
        if not isinstance(source, dict):
            raise ProbeError("evidence source record is invalid")
        relative = source.get("path")
        expected = source.get("sha256")
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ProbeError("evidence source path is invalid")
        source_path = (openclaw_root / relative).resolve()
        if openclaw_root.resolve() not in source_path.parents or not source_path.is_file():
            raise ProbeError("evidence source path escapes or is missing")
        if not isinstance(expected, str) or _sha256_bytes(source_path.read_bytes()) != expected:
            raise ProbeError("evidence source hash does not match candidate")
    _walk_evidence(payload)


def run_probe(openclaw_root: Path, evidence_file: Path, timeout: int) -> dict[str, Any]:
    head = validate_candidate_root(openclaw_root)
    runner_blob = _git(ROOT, "hash-object", str(Path(__file__).resolve()))
    committed_runner_blob = _git(
        ROOT, "rev-parse", f"HEAD:{Path(__file__).resolve().relative_to(ROOT).as_posix()}"
    )
    if runner_blob != committed_runner_blob:
        raise ProbeError("probe runner is not the exact committed Agentic OS HEAD blob")
    evidence_file = evidence_file.resolve()
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "AGENTIC_OS_EXPECTED_OPENCLAW_HEAD": head,
            "AGENTIC_OS_REAL_GATEWAY_EVIDENCE_FILE": str(evidence_file),
        }
    )
    command = [
        "node",
        "scripts/run-vitest.mjs",
        "run",
        "--config",
        "test/vitest/vitest.e2e.config.ts",
        E2E_TEST,
    ]
    proc = _run(command, cwd=openclaw_root, env=env, timeout=timeout)
    if proc.returncode != 0:
        raise ProbeError(
            "real Gateway E2E failed "
            f"returncode={proc.returncode} stdout_sha256={_sha256_bytes(proc.stdout.encode())} "
            f"stderr_sha256={_sha256_bytes(proc.stderr.encode())}"
        )
    if validate_candidate_root(openclaw_root) != head:
        raise ProbeError("OpenClaw candidate changed while the real Gateway E2E was running")
    try:
        payload = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError("real Gateway E2E did not write valid evidence") from exc
    if not isinstance(payload, dict):
        raise ProbeError("real Gateway evidence must be a JSON object")
    validate_evidence(payload, openclaw_root=openclaw_root, head=head)
    agentic_os_head = _git(ROOT, "rev-parse", "HEAD")
    payload["agentic_os_head_sha"] = agentic_os_head
    payload["probe_runner_sha256"] = _sha256_bytes(Path(__file__).read_bytes())
    payload["e2e_command_sha256"] = _sha256_bytes("\0".join(command).encode())
    _walk_evidence(payload)
    evidence_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openclaw-root", required=True, type=Path)
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=240)
    args = parser.parse_args(argv)
    try:
        payload = run_probe(args.openclaw_root, args.evidence_file, args.timeout_seconds)
    except (ProbeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "fail_closed", "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "pass",
                "openclaw_head_sha": payload["openclaw_head_sha"],
                "agentic_os_head_sha": payload["agentic_os_head_sha"],
                "child_completed": payload["child_completed"],
                "evidence_sha256": _sha256_bytes(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
