#!/usr/bin/env python3
"""Run the Agentic OS contract against an isolated, real OpenClaw Gateway."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
E2E_TEST = "test/agentic-os-runtime-contract.e2e.test.ts"
AGENTIC_SOURCE_PATHS = (
    "scripts/openclaw-real-gateway-contract-probe.py",
    "scripts/openclaw-live-accepted-session-probe.py",
    "src/agentic_os/openclaw_adapter.py",
    "src/agentic_os/runtime_attestation.py",
    "src/agentic_os/metadata.py",
)
FORBIDDEN_EVIDENCE_KEYS = {
    "authToken",
    "childResult",
    "childResultRaw",
    "childRunId",
    "child_result",
    "child_result_raw",
    "child_session_key",
    "child_run_id",
    "childSessionKey",
    "gatewayLeaseId",
    "gateway_lease_id",
    "sessionKey",
    "session_key",
    "taskMarker",
    "task_marker",
    "token",
    "rawChildResult",
    "raw_child_result",
}
FORBIDDEN_EVIDENCE_FRAGMENTS = (
    "gateway-lease:",
    "agent:",
    "test-token-placeholder",
)
REQUIRED_RUNTIME_PROOFS = (
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
    "lifecycle_running_observed",
    "lifecycle_completed_observed",
    "lifecycle_failure_observed",
    "duplicate_lease_identity_parity",
    "duplicate_spawn_identity_parity",
    "duplicate_release_identity_parity",
    "child_completed",
)
DISABLED_FUTURE_RUNTIME_PROOFS = (
    "agentic_adapter_live_catalog",
    "agentic_adapter_release_succeeded",
    "agentic_adapter_duplicate_release_parity",
    "agentic_adapter_release_metadata_parity",
    "agentic_adapter_post_release_absent",
)
REQUIRED_CHILD_HASH_PROOFS = (
    "child_result_sha256",
    "child_run_id_sha256",
    "child_session_key_sha256",
    "task_marker_sha256",
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
        windows_path = PureWindowsPath(value)
        if Path(value).is_absolute() or windows_path.is_absolute() or windows_path.drive or any(
            fragment in value for fragment in FORBIDDEN_EVIDENCE_FRAGMENTS
        ):
            raise ProbeError(f"evidence contains forbidden raw value at {'.'.join(path)}")


def _source_binding(root: Path, relative: str) -> dict[str, str]:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ProbeError("source binding path is invalid")
    source_path = (root / relative_path).resolve()
    if root.resolve() not in source_path.parents or not source_path.is_file():
        raise ProbeError("source binding path escapes or is missing")
    working_blob = _git(root, "hash-object", str(source_path))
    committed_blob = _git(root, "rev-parse", f"HEAD:{relative_path.as_posix()}")
    if working_blob != committed_blob:
        raise ProbeError(f"{relative} is not the exact committed Agentic OS HEAD blob")
    return {
        "path": relative_path.as_posix(),
        "sha256": _sha256_bytes(source_path.read_bytes()),
    }


def _validate_sources(value: Any, *, root: Path, label: str) -> None:
    if not isinstance(value, list) or not value:
        raise ProbeError(f"evidence {label} binding is missing")
    for source in value:
        if not isinstance(source, dict):
            raise ProbeError(f"evidence {label} record is invalid")
        relative = source.get("path")
        expected = source.get("sha256")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise ProbeError(f"evidence {label} path is invalid")
        source_path = (root / relative).resolve()
        if root.resolve() not in source_path.parents or not source_path.is_file():
            raise ProbeError(f"evidence {label} path escapes or is missing")
        if (
            not isinstance(expected, str)
            or _sha256_bytes(source_path.read_bytes()) != expected
        ):
            raise ProbeError(f"evidence {label} hash does not match candidate")


def _validate_sha256_field(payload: Mapping[str, Any], key: str) -> None:
    value = payload.get(key)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProbeError(f"evidence {key} must be a lowercase SHA-256 hex digest")


def _validate_disabled_future_proofs(payload: Mapping[str, Any]) -> None:
    advertised = [
        key
        for key in DISABLED_FUTURE_RUNTIME_PROOFS
        if key in payload and payload.get(key) is not False
    ]
    if advertised:
        raise ProbeError(
            "disabled future runtime proofs are not authoritative evidence: "
            + ", ".join(sorted(advertised))
        )


def validate_evidence(
    payload: dict[str, Any], *, openclaw_root: Path, agentic_root: Path, head: str
) -> None:
    if payload.get("status") != "pass" or payload.get("openclaw_head_sha") != head:
        raise ProbeError("evidence status or OpenClaw head binding is invalid")
    agentic_head = _git(agentic_root, "rev-parse", "HEAD")
    if payload.get("agentic_os_head_sha") != agentic_head:
        raise ProbeError("evidence Agentic OS head binding is invalid")
    _validate_disabled_future_proofs(payload)
    if not all(payload.get(key) is True for key in REQUIRED_RUNTIME_PROOFS):
        raise ProbeError("evidence is missing a required runtime proof")
    if payload.get("static_allow_agents_wildcard") is not False:
        raise ProbeError("evidence does not prove a non-wildcard static allowlist")
    if payload.get("model_request_count") != 2:
        raise ProbeError("evidence does not prove the successful and failed real child requests")
    if payload.get("committed_snapshot_authority") != "non_authoritative_last_run_snapshot":
        raise ProbeError("evidence does not declare the committed snapshot non-authoritative")
    if payload.get("current_head_evidence_required") is not True:
        raise ProbeError("evidence does not require current-head validation")
    if payload.get("child_completed") is True:
        for key in REQUIRED_CHILD_HASH_PROOFS:
            _validate_sha256_field(payload, key)
    _validate_sources(payload.get("sources"), root=openclaw_root, label="source")
    _validate_sources(
        payload.get("agentic_sources"), root=agentic_root, label="Agentic source"
    )
    _walk_evidence(payload)


def run_probe(openclaw_root: Path, evidence_file: Path, timeout: int) -> dict[str, Any]:
    head = validate_candidate_root(openclaw_root)
    agentic_sources = [
        _source_binding(ROOT, relative) for relative in AGENTIC_SOURCE_PATHS
    ]
    evidence_file = evidence_file.resolve()
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_evidence_file = evidence_file.with_name(
        f".{evidence_file.name}.{os.getpid()}.tmp"
    )
    env = dict(os.environ)
    env.update(
        {
            "AGENTIC_OS_EXPECTED_OPENCLAW_HEAD": head,
            "AGENTIC_OS_REAL_GATEWAY_EVIDENCE_FILE": str(temporary_evidence_file),
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
    try:
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
            payload = json.loads(temporary_evidence_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProbeError("real Gateway E2E did not write valid evidence") from exc
        if not isinstance(payload, dict):
            raise ProbeError("real Gateway evidence must be a JSON object")
        agentic_os_head = _git(ROOT, "rev-parse", "HEAD")
        payload["agentic_os_head_sha"] = agentic_os_head
        payload["committed_snapshot_authority"] = "non_authoritative_last_run_snapshot"
        payload["current_head_evidence_required"] = True
        payload["agentic_sources"] = agentic_sources
        payload["probe_runner_sha256"] = _sha256_bytes(Path(__file__).read_bytes())
        payload["e2e_command_sha256"] = _sha256_bytes("\0".join(command).encode())
        validate_evidence(
            payload, openclaw_root=openclaw_root, agentic_root=ROOT, head=head
        )
        temporary_evidence_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary_evidence_file.replace(evidence_file)
        return payload
    finally:
        if temporary_evidence_file.exists():
            temporary_evidence_file.unlink()


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
