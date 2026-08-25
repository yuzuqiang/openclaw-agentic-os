#!/usr/bin/env python3
"""Run the Agentic OS contract against an isolated, real OpenClaw Gateway."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
E2E_TEST = "test/agentic-os-runtime-contract.e2e.test.ts"
PERSISTENT_LIFECYCLE_RUNNER = "scripts/agentic-os-persistent-lifecycle-runner.mts"
PERSISTENT_LIFECYCLE_DEFAULT_PORT = 20189
PERSISTENT_ATTESTATION_SCHEMA_VERSION = "agentic-os.persistent-attested-preflight-evidence.v1"
AGENTIC_SOURCE_PATHS = (
    "scripts/openclaw-real-gateway-contract-probe.py",
    "scripts/openclaw-live-accepted-session-probe.py",
    "src/agentic_os/openclaw_adapter.py",
    "src/agentic_os/runtime_attestation.py",
    "src/agentic_os/metadata.py",
)
PERSISTENT_RUNTIME_SOURCE_PATHS = (
    "package.json",
    "openclaw.mjs",
    PERSISTENT_LIFECYCLE_RUNNER,
    "src/gateway/agentic-os-runtime-attestation.ts",
    "src/gateway/agentic-os-runtime-contract-descriptors.ts",
    "src/gateway/client.ts",
    "src/utils/message-channel.ts",
)
PERSISTENT_REQUIRED_TOOL_NAMES = (
    "agenticOs.runtime.attest",
    "subagents.allowLease.acquire",
    "subagents.allowLease.status",
    "subagents.allowLease.release",
    "sessions_spawn",
    "sessions_list",
    "session_status",
    "sessions_history",
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
    start_new_session: bool = False,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=start_new_session,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if start_new_session:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        stdout, stderr = proc.communicate()
        exc.stdout = stdout
        exc.stderr = stderr
        raise
    completed = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
    completed.pid = proc.pid  # type: ignore[attr-defined]
    return completed


def _git(root: Path, *args: str) -> str:
    proc = _run(["git", *args], cwd=root, timeout=30)
    if proc.returncode != 0:
        raise ProbeError(f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def validate_candidate_root(root: Path) -> str:
    root = root.resolve()
    package_path = root / "package.json"
    if not package_path.is_file():
        raise ProbeError("OpenClaw candidate is missing package.json")
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


def _candidate_probe_mode(root: Path) -> str:
    root = root.resolve()
    if (root / E2E_TEST).is_file():
        return "legacy_e2e"
    if (root / PERSISTENT_LIFECYCLE_RUNNER).is_file():
        return "persistent_lifecycle_runner"
    raise ProbeError(
        "OpenClaw candidate has neither the legacy real Gateway E2E nor the "
        "persistent lifecycle runner"
    )


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


def _source_bindings(root: Path, relatives: tuple[str, ...]) -> list[dict[str, str]]:
    return [_source_binding(root, relative) for relative in relatives]


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _text_sha256(value: str) -> str:
    return _sha256_bytes(value.encode())


def _read_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{label} did not contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return payload


def _record(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return value


def _require_pass(value: Mapping[str, Any], label: str) -> None:
    if value.get("status") != "pass":
        raise ProbeError(f"{label} did not pass")


def _optional_record(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha_field(section: Mapping[str, Any], key: str) -> str | None:
    value = section.get(key)
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return None


def _require_sha256_field(section: Mapping[str, Any], key: str, label: str) -> str:
    value = _sha_field(section, key)
    if value is None:
        raise ProbeError(f"{label}.{key} must be a lowercase SHA-256 hex digest")
    return value


def _require_non_empty_string(section: Mapping[str, Any], key: str, label: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value:
        raise ProbeError(f"{label}.{key} must be a non-empty string")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ProbeError(f"{label} must be a non-empty list")
    if not all(isinstance(item, str) and item for item in value):
        raise ProbeError(f"{label} must contain only non-empty strings")
    return value


def _validate_gateway_endpoint(endpoint: Any, *, port: int) -> None:
    if not isinstance(endpoint, str) or not endpoint:
        raise ProbeError("persistent lifecycle attestation gateway endpoint is missing")
    parsed = urlparse(endpoint)
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or parsed.port != port:
        raise ProbeError("persistent lifecycle attestation gateway endpoint is not the requested loopback listener")


def _loopback_port_closed(port: int) -> bool:
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return False
        except OSError:
            continue
    return True


def _wait_for_loopback_port_closed(port: int, *, timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _loopback_port_closed(port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _terminate_process_group(proc: subprocess.CompletedProcess[str]) -> bool:
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        return False
    return True


def _run_artifact_path(run_root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ProbeError(f"{label} path is missing")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = run_root / candidate
    resolved_root = run_root.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ProbeError(f"{label} path is outside the isolated run root") from exc
    if not resolved.is_file():
        raise ProbeError(f"{label} file is missing")
    return resolved


def _runtime_source_digest(runtime_sources: list[dict[str, str]], path: str) -> str:
    matches = [source.get("sha256") for source in runtime_sources if source.get("path") == path]
    if len(matches) != 1 or _sha_field({"sha256": matches[0]}, "sha256") is None:
        raise ProbeError(f"runtime source binding for {path} is missing or invalid")
    return str(matches[0])


def _validate_persistent_attestation_evidence(
    *,
    run_root: Path,
    preflight: Mapping[str, Any],
    attestation: Mapping[str, Any],
    immutable_inputs: Mapping[str, Any],
    runtime_sources: list[dict[str, str]],
    runtime_head: str,
    agentic_head: str,
    port: int,
) -> None:
    evidence_path = _run_artifact_path(
        run_root,
        preflight.get("persistent_evidence_file"),
        "persistent attestation evidence",
    )
    evidence_sha256 = _require_sha256_field(
        preflight, "persistent_evidence_sha256", "preflight"
    )
    if _sha256_bytes(evidence_path.read_bytes()) != evidence_sha256:
        raise ProbeError("persistent attestation evidence digest mismatch")
    evidence = _read_json_file(evidence_path, "persistent attestation evidence")
    if evidence.get("schema_version") != PERSISTENT_ATTESTATION_SCHEMA_VERSION:
        raise ProbeError("persistent attestation evidence schema mismatch")
    if evidence.get("expected_runtime_head") != runtime_head:
        raise ProbeError("persistent attestation runtime head binding mismatch")
    if evidence.get("expected_agentic_os_head") != agentic_head:
        raise ProbeError("persistent attestation Agentic OS head binding mismatch")

    runtime = _record(evidence.get("runtime"), "persistent attestation runtime")
    raw_attestation = _record(
        evidence.get("attestation"), "persistent attestation evidence attestation"
    )
    response = _record(raw_attestation.get("response"), "persistent attestation response")
    signed_payload = _record(
        response.get("signed_payload"), "persistent attestation signed payload"
    )
    rpc_evidence = _record(
        evidence.get("rpc_evidence"), "persistent attestation RPC evidence"
    )
    binding = _record(signed_payload.get("binding"), "persistent attestation binding")
    executable = _record(binding.get("executable"), "persistent attestation executable")
    catalog = _record(binding.get("catalog"), "persistent attestation catalog")
    gateway = _record(binding.get("gateway"), "persistent attestation gateway")

    executable_digest = _require_sha256_field(
        attestation, "executable_content_sha256", "attestation"
    )
    if executable_digest != _runtime_source_digest(runtime_sources, "openclaw.mjs"):
        raise ProbeError("persistent attestation executable digest is not source-bound")
    if runtime.get("executable_sha256") != executable_digest:
        raise ProbeError("persistent attestation executable digest is not runtime-bound")
    if executable.get("content_sha256") != executable_digest:
        raise ProbeError("persistent attestation executable digest is not signed-payload bound")
    request_params = _record(
        raw_attestation.get("request_params"), "persistent attestation request params"
    )
    if request_params.get("expected_executable_sha256") != executable_digest:
        raise ProbeError("persistent attestation executable digest is not request-bound")

    catalog_digest = _require_sha256_field(attestation, "catalog_sha256", "attestation")
    if runtime.get("expected_catalog_sha256") != catalog_digest:
        raise ProbeError("persistent attestation catalog digest is not runtime-bound")
    if request_params.get("expected_catalog_sha256") != catalog_digest:
        raise ProbeError("persistent attestation catalog digest is not request-bound")
    if catalog.get("sha256") != catalog_digest:
        raise ProbeError("persistent attestation catalog digest is not signed-payload bound")

    contract_vector_digest = _require_sha256_field(
        attestation, "contract_vector_sha256", "attestation"
    )
    if immutable_inputs.get("contract_vector_sha256") != contract_vector_digest:
        raise ProbeError("persistent attestation contract vector is not immutable-input bound")
    if catalog.get("contract_vector_sha256") != contract_vector_digest:
        raise ProbeError("persistent attestation contract vector is not signed-payload bound")

    endpoint = attestation.get("gateway_endpoint")
    _validate_gateway_endpoint(endpoint, port=port)
    if gateway.get("endpoint") != endpoint:
        raise ProbeError("persistent attestation Gateway endpoint is not signed-payload bound")
    build_id = _require_non_empty_string(attestation, "gateway_build_id", "attestation")
    if gateway.get("build_id") != build_id:
        raise ProbeError("persistent attestation Gateway build is not signed-payload bound")

    signed_payload_digest = _require_sha256_field(
        attestation, "signed_payload_sha256", "attestation"
    )
    if _canonical_sha256(signed_payload) != signed_payload_digest:
        raise ProbeError("persistent attestation signed payload digest mismatch")
    rpc_evidence_digest = _require_sha256_field(
        attestation, "runtime_authored_rpc_evidence_sha256", "attestation"
    )
    if _canonical_sha256(rpc_evidence) != rpc_evidence_digest:
        raise ProbeError("persistent attestation RPC evidence digest mismatch")
    transcript_records: list[dict[str, Any]] = []
    for key, method in (
        ("tools_catalog", "tools.catalog"),
        ("allow_lease_status", "subagents.allowLease.status"),
    ):
        record = _record(rpc_evidence.get(key), f"persistent attestation RPC evidence {key}")
        if record.get("method") != method:
            raise ProbeError(f"persistent attestation RPC evidence {key} method mismatch")
        request = _record(record.get("request_params"), f"persistent attestation {key} request")
        if request:
            raise ProbeError(f"persistent attestation RPC evidence {key} request is not empty")
        response_record = _record(
            record.get("response"), f"persistent attestation {key} response"
        )
        raw_response_digest = _require_sha256_field(
            record, "raw_response_sha256", f"persistent attestation RPC evidence {key}"
        )
        if _canonical_sha256(response_record) != raw_response_digest:
            raise ProbeError(f"persistent attestation RPC evidence {key} response mismatch")
        transcript_records.append(
            {
                "key": key,
                "method": method,
                "request_params": {},
                "raw_response_sha256": raw_response_digest,
            }
        )
    transcript_digest = _require_sha256_field(
        attestation, "rpc_transcript_sha256", "attestation"
    )
    expected_transcript_digest = _canonical_sha256(
        {
            "schema_version": "agentic-os.persistent-rpc-transcript.v1",
            "records": transcript_records,
        }
    )
    if transcript_digest != expected_transcript_digest:
        raise ProbeError("persistent attestation transcript digest mismatch")
    if signed_payload.get("rpc_transcript_sha256") != transcript_digest:
        raise ProbeError("persistent attestation transcript digest is not signed-payload bound")
    identity_digest = _require_sha256_field(
        attestation, "runtime_identity_token_sha256", "attestation"
    )
    if raw_attestation.get("runtime_identity_token_sha256") != identity_digest:
        raise ProbeError("persistent attestation runtime identity is not evidence-bound")
    if signed_payload.get("runtime_identity_token_sha256") != identity_digest:
        raise ProbeError("persistent attestation runtime identity is not signed-payload bound")


def _safe_status(value: Any) -> str:
    return value if isinstance(value, str) and value else "unknown"


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


def _run_legacy_e2e_probe(
    openclaw_root: Path,
    evidence_file: Path,
    timeout: int,
    *,
    head: str,
    agentic_sources: list[dict[str, str]],
) -> dict[str, Any]:
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


def _persistent_lifecycle_summary(
    *,
    openclaw_root: Path,
    run_root: Path,
    receipt_file: Path,
    validation_file: Path,
    head: str,
    agentic_sources: list[dict[str, str]],
    runtime_sources: list[dict[str, str]],
    command: list[str],
    proc: subprocess.CompletedProcess[str],
    port: int,
) -> dict[str, Any]:
    receipt = _read_json_file(receipt_file, "persistent lifecycle receipt")
    validation = _read_json_file(validation_file, "persistent lifecycle validation")
    _require_pass(receipt, "persistent lifecycle receipt")
    _require_pass(validation, "persistent lifecycle validation")
    receipt_sha256 = _sha256_bytes(receipt_file.read_bytes())
    if validation.get("receipt_sha256") != receipt_sha256:
        raise ProbeError("persistent lifecycle validation is not bound to the promoted receipt")

    agentic_head = _git(ROOT, "rev-parse", "HEAD")
    immutable_inputs = _record(receipt.get("immutable_inputs"), "receipt immutable_inputs")
    if immutable_inputs.get("runtime_head") != head:
        raise ProbeError("persistent lifecycle receipt runtime head binding is invalid")
    if immutable_inputs.get("agentic_os_head") != agentic_head:
        raise ProbeError("persistent lifecycle receipt Agentic OS head binding is invalid")

    production_before = _record(receipt.get("production_before"), "production_before")
    production_after = _record(receipt.get("production_after"), "production_after")
    candidate = _record(receipt.get("candidate"), "candidate")
    preflight = _record(receipt.get("preflight"), "preflight")
    attestation = _record(receipt.get("attestation"), "attestation")
    lifecycle = _record(receipt.get("lifecycle"), "lifecycle")
    rollback = _record(receipt.get("rollback"), "rollback")
    db_authority = _record(rollback.get("db_authority"), "rollback.db_authority")

    for label, section in (
        ("preflight", preflight),
        ("attestation", attestation),
        ("lifecycle", lifecycle),
        ("rollback", rollback),
    ):
        _require_pass(section, label)
    if rollback.get("candidate_port_closed") is not True:
        raise ProbeError("persistent lifecycle did not prove candidate port closure")
    if rollback.get("production_config_hash_unchanged") is not True:
        raise ProbeError("persistent lifecycle did not prove production config immutability")
    production_before_config_sha256 = _require_sha256_field(
        production_before, "config_sha256", "production_before"
    )
    production_after_config_sha256 = _require_sha256_field(
        production_after, "config_sha256", "production_after"
    )
    if production_before_config_sha256 != production_after_config_sha256:
        raise ProbeError("persistent lifecycle production config hashes changed")
    if db_authority.get("DB_AUTHORITY_ENABLED") is not False:
        raise ProbeError("persistent lifecycle did not prove DB authority remained disabled")
    if candidate.get("port") != port:
        raise ProbeError("persistent lifecycle candidate port binding is invalid")
    if preflight.get("runtime_ready") is not True:
        raise ProbeError("persistent lifecycle preflight did not pass runtime readiness")
    if lifecycle.get("first_spawn_status") != "accepted":
        raise ProbeError("persistent lifecycle did not prove accepted session spawn")
    if lifecycle.get("duplicate_spawn_same_session") is not True:
        raise ProbeError("persistent lifecycle did not prove duplicate spawn identity parity")
    if lifecycle.get("duplicate_acquire_same_lease") is not True:
        raise ProbeError("persistent lifecycle did not prove duplicate acquire lease identity parity")
    if lifecycle.get("post_release_lease_count") != 0:
        raise ProbeError("persistent lifecycle did not prove release cleanup")
    _require_sha256_field(lifecycle, "gateway_lease_id_sha256", "lifecycle")
    _require_sha256_field(lifecycle, "session_key_sha256", "lifecycle")
    _require_sha256_field(lifecycle, "child_run_id_sha256", "lifecycle")
    if lifecycle.get("matching_session_count") != 1:
        raise ProbeError("persistent lifecycle did not prove matching accepted session identity")

    required_tool_names = preflight.get("required_tool_names")
    hello = _optional_record(preflight.get("hello"))
    if "required_tool_names" in preflight:
        required_tool_names = _string_list(
            required_tool_names, "preflight.required_tool_names"
        )
    elif "required_methods" in hello:
        required_tool_names = _string_list(
            hello.get("required_methods"), "preflight.hello.required_methods"
        )
    else:
        raise ProbeError("persistent lifecycle preflight is missing required tool names")
    missing = sorted(set(PERSISTENT_REQUIRED_TOOL_NAMES) - set(required_tool_names))
    if missing:
        raise ProbeError("persistent lifecycle preflight is missing required tool names")

    runtime_launch = _optional_record(receipt.get("runtime_launch"))
    paths = _optional_record(receipt.get("paths"))
    logs = _optional_record(candidate.get("logs"))
    candidate_env = _optional_record(candidate.get("env"))
    if candidate_env.get("unexpected_provider_key_count") != 0:
        raise ProbeError("persistent lifecycle candidate environment includes provider secrets")
    _validate_gateway_endpoint(attestation.get("gateway_endpoint"), port=port)
    _require_non_empty_string(attestation, "gateway_build_id", "attestation")
    for key in (
        "executable_content_sha256",
        "catalog_sha256",
        "contract_vector_sha256",
        "rpc_transcript_sha256",
        "runtime_authored_rpc_evidence_sha256",
        "signed_payload_sha256",
        "runtime_identity_token_sha256",
    ):
        _require_sha256_field(attestation, key, "attestation")
    _validate_persistent_attestation_evidence(
        run_root=run_root,
        preflight=preflight,
        attestation=attestation,
        immutable_inputs=immutable_inputs,
        runtime_sources=runtime_sources,
        runtime_head=head,
        agentic_head=agentic_head,
        port=port,
    )
    soak = _optional_record(receipt.get("soak"))
    historical_probe_audit = _optional_record(receipt.get("historical_probe_audit"))

    payload: dict[str, Any] = {
        "status": "pass",
        "probe": "agentic-os-persistent-lifecycle-runner",
        "openclaw_head_sha": head,
        "agentic_os_head_sha": agentic_head,
        "runtime_ready": False,
        "runtime_ready_candidate_evidence": True,
        "runtime_ready_blocked_until_phase_c": True,
        "committed_snapshot_authority": "non_authoritative_phase_b_candidate_snapshot",
        "current_head_evidence_required": True,
        "phase_c_exact_head_required_before_review": True,
        "isolated_non_production_gateway": {
            "status": "pass",
            "loopback": True,
            "token_authenticated": True,
            "production_config_hash_unchanged": True,
            "candidate_port_closed": True,
            "db_authority_enabled": False,
            "provider_secret_env_count": candidate_env.get("unexpected_provider_key_count"),
            "port": port,
            "port_policy": (
                "downstream runner validated its fixed non-production loopback port"
                if port == PERSISTENT_LIFECYCLE_DEFAULT_PORT
                else "caller supplied non-production loopback port"
            ),
        },
        "required_tool_names": sorted(str(name) for name in required_tool_names),
        "authenticated_gateway": True,
        "effective_allow_lease": True,
        "runtime_catalog_discovered": True,
        "persistent_attestation_validated": True,
        "accepted_session_spawned": True,
        "duplicate_spawn_identity_parity": True,
        "duplicate_acquire_identity_parity": lifecycle.get("duplicate_acquire_same_lease")
        is True,
        "duplicate_release_observed": _sha_field(lifecycle, "duplicate_release_sha256")
        is not None,
        "session_list_status_history_observed": (
            _sha_field(lifecycle, "session_status_sha256") is not None
            and _sha_field(lifecycle, "sessions_history_sha256") is not None
        ),
        "lease_release_cleanup_observed": lifecycle.get("post_release_lease_count") == 0,
        "db_authority_enabled": False,
        "production_behavior_proven": False,
        "production_authority_enabled": False,
        "attestation": {
            "status": "pass",
            "gateway_endpoint": attestation.get("gateway_endpoint"),
            "gateway_build_id": attestation.get("gateway_build_id"),
            "executable_content_sha256": attestation.get("executable_content_sha256"),
            "catalog_sha256": attestation.get("catalog_sha256"),
            "contract_vector_sha256": attestation.get("contract_vector_sha256"),
            "rpc_transcript_sha256": attestation.get("rpc_transcript_sha256"),
            "runtime_authored_rpc_evidence_sha256": attestation.get(
                "runtime_authored_rpc_evidence_sha256"
            ),
            "signed_payload_sha256": attestation.get("signed_payload_sha256"),
            "runtime_identity_token_sha256": attestation.get(
                "runtime_identity_token_sha256"
            ),
        },
        "capability_preflight": {
            "status": "pass",
            "runtime_ready": True,
            "evidence_sha256": preflight.get("evidence_sha256"),
            "persistent_evidence_sha256": preflight.get("persistent_evidence_sha256"),
            "stdout_sha256": preflight.get("stdout_sha256"),
            "stderr_sha256": preflight.get("stderr_sha256"),
            "hello_required_methods": hello.get("required_methods"),
        },
        "lifecycle": {
            "status": "pass",
            "gateway_lease_id_sha256": lifecycle.get("gateway_lease_id_sha256"),
            "session_key_sha256": lifecycle.get("session_key_sha256"),
            "child_run_id_sha256": lifecycle.get("child_run_id_sha256"),
            "session_status_sha256": lifecycle.get("session_status_sha256"),
            "sessions_history_sha256": lifecycle.get("sessions_history_sha256"),
            "duplicate_release_sha256": lifecycle.get("duplicate_release_sha256"),
            "first_spawn_status": lifecycle.get("first_spawn_status"),
            "sessions_list_count": lifecycle.get("sessions_list_count"),
            "matching_session_count": lifecycle.get("matching_session_count"),
            "post_release_lease_count": lifecycle.get("post_release_lease_count"),
        },
        "rollback": {
            "status": "pass",
            "candidate_port_closed": rollback.get("candidate_port_closed"),
            "production_config_hash_unchanged": rollback.get(
                "production_config_hash_unchanged"
            ),
            "production_health_before_sha256": rollback.get(
                "production_health_before_sha256"
            ),
            "production_health_after_sha256": rollback.get("production_health_after_sha256"),
            "db_authority_enabled": db_authority.get("DB_AUTHORITY_ENABLED"),
            "candidate_shutdown_sha256": _canonical_sha256(
                _optional_record(rollback.get("candidate_shutdown"))
            ),
        },
        "production_snapshot": {
            "before_config_sha256": production_before_config_sha256,
            "after_config_sha256": production_after_config_sha256,
            "before_health_sha256": _canonical_sha256(production_before.get("health")),
            "after_health_sha256": _canonical_sha256(production_after.get("health")),
        },
        "runner": {
            "script": PERSISTENT_LIFECYCLE_RUNNER,
            "command_sha256": _text_sha256("\0".join(command)),
            "stdout_sha256": _sha256_bytes(proc.stdout.encode()),
            "stderr_sha256": _sha256_bytes(proc.stderr.encode()),
            "run_root_sha256": _text_sha256(str(run_root.resolve())),
            "receipt_sha256": receipt_sha256,
            "validation_sha256": _sha256_bytes(validation_file.read_bytes()),
            "validation_receipt_sha256": validation.get("receipt_sha256"),
            "runtime_launch_sha256": _canonical_sha256(runtime_launch),
            "path_receipts_sha256": {
                key: _optional_record(value).get("realpath_sha256")
                for key, value in sorted(paths.items())
            },
            "candidate_stdout_log_sha256": logs.get("stdout_sha256"),
            "candidate_stderr_log_sha256": logs.get("stderr_sha256"),
        },
        "soak": {
            "status": soak.get("status"),
            "started": soak.get("started"),
        },
        "historical_probe_audit": {
            "verdict": historical_probe_audit.get("verdict"),
            "sha256": historical_probe_audit.get("sha256"),
        },
        "agentic_sources": agentic_sources,
        "runtime_sources": runtime_sources,
    }
    _walk_evidence(payload)
    return payload


def _persistent_failure_summary(
    *,
    openclaw_root: Path,
    run_root: Path,
    head: str,
    agentic_sources: list[dict[str, str]],
    runtime_sources: list[dict[str, str]],
    command: list[str],
    proc: subprocess.CompletedProcess[str],
    port: int,
) -> dict[str, Any]:
    agentic_head = _git(ROOT, "rev-parse", "HEAD")
    receipts_dir = run_root / "receipts"
    failure_receipt = (
        _read_json_file(receipts_dir / "failure-receipt.json", "persistent failure receipt")
        if (receipts_dir / "failure-receipt.json").is_file()
        else {}
    )
    failure_cleanup = (
        _read_json_file(receipts_dir / "failure-cleanup.json", "persistent failure cleanup")
        if (receipts_dir / "failure-cleanup.json").is_file()
        else {}
    )
    error_record = _optional_record(failure_receipt.get("error"))
    cleanup_error = _optional_record(failure_cleanup.get("error"))
    candidate_shutdown = _optional_record(failure_cleanup.get("candidate_shutdown"))
    db_authority = _optional_record(failure_cleanup.get("db_authority"))
    production_before = _optional_record(failure_cleanup.get("production_before"))
    production_after = _optional_record(failure_cleanup.get("production_after"))
    payload: dict[str, Any] = {
        "status": "fail_closed",
        "classification": "persistent_lifecycle_runner_failed",
        "probe": "agentic-os-persistent-lifecycle-runner",
        "openclaw_head_sha": head,
        "agentic_os_head_sha": agentic_head,
        "runtime_ready": False,
        "runtime_ready_candidate_evidence": False,
        "production_behavior_proven": False,
        "production_authority_enabled": False,
        "isolated_non_production_gateway": {
            "status": "fail_closed",
            "loopback": True,
            "token_authenticated": True,
            "port": port,
            "candidate_port_closed": candidate_shutdown.get("port_closed"),
            "production_config_hash_unchanged": (
                production_before.get("config_sha256")
                == production_after.get("config_sha256")
                if production_before or production_after
                else None
            ),
            "db_authority_enabled": db_authority.get("DB_AUTHORITY_ENABLED"),
        },
        "fail_closed_matrix": [
            {
                "check": "candidate_exact_clean_head",
                "status": "pass",
                "evidence": head,
            },
            {
                "check": "persistent_runner_present",
                "status": "pass",
                "evidence_sha256": _sha256_bytes(
                    (openclaw_root / PERSISTENT_LIFECYCLE_RUNNER).read_bytes()
                ),
            },
            {
                "check": "runner_exit_code",
                "status": "fail",
                "exit_code": proc.returncode,
            },
            {
                "check": "runner_classification",
                "status": _safe_status(failure_receipt.get("status")),
                "classification": _safe_status(failure_receipt.get("classification")),
                "error_code": _safe_status(error_record.get("code")),
                "error_message_sha256": _text_sha256(str(error_record.get("message", ""))),
            },
            {
                "check": "failure_cleanup",
                "status": _safe_status(failure_cleanup.get("status")),
                "error_code": _safe_status(cleanup_error.get("code")),
                "error_message_sha256": _text_sha256(str(cleanup_error.get("message", ""))),
            },
        ],
        "runner": {
            "script": PERSISTENT_LIFECYCLE_RUNNER,
            "command_sha256": _text_sha256("\0".join(command)),
            "stdout_sha256": _sha256_bytes(proc.stdout.encode()),
            "stderr_sha256": _sha256_bytes(proc.stderr.encode()),
            "run_root_sha256": _text_sha256(str(run_root.resolve())),
        },
        "agentic_sources": agentic_sources,
        "runtime_sources": runtime_sources,
    }
    _walk_evidence(payload)
    return payload


def _write_validated_payload(evidence_file: Path, payload: dict[str, Any]) -> None:
    evidence_file = evidence_file.resolve()
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_evidence_file = evidence_file.with_name(
        f".{evidence_file.name}.{os.getpid()}.tmp"
    )
    try:
        temporary_evidence_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary_evidence_file.replace(evidence_file)
    finally:
        if temporary_evidence_file.exists():
            temporary_evidence_file.unlink()


def _run_persistent_lifecycle_probe(
    openclaw_root: Path,
    evidence_file: Path,
    timeout: int,
    *,
    head: str,
    agentic_sources: list[dict[str, str]],
    runtime_sources: list[dict[str, str]],
    run_root: Path,
    port: int,
    run_id: str,
    transition_id: str,
) -> dict[str, Any]:
    run_root = run_root.resolve()
    evidence_dir = run_root / "evidence"
    runner_home = run_root / "runner-home"
    runner_state = run_root / "runner-state"
    runner_tmp = run_root / "runner-tmp"
    for directory in (runner_home, runner_state, runner_tmp):
        directory.mkdir(parents=True, exist_ok=True)
    runner_env = dict(os.environ)
    runner_env.update(
        {
            "HOME": str(runner_home),
            "TMPDIR": str(runner_tmp),
            "OPENCLAW_HOME": str(runner_home),
            "OPENCLAW_STATE_DIR": str(runner_state),
            "OPENCLAW_SKIP_CHANNELS": "1",
            "OPENCLAW_NO_AUTO_UPDATE": "1",
            "OPENCLAW_DISABLE_AUTO_UPDATE": "1",
        }
    )
    command = [
        "node",
        "--import",
        "tsx",
        PERSISTENT_LIFECYCLE_RUNNER,
        "run",
        "--runtime-worktree",
        str(openclaw_root.resolve()),
        "--agentic-os-worktree",
        str(ROOT.resolve()),
        "--expected-runtime-head",
        head,
        "--expected-agentic-os-head",
        _git(ROOT, "rev-parse", "HEAD"),
        "--run-root",
        str(run_root),
        "--port",
        str(port),
        "--run-id",
        run_id,
        "--transition-id",
        transition_id,
        "--evidence-dir",
        str(evidence_dir),
    ]
    try:
        proc = _run(
            command,
            cwd=openclaw_root,
            env=runner_env,
            timeout=timeout,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        proc = subprocess.CompletedProcess(command, 124, stdout, stderr)
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            command=command,
            proc=proc,
            port=port,
        )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
        payload["fail_closed_matrix"].append(
            {
                "check": "timeout_process_group_cleanup",
                "status": "pass" if port_closed else "fail",
                "candidate_port_closed": port_closed,
            }
        )
        _write_validated_payload(evidence_file, payload)
        if not port_closed:
            raise ProbeError("persistent lifecycle runner timed out and candidate port remained open") from exc
        raise ProbeError(
            "persistent lifecycle runner timed out "
            f"evidence_file_sha256={_sha256_bytes(evidence_file.resolve().read_bytes())}"
        ) from exc
    if proc.returncode != 0:
        process_group_cleanup_attempted = _terminate_process_group(proc)
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            command=command,
            proc=proc,
            port=port,
        )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
        payload["fail_closed_matrix"].append(
            {
                "check": "failure_process_group_cleanup",
                "status": "pass" if port_closed else "fail",
                "process_group_cleanup_attempted": process_group_cleanup_attempted,
                "candidate_port_closed": port_closed,
            }
        )
        _write_validated_payload(evidence_file, payload)
        if not port_closed:
            raise ProbeError(
                "persistent lifecycle runner failed and candidate port remained open"
            )
        raise ProbeError(
            "persistent lifecycle runner failed "
            f"returncode={proc.returncode} evidence_file_sha256="
            f"{_sha256_bytes(evidence_file.resolve().read_bytes())}"
        )
    try:
        if validate_candidate_root(openclaw_root) != head:
            raise ProbeError("OpenClaw candidate changed while the persistent runner was running")
        receipt_file = run_root / "receipts" / "lifecycle-receipt.json"
        validation_file = run_root / "receipts" / "independent-validation.json"
        payload = _persistent_lifecycle_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            receipt_file=receipt_file,
            validation_file=validation_file,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            command=command,
            proc=proc,
            port=port,
        )
        _write_validated_payload(evidence_file, payload)
        return payload
    except Exception as exc:
        process_group_cleanup_attempted = _terminate_process_group(proc)
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            command=command,
            proc=proc,
            port=port,
        )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
        payload["fail_closed_matrix"].append(
            {
                "check": "post_success_validation_process_group_cleanup",
                "status": "pass" if port_closed else "fail",
                "process_group_cleanup_attempted": process_group_cleanup_attempted,
                "candidate_port_closed": port_closed,
                "rejected_after_runner_success": True,
            }
        )
        _write_validated_payload(evidence_file, payload)
        if not port_closed:
            raise ProbeError(
                "persistent lifecycle runner evidence was rejected and candidate port remained open"
            ) from exc
        raise ProbeError(
            "persistent lifecycle runner evidence was rejected after successful runner exit "
            f"evidence_file_sha256={_sha256_bytes(evidence_file.resolve().read_bytes())}"
        ) from exc


def run_probe(
    openclaw_root: Path,
    evidence_file: Path,
    timeout: int,
    *,
    run_root: Path | None = None,
    port: int | None = None,
    run_id: str | None = None,
    transition_id: str | None = None,
) -> dict[str, Any]:
    head = validate_candidate_root(openclaw_root)
    agentic_sources = _source_bindings(ROOT, AGENTIC_SOURCE_PATHS)
    mode = _candidate_probe_mode(openclaw_root)
    if mode == "legacy_e2e":
        return _run_legacy_e2e_probe(
            openclaw_root,
            evidence_file,
            timeout,
            head=head,
            agentic_sources=agentic_sources,
        )
    runtime_sources = _source_bindings(openclaw_root, PERSISTENT_RUNTIME_SOURCE_PATHS)
    default_run_root = (
        Path(tempfile.gettempdir())
        / "openclaw-real-gateway-contract-probe-runs"
        / head[:12]
    )
    return _run_persistent_lifecycle_probe(
        openclaw_root,
        evidence_file,
        timeout,
        head=head,
        agentic_sources=agentic_sources,
        runtime_sources=runtime_sources,
        run_root=run_root or default_run_root,
        port=port or PERSISTENT_LIFECYCLE_DEFAULT_PORT,
        run_id=run_id or "agentic-os-real-gateway-contract-probe",
        transition_id=transition_id or "persistent-lifecycle-runtime-readiness",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openclaw-root", required=True, type=Path)
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--port", type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--transition-id")
    args = parser.parse_args(argv)
    try:
        payload = run_probe(
            args.openclaw_root,
            args.evidence_file,
            args.timeout_seconds,
            run_root=args.run_root,
            port=args.port,
            run_id=args.run_id,
            transition_id=args.transition_id,
        )
    except (ProbeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "fail_closed", "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "pass",
                "openclaw_head_sha": payload["openclaw_head_sha"],
                "agentic_os_head_sha": payload["agentic_os_head_sha"],
                "runtime_ready": payload.get("runtime_ready"),
                "runtime_ready_candidate_evidence": payload.get(
                    "runtime_ready_candidate_evidence", payload.get("child_completed")
                ),
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
