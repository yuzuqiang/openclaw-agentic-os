#!/usr/bin/env python3
"""Run the Agentic OS contract against an isolated, real OpenClaw Gateway."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping
from urllib.parse import unquote, urlparse


ROOT = Path(
    os.environ.get("AGENTIC_OS_PROBE_ROOT", Path(__file__).resolve().parents[1])
).resolve()
E2E_TEST = "test/agentic-os-runtime-contract.e2e.test.ts"
PERSISTENT_LIFECYCLE_RUNNER = "scripts/agentic-os-persistent-lifecycle-runner.mts"
PERSISTENT_LIFECYCLE_DEFAULT_PORT = 20189
PERSISTENT_ATTESTATION_SCHEMA_VERSION = "agentic-os.persistent-attested-preflight-evidence.v1"
AGENTIC_SOURCE_PATHS = (
    "scripts/openclaw-real-gateway-contract-probe.py",
    "scripts/openclaw-live-accepted-session-probe.py",
    "scripts/openclaw-tool-capability-preflight.py",
    "src/agentic_os/__init__.py",
    "src/agentic_os/openclaw_adapter.py",
    "src/agentic_os/runtime_attestation.py",
    "src/agentic_os/metadata.py",
)
PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV = (
    "AGENTIC_OS_PERSISTENT_ATTESTATION_VERIFICATION_HMAC_KEY_HEX"
)
PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV = (
    "AGENTIC_OS_PERSISTENT_VALIDATION_ANCHOR_HMAC_KEY_HEX"
)
PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH = Path("keys/agentic-os-attestation.key")
PERSISTENT_VALIDATION_SCHEMA_VERSION = "agentic-os.persistent-lifecycle-independent-validation.v1"
PERSISTENT_ATTESTATION_VERIFICATION_SCHEMA_VERSION = (
    "agentic-os.persistent-attestation-verification.v1"
)
PERSISTENT_RPC_TRANSCRIPT_SCHEMA_VERSION = "agentic-os.persistent-rpc-transcript.v1"
PERSISTENT_LIFECYCLE_ATTESTATION_SCHEMA_VERSION = (
    "agentic-os.persistent-lifecycle-attestation.v1"
)
PERSISTENT_LIFECYCLE_OBSERVATIONS_SCHEMA_VERSION = (
    "agentic-os.persistent-lifecycle-observations.v1"
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
PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS = (
    "runtime-launcher:node",
    "runtime-preload:tsx",
    "runtime-preload-package:tsx",
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
STDIN_VALIDATOR_BOOTSTRAP = "\n".join(
    (
        "import hashlib, sys",
        "path = sys.argv[1]",
        "expected_digest = sys.argv[2]",
        "source = sys.stdin.buffer.read()",
        "actual_digest = hashlib.sha256(source).hexdigest()",
        "if actual_digest != expected_digest:",
        "    raise SystemExit('validator source digest mismatch')",
        "sys.argv = [path, *sys.argv[3:]]",
        "globals_dict = {",
        "    '__name__': '__main__',",
        "    '__file__': path,",
        "    '__package__': None,",
        "    '__cached__': None,",
        "}",
        "exec(compile(source, path, 'exec'), globals_dict)",
    )
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
RUNNER_ENV_ALLOWLIST = {
    "CI",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TMP",
    "TMPDIR",
    "TEMP",
    "USER",
}
PROVIDER_SECRET_ENV_MARKERS = (
    "ANTHROPIC",
    "API_KEY",
    "AZURE_OPENAI",
    "GEMINI",
    "GOOGLE_API",
    "OPENAI",
    "SECRET",
    "TOKEN",
)


class ProbeError(RuntimeError):
    pass


class CandidatePortOpenError(ProbeError):
    pass


class CandidateProcessGroupOpenError(ProbeError):
    pass


class DuplicateJsonKeyError(ProbeError):
    pass


PINNED_RUN_SUBDIRECTORIES = ("keys", "receipts", "evidence")


class _PinnedDirectory:
    def __init__(self, *, name: str, fd: int, device: int, inode: int) -> None:
        self.name = name
        self.fd = fd
        self.device = device
        self.inode = inode


class _PinnedRunRoot:
    def __init__(
        self,
        *,
        original_path: Path,
        root: _PinnedDirectory,
        keys: _PinnedDirectory,
        receipts: _PinnedDirectory,
        evidence: _PinnedDirectory,
    ) -> None:
        self.original_path = original_path
        self.root = root
        self.keys = keys
        self.receipts = receipts
        self.evidence = evidence
        self.closed = False

    def directory(self, name: str) -> _PinnedDirectory:
        if name not in PINNED_RUN_SUBDIRECTORIES:
            raise ProbeError(f"untrusted persistent lifecycle artifact directory: {name}")
        return getattr(self, name)

    def validator_fds(self) -> tuple[int, ...]:
        return (self.root.fd, self.keys.fd, self.receipts.fd, self.evidence.fd)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for directory in (self.evidence, self.receipts, self.keys, self.root):
            os.close(directory.fd)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_process_stream(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 240,
    start_new_session: bool = False,
    pass_fds: tuple[int, ...] = (),
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=input_bytes is None,
        stdin=subprocess.PIPE if input_bytes is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=start_new_session,
        close_fds=True,
        pass_fds=pass_fds,
    )
    try:
        stdout_raw, stderr_raw = proc.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if start_new_session:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        stdout_raw, stderr_raw = proc.communicate()
        stdout = _decode_process_stream(stdout_raw)
        stderr = _decode_process_stream(stderr_raw)
        exc.pid = proc.pid  # type: ignore[attr-defined]
        exc.stdout = stdout
        exc.stderr = stderr
        raise
    stdout = _decode_process_stream(stdout_raw)
    stderr = _decode_process_stream(stderr_raw)
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
    if (root / PERSISTENT_LIFECYCLE_RUNNER).is_file():
        return "persistent_lifecycle_runner"
    if (root / E2E_TEST).is_file():
        return "legacy_e2e"
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


def _assert_agentic_sources_still_bound(agentic_sources: list[dict[str, str]]) -> None:
    current_sources = _source_bindings(ROOT, AGENTIC_SOURCE_PATHS)
    expected = {
        (source.get("path"), source.get("sha256"))
        for source in agentic_sources
        if isinstance(source, dict)
    }
    current = {
        (source.get("path"), source.get("sha256"))
        for source in current_sources
        if isinstance(source, dict)
    }
    if expected != current:
        raise ProbeError(
            "Agentic OS validator source binding changed after candidate runner exit"
        )


def _bound_validator_script_source(
    *,
    agentic_sources: list[dict[str, str]],
    pinned_run_root: _PinnedRunRoot,
) -> tuple[bytes, str, str]:
    _assert_agentic_sources_still_bound(agentic_sources)
    validator_relative = "scripts/openclaw-real-gateway-contract-probe.py"
    validator_path = (ROOT / validator_relative).resolve()
    try:
        source_bytes = validator_path.read_bytes()
    except OSError as exc:
        raise ProbeError("persistent lifecycle validator executable is unavailable") from exc
    expected_digest = next(
        (
            str(source.get("sha256"))
            for source in agentic_sources
            if source.get("path") == validator_relative
        ),
        None,
    )
    if _sha256_bytes(source_bytes) != expected_digest:
        raise ProbeError("persistent lifecycle validator executable digest changed")
    _assert_pinned_run_root_identity(pinned_run_root)
    _assert_agentic_sources_still_bound(agentic_sources)
    return source_bytes, expected_digest, str(validator_path)


def _runtime_file_binding(path: Path, label: str) -> dict[str, str]:
    resolved = path.resolve()
    try:
        info = resolved.stat()
    except OSError as exc:
        raise ProbeError(f"{label} runtime launch source is missing") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ProbeError(f"{label} runtime launch source is not a regular file")
    return {
        "path": label,
        "sha256": _sha256_bytes(resolved.read_bytes()),
        "realpath_sha256": _text_sha256(str(resolved)),
    }


def _node_import_resolution_to_path(value: str, label: str) -> Path:
    specifier = value.strip()
    if not specifier:
        raise ProbeError(f"{label} runtime launch source resolution is empty")
    parsed = urlparse(specifier)
    if parsed.scheme == "file":
        return Path(unquote(parsed.path)).resolve()
    if parsed.scheme:
        raise ProbeError(f"{label} runtime launch source did not resolve to a file")
    candidate = Path(specifier)
    if not candidate.is_absolute():
        raise ProbeError(f"{label} runtime launch source did not resolve absolutely")
    return candidate.resolve()


def _resolve_node_import_path(
    *,
    openclaw_root: Path,
    node_executable: Path,
    runner_env: Mapping[str, str],
    specifier: str,
    label: str,
) -> Path:
    resolver = (
        "const resolved = await import.meta.resolve(process.argv[1]);"
        "console.log(resolved);"
    )
    proc = _run(
        [str(node_executable), "--input-type=module", "-e", resolver, specifier],
        cwd=openclaw_root,
        env=dict(runner_env),
        timeout=30,
    )
    if proc.returncode != 0:
        raise ProbeError(
            f"{label} runtime launch source could not be resolved "
            f"stderr_sha256={_sha256_bytes(proc.stderr.encode())}"
        )
    return _node_import_resolution_to_path(proc.stdout, label)


def _find_node_package_root(module_path: Path, package_name: str) -> Path:
    for candidate in (module_path.parent, *module_path.parents):
        package_json = candidate / "package.json"
        if not package_json.is_file():
            continue
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProbeError(f"{package_name} runtime package metadata is invalid") from exc
        if isinstance(payload, dict) and payload.get("name") == package_name:
            return candidate.resolve()
    raise ProbeError(f"{package_name} runtime package root could not be resolved")


def _directory_tree_sha256(root: Path) -> str:
    root = root.resolve()
    if not root.is_dir():
        raise ProbeError("runtime launch package root is missing")
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise ProbeError("runtime launch package root is empty")
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(_sha256_bytes(path.read_bytes()).encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _runtime_directory_binding(path: Path, label: str) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": label,
        "sha256": _directory_tree_sha256(resolved),
        "realpath_sha256": _text_sha256(str(resolved)),
    }


def _runtime_launch_bindings(
    openclaw_root: Path, runner_env: Mapping[str, str]
) -> tuple[Path, str, list[dict[str, str]]]:
    node = shutil.which("node", path=runner_env.get("PATH"))
    if node is None:
        raise ProbeError("runtime Node launcher could not be resolved")
    node_executable = Path(node).resolve()
    tsx_preload = _resolve_node_import_path(
        openclaw_root=openclaw_root,
        node_executable=node_executable,
        runner_env=runner_env,
        specifier="tsx",
        label="tsx",
    )
    tsx_package_root = _find_node_package_root(tsx_preload, "tsx")
    return (
        node_executable,
        tsx_preload.as_uri(),
        [
            _runtime_file_binding(node_executable, "runtime-launcher:node"),
            _runtime_file_binding(tsx_preload, "runtime-preload:tsx"),
            _runtime_directory_binding(
                tsx_package_root, "runtime-preload-package:tsx"
            ),
        ],
    )


def _validate_runtime_launch_sources(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ProbeError("runtime launch source binding is missing")
    by_path = {
        item.get("path"): item
        for item in value
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    missing = sorted(set(PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS) - set(by_path))
    if missing:
        raise ProbeError("runtime launch source binding is incomplete")
    validated: list[dict[str, str]] = []
    for label in PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS:
        item = by_path[label]
        _require_sha256_field(item, "sha256", label)
        _require_sha256_field(item, "realpath_sha256", label)
        validated.append(
            {
                "path": label,
                "sha256": str(item["sha256"]),
                "realpath_sha256": str(item["realpath_sha256"]),
            }
        )
    return validated


def _assert_runtime_launch_sources_still_bound(
    *,
    openclaw_root: Path,
    runner_env: Mapping[str, str],
    expected_node_executable: Path,
    expected_tsx_preload_specifier: str,
    expected_sources: list[dict[str, str]],
) -> None:
    node_executable, tsx_preload_specifier, current_sources = _runtime_launch_bindings(
        openclaw_root,
        runner_env,
    )
    if node_executable != expected_node_executable:
        raise ProbeError("runtime Node launcher binding changed after candidate runner exit")
    if tsx_preload_specifier != expected_tsx_preload_specifier:
        raise ProbeError("runtime tsx preload binding changed after candidate runner exit")
    if _validate_runtime_launch_sources(current_sources) != _validate_runtime_launch_sources(
        expected_sources
    ):
        raise ProbeError("runtime launch source binding changed after candidate runner exit")


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _text_sha256(value: str) -> str:
    return _sha256_bytes(value.encode())


def _read_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        return _json_object_from_bytes(path.read_bytes(), label)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{label} did not contain valid JSON") from exc


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
    if parsed.scheme != "ws":
        raise ProbeError("persistent lifecycle attestation gateway endpoint is not canonical ws")
    if parsed.username or parsed.password or parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ProbeError(
            "persistent lifecycle attestation gateway endpoint contains non-canonical credentials or path"
        )
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or parsed.port != port:
        raise ProbeError("persistent lifecycle attestation gateway endpoint is not the requested loopback listener")


def _is_provider_secret_env_name(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in PROVIDER_SECRET_ENV_MARKERS)


def _runner_base_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key in RUNNER_ENV_ALLOWLIST and not _is_provider_secret_env_name(key)
    }


def _validate_hmac_key_material(value: bytes, label: str) -> bytes:
    if len(value) != 32 or len(set(value)) < 16:
        raise ProbeError(f"{label} key is unavailable or too weak")
    return value


def _hmac_secret_from_env(env_name: str, label: str) -> bytes:
    value = os.environ.get(env_name)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProbeError(f"{label} key is unavailable, weak, or unsafe")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ProbeError(f"{label} key is unavailable, weak, or unsafe") from exc
    return _validate_hmac_key_material(decoded, label)


def _select_validation_anchor_key() -> bytes:
    if PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV in os.environ:
        return _hmac_secret_from_env(
            PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
            "persistent lifecycle validation anchor",
        )
    return _validate_hmac_key_material(
        secrets.token_bytes(32),
        "persistent lifecycle validation anchor",
    )


def _authentication_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(record)
    payload.pop("authentication", None)
    return payload


def _validate_hmac_authentication(
    record: Mapping[str, Any],
    *,
    label: str,
    expected_key_env: str,
    expected_key: bytes,
) -> None:
    authentication = _record(record.get("authentication"), f"{label} authentication")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise ProbeError(f"{label} authentication shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise ProbeError(f"{label} authentication scheme is invalid")
    if authentication.get("key_env") != expected_key_env:
        raise ProbeError(f"{label} authentication key authority is invalid")
    signature = _require_sha256_field(authentication, "signature", f"{label} authentication")
    expected = hmac.new(
        _validate_hmac_key_material(expected_key, f"{label} authentication"),
        _canonical_json_bytes(_authentication_payload(record)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ProbeError(f"{label} authentication signature mismatch")


def _hmac_authentication(record: Mapping[str, Any], *, key_env: str) -> dict[str, str]:
    signature = hmac.new(
        _hmac_secret_from_env(key_env, "persistent lifecycle validation"),
        _canonical_json_bytes(_authentication_payload(record)),
        hashlib.sha256,
    ).hexdigest()
    return {
        "scheme": "hmac-sha256-env",
        "key_env": key_env,
        "signature": signature,
    }


def _catalog_tool_names(response: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()

    def collect_tool(tool: Any) -> None:
        if not isinstance(tool, Mapping):
            return
        for key in ("name", "id"):
            value = tool.get(key)
            if isinstance(value, str) and value:
                names.add(value)

    tools = response.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            collect_tool(tool)
    groups = response.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, Mapping):
                continue
            group_tools = group.get("tools")
            if isinstance(group_tools, list):
                for tool in group_tools:
                    collect_tool(tool)
    runtime_methods = response.get("runtimeMethods")
    if isinstance(runtime_methods, list):
        for method in runtime_methods:
            collect_tool(method)
    return names


def _validate_runtime_catalog_response(response: Mapping[str, Any]) -> None:
    catalog_required_names = set(PERSISTENT_REQUIRED_TOOL_NAMES) - {
        "agenticOs.runtime.attest"
    }
    missing = sorted(catalog_required_names - _catalog_tool_names(response))
    if missing:
        raise ProbeError(
            "persistent lifecycle authenticated tools.catalog response is missing required tools"
        )


LIFECYCLE_OBSERVATION_FIELDS = (
    "status",
    "run_id",
    "transition_id",
    "duplicate_acquire_same_lease",
    "first_spawn_status",
    "duplicate_spawn_same_session",
    "post_release_lease_count",
    "gateway_lease_id_sha256",
    "session_key_sha256",
    "child_run_id_sha256",
    "session_status_sha256",
    "sessions_history_sha256",
    "release_status",
    "duplicate_release_status",
    "primary_release_sha256",
    "duplicate_release_sha256",
    "release_gateway_lease_id_sha256",
    "duplicate_release_gateway_lease_id_sha256",
    "release_owner_metadata_sha256",
    "duplicate_release_owner_metadata_sha256",
    "release_idempotency_key_sha256",
    "duplicate_release_idempotency_key_sha256",
    "sessions_list_count",
    "matching_session_count",
)


def _lifecycle_observation_snapshot(lifecycle: Mapping[str, Any]) -> dict[str, Any]:
    return {key: lifecycle.get(key) for key in LIFECYCLE_OBSERVATION_FIELDS}


def _lifecycle_attestation_record(lifecycle: Mapping[str, Any]) -> dict[str, Any]:
    observations = _lifecycle_observation_snapshot(lifecycle)
    return {
        "schema_version": PERSISTENT_LIFECYCLE_ATTESTATION_SCHEMA_VERSION,
        "record_authority": "agentic-os-persistent-lifecycle-runner-receipt",
        "authentication_authority": "agentic-os-independent-validation-subprocess",
        "record_transport": "non_rpc_pinned_run_root_receipt",
        "observations_schema_version": PERSISTENT_LIFECYCLE_OBSERVATIONS_SCHEMA_VERSION,
        "lifecycle_sha256": _canonical_sha256(observations),
        "observations": observations,
    }


def _validate_lifecycle_attestation_record(
    response: Mapping[str, Any],
    *,
    lifecycle: Mapping[str, Any],
) -> None:
    if response.get("schema_version") != PERSISTENT_LIFECYCLE_ATTESTATION_SCHEMA_VERSION:
        raise ProbeError("persistent lifecycle attestation schema is invalid")
    if response.get("record_authority") != "agentic-os-persistent-lifecycle-runner-receipt":
        raise ProbeError("persistent lifecycle attestation authority is invalid")
    if (
        response.get("authentication_authority")
        != "agentic-os-independent-validation-subprocess"
    ):
        raise ProbeError("persistent lifecycle attestation authentication authority is invalid")
    if response.get("record_transport") != "non_rpc_pinned_run_root_receipt":
        raise ProbeError("persistent lifecycle attestation transport is invalid")
    if (
        response.get("observations_schema_version")
        != PERSISTENT_LIFECYCLE_OBSERVATIONS_SCHEMA_VERSION
    ):
        raise ProbeError("persistent lifecycle observations schema is invalid")
    observations = _record(
        response.get("observations"), "persistent lifecycle observations"
    )
    expected_observations = _lifecycle_observation_snapshot(lifecycle)
    if observations != expected_observations:
        raise ProbeError("persistent lifecycle observations do not match receipt lifecycle")
    if response.get("lifecycle_sha256") != _canonical_sha256(expected_observations):
        raise ProbeError("persistent lifecycle observations digest mismatch")


def _validate_independent_validation(
    validation: Mapping[str, Any],
    *,
    receipt_sha256: str,
    attestation_response_sha256: str,
    tools_catalog_response_sha256: str,
    lifecycle_attestation: Mapping[str, Any],
    validation_anchor_key: bytes,
) -> None:
    if validation.get("schema_version") != PERSISTENT_VALIDATION_SCHEMA_VERSION:
        raise ProbeError("persistent lifecycle validation schema is invalid")
    if validation.get("receipt_sha256") != receipt_sha256:
        raise ProbeError("persistent lifecycle validation is not bound to the promoted receipt")
    if validation.get("attestation_response_sha256") != attestation_response_sha256:
        raise ProbeError("persistent lifecycle validation is not bound to the attestation response")
    if validation.get("tools_catalog_response_sha256") != tools_catalog_response_sha256:
        raise ProbeError("persistent lifecycle validation is not bound to the tools catalog")
    if "lifecycle_observations_response_sha256" in validation:
        raise ProbeError(
            "persistent lifecycle validation uses legacy RPC lifecycle observations"
        )
    validation_lifecycle_attestation = _record(
        validation.get("lifecycle_attestation"),
        "persistent lifecycle validation lifecycle attestation",
    )
    if _canonical_sha256(validation_lifecycle_attestation) != _canonical_sha256(
        lifecycle_attestation
    ):
        raise ProbeError("persistent lifecycle validation lifecycle attestation mismatch")
    if (
        validation.get("lifecycle_attestation_sha256")
        != _canonical_sha256(lifecycle_attestation)
    ):
        raise ProbeError(
            "persistent lifecycle validation is not bound to lifecycle attestation"
        )
    if validation.get("attestation_signature_verified") is not True:
        raise ProbeError("persistent lifecycle validation did not authenticate attestation signature")
    authority = _require_non_empty_string(validation, "validator_authority", "validation")
    if authority == "agentic-os-persistent-lifecycle-runner":
        raise ProbeError("persistent lifecycle validation authority is not independent")
    identity = _require_non_empty_string(validation, "validator_identity", "validation")
    if validation.get("validator_identity_sha256") != _text_sha256(identity):
        raise ProbeError("persistent lifecycle validation identity digest mismatch")
    _validate_hmac_authentication(
        validation,
        label="persistent lifecycle validation",
        expected_key_env=PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV,
        expected_key=validation_anchor_key,
    )


def _require_epoch_ms_field(section: Mapping[str, Any], key: str, label: str) -> int:
    value = section.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ProbeError(f"{label}.{key} must be a positive epoch milliseconds integer")
    return value


def _validate_expected_identity(
    section: Mapping[str, Any],
    *,
    key: str,
    expected: str,
    label: str,
) -> None:
    if section.get(key) != expected:
        raise ProbeError(f"{label}.{key} does not match requested lifecycle identity")


def _validate_capability_preflight_artifact(
    *,
    run_root: Path,
    preflight: Mapping[str, Any],
    required_tool_names: list[str],
    pinned_run_root: _PinnedRunRoot | None = None,
) -> None:
    evidence, evidence_bytes = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=preflight.get("evidence_file"),
        label="capability preflight evidence",
    )
    evidence_sha256 = _require_sha256_field(preflight, "evidence_sha256", "preflight")
    if _sha256_bytes(evidence_bytes) != evidence_sha256:
        raise ProbeError("capability preflight evidence digest mismatch")
    _require_pass(evidence, "capability preflight evidence")
    if evidence.get("runtime_ready") is not True:
        raise ProbeError("capability preflight evidence did not pass runtime readiness")
    if "required_tool_names" in evidence:
        evidence_required_tool_names = _string_list(
            evidence.get("required_tool_names"),
            "capability preflight evidence.required_tool_names",
        )
    elif "catalog" in evidence:
        catalog = _record(evidence.get("catalog"), "capability preflight evidence.catalog")
        model_catalog = _record(
            catalog.get("model_tool_catalog"),
            "capability preflight evidence.catalog.model_tool_catalog",
        )
        gateway_catalog = _record(
            catalog.get("gateway_rpc_catalog"),
            "capability preflight evidence.catalog.gateway_rpc_catalog",
        )
        attestation_catalog = _record(
            catalog.get("attestation_rpc_catalog"),
            "capability preflight evidence.catalog.attestation_rpc_catalog",
        )
        evidence_required_tool_names = [
            *_string_list(
                model_catalog.get("required_tool_names"),
                "capability preflight evidence.catalog.model_tool_catalog.required_tool_names",
            ),
            *_string_list(
                gateway_catalog.get("source_bound_rpc_names"),
                "capability preflight evidence.catalog.gateway_rpc_catalog.source_bound_rpc_names",
            ),
            _require_non_empty_string(
                attestation_catalog,
                "method",
                "capability preflight evidence.catalog.attestation_rpc_catalog",
            ),
        ]
    else:
        hello = _record(evidence.get("hello"), "capability preflight evidence.hello")
        evidence_required_tool_names = _string_list(
            hello.get("required_methods"),
            "capability preflight evidence.hello.required_methods",
        )
    if sorted(evidence_required_tool_names) != sorted(required_tool_names):
        raise ProbeError("capability preflight evidence required tool names mismatch")


def _build_independent_validation_record(
    *,
    run_root: Path,
    receipt_file: Path,
    pinned_run_root: _PinnedRunRoot | None = None,
) -> dict[str, Any]:
    receipt, receipt_bytes = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=(
            "receipts/lifecycle-receipt.json"
            if pinned_run_root is not None
            else str(receipt_file)
        ),
        label="persistent lifecycle receipt",
    )
    preflight = _record(receipt.get("preflight"), "preflight")
    lifecycle = _record(receipt.get("lifecycle"), "lifecycle")
    evidence, _ = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=preflight.get("persistent_evidence_file"),
        label="persistent attestation evidence",
    )
    raw_attestation = _record(
        evidence.get("attestation"), "persistent attestation evidence attestation"
    )
    response = _record(raw_attestation.get("response"), "persistent attestation response")
    if response.get("signature_algorithm") != "hmac-sha256":
        raise ProbeError("persistent attestation signature algorithm is invalid")
    signature = _require_sha256_field(response, "signature", "persistent attestation response")
    signed_payload = _record(
        response.get("signed_payload"), "persistent attestation signed payload"
    )
    expected_signature = hmac.new(
        _hmac_secret_from_env(
            PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV,
            "persistent attestation verification",
        ),
        _canonical_json_bytes(signed_payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ProbeError("persistent attestation signature mismatch")
    rpc_evidence = _record(
        evidence.get("rpc_evidence"), "persistent attestation RPC evidence"
    )
    _reject_unsupported_persistent_rpc_records(rpc_evidence)
    tools_catalog = _record(
        rpc_evidence.get("tools_catalog"), "persistent attestation RPC evidence tools_catalog"
    )
    tools_catalog_response = _record(
        tools_catalog.get("response"), "persistent attestation tools_catalog response"
    )
    _validate_runtime_catalog_response(tools_catalog_response)
    lifecycle_attestation = _lifecycle_attestation_record(lifecycle)
    _validate_lifecycle_attestation_record(lifecycle_attestation, lifecycle=lifecycle)
    validation: dict[str, Any] = {
        "schema_version": PERSISTENT_VALIDATION_SCHEMA_VERSION,
        "status": "pass",
        "receipt_sha256": _sha256_bytes(receipt_bytes),
        "attestation_response_sha256": _canonical_sha256(response),
        "tools_catalog_response_sha256": _canonical_sha256(tools_catalog_response),
        "lifecycle_attestation_sha256": _canonical_sha256(lifecycle_attestation),
        "lifecycle_attestation": lifecycle_attestation,
        "attestation_signature_verified": True,
        "attestation_verification": {
            "schema_version": PERSISTENT_ATTESTATION_VERIFICATION_SCHEMA_VERSION,
            "signature_algorithm": "hmac-sha256",
            "signature_sha256": _text_sha256(signature),
            "signed_payload_sha256": _canonical_sha256(signed_payload),
            "verified": True,
        },
        "validator_authority": "agentic-os-independent-validation-subprocess",
        "validator_identity": "agentic-os-persistent-validator",
        "validator_identity_sha256": _text_sha256("agentic-os-persistent-validator"),
    }
    validation["authentication"] = _hmac_authentication(
        validation, key_env=PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV
    )
    return validation


def _write_independent_validation_file(
    *,
    run_root: Path,
    receipt_file: Path,
    validation_file: Path,
    pinned_run_root: _PinnedRunRoot | None = None,
) -> None:
    validation = _build_independent_validation_record(
        run_root=run_root,
        receipt_file=receipt_file,
        pinned_run_root=pinned_run_root,
    )
    if pinned_run_root is not None:
        _assert_pinned_run_root_identity(pinned_run_root)
        output = (json.dumps(validation, indent=2, sort_keys=True) + "\n").encode()
        file_name = "independent-validation.json"
        temporary_name = f".{file_name}.{os.getpid()}.tmp"
        temporary_fd = -1
        try:
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=pinned_run_root.receipts.fd,
            )
            offset = 0
            while offset < len(output):
                offset += os.write(temporary_fd, output[offset:])
            os.fchmod(temporary_fd, 0o600)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            os.replace(
                temporary_name,
                file_name,
                src_dir_fd=pinned_run_root.receipts.fd,
                dst_dir_fd=pinned_run_root.receipts.fd,
            )
            _assert_pinned_run_root_identity(pinned_run_root)
            return
        except ProbeError:
            raise
        except OSError as exc:
            raise ProbeError(
                "persistent lifecycle validation output path is unsafe or unavailable"
            ) from exc
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            try:
                os.unlink(temporary_name, dir_fd=pinned_run_root.receipts.fd)
            except FileNotFoundError:
                pass
    validation_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_validation_file = validation_file.with_name(
        f".{validation_file.name}.{os.getpid()}.tmp"
    )
    try:
        temporary_validation_file.write_text(
            json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(temporary_validation_file, 0o600)
        temporary_validation_file.replace(validation_file)
        os.chmod(validation_file, 0o600)
    finally:
        if temporary_validation_file.exists():
            temporary_validation_file.unlink()


def _consume_attestation_verification_key(run_root: _PinnedRunRoot) -> bytes:
    _assert_pinned_run_root_identity(run_root)
    key_name = PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH.name
    key_fd = -1
    try:
        key_fd = os.open(
            key_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=run_root.keys.fd,
        )
        key_info = os.fstat(key_fd)
        if (
            not stat.S_ISREG(key_info.st_mode)
            or key_info.st_uid != os.getuid()
            or stat.S_IMODE(key_info.st_mode) != 0o600
            or key_info.st_nlink != 1
        ):
            raise ProbeError("persistent attestation verification key file is unsafe")
        key = _validate_hmac_key_material(
            os.read(key_fd, 33), "persistent attestation verification"
        )
        current_info = os.stat(
            key_name,
            dir_fd=run_root.keys.fd,
            follow_symlinks=False,
        )
        if (current_info.st_dev, current_info.st_ino) != (
            key_info.st_dev,
            key_info.st_ino,
        ):
            raise ProbeError("persistent attestation verification key changed during access")
        os.unlink(key_name, dir_fd=run_root.keys.fd)
        _assert_pinned_run_root_identity(run_root)
        return key
    except ProbeError:
        raise
    except OSError as exc:
        raise ProbeError(
            "persistent attestation verification key path is unsafe or unavailable"
        ) from exc
    finally:
        if key_fd >= 0:
            os.close(key_fd)


def _remove_attestation_verification_key(run_root: _PinnedRunRoot) -> bool:
    if run_root.closed:
        raise ProbeError("persistent lifecycle pinned run root is closed during cleanup")
    key_name = PERSISTENT_ATTESTATION_KEY_RELATIVE_PATH.name
    try:
        os.stat(key_name, dir_fd=run_root.keys.fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ProbeError(
            "persistent attestation verification key cleanup path is unsafe or unavailable"
        ) from exc
    try:
        os.unlink(key_name, dir_fd=run_root.keys.fd)
        os.stat(key_name, dir_fd=run_root.keys.fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise ProbeError(
            "persistent attestation verification key cleanup path is unsafe or unavailable"
        ) from exc
    raise ProbeError("persistent attestation verification key cleanup was incomplete")


def _validator_env(
    *,
    run_root: _PinnedRunRoot,
    validation_anchor_key: bytes,
) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in RUNNER_ENV_ALLOWLIST and not _is_provider_secret_env_name(key)
    }
    attestation_key = _consume_attestation_verification_key(run_root)
    anchor_key = _validate_hmac_key_material(
        validation_anchor_key,
        "persistent lifecycle validation anchor",
    )
    if hmac.compare_digest(attestation_key, anchor_key):
        raise ProbeError("persistent lifecycle HMAC keys are not domain separated")
    env[PERSISTENT_ATTESTATION_VERIFICATION_HMAC_ENV] = attestation_key.hex()
    env[PERSISTENT_VALIDATION_ANCHOR_HMAC_ENV] = anchor_key.hex()
    return env


def _run_independent_validator(
    *,
    pinned_run_root: _PinnedRunRoot,
    validation_anchor_key: bytes,
    agentic_sources: list[dict[str, str]],
    timeout: int = 30,
) -> None:
    validator_source, validator_digest, validator_path = _bound_validator_script_source(
        agentic_sources=agentic_sources,
        pinned_run_root=pinned_run_root,
    )
    validator_env = _validator_env(
        run_root=pinned_run_root,
        validation_anchor_key=validation_anchor_key,
    )
    validator_env["AGENTIC_OS_PROBE_ROOT"] = str(ROOT.resolve())
    _assert_pinned_run_root_identity(pinned_run_root)
    validation_name = "independent-validation.json"
    try:
        validation_info = os.stat(
            validation_name,
            dir_fd=pinned_run_root.receipts.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(validation_info.st_mode):
            raise ProbeError("persistent lifecycle validation output path is unsafe")
        os.unlink(validation_name, dir_fd=pinned_run_root.receipts.fd)
    command = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        STDIN_VALIDATOR_BOOTSTRAP,
        validator_path,
        validator_digest,
        "__persistent-validator",
        "--run-root-path",
        str(pinned_run_root.original_path),
    ]
    for name in ("root", *PINNED_RUN_SUBDIRECTORIES):
        directory = (
            pinned_run_root.root
            if name == "root"
            else pinned_run_root.directory(name)
        )
        command.extend(
            [
                f"--{name}-fd",
                str(directory.fd),
                f"--{name}-device",
                str(directory.device),
                f"--{name}-inode",
                str(directory.inode),
            ]
        )
    pass_fds = pinned_run_root.validator_fds()
    _assert_pinned_run_root_identity(pinned_run_root)
    proc = _run(
        command,
        cwd=pinned_run_root.original_path,
        env=validator_env,
        timeout=timeout,
        pass_fds=pass_fds,
        input_bytes=validator_source,
    )
    _assert_pinned_run_root_identity(pinned_run_root)
    if proc.returncode != 0:
        raise ProbeError(
            "persistent lifecycle independent validator failed "
            f"stdout_sha256={_sha256_bytes(proc.stdout.encode())} "
            f"stderr_sha256={_sha256_bytes(proc.stderr.encode())}"
        )
    try:
        validation_info = os.stat(
            validation_name,
            dir_fd=pinned_run_root.receipts.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise ProbeError(
            "persistent lifecycle independent validator produced no validation file"
        ) from exc
    if not stat.S_ISREG(validation_info.st_mode):
        raise ProbeError("persistent lifecycle validation output path is unsafe")


def _validate_attestation_signature_binding(
    response: Mapping[str, Any],
    *,
    validation: Mapping[str, Any],
) -> None:
    if response.get("signature_algorithm") != "hmac-sha256":
        raise ProbeError("persistent attestation signature algorithm is invalid")
    _require_sha256_field(response, "signature", "persistent attestation response")
    verification = _record(
        validation.get("attestation_verification"), "persistent attestation verification"
    )
    if verification.get("schema_version") != PERSISTENT_ATTESTATION_VERIFICATION_SCHEMA_VERSION:
        raise ProbeError("persistent attestation verification schema is invalid")
    if verification.get("signature_algorithm") != response.get("signature_algorithm"):
        raise ProbeError("persistent attestation verification algorithm mismatch")
    if verification.get("signature_sha256") != _text_sha256(str(response.get("signature"))):
        raise ProbeError("persistent attestation verification signature digest mismatch")
    if verification.get("signed_payload_sha256") != _canonical_sha256(
        _record(response.get("signed_payload"), "persistent attestation signed payload")
    ):
        raise ProbeError("persistent attestation verification payload digest mismatch")
    if verification.get("verified") is not True:
        raise ProbeError("persistent attestation signature was not verified")


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


def _process_group_reaped(proc: subprocess.CompletedProcess[str]) -> bool:
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def _wait_for_process_group_reaped(
    proc: subprocess.CompletedProcess[str], *, timeout_seconds: float = 5.0
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _process_group_reaped(proc):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _terminate_and_verify_process_group(
    proc: subprocess.CompletedProcess[str],
) -> tuple[bool, bool]:
    attempted = _terminate_process_group(proc)
    return attempted, _wait_for_process_group_reaped(proc)


def _prepare_private_directory(directory: Path) -> Path:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    info = directory.stat()
    if info.st_uid != os.getuid():
        raise ProbeError(f"{directory.name} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ProbeError(f"{directory.name} is not private to the current user")
    return directory


def _prepare_private_run_root(directory: Path) -> Path:
    unresolved = directory.absolute()
    if unresolved.is_symlink():
        raise ProbeError("persistent lifecycle run root must not be a symlink")
    if unresolved.exists():
        info = unresolved.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ProbeError("persistent lifecycle run root must be a directory")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ProbeError(
                "persistent lifecycle pre-existing run root must be owner-owned mode 0700"
            )
        if any(unresolved.iterdir()):
            raise ProbeError("persistent lifecycle pre-existing run root must be empty")
    else:
        unresolved.mkdir(parents=True, mode=0o700)
    resolved = unresolved.resolve()
    info = resolved.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProbeError("persistent lifecycle run root is not private to the current user")
    return resolved


def _secure_directory_flags() -> int:
    required_flag_names = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required_flag_names):
        raise ProbeError("secure pinned run-root directory access is unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _pinned_directory(name: str, descriptor: int) -> _PinnedDirectory:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ProbeError(f"persistent lifecycle pinned {name} directory is unsafe")
    os.set_inheritable(descriptor, False)
    return _PinnedDirectory(
        name=name,
        fd=descriptor,
        device=info.st_dev,
        inode=info.st_ino,
    )


def _descriptor_path(descriptor: int) -> Path:
    for base in (Path("/dev/fd"), Path("/proc/self/fd")):
        if base.is_dir():
            return base / str(descriptor)
    raise ProbeError("fd-pinned filesystem paths are unavailable")


def _pin_prepared_run_root(run_root: Path) -> _PinnedRunRoot:
    for name in PINNED_RUN_SUBDIRECTORIES:
        _prepare_private_directory(run_root / name)
    flags = _secure_directory_flags()
    opened: list[int] = []
    try:
        root_fd = os.open(run_root, flags)
        opened.append(root_fd)
        root = _pinned_directory("root", root_fd)
        subdirectories: dict[str, _PinnedDirectory] = {}
        for name in PINNED_RUN_SUBDIRECTORIES:
            descriptor = os.open(name, flags, dir_fd=root_fd)
            opened.append(descriptor)
            subdirectories[name] = _pinned_directory(name, descriptor)
        pinned = _PinnedRunRoot(
            original_path=run_root,
            root=root,
            keys=subdirectories["keys"],
            receipts=subdirectories["receipts"],
            evidence=subdirectories["evidence"],
        )
        _assert_pinned_run_root_identity(pinned)
        return pinned
    except Exception:
        for descriptor in reversed(opened):
            os.close(descriptor)
        raise


def _pinned_run_root_from_inherited_fds(
    *,
    original_path: Path,
    root_fd: int,
    keys_fd: int,
    receipts_fd: int,
    evidence_fd: int,
    expected_identities: Mapping[str, tuple[int, int]],
) -> _PinnedRunRoot:
    directories = {
        "root": _pinned_directory("root", root_fd),
        "keys": _pinned_directory("keys", keys_fd),
        "receipts": _pinned_directory("receipts", receipts_fd),
        "evidence": _pinned_directory("evidence", evidence_fd),
    }
    for name, directory in directories.items():
        if (directory.device, directory.inode) != expected_identities[name]:
            raise ProbeError(f"persistent lifecycle inherited {name} fd identity mismatch")
    pinned = _PinnedRunRoot(
        original_path=original_path,
        root=directories["root"],
        keys=directories["keys"],
        receipts=directories["receipts"],
        evidence=directories["evidence"],
    )
    _assert_pinned_run_root_identity(pinned)
    return pinned


def _assert_pinned_run_root_identity(pinned: _PinnedRunRoot) -> None:
    if pinned.closed:
        raise ProbeError("persistent lifecycle pinned run root is closed")
    try:
        root_info = os.fstat(pinned.root.fd)
        if (root_info.st_dev, root_info.st_ino) != (
            pinned.root.device,
            pinned.root.inode,
        ):
            raise ProbeError("persistent lifecycle pinned run-root fd identity changed")
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise ProbeError("persistent lifecycle pinned run root is unsafe")
        path_info = os.stat(pinned.original_path, follow_symlinks=False)
        if (path_info.st_dev, path_info.st_ino) != (
            pinned.root.device,
            pinned.root.inode,
        ):
            raise ProbeError("persistent lifecycle run-root pathname identity changed")
        for name in PINNED_RUN_SUBDIRECTORIES:
            directory = pinned.directory(name)
            descriptor_info = os.fstat(directory.fd)
            entry_info = os.stat(name, dir_fd=pinned.root.fd, follow_symlinks=False)
            expected = (directory.device, directory.inode)
            if (
                (descriptor_info.st_dev, descriptor_info.st_ino) != expected
                or (entry_info.st_dev, entry_info.st_ino) != expected
            ):
                raise ProbeError(
                    f"persistent lifecycle pinned {name} subtree identity changed"
                )
            if (
                not stat.S_ISDIR(descriptor_info.st_mode)
                or descriptor_info.st_uid != os.getuid()
                or stat.S_IMODE(descriptor_info.st_mode) != 0o700
            ):
                raise ProbeError(f"persistent lifecycle pinned {name} subtree is unsafe")
    except ProbeError:
        raise
    except OSError as exc:
        raise ProbeError(
            "persistent lifecycle run-root or pinned subtree identity is unavailable"
        ) from exc


def _pinned_artifact_parts(
    pinned: _PinnedRunRoot,
    value: Any,
    label: str,
) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, str) or not value:
        raise ProbeError(f"{label} path is missing")
    candidate = Path(os.path.normpath(value))
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(pinned.original_path)
        except ValueError as exc:
            raise ProbeError(f"{label} path is outside the isolated run root") from exc
    if candidate.is_absolute() or not candidate.parts or any(
        part in {"", ".", ".."} for part in candidate.parts
    ):
        raise ProbeError(f"{label} path is unsafe")
    subtree, *remaining = candidate.parts
    if subtree not in {"receipts", "evidence"} or not remaining:
        raise ProbeError(f"{label} path is outside pinned artifact subtrees")
    return subtree, tuple(remaining)


def _read_pinned_artifact_bytes(
    pinned: _PinnedRunRoot,
    value: Any,
    label: str,
) -> bytes:
    _assert_pinned_run_root_identity(pinned)
    subtree, parts = _pinned_artifact_parts(pinned, value, label)
    directory_fd = pinned.directory(subtree).fd
    opened_directories: list[int] = []
    file_fd = -1
    directory_flags = _secure_directory_flags()
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        for part in parts[:-1]:
            directory_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            opened_directories.append(directory_fd)
            info = os.fstat(directory_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ProbeError(f"{label} parent directory is unsafe")
        file_name = parts[-1]
        file_fd = os.open(file_name, file_flags, dir_fd=directory_fd)
        file_info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != os.getuid()
            or file_info.st_nlink != 1
        ):
            raise ProbeError(f"{label} file is unsafe")
        stable_snapshot = (
            file_info.st_dev,
            file_info.st_ino,
            file_info.st_mode,
            file_info.st_uid,
            file_info.st_gid,
            file_info.st_nlink,
            file_info.st_size,
            file_info.st_mtime_ns,
            file_info.st_ctime_ns,
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        post_read_info = os.fstat(file_fd)
        post_read_snapshot = (
            post_read_info.st_dev,
            post_read_info.st_ino,
            post_read_info.st_mode,
            post_read_info.st_uid,
            post_read_info.st_gid,
            post_read_info.st_nlink,
            post_read_info.st_size,
            post_read_info.st_mtime_ns,
            post_read_info.st_ctime_ns,
        )
        if post_read_snapshot != stable_snapshot:
            raise ProbeError(f"{label} file changed during pinned access")
        current_info = os.stat(file_name, dir_fd=directory_fd, follow_symlinks=False)
        current_snapshot = (
            current_info.st_dev,
            current_info.st_ino,
            current_info.st_mode,
            current_info.st_uid,
            current_info.st_gid,
            current_info.st_nlink,
            current_info.st_size,
            current_info.st_mtime_ns,
            current_info.st_ctime_ns,
        )
        if current_snapshot != stable_snapshot:
            raise ProbeError(f"{label} file changed during pinned access")
        _assert_pinned_run_root_identity(pinned)
        return b"".join(chunks)
    except ProbeError:
        raise
    except OSError as exc:
        raise ProbeError(f"{label} path is unsafe or unavailable") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for descriptor in reversed(opened_directories):
            os.close(descriptor)


def _read_pinned_json_file(
    pinned: _PinnedRunRoot,
    value: Any,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    raw = _read_pinned_artifact_bytes(pinned, value, label)
    return _json_object_from_bytes(raw, label), raw


def _json_object_from_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key, value in pairs:
            if key in payload:
                raise DuplicateJsonKeyError(
                    f"{label} contains duplicate JSON key: {key}"
                )
            payload[key] = value
        return payload

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except DuplicateJsonKeyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{label} did not contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return payload


def _read_run_json_artifact(
    *,
    run_root: Path,
    pinned_run_root: _PinnedRunRoot | None,
    value: Any,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    if pinned_run_root is not None:
        return _read_pinned_json_file(pinned_run_root, value, label)
    path = _run_artifact_path(run_root, value, label)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProbeError(f"cannot read {label}: {path}") from exc
    return _json_object_from_bytes(raw, label), raw


def _read_optional_pinned_receipt_json(
    pinned: _PinnedRunRoot,
    file_name: str,
    label: str,
) -> dict[str, Any]:
    if Path(file_name).name != file_name:
        raise ProbeError(f"{label} file name is unsafe")
    _assert_pinned_run_root_identity(pinned)
    try:
        os.stat(file_name, dir_fd=pinned.receipts.fd, follow_symlinks=False)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ProbeError(f"{label} path is unsafe or unavailable") from exc
    payload, _ = _read_pinned_json_file(
        pinned,
        f"receipts/{file_name}",
        label,
    )
    return payload


def _default_private_run_root(head: str) -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix=f"openclaw-real-gateway-contract-probe-{head[:12]}-",
            dir=tempfile.gettempdir(),
        )
    )


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


def _reject_unsupported_persistent_rpc_records(rpc_evidence: Mapping[str, Any]) -> None:
    expected = {"tools_catalog", "allow_lease_status"}
    unexpected = sorted(set(rpc_evidence) - expected)
    if unexpected:
        raise ProbeError(
            "persistent attestation RPC evidence contains unsupported non-Gateway records: "
            + ", ".join(unexpected)
        )


def _validate_allow_lease_status_response(response: Mapping[str, Any]) -> None:
    if response.get("status") != "ok":
        raise ProbeError("persistent attestation allowLease status response did not pass")
    leases = response.get("leases")
    if not isinstance(leases, list):
        raise ProbeError("persistent attestation allowLease status leases are malformed")
    for lease in leases:
        if not isinstance(lease, dict):
            raise ProbeError("persistent attestation allowLease status lease is malformed")


def _validate_persistent_attestation_evidence(
    *,
    run_root: Path,
    preflight: Mapping[str, Any],
    attestation: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    validation: Mapping[str, Any],
    immutable_inputs: Mapping[str, Any],
    runtime_sources: list[dict[str, str]],
    runtime_head: str,
    agentic_head: str,
    port: int,
    pinned_run_root: _PinnedRunRoot | None = None,
) -> None:
    evidence, evidence_bytes = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=preflight.get("persistent_evidence_file"),
        label="persistent attestation evidence",
    )
    evidence_sha256 = _require_sha256_field(
        preflight, "persistent_evidence_sha256", "preflight"
    )
    if _sha256_bytes(evidence_bytes) != evidence_sha256:
        raise ProbeError("persistent attestation evidence digest mismatch")
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
    _validate_attestation_signature_binding(response, validation=validation)
    signed_payload = _record(
        response.get("signed_payload"), "persistent attestation signed payload"
    )
    now_epoch_ms = int(time.time() * 1000)
    issued_at_epoch_ms = _require_epoch_ms_field(
        signed_payload, "issued_at_epoch_ms", "persistent attestation signed payload"
    )
    expires_at_epoch_ms = _require_epoch_ms_field(
        signed_payload, "expires_at_epoch_ms", "persistent attestation signed payload"
    )
    captured_at_epoch_ms = _require_epoch_ms_field(
        attestation, "captured_at_epoch_ms", "attestation"
    )
    if not (issued_at_epoch_ms <= captured_at_epoch_ms <= expires_at_epoch_ms):
        raise ProbeError("persistent attestation capture time is outside signed lifetime")
    if not (issued_at_epoch_ms <= now_epoch_ms <= expires_at_epoch_ms):
        raise ProbeError("persistent attestation is not fresh at promotion time")
    if attestation.get("expires_at_epoch_ms") != expires_at_epoch_ms:
        raise ProbeError("persistent attestation expiry is not signed-payload bound")
    rpc_evidence = _record(
        evidence.get("rpc_evidence"), "persistent attestation RPC evidence"
    )
    _reject_unsupported_persistent_rpc_records(rpc_evidence)
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
    for key, method, response_validator in (
        ("tools_catalog", "tools.catalog", _validate_runtime_catalog_response),
        (
            "allow_lease_status",
            "subagents.allowLease.status",
            _validate_allow_lease_status_response,
        ),
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
        if response_validator is not None:
            response_validator(response_record)
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
            "schema_version": PERSISTENT_RPC_TRANSCRIPT_SCHEMA_VERSION,
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


def _validate_duplicate_release_identity(lifecycle: Mapping[str, Any]) -> dict[str, str]:
    release_status = _require_non_empty_string(
        lifecycle, "release_status", "lifecycle"
    )
    if release_status != "released":
        raise ProbeError("persistent lifecycle primary release status was not successful")
    duplicate_release_status = _require_non_empty_string(
        lifecycle, "duplicate_release_status", "lifecycle"
    )
    if duplicate_release_status != release_status:
        raise ProbeError("persistent lifecycle duplicate release status mismatch")

    primary_release_sha256 = _require_sha256_field(
        lifecycle, "primary_release_sha256", "lifecycle"
    )
    duplicate_release_sha256 = _require_sha256_field(
        lifecycle, "duplicate_release_sha256", "lifecycle"
    )
    if duplicate_release_sha256 != primary_release_sha256:
        raise ProbeError("persistent lifecycle duplicate release response digest mismatch")

    identity_pairs = (
        (
            "release_gateway_lease_id_sha256",
            "duplicate_release_gateway_lease_id_sha256",
            "Gateway lease id",
        ),
        (
            "release_owner_metadata_sha256",
            "duplicate_release_owner_metadata_sha256",
            "owner metadata",
        ),
        (
            "release_idempotency_key_sha256",
            "duplicate_release_idempotency_key_sha256",
            "idempotency key",
        ),
    )
    identity: dict[str, str] = {
        "release_status": release_status,
        "duplicate_release_status": duplicate_release_status,
        "primary_release_sha256": primary_release_sha256,
        "duplicate_release_sha256": duplicate_release_sha256,
    }
    for primary_key, duplicate_key, label in identity_pairs:
        primary_digest = _require_sha256_field(lifecycle, primary_key, "lifecycle")
        duplicate_digest = _require_sha256_field(lifecycle, duplicate_key, "lifecycle")
        if duplicate_digest != primary_digest:
            raise ProbeError(
                f"persistent lifecycle duplicate release {label} identity mismatch"
            )
        identity[primary_key] = primary_digest
        identity[duplicate_key] = duplicate_digest
    return identity


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
    env = _runner_base_env()
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
    proc: subprocess.CompletedProcess[str] | None = None
    try:
        try:
            proc = _run(
                command,
                cwd=openclaw_root,
                env=env,
                timeout=timeout,
                start_new_session=True,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            proc = subprocess.CompletedProcess(command, 124, stdout, stderr)
            pid = getattr(exc, "pid", None)
            if isinstance(pid, int):
                proc.pid = pid  # type: ignore[attr-defined]
            cleanup_attempted, process_group_reaped = _terminate_and_verify_process_group(proc)
            if not process_group_reaped:
                raise ProbeError(
                    "real Gateway E2E timed out and candidate process group remained alive"
                ) from exc
            raise ProbeError(
                "real Gateway E2E timed out "
                f"process_group_cleanup_attempted={cleanup_attempted}"
            ) from exc
        cleanup_attempted, process_group_reaped = _terminate_and_verify_process_group(proc)
        if not process_group_reaped:
            raise ProbeError(
                "real Gateway E2E left candidate process group alive "
                f"process_group_cleanup_attempted={cleanup_attempted}"
            )
        if proc.returncode != 0:
            raise ProbeError(
                "real Gateway E2E failed "
                f"returncode={proc.returncode} stdout_sha256={_sha256_bytes(proc.stdout.encode())} "
                f"stderr_sha256={_sha256_bytes(proc.stderr.encode())}"
            )
        if validate_candidate_root(openclaw_root) != head:
            raise ProbeError("OpenClaw candidate changed while the real Gateway E2E was running")
        payload = _read_json_file(temporary_evidence_file, "real Gateway evidence")
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
    runtime_launch_sources: list[dict[str, str]],
    command: list[str],
    proc: subprocess.CompletedProcess[str],
    port: int,
    expected_run_id: str,
    expected_transition_id: str,
    validation_anchor_key: bytes,
    pinned_run_root: _PinnedRunRoot | None = None,
) -> dict[str, Any]:
    if pinned_run_root is not None:
        _assert_pinned_run_root_identity(pinned_run_root)
    receipt, receipt_bytes = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=(
            "receipts/lifecycle-receipt.json"
            if pinned_run_root is not None
            else str(receipt_file)
        ),
        label="persistent lifecycle receipt",
    )
    validation, validation_bytes = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=(
            "receipts/independent-validation.json"
            if pinned_run_root is not None
            else str(validation_file)
        ),
        label="persistent lifecycle validation",
    )
    run_root_display = str(
        pinned_run_root.original_path
        if pinned_run_root is not None
        else run_root.resolve()
    )
    _require_pass(receipt, "persistent lifecycle receipt")
    _require_pass(validation, "persistent lifecycle validation")
    receipt_sha256 = _sha256_bytes(receipt_bytes)
    if validation.get("receipt_sha256") != receipt_sha256:
        raise ProbeError("persistent lifecycle validation is not bound to the promoted receipt")

    agentic_head = _git(ROOT, "rev-parse", "HEAD")
    immutable_inputs = _record(receipt.get("immutable_inputs"), "receipt immutable_inputs")
    if immutable_inputs.get("runtime_head") != head:
        raise ProbeError("persistent lifecycle receipt runtime head binding is invalid")
    if immutable_inputs.get("agentic_os_head") != agentic_head:
        raise ProbeError("persistent lifecycle receipt Agentic OS head binding is invalid")
    _validate_expected_identity(
        immutable_inputs,
        key="run_id",
        expected=expected_run_id,
        label="receipt immutable_inputs",
    )
    _validate_expected_identity(
        immutable_inputs,
        key="transition_id",
        expected=expected_transition_id,
        label="receipt immutable_inputs",
    )

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
    production_before_health = _record(
        production_before.get("health"), "production_before.health"
    )
    production_after_health = _record(
        production_after.get("health"), "production_after.health"
    )
    production_health_before_sha256 = _require_sha256_field(
        rollback, "production_health_before_sha256", "rollback"
    )
    production_health_after_sha256 = _require_sha256_field(
        rollback, "production_health_after_sha256", "rollback"
    )
    if _canonical_sha256(production_before_health) != production_health_before_sha256:
        raise ProbeError("persistent lifecycle production health before digest mismatch")
    if _canonical_sha256(production_after_health) != production_health_after_sha256:
        raise ProbeError("persistent lifecycle production health after digest mismatch")
    if production_health_before_sha256 != production_health_after_sha256:
        raise ProbeError("persistent lifecycle production health changed")
    if db_authority.get("DB_AUTHORITY_ENABLED") is not False:
        raise ProbeError("persistent lifecycle did not prove DB authority remained disabled")
    if candidate.get("port") != port:
        raise ProbeError("persistent lifecycle candidate port binding is invalid")
    if preflight.get("runtime_ready") is not True:
        raise ProbeError("persistent lifecycle preflight did not pass runtime readiness")
    if lifecycle.get("first_spawn_status") != "accepted":
        raise ProbeError("persistent lifecycle did not prove accepted session spawn")
    _validate_expected_identity(
        lifecycle,
        key="run_id",
        expected=expected_run_id,
        label="lifecycle",
    )
    _validate_expected_identity(
        lifecycle,
        key="transition_id",
        expected=expected_transition_id,
        label="lifecycle",
    )
    if lifecycle.get("duplicate_spawn_same_session") is not True:
        raise ProbeError("persistent lifecycle did not prove duplicate spawn identity parity")
    if lifecycle.get("duplicate_acquire_same_lease") is not True:
        raise ProbeError("persistent lifecycle did not prove duplicate acquire lease identity parity")
    post_release_lease_count = lifecycle.get("post_release_lease_count")
    if (
        not isinstance(post_release_lease_count, int)
        or isinstance(post_release_lease_count, bool)
        or post_release_lease_count != 0
    ):
        raise ProbeError("persistent lifecycle did not prove release cleanup")
    gateway_lease_id_sha256 = _require_sha256_field(
        lifecycle, "gateway_lease_id_sha256", "lifecycle"
    )
    _require_sha256_field(lifecycle, "session_key_sha256", "lifecycle")
    _require_sha256_field(lifecycle, "child_run_id_sha256", "lifecycle")
    _require_sha256_field(lifecycle, "session_status_sha256", "lifecycle")
    _require_sha256_field(lifecycle, "sessions_history_sha256", "lifecycle")
    duplicate_release_identity = _validate_duplicate_release_identity(lifecycle)
    if (
        duplicate_release_identity["release_gateway_lease_id_sha256"]
        != gateway_lease_id_sha256
    ):
        raise ProbeError("persistent lifecycle release Gateway lease id did not match acquired lease")
    matching_session_count = lifecycle.get("matching_session_count")
    if (
        not isinstance(matching_session_count, int)
        or isinstance(matching_session_count, bool)
        or matching_session_count != 1
    ):
        raise ProbeError("persistent lifecycle did not prove matching accepted session identity")
    sessions_list_count = lifecycle.get("sessions_list_count")
    if (
        not isinstance(sessions_list_count, int)
        or isinstance(sessions_list_count, bool)
        or sessions_list_count < matching_session_count
    ):
        raise ProbeError("persistent lifecycle sessions list count is inconsistent")
    runtime_launch_sources = _validate_runtime_launch_sources(runtime_launch_sources)

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
    runtime_launch_token_sha256 = _require_sha256_field(
        runtime_launch, "token_sha256", "runtime_launch"
    )
    runtime_launch_executable_sha256 = _require_sha256_field(
        runtime_launch, "executable_sha256", "runtime_launch"
    )
    paths = _optional_record(receipt.get("paths"))
    logs = _optional_record(candidate.get("logs"))
    candidate_env = _optional_record(candidate.get("env"))
    unexpected_provider_key_count = candidate_env.get("unexpected_provider_key_count")
    if (
        not isinstance(unexpected_provider_key_count, int)
        or isinstance(unexpected_provider_key_count, bool)
        or unexpected_provider_key_count != 0
    ):
        raise ProbeError("persistent lifecycle candidate environment includes provider secrets")
    _validate_gateway_endpoint(attestation.get("gateway_endpoint"), port=port)
    _require_non_empty_string(attestation, "gateway_build_id", "attestation")
    attestation_executable_sha256 = _require_sha256_field(
        attestation, "executable_content_sha256", "attestation"
    )
    if runtime_launch_executable_sha256 != attestation_executable_sha256:
        raise ProbeError("persistent lifecycle runtime launch executable is not attestation-bound")
    for key in (
        "catalog_sha256",
        "contract_vector_sha256",
        "rpc_transcript_sha256",
        "runtime_authored_rpc_evidence_sha256",
        "signed_payload_sha256",
        "runtime_identity_token_sha256",
    ):
        _require_sha256_field(attestation, key, "attestation")
    _require_epoch_ms_field(attestation, "expires_at_epoch_ms", "attestation")
    _require_epoch_ms_field(attestation, "captured_at_epoch_ms", "attestation")
    if attestation.get("runtime_identity_token_sha256") != runtime_launch_token_sha256:
        raise ProbeError("persistent lifecycle Gateway token is not attestation-bound")
    _validate_capability_preflight_artifact(
        run_root=run_root,
        preflight=preflight,
        required_tool_names=required_tool_names,
        pinned_run_root=pinned_run_root,
    )
    _validate_persistent_attestation_evidence(
        run_root=run_root,
        preflight=preflight,
        attestation=attestation,
        lifecycle=lifecycle,
        validation=validation,
        immutable_inputs=immutable_inputs,
        runtime_sources=runtime_sources,
        runtime_head=head,
        agentic_head=agentic_head,
        port=port,
        pinned_run_root=pinned_run_root,
    )
    persistent_evidence, _ = _read_run_json_artifact(
        run_root=run_root,
        pinned_run_root=pinned_run_root,
        value=preflight.get("persistent_evidence_file"),
        label="persistent attestation evidence",
    )
    raw_attestation = _record(
        persistent_evidence.get("attestation"), "persistent attestation evidence attestation"
    )
    response = _record(raw_attestation.get("response"), "persistent attestation response")
    rpc_evidence = _record(
        persistent_evidence.get("rpc_evidence"), "persistent attestation RPC evidence"
    )
    _reject_unsupported_persistent_rpc_records(rpc_evidence)
    tools_catalog = _record(
        rpc_evidence.get("tools_catalog"), "persistent attestation RPC evidence tools_catalog"
    )
    tools_catalog_response = _record(
        tools_catalog.get("response"), "persistent attestation tools_catalog response"
    )
    lifecycle_attestation = _lifecycle_attestation_record(lifecycle)
    _validate_independent_validation(
        validation,
        receipt_sha256=receipt_sha256,
        attestation_response_sha256=_canonical_sha256(response),
        tools_catalog_response_sha256=_canonical_sha256(tools_catalog_response),
        lifecycle_attestation=lifecycle_attestation,
        validation_anchor_key=validation_anchor_key,
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
        "duplicate_release_observed": True,
        "duplicate_release_identity_parity": True,
        "session_list_status_history_observed": True,
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
        "lifecycle_attestation": {
            "status": "pass",
            "schema_version": lifecycle_attestation.get("schema_version"),
            "record_authority": lifecycle_attestation.get("record_authority"),
            "authentication_authority": lifecycle_attestation.get(
                "authentication_authority"
            ),
            "record_transport": lifecycle_attestation.get("record_transport"),
            "observations_schema_version": lifecycle_attestation.get(
                "observations_schema_version"
            ),
            "lifecycle_sha256": lifecycle_attestation.get("lifecycle_sha256"),
            "sha256": _canonical_sha256(lifecycle_attestation),
            "signed_by": "independent_validation_hmac",
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
            **duplicate_release_identity,
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
            "run_root_sha256": _text_sha256(run_root_display),
            "receipt_sha256": receipt_sha256,
            "validation_sha256": _sha256_bytes(validation_bytes),
            "validation_receipt_sha256": validation.get("receipt_sha256"),
            "runtime_launch_sha256": _canonical_sha256(runtime_launch),
            "expected_run_id_sha256": _text_sha256(expected_run_id),
            "expected_transition_id_sha256": _text_sha256(expected_transition_id),
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
        "runtime_launch_sources": runtime_launch_sources,
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
    runtime_launch_sources: list[dict[str, str]],
    command: list[str],
    proc: subprocess.CompletedProcess[str],
    port: int,
    pinned_run_root: _PinnedRunRoot | None = None,
) -> dict[str, Any]:
    agentic_head = _git(ROOT, "rev-parse", "HEAD")
    if pinned_run_root is None:
        receipts_dir = run_root / "receipts"
        failure_receipt = (
            _read_json_file(
                receipts_dir / "failure-receipt.json", "persistent failure receipt"
            )
            if (receipts_dir / "failure-receipt.json").is_file()
            else {}
        )
        failure_cleanup = (
            _read_json_file(
                receipts_dir / "failure-cleanup.json", "persistent failure cleanup"
            )
            if (receipts_dir / "failure-cleanup.json").is_file()
            else {}
        )
        run_root_display = str(run_root.resolve())
    else:
        failure_receipt = _read_optional_pinned_receipt_json(
            pinned_run_root,
            "failure-receipt.json",
            "persistent failure receipt",
        )
        failure_cleanup = _read_optional_pinned_receipt_json(
            pinned_run_root,
            "failure-cleanup.json",
            "persistent failure cleanup",
        )
        run_root_display = str(pinned_run_root.original_path)
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
            "run_root_sha256": _text_sha256(run_root_display),
        },
        "agentic_sources": agentic_sources,
        "runtime_sources": runtime_sources,
        "runtime_launch_sources": runtime_launch_sources,
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


def _run_persistent_lifecycle_probe_once(
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
    validation_anchor_key: bytes,
    pinned_run_root: _PinnedRunRoot,
) -> dict[str, Any]:
    _assert_pinned_run_root_identity(pinned_run_root)
    evidence_dir = run_root / "evidence"
    runner_home = run_root / "runner-home"
    runner_state = run_root / "runner-state"
    runner_tmp = run_root / "runner-tmp"
    for directory in (runner_home, runner_state, runner_tmp):
        _prepare_private_directory(directory)
    _assert_pinned_run_root_identity(pinned_run_root)
    runner_env = _runner_base_env()
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
    node_executable, tsx_preload_specifier, runtime_launch_sources = (
        _runtime_launch_bindings(openclaw_root, runner_env)
    )
    command = [
        str(node_executable),
        "--import",
        tsx_preload_specifier,
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
        pid = getattr(exc, "pid", None)
        if isinstance(pid, int):
            proc.pid = pid  # type: ignore[attr-defined]
        process_group_cleanup_attempted, process_group_reaped = (
            _terminate_and_verify_process_group(proc)
        )
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            runtime_launch_sources=runtime_launch_sources,
            command=command,
            proc=proc,
            port=port,
            pinned_run_root=pinned_run_root,
        )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
        payload["fail_closed_matrix"].append(
            {
                "check": "timeout_process_group_cleanup",
                "status": "pass" if process_group_reaped and port_closed else "fail",
                "process_group_cleanup_attempted": process_group_cleanup_attempted,
                "process_group_reaped": process_group_reaped,
                "candidate_port_closed": port_closed,
            }
        )
        _write_validated_payload(evidence_file, payload)
        if not process_group_reaped:
            raise ProbeError(
                "persistent lifecycle runner timed out and candidate process group remained alive"
            ) from exc
        if not port_closed:
            raise ProbeError("persistent lifecycle runner timed out and candidate port remained open") from exc
        raise ProbeError(
            "persistent lifecycle runner timed out "
            f"evidence_file_sha256={_sha256_bytes(evidence_file.resolve().read_bytes())}"
        ) from exc
    _assert_pinned_run_root_identity(pinned_run_root)
    if proc.returncode != 0:
        process_group_cleanup_attempted, process_group_reaped = (
            _terminate_and_verify_process_group(proc)
        )
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            runtime_launch_sources=runtime_launch_sources,
            command=command,
            proc=proc,
            port=port,
            pinned_run_root=pinned_run_root,
        )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
        payload["fail_closed_matrix"].append(
            {
                "check": "failure_process_group_cleanup",
                "status": "pass" if process_group_reaped and port_closed else "fail",
                "process_group_cleanup_attempted": process_group_cleanup_attempted,
                "process_group_reaped": process_group_reaped,
                "candidate_port_closed": port_closed,
            }
        )
        _write_validated_payload(evidence_file, payload)
        if not process_group_reaped:
            raise ProbeError(
                "persistent lifecycle runner failed and candidate process group remained alive"
            )
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
        _assert_pinned_run_root_identity(pinned_run_root)
        if validate_candidate_root(openclaw_root) != head:
            raise ProbeError("OpenClaw candidate changed while the persistent runner was running")
        _assert_runtime_launch_sources_still_bound(
            openclaw_root=openclaw_root,
            runner_env=runner_env,
            expected_node_executable=node_executable,
            expected_tsx_preload_specifier=tsx_preload_specifier,
            expected_sources=runtime_launch_sources,
        )
        process_group_cleanup_attempted, process_group_reaped = (
            _terminate_and_verify_process_group(proc)
        )
        if not process_group_reaped:
            port_closed = _wait_for_loopback_port_closed(port)
            payload = _persistent_failure_summary(
                openclaw_root=openclaw_root,
                run_root=run_root,
                head=head,
                agentic_sources=agentic_sources,
                runtime_sources=runtime_sources,
                runtime_launch_sources=runtime_launch_sources,
                command=command,
                proc=proc,
                port=port,
                pinned_run_root=pinned_run_root,
            )
            payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
            payload["fail_closed_matrix"].append(
                {
                    "check": "pre_validator_process_group_cleanup",
                    "status": "fail",
                    "process_group_cleanup_attempted": process_group_cleanup_attempted,
                    "process_group_reaped": process_group_reaped,
                    "candidate_port_closed": port_closed,
                }
            )
            _write_validated_payload(evidence_file, payload)
            raise CandidateProcessGroupOpenError(
                "persistent lifecycle runner left candidate process group alive before validator"
            )
        receipt_file = _descriptor_path(pinned_run_root.receipts.fd) / (
            "lifecycle-receipt.json"
        )
        validation_file = _descriptor_path(pinned_run_root.receipts.fd) / (
            "independent-validation.json"
        )
        _run_independent_validator(
            validation_anchor_key=validation_anchor_key,
            pinned_run_root=pinned_run_root,
            agentic_sources=agentic_sources,
        )
        _assert_pinned_run_root_identity(pinned_run_root)
        payload = _persistent_lifecycle_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            receipt_file=receipt_file,
            validation_file=validation_file,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            runtime_launch_sources=runtime_launch_sources,
            command=command,
            proc=proc,
            port=port,
            expected_run_id=run_id,
            expected_transition_id=transition_id,
            validation_anchor_key=validation_anchor_key,
            pinned_run_root=pinned_run_root,
        )
        if not _wait_for_loopback_port_closed(port):
            process_group_cleanup_attempted = _terminate_process_group(proc)
            port_closed = _wait_for_loopback_port_closed(port)
            payload = _persistent_failure_summary(
                openclaw_root=openclaw_root,
                run_root=run_root,
                head=head,
                agentic_sources=agentic_sources,
                runtime_sources=runtime_sources,
                runtime_launch_sources=runtime_launch_sources,
                command=command,
                proc=proc,
                port=port,
                pinned_run_root=pinned_run_root,
            )
            payload["isolated_non_production_gateway"]["candidate_port_closed"] = port_closed
            payload["fail_closed_matrix"].append(
                {
                    "check": "post_success_port_closure",
                    "status": "fail",
                    "process_group_cleanup_attempted": process_group_cleanup_attempted,
                    "candidate_port_closed": port_closed,
                }
            )
            _write_validated_payload(evidence_file, payload)
            raise CandidatePortOpenError(
                "persistent lifecycle runner succeeded but candidate port remained open before cleanup"
            )
        payload["isolated_non_production_gateway"]["candidate_port_closed"] = True
        _assert_pinned_run_root_identity(pinned_run_root)
        _write_validated_payload(evidence_file, payload)
        return payload
    except Exception as exc:
        if isinstance(exc, (CandidatePortOpenError, CandidateProcessGroupOpenError)):
            raise
        process_group_cleanup_attempted = _terminate_process_group(proc)
        port_closed = _wait_for_loopback_port_closed(port)
        payload = _persistent_failure_summary(
            openclaw_root=openclaw_root,
            run_root=run_root,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            runtime_launch_sources=runtime_launch_sources,
            command=command,
            proc=proc,
            port=port,
            pinned_run_root=pinned_run_root,
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
    validation_anchor_key = _select_validation_anchor_key()
    prepared_run_root = _prepare_private_run_root(run_root)
    pinned_run_root = _pin_prepared_run_root(prepared_run_root)
    result: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        result = _run_persistent_lifecycle_probe_once(
            openclaw_root,
            evidence_file,
            timeout,
            head=head,
            agentic_sources=agentic_sources,
            runtime_sources=runtime_sources,
            run_root=prepared_run_root,
            port=port,
            run_id=run_id,
            transition_id=transition_id,
            validation_anchor_key=validation_anchor_key,
            pinned_run_root=pinned_run_root,
        )
    except BaseException as exc:
        primary_error = exc
    cleanup_error: ProbeError | None = None
    try:
        _remove_attestation_verification_key(pinned_run_root)
    except ProbeError as exc:
        cleanup_error = exc
    finally:
        pinned_run_root.close()
    if cleanup_error is not None:
        if primary_error is not None:
            raise ProbeError(
                f"{primary_error}; persistent attestation key cleanup also failed: "
                f"{cleanup_error}"
            ) from primary_error
        raise cleanup_error
    if primary_error is not None:
        raise primary_error.with_traceback(primary_error.__traceback__)
    if result is None:
        raise ProbeError("persistent lifecycle runner produced no result")
    return result


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
    selected_run_root = run_root if run_root is not None else _default_private_run_root(head)
    return _run_persistent_lifecycle_probe(
        openclaw_root,
        evidence_file,
        timeout,
        head=head,
        agentic_sources=agentic_sources,
        runtime_sources=runtime_sources,
        run_root=selected_run_root,
        port=port or PERSISTENT_LIFECYCLE_DEFAULT_PORT,
        run_id=run_id or "agentic-os-real-gateway-contract-probe",
        transition_id=transition_id or "persistent-lifecycle-runtime-readiness",
    )


def _persistent_validator_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="internal persistent validation writer")
    parser.add_argument("--run-root-path", type=Path)
    for name in ("root", *PINNED_RUN_SUBDIRECTORIES):
        parser.add_argument(f"--{name}-fd", type=int)
        parser.add_argument(f"--{name}-device", type=int)
        parser.add_argument(f"--{name}-inode", type=int)
    args = parser.parse_args(argv)
    pinned_run_root: _PinnedRunRoot | None = None
    try:
        pinned_values = {
            name: (
                getattr(args, f"{name}_fd"),
                getattr(args, f"{name}_device"),
                getattr(args, f"{name}_inode"),
            )
            for name in ("root", *PINNED_RUN_SUBDIRECTORIES)
        }
        if args.run_root_path is None or any(
            not all(isinstance(value, int) and value >= 0 for value in values)
            for values in pinned_values.values()
        ):
            raise ProbeError("persistent validator pinned fd contract is incomplete")
        pinned_run_root = _pinned_run_root_from_inherited_fds(
            original_path=args.run_root_path,
            root_fd=pinned_values["root"][0],
            keys_fd=pinned_values["keys"][0],
            receipts_fd=pinned_values["receipts"][0],
            evidence_fd=pinned_values["evidence"][0],
            expected_identities={
                name: (values[1], values[2]) for name, values in pinned_values.items()
            },
        )
        run_root = _descriptor_path(pinned_run_root.root.fd)
        receipt_file = _descriptor_path(pinned_run_root.receipts.fd) / (
            "lifecycle-receipt.json"
        )
        validation_file = _descriptor_path(pinned_run_root.receipts.fd) / (
            "independent-validation.json"
        )
        _write_independent_validation_file(
            run_root=run_root,
            receipt_file=receipt_file,
            validation_file=validation_file,
            pinned_run_root=pinned_run_root,
        )
    except ProbeError as exc:
        print(json.dumps({"status": "fail_closed", "error": str(exc)}, sort_keys=True))
        return 1
    finally:
        if pinned_run_root is not None:
            pinned_run_root.close()
    print(json.dumps({"status": "pass"}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["__persistent-validator"]:
        return _persistent_validator_main(argv[1:])
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
