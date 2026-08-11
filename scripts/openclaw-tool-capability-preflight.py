#!/usr/bin/env python3
"""Validate a captured OpenClaw runtime tool catalog before production RPC use."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import agentic_os
from agentic_os.openclaw_adapter import (
    AdapterContractError,
    assert_preflighted_runtime_authority,
    assert_installed_runtime_tools,
)


TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
JS_TOOL_NAME = re.compile(r"\b(?:id|name):\s*[\"']([A-Za-z][A-Za-z0-9_.-]*)[\"']")
JS_METHOD_NAME = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_.-]*)[\"']\s*:")
OBJECT_SCHEMA_FIELD = re.compile(
    r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_]*)\s*:\s*(?:Type\.|optionalStringEnum)",
    re.MULTILINE,
)
IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)

GATEWAY_RPC_METHOD_NAMES = (
    "subagents.allowLease.acquire",
    "subagents.allowLease.status",
    "subagents.allowLease.release",
)
MODEL_CALLABLE_TOOL_NAMES = (
    "sessions_spawn",
    "sessions_list",
    "sessions_history",
    "session_status",
    "sessions_status",
)
LIVE_TOOL_NAMES = (
    *GATEWAY_RPC_METHOD_NAMES,
    *MODEL_CALLABLE_TOOL_NAMES,
)

MODEL_TOOL_SCHEMA_MARKERS = {
    "sessions_spawn": "function createSessionsSpawnToolSchema",
    "sessions_list": "function createSessionsListToolSchema",
    "sessions_history": "function createSessionsHistoryToolSchema",
    "session_status": "function createSessionStatusToolSchema",
    "sessions_status": "function createSessionsStatusToolSchema",
}
RUNTIME_SOURCE_PATTERNS = (
    "openclaw-tools-*.js",
    "core-descriptors-*.js",
    "server-methods-*.js",
)
FUTURE_DB_AUTHORITY_CONTRACT = {
    "db_authority_enabled": bool(agentic_os.DB_AUTHORITY_ENABLED),
    "db_authority_enabled_required_for_preflight": False,
    "allow_lease_acquire_required_metadata": [
        "agent_id",
        "client_lease_id",
        "idempotency_key",
        "phase",
        "requester_agent_id",
        "run_id",
        "transition_id",
        "ttl_ms",
    ],
    "allow_lease_release_required_metadata": [
        "agent_id",
        "client_lease_id",
        "gateway_lease_id",
        "phase",
        "release_idempotency_key",
        "requester_agent_id",
        "run_id",
        "transition_id",
    ],
    "sessions_spawn_required_metadata": [
        "client_request_id",
        "idempotency_key",
        "metadata",
    ],
    "accepted_session_identity_requirement": (
        "future_db_authority_requires_duplicate_spawn_to_return_the_same_non_empty_"
        "accepted_session_identity"
    ),
    "future_canonical_status_method": "sessions_status",
}
STATUS_RPC_INCIDENTAL_MUTATIONS = (
    "expired_lease_cleanup",
    "cli_bootstrap_state",
)
EVIDENCE_CAPABILITY_SOURCE_PATHS = (
    "scripts/openclaw-tool-capability-preflight.py",
    "src/agentic_os/openclaw_adapter.py",
    "src/agentic_os/__init__.py",
)


class RuntimeEvidenceError(AdapterContractError):
    """AdapterContractError with sanitized runtime evidence attached."""

    def __init__(
        self,
        message: str,
        *,
        catalog: dict[str, Any] | None = None,
        catalog_failure: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.catalog = catalog
        self.catalog_failure = catalog_failure


def _candidate_install_roots(
    *,
    include_env_override: bool = True,
) -> Iterable[Path]:
    override = os.environ.get("OPENCLAW_INSTALL_ROOT", "").strip()
    if include_env_override and override:
        yield Path(override).expanduser()
    executable = shutil.which("openclaw")
    if executable:
        resolved = Path(executable).resolve()
        for parent in (resolved.parent, *resolved.parents):
            if parent.name == "openclaw":
                yield parent
            yield parent / "lib" / "node_modules" / "openclaw"
            yield parent / "node_modules" / "openclaw"
    yield Path("/opt/homebrew/lib/node_modules/openclaw")
    yield Path("/usr/local/lib/node_modules/openclaw")


def _resolve_install_root(
    *,
    include_env_override: bool = True,
    require_env_override: bool = False,
) -> Path:
    if require_env_override:
        override = os.environ.get("OPENCLAW_INSTALL_ROOT", "").strip()
        if not override:
            raise AdapterContractError(
                "isolated candidate OpenClaw preflight requires OPENCLAW_INSTALL_ROOT"
            )
        resolved = Path(override).expanduser().resolve()
        if _is_openclaw_runtime_bundle(resolved):
            return resolved
        raise AdapterContractError(
            "OPENCLAW_INSTALL_ROOT does not point to a valid OpenClaw runtime bundle"
        )
    seen: set[Path] = set()
    for candidate in _candidate_install_roots(include_env_override=include_env_override):
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if _is_openclaw_runtime_bundle(resolved):
            return resolved
    raise AdapterContractError("OpenClaw runtime bundle was not found")


def _is_openclaw_runtime_bundle(root: Path) -> bool:
    package_path = root / "package.json"
    if not (root / "dist").is_dir() or not package_path.is_file():
        return False
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(package, Mapping) and package.get("name") == "openclaw"


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_file_digest(payload: dict[str, Any], key: str, path: Path) -> None:
    try:
        payload[key] = _file_digest(path)
    except OSError as exc:
        payload[f"{key}_error"] = type(exc).__name__


def _require_file_digest(payload: dict[str, Any], key: str, path: Path) -> None:
    try:
        payload[key] = _file_digest(path)
    except OSError as exc:
        raise AdapterContractError(
            f"active OpenClaw executable could not be hashed: {type(exc).__name__}"
        ) from exc


def _path_digest(path: Path) -> str:
    return hashlib.sha256(path.resolve().as_posix().encode("utf-8")).hexdigest()


def _stream_digest(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _relative_source_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _source_record_from_snapshot(
    root: Path,
    path: Path,
    source_digest_snapshot: Mapping[str, str],
) -> dict[str, str]:
    relative = _relative_source_path(root, path)
    return {"path": relative, "sha256": source_digest_snapshot[relative]}


def _runtime_source_digest_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for pattern in RUNTIME_SOURCE_PATTERNS:
        for path in sorted((root / "dist").glob(pattern)):
            snapshot[_relative_source_path(root, path)] = _file_digest(path)
    return snapshot


def _read_dist_files(root: Path, pattern: str) -> list[tuple[Path, str]]:
    return [
        (path, path.read_text(encoding="utf-8", errors="ignore"))
        for path in sorted((root / "dist").glob(pattern))
    ]


def _strip_js_comments_and_strings(
    text: str, *, preserve_property_string_keys: bool = False
) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                output.append(char)
            else:
                output.append(" ")
            index += 1
            continue
        if in_block_comment:
            if char == "*" and nxt == "/":
                output.extend((" ", " "))
                in_block_comment = False
                index += 2
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue
        if char == "/" and nxt == "/":
            in_line_comment = True
            output.extend((" ", " "))
            index += 2
            continue
        if char == "/" and nxt == "*":
            in_block_comment = True
            output.extend((" ", " "))
            index += 2
            continue
        if char in {"'", '"', "`"}:
            parsed = _parse_js_string_literal(text, index)
            if parsed is not None:
                _, end = parsed
                cursor = _skip_js_whitespace(text, end)
                if (
                    preserve_property_string_keys
                    and cursor < len(text)
                    and text[cursor] == ":"
                ):
                    output.append(text[index:end])
                else:
                    output.append(" " * (end - index))
                index = end
                continue
            quote = char
            output.append(" ")
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _parse_js_string_literal(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] not in {"'", '"', "`"}:
        return None
    quote = text[start]
    escaped = False
    value: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if escaped:
            value.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return "".join(value), index + 1
        else:
            value.append(char)
        index += 1
    return None


def _skip_js_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _scan_js_declared_tool_names(text: str) -> set[str]:
    names: set[str] = set()
    index = 0
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            if char == "*" and nxt == "/":
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if char == "/" and nxt == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            in_block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            parsed = _parse_js_string_literal(text, index)
            if parsed is None:
                index += 1
                continue
            value, end = parsed
            cursor = _skip_js_whitespace(text, end)
            if value in {"id", "name"} and cursor < len(text) and text[cursor] == ":":
                cursor = _skip_js_whitespace(text, cursor + 1)
                next_parsed = _parse_js_string_literal(text, cursor)
                if next_parsed is not None:
                    tool_name, index = next_parsed
                    if TOOL_NAME.fullmatch(tool_name) and tool_name in LIVE_TOOL_NAMES:
                        names.add(tool_name)
                    continue
            index = end
            continue
        if char.isalpha() or char in {"_", "$"}:
            start = index
            index += 1
            while index < len(text) and (
                text[index].isalnum() or text[index] in {"_", "$"}
            ):
                index += 1
            key = text[start:index]
            if key not in {"id", "name"}:
                continue
            cursor = _skip_js_whitespace(text, index)
            if cursor >= len(text) or text[cursor] != ":":
                continue
            cursor = _skip_js_whitespace(text, cursor + 1)
            parsed = _parse_js_string_literal(text, cursor)
            if parsed is None:
                continue
            value, index = parsed
            if TOOL_NAME.fullmatch(value) and value in LIVE_TOOL_NAMES:
                names.add(value)
            continue
        index += 1
    return names


def _scan_js_string_key_names(text: str) -> set[str]:
    names: set[str] = set()
    index = 0
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            if char == "*" and nxt == "/":
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if char == "/" and nxt == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            in_block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            parsed = _parse_js_string_literal(text, index)
            if parsed is None:
                index += 1
                continue
            value, end = parsed
            cursor = _skip_js_whitespace(text, end)
            if (
                cursor < len(text)
                and text[cursor] == ":"
                and TOOL_NAME.fullmatch(value)
                and value in LIVE_TOOL_NAMES
            ):
                names.add(value)
            index = end
            continue
        index += 1
    return names


def _balanced_slice(text: str, start: int, opener: str, closer: str) -> str | None:
    if start < 0 or start >= len(text) or text[start] != opener:
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _function_block(text: str, marker: str) -> str | None:
    start = text.find(marker)
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None
    return _balanced_slice(text, brace, "{", "}")


def _type_object_argument(block: str) -> str | None:
    return_index = block.find("return")
    search_start = return_index if return_index >= 0 else 0
    call = block.find("Type.Object(", search_start)
    if call < 0:
        return None
    paren = block.find("(", call)
    wrapped = _balanced_slice(block, paren, "(", ")")
    if wrapped is None:
        return None
    return wrapped[1:-1].strip()


def _assigned_object_literal(block: str, name: str) -> str | None:
    pattern = re.compile(rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*{{")
    matches = list(pattern.finditer(block))
    for match in reversed(matches):
        literal = _balanced_slice(block, match.end() - 1, "{", "}")
        if literal is not None:
            return literal
    return None


def _top_level_schema_keys(object_text: str) -> set[str]:
    if not object_text.startswith("{"):
        return set()
    keys: set[str] = set()
    index = 1
    depth = 1
    quote: str | None = None
    escaped = False
    while index < len(object_text) - 1:
        char = object_text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            if depth == 1:
                parsed = _parse_js_string_literal(object_text, index)
                if parsed is not None:
                    name, end = parsed
                    cursor = _skip_js_whitespace(object_text, end)
                    if (
                        cursor < len(object_text)
                        and object_text[cursor] == ":"
                        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name)
                    ):
                        keys.add(name)
                    index = end
                    continue
            quote = char
            index += 1
            continue
        if char in "{([":
            depth += 1
            index += 1
            continue
        if char in "})]":
            depth -= 1
            index += 1
            continue
        if depth == 1 and (char.isalpha() or char == "_"):
            start = index
            index += 1
            while index < len(object_text) and (
                object_text[index].isalnum() or object_text[index] == "_"
            ):
                index += 1
            name = object_text[start:index]
            cursor = index
            while cursor < len(object_text) and object_text[cursor].isspace():
                cursor += 1
            if cursor < len(object_text) and object_text[cursor] == ":":
                keys.add(name)
            continue
        index += 1
    return keys


def _extract_returned_schema_fields(block: str) -> set[str]:
    argument = _type_object_argument(block)
    if argument is None:
        return set()
    if argument.startswith("{"):
        literal = _balanced_slice(argument, 0, "{", "}")
    elif IDENTIFIER.fullmatch(argument):
        literal = _assigned_object_literal(block, argument)
    else:
        literal = None
    return _top_level_schema_keys(literal) if literal is not None else set()


def _extract_model_tool_schemas(root: Path) -> tuple[dict[str, set[str]], list[Path]]:
    discovered: dict[str, set[str]] = {}
    sources: list[Path] = []
    candidates: dict[str, list[tuple[Path, set[str]]]] = {}
    for path, text in _read_dist_files(root, "openclaw-tools-*.js"):
        code_text = _strip_js_comments_and_strings(
            text,
            preserve_property_string_keys=True,
        )
        for name, marker in MODEL_TOOL_SCHEMA_MARKERS.items():
            block = _function_block(code_text, marker)
            if block is None:
                continue
            names = _extract_returned_schema_fields(block)
            if names:
                candidates.setdefault(name, []).append((path, names))
    for name, items in candidates.items():
        if len(items) == 1:
            path, names = items[0]
            discovered[name] = set(names)
            sources.append(path)
        else:
            sources.extend(path for path, _ in items)
    return discovered, sources


def _extract_gateway_method_params(root: Path) -> tuple[dict[str, set[str]], list[Path]]:
    methods: dict[str, set[str]] = {}
    sources: list[Path] = []
    candidates: dict[str, list[tuple[Path, set[str]]]] = {}
    for path, text in _read_dist_files(root, "server-methods-*.js"):
        for method in (
            "subagents.allowLease.status",
            "subagents.allowLease.acquire",
            "subagents.allowLease.release",
        ):
            start = text.find(f'"{method}"')
            if start < 0:
                continue
            next_method = text.find('"subagents.allowLease.', start + len(method))
            next_group = text.find("const coreGatewayHandlers", start)
            block_boundaries = [value for value in (next_method, next_group) if value > start]
            end = min(block_boundaries) if block_boundaries else start + 2000
            block = _strip_js_comments_and_strings(text[start:end])
            keys = re.findall(r"params\?\.([A-Za-z][A-Za-z0-9_]*)", block)
            if keys:
                candidates.setdefault(method, []).append((path, set(keys)))
    for method, items in candidates.items():
        if len(items) == 1:
            path, keys = items[0]
            methods[method] = set(keys)
            sources.append(path)
        else:
            sources.extend(path for path, _ in items)
    return methods, sources


def _declared_core_names(root: Path) -> tuple[set[str], list[Path]]:
    names: set[str] = set()
    sources: list[Path] = []
    for pattern, scanner in (
        ("openclaw-tools-*.js", _scan_js_declared_tool_names),
        ("core-descriptors-*.js", _scan_js_declared_tool_names),
        ("server-methods-*.js", _scan_js_string_key_names),
    ):
        for path, text in _read_dist_files(root, pattern):
            matched = scanner(text)
            if matched:
                names.update(matched)
                sources.append(path)
    return names, sources


def _resolve_openclaw_executable() -> Path:
    executable = shutil.which("openclaw")
    if not executable:
        raise AdapterContractError("openclaw executable was not found on PATH")
    return Path(executable).resolve()


def _require_executable_matches_install_root(root: Path, executable: Path) -> None:
    resolved_root = root.resolve()
    try:
        executable.relative_to(resolved_root)
    except ValueError as exc:
        raise AdapterContractError(
            "OPENCLAW_INSTALL_ROOT does not match the active openclaw executable"
        ) from exc


def _run_gateway_tools_catalog(
    executable: Path,
    timeout_ms: int = 10_000,
    *,
    scrub_env_override: bool = False,
    failure_catalog: dict[str, Any] | None = None,
) -> Any:
    env = None
    if scrub_env_override:
        env = dict(os.environ)
        env.pop("OPENCLAW_INSTALL_ROOT", None)
    try:
        proc = subprocess.run(
            [
                str(executable),
                "gateway",
                "call",
                "tools.catalog",
                "--json",
                "--timeout",
                str(timeout_ms),
                "--params",
                "{}",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5, timeout_ms // 1000 + 5),
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"active OpenClaw tool catalog unavailable: {type(exc).__name__}"
        raise RuntimeEvidenceError(
            message,
            catalog=failure_catalog,
            catalog_failure={
                "message": message,
                "exception_type": type(exc).__name__,
                "runtime_provenance_preserved": True,
            },
        ) from exc
    try:
        payload = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        message = (
            "active OpenClaw tool catalog returned non-JSON output "
            f"stdout={_stream_digest(proc.stdout or '')} "
            f"stderr={_stream_digest(proc.stderr or '')}"
        )
        raise RuntimeEvidenceError(
            message,
            catalog=failure_catalog,
            catalog_failure={
                "message": "active OpenClaw tool catalog returned non-JSON output",
                "stdout": _stream_digest(proc.stdout or ""),
                "stderr": _stream_digest(proc.stderr or ""),
                "runtime_provenance_preserved": True,
            },
        ) from exc
    if proc.returncode != 0:
        payload_sha = _json_sha256(payload) if isinstance(payload, Mapping) else None
        message = (
            "active OpenClaw tool catalog failed "
            f"returncode={proc.returncode} "
            f"payload_sha256={payload_sha} "
            f"stdout={_stream_digest(proc.stdout or '')} "
            f"stderr={_stream_digest(proc.stderr or '')}"
        )
        raise RuntimeEvidenceError(
            message,
            catalog=failure_catalog,
            catalog_failure={
                "message": "active OpenClaw tool catalog failed before contract validation",
                "payload_sha256": payload_sha,
                "returncode": proc.returncode,
                "runtime_provenance_preserved": True,
                "stderr": _stream_digest(proc.stderr or ""),
                "stdout": _stream_digest(proc.stdout or ""),
            },
        )
    return payload


def _gateway_rpc_validation_failure_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    source_bound_rpc_names: Iterable[str],
    status: str,
    error: str | None = None,
    response_sha256: str | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    returncode: int | None = None,
) -> dict[str, Any]:
    catalog = dict(runtime_identity_catalog)
    status_corroboration: dict[str, Any] = {
        "method": "subagents.allowLease.status",
        "request_semantics": "read_only_request",
        "requested_mutation": False,
        "incidental_mutations_possible": list(STATUS_RPC_INCIDENTAL_MUTATIONS),
        "status": status,
    }
    if error is not None:
        status_corroboration["error"] = error
    if response_sha256 is not None:
        status_corroboration["raw_response_sha256"] = response_sha256
    if stdout is not None:
        status_corroboration["stdout"] = _stream_digest(stdout)
    if stderr is not None:
        status_corroboration["stderr"] = _stream_digest(stderr)
    if returncode is not None:
        status_corroboration["returncode"] = returncode
    catalog["model_tool_catalog"] = {
        "catalog_kind": "model_callable_tools_catalog",
        "authority": "tools.catalog",
        "method": "tools.catalog",
    }
    if active_catalog_sha256 is not None:
        catalog["model_tool_catalog"]["raw_response_sha256"] = active_catalog_sha256
    catalog["gateway_rpc_catalog"] = {
        "catalog_kind": "source_bound_gateway_rpc_catalog",
        "authority": "installed_runtime_dist_sources",
        "source_bound_rpc_names": sorted(source_bound_rpc_names),
        "status": "status_corroboration_failed",
        "status_corroboration": status_corroboration,
    }
    return catalog


def _run_gateway_allow_lease_status(
    executable: Path,
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    source_bound_rpc_names: Iterable[str],
    timeout_ms: int = 10_000,
    scrub_env_override: bool = False,
) -> dict[str, Any]:
    env = None
    if scrub_env_override:
        env = dict(os.environ)
        env.pop("OPENCLAW_INSTALL_ROOT", None)
    try:
        proc = subprocess.run(
            [
                str(executable),
                "gateway",
                "call",
                "subagents.allowLease.status",
                "--json",
                "--timeout",
                str(timeout_ms),
                "--params",
                "{}",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5, timeout_ms // 1000 + 5),
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        catalog = _gateway_rpc_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_bound_rpc_names=source_bound_rpc_names,
            status="status_rpc_unavailable",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw Gateway status RPC unavailable",
            catalog=catalog,
        ) from exc
    try:
        payload = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        catalog = _gateway_rpc_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_bound_rpc_names=source_bound_rpc_names,
            status="status_rpc_non_json",
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw Gateway status RPC returned non-JSON output",
            catalog=catalog,
        ) from exc
    response_sha256 = _json_sha256(payload)
    if proc.returncode != 0:
        catalog = _gateway_rpc_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_bound_rpc_names=source_bound_rpc_names,
            status="status_rpc_failed",
            response_sha256=response_sha256,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw Gateway status RPC failed before contract validation",
            catalog=catalog,
        )
    if not isinstance(payload, Mapping):
        catalog = _gateway_rpc_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_bound_rpc_names=source_bound_rpc_names,
            status="status_rpc_response_shape_invalid",
            error=type(payload).__name__,
            response_sha256=response_sha256,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw Gateway status RPC response must be a JSON object",
            catalog=catalog,
        )
    status_payload = payload.get("result")
    if not isinstance(status_payload, Mapping):
        status_payload = payload
    ok_value = status_payload.get("ok")
    if ok_value is not True:
        catalog = _gateway_rpc_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_bound_rpc_names=source_bound_rpc_names,
            status="status_rpc_returned_not_ok",
            error=type(ok_value).__name__ if ok_value is not None else "missing_ok",
            response_sha256=response_sha256,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw Gateway status RPC did not return ok=true",
            catalog=catalog,
        )
    corroboration: dict[str, Any] = {
        "method": "subagents.allowLease.status",
        "request_semantics": "read_only_request",
        "requested_mutation": False,
        "incidental_mutations_possible": list(STATUS_RPC_INCIDENTAL_MUTATIONS),
        "live_reachability": "reachable",
        "status": "ok",
        "raw_response_sha256": response_sha256,
        "ok": True,
    }
    write_mode = status_payload.get("writeMode")
    if isinstance(write_mode, str):
        corroboration["writeMode"] = write_mode
    allow_agents = status_payload.get("allowAgents")
    if isinstance(allow_agents, list):
        corroboration["allowAgents_count"] = len(allow_agents)
    leases = status_payload.get("leases")
    if isinstance(leases, list):
        corroboration["leases_count"] = len(leases)
    return corroboration


def _runtime_identity_catalog(
    *,
    runtime_target: str,
    package: Mapping[str, Any],
    package_json_digest: str,
    root: Path,
    executable: Path,
    executable_digest: str,
) -> dict[str, Any]:
    return {
        "catalog_kind": "sanitized_openclaw_runtime",
        "runtime_target": runtime_target,
        "openclaw_version": package.get("version"),
        "openclaw_package_name": package.get("name"),
        "package_json_sha256": package_json_digest,
        "install_root_basename": root.name,
        "install_root_path_sha256": _path_digest(root),
        "active_executable_path_sha256": _path_digest(executable),
        "active_executable_sha256": executable_digest,
    }


def _runtime_failure_catalog_from_identity(
    *,
    runtime_target: str,
    package: Mapping[str, Any],
    package_json_digest: str,
    root: Path,
    executable: Path,
    executable_digest: str,
) -> dict[str, Any]:
    catalog = _runtime_identity_catalog(
        runtime_target=runtime_target,
        package=package,
        package_json_digest=package_json_digest,
        root=root,
        executable=executable,
        executable_digest=executable_digest,
    )
    catalog["catalog_capture"] = {
        "method": "tools.catalog",
        "status": "catalog_unavailable_before_contract_validation",
        "validation_stage": "catalog_capture",
    }
    return catalog


def _runtime_identity_snapshot_failure_catalog(
    *,
    runtime_target: str,
    root: Path,
    executable: Path,
    error: str,
) -> dict[str, Any]:
    catalog: dict[str, Any] = {
        "catalog_kind": "sanitized_openclaw_runtime",
        "runtime_target": runtime_target,
        "install_root_basename": root.name,
        "install_root_path_sha256": _path_digest(root),
        "active_executable_path_sha256": _path_digest(executable),
        "catalog_capture": {
            "method": "tools.catalog",
            "status": "runtime_identity_snapshot_failed",
            "validation_stage": "runtime_identity_snapshot",
            "identity_verification_error": error,
        },
    }
    _record_file_digest(catalog, "active_executable_sha256", executable)
    _record_file_digest(catalog, "package_json_sha256", root / "package.json")
    return catalog


def _runtime_identity_snapshot(
    *,
    runtime_target: str,
    include_env_override: bool,
    require_env_override: bool,
) -> tuple[Path, Path, Mapping[str, Any], dict[str, Any], dict[str, Any]]:
    root = _resolve_install_root(
        include_env_override=include_env_override,
        require_env_override=require_env_override,
    )
    executable = _resolve_openclaw_executable()
    _require_executable_matches_install_root(root, executable)
    package_path = root / "package.json"
    try:
        package_raw = package_path.read_bytes()
        package_json_digest = hashlib.sha256(package_raw).hexdigest()
        package = json.loads(package_raw.decode("utf-8"))
        if not isinstance(package, Mapping):
            raise AdapterContractError("OpenClaw package.json must be a JSON object")
    except (OSError, json.JSONDecodeError, AdapterContractError) as exc:
        catalog = _runtime_identity_snapshot_failure_catalog(
            runtime_target=runtime_target,
            root=root,
            executable=executable,
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime identity could not be snapshotted before catalog capture",
            catalog=catalog,
        ) from exc
    try:
        executable_digest = _file_digest(executable)
    except OSError as exc:
        raise AdapterContractError(
            f"active OpenClaw executable could not be hashed: {type(exc).__name__}"
        ) from exc
    failure_catalog = _runtime_failure_catalog_from_identity(
        runtime_target=runtime_target,
        package=package,
        package_json_digest=package_json_digest,
        root=root,
        executable=executable,
        executable_digest=executable_digest,
    )
    positive_catalog = _runtime_identity_catalog(
        runtime_target=runtime_target,
        package=package,
        package_json_digest=package_json_digest,
        root=root,
        executable=executable,
        executable_digest=executable_digest,
    )
    return root, executable, package, positive_catalog, failure_catalog


def _catalog_parameter_names(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            return {str(key) for key in properties}
        return {str(key) for key in value}
    if isinstance(value, list):
        names: set[str] = set()
        for item in value:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, Mapping):
                name = item.get("name")
                if isinstance(name, str) and name:
                    names.add(name)
        return names
    return set()


def _active_entry_parameters(entry: Mapping[str, Any]) -> set[str]:
    candidates: list[tuple[str, set[str]]] = []
    for key in ("parameters", "input_schema", "inputSchema"):
        if key in entry:
            candidates.append((key, _catalog_parameter_names(entry[key])))
    schema = entry.get("schema")
    if isinstance(schema, Mapping):
        for key in ("parameters", "input_schema", "inputSchema"):
            if key in schema:
                candidates.append((f"schema.{key}", _catalog_parameter_names(schema[key])))
    if not candidates:
        return set()
    first_label, first_params = candidates[0]
    for label, params in candidates[1:]:
        if params != first_params:
            raise AdapterContractError(
                "active OpenClaw tool catalog has conflicting schema forms: "
                f"{first_label}={sorted(first_params)} {label}={sorted(params)}"
            )
    return set(first_params)


def _active_entry_has_parameter_schema(entry: Mapping[str, Any]) -> bool:
    if any(key in entry for key in ("parameters", "input_schema", "inputSchema")):
        return True
    schema = entry.get("schema")
    return isinstance(schema, Mapping) and any(
        key in schema for key in ("parameters", "input_schema", "inputSchema")
    )


def _adapter_tool_name(entry: Mapping[str, Any]) -> str | None:
    for key in ("name", "method", "id"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value if value in LIVE_TOOL_NAMES else None
    return None


def _active_tool_parameter_evidence(
    catalog: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}

    def add_entry(name: str, entry: Mapping[str, Any]) -> None:
        if name not in LIVE_TOOL_NAMES:
            return
        if name in entries:
            raise AdapterContractError(f"active OpenClaw tool catalog has duplicate {name} entries")
        entries[name] = {
            "parameters": _active_entry_parameters(entry),
            "schema_available": _active_entry_has_parameter_schema(entry),
        }

    groups = catalog.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, Mapping):
                continue
            tools = group.get("tools")
            if not isinstance(tools, list):
                continue
            for tool in tools:
                if not isinstance(tool, Mapping):
                    continue
                name = _adapter_tool_name(tool)
                if name is not None:
                    add_entry(name, tool)
    tools = catalog.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            name = _adapter_tool_name(tool)
            if name is not None:
                add_entry(name, tool)
    elif isinstance(tools, Mapping):
        for name, value in tools.items():
            if isinstance(name, str) and name in LIVE_TOOL_NAMES:
                entry = value if isinstance(value, Mapping) else {}
                add_entry(name, entry)
    return entries


def _active_tool_parameters(catalog: Mapping[str, Any]) -> dict[str, set[str]]:
    return {
        name: set(evidence["parameters"])
        for name, evidence in _active_tool_parameter_evidence(catalog).items()
    }


def _active_catalog_validation_failure_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str,
    validation_stage: str = "active_tool_parameters",
    required_tool_names: list[str] | None = None,
) -> dict[str, Any]:
    catalog = dict(runtime_identity_catalog)
    catalog.update(
        {
            "required_canonical_session_status_method": "sessions_status",
            "active_catalog": {
                "method": "tools.catalog",
                "status": "contract_validation_failed",
                "validation_stage": validation_stage,
                "raw_response_sha256": active_catalog_sha256,
            },
        }
    )
    if required_tool_names is not None:
        catalog["active_catalog"]["required_tool_names"] = required_tool_names
    return catalog


def _runtime_identity_binding_failure_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    status: str,
    error: str | None = None,
) -> dict[str, Any]:
    catalog = dict(runtime_identity_catalog)
    catalog["active_catalog"] = {
        "method": "tools.catalog",
        "status": status,
        "validation_stage": "runtime_identity_binding",
    }
    if active_catalog_sha256 is not None:
        catalog["active_catalog"]["raw_response_sha256"] = active_catalog_sha256
    if error is not None:
        catalog["active_catalog"]["identity_verification_error"] = error
    return catalog


def _runtime_source_binding_failure_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    status: str,
    expected_sources: Mapping[str, str] | None = None,
    observed_sources: Mapping[str, str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    catalog = dict(runtime_identity_catalog)
    catalog["active_catalog"] = {
        "method": "tools.catalog",
        "status": status,
        "validation_stage": "runtime_source_binding",
    }
    if active_catalog_sha256 is not None:
        catalog["active_catalog"]["raw_response_sha256"] = active_catalog_sha256
    if error is not None:
        catalog["active_catalog"]["source_verification_error"] = error
    if expected_sources is not None:
        catalog["runtime_source_binding"] = {
            "expected_sources": dict(sorted(expected_sources.items())),
            "observed_sources": dict(sorted((observed_sources or {}).items())),
        }
    return catalog


def _require_runtime_identity_unchanged_after_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    runtime_target: str,
    include_env_override: bool,
    require_env_override: bool,
    active_catalog_sha256: str | None,
) -> None:
    try:
        _, _, _, current_identity, _ = _runtime_identity_snapshot(
            runtime_target=runtime_target,
            include_env_override=include_env_override,
            require_env_override=require_env_override,
        )
    except RuntimeEvidenceError as exc:
        catalog = _runtime_identity_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_identity_verification_failed",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime identity could not be verified after catalog capture",
            catalog=catalog,
        ) from exc
    except (AdapterContractError, OSError, json.JSONDecodeError) as exc:
        catalog = _runtime_identity_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_identity_verification_failed",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime identity could not be verified after catalog capture",
            catalog=catalog,
        ) from exc
    if current_identity != dict(runtime_identity_catalog):
        catalog = _runtime_identity_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_identity_changed_after_catalog_capture",
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime identity changed during catalog capture",
            catalog=catalog,
        )


def _require_runtime_sources_unchanged_after_scan(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    source_digest_snapshot: Mapping[str, str],
    root: Path,
) -> None:
    try:
        observed_sources = _runtime_source_digest_snapshot(root)
    except OSError as exc:
        catalog = _runtime_source_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_source_verification_failed",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime sources could not be verified after catalog capture",
            catalog=catalog,
        ) from exc
    if dict(source_digest_snapshot) != observed_sources:
        catalog = _runtime_source_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_sources_changed_after_catalog_capture",
            expected_sources=source_digest_snapshot,
            observed_sources=observed_sources,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime sources changed during catalog capture",
            catalog=catalog,
        )


def _scan_runtime_source_contract(
    *,
    root: Path,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
) -> tuple[
    dict[str, set[str]],
    list[Path],
    dict[str, set[str]],
    list[Path],
    set[str],
    list[Path],
]:
    try:
        model_tool_params, model_tool_sources = _extract_model_tool_schemas(root)
        gateway_params, gateway_sources = _extract_gateway_method_params(root)
        declared_names, declaration_sources = _declared_core_names(root)
    except OSError as exc:
        catalog = _runtime_source_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            status="runtime_source_scan_failed",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime sources could not be scanned after catalog capture",
            catalog=catalog,
        ) from exc
    return (
        model_tool_params,
        model_tool_sources,
        gateway_params,
        gateway_sources,
        declared_names,
        declaration_sources,
    )


def _source_bound_gateway_rpc_names(
    *,
    gateway_params: Mapping[str, set[str]],
    declared_names: set[str],
) -> set[str]:
    return {
        name
        for name in GATEWAY_RPC_METHOD_NAMES
        if name in gateway_params or name in declared_names
    }


def _gateway_status_for_source_bound_names(
    *,
    executable: Path,
    runtime_identity_catalog: Mapping[str, Any],
    active_catalog_sha256: str | None,
    source_bound_rpc_names: set[str],
    scrub_env_override: bool,
) -> dict[str, Any]:
    if "subagents.allowLease.status" not in source_bound_rpc_names:
        return {
            "method": "subagents.allowLease.status",
            "request_semantics": "read_only_request",
            "requested_mutation": False,
            "incidental_mutations_possible": list(STATUS_RPC_INCIDENTAL_MUTATIONS),
            "live_reachability": "unproven",
            "status": "disk_source_declaration_missing",
        }
    return _run_gateway_allow_lease_status(
        executable,
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
        source_bound_rpc_names=source_bound_rpc_names,
        scrub_env_override=scrub_env_override,
    )


def _gateway_catalog_status(
    source_bound_rpc_names: set[str],
) -> str:
    if set(GATEWAY_RPC_METHOD_NAMES).issubset(source_bound_rpc_names):
        return "disk_source_declarations_complete"
    return "partial_source_bound"


def _gateway_rpc_evidence(
    *,
    source_bound_rpc_names: set[str],
    gateway_status: Mapping[str, Any],
) -> list[dict[str, Any]]:
    status_reachable = gateway_status.get("status") == "ok"
    return [
        {
            "name": name,
            "disk_source_declaration": (
                "observed"
                if name in source_bound_rpc_names
                else "not_observed"
            ),
            "live_reachability": (
                "reachable"
                if name == "subagents.allowLease.status" and status_reachable
                else "unproven"
            ),
        }
        for name in GATEWAY_RPC_METHOD_NAMES
    ]


def _gateway_tools_from_sources(
    *,
    gateway_params: Mapping[str, set[str]],
    source_bound_rpc_names: set[str],
) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for name in GATEWAY_RPC_METHOD_NAMES:
        if name not in source_bound_rpc_names:
            continue
        params = sorted(gateway_params.get(name, set()))
        source_kind = (
            "gateway_server_method_params"
            if name in gateway_params
            else "declared_gateway_rpc_name"
        )
        tools.append(
            {
                "name": name,
                "parameters": params,
                "catalog_surface": "gateway_rpc",
                "schema_source": source_kind,
            }
        )
    return tools


def _status_alias_requirement(
    *,
    active_names: set[str],
    model_tool_params: Mapping[str, set[str]],
    declared_names: set[str],
    model_catalog_available: bool,
) -> dict[str, Any]:
    return {
        "future_canonical_status_method": "sessions_status",
        "future_canonical_status_method_status": (
            "available"
            if "sessions_status" in active_names
            else (
                "unproven_model_catalog_unavailable"
                if not model_catalog_available
                else "missing_from_model_callable_tools_catalog"
            )
        ),
        "legacy_status_alias": "session_status",
        "observed_model_status_aliases": sorted(
            name
            for name in ("session_status", "sessions_status")
            if name in active_names or name in model_tool_params or name in declared_names
        ),
        "future_canonical_status_alias_available": "sessions_status" in active_names,
        "db_authority_requirement": "future_db_authority_requires_canonical_sessions_status",
    }


def _tools_catalog_failure_sha(catalog_failure: Mapping[str, Any] | None) -> str | None:
    if catalog_failure is None:
        return None
    payload_sha = catalog_failure.get("payload_sha256")
    return payload_sha if isinstance(payload_sha, str) else None


def _model_catalog_unavailable_catalog(
    *,
    runtime_identity_catalog: Mapping[str, Any],
    catalog_failure: Mapping[str, Any] | None,
    model_tool_params: Mapping[str, set[str]],
    gateway_params: Mapping[str, set[str]],
    declared_names: set[str],
    source_bound_rpc_names: set[str],
    gateway_status: Mapping[str, Any],
    source_paths: Iterable[Path],
    source_digest_snapshot: Mapping[str, str],
    root: Path,
) -> dict[str, Any]:
    failure_sha = _tools_catalog_failure_sha(catalog_failure)
    gateway_tools = _gateway_tools_from_sources(
        gateway_params=gateway_params,
        source_bound_rpc_names=source_bound_rpc_names,
    )
    model_tool_catalog: dict[str, Any] = {
        "catalog_kind": "model_callable_tools_catalog",
        "authority": "tools.catalog",
        "method": "tools.catalog",
        "status": "catalog_unavailable_before_contract_validation",
        "validation_stage": "catalog_capture",
        "required_tool_names": [],
        "source_declared_tool_names": sorted(
            name for name in MODEL_CALLABLE_TOOL_NAMES if name in declared_names
        ),
    }
    if failure_sha is not None:
        model_tool_catalog["failure_payload_sha256"] = failure_sha
    return {
        **runtime_identity_catalog,
        "required_canonical_session_status_method": "sessions_status",
        "future_db_authority_contract": dict(FUTURE_DB_AUTHORITY_CONTRACT),
        "runtime_process_binding_limit": (
            "installed dist source identity does not prove the connected Gateway "
            "process is executing that exact bundle"
        ),
        "connected_gateway_build_identity": "unproven",
        "status_alias_requirement": _status_alias_requirement(
            active_names=set(),
            model_tool_params=model_tool_params,
            declared_names=declared_names,
            model_catalog_available=False,
        ),
        "active_catalog": {
            "method": "tools.catalog",
            "status": "catalog_unavailable_before_contract_validation",
            "validation_stage": "catalog_capture",
            **({"failure_payload_sha256": failure_sha} if failure_sha else {}),
        },
        "model_tool_catalog": model_tool_catalog,
        "gateway_rpc_catalog": {
            "catalog_kind": "source_bound_gateway_rpc_catalog",
            "authority": "installed_runtime_dist_sources",
            "status": _gateway_catalog_status(source_bound_rpc_names),
            "source_bound_rpc_names": sorted(source_bound_rpc_names),
            "rpc_evidence": _gateway_rpc_evidence(
                source_bound_rpc_names=source_bound_rpc_names,
                gateway_status=gateway_status,
            ),
            "status_corroboration": gateway_status,
            "tools": gateway_tools,
        },
        "sources": [
            _source_record_from_snapshot(root, path, source_digest_snapshot)
            for path in sorted(source_paths)
        ],
        "tools": gateway_tools,
    }


def live_installed_openclaw_catalog(
    *,
    runtime_target: str = "live_installed_openclaw",
    include_env_override: bool = True,
    require_env_override: bool = False,
    scrub_env_override: bool = False,
) -> dict[str, Any]:
    root, executable, package, runtime_identity_catalog, failure_catalog = _runtime_identity_snapshot(
        runtime_target=runtime_target,
        include_env_override=include_env_override,
        require_env_override=require_env_override,
    )
    try:
        source_digest_snapshot = _runtime_source_digest_snapshot(root)
    except OSError as exc:
        catalog = _runtime_source_binding_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=None,
            status="runtime_source_snapshot_failed",
            error=type(exc).__name__,
        )
        raise RuntimeEvidenceError(
            "active OpenClaw runtime sources could not be snapshotted before catalog capture",
            catalog=catalog,
        ) from exc
    try:
        active_catalog = _run_gateway_tools_catalog(
            executable,
            scrub_env_override=scrub_env_override,
            failure_catalog=failure_catalog,
        )
    except RuntimeEvidenceError as exc:
        active_catalog_sha256 = _tools_catalog_failure_sha(exc.catalog_failure)
        (
            model_tool_params,
            model_tool_sources,
            gateway_params,
            gateway_sources,
            declared_names,
            declaration_sources,
        ) = _scan_runtime_source_contract(
            root=root,
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
        )
        _require_runtime_sources_unchanged_after_scan(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_digest_snapshot=source_digest_snapshot,
            root=root,
        )
        source_bound_rpc_names = _source_bound_gateway_rpc_names(
            gateway_params=gateway_params,
            declared_names=declared_names,
        )
        try:
            gateway_status = _gateway_status_for_source_bound_names(
                executable=executable,
                runtime_identity_catalog=runtime_identity_catalog,
                active_catalog_sha256=active_catalog_sha256,
                source_bound_rpc_names=source_bound_rpc_names,
                scrub_env_override=scrub_env_override,
            )
        except RuntimeEvidenceError as status_exc:
            status_catalog = status_exc.catalog or {}
            gateway_catalog = status_catalog.get("gateway_rpc_catalog", {})
            if isinstance(gateway_catalog, Mapping):
                corroboration = gateway_catalog.get("status_corroboration", {})
            else:
                corroboration = {}
            gateway_status = (
                dict(corroboration)
                if isinstance(corroboration, Mapping)
                else {
                    "method": "subagents.allowLease.status",
                    "request_semantics": "read_only_request",
                    "requested_mutation": False,
                    "incidental_mutations_possible": list(
                        STATUS_RPC_INCIDENTAL_MUTATIONS
                    ),
                    "live_reachability": "unproven",
                    "status": "status_corroboration_failed",
                }
            )
        _require_runtime_sources_unchanged_after_scan(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            source_digest_snapshot=source_digest_snapshot,
            root=root,
        )
        source_paths = {
            *model_tool_sources,
            *gateway_sources,
            *declaration_sources,
        }
        split_catalog = _model_catalog_unavailable_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            catalog_failure=exc.catalog_failure,
            model_tool_params=model_tool_params,
            gateway_params=gateway_params,
            declared_names=declared_names,
            source_bound_rpc_names=source_bound_rpc_names,
            gateway_status=gateway_status,
            source_paths=source_paths,
            source_digest_snapshot=source_digest_snapshot,
            root=root,
        )
        raise RuntimeEvidenceError(
            str(exc)
            + "; model-callable tools.catalog is unavailable, so future "
            "DB-authority metadata/idempotency/accepted-session/status-alias "
            "requirements remain unproven",
            catalog=split_catalog,
            catalog_failure=exc.catalog_failure,
        ) from exc
    active_catalog_sha256 = _json_sha256(active_catalog)
    _require_runtime_identity_unchanged_after_catalog(
        runtime_identity_catalog=runtime_identity_catalog,
        runtime_target=runtime_target,
        include_env_override=include_env_override,
        require_env_override=require_env_override,
        active_catalog_sha256=active_catalog_sha256,
    )
    if not isinstance(active_catalog, Mapping):
        validation_catalog = _active_catalog_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            validation_stage="active_catalog_shape",
        )
        validation_catalog["active_catalog"]["observed_json_type"] = type(
            active_catalog
        ).__name__
        raise RuntimeEvidenceError(
            "active OpenClaw tool catalog must be a JSON object",
            catalog=validation_catalog,
        )
    try:
        active_parameter_evidence = _active_tool_parameter_evidence(active_catalog)
    except AdapterContractError as exc:
        validation_catalog = _active_catalog_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
        )
        raise RuntimeEvidenceError(str(exc), catalog=validation_catalog) from exc
    active_names = set(active_parameter_evidence)
    if not active_parameter_evidence:
        exc = AdapterContractError("active OpenClaw tool catalog did not expose required tools")
        validation_catalog = _active_catalog_validation_failure_catalog(
            runtime_identity_catalog=runtime_identity_catalog,
            active_catalog_sha256=active_catalog_sha256,
            required_tool_names=sorted(active_names),
        )
        raise RuntimeEvidenceError(str(exc), catalog=validation_catalog) from exc
    (
        model_tool_params,
        model_tool_sources,
        gateway_params,
        gateway_sources,
        declared_names,
        declaration_sources,
    ) = _scan_runtime_source_contract(
        root=root,
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
    )
    _require_runtime_sources_unchanged_after_scan(
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
        source_digest_snapshot=source_digest_snapshot,
        root=root,
    )
    _require_runtime_identity_unchanged_after_catalog(
        runtime_identity_catalog=runtime_identity_catalog,
        runtime_target=runtime_target,
        include_env_override=include_env_override,
        require_env_override=require_env_override,
        active_catalog_sha256=active_catalog_sha256,
    )
    _require_runtime_sources_unchanged_after_scan(
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
        source_digest_snapshot=source_digest_snapshot,
        root=root,
    )
    source_bound_rpc_names = _source_bound_gateway_rpc_names(
        gateway_params=gateway_params,
        declared_names=declared_names,
    )
    gateway_status = _gateway_status_for_source_bound_names(
        executable=executable,
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
        source_bound_rpc_names=source_bound_rpc_names,
        scrub_env_override=scrub_env_override,
    )
    _require_runtime_identity_unchanged_after_catalog(
        runtime_identity_catalog=runtime_identity_catalog,
        runtime_target=runtime_target,
        include_env_override=include_env_override,
        require_env_override=require_env_override,
        active_catalog_sha256=active_catalog_sha256,
    )
    _require_runtime_sources_unchanged_after_scan(
        runtime_identity_catalog=runtime_identity_catalog,
        active_catalog_sha256=active_catalog_sha256,
        source_digest_snapshot=source_digest_snapshot,
        root=root,
    )
    tools: list[dict[str, Any]] = []
    gateway_tools = _gateway_tools_from_sources(
        gateway_params=gateway_params,
        source_bound_rpc_names=source_bound_rpc_names,
    )
    model_tools: list[dict[str, Any]] = []
    tools.extend(gateway_tools)
    for name in MODEL_CALLABLE_TOOL_NAMES:
        declared = name in declared_names
        active = name in active_names
        source_params = set(model_tool_params.get(name, set()))
        source_kind = "model_tool_schema" if declared and name in model_tool_params else "absent"
        if declared and active and source_kind == "absent":
            source_kind = "declared_tool_name"
        if active and declared:
            catalog_params = set(active_parameter_evidence[name]["parameters"])
            catalog_schema_available = bool(
                active_parameter_evidence[name]["schema_available"]
            )
            if catalog_schema_available:
                params = sorted(catalog_params & source_params)
                parameter_evidence = {
                    "status": "catalog_schema_intersected_with_installed_source",
                    "catalog_schema_available": True,
                    "catalog_parameters": sorted(catalog_params),
                    "parameter_authority": [
                        "tools.catalog",
                        "installed_runtime_dist_sources",
                    ],
                }
            elif name in model_tool_params:
                params = sorted(source_params)
                parameter_evidence = {
                    "status": "installed_source_bound_catalog_schema_unavailable",
                    "catalog_schema_available": False,
                    "parameter_authority": "installed_runtime_dist_sources",
                }
            else:
                params = []
                parameter_evidence = {
                    "status": "unproven_from_catalog_and_installed_sources",
                    "catalog_schema_available": False,
                    "parameter_authority": "unproven",
                }
            tool = {
                "name": name,
                "parameters": params,
                "catalog_surface": "model_tool",
                "schema_source": source_kind,
                "parameter_evidence": parameter_evidence,
            }
            model_tools.append(tool)
            tools.append(tool)
    source_paths = sorted({*model_tool_sources, *gateway_sources, *declaration_sources})
    model_tool_names = sorted(active_names & set(MODEL_CALLABLE_TOOL_NAMES))
    model_tools_with_catalog_schema = sorted(
        name
        for name in model_tool_names
        if active_parameter_evidence[name]["schema_available"]
    )
    model_tools_without_catalog_schema = sorted(
        set(model_tool_names) - set(model_tools_with_catalog_schema)
    )
    return {
        **runtime_identity_catalog,
        "required_canonical_session_status_method": "sessions_status",
        "future_db_authority_contract": dict(FUTURE_DB_AUTHORITY_CONTRACT),
        "runtime_process_binding_limit": (
            "installed dist source identity does not prove the connected Gateway "
            "process is executing that exact bundle"
        ),
        "connected_gateway_build_identity": "unproven",
        "status_alias_requirement": _status_alias_requirement(
            active_names=active_names,
            model_tool_params=model_tool_params,
            declared_names=declared_names,
            model_catalog_available=True,
        ),
        "active_catalog": {
            "method": "tools.catalog",
            "raw_response_sha256": active_catalog_sha256,
            "required_tool_names": sorted(active_names),
            "parameter_schema_tool_names": model_tools_with_catalog_schema,
            "parameter_schema_unavailable_tool_names": (
                model_tools_without_catalog_schema
            ),
        },
        "model_tool_catalog": {
            "catalog_kind": "model_callable_tools_catalog",
            "authority": "tools.catalog",
            "method": "tools.catalog",
            "raw_response_sha256": active_catalog_sha256,
            "required_tool_names": model_tool_names,
            "parameter_schema_tool_names": model_tools_with_catalog_schema,
            "parameter_schema_unavailable_tool_names": (
                model_tools_without_catalog_schema
            ),
            "tools": model_tools,
        },
        "gateway_rpc_catalog": {
            "catalog_kind": "source_bound_gateway_rpc_catalog",
            "authority": "installed_runtime_dist_sources",
            "status": _gateway_catalog_status(source_bound_rpc_names),
            "source_bound_rpc_names": sorted(source_bound_rpc_names),
            "rpc_evidence": _gateway_rpc_evidence(
                source_bound_rpc_names=source_bound_rpc_names,
                gateway_status=gateway_status,
            ),
            "status_corroboration": gateway_status,
            "tools": gateway_tools,
        },
        "sources": [
            _source_record_from_snapshot(root, path, source_digest_snapshot)
            for path in source_paths
        ],
        "tools": tools,
    }


def _runtime_failure_catalog(
    *,
    runtime_target: str,
    include_env_override: bool,
    require_env_override: bool,
) -> dict[str, Any]:
    catalog: dict[str, Any] = {
        "catalog_kind": "sanitized_openclaw_runtime",
        "runtime_target": runtime_target,
        "catalog_capture": {
            "method": "tools.catalog",
            "status": "catalog_unavailable_before_contract_validation",
            "validation_stage": "catalog_capture",
        },
    }
    try:
        root = _resolve_install_root(
            include_env_override=include_env_override,
            require_env_override=require_env_override,
        )
    except AdapterContractError as exc:
        catalog["install_root_resolution_error"] = str(exc)
        return catalog
    catalog["install_root_basename"] = root.name
    catalog["install_root_path_sha256"] = _path_digest(root)
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        if not isinstance(package, Mapping):
            raise AdapterContractError("OpenClaw package.json must be a JSON object")
    except (OSError, json.JSONDecodeError, AdapterContractError) as exc:
        catalog["package_resolution_error"] = type(exc).__name__
    else:
        catalog["openclaw_version"] = package.get("version")
        catalog["openclaw_package_name"] = package.get("name")
    try:
        executable = _resolve_openclaw_executable()
        catalog["active_executable_path_sha256"] = _path_digest(executable)
        _record_file_digest(catalog, "active_executable_sha256", executable)
        _require_executable_matches_install_root(root, executable)
    except AdapterContractError as exc:
        catalog["executable_resolution_error"] = str(exc)
    return catalog


def isolated_candidate_openclaw_catalog() -> dict[str, Any]:
    return live_installed_openclaw_catalog(
        runtime_target="isolated_candidate",
        include_env_override=True,
        require_env_override=True,
    )


def installed_negative_baseline_catalog() -> dict[str, Any]:
    return live_installed_openclaw_catalog(
        runtime_target="installed_openclaw_negative_baseline",
        include_env_override=False,
        scrub_env_override=True,
    )


def _runtime_failure_catalog_for_args(args: argparse.Namespace) -> dict[str, Any] | None:
    if args.isolated_candidate_openclaw:
        return _runtime_failure_catalog(
            runtime_target="isolated_candidate",
            include_env_override=True,
            require_env_override=True,
        )
    if args.installed_openclaw_negative_baseline:
        return _runtime_failure_catalog(
            runtime_target="installed_openclaw_negative_baseline",
            include_env_override=False,
            require_env_override=False,
        )
    if args.live_installed_openclaw:
        return _runtime_failure_catalog(
            runtime_target="live_installed_openclaw",
            include_env_override=True,
            require_env_override=False,
        )
    return None


def _read_catalog(args: argparse.Namespace) -> dict[str, Any]:
    if args.catalog_json is not None and args.catalog_json_file is not None:
        raise SystemExit("provide only one of --catalog-json or --catalog-json-file")

    if args.catalog_json is not None:
        raw = args.catalog_json
    elif args.catalog_json_file is not None:
        raw = Path(args.catalog_json_file).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()

    try:
        catalog = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"tool catalog is not valid JSON: {exc}") from exc

    if not isinstance(catalog, dict):
        raise SystemExit("tool catalog must be a JSON object")
    return catalog


def _runtime_target_requested(args: argparse.Namespace) -> bool:
    return bool(
        args.live_installed_openclaw
        or args.isolated_candidate_openclaw
        or args.installed_openclaw_negative_baseline
    )


def _caller_catalog_tool_entries(catalog: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entries: list[Mapping[str, Any]] = []

    def extend_mapping_entries(tools: Mapping[str, Any]) -> None:
        for name, value in tools.items():
            if not isinstance(name, str):
                continue
            entry: dict[str, Any] = dict(value) if isinstance(value, Mapping) else {}
            entry["id"] = name
            entry["name"] = name
            entries.append(entry)

    tools = catalog.get("tools")
    if isinstance(tools, list):
        entries.extend(tool for tool in tools if isinstance(tool, Mapping))
    elif isinstance(tools, Mapping):
        extend_mapping_entries(tools)
    elif "tools" not in catalog:
        extend_mapping_entries(catalog)
    groups = catalog.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, Mapping):
                continue
            group_tools = group.get("tools")
            if isinstance(group_tools, list):
                entries.extend(tool for tool in group_tools if isinstance(tool, Mapping))
    return entries


def _sanitize_caller_catalog_for_evidence(catalog: Mapping[str, Any]) -> dict[str, Any]:
    raw_catalog_sha256 = hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    required_names: set[str] = set()
    for entry in _caller_catalog_tool_entries(catalog):
        name = _adapter_tool_name(entry)
        if name is not None:
            required_names.add(name)
    return {
        "catalog_kind": "sanitized_caller_tool_catalog",
        "raw_catalog_sha256": raw_catalog_sha256,
        "tool_entry_count": len(_caller_catalog_tool_entries(catalog)),
        "required_tool_names": sorted(required_names),
    }


def _catalog_for_payload(args: argparse.Namespace, catalog: dict[str, Any]) -> dict[str, Any]:
    if args.write_evidence and not _runtime_target_requested(args):
        return _sanitize_caller_catalog_for_evidence(catalog)
    return catalog


def _assert_preflight_runtime_tools(
    catalog: Mapping[str, Any], *, runtime_target: bool
) -> None:
    """Keep offline schema validation separate from online runtime authority."""

    if runtime_target:
        assert_preflighted_runtime_authority({"status": "pass", "catalog": catalog})
        return
    assert_installed_runtime_tools(catalog)


def _write_evidence(path: str | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    Path(path).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _git_rev_parse(root: Path, revision: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", revision],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = proc.stdout.strip()
    return value or None


def _require_valid_git_revision(root: Path, revision: str) -> str:
    value = _git_rev_parse(root, revision)
    if value is None or GIT_SHA.fullmatch(value) is None:
        raise SystemExit(
            f"cannot verify Git revision {revision} before writing exact-head evidence"
        )
    return value.lower()


def _git_status_porcelain(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return proc.stdout


def _require_clean_worktree_for_evidence(root: Path) -> None:
    status = _git_status_porcelain(root)
    if status is None:
        raise SystemExit("cannot verify Git worktree cleanliness before writing evidence")
    if status.strip():
        raise SystemExit("refusing to write exact-head evidence from a dirty Git worktree")


def _display_path(root: Path, value: str) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        try:
            path_identity = path.resolve().as_posix()
        except OSError:
            path_identity = path.as_posix()
        digest = hashlib.sha256(path_identity.encode("utf-8")).hexdigest()
        return f"<external-path:sha256:{digest}>"


def _sanitize_invocation_argv(
    root: Path,
    argv: list[str],
    path_options: Mapping[str, str | None],
    inline_json_options: set[str] | None = None,
) -> list[str]:
    inline_json_options = inline_json_options or set()
    sanitized: list[str] = []
    pending_path_option: str | None = None
    pending_inline_json_option: str | None = None
    for item in argv:
        if pending_path_option is not None:
            sanitized.append(_display_path(root, item))
            pending_path_option = None
            continue
        if pending_inline_json_option is not None:
            digest = hashlib.sha256(item.encode("utf-8")).hexdigest()
            sanitized.append(f"<redacted:{pending_inline_json_option}:sha256:{digest}>")
            pending_inline_json_option = None
            continue
        matched_equals = False
        for option in path_options:
            prefix = f"{option}="
            if item.startswith(prefix):
                value = item[len(prefix) :]
                sanitized.append(f"{option}={_display_path(root, value)}")
                matched_equals = True
                break
        if matched_equals:
            continue
        for option in inline_json_options:
            prefix = f"{option}="
            if item.startswith(prefix):
                value = item[len(prefix) :]
                digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
                sanitized.append(f"{option}=<redacted:sha256:{digest}>")
                matched_equals = True
                break
        if matched_equals:
            continue
        sanitized.append(item)
        if item in path_options:
            pending_path_option = item
        elif item in inline_json_options:
            pending_inline_json_option = item
    return sanitized


def _capture_evidence_binding(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    _require_clean_worktree_for_evidence(root)
    sanitized_argv = _sanitize_invocation_argv(
        root,
        argv,
        {
            "--catalog-json-file": args.catalog_json_file,
            "--write-evidence": args.write_evidence,
        },
        {"--catalog-json"},
    )
    return {
        "binding_kind": "generator_revision",
        "agentic_os_head_sha": _require_valid_git_revision(root, "HEAD"),
        "agentic_os_tree_sha": _require_valid_git_revision(root, "HEAD^{tree}"),
        "capability_source_paths": list(EVIDENCE_CAPABILITY_SOURCE_PATHS),
        "containing_commit_self_binding": False,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "invocation": {
            "script": "scripts/openclaw-tool-capability-preflight.py",
            "argv": sanitized_argv,
        },
        "preflight_script_sha256": _file_digest(Path(__file__).resolve()),
    }


def _require_same_evidence_binding(binding: Mapping[str, Any]) -> None:
    root = Path(__file__).resolve().parents[1]
    _require_clean_worktree_for_evidence(root)
    current = {
        "agentic_os_head_sha": _require_valid_git_revision(root, "HEAD"),
        "agentic_os_tree_sha": _require_valid_git_revision(root, "HEAD^{tree}"),
        "preflight_script_sha256": _file_digest(Path(__file__).resolve()),
    }
    expected = {
        "agentic_os_head_sha": binding.get("agentic_os_head_sha"),
        "agentic_os_tree_sha": binding.get("agentic_os_tree_sha"),
        "preflight_script_sha256": binding.get("preflight_script_sha256"),
    }
    if current != expected:
        raise SystemExit(
            "refusing to write exact-head evidence after Git identity changed during preflight"
        )


def _finalize_payload(
    args: argparse.Namespace,
    argv: list[str],
    payload: dict[str, Any],
    evidence_binding: dict[str, Any] | None,
) -> dict[str, Any]:
    if args.write_evidence:
        if evidence_binding is None:
            evidence_binding = _capture_evidence_binding(args, argv)
        _require_same_evidence_binding(evidence_binding)
        payload["preflight_evidence_binding"] = dict(evidence_binding)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Fail closed unless OpenClaw runtime evidence exposes the model-callable "
            "session tools and source-bound Gateway allowLease RPC surface required "
            "by the Agentic OS adapter."
        )
    )
    parser.add_argument(
        "--catalog-json",
        help="Runtime tool catalog JSON. If omitted, read JSON from stdin.",
    )
    parser.add_argument(
        "--catalog-json-file",
        help="Path to a runtime tool catalog JSON file.",
    )
    parser.add_argument(
        "--live-installed-openclaw",
        action="store_true",
        help=(
            "Build a sanitized catalog from the installed OpenClaw runtime bundle "
            "instead of reading caller-provided JSON."
        ),
    )
    parser.add_argument(
        "--isolated-candidate-openclaw",
        action="store_true",
        help=(
            "Build a sanitized catalog from the isolated candidate runtime named by "
            "OPENCLAW_INSTALL_ROOT and the matching PATH openclaw executable."
        ),
    )
    parser.add_argument(
        "--installed-openclaw-negative-baseline",
        action="store_true",
        help=(
            "Build a sanitized historical compatibility baseline from the active "
            "installed OpenClaw runtime, ignoring OPENCLAW_INSTALL_ROOT. The "
            "2026-08-09 installed-runtime negative baseline is retracted as a "
            "combined-catalog false negative; use live split-catalog evidence for "
            "current decisions."
        ),
    )
    parser.add_argument(
        "--write-evidence",
        help="Write the preflight result and sanitized catalog evidence to this JSON file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the detailed preflight payload instead of the legacy compact status.",
    )
    original_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(original_argv)
    evidence_binding = (
        _capture_evidence_binding(args, original_argv) if args.write_evidence else None
    )

    live_targets = [
        flag
        for flag in (
            args.live_installed_openclaw,
            args.isolated_candidate_openclaw,
            args.installed_openclaw_negative_baseline,
        )
        if flag
    ]
    if len(live_targets) > 1:
        raise SystemExit("provide only one OpenClaw runtime target flag")

    if args.live_installed_openclaw or args.isolated_candidate_openclaw or args.installed_openclaw_negative_baseline:
        if args.catalog_json is not None or args.catalog_json_file is not None:
            raise SystemExit("OpenClaw runtime target flags cannot be combined with catalog input")
        try:
            if args.isolated_candidate_openclaw:
                catalog = isolated_candidate_openclaw_catalog()
            elif args.installed_openclaw_negative_baseline:
                catalog = installed_negative_baseline_catalog()
            else:
                catalog = live_installed_openclaw_catalog()
        except RuntimeEvidenceError as exc:
            payload = {
                "classification": "fail_closed_future_contract",
                "error": str(exc),
                "runtime_ready": False,
                "status": "fail",
            }
            if exc.catalog_failure is not None:
                payload["catalog_failure"] = exc.catalog_failure
            failure_catalog = exc.catalog or _runtime_failure_catalog_for_args(args)
            if failure_catalog is not None:
                payload["catalog"] = failure_catalog
            _finalize_payload(args, original_argv, payload, evidence_binding)
            _write_evidence(args.write_evidence, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1
        except AdapterContractError as exc:
            payload = {
                "classification": "fail_closed_future_contract",
                "error": str(exc),
                "runtime_ready": False,
                "status": "fail",
            }
            failure_catalog = _runtime_failure_catalog_for_args(args)
            if failure_catalog is not None:
                payload["catalog"] = failure_catalog
            _finalize_payload(args, original_argv, payload, evidence_binding)
            _write_evidence(args.write_evidence, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1
    else:
        catalog = _read_catalog(args)

    payload: dict[str, Any]
    try:
        _assert_preflight_runtime_tools(
            catalog,
            runtime_target=_runtime_target_requested(args),
        )
    except AdapterContractError as exc:
        payload = {"error": str(exc), "runtime_ready": False, "status": "fail"}
        if _runtime_target_requested(args):
            payload["classification"] = "fail_closed_future_contract"
        else:
            payload["classification"] = "offline_schema_validation_failed"
        if (
            args.live_installed_openclaw
            or args.isolated_candidate_openclaw
            or args.installed_openclaw_negative_baseline
            or args.json
            or args.write_evidence
        ):
            payload["catalog"] = _catalog_for_payload(args, catalog)
        _finalize_payload(args, original_argv, payload, evidence_binding)
        _write_evidence(args.write_evidence, payload)
        print(json.dumps(payload, sort_keys=True))
        return 1

    if _runtime_target_requested(args):
        payload = {"runtime_ready": True, "status": "pass"}
    else:
        payload = {
            "classification": "offline_schema_validation_only",
            "runtime_ready": False,
            "status": "declared_schema_validated",
        }
    if (
        args.live_installed_openclaw
        or args.isolated_candidate_openclaw
        or args.installed_openclaw_negative_baseline
        or args.json
        or args.write_evidence
    ):
        payload["catalog"] = _catalog_for_payload(args, catalog)
    _finalize_payload(args, original_argv, payload, evidence_binding)
    _write_evidence(args.write_evidence, payload)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            json.dumps(
                {
                    "runtime_ready": payload["runtime_ready"],
                    "status": payload["status"],
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
