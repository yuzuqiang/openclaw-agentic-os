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

from agentic_os.openclaw_adapter import (
    AdapterContractError,
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

LIVE_TOOL_NAMES = (
    "subagents.allowLease.acquire",
    "subagents.allowLease.status",
    "subagents.allowLease.release",
    "sessions_spawn",
    "sessions_list",
    "sessions_history",
    "session_status",
    "sessions_status",
)

MODEL_TOOL_SCHEMA_MARKERS = {
    "sessions_spawn": "function createSessionsSpawnToolSchema",
    "sessions_list": "function createSessionsListToolSchema",
    "sessions_history": "function createSessionsHistoryToolSchema",
    "session_status": "function createSessionStatusToolSchema",
    "sessions_status": "function createSessionsStatusToolSchema",
}


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


def _path_digest(path: Path) -> str:
    return hashlib.sha256(path.resolve().as_posix().encode("utf-8")).hexdigest()


def _stream_digest(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _source_record(root: Path, path: Path) -> dict[str, str]:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        relative = path.name
    return {"path": relative, "sha256": _file_digest(path)}


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
            catalog_failure={
                "message": "active OpenClaw tool catalog returned non-JSON output",
                "stdout": _stream_digest(proc.stdout or ""),
                "stderr": _stream_digest(proc.stderr or ""),
                "runtime_provenance_preserved": True,
            },
        ) from exc
    if proc.returncode != 0:
        payload_sha = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest() if isinstance(payload, Mapping) else None
        message = (
            "active OpenClaw tool catalog failed "
            f"returncode={proc.returncode} "
            f"payload_sha256={payload_sha} "
            f"stdout={_stream_digest(proc.stdout or '')} "
            f"stderr={_stream_digest(proc.stderr or '')}"
        )
        raise RuntimeEvidenceError(
            message,
            catalog_failure={
                "message": "active OpenClaw tool catalog failed before contract validation",
                "payload_sha256": payload_sha,
                "returncode": proc.returncode,
                "runtime_provenance_preserved": True,
                "stderr": _stream_digest(proc.stderr or ""),
                "stdout": _stream_digest(proc.stdout or ""),
            },
        )
    if not isinstance(payload, dict):
        raise AdapterContractError("active OpenClaw tool catalog must be a JSON object")
    return payload


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


def _active_tool_parameters(catalog: Mapping[str, Any]) -> dict[str, set[str]]:
    entries: dict[str, set[str]] = {}

    def add_entry(name: str, params: set[str]) -> None:
        if name not in LIVE_TOOL_NAMES:
            return
        if name in entries:
            raise AdapterContractError(f"active OpenClaw tool catalog has duplicate {name} entries")
        entries[name] = set(params)

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
                for key in ("id", "name", "method"):
                    value = tool.get(key)
                    if isinstance(value, str) and value in LIVE_TOOL_NAMES:
                        add_entry(value, _active_entry_parameters(tool))
                        break
    tools = catalog.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            for key in ("id", "name", "method"):
                value = tool.get(key)
                if isinstance(value, str) and value in LIVE_TOOL_NAMES:
                    add_entry(value, _active_entry_parameters(tool))
                    break
    elif isinstance(tools, Mapping):
        for name, value in tools.items():
            if isinstance(name, str) and name in LIVE_TOOL_NAMES:
                params = _active_entry_parameters(value) if isinstance(value, Mapping) else set()
                add_entry(name, params)
    return entries


def live_installed_openclaw_catalog(
    *,
    runtime_target: str = "live_installed_openclaw",
    include_env_override: bool = True,
    require_env_override: bool = False,
    scrub_env_override: bool = False,
) -> dict[str, Any]:
    root = _resolve_install_root(
        include_env_override=include_env_override,
        require_env_override=require_env_override,
    )
    executable = _resolve_openclaw_executable()
    _require_executable_matches_install_root(root, executable)
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    active_catalog = _run_gateway_tools_catalog(
        executable,
        scrub_env_override=scrub_env_override,
    )
    active_catalog_sha256 = hashlib.sha256(
        json.dumps(active_catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        active_params = _active_tool_parameters(active_catalog)
    except AdapterContractError as exc:
        validation_catalog: dict[str, Any] = {
            "catalog_kind": "sanitized_openclaw_runtime",
            "runtime_target": runtime_target,
            "required_canonical_session_status_method": "sessions_status",
            "openclaw_version": package.get("version"),
            "openclaw_package_name": package.get("name"),
            "install_root_basename": root.name,
            "install_root_path_sha256": _path_digest(root),
            "active_executable_path_sha256": _path_digest(executable),
            "active_catalog": {
                "method": "tools.catalog",
                "status": "contract_validation_failed",
                "validation_stage": "active_tool_parameters",
                "raw_response_sha256": active_catalog_sha256,
            },
        }
        _record_file_digest(validation_catalog, "active_executable_sha256", executable)
        raise RuntimeEvidenceError(str(exc), catalog=validation_catalog) from exc
    active_names = set(active_params)
    if not active_params:
        raise AdapterContractError("active OpenClaw tool catalog did not expose required tools")
    model_tool_params, model_tool_sources = _extract_model_tool_schemas(root)
    gateway_params, gateway_sources = _extract_gateway_method_params(root)
    declared_names, declaration_sources = _declared_core_names(root)
    tools: list[dict[str, Any]] = []
    for name in LIVE_TOOL_NAMES:
        source_params = set()
        source_kind = "absent"
        declared = name in declared_names
        active = name in active_names
        if name in gateway_params:
            source_params.update(gateway_params[name])
            source_kind = "gateway_server_method_params"
        if declared and name in model_tool_params:
            source_params.update(model_tool_params[name])
            if source_kind == "absent":
                source_kind = "model_tool_schema"
        if declared and active and source_kind == "absent":
            source_kind = "declared_tool_name"
        if active and (declared or name in gateway_params):
            params = sorted(active_params[name] & source_params)
            tools.append(
                {
                    "name": name,
                    "parameters": params,
                    "active_parameters": sorted(active_params[name]),
                    "schema_source": source_kind,
                }
            )
    source_paths = sorted({*model_tool_sources, *gateway_sources, *declaration_sources})
    return {
        "catalog_kind": "sanitized_openclaw_runtime",
        "runtime_target": runtime_target,
        "required_canonical_session_status_method": "sessions_status",
        "openclaw_version": package.get("version"),
        "openclaw_package_name": package.get("name"),
        "install_root_basename": root.name,
        "install_root_path_sha256": _path_digest(root),
        "active_executable_path_sha256": _path_digest(executable),
        "active_executable_sha256": _file_digest(executable),
        "active_catalog": {
            "method": "tools.catalog",
            "raw_response_sha256": active_catalog_sha256,
            "required_tool_names": sorted(active_names),
        },
        "sources": [_source_record(root, path) for path in source_paths],
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
    except (OSError, json.JSONDecodeError) as exc:
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


def _display_path(root: Path, value: str) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _evidence_binding(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    sanitized_argv = list(argv)
    if args.write_evidence:
        sanitized_argv = [
            _display_path(root, item) if item == args.write_evidence else item
            for item in sanitized_argv
        ]
    return {
        "agentic_os_head_sha": _git_rev_parse(root, "HEAD"),
        "agentic_os_tree_sha": _git_rev_parse(root, "HEAD^{tree}"),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "invocation": {
            "script": "scripts/openclaw-tool-capability-preflight.py",
            "argv": sanitized_argv,
        },
        "preflight_script_sha256": _file_digest(Path(__file__).resolve()),
    }


def _finalize_payload(
    args: argparse.Namespace,
    argv: list[str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    if args.write_evidence:
        payload["preflight_evidence_binding"] = _evidence_binding(args, argv)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail closed unless an OpenClaw runtime tool catalog exposes the "
            "allowLease and session tool surface required by the Agentic OS adapter."
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
            "Build a sanitized catalog from the active installed OpenClaw baseline, "
            "ignoring OPENCLAW_INSTALL_ROOT, so incompatible installs fail closed."
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
            payload = {"error": str(exc), "status": "fail"}
            if exc.catalog_failure is not None:
                payload["catalog_failure"] = exc.catalog_failure
            failure_catalog = exc.catalog or _runtime_failure_catalog_for_args(args)
            if failure_catalog is not None:
                payload["catalog"] = failure_catalog
            _finalize_payload(args, original_argv, payload)
            _write_evidence(args.write_evidence, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1
        except AdapterContractError as exc:
            payload = {"error": str(exc), "status": "fail"}
            failure_catalog = _runtime_failure_catalog_for_args(args)
            if failure_catalog is not None:
                payload["catalog"] = failure_catalog
            _finalize_payload(args, original_argv, payload)
            _write_evidence(args.write_evidence, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1
    else:
        catalog = _read_catalog(args)

    payload: dict[str, Any]
    try:
        assert_installed_runtime_tools(catalog)
    except AdapterContractError as exc:
        payload = {"error": str(exc), "status": "fail"}
        if (
            args.live_installed_openclaw
            or args.isolated_candidate_openclaw
            or args.installed_openclaw_negative_baseline
            or args.json
            or args.write_evidence
        ):
            payload["catalog"] = catalog
        _finalize_payload(args, original_argv, payload)
        _write_evidence(args.write_evidence, payload)
        print(json.dumps(payload, sort_keys=True))
        return 1

    payload = {"status": "pass"}
    if (
        args.live_installed_openclaw
        or args.isolated_candidate_openclaw
        or args.installed_openclaw_negative_baseline
        or args.json
        or args.write_evidence
    ):
        payload["catalog"] = catalog
    _finalize_payload(args, original_argv, payload)
    _write_evidence(args.write_evidence, payload)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps({"status": "pass"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
