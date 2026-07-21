#!/usr/bin/env python3
"""Validate a captured OpenClaw runtime tool catalog before production RPC use."""

from __future__ import annotations

import argparse
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


def _candidate_install_roots() -> Iterable[Path]:
    override = os.environ.get("OPENCLAW_INSTALL_ROOT", "").strip()
    if override:
        yield Path(override).expanduser()
    executable = shutil.which("openclaw")
    if executable:
        resolved = Path(executable).resolve()
        for parent in (resolved.parent, *resolved.parents):
            yield parent / "lib" / "node_modules" / "openclaw"
            yield parent / "node_modules" / "openclaw"
    yield Path("/opt/homebrew/lib/node_modules/openclaw")
    yield Path("/usr/local/lib/node_modules/openclaw")


def _resolve_install_root() -> Path:
    seen: set[Path] = set()
    for candidate in _candidate_install_roots():
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if (resolved / "dist").is_dir() and (resolved / "package.json").is_file():
            return resolved
    raise AdapterContractError("installed OpenClaw runtime bundle was not found")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_digest(path: Path) -> str:
    return hashlib.sha256(path.resolve().as_posix().encode("utf-8")).hexdigest()


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
            index = parsed[1] if parsed is not None else index + 1
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


def _run_gateway_tools_catalog(executable: Path, timeout_ms: int = 10_000) -> dict[str, Any]:
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
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterContractError(f"active OpenClaw tool catalog unavailable: {exc}") from exc
    try:
        payload = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        raise AdapterContractError("active OpenClaw tool catalog returned non-JSON output") from exc
    if proc.returncode != 0:
        detail = payload.get("error") if isinstance(payload, Mapping) else None
        raise AdapterContractError(f"active OpenClaw tool catalog failed: {detail or proc.stderr}")
    if not isinstance(payload, dict):
        raise AdapterContractError("active OpenClaw tool catalog must be a JSON object")
    return payload


def _active_tool_names(catalog: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
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
                        names.add(value)
    tools = catalog.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            for key in ("id", "name", "method"):
                value = tool.get(key)
                if isinstance(value, str) and value in LIVE_TOOL_NAMES:
                    names.add(value)
    elif isinstance(tools, Mapping):
        for name in tools:
            if isinstance(name, str) and name in LIVE_TOOL_NAMES:
                names.add(name)
    return names


def live_installed_openclaw_catalog() -> dict[str, Any]:
    root = _resolve_install_root()
    executable = _resolve_openclaw_executable()
    _require_executable_matches_install_root(root, executable)
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    active_catalog = _run_gateway_tools_catalog(executable)
    active_names = _active_tool_names(active_catalog)
    if not active_names:
        raise AdapterContractError("active OpenClaw tool catalog did not expose required tools")
    model_tool_params, model_tool_sources = _extract_model_tool_schemas(root)
    gateway_params, gateway_sources = _extract_gateway_method_params(root)
    declared_names, declaration_sources = _declared_core_names(root)
    tools: list[dict[str, Any]] = []
    for name in LIVE_TOOL_NAMES:
        params = set()
        source_kind = "absent"
        declared = name in declared_names
        active = name in active_names
        if name in gateway_params:
            params.update(gateway_params[name])
            source_kind = "gateway_server_method_params"
        if declared and name in model_tool_params:
            params.update(model_tool_params[name])
            if source_kind == "absent":
                source_kind = "model_tool_schema"
        if declared and active and source_kind == "absent":
            source_kind = "declared_tool_name"
        if active and (declared or name in gateway_params):
            tools.append(
                {
                    "name": name,
                    "parameters": sorted(params),
                    "schema_source": source_kind,
                }
            )
    source_paths = sorted({*model_tool_sources, *gateway_sources, *declaration_sources})
    return {
        "catalog_kind": "sanitized_installed_openclaw_runtime",
        "openclaw_version": package.get("version"),
        "openclaw_package_name": package.get("name"),
        "install_root_basename": root.name,
        "install_root_path_sha256": _path_digest(root),
        "active_executable_path_sha256": _path_digest(executable),
        "active_catalog": {
            "method": "tools.catalog",
            "raw_response_sha256": hashlib.sha256(
                json.dumps(active_catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "required_tool_names": sorted(active_names),
        },
        "sources": [_source_record(root, path) for path in source_paths],
        "tools": tools,
    }


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
        "--write-evidence",
        help="Write the preflight result and sanitized catalog evidence to this JSON file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the detailed preflight payload instead of the legacy compact status.",
    )
    args = parser.parse_args(argv)

    if args.live_installed_openclaw:
        if args.catalog_json is not None or args.catalog_json_file is not None:
            raise SystemExit("--live-installed-openclaw cannot be combined with catalog input")
        try:
            catalog = live_installed_openclaw_catalog()
        except AdapterContractError as exc:
            payload = {"error": str(exc), "status": "fail"}
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
        if args.live_installed_openclaw or args.json or args.write_evidence:
            payload["catalog"] = catalog
        _write_evidence(args.write_evidence, payload)
        print(json.dumps(payload, sort_keys=True))
        return 1

    payload = {"status": "pass"}
    if args.live_installed_openclaw or args.json or args.write_evidence:
        payload["catalog"] = catalog
    _write_evidence(args.write_evidence, payload)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps({"status": "pass"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
