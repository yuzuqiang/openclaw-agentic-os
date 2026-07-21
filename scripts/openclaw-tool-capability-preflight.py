#!/usr/bin/env python3
"""Validate a captured OpenClaw runtime tool catalog before production RPC use."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentic_os.openclaw_adapter import (
    AdapterContractError,
    assert_installed_runtime_tools,
)


TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
JS_TOOL_NAME = re.compile(r"\b(?:id|name):\s*[\"']([A-Za-z][A-Za-z0-9_.-]*)[\"']")
JS_METHOD_NAME = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_.-]*)[\"']\s*:")
DETAIL_KEYS = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*:\s*\{[^{}]*?detailKeys:\s*\[(?P<keys>[^\]]*)\]",
    re.DOTALL,
)
QUOTED = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_.-]*)[\"']")
OBJECT_SCHEMA_FIELD = re.compile(
    r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_]*)\s*:\s*(?:Type\.|optionalStringEnum)",
    re.MULTILINE,
)

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


def _extract_detail_key_catalog(root: Path) -> tuple[dict[str, set[str]], list[Path]]:
    discovered: dict[str, set[str]] = {}
    sources: list[Path] = []
    for path, text in _read_dist_files(root, "tool-display-*.js"):
        for match in DETAIL_KEYS.finditer(text):
            name = match.group("name")
            if name not in LIVE_TOOL_NAMES:
                continue
            discovered.setdefault(name, set()).update(QUOTED.findall(match.group("keys")))
            sources.append(path)
    return discovered, sources


def _extract_sessions_spawn_schema(root: Path) -> tuple[set[str], list[Path]]:
    sources: list[Path] = []
    for path, text in _read_dist_files(root, "openclaw-tools-*.js"):
        marker = "function createSessionsSpawnToolSchema"
        start = text.find(marker)
        if start < 0:
            continue
        end = text.find("function resolveAcpUnavailableMessage", start)
        block = text[start : end if end > start else start + 12000]
        names = set(OBJECT_SCHEMA_FIELD.findall(block))
        if names:
            sources.append(path)
            return names, sources
    return set(), sources


def _extract_gateway_method_params(root: Path) -> tuple[dict[str, set[str]], list[Path]]:
    methods: dict[str, set[str]] = {}
    sources: list[Path] = []
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
            candidates = [value for value in (next_method, next_group) if value > start]
            end = min(candidates) if candidates else start + 2000
            block = text[start:end]
            keys = re.findall(r"params\?\.([A-Za-z][A-Za-z0-9_]*)", block)
            if keys:
                methods.setdefault(method, set()).update(keys)
                sources.append(path)
    return methods, sources


def _declared_core_names(root: Path) -> set[str]:
    names: set[str] = set()
    for pattern, matcher in (
        ("tool-catalog-*.js", JS_TOOL_NAME),
        ("openclaw-tools-*.js", JS_TOOL_NAME),
        ("core-descriptors-*.js", JS_TOOL_NAME),
        ("server-methods-*.js", JS_METHOD_NAME),
    ):
        for _, text in _read_dist_files(root, pattern):
            names.update(name for name in matcher.findall(text) if TOOL_NAME.fullmatch(name))
    return names


def live_installed_openclaw_catalog() -> dict[str, Any]:
    root = _resolve_install_root()
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    detail_keys, detail_sources = _extract_detail_key_catalog(root)
    sessions_spawn_params, spawn_sources = _extract_sessions_spawn_schema(root)
    gateway_params, gateway_sources = _extract_gateway_method_params(root)
    declared_names = _declared_core_names(root)
    tools: list[dict[str, Any]] = []
    for name in LIVE_TOOL_NAMES:
        params = set()
        source_kind = "absent"
        if name in gateway_params:
            params.update(gateway_params[name])
            source_kind = "gateway_server_method_params"
        if name == "sessions_spawn" and sessions_spawn_params:
            params.update(sessions_spawn_params)
            source_kind = "model_tool_schema"
        if name in detail_keys:
            params.update(detail_keys[name])
            if source_kind == "absent":
                source_kind = "display_detail_keys"
        if name in declared_names or params:
            tools.append(
                {
                    "name": name,
                    "parameters": sorted(params),
                    "schema_source": source_kind,
                }
            )
    source_paths = sorted({*detail_sources, *spawn_sources, *gateway_sources})
    return {
        "catalog_kind": "sanitized_installed_openclaw_runtime",
        "openclaw_version": package.get("version"),
        "openclaw_package_name": package.get("name"),
        "install_root_basename": root.name,
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
        if args.write_evidence:
            Path(args.write_evidence).write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(payload, sort_keys=True))
        return 1

    payload = {"status": "pass"}
    if args.live_installed_openclaw or args.json or args.write_evidence:
        payload["catalog"] = catalog
    if args.write_evidence:
        Path(args.write_evidence).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps({"status": "pass"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
