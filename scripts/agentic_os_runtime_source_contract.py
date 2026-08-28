#!/usr/bin/env python3
"""Shared source-closure contract for persistent OpenClaw runtime evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


PERSISTENT_LIFECYCLE_RUNNER = "scripts/agentic-os-persistent-lifecycle-runner.mts"
PERSISTENT_RUNTIME_SOURCE_PATHS = (
    "package.json",
    "openclaw.mjs",
    PERSISTENT_LIFECYCLE_RUNNER,
    "src/gateway/agentic-os-runtime-attestation.ts",
    "src/gateway/agentic-os-runtime-contract-descriptors.ts",
    "src/gateway/client.ts",
    "src/utils/message-channel.ts",
)
PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS = PERSISTENT_RUNTIME_SOURCE_PATHS
PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES = frozenset(
    (".cjs", ".cts", ".js", ".mjs", ".mts", ".ts", ".tsx")
)
PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES = (
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".d.ts",
    ".js",
    ".mjs",
    ".cjs",
    ".json",
)
PERSISTENT_RUNTIME_IMPORT_SUFFIX_ALIASES = {
    ".js": (".ts", ".tsx", ".mts", ".cts", ".d.ts", ".js"),
    ".mjs": (".mts", ".mjs"),
    ".cjs": (".cts", ".cjs"),
}

NODE_BUILTIN_MODULES = frozenset(
    {
        "assert",
        "buffer",
        "child_process",
        "crypto",
        "events",
        "fs",
        "http",
        "https",
        "module",
        "net",
        "os",
        "path",
        "process",
        "stream",
        "timers",
        "url",
        "util",
        "worker_threads",
    }
)

STATIC_RUNTIME_IMPORT_SPECIFIER = re.compile(
    r"""
    \b(?:import|export)\s+(?:type\s+)?
    (?:
        [^;"']*?\s+from\s*
      |
    )
    ["'](?P<specifier>[^"']+)["']
    """,
    re.VERBOSE | re.DOTALL,
)
DYNAMIC_RUNTIME_IMPORT_SPECIFIER = re.compile(
    r"""\bimport\s*\(\s*["'](?P<specifier>[^"']+)["']\s*\)""",
    re.VERBOSE,
)


class RuntimeSourceContractError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def path_sha256(path: Path) -> str:
    return sha256_bytes(path.resolve().as_posix().encode("utf-8"))


def source_relative_path(root: Path, source_path: Path) -> str:
    root = root.resolve()
    source_path = source_path.resolve()
    try:
        return source_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeSourceContractError(
            "runtime source import escapes the OpenClaw candidate root"
        ) from exc


def import_candidates(base: Path) -> list[Path]:
    candidates: list[Path] = []
    if base.suffix:
        candidates.append(base)
        for suffix in PERSISTENT_RUNTIME_IMPORT_SUFFIX_ALIASES.get(
            base.suffix, (base.suffix,)
        ):
            candidates.append(base.with_suffix(suffix))
    else:
        candidates.append(base)
        candidates.extend(
            Path(f"{base}{suffix}") for suffix in PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES
        )
        candidates.extend(
            base / f"index{suffix}" for suffix in PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES
        )
    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def strip_source_comments(source_text: str) -> str:
    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if character == "\n":
                output.append(character)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
            else:
                output.append("\n" if character == "\n" else " ")
                index += 1
            continue
        if state == "string":
            output.append(character)
            if character == "\\" and index + 1 < len(source_text):
                output.append(source_text[index + 1])
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            output.extend((" ", " "))
            index += 2
            state = "line_comment"
            continue
        if character == "/" and next_character == "*":
            output.extend((" ", " "))
            index += 2
            state = "block_comment"
            continue
        if character in {"'", '"', "`"}:
            state = "string"
            quote = character
        output.append(character)
        index += 1
    return "".join(output)


def import_specifiers(source_text: str) -> list[tuple[str, bool]]:
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, bool]] = []
    specifiers.extend(
        (match.group("specifier"), True)
        for match in STATIC_RUNTIME_IMPORT_SPECIFIER.finditer(source_text)
    )
    specifiers.extend(
        (match.group("specifier"), False)
        for match in DYNAMIC_RUNTIME_IMPORT_SPECIFIER.finditer(source_text)
    )
    return specifiers


def _package_name(specifier: str) -> str:
    parts = specifier.split("/")
    if specifier.startswith("@"):
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise RuntimeSourceContractError(
                f"runtime package import is invalid: {specifier}"
            )
        return "/".join(parts[:2])
    if not parts[0]:
        raise RuntimeSourceContractError(f"runtime package import is invalid: {specifier}")
    return parts[0]


def _package_subpath(specifier: str, package_name: str) -> str:
    remainder = specifier[len(package_name) :].lstrip("/")
    return remainder


def _is_node_builtin(specifier: str) -> bool:
    name = specifier[5:] if specifier.startswith("node:") else specifier
    return name.split("/", 1)[0] in NODE_BUILTIN_MODULES


def _load_package_json(package_json: Path, package_name: str) -> dict[str, Any]:
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeSourceContractError(
            f"{package_name} runtime package metadata is invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeSourceContractError(
            f"{package_name} runtime package metadata is invalid"
        )
    return payload


def _package_entry_bases(package_root: Path, package_json: dict[str, Any]) -> list[Path]:
    bases: list[Path] = []
    for field in ("module", "main", "browser", "types", "typings"):
        value = package_json.get(field)
        if isinstance(value, str) and value:
            bases.append((package_root / value).resolve())
    exports = package_json.get("exports")
    if isinstance(exports, str) and exports:
        bases.append((package_root / exports).resolve())
    elif isinstance(exports, dict):
        dot_export = exports.get(".")
        if isinstance(dot_export, str) and dot_export:
            bases.append((package_root / dot_export).resolve())
        elif isinstance(dot_export, dict):
            for field in ("import", "require", "default", "types"):
                value = dot_export.get(field)
                if isinstance(value, str) and value:
                    bases.append((package_root / value).resolve())
    bases.append(package_root / "index")
    return bases


def _resolve_existing_candidate(root: Path, base: Path) -> Path | None:
    for candidate in import_candidates(base):
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise RuntimeSourceContractError(
                "runtime source import escapes the OpenClaw candidate root"
            ) from exc
        if resolved.is_file():
            return resolved
    return None


def resolve_import(
    *,
    root: Path,
    importer: Path,
    specifier: str,
    required: bool,
) -> tuple[Path, ...]:
    normalized = specifier.split("?", 1)[0].split("#", 1)[0]
    if _is_node_builtin(normalized):
        return ()
    root = root.resolve()
    if normalized.startswith("."):
        base = (importer.parent / normalized).resolve()
        try:
            base.relative_to(root)
        except ValueError as exc:
            raise RuntimeSourceContractError(
                "runtime source import escapes the OpenClaw candidate root"
            ) from exc
        resolved = _resolve_existing_candidate(root, base)
        if resolved is not None:
            return (resolved,)
        if required:
            importer_relative = source_relative_path(root, importer)
            raise RuntimeSourceContractError(
                "runtime source import could not be resolved: "
                f"{importer_relative} imports {specifier}"
            )
        return ()

    package_name = _package_name(normalized)
    package_root = (root / "node_modules" / package_name).resolve()
    try:
        package_root.relative_to(root)
    except ValueError as exc:
        raise RuntimeSourceContractError(
            "runtime package import escapes the OpenClaw candidate root"
        ) from exc
    package_json = package_root / "package.json"
    if not package_json.is_file():
        if required:
            importer_relative = source_relative_path(root, importer)
            raise RuntimeSourceContractError(
                "runtime package import could not be resolved: "
                f"{importer_relative} imports {specifier}"
            )
        return ()
    package_payload = _load_package_json(package_json, package_name)
    subpath = _package_subpath(normalized, package_name)
    entry_bases = (
        [(package_root / subpath).resolve()]
        if subpath
        else _package_entry_bases(package_root, package_payload)
    )
    for base in entry_bases:
        resolved = _resolve_existing_candidate(root, base)
        if resolved is not None:
            return (package_json.resolve(), resolved)
    if required:
        importer_relative = source_relative_path(root, importer)
        raise RuntimeSourceContractError(
            "runtime package import could not be resolved: "
            f"{importer_relative} imports {specifier}"
        )
    return (package_json.resolve(),)


def runtime_source_paths(root: Path) -> tuple[str, ...]:
    root = root.resolve()
    queue: list[Path] = []
    for relative in PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise RuntimeSourceContractError(
                "persistent runtime source entrypoint escapes root"
            ) from exc
        if not path.is_file():
            raise RuntimeSourceContractError(
                f"persistent runtime source entrypoint is missing: {relative}"
            )
        queue.append(path)

    seen: set[str] = set()
    while queue:
        source_path = queue.pop(0).resolve()
        relative = source_relative_path(root, source_path)
        if relative in seen:
            continue
        seen.add(relative)
        if source_path.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:
            continue
        try:
            source_text = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeSourceContractError(
                f"runtime source is unavailable: {relative}"
            ) from exc
        except UnicodeDecodeError as exc:
            raise RuntimeSourceContractError(
                f"runtime source is not UTF-8: {relative}"
            ) from exc
        for specifier, required in import_specifiers(source_text):
            for imported in resolve_import(
                root=root,
                importer=source_path,
                specifier=specifier,
                required=required,
            ):
                imported_relative = source_relative_path(root, imported)
                if imported_relative not in seen:
                    queue.append(imported)
    if not seen:
        raise RuntimeSourceContractError("persistent runtime source closure is empty")
    return tuple(sorted(seen))


def runtime_source_digest_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for relative in runtime_source_paths(root):
        path = (root / relative).resolve()
        try:
            snapshot[relative] = sha256_bytes(path.read_bytes())
        except OSError as exc:
            raise RuntimeSourceContractError(
                f"runtime source is unavailable: {relative}"
            ) from exc
    return snapshot


def source_records_from_snapshot(snapshot: dict[str, str]) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": digest}
        for path, digest in sorted(snapshot.items())
    ]
