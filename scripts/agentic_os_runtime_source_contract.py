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
NODE_BUILTIN_SUBPATHS = frozenset(
    {
        "assert/strict",
        "fs/promises",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "timers/promises",
        "util/types",
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
COMMONJS_REQUIRE_TOKEN = "require"
COMMONJS_REQUIRE_RESOLVE_MEMBER = "resolve"
DYNAMIC_IMPORT_TOKEN = "import"
RUNTIME_PACKAGE_CONDITIONS = {
    "import": frozenset(("import", "node", "default")),
    "require": frozenset(("require", "node", "default")),
}


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


def _is_identifier_character(character: str) -> bool:
    return character.isalnum() or character in {"_", "$"}


def _skip_whitespace(source_text: str, index: int) -> int:
    while index < len(source_text) and source_text[index].isspace():
        index += 1
    return index


def _skip_js_trivia(source_text: str, index: int) -> int:
    while index < len(source_text):
        index = _skip_whitespace(source_text, index)
        if source_text.startswith("//", index):
            newline_index = source_text.find("\n", index + 2)
            if newline_index == -1:
                return len(source_text)
            index = newline_index + 1
            continue
        if source_text.startswith("/*", index):
            close_index = source_text.find("*/", index + 2)
            if close_index == -1:
                raise RuntimeSourceContractError(
                    "runtime source contains an unterminated JavaScript comment"
                )
            index = close_index + 2
            continue
        return index
    return index


def _parse_quoted_specifier(source_text: str, index: int) -> tuple[str, int] | None:
    if index >= len(source_text) or source_text[index] not in {"'", '"'}:
        return None
    quote = source_text[index]
    index += 1
    specifier: list[str] = []
    saw_escape = False
    while index < len(source_text):
        character = source_text[index]
        if character == "\\" and index + 1 < len(source_text):
            saw_escape = True
            specifier.append(source_text[index : index + 2])
            index += 2
            continue
        if character == quote:
            if saw_escape:
                raise RuntimeSourceContractError(
                    "runtime source import specifier contains an unsupported JavaScript escape"
                )
            return "".join(specifier), index + 1
        specifier.append(character)
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated CommonJS require specifier"
    )


def _optional_call_tail_index(source_text: str, index: int) -> int:
    optional_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", optional_index):
        call_index = _skip_js_trivia(source_text, optional_index + 2)
        if call_index < len(source_text) and source_text[call_index] == "(":
            return call_index
    return index


def _commonjs_require_resolve_call_index(
    source_text: str, index: int
) -> int | None:
    dot_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", dot_index):
        resolve_index = _skip_js_trivia(source_text, dot_index + 2)
    else:
        if dot_index >= len(source_text) or source_text[dot_index] != ".":
            return None
        resolve_index = _skip_js_trivia(source_text, dot_index + 1)
    if not source_text.startswith(COMMONJS_REQUIRE_RESOLVE_MEMBER, resolve_index):
        return None
    call_index = resolve_index + len(COMMONJS_REQUIRE_RESOLVE_MEMBER)
    after_resolve = source_text[call_index] if call_index < len(source_text) else ""
    if after_resolve and _is_identifier_character(after_resolve):
        return None
    return _optional_call_tail_index(source_text, call_index)


def _bracketed_require_resolve_call_index(source_text: str, index: int) -> int | None:
    bracket_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", bracket_index):
        bracket_index = _skip_js_trivia(source_text, bracket_index + 2)
    if bracket_index >= len(source_text) or source_text[bracket_index] != "[":
        return None
    member_index = _skip_js_trivia(source_text, bracket_index + 1)
    parsed = _parse_quoted_specifier(source_text, member_index)
    if parsed is None:
        return None
    member, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if (
        member != COMMONJS_REQUIRE_RESOLVE_MEMBER
        or close_index >= len(source_text)
        or source_text[close_index] != "]"
    ):
        return None
    return _optional_call_tail_index(source_text, close_index + 1)


def _optional_require_call_index(source_text: str, index: int) -> int | None:
    optional_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", optional_index):
        return optional_index + 2
    return None


def _parse_commonjs_require_call_index(source_text: str, index: int) -> int:
    for parser in (
        _commonjs_require_resolve_call_index,
        _bracketed_require_resolve_call_index,
        _optional_require_call_index,
    ):
        call_index = parser(source_text, index)
        if call_index is not None:
            return call_index
    return _skip_js_trivia(source_text, index)


def _parse_parenthesized_require_invocation(
    source_text: str, index: int
) -> tuple[str, int] | None:
    require_index = _skip_js_trivia(source_text, index + 1)
    if not source_text.startswith(COMMONJS_REQUIRE_TOKEN, require_index):
        return None
    after_index = require_index + len(COMMONJS_REQUIRE_TOKEN)
    before = source_text[require_index - 1] if require_index > 0 else ""
    after = source_text[after_index] if after_index < len(source_text) else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    if after and _is_identifier_character(after):
        return None
    callee_end = _parse_commonjs_require_call_index(source_text, after_index)
    close_index = _skip_js_trivia(source_text, callee_end)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        return None
    call_index = _skip_js_trivia(source_text, close_index + 1)
    if source_text.startswith("?.", call_index):
        call_index = _skip_js_trivia(source_text, call_index + 2)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, call_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic CommonJS require"
        )
    specifier, end_index = parsed
    invocation_end = _skip_js_trivia(source_text, end_index)
    if invocation_end >= len(source_text) or source_text[invocation_end] != ")":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS require signature"
        )
    return specifier, invocation_end + 1


def _template_expression_end(source_text: str, index: int) -> int:
    depth = 1
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if character == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                index += 2
                state = "code"
            else:
                index += 1
            continue
        if state == "string":
            if character == "\\" and index + 1 < len(source_text):
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            index += 2
            state = "line_comment"
            continue
        if character == "/" and next_character == "*":
            index += 2
            state = "block_comment"
            continue
        if character in {"'", '"', "`"}:
            state = "string"
            quote = character
            index += 1
            continue
        if character == "{":
            depth += 1
            index += 1
            continue
        if character == "}":
            depth -= 1
            if depth == 0:
                return index
            index += 1
            continue
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated JavaScript template expression"
    )


def _template_expression_chunks(source_text: str, index: int) -> tuple[list[str], int]:
    chunks: list[str] = []
    index += 1
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if character == "\\" and index + 1 < len(source_text):
            index += 2
            continue
        if character == "`":
            return chunks, index + 1
        if character == "$" and next_character == "{":
            expression_start = index + 2
            expression_end = _template_expression_end(source_text, expression_start)
            chunks.append(source_text[expression_start:expression_end])
            index = expression_end + 1
            continue
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated JavaScript template literal"
    )


def _parse_require_invocation(
    source_text: str, require_index: int
) -> tuple[str, int] | None:
    after_index = require_index + len(COMMONJS_REQUIRE_TOKEN)
    before = source_text[require_index - 1] if require_index > 0 else ""
    after = source_text[after_index] if after_index < len(source_text) else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    if after and _is_identifier_character(after):
        return None
    call_index = _skip_js_trivia(
        source_text, _parse_commonjs_require_call_index(source_text, after_index)
    )
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, call_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic CommonJS require"
        )
    specifier, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS require signature"
        )
    return specifier, close_index + 1


def _parse_property_require_invocation(
    source_text: str, require_index: int
) -> tuple[str, int] | None:
    if require_index == 0 or source_text[require_index - 1] != ".":
        return None
    object_end = require_index - 1
    object_start = object_end
    while object_start > 0 and _is_identifier_character(source_text[object_start - 1]):
        object_start -= 1
    object_name = source_text[object_start:object_end]
    if object_name != "module":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported property CommonJS require"
        )
    after_index = require_index + len(COMMONJS_REQUIRE_TOKEN)
    after = source_text[after_index] if after_index < len(source_text) else ""
    if after and _is_identifier_character(after):
        return None
    call_index = _skip_js_trivia(source_text, after_index)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, call_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic CommonJS require"
        )
    specifier, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS require signature"
        )
    return specifier, close_index + 1


def _commonjs_require_specifiers(source_text: str) -> list[str]:
    specifiers: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if character == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                index += 2
                state = "code"
            else:
                index += 1
            continue
        if state == "string":
            if character == "\\" and index + 1 < len(source_text):
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            index += 2
            state = "line_comment"
            continue
        if character == "/" and next_character == "*":
            index += 2
            state = "block_comment"
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_commonjs_require_specifiers(chunk))
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if source_text.startswith(COMMONJS_REQUIRE_TOKEN, index):
            parsed = _parse_property_require_invocation(source_text, index)
            if parsed is not None:
                specifier, index = parsed
                specifiers.append(specifier)
                continue
            parsed = _parse_require_invocation(source_text, index)
            if parsed is not None:
                specifier, index = parsed
                specifiers.append(specifier)
                continue
        if character == "(":
            parsed = _parse_parenthesized_require_invocation(source_text, index)
            if parsed is not None:
                specifier, index = parsed
                specifiers.append(specifier)
                continue
        index += 1
    return specifiers


def _dynamic_import_specifiers(source_text: str) -> list[str]:
    specifiers: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if character == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                index += 2
                state = "code"
            else:
                index += 1
            continue
        if state == "string":
            if character == "\\" and index + 1 < len(source_text):
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            index += 2
            state = "line_comment"
            continue
        if character == "/" and next_character == "*":
            index += 2
            state = "block_comment"
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_dynamic_import_specifiers(chunk))
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if source_text.startswith(DYNAMIC_IMPORT_TOKEN, index):
            before = source_text[index - 1] if index > 0 else ""
            after_index = index + len(DYNAMIC_IMPORT_TOKEN)
            after = source_text[after_index] if after_index < len(source_text) else ""
            if before and (_is_identifier_character(before) or before == "."):
                index += 1
                continue
            if after and _is_identifier_character(after):
                index += 1
                continue
            call_index = _skip_js_trivia(source_text, after_index)
            if call_index >= len(source_text) or source_text[call_index] != "(":
                index += 1
                continue
            argument_index = _skip_js_trivia(source_text, call_index + 1)
            parsed = _parse_quoted_specifier(source_text, argument_index)
            if parsed is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic import"
                )
            specifier, end_index = parsed
            close_index = _skip_js_trivia(source_text, end_index)
            if close_index >= len(source_text) or source_text[close_index] != ")":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic import signature"
                )
            specifiers.append(specifier)
            index = close_index + 1
            continue
        index += 1
    return specifiers


def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:
    commonjs_specifiers = _commonjs_require_specifiers(source_text)
    dynamic_specifiers = _dynamic_import_specifiers(source_text)
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, bool, str]] = []
    for match in STATIC_RUNTIME_IMPORT_SPECIFIER.finditer(source_text):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source import specifier contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, True, "import"))
    specifiers.extend((specifier, True, "import") for specifier in dynamic_specifiers)
    specifiers.extend((specifier, True, "require") for specifier in commonjs_specifiers)
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
    return name in NODE_BUILTIN_MODULES or name in NODE_BUILTIN_SUBPATHS


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


def _export_condition_targets(
    target: Any, conditions: frozenset[str]
) -> list[str]:
    if isinstance(target, str) and target:
        return [target]
    if isinstance(target, list):
        targets: list[str] = []
        for item in target:
            targets.extend(_export_condition_targets(item, conditions))
        return targets
    if isinstance(target, dict):
        for condition, value in target.items():
            if condition in conditions:
                selected = _export_condition_targets(value, conditions)
                if selected:
                    return selected
        return []
    return []


def _substitute_export_target(target: Any, replacement: str) -> Any:
    if isinstance(target, str):
        return target.replace("*", replacement)
    if isinstance(target, list):
        return [_substitute_export_target(item, replacement) for item in target]
    if isinstance(target, dict):
        return {
            key: _substitute_export_target(value, replacement)
            for key, value in target.items()
        }
    return target


def _exports_pattern_target(exports: dict[str, Any], export_key: str) -> Any:
    matches: list[tuple[int, str, Any]] = []
    for key, target in exports.items():
        if not isinstance(key, str) or "*" not in key or not key.startswith("."):
            continue
        prefix, suffix = key.split("*", 1)
        if not export_key.startswith(prefix) or not export_key.endswith(suffix):
            continue
        replacement = export_key[len(prefix) : len(export_key) - len(suffix)]
        if not replacement:
            continue
        matches.append((len(prefix) + len(suffix), replacement, target))
    if not matches:
        return None
    _, replacement, target = max(matches, key=lambda item: item[0])
    return _substitute_export_target(target, replacement)


def _exports_map_target(exports: Any, subpath: str) -> Any:
    export_key = "." if not subpath else f"./{subpath}"
    if isinstance(exports, str) or isinstance(exports, list):
        return exports if export_key == "." else None
    if not isinstance(exports, dict):
        return None
    if any(isinstance(key, str) and key.startswith(".") for key in exports):
        if export_key in exports:
            return exports.get(export_key)
        return _exports_pattern_target(exports, export_key)
    return exports if export_key == "." else None


def _package_entry_bases(
    package_root: Path,
    package_json: dict[str, Any],
    *,
    subpath: str,
    import_kind: str,
) -> tuple[list[Path], bool]:
    conditions = RUNTIME_PACKAGE_CONDITIONS.get(
        import_kind, RUNTIME_PACKAGE_CONDITIONS["import"]
    )
    exports = package_json.get("exports")
    if exports is not None:
        export_target = _exports_map_target(exports, subpath)
        targets = _export_condition_targets(export_target, conditions)
        return [(package_root / target).resolve() for target in targets], True
    if subpath:
        return [(package_root / subpath).resolve()], False
    bases: list[Path] = []
    main = package_json.get("main")
    if isinstance(main, str) and main:
        bases.append((package_root / main).resolve())
    bases.append(package_root / "index")
    return bases, False


def _package_root_candidates(root: Path, importer: Path, package_name: str) -> list[Path]:
    root = root.resolve()
    current = importer.resolve().parent
    candidates: list[Path] = []
    while True:
        try:
            current.relative_to(root)
        except ValueError:
            break
        candidates.append((current / "node_modules" / package_name).resolve())
        if current == root:
            break
        current = current.parent
    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


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
    import_kind: str = "import",
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
    subpath = _package_subpath(normalized, package_name)
    found_package_json: Path | None = None
    for package_root in _package_root_candidates(root, importer, package_name):
        try:
            package_root.relative_to(root)
        except ValueError as exc:
            raise RuntimeSourceContractError(
                "runtime package import escapes the OpenClaw candidate root"
            ) from exc
        package_json = package_root / "package.json"
        if not package_json.is_file():
            continue
        found_package_json = package_json
        package_payload = _load_package_json(package_json, package_name)
        entry_bases, export_restricted = _package_entry_bases(
            package_root,
            package_payload,
            subpath=subpath,
            import_kind=import_kind,
        )
        for base in entry_bases:
            resolved = _resolve_existing_candidate(root, base)
            if resolved is not None:
                return (package_json.resolve(), resolved)
        if export_restricted:
            break
    if required or found_package_json is None:
        importer_relative = source_relative_path(root, importer)
        raise RuntimeSourceContractError(
            "runtime package import could not be resolved: "
            f"{importer_relative} imports {specifier}"
        )
    return (found_package_json.resolve(),)


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
        for specifier, required, import_kind in import_specifiers(source_text):
            for imported in resolve_import(
                root=root,
                importer=source_path,
                specifier=specifier,
                required=required,
                import_kind=import_kind,
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
