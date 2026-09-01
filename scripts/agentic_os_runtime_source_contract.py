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
NODE_LEGACY_PACKAGE_RESOLUTION_SUFFIXES = (".js", ".json", ".node")
PERSISTENT_RUNTIME_IMPORT_SUFFIX_ALIASES = {
    ".js": (".ts", ".tsx", ".mts", ".cts", ".d.ts", ".js"),
    ".mjs": (".mts", ".mjs"),
    ".cjs": (".cts", ".cjs"),
}

JS_IDENTIFIER = r"[A-Za-z_$][0-9A-Za-z_$]*"
NODE_BUILTIN_MODULES = frozenset(
    {
        "_http_agent",
        "_http_client",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "_stream_duplex",
        "_stream_passthrough",
        "_stream_readable",
        "_stream_transform",
        "_stream_wrap",
        "_stream_writable",
        "_tls_common",
        "_tls_wrap",
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)
NODE_BUILTIN_SUBPATHS = frozenset(
    {
        "assert/strict",
        "dns/promises",
        "fs/promises",
        "inspector/promises",
        "path/posix",
        "path/win32",
        "readline/promises",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "timers/promises",
        "util/types",
    }
)
NODE_BUILTIN_NODE_ONLY_SPECIFIERS = frozenset(
    {
        "node:sea",
        "node:sqlite",
        "node:test",
        "node:test/reporters",
    }
)

STATIC_IMPORT_CLAUSE_FRAGMENT = r"""
    (?:
        "(?:\\.|[^"\\])*"
      | '(?:\\.|[^'\\])*'
      | [^;"'`]
    )*?
"""
STATIC_RUNTIME_IMPORT_SPECIFIER = re.compile(
    r"""
    \b(?:import|export)\s+(?:type\s+)?
    (?:
        __STATIC_IMPORT_CLAUSE_FRAGMENT__\s+from\s*
      |
    )
    ["'](?P<specifier>[^"']+)["']
    """.replace("__STATIC_IMPORT_CLAUSE_FRAGMENT__", STATIC_IMPORT_CLAUSE_FRAGMENT),
    re.VERBOSE | re.DOTALL,
)
COMMONJS_REQUIRE_TOKEN = "require"
COMMONJS_REQUIRE_RESOLVE_MEMBER = "resolve"
DYNAMIC_IMPORT_TOKEN = "import"
WORKER_ENTRYPOINT_SPECIFIER = re.compile(
    r"""
    \bnew\s+Worker\s*\(\s*
    new\s+URL\s*\(\s*
    ["'](?P<specifier>[^"']+)["']\s*,\s*
    import\.meta\.url\s*
    \)
    """,
    re.VERBOSE | re.DOTALL,
)
FORK_ENTRYPOINT_SPECIFIER = re.compile(
    r"""
    (?<![\w$])
    (?:fork|child_process\.fork)\s*\(\s*
    ["'](?P<specifier>[^"']+)["']
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_NODE_ENTRYPOINT_SPECIFIER = re.compile(
    r"""
    (?<![\w$])
    (?:spawn|execFile|child_process\.(?:spawn|execFile))\s*\(\s*
    process\.execPath\s*,\s*
    \[\s*["'](?P<specifier>[^"']+)["']
    """,
    re.VERBOSE | re.DOTALL,
)
EVALUATED_RUNTIME_LOADER_TOKENS = frozenset(("eval", "Function"))
CREATE_REQUIRE_IMPORT = re.compile(
    rf"""
    \bimport\s*\{{(?P<body>.*?)\}}\s*
    from\s*["'](?:node:)?module["']
    """,
    re.VERBOSE | re.DOTALL,
)
CREATE_REQUIRE_DESTRUCTURED_REQUIRE = re.compile(
    rf"""
    \b(?:const|let|var)\s*\{{(?P<body>.*?)\}}\s*=\s*
    require\s*\(\s*["'](?:node:)?module["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
CREATE_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    (?P<factory>{JS_IDENTIFIER})\s*\(
    """,
    re.VERBOSE,
)
COMMONJS_REQUIRE_ALIAS_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    \(?\s*require\s*\)?\s*(?:;|,|\n|$)
    """,
    re.VERBOSE,
)
RUNTIME_PACKAGE_CONDITIONS = {
    "import": frozenset(("import", "node-addons", "node", "default")),
    "require": frozenset(("require", "node-addons", "node", "default")),
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


def import_candidates(
    base: Path,
    *,
    suffixes: tuple[str, ...] = PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES,
    suffix_aliases: dict[str, tuple[str, ...]] | None = PERSISTENT_RUNTIME_IMPORT_SUFFIX_ALIASES,
    include_directory_index: bool = True,
) -> list[Path]:
    candidates: list[Path] = []
    suffix_aliases = suffix_aliases or {}
    if base.suffix:
        candidates.append(base)
        for suffix in suffix_aliases.get(base.suffix, (base.suffix,)):
            candidates.append(base.with_suffix(suffix))
    else:
        candidates.append(base)
        candidates.extend(
            Path(f"{base}{suffix}") for suffix in suffixes
        )
        if include_directory_index:
            candidates.extend(
                base / f"index{suffix}" for suffix in suffixes
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


def _parse_global_base(source_text: str, index: int) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if index < len(source_text) and source_text[index] == "(":
        inner_end = _parse_global_base(source_text, index + 1)
        if inner_end is None:
            return None
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        return close_index + 1
    for global_name in ("globalThis", "global"):
        if not source_text.startswith(global_name, index):
            continue
        before = source_text[index - 1] if index > 0 else ""
        end = index + len(global_name)
        after = source_text[end] if end < len(source_text) else ""
        if (before and (_is_identifier_character(before) or before == ".")) or (
            after and _is_identifier_character(after)
        ):
            continue
        return end
    return None


def _parse_process_base(source_text: str, index: int) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if index < len(source_text) and source_text[index] == "(":
        inner_end = _parse_process_base(source_text, index + 1)
        if inner_end is not None:
            close_index = _skip_js_trivia(source_text, inner_end)
            if close_index < len(source_text) and source_text[close_index] == ")":
                return close_index + 1

    process_start = index
    global_end = _parse_global_base(source_text, index)
    if global_end is not None:
        member_index = _skip_js_trivia(source_text, global_end)
        if source_text.startswith("?.", member_index):
            property_index = _skip_js_trivia(source_text, member_index + 2)
        elif member_index < len(source_text) and source_text[member_index] == ".":
            property_index = _skip_js_trivia(source_text, member_index + 1)
        elif member_index < len(source_text) and source_text[member_index] == "[":
            property_index = member_index
        else:
            return None
        if property_index < len(source_text) and source_text[property_index] == "[":
            value_index = _skip_js_trivia(source_text, property_index + 1)
            parsed = _parse_quoted_specifier(source_text, value_index)
            if parsed is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic native add-on global property access"
                )
            property_name, property_end = parsed
            bracket_end = _skip_js_trivia(source_text, property_end)
            if bracket_end >= len(source_text) or source_text[bracket_end] != "]":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic native add-on global property access"
                )
            if property_name != "process":
                return None
            return bracket_end + 1
        if source_text.startswith("process", property_index):
            index = property_index
            process_end = index + len("process")
        else:
            return None
        after = source_text[process_end] if process_end < len(source_text) else ""
        if after and _is_identifier_character(after):
            return None
        return process_end
    if not source_text.startswith("process", index):
        return None
    before = source_text[process_start - 1] if process_start > 0 else ""
    after_process = index + len("process")
    after = source_text[after_process] if after_process < len(source_text) else ""
    if (before and (_is_identifier_character(before) or before == ".")) or (
        after and _is_identifier_character(after)
    ):
        return None
    return after_process


def _parse_process_member(
    source_text: str, index: int
) -> tuple[str, int] | None:
    member_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", member_index):
        property_index = _skip_js_trivia(source_text, member_index + 2)
    elif member_index < len(source_text) and source_text[member_index] == ".":
        property_index = _skip_js_trivia(source_text, member_index + 1)
    elif member_index < len(source_text) and source_text[member_index] == "[":
        property_index = member_index
    else:
        return None

    if property_index < len(source_text) and source_text[property_index] == "[":
        value_index = _skip_js_trivia(source_text, property_index + 1)
        parsed = _parse_quoted_specifier(source_text, value_index)
        if parsed is None:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported dynamic native add-on process property access"
            )
        property_name, property_end = parsed
        bracket_end = _skip_js_trivia(source_text, property_end)
        if bracket_end >= len(source_text) or source_text[bracket_end] != "]":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported dynamic native add-on process property access"
            )
        return property_name, bracket_end + 1

    property_match = re.match(r"[A-Za-z_$][\w$]*", source_text[property_index:])
    if property_match is None:
        return None
    property_name = property_match.group(0)
    property_end = property_index + len(property_name)
    return property_name, property_end


def _parse_process_dlopen_target(source_text: str, index: int) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if index < len(source_text) and source_text[index] == "(":
        inner_end = _parse_process_dlopen_target(source_text, index + 1)
        if inner_end is not None:
            close_index = _skip_js_trivia(source_text, inner_end)
            if close_index >= len(source_text) or source_text[close_index] != ")":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on entrypoint"
                )
            return close_index + 1

    base_end = _parse_process_base(source_text, index)
    if base_end is None:
        return None
    member = _parse_process_member(source_text, base_end)
    if member is None:
        return None
    property_name, property_end = member
    if property_name != "dlopen":
        return None
    return property_end


def _parse_safe_process_member_access(source_text: str, index: int) -> int | None:
    base_end = _parse_process_base(source_text, index)
    if base_end is None:
        return None
    member = _parse_process_member(source_text, base_end)
    if member is None:
        return None
    property_name, property_end = member
    if property_name in {
        "_linkedBinding",
        "binding",
        "dlopen",
        "getBuiltinModule",
        "mainModule",
    }:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on process capability"
        )
    return property_end


def _parse_grouped_named_base(
    source_text: str, index: int, base_name: str
) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if index < len(source_text) and source_text[index] == "(":
        inner_end = _parse_grouped_named_base(source_text, index + 1, base_name)
        if inner_end is None:
            return None
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        return close_index + 1
    if not source_text.startswith(base_name, index):
        return None
    before = source_text[index - 1] if index > 0 else ""
    end = index + len(base_name)
    after = source_text[end] if end < len(source_text) else ""
    if (before and (_is_identifier_character(before) or before == ".")) or (
        after and _is_identifier_character(after)
    ):
        return None
    return end


def _capability_member_end_or_fail(source_text: str, index: int) -> int | None:
    forbidden_by_base = {
        "Module": {"_load", "constructor", "process"},
        "Reflect": {"constructor", "get", "process"},
        "module": {"_load", "constructor", "process"},
        "this": {"constructor", "process"},
    }
    for base_name, forbidden_members in forbidden_by_base.items():
        base_end = _parse_grouped_named_base(source_text, index, base_name)
        if base_end is None:
            continue
        member = _parse_process_member(source_text, base_end)
        if member is None:
            before_base = index - 1
            while before_base >= 0 and source_text[before_base].isspace():
                before_base -= 1
            if before_base >= 0 and source_text[before_base] == "=":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on capability transfer"
                )
            return None
        member_name, member_end = member
        if member_name in forbidden_members:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported native add-on capability access"
            )
        return member_end
    return None


def _quoted_literal_is_computed_member(source_text: str, quote_index: int) -> bool:
    bracket_index = quote_index - 1
    while bracket_index >= 0 and source_text[bracket_index].isspace():
        bracket_index -= 1
    if bracket_index < 0 or source_text[bracket_index] != "[":
        return False
    before_bracket = bracket_index - 1
    while before_bracket >= 0 and source_text[before_bracket].isspace():
        before_bracket -= 1
    if before_bracket < 0:
        return False
    character = source_text[before_bracket]
    if character in {")", "]", "."}:
        return True
    if not _is_identifier_character(character):
        return False
    token_end = before_bracket + 1
    token_start = before_bracket
    while token_start > 0 and _is_identifier_character(source_text[token_start - 1]):
        token_start -= 1
    token = source_text[token_start:token_end]
    return token not in {"await", "case", "return", "throw", "yield"}


def _parse_process_dlopen_invocation(
    source_text: str, index: int
) -> tuple[str, int] | None:
    target_end = _parse_process_dlopen_target(source_text, index)
    if target_end is None:
        return None
    call_index = _skip_js_trivia(source_text, target_end)
    if source_text.startswith("?.", call_index):
        call_index = _skip_js_trivia(source_text, call_index + 2)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on entrypoint"
        )
    module_index = _skip_js_trivia(source_text, call_index + 1)
    if not source_text.startswith("module", module_index):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on signature"
        )
    module_end = module_index + len("module")
    after_module = source_text[module_end] if module_end < len(source_text) else ""
    if after_module and _is_identifier_character(after_module):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on signature"
        )
    comma_index = _skip_js_trivia(source_text, module_end)
    if comma_index >= len(source_text) or source_text[comma_index] != ",":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on signature"
        )
    specifier_index = _skip_js_trivia(source_text, comma_index + 1)
    parsed = _parse_quoted_specifier(source_text, specifier_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic native add-on entrypoint"
        )
    specifier, specifier_end = parsed
    argument_end = _skip_js_trivia(source_text, specifier_end)
    if argument_end >= len(source_text) or source_text[argument_end] not in {
        ",",
        ")",
    }:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic native add-on entrypoint"
        )
    return specifier, argument_end


def _native_addon_entrypoint_specifiers(source_text: str) -> list[str]:
    specifiers: list[str] = []
    index = 0
    while index < len(source_text):
        if source_text.startswith("//", index):
            newline = source_text.find("\n", index + 2)
            index = len(source_text) if newline == -1 else newline + 1
            continue
        if source_text.startswith("/*", index):
            close = source_text.find("*/", index + 2)
            if close == -1:
                raise RuntimeSourceContractError(
                    "runtime source contains an unterminated JavaScript comment"
                )
            index = close + 2
            continue
        character = source_text[index]
        if character in {"'", '"'}:
            quote_index = index
            parsed = _parse_quoted_specifier(source_text, index)
            if parsed is None:
                raise AssertionError("quoted JavaScript literal did not parse")
            literal_value, index = parsed
            if literal_value in {"_load", "constructor", "process"} and (
                _quoted_literal_is_computed_member(source_text, quote_index)
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on capability access"
                )
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_native_addon_entrypoint_specifiers(chunk))
            continue
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        if character == "(" or (
            (character.isalpha() or character in {"_", "$"})
            and (index == 0 or not _is_identifier_character(source_text[index - 1]))
        ):
            capability_member_end = _capability_member_end_or_fail(
                source_text, index
            )
            if capability_member_end is not None:
                index = capability_member_end
                continue
            parsed = _parse_process_dlopen_invocation(source_text, index)
            if parsed is not None:
                specifier, index = parsed
                specifiers.append(specifier)
                continue
            safe_member_end = _parse_safe_process_member_access(source_text, index)
            if safe_member_end is not None:
                index = safe_member_end
                continue
            process_end = _parse_process_base(source_text, index)
            if process_end is not None:
                after_process = _skip_js_trivia(source_text, process_end)
                before_process = index - 1
                while before_process >= 0 and source_text[before_process].isspace():
                    before_process -= 1
                if (
                    after_process < len(source_text)
                    and source_text[after_process] == ":"
                    and before_process >= 0
                    and source_text[before_process] in {"{", ","}
                ):
                    index = process_end
                    continue
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on process reference transfer"
                )
            global_end = _parse_global_base(source_text, index)
            if global_end is not None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on global reference transfer"
                )
            for forbidden_member in ("_load", "process"):
                if not source_text.startswith(forbidden_member, index):
                    continue
                member_end = index + len(forbidden_member)
                after_member = (
                    source_text[member_end] if member_end < len(source_text) else ""
                )
                if after_member and _is_identifier_character(after_member):
                    continue
                before_member = index - 1
                while before_member >= 0 and source_text[before_member].isspace():
                    before_member -= 1
                if before_member >= 0 and source_text[before_member] == ".":
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported native add-on process acquisition"
                    )
        index += 1
    return specifiers


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


def _parse_bracketed_module_require_invocation(
    source_text: str, index: int
) -> tuple[str, int] | None:
    if not source_text.startswith("module", index):
        return None
    after_module = index + len("module")
    before = source_text[index - 1] if index > 0 else ""
    after = source_text[after_module] if after_module < len(source_text) else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    if after and _is_identifier_character(after):
        return None
    bracket_index = _skip_js_trivia(source_text, after_module)
    if source_text.startswith("?.", bracket_index):
        bracket_index = _skip_js_trivia(source_text, bracket_index + 2)
    if bracket_index >= len(source_text) or source_text[bracket_index] != "[":
        return None
    member_index = _skip_js_trivia(source_text, bracket_index + 1)
    parsed_member = _parse_quoted_specifier(source_text, member_index)
    if parsed_member is None:
        return None
    member, member_end = parsed_member
    if member != COMMONJS_REQUIRE_TOKEN:
        return None
    close_member = _skip_js_trivia(source_text, member_end)
    if close_member >= len(source_text) or source_text[close_member] != "]":
        return None
    call_index = _skip_js_trivia(source_text, close_member + 1)
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
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS require signature"
        )
    return specifier, close_index + 1


def _create_require_factory_names(source_text: str) -> set[str]:
    factories = {"createRequire"}
    stripped = strip_source_comments(source_text)
    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
            for part in match.group("body").split(","):
                part = part.strip()
                imported = re.fullmatch(
                    rf"createRequire(?:\s+(?:as\s+)?(?P<alias>{JS_IDENTIFIER})|\s*:\s*(?P<prop_alias>{JS_IDENTIFIER}))?",
                    part,
                )
                if imported is None:
                    continue
                factories.add(
                    imported.group("alias")
                    or imported.group("prop_alias")
                    or "createRequire"
                )
    return factories


def _create_require_loader_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    factories = _create_require_factory_names(source_text)
    loaders: set[str] = set()
    declaration_spans: set[tuple[int, int]] = set()
    stripped = strip_source_comments(source_text)
    for match in CREATE_REQUIRE_ASSIGNMENT.finditer(stripped):
        if match.group("factory") in factories:
            loaders.add(match.group("name"))
            declaration_spans.add(match.span("name"))
    return loaders, declaration_spans


def _commonjs_require_alias_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    aliases: set[str] = set()
    declaration_spans: set[tuple[int, int]] = set()
    stripped = strip_source_comments(source_text)
    for match in COMMONJS_REQUIRE_ALIAS_ASSIGNMENT.finditer(stripped):
        aliases.add(match.group("name"))
        declaration_spans.add(match.span("name"))
    return aliases, declaration_spans


def _module_register_loader_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    loaders = {"module.register"}
    declaration_spans: set[tuple[int, int]] = set()
    stripped = strip_source_comments(source_text)
    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
            for part in match.group("body").split(","):
                part = part.strip()
                imported = re.fullmatch(
                    rf"register(?:\s+(?:as\s+)?(?P<alias>{JS_IDENTIFIER})|\s*:\s*(?P<prop_alias>{JS_IDENTIFIER}))?",
                    part,
                )
                if imported is None:
                    continue
                loaders.add(
                    imported.group("alias")
                    or imported.group("prop_alias")
                    or "register"
                )
                declaration_spans.add(match.span())
    return loaders, declaration_spans


def _parse_named_loader_invocation(
    source_text: str,
    index: int,
    loader_name: str,
    *,
    loader_description: str = "createRequire loader",
) -> tuple[str, int] | None:
    if not source_text.startswith(loader_name, index):
        return None
    after_index = index + len(loader_name)
    before = source_text[index - 1] if index > 0 else ""
    after = source_text[after_index] if after_index < len(source_text) else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    if after and _is_identifier_character(after):
        return None
    call_index = _skip_js_trivia(source_text, after_index)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, call_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            f"runtime source contains an unsupported dynamic {loader_description}"
        )
    specifier, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        raise RuntimeSourceContractError(
            f"runtime source contains an unsupported {loader_description} signature"
        )
    return specifier, close_index + 1


def _parse_module_register_invocation(
    source_text: str, index: int, loader_name: str
) -> tuple[str, int] | None:
    if not source_text.startswith(loader_name, index):
        return None
    after_index = index + len(loader_name)
    before = source_text[index - 1] if index > 0 else ""
    after = source_text[after_index] if after_index < len(source_text) else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    if after and _is_identifier_character(after):
        return None
    call_index = _skip_js_trivia(source_text, after_index)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, call_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic module.register hook"
        )
    specifier, end_index = parsed
    delimiter_index = _skip_js_trivia(source_text, end_index)
    if delimiter_index >= len(source_text) or source_text[delimiter_index] != ",":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported module.register hook signature"
        )
    parent_index = _skip_js_trivia(source_text, delimiter_index + 1)
    parent_url = "import.meta.url"
    if not source_text.startswith(parent_url, parent_index):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported module.register hook parent URL"
        )
    close_index = _skip_js_trivia(source_text, parent_index + len(parent_url))
    if close_index >= len(source_text) or source_text[close_index] != ")":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported module.register hook signature"
        )
    return specifier, close_index + 1


def _is_forbidden_runtime_loader_reference(
    source_text: str, index: int, token: str
) -> bool:
    if not source_text.startswith(token, index):
        return False
    after_index = index + len(token)
    before = source_text[index - 1] if index > 0 else ""
    after = source_text[after_index] if after_index < len(source_text) else ""
    if before and _is_identifier_character(before):
        return False
    if after and _is_identifier_character(after):
        return False
    return True


def _reject_evaluated_runtime_loaders(source_text: str) -> None:
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
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                _reject_evaluated_runtime_loaders(chunk)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        for token in EVALUATED_RUNTIME_LOADER_TOKENS:
            if _is_forbidden_runtime_loader_reference(source_text, index, token):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported evaluated loader reference"
                )
        index += 1


def _previous_non_trivia_character(source_text: str, index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    return source_text[cursor] if cursor >= 0 else ""


def _previous_code_word(source_text: str, index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    return source_text[cursor + 1 : end]


def _is_regex_literal_start(source_text: str, index: int) -> bool:
    if index >= len(source_text) or source_text[index] != "/":
        return False
    next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
    if next_character in {"/", "*", ""}:
        return False
    previous = _previous_non_trivia_character(source_text, index)
    if not previous:
        return True
    if previous in "({[=,:;!&|?+-*%^~<>":
        return True
    return _previous_code_word(source_text, index) in {
        "await",
        "case",
        "delete",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }


def _regex_literal_end(source_text: str, index: int) -> int:
    if not _is_regex_literal_start(source_text, index):
        return index
    cursor = index + 1
    in_character_class = False
    while cursor < len(source_text):
        character = source_text[cursor]
        if character == "\\":
            cursor += 2
            continue
        if character == "[":
            in_character_class = True
            cursor += 1
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            cursor += 1
            continue
        if character == "/" and not in_character_class:
            cursor += 1
            while cursor < len(source_text) and _is_identifier_character(source_text[cursor]):
                cursor += 1
            return cursor
        if character in "\r\n":
            break
        cursor += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated JavaScript regex literal"
    )


def _regex_literal_end_or_fail_closed(source_text: str, index: int) -> int | None:
    """Return the regex end, or reject slash contexts the scanner cannot prove safe.

    A closing parenthesis or brace can end either an expression (where ``/`` is
    division) or a control-flow/block construct (where ``/`` can begin a regex
    literal).  Treating either case as division can make a quote inside the regex
    hide a later loader call.  Until this scanner tracks full JavaScript grammar,
    those contexts must fail closed instead of guessing.
    """

    if index >= len(source_text) or source_text[index] != "/":
        return None
    if _is_regex_literal_start(source_text, index):
        return _regex_literal_end(source_text, index)
    if _previous_non_trivia_character(source_text, index) in {")", "}"}:
        raise RuntimeSourceContractError(
            "runtime source contains an ambiguous JavaScript slash token"
        )
    return None


def _create_require_specifiers(
    source_text: str,
    inherited_loader_names: set[str] | None = None,
) -> list[str]:
    local_loader_names, declaration_spans = _create_require_loader_bindings(
        source_text
    )
    loader_names = set(inherited_loader_names or ()) | local_loader_names
    if not loader_names:
        return []
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
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_create_require_specifiers(chunk, loader_names))
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        for loader_name in sorted(loader_names, key=len, reverse=True):
            after_index = index + len(loader_name)
            before = source_text[index - 1] if index > 0 else ""
            after = source_text[after_index] if after_index < len(source_text) else ""
            is_loader_identifier = (
                source_text.startswith(loader_name, index)
                and not (before and (_is_identifier_character(before) or before == "."))
                and not (after and _is_identifier_character(after))
            )
            if not is_loader_identifier:
                continue
            if (index, after_index) in declaration_spans:
                index = after_index
                break
            parsed = _parse_named_loader_invocation(source_text, index, loader_name)
            if parsed is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported createRequire loader usage"
                )
            specifier, index = parsed
            specifiers.append(specifier)
            break
        else:
            index += 1
    return specifiers


def _commonjs_require_specifiers(
    source_text: str,
    inherited_alias_names: set[str] | None = None,
) -> list[str]:
    local_alias_names, declaration_spans = _commonjs_require_alias_bindings(source_text)
    alias_names = set(inherited_alias_names or ()) | local_alias_names
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
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_commonjs_require_specifiers(chunk, alias_names))
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        for alias_name in sorted(alias_names, key=len, reverse=True):
            after_index = index + len(alias_name)
            before = source_text[index - 1] if index > 0 else ""
            after = source_text[after_index] if after_index < len(source_text) else ""
            is_alias_identifier = (
                source_text.startswith(alias_name, index)
                and not (before and (_is_identifier_character(before) or before == "."))
                and not (after and _is_identifier_character(after))
            )
            if not is_alias_identifier:
                continue
            if (index, after_index) in declaration_spans:
                index = after_index
                break
            parsed = _parse_named_loader_invocation(
                source_text,
                index,
                alias_name,
                loader_description="CommonJS require alias",
            )
            if parsed is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS require alias usage"
                )
            specifier, index = parsed
            specifiers.append(specifier)
            break
        else:
            parsed_module_require = _parse_bracketed_module_require_invocation(
                source_text, index
            )
            if parsed_module_require is not None:
                specifier, index = parsed_module_require
                specifiers.append(specifier)
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
            continue
        continue
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
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
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


def _runtime_execution_entrypoint_specifiers(
    source_text: str,
) -> list[tuple[str, str]]:
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, str]] = []
    accepted_spans: list[tuple[int, int]] = []
    for match in WORKER_ENTRYPOINT_SPECIFIER.finditer(source_text):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source worker entrypoint contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, "import"))
        accepted_spans.append(match.span())
    for match in FORK_ENTRYPOINT_SPECIFIER.finditer(source_text):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source fork entrypoint contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, "require"))
        accepted_spans.append(match.span())
    for match in CHILD_PROCESS_NODE_ENTRYPOINT_SPECIFIER.finditer(source_text):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source child-process entrypoint contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, "import"))
        accepted_spans.append(match.span())
    for specifier in _native_addon_entrypoint_specifiers(source_text):
        specifiers.append((specifier, "require"))

    for match in re.finditer(r"\bnew\s+Worker\s*\(", source_text):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported Worker entrypoint"
            )
    for match in re.finditer(
        r"(?<![\w$])(?:fork|child_process\.fork)\s*\(", source_text
    ):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported fork entrypoint"
            )
    for match in re.finditer(
        r"(?<![\w$])(?:spawn|execFile|child_process\.(?:spawn|execFile))\s*\(\s*process\.execPath\s*,",
        source_text,
    ):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    return specifiers


def _module_register_hook_specifiers(
    source_text: str,
    inherited_loader_names: set[str] | None = None,
) -> list[str]:
    local_loader_names, declaration_spans = _module_register_loader_bindings(
        source_text
    )
    loader_names = set(inherited_loader_names or ()) | local_loader_names
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
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        if character == "`":
            chunks, index = _template_expression_chunks(source_text, index)
            for chunk in chunks:
                specifiers.extend(_module_register_hook_specifiers(chunk, loader_names))
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        for loader_name in sorted(loader_names, key=len, reverse=True):
            after_index = index + len(loader_name)
            before = source_text[index - 1] if index > 0 else ""
            after = source_text[after_index] if after_index < len(source_text) else ""
            is_loader_identifier = (
                source_text.startswith(loader_name, index)
                and not (before and (_is_identifier_character(before) or before == "."))
                and not (after and _is_identifier_character(after))
            )
            if not is_loader_identifier:
                continue
            if any(start <= index < end for start, end in declaration_spans):
                index = after_index
                break
            parsed = _parse_module_register_invocation(source_text, index, loader_name)
            if parsed is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported module.register hook usage"
                )
            specifier, index = parsed
            specifiers.append(specifier)
            break
        else:
            index += 1
    return specifiers


def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:
    _reject_evaluated_runtime_loaders(source_text)
    commonjs_specifiers = _commonjs_require_specifiers(source_text)
    create_require_specifiers = _create_require_specifiers(source_text)
    dynamic_specifiers = _dynamic_import_specifiers(source_text)
    process_module_specifiers = {"process", "node:process"}
    if process_module_specifiers.intersection(
        commonjs_specifiers + create_require_specifiers + dynamic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on process module import"
        )
    execution_entrypoints = _runtime_execution_entrypoint_specifiers(source_text)
    module_register_hooks = _module_register_hook_specifiers(source_text)
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, bool, str]] = []
    for match in STATIC_RUNTIME_IMPORT_SPECIFIER.finditer(source_text):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source import specifier contains an unsupported JavaScript escape"
            )
        if specifier in process_module_specifiers:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported native add-on process module import"
            )
        specifiers.append((specifier, True, "import"))
    specifiers.extend((specifier, True, "import") for specifier in dynamic_specifiers)
    specifiers.extend((specifier, True, "require") for specifier in commonjs_specifiers)
    specifiers.extend((specifier, True, "require") for specifier in create_require_specifiers)
    specifiers.extend(
        (specifier, True, import_kind)
        for specifier, import_kind in execution_entrypoints
    )
    specifiers.extend((specifier, True, "import") for specifier in module_register_hooks)
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
    if specifier in NODE_BUILTIN_NODE_ONLY_SPECIFIERS:
        return True
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
) -> tuple[list[tuple[Path, str]], bool]:
    conditions = RUNTIME_PACKAGE_CONDITIONS.get(
        import_kind, RUNTIME_PACKAGE_CONDITIONS["import"]
    )
    exports = package_json.get("exports")
    if exports is not None:
        export_target = _exports_map_target(exports, subpath)
        targets = _export_condition_targets(export_target, conditions)
        return [((package_root / target).resolve(), "runtime") for target in targets], True
    if subpath:
        return [((package_root / subpath).resolve(), "node_legacy")], False
    bases: list[tuple[Path, str]] = []
    main = package_json.get("main")
    if isinstance(main, str) and main:
        bases.append(((package_root / main).resolve(), "node_legacy"))
    bases.append((package_root / "index", "node_legacy"))
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


def _resolve_existing_candidate(
    root: Path,
    base: Path,
    *,
    suffixes: tuple[str, ...] = PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES,
    suffix_aliases: dict[str, tuple[str, ...]] | None = PERSISTENT_RUNTIME_IMPORT_SUFFIX_ALIASES,
    include_directory_index: bool = True,
) -> Path | None:
    for candidate in import_candidates(
        base,
        suffixes=suffixes,
        suffix_aliases=suffix_aliases,
        include_directory_index=include_directory_index,
    ):
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


def _resolve_commonjs_directory_package(
    root: Path,
    directory: Path,
    *,
    package_name: str,
) -> tuple[Path, ...]:
    package_json = directory / "package.json"
    if not package_json.is_file():
        return ()
    package_payload = _load_package_json(package_json, package_name)
    bases: list[Path] = []
    main = package_payload.get("main")
    if isinstance(main, str) and main:
        bases.append((directory / main).resolve())
    bases.append((directory / "index").resolve())
    for base in bases:
        resolved = _resolve_existing_candidate(
            root,
            base,
            suffixes=NODE_LEGACY_PACKAGE_RESOLUTION_SUFFIXES,
            suffix_aliases={},
            include_directory_index=True,
        )
        if resolved is not None:
            return (package_json.resolve(), resolved)
    return (package_json.resolve(),)


def resolve_import(
    *,
    root: Path,
    importer: Path,
    specifier: str,
    required: bool,
    import_kind: str = "import",
) -> tuple[Path, ...]:
    normalized = (
        specifier
        if import_kind == "require"
        else specifier.split("?", 1)[0].split("#", 1)[0]
    )
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
        resolved = _resolve_existing_candidate(
            root,
            base,
            include_directory_index=import_kind != "require",
        )
        if resolved is not None:
            return (resolved,)
        if import_kind == "require":
            resolved_package = _resolve_commonjs_directory_package(
                root,
                base,
                package_name=specifier,
            )
            if len(resolved_package) > 1:
                return resolved_package
            resolved = _resolve_existing_candidate(root, base)
            if resolved is not None:
                return resolved_package + (resolved,) if resolved_package else (resolved,)
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
        for base, resolution_style in entry_bases:
            if resolution_style == "node_legacy":
                resolved = _resolve_existing_candidate(
                    root,
                    base,
                    suffixes=NODE_LEGACY_PACKAGE_RESOLUTION_SUFFIXES,
                    suffix_aliases={},
                )
            else:
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
