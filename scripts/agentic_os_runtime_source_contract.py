#!/usr/bin/env python3
"""Shared source-closure contract for persistent OpenClaw runtime evidence."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
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
    (".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx")
)
PERSISTENT_RUNTIME_RESOLUTION_SUFFIXES = (
    ".ts",
    ".tsx",
    ".jsx",
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
    ".js": (".ts", ".tsx", ".jsx", ".mts", ".cts", ".d.ts", ".js"),
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
    \b(?:import|export)\s*(?:type\s+)?
    (?:
        __STATIC_IMPORT_CLAUSE_FRAGMENT__\s*from\s*
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
WORKER_THREADS_IMPORT = re.compile(
    rf"""
    \bimport\s*(?:{JS_IDENTIFIER}\s*,\s*)?\{{(?P<body>.*?)\}}\s*
    from\s*["'](?:node:)?worker_threads["']
    """,
    re.VERBOSE | re.DOTALL,
)
WORKER_THREADS_NAMESPACE_IMPORT = re.compile(
    rf"""
    \bimport\s+\*\s+as\s+(?P<name>{JS_IDENTIFIER})\s*
    from\s*["'](?:node:)?worker_threads["']
    """,
    re.VERBOSE | re.DOTALL,
)
WORKER_THREADS_DEFAULT_IMPORT = re.compile(
    rf"""
    \bimport\s+(?P<name>{JS_IDENTIFIER})\s*
    (?:,\s*(?:\{{.*?\}}|\*\s+as\s+{JS_IDENTIFIER})\s*)?
    from\s*["'](?:node:)?worker_threads["']
    """,
    re.VERBOSE | re.DOTALL,
)
WORKER_THREADS_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?worker_threads["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
WORKER_THREADS_DESTRUCTURED_REQUIRE = re.compile(
    rf"""
    \b(?:const|let|var)\s*\{{(?P<body>.*?)\}}\s*=\s*
    require\s*\(\s*["'](?:node:)?worker_threads["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_IMPORT = re.compile(
    rf"""
    \bimport\s*(?:(?P<default>{JS_IDENTIFIER})\s*,\s*)?\{{(?P<body>.*?)\}}\s*
    from\s*["'](?:node:)?child_process["']
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_DESTRUCTURED_REQUIRE = re.compile(
    rf"""
    \b(?:const|let|var)\s*\{{(?P<body>.*?)\}}\s*=\s*
    require\s*\(\s*["'](?:node:)?child_process["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_NAMESPACE_IMPORT = re.compile(
    rf"""
    \bimport\s+\*\s+as\s+(?P<name>{JS_IDENTIFIER})\s*
    from\s*["'](?:node:)?child_process["']
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_DEFAULT_IMPORT = re.compile(
    rf"""
    \bimport\s+(?P<name>{JS_IDENTIFIER})\s*
    (?:,\s*(?:\{{.*?\}}|\*\s+as\s+{JS_IDENTIFIER})\s*)?
    from\s*["'](?:node:)?child_process["']
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?child_process["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
CHILD_PROCESS_FORK_ENTRYPOINT_NAMES = frozenset(("fork",))
CHILD_PROCESS_NODE_ENTRYPOINT_NAMES = frozenset(
    ("spawn", "spawnSync", "execFile", "execFileSync")
)
CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES = frozenset(("exec", "execSync"))
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
    (?:
        spawn
      | spawnSync
      | execFile
      | execFileSync
      | child_process\.(?:spawn|spawnSync|execFile|execFileSync)
    )\s*\(\s*
    process\.execPath\s*,\s*
    \[\s*["'](?P<specifier>[^"']+)["']
    """,
    re.VERBOSE | re.DOTALL,
)
INLINE_REQUIRE_CHILD_PROCESS_ENTRYPOINT = re.compile(
    r"""
    \brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)
    \s*(?:
        (?:\.|\?\.)\s*(?:fork|spawn|spawnSync|execFile|execFileSync|exec|execSync)
      |
        (?:\.|\?\.)?\s*\[\s*["'](?:fork|spawn|spawnSync|execFile|execFileSync|exec|execSync)["']\s*\]
    )\s*\(
    """,
    re.VERBOSE | re.DOTALL,
)
INLINE_REQUIRE_CHILD_PROCESS_COMPUTED_MEMBER = re.compile(
    r"""
    \brequire\s*\(\s*[\"'](?:node:)?child_process[\"']\s*\)
    \s*(?:\.|\?\.)?\s*\[
    """,
    re.VERBOSE | re.DOTALL,
)
INLINE_REQUIRE_MODULE_COMPUTED_MEMBER = re.compile(
    r"""
    \brequire\s*\(\s*[\"'](?:node:)?module[\"']\s*\)
    \s*(?:\.|\?\.)?\s*\[
    """,
    re.VERBOSE | re.DOTALL,
)
EVALUATED_RUNTIME_LOADER_TOKENS = frozenset(
    ("constructor", "eval", "Function", "registerHooks")
)
EVALUATED_RUNTIME_WEBASSEMBLY_TOKENS = frozenset(("WebAssembly",))
EVALUATED_RUNTIME_TEST_RUNNER_SPECIFIERS = frozenset(
    ("test", "node:test", "test/reporters", "node:test/reporters")
)
EVALUATED_RUNTIME_VM_SPECIFIERS = frozenset(("vm", "node:vm"))
EVALUATED_RUNTIME_SQLITE_SPECIFIERS = frozenset(("sqlite", "node:sqlite"))
EVALUATED_RUNTIME_INSPECTOR_SPECIFIERS = frozenset(
    ("inspector", "inspector/promises", "node:inspector", "node:inspector/promises")
)
EVALUATED_RUNTIME_REPL_SPECIFIERS = frozenset(("repl", "node:repl"))
EVALUATED_RUNTIME_CLUSTER_SPECIFIERS = frozenset(("cluster", "node:cluster"))
EVALUATED_RUNTIME_SQLITE_TOKENS = frozenset(("loadExtension",))
NODE_MODULE_SPECIFIERS = frozenset(("module", "node:module"))
CHILD_PROCESS_SPECIFIERS = frozenset(("child_process", "node:child_process"))
COMMONJS_CUSTOM_EXTENSION_MEMBER_NAMES = frozenset(("_extensions", "extensions"))
COMMONJS_COMPILE_MEMBER_NAMES = frozenset(("_compile",))
COMMONJS_RUNTIME_LOADER_MEMBER_NAMES = frozenset(
    ("register", "registerHooks", "runMain")
)
COMMONJS_MODULE_CONSTRUCTOR_MEMBER_NAMES = frozenset(("Module", "default"))
COMMONJS_MODULE_INSTANCE_RUNTIME_LOADER_MEMBER_NAMES = frozenset(("load",))
EVALUATED_RUNTIME_VM_MEMBER_NAMES = frozenset(
    (
        "compileFunction",
        "createContext",
        "runInContext",
        "runInNewContext",
        "runInThisContext",
        "Script",
        "SourceTextModule",
        "SyntheticModule",
    )
)
CREATE_REQUIRE_IMPORT = re.compile(
    rf"""
    \bimport\s*(?:{JS_IDENTIFIER}\s*,\s*)?\{{(?P<body>.*?)\}}\s*
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
INLINE_CREATE_REQUIRE_SPECIFIER = re.compile(
    rf"""
    (?:
        require\s*\(\s*["'](?:node:)?module["']\s*\)
      | process\s*(?:\.|\?\.)\s*getBuiltinModule\s*\(\s*["'](?:node:)?module["']\s*\)
      | {JS_IDENTIFIER}
    )
    \s*(?:\.|\?\.)\s*createRequire\s*
    \([^)]*\)\s*
    \(\s*["'](?P<specifier>[^"']+)["']
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_MODULE_NAMESPACE_IMPORT = re.compile(
    rf"""
    \bimport\s+\*\s+as\s+(?P<name>{JS_IDENTIFIER})\s*
    from\s*["'](?:node:)?module["']
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_MODULE_DEFAULT_IMPORT = re.compile(
    rf"""
    \bimport\s+(?P<name>{JS_IDENTIFIER})\s*
    (?:,\s*(?:\{{.*?\}}|\*\s+as\s+{JS_IDENTIFIER})\s*)?
    from\s*["'](?:node:)?module["']
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_MODULE_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?module["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_TEST_IMPORT = re.compile(
    rf"""
    \bimport\s+\{{(?P<body>.*?)\}}\s*from\s*["'](?:node:)?test(?:/reporters)?["']
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_TEST_DEFAULT_OR_NAMESPACE_IMPORT = re.compile(
    rf"""
    \bimport\s+(?:
        (?P<default>{JS_IDENTIFIER})\s*
      | \*\s+as\s+(?P<namespace>{JS_IDENTIFIER})
    )\s+from\s*["'](?:node:)?test(?:/reporters)?["']
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_TEST_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?test(?:/reporters)?["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_TEST_REQUIRE_DESTRUCTURED_REQUIRE = re.compile(
    rf"""
    \b(?:const|let|var)\s*\{{(?P<body>.*?)\}}\s*=\s*
    require\s*\(\s*["'](?:node:)?test(?:/reporters)?["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
VM_IMPORT = re.compile(
    rf"""
    \bimport\s+(?:
        (?P<default>{JS_IDENTIFIER})\s*
      | \*\s+as\s+(?P<namespace>{JS_IDENTIFIER})
    )\s+from\s*["'](?:node:)?vm["']
    """,
    re.VERBOSE | re.DOTALL,
)
VM_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?vm["']\s*\)
    """,
    re.VERBOSE | re.DOTALL,
)
NODE_MODULE_MEMBER_REQUIRE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(\s*["'](?:node:)?module["']\s*\)
    \s*(?:\.|\?\.)\s*Module
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
INDIRECT_COMMONJS_REQUIRE_INVOCATION = re.compile(
    rf"""
    (?:
        (?<![\w$.])
        require\s*(?:\.|\?\.)\s*(?:call|apply)\s*\(
      |
        (?<![\w$.])
        Reflect\s*(?:\.|\?\.)\s*apply\s*\(\s*require\s*,
    )
    """,
    re.VERBOSE | re.DOTALL,
)
RUNTIME_PACKAGE_CONDITIONS = {
    "import": frozenset(
        ("module-sync", "import", "node-addons", "node", "default")
    ),
    "require": frozenset(
        ("module-sync", "require", "node-addons", "node", "default")
    ),
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


def _javascript_lexical_items(source_text: str):
    """Yield (kind, start, end) without losing executable template expressions.

    Comment recognition belongs here, not in the individual loader collectors.
    Offsets always refer to the original input, including nested templates. This
    is a conservative lexical scanner, not a JavaScript grammar validator: an
    ambiguous slash context is rejected rather than guessed.
    """
    length = len(source_text)
    prefix_words = {"await", "case", "delete", "else", "in", "instanceof",
                    "new", "of", "return", "throw", "typeof", "void", "yield"}
    prefix_tokens = {"(", "{", "[", "=", ",", ":", ";", "!", "&", "|",
                     "?", "+", "-", "*", "/", "%", "^", "~", "<", ">"}

    def code(index: int, *, template_expression: bool = False, level: int = 0):
        if level > 128:
            raise RuntimeSourceContractError("runtime source nesting is unsupported")
        braces = 0
        previous = ""
        line_has_code = template_expression
        while index < length:
            start = index
            character = source_text[index]
            if character.isspace():
                if _is_js_line_terminator(character):
                    line_has_code = False
                index += 1
                continue
            line_comment = (
                source_text.startswith("//", index)
                or source_text.startswith("<!--", index)
                or (not line_has_code and source_text.startswith("-->", index))
                or (index == 0 and source_text.startswith("#!", index))
            )
            if line_comment:
                while index < length and not _is_js_line_terminator(source_text[index]):
                    index += 1
                yield "comment", start, index
                continue
            if source_text.startswith("/*", index):
                close = source_text.find("*/", index + 2)
                if close < 0:
                    raise RuntimeSourceContractError(
                        "runtime source contains an unterminated JavaScript comment"
                    )
                index = close + 2
                if any(_is_js_line_terminator(c) for c in source_text[start:index]):
                    line_has_code = False
                yield "comment", start, index
                continue
            line_has_code = True
            if character in {"'", '"'}:
                index = _quoted_literal_end(source_text, index)
                yield "string", start, index
                previous = "literal"
                continue
            if character == "`":
                yield "template-start", index, index + 1
                index += 1
                raw_start = index
                while index < length:
                    if source_text[index] == "\\":
                        index += 2
                        continue
                    if source_text[index] == "`":
                        yield "template-raw", raw_start, index
                        yield "template-end", index, index + 1
                        index += 1
                        break
                    if source_text.startswith("${", index):
                        yield "template-raw", raw_start, index
                        yield "template-open", index, index + 2
                        index = yield from code(index + 2, template_expression=True,
                                                level=level + 1)
                        raw_start = index
                        continue
                    index += 1
                else:
                    raise RuntimeSourceContractError(
                        "runtime source contains an unterminated JavaScript template literal"
                    )
                previous = "literal"
                continue
            if character == "/":
                # Contextual keywords can be identifiers in CommonJS; keyword
                # properties are values. TypeScript also has postfix ! and
                # instantiation expressions ending in >. In these contexts a
                # slash may be division whose RHS executes a loader. Reject the
                # ambiguity rather than masking that RHS as a regex literal.
                if previous in {")", "}", "!", ">", "of", "await", "yield"} or previous.startswith("property-keyword:"):
                    raise RuntimeSourceContractError(
                        "runtime source contains an ambiguous JavaScript slash token"
                    )
                if not previous or previous in prefix_tokens or previous in prefix_words:
                    index += 1
                    in_class = False
                    while index < length:
                        c = source_text[index]
                        if _is_js_line_terminator(c):
                            break
                        if c == "\\":
                            index += 2
                            continue
                        if c == "[":
                            in_class = True
                        elif c == "]":
                            in_class = False
                        elif c == "/" and not in_class:
                            index += 1
                            while index < length and _is_identifier_character(source_text[index]):
                                index += 1
                            yield "regex", start, index
                            previous = "literal"
                            break
                        index += 1
                    else:
                        index = length
                    if previous != "literal":
                        raise RuntimeSourceContractError(
                            "runtime source contains an unterminated JavaScript regex literal"
                        )
                    continue
            if character == "}" and template_expression and braces == 0:
                yield "template-close", index, index + 1
                return index + 1
            if character == "{":
                braces += 1
            elif character == "}":
                braces -= 1
            if _is_identifier_character(character) or character == "\\":
                index += 1
                while index < length and _is_identifier_character(source_text[index]):
                    index += 1
            elif source_text[index:index + 2] in {"++", "--", "?."}:
                index += 2
            else:
                index += 1
            token = source_text[start:index]
            previous = ("property-keyword:" + token
                        if previous in {".", "?.", "#"} and token in prefix_words
                        else token)
            yield "code", start, index
        if template_expression:
            raise RuntimeSourceContractError(
                "runtime source contains an unterminated JavaScript template expression"
            )
        return index

    yield from code(0)


def strip_source_comments(source_text: str) -> str:
    output = list(source_text)
    for kind, start, end in _javascript_lexical_items(source_text):
        if kind == "comment":
            output[start:end] = [
                c if _is_js_line_terminator(c) else " "
                for c in source_text[start:end]
            ]
    return "".join(output)


def _is_identifier_character(character: str) -> bool:
    return character.isalnum() or character in {"_", "$"}


def _is_js_line_terminator(character: str) -> bool:
    return character in {"\n", "\r", "\u2028", "\u2029"}


def _decode_js_identifier_escape(source_text: str, index: int) -> tuple[str, int]:
    if not source_text.startswith("\\u", index):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported JavaScript identifier escape"
        )
    if index + 2 < len(source_text) and source_text[index + 2] == "{":
        close_index = source_text.find("}", index + 3)
        if close_index == -1:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported JavaScript identifier escape"
            )
        digits = source_text[index + 3 : close_index]
        next_index = close_index + 1
    else:
        digits = source_text[index + 2 : index + 6]
        next_index = index + 6
    if not digits or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported JavaScript identifier escape"
        )
    try:
        character = chr(int(digits, 16))
    except (OverflowError, ValueError) as exc:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported JavaScript identifier escape"
        ) from exc
    if not character.isascii() or not _is_identifier_character(character):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported JavaScript identifier escape"
        )
    return character, next_index


def _parse_js_identifier(source_text: str, index: int) -> tuple[str, int] | None:
    if index >= len(source_text):
        return None
    parts: list[str] = []
    first = True
    while index < len(source_text):
        character = source_text[index]
        if character == "\\":
            character, index = _decode_js_identifier_escape(source_text, index)
        elif _is_identifier_character(character):
            index += 1
        else:
            break
        if first and character.isdigit():
            return None
        parts.append(character)
        first = False
    return ("".join(parts), index) if parts else None


def _decode_js_identifier_escapes_in_executable_code(source_text: str) -> str:
    output: list[str] = []
    copied = 0
    for kind, start, _end in _javascript_lexical_items(source_text):
        if kind != "code" or start < copied or source_text[start] != "\\":
            continue
        decoded, end = _decode_js_identifier_escape(source_text, start)
        output.extend((source_text[copied:start], decoded))
        copied = end
    output.append(source_text[copied:])
    return "".join(output)


def _parse_named_binding_part(part: str) -> tuple[str, str] | None:
    part = part.strip()
    if not part:
        return None
    if part[0] in {"'", '"'}:
        parsed_literal = _parse_quoted_specifier(part, 0)
        if parsed_literal is None:
            return None
        imported_name, index = parsed_literal
    else:
        parsed_identifier = _parse_js_identifier(part, 0)
        if parsed_identifier is None:
            return None
        imported_name, index = parsed_identifier
    index = _skip_whitespace(part, index)
    if index == len(part):
        return imported_name, imported_name
    if part.startswith("as", index):
        after_as = index + 2
        after = part[after_as] if after_as < len(part) else ""
        if after and not after.isspace():
            return None
        parsed_alias = _parse_js_identifier(part, _skip_whitespace(part, after_as))
        if parsed_alias is None:
            return None
        alias_name, alias_end = parsed_alias
        return (imported_name, alias_name) if part[alias_end:].strip() == "" else None
    if part[index] != ":":
        return None
    parsed_alias = _parse_js_identifier(part, _skip_whitespace(part, index + 1))
    if parsed_alias is None:
        return None
    alias_name, alias_end = parsed_alias
    return (imported_name, alias_name) if part[alias_end:].strip() == "" else None


def _skip_whitespace(source_text: str, index: int) -> int:
    while index < len(source_text) and source_text[index].isspace():
        index += 1
    return index


def _skip_js_trivia(source_text: str, index: int) -> int:
    while index < len(source_text):
        index = _skip_whitespace(source_text, index)
        if source_text.startswith("//", index):
            index += 2
            while index < len(source_text) and not _is_js_line_terminator(
                source_text[index]
            ):
                index += 1
            if index == len(source_text):
                return len(source_text)
            index += 1
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


def _quoted_literal_end(source_text: str, index: int) -> int:
    if index >= len(source_text) or source_text[index] not in {"'", '"'}:
        raise RuntimeSourceContractError(
            "runtime source contains an unterminated JavaScript string"
        )
    quote = source_text[index]
    index += 1
    while index < len(source_text):
        character = source_text[index]
        if character == "\\" and index + 1 < len(source_text):
            index += 2
            continue
        if character == quote:
            return index + 1
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated JavaScript string"
    )


def _skip_static_dynamic_import_attributes(source_text: str, index: int) -> int:
    index = _skip_js_trivia(source_text, index)
    if index >= len(source_text) or source_text[index] != "{":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic import signature"
        )
    depth = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
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
            if character == "\\":
                raise RuntimeSourceContractError(
                    "runtime source import attributes contain an unsupported JavaScript escape"
                )
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
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            if character != "{":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic import signature"
                )
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if character != "}":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic import signature"
                )
            depth -= 1
            index += 1
            if depth == 0:
                return index
            continue
        if character in "`,;":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported dynamic import signature"
            )
        if not (
            character.isspace()
            or character in ":_-"
            or character.isalnum()
            or character in "$"
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported dynamic import signature"
            )
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unsupported dynamic import signature"
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
    parsed_global = _parse_js_identifier(source_text, index)
    if parsed_global is None:
        return None
    parsed_global_name, end = parsed_global
    for global_name in ("globalThis", "global"):
        if parsed_global_name != global_name:
            continue
        before = source_text[index - 1] if index > 0 else ""
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
        parsed_process = _parse_js_identifier(source_text, property_index)
        if parsed_process is None or parsed_process[0] != "process":
            return None
        process_end = parsed_process[1]
        after = source_text[process_end] if process_end < len(source_text) else ""
        if after and _is_identifier_character(after):
            return None
        return process_end
    parsed_process = _parse_js_identifier(source_text, index)
    if parsed_process is None or parsed_process[0] != "process":
        return None
    before = source_text[process_start - 1] if process_start > 0 else ""
    after_process = parsed_process[1]
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

    parsed_property = _parse_js_identifier(source_text, property_index)
    if parsed_property is None:
        return None
    return parsed_property


def _parse_named_runtime_base(
    source_text: str, index: int, base_name: str
) -> int | None:
    parsed = _parse_js_identifier(source_text, index)
    if parsed is None or parsed[0] != base_name:
        return None
    before = source_text[index - 1] if index > 0 else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    return parsed[1]


def _parse_named_runtime_member(
    source_text: str, index: int, base_name: str
) -> tuple[str, int] | None:
    base_end = _parse_named_runtime_base(source_text, index, base_name)
    if base_end is None:
        return None
    return _parse_process_member(source_text, base_end)


def _parse_static_runtime_member(
    source_text: str, index: int, *, dynamic_error: str
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
        computed_member = _static_computed_member_name(source_text, property_index)
        if computed_member is None:
            raise RuntimeSourceContractError(dynamic_error)
        return computed_member

    parsed_property = _parse_js_identifier(source_text, property_index)
    if parsed_property is None:
        return None
    return parsed_property


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
        "execve",
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
    depth = 0
    while index < len(source_text) and source_text[index] == "(":
        depth += 1
        index = _skip_js_trivia(source_text, index + 1)
    if not source_text.startswith(base_name, index):
        return None
    before = source_text[index - 1] if index > 0 else ""
    end = index + len(base_name)
    after = source_text[end] if end < len(source_text) else ""
    if (before and (_is_identifier_character(before) or before == ".")) or (
        after and _is_identifier_character(after)
    ):
        return None
    for _ in range(depth):
        end = _skip_js_trivia(source_text, end)
        if end >= len(source_text) or source_text[end] != ")":
            return None
        end += 1
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
            after_base = _skip_js_trivia(source_text, base_end)
            if (
                after_base < len(source_text)
                and source_text[after_base] == ":"
                and before_base >= 0
                and source_text[before_base] in {"{", ","}
            ):
                return base_end
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported native add-on capability transfer"
            )
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


def _computed_member_bracket_has_target(source_text: str, bracket_index: int) -> bool:
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


def _parse_static_template_member(
    source_text: str, index: int
) -> tuple[str, int] | None:
    if index >= len(source_text) or source_text[index] != "`":
        return None
    index += 1
    value: list[str] = []
    while index < len(source_text):
        character = source_text[index]
        if character == "\\" or source_text.startswith("${", index):
            return None
        if character == "`":
            return "".join(value), index + 1
        value.append(character)
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unterminated JavaScript template literal"
    )


def _static_computed_member_name(
    source_text: str, bracket_index: int
) -> tuple[str, int] | None:
    if not _computed_member_bracket_has_target(source_text, bracket_index):
        return None
    index = _skip_js_trivia(source_text, bracket_index + 1)
    pieces: list[str] = []
    while index < len(source_text):
        parsed = _parse_quoted_specifier(source_text, index)
        if parsed is None:
            parsed = _parse_static_template_member(source_text, index)
        if parsed is None:
            return None
        piece, index = parsed
        pieces.append(piece)
        index = _skip_js_trivia(source_text, index)
        if index < len(source_text) and source_text[index] == "]":
            return "".join(pieces), index + 1
        if index >= len(source_text) or source_text[index] != "+":
            return None
        index = _skip_js_trivia(source_text, index + 1)
    return None


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
        if character == "[":
            computed_member = _static_computed_member_name(source_text, index)
            if computed_member is not None:
                member_name, member_end = computed_member
                if member_name in {"_load", "constructor", "dlopen", "process"}:
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported native add-on capability access"
                    )
                index = member_end
                continue
        if character in {"'", '"'}:
            quote_index = index
            if not _quoted_literal_is_computed_member(source_text, quote_index):
                index = _quoted_literal_end(source_text, index)
                continue
            parsed = _parse_quoted_specifier(source_text, index)
            if parsed is None:
                raise AssertionError("quoted JavaScript literal did not parse")
            literal_value, index = parsed
            if literal_value in {"_load", "constructor", "process"}:
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


def _reject_indirect_parenthesized_commonjs_require_invocation(
    source_text: str, index: int
) -> None:
    if index >= len(source_text) or source_text[index] != "(":
        return
    expression_end = _parenthesized_expression_end(source_text, index)
    call_index = _skip_js_trivia(source_text, expression_end)
    if source_text.startswith("?.", call_index):
        call_index = _skip_js_trivia(source_text, call_index + 2)
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return
    expression = source_text[index + 1 : expression_end - 1]
    if re.search(rf"(?<![\w$.]){COMMONJS_REQUIRE_TOKEN}(?![\w$])", expression):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect CommonJS require invocation"
        )


def _template_expression_chunks(source_text: str, index: int) -> tuple[list[str], int]:
    if source_text[index:index + 1] != "`":
        raise RuntimeSourceContractError("runtime source has an invalid template start")
    chunks: list[str] = []
    template_depth = 0
    expression_start: int | None = None
    for kind, start, end in _javascript_lexical_items(source_text[index:]):
        if kind == "template-start":
            template_depth += 1
        elif kind == "template-end":
            template_depth -= 1
            if template_depth == 0:
                return chunks, index + end
        elif template_depth == 1 and kind == "template-open":
            expression_start = index + end
        elif template_depth == 1 and kind == "template-close":
            if expression_start is None:
                raise RuntimeSourceContractError("runtime source has an invalid template expression")
            chunks.append(source_text[expression_start:index + start])
            expression_start = None
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
        for match in _executable_pattern_matches(stripped, pattern):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "createRequire":
                    factories.add(local_name)
    return factories


def _create_require_loader_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    factories = _create_require_factory_names(source_text)
    loaders: set[str] = set()
    declaration_spans: set[tuple[int, int]] = set()
    stripped = strip_source_comments(source_text)
    for match in _executable_pattern_matches(stripped, CREATE_REQUIRE_ASSIGNMENT):
        if match.group("factory") in factories:
            loaders.add(match.group("name"))
            declaration_spans.add(match.span("name"))
    return loaders, declaration_spans


def _commonjs_require_alias_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    aliases: set[str] = set()
    declaration_spans: set[tuple[int, int]] = set()
    assignment = re.compile(rf"\b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*")
    for match in _executable_pattern_matches(source_text, assignment):
        end = _parse_grouped_named_base(source_text, match.end(), "require")
        if end is None:
            continue
        tail = _skip_js_trivia(source_text, end)
        if tail != len(source_text) and source_text[tail] not in ";,":
            # ASI is only safe when the following token cannot continue the RHS.
            if not any(_is_js_line_terminator(c) for c in source_text[end:tail]):
                continue
            if source_text[tail] in "([.`?":
                continue
        aliases.add(match.group("name"))
        declaration_spans.add(match.span("name"))
    return aliases, declaration_spans


def _node_test_runner_bindings(
    source_text: str,
) -> tuple[set[str], set[str]]:
    run_names: set[str] = set()
    namespace_names: set[str] = set()
    stripped = strip_source_comments(source_text)
    for match in NODE_TEST_IMPORT.finditer(stripped):
        for part in match.group("body").split(","):
            binding = _parse_named_binding_part(part)
            if binding is None:
                continue
            imported_name, local_name = binding
            if imported_name == "run":
                run_names.add(local_name)
    for match in NODE_TEST_DEFAULT_OR_NAMESPACE_IMPORT.finditer(stripped):
        default_name = match.group("default")
        namespace_name = match.group("namespace")
        if default_name is not None:
            namespace_names.add(default_name)
        if namespace_name is not None:
            namespace_names.add(namespace_name)
    for match in NODE_TEST_REQUIRE_ASSIGNMENT.finditer(stripped):
        namespace_names.add(match.group("name"))
    for match in NODE_TEST_REQUIRE_DESTRUCTURED_REQUIRE.finditer(stripped):
        for part in match.group("body").split(","):
            binding = _parse_named_binding_part(part)
            if binding is None:
                continue
            imported_name, local_name = binding
            if imported_name == "run":
                run_names.add(local_name)
    return run_names, namespace_names


def _vm_namespace_names(
    source_text: str,
) -> set[str]:
    names: set[str] = {"vm"}
    stripped = strip_source_comments(source_text)
    for match in VM_IMPORT.finditer(stripped):
        default_name = match.group("default")
        namespace_name = match.group("namespace")
        if default_name is not None:
            names.add(default_name)
        if namespace_name is not None:
            names.add(namespace_name)
    for match in VM_REQUIRE_ASSIGNMENT.finditer(stripped):
        names.add(match.group("name"))
    return names


def _module_register_loader_bindings(
    source_text: str,
) -> tuple[set[str], set[tuple[int, int]]]:
    loaders = {"module.register"}
    declaration_spans: set[tuple[int, int]] = set()
    stripped = strip_source_comments(source_text)
    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "register":
                    loaders.add(local_name)
                    declaration_spans.add(match.span())
    return loaders, declaration_spans


def _worker_thread_bindings(source_text: str) -> tuple[set[str], set[str]]:
    stripped = strip_source_comments(source_text)
    constructor_names = {"Worker"}
    namespace_names: set[str] = set()

    for pattern in (WORKER_THREADS_IMPORT, WORKER_THREADS_DESTRUCTURED_REQUIRE):
        for match in _executable_pattern_matches(stripped, pattern):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "Worker":
                    constructor_names.add(local_name)
    for pattern in (
        WORKER_THREADS_NAMESPACE_IMPORT,
        WORKER_THREADS_DEFAULT_IMPORT,
        WORKER_THREADS_REQUIRE_ASSIGNMENT,
    ):
        for match in _executable_pattern_matches(stripped, pattern):
            namespace_names.add(match.group("name"))
    return constructor_names, namespace_names


def _child_process_sync_alias_bindings(
    source_text: str,
) -> tuple[set[str], set[str], set[str], set[str]]:
    stripped = strip_source_comments(source_text)
    fork_entrypoint_names: set[str] = set()
    node_entrypoint_names: set[str] = set()
    sync_shell_names: set[str] = set()
    namespace_names = {"child_process"}

    for pattern in (CHILD_PROCESS_IMPORT, CHILD_PROCESS_DESTRUCTURED_REQUIRE):
        for match in _executable_pattern_matches(stripped, pattern):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                entrypoint, local_name = binding
                if entrypoint in CHILD_PROCESS_FORK_ENTRYPOINT_NAMES:
                    fork_entrypoint_names.add(local_name)
                elif entrypoint in CHILD_PROCESS_NODE_ENTRYPOINT_NAMES:
                    node_entrypoint_names.add(local_name)
                elif entrypoint in CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES:
                    sync_shell_names.add(local_name)
    for pattern in (
        CHILD_PROCESS_NAMESPACE_IMPORT,
        CHILD_PROCESS_DEFAULT_IMPORT,
        CHILD_PROCESS_REQUIRE_ASSIGNMENT,
    ):
        for match in _executable_pattern_matches(stripped, pattern):
            namespace_names.add(match.group("name"))
    _add_child_process_transferred_aliases(
        stripped,
        fork_entrypoint_names=fork_entrypoint_names,
        node_entrypoint_names=node_entrypoint_names,
        sync_shell_names=sync_shell_names,
        namespace_names=namespace_names,
    )
    return (
        fork_entrypoint_names,
        node_entrypoint_names,
        sync_shell_names,
        namespace_names,
    )


def _add_child_process_transferred_aliases(
    source_text: str,
    *,
    fork_entrypoint_names: set[str],
    node_entrypoint_names: set[str],
    sync_shell_names: set[str],
    namespace_names: set[str],
) -> None:
    assignment_pattern = re.compile(
        rf"""
        \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
        (?:\(\s*)*(?P<source>{JS_IDENTIFIER})(?:\s*\))*\s*(?:;|,|\n|$)
        """,
        re.VERBOSE | re.DOTALL,
    )
    changed = True
    while changed:
        changed = False
        for match in _executable_pattern_matches(source_text, assignment_pattern):
            name = match.group("name")
            source = match.group("source")
            if source in fork_entrypoint_names and name not in fork_entrypoint_names:
                fork_entrypoint_names.add(name)
                changed = True
            elif source in node_entrypoint_names and name not in node_entrypoint_names:
                node_entrypoint_names.add(name)
                changed = True
            elif source in sync_shell_names and name not in sync_shell_names:
                sync_shell_names.add(name)
                changed = True

    if not namespace_names:
        return
    namespace_alternatives = "|".join(
        re.escape(name) for name in sorted(namespace_names, key=len, reverse=True)
    )
    member_pattern = re.compile(
        rf"""
        \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
        (?:\(\s*)*
        (?P<namespace>{namespace_alternatives})\s*(?:\.|\?\.)\s*
        (?P<member>{JS_IDENTIFIER})
        (?:\s*\))*\s*(?:;|,|\n|$)
        """,
        re.VERBOSE | re.DOTALL,
    )
    for match in _executable_pattern_matches(source_text, member_pattern):
        name = match.group("name")
        member = match.group("member")
        if member in CHILD_PROCESS_FORK_ENTRYPOINT_NAMES:
            fork_entrypoint_names.add(name)
        elif member in CHILD_PROCESS_NODE_ENTRYPOINT_NAMES:
            node_entrypoint_names.add(name)
        elif member in CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES:
            sync_shell_names.add(name)


def _child_process_fork_entrypoint_pattern(
    fork_entrypoint_names: set[str],
) -> re.Pattern[str] | None:
    if not fork_entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name) for name in sorted(fork_entrypoint_names, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        (?<![\w$.])
        (?:{alternatives})\s*\(\s*
        ["'](?P<specifier>[^"']+)["']
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_alias_node_entrypoint_pattern(
    node_entrypoint_names: set[str],
    *,
    require_literal_script_argument: bool,
    require_node_executable: bool = True,
) -> re.Pattern[str] | None:
    if not node_entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name) for name in sorted(node_entrypoint_names, key=len, reverse=True)
    )
    suffix = r"\s*(?:\?\.)?\s*\("
    if require_node_executable:
        suffix += r"\s*process\.execPath\s*,"
    if require_literal_script_argument:
        suffix += r"\s*\[\s*[\"'](?P<specifier>[^\"']+)[\"']"
    return re.compile(
        rf"(?<![\w$.])(?:{alternatives}){suffix}",
        re.VERBOSE | re.DOTALL,
    )


def _child_process_namespace_node_entrypoint_pattern(
    namespace_names: set[str],
) -> re.Pattern[str] | None:
    if not namespace_names:
        return None
    namespaces = "|".join(
        re.escape(name) for name in sorted(namespace_names, key=len, reverse=True)
    )
    members = "|".join(
        re.escape(name)
        for name in sorted(CHILD_PROCESS_NODE_ENTRYPOINT_NAMES, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        (?<![\w$])(?:{namespaces})\s*(?:\.|\?\.)?\s*
        (?:{members}|\[\s*["'](?:{members})["']\s*\])\s*(?:\?\.)?\s*\(
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_grouped_alias_node_entrypoint_pattern(
    node_entrypoint_names: set[str],
) -> re.Pattern[str] | None:
    if not node_entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name) for name in sorted(node_entrypoint_names, key=len, reverse=True)
    )
    return re.compile(
        rf"\(\s*(?:\(\s*)*(?:{alternatives})(?:\s*\))*\s*(?:\?\.)?\s*\(",
        re.DOTALL,
    )


def _child_process_sync_shell_call_pattern(
    sync_shell_names: set[str],
) -> re.Pattern[str]:
    named_alternatives = "|".join(
        re.escape(name)
        for name in sorted(
            set(sync_shell_names) | CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES,
            key=len,
            reverse=True,
        )
    )
    member_alternatives = "|".join(
        re.escape(name)
        for name in sorted(CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        (?:
            (?<![\w$.])(?:{named_alternatives})\s*\(
          |
            (?<![\w$])(?:child_process|{JS_IDENTIFIER})\s*\.\s*(?:{member_alternatives})\s*\(
        )
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_indirect_alias_node_entrypoint_pattern(
    node_entrypoint_names: set[str],
) -> re.Pattern[str] | None:
    if not node_entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name) for name in sorted(node_entrypoint_names, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        \(\s*
        [^()]*,\s*
        (?:{alternatives})\s*
        \)\s*\(\s*process\.execPath\s*,
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_callable_indirect_entrypoint_pattern(
    entrypoint_names: set[str],
) -> re.Pattern[str] | None:
    if not entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name) for name in sorted(entrypoint_names, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        (?:
            (?<![\w$.])(?:{alternatives})\s*(?:\.|\?\.)\s*(?:call|apply)\s*\(
          |
            (?<![\w$.])Reflect\s*(?:\.|\?\.)\s*apply\s*\(\s*(?:{alternatives})\s*,
        )
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_indirect_fork_entrypoint_pattern(
    fork_entrypoint_names: set[str],
) -> re.Pattern[str] | None:
    if not fork_entrypoint_names:
        return None
    alternatives = "|".join(
        re.escape(name)
        for name in sorted(fork_entrypoint_names, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        (?:
            \(\s*[^()]*,\s*(?:{alternatives})\s*\)\s*\(
          |
            \bReflect\s*\.\s*(?:apply|call)\s*\(\s*(?:{alternatives})\s*,
        )
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_indirect_namespace_node_entrypoint_pattern() -> re.Pattern[str]:
    member_alternatives = "|".join(
        re.escape(name)
        for name in sorted(CHILD_PROCESS_NODE_ENTRYPOINT_NAMES, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        \(\s*
        [^()]*,\s*
        (?:child_process|{JS_IDENTIFIER})\s*(?:\.|\?\.)\s*
        (?:{member_alternatives})\s*
        \)\s*\(\s*process\.execPath\s*,
        """,
        re.VERBOSE | re.DOTALL,
    )


def _child_process_indirect_shell_call_pattern(
    sync_shell_names: set[str],
) -> re.Pattern[str]:
    named_alternatives = "|".join(
        re.escape(name)
        for name in sorted(
            set(sync_shell_names) | CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES,
            key=len,
            reverse=True,
        )
    )
    member_alternatives = "|".join(
        re.escape(name)
        for name in sorted(CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES, key=len, reverse=True)
    )
    return re.compile(
        rf"""
        \(\s*
        [^()]*,\s*
        (?:
            (?:{named_alternatives})
          |
            (?:child_process|{JS_IDENTIFIER})\s*(?:\.|\?\.)\s*
            (?:{member_alternatives})
        )\s*
        \)\s*\(
        """,
        re.VERBOSE | re.DOTALL,
    )


def _worker_constructor_pattern(
    constructor_names: set[str],
    namespace_names: set[str],
) -> re.Pattern[str]:
    alternatives: list[str] = [re.escape(name) for name in constructor_names]
    alternatives.extend(
        rf"{re.escape(name)}\s*(?:\.|\?\.)\s*Worker" for name in namespace_names
    )
    alternatives.extend(
        rf"{re.escape(name)}\s*(?:\.|\?\.)?\s*\[\s*['\"]Worker['\"]\s*\]"
        for name in namespace_names
    )
    return re.compile(
        rf"""
        \bnew\s+(?:{'|'.join(sorted(alternatives, key=len, reverse=True))})\s*\(\s*
        new\s+URL\s*\(\s*
        ["'](?P<specifier>[^"']+)["']\s*,\s*
        import\.meta\.url\s*
        \)
        """,
        re.VERBOSE | re.DOTALL,
    )


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


def _node_module_runtime_binding_names(
    source_text: str,
) -> tuple[set[str], set[str], set[str]]:
    stripped = strip_source_comments(source_text)
    namespace_names: set[str] = set()
    constructor_names: set[str] = set()
    runtime_loader_names: set[str] = set()

    for match in _executable_pattern_matches(stripped, NODE_MODULE_NAMESPACE_IMPORT):
        namespace_names.add(match.group("name"))
    for match in _executable_pattern_matches(stripped, NODE_MODULE_DEFAULT_IMPORT):
        name = match.group("name")
        namespace_names.add(name)
        constructor_names.add(name)
    for match in _executable_pattern_matches(stripped, NODE_MODULE_REQUIRE_ASSIGNMENT):
        name = match.group("name")
        namespace_names.add(name)
        constructor_names.add(name)
    for match in _executable_pattern_matches(stripped, NODE_MODULE_MEMBER_REQUIRE_ASSIGNMENT):
        constructor_names.add(match.group("name"))

    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in _executable_pattern_matches(stripped, pattern):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "Module":
                    constructor_names.add(local_name)

    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in _executable_pattern_matches(stripped, pattern):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "runMain":
                    runtime_loader_names.add(local_name)

    return namespace_names, constructor_names, runtime_loader_names


def _parse_commonjs_module_require_namespace_end(
    source_text: str, index: int
) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if index < len(source_text) and source_text[index] == "(":
        inner_end = _parse_commonjs_module_require_namespace_end(
            source_text, index + 1
        )
        if inner_end is None:
            return None
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        return close_index + 1

    if not source_text.startswith(COMMONJS_REQUIRE_TOKEN, index):
        return None
    parsed = _parse_require_invocation(source_text, index)
    if parsed is None:
        return None
    specifier, end_index = parsed
    if specifier not in NODE_MODULE_SPECIFIERS:
        return None
    return end_index


def _parse_known_node_module_namespace_end(
    source_text: str, index: int, namespace_names: set[str]
) -> int | None:
    direct_end = _parse_commonjs_module_require_namespace_end(source_text, index)
    if direct_end is not None:
        return direct_end
    for namespace_name in sorted(namespace_names, key=len, reverse=True):
        namespace_end = _parse_grouped_named_base(source_text, index, namespace_name)
        if namespace_end is not None:
            return namespace_end
    return None


def _reject_commonjs_module_dangerous_member(member_name: str) -> None:
    if member_name in COMMONJS_RUNTIME_LOADER_MEMBER_NAMES:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS runtime loader"
        )
    if member_name in COMMONJS_COMPILE_MEMBER_NAMES:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS runtime compiler"
        )
    if member_name in COMMONJS_CUSTOM_EXTENSION_MEMBER_NAMES:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported custom CommonJS extension loader"
        )


def _commonjs_module_namespace_access_end_or_fail(
    source_text: str,
    index: int,
    *,
    namespace_names: set[str],
    constructor_names: set[str],
) -> int | None:
    namespace_end = _parse_known_node_module_namespace_end(
        source_text, index, namespace_names
    )
    if namespace_end is None:
        for constructor_name in sorted(constructor_names, key=len, reverse=True):
            namespace_end = _parse_grouped_named_base(
                source_text, index, constructor_name
            )
            if namespace_end is not None:
                break
    if namespace_end is None:
        return None

    member = _parse_static_runtime_member(
        source_text,
        namespace_end,
        dynamic_error=(
            "runtime source contains an unsupported custom CommonJS extension loader"
        ),
    )
    if member is None:
        return namespace_end
    member_name, member_end = member
    _reject_commonjs_module_dangerous_member(member_name)
    if member_name not in COMMONJS_MODULE_CONSTRUCTOR_MEMBER_NAMES:
        return member_end

    constructor_member = _parse_static_runtime_member(
        source_text,
        member_end,
        dynamic_error=(
            "runtime source contains an unsupported custom CommonJS extension loader"
        ),
    )
    if constructor_member is None:
        return member_end
    constructor_member_name, constructor_member_end = constructor_member
    _reject_commonjs_module_dangerous_member(constructor_member_name)
    return constructor_member_end


def _parenthesized_expression_has_target(source_text: str, paren_index: int) -> bool:
    before = paren_index - 1
    while before >= 0 and source_text[before].isspace():
        before -= 1
    if before < 0:
        return False
    character = source_text[before]
    if _is_identifier_character(character) and _previous_code_word(
        source_text, paren_index
    ) == "new":
        return False
    return character in {")", "]"} or _is_identifier_character(character)


def _parenthesized_expression_end(source_text: str, index: int) -> int:
    if index >= len(source_text) or source_text[index] != "(":
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS runtime compiler"
        )
    depth = 1
    index += 1
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
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
            _, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character == "\\" and next_character == "u":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported escaped JavaScript identifier"
            )
        if character == "(":
            depth += 1
            index += 1
            continue
        if character == ")":
            depth -= 1
            index += 1
            if depth == 0:
                return index
            continue
        index += 1
    raise RuntimeSourceContractError(
        "runtime source contains an unsupported CommonJS runtime compiler"
    )


def _parse_commonjs_module_constructor_reference_end(
    source_text: str,
    index: int,
    *,
    namespace_names: set[str],
    constructor_names: set[str],
) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if (
        index < len(source_text)
        and source_text[index] == "("
        and not _parenthesized_expression_has_target(source_text, index)
    ):
        inner_end = _parse_commonjs_module_constructor_reference_end(
            source_text,
            index + 1,
            namespace_names=namespace_names,
            constructor_names=constructor_names,
        )
        if inner_end is None:
            return None
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        return close_index + 1

    namespace_end = _parse_known_node_module_namespace_end(
        source_text, index, namespace_names
    )
    if namespace_end is not None:
        member = _parse_static_runtime_member(
            source_text,
            namespace_end,
            dynamic_error=(
                "runtime source contains an unsupported custom CommonJS extension loader"
            ),
        )
        if member is None:
            return namespace_end
        member_name, member_end = member
        _reject_commonjs_module_dangerous_member(member_name)
        if member_name in COMMONJS_MODULE_CONSTRUCTOR_MEMBER_NAMES:
            return member_end
        return None

    for constructor_name in sorted(constructor_names, key=len, reverse=True):
        constructor_end = _parse_grouped_named_base(source_text, index, constructor_name)
        if constructor_end is not None:
            return constructor_end
    return None


def _commonjs_module_instance_access_end_or_fail(
    source_text: str,
    index: int,
    *,
    namespace_names: set[str],
    constructor_names: set[str],
) -> int | None:
    index = _skip_js_trivia(source_text, index)
    if (
        index < len(source_text)
        and source_text[index] == "("
        and not _parenthesized_expression_has_target(source_text, index)
    ):
        inner_end = _commonjs_module_instance_access_end_or_fail(
            source_text,
            index + 1,
            namespace_names=namespace_names,
            constructor_names=constructor_names,
        )
        if inner_end is None:
            return None
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        instance_end = close_index + 1
    else:
        parsed_new = _parse_js_identifier(source_text, index)
        if parsed_new is None or parsed_new[0] != "new":
            return None
        constructor_start = _skip_js_trivia(source_text, parsed_new[1])
        constructor_end = _parse_commonjs_module_constructor_reference_end(
            source_text,
            constructor_start,
            namespace_names=namespace_names,
            constructor_names=constructor_names,
        )
        if constructor_end is None:
            return None
        call_index = _skip_js_trivia(source_text, constructor_end)
        if call_index < len(source_text) and source_text[call_index] == "(":
            instance_end = _parenthesized_expression_end(source_text, call_index)
        else:
            instance_end = constructor_end

    member = _parse_static_runtime_member(
        source_text,
        instance_end,
        dynamic_error=(
            "runtime source contains an unsupported CommonJS runtime compiler"
        ),
    )
    if member is None:
        return instance_end
    member_name, member_end = member
    if member_name in COMMONJS_COMPILE_MEMBER_NAMES:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS runtime compiler"
        )
    if member_name in COMMONJS_MODULE_INSTANCE_RUNTIME_LOADER_MEMBER_NAMES:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS runtime loader"
        )
    return member_end


def _reject_evaluated_runtime_loaders(source_text: str) -> None:
    source_text = _decode_js_identifier_escapes_in_executable_code(source_text)
    (
        node_module_namespace_names,
        node_module_constructor_names,
        node_module_runtime_loader_names,
    ) = (
        _node_module_runtime_binding_names(source_text)
    )
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
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
        if character == "[":
            computed_member = _static_computed_member_name(source_text, index)
            if (
                computed_member is not None
                and computed_member[0] in EVALUATED_RUNTIME_VM_MEMBER_NAMES
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported evaluated loader reference"
                )
            if (
                computed_member is not None
                and computed_member[0] in EVALUATED_RUNTIME_WEBASSEMBLY_TOKENS
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported WebAssembly evaluation reference"
                )
        module_instance_end = _commonjs_module_instance_access_end_or_fail(
            source_text,
            index,
            namespace_names=node_module_namespace_names,
            constructor_names=node_module_constructor_names,
        )
        if module_instance_end is not None:
            index = max(index + 1, module_instance_end)
            continue
        module_namespace_end = _commonjs_module_namespace_access_end_or_fail(
            source_text,
            index,
            namespace_names=node_module_namespace_names,
            constructor_names=node_module_constructor_names,
        )
        if module_namespace_end is not None:
            index = max(index + 1, module_namespace_end)
            continue
        module_member = _parse_named_runtime_member(source_text, index, "module")
        if module_member is not None:
            member_name, member_end = module_member
            if member_name in COMMONJS_RUNTIME_LOADER_MEMBER_NAMES:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS runtime loader"
                )
            if member_name in COMMONJS_COMPILE_MEMBER_NAMES:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS runtime compiler"
                )
            if member_name in COMMONJS_CUSTOM_EXTENSION_MEMBER_NAMES:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported custom CommonJS extension loader"
                )
            index = max(index, member_end - 1)
            continue
        require_member = _parse_named_runtime_member(source_text, index, "require")
        if (
            require_member is not None
            and require_member[0] in COMMONJS_CUSTOM_EXTENSION_MEMBER_NAMES
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported custom CommonJS extension loader"
            )
        for token in EVALUATED_RUNTIME_LOADER_TOKENS:
            if _is_forbidden_runtime_loader_reference(source_text, index, token):
                if token == "constructor":
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported evaluated loader reference "
                        "or native add-on capability"
                    )
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported evaluated loader reference"
                )
        parsed_identifier = _parse_js_identifier(source_text, index)
        if parsed_identifier is not None and parsed_identifier[0] in node_module_runtime_loader_names:
            call_index = _skip_js_trivia(source_text, parsed_identifier[1])
            while call_index < len(source_text) and source_text[call_index] == ")":
                call_index = _skip_js_trivia(source_text, call_index + 1)
            if (
                source_text.startswith("?.(", call_index)
                or (call_index < len(source_text) and source_text[call_index] == "(")
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS runtime loader"
                )
        if (
            parsed_identifier is not None
            and parsed_identifier[0] in EVALUATED_RUNTIME_VM_MEMBER_NAMES
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported evaluated loader reference"
            )
        if (
            parsed_identifier is not None
            and parsed_identifier[0] in EVALUATED_RUNTIME_WEBASSEMBLY_TOKENS
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported WebAssembly evaluation reference"
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
        previous_index = index - 1
        while previous_index >= 0 and source_text[previous_index].isspace():
            previous_index -= 1
        if (
            previous in {"+", "-"}
            and previous_index > 0
            and source_text[previous_index - 1] == previous
        ):
            return False
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


def _executable_pattern_matches(
    source_text: str, pattern: re.Pattern[str]
) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    matched_end = -1
    for kind, start, _end in _javascript_lexical_items(source_text):
        if kind != "code" or start < matched_end:
            continue
        match = pattern.match(source_text, start)
        if match is not None:
            matches.append(match)
            matched_end = match.end()
    return matches


def _create_require_base_end(source_text: str, opening_index: int) -> int | None:
    index = _skip_js_trivia(source_text, opening_index + 1)
    if source_text.startswith("__filename", index):
        end_index = index + len("__filename")
        if end_index < len(source_text) and _is_identifier_character(source_text[end_index]):
            return None
    else:
        match = re.match(
            r"import\s*\.\s*meta\s*\.\s*url\b", source_text[index:]
        )
        if match is None:
            return None
        end_index = index + match.end()
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        return None
    return close_index + 1


def _validate_create_require_factory_calls(source_text: str) -> None:
    factories = _create_require_factory_names(source_text)
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
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
                _validate_create_require_factory_calls(chunk)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        for factory in sorted(factories, key=len, reverse=True):
            end_index = index + len(factory)
            before = source_text[index - 1] if index > 0 else ""
            after = source_text[end_index] if end_index < len(source_text) else ""
            if (
                not source_text.startswith(factory, index)
                or (before and _is_identifier_character(before))
                or (after and _is_identifier_character(after))
            ):
                continue
            next_index = _skip_js_trivia(source_text, end_index)
            if next_index < len(source_text) and source_text[next_index] == "(":
                base_end = _create_require_base_end(source_text, next_index)
                if base_end is None:
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported non-local createRequire base"
                    )
                index = base_end
                break
            if next_index < len(source_text) and source_text[next_index] == ")":
                while next_index < len(source_text) and source_text[next_index] == ")":
                    next_index = _skip_js_trivia(source_text, next_index + 1)
                if next_index < len(source_text) and source_text[next_index] == "(":
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported indirect createRequire factory invocation"
                    )
            if source_text.startswith("?.", next_index) or (
                next_index < len(source_text) and source_text[next_index] == "."
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported indirect createRequire factory invocation"
                )
        else:
            index += 1


def _create_require_specifiers(
    source_text: str,
    inherited_loader_names: set[str] | None = None,
) -> list[str]:
    specifiers: list[str] = []
    _validate_create_require_factory_calls(source_text)
    for match in _executable_pattern_matches(
        source_text, INLINE_CREATE_REQUIRE_SPECIFIER
    ):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source createRequire specifier contains an unsupported JavaScript escape"
            )
        specifiers.append(specifier)
    local_loader_names, declaration_spans = _create_require_loader_bindings(
        source_text
    )
    loader_names = set(inherited_loader_names or ()) | local_loader_names
    if not loader_names:
        return specifiers
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
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
    if _executable_pattern_matches(source_text, INDIRECT_COMMONJS_REQUIRE_INVOCATION):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect CommonJS require invocation"
        )
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
            if _is_js_line_terminator(character):
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
                _reject_indirect_parenthesized_commonjs_require_invocation(
                    source_text, index
                )
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
            if _is_js_line_terminator(character):
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
            if close_index < len(source_text) and source_text[close_index] == ",":
                close_index = _skip_js_trivia(
                    source_text,
                    _skip_static_dynamic_import_attributes(source_text, close_index + 1),
                )
            if close_index >= len(source_text) or source_text[close_index] != ")":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported dynamic import signature"
                )
            specifiers.append(specifier)
            index = close_index + 1
            continue
        index += 1
    return specifiers


def _execution_binding_spans(source_text: str) -> list[tuple[int, int]]:
    """Only explicit, supported builtin bindings can introduce capabilities."""
    spans: list[tuple[int, int]] = []
    for pattern in (
        WORKER_THREADS_IMPORT, WORKER_THREADS_DESTRUCTURED_REQUIRE,
        WORKER_THREADS_NAMESPACE_IMPORT, WORKER_THREADS_DEFAULT_IMPORT,
        WORKER_THREADS_REQUIRE_ASSIGNMENT, CHILD_PROCESS_IMPORT,
        CHILD_PROCESS_DESTRUCTURED_REQUIRE, CHILD_PROCESS_NAMESPACE_IMPORT,
        CHILD_PROCESS_DEFAULT_IMPORT, CHILD_PROCESS_REQUIRE_ASSIGNMENT,
    ):
        for match in _executable_pattern_matches(source_text, pattern):
            if "body" in match.re.groupindex:
                for part in match.group("body").split(","):
                    if part.strip() and _parse_named_binding_part(part) is None:
                        raise RuntimeSourceContractError(
                            "runtime source contains an unsupported execution capability binding"
                        )
            spans.append(match.span())
    return spans


def _reject_unbound_execution_references(
    source_text: str,
    *,
    accepted_spans: list[tuple[int, int]],
    worker_names: set[str],
    worker_namespaces: set[str],
    fork_names: set[str],
    node_names: set[str],
    shell_names: set[str],
    child_namespaces: set[str],
) -> None:
    """Check references, not a growing blacklist of alias/call spellings.

    A capability may be introduced by an explicit builtin binding and consumed
    by a directly inspected call. Other uses (assignment, export, destructuring,
    callbacks, bind/call/apply, computed access, etc.) fail closed at the source
    reference; no downstream alias spelling can then evade the closure.
    """
    bindings = _execution_binding_spans(source_text)
    for match in _executable_pattern_matches(source_text, STATIC_RUNTIME_IMPORT_SPECIFIER):
        if match.group("specifier") not in CHILD_PROCESS_SPECIFIERS | {
            "worker_threads", "node:worker_threads"
        }:
            continue
        if any(a <= match.start() < b for a, b in bindings):
            continue
        # A side-effect import exposes no value; re-exports and unsupported
        # binding forms do, and cannot be treated as an empty dependency edge.
        if re.fullmatch(r"import\s*[\"'][^\"']+[\"']", match.group().strip()):
            continue
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported execution capability import or re-export"
        )
    workers = worker_names | worker_namespaces
    forks = fork_names | {"fork"}
    nodes = node_names | set(CHILD_PROCESS_NODE_ENTRYPOINT_NAMES)
    shells = shell_names | set(CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES)
    names = workers | forks | nodes | shells | child_namespaces
    for kind, start, end in _javascript_lexical_items(source_text):
        if kind != "code":
            continue
        parsed_name = _parse_js_identifier(source_text, start)
        if parsed_name is None:
            continue
        name, end = parsed_name
        if name == "require":
            parsed = _parse_require_invocation(source_text, start)
            if parsed is not None and parsed[0] in {
                "worker_threads", "node:worker_threads", "child_process", "node:child_process"
            } and not any(a <= start < b for a, b in bindings):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported execution capability acquisition"
                )
        if name not in names:
            continue
        if any(a <= start < b for a, b in bindings + accepted_spans):
            continue
        before = _previous_non_trivia_character(source_text, start)
        after = _skip_js_trivia(source_text, end)
        if before in {"{", ","} and source_text[after:after + 1] == ":":
            continue  # An ordinary, non-shorthand property key is not a read.
        if before == "." and name not in worker_namespaces | child_namespaces:
            continue  # Qualified receivers are checked at their own reference.
        if _previous_code_word(source_text, start) == "typeof":
            continue
        if name in worker_namespaces:
            member = _parse_process_member(source_text, end)
            if member is not None and member[0] in {
                "isMainThread", "parentPort", "workerData", "threadId",
                "resourceLimits", "SHARE_ENV", "MessageChannel", "MessagePort",
            }:
                continue
        if name in workers:
            description = "Worker entrypoint capability reference"
        elif name in shells:
            description = "shell child-process entrypoint capability reference"
        elif name in forks:
            description = "indirect child-process fork entrypoint capability reference"
        else:
            description = "child-process Node entrypoint capability reference"
        raise RuntimeSourceContractError(f"runtime source contains an unsupported {description}")


def _module_loader_reference_specifiers(source_text: str) -> list[str]:
    """Account for every introduced module loader and every factory result.

    Only createRequire and non-executing module metadata are supported exports.
    A factory result must be a tracked local binding or immediately consumed by
    a literal require call. Returning/transferring either the namespace, factory
    or loader cannot be made safe by recognizing one more alias spelling.
    """
    bindings: list[tuple[int, int]] = []
    harmless_members = {"builtinModules", "isBuiltin"}
    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE,
                    NODE_MODULE_NAMESPACE_IMPORT, NODE_MODULE_DEFAULT_IMPORT,
                    NODE_MODULE_REQUIRE_ASSIGNMENT, NODE_MODULE_MEMBER_REQUIRE_ASSIGNMENT):
        for match in _executable_pattern_matches(source_text, pattern):
            if "body" in match.re.groupindex:
                for part in match.group("body").split(","):
                    if not part.strip():
                        continue
                    binding = _parse_named_binding_part(part)
                    if binding is None or binding[0] not in harmless_members | {"createRequire"}:
                        raise RuntimeSourceContractError(
                            "runtime source contains an unsupported CommonJS runtime loader binding"
                        )
            bindings.append(match.span())
    for match in _executable_pattern_matches(source_text, STATIC_RUNTIME_IMPORT_SPECIFIER):
        if match.group("specifier") in NODE_MODULE_SPECIFIERS and not any(
            a <= match.start() < b for a, b in bindings
        ):
            if re.fullmatch(r"import\s*[\"'][^\"']+[\"']", match.group().strip()):
                continue
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported CommonJS runtime loader re-export or binding"
            )
    factories = _create_require_factory_names(source_text)
    namespaces, constructors, _loaders = _node_module_runtime_binding_names(source_text)
    bound_factory_calls: set[int] = set()
    for match in _executable_pattern_matches(source_text, CREATE_REQUIRE_ASSIGNMENT):
        if match.group("factory") in factories:
            bound_factory_calls.add(match.start("factory"))
    specifiers: list[str] = []
    consumed: list[tuple[int, int]] = []

    def consume_loader(call_index: int) -> int:
        call_index = _skip_js_trivia(source_text, call_index)
        if source_text[call_index:call_index + 1] != "(":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported createRequire loader capability transfer"
            )
        parsed = _parse_quoted_specifier(source_text, _skip_js_trivia(source_text, call_index + 1))
        if parsed is None:
            raise RuntimeSourceContractError("runtime source contains an unsupported dynamic createRequire loader")
        specifier, end = parsed
        end = _skip_js_trivia(source_text, end)
        if source_text[end:end + 1] != ")":
            raise RuntimeSourceContractError("runtime source contains an unsupported createRequire loader signature")
        specifiers.append(specifier)
        return end + 1

    def consume_factory(start: int, member_end: int, *, local_binding: bool = False) -> None:
        call_index = _skip_js_trivia(source_text, member_end)
        if source_text[call_index:call_index + 1] != "(":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported createRequire factory capability transfer"
            )
        factory_end = _create_require_base_end(source_text, call_index)
        if factory_end is None:
            raise RuntimeSourceContractError("runtime source contains an unsupported non-local createRequire base")
        tail = _skip_js_trivia(source_text, factory_end)
        if source_text[tail:tail + 1] == "(":
            consumed.append((start, consume_loader(tail)))
        elif local_binding:
            # The existing loader-binding collector follows every use of this
            # local. Do not allow another expression to change the bound value.
            if tail < len(source_text) and source_text[tail] not in ";,":
                if not any(_is_js_line_terminator(c) for c in source_text[factory_end:tail]):
                    raise RuntimeSourceContractError("runtime source contains an unsupported createRequire loader binding")
                if source_text[tail] in "([.`?":
                    raise RuntimeSourceContractError("runtime source contains an unsupported createRequire loader binding")
            consumed.append((start, factory_end))
        else:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported createRequire loader capability transfer"
            )

    for kind, start, end in _javascript_lexical_items(source_text):
        if kind != "code" or any(a <= start < b for a, b in bindings + consumed):
            continue
        # Inspect the complete receiver, including arbitrary balanced grouping,
        # before inspecting identifiers. Looking only after the `module` token
        # misses `(module)["require"]` and its optional/computed variants.
        module_end = _parse_grouped_named_base(source_text, start, "module")
        if module_end is not None:
            member = _parse_process_member(source_text, module_end)
            if member is not None and member[0] == "require":
                call = _optional_call_tail_index(source_text, member[1])
                if source_text[call:call + 1] != "(":
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported CommonJS require capability transfer"
                    )
                consumed.append((start, consume_loader(call)))
                continue
        parsed = _parse_js_identifier(source_text, start)
        if parsed is None:
            continue
        name, end = parsed
        before = _previous_non_trivia_character(source_text, start)
        after = _skip_js_trivia(source_text, end)
        if before in {"{", ","} and source_text[after:after + 1] == ":":
            continue
        if name in factories:
            consume_factory(start, end, local_binding=start in bound_factory_calls)
            continue
        namespace_end = None
        if name in namespaces | constructors:
            namespace_end = end
        elif name == "require":
            call = _parse_require_invocation(source_text, start)
            if call is not None and call[0] in NODE_MODULE_SPECIFIERS:
                namespace_end = call[1]
        if namespace_end is None:
            continue
        member = _parse_static_runtime_member(
            source_text, namespace_end,
            dynamic_error="runtime source contains an unsupported CommonJS runtime loader member",
        )
        if member is not None and member[0] == "createRequire":
            consume_factory(start, member[1])
        elif member is not None and member[0] in harmless_members:
            consumed.append((start, member[1]))
        elif _previous_code_word(source_text, start) != "typeof":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported CommonJS runtime loader capability transfer"
            )
    return specifiers


def _reject_mutable_launch_configuration(source_text: str) -> None:
    """Keep the cwd/launcher/environment assumptions of direct launches fixed.

    Read-only, statically named environment lookups remain supported. Passing
    process/env objects around, mutating them, or altering inherited execArgv is
    not a source-closed launch. Existing process acquisition guards reject other
    aliases/reflection routes to these objects.
    """
    for kind, start, _end in _javascript_lexical_items(source_text):
        if kind != "code":
            continue
        base_end = _parse_process_base(source_text, start)
        if base_end is None:
            continue
        member = _parse_process_member(source_text, base_end)
        if member is None:
            continue
        name, end = member
        if name in {"chdir", "execArgv"}:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported mutable launch configuration"
            )
        if name not in {"env", "execPath", "cwd"}:
            continue
        if name == "env":
            member = _parse_process_member(source_text, end)
            if member is None:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported environment capability transfer"
                )
            _key, end = member
        tail = _skip_js_trivia(source_text, end)
        while source_text[tail:tail + 1] in {")", "]", "}"}:
            tail = _skip_js_trivia(source_text, tail + 1)
        rest = source_text[tail:]
        before = source_text[:start].rstrip()
        write = bool(re.match(r"(?:=(?!=)|[+*/%&|^\-]=|\*\*=|<<=|>>>=|>>=|&&=|\|\|=|\?\?=|\+\+|--)", rest))
        if write or before.endswith(("++", "--")) or _previous_code_word(source_text, start) == "delete":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported mutable launch configuration"
            )


def _reject_unbound_require_references(source_text: str) -> None:
    assignment = re.compile(rf"\b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*")
    aliases, declarations = _commonjs_require_alias_bindings(source_text)
    alias_initializers: list[tuple[int, int]] = []
    for match in _executable_pattern_matches(source_text, assignment):
        if match.span("name") in declarations:
            end = _parse_grouped_named_base(source_text, match.end(), "require")
            if end is not None:
                alias_initializers.append((match.end(), end))
    for match in _executable_pattern_matches(source_text, re.compile(r"\brequire\b")):
        start, end = match.span()
        before = _previous_non_trivia_character(source_text, start)
        if before == "." or _previous_code_word(source_text, start) == "typeof":
            continue
        after = _skip_js_trivia(source_text, end)
        if before in {"{", ","} and source_text[after:after + 1] == ":":
            continue
        if any(a <= start < b for a, b in alias_initializers):
            continue
        if _parse_require_invocation(source_text, start) is not None:
            continue
        opening = start - 1
        while opening >= 0 and source_text[opening].isspace():
            opening -= 1
        if opening >= 0 and source_text[opening] == "(":
            if _parse_parenthesized_require_invocation(source_text, opening) is not None:
                continue
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported CommonJS require capability reference"
        )


def _require_closed_launch_signature(
    source_text: str, end: int, *, description: str, close_argv: bool = False
) -> None:
    end = _skip_js_trivia(source_text, end)
    if close_argv:
        if source_text[end:end + 1] == ",":
            end = _skip_js_trivia(source_text, end + 1)
        if source_text[end:end + 1] != "]":
            raise RuntimeSourceContractError(
                f"runtime source contains an unsupported {description} argument vector"
            )
        end = _skip_js_trivia(source_text, end + 1)
    if source_text[end:end + 1] == ",":
        end = _skip_js_trivia(source_text, end + 1)
    if source_text[end:end + 1] != ")":
        raise RuntimeSourceContractError(
            f"runtime source contains an unsupported {description} launch options"
        )


def _runtime_execution_entrypoint_specifiers(
    source_text: str,
) -> list[tuple[str, str]]:
    source_text = _decode_js_identifier_escapes_in_executable_code(source_text)
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, str]] = []
    accepted_spans: list[tuple[int, int]] = []
    worker_constructor_names, worker_namespace_names = _worker_thread_bindings(source_text)
    worker_entrypoint_pattern = _worker_constructor_pattern(
        worker_constructor_names, worker_namespace_names
    )
    (
        child_process_fork_alias_names,
        child_process_node_alias_names,
        child_process_sync_alias_names,
        child_process_namespace_names,
    ) = (
        _child_process_sync_alias_bindings(source_text)
    )
    if _executable_pattern_matches(
        source_text, INLINE_REQUIRE_CHILD_PROCESS_COMPUTED_MEMBER
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported computed inline require "
            "child-process entrypoint"
        )
    if _executable_pattern_matches(source_text, INLINE_REQUIRE_MODULE_COMPUTED_MEMBER):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported computed inline require module member"
        )
    if _executable_pattern_matches(source_text, INLINE_REQUIRE_CHILD_PROCESS_ENTRYPOINT):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported inline require child-process entrypoint"
        )
    for match in _executable_pattern_matches(source_text, worker_entrypoint_pattern):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source worker entrypoint contains an unsupported JavaScript escape"
            )
        _require_closed_launch_signature(
            source_text, match.end(), description="Worker entrypoint"
        )
        specifiers.append((specifier, "import"))
        accepted_spans.append(match.span())
    for match in _executable_pattern_matches(source_text, FORK_ENTRYPOINT_SPECIFIER):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source fork entrypoint contains an unsupported JavaScript escape"
            )
        _require_closed_launch_signature(
            source_text, match.end(), description="fork entrypoint"
        )
        specifiers.append((specifier, "child"))
        accepted_spans.append(match.span())
    child_process_fork_alias_pattern = _child_process_fork_entrypoint_pattern(
        child_process_fork_alias_names
    )
    if child_process_fork_alias_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_fork_alias_pattern):
            specifier = match.group("specifier")
            if "\\" in specifier:
                raise RuntimeSourceContractError(
                    "runtime source fork entrypoint contains an unsupported JavaScript escape"
                )
            _require_closed_launch_signature(
                source_text, match.end(), description="fork entrypoint"
            )
            specifiers.append((specifier, "child"))
            accepted_spans.append(match.span())
    for match in _executable_pattern_matches(source_text, CHILD_PROCESS_NODE_ENTRYPOINT_SPECIFIER):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source child-process entrypoint contains an unsupported JavaScript escape"
            )
        _require_closed_launch_signature(
            source_text, match.end(), description="child-process Node entrypoint", close_argv=True
        )
        specifiers.append((specifier, "child"))
        accepted_spans.append(match.span())
    child_process_alias_pattern = _child_process_alias_node_entrypoint_pattern(
        child_process_node_alias_names,
        require_literal_script_argument=True,
    )
    if child_process_alias_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_alias_pattern):
            specifier = match.group("specifier")
            if "\\" in specifier:
                raise RuntimeSourceContractError(
                    "runtime source child-process entrypoint contains an unsupported JavaScript escape"
                )
            _require_closed_launch_signature(
                source_text, match.end(), description="child-process Node entrypoint", close_argv=True
            )
            specifiers.append((specifier, "child"))
            accepted_spans.append(match.span())
    child_process_alias_call_pattern = _child_process_alias_node_entrypoint_pattern(
        child_process_node_alias_names,
        require_literal_script_argument=False,
        require_node_executable=False,
    )
    if child_process_alias_call_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_alias_call_pattern):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported child-process Node entrypoint"
                )
    grouped_child_process_alias_pattern = (
        _child_process_grouped_alias_node_entrypoint_pattern(
            child_process_node_alias_names
        )
    )
    if grouped_child_process_alias_pattern is not None and _executable_pattern_matches(
        source_text, grouped_child_process_alias_pattern
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported child-process Node entrypoint"
        )
    child_process_namespace_pattern = _child_process_namespace_node_entrypoint_pattern(
        child_process_namespace_names
    )
    if child_process_namespace_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_namespace_pattern):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported child-process Node entrypoint"
                )
    for specifier in _native_addon_entrypoint_specifiers(source_text):
        specifiers.append((specifier, "require"))

    if _child_process_sync_shell_call_pattern(child_process_sync_alias_names).search(
        source_text
    ) or _child_process_indirect_shell_call_pattern(
        child_process_sync_alias_names
    ).search(
        source_text
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported shell child-process entrypoint"
        )
    indirect_fork_pattern = _child_process_indirect_fork_entrypoint_pattern(
        child_process_fork_alias_names
    )
    if indirect_fork_pattern is not None and indirect_fork_pattern.search(source_text):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect child-process fork entrypoint"
        )

    for constructor_name in sorted(worker_constructor_names, key=len, reverse=True):
        for match in re.finditer(rf"\bnew\s+{re.escape(constructor_name)}\s*\(", source_text):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported Worker entrypoint"
                )
        if re.search(
            rf"\bnew\s*\(\s*[^()]*,\s*{re.escape(constructor_name)}\s*\)\s*\(",
            source_text,
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported indirect Worker entrypoint"
            )
    for namespace_name in sorted(worker_namespace_names, key=len, reverse=True):
        for pattern in (
            rf"\bnew\s+{re.escape(namespace_name)}\s*(?:\.|\?\.)\s*Worker\s*\(",
            rf"\bnew\s+{re.escape(namespace_name)}\s*(?:\.|\?\.)?\s*\[\s*['\"]Worker['\"]\s*\]\s*\(",
        ):
            for match in re.finditer(pattern, source_text):
                if not any(start <= match.start() < end for start, end in accepted_spans):
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported Worker entrypoint"
                    )
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
    if child_process_fork_alias_names:
        fork_alias_alternatives = "|".join(
            re.escape(name)
            for name in sorted(child_process_fork_alias_names, key=len, reverse=True)
        )
        for match in re.finditer(
            rf"(?<![\w$.])(?:{fork_alias_alternatives})\s*\(",
            source_text,
        ):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported fork entrypoint"
                )
    for match in re.finditer(
        r"(?<![\w$])(?:spawn|spawnSync|execFile|execFileSync|child_process\.(?:spawn|spawnSync|execFile|execFileSync)|[A-Za-z_$][0-9A-Za-z_$]*\s*\.\s*(?:spawn|spawnSync|execFile|execFileSync))\s*\(\s*process\.execPath\s*,",
        source_text,
    ):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    for match in re.finditer(
        rf"(?<![\w$])(?:child_process|{JS_IDENTIFIER})\s*(?:\?\.)?\s*\[\s*['\"](?:spawn|spawnSync|execFile|execFileSync)['\"]\s*\]\s*\(\s*process\.execPath\s*,",
        source_text,
        re.DOTALL,
    ):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    if re.search(
        rf"(?<![\w$])(?:child_process|{JS_IDENTIFIER})\s*(?:\?\.)?\s*\[\s*['\"](?:exec|execSync)['\"]\s*\]\s*\(",
        source_text,
        re.DOTALL,
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported shell child-process entrypoint"
        )
    child_process_alias_process_execpath_pattern = _child_process_alias_node_entrypoint_pattern(
        child_process_node_alias_names,
        require_literal_script_argument=False,
    )
    if child_process_alias_process_execpath_pattern is not None:
        for match in child_process_alias_process_execpath_pattern.finditer(
            source_text
        ):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported child-process Node entrypoint"
                )
    child_process_indirect_alias_pattern = (
        _child_process_indirect_alias_node_entrypoint_pattern(
            child_process_node_alias_names
        )
    )
    if child_process_indirect_alias_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_indirect_alias_pattern):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported child-process Node entrypoint"
                )
    child_process_callable_indirect_alias_pattern = (
        _child_process_callable_indirect_entrypoint_pattern(
            child_process_node_alias_names
        )
    )
    if (
        child_process_callable_indirect_alias_pattern is not None
        and child_process_callable_indirect_alias_pattern.search(source_text)
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported child-process Node entrypoint"
        )
    child_process_callable_indirect_shell_pattern = (
        _child_process_callable_indirect_entrypoint_pattern(
            child_process_sync_alias_names
        )
    )
    if (
        child_process_callable_indirect_shell_pattern is not None
        and child_process_callable_indirect_shell_pattern.search(source_text)
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported shell child-process entrypoint"
        )
    child_process_callable_indirect_fork_pattern = (
        _child_process_callable_indirect_entrypoint_pattern(
            child_process_fork_alias_names
        )
    )
    if (
        child_process_callable_indirect_fork_pattern is not None
        and child_process_callable_indirect_fork_pattern.search(source_text)
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect child-process fork entrypoint"
        )
    for match in _child_process_indirect_namespace_node_entrypoint_pattern().finditer(
        source_text
    ):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    _reject_unbound_execution_references(
        source_text,
        accepted_spans=accepted_spans,
        worker_names=worker_constructor_names,
        worker_namespaces=worker_namespace_names,
        fork_names=child_process_fork_alias_names,
        node_names=child_process_node_alias_names,
        shell_names=child_process_sync_alias_names,
        child_namespaces=child_process_namespace_names,
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
            if _is_js_line_terminator(character):
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
            _specifier, index = parsed
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported module.register hook"
            )
        else:
            index += 1
    return specifiers


def _static_runtime_import_specifiers(source_text: str) -> list[str]:
    """Return static import/export specifiers found in executable code only."""
    return [match.group("specifier") for match in _executable_pattern_matches(
        strip_source_comments(source_text), STATIC_RUNTIME_IMPORT_SPECIFIER
    )]


def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:
    source_text = strip_source_comments(source_text)
    source_text = _decode_js_identifier_escapes_in_executable_code(source_text)
    _reject_evaluated_runtime_loaders(source_text)
    commonjs_specifiers = _commonjs_require_specifiers(source_text)
    create_require_specifiers = _create_require_specifiers(source_text)
    module_register_hooks = _module_register_hook_specifiers(source_text)
    create_require_specifiers.extend(_module_loader_reference_specifiers(source_text))
    dynamic_specifiers = _dynamic_import_specifiers(source_text)
    nonstatic_specifiers = (
        commonjs_specifiers + create_require_specifiers + dynamic_specifiers
    )
    process_module_specifiers = {"process", "node:process"}
    if process_module_specifiers.intersection(
        nonstatic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported native add-on process module import"
        )
    if any(
        specifier in EVALUATED_RUNTIME_CLUSTER_SPECIFIERS
        for specifier in nonstatic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported cluster execution capability"
        )
    if any(specifier in {"worker_threads", "node:worker_threads"} for specifier in dynamic_specifiers):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic Worker execution capability"
        )
    if any(specifier in CHILD_PROCESS_SPECIFIERS for specifier in dynamic_specifiers):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic child-process execution capability"
        )
    if any(specifier in NODE_MODULE_SPECIFIERS for specifier in dynamic_specifiers):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported dynamic CommonJS runtime loader capability"
        )
    if any(
        specifier
        in (
            EVALUATED_RUNTIME_TEST_RUNNER_SPECIFIERS
            | EVALUATED_RUNTIME_VM_SPECIFIERS
            | EVALUATED_RUNTIME_SQLITE_SPECIFIERS
        )
        for specifier in nonstatic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported unbound execution capability"
        )
    _reject_unbound_require_references(source_text)
    _reject_mutable_launch_configuration(source_text)
    execution_entrypoints = _runtime_execution_entrypoint_specifiers(source_text)
    source_text = strip_source_comments(source_text)
    specifiers: list[tuple[str, bool, str]] = []
    for specifier in _static_runtime_import_specifiers(source_text):
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source import specifier contains an unsupported JavaScript escape"
            )
        if specifier in process_module_specifiers:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported native add-on process module import"
            )
        if specifier in EVALUATED_RUNTIME_INSPECTOR_SPECIFIERS:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported inspector evaluation capability"
            )
        if specifier in EVALUATED_RUNTIME_REPL_SPECIFIERS:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported REPL evaluated loader capability"
            )
        if specifier in EVALUATED_RUNTIME_CLUSTER_SPECIFIERS:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported cluster execution capability"
            )
        if specifier in (
            EVALUATED_RUNTIME_TEST_RUNNER_SPECIFIERS
            | EVALUATED_RUNTIME_VM_SPECIFIERS
            | EVALUATED_RUNTIME_SQLITE_SPECIFIERS
        ):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported unbound execution capability"
            )
        specifiers.append((specifier, True, "import"))
    if any(
        specifier in EVALUATED_RUNTIME_INSPECTOR_SPECIFIERS
        for specifier in commonjs_specifiers + create_require_specifiers + dynamic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported inspector evaluation capability"
        )
    if any(
        specifier in EVALUATED_RUNTIME_REPL_SPECIFIERS
        for specifier in commonjs_specifiers + create_require_specifiers + dynamic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported REPL evaluated loader capability"
        )
    if any(
        specifier in EVALUATED_RUNTIME_CLUSTER_SPECIFIERS
        for specifier in commonjs_specifiers + create_require_specifiers + dynamic_specifiers
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported cluster execution capability"
        )
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


def _normalize_import_specifier_for_resolution(
    specifier: str, *, import_kind: str
) -> str:
    if import_kind == "require":
        return specifier
    normalized = specifier.split("?", 1)[0].split("#", 1)[0]
    if not normalized.startswith(".") or "%" not in normalized:
        return normalized
    if re.search(r"%(?![0-9A-Fa-f]{2})", normalized):
        raise RuntimeSourceContractError(
            f"runtime source import specifier contains an invalid file URL escape: {specifier}"
        )
    if re.search(r"%(?:2[fF]|5[cC])", normalized):
        raise RuntimeSourceContractError(
            f"runtime source import specifier contains an encoded path separator: {specifier}"
        )
    try:
        decoded = urllib.parse.unquote(normalized, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeSourceContractError(
            f"runtime source import specifier contains an invalid UTF-8 file URL escape: {specifier}"
        ) from exc
    if "\x00" in decoded:
        raise RuntimeSourceContractError(
            f"runtime source import specifier contains a NUL path segment: {specifier}"
        )
    return decoded


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
    matches: list[tuple[int, int, str, Any]] = []
    for key, target in exports.items():
        if not isinstance(key, str) or "*" not in key or not key.startswith("."):
            continue
        prefix, suffix = key.split("*", 1)
        if not export_key.startswith(prefix) or not export_key.endswith(suffix):
            continue
        replacement = export_key[len(prefix) : len(export_key) - len(suffix)]
        if not replacement:
            continue
        matches.append((len(prefix), len(key), replacement, target))
    if not matches:
        return None
    _, _, replacement, target = max(matches, key=lambda item: item[:2])
    return _substitute_export_target(target, replacement)


def _imports_pattern_target(imports: dict[str, Any], specifier: str) -> Any:
    matches: list[tuple[int, int, str, Any]] = []
    for key, target in imports.items():
        if not isinstance(key, str) or "*" not in key or not key.startswith("#"):
            continue
        prefix, suffix = key.split("*", 1)
        if not specifier.startswith(prefix) or not specifier.endswith(suffix):
            continue
        replacement = specifier[len(prefix) : len(specifier) - len(suffix)]
        if not replacement:
            continue
        matches.append((len(prefix), len(key), replacement, target))
    if not matches:
        return None
    _, _, replacement, target = max(matches, key=lambda item: item[:2])
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


def _imports_map_target(imports: Any, specifier: str) -> Any:
    if not isinstance(imports, dict):
        return None
    if not specifier.startswith("#") or specifier in {"#", "#/"}:
        raise RuntimeSourceContractError(
            f"runtime package import is invalid: {specifier}"
        )
    if specifier in imports:
        return imports.get(specifier)
    return _imports_pattern_target(imports, specifier)


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
        if any("%" in target for target in targets):
            raise RuntimeSourceContractError(
                "runtime package export target contains an unsupported percent-encoded path"
            )
        if any("?" in target or "#" in target for target in targets):
            raise RuntimeSourceContractError(
                "runtime package export target contains an unsupported URL suffix"
            )
        if any(not target.startswith("./") for target in targets):
            raise RuntimeSourceContractError(
                "runtime package export target is unsupported"
            )
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


def _nearest_package_self_reference(
    root: Path, importer: Path, package_name: str
) -> tuple[Path, dict[str, Any]] | None:
    root = root.resolve()
    current = importer.resolve().parent
    while True:
        try:
            current.relative_to(root)
        except ValueError:
            return None
        package_json = current / "package.json"
        if package_json.is_file():
            payload = _load_package_json(package_json, package_name)
            if payload.get("name") == package_name and payload.get("exports") is not None:
                return current, payload
        if current == root:
            return None
        current = current.parent


def _nearest_package_imports_scope(
    root: Path, importer: Path
) -> tuple[Path, dict[str, Any]] | None:
    root = root.resolve()
    current = importer.resolve().parent
    while True:
        try:
            current.relative_to(root)
        except ValueError:
            return None
        package_json = current / "package.json"
        if package_json.is_file():
            payload = _load_package_json(package_json, "package imports")
            if payload.get("imports") is not None:
                return current, payload
        if current == root:
            return None
        current = current.parent


def _resolve_package_import(
    *,
    root: Path,
    importer: Path,
    specifier: str,
    required: bool,
    import_kind: str,
) -> tuple[Path, ...]:
    scope = _nearest_package_imports_scope(root, importer)
    if scope is None:
        if required:
            importer_relative = source_relative_path(root, importer)
            raise RuntimeSourceContractError(
                "runtime package import could not be resolved: "
                f"{importer_relative} imports {specifier}"
            )
        return ()
    package_root, package_payload = scope
    package_json = (package_root / "package.json").resolve()
    imports_target = _imports_map_target(package_payload.get("imports"), specifier)
    targets = _export_condition_targets(
        imports_target,
        RUNTIME_PACKAGE_CONDITIONS.get(
            import_kind, RUNTIME_PACKAGE_CONDITIONS["import"]
        ),
    )
    for target in targets:
        if "%" in target:
            raise RuntimeSourceContractError(
                "runtime package import target contains an unsupported percent-encoded path"
            )
        if "?" in target or "#" in target:
            raise RuntimeSourceContractError(
                "runtime package import target contains an unsupported URL suffix"
            )
        if not target.startswith("./"):
            raise RuntimeSourceContractError(
                "runtime package import target is unsupported: "
                f"{specifier}"
            )
        base = (package_root / target).resolve()
        resolved = _resolve_existing_candidate(
            root,
            base,
            include_directory_index=import_kind != "require",
        )
        if resolved is not None:
            return (package_json, resolved)
        if import_kind == "require":
            resolved_package = _resolve_commonjs_directory_package(
                root,
                base,
                package_name=specifier,
            )
            if len(resolved_package) > 1:
                return (package_json, *resolved_package)
            resolved = _resolve_existing_candidate(root, base)
            if resolved is not None:
                return (
                    (package_json, *resolved_package, resolved)
                    if resolved_package
                    else (package_json, resolved)
                )
    if required:
        importer_relative = source_relative_path(root, importer)
        raise RuntimeSourceContractError(
            "runtime package import could not be resolved: "
            f"{importer_relative} imports {specifier}"
        )
    return (package_json,)


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
            if resolved.suffix == ".node":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on"
                )
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
    root = root.resolve()
    if import_kind == "child":
        # The parent launches with cwd=root; source code may not mutate cwd,
        # execPath, execArgv or the inherited environment (checked above).
        if not specifier or specifier.startswith("-") or Path(specifier).is_absolute():
            raise RuntimeSourceContractError("runtime child entrypoint is unsupported")
        child = (root / specifier).resolve()
        source_relative_path(root, child)
        if not child.is_file() or child.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:
            raise RuntimeSourceContractError("runtime child entrypoint must name an exact source file")
        return (child,)
    if specifier.startswith("#"):
        return _resolve_package_import(
            root=root,
            importer=importer,
            specifier=specifier,
            required=required,
            import_kind=import_kind,
        )
    normalized = _normalize_import_specifier_for_resolution(
        specifier, import_kind=import_kind
    )
    if _is_node_builtin(normalized):
        return ()
    if not normalized.startswith(".") and "%" in normalized:
        raise RuntimeSourceContractError(
            "runtime package import contains an unsupported percent-encoded path"
        )
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
    self_reference = _nearest_package_self_reference(root, importer, package_name)
    if self_reference is not None:
        package_root, package_payload = self_reference
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
                    include_directory_index=import_kind != "require",
                )
                if resolved is None and import_kind == "require":
                    resolved_package = _resolve_commonjs_directory_package(
                        root,
                        base,
                        package_name=specifier,
                    )
                    if len(resolved_package) > 1:
                        return ((package_root / "package.json").resolve(), *resolved_package)
            else:
                resolved = _resolve_existing_candidate(root, base)
            if resolved is not None:
                return ((package_root / "package.json").resolve(), resolved)
        if export_restricted:
            if required:
                importer_relative = source_relative_path(root, importer)
                raise RuntimeSourceContractError(
                    "runtime package import could not be resolved: "
                    f"{importer_relative} imports {specifier}"
                )
            return ((package_root / "package.json").resolve(),)
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
                    include_directory_index=import_kind != "require",
                )
                if resolved is None and import_kind == "require":
                    resolved_package = _resolve_commonjs_directory_package(
                        root,
                        base,
                        package_name=specifier,
                    )
                    if len(resolved_package) > 1:
                        return (package_json.resolve(), *resolved_package)
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


def _runtime_package_scope_metadata(root: Path, source_path: Path) -> tuple[Path, ...]:
    """Bind controlling scope metadata; Node does not inherit across node_modules.

    Recomputed on every snapshot, so insertion/removal of a nearer scope changes
    the path set, even when all executable bytes are unchanged. Resolve and check
    manifests before reading them, including symlinked manifests.
    """
    directory = source_path.resolve().parent
    while directory.is_relative_to(root):
        if directory.name == "node_modules":
            break
        package_json = directory / "package.json"
        if package_json.is_symlink() or package_json.exists():
            source_relative_path(root, package_json)
            if not package_json.is_file():
                raise RuntimeSourceContractError("runtime package scope metadata is unavailable")
            _load_package_json(package_json, "runtime package scope")
            return (package_json.resolve(),)
        if directory == root:
            break
        directory = directory.parent
    return ()


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
        for package_json in _runtime_package_scope_metadata(root, source_path):
            package_relative = source_relative_path(root, package_json)
            if package_relative not in seen:
                queue.append(package_json)
        if source_path.suffix == ".json":
            continue
        if source_path.suffix in {".node", ".wasm"}:
            raise RuntimeSourceContractError("runtime source contains an unsupported native code module")
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
