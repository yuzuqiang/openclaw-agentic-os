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
STATIC_RUNTIME_IMPORT_BINDING = re.compile(
    r"""
    \bimport\s+(?!type\b)
    (?P<clause>__STATIC_IMPORT_CLAUSE_FRAGMENT__)\s+from\s*
    ["'][^"']+["']
    """.replace("__STATIC_IMPORT_CLAUSE_FRAGMENT__", STATIC_IMPORT_CLAUSE_FRAGMENT),
    re.VERBOSE | re.DOTALL,
)
COMMONJS_REQUIRE_VALUE_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    require\s*\(
    """,
    re.VERBOSE,
)
COMMONJS_REQUIRE_VALUE_DESTRUCTURING_ASSIGNMENT = re.compile(
    r"""
    \b(?:const|let|var)\s*\{(?P<body>[^{}]*)\}\s*=\s*
    require\s*\(
    """,
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
    \bimport\s*\{{(?P<body>.*?)\}}\s*
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
COMMONJS_MODULE_GRAPH_MEMBER_NAMES = frozenset(("children", "parent", "paths"))
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
COMMONJS_REQUIRE_ALIAS_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    \(?\s*require\s*\)?\s*(?:;|,|\n|$)
    """,
    re.VERBOSE,
)
PROCESS_ENV_PROTOTYPE_MUTATOR_ALIAS_ASSIGNMENT = re.compile(
    rf"""
    \b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*
    """,
    re.VERBOSE,
)
PROCESS_ENV_PROTOTYPE_MUTATOR_DESTRUCTURING_ASSIGNMENT = re.compile(
    r"""
    \b(?:const|let|var)\s*\{(?P<body>[^{}]*)\}\s*=\s*
    """,
    re.VERBOSE | re.DOTALL,
)
PROCESS_ENV_PROTOTYPE_MUTATOR_ALIAS_REASSIGNMENT = re.compile(
    rf"""
    (?<![\w$.])
    (?P<name>{JS_IDENTIFIER})\s*=\s*
    """,
    re.VERBOSE,
)
PROCESS_ENV_PROTOTYPE_MUTATOR_DESTRUCTURING_REASSIGNMENT = re.compile(
    r"""
    (?<![\w$.])
    \(?\s*\{(?P<body>[^{}]*)\}\s*=\s*
    """,
    re.VERBOSE | re.DOTALL,
)
BUILTIN_FUNCTION_DESTRUCTURING_ASSIGNMENT = re.compile(
    r"""
    \b(?:const|let|var)\s*\{(?P<body>[^{}]*)\}\s*=\s*
    """,
    re.VERBOSE | re.DOTALL,
)
BUILTIN_FUNCTION_DESTRUCTURING_REASSIGNMENT = re.compile(
    r"""
    (?<![\w$.])
    \(?\s*\{(?P<body>[^{}]*)\}\s*=\s*
    """,
    re.VERBOSE | re.DOTALL,
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


_REGEXP_PREFIX_KEYWORDS = frozenset({
    "break", "case", "continue", "debugger", "default", "delete", "do", "else", "extends",
    "in", "instanceof", "new", "return", "throw", "typeof", "void",
})


def _source_tokens(source_text: str) -> list[tuple[str, str, int, int]]:
    """Lex code without interpreting it; retain offsets through template expressions.

    This is deliberately not a permissive JavaScript parser.  Ambiguous slash
    contexts fail closed.  Every consumer gets the same comment/string/regexp
    boundaries, including Annex B script comments and nested template expressions.
    """
    tokens: list[tuple[str, str, int, int]] = []
    size = len(source_text)

    def token(kind: str, start: int, end: int, value: str | None = None) -> None:
        tokens.append((kind, source_text[start:end] if value is None else value, start, end))

    def template(index: int) -> int:
        start = index
        interpolated = False
        index += 1
        while index < size:
            if source_text[index] == "\\":
                index += 2
            elif source_text[index] == "`":
                token("template" if interpolated else "static-template", start, index + 1)
                return index + 1
            elif source_text.startswith("${", index):
                interpolated = True
                token("template", start, index)
                token("punctuation", index, index + 2, "${")
                index = code(index + 2, expression=True)
                start = index
            else:
                index += 1
        raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript template literal")

    def within_for_header() -> bool:
        significant = [item for item in tokens if item[0] != "comment"]
        depth = 0
        for cursor in range(len(significant) - 1, -1, -1):
            value = significant[cursor][1]
            if value == ")":
                depth += 1
            elif value == "(":
                if depth:
                    depth -= 1
                else:
                    words = [item[1] for item in significant[max(0, cursor - 2):cursor]]
                    return bool(words and (words[-1] == "for" or words == ["for", "await"]))
        return False

    def code(index: int, *, expression: bool = False) -> int:
        depth = 0
        previous: tuple[str, str] | None = None
        before_previous: tuple[str, str] | None = None
        line_has_code = False
        while index < size:
            start = index
            character = source_text[index]
            if character.isspace() or character == "\ufeff":
                if _is_js_line_terminator(character):
                    line_has_code = False
                index += 1
                continue
            is_hashbang = (
                source_text.startswith("#!", index)
                and (index == 0 or (index == 1 and source_text[0] == "\ufeff"))
            )
            if (
                source_text.startswith("//", index)
                or source_text.startswith("<!--", index)
                or (not line_has_code and source_text.startswith("-->", index))
                or is_hashbang
            ):
                while index < size and not _is_js_line_terminator(source_text[index]):
                    index += 1
                token("comment", start, index)
                continue
            if source_text.startswith("/*", index):
                end = source_text.find("*/", index + 2)
                if end < 0:
                    raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript comment")
                index = end + 2
                if any(_is_js_line_terminator(c) for c in source_text[start:index]):
                    line_has_code = False
                token("comment", start, index)
                continue
            if character == "<":
                following = index + 1
                while following < size and source_text[following].isspace():
                    following += 1
                tag_like = following < size and (
                    source_text[following] == ">"
                    or _is_identifier_character(source_text[following])
                )
                preceding = next((item for item in reversed(tokens) if item[0] != "comment"), None)
                line_break = preceding is not None and any(
                    _is_js_line_terminator(c) for c in source_text[preceding[3]:index]
                )
                expression_prefix = previous is None or (
                    previous[0] == "punctuation" and previous[1] in
                    {"(", "[", "{", "=", ",", ":", ";", "?", "!", "&", "|", "+", "-", "*", "%", "^", "~", "<", ">", "@", "=>"}
                ) or (
                    previous[0] == "identifier"
                    and previous[1] in _REGEXP_PREFIX_KEYWORDS | {"await", "yield", "of"}
                )
                # Attribute-free lowercase JSX intrinsics are inert text for the
                # source scan.  Other JSX/angle contexts need a TSX-aware lexer,
                # so fail closed rather than treating child quotes as strings.
                if tag_like and (expression_prefix or line_break):
                    intrinsic = re.match(r"<[a-z][A-Za-z0-9_-]*\s*/>", source_text[index:])
                    generic_arrow = re.match(
                        rf"<\s*{JS_IDENTIFIER}(?:\s*,\s*{JS_IDENTIFIER})*\s*>\s*\(",
                        source_text[index:],
                    )
                    if intrinsic is None:
                        if generic_arrow is None:
                            raise RuntimeSourceContractError("runtime source contains an unsupported JSX/angle-assertion lexical context")
                    else:
                        index += intrinsic.end()
                        token("jsx-intrinsic", start, index)
                        before_previous, previous = previous, ("literal", "jsx-intrinsic")
                        line_has_code = True
                        continue
            if character in {"'", '"'}:
                index += 1
                while index < size:
                    if source_text[index] == "\\":
                        index += 2
                        # A CRLF line continuation consumes both terminators.
                        if index <= size and source_text[index - 1] == "\r" and source_text[index:index + 1] == "\n":
                            index += 1
                    elif source_text[index] == character:
                        index += 1
                        break
                    elif source_text[index] in {"\r", "\n"}:
                        raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript string")
                    else:
                        index += 1
                else:
                    raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript string")
                token("string", start, index)
                current = ("literal", "string")
            elif character == "`":
                index = template(index)
                current = ("literal", "template")
            elif character == "/":
                previous_value = previous[1] if previous is not None else ""
                member_keyword = before_previous in {("punctuation", "."), ("punctuation", "?.")}
                ambiguous_keyword = (
                    previous is not None and previous[0] == "identifier"
                    and (
                        previous_value in {"await", "yield"}
                        or (previous_value == "of" and within_for_header())
                    )
                    and not member_keyword
                )
                postfix_assertion = previous_value == "postfix!"
                preceding = next((item for item in reversed(tokens) if item[0] != "comment"), None)
                after_line_break = (
                    previous is not None and previous[0] in {"identifier", "literal"}
                    and preceding is not None
                    and not (previous_value in _REGEXP_PREFIX_KEYWORDS and not member_keyword)
                    and any(_is_js_line_terminator(c) for c in source_text[preceding[3]:index])
                )
                if previous_value in {")", "}", ">", "<"} or ambiguous_keyword or postfix_assertion or after_line_break:
                    raise RuntimeSourceContractError("runtime source contains an ambiguous JavaScript slash token")
                regex_start = previous is None or (
                    previous[0] == "punctuation"
                    and previous_value in {"(", "{", "[", "=", ",", ":", ";", "!", "&", "|", "?", "+", "-", "*", "%", "^", "~", "@", "=>"}
                ) or (
                    previous[0] == "identifier"
                    and previous_value in _REGEXP_PREFIX_KEYWORDS
                    and not member_keyword
                )
                if regex_start:
                    index += 1
                    in_class = False
                    while index < size:
                        c = source_text[index]
                        if c == "\\":
                            index += 2
                            continue
                        if _is_js_line_terminator(c):
                            raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript regex literal")
                        if c == "[":
                            in_class = True
                        elif c == "]":
                            in_class = False
                        elif c == "/" and not in_class:
                            index += 1
                            while index < size and _is_identifier_character(source_text[index]):
                                index += 1
                            break
                        index += 1
                    else:
                        raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript regex literal")
                    token("regex", start, index)
                    current = ("literal", "regex")
                else:
                    index += 1
                    token("punctuation", start, index)
                    current = ("punctuation", "/")
            elif character == "#":
                parsed = _parse_js_identifier(source_text, index + 1)
                if parsed is None:
                    raise RuntimeSourceContractError("runtime source contains an invalid JavaScript private identifier")
                name, index = parsed
                token("private-identifier", start, index, "#" + name)
                current = ("literal", "private-identifier")
            elif _is_identifier_character(character) or character == "\\":
                parsed = _parse_js_identifier(source_text, index)
                if parsed is None:  # Numeric text cannot name a loader capability.
                    index += 1
                    while index < size and (source_text[index].isalnum() or source_text[index] in "._"):
                        index += 1
                    token("number", start, index)
                    current = ("literal", "number")
                else:
                    name, index = parsed
                    token("identifier", start, index, name)
                    current = ("identifier", name)
            else:
                if not character.isascii():
                    raise RuntimeSourceContractError("runtime source contains an unsupported JavaScript token")
                if expression and character == "}" and depth == 0:
                    token("template-expression-end", start, start + 1)
                    return index + 1
                if character == "{":
                    depth += 1
                elif character == "}":
                    depth -= 1
                pair = source_text[index:index + 2]
                value = pair if pair in {"?.", "++", "--", "=>"} else character
                index += len(value)
                token("punctuation", start, index)
                current = ("punctuation", value)
                if value == "!" and previous is not None:
                    ends_expression = previous[0] == "literal" or previous[1] in {
                        ")", "]", "}", "++", "--", "postfix!",
                    }
                    if previous[0] == "identifier" and previous[1] not in _REGEXP_PREFIX_KEYWORDS | {
                        "await", "yield", "of", "const", "let", "var", "export", "import",
                    }:
                        ends_expression = True
                    if ends_expression:
                        current = ("punctuation", "postfix!")
            before_previous, previous = previous, current
            line_has_code = True
        if expression:
            raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript template expression")
        return index

    code(0)
    return tokens


def _erased_type_alias_spans(
    source_text: str, tokens: list[tuple[str, str, int, int]],
) -> list[tuple[int, int]]:
    """Recognize a bounded, non-evaluating subset of TS type aliases."""
    code_tokens = [item for item in tokens if item[0] != "comment"]
    size = len(code_tokens)

    def text(index: int) -> str:
        return code_tokens[index][1] if 0 <= index < size else ""

    def identifier(index: int) -> bool:
        return 0 <= index < size and code_tokens[index][0] == "identifier"

    def type_expression(index: int, depth: int = 0) -> int | None:
        if depth > 64:
            return None
        start = index
        if text(index) in {"typeof", "keyof", "readonly", "unique"}:
            index += 1
        if identifier(index) or (index < size and code_tokens[index][0] in {"string", "number"}):
            index += 1
            while text(index) == "." and identifier(index + 1):
                index += 2
            if text(index) == "<":
                index += 1
                while True:
                    end = type_expression(index, depth + 1)
                    if end is None:
                        return None
                    index = end
                    if text(index) != ",":
                        break
                    index += 1
                if text(index) != ">":
                    return None
                index += 1
        elif text(index) == "(":
            end = type_expression(index + 1, depth + 1)
            if end is None or text(end) != ")":
                return None
            index = end + 1
        else:
            return None
        while text(index) == "[":
            index += 1
            if text(index) != "]":
                end = type_expression(index, depth + 1)
                if end is None:
                    return None
                index = end
            if text(index) != "]":
                return None
            index += 1
        if text(index) in {"|", "&"}:
            end = type_expression(index + 1, depth + 1)
            if end is None:
                return None
            index = end
        return index if index > start else None

    spans: list[tuple[int, int]] = []
    for index, (kind, value, start, end) in enumerate(code_tokens):
        if kind != "identifier" or value != "type" or not identifier(index + 1):
            continue
        boundary = index - 1
        if text(boundary) == "export":
            boundary -= 1
        if boundary >= 0 and text(boundary) not in {";", "{", "}"}:
            continue
        if any(_is_js_line_terminator(c) for c in source_text[end:code_tokens[index + 1][2]]):
            continue
        if text(index + 2) != "=":
            continue
        type_end = type_expression(index + 3)
        if type_end is None:
            continue
        if text(type_end) not in {"", ";", "}"}:
            gap = source_text[code_tokens[type_end - 1][3]:code_tokens[type_end][2]]
            if not any(_is_js_line_terminator(c) for c in gap):
                continue
        spans.append((start, code_tokens[type_end - 1][3]))
    return spans


def _source_scan_view(source_text: str) -> str:
    """A shared lexical view for the legacy, non-evaluating recognizers.

    Classify lexical boundaries exactly once.  Regex contents and template text
    are inert; template expressions remain executable.  Replace division tokens
    by a neutral binary operator so no later recognizer guesses whether a slash
    starts a regexp.  Normalize escaped/non-ASCII identifiers consistently, using
    collision-free local names where the recognizers need ASCII identifiers.
    This view is never executed and never used for file hashes.
    """
    output = list(source_text)
    tokens = _source_tokens(source_text)
    erased_spans = _erased_type_alias_spans(source_text, tokens)
    for start, end in erased_spans:
        for index in range(start, end):
            if not _is_js_line_terminator(source_text[index]):
                output[index] = " "
    tokens = [token for token in tokens if not any(
        start <= token[2] < end for start, end in erased_spans
    )]
    identifiers = {value for kind, value, _start, _end in tokens if kind == "identifier"}
    canonical_names: dict[str, str] = {}
    counter = 0
    for value in sorted(identifiers):
        if value.isascii():
            continue
        while True:
            name = f"__agentic_source_identifier_{counter}__"
            counter += 1
            if name not in identifiers:
                break
        canonical_names[value] = name
    for kind, value, start, end in tokens:
        if kind in {"comment", "regex", "template", "jsx-intrinsic"}:
            for index in range(start, end):
                if not _is_js_line_terminator(source_text[index]):
                    output[index] = " "
            if kind in {"regex", "jsx-intrinsic"}:
                output[start] = "0"
        elif kind == "punctuation" and value == "/":
            output[start] = "*"
        elif kind == "punctuation" and value == "${":
            output[start:end] = "( "
        elif kind == "template-expression-end":
            output[start] = ")"
    for kind, value, start, end in reversed(tokens):
        if kind == "identifier":
            output[start:end] = canonical_names.get(value, value)
    return "".join(output)


def strip_source_comments(source_text: str) -> str:
    """Blank comments, not their line terminators or offsets."""
    output = list(source_text)
    for kind, _value, start, end in _source_tokens(source_text):
        if kind == "comment":
            for index in range(start, end):
                if not _is_js_line_terminator(source_text[index]):
                    output[index] = " "
    return "".join(output)


def _is_identifier_character(character: str) -> bool:
    # ECMAScript identifier continuations also include combining marks and the
    # two join controls.  Unsupported non-ASCII tokens are rejected by the lexer.
    return ("_" + character).isidentifier() or character in {"$", "\u200c", "\u200d"}


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
    index = 0
    state = "code"
    quote = ""
    while index < len(source_text):
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
        if state == "line_comment":
            output.append(character)
            if _is_js_line_terminator(character):
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            output.append(character)
            if character == "*" and next_character == "/":
                output.append(next_character)
                index += 2
                state = "code"
            else:
                index += 1
            continue
        if state == "string":
            output.append(character)
            if character == "\\" and index + 1 < len(source_text):
                output.append(next_character)
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            output.extend((character, next_character))
            index += 2
            state = "line_comment"
            continue
        if character == "/" and next_character == "*":
            output.extend((character, next_character))
            index += 2
            state = "block_comment"
            continue
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            output.append(source_text[index:regex_end])
            index = regex_end
            continue
        if character == "`":
            template_start = index
            _chunks, index = _template_expression_chunks(source_text, index)
            output.append(source_text[template_start:index])
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            output.append(character)
            index += 1
            continue
        if character == "\\" and next_character == "u":
            decoded, index = _decode_js_identifier_escape(source_text, index)
            output.append(decoded)
            continue
        output.append(character)
        index += 1
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
    if property_name == "chdir":
        raise RuntimeSourceContractError("runtime source contains an unsupported runtime working-directory mutation")
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
    if token == "of" and _token_is_contextual_for_of(source_text, token_start, token_end):
        return False
    if token == "let" and _let_token_starts_lexical_declaration(
        source_text, token_start, token_end, bracket_index
    ):
        return False
    if token in {"await", "case", "const", "return", "throw", "var", "yield"}:
        before_token = token_start - 1
        while before_token >= 0 and source_text[before_token].isspace():
            before_token -= 1
        return before_token >= 0 and source_text[before_token] == "."
    return True


def _let_token_starts_lexical_declaration(
    source_text: str, token_start: int, token_end: int, bracket_index: int
) -> bool:
    if source_text[token_start:token_end] != "let":
        return False
    after_token = _skip_js_trivia(source_text, token_end)
    if after_token != bracket_index or source_text[bracket_index] not in "[{":
        return False
    before_token = _previous_non_trivia_index(source_text, token_start)
    if before_token < 0:
        return True
    if source_text[before_token] in ";{}":
        return True
    return source_text[before_token] == "(" and _for_header_opener_belongs_to_for(
        source_text, before_token
    )


def _token_is_contextual_for_of(source_text: str, token_start: int, token_end: int) -> bool:
    if source_text[token_start:token_end] != "of":
        return False
    cursor = token_start - 1
    depth = 0
    opener = -1
    while cursor >= 0:
        character = source_text[cursor]
        if character == ")":
            depth += 1
        elif character == "(":
            if depth == 0:
                opener = cursor
                break
            depth -= 1
        cursor -= 1
    if opener < 0:
        return False
    before_opener = opener - 1
    while before_opener >= 0 and source_text[before_opener].isspace():
        before_opener -= 1
    word_end = before_opener + 1
    while before_opener >= 0 and _is_identifier_character(source_text[before_opener]):
        before_opener -= 1
    word = source_text[before_opener + 1 : word_end]
    if word == "await":
        before_await = before_opener
        while before_await >= 0 and source_text[before_await].isspace():
            before_await -= 1
        await_prefix_end = before_await + 1
        while before_await >= 0 and _is_identifier_character(source_text[before_await]):
            before_await -= 1
        word = source_text[before_await + 1 : await_prefix_end]
    if word != "for":
        return False
    header_close = _matching_for_header_close_index(source_text, opener)
    if header_close < 0:
        return False
    separator = _for_header_top_level_of_separator_span(
        source_text, opener + 1, header_close
    )
    if separator is None:
        return False
    previous = source_text[token_start - 1] if token_start > 0 else ""
    following = source_text[token_end] if token_end < len(source_text) else ""
    return (
        separator == (token_start, token_end)
        and not _is_identifier_character(previous)
        and not _is_identifier_character(following)
    )


def _matching_for_header_close_index(source_text: str, opener: int) -> int:
    index = opener + 1
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
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if depth == 0:
                return index if character == ")" else -1
            depth -= 1
            index += 1
            continue
        index += 1
    return -1


def _for_header_has_top_level_semicolon(
    source_text: str, start_index: int, end_index: int
) -> bool:
    index = start_index
    depth = 0
    state = "code"
    quote = ""
    while index < end_index:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < end_index else ""
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
            if character == "\\" and index + 1 < end_index:
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
        if regex_end is not None and regex_end <= end_index:
            index = regex_end
            continue
        if character == "`":
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if depth > 0:
                depth -= 1
            index += 1
            continue
        if character == ";" and depth == 0:
            return True
        index += 1
    return False


def _for_header_top_level_of_separator_span(
    source_text: str, start_index: int, end_index: int
) -> tuple[int, int] | None:
    index = start_index
    depth = 0
    state = "code"
    quote = ""
    separator: tuple[int, int] | None = None
    while index < end_index:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < end_index else ""
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
            if character == "\\" and index + 1 < end_index:
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
        if regex_end is not None and regex_end <= end_index:
            index = regex_end
            continue
        if character == "`":
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if depth > 0:
                depth -= 1
            index += 1
            continue
        if character == ";" and depth == 0:
            return None
        token_end = index + 2
        if (
            depth == 0
            and source_text.startswith("of", index)
            and (
                index == start_index
                or not _is_identifier_character(source_text[index - 1])
            )
            and (
                token_end >= end_index
                or not _is_identifier_character(source_text[token_end])
            )
        ):
            prefix = source_text[start_index:index].strip()
            suffix = source_text[token_end:end_index].strip()
            if prefix and suffix and prefix not in {
                "await using",
                "const",
                "let",
                "using",
                "var",
            }:
                if separator is None:
                    separator = (index, token_end)
            index = token_end
            continue
        index += 1
    return separator


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
    if token == "of" and _token_is_contextual_for_of(source_text, token_start, token_end):
        return False
    if token == "let" and _let_token_starts_lexical_declaration(
        source_text, token_start, token_end, bracket_index
    ):
        return False
    if token in {"await", "case", "const", "return", "throw", "var", "yield"}:
        before_token = token_start - 1
        while before_token >= 0 and source_text[before_token].isspace():
            before_token -= 1
        return before_token >= 0 and source_text[before_token] == "."
    return True


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


def _parse_static_numeric_member(
    source_text: str, index: int
) -> tuple[str, int] | None:
    start = index
    if index >= len(source_text) or not source_text[index].isdigit():
        return None
    while index < len(source_text) and source_text[index].isdigit():
        index += 1
    if index < len(source_text) and source_text[index] == ".":
        index += 1
        while index < len(source_text) and source_text[index].isdigit():
            index += 1
    return source_text[start:index], index


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
            parsed = _parse_static_numeric_member(source_text, index)
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


def _computed_member_target_may_be_function_constructor(
    source_text: str, bracket_index: int
) -> bool:
    if not _computed_member_bracket_has_target(source_text, bracket_index):
        return False
    process_env_target_start = _computed_member_process_env_target_start(
        source_text, bracket_index
    )
    if process_env_target_start is not None:
        return _process_env_target_was_reassigned(
            source_text, process_env_target_start
        )
    receiver = _computed_member_identifier_receiver(source_text, bracket_index)
    return (
        _computed_member_receiver_is_builtin_function(source_text, bracket_index)
        or (
            receiver is not None
            and _identifier_was_bound_to_function_like_value(
                source_text, receiver, bracket_index
            )
        )
        or _computed_member_direct_receiver_is_function_like_literal(
            source_text, bracket_index
        )
    )


def _computed_member_receiver_is_builtin_function(
    source_text: str, bracket_index: int
) -> bool:
    receiver = _computed_member_identifier_receiver(source_text, bracket_index)
    if receiver is not None and (
        _identifier_was_bound_to_builtin_function(source_text, receiver, bracket_index)
        or _identifier_was_bound_to_runtime_import(source_text, receiver, bracket_index)
    ):
        return True
    receiver_start = _computed_member_direct_receiver_start(source_text, bracket_index)
    if receiver_start is None:
        return False
    return _parse_builtin_function_reference_end(source_text, receiver_start) is not None


def _computed_member_identifier_receiver(
    source_text: str, bracket_index: int
) -> str | None:
    cursor = bracket_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    if cursor < 0 or not _is_identifier_character(source_text[cursor]):
        return None
    token_end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    before = source_text[cursor] if cursor >= 0 else ""
    if before and (_is_identifier_character(before) or before in ".]"):
        return None
    return source_text[cursor + 1 : token_end]


def _computed_member_direct_receiver_start(
    source_text: str, bracket_index: int
) -> int | None:
    cursor = bracket_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return None
    if not _is_identifier_character(source_text[cursor]):
        return None
    token_end = cursor + 1
    while cursor >= 0 and (
        _is_identifier_character(source_text[cursor]) or source_text[cursor] == "."
    ):
        cursor -= 1
    return cursor + 1 if cursor + 1 < token_end else None


def _identifier_was_bound_to_function_like_value(
    source_text: str, name: str, end_index: int
) -> bool:
    escaped = re.escape(name)
    patterns = (
        re.compile(
            rf"\b(?:async\s+)?function\s*\*?\s+{escaped}\b",
            re.VERBOSE,
        ),
        re.compile(rf"\bclass\s+{escaped}\b", re.VERBOSE),
        re.compile(
            rf"""
            (?:
                \b(?:const|let|var)\s+{escaped}
              |
                (?<![\w$.]){escaped}
            )
            \s*=\s*
            (?:
                (?:async\s+)?function\b
              | class\b
              | (?:async\s*)?\([^)]*\)\s*=>
              | (?:async\s+)?{JS_IDENTIFIER}\s*=>
            )
            """,
            re.VERBOSE | re.DOTALL,
        ),
    )
    for pattern in patterns:
        for match in _executable_pattern_matches(source_text, pattern):
            if match.start() >= end_index:
                break
            return True
    return False


def _computed_member_direct_receiver_is_function_like_literal(
    source_text: str, bracket_index: int
) -> bool:
    receiver_start = _computed_member_expression_receiver_start(
        source_text, bracket_index
    )
    if receiver_start is None:
        return False
    receiver = source_text[receiver_start:bracket_index]
    return bool(
        re.search(
            r"(?:^|[^\w$])(?:async\s+)?function\b|(?:^|[^\w$])class\b|=>",
            receiver,
        )
    )


def _computed_member_expression_receiver_start(
    source_text: str, bracket_index: int
) -> int | None:
    cursor = bracket_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return None
    if source_text[cursor] in ")]}":
        matching = _matching_open_js_delimiter_index(source_text, cursor)
        return matching
    return None


def _matching_open_js_delimiter_index(source_text: str, close_index: int) -> int | None:
    closer = source_text[close_index]
    opener = {")": "(", "]": "[", "}": "{"}.get(closer)
    if opener is None:
        return None
    depth = 0
    for kind, value, start, _end in reversed(_source_tokens(source_text[: close_index + 1])):
        if kind in {"comment", "string", "template", "static-template", "regexp"}:
            continue
        if value == closer:
            depth += 1
        elif value == opener:
            depth -= 1
            if depth == 0:
                return start
    return None


def _identifier_was_bound_to_runtime_import(
    source_text: str, name: str, end_index: int
) -> bool:
    for match in _executable_pattern_matches(source_text, STATIC_RUNTIME_IMPORT_BINDING):
        if match.start() >= end_index:
            break
        if name in _static_import_clause_local_names(match.group("clause")):
            return True
    for match in _executable_pattern_matches(source_text, COMMONJS_REQUIRE_VALUE_ASSIGNMENT):
        if match.start() >= end_index:
            break
        if match.group("name") == name:
            return True
    for match in _executable_pattern_matches(
        source_text, COMMONJS_REQUIRE_VALUE_DESTRUCTURING_ASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        if name in _destructured_aliases_for_static_members(
            match.group("body"), allowed_members=None, fail_closed_on_unsupported=True
        ):
            return True
    return False


def _static_import_clause_local_names(clause: str) -> set[str]:
    names: set[str] = set()
    clause = clause.strip()
    if not clause:
        return names
    default_part, separator, rest = clause.partition(",")
    first_part = default_part.strip()
    if first_part.startswith("*"):
        match = re.fullmatch(rf"\*\s+as\s+({JS_IDENTIFIER})", first_part)
        if match is not None:
            names.add(match.group(1))
    elif first_part.startswith("{"):
        names.update(_static_import_named_clause_local_names(clause))
        return names
    else:
        parsed_default = _parse_js_identifier(first_part, 0)
        if parsed_default is not None:
            local_name, local_end = parsed_default
            if first_part[local_end:].strip() == "":
                names.add(local_name)
    if separator:
        rest = rest.strip()
        if rest.startswith("{"):
            names.update(_static_import_named_clause_local_names(rest))
        elif rest.startswith("*"):
            match = re.fullmatch(rf"\*\s+as\s+({JS_IDENTIFIER})", rest)
            if match is not None:
                names.add(match.group(1))
    return names


def _static_import_named_clause_local_names(clause: str) -> set[str]:
    start = clause.find("{")
    end = clause.rfind("}")
    if start < 0 or end <= start:
        return set()
    names: set[str] = set()
    for part in _split_top_level_comma_parts(clause[start + 1 : end]):
        part = part.strip()
        if part.startswith("type "):
            part = part[5:].strip()
        parsed = _parse_named_binding_part(part)
        if parsed is None:
            continue
        _imported, local = parsed
        names.add(local)
    return names


def _identifier_was_bound_to_builtin_function(
    source_text: str, name: str, end_index: int
) -> bool:
    assignment = re.compile(
        rf"""
        (?:
            \b(?:const|let|var)\s+{re.escape(name)}
          |
            (?<![\w$.]){re.escape(name)}
        )
        \s*=\s*
        """,
        re.VERBOSE,
    )
    for match in _executable_pattern_matches(source_text, assignment):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        rhs_end = _parse_builtin_function_or_bound_reference_end(
            source_text, rhs_start
        )
        if rhs_end is None:
            continue
        assignment_end = _skip_js_trivia(source_text, rhs_end)
        if assignment_end >= end_index or source_text[assignment_end] in {
            ";",
            ",",
            "\r",
            "\n",
        }:
            return True
    for match in _executable_pattern_matches(
        source_text, BUILTIN_FUNCTION_DESTRUCTURING_ASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        parsed_base = _parse_builtin_function_destructuring_base(source_text, rhs_start)
        if parsed_base is None:
            continue
        base, rhs_end = parsed_base
        assignment_end = _skip_js_trivia(source_text, rhs_end)
        if assignment_end < end_index and source_text[assignment_end] not in {
            ";",
            ",",
            "\r",
            "\n",
        }:
            continue
        if name in _builtin_function_destructured_aliases(base, match.group("body")):
            return True
    for match in _executable_pattern_matches(
        source_text, BUILTIN_FUNCTION_DESTRUCTURING_REASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        parsed_base = _parse_builtin_function_destructuring_base(source_text, rhs_start)
        if parsed_base is None:
            continue
        base, rhs_end = parsed_base
        assignment_end = _skip_js_trivia(source_text, rhs_end)
        if assignment_end < end_index and source_text[assignment_end] not in {
            ";",
            ",",
            ")",
            "\r",
            "\n",
        }:
            continue
        if name in _builtin_function_destructured_aliases(base, match.group("body")):
            return True
    return False


def _parse_builtin_function_or_bound_reference_end(
    source_text: str, index: int
) -> int | None:
    builtin_end = _parse_builtin_function_reference_end(source_text, index)
    if builtin_end is None:
        return None
    try:
        member = _parse_static_runtime_member(
            source_text,
            builtin_end,
            dynamic_error="runtime source contains an unsupported evaluated loader reference",
        )
    except RuntimeSourceContractError:
        return builtin_end
    if member is None or member[0] != "bind":
        return builtin_end
    call_index = _skip_js_trivia(source_text, member[1])
    if call_index >= len(source_text) or source_text[call_index] != "(":
        return builtin_end
    close_index = _matching_js_delimiter_index(source_text, call_index, len(source_text))
    if close_index is None:
        return builtin_end
    return close_index + 1


def _parse_builtin_function_reference_end(source_text: str, index: int) -> int | None:
    parsed_math = _parse_grouped_named_base(source_text, index, "Math")
    if parsed_math is not None:
        try:
            member = _parse_static_runtime_member(
                source_text,
                parsed_math,
                dynamic_error="runtime source contains an unsupported evaluated loader reference",
            )
        except RuntimeSourceContractError:
            return None
        if member is not None:
            return member[1]

    for base in ("Object", "Reflect"):
        parsed_base = _parse_grouped_named_base(source_text, index, base)
        if parsed_base is None:
            continue
        try:
            member = _parse_static_runtime_member(
                source_text,
                parsed_base,
                dynamic_error="runtime source contains an unsupported evaluated loader reference",
            )
        except RuntimeSourceContractError:
            return None
        if member is not None and member[0] in {
            "assign",
            "create",
            "defineProperty",
            "getPrototypeOf",
            "setPrototypeOf",
        }:
            return member[1]
    return None


def _parse_builtin_function_destructuring_base(
    source_text: str, index: int
) -> tuple[str, int] | None:
    for base in ("Math", "Object", "Reflect"):
        parsed = _parse_grouped_named_base(source_text, index, base)
        if parsed is None:
            continue
        before = source_text[index - 1] if index > 0 else ""
        if before and (_is_identifier_character(before) or before == "."):
            continue
        after = _skip_js_trivia(source_text, parsed)
        if after < len(source_text) and (
            _is_identifier_character(source_text[after])
            or source_text[after] in ".([`"
            or source_text.startswith("?.", after)
        ):
            continue
        return base, parsed
    return None


def _builtin_function_destructured_aliases(base: str, body: str) -> set[str]:
    allowed_object_members = {
        "assign",
        "create",
        "defineProperty",
        "getPrototypeOf",
        "setPrototypeOf",
    }
    allowed_members = allowed_object_members if base in {"Object", "Reflect"} else None
    return _destructured_aliases_for_static_members(
        body, allowed_members=allowed_members, fail_closed_on_unsupported=True
    )


def _destructured_aliases_for_static_members(
    body: str,
    *,
    allowed_members: set[str] | None,
    fail_closed_on_unsupported: bool,
) -> set[str]:
    aliases: set[str] = set()
    for segment in _split_top_level_comma_parts(body):
        parsed = _parse_static_destructured_property_alias(segment)
        if parsed is None:
            if fail_closed_on_unsupported:
                alias = _destructured_property_fallback_alias(segment)
                if alias is not None:
                    aliases.add(alias)
            continue
        member, alias = parsed
        if allowed_members is None or member in allowed_members:
            aliases.add(alias)
    return aliases


def _split_top_level_comma_parts(source_text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    index = 0
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
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            depth = max(0, depth - 1)
            index += 1
            continue
        if character == "," and depth == 0:
            parts.append(source_text[start:index])
            start = index + 1
        index += 1
    parts.append(source_text[start:])
    return parts


def _parse_static_destructured_property_alias(
    segment: str,
) -> tuple[str, str] | None:
    index = _skip_js_trivia(segment, 0)
    if index >= len(segment):
        return None
    if segment[index] == "[":
        member_index = _skip_js_trivia(segment, index + 1)
        parsed = _parse_quoted_specifier(segment, member_index)
        if parsed is None:
            parsed = _parse_static_template_member(segment, member_index)
        if parsed is None:
            return None
        member, member_end = parsed
        close_index = _skip_js_trivia(segment, member_end)
        if close_index >= len(segment) or segment[close_index] != "]":
            return None
        colon_index = _skip_js_trivia(segment, close_index + 1)
        if colon_index >= len(segment) or segment[colon_index] != ":":
            return None
        alias_index = _skip_js_trivia(segment, colon_index + 1)
        parsed_alias = _parse_js_identifier(segment, alias_index)
        if parsed_alias is None:
            return None
        alias, alias_end = parsed_alias
        return (member, alias) if segment[_skip_js_trivia(segment, alias_end):].strip() == "" else None
    parsed_literal = _parse_quoted_specifier(segment, index)
    if parsed_literal is not None:
        member, member_end = parsed_literal
        colon_index = _skip_js_trivia(segment, member_end)
        if colon_index >= len(segment) or segment[colon_index] != ":":
            return None
        alias_index = _skip_js_trivia(segment, colon_index + 1)
        parsed_alias = _parse_js_identifier(segment, alias_index)
        if parsed_alias is None:
            return None
        alias, alias_end = parsed_alias
        return (member, alias) if segment[_skip_js_trivia(segment, alias_end):].strip() == "" else None
    parsed_identifier = _parse_js_identifier(segment, index)
    if parsed_identifier is None:
        return None
    member, member_end = parsed_identifier
    after_member = _skip_js_trivia(segment, member_end)
    if after_member == len(segment):
        return member, member
    if after_member >= len(segment) or segment[after_member] != ":":
        return None
    alias_index = _skip_js_trivia(segment, after_member + 1)
    parsed_alias = _parse_js_identifier(segment, alias_index)
    if parsed_alias is None:
        return None
    alias, alias_end = parsed_alias
    return (member, alias) if segment[_skip_js_trivia(segment, alias_end):].strip() == "" else None


def _destructured_property_fallback_alias(segment: str) -> str | None:
    colon_index = _top_level_colon_index(segment)
    if colon_index is None:
        return None
    alias_index = _skip_js_trivia(segment, colon_index + 1)
    parsed_alias = _parse_js_identifier(segment, alias_index)
    if parsed_alias is None:
        return None
    alias, alias_end = parsed_alias
    return alias if segment[_skip_js_trivia(segment, alias_end):].strip() == "" else None


def _top_level_colon_index(source_text: str) -> int | None:
    index = 0
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
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            depth = max(0, depth - 1)
            index += 1
            continue
        if character == ":" and depth == 0:
            return index
        index += 1
    return None


def _computed_member_process_env_target_start(
    source_text: str, bracket_index: int
) -> int | None:
    target_end = bracket_index
    while target_end > 0 and source_text[target_end - 1].isspace():
        target_end -= 1
    if target_end <= 0:
        return None

    candidate_starts: list[int] = []
    if source_text[target_end - 1] == ")":
        opener_index = _matching_js_opener_index(source_text, target_end - 1)
        if opener_index is not None:
            candidate_starts.append(opener_index)

    candidate_starts.extend(
        _computed_member_receiver_process_candidate_starts(source_text, target_end)
    )

    seen: set[int] = set()
    for candidate_start in candidate_starts:
        if candidate_start in seen:
            continue
        seen.add(candidate_start)
        try:
            parsed = _parse_grouped_process_env_target(source_text, candidate_start)
        except RuntimeSourceContractError:
            continue
        if parsed is None:
            continue
        process_start, parsed_end = parsed
        if _skip_js_trivia(source_text, parsed_end) == target_end:
            return process_start
    return None


def _computed_member_receiver_process_candidate_starts(
    source_text: str, target_end: int
) -> list[int]:
    cursor = target_end - 1
    budget = 4096
    while cursor >= 0 and target_end - cursor <= budget:
        character = source_text[cursor]
        if character in ";\r\n{}=,:+-*/%&|^!<>~":
            cursor += 1
            break
        cursor -= 1
    else:
        cursor = max(0, target_end - budget)

    starts: list[int] = []
    window = source_text[cursor:target_end]
    for match in re.finditer(r"\b(?:globalThis|global|process)\b", window):
        starts.append(cursor + match.start())
    return starts


def _parse_grouped_process_env_target(
    source_text: str, index: int
) -> tuple[int, int] | None:
    if index < 0:
        return None
    index = _skip_js_trivia(source_text, index)
    if index < 0 or index >= len(source_text):
        return None
    if source_text[index] == "(":
        parsed = _parse_grouped_process_env_target(source_text, index + 1)
        if parsed is None:
            return None
        process_start, inner_end = parsed
        close_index = _skip_js_trivia(source_text, inner_end)
        if close_index >= len(source_text) or source_text[close_index] != ")":
            return None
        return process_start, close_index + 1

    process_start = index
    process_end = _parse_process_base(source_text, index)
    if process_end is None:
        return None
    member = _parse_process_member(source_text, process_end)
    if member is None or member[0] != "env":
        return None
    return process_start, member[1]


def _process_env_target_was_reassigned(source_text: str, target_start: int) -> bool:
    index = 0
    state = "code"
    quote = ""
    while index < target_start:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < target_start else ""
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
            if character == "\\" and index + 1 < target_start:
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
        if regex_end is not None and regex_end <= target_start:
            index = regex_end
            continue
        if character == "`":
            chunks, new_index = _template_expression_chunks(source_text, index)
            if new_index <= target_start and any(
                _process_env_target_was_reassigned(chunk, len(chunk)) for chunk in chunks
            ):
                return True
            index = new_index
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        process_end = _parse_process_base(source_text, index)
        if process_end is not None:
            member = _parse_process_member(source_text, process_end)
            if member is not None and member[0] == "env":
                assignment_target_end = _parenthesized_process_env_target_end(
                    source_text, index, member[1], target_start
                )
                after_target = _skip_js_trivia(source_text, assignment_target_end)
                if after_target < target_start and _starts_js_assignment_operator(
                    source_text, after_target
                ):
                    return True
                if _process_env_reference_is_destructuring_assignment_target(
                    source_text, index, target_start
                ):
                    return True
                if _process_env_reference_is_for_of_assignment_target(
                    source_text, index, member[1], target_start
                ):
                    return True
                if _process_env_reference_is_prototype_mutation_target(
                    source_text, index, member[1], target_start
                ):
                    return True
                index = max(index + 1, member[1])
                continue
        index += 1
    return False


def _parenthesized_process_env_target_end(
    source_text: str, process_start: int, process_end: int, target_start: int
) -> int:
    target_start_index = process_start
    target_end = process_end
    while True:
        opener_index = _previous_non_trivia_index(source_text, target_start_index)
        if opener_index < 0 or source_text[opener_index] != "(":
            return target_end
        closer_index = _skip_js_trivia(source_text, target_end)
        if closer_index >= target_start or source_text[closer_index] != ")":
            return target_end
        matching_close = _matching_js_delimiter_index(
            source_text, opener_index, target_start
        )
        if matching_close != closer_index:
            return target_end
        target_start_index = opener_index
        target_end = closer_index + 1


def _process_env_reference_is_destructuring_assignment_target(
    source_text: str, process_start: int, target_start: int
) -> bool:
    stack = _js_delimiter_stack_at(source_text, process_start)
    for opener, opener_index in reversed(stack):
        if opener not in "{[":
            continue
        close_index = _matching_js_delimiter_index(source_text, opener_index, target_start)
        if close_index is None:
            continue
        after_close = _skip_js_trivia(source_text, close_index + 1)
        if after_close < target_start and _starts_js_assignment_operator(
            source_text, after_close
        ):
            return True
    return False


def _process_env_reference_is_for_of_assignment_target(
    source_text: str, process_start: int, process_end: int, target_start: int
) -> bool:
    for opener, opener_index in reversed(
        _js_delimiter_stack_at(source_text, process_start)
    ):
        if opener != "(" or not _for_header_opener_belongs_to_for(
            source_text, opener_index
        ):
            continue
        header_close = _matching_for_header_close_index(source_text, opener_index)
        if header_close < 0 or header_close >= target_start:
            continue
        separator = _for_header_top_level_of_separator_span(
            source_text, opener_index + 1, header_close
        )
        if (
            separator is not None
            and opener_index < process_start
            and process_end <= separator[0]
        ):
            return True
    return False


def _process_env_reference_is_prototype_mutation_target(
    source_text: str, process_start: int, process_end: int, target_start: int
) -> bool:
    for opener, opener_index in reversed(
        _js_delimiter_stack_at(source_text, process_start)
    ):
        if opener != "(":
            continue
        target_end = _parenthesized_process_env_target_end(
            source_text, process_start, process_end, target_start
        )
        after_target = _skip_js_trivia(source_text, target_end)
        if after_target >= target_start or source_text[after_target] not in ",)":
            continue
        argument_index = _call_argument_index_before(source_text, opener_index, process_start)
        try:
            invocation = _callee_process_env_prototype_mutator_invocation(
                source_text, opener_index
            )
        except RuntimeSourceContractError:
            if argument_index == 0:
                raise
            continue
        if invocation is None:
            continue
        if invocation == "direct" and argument_index == 0:
            return True
        if invocation in {"call", "bind"} and argument_index >= 1:
            return True
        if invocation == "apply" and argument_index >= 1:
            return True
    return False


def _callee_is_process_env_prototype_mutator(source_text: str, opener_index: int) -> bool:
    return (
        _callee_process_env_prototype_mutator_invocation(source_text, opener_index)
        is not None
    )


def _callee_process_env_prototype_mutator_invocation(
    source_text: str, opener_index: int
) -> str | None:
    for kind, value, start, _end in _source_tokens(source_text):
        if start >= opener_index:
            break
        if kind != "identifier" or value not in {"Object", "Reflect"}:
            continue
        for candidate_start in _grouped_identifier_candidate_starts(source_text, start):
            member_end = _parse_process_env_prototype_mutator_member_at(
                source_text, candidate_start, opener_index=opener_index
            )
            if member_end is not None and _callee_end_reaches_call_opener(
                source_text, candidate_start, member_end, opener_index
            ):
                return "direct"
            helper = _process_env_prototype_mutator_invocation_helper(
                source_text, member_end, opener_index
            )
            if helper is not None:
                return helper

    alias = _callee_identifier_before_call(source_text, opener_index)
    if alias in _process_env_prototype_mutator_alias_names(source_text, opener_index):
        return "direct"
    alias_invocation = _callee_process_env_prototype_mutator_alias_invocation(
        source_text, opener_index
    )
    if alias_invocation is not None:
        return alias_invocation
    return None


def _callee_process_env_prototype_mutator_alias_invocation(
    source_text: str, opener_index: int
) -> str | None:
    aliases = _process_env_prototype_mutator_alias_names(source_text, opener_index)
    if not aliases:
        return None
    for kind, value, start, _end in _source_tokens(source_text):
        if start >= opener_index:
            break
        if kind != "identifier" or value not in aliases:
            continue
        for candidate_start in _grouped_identifier_candidate_starts(source_text, start):
            alias_end = _parse_grouped_named_base(source_text, candidate_start, value)
            if alias_end is None:
                continue
            if _callee_end_reaches_call_opener(
                source_text, candidate_start, alias_end, opener_index
            ):
                return "direct"
            helper = _process_env_prototype_mutator_invocation_helper(
                source_text, alias_end, opener_index
            )
            if helper is not None:
                return helper
    return None


def _process_env_prototype_mutator_invocation_helper(
    source_text: str, member_end: int | None, opener_index: int
) -> str | None:
    if member_end is None:
        return None
    try:
        member = _parse_static_runtime_member(
            source_text,
            member_end,
            dynamic_error="runtime source contains an unsupported process.env prototype mutator",
        )
    except RuntimeSourceContractError:
        return None
    if member is None or member[0] not in {"apply", "bind", "call"}:
        return None
    if _callee_end_reaches_call_opener(source_text, member_end, member[1], opener_index):
        return member[0]
    return None


def _call_argument_index_before(
    source_text: str, opener_index: int, position: int
) -> int:
    argument_index = 0
    index = opener_index + 1
    depth = 0
    state = "code"
    quote = ""
    while index < position:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < position else ""
        if state == "line_comment":
            if _is_js_line_terminator(character):
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if state == "string":
            if character == "\\" and index + 1 < position:
                index += 2
                continue
            if character == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if character == "/" and next_character == "/":
            state = "line_comment"
            index += 2
            continue
        if character == "/" and next_character == "*":
            state = "block_comment"
            index += 2
            continue
        if character in {"'", '"', "`"}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            depth = max(0, depth - 1)
            index += 1
            continue
        if character == "," and depth == 0:
            argument_index += 1
        index += 1
    return argument_index


def _grouped_identifier_candidate_starts(
    source_text: str, identifier_start: int
) -> list[int]:
    starts = [identifier_start]
    for opener, opener_index in reversed(
        _js_delimiter_stack_at(source_text, identifier_start)
    ):
        if opener != "(":
            continue
        starts.append(opener_index)
    return starts


def _callee_end_reaches_call_opener(
    source_text: str, callee_start: int, callee_end: int, opener_index: int
) -> bool:
    cursor = _skip_js_trivia(source_text, callee_end)
    wrappers = [
        wrapper_index
        for wrapper, wrapper_index in reversed(
            _js_delimiter_stack_at(source_text, callee_start)
        )
        if wrapper == "("
    ]
    while cursor < opener_index and cursor < len(source_text) and source_text[cursor] == ")":
        matching_wrapper = next(
            (
                wrapper_index
                for wrapper_index in wrappers
                if _matching_js_delimiter_index(source_text, wrapper_index, opener_index)
                == cursor
            ),
            None,
        )
        if matching_wrapper is None or not _paren_can_wrap_callee_expression(
            source_text, matching_wrapper
        ):
            break
        wrappers.remove(matching_wrapper)
        cursor = _skip_js_trivia(source_text, cursor + 1)
    if cursor == opener_index:
        return True
    if source_text.startswith("?.", cursor):
        return _skip_js_trivia(source_text, cursor + 2) == opener_index
    return False


def _paren_can_wrap_callee_expression(source_text: str, opener_index: int) -> bool:
    cursor = opener_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    word_end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    preceding_word = source_text[cursor + 1 : word_end]
    return preceding_word not in {"catch", "for", "if", "switch", "while", "with"}


def _parse_process_env_prototype_mutator_member_at(
    source_text: str, candidate_start: int, *, opener_index: int | None = None
) -> int | None:
    base_end = None
    for base_name in ("Object", "Reflect"):
        parsed_base_end = _parse_grouped_named_base(
            source_text, candidate_start, base_name
        )
        if parsed_base_end is not None:
            base_end = parsed_base_end
            break
    if base_end is None:
        return None
    try:
        member = _parse_static_runtime_member(
            source_text,
            base_end,
            dynamic_error="runtime source contains an unsupported process.env prototype mutator",
        )
    except RuntimeSourceContractError:
        if opener_index is not None:
            member_end = _unsupported_computed_runtime_member_end(
                source_text, base_end
            )
            if member_end is not None and _callee_end_reaches_call_opener(
                source_text, candidate_start, member_end, opener_index
            ):
                raise
        return None
    if member is not None and member[0] == "setPrototypeOf":
        return member[1]
    return None


def _unsupported_computed_runtime_member_end(
    source_text: str, index: int
) -> int | None:
    member_index = _skip_js_trivia(source_text, index)
    if source_text.startswith("?.", member_index):
        property_index = _skip_js_trivia(source_text, member_index + 2)
    elif member_index < len(source_text) and source_text[member_index] == ".":
        property_index = _skip_js_trivia(source_text, member_index + 1)
    elif member_index < len(source_text) and source_text[member_index] == "[":
        property_index = member_index
    else:
        return None

    if property_index >= len(source_text) or source_text[property_index] != "[":
        return None
    close_index = _matching_js_delimiter_index(
        source_text, property_index, len(source_text)
    )
    if close_index is None:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported process.env prototype mutator"
        )
    return close_index + 1


def _callee_identifier_before_call(source_text: str, opener_index: int) -> str | None:
    cursor = opener_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    if cursor >= 1 and source_text[cursor - 1 : cursor + 1] == "?.":
        cursor -= 2
        while cursor >= 0 and source_text[cursor].isspace():
            cursor -= 1
    if cursor < 0 or not _is_identifier_character(source_text[cursor]):
        return None
    token_end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    token_start = cursor + 1
    before = source_text[cursor] if cursor >= 0 else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    return source_text[token_start:token_end]


def _process_env_prototype_mutator_alias_names(
    source_text: str, end_index: int
) -> set[str]:
    aliases: set[str] = set()
    for match in _executable_pattern_matches(
        source_text, PROCESS_ENV_PROTOTYPE_MUTATOR_ALIAS_ASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        member_end = _parse_process_env_prototype_mutator_member_at(source_text, rhs_start)
        if member_end is None:
            continue
        assignment_end = _skip_js_trivia(source_text, member_end)
        if assignment_end >= end_index or source_text[assignment_end] in {";", ",", "\r", "\n"}:
            aliases.add(match.group("name"))
    for match in _executable_pattern_matches(
        source_text, PROCESS_ENV_PROTOTYPE_MUTATOR_ALIAS_REASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        name = match.group("name")
        if name in {"const", "let", "var"}:
            continue
        rhs_start = _skip_js_trivia(source_text, match.end())
        member_end = _parse_process_env_prototype_mutator_member_at(source_text, rhs_start)
        if member_end is None:
            continue
        assignment_end = _skip_js_trivia(source_text, member_end)
        if assignment_end >= end_index or source_text[assignment_end] in {
            ";",
            ",",
            "\r",
            "\n",
        }:
            aliases.add(name)
    for match in _executable_pattern_matches(
        source_text, PROCESS_ENV_PROTOTYPE_MUTATOR_DESTRUCTURING_ASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        rhs_end = _parse_process_env_prototype_mutator_destructuring_base(
            source_text, rhs_start
        )
        if rhs_end is None:
            continue
        assignment_end = _skip_js_trivia(source_text, rhs_end)
        if assignment_end < end_index and source_text[assignment_end] not in {
            ";",
            ",",
            "\r",
            "\n",
        }:
            continue
        for alias in _process_env_prototype_mutator_destructured_aliases(
            match.group("body")
        ):
            aliases.add(alias)
    for match in _executable_pattern_matches(
        source_text, PROCESS_ENV_PROTOTYPE_MUTATOR_DESTRUCTURING_REASSIGNMENT
    ):
        if match.start() >= end_index:
            break
        rhs_start = _skip_js_trivia(source_text, match.end())
        rhs_end = _parse_process_env_prototype_mutator_destructuring_base(
            source_text, rhs_start
        )
        if rhs_end is None:
            continue
        assignment_end = _skip_js_trivia(source_text, rhs_end)
        if assignment_end < end_index and source_text[assignment_end] not in {
            ";",
            ",",
            ")",
            "\r",
            "\n",
        }:
            continue
        for alias in _process_env_prototype_mutator_destructured_aliases(
            match.group("body")
        ):
            aliases.add(alias)
    return aliases


def _parse_process_env_prototype_mutator_destructuring_base(
    source_text: str, index: int
) -> int | None:
    parsed = (
        _parse_grouped_named_base(source_text, index, "Object")
        or _parse_grouped_named_base(source_text, index, "Reflect")
    )
    if parsed is None:
        return None
    before = source_text[index - 1] if index > 0 else ""
    if before and (_is_identifier_character(before) or before == "."):
        return None
    after = _skip_js_trivia(source_text, parsed)
    if after < len(source_text) and (
        _is_identifier_character(source_text[after])
        or source_text[after] in ".([`"
        or source_text.startswith("?.", after)
    ):
        return None
    return parsed


def _process_env_prototype_mutator_destructured_aliases(body: str) -> set[str]:
    return _destructured_aliases_for_static_members(
        body, allowed_members={"setPrototypeOf"}, fail_closed_on_unsupported=True
    )


def _for_header_opener_belongs_to_for(source_text: str, opener_index: int) -> bool:
    cursor = opener_index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    word_end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    word = source_text[cursor + 1 : word_end]
    if word == "await":
        cursor -= 1
        while cursor >= 0 and source_text[cursor].isspace():
            cursor -= 1
        word_end = cursor + 1
        while cursor >= 0 and _is_identifier_character(source_text[cursor]):
            cursor -= 1
        word = source_text[cursor + 1 : word_end]
    return word == "for"


def _js_delimiter_stack_at(source_text: str, target_index: int) -> list[tuple[str, int]]:
    index = 0
    state = "code"
    quote = ""
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    while index < target_index:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < target_index else ""
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
            if character == "\\" and index + 1 < target_index:
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
        if regex_end is not None and regex_end <= target_index:
            index = regex_end
            continue
        if character == "`":
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character in "([{":
            stack.append((character, index))
            index += 1
            continue
        if character in ")]}":
            expected = pairs[character]
            if stack and stack[-1][0] == expected:
                stack.pop()
            index += 1
            continue
        index += 1
    return stack


def _matching_js_delimiter_index(
    source_text: str, opener_index: int, end_index: int
) -> int | None:
    opener = source_text[opener_index]
    closer = {"(": ")", "[": "]", "{": "}"}[opener]
    index = opener_index + 1
    depth = 0
    state = "code"
    quote = ""
    while index < end_index:
        character = source_text[index]
        next_character = source_text[index + 1] if index + 1 < end_index else ""
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
            if character == "\\" and index + 1 < end_index:
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
        if regex_end is not None and regex_end <= end_index:
            index = regex_end
            continue
        if character == "`":
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            state = "string"
            quote = character
            index += 1
            continue
        if character == opener:
            depth += 1
            index += 1
            continue
        if character == closer:
            if depth == 0:
                return index
            depth -= 1
            index += 1
            continue
        if character in "([{" and character != opener:
            depth += 1
            index += 1
            continue
        if character in ")]}" and character != closer and depth > 0:
            depth -= 1
            index += 1
            continue
        index += 1
    return None


def _matching_js_opener_index(source_text: str, closer_index: int) -> int | None:
    closer = source_text[closer_index] if closer_index < len(source_text) else ""
    expected = {")": "(", "]": "[", "}": "{"}.get(closer)
    if expected is None:
        return None
    stack = _js_delimiter_stack_at(source_text, closer_index)
    if not stack or stack[-1][0] != expected:
        return None
    opener_index = stack[-1][1]
    if (
        _matching_js_delimiter_index(source_text, opener_index, closer_index + 1)
        != closer_index
    ):
        return None
    return opener_index


def _starts_js_assignment_operator(source_text: str, index: int) -> bool:
    for operator in ("**=", ">>>=", "<<=", ">>=", "&&=", "||=", "??="):
        if source_text.startswith(operator, index):
            return True
    if index >= len(source_text):
        return False
    character = source_text[index]
    next_character = source_text[index + 1] if index + 1 < len(source_text) else ""
    if character == "=":
        return next_character not in {"=", ">"}
    return character in {"+", "-", "*", "/", "%", "&", "|", "^"} and next_character == "="


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
    declaration_spans = [
        match.span()
        for pattern in (CREATE_REQUIRE_IMPORT,)
        for match in _executable_pattern_matches(source_text, pattern)
    ]
    index = 0
    while index < len(source_text):
        skipped = False
        for start, end in declaration_spans:
            if start <= index < end:
                index = end
                skipped = True
                break
        if skipped:
            continue
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
    for kind, value, start, _end in _source_tokens(expression):
        if kind != "identifier" or value != COMMONJS_REQUIRE_TOKEN:
            continue
        if _parse_require_invocation(expression, start) is None:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported indirect CommonJS require invocation"
            )


def _template_expression_end(source_text: str, index: int) -> int:
    depth = 1
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
    after_module = _parse_grouped_named_base(source_text, index, "module")
    if after_module is None:
        return None
    parsed_member = _parse_process_member(source_text, after_module)
    if parsed_member is None:
        return None
    member, member_end = parsed_member
    if member != COMMONJS_REQUIRE_TOKEN:
        return None
    call_index = _skip_js_trivia(source_text, member_end)
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


def _reject_commonjs_module_graph_capabilities(source_text: str) -> None:
    """Reject CommonJS module graph/search-path handles that can load source."""
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    for kind, value, start, _end in tokens:
        if (kind, value) not in {("identifier", "module"), ("punctuation", "(")}:
            continue
        module_end = _parse_grouped_named_base(source_text, start, "module")
        if module_end is None:
            continue
        member = _parse_process_member(source_text, module_end)
        if member is None:
            continue
        member_name, member_end = member
        if member_name in COMMONJS_MODULE_GRAPH_MEMBER_NAMES:
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported CommonJS module graph capability"
            )
        if member_name != COMMONJS_REQUIRE_TOKEN:
            continue
        call_index = _skip_js_trivia(source_text, member_end)
        if source_text.startswith("?.", call_index):
            call_index = _skip_js_trivia(source_text, call_index + 2)
        if call_index >= len(source_text) or source_text[call_index] != "(":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported CommonJS runtime loader"
            )


def _create_require_factory_names(source_text: str) -> set[str]:
    factories = {"createRequire"}
    stripped = strip_source_comments(source_text)
    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
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


def _execution_capability_bindings(
    source_text: str,
) -> tuple[dict[str, str], list[tuple[int, int]], list[str]]:
    """Inventory capability origins, not spellings of subsequent alias assignments.

    Binding an imported function is supported; transferring that function or its
    namespace is not.  The usage audit below accounts for *every* reference, so a
    new JavaScript assignment/call spelling cannot silently introduce an alias.
    """
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    # This inventory records explicit value origins. Ambient Node-compatible
    # spellings are added by the usage audits so type-only imports cannot shadow
    # an actually available Worker or child_process value.
    bindings: dict[str, str] = {}
    declarations: list[tuple[int, int]] = []
    builtin_loads: list[str] = []

    def text(index: int) -> str:
        return tokens[index][1] if 0 <= index < len(tokens) else ""

    def literal(index: int) -> str | None:
        if not 0 <= index < len(tokens) or tokens[index][0] != "string":
            return None
        parsed = _parse_quoted_specifier(source_text, tokens[index][2])
        return parsed[0] if parsed is not None else None

    def erased_clause(start: int, end: int) -> bool:
        if text(start) == "type" and start + 1 < end and text(start + 1) != ",":
            return True
        if text(start) != "{" or text(end - 1) != "}":
            return False
        parts: list[list[tuple[str, str, int, int]]] = [[]]
        for item in tokens[start + 1:end - 1]:
            if item[1] == ",":
                parts.append([])
            else:
                parts[-1].append(item)
        return all(
            not part or (
                len(part) > 1
                and part[0][0] == "identifier"
                and part[0][1] == "type"
                and part[1][1] != "as"
            )
            for part in parts
        )

    def bind(module: str, imported: str, local: str) -> None:
        if module == "worker_threads":
            if imported in {"*", "default"}:
                bindings[local] = "worker-namespace"
            elif imported == "Worker":
                bindings[local] = "worker"
        elif module == "module":
            if imported in {"*", "default", "Module"}:
                bindings[local] = "module-namespace"
            elif imported not in {
                "builtinModules", "createRequire", "findSourceMap",
                "isBuiltin", "register", "registerHooks", "SourceMap",
            }:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS runtime loader binding"
                )
        elif module == "child_process":
            if imported in {"*", "default"}:
                bindings[local] = "child-namespace"
            elif imported in CHILD_PROCESS_FORK_ENTRYPOINT_NAMES:
                bindings[local] = "fork"
            elif imported in CHILD_PROCESS_NODE_ENTRYPOINT_NAMES:
                bindings[local] = "child-node"
            elif imported in CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES:
                bindings[local] = "child-shell"
            else:
                # ChildProcess/_forkChild can launch code too.  They are not safe
                # merely because the older entrypoint allowlist omitted them.
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported child-process Node entrypoint binding"
                )

    def clause(start: int, end: int, module: str, *, commonjs: bool) -> None:
        index = start
        if not commonjs and text(index) == "type" and index + 1 < end and text(index + 1) != ",":
            return
        if index < end and tokens[index][0] == "identifier" and text(index) not in {"{", "*"}:
            bind(module, "default", text(index))
            index += 1
            if text(index) == ",":
                index += 1
        if index == end:
            return
        if not commonjs and text(index) == "*" and text(index + 1) == "as" and index + 3 == end:
            bind(module, "*", text(index + 2))
            return
        if text(index) != "{" or text(end - 1) != "}":
            raise RuntimeSourceContractError("runtime source contains an unsupported execution capability binding")
        index += 1
        while index < end - 1:
            if text(index) == ",":
                index += 1
                continue
            specifier_type_only = False
            if not commonjs and text(index) == "type" and text(index + 1) not in {",", "}", "as"}:
                specifier_type_only = True
                index += 1
            imported = literal(index) if tokens[index][0] == "string" else text(index)
            if tokens[index][0] not in {"string", "identifier"}:
                raise RuntimeSourceContractError("runtime source contains an unsupported execution capability binding")
            local = imported
            index += 1
            if text(index) == (":" if commonjs else "as"):
                index += 1
                if index >= end - 1 or tokens[index][0] != "identifier":
                    raise RuntimeSourceContractError("runtime source contains an unsupported execution capability binding")
                local = text(index)
                index += 1
            if index < end - 1 and text(index) != ",":
                raise RuntimeSourceContractError("runtime source contains an unsupported execution capability binding")
            assert imported is not None and local is not None
            if not specifier_type_only:
                bind(module, imported, local)

    for index, (kind, value, start, _end) in enumerate(tokens):
        if kind != "identifier" or value not in {"import", "export"}:
            continue
        if text(index + 1) in {"(", "."}:
            continue
        if value == "export":
            whole_type = text(index + 1) == "type" and text(index + 2) == "{"
            opening = index + 2 if whole_type else index + 1
            if text(opening) == "{":
                closing = opening + 1
                while closing < len(tokens) and text(closing) not in {"}", ";"}:
                    closing += 1
                if text(closing) == "}" and text(closing + 1) != "from":
                    if whole_type:
                        declarations.append((start, tokens[closing][3]))
                    else:
                        part = opening + 1
                        for end in range(part, closing + 1):
                            if end == closing or text(end) == ",":
                                if (
                                    end - part >= 2
                                    and tokens[part][0] == "identifier"
                                    and text(part) == "type"
                                    and not (end - part == 3 and text(part + 1) == "as")
                                ):
                                    declarations.append((tokens[part][2], tokens[end - 1][3]))
                                part = end + 1
        # Side-effect imports declare no local capabilities.
        if value == "import" and index + 1 < len(tokens) and tokens[index + 1][0] == "string":
            declarations.append((start, tokens[index + 1][3]))
            continue
        cursor = index + 1
        depth = 0
        while cursor < len(tokens) and text(cursor) != ";":
            if depth == 0 and cursor > index + 1 and text(cursor) in {"import", "export"}:
                break
            if text(cursor) == "{":
                depth += 1
            elif text(cursor) == "}":
                depth -= 1
            if text(cursor) == "from" and literal(cursor + 1) is not None:
                specifier = literal(cursor + 1)
                assert specifier is not None
                module = specifier.removeprefix("node:")
                if module in {"worker_threads", "child_process", "module"} and value == "export":
                    if erased_clause(index + 1, cursor):
                        declarations.append((start, tokens[cursor + 1][3]))
                        break
                    raise RuntimeSourceContractError("runtime source contains an unsupported execution capability re-export")
                if module in {"worker_threads", "child_process", "module"}:
                    clause(index + 1, cursor, module, commonjs=False)
                if value == "import":
                    declarations.append((start, tokens[cursor + 1][3]))
                break
            # An export declaration without `from` is not an import clause.
            if value == "export" and text(cursor) in {"=", "const", "let", "var", "function", "class", "default"}:
                break
            cursor += 1

    for index, (kind, value, start, _end) in enumerate(tokens):
        if kind != "identifier" or value != "require" or text(index + 1) != "(":
            continue
        specifier = literal(index + 2)
        if specifier is None or text(index + 3) != ")":
            continue
        module = specifier.removeprefix("node:")
        if module not in {"worker_threads", "child_process", "module"}:
            continue
        # Only a direct require on a simple declaration RHS has a locally
        # accounted-for returned namespace.  Inline/grouped/aliased factories
        # are rejected by the origin count, rather than guessed at.
        if text(index - 1) != "=":
            if module == "module" and text(index + 4) == "." and text(index + 5) == "createRequire":
                builtin_loads.append(module)
            continue
        lhs = index - 2
        if text(lhs) == "}":
            while lhs >= 0 and text(lhs) != "{":
                lhs -= 1
        if lhs < 1 or text(lhs - 1) not in {"const", "let", "var"}:
            continue
        clause(lhs, index - 1, module, commonjs=True)
        declarations.append((tokens[lhs - 1][2], tokens[index - 1][3]))
        builtin_loads.append(module)
    return bindings, declarations, builtin_loads


def _typescript_type_reference_spans(source_text: str) -> list[tuple[int, int]]:
    """Recognize type positions without declaring value names harmless."""
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    size = len(tokens)
    spans: list[tuple[int, int]] = []

    def text(index: int) -> str:
        return tokens[index][1] if 0 <= index < size else ""

    def same_line(left: int, right: int) -> bool:
        return not any(_is_js_line_terminator(c) for c in source_text[tokens[left][3]:tokens[right][2]])

    def balanced(index: int, opener: str, closer: str) -> int | None:
        stack = [closer]
        index += 1
        pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
        while index < size:
            value = text(index)
            if value in pairs:
                stack.append(pairs[value])
            elif value in {")", "]", "}", ">"}:
                if value != stack.pop():
                    return None
                if not stack:
                    return index + 1
            index += 1
        return None

    def parse_type(index: int, depth: int = 0) -> int | None:
        if depth > 64 or index >= size:
            return None
        start = index
        value = text(index)
        if value in {"keyof", "readonly", "unique", "typeof", "infer"}:
            return parse_type(index + 1, depth + 1)
        if value == "abstract" and text(index + 1) == "new":
            index += 1
            value = "new"
        if value == "new":
            index += 1
            if text(index) != "(":
                return None
            end = balanced(index, "(", ")")
            if end is None or text(end) != "=>":
                return None
            return parse_type(end + 1, depth + 1)
        if value in {"{", "["}:
            index = balanced(index, value, "}" if value == "{" else "]")
            if index is None:
                return None
        elif value == "(":
            end = balanced(index, "(", ")")
            if end is None:
                return None
            if text(end) == "=>":
                return parse_type(end + 1, depth + 1)
            inner = parse_type(index + 1, depth + 1)
            if inner != end - 1:
                return None
            index = end
        elif tokens[index][0] in {"identifier", "string", "number", "static-template"}:
            if value == "import" and text(index + 1) == "(":
                if index + 3 >= size or tokens[index + 2][0] != "string" or text(index + 3) != ")":
                    return None
                index += 4
            else:
                index += 1
            while text(index) == "." and index + 1 < size and tokens[index + 1][0] == "identifier":
                index += 2
            if text(index) == "<":
                index = balanced(index, "<", ">")
                if index is None:
                    return None
        else:
            return None
        while text(index) == "[":
            end = balanced(index, "[", "]")
            if end is None:
                return None
            index = end
        if text(index) in {"|", "&"}:
            return parse_type(index + 1, depth + 1)
        if text(index) == "extends":
            constraint = parse_type(index + 1, depth + 1)
            if constraint is None or text(constraint) != "?":
                return None
            positive = parse_type(constraint + 1, depth + 1)
            if positive is None or text(positive) != ":":
                return None
            return parse_type(positive + 1, depth + 1)
        return index if index > start else None

    def add(start: int, type_start: int) -> int | None:
        end = parse_type(type_start)
        if end is not None:
            if text(end) == "(" and same_line(end - 1, end):
                return None
            spans.append((tokens[start][2], tokens[end - 1][3]))
        return end

    stack: list[tuple[str, int]] = []
    questions = [0]
    for index, (kind, value, _start, _end) in enumerate(tokens):
        if kind == "identifier" and value == "type" and index + 2 < size:
            if tokens[index + 1][0] == "identifier" and same_line(index, index + 1) and text(index - 1) not in {".", "?."}:
                cursor = index + 2
                if text(cursor) == "<":
                    cursor = balanced(cursor, "<", ">")
                if cursor is not None and text(cursor) == "=":
                    add(index, cursor + 1)
        if kind == "identifier" and value in {"as", "satisfies"} and index + 1 < size:
            previous = tokens[index - 1] if index > 0 else None
            operand = previous is not None and (
                previous[0] in {"string", "number", "static-template"}
                or previous[1] in {")", "]", "}"}
                or (
                    previous[0] == "identifier"
                    and previous[1] not in _REGEXP_PREFIX_KEYWORDS | {"await", "yield", "of", "const", "let", "var", "export", "import"}
                )
            )
            type_prefix = tokens[index + 1][0] in {"identifier", "string", "number"} or text(index + 1) == "{"
            if operand and type_prefix and same_line(index - 1, index) and same_line(index, index + 1):
                add(index + 1, index + 1)
        if value in {"(", "[", "{"}:
            stack.append((value, index))
            questions.append(0)
        elif value in {")", "]", "}"}:
            if stack:
                stack.pop()
                questions.pop()
        elif value == "?" and text(index + 1) != ":":
            questions[-1] += 1
        elif value == ":":
            if questions[-1]:
                questions[-1] -= 1
                continue
            name_index = index - 2 if text(index - 1) == "?" else index - 1
            if name_index < 0 or tokens[name_index][0] != "identifier":
                continue
            previous = text(name_index - 1)
            variable = previous in {"const", "let", "var"} and same_line(name_index - 1, name_index)
            parameter = bool(stack and stack[-1][0] == "(" and previous in {"(", ","})
            if variable or parameter:
                add(index + 1, index + 1)
    return spans


def _reject_execution_capability_escapes(
    source_text: str,
    *,
    accepted_spans: list[tuple[int, int]],
    loaded_execution_modules: list[str],
) -> None:
    explicit_bindings, declarations, builtin_loads = _execution_capability_bindings(source_text)
    bindings = {"Worker": "worker", "child_process": "child-namespace", **explicit_bindings}
    expected = sorted(specifier.removeprefix("node:") for specifier in loaded_execution_modules)
    if sorted(builtin_loads) != expected:
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported Worker entrypoint or child-process Node entrypoint namespace origin"
        )
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    type_spans = _typescript_type_reference_spans(source_text)
    for index, (kind, value, start, _end) in enumerate(tokens):
        if kind != "identifier" or value not in bindings:
            continue
        # Property names on unrelated objects are not references to a binding.
        if index and tokens[index - 1][1] in {".", "?."}:
            if not (
                tokens[index - 1][1] == "."
                and index >= 3
                and all(t[1] == "." for t in tokens[index - 3:index])
            ):
                continue
        if any(left <= start < right for left, right in declarations + accepted_spans + type_spans):
            continue
        capability = bindings[value]
        if capability == "module-namespace":
            if (
                index + 2 < len(tokens)
                and tokens[index + 1][1] == "."
                and tokens[index + 2][1] in {
                    "builtinModules", "createRequire", "findSourceMap",
                    "isBuiltin", "SourceMap",
                }
            ):
                continue
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported CommonJS runtime loader namespace transfer"
            )
        if capability.startswith("worker"):
            description = "Worker entrypoint"
        elif capability == "child-shell":
            description = "shell child-process entrypoint"
        elif capability == "fork":
            description = "indirect child-process fork entrypoint"
        else:
            description = "child-process Node entrypoint"
        raise RuntimeSourceContractError(
            f"runtime source contains an unsupported {description} capability usage"
        )


def _reject_unaccounted_require_references(source_text: str) -> None:
    """Require may be called or assigned to an audited simple alias, not escape."""
    accepted: list[tuple[int, int]] = [
        match.span() for match in _executable_pattern_matches(source_text, COMMONJS_REQUIRE_ALIAS_ASSIGNMENT)
    ]
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    for kind, value, start, _end in tokens:
        if (kind, value) in {("identifier", "module"), ("punctuation", "(")}:
            parsed_module_require = _parse_bracketed_module_require_invocation(
                source_text, start
            )
            if parsed_module_require is not None:
                accepted.append((start, parsed_module_require[1]))
        if kind == "punctuation" and value == "(":
            parsed = _parse_parenthesized_require_invocation(source_text, start)
            if parsed is not None:
                accepted.append((start, parsed[1]))
        elif kind == "identifier" and value == "require":
            if any(left <= start < right for left, right in accepted):
                continue
            parsed = _parse_property_require_invocation(source_text, start)
            if parsed is None:
                parsed = _parse_require_invocation(source_text, start)
            if parsed is not None:
                accepted.append((start, parsed[1]))
    for index, (kind, value, start, _end) in enumerate(tokens):
        if kind != "identifier" or value != "require":
            continue
        if any(left <= start < right for left, right in accepted):
            continue
        if index and tokens[index - 1][1] == "typeof":
            continue
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect CommonJS require capability usage"
        )


def _reject_unaccounted_create_require_references(source_text: str) -> None:
    """Account for the factory *and* its returned loader, not just factory calls."""
    factories = _create_require_factory_names(source_text)
    declarations = [
        match.span()
        for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE)
        for match in _executable_pattern_matches(source_text, pattern)
    ]
    assignments = [
        match for match in _executable_pattern_matches(source_text, CREATE_REQUIRE_ASSIGNMENT)
        if match.group("factory") in factories
    ]
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    for index, (kind, value, start, end) in enumerate(tokens):
        if any(left <= start < right for left, right in declarations):
            continue
        if kind in {"string", "static-template"} and index and tokens[index - 1][1] == "[":
            if value[1:-1] == "createRequire":
                raise RuntimeSourceContractError("runtime source contains an unsupported computed createRequire factory reference")
        if kind != "identifier" or value not in factories:
            continue
        call_index = _skip_js_trivia(source_text, end)
        if source_text[call_index:call_index + 1] != "(":
            raise RuntimeSourceContractError("runtime source contains an unsupported indirect createRequire factory reference")
        base_end = _create_require_base_end(source_text, call_index)
        if base_end is None:
            raise RuntimeSourceContractError("runtime source contains an unsupported non-local createRequire base")
        after = _skip_js_trivia(source_text, base_end)
        if source_text[after:after + 1] == "(":
            parsed = _parse_quoted_specifier(source_text, _skip_js_trivia(source_text, after + 1))
            if parsed is None or source_text[_skip_js_trivia(source_text, parsed[1]):][:1] != ")":
                raise RuntimeSourceContractError("runtime source contains an unsupported createRequire loader signature")
            continue
        assigned = any(match.span("factory") == (start, end) for match in assignments)
        delimiter = source_text[after:after + 1]
        terminated = not delimiter or delimiter in {";", ","}
        # ASI is only allowed when the next token cannot continue the initializer.
        if not terminated and any(_is_js_line_terminator(c) for c in source_text[base_end:after]):
            terminated = delimiter not in {"(", "[", ".", "?", "`", "+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "="}
        if not assigned or not terminated:
            raise RuntimeSourceContractError("runtime source contains an unsupported createRequire loader transfer")


def _worker_thread_bindings(source_text: str) -> tuple[set[str], set[str]]:
    bindings, _declarations, _loads = _execution_capability_bindings(source_text)
    return (
        {"Worker"} | {name for name, kind in bindings.items() if kind == "worker"},
        {name for name, kind in bindings.items() if kind == "worker-namespace"},
    )


def _child_process_sync_alias_bindings(
    source_text: str,
) -> tuple[set[str], set[str], set[str], set[str]]:
    bindings, _declarations, _loads = _execution_capability_bindings(source_text)
    return (
        {name for name, kind in bindings.items() if kind == "fork"},
        {name for name, kind in bindings.items() if kind == "child-node"},
        {name for name, kind in bindings.items() if kind == "child-shell"},
        {"child_process"} | {name for name, kind in bindings.items() if kind == "child-namespace"},
    )


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

    for match in NODE_MODULE_NAMESPACE_IMPORT.finditer(stripped):
        namespace_names.add(match.group("name"))
    for match in NODE_MODULE_DEFAULT_IMPORT.finditer(stripped):
        name = match.group("name")
        namespace_names.add(name)
        constructor_names.add(name)
    for match in NODE_MODULE_REQUIRE_ASSIGNMENT.finditer(stripped):
        name = match.group("name")
        namespace_names.add(name)
        constructor_names.add(name)
    for match in NODE_MODULE_MEMBER_REQUIRE_ASSIGNMENT.finditer(stripped):
        constructor_names.add(match.group("name"))

    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
            for part in match.group("body").split(","):
                binding = _parse_named_binding_part(part)
                if binding is None:
                    continue
                imported_name, local_name = binding
                if imported_name == "Module":
                    constructor_names.add(local_name)

    for pattern in (CREATE_REQUIRE_IMPORT, CREATE_REQUIRE_DESTRUCTURED_REQUIRE):
        for match in pattern.finditer(stripped):
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
                computed_member is None
                and _computed_member_target_may_be_function_constructor(
                    source_text, index
                )
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported evaluated loader reference"
                )
            if (
                computed_member is not None
                and computed_member[0] in EVALUATED_RUNTIME_LOADER_TOKENS
            ):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported evaluated loader reference"
                )
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
    cursor = _previous_non_trivia_index(source_text, index)
    return source_text[cursor] if cursor >= 0 else ""


def _previous_non_trivia_index(source_text: str, index: int) -> int:
    cursor = index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    return cursor


def _previous_code_word(source_text: str, index: int) -> str:
    word, _start = _previous_code_word_and_start(source_text, index)
    return word


def _previous_code_word_and_start(source_text: str, index: int) -> tuple[str, int]:
    cursor = index - 1
    while cursor >= 0 and source_text[cursor].isspace():
        cursor -= 1
    end = cursor + 1
    while cursor >= 0 and _is_identifier_character(source_text[cursor]):
        cursor -= 1
    start = cursor + 1
    return source_text[start:end], start


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
    previous_word, previous_word_start = _previous_code_word_and_start(source_text, index)
    if previous_word_start > 0 and source_text[previous_word_start - 1] == ".":
        return False
    if previous_word_start > 1 and source_text[previous_word_start - 2:previous_word_start] == "?.":
        return False
    return previous_word in {
        "await",
        "case",
        "default",
        "delete",
        "else",
        "extends",
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
    # Match only at actual code-token boundaries, including nested template
    # expressions.  Offsets remain in the original string, never in a substring.
    matches: list[re.Match[str]] = []
    consumed = 0
    for kind, _value, start, _end in _source_tokens(source_text):
        if kind not in {"identifier", "punctuation"} or start < consumed:
            continue
        match = pattern.match(source_text, start)
        if match is not None:
            matches.append(match)
            consumed = match.end()
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
    factories = _create_require_factory_names(source_text)
    for kind, value, start, end in _source_tokens(source_text):
        if kind != "identifier" or value not in factories:
            continue
        if _previous_non_trivia_character(source_text, start) == ".":
            continue
        opening = _skip_js_trivia(source_text, end)
        if source_text[opening:opening + 1] != "(":
            continue
        base_end = _create_require_base_end(source_text, opening)
        if base_end is None:
            continue
        call = _skip_js_trivia(source_text, base_end)
        if source_text[call:call + 1] != "(":
            continue
        parsed = _parse_quoted_specifier(source_text, _skip_js_trivia(source_text, call + 1))
        if parsed is None or source_text[_skip_js_trivia(source_text, parsed[1]):][:1] != ")":
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported createRequire loader signature"
            )
        specifiers.append(parsed[0])
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


def _parse_literal_string_array_specifiers(source_text: str, index: int) -> tuple[list[str], int] | None:
    if index >= len(source_text) or source_text[index] != "[":
        return None
    values: list[str] = []
    index = _skip_js_trivia(source_text, index + 1)
    if index < len(source_text) and source_text[index] == "]":
        return values, index + 1
    while index < len(source_text):
        parsed = _parse_quoted_specifier(source_text, index)
        if parsed is None:
            return None
        value, index = parsed
        values.append(value)
        index = _skip_js_trivia(source_text, index)
        if index < len(source_text) and source_text[index] == ",":
            index = _skip_js_trivia(source_text, index + 1)
            if index < len(source_text) and source_text[index] == "]":
                return values, index + 1
            continue
        if index < len(source_text) and source_text[index] == "]":
            return values, index + 1
        return None
    return None


def _matching_js_delimiter_end(
    source_text: str, open_index: int, open_character: str, close_character: str
) -> int | None:
    depth = 0
    for kind, value, start, end in _source_tokens(source_text):
        if start < open_index or kind != "punctuation":
            continue
        if value == open_character:
            depth += 1
        elif value == close_character:
            depth -= 1
            if depth == 0:
                return end
    return None


def _parse_dynamic_import_identifier_argument(
    source_text: str, argument_index: int
) -> tuple[str, int] | None:
    parsed = _parse_js_identifier(source_text, argument_index)
    if parsed is None:
        return None
    argument, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        return None
    return argument, close_index


def _literal_for_of_dynamic_import_specifiers(
    source_text: str, argument: str, call_index: int
) -> list[str] | None:
    # Even `for (const specifier of ["./safe.mjs"])` depends on mutable
    # Array.prototype[Symbol.iterator] semantics.  This recognizer cannot prove
    # the iterator path immutable, so loop-bound computed imports fail closed.
    return None


def _parse_literal_helper_call(source_text: str, name_start: int, name_end: int) -> tuple[str, int] | None:
    if _previous_non_trivia_character(source_text, name_start) in {".", "?"}:
        return None
    open_index = _skip_js_trivia(source_text, name_end)
    if open_index >= len(source_text) or source_text[open_index] != "(":
        return None
    argument_index = _skip_js_trivia(source_text, open_index + 1)
    parsed = _parse_quoted_specifier(source_text, argument_index)
    if parsed is None:
        return None
    specifier, end_index = parsed
    close_index = _skip_js_trivia(source_text, end_index)
    if close_index >= len(source_text) or source_text[close_index] != ")":
        return None
    return specifier, close_index + 1


def _js_with_block_ranges(source_text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    tokens = _source_tokens(source_text)
    for index, (kind, value, _start, _end) in enumerate(tokens):
        if kind != "identifier" or value != "with":
            continue
        cursor = index + 1
        while cursor < len(tokens) and tokens[cursor][0] == "comment":
            cursor += 1
        if (
            cursor >= len(tokens)
            or tokens[cursor][0] != "punctuation"
            or tokens[cursor][1] != "("
        ):
            continue
        condition_end = _matching_js_delimiter_end(source_text, tokens[cursor][2], "(", ")")
        if condition_end is None:
            continue
        body_index = _skip_js_trivia(source_text, condition_end)
        if body_index >= len(source_text) or source_text[body_index] != "{":
            ranges.append((body_index, _js_statement_end(source_text, body_index)))
            continue
        body_end = _matching_js_delimiter_end(source_text, body_index, "{", "}")
        if body_end is not None:
            ranges.append((body_index, body_end))
    return ranges


def _index_in_ranges(index: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < index < end for start, end in ranges)


def _helper_parameter_is_only_dynamic_import_argument(
    source_text: str, argument: str, body_start: int, body_end: int
) -> bool:
    tokens = [
        token
        for token in _source_tokens(source_text)
        if token[0] != "comment" and body_start < token[2] and token[3] < body_end
    ]
    dynamic_import_arguments: set[tuple[int, int]] = set()
    for index, (kind, value, _start, _end) in enumerate(tokens):
        if kind == "identifier" and value == "with":
            return False
        if kind != "identifier" or value != "import":
            continue
        if index + 3 >= len(tokens):
            continue
        open_token = tokens[index + 1]
        argument_token = tokens[index + 2]
        close_token = tokens[index + 3]
        if (
            open_token[0] == "punctuation"
            and open_token[1] == "("
            and argument_token[0] == "identifier"
            and argument_token[1] == argument
            and close_token[0] == "punctuation"
            and close_token[1] == ")"
        ):
            dynamic_import_arguments.add((argument_token[2], argument_token[3]))
    if not dynamic_import_arguments:
        return False
    for kind, value, start, end in tokens:
        if kind == "identifier" and value == argument and (start, end) not in dynamic_import_arguments:
            return False
    return True


def _enclosing_js_block_end(source_text: str, index: int) -> int:
    block_stack: list[int] = []
    for kind, value, start, _end in _source_tokens(source_text):
        if start >= index:
            break
        if kind != "punctuation":
            continue
        if value == "{":
            block_stack.append(start)
        elif value == "}" and block_stack:
            block_stack.pop()
    if not block_stack:
        return len(source_text)
    end = _matching_js_delimiter_end(source_text, block_stack[-1], "{", "}")
    return len(source_text) if end is None else end


def _js_statement_end(source_text: str, statement_start: int) -> int:
    statement_start = _skip_js_trivia(source_text, statement_start)
    if statement_start >= len(source_text):
        return len(source_text)
    if source_text[statement_start] == "{":
        block_end = _matching_js_delimiter_end(source_text, statement_start, "{", "}")
        return len(source_text) if block_end is None else block_end
    depth = 0
    for kind, value, start, end in _source_tokens(source_text):
        if start < statement_start or kind != "punctuation":
            continue
        if value in {"(", "[", "{"}:
            depth += 1
            continue
        if value in {")", "]", "}"}:
            if depth == 0:
                return start
            depth -= 1
            if value == "}" and depth == 0:
                return end
            continue
        if value == ";" and depth == 0:
            return end
    return len(source_text)


def _for_initializer_lexical_scope_end(source_text: str, index: int) -> int | None:
    tokens = _source_tokens(source_text)
    for token_index, (kind, value, _start, _end) in enumerate(tokens):
        if kind != "identifier" or value != "for":
            continue
        cursor = token_index + 1
        while cursor < len(tokens) and tokens[cursor][0] == "comment":
            cursor += 1
        if (
            cursor >= len(tokens)
            or tokens[cursor][0] != "punctuation"
            or tokens[cursor][1] != "("
        ):
            continue
        header_start = tokens[cursor][2]
        header_end = _matching_js_delimiter_end(source_text, header_start, "(", ")")
        if header_end is None or not (header_start < index < header_end):
            continue
        body_start = _skip_js_trivia(source_text, header_end)
        return _js_statement_end(source_text, body_start)
    return None


def _literal_forwarded_dynamic_import_specifiers(
    source_text: str, argument: str, call_index: int
) -> list[str] | None:
    helper = re.compile(
        rf"\bconst\s+(?P<name>{JS_IDENTIFIER})\s*=\s*async\s*"
        rf"\(\s*{re.escape(argument)}\s*\)\s*=>\s*\{{",
        re.DOTALL,
    )
    for match in _executable_pattern_matches(source_text, helper):
        body_start = match.end() - 1
        body_end = _matching_js_delimiter_end(source_text, body_start, "{", "}")
        if body_end is None or not (body_start < call_index < body_end):
            continue
        if not _helper_parameter_is_only_dynamic_import_argument(
            source_text, argument, body_start, body_end
        ):
            continue
        scope_end = _for_initializer_lexical_scope_end(
            source_text, match.start()
        ) or _enclosing_js_block_end(source_text, match.start())
        name = match.group("name")
        name_start, name_end = match.span("name")
        with_ranges = _js_with_block_ranges(source_text)
        values: list[str] = []
        for kind, value, start, end in _source_tokens(source_text):
            if kind != "identifier" or value != name:
                continue
            if start == name_start and end == name_end:
                continue
            if body_start < start < body_end:
                return None
            if not (body_end <= start < scope_end):
                continue
            if _index_in_ranges(start, with_ranges):
                return None
            parsed_call = _parse_literal_helper_call(source_text, start, end)
            if parsed_call is None:
                return None
            values.append(parsed_call[0])
        if values:
            return values
    return None


def _literal_bound_dynamic_import_specifiers(
    source_text: str, argument_index: int, call_index: int
) -> tuple[list[str], int] | None:
    parsed_argument = _parse_dynamic_import_identifier_argument(source_text, argument_index)
    if parsed_argument is None:
        return None
    argument, close_index = parsed_argument
    specifiers = _literal_for_of_dynamic_import_specifiers(
        source_text, argument, call_index
    )
    if specifiers is None:
        specifiers = _literal_forwarded_dynamic_import_specifiers(
            source_text, argument, call_index
        )
    if specifiers is None:
        return None
    return specifiers, close_index


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
                literal_bound = _literal_bound_dynamic_import_specifiers(
                    source_text, argument_index, index
                )
                if literal_bound is None:
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported dynamic import"
                    )
                literal_specifiers, close_index = literal_bound
                specifiers.extend(literal_specifiers)
                index = close_index + 1
                continue
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


def _validate_execution_entrypoint_tail(source_text: str, start: int, end: int) -> None:
    """Do not accept a matched literal prefix followed by executable options.

    Explicit env/execArgv/execPath/cwd, shell mode, eval mode, spread arguments,
    and computed suffixes can change which code runs.  Supported calls use only
    the bound entrypoint and (for child processes) an optional literal argv list.
    """
    prefix = source_text[start:end]
    is_worker = prefix.lstrip().startswith("new ")
    is_node_argv = "process.execPath" in prefix
    description = "Worker entrypoint" if is_worker else "child-process Node entrypoint"

    def fail() -> None:
        raise RuntimeSourceContractError(f"runtime source contains an unsupported {description} argument or option")

    def literal_array(index: int, *, first_consumed: bool = False) -> int:
        index = _skip_js_trivia(source_text, index)
        if not first_consumed:
            if source_text[index:index + 1] != "[":
                fail()
            index = _skip_js_trivia(source_text, index + 1)
        elif source_text[index:index + 1] == ",":
            index = _skip_js_trivia(source_text, index + 1)
        elif source_text[index:index + 1] != "]":
            fail()
        while source_text[index:index + 1] != "]":
            literal = _parse_quoted_specifier(source_text, index)
            if literal is None:
                fail()
            index = _skip_js_trivia(source_text, literal[1])
            if source_text[index:index + 1] == ",":
                index = _skip_js_trivia(source_text, index + 1)
            elif source_text[index:index + 1] != "]":
                fail()
        return _skip_js_trivia(source_text, index + 1)

    index = _skip_js_trivia(source_text, end)
    if is_node_argv:
        index = literal_array(index, first_consumed=True)
    elif not is_worker and source_text[index:index + 1] == ",":
        next_index = _skip_js_trivia(source_text, index + 1)
        if source_text[next_index:next_index + 1] == "[":
            index = literal_array(next_index)
    if source_text[index:index + 1] == ",":
        index = _skip_js_trivia(source_text, index + 1)
    if source_text[index:index + 1] != ")":
        fail()


def _runtime_execution_entrypoint_specifiers(
    source_text: str,
    *,
    loaded_execution_modules: list[str],
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
        specifiers.append((specifier, "import"))
        accepted_spans.append(match.span())
    for match in _executable_pattern_matches(source_text, FORK_ENTRYPOINT_SPECIFIER):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source fork entrypoint contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, "fork"))
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
            specifiers.append((specifier, "fork"))
            accepted_spans.append(match.span())
    for match in _executable_pattern_matches(source_text, CHILD_PROCESS_NODE_ENTRYPOINT_SPECIFIER):
        specifier = match.group("specifier")
        if "\\" in specifier:
            raise RuntimeSourceContractError(
                "runtime source child-process entrypoint contains an unsupported JavaScript escape"
            )
        specifiers.append((specifier, "spawn"))
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
            specifiers.append((specifier, "spawn"))
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
    # A direct child-process call can appear as another expression's argument.
    # Grouped/transferred callables remain rejected by the capability audit.
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

    if _executable_pattern_matches(source_text, _child_process_sync_shell_call_pattern(child_process_sync_alias_names)) or _executable_pattern_matches(source_text, _child_process_indirect_shell_call_pattern(child_process_sync_alias_names)):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported shell child-process entrypoint"
        )
    indirect_fork_pattern = _child_process_indirect_fork_entrypoint_pattern(
        child_process_fork_alias_names
    )
    if indirect_fork_pattern is not None and _executable_pattern_matches(source_text, indirect_fork_pattern):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect child-process fork entrypoint"
        )

    for constructor_name in sorted(worker_constructor_names, key=len, reverse=True):
        for match in _executable_pattern_matches(source_text, re.compile(f'\\bnew\\s+{re.escape(constructor_name)}\\s*\\(')):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported Worker entrypoint"
                )
        if _executable_pattern_matches(source_text, re.compile(f'\\bnew\\s*\\(\\s*[^()]*,\\s*{re.escape(constructor_name)}\\s*\\)\\s*\\(')):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported indirect Worker entrypoint"
            )
    for namespace_name in sorted(worker_namespace_names, key=len, reverse=True):
        for pattern in (
            rf"\bnew\s+{re.escape(namespace_name)}\s*(?:\.|\?\.)\s*Worker\s*\(",
            rf"\bnew\s+{re.escape(namespace_name)}\s*(?:\.|\?\.)?\s*\[\s*['\"]Worker['\"]\s*\]\s*\(",
        ):
            for match in _executable_pattern_matches(source_text, re.compile(pattern)):
                if not any(start <= match.start() < end for start, end in accepted_spans):
                    raise RuntimeSourceContractError(
                        "runtime source contains an unsupported Worker entrypoint"
                    )
    for match in _executable_pattern_matches(source_text, re.compile('\\bnew\\s+Worker\\s*\\(')):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported Worker entrypoint"
            )
    for match in _executable_pattern_matches(source_text, re.compile('(?<![\\w$])(?:fork|child_process\\.fork)\\s*\\(')):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported fork entrypoint"
            )
    if child_process_fork_alias_names:
        fork_alias_alternatives = "|".join(
            re.escape(name)
            for name in sorted(child_process_fork_alias_names, key=len, reverse=True)
        )
        for match in _executable_pattern_matches(source_text, re.compile(f'(?<![\\w$.])(?:{fork_alias_alternatives})\\s*\\(')):
            if not any(start <= match.start() < end for start, end in accepted_spans):
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported fork entrypoint"
                )
    for match in _executable_pattern_matches(source_text, re.compile('(?<![\\w$])(?:spawn|spawnSync|execFile|execFileSync|child_process\\.(?:spawn|spawnSync|execFile|execFileSync)|[A-Za-z_$][0-9A-Za-z_$]*\\s*\\.\\s*(?:spawn|spawnSync|execFile|execFileSync))\\s*\\(\\s*process\\.execPath\\s*,')):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    for match in _executable_pattern_matches(source_text, re.compile(f"""(?<![\\w$])(?:child_process|{JS_IDENTIFIER})\\s*(?:\\?\\.)?\\s*\\[\\s*['\\"](?:spawn|spawnSync|execFile|execFileSync)['\\"]\\s*\\]\\s*\\(\\s*process\\.execPath\\s*,""", re.DOTALL)):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    if _executable_pattern_matches(source_text, re.compile(f"""(?<![\\w$])(?:child_process|{JS_IDENTIFIER})\\s*(?:\\?\\.)?\\s*\\[\\s*['\\"](?:exec|execSync)['\\"]\\s*\\]\\s*\\(""", re.DOTALL)):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported shell child-process entrypoint"
        )
    child_process_alias_process_execpath_pattern = _child_process_alias_node_entrypoint_pattern(
        child_process_node_alias_names,
        require_literal_script_argument=False,
    )
    if child_process_alias_process_execpath_pattern is not None:
        for match in _executable_pattern_matches(source_text, child_process_alias_process_execpath_pattern):
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
        and _executable_pattern_matches(source_text, child_process_callable_indirect_alias_pattern)
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
        and _executable_pattern_matches(source_text, child_process_callable_indirect_shell_pattern)
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
        and _executable_pattern_matches(source_text, child_process_callable_indirect_fork_pattern)
    ):
        raise RuntimeSourceContractError(
            "runtime source contains an unsupported indirect child-process fork entrypoint"
        )
    for match in _executable_pattern_matches(source_text, _child_process_indirect_namespace_node_entrypoint_pattern()):
        if not any(start <= match.start() < end for start, end in accepted_spans):
            raise RuntimeSourceContractError(
                "runtime source contains an unsupported child-process Node entrypoint"
            )
    for start, end in accepted_spans:
        _validate_execution_entrypoint_tail(source_text, start, end)
    _reject_execution_capability_escapes(
        source_text,
        accepted_spans=accepted_spans,
        loaded_execution_modules=loaded_execution_modules,
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
    source_text = strip_source_comments(source_text)
    specifiers: list[str] = []
    index = 0
    while index < len(source_text):
        character = source_text[index]
        if character == "`":
            _chunks, index = _template_expression_chunks(source_text, index)
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            while index < len(source_text):
                if source_text[index] == "\\" and index + 1 < len(source_text):
                    index += 2
                    continue
                if source_text[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                raise RuntimeSourceContractError(
                    "runtime source contains an unterminated JavaScript string"
                )
            continue
        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
        if regex_end is not None:
            index = regex_end
            continue
        match = STATIC_RUNTIME_IMPORT_SPECIFIER.match(source_text, index)
        if match is not None:
            specifiers.append(match.group("specifier"))
            index = match.end()
            continue
        index += 1
    return specifiers


def _reject_module_metadata_mutations(source_text: str) -> None:
    """Do not let writes to a CommonJS module redirect later literal requires."""
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, token in enumerate(tokens):
        if token[1] in {"(", "[", "{", "${"}:
            stack.append(index)
        elif token[1] in {")", "]", "}"} and stack:
            opening = stack.pop()
            pairs[index] = opening
            pairs[opening] = index
    protected: list[tuple[int, int]] = []
    for index, (kind, value, start, _end) in enumerate(tokens):
        if (kind, value) not in {("identifier", "module"), ("punctuation", "(")}:
            continue
        end = _parse_grouped_named_base(source_text, start, "module")
        if end is None:
            continue
        member = _parse_process_member(source_text, end)
        if member is None or member[0] not in {"filename", "id", "path", "loaded", "isPreloading"}:
            continue
        last = index
        while last + 1 < len(tokens) and tokens[last + 1][3] <= member[1]:
            last += 1
        protected.append((index, last))
    if not protected:
        return

    def target_start(end: int) -> int:
        if end < 0:
            return 0
        start = pairs.get(end, end) if tokens[end][1] in {")", "]", "}"} else end
        while start > 0:
            if tokens[start - 1][1] in {".", "?."} and start > 1:
                start = target_start(start - 2)
            elif tokens[start][1] in {"(", "["} and (
                tokens[start - 1][0] == "identifier" or tokens[start - 1][1] in {")", "]"}
            ) and tokens[start - 1][1] not in {"for", "in", "of", "return", "throw", "delete", "typeof", "void"}:
                start = target_start(start - 1)
            else:
                break
        return start

    def check_target(left: int, right: int) -> None:
        for start, end in protected:
            if not left <= start <= end <= right:
                continue
            readonly = False
            for opening, closing in pairs.items():
                if not left <= opening < start <= end < closing <= right:
                    continue
                preceding = tokens[opening - 1] if opening else ("", "", 0, 0)
                if tokens[opening][1] in {"(", "["} and (
                    preceding[0] == "identifier" or preceding[1] in {")", "]"}
                ) and preceding[1] not in {"for", "in", "of", "return", "throw", "delete", "typeof", "void"}:
                    readonly = True
                if tokens[opening][1] == "[" and closing + 1 < len(tokens) and tokens[closing + 1][1] == ":":
                    readonly = True
            cursor = start - 1
            while cursor >= left and tokens[cursor][1] not in {",", ":", "{", "[", "("}:
                if tokens[cursor][1] == "=":
                    readonly = True
                cursor -= 1
            if not readonly:
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported CommonJS module metadata mutation"
                )

    operators = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="}
    index = 0
    while index < len(tokens):
        kind, value, start, end = tokens[index]
        if kind == "punctuation" and set(value) <= set("=+-*/%<>!&|^?*"):
            cursor = index + 1
            while (
                cursor < len(tokens)
                and tokens[cursor][0] == "punctuation"
                and tokens[cursor][2] == end
                and set(tokens[cursor][1]) <= set("=+-*/%<>!&|^?*")
            ):
                end = tokens[cursor][3]
                cursor += 1
            operator = source_text[start:end]
            if operator in operators:
                check_target(target_start(index - 1), index - 1)
            if operator in {"++", "--"}:
                check_target(target_start(index - 1), index - 1)
                for pstart, pend in protected:
                    if index < pstart and all(t[1] == "(" for t in tokens[cursor:pstart]):
                        check_target(pstart, pend)
            index = cursor
            continue
        if kind == "identifier" and value == "delete":
            for pstart, pend in protected:
                if index < pstart and all(t[1] == "(" for t in tokens[index + 1:pstart]):
                    check_target(pstart, pend)
        if kind == "identifier" and value in {"in", "of"}:
            for opening, closing in pairs.items():
                if (
                    opening < index < closing
                    and tokens[opening][1] == "("
                    and opening
                    and tokens[opening - 1][1] in {"for", "await"}
                ):
                    if not any(t[1] == ";" for t in tokens[opening + 1:closing]):
                        check_target(target_start(index - 1), index - 1)
        index += 1


def _runtime_resolution_base_audit(source_text: str) -> tuple[bool, bool]:
    """Account for the identities assumed by literal loader-base recognition."""
    source_text = _source_scan_view(source_text)
    tokens = [token for token in _source_tokens(source_text) if token[0] != "comment"]
    allowed_bases: list[tuple[int, int]] = []
    url_declarations: list[tuple[int, int]] = []
    url_names = {"URL"}
    url_origin_risk = False
    recognized_url_requires = 0
    required_filename = False
    required_meta = False

    def text(index: int) -> str:
        return tokens[index][1] if 0 <= index < len(tokens) else ""

    def literal(index: int) -> str | None:
        if not 0 <= index < len(tokens) or tokens[index][0] != "string":
            return None
        parsed = _parse_quoted_specifier(source_text, tokens[index][2])
        return parsed[0] if parsed is not None else None

    def clause(start: int, end: int, *, commonjs: bool) -> bool:
        index = start
        if not commonjs and text(index) == "type" and index + 1 < end and text(index + 1) != ",":
            return True
        if index < end and tokens[index][0] == "identifier":
            url_names.add(text(index))
            index += 1
            if text(index) == ",":
                index += 1
        if index == end:
            return True
        if not commonjs and text(index) == "*" and text(index + 1) == "as" and index + 3 == end:
            url_names.add(text(index + 2))
            return True
        if text(index) != "{" or text(end - 1) != "}":
            return False
        index += 1
        while index < end - 1:
            if text(index) == ",":
                index += 1
                continue
            type_only = not commonjs and text(index) == "type" and text(index + 1) not in {",", "}", "as"}
            if type_only:
                index += 1
            if tokens[index][0] not in {"identifier", "string"}:
                return False
            imported = literal(index) if tokens[index][0] == "string" else text(index)
            local = imported
            index += 1
            if text(index) == (":" if commonjs else "as"):
                index += 1
                if index >= end - 1 or tokens[index][0] != "identifier":
                    return False
                local = text(index)
                index += 1
            if index < end - 1 and text(index) != ",":
                return False
            if not type_only and imported in {"URL", "default", "pathToFileURL"} and local is not None:
                url_names.add(local)
        return True

    for index, (kind, value, start, _end) in enumerate(tokens):
        if kind != "identifier" or value not in {"import", "export"} or text(index + 1) in {"(", "."}:
            continue
        cursor = index + 1
        while cursor < len(tokens) and text(cursor) != ";":
            if text(cursor) == "from" and literal(cursor + 1) is not None:
                if literal(cursor + 1) in {"url", "node:url"}:
                    if value != "import" or not clause(index + 1, cursor, commonjs=False):
                        url_origin_risk = True
                    else:
                        url_declarations.append((start, tokens[cursor + 1][3]))
                break
            if cursor > index + 1 and text(cursor) in {"import", "export"}:
                break
            cursor += 1

    for index, (kind, value, _start, _end) in enumerate(tokens):
        if kind != "identifier" or value != "require" or text(index + 1) != "(":
            continue
        if literal(index + 2) not in {"url", "node:url"} or text(index + 3) != ")" or text(index - 1) != "=":
            continue
        lhs = index - 2
        if text(lhs) == "}":
            while lhs >= 0 and text(lhs) != "{":
                lhs -= 1
        if lhs >= 1 and text(lhs - 1) in {"const", "let", "var"} and clause(lhs, index - 1, commonjs=True):
            recognized_url_requires += 1
            url_declarations.append((tokens[lhs - 1][2], tokens[index - 1][3]))
    url_loads = sum(
        specifier in {"url", "node:url"}
        for specifier in (
            _commonjs_require_specifiers(source_text)
            + _create_require_specifiers(source_text)
            + _dynamic_import_specifiers(source_text)
        )
    )
    url_origin_risk |= url_loads != recognized_url_requires

    factories = _create_require_factory_names(source_text)
    for index, (kind, value, _start, end) in enumerate(tokens):
        if kind != "identifier" or value not in factories:
            continue
        opening = _skip_js_trivia(source_text, end)
        if source_text[opening:opening + 1] != "(":
            continue
        base_end = _create_require_base_end(source_text, opening)
        if base_end is None:
            continue
        allowed_bases.append((opening, base_end))
        if text(index + 2) == "__filename":
            required_filename = True
        else:
            required_meta = True

    constructors, namespaces = _worker_thread_bindings(source_text)
    worker_matches = _executable_pattern_matches(source_text, _worker_constructor_pattern(constructors, namespaces))
    allowed_bases.extend(match.span() for match in worker_matches)
    requires_url = bool(worker_matches)
    required_meta |= requires_url

    safe_meta_members = {
        "Object": {
            "create", "entries", "freeze", "fromEntries", "hasOwn", "is",
            "isExtensible", "isFrozen", "isSealed", "keys",
            "preventExtensions", "seal", "values",
        },
        "Reflect": {"has", "isExtensible", "preventExtensions"},
    }
    for index, (kind, value, start, end) in enumerate(tokens):
        if kind != "identifier":
            continue
        spread = index >= 3 and all(text(item) == "." for item in range(index - 3, index))
        member_reference = index > 0 and text(index - 1) in {".", "?."} and not spread
        if value in safe_meta_members and not member_reference:
            try:
                member = _parse_process_member(source_text, end)
            except RuntimeSourceContractError:
                member = None
            if member is None or member[0] not in safe_meta_members[value]:
                url_origin_risk = True
        allowed = any(left <= start < right for left, right in allowed_bases)
        if required_filename and value == "__filename" and not allowed:
            raise RuntimeSourceContractError("runtime source contains an unbound createRequire filename base")
        if required_meta and value == "import" and text(index + 1) == "." and text(index + 2) == "meta" and not allowed:
            raise RuntimeSourceContractError("runtime source contains an unbound import.meta loader base")
        if value not in url_names:
            continue
        if member_reference:
            continue
        if allowed or any(left <= start < right for left, right in url_declarations):
            continue
        url_origin_risk = True
    if requires_url and url_origin_risk:
        raise RuntimeSourceContractError("runtime source contains an unbound Worker URL constructor")
    return requires_url, url_origin_risk


def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:
    source_text = _source_scan_view(source_text)
    _reject_evaluated_runtime_loaders(source_text)
    commonjs_specifiers = _commonjs_require_specifiers(source_text)
    create_require_specifiers = _create_require_specifiers(source_text)
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
    if any(specifier in {"worker_threads", "node:worker_threads"} for specifier in dynamic_specifiers):
        raise RuntimeSourceContractError("runtime source contains an unsupported dynamic Worker entrypoint namespace")
    _reject_unaccounted_require_references(source_text)
    _reject_commonjs_module_graph_capabilities(source_text)
    execution_entrypoints = _runtime_execution_entrypoint_specifiers(
        source_text,
        loaded_execution_modules=[
            specifier for specifier in commonjs_specifiers + create_require_specifiers
            if specifier.removeprefix("node:") in {"worker_threads", "child_process", "module"}
        ],
    )
    _reject_unaccounted_create_require_references(source_text)
    _reject_module_metadata_mutations(source_text)
    _runtime_resolution_base_audit(source_text)
    module_register_hooks = _module_register_hook_specifiers(source_text)
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
    def reject_non_json_constant(value: str) -> None:
        raise ValueError(f"non-JSON constant: {value}")

    try:
        payload = json.loads(
            package_json.read_text(encoding="utf-8"),
            parse_constant=reject_non_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
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


def _validate_package_map_target(target: str, label: str) -> None:
    if "%" in target:
        raise RuntimeSourceContractError(
            f"runtime package {label} target contains an unsupported percent-encoded path"
        )
    if "?" in target or "#" in target:
        raise RuntimeSourceContractError(
            f"runtime package {label} target contains an unsupported URL suffix"
        )
    if not target.startswith("./"):
        raise RuntimeSourceContractError(
            f"runtime package {label} target is unsupported"
        )
    segments = target[2:].split("/")
    if any(segment in {"", ".", "..", "node_modules"} for segment in segments):
        raise RuntimeSourceContractError(
            f"runtime package {label} target contains an unsupported path segment"
        )


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
        for target in targets:
            _validate_package_map_target(target, "export")
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
        if current.name != "node_modules":
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


def _nearest_controlling_package_scope(
    root: Path, importer: Path
) -> tuple[Path, dict[str, Any]] | None:
    """Read the first scope, even when it has no imports/name/exports fields."""
    root = root.resolve()
    current = importer.resolve().parent
    while current.is_relative_to(root) and current.name != "node_modules":
        manifest = current / "package.json"
        try:
            present = manifest.is_symlink() or manifest.exists()
            if present:
                target = manifest.resolve(strict=True)
                source_relative_path(root, target)
                if not target.is_file():
                    raise RuntimeSourceContractError(
                        "runtime package scope metadata is not a regular file"
                    )
                return current, _load_package_json(manifest, "package scope")
        except RuntimeSourceContractError:
            raise
        except (OSError, RuntimeError) as exc:
            raise RuntimeSourceContractError(
                "runtime package scope metadata is unavailable"
            ) from exc
        if current == root:
            break
        current = current.parent
    return None


def _nearest_package_self_reference(
    root: Path, importer: Path, package_name: str
) -> tuple[Path, dict[str, Any]] | None:
    scope = _nearest_controlling_package_scope(root, importer)
    if scope is not None:
        _directory, payload = scope
        if payload.get("name") == package_name and payload.get("exports") is not None:
            return scope
    return None


def _nearest_package_imports_scope(
    root: Path, importer: Path
) -> tuple[Path, dict[str, Any]] | None:
    scope = _nearest_controlling_package_scope(root, importer)
    if scope is not None and scope[1].get("imports") is not None:
        return scope
    return None


def _resolve_package_import(
    *,
    root: Path,
    importer: Path,
    specifier: str,
    required: bool,
    import_kind: str,
    node_resolution: bool = False,
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
        _validate_package_map_target(target, "import")
        base = (package_root / target).resolve()
        resolved = _resolve_existing_candidate(
            root,
            base,
            node_resolution=node_resolution,
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
            resolved = _resolve_existing_candidate(root, base, node_resolution=node_resolution)
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
    node_resolution: bool = False,
) -> Path | None:
    if node_resolution:
        suffixes = NODE_LEGACY_PACKAGE_RESOLUTION_SUFFIXES
        suffix_aliases = {}
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
    node_resolution: bool = False,
) -> tuple[Path, ...]:
    root = root.resolve()
    if import_kind in {"fork", "spawn"}:
        # The probe launches with cwd=root.  Node CLI/fork paths are not module
        # specifiers and do not resolve relative to the JavaScript caller.
        if not specifier or specifier.startswith("-"):
            raise RuntimeSourceContractError("runtime process entrypoint is not a literal script path")
        path = (root / specifier).resolve()
        source_relative_path(root, path)
        if not path.is_file() or path.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:
            raise RuntimeSourceContractError("runtime process entrypoint could not be resolved to an in-root script")
        return (path,)
    if specifier.startswith("#"):
        return _resolve_package_import(
            root=root,
            importer=importer,
            specifier=specifier,
            required=required,
            import_kind=import_kind,
            node_resolution=node_resolution,
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
            node_resolution=node_resolution,
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
            resolved = _resolve_existing_candidate(root, base, node_resolution=node_resolution)
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
                    node_resolution=node_resolution,
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
                resolved = _resolve_existing_candidate(root, base, node_resolution=node_resolution)
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
                    node_resolution=node_resolution,
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
                resolved = _resolve_existing_candidate(root, base, node_resolution=node_resolution)
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


def _uses_ambient_child_launch_state(source_text: str) -> bool:
    """Detect launch-state handles that can change child process source closure."""
    code = _source_scan_view(source_text)
    tokens = _source_tokens(code)
    for kind, value, start, _end in tokens:
        if kind != "identifier" and value != "(":
            continue
        base_end = _parse_process_base(code, start)
        if base_end is None:
            continue
        member = _parse_process_member(code, base_end)
        if member is None:
            continue
        name, member_end = member
        if name in {"chdir", "env", "execArgv", "loadEnvFile"}:
            return True
        if name == "execPath":
            before = _previous_non_trivia_character(code, start)
            after = _skip_js_trivia(code, member_end)
            if before != "(" or after >= len(code) or code[after] != ",":
                return True
    return False


def runtime_source_paths(root: Path) -> tuple[str, ...]:
    root = root.resolve()
    queue: list[tuple[Path, bool]] = []
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
        queue.append((path, False))

    seen: set[tuple[str, bool]] = set()
    child_launch = False
    ambient_launch_state = False
    requires_url = False
    url_origin_risk = False
    while queue:
        source_path, node_resolution = queue.pop(0)
        source_path = source_path.resolve()
        relative = source_relative_path(root, source_path)
        if (relative, node_resolution) in seen:
            continue
        seen.add((relative, node_resolution))
        if source_path.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:
            continue
        _nearest_controlling_package_scope(root, source_path)
        # File contents alone do not determine Node's interpretation.  Bind the
        # enclosing package scopes for every source, including direct relative
        # imports and the initial entrypoints (not only bare package imports).
        # Keep all in-root ancestors: this conservative superset also notices a
        # newly added, removed, or retargeted nearer scope during revalidation.
        for directory in (source_path.parent, *source_path.parent.parents):
            if not directory.is_relative_to(root):
                break
            manifest = directory / "package.json"
            if manifest.is_file():
                source_relative_path(root, manifest)  # Reject escaping symlinks.
                queue.append((manifest, node_resolution))
            if directory == root:
                break
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
        specifiers = import_specifiers(source_text)
        ambient_launch_state |= _uses_ambient_child_launch_state(source_text)
        source_requires_url, source_url_risk = _runtime_resolution_base_audit(source_text)
        requires_url |= source_requires_url
        url_origin_risk |= source_url_risk
        for specifier, required, import_kind in specifiers:
            child_launch |= import_kind in {"fork", "spawn"}
            child_node_resolution = node_resolution or import_kind == "spawn"
            for imported in resolve_import(
                root=root,
                importer=source_path,
                specifier=specifier,
                required=required,
                import_kind=import_kind,
                node_resolution=child_node_resolution,
            ):
                imported_relative = source_relative_path(root, imported)
                if (imported_relative, child_node_resolution) not in seen:
                    queue.append((imported, child_node_resolution))
    if child_launch and ambient_launch_state:
        raise RuntimeSourceContractError(
            "runtime child-process closure contains unbound ambient launch state"
        )
    if requires_url and url_origin_risk:
        raise RuntimeSourceContractError("runtime source closure contains an unbound Worker URL constructor")
    if not seen:
        raise RuntimeSourceContractError("persistent runtime source closure is empty")
    return tuple(sorted({relative for relative, _mode in seen}))


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
