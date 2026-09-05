from __future__ import annotations

import ast
from pathlib import Path


def _javascript_lexical_view(source_text: str) -> tuple[str, list[tuple[str, int, int]]]:
    """Mask trivia once, preserving offsets and executable template expressions.

    HTML-like comments depend on the Script/Module parser goal. Reject them in
    executable code instead of guessing; quoted/regex/template text stays inert.
    """
    masked = list(source_text)
    tokens: list[tuple[str, int, int]] = []

    def mask(start: int, end: int) -> None:
        for cursor in range(start, end):
            if not _is_js_line_terminator(source_text[cursor]):
                masked[cursor] = " "

    def code(index: int, *, interpolation: bool = False, nesting: int = 0) -> int:
        if nesting > 128:
            raise RuntimeSourceContractError("runtime source nesting exceeds lexical limit")
        braces = 0
        delimiters: list[str] = []
        while index < len(source_text):
            start = index
            character = source_text[index]
            if character.isspace():
                index += 1
                continue
            if source_text.startswith("#!", index):
                if index != 0:
                    raise RuntimeSourceContractError("runtime source has a misplaced hashbang")
                while index < len(source_text) and not _is_js_line_terminator(source_text[index]):
                    index += 1
                mask(start, index)
                continue
            if source_text.startswith("<!--", index) or source_text.startswith("-->", index):
                raise RuntimeSourceContractError("runtime source contains unsupported HTML-like comment syntax")
            if source_text.startswith("//", index):
                while index < len(source_text) and not _is_js_line_terminator(source_text[index]):
                    index += 1
                mask(start, index)
                continue
            if source_text.startswith("/*", index):
                close = source_text.find("*/", index + 2)
                if close == -1:
                    raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript comment")
                index = close + 2
                mask(start, index)
                continue
            if character in {"'", '"'}:
                index = _quoted_literal_end(source_text, index)
                tokens.append((source_text[start:index], start, index))
                continue
            if character == "/":
                end = _regex_literal_end_or_fail_closed("".join(masked), index)
                if end is not None:
                    tokens.append((source_text[start:end], start, end))
                    index = end
                    continue
            if character == "`":
                tokens.append(("`", index, index + 1))
                index += 1
                while index < len(source_text):
                    if source_text[index] == "\\":
                        index += 2
                    elif source_text[index] == "`":
                        tokens.append(("`", index, index + 1))
                        index += 1
                        break
                    elif source_text.startswith("${", index):
                        tokens.append(("${", index, index + 2))
                        index = code(index + 2, interpolation=True, nesting=nesting + 1)
                    else:
                        index += 1
                else:
                    raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript template literal")
                continue
            if character in "({[":
                delimiters.append(character)
                if len(delimiters) + nesting > 128:
                    raise RuntimeSourceContractError("runtime source nesting exceeds lexical limit")
            elif character in ")}]" and delimiters:
                delimiters.pop()
            if character == "}":
                if interpolation and braces == 0:
                    tokens.append(("}", index, index + 1))
                    return index + 1
                braces -= 1
            elif character == "{":
                braces += 1
            parsed = _parse_js_identifier(source_text, index)
            if parsed is not None:
                name, index = parsed
                masked[start:index] = list(name.ljust(index - start))
                tokens.append((name, start, index))
                continue
            end = index + (2 if source_text.startswith("?.", index) else 1)
            tokens.append((source_text[index:end], index, end))
            index = end
        if interpolation:
            raise RuntimeSourceContractError("runtime source contains an unterminated JavaScript template expression")
        return index

    code(0)
    return "".join(masked), tokens


def strip_source_comments(source_text: str) -> str:
    return _javascript_lexical_view(source_text)[0]


def _parse_grouped_named_base(source_text: str, index: int, base_name: str) -> int | None:
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
    while depth:
        end = _skip_js_trivia(source_text, end)
        if end >= len(source_text) or source_text[end] != ")":
            return None
        end += 1
        depth -= 1
    return end


def _commonjs_require_alias_assignments(source_text: str) -> list[tuple[str, tuple[int, int], tuple[int, int]]]:
    declarations: list[tuple[str, tuple[int, int], tuple[int, int]]] = []
    pattern = re.compile(rf"\b(?:const|let|var)\s+(?P<name>{JS_IDENTIFIER})\s*=\s*")
    source_text, tokens = _javascript_lexical_view(source_text)
    starts = {start for _value, start, _end in tokens}
    for match in pattern.finditer(source_text):
        if match.start() not in starts:
            continue
        end = _parse_grouped_named_base(source_text, match.end(), "require")
        if end is None:
            continue
        tail = _skip_js_trivia(source_text, end)
        if tail < len(source_text) and source_text[tail] not in ";,":
            next_identifier = _parse_js_identifier(source_text, tail)
            has_line_break = any(_is_js_line_terminator(c) for c in source_text[end:tail])
            if not (has_line_break and next_identifier is not None and next_identifier[0] not in {
                "in", "instanceof", "as", "satisfies"
            }):
                continue
        declarations.append((match.group("name"), match.span("name"), (match.end(), end)))
    return declarations


def _commonjs_require_alias_bindings(source_text: str) -> tuple[set[str], set[tuple[int, int]]]:
    declarations = _commonjs_require_alias_assignments(source_text)
    return ({name for name, _lhs, _rhs in declarations}, {lhs for _name, lhs, _rhs in declarations})


def _reject_unbound_loader_references(source_text: str) -> None:
    """Reject capabilities escaping the source scanner's supported grammar.

    Calls alone miss aliases, containers, callbacks, re-exports and factory
    results. Permit only recognized declarations and actually enumerated calls.
    This conservative source contract is not a JavaScript sandbox or a substitute
    for the independent immutable-launcher boundary.
    """
    source_text, tokens = _javascript_lexical_view(source_text)
    starts = {start for _value, start, _end in tokens}
    declarations: list[tuple[int, int]] = []
    roles = {"Worker": "Worker", "module": "CommonJS runtime loader",
             "createRequire": "createRequire", "child_process": "child-process"}
    critical_modules = {"worker_threads": "Worker", "child_process": "child-process",
                        "module": "CommonJS runtime loader"}

    def fail(role: str) -> None:
        raise RuntimeSourceContractError(f"runtime source contains an unsupported {role} capability transfer")

    def literal(token: tuple[str, int, int]) -> str | None:
        if not token[0].startswith(("'", '"')):
            return None
        parsed = _parse_quoted_specifier(source_text, token[1])
        return parsed[0] if parsed is not None else None

    def bind(imported: str, local: str, role: str) -> None:
        if not re.fullmatch(JS_IDENTIFIER, local):
            fail(role)
        sensitive = (
            imported == "*"
            or (role == "Worker" and imported in {"Worker", "default"})
            or (role == "child-process" and imported in (
                CHILD_PROCESS_FORK_ENTRYPOINT_NAMES | CHILD_PROCESS_NODE_ENTRYPOINT_NAMES
                | CHILD_PROCESS_SYNC_SHELL_ENTRYPOINT_NAMES | {"default"}
            ))
            or (role == "CommonJS runtime loader" and imported not in {"builtinModules", "isBuiltin"})
        )
        if sensitive:
            roles[local] = "createRequire" if imported == "createRequire" else role

    def named_bindings(clause: list[tuple[str, int, int]], role: str, separator: str) -> None:
        if not clause or clause[0][0] != "{" or clause[-1][0] != "}":
            fail(role)
        parts: list[list[tuple[str, int, int]]] = [[]]
        for token in clause[1:-1]:
            if token[0] == ",":
                parts.append([])
            else:
                parts[-1].append(token)
        for part in parts:
            if not part:
                continue
            if separator == "as" and len(part) > 1 and part[0][0] == "type" and part[1][0] != "as":
                continue
            imported = literal(part[0]) or part[0][0]
            if len(part) == 1 and re.fullmatch(JS_IDENTIFIER, imported):
                bind(imported, imported, role)
            elif len(part) == 3 and part[1][0] == separator:
                bind(imported, part[2][0], role)
            else:
                fail(role)

    for i, (value, start, _end) in enumerate(tokens):
        if value not in {"import", "export"} or i + 1 == len(tokens):
            continue
        if tokens[i + 1][0] in {"(", ".", "?."}:
            continue
        depth = 0
        source_index: int | None = None
        for j in range(i + 1, len(tokens)):
            item = tokens[j][0]
            if item in {"{", "["}:
                depth += 1
            elif item in {"}", "]"}:
                depth -= 1
            if depth == 0 and item == ";":
                break
            if depth == 0 and item == "from" and j + 1 < len(tokens):
                source_index = j + 1
                break
            if j == i + 1 and item.startswith(("'", '"')):
                source_index = j
                break
        if source_index is None:
            continue
        specifier = literal(tokens[source_index])
        if specifier is None:
            continue
        role = critical_modules.get(specifier.removeprefix("node:"))
        if role is None:
            continue
        if value == "export":
            fail(role)
        declarations.append((start, tokens[source_index][2]))
        clause = tokens[i + 1:source_index - 1] if source_index > i + 1 else []
        if not clause:
            continue
        if len(clause) > 1 and clause[0][0] == "type":
            continue
        if clause[0][0] not in {"*", "{"}:
            bind("default", clause[0][0], role)
            clause = clause[1:]
            if clause:
                if clause[0][0] != ",":
                    fail(role)
                clause = clause[1:]
        if clause and clause[0][0] == "*":
            if len(clause) != 3 or clause[1][0] != "as":
                fail(role)
            bind("*", clause[2][0], role)
        elif clause:
            named_bindings(clause, role, "as")

    aliases = _commonjs_require_alias_assignments(source_text)
    require_names = {"require"} | {name for name, _lhs, _rhs in aliases}
    created_loaders, created_declarations = _create_require_loader_bindings(source_text)
    require_names |= created_loaders
    declarations.extend(created_declarations)
    for _name, lhs, rhs in aliases:
        declarations.extend((lhs, rhs))
    factory_consumptions = [match.span() for match in INLINE_CREATE_REQUIRE_SPECIFIER.finditer(source_text)
                            if match.start() in starts]
    factories = _create_require_factory_names(source_text)
    for match in CREATE_REQUIRE_ASSIGNMENT.finditer(source_text):
        if match.start() not in starts or match.group("factory") not in factories:
            continue
        factory_end = _create_require_base_end(source_text, match.end() - 1)
        if factory_end is not None:
            factory_consumptions.append((match.start(), factory_end))
    require_calls: list[tuple[int, int]] = []
    for i, (value, start, _end) in enumerate(tokens):
        parsed: tuple[str, int] | None = None
        if value == "(":
            parsed = _parse_parenthesized_require_invocation(source_text, start)
        elif value == "require":
            parsed = _parse_property_require_invocation(source_text, start)
            if parsed is None:
                parsed = _parse_require_invocation(source_text, start)
        elif value in require_names:
            if any(a <= start < b for a, b in declarations):
                continue
            parsed = _parse_named_loader_invocation(source_text, start, value)
        if parsed is None:
            continue
        specifier, end = parsed
        require_calls.append((start, end))
        role = critical_modules.get(specifier.removeprefix("node:"))
        if role is None:
            continue
        if value != "require" or i < 2 or tokens[i - 1][0] != "=":
            if role == "CommonJS runtime loader":
                member = _parse_static_runtime_member(source_text, end, dynamic_error="unsupported CommonJS runtime loader")
                if member is not None and member[0] == "createRequire":
                    if any(a <= start < b for a, b in factory_consumptions):
                        continue
            fail(role)
        lhs_end = i - 1
        lhs_start = lhs_end - 1
        if tokens[lhs_start][0] == "}":
            while lhs_start >= 0 and tokens[lhs_start][0] != "{":
                lhs_start -= 1
        if lhs_start <= 0 or tokens[lhs_start - 1][0] not in {"const", "let", "var"}:
            fail(role)
        tail = _skip_js_trivia(source_text, end)
        if tail < len(source_text) and source_text[tail] not in ";,":
            fail(role)
        clause = tokens[lhs_start:lhs_end]
        if len(clause) == 1:
            bind("*", clause[0][0], role)
        else:
            named_bindings(clause, role, ":")
        declarations.append((tokens[lhs_start][1], tokens[lhs_end - 1][2]))
    workers, worker_namespaces = _worker_thread_bindings(source_text)
    forks, children, _shells, _namespaces = _child_process_sync_alias_bindings(source_text)
    patterns = [_worker_constructor_pattern(workers, worker_namespaces),
                FORK_ENTRYPOINT_SPECIFIER, CHILD_PROCESS_NODE_ENTRYPOINT_SPECIFIER,
                _child_process_fork_entrypoint_pattern(forks),
                _child_process_alias_node_entrypoint_pattern(children, require_literal_script_argument=True)]
    calls = [match.span() for pattern in patterns if pattern is not None
             for match in pattern.finditer(source_text) if match.start() in starts]
    for i, (value, start, end) in enumerate(tokens):
        if value not in roles and value not in require_names:
            continue
        if any(a <= start < b for a, b in declarations):
            continue
        if value in require_names:
            if any(a <= start < b for a, b in require_calls):
                continue
            previous = i - 1
            while previous >= 0 and tokens[previous][0] == "(":
                previous -= 1
            if previous >= 0 and tokens[previous][0] == "typeof" and (
                previous == 0 or tokens[previous - 1][0] not in {".", "?."}
            ):
                continue
            fail("CommonJS require")
        if any(a <= start < b for a, b in calls):
            continue
        if value == "module":
            member = _parse_static_runtime_member(source_text, end, dynamic_error="unsupported CommonJS runtime loader")
            if member is not None and member[0] == "exports":
                continue
            if member is not None and member[0] == "require":
                if any(a <= member[1] < b for a, b in require_calls):
                    continue
                if _parse_bracketed_module_require_invocation(source_text, start) is not None:
                    continue
        if roles[value] in {"createRequire", "CommonJS runtime loader"}:
            if any(a <= start < b for a, b in factory_consumptions):
                continue
        fail(roles[value])


def _runtime_package_scope(root: Path, source_path: Path) -> tuple[Path, ...]:
    """Bind the nearest physical package.json; stop at node_modules or root."""
    directory = source_path.parent
    while directory == root or root in directory.parents:
        if directory.name == "node_modules":
            break
        manifest = directory / "package.json"
        if manifest.exists() or manifest.is_symlink():
            try:
                resolved = manifest.resolve()
            except (OSError, RuntimeError) as exc:
                raise RuntimeSourceContractError("runtime package scope path is invalid") from exc
            source_relative_path(root, resolved)
            _load_package_json(resolved, "runtime package scope")
            return (resolved,)
        if directory == root:
            break
        directory = directory.parent
    return ()


def _runtime_preload_package_binding(openclaw_root: Path, package_root: Path, preload: Path) -> dict[str, str]:
    """Bind package assets AND the complete statically supported preload closure.

    A tsx-directory hash omits hoisted/pnpm siblings. Start at the actual --import
    file using the same fail-closed source resolver. Dynamic/evaluated/native and
    out-of-root dependencies are not attestable here. This is not a replacement
    for the independent immutable-launcher boundary.
    """
    root = openclaw_root.resolve()
    try:
        relative = runtime_source_contract.source_relative_path(root, preload)
        closure = runtime_source_contract.runtime_source_digest_snapshot(root, entrypoints=(relative,))
        binding = _runtime_directory_binding(package_root, "runtime-preload-package:tsx")
        payload = {"schema": "agentic-os.runtime-preload-closure.v1",
                   "package_tree_sha256": binding["sha256"], "sources": closure}
        binding["sha256"] = _sha256_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        return binding
    except (runtime_source_contract.RuntimeSourceContractError, OSError, ValueError) as exc:
        raise ProbeError("tsx runtime preload source closure could not be bound") from exc


def apply() -> None:
    own = Path(__file__).read_text(encoding="utf-8")
    definitions = {node.name: ast.get_source_segment(own, node) + "\n\n"
                   for node in ast.parse(own).body if isinstance(node, ast.FunctionDef)}
    target = Path("scripts/agentic_os_runtime_source_contract.py")
    source = target.read_text(encoding="utf-8")
    for first, after, names in (
        ("def strip_source_comments(", "def _is_identifier_character", ("_javascript_lexical_view", "strip_source_comments")),
        ("def _parse_grouped_named_base(", "def _capability_member_end_or_fail", ("_parse_grouped_named_base",)),
        ("def _commonjs_require_alias_bindings(", "def _node_test_runner_bindings", ("_commonjs_require_alias_assignments", "_commonjs_require_alias_bindings")),
    ):
        start = source.index(first)
        end = source.index(after, start)
        source = source[:start] + "".join(definitions[name] for name in names) + source[end:]
    start = source.index("COMMONJS_REQUIRE_ALIAS_ASSIGNMENT = re.compile(")
    end = source.index("INDIRECT_COMMONJS_REQUIRE_INVOCATION", start)
    source = source[:start] + source[end:]
    start = source.index("def import_specifiers(")
    source = source[:start] + definitions["_reject_unbound_loader_references"] + source[start:]
    source = source.replace(
        "def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:\n    _reject",
        "def import_specifiers(source_text: str) -> list[tuple[str, bool, str]]:\n    source_text = strip_source_comments(source_text)\n    _reject",
    )
    source = source.replace(
        '    specifiers.extend((specifier, True, "import") for specifier in module_register_hooks)\n    return specifiers',
        '    specifiers.extend((specifier, True, "import") for specifier in module_register_hooks)\n    _reject_unbound_loader_references(source_text)\n    return specifiers',
    )
    source = source.replace(
        "    if any(specifier in CHILD_PROCESS_SPECIFIERS for specifier in dynamic_specifiers):",
        '    if any(specifier in {"worker_threads", "node:worker_threads"} for specifier in dynamic_specifiers):\n        raise RuntimeSourceContractError("runtime source contains an unsupported dynamic Worker execution capability")\n    if any(specifier in CHILD_PROCESS_SPECIFIERS for specifier in dynamic_specifiers):',
    )
    source = source.replace(
        '''        if character in {"'", '"', "`"}:
            state = "string"
            quote = character
            index += 1
            continue
        if character == "{":''',
        '''        regex_end = _regex_literal_end_or_fail_closed(source_text, index)
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
        if character == "{":''',
    )
    source = source.replace(
        '    for specifier in _native_addon_entrypoint_specifiers(source_text):\n        specifiers.append((specifier, "require"))',
        '    if _native_addon_entrypoint_specifiers(source_text):\n        # A native binary remains unbound even when renamed .cjs or .so.\n        raise RuntimeSourceContractError("runtime source contains an unsupported native add-on")',
    )
    source = source.replace(
        '''            if resolved.suffix == ".node":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on"
                )
            return resolved''',
        '''            if resolved.suffix == ".node":
                raise RuntimeSourceContractError(
                    "runtime source contains an unsupported native add-on"
                )
            if resolved.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES | {".json"}:
                raise RuntimeSourceContractError("runtime source contains an unsupported executable file extension")
            return resolved''',
    )
    start = source.index("def runtime_source_paths(")
    source = source[:start] + definitions["_runtime_package_scope"] + source[start:]
    source = source.replace("def runtime_source_paths(root: Path) -> tuple[str, ...]:", "def runtime_source_paths(\n    root: Path, *, entrypoints: tuple[str, ...] = PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS\n) -> tuple[str, ...]:")
    source = source.replace("    for relative in PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:\n", "    for relative in entrypoints:\n")
    source = source.replace(
        "        if source_path.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:\n            continue\n        try:\n            source_text",
        "        if source_path.suffix not in PERSISTENT_RUNTIME_PARSEABLE_SUFFIXES:\n            continue\n        queue.extend(_runtime_package_scope(root, source_path))\n        try:\n            source_text",
    )
    source = source.replace("def runtime_source_digest_snapshot(root: Path) -> dict[str, str]:", "def runtime_source_digest_snapshot(\n    root: Path, *, entrypoints: tuple[str, ...] = PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS\n) -> dict[str, str]:")
    source = source.replace("    for relative in runtime_source_paths(root):", "    for relative in runtime_source_paths(root, entrypoints=entrypoints):")
    ast.parse(source)
    target.write_text(source, encoding="utf-8")
    target = Path("scripts/openclaw-real-gateway-contract-probe.py")
    source = target.read_text(encoding="utf-8")
    start = source.index("def _runtime_launch_bindings(")
    source = source[:start] + definitions["_runtime_preload_package_binding"] + source[start:]
    source = source.replace(
        '            _runtime_directory_binding(\n                tsx_package_root, "runtime-preload-package:tsx"\n            ),',
        '            _runtime_preload_package_binding(\n                openclaw_root, tsx_package_root, tsx_preload\n            ),',
    )
    ast.parse(source)
    target.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    apply()
