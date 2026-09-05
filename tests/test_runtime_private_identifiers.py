"""PrivateIdentifier lexical boundaries must never erase executable dependencies."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_runtime_source_contract_regressions import CONTRACT

NODE = shutil.which("node")
PRIVATE_NAMES = (
    "return", "default", "extends", "in", "typeof", "delete", "instanceof",
    "new", "throw", "yield", "await", "of", "case", "else", "do", "void",
    "break", "continue", "debugger", "export", "import", "class", "function",
)


def private_source(name: str, *, optional: bool = False, postfix: str = "") -> str:
    member = "?." if optional else "."
    return (
        f"class Box {{ #{name}=4; static run(o){{ "
        f"return o{member}#{name}{postfix} / [require('bound-package')] / 2; "
        "} } Box.run(new Box());"
    )


class RuntimePrivateIdentifierTests(unittest.TestCase):
    def test_private_keyword_division_preserves_dependencies(self) -> None:
        for name in PRIVATE_NAMES + (r"\u0072eturn", r"\u{72}eturn"):
            for optional in (False, True):
                source = private_source(name, optional=optional)
                with self.subTest(name=name, optional=optional):
                    specifiers = CONTRACT.import_specifiers(source)
                    self.assertIn(("bound-package", True, "require"), specifiers)
                    private = [token for token in CONTRACT._source_tokens(source)
                               if token[0] == "private-identifier"]
                    self.assertEqual(len(private), 2)
                    self.assertTrue(all(token[1].startswith("#") for token in private))

    def test_private_keyword_plain_call_is_bound_or_fails_closed(self) -> None:
        # The conservative scanner may reject division after a closing call
        # parenthesis. It must never return success with the load omitted.
        for name in ("return", "default", "extends", "in", "typeof"):
            source = private_source(name).replace("[require('bound-package')]", "require('bound-package')")
            with self.subTest(name=name):
                try:
                    specifiers = CONTRACT.import_specifiers(source)
                except CONTRACT.RuntimeSourceContractError:
                    continue
                self.assertIn(("bound-package", True, "require"), specifiers)

    def test_private_fields_are_not_execution_capability_references(self) -> None:
        for module, name in (("worker_threads", "Worker"), ("child_process", "spawnSync")):
            source = (
                f"import {{{name}}} from 'node:{module}';"
                f"class Box {{ #{name}=4; static read(o){{return o.#{name};}} }}"
            )
            with self.subTest(module=module, name=name):
                self.assertIn((f"node:{module}", True, "import"), CONTRACT.import_specifiers(source))

    def test_typescript_postfix_after_private_field_cannot_hide_require(self) -> None:
        for name in ("return", "value", "await", r"\u0072eturn"):
            for optional in (False, True):
                with self.subTest(name=name, optional=optional):
                    source = private_source(name, optional=optional, postfix="!")
                    try:
                        specifiers = CONTRACT.import_specifiers(source)
                    except CONTRACT.RuntimeSourceContractError:
                        continue
                    self.assertIn(("bound-package", True, "require"), specifiers)

    @unittest.skipUnless(NODE, "requires Node execution witness")
    def test_node_execution_and_full_closure_bind_private_division_loads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-identifier-") as directory:
            root = Path(directory)
            for relative in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"name":"openclaw"}\n' if relative == "package.json" else "export {};\n", encoding="utf-8")
            package = root / "node_modules/bound-package"
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps({"name": "bound-package", "main": "index.cjs"}), encoding="utf-8")
            (package / "index.cjs").write_text("console.log('PRIVATE_IDENTIFIER_WITNESS');module.exports=1;\n", encoding="utf-8")
            script = root / "scripts/private-case.cjs"
            script.parent.mkdir(parents=True, exist_ok=True)
            runner = root / CONTRACT.PERSISTENT_LIFECYCLE_RUNNER
            runner.write_text("import './private-case.cjs';\n", encoding="utf-8")
            for name in ("return", "default", "extends", "in", "typeof", r"\u0072eturn", r"\u{72}eturn"):
                for optional in (False, True):
                    with self.subTest(name=name, optional=optional):
                        script.write_text(private_source(name, optional=optional), encoding="utf-8")
                        proc = subprocess.run([NODE, str(script)], cwd=root, capture_output=True, text=True, timeout=10)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertIn("PRIVATE_IDENTIFIER_WITNESS", proc.stdout)
                        snapshot = CONTRACT.runtime_source_paths(root)
                        self.assertIn("node_modules/bound-package/index.cjs", snapshot)
                        self.assertIn("node_modules/bound-package/package.json", snapshot)
