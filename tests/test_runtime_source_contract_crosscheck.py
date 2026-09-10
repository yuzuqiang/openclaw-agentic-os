"""Independently reproduced loader omissions on PR45 head bb160fb."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_openclaw_real_gateway_contract_probe import MODULE

SOURCE = MODULE.runtime_source_contract


class RuntimeSourceCrosscheckTests(unittest.TestCase):
    def assert_rejected(self, source: str) -> None:
        with self.assertRaises(SOURCE.RuntimeSourceContractError):
            SOURCE.import_specifiers(source)

    def assert_bound(self, source: str) -> None:
        self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source))

    def test_module_require_value_transfers_reject_all_groupings_and_members(self) -> None:
        for depth in (0, 1, 2, 4, 16):
            base = "(" * depth + "module" + ")" * depth
            for member in (".require", "['require']", '?.["require"]'):
                with self.subTest(depth=depth, member=member):
                    self.assert_rejected(f"const r={base}{member};r('./hidden.cjs');")

    def test_direct_module_require_calls_remain_bound(self) -> None:
        for depth in (0, 1, 2, 4, 16):
            base = "(" * depth + "module" + ")" * depth
            for member in (".require", "['require']", '?.["require"]'):
                with self.subTest(depth=depth, member=member):
                    self.assert_bound(f"{base}{member}('./hidden.cjs');")

    def test_node_module_namespace_and_constructor_values_cannot_escape(self) -> None:
        for declaration in (
            "import * as M from 'node:module';", "import M from 'node:module';",
            "const M=require('module');", "const {Module:M}=require('node:module');",
        ):
            for expression in (
                "const C=M;new C().load('./hidden.cjs');",
                "const h={v:M};new h.v().load('./hidden.cjs');",
                "const h=[M];new h[0]().load('./hidden.cjs');",
                "function get(){return M;}new (get())().load('./hidden.cjs');",
                "consume(M);",
            ):
                with self.subTest(declaration=declaration, expression=expression):
                    self.assert_rejected(declaration + expression)

    def test_run_main_aliases_cannot_bypass_module_capability_accounting(self) -> None:
        for declaration in (
            "import {runMain as go} from 'node:module';",
            "const {runMain:go}=require('module');",
        ):
            with self.subTest(declaration=declaration):
                self.assert_rejected(declaration + "const f=go;f('./hidden.cjs');")

    def test_grouped_and_aliased_module_origins_cannot_escape_accounting(self) -> None:
        for acquisition in (
            "(require)('module')", "((require))('module')",
            "module['require']('node:module')", "r('module')",
        ):
            with self.subTest(acquisition=acquisition):
                self.assert_rejected("const r=require;const M=" + acquisition + ";const C=M;new C().load('./hidden.cjs');")

    def test_named_inline_create_require_is_bound(self) -> None:
        for declaration, factory in (
            ("import {createRequire} from 'node:module';", "createRequire"),
            ("import {createRequire as c} from 'node:module';", "c"),
            ("const {createRequire:c}=require('node:module');", "c"),
        ):
            for base in ("import.meta.url", "__filename"):
                with self.subTest(declaration=declaration, base=base):
                    self.assert_bound(declaration + f"{factory}({base})('./hidden.cjs');")

    def test_inline_factory_inside_nested_templates_is_bound(self) -> None:
        for expression in (
            "`${c(import.meta.url)('./hidden.cjs')}`",
            "`outer ${`inner ${c(import.meta.url)('./hidden.cjs')}`}`",
        ):
            with self.subTest(expression=expression):
                self.assert_bound("import {createRequire as c} from 'node:module';const s=" + expression + ";")

    def test_direct_namespace_factory_controls_remain_bound(self) -> None:
        for source in (
            "require('module').createRequire(__filename)('./hidden.cjs');",
            "const M=require('module');M.createRequire(__filename)('./hidden.cjs');",
            "import * as M from 'node:module';M.createRequire(import.meta.url)('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_bound(source)

    def test_spread_is_not_mistaken_for_property_access(self) -> None:
        for module in ("worker_threads", "child_process", "module"):
            for trivia in ("", " ", "/*comment*/", "\n"):
                source = f"import * as M from 'node:{module}';const h={{...{trivia}M}};"
                with self.subTest(module=module, trivia=trivia):
                    self.assert_rejected(source)

    def test_contextual_and_typescript_postfix_division_fail_closed(self) -> None:
        for source in (
            "var await=2;await / require('hidden-package') / 2;",
            "var yield=2;yield / require('hidden-package') / 2;",
            "const value=2;value! / require('hidden-package') / 2;",
            "const value=<T>(x:T)=>x;value<number> / require('hidden-package') / 2;",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    @unittest.skipUnless(shutil.which("node"), "requires Node execution witness")
    def test_real_node_witnesses_for_module_require_and_constructor_transfers(self) -> None:
        for source in (
            "const r=module['require'];r('./hidden.cjs');",
            "const r=((module))?.['require'];r('./hidden.cjs');",
            "const M=require('node:module');const C=M;new C().load('./hidden.cjs');",
            "const {runMain:go}=require('node:module');const f=go;f('./hidden.cjs');",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hidden.cjs").write_text("console.log('DEPENDENCY_EXECUTED');module.exports=2;", encoding="utf-8")
                (root / "main.cjs").write_text(source, encoding="utf-8")
                result = subprocess.run([shutil.which("node"), str(root / "main.cjs")], cwd=root,
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual("DEPENDENCY_EXECUTED", result.stdout.strip())
                self.assert_rejected(source)

    @unittest.skipUnless(shutil.which("node"), "requires Node execution witness")
    def test_real_node_witnesses_for_named_inline_factories(self) -> None:
        for expression in (
            "createRequire(import.meta.url)('./hidden.cjs');",
            "const s=`${createRequire(import.meta.url)('./hidden.cjs')}`;",
        ):
            source = "import {createRequire} from 'node:module';" + expression
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hidden.cjs").write_text("console.log('DEPENDENCY_EXECUTED');module.exports=2;", encoding="utf-8")
                (root / "main.mjs").write_text(source, encoding="utf-8")
                result = subprocess.run([shutil.which("node"), str(root / "main.mjs")], cwd=root,
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual("DEPENDENCY_EXECUTED", result.stdout.strip())
                self.assert_bound(source)

    @unittest.skipUnless(shutil.which("node"), "requires Node execution witness")
    def test_real_node_witness_for_destructured_process_env_prototype_mutator_alias(self) -> None:
        sources = (
            (
                "const {setPrototypeOf:set}=Object;"
                "set(process.env,()=>{});"
                "const key='constructor';"
                "const build=process.env[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "let set;"
                "({'setPrototypeOf':set}=Object);"
                "set(process.env,()=>{});"
                "const key='constructor';"
                "const build=process.env[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "let set;"
                "({['setPrototypeOf']:set}=Reflect);"
                "set(process.env,()=>{});"
                "const key='constructor';"
                "const build=process.env[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "let set;"
                "set=Object.setPrototypeOf;"
                "set(process.env,()=>{});"
                "const key='constructor';"
                "const build=process.env[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "const key='constructor';"
                "const {'max':f}=Math;"
                "const build=f[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "const {['assign']:f}=Object;"
                "const build=f['constructor'];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
            (
                "const key='constructor';"
                "const f=Math.max;"
                "const build=f[key];"
                "await build(\"return import('./hidden.mjs')\")();"
            ),
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hidden.mjs").write_text(
                    "console.log('DEPENDENCY_EXECUTED');", encoding="utf-8"
                )
                (root / "main.mjs").write_text(source, encoding="utf-8")
                result = subprocess.run(
                    [shutil.which("node"), str(root / "main.mjs")],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                self.assertEqual("DEPENDENCY_EXECUTED", result.stdout.strip())
                self.assert_rejected(source)
