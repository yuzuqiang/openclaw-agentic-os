"""Regression witnesses for review 5119792197 and adjacent lexical boundaries."""
from __future__ import annotations

import ast
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_openclaw_real_gateway_contract_probe import MODULE

SOURCE = MODULE.runtime_source_contract
NODE = shutil.which("node")


class RuntimeLexicalTypeBoundaryTests(unittest.TestCase):
    def assert_accounted(self, source: str, specifier: str = "./hidden.cjs") -> None:
        try:
            imports = SOURCE.import_specifiers(source)
        except SOURCE.RuntimeSourceContractError:
            return  # Unsupported syntax must fail closed, not omit a dependency.
        self.assertIn(specifier, [item[0] for item in imports])

    def test_regex_after_reserved_statement_and_heritage_keywords(self) -> None:
        cases = (
            'class A extends /"/.constructor {} require("./hidden.cjs"); // "',
            'while(true){break\n /"/;} require("./hidden.cjs"); // "',
            'for(let i=0;i<1;i++){continue\n /"/;} require("./hidden.cjs"); // "',
            'debugger\n /"/; require("./hidden.cjs"); // "',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_accounted(source)
                self.assertIn("require", SOURCE._source_scan_view(source))

    def test_labeled_jump_asi_regex_cannot_hide_dependencies(self) -> None:
        for jump in ("break outer", "continue outer"):
            for gap in ("\n", "\r", "\r\n", "\u2028", "\u2029", "/*\n*/"):
                source = (
                    f'outer: for(let i=0;i<1;i++) {{ if(false) {jump}{gap}'
                    ' /"/; require("./hidden.cjs"); // "\n}'
                )
                with self.subTest(jump=jump, gap=gap), self.assertRaises(SOURCE.RuntimeSourceContractError):
                    SOURCE.import_specifiers(source)

    def test_export_default_regex_does_not_hide_static_import(self) -> None:
        source = 'export default /"/; import "./hidden.mjs"; // "'
        self.assertIn(("./hidden.mjs", True, "import"), SOURCE.import_specifiers(source))

    def test_private_keyword_names_are_property_names_not_regex_prefixes(self) -> None:
        for name in ("return", "throw", "case", "delete", "typeof", "void", "new", "extends", "default", "break", "continue", "debugger", "await", "yield", "of"):
            source = f'class C {{ #{name}=2; m(){{ this.#{name} / require("./hidden.cjs") + 0 / 2; }} }} new C().m();'
            with self.subTest(name=name):
                self.assert_accounted(source)

    def test_contextual_of_slash_is_not_guessed(self) -> None:
        for source in (
            'for(const x of /"/.source) {} require("./hidden.cjs"); // "',
            'for(const [x] of /"/.source) {} require("./hidden.cjs"); // "',
            'for(const {x} of /"/.source) {} require("./hidden.cjs"); // "',
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)
        self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(
            'var of=2;of / require("./hidden.cjs") + 0 / 2;'
        ))

    def test_prefix_negation_regex_controls_remain_supported(self) -> None:
        for prefix in ("!", "!!", "!!!", "!(", "!!("):
            suffix = ")" if prefix.endswith("(") else ""
            source = f'const x={prefix}/"/.test("x"){suffix};require("./hidden.cjs");'
            with self.subTest(prefix=prefix):
                self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source))

    def test_typescript_postfix_non_null_slash_fails_closed(self) -> None:
        for suffix in ("!", "!!", "!!!"):
            with self.subTest(suffix=suffix), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(f'const value=2;value{suffix} / require("./hidden.cjs") + 0 / 2;')

    def test_jsx_text_cannot_hide_executable_code(self) -> None:
        for expression in ('<div>"</div>', '<>"</>', '<Comp title="x" />', '<Comp>{"quote"}</Comp>'):
            with self.subTest(expression=expression), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(f'const x={expression};require("./hidden.cjs"); // "')

    def test_non_jsx_angle_and_literal_controls(self) -> None:
        for source in (
            'const identity=<T>(value:T)=>value;require("./hidden.cjs");',
            'const comparison=2<3; const data="</div>";require("./hidden.cjs");',
            'const data="<div>quote</div>";require("./hidden.cjs");',
            'const element=<div />;require("./hidden.cjs");',
        ):
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source))

    def test_erased_type_imports_are_not_runtime_capability_origins(self) -> None:
        for source in (
            "import { type Worker, isMainThread } from 'node:worker_threads'; type W=Worker;",
            "import { type Worker as W, isMainThread } from 'node:worker_threads'; let w:W;",
            "import type { Worker } from 'node:worker_threads'; type W=Worker;",
            "import type Worker from 'node:worker_threads'; type W=Worker;",
            "import type * as W from 'node:worker_threads'; type T=W.Worker;",
            "import {type Module} from 'node:module'; type T=Module;",
            "import {type createRequire} from 'node:module'; type T=typeof createRequire;",
            "import {type spawnSync as S} from 'node:child_process'; type T=typeof S;",
            "export type {Worker} from 'node:worker_threads';",
            "export {type Worker, type MessagePort} from 'node:worker_threads';",
        ):
            with self.subTest(source=source):
                SOURCE.import_specifiers(source)

    def test_type_modifiers_do_not_hide_real_value_imports_or_exports(self) -> None:
        for source in (
            "import type from 'node:child_process';const go=type.spawn;go('./hidden.sh');",
            "import type, {type Worker} from 'node:worker_threads';const W=type.Worker;",
            "import {type Worker, Worker as W} from 'node:worker_threads';const Alias=W;",
            "import {type Module,createRequire as make} from 'node:module';const alias=make;",
            "export {type Worker, Worker as W} from 'node:worker_threads';",
            "export {Worker as type} from 'node:worker_threads';",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_type_declaration_asi_does_not_exempt_runtime_alias_transfers(self) -> None:
        for declaration in ("type T = {value: string}", "interface T {value: string}"):
            for tail in (
                "const W=Worker; new W(new URL('./hidden.mjs',import.meta.url));",
                "const make=Worker.bind(null); new make('./hidden.mjs');",
            ):
                source = "import {Worker} from 'node:worker_threads'; " + declaration + "\n" + tail
                with self.subTest(declaration=declaration, tail=tail), self.assertRaises(SOURCE.RuntimeSourceContractError):
                    SOURCE.import_specifiers(source)

    def test_integrated_source_has_no_shadowed_top_level_function_definitions(self) -> None:
        tree = ast.parse(Path(SOURCE.__file__).read_text(encoding="utf-8"))
        names = [node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.assertEqual(len(names), len(set(names)))

    @unittest.skipUnless(NODE, "requires a real Node lexical witness")
    def test_real_node_executes_dependencies_after_reserved_keyword_regexes(self) -> None:
        cases = (
            ('class A extends /"/.constructor {} require("./hidden.cjs"); // "', "cjs"),
            ('while(true){break\n /"/;} require("./hidden.cjs"); // "', "cjs"),
            ('for(let i=0;i<1;i++){continue\n /"/;} require("./hidden.cjs"); // "', "cjs"),
            ('debugger\n /"/; require("./hidden.cjs"); // "', "cjs"),
            ('outer:for(let i=0;i<1;i++){if(false)break outer\n /"/;require("./hidden.cjs"); // "\n}', "cjs"),
            ('outer:for(let i=0;i<1;i++){if(false)continue outer/*\n*/ /"/;require("./hidden.cjs"); // "\n}', "cjs"),
            ('for(const x of /"/.source) {} require("./hidden.cjs"); // "', "cjs"),
            ('export default /"/; import "./hidden.cjs"; // "', "mjs"),
            ('class C{#return=2;m(){this.#return / require("./hidden.cjs") + 0 / 2;}}new C().m();', "cjs"),
        )
        for source, suffix in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hidden.cjs").write_text("console.log('DEPENDENCY_EXECUTED');module.exports=2;", encoding="utf-8")
                entry = root / ("entry." + suffix)
                entry.write_text(source, encoding="utf-8")
                completed = subprocess.run([NODE, str(entry)], cwd=root, capture_output=True,
                                           text=True, timeout=10, check=True)
                self.assertEqual("DEPENDENCY_EXECUTED", completed.stdout.strip())
                self.assert_accounted(source)


if __name__ == "__main__":
    unittest.main()
