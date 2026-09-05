"""Exact-head Codex regressions and non-erasure safety witnesses for PR45."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "runtime_lexical_type_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert _spec is not None and _spec.loader is not None
CONTRACT = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


class RuntimeLexicalTypeBoundaryTests(unittest.TestCase):
    def assert_closed(self, source: str) -> None:
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers(source)

    def assert_bound_or_closed(self, source: str, expected: str = "./hidden.cjs") -> None:
        try:
            specifiers = CONTRACT.import_specifiers(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(expected, [item[0] for item in specifiers])

    def test_regex_after_extends_cannot_hide_executable_suffix(self) -> None:
        for gap in (" ", "/* comment */", "\n", "\r\n", "\u2028", "\u2029"):
            with self.subTest(gap=repr(gap)):
                source = 'class A extends' + gap + '/"/.constructor {} require("./hidden.cjs"); // "'
                self.assertIn("require", [value for kind, value, _, _ in CONTRACT._source_tokens(source) if kind == "identifier"])
                self.assertIn('/"/', [value for kind, value, _, _ in CONTRACT._source_tokens(source) if kind == "regex"])
                self.assert_bound_or_closed(source)

    def test_property_extends_is_division_not_a_regex_prefix(self) -> None:
        for property_use in ("obj.extends", "obj?.extends", "obj./*comment*/extends", "obj.\nextends"):
            with self.subTest(property_use=property_use):
                source = 'const obj={extends:2}; ' + property_use + ' / require("./hidden.cjs");'
                self.assertIn("./hidden.cjs", [item[0] for item in CONTRACT.import_specifiers(source)])

    def test_mixed_type_only_worker_imports_do_not_bind_values(self) -> None:
        for declaration, reference in (
            ("import {type Worker, isMainThread} from 'node:worker_threads';", "Worker"),
            ("import {type Worker as W, isMainThread} from 'node:worker_threads';", "W"),
            ("import type {Worker} from 'node:worker_threads';", "Worker"),
            ("import type {Worker as W} from 'node:worker_threads';", "W"),
            ("import type wt from 'node:worker_threads';", "wt.Worker"),
            ("import type * as wt from 'node:worker_threads';", "wt.Worker"),
        ):
            for annotation in (reference, "Promise<" + reference + ">", reference + "[]", reference + " | undefined"):
                with self.subTest(declaration=declaration, annotation=annotation):
                    source = declaration + " type T = " + annotation + ";"
                    self.assertEqual(CONTRACT.import_specifiers(source), [("node:worker_threads", True, "import")])

    def test_type_only_child_process_names_are_not_unsupported_value_exports(self) -> None:
        for declaration in (
            "import {type SpawnOptions, spawn} from 'node:child_process';",
            "import {type ChildProcess as Child, execFile} from 'node:child_process';",
            "import type {ChildProcess} from 'node:child_process';",
            "import type child_process from 'node:child_process';",
            "import {type SpawnOptions, type ChildProcess} from 'node:child_process';",
        ):
            with self.subTest(declaration=declaration):
                self.assertEqual(CONTRACT.import_specifiers(declaration), [("node:child_process", True, "import")])

    def test_type_keyword_as_default_value_import_is_audited(self) -> None:
        for declaration, usage in (
            ("import type from 'node:worker_threads';", "const W=type.Worker; new W('./hidden.mjs');"),
            ("import type, {isMainThread} from 'node:worker_threads';", "const W=type.Worker; new W('./hidden.mjs');"),
            ("import type from 'node:child_process';", "const launch=type.spawn; launch('node',['./hidden.cjs']);"),
            ("import type, {spawn} from 'node:child_process';", "const launch=type.spawn; launch('node',['./hidden.cjs']);"),
            ("import {spawn as type} from 'node:child_process';", "const launch=type; launch('node',['./hidden.cjs']);"),
        ):
            with self.subTest(declaration=declaration):
                self.assert_closed(declaration + usage)

    def test_type_only_and_value_imports_of_same_export_remain_distinct(self) -> None:
        declarations = (
            "import {type Worker as W, Worker as V} from 'node:worker_threads'; type T=W;",
            "import type, {Worker as V} from 'node:worker_threads';",
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                self.assert_closed(declaration + "const Alias=V; new Alias('./hidden.mjs');")
                result = CONTRACT.import_specifiers(declaration + "new V(new URL('./hidden.mjs', import.meta.url));")
                self.assertIn("./hidden.mjs", [item[0] for item in result])

    def test_commonjs_type_member_does_not_mean_type_only(self) -> None:
        self.assert_closed("const {type: spawn} = require('node:child_process'); spawn('node', ['./hidden.cjs']);")
        self.assert_closed("const {spawn: type} = require('node:child_process'); const call=type; call('node', ['./hidden.cjs']);")

    def test_type_aliases_do_not_disable_global_worker_audit(self) -> None:
        for declaration in (
            "import type {Worker} from 'node:worker_threads';",
            "import {type Worker, isMainThread} from 'node:worker_threads';",
            "type Worker = string;",
            "type T = Worker;",
            "type T = typeof Worker;",
        ):
            with self.subTest(declaration=declaration):
                self.assert_closed(declaration + "const C=Worker; new C('./hidden.mjs');")

    def test_newline_after_type_is_a_value_statement_not_erased_alias(self) -> None:
        for gap in ("\n", "\r", "\r\n", "\u2028", "\u2029", "/*\n*/", "// comment\n"):
            with self.subTest(gap=repr(gap)):
                source = "import type {Worker} from 'node:worker_threads'; type" + gap + " W=Worker;"
                self.assert_closed(source)
                view = CONTRACT._source_scan_view(source)
                self.assertIn("W=Worker", view)

    def test_erasure_does_not_consume_runtime_expression_after_type_alias(self) -> None:
        for tail in (
            '; require("./hidden.cjs");',
            '\nrequire("./hidden.cjs");',
            '; const C=Worker; new C("./hidden.cjs");',
        ):
            with self.subTest(tail=tail):
                self.assert_bound_or_closed("type T=Worker" + tail)
        self.assert_closed("type T=Worker; const C=Worker;")
        self.assert_closed("const type=1; type\nW=Worker;")

    def test_inert_type_aliases_preserve_executable_template_children(self) -> None:
        self.assert_bound_or_closed('type T=Worker; const text=`${require("./hidden.cjs")}`;')
        self.assert_bound_or_closed('type T="quote \\\" ;"; require("./hidden.cjs");')
        self.assert_closed('type T=Worker; const text=`${Worker}`;')

    @unittest.skipUnless(NODE, "Node is required for the JavaScript execution witness")
    def test_real_node_executes_hidden_module_after_extends_regex(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text('globalThis.hiddenLoaded=true; module.exports=1;', encoding="utf-8")
            source = 'class A extends /"/.constructor {} require("./hidden.cjs"); // "\nif(!globalThis.hiddenLoaded) throw Error("missing execution");'
            (root / "entry.cjs").write_text(source, encoding="utf-8")
            result = subprocess.run([NODE, str(root / "entry.cjs")], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_bound_or_closed(source)

    @unittest.skipUnless(NODE, "Node is required for the TypeScript erasure witness")
    def test_real_node_typescript_keeps_value_type_but_erases_type_alias(self) -> None:
        availability = subprocess.run(
            [NODE, "-p", "typeof require('node:module').stripTypeScriptTypes"],
            capture_output=True, text=True, timeout=15,
        )
        if availability.returncode != 0 or availability.stdout.strip() != "function":
            self.skipTest("Node lacks stripTypeScriptTypes; run with Node 22.13+ or 24")
        sources = [
            "import {type Worker, isMainThread} from 'node:worker_threads'; type W=Worker;",
            "import type from 'node:worker_threads'; type.Worker;",
            "type\nW=Worker;",
            "import {type as Worker} from './fixture.mjs'; Worker;",
        ]
        result = subprocess.run(
            [NODE, "-e", "const fs=require('node:fs'); const m=require('node:module'); console.log(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(s=>m.stripTypeScriptTypes(s))))"],
            input=json.dumps(sources), capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = json.loads(result.stdout)
        self.assertNotIn("Worker", outputs[0])
        self.assertIn("type.Worker", outputs[1])
        self.assertIn("W=Worker", outputs[2])
        self.assertIn("type as Worker", outputs[3])
        self.assertEqual(CONTRACT.import_specifiers(sources[0]), [("node:worker_threads", True, "import")])
        self.assert_closed(sources[1])
        self.assert_closed(sources[2])


if __name__ == "__main__":
    unittest.main()
