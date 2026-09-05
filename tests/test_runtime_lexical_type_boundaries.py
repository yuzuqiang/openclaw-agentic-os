"""Syntax cross-regressions for the exact-head Codex findings on PR45."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "runtime_lexical_type_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert _SPEC is not None and _SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


class RuntimeLexicalTypeBoundaryTests(unittest.TestCase):
    def assert_bound_or_closed(self, source: str) -> None:
        try:
            imports = CONTRACT.import_specifiers(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(("./hidden.cjs", True, "require"), imports)

    def assert_closed(self, source: str) -> None:
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers(source)

    def test_regex_after_extends_cannot_hide_following_load(self) -> None:
        source = 'class A extends /"/.constructor {} require("./hidden.cjs"); // "'
        view = CONTRACT._source_scan_view(source)
        self.assertIn('require("./hidden.cjs")', view)
        self.assertNotIn('/"/', view)
        self.assert_bound_or_closed(source)

    def test_reserved_regex_prefixes_do_not_swallow_following_code(self) -> None:
        prefixes = (
            'export default ', 'debugger\n', 'class A extends ',
            'return ', 'throw ', 'void ', 'typeof ', 'delete ', 'case ',
            'x instanceof ', 'x in ', 'new ', 'do ', 'else ',
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assert_bound_or_closed(prefix + '/"/; require("./hidden.cjs"); // "')

    def test_contextual_keywords_cannot_hide_executable_division(self) -> None:
        for name in ('await', 'yield', 'of'):
            with self.subTest(name=name):
                self.assert_bound_or_closed(
                    f'const {name}=1; {name} / require("./hidden.cjs") / 2;'
                )

    def test_contextual_regex_goals_fail_closed_rather_than_guess(self) -> None:
        for source in (
            'async function f(){ await /"/; require("./hidden.cjs"); } // "',
            'function* f(){ yield /"/; require("./hidden.cjs"); } // "',
            'for (const x of /"/.source) { require("./hidden.cjs"); } // "',
        ):
            with self.subTest(source=source):
                self.assert_bound_or_closed(source)

    def test_typescript_postfix_operators_cannot_hide_executable_division(self) -> None:
        for source in (
            'const x=1; x! / require("./hidden.cjs") / 2;',
            'const f=<T>()=>1; f<string> / require("./hidden.cjs") / 2;',
        ):
            with self.subTest(source=source):
                self.assert_bound_or_closed(source)

    def test_keyword_member_division_remains_visible(self) -> None:
        for name in ('extends', 'default', 'debugger', 'await', 'yield', 'of'):
            with self.subTest(name=name):
                self.assertIn(
                    ('./hidden.cjs', True, 'require'),
                    CONTRACT.import_specifiers(
                        f'const obj={{{name}:1}}; obj.{name} / require("./hidden.cjs");'
                    ),
                )

    def test_benign_regex_and_numeric_division_still_work(self) -> None:
        for prefix in ('const re=/"/;', 'export default /"/;', 'debugger\n/"/;', 'let n=8/2;'):
            with self.subTest(prefix=prefix):
                self.assertIn(
                    ('./hidden.cjs', True, 'require'),
                    CONTRACT.import_specifiers(prefix + 'require("./hidden.cjs");'),
                )
        self.assertEqual(CONTRACT.import_specifiers('const re=/require("fake")/;'), [])

    def test_inline_type_only_worker_does_not_create_value_capability(self) -> None:
        for specifier, local in (
            ('type Worker', 'Worker'),
            ('type Worker as W', 'W'),
            ('type /* trivia */ Worker as W', 'W'),
            ('type "Worker" as W', 'W'),
        ):
            with self.subTest(specifier=specifier):
                source = f"import {{ {specifier}, isMainThread }} from 'node:worker_threads'; type T={local};"
                self.assertIn(('node:worker_threads', True, 'import'), CONTRACT.import_specifiers(source))
                self.assertNotIn(local, CONTRACT._execution_capability_bindings(CONTRACT._source_scan_view(source))[0])

    def test_inline_type_only_child_process_does_not_create_value_capability(self) -> None:
        for symbol in ('ChildProcess', 'spawn', 'spawnSync', 'fork', 'exec', 'execSync'):
            with self.subTest(symbol=symbol):
                source = f"import {{ type {symbol} as T }} from 'node:child_process'; type Alias=T;"
                self.assertIn(('node:child_process', True, 'import'), CONTRACT.import_specifiers(source))
                self.assertNotIn('T', CONTRACT._execution_capability_bindings(source)[0])

    def test_whole_type_only_imports_do_not_create_capabilities(self) -> None:
        for clause, local in (
            ('{Worker}', 'Worker'), ('{Worker as W}', 'W'),
            ('* as wt', 'wt'), ('wt', 'wt'),
        ):
            with self.subTest(clause=clause):
                source = f"import type {clause} from 'node:worker_threads'; type T={local};"
                CONTRACT.import_specifiers(source)
                self.assertNotIn(local, CONTRACT._execution_capability_bindings(source)[0])

    def test_type_only_reexports_do_not_transfer_capabilities(self) -> None:
        for source in (
            "export type {Worker} from 'node:worker_threads';",
            "export type * from 'node:child_process';",
            "export {type Worker} from 'node:worker_threads';",
        ):
            with self.subTest(source=source):
                CONTRACT.import_specifiers(source)

    def test_local_type_exports_do_not_hide_neighbouring_value_exports(self) -> None:
        declaration="import {Worker} from 'node:worker_threads';"
        for export in ("export type {Worker};", "export {type Worker};", "export {type Worker as W};"):
            with self.subTest(export=export):
                CONTRACT.import_specifiers(declaration + export)
        for export in ("export {type Worker as T,Worker};", "export {Worker,type Worker as T};"):
            with self.subTest(export=export):
                self.assert_closed(declaration + export)

    def test_mixed_value_worker_remains_bound(self) -> None:
        declarations = (
            "import {type Worker as T, Worker as W} from 'node:worker_threads';",
            "import {Worker as W, type Worker as T} from 'node:worker_threads';",
            "import wt, {type Worker as T, Worker as W} from 'node:worker_threads';",
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                self.assertIn(('./hidden.mjs', True, 'import'), CONTRACT.import_specifiers(
                    declaration + "type Alias=T;new W(new URL('./hidden.mjs',import.meta.url));"
                ))
                self.assert_closed(declaration + "const Alias=W;new Alias('./hidden.mjs');")

    def test_type_modifier_does_not_erase_real_value_origins(self) -> None:
        for module, name, use in (
            ('worker_threads', 'Worker', "const Alias=Worker;new Alias('./hidden.mjs');"),
            ('child_process', 'spawn', "const Alias=spawn;Alias('node',['./hidden.cjs']);"),
        ):
            type_import = f"import {{type {name}}} from 'node:{module}';"
            value_import = f"import {{{name}}} from 'node:{module}';"
            for source in (type_import + value_import + use, value_import + type_import + use):
                with self.subTest(source=source):
                    self.assert_closed(source)

    def test_default_binding_named_type_is_not_a_type_modifier(self) -> None:
        self.assert_closed("import type from 'node:worker_threads';const W=type.Worker;new W('./hidden.mjs');")
        self.assert_closed("import type, {isMainThread} from 'node:worker_threads';const W=type.Worker;")

    def test_type_as_value_export_is_not_erased(self) -> None:
        for source in (
            "export {type as T} from 'node:worker_threads';",
            "export {'type' as T} from 'node:worker_threads';",
            "export {type Worker, Worker as W} from 'node:worker_threads';",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_type_import_does_not_suppress_implicit_value_escape(self) -> None:
        for use in (
            "const W=Worker;new W('./hidden.mjs');",
            "const box={make:Worker};new box.make('./hidden.mjs');",
            "fn(flag ? first, last : Worker);",
            "type T=Worker;const W=Worker;",
        ):
            with self.subTest(use=use):
                self.assert_closed("import {type Worker} from 'node:worker_threads';" + use)

    def test_type_annotations_do_not_create_value_references(self) -> None:
        for use in (
            "let worker:Worker;", "const worker:Worker|null=null;",
            "function f(worker:Worker){}", "const f=(worker:Worker)=>{};",
            "const worker=other as Worker;", "type W=Array<Worker>;",
            "type W={worker:Worker};", "type W=(worker:Worker)=>void;",
        ):
            with self.subTest(use=use):
                CONTRACT.import_specifiers("import {type Worker} from 'node:worker_threads';" + use)

    def test_type_contextual_names_remain_real_callable_values(self) -> None:
        for name in ("as", "satisfies"):
            for prefix in ("", "return ", "await ", "yield ", "void ", "typeof ", "new ", "else ", "other;", "other\n", "if(true) ", "while(true) ", "for(;;) ", "{} ", "if(true){} "):
                with self.subTest(name=name, prefix=prefix):
                    self.assert_closed("import {type Worker} from 'node:worker_threads';" + prefix + name + "(Worker);")

    def test_type_contextual_computed_access_is_not_a_type_assertion(self) -> None:
        for source in (
            "if(ok) as[Worker];", "if(ok) satisfies[Worker];",
            "{} as[Worker];", "if(ok) as`${Worker}`;",
        ):
            with self.subTest(source=source):
                self.assert_closed("import {Worker} from 'node:worker_threads';" + source)

    def test_attribute_free_intrinsic_jsx_preserves_dependency_scan(self) -> None:
        for tag in ("<div/>", "<div />", "<span\n/>", "<custom-element />"):
            with self.subTest(tag=tag):
                source = f"export const View=()=>{tag};require('./hidden.cjs');"
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
        # Constructor components and attribute/expression syntax are not part
        # of this narrow compatibility allowance.
        for tag in ("<Worker />", "<div value={Worker}/>", '<div value="{x}"/>'):
            with self.subTest(tag=tag):
                self.assert_closed(f"const View=()=>{tag};")

    def test_jsx_text_quotes_cannot_hide_executable_expressions(self) -> None:
        for source in (
            'const y=<div>"{require("./hidden.cjs")}</div>; // "',
            'const y=<><p>"</p>{require("./hidden.cjs")}</>; // "',
            'let value\n<div>"{require("./hidden.cjs")}</div>; // "',
            'const y=flag?<div>"{require("./hidden.cjs")}</div>:null; // "',
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_declaration_asi_before_regex_does_not_hide_following_load(self) -> None:
        for prefix in ("var value\n", "let value\n", "type Value=string\n"):
            with self.subTest(prefix=prefix):
                self.assert_bound_or_closed(prefix + '/"/;require("./hidden.cjs"); // "')

    def test_type_alias_asi_does_not_hide_following_value_call(self) -> None:
        source="import {type Worker} from 'node:worker_threads';type T=Worker\nrequire('./hidden.cjs');"
        self.assertIn(('./hidden.cjs', True, 'require'), CONTRACT.import_specifiers(source))

    def test_commonjs_type_property_is_not_a_typescript_modifier(self) -> None:
        self.assert_closed("const {type:Worker}=require('node:child_process');const Alias=Worker;")

    @unittest.skipUnless(NODE, 'Node is required for the independent execution witness')
    def test_node_extends_regex_executes_hidden_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'hidden.cjs').write_text("console.log('HIDDEN_EXECUTED');module.exports=1;", encoding='utf-8')
            source = 'class A extends /"/.constructor {} require("./hidden.cjs"); // "'
            entry = root/'entry.cjs'
            entry.write_text(source, encoding='utf-8')
            env = {key:value for key,value in os.environ.items() if not key.startswith('NODE_')}
            result = subprocess.run([NODE, str(entry)], cwd=root, env=env,
                                    capture_output=True, text=True, check=True, timeout=30)
            self.assertEqual(result.stdout.strip(), 'HIDDEN_EXECUTED')
            self.assert_bound_or_closed(source)

    @unittest.skipUnless(NODE, 'Node is required for the independent execution witness')
    def test_node_control_body_as_call_receives_real_worker_value(self) -> None:
        source = "import {Worker} from 'node:worker_threads';function as(value){console.log(typeof value);}if(true) as(Worker);"
        env = {key:value for key,value in os.environ.items() if not key.startswith('NODE_')}
        result = subprocess.run([NODE, '--input-type=module', '-e', source], env=env,
                                capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(result.stdout.strip(), 'function')
        self.assert_closed(source)

    @unittest.skipUnless(NODE, 'Node is required for the independent TypeScript witness')
    def test_node_erases_type_only_worker_import(self) -> None:
        source = "import {type Worker,isMainThread} from 'node:worker_threads';type W=Worker;console.log(isMainThread);"
        env = {key:value for key,value in os.environ.items() if not key.startswith('NODE_')}
        script = """
const {stripTypeScriptTypes}=require('node:module');
if(typeof stripTypeScriptTypes!=='function')process.exit(77);
const fs=require('node:fs');
process.stdout.write(stripTypeScriptTypes(fs.readFileSync(0,'utf8')));
"""
        stripped = subprocess.run([NODE, '-e', script], input=source, env=env,
                                  capture_output=True, text=True, timeout=30)
        if stripped.returncode == 77:
            self.skipTest('Node version does not provide stripTypeScriptTypes')
        self.assertEqual(stripped.returncode, 0, stripped.stderr)
        result = subprocess.run([NODE, '--input-type=module', '-e', stripped.stdout], env=env,
                                capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(result.stdout.strip(), 'true')
        CONTRACT.import_specifiers(source)
