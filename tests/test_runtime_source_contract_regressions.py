"""Cross-syntax and real-Node regression witnesses for PR45's source boundary."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = _load("source_contract_regression", "scripts/agentic_os_runtime_source_contract.py")
PROBE = _load("gateway_contract_regression", "scripts/openclaw-real-gateway-contract-probe.py")
NODE = shutil.which("node")


class RuntimeSourceRegressionTests(unittest.TestCase):
    def fixture(self, root: Path, source: str, extra: dict[str, str] | None = None) -> None:
        files = {path: "export const value = 1;\n" for path in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS}
        files["package.json"] = '{"name":"openclaw"}\n'
        files[CONTRACT.PERSISTENT_LIFECYCLE_RUNNER] = source
        files.update(extra or {})
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def assert_closed(self, source: str) -> None:
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers(source)

    def assert_closed_with_message(self, source: str, expected: str) -> None:
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, expected):
            CONTRACT.import_specifiers(source)

    def test_worker_transfers_do_not_escape_through_new_syntax(self) -> None:
        imports = (
            "import {Worker as W} from 'node:worker_threads';",
            "import wt, {Worker as W} from 'worker_threads';",
            "import {'Worker' as W} from 'node:worker_threads';",
            "const {Worker: W} = require('node:worker_threads');",
        )
        uses = (
            "const Alias = W; new Alias(new URL('./hidden.mjs', import.meta.url));",
            "const Alias = ((W)); new Alias('./hidden.mjs');",
            "let Alias; Alias = W; new Alias('./hidden.mjs');",
            "const box = [W]; new box[0]('./hidden.mjs');",
            "const box = {make: W}; new box.make('./hidden.mjs');",
            "const get = () => W; new (get())('./hidden.mjs');",
            "Reflect.construct(W, ['./hidden.mjs']);",
            "const Alias = W.bind(null); new Alias('./hidden.mjs');",
            "const Alias = true ? W : null; new Alias('./hidden.mjs');",
            "export {W};",
            "function wrap(C) { return new C('./hidden.mjs'); } wrap(W);",
            "`${W}`;",
        )
        for declaration in imports:
            for use in uses:
                with self.subTest(declaration=declaration, use=use):
                    self.assert_closed(declaration + use)

    def test_unbound_execution_capability_messages_match_first_fail_closed_boundary(
        self,
    ) -> None:
        cases = {
            "node_test": (
                "import { run } from 'node:test';\n"
                "run({ files: ['./hidden.cjs'] });\n",
                "unbound execution capability",
            ),
            "node_vm": (
                "import vm from 'node:vm';\n"
                "const member = ['run', 'InThis', 'Context'].join('');\n"
                "vm[member]('hidden source');\n",
                "evaluated loader",
            ),
            "node_sqlite": (
                "import { DatabaseSync } from 'node:sqlite';\n"
                "new DatabaseSync(':memory:', { allowExtension: true })"
                ".loadExtension('./hidden.so');\n",
                "unbound execution capability",
            ),
        }
        for name, (source, expected) in cases.items():
            with self.subTest(name=name):
                self.assert_closed_with_message(source, expected)

    def test_worker_namespace_transfers_and_unknown_origins_fail_closed(self) -> None:
        sources = (
            "import * as wt from 'node:worker_threads'; const Alias=wt; new Alias.Worker('./hidden.mjs');",
            "import wt from 'node:worker_threads'; const {Worker: W}=wt; new W('./hidden.mjs');",
            "import wt from 'node:worker_threads'; const W=wt['Worker']; new W('./hidden.mjs');",
            "import wt from 'node:worker_threads'; const W=wt[`Worker`]; new W('./hidden.mjs');",
            "const wt = await import('node:worker_threads'); new wt.Worker('./hidden.mjs');",
            "const W = require('node:worker_threads').Worker; new W('./hidden.mjs');",
            "const r=require; const wt=r('node:worker_threads'); new wt.Worker('./hidden.mjs');",
            "import {createRequire} from 'node:module'; const r=createRequire(import.meta.url); const wt=r('node:worker_threads'); new wt.Worker('./hidden.mjs');",
            "export * from 'node:worker_threads';",
            "export {Worker as W} from 'node:worker_threads';",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_direct_worker_imports_remain_supported_including_combined_bindings(self) -> None:
        declarations = (
            "import {Worker as W} from 'node:worker_threads';",
            "import wt, {Worker as W} from 'node:worker_threads';",
            "import {'Worker' as W} from 'node:worker_threads';",
            "const {Worker: W} = require('node:worker_threads');",
        )
        for declaration in declarations:
            for use in (
                "new W(new URL('./hidden.mjs', import.meta.url));",
                "`${new W(new URL('./hidden.mjs', import.meta.url))}`;",
            ):
                with self.subTest(declaration=declaration, use=use):
                    self.assertIn(("./hidden.mjs", True, "import"), CONTRACT.import_specifiers(declaration + use))

    def test_type_only_worker_imports_do_not_create_execution_bindings(self) -> None:
        sources = (
            "import type {Worker} from 'node:worker_threads'; type W = Worker;",
            "import {type Worker, isMainThread} from 'node:worker_threads'; type W = Worker; void isMainThread;",
            "import {type Worker as W, parentPort} from 'node:worker_threads'; type Local = W; void parentPort;",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(("node:worker_threads", True, "import"), CONTRACT.import_specifiers(source))

    def test_semicolonless_type_declaration_does_not_hide_runtime_child_process_alias(self) -> None:
        source = (
            "import {spawnSync} from 'node:child_process';\n"
            "type Foo = string\n"
            "const go = spawnSync; go('./hidden.sh');"
        )
        self.assert_closed(source)

    def test_multiline_type_declarations_remain_type_only_until_actual_boundary(self) -> None:
        source = (
            "import {type Worker, isMainThread} from 'node:worker_threads';\n"
            "type Local =\n"
            "  Worker | string\n"
            "void isMainThread;"
        )
        self.assertIn(("node:worker_threads", True, "import"), CONTRACT.import_specifiers(source))

    def test_child_process_member_transfers_fail_closed_for_all_member_spellings(self) -> None:
        members = ("fork", "spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync")
        for member in members:
            for expression in (
                f"cp.{member}", f"cp['{member}']", f'cp["{member}"]',
                f"cp[`{member}`]", f"cp?.['{member}']", f"((cp['{member}']))",
                f"(cp).{member}", f"cp['{member[:2]}' + '{member[2:]}']",
            ):
                for assignment in (f"const go={expression};", f"let go; go={expression};", f"const go=[{expression}][0];"):
                    with self.subTest(member=member, assignment=assignment):
                        self.assert_closed("import * as cp from 'node:child_process';" + assignment + "go('./hidden.sh');")

    def test_child_process_namespace_and_constructor_cannot_escape(self) -> None:
        for source in (
            "import cp from 'node:child_process'; const alias=cp; alias.exec('hidden');",
            "import cp from 'node:child_process'; const {spawnSync: run}=cp; run('./hidden');",
            "import {ChildProcess} from 'node:child_process'; new ChildProcess().spawn({file:'./hidden'});",
            "const {ChildProcess} = require('node:child_process'); new ChildProcess().spawn({file:'./hidden'});",
            "export * from 'node:child_process';",
            "import {spawnSync as run} from 'node:child_process'; export {run};",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_standalone_identifier_named_of_is_still_a_computed_member_target(self) -> None:
        self.assert_closed(
            "const of=()=>{}; const build=of['constructor']; "
            "build(\"return import('./hidden.mjs')\")();"
        )

    def test_for_initializer_identifier_named_of_is_still_a_computed_member_target(self) -> None:
        self.assert_closed(
            "const of=()=>{}; "
            "for (const build=of['constructor']; false;) { "
            "build(\"return import('./hidden.mjs')\")() "
            "}"
        )

    def test_for_of_rhs_identifier_named_of_is_still_a_computed_member_target(self) -> None:
        for source in (
            "const of=()=>{}; "
            "for (const build of [of['constructor']]) { "
            "build(\"return import('./hidden.mjs')\")() "
            "}",
            "const of=()=>{}; "
            "for (const build of of['constructor']) { "
            "build(\"return import('./hidden.mjs')\")() "
            "}",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_contextual_for_of_array_literals_do_not_look_like_computed_members(self) -> None:
        source = "for (const value of ['constructor']) { void value; }"
        self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_require_non_call_references_fail_closed_regardless_of_grouping(self) -> None:
        for depth in (2, 3, 8, 32):
            source = "const r=" + "(" * depth + "require" + ")" * depth + ";r('./hidden.cjs');"
            with self.subTest(depth=depth):
                self.assert_closed(source)
        for source in (
            "let r; r=require; r('./hidden.cjs');",
            "const {r}={r: require}; r('./hidden.cjs');",
            "const r=[require][0]; r('./hidden.cjs');",
            "const r=true ? require : null; r('./hidden.cjs');",
            "function run(r){r('./hidden.cjs')} run(require);",
            "const r=module.require; r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_supported_require_forms_still_bind(self) -> None:
        for source in (
            "const r=require; r('./hidden.cjs');",
            "const r=(require); r('./hidden.cjs');",
            "(require)('./hidden.cjs');",
            "module.require('./hidden.cjs');",
            "module['require']('./hidden.cjs');",
            "require?.('./hidden.cjs');",
            "require['resolve']('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_escaped_and_unicode_loader_bindings_are_normalized_consistently(self) -> None:
        for name in (r"f\u006f", "构建", "cafe\u0301", "name\u200cjoin", "__agentic_source_identifier_0__"):
            source = (
                f"import {{createRequire as {name}}} from 'node:module';"
                f"const load={name}(import.meta.url); load('./hidden.cjs');"
            )
            with self.subTest(name=name):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
        source = "const __agentic_source_identifier_0__=1; const 加载=require; 加载('./hidden.cjs');"
        self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_create_require_factory_and_returned_loader_cannot_escape(self) -> None:
        prefix = "import {createRequire} from 'node:module';"
        for use in (
            "const f=createRequire; const r=f(import.meta.url); r('./hidden.cjs');",
            "const f=((createRequire)); const r=f(import.meta.url); r('./hidden.cjs');",
            "const r=((createRequire(import.meta.url))); r('./hidden.cjs');",
            "const r=createRequire(import.meta.url).bind(null,'./hidden.cjs'); r('./decoy.cjs');",
            "const get=()=>createRequire(import.meta.url); get()('./hidden.cjs');",
            "export {createRequire};",
        ):
            with self.subTest(use=use):
                self.assert_closed(prefix + use)
        for source in (
            "import M from 'node:module'; const r=M['createRequire'](import.meta.url); r('./hidden.cjs');",
            "import M from 'node:module'; const r=M.createRequire(import.meta.url); r('./hidden.cjs');",
            "export * from 'node:module';",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_hashbang_and_annex_b_comments_cannot_hide_loaders(self) -> None:
        for terminator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for comment in ('<!-- "\'`', '--> "\'`', '#!/usr/bin/env node "\'`'):
                source = comment + terminator + "require('./hidden.cjs');" + terminator + '// "\'`'
                with self.subTest(comment=comment, terminator=repr(terminator)):
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_comment_boundaries_are_shared_by_all_loader_scans(self) -> None:
        for comment in ('<!-- "', '--> "', '#!/usr/bin/env node "'):
            for source, expected in (
                ("import './hidden.mjs';", ("./hidden.mjs", True, "import")),
                ("import('./hidden.mjs');", ("./hidden.mjs", True, "import")),
                ("import {createRequire} from 'node:module'; const r=createRequire(import.meta.url); r('./hidden.cjs');", ("./hidden.cjs", True, "require")),
                ("new Worker(new URL('./hidden.mjs', import.meta.url));", ("./hidden.mjs", True, "import")),
            ):
                with self.subTest(comment=comment, source=source):
                    self.assertIn(expected, CONTRACT.import_specifiers(comment + "\n" + source + '\n// "'))
            with self.subTest(comment=comment, evaluated=True):
                self.assert_closed(comment + '\neval("hidden");\n// "')

    def test_inert_source_text_does_not_create_dependencies_or_capabilities(self) -> None:
        for literal in (
            '"new Worker(new URL(\'./ghost.mjs\', import.meta.url));"',
            '"require(\'./ghost.cjs\'); cp.exec(\'hidden\');"',
            "`new Worker(new URL('./ghost.mjs', import.meta.url));`",
            "/[/*\"'`]/", "/require('ghost')/", "'<!-- \"'", "'--> \"'", "'#! \"'",
        ):
            with self.subTest(literal=literal):
                self.assertEqual([], CONTRACT.import_specifiers("const inert=" + literal + ";"))

    def test_regex_literal_after_extends_does_not_hide_later_require(self) -> None:
        source = "class A extends /\"/.source {} require('./hidden.cjs'); // \""
        self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers("class A extends /\"/.constructor {} require('./hidden.cjs'); // \"")

    def test_regex_literal_after_export_default_does_not_hide_later_import(self) -> None:
        source = "export default /\"/; await import('./hidden.mjs'); // \""
        self.assertIn(("./hidden.mjs", True, "import"), CONTRACT.import_specifiers(source))

    def test_jsx_text_quotes_fail_closed_instead_of_hiding_imports(self) -> None:
        for source in (
            'const view = <div>"</div>; await import("./hidden.mjs"); // "',
            'const view = <><p>"</p>{require("./hidden.cjs")}</>; // "',
            'let value\n<div>"{require("./hidden.cjs")}</div>; // "',
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_attribute_free_intrinsic_jsx_still_preserves_following_imports(self) -> None:
        for tag in ("<div/>", "<div />", "<span\n/>", "<custom-element />"):
            with self.subTest(tag=tag):
                source = f"export const View = () => {tag}; require('./hidden.cjs');"
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_unresolved_computed_function_constructor_access_fails_closed(self) -> None:
        padded_process_env_reassignment = (
            "process.env=()=>{};\n"
            + "/*"
            + ("x" * 320)
            + "*/\n"
            + "const key='constructor';"
        )
        process_env_computed_accesses = (
            "process.env[key]",
            "(process.env)[key]",
            "((process.env))[key]",
            "process . env[key]",
            "process/*c*/.env[key]",
            "process['env'][key]",
            "process?.env[key]",
            "process?.['env'][key]",
            "global.process.env[key]",
            "globalThis.process.env[key]",
        )
        for source in (
            "const member='constructor'; const build=(()=>{})[member]; build(\"return import('./hidden.mjs')\")();",
            "const member='constructor'; const build=(function(){})[member]; build(\"return require('./hidden.cjs')\")();",
            "const member='constructor'; const build=(class {})[member]; build(\"return import('./hidden.mjs')\")();",
            "const build=(()=>{})['constructor']; build(\"return import('./hidden.mjs')\")();",
            "var let=()=>{}; const build=let['constructor']; build(\"return import('./hidden.mjs')\")();",
            "process.env=()=>{}; const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "(process.env)=()=>{}; const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "((process.env))=()=>{}; const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "({env:process.env}={env:()=>{}}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "[process.env]=[()=>{}]; const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "({nested:{env:process.env}}={nested:{env:()=>{}}}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "for (process.env of [()=>{}]) {} const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "for ((process.env) of [()=>{}]) {} const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "for ([process.env] of [[()=>{}]]) {} const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "for ({env:process.env} of [{env:()=>{}}]) {} const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "Object.setPrototypeOf(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "Reflect.setPrototypeOf(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "Object.setPrototypeOf?.(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "Reflect.setPrototypeOf?.(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "const name='setPrototypeOf'; Object[name](process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "const name='setPrototypeOf'; Reflect[name](process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "const set=Object.setPrototypeOf; set(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "let set; set=Object.setPrototypeOf; set(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "let set; ({setPrototypeOf:set}=Object); set(process.env,()=>{}); const key='constructor'; const build=process.env[key]; build(\"return import('./hidden.mjs')\")();",
            "const key='constructor'; const f=Math.max; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const key='constructor'; const build=Math.max[key]; build(\"return import('./hidden.mjs')\")();",
            "const {max:f}=Math; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {'max':f}=Math; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {'max':f}=Math; const build=f['constructor']; build(\"return import('./hidden.mjs')\")();",
            "const {['max']:f}=Math; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const name='max'; const {[name]:f}=Math; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "let f; ({max:f}=Math); const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {assign:f}=Object; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {'assign':f}=Object; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {['assign']:f}=Object; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {setPrototypeOf:f}=Reflect; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const f=Math.max.bind(null); const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const f=Object.assign.bind(Object); const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "import f from './dep.mjs'; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "import {make as f} from './dep.mjs'; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "import * as f from './dep.mjs'; const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const f=require('./dep.cjs'); const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            "const {make:f}=require('./dep.cjs'); const key='constructor'; const build=f[key]; build(\"return import('./hidden.mjs')\")();",
            *(
                padded_process_env_reassignment
                + f" const build={access}; build(\"return import('./hidden.mjs')\")();"
                for access in process_env_computed_accesses
            ),
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_function_like_receiver_bindings_fail_closed_beyond_local_window(self) -> None:
        padding = "\n".join(f"const harmless{i} = {i};" for i in range(40))
        for declaration in (
            "function f(){}",
            "async function f(){}",
            "function* f(){}",
            "class f {}",
            "const f = function(){};",
            "let f = class {};",
            "var f = () => true;",
            "let f; f = async () => true;",
        ):
            source = (
                f"{declaration}\n"
                f"{padding}\n"
                "const key='constructor'; "
                "const build=f[key]; "
                "build(\"return import('./hidden.mjs')\")();"
            )
            with self.subTest(declaration=declaration):
                self.assert_closed(source)

    def test_aliased_process_env_prototype_mutators_fail_closed(self) -> None:
        for alias_assignment in (
            "const set=Object.setPrototypeOf;",
            'const set=Object["setPrototypeOf"];',
            "const set=Reflect?.setPrototypeOf;",
            'const set=Reflect["setPrototypeOf"];',
            "let set=Object.setPrototypeOf;",
            "var set=Reflect.setPrototypeOf;",
            "let set; set=Object.setPrototypeOf;",
            "var set; set=Reflect.setPrototypeOf;",
            "let set; ({{setPrototypeOf:set}}=Object);",
            "let set; ({{'setPrototypeOf':set}}=Object);",
            "let set; ({{['setPrototypeOf']:set}}=Object);",
            "let set; ({{[`setPrototypeOf`]:set}}=Reflect);",
            "let name='setPrototypeOf', set; ({{[name]:set}}=Object);",
        ):
            source = (
                f"{alias_assignment} "
                "{call} "
                "const key='constructor'; "
                "const build=process.env[key]; "
                "build(\"return import('./hidden.mjs')\")();"
            )
            for call in (
                "set(process.env,()=>{});",
                "set?.(process.env,()=>{});",
                "set.call(null, process.env,()=>{});",
                "set.apply(null, [process.env,()=>{}]);",
                "set.bind(null, process.env,()=>{})();",
            ):
                with self.subTest(alias_assignment=alias_assignment, call=call):
                    self.assert_closed(source.format(call=call))

    def test_dynamic_process_env_prototype_mutator_callees_fail_closed(self) -> None:
        long_trivia = "/*" + ("x" * 640) + "*/"
        for callee in (
            "Object[name]",
            "Reflect[name]",
            "(Object)[name]",
            "(Reflect)[name]",
            "((Object))[name]",
            "((Reflect))[name]",
            "Object?.[name]",
            "Reflect?.[name]",
            "(Object)?.[name]",
            "(Reflect)?.[name]",
            "((Object))?.[name]",
            "((Reflect))?.[name]",
            "(Object[name])",
            "(Reflect[name])",
            "((Object)[name])",
            "((Reflect)[name])",
            "((Object)?.[name])",
            "((Reflect)?.[name])",
            "Object/*c*/[name]",
            "Reflect /*c*/ [name]",
            f"Object{long_trivia}[name]",
            f"Reflect{long_trivia}[name]",
            f"(Object{long_trivia})[name]",
            f"(Reflect{long_trivia})[name]",
            f"((Object){long_trivia})[name]",
            f"((Reflect){long_trivia})[name]",
            f"(Object{long_trivia}[name])",
            f"(Reflect{long_trivia}[name])",
            f"((Object){long_trivia}[name])",
            f"((Reflect){long_trivia}[name])",
            f"Object?.[{long_trivia}name]",
            f"Reflect?.[{long_trivia}name]",
            f"(Object)?.[{long_trivia}name]",
            f"(Reflect)?.[{long_trivia}name]",
            f"(Object?.[{long_trivia}name])",
            f"(Reflect?.[{long_trivia}name])",
        ):
            for call_operator in ("", "?."):
                source = (
                    "const name='setPrototypeOf'; "
                    f"{callee}{call_operator}(process.env,()=>{{}}); "
                    "const key='constructor'; "
                    "const build=process.env[key]; "
                    "build(\"return import('./hidden.mjs')\")();"
                )
                with self.subTest(callee=callee, call_operator=call_operator):
                    self.assert_closed(source)

    def test_process_env_computed_lookup_does_not_inherit_function_window_risk(self) -> None:
        for access in (
            "process.env[key]",
            "(process.env)[key]",
            "((process.env))[key]",
            "process . env[key]",
            "process/*c*/.env[key]",
            "process['env'][key]",
            "process?.env[key]",
            "process?.['env'][key]",
            "global.process.env[key]",
            "globalThis.process.env[key]",
        ):
            source = (
                "const f = () => true;\n"
                "const snapshot = { env: process.env };\n"
                "const key = 'OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED';\n"
                f"if ({access} === '1') {{ await import('./entry.mjs'); }}\n"
            )
            with self.subTest(access=access):
                self.assertIn(
                    ("./entry.mjs", True, "import"),
                    CONTRACT.import_specifiers(source),
                )

    def test_static_process_env_prototype_mutator_callee_variants_fail_closed(self) -> None:
        for callee in (
            "(Object).setPrototypeOf",
            "(Reflect).setPrototypeOf",
            "((Object)).setPrototypeOf",
            "((Reflect)).setPrototypeOf",
            "(Object.setPrototypeOf)",
            "(Reflect.setPrototypeOf)",
            "((Object).setPrototypeOf)",
            "((Reflect).setPrototypeOf)",
            'Object["setPrototypeOf"]',
            'Reflect["setPrototypeOf"]',
            '(Object)["setPrototypeOf"]',
            '(Reflect)["setPrototypeOf"]',
            '(Object["setPrototypeOf"])',
            '(Reflect["setPrototypeOf"])',
            '((Object)["setPrototypeOf"])',
            '((Reflect)["setPrototypeOf"])',
            "Object?.setPrototypeOf",
            "Reflect?.setPrototypeOf",
            "(Object)?.setPrototypeOf",
            "(Reflect)?.setPrototypeOf",
            "(Object?.setPrototypeOf)",
            "(Reflect?.setPrototypeOf)",
        ):
            source = (
                f"{callee}(process.env,()=>{{}}); "
                "const key='constructor'; "
                "const build=process.env[key]; "
                "build(\"return import('./hidden.mjs')\")();"
            )
            with self.subTest(callee=callee):
                self.assert_closed(source)

    def test_indirect_process_env_prototype_mutator_invocations_fail_closed(self) -> None:
        for call in (
            "Object.setPrototypeOf.call(null, process.env,()=>{});",
            "Reflect.setPrototypeOf.call(null, process.env,()=>{});",
            "Object.setPrototypeOf.apply(null, [process.env,()=>{}]);",
            "Reflect.setPrototypeOf.apply(null, [process.env,()=>{}]);",
            "Object.setPrototypeOf.bind(null, process.env,()=>{})();",
            "Reflect.setPrototypeOf.bind(null, process.env,()=>{})();",
        ):
            source = (
                f"{call} "
                "const key='constructor'; "
                "const build=process.env[key]; "
                "build(\"return import('./hidden.mjs')\")();"
            )
            with self.subTest(call=call):
                self.assert_closed(source)

    def test_process_env_prototype_mutator_detection_preserves_safe_controls(self) -> None:
        long_trivia = "/*" + ("x" * 640) + "*/"
        for source in (
            "Object.assign(process.env,{}); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            f"Object{long_trivia}[\"assign\"](process.env,{{}}); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            'Object["assign"](process.env,{}); '
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            'Object["setPrototypeOf"]({}, process.env); '
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            "Reflect?.setPrototypeOf({}, process.env); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            "const set=Object.assign; set(process.env,{}); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            "const set=Object.setPrototypeOf; set({}, process.env); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
            "const name='setPrototypeOf'; Object[name]({}, process.env); "
            "const key='OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED'; "
            "if (process.env[key] === '1') { await import('./entry.mjs'); }",
        ):
            with self.subTest(source=source):
                self.assertIn(
                    ("./entry.mjs", True, "import"),
                    CONTRACT.import_specifiers(source),
                )

    def test_grouped_control_condition_does_not_become_prototype_mutator_call(self) -> None:
        long_trivia = "/*" + ("x" * 640) + "*/"
        source = (
            f"if (Object.setPrototypeOf) (process.env,Object); {long_trivia}"
            "const key='con'+'structor'; process.env[key];"
        )
        self.assertEqual([], CONTRACT.import_specifiers(source))

    def test_unresolved_computed_member_scan_is_local_to_receiver(self) -> None:
        source = " ".join(f"value{i}[key]" for i in range(5000))
        bracket_index = source.rfind("[")
        start = time.perf_counter()

        self.assertIsNone(
            CONTRACT._computed_member_process_env_target_start(source, bracket_index)
        )

        self.assertLess(time.perf_counter() - start, 1.0)

    def test_process_env_for_of_reads_do_not_become_reassignments(self) -> None:
        source = (
            "const f = () => true;\n"
            "for (const env of [process.env]) { String(env.OPENCLAW_MODE); }\n"
            "const key = 'OPENCLAW_COMPILE_CACHE_DISABLED_RESPAWNED';\n"
            "if (process.env[key] === '1') { await import('./entry.mjs'); }\n"
        )
        self.assertIn(("./entry.mjs", True, "import"), CONTRACT.import_specifiers(source))

    def test_array_destructuring_after_declaration_is_not_computed_member_access(self) -> None:
        source = (
            "const parse = (raw) => {\n"
            "  const [major = '0', minor = '0'] = raw.split('.');\n"
            "  return major + minor;\n"
            "};\n"
            "await import('./entry.mjs');\n"
        )
        self.assertIn(("./entry.mjs", True, "import"), CONTRACT.import_specifiers(source))

    def test_let_array_declaration_is_not_computed_member_access(self) -> None:
        for source in (
            "const f=()=>true; let [value]=['x']; await import('./entry.mjs');",
            "for (let [value] of [['x']]) { String(value); } await import('./entry.mjs');",
        ):
            with self.subTest(source=source):
                self.assertIn(
                    ("./entry.mjs", True, "import"),
                    CONTRACT.import_specifiers(source),
                )

    def test_sloppy_identifier_named_let_still_can_be_computed_member_target(
        self,
    ) -> None:
        source = (
            "var let=()=>{}; "
            "const member='constructor'; "
            "const build=let[member]; "
            "build(\"return import('./hidden.mjs')\")();"
        )
        self.assert_closed(source)

    def test_numeric_computed_index_does_not_inherit_function_window_risk(self) -> None:
        source = (
            "const isRelay = (argv) => argv[2] === 'hooks' && argv[3] === 'relay';\n"
            "if (isRelay(process.argv)) { await import('./entry.mjs'); }\n"
        )
        self.assertIn(("./entry.mjs", True, "import"), CONTRACT.import_specifiers(source))

    def test_array_literal_after_for_of_is_not_computed_member_access(self) -> None:
        source = (
            "const install = async () => {\n"
            "  for (const specifier of ['./a.mjs', './b.mjs']) { String(specifier); }\n"
            "};\n"
            "await import('./entry.mjs');\n"
        )
        self.assertIn(("./entry.mjs", True, "import"), CONTRACT.import_specifiers(source))

    def test_package_exports_reject_targets_that_escape_before_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import 'pkg';", {
                "decoy.mjs": "export const decoy = true;",
                "node_modules/pkg/package.json": '{"name":"pkg","exports":["./../decoy.mjs","./hidden.mjs"]}',
                "node_modules/pkg/hidden.mjs": "export const hidden = true;",
            })
            with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "unsupported path segment"):
                CONTRACT.runtime_source_paths(root)

    def test_package_imports_reject_targets_that_escape_before_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import '#pkg';", {
                "scripts/package.json": '{"imports":{"#pkg":["./../decoy.mjs","./hidden.mjs"]}}',
                "decoy.mjs": "export const decoy = true;",
                "scripts/hidden.mjs": "export const hidden = true;",
            })
            with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "unsupported path segment"):
                CONTRACT.runtime_source_paths(root)

    def test_runtime_default_import_named_type_is_a_value_binding(self) -> None:
        for source in (
            "import type from 'node:worker_threads'; const W = type.Worker; new W('./hidden.mjs');",
            "import type, {isMainThread} from 'node:worker_threads'; const W = type.Worker; void isMainThread;",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_type_references_do_not_create_capability_false_positives(self) -> None:
        for use in (
            "let worker:Worker;",
            "const worker:Worker|null=null;",
            "function f(worker:Worker){}",
            "const f=(worker:Worker)=>{};",
            "const worker=other as Worker;",
            "type W=Array<Worker>;",
            "type W={worker:Worker};",
            "type W=(worker:Worker)=>void;",
        ):
            with self.subTest(use=use):
                CONTRACT.import_specifiers("import {type Worker} from 'node:worker_threads';" + use)

    def test_declaration_asi_before_slash_fails_closed_or_binds_following_load(self) -> None:
        for prefix in ("var value\n", "let value\n", "type Value=string\n"):
            with self.subTest(prefix=prefix):
                try:
                    imports = CONTRACT.import_specifiers(prefix + '/"/;require("./hidden.cjs"); // "')
                except CONTRACT.RuntimeSourceContractError:
                    continue
                self.assertIn(("./hidden.cjs", True, "require"), imports)

    def test_private_identifier_keyword_does_not_hide_division_dependency(self) -> None:
        source = (
            "class Box { #return = 1; get(other) { "
            "return other.#return / require('./hidden.cjs'); } }"
        )
        self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_module_namespace_and_runtime_loader_origins_cannot_transfer(self) -> None:
        for source in (
            "import * as M from 'node:module'; const C = M; new C().load('./hidden.cjs');",
            "import M from 'node:module'; const box = {M}; new box.M().load('./hidden.cjs');",
            "const M = require('node:module'); const C = M; new C().load('./hidden.cjs');",
            "import {runMain as go} from 'node:module'; const f = go; f('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_node_modules_package_lookup_skips_node_modules_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import '../node_modules/host/main.cjs';", {
                "node_modules/host/main.cjs": "module.exports = require('p');",
                "node_modules/node_modules/p/package.json": '{"name":"p","main":"decoy.cjs"}',
                "node_modules/node_modules/p/decoy.cjs": "module.exports = 'decoy';",
                "node_modules/p/package.json": '{"name":"p","main":"real.cjs"}',
                "node_modules/p/real.cjs": "module.exports = 'real';",
            })
            paths = CONTRACT.runtime_source_paths(root)

        self.assertIn("node_modules/p/real.cjs", paths)
        self.assertNotIn("node_modules/node_modules/p/decoy.cjs", paths)

    def test_nearest_manifest_without_imports_does_not_inherit_outer_imports_map(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import '#hidden';", {
                "package.json": '{"imports":{"#hidden":"./decoy.mjs"}}',
                "decoy.mjs": "export {};",
                "scripts/package.json": '{"name":"inner"}',
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_invalid_controlling_manifest_fails_even_without_package_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "export const ok = 1;", {
                "scripts/package.json": '{"name":NaN}',
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_url_metaobject_mutation_in_transitive_module_closes_worker_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, (
                "import './mutator.mjs';"
                "import {Worker} from 'node:worker_threads';"
                "new Worker(new URL('./bound.mjs', import.meta.url));"
            ), {
                "scripts/bound.mjs": "export {};",
                "scripts/mutator.mjs": (
                    "import {pathToFileURL as file} from 'node:url';"
                    "Object.setPrototypeOf(file('/tmp/x'), URL.prototype);"
                ),
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_supported_url_bases_still_bind_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, (
                "import {Worker} from 'node:worker_threads';"
                "new Worker(new URL('./bound.mjs', import.meta.url));"
            ), {
                "scripts/bound.mjs": "export {};",
            })
            self.assertIn("scripts/bound.mjs", CONTRACT.runtime_source_paths(root))

    def test_nested_templates_and_regex_braces_do_not_hide_dependencies(self) -> None:
        sources = (
            "`${ /}/.test('}') && `${require('./hidden.cjs')}` }`;",
            "`${ `inner ${require('./hidden.cjs')}` }`;",
            "`${ /* } ` */ require('./hidden.cjs') }`;",
            "`${ // ` }\n require('./hidden.cjs') }`;",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_division_after_identifiers_and_postfix_operators_is_not_a_regex(self) -> None:
        for prefix in ("const of=1; of", "const x=1; x++", "const x=1; x--", "const x={of:1}; x.of", "const x={default:1}; x.default"):
            with self.subTest(prefix=prefix):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(prefix + " / require('./hidden.cjs');"))

    def test_computed_entrypoints_and_startup_options_fail_closed(self) -> None:
        for source in (
            "import {fork} from 'node:child_process'; fork('./bound.cjs' + suffix);",
            "import {fork} from 'node:child_process'; fork('./bound.cjs', {execArgv: ['--import','./hidden.mjs']});",
            "import {fork} from 'node:child_process'; fork('./bound.cjs', [], {execPath:'./hidden'});",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./bound.mjs' + suffix]);",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./bound.mjs'], {shell:true});",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./bound.mjs'], {env:{NODE_OPTIONS:'--import ./hidden.mjs'}});",
            "new Worker(new URL('./bound.mjs', import.meta.url), {execArgv:['--import','./hidden.mjs']});",
            "new Worker(new URL('./bound.mjs', import.meta.url), {eval:true});",
            "process.chdir('./elsewhere');",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_literal_for_of_dynamic_imports_fail_closed(self) -> None:
        sources = (
            "for (const specifier of ['./dist/warning-filter.js']) { await import(specifier); }",
            (
                "for (let specifier of ['./dist/warning-filter.js']) {"
                "  specifier = attackerValue; await import(specifier);"
                "}"
            ),
            (
                "Array.prototype[Symbol.iterator] = function* () { yield attackerValue; };"
                "for (const specifier of ['./dist/warning-filter.js']) { await import(specifier); }"
            ),
            (
                "const specifier = getUserInput();"
                "const marker = \"for (const specifier of ['./dist/warning-filter.js']) {\";"
                "await import(specifier);"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_are_source_bound(self) -> None:
        source = (
            "const tryImport = async (specifier) => {"
            "  try { await import(specifier); return true; }"
            "  catch (err) { return false; }"
            "};"
            "if (await tryImport('./dist/entry.js')) {}"
            "else if (await tryImport('./dist/entry.mjs')) {}"
        )
        self.assertEqual(
            [
                ("./dist/entry.js", True, "import"),
                ("./dist/entry.mjs", True, "import"),
            ],
            CONTRACT.import_specifiers(source),
        )

    def test_literal_forwarded_dynamic_imports_reject_nonliteral_uses(self) -> None:
        source = (
            "const tryImport = async (specifier) => { await import(specifier); };"
            "const escaped = tryImport;"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_mutated_parameter(self) -> None:
        sources = (
            (
                "const tryImport = async (specifier) => {"
                "  specifier = attackerValue; await import(specifier);"
                "};"
                "await tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => {"
                "  const specifier = attackerValue; await import(specifier);"
                "};"
                "await tryImport('./dist/entry.js');"
            ),
            (
                "const marker = \"const tryImport = async (specifier) => {\";"
                "const specifier = getUserInput();"
                "await import(specifier);"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_with_shadowed_parameter(self) -> None:
        source = (
            "const tryImport = async (specifier) => {"
            "  with (scope) { await import(specifier); }"
            "};"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_body_self_reference(self) -> None:
        sources = (
            (
                "const tryImport = async (specifier) => {"
                "  await import(specifier);"
                "  queueMicrotask(() => tryImport(attackerValue));"
                "};"
                "await tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => {"
                "  await import(specifier);"
                "  return tryImport;"
                "};"
                "await tryImport('./dist/entry.js');"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_predeclaration_escape(self) -> None:
        source = (
            "queueMicrotask(() => tryImport(attackerValue));"
            "const tryImport = async (specifier) => { await import(specifier); };"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_with_scoped_call_site(self) -> None:
        sources = (
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) { await tryImport('./dist/entry.js'); }"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) /* comment */ tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) await tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) for (let i = 0; i < 1; i++) "
                "await tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) if (false) noop(); else tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) label: if (false) noop(); else tryImport('./dist/entry.js');"
            ),
            (
                "const tryImport = async (specifier) => { await import(specifier); };"
                "with (scope) x = {a: 1}, tryImport('./dist/entry.js');"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_out_of_scope_calls(self) -> None:
        source = (
            "{"
            "  const tryImport = async (specifier) => { await import(specifier); };"
            "}"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_for_initializer_scope_escape(self) -> None:
        source = (
            "for (const tryImport = async (specifier) => { await import(specifier); }; false;) {}"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_accept_direct_for_initializer_calls(self) -> None:
        source = (
            "for (const tryImport = async (specifier) => { await import(specifier); }; false;) {"
            "  await tryImport('./dist/entry.js');"
            "}"
        )
        self.assertEqual(
            [("./dist/entry.js", True, "import")],
            CONTRACT.import_specifiers(source),
        )

    def test_literal_forwarded_dynamic_imports_reject_nested_for_initializer_scope_escape(self) -> None:
        source = (
            "for (let x = (() => {"
            "  const tryImport = async (specifier) => { await import(specifier); };"
            "  return 0;"
            "})(); x === 0; x++) {"
            "  await tryImport('./dist/entry.js');"
            "}"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_do_not_treat_property_for_as_loop(self) -> None:
        source = (
            "obj.for(() => {"
            "  const tryImport = async (specifier) => { await import(specifier); };"
            "}), await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_literal_forwarded_dynamic_imports_reject_in_scope_helper_escape(self) -> None:
        source = (
            "const tryImport = async (specifier) => { await import(specifier); };"
            "{ const escaped = tryImport; }"
            "await tryImport('./dist/entry.js');"
        )
        self.assert_closed(source)

    def test_downstream_launcher_dynamic_imports_fail_closed_on_for_of_boundary(self) -> None:
        source = (
            "const installProcessWarningFilter = async () => {"
            "  for (const specifier of ['./dist/warning-filter.js', './dist/warning-filter.mjs']) {"
            "    try { const mod = await import(specifier); void mod; } catch (err) {}"
            "  }"
            "};"
            "const tryImport = async (specifier) => {"
            "  try { await import(specifier); return true; }"
            "  catch (err) { return false; }"
            "};"
            "await installProcessWarningFilter();"
            "if (await tryImport('./dist/entry.js')) {}"
            "else if (await tryImport('./dist/entry.mjs')) {}"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, source)
            with self.assertRaisesRegex(
                CONTRACT.RuntimeSourceContractError,
                "unsupported dynamic import",
            ):
                CONTRACT.runtime_source_paths(root)

    def test_literal_process_arguments_remain_supported(self) -> None:
        for source, import_kind in (
            ("import {fork} from 'node:child_process'; fork('./bound.cjs', ['a','b',]);", "fork"),
            ("import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./bound.cjs','a','b',]);", "spawn"),
        ):
            with self.subTest(source=source):
                self.assertIn(("./bound.cjs", True, import_kind), CONTRACT.import_specifiers(source))

    def test_process_script_resolution_uses_launch_cwd_not_importer_directory(self) -> None:
        for launch in (
            "import {fork} from 'node:child_process'; fork('./entry.cjs');",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./entry.cjs']);",
        ):
            with self.subTest(launch=launch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, launch, {"entry.cjs": "module.exports=1;", "scripts/entry.cjs": "module.exports=2;"})
                paths = CONTRACT.runtime_source_paths(root)
                self.assertIn("entry.cjs", paths)
                self.assertNotIn("scripts/entry.cjs", paths)

    def test_relative_source_controlling_package_manifest_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import '../node_modules/pkg/sub/file.js';", {
                "node_modules/pkg/package.json": '{"name":"pkg"}',
                "node_modules/pkg/sub/package.json": '{"type":"module"}',
                "node_modules/pkg/sub/file.js": "console.log(typeof require);",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            manifest = "node_modules/pkg/sub/package.json"
            self.assertIn(manifest, before)
            (root / manifest).write_text('{"type":"commonjs"}')
            after = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertNotEqual(before, after)
            self.assertNotEqual(before[manifest], after[manifest])
            self.assertEqual(before["node_modules/pkg/sub/file.js"], after["node_modules/pkg/sub/file.js"])

    def test_new_or_removed_entrypoint_scope_changes_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "export const ok=1;")
            before = CONTRACT.runtime_source_digest_snapshot(root)
            (root / "scripts/package.json").write_text('{"type":"module"}')
            after = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("scripts/package.json", after)
            self.assertNotEqual(before, after)
            (root / "scripts/package.json").unlink()
            self.assertEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_package_scope_symlink_cannot_escape_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self.fixture(root, "export const ok=1;")
            external = Path(outside) / "package.json"
            external.write_text('{"type":"module"}')
            (root / "scripts/package.json").symlink_to(external)
            with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "escapes"):
                CONTRACT.runtime_source_digest_snapshot(root)

    def test_nearest_package_scope_blocks_outer_self_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import 'outer';", {
                "package.json": '{"name":"outer","type":"module","exports":"./root-decoy.mjs"}',
                "root-decoy.mjs": "export const selected = 'root-decoy';",
                "scripts/package.json": '{"name":"inner","type":"module"}',
                "node_modules/outer/package.json": '{"name":"outer","type":"module","exports":"./actual.mjs"}',
                "node_modules/outer/actual.mjs": "export const selected = 'installed-actual';",
            })

            paths = CONTRACT.runtime_source_paths(root)

        self.assertIn("node_modules/outer/actual.mjs", paths)
        self.assertNotIn("root-decoy.mjs", paths)

    @unittest.skipUnless(NODE, "Node is required for independent execution witnesses")
    def test_node_reproduces_rejected_capability_transfers(self) -> None:
        cases = (
            ("mjs", "import {Worker} from 'node:worker_threads'; const W=Worker; new W(new URL('./hidden.mjs', import.meta.url));"),
            ("mjs", "import * as cp from 'node:child_process'; const go=cp['spawnSync']; const c=go(process.execPath, ['./hidden.mjs']); process.stdout.write(c.stdout);"),
            ("cjs", "const r=((require)); r('./hidden.cjs');"),
        )
        for extension, source in cases:
            with self.subTest(extension=extension, source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                entry = root / f"entry.{extension}"
                entry.write_text(source)
                for suffix in ("cjs", "mjs"):
                    (root / f"hidden.{suffix}").write_text("console.log('executed');")
                env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual("executed", result.stdout.strip())
                self.assert_closed(source)

    @unittest.skipUnless(NODE, "Node is required for the package self-reference witness")
    def test_node_nested_scope_resolves_bare_package_from_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import 'outer';", {
                "package.json": '{"name":"outer","type":"module","exports":"./root-decoy.mjs"}',
                "root-decoy.mjs": "console.log('root-decoy');",
                "scripts/package.json": '{"name":"inner","type":"module"}',
                "node_modules/outer/package.json": '{"name":"outer","type":"module","exports":"./actual.mjs"}',
                "node_modules/outer/actual.mjs": "console.log('installed-actual');",
            })
            entry = root / CONTRACT.PERSISTENT_LIFECYCLE_RUNNER
            env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
            result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)

            self.assertEqual("installed-actual", result.stdout.strip())
            paths = CONTRACT.runtime_source_paths(root)
            self.assertIn("node_modules/outer/actual.mjs", paths)
            self.assertNotIn("root-decoy.mjs", paths)

    @unittest.skipUnless(NODE, "Node is required for the working-directory witness")
    def test_node_process_entrypoint_is_resolved_from_launch_working_directory(self) -> None:
        for source in (
            "import {fork} from 'node:child_process'; fork('./entry.cjs');",
            "import {spawnSync} from 'node:child_process'; const c=spawnSync(process.execPath, ['./entry.cjs']); process.stdout.write(c.stdout);",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, source, {
                    "scripts/main.mjs": source,
                    "entry.cjs": "console.log('cwd-root');",
                    "scripts/entry.cjs": "console.log('importer-decoy');",
                })
                env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                result = subprocess.run([NODE, str(root / "scripts/main.mjs")], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual("cwd-root", result.stdout.strip())
                paths = CONTRACT.runtime_source_paths(root)
                self.assertIn("entry.cjs", paths)
                self.assertNotIn("scripts/entry.cjs", paths)

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_executes_dependencies_after_annex_b_comments_and_hashbang(self) -> None:
        for comment in ('<!-- "', '--> "', '#!/usr/bin/env node "'):
            with self.subTest(comment=comment), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                entry = root / "entry.cjs"
                entry.write_text(comment + '\nrequire("./hidden.cjs");\n// "')
                (root / "hidden.cjs").write_text("console.log('executed');")
                env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual("executed", result.stdout.strip())
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(entry.read_text()))

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_scope_type_change_alters_execution_and_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "import './scope/file.js';", {
                "scripts/scope/package.json": '{"type":"module"}',
                "scripts/scope/file.js": "console.log(typeof require);",
            })
            entry = root / "scripts/scope/file.js"
            env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
            before = CONTRACT.runtime_source_digest_snapshot(root)
            first = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
            (entry.parent / "package.json").write_text('{"type":"commonjs"}')
            second = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual("undefined", first.stdout.strip())
            self.assertEqual("function", second.stdout.strip())
            self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_dynamic_function_constructor_executes_hidden_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / "entry.mjs"
            entry.write_text(
                "const member='constructor';\n"
                "const build=(()=>{})[member];\n"
                "await build(\"return import('./hidden.mjs')\")();\n",
                encoding="utf-8",
            )
            (root / "hidden.mjs").write_text("console.log('executed');\n", encoding="utf-8")
            env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
            result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual("executed", result.stdout.strip())
            self.assert_closed(entry.read_text(encoding="utf-8"))

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_destructured_builtin_function_alias_executes_hidden_import(self) -> None:
        witnesses = (
            "const {max:f}=Math;\n",
            "const {'max':f}=Math;\n",
            "const {['max']:f}=Math;\n",
            "const {assign:f}=Object;\n",
            "const {'assign':f}=Object;\n",
            "const f=Math.max.bind(null);\n",
        )
        for declaration in witnesses:
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    entry = root / "entry.mjs"
                    entry.write_text(
                        declaration
                        + "const member='constructor';\n"
                        + "const build=f[member];\n"
                        + "await build(\"return import('./hidden.mjs')\")();\n",
                        encoding="utf-8",
                    )
                    (root / "hidden.mjs").write_text("console.log('executed');\n", encoding="utf-8")
                    env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                    result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                    self.assertEqual("executed", result.stdout.strip())
                    self.assert_closed(entry.read_text(encoding="utf-8"))

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_grouped_dynamic_process_env_prototype_mutator_exposes_constructor(
        self,
    ) -> None:
        long_trivia = "/*" + ("x" * 640) + "*/"
        witnesses = (
            f"const name='setPrototypeOf';\n(Object{long_trivia})[name](process.env,()=>{{}});\n",
            f"const name='setPrototypeOf';\n((Object){long_trivia})?.[name]?.(process.env,()=>{{}});\n",
            "const name='setPrototypeOf';\n(Object.setPrototypeOf)(process.env,()=>{});\n",
            f"const name='setPrototypeOf';\n(Object{long_trivia}[name])(process.env,()=>{{}});\n",
            f"const name='setPrototypeOf';\n(Reflect?.[{long_trivia}name])?.(process.env,()=>{{}});\n",
        )
        for declaration in witnesses:
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    entry = root / "entry.mjs"
                    entry.write_text(
                        declaration
                        + "const member='constructor';\n"
                        + "const build=process.env[member];\n"
                        + "await build(\"return import('./hidden.mjs')\")();\n",
                        encoding="utf-8",
                    )
                    (root / "hidden.mjs").write_text("console.log('executed');\n", encoding="utf-8")
                    env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                    result = subprocess.run([NODE, str(entry)], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                    self.assertEqual("executed", result.stdout.strip())
                    self.assert_closed(entry.read_text(encoding="utf-8"))


class RuntimePreloadRegressionTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        tsx = root / "node_modules/tsx"
        helper = root / "node_modules/helper"
        tsx.mkdir(parents=True)
        helper.mkdir(parents=True)
        (tsx / "package.json").write_text('{"name":"tsx","type":"module","exports":"./loader.mjs"}')
        (tsx / "loader.mjs").write_text("import 'helper';")
        (helper / "package.json").write_text('{"name":"helper","type":"module","exports":"./index.mjs"}')
        (helper / "index.mjs").write_text("console.log('first');")
        return tsx / "loader.mjs"

    def test_sibling_package_and_nested_helper_changes_alter_installation_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = self.fixture(root)
            before = PROBE._runtime_installation_binding(root)
            package_before = PROBE._directory_tree_sha256(loader.parent)
            (root / "node_modules/helper/index.mjs").write_text("console.log('second');")
            self.assertNotEqual(before, PROBE._runtime_installation_binding(root))
            self.assertEqual(package_before, PROBE._directory_tree_sha256(loader.parent))
            self.assertNotIn(str(root), json.dumps(PROBE._runtime_installation_binding(root)))

    def test_internal_pnpm_links_bind_both_target_bytes_and_link_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "node_modules/.pnpm/helper/node_modules/helper"
            store.mkdir(parents=True)
            target = store / "index.mjs"
            target.write_text("export const n=1;")
            link = root / "node_modules/helper"
            link.symlink_to(store, target_is_directory=True)
            before = PROBE._runtime_installation_binding(root)
            target.write_text("export const n=2;")
            after = PROBE._runtime_installation_binding(root)
            self.assertNotEqual(before, after)
            copy = root / "node_modules/copy"
            shutil.copytree(store, copy)
            before = PROBE._runtime_installation_binding(root)
            link.unlink()
            link.symlink_to(copy, target_is_directory=True)
            self.assertNotEqual(before, PROBE._runtime_installation_binding(root))

    def test_external_or_dangling_links_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = Path(outside) / "helper.mjs"
            target.write_text("export const n=1;")
            link = root / "helper.mjs"
            link.symlink_to(target)
            with self.assertRaisesRegex(PROBE.ProbeError, "escapes"):
                PROBE._runtime_installation_binding(root)
            target.unlink()
            with self.assertRaisesRegex(PROBE.ProbeError, "completely bound"):
                PROBE._runtime_installation_binding(root)

    def test_directory_links_do_not_cause_recursive_walks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "entry.mjs").write_text("export const n=1;")
            (root / "loop").symlink_to(root, target_is_directory=True)
            self.assertEqual(PROBE._runtime_installation_binding(root), PROBE._runtime_installation_binding(root))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX file types")
    def test_non_regular_installation_entries_fail_without_reading_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(PROBE.ProbeError, "file type"):
                PROBE._runtime_installation_binding(root)

    def test_hardlinked_installation_entries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / "entry.mjs"
            entry.write_text("export const n=1;\n")
            os.link(entry, root / "entry-alias.mjs")
            with self.assertRaisesRegex(PROBE.ProbeError, "hardlink"):
                PROBE._runtime_installation_binding(root)

    def test_executable_mode_and_scope_metadata_are_in_installation_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = self.fixture(root)
            before = PROBE._runtime_installation_binding(root)
            loader.chmod(0o700)
            after = PROBE._runtime_installation_binding(root)
            self.assertNotEqual(before, after)
            (root / "node_modules/helper/package.json").write_text('{"type":"commonjs"}')
            self.assertNotEqual(after, PROBE._runtime_installation_binding(root))

    def test_preload_outside_candidate_installation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            loader = self.fixture(Path(outside))
            with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader), mock.patch.object(PROBE.shutil, "which", return_value="/bound/node"):
                with self.assertRaisesRegex(PROBE.ProbeError, "escapes"):
                    PROBE._runtime_launch_bindings(root, {"PATH": "/bound"})

    def test_launch_source_validation_rejects_duplicate_and_incomplete_identity(self) -> None:
        sources = [{"path": label, "sha256": "a" * 64, "realpath_sha256": "b" * 64} for label in PROBE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS]
        self.assertEqual(sources, PROBE._validate_runtime_launch_sources(sources))
        for invalid in (sources[:-1], sources + [sources[0]], sources + [{"path": "unaccounted"}]):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeError):
                PROBE._validate_runtime_launch_sources(invalid)

    @unittest.skipUnless(NODE, "Node is required for the independent preload witness")
    def test_actual_node_preload_sibling_mutation_is_detected_before_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = self.fixture(root)
            env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
            with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                node, preload, sources = PROBE._runtime_launch_bindings(root, env)
                first = subprocess.run([str(node), "--import", preload, "-e", ""], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                (root / "node_modules/helper/index.mjs").write_text("console.log('second');")
                second = subprocess.run([str(node), "--import", preload, "-e", ""], cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual("first", first.stdout.strip())
                self.assertEqual("second", second.stdout.strip())
                with self.assertRaisesRegex(PROBE.ProbeError, "source binding changed"):
                    PROBE._assert_runtime_launch_sources_still_bound(openclaw_root=root, runner_env=env, expected_node_executable=node, expected_tsx_preload_specifier=preload, expected_sources=sources)


if __name__ == "__main__":
    unittest.main()
