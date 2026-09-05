"""Regression matrix for PR45's source/loader closure review boundaries.

The collector supports a conservative source subset, not arbitrary JavaScript
value flow. An unsupported program must fail closed instead of returning a
plausible, incomplete list of dependencies. Positive fixtures guard that this
policy does not accidentally reject supported imports or inert source data.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import agentic_os_runtime_source_contract as contract


PROBE_PATH = Path(__file__).resolve().parents[1] / "scripts/openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("source_boundary_probe", PROBE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
NODE = shutil.which("node")


def write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class RuntimeSourceBoundaryTests(unittest.TestCase):
    def assert_bound(self, source: str, target: str = "./hidden.cjs") -> None:
        self.assertIn(target, {item[0] for item in contract.import_specifiers(source)})

    def assert_closed(self, source: str) -> None:
        with self.assertRaises(contract.RuntimeSourceContractError, msg=source):
            contract.import_specifiers(source)

    def test_worker_value_transfers_are_not_silently_ignored(self) -> None:
        declarations = (
            ("import { Worker } from 'node:worker_threads';", "Worker"),
            ("import { Worker as Native } from 'worker_threads';", "Native"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("import wt, { Worker } from 'node:worker_threads';", "wt['Worker']"),
            ("const {Worker: Native} = require('worker_threads');", "Native"),
            ("const wt = require('node:worker_threads');", "wt.Worker"),
        )
        transfers = (
            "const W = REF;", "let W; W = REF;", "const W = (((REF)));",
            "const W = (0, REF);", "const W = true ? REF : null;",
            "const W = [REF][0];", "const W = {value: REF}.value;",
            "function choose(){return REF;} const W = choose();",
            "const W = REF.bind(null);", "const W = ((v) => v)(REF);",
        )
        for declaration, reference in declarations:
            for transfer in transfers:
                with self.subTest(declaration=declaration, transfer=transfer):
                    self.assert_closed(declaration + transfer.replace("REF", reference)
                                       + "new W(new URL('./hidden.mjs', import.meta.url));")

    def test_child_process_namespace_and_member_transfers_fail_closed(self) -> None:
        declarations = (
            "import * as cp from 'node:child_process';",
            "import cp from 'child_process';",
            "import cp, {spawnSync as other} from 'node:child_process';",
            "const cp = require('child_process');",
        )
        for declaration in declarations:
            for name in ("spawn", "spawnSync", "execFile", "execFileSync", "fork", "exec", "execSync"):
                for member in (f".{name}", f"['{name}']", f'["{name}"]', f"[`{name}`]", f"?.['{name}']"):
                    for template in ("const go = cpMEMBER;", "const go = (((cpMEMBER)));",
                                     "const go = [cpMEMBER][0];", "const go = Reflect.get(cp, 'NAME');"):
                        with self.subTest(declaration=declaration, member=member, template=template):
                            self.assert_closed(declaration + template.replace("MEMBER", member).replace("NAME", name)
                                               + "go('./hidden.sh');")
        self.assert_closed("import * as cp from 'node:child_process';const other=cp;other.spawnSync('./hidden.sh');")
        self.assert_closed("import * as cp from 'node:child_process';const {spawnSync:go}=cp;go('./hidden.sh');")

    def test_indirect_capability_calls_and_reexports_fail_closed(self) -> None:
        for call in ("go.call(null, './hidden.sh');", "go.apply(null, ['./hidden.sh']);",
                     "Reflect.apply(go, null, ['./hidden.sh']);", "(0,go)('./hidden.sh');",
                     "go?.('./hidden.sh');", "((go))('./hidden.sh');"):
            with self.subTest(call=call):
                self.assert_closed("import {spawnSync as go} from 'node:child_process';" + call)
        for source in ("export * from 'node:worker_threads';",
                       "export {Worker as W} from 'worker_threads';",
                       "export * as cp from 'node:child_process';",
                       "import {Worker} from 'node:worker_threads'; export {Worker};"):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_supported_direct_capability_uses_still_bind(self) -> None:
        for source in (
            "import {Worker as W} from 'node:worker_threads';new W(new URL('./hidden.mjs',import.meta.url));",
            "import {Worker as $W} from 'node:worker_threads';new $W(new URL('./hidden.mjs',import.meta.url));",
            "import wt, {Worker as W} from 'node:worker_threads';new W(new URL('./hidden.mjs',import.meta.url));",
            "import wt from 'worker_threads';new wt['Worker'](new URL('./hidden.mjs',import.meta.url));",
            "const {Worker:W}=require('worker_threads');new W(new URL('./hidden.mjs',import.meta.url));",
            "import {spawnSync as go} from 'node:child_process';go(process.execPath,['./hidden.mjs']);",
            "import {execFileSync as $go} from 'node:child_process';$go(process.execPath,['./hidden.mjs']);",
        ):
            with self.subTest(source=source):
                self.assert_bound(source, "./hidden.mjs")

    def test_commonjs_alias_grouping_and_trivia_preserve_dependency(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32):
            for keyword in ("const", "let", "var"):
                for trivia in ("", " ", "/* ' quote */", "\n", "\u2028", "\u2029"):
                    with self.subTest(depth=depth, keyword=keyword, trivia=trivia):
                        expression = "(" * depth + trivia + "require" + trivia + ")" * depth
                        self.assert_bound(f"{keyword} r = {expression}; r('./hidden.cjs');")

    def test_unrecognized_require_transfers_fail_closed(self) -> None:
        for transfer in ("let r; r=require;", "const r=[require][0];",
                         "const r={value:require}.value;", "const r=(0,require);",
                         "const r=true?require:null;", "const r=require.bind(null);",
                         "function choose(){return require} const r=choose();",
                         "const r=require; const other=r;"):
            with self.subTest(transfer=transfer):
                self.assert_closed(transfer + "r('./hidden.cjs');")
        self.assert_bound("const kind = typeof require; require('./hidden.cjs');")

    def test_unrecognized_builtin_acquisitions_fail_closed(self) -> None:
        for declaration in (
            "const wt=(require)('node:worker_threads');",
            "const r=require;const wt=r('node:worker_threads');",
            "const wt=module.require('node:worker_threads');",
            "const wt=await import('node:worker_threads');",
            "import {createRequire} from 'node:module';const r=createRequire(import.meta.url);const wt=r('node:worker_threads');",
        ):
            with self.subTest(declaration=declaration):
                self.assert_closed(declaration + "new wt.Worker(new URL('./hidden.mjs',import.meta.url));")

    def test_entrypoint_options_cannot_add_unbound_preloads_or_executables(self) -> None:
        for source in (
            "import {Worker} from 'node:worker_threads';new Worker(new URL('./main.mjs',import.meta.url),{execArgv:['--import','./hidden.mjs']});",
            "import {fork} from 'node:child_process';fork('./main.cjs',[],{execArgv:['--require','./hidden.cjs']});",
            "import {spawnSync} from 'node:child_process';spawnSync(process.execPath,['./main.mjs'],{env:{NODE_OPTIONS:'--import=./hidden.mjs'}});",
            "import {fork} from 'node:child_process';fork('./main.cjs',{execPath:'./hidden.sh'});",
        ):
            with self.subTest(source=source):
                self.assert_closed(source)

    def test_hashbang_and_html_comments_cannot_hide_live_loaders(self) -> None:
        for terminator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for comment in ("#!/usr/bin/env node '\"", "<!-- '\"", "0; <!-- '\"",
                            "   --> '\"", "/* lead */ --> '\""):
                with self.subTest(terminator=terminator, comment=comment):
                    self.assert_bound(comment + terminator + "require('./hidden.cjs');" + terminator + "// '\"")
        self.assert_bound("\ufeff#!'\"\nrequire('./hidden.cjs');\n// '\"")

    def test_nested_template_code_uses_the_same_comment_boundaries(self) -> None:
        for source in (
            "const t = `raw <!-- '${ /* ' ignored */ require('./hidden.cjs') } end`;",
            "const t = `outer ${ `inner ${ /* } ` ' */ require('./hidden.cjs') }` } end`;",
            "const t = `outer ${ /[}'\"]/.test('x') ? require('./hidden.cjs') : '' } end`;",
            "const t = `${(()=>{<!-- '\"\nreturn require('./hidden.cjs');\n})()}`;",
            "const r=require;const t=`outer ${ `inner ${r('./hidden.cjs')}` }`;",
        ):
            with self.subTest(source=source):
                self.assert_bound(source)

    def test_inert_capability_text_cannot_authorize_or_reject_code(self) -> None:
        for data in ("const doc = \"import {Worker as W} from 'node:worker_threads';\";",
                     "const doc = \"new Worker(new URL('./ignored.mjs',import.meta.url))\";",
                     "const doc = /import'not-a-package'/;", "const doc=`raw require('ignored')`;",
                     "const doc = {Worker: 1, spawnSync: 2};"):
            with self.subTest(data=data):
                self.assert_bound(data + "require('./hidden.cjs');")
        self.assert_closed("const doc=\"import {Worker as W} from 'node:worker_threads';\";"
                           "import {Worker} from 'node:worker_threads';const W=Worker;"
                           "new W(new URL('./hidden.mjs',import.meta.url));")
        self.assert_bound("import {spawnSync as go} from 'node:child_process';"
                          "const doc=\"go.call(null,'ignored')\";"
                          "go(process.execPath,['./hidden.mjs']);", "./hidden.mjs")

    def test_slash_lexical_goals_cannot_hide_a_following_dependency(self) -> None:
        for prefix in ("const r=/['\"]/;", "const n=8 / /['\"]/.source.length;",
                       "const obj={return: 8}; const n=obj.return / '2/' / 1;",
                       "const n=8 / 2;", "const r=/[/*]/;"):
            with self.subTest(prefix=prefix):
                self.assert_bound(prefix + "require('./hidden.cjs'); // '\"")
        for keyword in ("of", "await", "yield"):
            self.assert_closed(f"const {keyword}=1;const n={keyword} / '2/' / 1; require('./hidden.cjs'); // '")

    def test_child_process_launch_targets_use_candidate_cwd_not_importer(self) -> None:
        for method in ("spawn", "spawnSync", "execFile", "execFileSync", "fork"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                invocation = "launch('./child.cjs')" if method == "fork" else "launch(process.execPath,['./child.cjs'])"
                write_files(root, {
                    "package.json": "{}",
                    "scripts/entry.cjs": f"const {{ {method}: launch }}=require('node:child_process');{invocation};",
                    "scripts/child.cjs": "module.exports='decoy';",
                    "child.cjs": "require('./actual.cjs');",
                    "actual.cjs": "module.exports='actual';",
                })
                before = contract.runtime_source_digest_snapshot(root, entrypoints=("scripts/entry.cjs",))
                self.assertIn("child.cjs", before)
                self.assertIn("actual.cjs", before)
                self.assertNotIn("scripts/child.cjs", before)
                (root / "actual.cjs").write_text("module.exports='changed';")
                self.assertNotEqual(before, contract.runtime_source_digest_snapshot(root, entrypoints=("scripts/entry.cjs",)))
                (root / "child.cjs").unlink()
                with self.assertRaises(contract.RuntimeSourceContractError):
                    contract.runtime_source_paths(root, entrypoints=("scripts/entry.cjs",))

    @unittest.skipUnless(shutil.which("node"), "Node is required for execution oracle")
    def test_node_oracle_child_process_runs_cwd_relative_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                "package.json": "{}",
                "scripts/entry.cjs": "const {spawnSync}=require('node:child_process');spawnSync(process.execPath,['./child.cjs']);",
                "scripts/child.cjs": "throw Error('wrong module-relative target');",
                "child.cjs": "require('node:fs').writeFileSync('executed','cwd-target');",
            })
            subprocess.run([shutil.which("node"), "scripts/entry.cjs"], cwd=root, check=True, capture_output=True, timeout=10)
            self.assertEqual((root / "executed").read_text(), "cwd-target")
            self.assertIn("child.cjs", contract.runtime_source_paths(root, entrypoints=("scripts/entry.cjs",)))

    def test_mutable_launch_defaults_cannot_escape_fixed_entrypoint_binding(self) -> None:
        for prefix in (
            "process.chdir('./other');", "const change=process.chdir;change('./other');",
            "process.execArgv.push('--import','./hidden.mjs');",
            "process['execArgv']=['--require','./hidden.cjs'];",
            "process.env.NODE_OPTIONS='--import=./hidden.mjs';",
            "process.env['NODE_PATH']='./unbound';",
            "process.env.LD_PRELOAD='./unbound.so';",
            "const env=process.env;env.NODE_OPTIONS='--import=./hidden.mjs';",
            "process.env[key]='--import=./hidden.mjs';",
            "process.execPath='./hidden.sh';",
            "(process).execPath='./hidden.sh';",
            "((process)).execPath='./hidden.sh';",
            "(globalThis.process).execPath='./hidden.sh';",
            "({path: process.execPath}={path:'./hidden.sh'});",
            "globalThis.process.execPath='./hidden.sh';",
        ):
            with self.subTest(prefix=prefix):
                self.assert_closed(prefix + "import {spawnSync} from 'node:child_process';spawnSync(process.execPath,['./main.mjs']);")
        self.assert_bound("const mode=process.env.NODE_ENV;const token=process.env.AGENTIC_TOKEN;require('./hidden.cjs');")

    def test_child_launch_does_not_reinterpret_switches_urls_or_assets_as_sources(self) -> None:
        for target in ("--test", "--eval", "-", "file:child.cjs", "data:text/javascript,0",
                       "child.json", "child", "../child.cjs", "/tmp/child.cjs"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_files(root, {"package.json": "{}", "child.json": "{}", "child": "require('./hidden.cjs');",
                                   "entry.cjs": f"const {{fork}}=require('child_process');fork({json.dumps(target)});"})
                with self.assertRaises(contract.RuntimeSourceContractError):
                    contract.runtime_source_paths(root, entrypoints=("entry.cjs",))

    def test_package_scope_changes_alter_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                "package.json": '{"name":"fixture","type":"module"}',
                "entry.mjs": "import './sub/file.js';",
                "sub/file.js": "console.log(typeof require);",
                "sub/package.json": '{"type":"module"}',
            })
            before = contract.runtime_source_digest_snapshot(root, entrypoints=("entry.mjs",))
            self.assertIn("sub/package.json", before)
            (root / "sub/package.json").write_text('{"type":"commonjs"}')
            after = contract.runtime_source_digest_snapshot(root, entrypoints=("entry.mjs",))
            self.assertEqual(before["sub/file.js"], after["sub/file.js"])
            self.assertNotEqual(before, after)
            (root / "sub/package.json").unlink()
            self.assertNotIn("sub/package.json", contract.runtime_source_digest_snapshot(root, entrypoints=("entry.mjs",)))

    def test_entrypoint_without_imports_still_binds_its_package_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {"package.json": "{}", "sub/package.json": '{"type":"module"}',
                               "sub/file.js": "console.log(typeof require);"})
            snapshot = contract.runtime_source_digest_snapshot(root, entrypoints=("sub/file.js",))
            self.assertIn("sub/package.json", snapshot)

    def test_nested_scope_does_not_inherit_outer_imports_or_self_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                "package.json": '{"name":"fixture","exports":"./decoy.mjs","imports":{"#hidden":"./decoy.mjs"}}',
                "decoy.mjs": "export default 'decoy';", "nested/package.json": "{}",
                "nested/entry.mjs": "import '#hidden';",
                "node_modules/fixture/package.json": '{"name":"fixture","exports":"./real.mjs"}',
                "node_modules/fixture/real.mjs": "export default 'actual';",
            })
            with self.assertRaises(contract.RuntimeSourceContractError):
                contract.runtime_source_paths(root, entrypoints=("nested/entry.mjs",))
            (root / "nested/entry.mjs").write_text("import 'fixture';")
            paths = contract.runtime_source_paths(root, entrypoints=("nested/entry.mjs",))
            self.assertIn("node_modules/fixture/real.mjs", paths)
            self.assertNotIn("decoy.mjs", paths)

    def test_node_modules_is_a_package_scope_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {"package.json": '{"imports":{"#hidden":"./decoy.mjs"}}',
                               "decoy.mjs": "export default 1;", "node_modules/pkg/entry.mjs": "import '#hidden';"})
            with self.assertRaises(contract.RuntimeSourceContractError):
                contract.runtime_source_paths(root, entrypoints=("node_modules/pkg/entry.mjs",))

    def test_package_scope_escape_or_invalid_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            write_files(root, {"package.json": "{}", "sub/entry.js": "export default 1;"})
            outside = Path(external) / "package.json"
            outside.write_text('{"type":"module"}')
            package = root / "sub/package.json"
            package.symlink_to(outside)
            with self.assertRaises(contract.RuntimeSourceContractError):
                contract.runtime_source_paths(root, entrypoints=("sub/entry.js",))
            package.unlink()
            for invalid in ("{", "[]", '"module"'):
                package.write_text(invalid)
                with self.subTest(invalid=invalid), self.assertRaises(contract.RuntimeSourceContractError):
                    contract.runtime_source_paths(root, entrypoints=("sub/entry.js",))

    def test_unknown_commonjs_extensions_are_not_silently_inert_leaves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix in ("", ".txt", ".asset"):
                with self.subTest(suffix=suffix):
                    write_files(root, {"package.json": "{}", "entry.cjs": f"require('./payload{suffix}');",
                                       f"payload{suffix}": "require('./hidden.cjs');", "hidden.cjs": "module.exports=1;"})
                    with self.assertRaises(contract.RuntimeSourceContractError):
                        contract.runtime_source_paths(root, entrypoints=("entry.cjs",))

    @unittest.skipUnless(NODE, "Node is required for the differential fixture")
    def test_node_executes_the_reported_commonjs_lexical_and_alias_cases(self) -> None:
        cases = (
            "const r=((require));r('./hidden.cjs');",
            "#!/usr/bin/env node '\"\nrequire('./hidden.cjs');\n// '\"",
            "<!-- '\"\nrequire('./hidden.cjs');\n<!-- '\"",
            "   --> '\"\nrequire('./hidden.cjs');\n --> '\"",
            "const n=8 / /['\"]/.source.length;require('./hidden.cjs'); // '\"",
            "const obj={return:8};const n=obj.return / '2/' / 1;require('./hidden.cjs'); // '\"",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {"hidden.cjs": "console.log('HIDDEN_EXECUTED');"})
            for source in cases:
                with self.subTest(source=source):
                    write_files(root, {"entry.cjs": source})
                    result = subprocess.run([str(NODE), "entry.cjs"], cwd=root, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("HIDDEN_EXECUTED", result.stdout)
                    self.assert_bound(source)


class RuntimePreloadClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        write_files(self.root, {
            "package.json": '{"name":"fixture","type":"module"}',
            "bin/node": "#!/bin/sh\nexit 0\n",
            "node_modules/tsx/package.json": '{"name":"tsx","type":"module","exports":"./dist/loader.mjs"}',
            "node_modules/tsx/dist/loader.mjs": "import 'helper';",
            "node_modules/helper/package.json": '{"name":"helper","type":"module","exports":"./index.mjs"}',
            "node_modules/helper/index.mjs": "import './sub/leaf.js';",
            "node_modules/helper/sub/package.json": '{"type":"module"}',
            "node_modules/helper/sub/leaf.js": "export default 'before';",
        })
        (self.root / "bin/node").chmod(0o755)
        self.loader = self.root / "node_modules/tsx/dist/loader.mjs"
        self.env = {"PATH": str(self.root / "bin")}
        patcher = mock.patch.object(probe, "_resolve_node_import_path", side_effect=lambda **_: self.loader.resolve())
        patcher.start()
        self.addCleanup(patcher.stop)

    def bindings(self):
        return probe._runtime_launch_bindings(self.root, self.env)

    def assert_drift_rejected(self, expected) -> None:
        with self.assertRaisesRegex(probe.ProbeError, "source binding changed"):
            probe._assert_runtime_launch_sources_still_bound(
                openclaw_root=self.root, runner_env=self.env,
                expected_node_executable=expected[0], expected_tsx_preload_specifier=expected[1],
                expected_sources=expected[2],
            )

    def test_transitive_sibling_dependency_drift_changes_binding(self) -> None:
        before = self.bindings()
        (self.root / "node_modules/helper/sub/leaf.js").write_text("export default 'after';")
        after = self.bindings()
        self.assertEqual(before[0:2], after[0:2])
        self.assertEqual(before[2][0:2], after[2][0:2])
        self.assertNotEqual(before[2][2], after[2][2])
        self.assertNotIn(str(self.root), json.dumps(after[2]))
        self.assert_drift_rejected(before)

    def test_preload_uses_node_not_tsx_suffix_resolution(self) -> None:
        self.loader = self.loader.with_suffix(".cjs")
        self.loader.write_text("require('./bootstrap');")
        write_files(self.root, {
            "node_modules/tsx/dist/bootstrap.ts": "export default 'typescript-decoy';",
            "node_modules/tsx/dist/bootstrap.js": "require('helper');",
            "node_modules/tsx/package.json": '{"name":"tsx","type":"commonjs","main":"./dist/loader.cjs"}',
        })
        before = self.bindings()
        (self.root / "node_modules/helper/sub/leaf.js").write_text("export default 'after';")
        self.assert_drift_rejected(before)

    def test_preload_esm_does_not_guess_missing_extensions(self) -> None:
        self.loader.write_text("import './not-present.js';")
        self.loader.with_name("not-present.ts").write_text("export default 1;")
        with self.assertRaisesRegex(probe.ProbeError, "preload closure could not be bound"):
            self.bindings()

    def test_sibling_resolution_metadata_drift_changes_binding(self) -> None:
        before = self.bindings()
        (self.root / "node_modules/helper/sub/package.json").write_text('{"type":"commonjs"}')
        self.assert_drift_rejected(before)

    def test_preload_dependency_cycle_is_finite_and_bound(self) -> None:
        (self.root / "node_modules/helper/sub/leaf.js").write_text("import '../index.mjs';export default 1;")
        self.assertEqual(self.bindings(), self.bindings())

    def test_missing_dynamic_or_external_preload_dependency_never_falls_back_to_tree_only(self) -> None:
        for source in ("import 'missing-helper';", "const name='helper';await import(name);",
                       "import '../../../../outside.mjs';"):
            with self.subTest(source=source):
                self.loader.write_text(source)
                with self.assertRaisesRegex(probe.ProbeError, "preload closure could not be bound"):
                    self.bindings()

    def test_symlinked_sibling_dependencies_inside_candidate_root_are_bound(self) -> None:
        helper = self.root / "node_modules/helper"
        store = self.root / "node_modules/.store/helper"
        store.parent.mkdir()
        helper.rename(store)
        helper.symlink_to(store, target_is_directory=True)
        before = self.bindings()
        (store / "sub/leaf.js").write_text("export default 'changed';")
        self.assert_drift_rejected(before)

    def test_external_sibling_dependency_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            helper = self.root / "node_modules/helper"
            shutil.rmtree(helper)
            helper.symlink_to(Path(outside), target_is_directory=True)
            write_files(Path(outside), {"package.json": '{"name":"helper","exports":"./index.mjs"}',
                                        "index.mjs": "export default 1;"})
            with self.assertRaisesRegex(probe.ProbeError, "preload closure could not be bound"):
                self.bindings()

    @unittest.skipUnless(NODE, "Node is required for the differential fixture")
    def test_node_preload_really_executes_changed_sibling_bytes(self) -> None:
        leaf = self.root / "node_modules/helper/sub/leaf.js"
        leaf.write_text("console.log('PRELOAD_BEFORE');")
        before = self.bindings()
        first = subprocess.run([str(NODE), "--import", self.loader.as_uri(), "-e", ""],
                               cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("PRELOAD_BEFORE", first.stdout)
        leaf.write_text("console.log('PRELOAD_AFTER');")
        second = subprocess.run([str(NODE), "--import", self.loader.as_uri(), "-e", ""],
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("PRELOAD_AFTER", second.stdout)
        self.assert_drift_rejected(before)


if __name__ == "__main__":
    unittest.main()
