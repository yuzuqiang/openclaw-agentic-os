"""Regression families for PR45's source-closure review (not runtime evidence)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("closure_review_probe", SCRIPTS / "openclaw-real-gateway-contract-probe.py")
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
CONTRACT = PROBE.runtime_source_contract


def write_files(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def fixture(root: Path, extra: dict[str, str]) -> None:
    files = {path: "export const value = 1;\n" for path in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS}
    files["package.json"] = '{"name":"closure-fixture","type":"module"}\n'
    files.update(extra)
    write_files(root, files)


class SourceClosureReviewTests(unittest.TestCase):
    def assert_bound_or_rejected(self, source: str, dependency: str = "./hidden.cjs") -> None:
        try:
            specs = CONTRACT.import_specifiers(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(dependency, {item[0] for item in specs}, source)

    def test_worker_capability_cannot_escape_via_alias_or_container(self) -> None:
        declarations = (
            "import { Worker } from 'node:worker_threads';",
            "import wt, { Worker } from 'node:worker_threads';",
            "const { Worker } = require('node:worker_threads');",
        )
        transfers = (
            "const W = Worker; new W(new URL('./hidden.cjs', import.meta.url));",
            "let W; W = Worker; new W(new URL('./hidden.cjs', import.meta.url));",
            "const W = (((Worker))); new W(new URL('./hidden.cjs', import.meta.url));",
            "const x = { W: Worker }; new x.W(new URL('./hidden.cjs', import.meta.url));",
            "const x = [Worker]; new x[0](new URL('./hidden.cjs', import.meta.url));",
            "((W) => new W(new URL('./hidden.cjs', import.meta.url)))(Worker);",
            "const x = `${(() => { const W = Worker; return new W(new URL('./hidden.cjs', import.meta.url)); })()}`;",
        )
        for declaration in declarations:
            for transfer in transfers:
                with self.subTest(declaration=declaration, transfer=transfer):
                    self.assert_bound_or_rejected(declaration + transfer)

    def test_namespace_capability_cannot_escape_via_member_syntax(self) -> None:
        for module, member, invocation in (
            ("child_process", "spawnSync", "go('./hidden.cjs')"),
            ("worker_threads", "Worker", "new go(new URL('./hidden.cjs', import.meta.url))"),
        ):
            for access in (f"cp.{member}", f"cp['{member}']", f'cp["{member}"]', f"cp[`{member}`]", "cp[member]", f"(cp)['{member}']"):
                for transfer in (f"const go = {access};", f"let go; go = {access};", f"const box = {{ go: {access} }}; const go = box.go;"):
                    source = f"import * as cp from 'node:{module}'; const member = '{member}'; {transfer} {invocation};"
                    with self.subTest(source=source):
                        self.assert_bound_or_rejected(source)

    def test_namespace_aliases_and_reflective_calls_fail_closed(self) -> None:
        sources = (
            "import * as cp from 'node:child_process'; const other = cp; other.spawnSync('./hidden.cjs');",
            "import * as cp from 'node:child_process'; const {spawnSync: go} = cp; go('./hidden.cjs');",
            "import * as cp from 'node:child_process'; Reflect.apply(cp['spawnSync'], null, ['./hidden.cjs']);",
            "import * as wt from 'node:worker_threads'; const other = wt; new other.Worker(new URL('./hidden.cjs', import.meta.url));",
            "import * as wt from 'node:worker_threads'; Reflect.construct(wt.Worker, [new URL('./hidden.cjs', import.meta.url)]);",
            "const { Worker } = await import('node:worker_threads'); const W = Worker; new W(new URL('./hidden.cjs', import.meta.url));",
            "import { ChildProcess } from 'node:child_process'; new ChildProcess().spawn({file:'./hidden.cjs'});",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source)

    def test_require_grouping_and_non_declaration_transfers(self) -> None:
        for depth in (0, 1, 2, 3, 10, 64):
            for value in ("require", "module.require", "module['require']"):
                rhs = "(" * depth + value + ")" * depth
                for assignment in (f"const r = {rhs};", f"let r; r = {rhs};", f"const box = [{rhs}]; const r = box[0];"):
                    source = assignment + "r('./hidden.cjs');"
                    with self.subTest(source=source):
                        self.assert_bound_or_rejected(source)

    def test_hashbang_and_html_comments_do_not_hide_loaders(self) -> None:
        for terminator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for source in (
                '#! /usr/bin/node "' + terminator + "require('./hidden.cjs'); //\"",
                '<!-- "' + terminator + "require('./hidden.cjs');" + terminator + '<!-- "',
                '--> "' + terminator + "require('./hidden.cjs');" + terminator + '--> "',
                '  /* trivia */ --> "' + terminator + "require('./hidden.cjs'); //\"",
            ):
                with self.subTest(source=source):
                    self.assert_bound_or_rejected(source)

    def test_inert_text_is_not_a_capability_reference(self) -> None:
        sources = (
            'const text = "const W = Worker; cp[\'spawnSync\']; require";',
            'const text = `const W = Worker; cp[\'spawnSync\']; require`;',
            'const pattern = /Worker|cp|require|<!--|-->/;',
            '/* require Worker cp */\n// require Worker cp\nexport const value = 1;',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_relative_module_scope_metadata_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../node_modules/pkg/sub/file.js';",
                "node_modules/pkg/package.json": '{"name":"pkg"}',
                "node_modules/pkg/sub/package.json": '{"type":"module"}',
                "node_modules/pkg/sub/file.js": "export const value = 1;",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("node_modules/pkg/sub/package.json", before)
            (root / "node_modules/pkg/sub/package.json").write_text('{"type":"commonjs"}')
            self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_entrypoint_scope_metadata_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {"scripts/package.json": '{"type":"module"}'})
            self.assertIn("scripts/package.json", CONTRACT.runtime_source_paths(root))

    def test_tsx_transitive_preload_bytes_and_metadata_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                "package.json": '{"name":"fixture","type":"module"}',
                "bin/node": "#!/bin/sh\n",
                "node_modules/tsx/package.json": '{"name":"tsx","type":"module"}',
                "node_modules/tsx/loader.mjs": "import 'helper';",
                "node_modules/helper/package.json": '{"name":"helper","main":"index.mjs"}',
                "node_modules/helper/index.mjs": "export const value = 1;",
            })
            node = root / "bin/node"
            node.chmod(0o755)
            loader = root / "node_modules/tsx/loader.mjs"
            env = {"PATH": str(node.parent)}
            with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                _, _, before = PROBE._runtime_launch_bindings(root, env)
                (root / "node_modules/helper/index.mjs").write_text("export const value = 2;")
                _, _, after = PROBE._runtime_launch_bindings(root, env)
                self.assertNotEqual(before, after)
                with self.assertRaises(PROBE.ProbeError):
                    PROBE._assert_runtime_launch_sources_still_bound(
                        openclaw_root=root, runner_env=env,
                        expected_node_executable=node.resolve(),
                        expected_tsx_preload_specifier=loader.as_uri(), expected_sources=before,
                    )


    def test_complete_launch_signature_rejects_unbound_preload_options(self) -> None:
        sources = (
            "import { Worker } from 'node:worker_threads'; new Worker(new URL('./bound.mjs', import.meta.url), {execArgv:['--require', './hidden.cjs']});",
            "import { fork } from 'node:child_process'; fork('./bound.cjs', [], {execArgv:['--require','./hidden.cjs']});",
            "import { spawnSync } from 'node:child_process'; spawnSync(process.execPath, ['./bound.cjs'], {env:{NODE_OPTIONS:'--require ./hidden.cjs'}});",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_combined_and_default_namespace_imports_do_not_lose_capabilities(self) -> None:
        for module, member in (("worker_threads", "Worker"), ("child_process", "spawnSync")):
            for declaration in (
                f"import first, * as ns from 'node:{module}';",
                f"import {{ default as ns }} from 'node:{module}';",
            ):
                source = declaration + f"const go = ns['{member}']; go('./hidden.cjs');"
                with self.subTest(source=source):
                    self.assert_bound_or_rejected(source)

    def test_all_execution_module_acquisitions_require_recognized_bindings(self) -> None:
        for module in ("child_process", "worker_threads", "module"):
            for source in (
                f"const ns = (require)('node:{module}');",
                f"const {{default: ns}} = (require)('node:{module}');",
                f"import * as 工人 from 'node:{module}';",
                f"import 工人 from 'node:{module}';",
                f"export * from 'node:{module}';",
                f"export * as ns from 'node:{module}';",
                f"export {{default as ns}} from 'node:{module}';",
            ):
                with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(source)

    def test_direct_literal_require_still_works_when_parenthesized(self) -> None:
        self.assertIn(
            ("./hidden.cjs", True, "require"),
            CONTRACT.import_specifiers("(require)('./hidden.cjs');"),
        )

    def test_mutable_launch_context_cannot_redirect_literal_entrypoints(self) -> None:
        mutations = (
            "process.env.NODE_OPTIONS = '--require ./hidden.cjs';",
            "process.env['NODE_PATH'] = './hidden';",
            "process.env[`NODE_OPTIONS`] = '--require ./hidden.cjs';",
            "const env = process.env; env.NODE_OPTIONS = '--require ./hidden.cjs';",
            "Object.assign(process.env, {NODE_OPTIONS:'--require ./hidden.cjs'});",
            "process.execArgv.push('--require', './hidden.cjs');",
            "process.chdir('./hidden');",
            "process.execPath = './hidden.sh';",
            "process.loadEnvFile('./hidden.env');",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(
                    "import { fork } from 'node:child_process';" + mutation + "fork('./bound.cjs');"
                )

    def test_launch_context_is_checked_across_side_effect_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER:
                    "import './configure.cjs'; import {fork} from 'node:child_process'; fork('./bound.cjs');",
                'scripts/configure.cjs': "process.env.NODE_OPTIONS = '--require ./hidden.cjs';",
                'scripts/bound.cjs': 'module.exports = 1;',
                'bound.cjs': 'module.exports = 1;',
            })
            with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, 'process environment'):
                CONTRACT.runtime_source_paths(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                'node_modules/tsx/package.json': '{"name":"tsx"}',
                'node_modules/tsx/loader.cjs': "process.env.NODE_OPTIONS = '--require ./hidden.cjs';",
            })
            with self.assertRaisesRegex(PROBE.ProbeError, 'preload source closure'):
                PROBE._runtime_preload_closure_binding(root, root / 'node_modules/tsx/loader.cjs')

    def test_native_url_cannot_be_shadowed_or_transferred(self) -> None:
        sources = (
            "import {URL as RealURL} from 'node:url'; const URL = function(){return new RealURL('./hidden.cjs',import.meta.url)};",
            "import {URL} from './hidden-factory.mjs';",
            "const RealURL = URL;",
            "function launch(URL) { new URL('./hidden.cjs',import.meta.url); }",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(
                    "import {Worker} from 'node:worker_threads';" + source +
                    "new Worker(new URL('./bound.cjs',import.meta.url));"
                )
        for declaration in ("", "import {URL} from 'node:url';", "const {URL} = require('node:url');"):
            specs = CONTRACT.import_specifiers(
                "import {Worker} from 'node:worker_threads';" + declaration +
                "new Worker(new URL('./bound.cjs',import.meta.url));"
            )
            self.assertIn('./bound.cjs', {item[0] for item in specs})
        self.assertEqual(CONTRACT.import_specifiers("const name = process.env.APP_NAME;"), [])

    def test_module_and_factory_capabilities_cannot_escape(self) -> None:
        sources = (
            "import m from 'node:module'; const other = m; other._load('./hidden.cjs');",
            "import module from 'node:module'; const other = module; other._load('./hidden.cjs');",
            "import { createRequire } from 'node:module'; const f = createRequire; const r = f(import.meta.url); r('./hidden.cjs');",
            "const {ChildProcess: C} = require('node:child_process'); new C().spawn({file:'./hidden.cjs'});",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source)

    def test_comments_before_regex_and_nested_templates_preserve_real_loads(self) -> None:
        sources = (
            "const pattern = /* trivia */ /[//]/; require('./hidden.cjs');",
            "const pattern = /* trivia */ /'/; require('./hidden.cjs');",
            "const text = `${(() => { const r = /* trivia */ /[}//]/; return require('./hidden.cjs'); })()}`;",
            "const text = `${`nested ${require('./hidden.cjs')}`}`;",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertIn('./hidden.cjs', {item[0] for item in CONTRACT.import_specifiers(source)})
                normalized = CONTRACT.strip_source_comments(source)
                self.assertEqual(len(normalized), len(source))
                self.assertEqual(CONTRACT.strip_source_comments(normalized), normalized)

    def test_inert_call_examples_and_fake_imports_are_not_executable(self) -> None:
        sources = (
            'const doc = "new Worker(new URL(\'./missing.cjs\', import.meta.url));";',
            'const doc = `execSync("./missing.sh"); child_process.fork("./missing.cjs")`;',
            'const doc = "import {Worker as W} from \'node:worker_threads\';"; const W = () => 1; W();',
            'const doc = "const r = require;"; const r = () => 1; r();',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_template_match_offsets_cannot_authorize_another_reference(self) -> None:
        sources = (
            "import { Worker } from 'node:worker_threads'; const a = `${new Worker(new URL('./bound.cjs',import.meta.url))}`; const b = `${(() => { const W = Worker; return new W(new URL('./hidden.cjs',import.meta.url)); })()}`;",
            "import { spawnSync } from 'node:child_process'; const a = `${spawnSync(process.execPath,['./bound.cjs'])}`; const b = `${spawnSync('./hidden.cjs')}`;",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source)

    def test_native_loading_is_not_allowed_by_renaming_the_binary(self) -> None:
        for suffix in ('.node', '.so', '.txt', ''):
            source = f"process.dlopen(module, './hidden{suffix}');"
            with self.subTest(suffix=suffix), self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, 'native add-on'):
                CONTRACT.import_specifiers(source)

    def test_package_imports_stop_at_the_nearest_package_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {
                "package.json": '{"name":"root","imports":{"#helper":"./outer.mjs"}}',
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../nested/entry.mjs';",
                "nested/package.json": '{"name":"nested"}',
                "nested/entry.mjs": "import '#helper';",
                "outer.mjs": "export const hidden = 1;",
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_package_lookup_skips_spurious_node_modules_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import 'outer';",
                "node_modules/outer/package.json": '{"name":"outer","main":"index.cjs"}',
                "node_modules/outer/index.cjs": "require('helper');",
                "node_modules/helper/package.json": '{"name":"helper","main":"index.cjs"}',
                "node_modules/helper/index.cjs": "module.exports = 1;",
                "node_modules/node_modules/helper/package.json": '{"name":"helper","main":"decoy.cjs"}',
                "node_modules/node_modules/helper/decoy.cjs": "module.exports = 2;",
            })
            paths = CONTRACT.runtime_source_paths(root)
            self.assertIn('node_modules/helper/index.cjs', paths)
            self.assertNotIn('node_modules/node_modules/helper/decoy.cjs', paths)

    def test_preload_require_uses_node_js_before_typescript_decoy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                "node_modules/tsx/package.json": '{"name":"tsx","main":"loader.cjs"}',
                "node_modules/tsx/loader.cjs": "require('./helper');",
                "node_modules/tsx/helper.ts": "export const decoy = true;",
                "node_modules/tsx/helper.js": "module.exports = 1;",
            })
            loader = root / 'node_modules/tsx/loader.cjs'
            before = PROBE._runtime_preload_closure_binding(root, loader)
            (root / 'node_modules/tsx/helper.js').write_text('module.exports = 2;')
            after = PROBE._runtime_preload_closure_binding(root, loader)
            self.assertNotEqual(before, after)
            paths = CONTRACT.runtime_source_paths(root, entrypoints=('node_modules/tsx/loader.cjs',), node_only=True)
            self.assertIn('node_modules/tsx/helper.js', paths)
            self.assertNotIn('node_modules/tsx/helper.ts', paths)

    def test_preload_scope_metadata_and_dynamic_failures_are_not_silently_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {
                'node_modules/tsx/package.json': '{"name":"tsx"}',
                'node_modules/tsx/loader.mjs': "import '../helper/sub/code.js';",
                'node_modules/helper/sub/package.json': '{"type":"module"}',
                'node_modules/helper/sub/code.js': 'export const value = 1;',
            })
            loader = root / 'node_modules/tsx/loader.mjs'
            before = PROBE._runtime_preload_closure_binding(root, loader)
            (root / 'node_modules/helper/sub/package.json').write_text('{"type":"commonjs"}')
            self.assertNotEqual(before, PROBE._runtime_preload_closure_binding(root, loader))
            for source in ("import(process.env.HIDDEN);", "require('./native.node');", "import './missing.mjs';"):
                loader.write_text(source)
                with self.subTest(source=source), self.assertRaisesRegex(PROBE.ProbeError, 'preload source closure'):
                    PROBE._runtime_preload_closure_binding(root, loader)

    def test_preload_symlink_cannot_escape_the_bound_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'candidate'
            write_files(root, {
                'node_modules/tsx/package.json': '{"name":"tsx"}',
                'node_modules/tsx/loader.mjs': "import './linked.mjs';",
            })
            external = parent / 'outside.mjs'
            external.write_text('export const value = 1;')
            (root / 'node_modules/tsx/linked.mjs').symlink_to(external)
            with self.assertRaisesRegex(PROBE.ProbeError, 'preload source closure'):
                PROBE._runtime_preload_closure_binding(root, root / 'node_modules/tsx/loader.mjs')

    def test_launch_binding_schema_rejects_duplicates_and_old_incomplete_records(self) -> None:
        records = [{"path": label, "sha256": "a" * 64, "realpath_sha256": "b" * 64} for label in PROBE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS]
        self.assertEqual(PROBE._validate_runtime_launch_sources(records), records)
        for invalid in (records[:-1], records + [records[0]], records[:-1] + [records[0]]):
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeError):
                PROBE._validate_runtime_launch_sources(invalid)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the independent execution oracle')
    def test_real_node_executes_the_review_counterexamples(self) -> None:
        examples = (
            ('require.cjs', "const r = ((require)); r('./hidden.cjs');"),
            ('comments.cjs', '<!-- "\nrequire("./hidden.cjs");\n<!-- "'),
            ('hashbang.cjs', '#! /usr/bin/node "\nrequire("./hidden.cjs"); //"'),
            ('worker.mjs', "import {Worker} from 'node:worker_threads'; const W = Worker; new W(new URL('./hidden.cjs', import.meta.url));"),
            ('child.cjs', "const cp = require('node:child_process'); const go = cp['spawnSync']; const result = go(process.execPath, ['./hidden.cjs'], {encoding:'utf8'}); process.stdout.write(result.stdout);"),
            ('env.cjs', "const {fork} = require('node:child_process'); process.env.NODE_OPTIONS='--require ./hidden.cjs'; fork('./bound.cjs');"),
            ('argv.cjs', "const {fork} = require('node:child_process'); process.execArgv.push('--require', './hidden.cjs'); fork('./bound.cjs');"),
            ('url.mjs', "import {Worker} from 'node:worker_threads'; import {URL as RealURL} from 'node:url'; const URL = function(){return new RealURL('./hidden.cjs',import.meta.url)}; new Worker(new URL('./bound.cjs',import.meta.url));"),
        )
        for filename, source in examples:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_files(root, {filename: source, 'hidden.cjs': "process.stdout.write('closure-marker');", 'bound.cjs': 'module.exports = 1;'})
                proc = subprocess.run(
                    [str(shutil.which('node')), str(root / filename)], cwd=root,
                    env={'PATH': os.environ.get('PATH', ''), 'HOME': str(root)},
                    capture_output=True, text=True, timeout=15, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout, 'closure-marker')
                self.assert_bound_or_rejected(source)


if __name__ == "__main__":
    unittest.main()
