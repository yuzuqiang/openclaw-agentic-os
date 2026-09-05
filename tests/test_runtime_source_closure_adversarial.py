"""Regression matrix for executable capability escapes and launch-source closure."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import agentic_os_runtime_source_contract as CONTRACT

SPEC = importlib.util.spec_from_file_location(
    "adversarial_gateway_probe", SCRIPTS / "openclaw-real-gateway-contract-probe.py"
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class SourceClosureAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(name, '{"name":"openclaw"}\n' if name == "package.json" else "export {};\n")
        self.write("scripts/hidden.cjs", "module.exports = {};\n")
        self.write("scripts/hidden.mjs", "export {};\n")

    def write(self, relative: str, source: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def snapshot(self, source: str) -> dict[str, str]:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        return CONTRACT.runtime_source_digest_snapshot(self.root)

    def assert_bound_or_rejected(self, source: str, path: str) -> None:
        try:
            snapshot = self.snapshot(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(path, snapshot, source)

    def test_worker_capability_cannot_escape_through_value_transfers(self) -> None:
        transfers = (
            "const W = Worker;", "let W; W = Worker;", "const W = ((Worker));",
            "const box = {W: Worker}; const W = box.W;",
            "const [W] = [Worker];", "const W = Worker.bind(null);",
            "const W = (() => Worker)();", "const W = true ? Worker : null;",
            "const W = ((x) => x)(Worker);",
        )
        for transfer in transfers:
            with self.subTest(transfer=transfer):
                self.assert_bound_or_rejected(
                    "import { Worker } from 'node:worker_threads';\n" + transfer
                    + "new W(new URL('./hidden.mjs', import.meta.url));",
                    "scripts/hidden.mjs",
                )

    def test_worker_namespace_and_dynamic_loads_cannot_escape(self) -> None:
        sources = (
            "import * as wt from 'node:worker_threads'; const W = wt['Worker'];",
            "import wt from 'node:worker_threads'; const W = wt[`Worker`];",
            "import * as wt from 'node:worker_threads'; const alias = wt; const W = alias.Worker;",
            "const W = require('node:worker_threads').Worker;",
            "const {['Worker']: W} = require('node:worker_threads');",
            "const {Worker: W = null} = require('node:worker_threads');",
            "const { Worker: W } = await import('node:worker_threads');",
        )
        for prefix in sources:
            with self.subTest(prefix=prefix):
                self.assert_bound_or_rejected(
                    prefix + "new W(new URL('./hidden.mjs', import.meta.url));",
                    "scripts/hidden.mjs",
                )

    def test_every_child_process_capability_transfer_fails_closed(self) -> None:
        for member in ("spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync", "fork"):
            for expression in (f"cp.{member}", f"cp['{member}']", f"cp[`{member}`]", f"((cp))['{member}']"):
                with self.subTest(member=member, expression=expression):
                    source = "import * as cp from 'node:child_process'; const go = " + expression + "; go('./hidden.sh');"
                    with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                        self.snapshot(source)

    def test_child_process_namespace_container_and_callback_transfers_fail_closed(self) -> None:
        for source in (
            "const cp2 = cp; cp2.spawnSync('./hidden.sh');",
            "const {spawnSync: go} = cp; go('./hidden.sh');",
            "const go = [cp.spawnSync][0]; go('./hidden.sh');",
            "((go) => go('./hidden.sh'))(cp.spawnSync);",
            "new cp.ChildProcess().spawn({file: './hidden.sh', args: []});",
        ):
            with self.subTest(source=source):
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("import * as cp from 'node:child_process'; " + source)

    def test_require_aliases_with_arbitrary_balanced_grouping_are_bound(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32, 64):
            with self.subTest(depth=depth):
                source = "const r = " + "(" * depth + "require" + ")" * depth + "; r('./hidden.cjs');"
                self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_unaccounted_require_value_transfers_fail_closed(self) -> None:
        for source in (
            "const r = [require][0]; r('./hidden.cjs');",
            "const {r} = {r: require}; r('./hidden.cjs');",
            "((r) => r('./hidden.cjs'))(require);",
            "const r = true ? require : null; r('./hidden.cjs');",
            "const r = require.bind(null); r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.cjs")

    def test_hashbang_and_annex_b_comments_cannot_hide_executable_loads(self) -> None:
        for newline in ("\n", "\r", "\u2028", "\u2029"):
            for prefix, suffix in (
                ('<!-- "', '<!-- "'),
                ('#! /usr/bin/env node "', '// "'),
                ('--> "', '--> "'),
                ('/* prefix */ --> "', '<!-- "'),
            ):
                with self.subTest(newline=repr(newline), prefix=prefix):
                    source = prefix + newline + "require('./hidden.cjs');" + newline + suffix
                    self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_comment_markers_in_data_stay_inert(self) -> None:
        for source in (
            'const s = "<!-- require(unknown)";',
            'const s = `<!-- require(unknown)`;',
            'const s = "#! require(unknown)";',
            'const s = /<!-- require\\(unknown\\)/;',
            "<!-- require(unknown)\nexport {};",
            "#!/usr/bin/env node require(unknown)\nexport {};",
        ):
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_template_expression_comments_do_not_hide_loader_references(self) -> None:
        for source in (
            '`raw ${ /* " */ require("./hidden.cjs") } tail`;',
            '`raw ${ `nested ${require("./hidden.cjs")}` } tail`;',
            '`raw ${ /[}]/.test("}") ? require("./hidden.cjs") : null } tail`;',
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.cjs")

    def test_relative_modules_bind_nearest_package_scope_and_detect_changes(self) -> None:
        self.write("node_modules/pkg/package.json", '{"name":"pkg","exports":"./sub/file.js"}')
        self.write("node_modules/pkg/sub/file.js", "export {};\n")
        metadata = self.write("node_modules/pkg/sub/package.json", '{"type":"module"}')
        source = "import '../node_modules/pkg/sub/file.js';"
        before = self.snapshot(source)
        self.assertIn("node_modules/pkg/sub/package.json", before)
        metadata.write_text('{"type":"commonjs"}', encoding="utf-8")
        self.assertNotEqual(before, self.snapshot(source))

    def test_entrypoints_and_transitive_modules_bind_package_scope(self) -> None:
        self.write("scripts/package.json", '{"type":"module"}')
        self.write("scripts/sub/package.json", '{"type":"commonjs"}')
        self.write("scripts/sub/file.js", "module.exports = {};\n")
        paths = self.snapshot("import './sub/file.js';")
        self.assertIn("scripts/package.json", paths)
        self.assertIn("scripts/sub/package.json", paths)

    def test_new_package_scope_changes_snapshot(self) -> None:
        self.write("scripts/sub/file.js", "export {};\n")
        source = "import './sub/file.js';"
        before = self.snapshot(source)
        self.write("scripts/sub/package.json", '{"type":"module"}')
        self.assertNotEqual(before, self.snapshot(source))

    def test_malformed_controlling_package_scope_fails_closed(self) -> None:
        self.write("scripts/sub/file.js", "export {};\n")
        self.write("scripts/sub/package.json", "{")
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("import './sub/file.js';")

    def test_launcher_binds_transitive_preload_and_revalidates_drift(self) -> None:
        node = self.write("bin/node", "#!/bin/sh\nexit 0\n")
        node.chmod(0o755)
        self.write("node_modules/tsx/package.json", '{"name":"tsx","type":"module"}')
        loader = self.write("node_modules/tsx/dist/loader.mjs", "import 'helper';\n")
        self.write("node_modules/helper/package.json", '{"name":"helper","main":"index.mjs"}')
        helper = self.write("node_modules/helper/index.mjs", "export const n = 1;\n")
        env = {"PATH": str(node.parent)}
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            executable, preload, before = PROBE._runtime_launch_bindings(self.root, env)
            helper.write_text("export const n = 2;\n", encoding="utf-8")
            after = PROBE._runtime_launch_bindings(self.root, env)[2]
            self.assertNotEqual(before, after)
            with self.assertRaises(PROBE.ProbeError):
                PROBE._assert_runtime_launch_sources_still_bound(
                    openclaw_root=self.root, runner_env=env,
                    expected_node_executable=executable,
                    expected_tsx_preload_specifier=preload, expected_sources=before,
                )

    @unittest.skipUnless(shutil.which("node"), "Node is needed for the CJS syntax oracle")
    def test_node_executes_review_comment_reproductions(self) -> None:
        hidden = self.write("scripts/hidden.cjs", "console.log('hidden-loaded');\n")
        for source in (
            '<!-- "\nrequire("./hidden.cjs");\n<!-- "',
            '#!/usr/bin/env node "\nrequire("./hidden.cjs");\n// "',
            'const r = ((require)); r("./hidden.cjs");',
        ):
            with self.subTest(source=source):
                entry = self.write("scripts/oracle.cjs", source)
                proc = subprocess.run([shutil.which("node"), str(entry)], capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("hidden-loaded", proc.stdout)
                self.assert_bound_or_rejected(source, hidden.relative_to(self.root).as_posix())

    def test_execution_capability_reexports_fail_closed(self) -> None:
        for module, name in (("node:worker_threads", "Worker"), ("node:child_process", "spawnSync"), ("node:module", "Module")):
            for clause in ("*", f"{{ {name} as W }}", f"{{ '{name}' as W }}"):
                with self.subTest(module=module, clause=clause):
                    with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                        self.snapshot(f"export {clause} from '{module}';")

    def test_module_require_transfers_and_indirect_module_objects_fail_closed(self) -> None:
        for source in (
            "const r = module['require']; r('./hidden.cjs');",
            "const r = ((module))['require']; r('./hidden.cjs');",
            "const r = globalThis['require']; r('./hidden.cjs');",
            "const r = module['parent']['require']; r('./hidden.cjs');",
            "import M from 'node:module'; const Alias = M; new Alias().load('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.cjs")

    def test_execution_options_after_a_bound_prefix_fail_closed(self) -> None:
        for source in (
            "new Worker(new URL('./hidden.mjs', import.meta.url), {execArgv:['--import','./extra.mjs']});",
            "import { fork } from 'child_process'; fork('./hidden.cjs', [], {execArgv:['--require','./extra.cjs']});",
            "import { spawnSync } from 'child_process'; spawnSync(process.execPath, ['./hidden.mjs'], {env:{NODE_OPTIONS:'--import ./extra.mjs'}});",
            "import { spawnSync } from 'child_process'; spawnSync(process.execPath, ['./hidden.mjs', ...unknownArgs]);",
        ):
            with self.subTest(source=source):
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot(source)

    def test_nested_package_scope_does_not_inherit_outer_imports(self) -> None:
        self.write("package.json", '{"name":"openclaw","imports":{"#hidden":"./outer.mjs"}}')
        self.write("outer.mjs", "export {};\n")
        self.write("scripts/package.json", '{"name":"inner"}')
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("import '#hidden';")

    def test_actual_jsx_markup_and_implicit_runtime_imports_fail_closed(self) -> None:
        for body in (
            "export const View = () => <div />;",
            'export const view = <div>"{require("./hidden.cjs")}"</div>;',
            'export const view = <div>`{require("./hidden.cjs")}`</div>;',
            '/** @jsxImportSource unbound */ export const View = () => <div />;',
        ):
            with self.subTest(body=body):
                self.write("scripts/view.jsx", "import './hidden.mjs';\n" + body)
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("import './view.jsx';")

    def test_minified_division_and_comment_context_keep_loader_visible(self) -> None:
        source = "const ratio = numerator /* context */ / denominator;\nrequire('./hidden.cjs');"
        self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_unicode_separators_in_string_data_are_not_comment_terminators(self) -> None:
        for separator in ("\u2028", "\u2029"):
            source = f'const data = "{separator}require(unknown)"; require("./hidden.cjs");'
            with self.subTest(separator=repr(separator)):
                self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_symlinked_manifest_keeps_lexical_scope_resolution_base(self) -> None:
        target = self.write("metadata/package.json", '{"name":"inner","imports":{"#hidden":"./hidden.cjs"}}')
        scope = self.root / "scripts/package.json"
        scope.symlink_to(target)
        self.write("metadata/hidden.cjs", "module.exports = {decoy: true};")
        snapshot = self.snapshot("require('#hidden');")
        self.assertIn("scripts/hidden.cjs", snapshot)
        self.assertIn("metadata/package.json", snapshot)
        self.assertNotIn("metadata/hidden.cjs", snapshot)

    def test_native_or_unknown_custom_preload_entrypoints_fail_closed(self) -> None:
        for name in ("loader.node", "loader.wasm", "loader.unknown"):
            self.write(name, "not a parseable runtime entrypoint")
            with self.subTest(name=name), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(self.root, entrypoints=(name,))

    def test_child_entrypoints_bind_launch_cwd_not_calling_module_directory(self) -> None:
        for source in (
            "import {fork} from 'node:child_process'; fork('./hidden.cjs');",
            "import {fork} from 'node:child_process'; fork('hidden.cjs');",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./hidden.cjs']);",
            "import {execFileSync} from 'node:child_process'; execFileSync(process.execPath, ['hidden.cjs']);",
        ):
            with self.subTest(source=source):
                self.write("hidden.cjs", "module.exports = {actual: true};")
                snapshot = self.snapshot(source)
                self.assertIn("hidden.cjs", snapshot)
                self.assertNotIn("scripts/hidden.cjs", snapshot)

    def test_spawned_node_and_transitive_fork_keep_native_resolution(self) -> None:
        self.write("plain.cjs", "const {fork} = require('node:child_process'); fork('./nested.cjs');")
        self.write("nested.cjs", "require('./dependency');")
        self.write("dependency.ts", "require('./decoy.cjs');")
        self.write("dependency.js", "require('./actual.cjs');")
        self.write("decoy.cjs", "module.exports = {};")
        self.write("actual.cjs", "module.exports = {};")
        snapshot = self.snapshot("import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./plain.cjs']);")
        self.assertIn("dependency.js", snapshot)
        self.assertIn("actual.cjs", snapshot)
        self.assertNotIn("dependency.ts", snapshot)
        self.assertNotIn("decoy.cjs", snapshot)

    def test_same_file_reached_by_distinct_loaders_binds_both_dependency_closures(self) -> None:
        self.write("shared.cjs", "require('./dependency');")
        self.write("dependency.ts", "export {};")
        self.write("dependency.js", "module.exports = {};")
        snapshot = self.snapshot(
            "require('../shared.cjs'); import {spawnSync} from 'node:child_process'; "
            "spawnSync(process.execPath, ['./shared.cjs']);"
        )
        self.assertIn("dependency.ts", snapshot)
        self.assertIn("dependency.js", snapshot)

    def test_child_closure_rejects_transitive_ambient_launch_state_capabilities(self) -> None:
        self.write("hidden.cjs", "module.exports = {};")
        for state in (
            "process.chdir('./scripts');", "const move = process.chdir;",
            "process.env.NODE_OPTIONS = '--require ./unbound.cjs';",
            "const environment = globalThis.process['env'];",
            "process.execArgv.push('--require', './unbound.cjs');",
            "process.execPath = './unbound';", "({path: process.execPath} = value);",
            "const launchPath = process.execPath;", "process.loadEnvFile('./unbound.env');",
        ):
            with self.subTest(state=state):
                self.write("scripts/state.mjs", state)
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("import './state.mjs'; import {fork} from 'child_process'; fork('./hidden.cjs');")
        # Ordinary environment reads without a child execution capability retain
        # their pre-existing behavior; this is not a blanket process API ban.
        self.assertTrue(self.snapshot("const mode = process.env.MODE;"))

    def test_child_argv_options_and_absolute_or_escaping_paths_fail_closed(self) -> None:
        for path in ("--import", "-e", "../outside.cjs", "/tmp/absolute.cjs"):
            with self.subTest(path=path), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot("import {spawnSync} from 'child_process'; spawnSync(process.execPath, [" + json.dumps(path) + "]);")

    @unittest.skipUnless(shutil.which("node"), "Node is needed for the child cwd oracle")
    def test_node_child_cwd_oracle_loads_the_bound_file_not_the_importer_decoy(self) -> None:
        self.write("hidden.cjs", "console.log('cwd-target-loaded');")
        self.write("scripts/hidden.cjs", "throw new Error('wrong importer-relative target');")
        source = (
            "const {spawnSync} = require('node:child_process'); "
            "spawnSync(process.execPath, ['./hidden.cjs']);"
        )
        # Execute the identical accepted call and inspect its result without
        # adding unbound loader options or mutating the parent's environment.
        entry = self.write("scripts/cwd-oracle.cjs", source.replace("spawnSync(process", "const result = spawnSync(process") + "console.log(result.stdout.toString()); process.exit(result.status);")
        proc = subprocess.run([shutil.which("node"), str(entry)], cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("cwd-target-loaded", proc.stdout)
        self.assertIn("hidden.cjs", self.snapshot(source))
        self.assertNotIn("scripts/hidden.cjs", self.snapshot(source))

    def test_native_preload_closure_uses_node_not_typescript_suffix_fallback(self) -> None:
        node = self.write("bin/node", "#!/bin/sh\nexit 0\n")
        node.chmod(0o755)
        self.write("node_modules/tsx/package.json", '{"name":"tsx"}')
        loader = self.write("node_modules/tsx/loader.cjs", "require('helper');")
        self.write("node_modules/helper/package.json", '{"name":"helper","main":"index.cjs"}')
        self.write("node_modules/helper/index.cjs", "require('./dependency');")
        native = self.write("node_modules/helper/dependency.js", "module.exports = {v: 1};")
        decoy = self.write("node_modules/helper/dependency.ts", "export const v = 1;")
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            before = PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})[2]
            decoy.write_text("export const v = 2;", encoding="utf-8")
            self.assertEqual(before, PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})[2])
            native.write_text("module.exports = {v: 2};", encoding="utf-8")
            self.assertNotEqual(before, PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})[2])

    def test_unsupported_identifier_grammars_cannot_hide_execution_namespaces(self) -> None:
        for source in (
            "import 进程 from 'node:child_process'; 进程.spawnSync('./unbound.sh');",
            "import 模块 from 'node:module'; new 模块().load('./hidden.cjs');",
            "const 模块 = require('node:module'); new 模块().load('./hidden.cjs');",
            "import M\u200c from 'node:module'; new M\u200c().load('./hidden.cjs');",
            r"import \u6a21\u5757 from 'node:module'; new \u6a21\u5757().load('./hidden.cjs');",
        ):
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot(source)

    def test_unicode_data_comments_and_literal_import_paths_remain_supported(self) -> None:
        self.write("scripts/实现.cjs", "module.exports = {};")
        source = "// 模块名称\nconst text = '进程'; const re = /模块/; require('./实现.cjs');"
        self.assertIn("scripts/实现.cjs", self.snapshot(source))
