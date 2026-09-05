"""Regression matrix for PR45's source-closure review, without executing candidates."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_openclaw_real_gateway_contract_probe as probe_tests


PROBE = probe_tests.MODULE
CONTRACT = PROBE.runtime_source_contract


class RuntimeSourceContractReviewTests(unittest.TestCase):
    def fixture(self, root: Path, files: dict[str, str]) -> None:
        probe_tests.RealGatewayProbeTests._write_runtime_source_fixture(self, root, files)

    def test_worker_capability_transfers_fail_closed(self) -> None:
        transfers = (
            "const W = Worker; new W(new URL('./hidden.mjs', import.meta.url));",
            "const W = ((Worker)); new W(new URL('./hidden.mjs', import.meta.url));",
            "let W; W = Worker; new W(new URL('./hidden.mjs', import.meta.url));",
            "const box = [Worker]; new box[0](new URL('./hidden.mjs', import.meta.url));",
            "const box = { Worker }; new box.Worker(new URL('./hidden.mjs', import.meta.url));",
            "const W = (() => Worker)(); new W(new URL('./hidden.mjs', import.meta.url));",
            "Reflect.construct(Worker, [new URL('./hidden.mjs', import.meta.url)]);",
            "const W = Worker.bind(null); new W(new URL('./hidden.mjs', import.meta.url));",
            "export { Worker as HiddenWorker };",
            "const text = `${(() => Worker)()}`;",
            "const text = `${`${(() => Worker)()}`}`;",
        )
        for transfer in transfers:
            with self.subTest(transfer=transfer), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers("import { Worker } from 'node:worker_threads';\n" + transfer)

    def test_namespace_and_acquisition_transfers_fail_closed(self) -> None:
        cases = (
            "import * as wt from 'node:worker_threads'; const W = wt['Worker'];",
            "import * as wt from 'node:worker_threads'; const W = wt[`Worker`];",
            "import * as wt from 'node:worker_threads'; const ns = wt;",
            "import * as wt from 'node:worker_threads'; const { Worker: W } = wt;",
            "const {Worker: W} = (require('node:worker_threads'));",
            "const wt = ((require('node:worker_threads')));",
            "const wt = await import('node:worker_threads');",
            "export * from 'node:worker_threads';",
            "export { 'Worker' as W } from 'node:worker_threads';",
            "const load = require; const wt = load('node:worker_threads');",
            "import * as cp from 'node:child_process'; const go = cp['spawnSync'];",
            "import * as cp from 'node:child_process'; const go = cp[`spawnSync`];",
            "import * as cp from 'node:child_process'; const go = cp['spawn' + 'Sync'];",
            "import * as cp from 'node:child_process'; const ns = cp;",
            "import * as cp from 'node:child_process'; const {spawnSync: go} = cp;",
            "import * as cp from 'node:child_process'; const go = Reflect.get(cp, 'spawnSync');",
            "import {spawnSync as go} from 'node:child_process'; const box = [go];",
            "import {spawnSync as go} from 'node:child_process'; const f = () => go;",
            "import {spawnSync as go} from 'node:child_process'; export {go};",
            "const cp = ((require('node:child_process')));",
            "module.exports = require('node:child_process');",
            "export * from 'node:child_process';",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_grouped_require_values_are_bound_or_rejected_at_any_depth(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32):
            expression = "(" * depth + "require" + ")" * depth
            with self.subTest(depth=depth):
                try:
                    specifiers = CONTRACT.import_specifiers(
                        f"const r = {expression}; r('./hidden.cjs');"
                    )
                except CONTRACT.RuntimeSourceContractError:
                    continue
                self.assertIn(("./hidden.cjs", True, "require"), specifiers)

    def test_non_declaration_require_transfers_fail_closed(self) -> None:
        cases = (
            "let r; r = ((require)); r('./hidden.cjs');",
            "const box = [require]; box[0]('./hidden.cjs');",
            "const box = {require}; box.require('./hidden.cjs');",
            "const r = (() => require)(); r('./hidden.cjs');",
            "const r = module.require; r('./hidden.cjs');",
            "const r = module['require']; r('./hidden.cjs');",
            "const m = module; m.require('./hidden.cjs');",
            "const r = globalThis['require']; r('./hidden.cjs');",
            "const r = globalThis['requ' + 'ire']; r('./hidden.cjs');",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_supported_static_calls_still_bind(self) -> None:
        cases = (
            "const r = require; r('./hidden.cjs');",
            "((require))('./hidden.cjs');",
            "module?.['require']?.('./hidden.cjs');",
            "import { Worker as W } from 'node:worker_threads'; new W(new URL('./hidden.cjs', import.meta.url));",
            "import wt, { Worker as W } from 'node:worker_threads'; new W(new URL('./hidden.cjs', import.meta.url));",
            "import * as wt from 'node:worker_threads'; new wt['Worker'](new URL('./hidden.cjs', import.meta.url));",
            "import {spawnSync as go} from 'node:child_process'; go(process.execPath, ['./hidden.cjs', '--data']);",
            "import {fork as go} from 'node:child_process'; go('./hidden.cjs');",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertIn("./hidden.cjs", [item[0] for item in CONTRACT.import_specifiers(source)])

    def test_entrypoint_options_cannot_add_unbound_loaders(self) -> None:
        calls = (
            "new Worker(new URL('./safe.mjs', import.meta.url), {execArgv: ['--import', './hidden.mjs']});",
            "new Worker(new URL('./safe.mjs', import.meta.url), options);",
            "fork('./safe.cjs', [], {execArgv: ['--require', './hidden.cjs']});",
            "spawnSync(process.execPath, ['./safe.cjs'], {shell:true});",
            "spawnSync(process.execPath, ['./safe.cjs'], {env:{NODE_OPTIONS:'--require ./hidden.cjs'}});",
            "spawnSync(process.execPath, ['./safe.cjs', ...args]);",
        )
        prefix = "import {Worker} from 'node:worker_threads'; import {fork,spawnSync} from 'node:child_process';\n"
        for call in calls:
            with self.subTest(call=call), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(prefix + call)

    def test_all_script_comment_forms_and_terminators_preserve_real_imports(self) -> None:
        for marker in ("#! /usr/bin/node", "<!--", "-->", "//"):
            for terminator in ("\n", "\r", "\u2028", "\u2029"):
                source = marker + ' " ` /' + terminator + "require('./hidden.cjs');" + terminator
                with self.subTest(marker=marker, terminator=repr(terminator)):
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
                    cleaned = CONTRACT.strip_source_comments(source)
                    self.assertEqual(len(cleaned), len(source))
                    self.assertIn(terminator, cleaned)

    def test_annex_b_comment_after_block_comment_line_break(self) -> None:
        for terminator in ("\n", "\r", "\u2028", "\u2029"):
            with self.subTest(terminator=repr(terminator)):
                source = 'const x = 1; /*' + terminator + '*/ --> "' + terminator + "require('./hidden.cjs');"
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_comment_markers_and_capabilities_in_literal_data_are_inert(self) -> None:
        cases = (
            "const s = `<!-- require('./absent.cjs') -->`;",
            "const s = \"#! require('./absent.cjs')\";",
            "const s = \"import {Worker} from 'node:worker_threads'; const W = Worker;\";",
            "const s = \"new Worker(new URL('./absent.cjs', import.meta.url))\";",
            "const r = /<!--['`]/;",
            "const r = /[/*]/;",
            "const s = `raw ${`nested ${/}/.test('}') ? 1 : 0}`} <!--`;",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_nested_template_expressions_keep_imports_and_ignore_comment_quotes(self) -> None:
        cases = (
            "const x = `${/* ' */ require('./hidden.cjs')}`;",
            "const x = `${`${require('./hidden.cjs')}`}`;",
            "const x = `${/}/.test('}') ? require('./hidden.cjs') : 0}`;",
            "const x = `${<!-- ' \n require('./hidden.cjs')}`;",
            "const x = `${re\\u0071uire('./hidden.cjs')}`;",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_nested_package_scope_edits_additions_and_removals_change_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../lib/sub/entry.js';",
                "lib/sub/entry.js": "export const value = 1;",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            manifest = root / "lib/sub/package.json"
            manifest.write_text('{"type":"module"}')
            added = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("lib/sub/package.json", added)
            self.assertNotEqual(before, added)
            manifest.write_text('{"type":"commonjs"}')
            self.assertNotEqual(added, CONTRACT.runtime_source_digest_snapshot(root))
            manifest.unlink()
            self.assertEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_relative_dependency_inside_package_binds_nearest_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import 'pkg';",
                "node_modules/pkg/package.json": '{"name":"pkg","main":"index.js"}',
                "node_modules/pkg/index.js": "require('./sub/entry.js');",
                "node_modules/pkg/sub/entry.js": "module.exports = 1;",
                "node_modules/pkg/sub/package.json": '{"type":"commonjs"}',
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("node_modules/pkg/sub/package.json", before)
            (root / "node_modules/pkg/sub/package.json").write_text('{"type":"module"}')
            self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_invalid_and_external_scope_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../lib/entry.js';",
                "lib/entry.js": "export const value = 1;",
                "lib/package.json": "{",
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_digest_snapshot(root)
            manifest = root / "lib/package.json"
            manifest.unlink()
            target = Path(external) / "package.json"
            target.write_text('{"type":"module"}')
            manifest.symlink_to(target)
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_digest_snapshot(root)

    def test_module_and_factory_capability_transfers_fail_closed(self) -> None:
        cases = (
            "import M from 'node:module'; const N = M; new N().load('./hidden.cjs');",
            "import * as M from 'node:module'; const N = M['Module'];",
            "import {Module as M} from 'node:module'; const box = [M];",
            "import {createRequire as make} from 'node:module'; const alias = make;",
            "import M from 'node:module'; const make = M['createRequire'];",
            "const M = ((require('node:module')));",
            "export * from 'node:module';",
            "import {default as wt} from 'node:worker_threads'; const W = wt['Worker'];",
            "import {default as cp} from 'node:child_process'; const go = cp['spawnSync'];",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_literal_import_prefix_cannot_consume_a_real_binding(self) -> None:
        for prefix in ('const text = "import {decoy}";', 'const text = `import {decoy}`;'):
            for binding, transfer in (
                ("import {Worker as W} from 'node:worker_threads';", "const Alias = W;"),
                ("import {spawnSync as run} from 'node:child_process';", "const Alias = run;"),
                ("import {createRequire as make} from 'node:module';", "const Alias = make;"),
            ):
                with self.subTest(prefix=prefix, binding=binding), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(prefix + "\n" + binding + "\n" + transfer)

    def test_unknown_and_extensionless_executable_leaves_fail_closed(self) -> None:
        for filename in ('hidden.data', 'hidden'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, {
                    CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "require('./" + filename + "');",
                    'scripts/' + filename: "require('./unbound.cjs');",
                    'scripts/unbound.cjs': 'module.exports = 1;',
                })
                with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, 'extension'):
                    CONTRACT.runtime_source_paths(root)

    def test_nearer_manifest_stops_outer_package_imports_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                'package.json': '{"name":"openclaw","imports":{"#dep":"./outer.cjs"}}',
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../lib/entry.mjs';",
                'lib/package.json': '{"type":"module"}',
                'lib/entry.mjs': "import '#dep';",
                'outer.cjs': 'module.exports = 1;',
            })
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_nearer_manifest_stops_outer_package_self_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                'package.json': '{"name":"pkg","exports":"./outer.mjs"}',
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../lib/entry.mjs';",
                'lib/package.json': '{"name":"inner","type":"module"}',
                'lib/entry.mjs': "import 'pkg';",
                'outer.mjs': 'export const wrong = 1;',
                'node_modules/pkg/package.json': '{"name":"pkg","exports":"./index.mjs"}',
                'node_modules/pkg/index.mjs': 'export const right = 1;',
            })
            paths = CONTRACT.runtime_source_paths(root)
            self.assertIn('node_modules/pkg/index.mjs', paths)
            self.assertNotIn('outer.mjs', paths)

    def test_scope_manifest_symlink_does_not_move_imports_base_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import '../lib/entry.mjs';",
                'lib/entry.mjs': "import '#dep';",
                'metadata/scope.json': '{"type":"module","imports":{"#dep":"./dep.mjs"}}',
                'metadata/dep.mjs': 'export const wrong = 1;',
                'lib/dep.mjs': 'export const right = 1;',
            })
            (root / 'lib/package.json').symlink_to('../metadata/scope.json')
            paths = CONTRACT.runtime_source_paths(root)
            self.assertIn('lib/dep.mjs', paths)
            self.assertIn('metadata/scope.json', paths)
            self.assertNotIn('metadata/dep.mjs', paths)

    def test_child_scripts_bind_candidate_cwd_not_importer_directory(self) -> None:
        for statement in (
            "spawnSync(process.execPath, ['./child.cjs']);",
            "fork('./child.cjs');",
        ):
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, {
                    CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import {spawnSync,fork} from 'node:child_process'; " + statement,
                    'child.cjs': "require('./actual.cjs');",
                    'actual.cjs': 'module.exports = 1;',
                    'scripts/child.cjs': 'module.exports = 0;',
                })
                paths = CONTRACT.runtime_source_paths(root)
                self.assertIn('child.cjs', paths)
                self.assertIn('actual.cjs', paths)
                self.assertNotIn('scripts/child.cjs', paths)

    def test_child_cwd_mutation_and_unresolved_cli_paths_fail_closed(self) -> None:
        for source in (
            "process.chdir('./other');",
            "process['chdir']('./other');",
            "const cd = process.chdir;",
            "const p = process; p.chdir('./other');",
        ):
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import {fork} from 'node:child_process'; fork('./child.cjs');",
                'scripts/child.cjs': 'module.exports = 0;',
            })
            with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, 'candidate cwd'):
                CONTRACT.runtime_source_paths(root)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the CLI differential check')
    def test_child_cwd_contract_matches_real_node(self) -> None:
        # Only these fixed test-owned programs execute; no candidate code does.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                'child.cjs': "process.stdout.write('root');",
                'scripts/child.cjs': "process.stdout.write('importer');",
                'scripts/parent.cjs': (
                    "const {spawnSync}=require('node:child_process');"
                    "process.stdout.write(spawnSync(process.execPath,['./child.cjs']).stdout);"
                ),
            })
            result = subprocess.run(
                [shutil.which('node'), 'scripts/parent.cjs'], cwd=root,
                text=True, capture_output=True, check=True, timeout=10,
                env={key: value for key, value in os.environ.items() if not key.startswith('NODE_')},
            )
            self.assertEqual(result.stdout, 'root')
            self.assertEqual(CONTRACT.resolve_import(
                root=root, importer=root/'scripts/parent.cjs', specifier='./child.cjs',
                required=True, import_kind='process',
            ), (root/'child.cjs',))

    def launch_fixture(self, root: Path) -> tuple[Path, Path]:
        node = root / "bin/node"
        node.parent.mkdir()
        node.write_bytes(b"fake Node binary, never executed")
        node.chmod(0o755)
        loader = root / "node_modules/tsx/dist/loader.mjs"
        loader.parent.mkdir(parents=True)
        (loader.parent.parent / "package.json").write_text('{"name":"tsx"}')
        loader.write_text("import '../../helper/entry.mjs';")
        helper = root / "node_modules/helper/entry.mjs"
        helper.parent.mkdir(parents=True)
        helper.write_text("export const value = 1;")
        return node, loader

    def launch_bindings(self, root: Path, node: Path, loader: Path) -> list[dict[str, str]]:
        with mock.patch.object(PROBE.shutil, "which", return_value=str(node)), mock.patch.object(
            PROBE, "_resolve_node_import_path", return_value=loader
        ):
            return PROBE._runtime_launch_bindings(root, {"PATH": str(node.parent)})[2]

    def test_preload_sibling_transitive_native_and_config_bytes_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader = self.launch_fixture(root)
            baseline = self.launch_bindings(root, node, loader)
            self.assertIn("runtime-preload-installation:tsx", {item["path"] for item in baseline})
            for relative in ("node_modules/helper/entry.mjs", "node_modules/helper/deep/extra.cjs", "node_modules/@esbuild/platform/bin/esbuild", "tsconfig.json"):
                with self.subTest(relative=relative):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"changed dependency bytes")
                    current = self.launch_bindings(root, node, loader)
                    self.assertNotEqual(baseline, current)
                    baseline = current
            self.assertNotIn(str(root), json.dumps(baseline))

    def test_preload_inventory_binds_symlink_topology_and_execute_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.launch_fixture(root)
            alias = root / "node_modules/alias"
            alias.symlink_to("helper", target_is_directory=True)
            before = PROBE._runtime_installation_binding(root)
            helper = root / "node_modules/helper/entry.mjs"
            helper.chmod(0o755)
            self.assertNotEqual(before, PROBE._runtime_installation_binding(root))
            before = PROBE._runtime_installation_binding(root)
            alias.unlink()
            alias.symlink_to("./helper", target_is_directory=True)
            self.assertNotEqual(before, PROBE._runtime_installation_binding(root))

    def test_preload_inventory_rejects_external_dangling_and_cyclic_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            self.launch_fixture(root)
            link = root / "node_modules/bad"
            for target in (external, "missing", "bad"):
                with self.subTest(target=target):
                    link.symlink_to(target)
                    with self.assertRaises(PROBE.ProbeError):
                        PROBE._runtime_installation_binding(root)
                    link.unlink()

    def test_preload_inventory_rejects_special_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.launch_fixture(root)
            os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(PROBE.ProbeError, "non-regular"):
                PROBE._runtime_installation_binding(root)

    def test_external_preload_is_not_a_bound_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            node, _ = self.launch_fixture(root)
            _, loader = self.launch_fixture(Path(external))
            with self.assertRaisesRegex(PROBE.ProbeError, "escapes"):
                self.launch_bindings(root, node, loader)

    def test_old_launch_receipt_without_installation_binding_is_rejected(self) -> None:
        records = [{"path": name, "sha256": "a" * 64, "realpath_sha256": "b" * 64}
                   for name in PROBE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS
                   if name != "runtime-preload-installation:tsx"]
        with self.assertRaisesRegex(PROBE.ProbeError, "incomplete"):
            PROBE._validate_runtime_launch_sources(records)


if __name__ == "__main__":
    unittest.main()
