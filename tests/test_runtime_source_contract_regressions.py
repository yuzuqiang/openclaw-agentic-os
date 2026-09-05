"""Adversarial source/launch binding regressions for the PR45 review boundary.

These fixtures never launch a real Gateway or acquire production authority.
"""
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
SOURCE = PROBE.runtime_source_contract


class RuntimeSourceContractRegressionTests(unittest.TestCase):
    def write_fixture(self, root: Path, files: dict[str, str]) -> None:
        defaults = {p: "export const fixture = true;\n" for p in SOURCE.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS}
        defaults["package.json"] = '{"name":"openclaw","type":"module"}\n'
        defaults.update(files)
        for relative, content in defaults.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_worker_capability_transfers_fail_closed_at_the_origin(self) -> None:
        declarations = (
            ("import { Worker } from 'node:worker_threads';", "Worker"),
            ("import { Worker as W } from 'worker_threads';", "W"),
            ("const { Worker: W } = require('node:worker_threads');", "W"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("import wt from 'node:worker_threads';", "wt['Worker']"),
            ("const wt = require('worker_threads');", "wt[`Worker`]"),
        )
        transfers = (
            "const launch = {cap};",
            "const launch = ((({cap})));",
            "let launch; launch = {cap};",
            "const [launch] = [{cap}];",
            "const box = {{ launch: {cap} }}; const launch = box.launch;",
            "const launch = ((arg) => arg)({cap});",
            "const launch = (() => {cap})();",
            "const launch = {cap}.bind(null);",
        )
        for declaration, capability in declarations:
            for transfer in transfers:
                source = declaration + transfer.format(cap=capability) + "new launch(new URL('./hidden.mjs', import.meta.url));"
                with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                    SOURCE.import_specifiers(source)

    def test_child_process_transfers_cover_members_namespaces_and_chains(self) -> None:
        members = ("fork", "spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync", "ChildProcess")
        for member in members:
            for access in (f"cp.{member}", f"cp['{member}']", f'cp["{member}"]', f"cp[`{member}`]", f"cp?.['{member}']"):
                for expression in (access, f"(({access}))", f"((v) => v)({access})"):
                    source = "import * as cp from 'node:child_process';" + f"const first = {expression}; const go = first; go('./hidden.sh');"
                    with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                        SOURCE.import_specifiers(source)
        for declaration in (
            "import * as cp from 'node:child_process';",
            "import cp from 'child_process';",
            "const cp = require('child_process');",
        ):
            source = declaration + "const next = cp; next.spawnSync('./hidden.sh');"
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_require_aliases_use_balanced_groups_not_a_parenthesis_count_regex(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32):
            for separator in (";", "\n", "\r\n", "\u2028", "\u2029"):
                source = "const load = " + "(" * depth + "/* origin */ require" + ")" * depth + separator + "load('./hidden.cjs');"
                with self.subTest(depth=depth, separator=repr(separator)):
                    self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source))

    def test_require_transfers_that_are_not_proven_alias_declarations_fail_closed(self) -> None:
        sources = (
            "let load; load = require; load('./hidden.cjs');",
            "const [load] = [require]; load('./hidden.cjs');",
            "const box = { load: require }; box.load('./hidden.cjs');",
            "const load = (arg => arg)(require); load('./hidden.cjs');",
            "const load = require.bind(null); load('./hidden.cjs');",
            "const load = require; const other = load; other('./hidden.cjs');",
            "const load = ((require))['bind'](null); load('./hidden.cjs');",
            "const load = ((require))\n('./hidden.cjs');",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_acquisition_reexports_and_dynamic_worker_imports_fail_closed(self) -> None:
        for source in (
            "export { Worker as W } from 'node:worker_threads';",
            "export * from 'node:child_process';",
            "const {Worker: W} = await import('node:worker_threads'); new W('./hidden.mjs');",
            "const load = require; const cp = load('node:child_process'); cp.spawnSync('./hidden.sh');",
            "const W = require('node:worker_threads').Worker; new W('./hidden.mjs');",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_template_data_cannot_authorize_an_executable_capability_transfer(self) -> None:
        source = (
            "import { Worker } from 'node:worker_threads';"
            '`new Worker(new URL("ignored ${save(Worker)}", import.meta.url))`;'
        )
        with self.assertRaises(SOURCE.RuntimeSourceContractError):
            SOURCE.import_specifiers(source)

    def test_inert_literals_do_not_create_execution_entrypoints(self) -> None:
        for source in (
            '''const s = "new Worker(new URL('./missing.mjs', import.meta.url))";''',
            '''const s = `child_process.execSync('./missing.sh')`;''',
            '''const r = /new Worker\\('ignored'\\)/;''',
            '''const s = "import { Worker as hidden } from 'node:worker_threads'";''',
        ):
            with self.subTest(source=source):
                self.assertEqual(SOURCE.import_specifiers(source), [])

    def test_hashbang_and_commonjs_html_comments_do_not_hide_loader_calls(self) -> None:
        for terminator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            sources = (
                '#! /usr/bin/env node "' + terminator + "require('./hidden.cjs'); // \"",
                '<!-- "' + terminator + "require('./hidden.cjs');" + terminator + '<!-- "',
                '  --> "' + terminator + "require('./hidden.cjs');" + terminator + '--> "',
                '/* first' + terminator + 'line */ --> "' + terminator + "require('./hidden.cjs'); // \"",
            )
            for source in sources:
                with self.subTest(source=source):
                    self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source, allow_html_comments=True))
                    normalized = SOURCE.strip_source_comments(source, allow_html_comments=True)
                    self.assertEqual(len(normalized), len(source))
                    self.assertEqual([c for c in normalized if SOURCE._is_js_line_terminator(c)], [c for c in source if SOURCE._is_js_line_terminator(c)])

    def test_html_like_tokens_are_not_silently_erased_from_module_code(self) -> None:
        # In a Module, '<!--' can be '< ! --', not a Script HTML comment.
        for source in ("let a=1,b=2; a<!--b; await import('./hidden.mjs');", "<!-- fake\nimport('./hidden.mjs');"):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_comment_markers_inside_literals_remain_inert(self) -> None:
        source = '''const a = '<!-- "'; const b = `#! /usr/bin/node "`; const c = /<!--/; require('./hidden.cjs');'''
        self.assertEqual(SOURCE.strip_source_comments(source, allow_html_comments=True), source)
        self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source))

    def test_template_interpolation_regex_and_nested_templates_share_lexing(self) -> None:
        for source in (
            '''const s = `${/}/.test('x') ? require('./hidden.cjs') : 0}`;''',
            '''const s = `${`nested ${require('./hidden.cjs')}`}`;''',
            '''const s = `${/* } " */ require('./hidden.cjs')}`;''',
            '''const s = `${<!-- "\nrequire('./hidden.cjs')}`;''',
        ):
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source, allow_html_comments=True))

    def test_scope_manifests_are_bound_for_relative_imports_and_entrypoints(self) -> None:
        for syntax in ("import './sub/entry.js';", "await import('./sub/entry.js');", "require('./sub/entry.js');"):
            with self.subTest(syntax=syntax), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write_fixture(root, {
                    SOURCE.PERSISTENT_LIFECYCLE_RUNNER: "import 'pkg';",
                    "node_modules/pkg/package.json": '{"name":"pkg","main":"index.js"}',
                    "node_modules/pkg/index.js": syntax,
                    "node_modules/pkg/sub/package.json": '{"type":"commonjs"}',
                    "node_modules/pkg/sub/entry.js": "console.log(typeof require);",
                })
                first = SOURCE.runtime_source_digest_snapshot(root)
                scope = "node_modules/pkg/sub/package.json"
                self.assertIn(scope, first)
                (root / scope).write_text('{"type":"module"}')
                self.assertNotEqual(first, SOURCE.runtime_source_digest_snapshot(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {"scripts/package.json": '{"type":"module"}'})
            self.assertIn("scripts/package.json", SOURCE.runtime_source_digest_snapshot(root))

    def test_insertion_and_removal_of_nearer_scope_metadata_change_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {SOURCE.PERSISTENT_LIFECYCLE_RUNNER: "import './sub/entry.js';", "scripts/sub/entry.js": "export const ok=1;"})
            first = SOURCE.runtime_source_digest_snapshot(root)
            scope = root / "scripts/sub/package.json"
            scope.write_text('{"type":"module"}')
            second = SOURCE.runtime_source_digest_snapshot(root)
            self.assertNotEqual(first, second)
            scope.unlink()
            self.assertEqual(first, SOURCE.runtime_source_digest_snapshot(root))

    def test_scope_metadata_cannot_escape_via_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self.write_fixture(root, {})
            external = Path(outside) / "package.json"
            external.write_text('{"type":"module"}')
            (root / "scripts/package.json").symlink_to(external)
            with self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.runtime_source_digest_snapshot(root)

    def test_explicit_commonjs_scope_supports_html_comments_in_js_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {
                SOURCE.PERSISTENT_LIFECYCLE_RUNNER: "import './sub/entry.js';",
                "scripts/sub/package.json": '{"type":"commonjs"}',
                "scripts/sub/entry.js": '<!-- "\nrequire("./hidden.cjs");\n<!-- "',
                "scripts/sub/hidden.cjs": "module.exports = 1;",
            })
            self.assertIn("scripts/sub/hidden.cjs", SOURCE.runtime_source_digest_snapshot(root))

    def test_division_after_keyword_named_properties_cannot_hide_a_bare_package(self) -> None:
        for member in ("of", "return", "throw", "yield", "await", "delete", "new", "in"):
            source = f"const obj={{'{member}':10}}; obj.{member} / require('hidden-package');"
            with self.subTest(member=member):
                self.assertIn(("hidden-package", True, "require"), SOURCE.import_specifiers(source))

    def test_contextual_slash_and_typescript_postfix_ambiguities_fail_closed(self) -> None:
        for source in (
            "const of=10; of / require('hidden-package') / 2;",
            "const await=10; await / require('hidden-package') / 2;",
            "const yield=10; yield / require('hidden-package') / 2;",
            "value! / require('hidden-package') / 2;",
            "value<Type> / require('hidden-package') / 2;",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_ecmascript_bom_whitespace_is_normalized_only_in_code(self) -> None:
        for source in (
            "require\ufeff('hidden-package');",
            "import\ufeff('hidden-package');",
            "import\ufeff'hidden-package';",
            "const load\ufeff=\ufeff((require)); load('hidden-package');",
        ):
            with self.subTest(source=source):
                self.assertTrue(any(s[0] == "hidden-package" for s in SOURCE.import_specifiers(source)))
        inert = "const s='\ufeff'; const t=`\ufeff`;"
        self.assertEqual(SOURCE.strip_source_comments(inert), inert)

    def test_bracketed_module_require_transfers_fail_closed(self) -> None:
        for source in (
            "const load=module['require']; load('hidden-package');",
            'const load=(module["require"]); load("hidden-package");',
            "const load=module?.['require']; load('hidden-package');",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_jsx_text_quotes_and_attributes_cannot_hide_later_loader_calls(self) -> None:
        for source in (
            '''const element=<div>" plain text</div>; require('hidden-package'); // "''',
            '''const element=<div title='"'>plain text</div>; require('hidden-package'); // "''',
            '''const element=<><span>' text</span><span>" text</span></>; require('hidden-package');''',
            '''const element=<div>{require('hidden-package')}</div>;''',
            '''const element=<div title={require('hidden-package')} />;''',
            '''const element=<div>{`text ${require('hidden-package')}`}</div>;''',
            '''const element=<div>require('inert-package')</div>; require('hidden-package');''',
        ):
            with self.subTest(source=source):
                specs = SOURCE.import_specifiers(source)
                self.assertIn(("hidden-package", True, "require"), specs)
                self.assertNotIn(("inert-package", True, "require"), specs)

    def test_jsx_components_do_not_hide_runtime_capability_transfers(self) -> None:
        for source in (
            "import {Worker} from 'node:worker_threads'; const el=<Worker />;",
            "import * as wt from 'node:worker_threads'; const el=<wt.Worker />;",
            "import {spawn as Spawn} from 'node:child_process'; const el=<Spawn />;",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    def test_malformed_lexical_inputs_fail_closed(self) -> None:
        for source in (
            "const el=<div><span /></other>; require('hidden-package');",
            "const el=<div>unterminated; require('hidden-package');",
            "/* unterminated",
            "const t=`unterminated ${require('hidden-package')}",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)

    @unittest.skipUnless(shutil.which("node"), "Node is needed only for the execution witness")
    def test_node_witness_for_grouped_aliases_and_non_slash_comments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text("console.log('BOUND-HIDDEN');")
            for source in (
                "const load = (((require))); load('./hidden.cjs');",
                '<!-- "\nrequire("./hidden.cjs");\n<!-- "',
                '#! /usr/bin/env node "\nrequire("./hidden.cjs"); // "',
            ):
                (root / "entry.cjs").write_text(source)
                with self.subTest(source=source):
                    proc = subprocess.run([shutil.which("node"), str(root / "entry.cjs")], cwd=root, capture_output=True, text=True, timeout=10, check=True)
                    self.assertEqual(proc.stdout.strip(), "BOUND-HIDDEN")
                    self.assertIn(("./hidden.cjs", True, "require"), SOURCE.import_specifiers(source, allow_html_comments=True))


class RuntimeLaunchInstallationRegressionTests(unittest.TestCase):
    def setup_installation(self, root: Path):
        node = root / "bin/node"
        node.parent.mkdir()
        node.write_text("#!/bin/sh\n")
        node.chmod(0o755)
        loader = root / "node_modules/tsx/dist/loader.mjs"
        loader.parent.mkdir(parents=True)
        (loader.parent.parent / "package.json").write_text('{"name":"tsx"}')
        loader.write_text("import 'helper-package'; export const ok=1;")
        helper = root / "node_modules/helper-package/index.mjs"
        helper.parent.mkdir()
        (helper.parent / "package.json").write_text('{"name":"helper-package","type":"module","main":"index.mjs"}')
        helper.write_text("export const helper=1;")
        return node, loader, helper

    def bindings(self, root: Path, node: Path, loader: Path):
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            return PROBE._runtime_launch_bindings(root, {"PATH": str(node.parent)})

    def test_hoisted_helper_changes_invalidate_launch_binding_and_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader, helper = self.setup_installation(root)
            executable, preload, first = self.bindings(root, node, loader)
            helper.write_text("export const helper=2;")
            second = self.bindings(root, node, loader)[2]
            self.assertNotEqual(first, second)
            self.assertNotIn(str(root), json.dumps(second))
            with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader), self.assertRaisesRegex(PROBE.ProbeError, "binding changed"):
                PROBE._assert_runtime_launch_sources_still_bound(openclaw_root=root, runner_env={"PATH": str(node.parent)}, expected_node_executable=executable, expected_tsx_preload_specifier=preload, expected_sources=first)

    def test_workspace_config_native_helpers_and_new_files_are_in_the_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader, helper = self.setup_installation(root)
            first = self.bindings(root, node, loader)[2]
            for relative, data in (("tsconfig.json", b'{"compilerOptions":{}}'), ("workspace/helper.mjs", b"export const v=1;"), ("node_modules/helper-package/helper.node", b"fixture-not-executable")):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                current = self.bindings(root, node, loader)[2]
                self.assertNotEqual(first, current)
                path.unlink()
                # Empty-directory topology is intentionally bound too.
                first = self.bindings(root, node, loader)[2]

    def test_internal_symlink_targets_and_topology_are_bound_without_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader, helper = self.setup_installation(root)
            link = root / "node_modules/tsx/linked-helper"
            link.symlink_to(helper.parent, target_is_directory=True)
            (helper.parent / "back-link").symlink_to(loader.parent.parent, target_is_directory=True)
            first = self.bindings(root, node, loader)[2]
            helper.write_text("export const helper=3;")
            self.assertNotEqual(first, self.bindings(root, node, loader)[2])

    def test_outside_and_dangling_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            node, loader, helper = self.setup_installation(root)
            for target in (Path(outside), root / "missing"):
                link = root / "node_modules/external"
                link.symlink_to(target, target_is_directory=True)
                with self.subTest(target=target), self.assertRaises(PROBE.ProbeError):
                    self.bindings(root, node, loader)
                link.unlink()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_special_files_are_rejected_without_reading_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader, _helper = self.setup_installation(root)
            os.mkfifo(root / "node_modules/pipe")
            with self.assertRaisesRegex(PROBE.ProbeError, "special file"):
                self.bindings(root, node, loader)

    def test_legacy_three_record_launch_binding_is_not_sufficient(self) -> None:
        sources = [{"path": label, "sha256": "1" * 64, "realpath_sha256": "2" * 64} for label in PROBE.PERSISTENT_RUNTIME_LAUNCH_SOURCE_PATHS if label != "runtime-preload-installation:openclaw"]
        with self.assertRaisesRegex(PROBE.ProbeError, "incomplete"):
            PROBE._validate_runtime_launch_sources(sources)


if __name__ == "__main__":
    unittest.main()
