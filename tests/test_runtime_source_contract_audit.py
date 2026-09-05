"""Regression matrix for PR45: capability provenance and complete file identity."""
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


class RuntimeSourceAuditTests(unittest.TestCase):
    def write_fixture(self, root: Path, files: dict[str, str]) -> None:
        probe_tests.RealGatewayProbeTests._write_runtime_source_fixture(self, root, files)

    def assert_rejected(self, source: str) -> None:
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers(source)

    def test_worker_capabilities_cannot_escape_through_value_expressions(self) -> None:
        expressions = (
            "const W = Worker;", "let W; W = Worker;", "const W = (((Worker)));",
            "const holder = {W: Worker};", "const holder = [Worker];",
            "function get() { return Worker; }", "consume(Worker);",
            "const W = Worker.bind(null);", "const W = (0, Worker);",
            "export { Worker };", "class W extends Worker {}",
            "const s = `${(() => { const W = Worker; return 1; })()}`;",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assert_rejected("import {Worker} from 'node:worker_threads';" + expression)

    def test_namespace_capabilities_cannot_escape_through_member_spellings(self) -> None:
        for module, name, member in (
            ("node:worker_threads", "wt", "Worker"),
            ("node:child_process", "cp", "spawnSync"),
        ):
            for expression in (
                f"{name}.{member}", f"{name}['{member}']", f'{name}["{member}"]',
                f"{name}[`{member}`]", f"{name}?.['{member}']", f"(({name})).{member}",
                f"{name}[key]", name,
            ):
                for wrapper in ("const go = %s;", "consume(%s);", "const holder = {go: %s};"):
                    with self.subTest(module=module, expression=expression, wrapper=wrapper):
                        self.assert_rejected(
                            f"import * as {name} from '{module}';" + wrapper % expression
                        )

    def test_indirect_builtin_acquisition_fails_closed(self) -> None:
        cases = (
            "const wt = module['require']('node:worker_threads');"
            "const W=wt['Worker'];new W(new URL('./hidden.mjs',import.meta.url));",
            "const wt = await import('node:worker_threads');"
            "new wt.Worker(new URL('./hidden.mjs',import.meta.url));",
            "import {createRequire} from 'node:module';"
            "const wt=createRequire(import.meta.url)('node:worker_threads');"
            "const W=wt['Worker'];new W(new URL('./hidden.mjs',import.meta.url));",
            "export {Worker as W} from 'node:worker_threads';",
            "export * from 'node:child_process';",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_known_loader_alias_cannot_hide_execution_module_origin(self) -> None:
        self.assert_rejected(
            "const r = ((require));const cp = r('node:child_process');"
            "const go=cp['spawnSync'];go('./hidden.sh');"
        )

    def test_escaped_identifiers_and_nested_template_bodies_are_checked(self) -> None:
        self.assert_rejected(
            r"import {Worker as \u0057} from 'node:worker_threads';"
            r"const s=`outer ${`inner ${(() => {const C=\u0057; return 1;})()}`}`;"
        )
        self.assert_rejected(
            r"const r=((\u0072equire)); const later=r; later('./hidden.cjs');"
        )

    def test_multiply_grouped_require_aliases_bind_the_target(self) -> None:
        for depth in (0, 1, 2, 3, 8, 64):
            with self.subTest(depth=depth):
                source = "const r = " + "(" * depth + "require" + ")" * depth + ";r('./hidden.cjs');"
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_require_aliases_with_asi_and_iife_remain_bound(self) -> None:
        for source in (
            "const r=((require))\nr('./hidden.cjs');",
            "(() => {const r=((require));r('./hidden.cjs');})();",
        ):
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_unrecognized_require_value_transfers_fail_closed(self) -> None:
        for source in (
            "let r; r=((require));r('./hidden.cjs');",
            "const r = (0, require);r('./hidden.cjs');",
            "const box={r:require};box.r('./hidden.cjs');",
            "consume(require);", "function f(){return require;}",
            "const r=module.require;r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_module_require_transfers_fail_closed_at_every_grouping_depth(self) -> None:
        for depth in (0, 1, 2, 8):
            base = "(" * depth + "module" + ")" * depth
            for member in (".require", "['require']", '?.["require"]'):
                with self.subTest(depth=depth, member=member):
                    self.assert_rejected(f"const r={base}{member};r('./hidden.cjs');")
                    self.assertIn(
                        ("./hidden.cjs", True, "require"),
                        CONTRACT.import_specifiers(f"{base}{member}('./hidden.cjs');"),
                    )

    def test_module_constructors_and_factories_cannot_escape(self) -> None:
        for declaration in (
            "import M from 'node:module';", "import * as M from 'node:module';",
            "const M=require('module');", "const {Module:M}=require('module');",
        ):
            for expression in (
                "const C=M;new C().load('./hidden.cjs');",
                "const r=M.prototype['require'];r('./hidden.cjs');",
                "const f=M.createRequire;const r=f(import.meta.url);r('./hidden.cjs');",
                "consume(M);", "const holder=[M];", "export {M};",
            ):
                with self.subTest(declaration=declaration, expression=expression):
                    self.assert_rejected(declaration + expression)
        for expression in (
            "const f=c;const r=f(import.meta.url);r('./hidden.cjs');",
            "consume(c);", "function f(){return c;}",
            "function f(){return c(import.meta.url);}",
            "const r=c(import.meta.url).bind(null);r('./hidden.cjs');",
        ):
            with self.subTest(expression=expression):
                self.assert_rejected("import {createRequire as c} from 'node:module';" + expression)

    def test_namespace_create_require_loaders_bind_their_literal_targets(self) -> None:
        for declaration, base in (
            ("import M from 'node:module';", "import.meta.url"),
            ("import * as M from 'node:module';", "import.meta.url"),
            ("const M=require('module');", "__filename"),
        ):
            for separator in (";", "\n"):
                with self.subTest(declaration=declaration, separator=separator):
                    source = declaration + f"const r=M.createRequire({base})" + separator + "r('./hidden.cjs');"
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_worker_and_child_launch_options_cannot_add_unbound_preloads(self) -> None:
        for source in (
            "import {Worker} from 'node:worker_threads';"
            "new Worker(new URL('./bound.mjs',import.meta.url),{execArgv:['--require','./hidden.cjs']});",
            "import {fork} from 'node:child_process';"
            "fork('./bound.cjs',[],{execArgv:['--require','./hidden.cjs']});",
            "import {spawn} from 'node:child_process';"
            "spawn(process.execPath,['./bound.mjs'],{env:{NODE_OPTIONS:'--require ./hidden.cjs'}});",
            "import {spawnSync} from 'node:child_process';"
            "spawnSync(process.execPath,['./bound.mjs'],{shell:true});",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_direct_bound_execution_forms_remain_supported(self) -> None:
        cases = (
            "import {Worker as W} from 'node:worker_threads';new W(new URL('./bound.mjs',import.meta.url));",
            "import wt from 'node:worker_threads';new wt.Worker(new URL('./bound.mjs',import.meta.url));",
            "const {Worker: W}=require('worker_threads');new W(new URL('./bound.mjs',import.meta.url));",
            "import {spawnSync as run} from 'child_process';run(process.execPath,['./bound.mjs']);",
            "const {fork:run}=require('child_process');run('./bound.mjs');",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertIn("./bound.mjs", [item[0] for item in CONTRACT.import_specifiers(source)])

    def test_hashbang_and_html_comments_preserve_dependencies(self) -> None:
        for ending in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for prefix, suffix in (("#! /usr/bin/env node \"", "// \""), ("<!-- \"", "<!-- \""), ("--> \"", "--> \"")):
                source = prefix + ending + "require('./hidden.cjs');" + ending + suffix
                with self.subTest(ending=repr(ending), prefix=prefix):
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
                    masked = CONTRACT.strip_source_comments(source)
                    self.assertEqual(len(source), len(masked))
                    self.assertEqual(
                        [(i, c) for i, c in enumerate(source) if c in "\r\n\u2028\u2029"],
                        [(i, c) for i, c in enumerate(masked) if c in "\r\n\u2028\u2029"],
                    )

    def test_html_comments_in_template_expressions_do_not_hide_code(self) -> None:
        source = "const s=`text ${(() => {\n<!-- \"\nrequire('./hidden.cjs');\n<!-- \"\nreturn 1;})()}`;"
        self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_comment_spelling_in_data_and_midline_decrement_is_not_a_comment(self) -> None:
        source = (
            "const a='<!-- \\\"';const b=`--> #! \\\"`;const r=/<!-- \\\"/;"
            "let n=2;n-->require('./bound.cjs');"
        )
        self.assertIn(("./bound.cjs", True, "require"), CONTRACT.import_specifiers(source))
        self.assertIn("n-->", CONTRACT.strip_source_comments(source))

    @unittest.skipUnless(shutil.which("node"), "Node is required for the lexical differential oracle")
    def test_comment_fixtures_execute_the_dependency_in_node(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text("console.log('dependency-executed');\n")
            for prefix in ('#! /usr/bin/env node "', '<!-- "', '--> "'):
                source = prefix + "\nrequire('./hidden.cjs');\n// \"\n"
                path = root / "main.cjs"
                path.write_text(source)
                result = subprocess.run([shutil.which("node"), str(path)], capture_output=True, text=True, timeout=10)
                with self.subTest(prefix=prefix):
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual("dependency-executed", result.stdout.strip())
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_ambiguous_asi_regex_contexts_fail_closed(self) -> None:
        prefixes = (
            "debugger\n", "while(true){break\n",
            "outer: while(true){break outer\n",
            "for(let i=0;i<1;i++){continue\n",
        )
        for prefix in prefixes:
            suffix = "}\n" if "{" in prefix else ""
            source = prefix + '/"/;' + suffix + "require('./hidden.cjs');\n/\"/;"
            with self.subTest(prefix=prefix):
                self.assert_rejected(source)

    def test_contextual_keywords_and_keyword_members_do_not_select_regex_goal(self) -> None:
        for name in ("of", "await", "yield"):
            self.assert_rejected(f"let {name}=1; {name} / x / require('./hidden.cjs');")
        for name in ("return", "throw", "in", "new", "of", r"ret\u0075rn"):
            self.assert_rejected(f"obj.{name} / x / require('./hidden.cjs');")

    def test_nested_template_regex_braces_do_not_terminate_expressions(self) -> None:
        source = "const s=`outer ${`inner ${ /}/.test('x') ? require('./bound.cjs') : '' }`}`;"
        self.assertIn(("./bound.cjs", True, "require"), CONTRACT.import_specifiers(source))

    @unittest.skipUnless(shutil.which("node"), "Node is required for the ASI differential oracle")
    def test_node_executes_dependency_after_asi_regex_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text("console.log('dependency-executed');")
            for prefix in ("debugger\n", "while(true){break\n", "outer: while(true){break outer\n"):
                suffix = "}\n" if "{" in prefix else ""
                source = prefix + '/"/;' + suffix + "require('./hidden.cjs');\n/\"/;"
                path = root / "main.cjs"
                path.write_text(source)
                result = subprocess.run([shutil.which("node"), str(path)], capture_output=True, text=True, timeout=10)
                with self.subTest(prefix=prefix):
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual("dependency-executed", result.stdout.strip())
                    self.assert_rejected(source)

    def test_relative_module_scope_metadata_is_bound_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {
                "openclaw.mjs": "import './node_modules/pkg/sub/file.js';\n",
                "node_modules/pkg/package.json": '{"name":"pkg","type":"commonjs"}',
                "node_modules/pkg/sub/file.js": "console.log(typeof require);\n",
            })
            (root / ".gitignore").write_text("node_modules/\n")
            for args in (
                ("init", "-q"), ("config", "user.name", "fixture"),
                ("config", "user.email", "fixture@example.invalid"),
                ("add", "."), ("commit", "-qm", "source fixture"),
            ):
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("node_modules/pkg/package.json", before)
            manifest = root / "node_modules/pkg/sub/package.json"
            manifest.write_text('{"type":"module"}')
            after = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertNotEqual(before, after)
            self.assertIn("node_modules/pkg/sub/package.json", after)
            manifest.write_text('{"type":"commonjs"}')
            changed = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertNotEqual(after, changed)
            expected = CONTRACT.source_records_from_snapshot(after)
            with self.assertRaisesRegex(PROBE.ProbeError, "closure changed"):
                PROBE._assert_runtime_sources_still_bound(root, expected)
            manifest.unlink()
            self.assertEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_entrypoint_scope_and_invalid_metadata_are_not_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {"scripts/package.json": '{"type":"module"}'})
            self.assertIn("scripts/package.json", CONTRACT.runtime_source_paths(root))
            (root / "scripts/package.json").write_text("{")
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)

    def test_package_scope_does_not_cross_node_modules_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {
                "openclaw.mjs": "import './node_modules/pkg/file.js';",
                "node_modules/package.json": "not valid metadata",
                "node_modules/pkg/file.js": "console.log('bound');",
            })
            self.assertNotIn("node_modules/package.json", CONTRACT.runtime_source_paths(root))

    def test_scope_symlinks_cannot_hide_a_new_lookup_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, {})
            (root / "scripts/package.json").symlink_to(root / "package.json")
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.runtime_source_paths(root)


class RuntimePreloadInventoryTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, dict[str, str]]:
        node = root / "bin/node"
        node.parent.mkdir()
        node.write_text("#!/bin/sh\n")
        node.chmod(0o755)
        loader = root / "node_modules/tsx/dist/loader.mjs"
        loader.parent.mkdir(parents=True)
        (loader.parent.parent / "package.json").write_text('{"name":"tsx","type":"module"}')
        loader.write_text("export * from 'helper';")
        helper = root / "node_modules/helper/index.mjs"
        helper.parent.mkdir(parents=True)
        helper.write_text("export const version = 1;")
        (helper.parent / "package.json").write_text('{"name":"helper","type":"module","exports":"./index.mjs"}')
        return node, loader, {"PATH": str(node.parent)}

    def bindings(self, root: Path, loader: Path, env: dict[str, str]):
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            return PROBE._runtime_launch_bindings(root, env)

    def test_transitive_preload_sibling_and_metadata_change_the_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, loader, env = self.fixture(root)
            _, specifier, expected = self.bindings(root, loader, env)
            before = {item["path"]: item for item in expected}
            helper = root / "node_modules/helper/index.mjs"
            helper.write_text("export const version = 2;")
            after = {item["path"]: item for item in self.bindings(root, loader, env)[2]}
            self.assertEqual(before["runtime-preload:tsx"], after["runtime-preload:tsx"])
            self.assertEqual(before["runtime-preload-package:tsx"], after["runtime-preload-package:tsx"])
            self.assertNotEqual(before["runtime-preload-installation:tsx"], after["runtime-preload-installation:tsx"])
            with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                with self.assertRaisesRegex(PROBE.ProbeError, "source binding changed"):
                    PROBE._assert_runtime_launch_sources_still_bound(
                        openclaw_root=root, runner_env=env, expected_node_executable=node,
                        expected_tsx_preload_specifier=specifier, expected_sources=expected,
                    )
            baseline = self.bindings(root, loader, env)[2]
            (helper.parent / "package.json").write_text('{"name":"helper","exports":"./alternate.mjs"}')
            self.assertNotEqual(baseline, self.bindings(root, loader, env)[2])

    def test_inventory_binds_pnpm_links_targets_and_retargeting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, loader, env = self.fixture(root)
            store = root / "node_modules/.pnpm/dep/node_modules/dep"
            store.mkdir(parents=True)
            target = store / "index.cjs"
            target.write_text("module.exports=1;")
            link = root / "node_modules/dep"
            link.symlink_to(store, target_is_directory=True)
            before = self.bindings(root, loader, env)[2]
            target.write_text("module.exports=2;")
            self.assertNotEqual(before, self.bindings(root, loader, env)[2])
            before = self.bindings(root, loader, env)[2]
            link.unlink()
            link.symlink_to(root / "node_modules/helper", target_is_directory=True)
            self.assertNotEqual(before, self.bindings(root, loader, env)[2])

    def test_external_dangling_and_special_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            _, loader, env = self.fixture(root)
            outside = Path(external) / "hidden.cjs"
            outside.write_text("module.exports=1;")
            link = root / "node_modules/hidden.cjs"
            for target in (outside, root / "missing.cjs"):
                link.symlink_to(target)
                with self.subTest(target=str(target)), self.assertRaises(PROBE.ProbeError):
                    self.bindings(root, loader, env)
                link.unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(link)
                with self.assertRaisesRegex(PROBE.ProbeError, "non-regular"):
                    self.bindings(root, loader, env)

    def test_launch_binding_validation_requires_exact_unique_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, loader, env = self.fixture(root)
            expected = self.bindings(root, loader, env)[2]
            self.assertEqual(expected, PROBE._validate_runtime_launch_sources(expected))
            for invalid in (expected[:-1], expected + [expected[-1]], expected + [{"path":"extra"}]):
                with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeError):
                    PROBE._validate_runtime_launch_sources(invalid)

    def test_persistent_authority_guard_remains_disabled(self) -> None:
        with self.assertRaisesRegex(PROBE.ProbeError, "authority is disabled"):
            PROBE._require_trusted_persistent_lifecycle_boundary()


if __name__ == "__main__":
    unittest.main()
