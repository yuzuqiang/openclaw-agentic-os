"""Adversarial regression matrix for the PR45 source-closure review.

Keep these tests independent from the persistent-runner mocks: the closure is
computed from real temporary files, and representative syntax is also executed
by Node when it is installed. No test requests production runtime authority.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = _load_script("closure_review_regressions", "agentic_os_runtime_source_contract.py")
PROBE = _load_script("preload_review_regressions", "openclaw-real-gateway-contract-probe.py")
NODE = shutil.which("node")


class RuntimeSourceContractReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pr45-closure-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(relative, "{}\n" if relative == "package.json" else "export {};\n")

    def write(self, relative: str, source: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def source(self, source: str) -> None:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)

    def test_worker_capability_transfers_are_rejected_at_the_origin(self) -> None:
        acquisitions = (
            ("import {Worker} from 'node:worker_threads';", "Worker"),
            ("import {Worker as W} from 'worker_threads';", "W"),
            ("import wt, {Worker as W} from 'node:worker_threads';", "W"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("import wt from 'node:worker_threads';", "wt['Worker']"),
            ("const {Worker: W} = require('node:worker_threads');", "W"),
        )
        transfers = (
            "const Alias = {cap};",
            "const Alias = (({cap}));",
            "let Alias; Alias = {cap};",
            "const aliases = [{cap}];",
            "const aliases = {{ run: {cap} }};",
            "accept({cap});",
            "function get() {{ return {cap}; }}",
            "export const Alias = {cap};",
            "const ignored = `text ${{accept({cap})}}`;",
        )
        for declaration, capability in acquisitions:
            for transfer in transfers:
                source = declaration + "\n" + transfer.format(cap=capability)
                with self.subTest(source=source), self.assertRaisesRegex(
                    CONTRACT.RuntimeSourceContractError, "Worker entrypoint.*transfer"
                ):
                    CONTRACT.import_specifiers(source)

    def test_worker_namespace_cannot_escape_or_be_reexported(self) -> None:
        sources = (
            "import * as wt from 'node:worker_threads'; const ns = ((wt));",
            "import wt from 'node:worker_threads'; const {Worker: W} = wt;",
            "const wt = ((require('node:worker_threads'))); const W = wt.Worker;",
            "export {Worker as Hidden} from 'node:worker_threads';",
            "export * from 'node:worker_threads';",
            "const {Worker} = await import('node:worker_threads');",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_child_process_transfer_matrix_is_fail_closed(self) -> None:
        for member in ("fork", "spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync"):
            for expression in (f"cp.{member}", f"cp['{member}']", f'cp["{member}"]', f"cp[`{member}`]", f"(cp)['{member}']"):
                for transfer in ("const go = {cap};", "let go; go = (({cap}));", "accept({cap});", "const box = {{go: {cap}}};"):
                    source = "import * as cp from 'node:child_process';\n" + transfer.format(cap=expression)
                    with self.subTest(source=source), self.assertRaisesRegex(
                        CONTRACT.RuntimeSourceContractError, "child-process"
                    ):
                        CONTRACT.import_specifiers(source)

    def test_child_namespace_and_constructor_acquisitions_are_not_silent(self) -> None:
        sources = (
            "import * as cp from 'node:child_process'; const copy = cp; copy.spawn('./hidden.sh');",
            "const cp = ((require('node:child_process'))); cp.spawn('./hidden.sh');",
            "const r = require; const cp = r('child_process'); cp.spawn('./hidden.sh');",
            "import {ChildProcess} from 'node:child_process'; const c = new ChildProcess();",
            "export {spawnSync as go} from 'node:child_process';",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_require_arbitrary_grouping_cannot_create_an_untracked_alias(self) -> None:
        for depth in (2, 3, 8, 40):
            for gap in ("", " ", "/* quote: \" */", "\r", "\u2028", "\u2029"):
                reference = "(" * depth + gap + "require" + gap + ")" * depth
                source = f"const r = {reference}; r('./hidden.cjs');"
                with self.subTest(depth=depth, gap=gap), self.assertRaisesRegex(
                    CONTRACT.RuntimeSourceContractError, "CommonJS require"
                ):
                    CONTRACT.import_specifiers(source)

    def test_require_non_assignment_transfers_are_not_silent(self) -> None:
        sources = (
            "let r; r = require; r('./hidden.cjs');",
            "const [r] = [require]; r('./hidden.cjs');",
            "const box = {r: require}; box.r('./hidden.cjs');",
            "function get() { return require; } get()('./hidden.cjs');",
            "accept(require);",
            "const value = `text ${accept(require)}`;",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(
                CONTRACT.RuntimeSourceContractError, "CommonJS require"
            ):
                CONTRACT.import_specifiers(source)

    def test_module_require_reference_transfers_are_rejected(self) -> None:
        for reference in ("module.require", "module . require", "(module).require", "((module)) . require", "module['require']", "module[`require`]", "module?.['require']"):
            with self.subTest(reference=reference), self.assertRaisesRegex(
                CONTRACT.RuntimeSourceContractError,
                "CommonJS require|dynamic native add-on process property access",
            ):
                CONTRACT.import_specifiers(f"const r = {reference}; r('./hidden.cjs');")

    def test_identifier_escapes_are_decoded_before_every_scanner(self) -> None:
        for name in (r"requ\u0069re", r"requ\u{69}re"):
            for source in (f"{name}('./hidden.cjs');", f"const text = `value ${{{name}('./hidden.cjs')}}`;"):
                with self.subTest(source=source):
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_non_ascii_capability_alias_cannot_escape(self) -> None:
        source = "import {Worker as 工作} from 'node:worker_threads'; const W = 工作;"
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "Worker entrypoint"):
            CONTRACT.import_specifiers(source)
        source = "import * as 线程 from 'node:worker_threads'; const W = 线程.Worker;"
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "import binding"):
            CONTRACT.import_specifiers(source)

    def test_property_keywords_cannot_turn_division_into_an_inert_regex(self) -> None:
        for property_name in ("of", "return", "await", "yield", "typeof", "new"):
            source = f"const obj = {{ {property_name}: 1 }}; const value = obj.{property_name} / require('hidden') + 1 / 2;"
            with self.subTest(property_name=property_name):
                self.assertIn(("hidden", True, "require"), CONTRACT.import_specifiers(source))
        for name in ("of", "await", "yield"):
            source = f"const {name} = 1; const value = {name} / require('hidden') / 2;"
            with self.subTest(name=name), self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "ambiguous JavaScript slash"):
                CONTRACT.import_specifiers(source)

    def test_custom_child_and_worker_launch_envelopes_fail_closed(self) -> None:
        sources = (
            "import {Worker} from 'node:worker_threads'; new Worker(new URL('./bound.mjs', import.meta.url), {execArgv: ['--import', './hidden.mjs']});",
            "import {fork} from 'node:child_process'; fork('./bound.cjs', [], {execArgv: ['--require', './hidden.cjs']});",
            "import {spawn} from 'node:child_process'; spawn(process.execPath, ['./bound.mjs'], {env:{NODE_OPTIONS:'--import ./hidden.mjs'}});",
            "import {spawn} from 'node:child_process'; spawn(process.execPath, ['./bound.mjs'], {shell:true});",
            "import {spawn} from 'node:child_process'; spawn(process.execPath, ['./bound.mjs', ...args]);",
            "import {fork} from 'node:child_process'; fork('./bound.cjs', {cwd: '/elsewhere'});",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "entrypoint options or arguments"):
                CONTRACT.import_specifiers(source)

    def test_child_launches_bind_the_candidate_cwd_not_the_importer_directory(self) -> None:
        self.source("import {fork, spawnSync} from 'node:child_process'; fork('./child.cjs'); spawnSync(process.execPath, ['./child.cjs', '--application-argument']);")
        self.write("child.cjs", "module.exports = 'actual';")
        self.write("scripts/child.cjs", "module.exports = 'decoy';")
        paths = CONTRACT.runtime_source_paths(self.root)
        self.assertIn("child.cjs", paths)
        self.assertNotIn("scripts/child.cjs", paths)

    def test_node_launch_flags_are_not_interpreted_as_package_imports(self) -> None:
        self.source("import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['--require', './hidden.cjs']);")
        self.write("node_modules/--require/package.json", '{"main":"decoy.js"}')
        self.write("node_modules/--require/decoy.js", "module.exports = 1;")
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "Node launch flags"):
            CONTRACT.runtime_source_paths(self.root)

    def test_source_cannot_change_the_default_launch_cwd(self) -> None:
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "working-directory change"):
            CONTRACT.import_specifiers("process.chdir('/elsewhere');")

    def test_supported_direct_calls_and_single_hop_require_still_bind(self) -> None:
        cases = (
            ("require('./hidden.cjs');", "./hidden.cjs", "require"),
            ("const load = require; load('./hidden.cjs');", "./hidden.cjs", "require"),
            ("import wt, {Worker as W} from 'node:worker_threads'; new W(new URL('./hidden.mjs', import.meta.url));", "./hidden.mjs", "import"),
            ("import {default as wt} from 'node:worker_threads'; new wt.Worker(new URL('./hidden.mjs', import.meta.url));", "./hidden.mjs", "import"),
            ("const {Worker: W} = require('worker_threads'); new W(new URL('./hidden.mjs', import.meta.url));", "./hidden.mjs", "import"),
        )
        for source, path, kind in cases:
            with self.subTest(source=source):
                self.assertIn((path, True, kind), CONTRACT.import_specifiers(source))

    def test_inert_literals_cannot_manufacture_binding_declarations(self) -> None:
        cases = (
            "const example = \"import {Worker as harmless} from 'node:worker_threads';\"; const harmless = 1;",
            "const example = `import {spawnSync as harmless} from 'child_process';`; const harmless = 1;",
            "const example = /import {Worker as harmless} from 'node:worker_threads';/; const harmless = 1;",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    def test_hashbang_and_html_comments_cannot_hide_loaders(self) -> None:
        for newline in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            sources = (
                f'#!/usr/bin/env node "{newline}require("./hidden.cjs");{newline}// "',
                f'<!-- "{newline}require("./hidden.cjs");{newline}<!-- "',
                f'  --> "{newline}require("./hidden.cjs");{newline}  --> "',
                f'/* first{newline}line */ --> "{newline}require("./hidden.cjs");{newline}// "',
                f'const value = `${{{newline}<!-- "{newline}require("./hidden.cjs"){newline}<!-- "{newline}}}`;',
            )
            for source in sources:
                with self.subTest(source=source):
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_legacy_comment_markers_in_literals_remain_inert(self) -> None:
        sources = (
            "const text = '<!-- \\\" require(\\\"./absent.cjs\\\")';",
            "const text = `#!/usr/bin/env node \"\n<!-- \"\n--> \"`;",
            'const pattern = /["<]!--/; require("./hidden.cjs");',
            'let value = 2; value-->0; require("./hidden.cjs");',
        )
        for source in sources:
            with self.subTest(source=source):
                result = CONTRACT.import_specifiers(source)
                self.assertNotIn(("./absent.cjs", True, "require"), result)
                if 'require("./hidden.cjs")' in source:
                    self.assertIn(("./hidden.cjs", True, "require"), result)

    def test_template_match_offsets_are_relative_to_the_original_source(self) -> None:
        source = 'const value = `inert import("fake") ${import("./real.mjs")}`;'
        matches = CONTRACT._executable_pattern_matches(source, re.compile(r'\bimport\s*\('))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].start(), source.index('import("./real.mjs")'))

    def test_nearest_package_type_participates_in_snapshot(self) -> None:
        self.source("import '../node_modules/pkg/sub/file.js';\n")
        self.write("node_modules/pkg/package.json", '{"name":"pkg","type":"module"}')
        scope = self.write("node_modules/pkg/sub/package.json", '{"type":"module"}')
        self.write("node_modules/pkg/sub/file.js", "console.log(typeof require);\n")
        before = CONTRACT.runtime_source_digest_snapshot(self.root)
        self.assertIn("node_modules/pkg/sub/package.json", before)
        scope.write_text('{"type":"commonjs"}', encoding="utf-8")
        after = CONTRACT.runtime_source_digest_snapshot(self.root)
        self.assertNotEqual(before, after)
        self.assertEqual(before["node_modules/pkg/sub/file.js"], after["node_modules/pkg/sub/file.js"])

    def test_package_scope_addition_and_removal_change_the_snapshot(self) -> None:
        self.source("import './sub/entry.js';")
        self.write("scripts/sub/entry.js", "export {};\n")
        initial = CONTRACT.runtime_source_digest_snapshot(self.root)
        scope = self.write("scripts/sub/package.json", '{"type":"module"}')
        added = CONTRACT.runtime_source_digest_snapshot(self.root)
        self.assertNotEqual(initial, added)
        scope.unlink()
        self.assertEqual(initial, CONTRACT.runtime_source_digest_snapshot(self.root))

    def test_nearer_scope_without_imports_stops_parent_imports_lookup(self) -> None:
        self.write("package.json", '{"imports":{"#hidden":"./hidden.mjs"}}')
        self.write("hidden.mjs", "export {};\n")
        self.write("scripts/package.json", '{"type":"module"}')
        self.source("import '#hidden';")
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "imports|scope"):
            CONTRACT.runtime_source_paths(self.root)

    def test_node_modules_is_a_package_scope_boundary(self) -> None:
        self.source("import '../node_modules/pkg/file.js';")
        self.write("node_modules/package.json", 'not valid package metadata')
        self.write("node_modules/pkg/file.js", "export {};\n")
        self.assertNotIn("node_modules/package.json", CONTRACT.runtime_source_paths(self.root))

    def test_invalid_package_scope_fails_closed(self) -> None:
        self.source("import './sub/file.js';")
        self.write("scripts/sub/file.js", "export {};\n")
        scope = self.write("scripts/sub/package.json", "invalid")
        for payload in (b"invalid", b"[]", b"\xff"):
            scope.write_bytes(payload)
            with self.subTest(payload=payload), self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "metadata is invalid"):
                CONTRACT.runtime_source_paths(self.root)

    def test_opaque_commonjs_extensions_are_not_treated_as_data(self) -> None:
        self.source("require('./hidden.data');")
        self.write("scripts/hidden.data", "require('./deeper.cjs');")
        self.write("scripts/deeper.cjs", "module.exports = 1;")
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "unsupported executable extension"):
            CONTRACT.runtime_source_paths(self.root)

    @unittest.skipUnless(NODE, "Node is required for the launch resolution oracle")
    def test_node_confirms_child_entrypoint_resolution_against_launch_cwd(self) -> None:
        self.source("import './launcher.cjs';")
        source = (
            "const {spawnSync} = require('node:child_process');\n"
            "const result = spawnSync(process.execPath, ['./child.cjs']);\n"
            "console.log(result.stdout.toString().trim());\n"
        )
        launcher = self.write("scripts/launcher.cjs", source)
        self.write("child.cjs", "console.log('actual-cwd-entrypoint');")
        self.write("scripts/child.cjs", "console.log('importer-relative-decoy');")
        result = subprocess.run(
            [NODE, str(launcher)], cwd=self.root, text=True,
            capture_output=True, timeout=10, check=True,
        )
        self.assertEqual(result.stdout.strip(), "actual-cwd-entrypoint")
        paths = CONTRACT.runtime_source_paths(self.root)
        self.assertIn("child.cjs", paths)
        self.assertNotIn("scripts/child.cjs", paths)

    @unittest.skipUnless(NODE, "Node is required for the package-scope oracle")
    def test_node_confirms_nearest_package_type_changes_runtime_semantics(self) -> None:
        self.source("import './nested/entry.js';")
        entry = self.write("scripts/nested/entry.js", "console.log(typeof require);")
        scope = self.write("scripts/nested/package.json", '{"type":"module"}')
        before = CONTRACT.runtime_source_digest_snapshot(self.root)
        esm = subprocess.run(
            [NODE, str(entry)], cwd=self.root, text=True,
            capture_output=True, timeout=10, check=True,
        )
        scope.write_text('{"type":"commonjs"}', encoding="utf-8")
        cjs = subprocess.run(
            [NODE, str(entry)], cwd=self.root, text=True,
            capture_output=True, timeout=10, check=True,
        )
        self.assertEqual(esm.stdout.strip(), "undefined")
        self.assertEqual(cjs.stdout.strip(), "function")
        self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(self.root))

    @unittest.skipUnless(NODE, "Node is required for the executable lexical oracle")
    def test_node_executes_the_loader_after_hashbang_and_html_comments(self) -> None:
        hidden = self.write("hidden.cjs", "console.log('dependency-executed');")
        for prefix, suffix in (
            ('#!/usr/bin/env node "\n', '// "'),
            ('<!-- "\n', '<!-- "'),
            (' --> "\n', ' --> "'),
        ):
            source = prefix + "require('./hidden.cjs');\n" + suffix
            entry = self.write("oracle.cjs", source)
            result = subprocess.run([NODE, str(entry)], cwd=self.root, text=True, capture_output=True, timeout=10, check=True)
            self.assertEqual(result.stdout.strip(), "dependency-executed")
            self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
            self.assertTrue(hidden.is_file())


class RuntimePreloadClosureReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pr45-preload-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.node = self.root / "bin" / "node"
        self.node.parent.mkdir()
        self.node.write_text("#!/bin/sh\n", encoding="utf-8")
        self.node.chmod(0o755)
        self.write("package.json", '{"type":"module"}')
        self.write("node_modules/tsx/package.json", '{"name":"tsx","type":"module"}')
        self.loader = self.write("node_modules/tsx/dist/loader.mjs", "import 'helper';")
        self.write("node_modules/helper/package.json", '{"name":"helper","exports":"./index.mjs"}')
        self.helper = self.write("node_modules/helper/index.mjs", "export const value = 1;")

    def write(self, relative: str, source: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def bindings(self):
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=self.loader.resolve()):
            return PROBE._runtime_launch_bindings(self.root, {"PATH": str(self.node.parent)})

    def test_sibling_dependency_content_changes_preload_binding(self) -> None:
        before = self.bindings()
        self.helper.write_text("export const value = 2;", encoding="utf-8")
        after = self.bindings()
        self.assertEqual(before[:2], after[:2])
        self.assertNotEqual(before[2], after[2])
        self.assertNotIn(str(self.root), json.dumps(after[2]))

    def test_transitive_dependency_and_its_scope_metadata_are_bound(self) -> None:
        self.helper.write_text("import './sub/leaf.js';", encoding="utf-8")
        leaf = self.write("node_modules/helper/sub/leaf.js", "console.log(typeof require);")
        scope = self.write("node_modules/helper/sub/package.json", '{"type":"module"}')
        initial = self.bindings()[2]
        leaf.write_text("console.log('changed');", encoding="utf-8")
        changed_leaf = self.bindings()[2]
        self.assertNotEqual(initial, changed_leaf)
        scope.write_text('{"type":"commonjs"}', encoding="utf-8")
        self.assertNotEqual(changed_leaf, self.bindings()[2])

    def test_preload_package_resolution_metadata_is_bound(self) -> None:
        before = self.bindings()[2]
        self.write("node_modules/helper/other.mjs", "export const value = 3;")
        self.write("node_modules/helper/package.json", '{"name":"helper","exports":"./other.mjs"}')
        self.assertNotEqual(before, self.bindings()[2])

    def test_unprovable_preload_code_fails_closed(self) -> None:
        for source in ("await import(globalThis.name);", "import {register} from 'node:module'; register('./loader.mjs', import.meta.url);", "require('./native.node');"):
            self.loader.write_text(source, encoding="utf-8")
            self.write("node_modules/tsx/dist/native.node", "native")
            with self.subTest(source=source), self.assertRaisesRegex(PROBE.ProbeError, "preload dependency closure is unbound"):
                self.bindings()

    def test_preload_dependency_symlink_outside_candidate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr45-outside-") as directory:
            outside = Path(directory) / "outside.mjs"
            outside.write_text("export {};", encoding="utf-8")
            self.helper.unlink()
            self.helper.symlink_to(outside)
            with self.assertRaisesRegex(PROBE.ProbeError, "preload dependency closure is unbound.*escapes"):
                self.bindings()

    def test_source_drift_is_rejected_by_post_runner_launch_revalidation(self) -> None:
        node, preload, sources = self.bindings()
        self.helper.write_text("export const value = 99;", encoding="utf-8")
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=self.loader.resolve()):
            with self.assertRaisesRegex(PROBE.ProbeError, "source binding changed"):
                PROBE._assert_runtime_launch_sources_still_bound(
                    openclaw_root=self.root,
                    runner_env={"PATH": str(self.node.parent)},
                    expected_node_executable=node,
                    expected_tsx_preload_specifier=preload,
                    expected_sources=sources,
                )


if __name__ == "__main__":
    unittest.main()
