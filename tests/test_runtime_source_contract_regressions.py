"""Cross-syntax and real-Node regression witnesses for PR45's source boundary."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
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
        for prefix in ("const of=1; of", "const x=1; x++", "const x=1; x--", "const x={of:1}; x.of"):
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

    def test_literal_process_arguments_remain_supported(self) -> None:
        for source in (
            "import {fork} from 'node:child_process'; fork('./bound.cjs', ['a','b',]);",
            "import {spawnSync} from 'node:child_process'; spawnSync(process.execPath, ['./bound.cjs','a','b',]);",
        ):
            with self.subTest(source=source):
                self.assertIn(("./bound.cjs", True, "process"), CONTRACT.import_specifiers(source))

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
