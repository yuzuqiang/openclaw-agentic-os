"""Reference-level and mutation regressions for PR45's source/launch bindings."""
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
SPEC = importlib.util.spec_from_file_location(
    "source_closure_regression_probe", ROOT / "scripts/openclaw-real-gateway-contract-probe.py"
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
SOURCE = PROBE.runtime_source_contract


class RuntimeSourceClosureRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in SOURCE.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(name, '{"name":"fixture"}\n' if name == "package.json" else "export {};\n")

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def snapshot(self, runner: str) -> dict[str, str]:
        self.write(SOURCE.PERSISTENT_LIFECYCLE_RUNNER, runner)
        return SOURCE.runtime_source_digest_snapshot(self.root)

    def test_worker_capability_transfers_are_rejected_at_the_reference(self) -> None:
        bindings = (
            ("import {Worker} from 'node:worker_threads';", "Worker"),
            ("import {Worker as W} from 'worker_threads';", "W"),
            ("import wt, {Worker as W} from 'node:worker_threads';", "W"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("const wt = require('node:worker_threads');", "wt['Worker']"),
            ("import wt from 'node:worker_threads';", "wt[`Worker`]"),
            ("import wt from 'node:worker_threads';", "wt['W' + 'orker']"),
        )
        transfers = (
            "const Alias = {ref}; new Alias(new URL('./hidden.mjs', import.meta.url));",
            "let Alias; Alias = {ref}; new Alias(new URL('./hidden.mjs', import.meta.url));",
            "const holder = [{ref}]; new holder[0](new URL('./hidden.mjs', import.meta.url));",
            "const holder = {{ run: {ref} }}; new holder.run(new URL('./hidden.mjs', import.meta.url));",
            "Reflect.construct({ref}, [new URL('./hidden.mjs', import.meta.url)]);",
            "const Alias = ({ref}).bind(null); new Alias(new URL('./hidden.mjs', import.meta.url));",
            "consume((({ref})));",
            "const text = `${{consume({ref})}}`;",
            "export const Alias = {ref};",
        )
        for declaration, reference in bindings:
            for transfer in transfers:
                source = declaration + transfer.format(ref=reference)
                with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                    self.snapshot(source)

    def test_worker_namespace_transfers_and_dynamic_acquisition_are_rejected(self) -> None:
        cases = (
            "import * as wt from 'node:worker_threads'; const alias=wt; new alias.Worker('./hidden.mjs');",
            "const wt = await import('node:worker_threads'); new wt.Worker('./hidden.mjs');",
            "const W = require('node:worker_threads').Worker; new W('./hidden.mjs');",
            "consume(require('node:worker_threads'));",
            "import * as wt from 'node:worker_threads'; const {Worker: W}=wt; new W('./hidden.mjs');",
            "import * as wt from 'node:worker_threads'; new wt[choose()]('./hidden.mjs');",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    def test_direct_workers_remain_bound_in_nested_template_expressions(self) -> None:
        self.write("scripts/worker.mjs", "export const worker = true;\n")
        for expression in (
            "new Worker(new URL('./worker.mjs', import.meta.url))",
            "`${new Worker(new URL('./worker.mjs', import.meta.url))}`",
            "`outer ${`inner ${new Worker(new URL('./worker.mjs', import.meta.url))}`}`",
        ):
            with self.subTest(expression=expression):
                paths = self.snapshot("import {Worker} from 'node:worker_threads';\n" + expression + ";")
                self.assertIn("scripts/worker.mjs", paths)

    def test_all_child_process_capabilities_reject_transfers(self) -> None:
        for member in ("fork", "spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync"):
            for reference in (f"cp.{member}", f"cp['{member}']", f"cp[`{member}`]", f"(cp)['{member}']"):
                for transfer in (
                    "const go = {ref}; go('./hidden.sh');",
                    "let go; go = {ref}; go('./hidden.sh');",
                    "const box = {{go: {ref}}}; box.go('./hidden.sh');",
                    "consume({ref});",
                    "Reflect.apply({ref}, null, ['./hidden.sh']);",
                    "const go = {ref}.bind(null); go('./hidden.sh');",
                    "const text = `${{consume({ref})}}`;",
                ):
                    source = "import * as cp from 'node:child_process';\n" + transfer.format(ref=reference)
                    with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                        self.snapshot(source)

    def test_child_namespace_aliases_and_destructuring_are_rejected(self) -> None:
        for transfer in (
            "const alias=cp; alias.spawnSync('./hidden.sh');",
            "const {spawnSync: run}=cp; run('./hidden.sh');",
            "const run=cp[name]; run('./hidden.sh');",
            "export {cp};",
            "consume(cp);",
        ):
            with self.subTest(transfer=transfer), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot("import cp from 'node:child_process';" + transfer)

    def test_require_alias_grouping_is_balanced_and_unbounded_by_regex_depth(self) -> None:
        self.write("scripts/hidden.cjs", "module.exports = 42;\n")
        for depth in (0, 1, 2, 8, 32, 128):
            for whitespace in (" ", "/* comment */"):
                rhs = "(" * depth + whitespace + "require" + whitespace + ")" * depth
                with self.subTest(depth=depth, whitespace=whitespace):
                    snapshot = self.snapshot(f"const r = {rhs}; r('./hidden.cjs');")
                    self.assertIn("scripts/hidden.cjs", snapshot)
        self.assertIn("scripts/hidden.cjs", self.snapshot("const r=((require))\nr('./hidden.cjs');"))

    def test_require_reference_transfers_outside_supported_declarations_fail_closed(self) -> None:
        for source in (
            "let r; r=((require)); r('./hidden.cjs');",
            "const box=[require]; box[0]('./hidden.cjs');",
            "const box={load:require}; box.load('./hidden.cjs');",
            "consume(require);",
            "const r=require.bind(null); r('./hidden.cjs');",
            "const r=require; export {r};",
            "const r=require; const rr=r; rr('./hidden.cjs');",
            "const text=`${consume(require)}`;",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    def test_all_line_comment_forms_preserve_following_loaders(self) -> None:
        self.write("scripts/hidden.cjs", "module.exports = 42;\n")
        for ending in ("\n", "\r", "\u2028", "\u2029"):
            for opener in ("//", "<!--", "-->", "#!/usr/bin/env node"):
                for quote in ("'", '"', "`"):
                    source = f"{opener} {quote}{ending}require('./hidden.cjs');{ending}// {quote}"
                    with self.subTest(ending=repr(ending), opener=opener, quote=quote):
                        self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_ambiguous_division_cannot_mask_runtime_loaders(self) -> None:
        sources = [
            f"obj.{name} / require('hidden-package') / 2;"
            for name in ("return", "throw", "new", "delete", "case", "else", "in",
                         "instanceof", "typeof", "void", "of", "await", "yield")
        ]
        sources += [
            "var of=2;of / require('hidden-package') / 2;",
            "var await=2;await / require('hidden-package') / 2;",
            "var yield=2;yield / require('hidden-package') / 2;",
            "value! / require('hidden-package') / 2;",
            "value<Type> / require('hidden-package') / 2;",
            "obj?.return / require('hidden-package') / 2;",
            "class C{#return=2;run(){this.#return / require('hidden-package') / 2;}}",
            r"obj.re\u0074urn / require('hidden-package') / 2;",
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    @unittest.skipUnless(shutil.which("node"), "requires Node for lexical parity")
    def test_node_executes_loaders_in_keyword_property_and_identifier_division(self) -> None:
        self.write("node_modules/hidden-package/package.json", '{"main":"index.cjs"}')
        self.write("node_modules/hidden-package/index.cjs",
                   "console.log('DIVISION_LOADER_EXECUTED');module.exports=2;")
        for source in (
            "const obj={return:2};obj.return / require('hidden-package') / 2;",
            "var of=2;of / require('hidden-package') / 2;",
            "var await=2;await / require('hidden-package') / 2;",
        ):
            with self.subTest(source=source):
                path = self.write("scripts/division.cjs", source)
                result = subprocess.run([shutil.which("node"), str(path)], cwd=self.root,
                                        text=True, capture_output=True, check=True, timeout=10)
                self.assertEqual(result.stdout.strip(), "DIVISION_LOADER_EXECUTED")
                with self.assertRaises(SOURCE.RuntimeSourceContractError):
                    self.snapshot(source)

    def test_html_comments_in_template_expressions_do_not_hide_loaders(self) -> None:
        self.write("scripts/hidden.cjs", "module.exports = 42;\n")
        source = "const value = `${<!-- \"\nrequire('./hidden.cjs')\n}`;"
        self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_html_close_after_block_comment_is_trivia_but_postfix_is_not(self) -> None:
        self.write("scripts/hidden.cjs", "module.exports = 42;\n")
        for source in (
            "/* leading */ --> \"\nrequire('./hidden.cjs');\n// \"",
            "const n=2; n-->0; require('./hidden.cjs');",
            "const n=2; n-- >0; require('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_comment_markers_and_alias_declarations_in_data_are_inert(self) -> None:
        for source in (
            "const data = `<!-- \" require('./missing.cjs') -->` ;",
            'const data = "const r=((require)); r(\'./missing.cjs\');";',
            "const data = /<!--require('missing')-->/;",
            "const data = '#!/usr/bin/env node \"';",
            "// const r=require;\nexport const r = 1;",
        ):
            with self.subTest(source=source):
                self.assertEqual(set(self.snapshot(source)), set(SOURCE.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS))

    def test_lexical_match_offsets_survive_nested_templates(self) -> None:
        import re
        source = "const text = `one ${`two ${require('./x.cjs')}`} three`;"
        matches = SOURCE._executable_pattern_matches(source, re.compile(r"\brequire\b"))
        self.assertEqual([m.start() for m in matches], [source.index("require")])

    def test_unterminated_comment_fails_closed(self) -> None:
        with self.assertRaises(SOURCE.RuntimeSourceContractError):
            self.snapshot("/* require('./hidden.cjs');")

    def test_nearest_package_scope_is_bound_for_relative_and_entrypoint_sources(self) -> None:
        self.write("scripts/scope/entry.mjs", "import './nested/leaf.js';\n")
        self.write("scripts/scope/nested/leaf.js", "export const leaf=1;\n")
        manifest = self.write("scripts/scope/nested/package.json", '{"type":"module"}\n')
        before = self.snapshot("import './scope/entry.mjs';")
        self.assertIn("scripts/scope/nested/package.json", before)
        manifest.write_text('{"type":"commonjs"}\n', encoding="utf-8")
        after = SOURCE.runtime_source_digest_snapshot(self.root)
        self.assertNotEqual(before, after)
        entry_scope = self.write("scripts/package.json", '{"type":"module"}\n')
        self.assertIn("scripts/package.json", SOURCE.runtime_source_digest_snapshot(self.root))
        entry_scope.unlink()

    def test_scope_insertion_and_deletion_change_snapshot_without_code_edits(self) -> None:
        self.write("scripts/nested/leaf.js", "export const leaf=1;\n")
        before = self.snapshot("import './nested/leaf.js';")
        scope = self.write("scripts/nested/package.json", '{"type":"module"}\n')
        inserted = SOURCE.runtime_source_digest_snapshot(self.root)
        self.assertNotEqual(before, inserted)
        scope.unlink()
        self.assertEqual(before, SOURCE.runtime_source_digest_snapshot(self.root))

    def test_node_modules_is_a_package_scope_boundary(self) -> None:
        path = self.write("node_modules/no-manifest/leaf.js", "export {};\n")
        self.assertEqual(SOURCE._runtime_package_scope_metadata(self.root, path), ())

    def test_package_scope_symlink_cannot_escape_candidate_root(self) -> None:
        with tempfile.TemporaryDirectory() as other:
            target = Path(other) / "package.json"
            target.write_text('{"type":"module"}', encoding="utf-8")
            self.write("scripts/nested/leaf.js", "export {};\n")
            (self.root / "scripts/nested/package.json").symlink_to(target)
            with self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot("import './nested/leaf.js';")

    def test_node_executes_the_comment_and_grouped_alias_reproductions(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node is required for the independent JavaScript semantics check")
        self.write("scripts/hidden.cjs", "console.log('closure-fixture-executed');\n")
        for source in (
            '<!-- "\nrequire("./hidden.cjs");\n<!-- "',
            '#!/usr/bin/env node "\nrequire("./hidden.cjs");\n// "',
            'const r=((require)); r("./hidden.cjs");',
        ):
            with self.subTest(source=source):
                script = self.write("scripts/fixture.cjs", source)
                result = subprocess.run([node, str(script)], cwd=self.root,
                                        env={"PATH": str(Path(node).parent)},
                                        capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(result.stdout.strip(), "closure-fixture-executed")
                self.assertIn("scripts/hidden.cjs", self.snapshot("require('./fixture.cjs');"))



    def test_unicode_and_reexported_execution_bindings_fail_closed(self) -> None:
        cases = (
            "import{Worker as 工人}from'node:worker_threads';const W=工人;new W('./hidden.mjs');",
            "import*as 工人 from'node:child_process';工人.spawnSync('./hidden.sh');",
            "import{spawnSync as g\\u006f}from'node:child_process';consume(g\\u006f);",
            "export*from'node:worker_threads';",
            "export{'spawnSync'as go}from'node:child_process';",
            "export*from'node:module';",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    def test_launch_options_cannot_add_unbound_preloads(self) -> None:
        self.write('scripts/worker.mjs', 'export {};')
        self.write('child.cjs', 'module.exports=1;')
        cases = (
            "import{Worker}from'node:worker_threads';new Worker(new URL('./worker.mjs',import.meta.url),{execArgv:['--import','./hidden.mjs']});",
            "import{fork}from'node:child_process';fork('./child.cjs',[],{execArgv:['--require','./hidden.cjs']});",
            "import{spawn}from'node:child_process';spawn(process.execPath,['./child.cjs'],{env:{NODE_OPTIONS:'--require ./hidden.cjs'}});",
            "import{spawnSync}from'node:child_process';spawnSync(process.execPath,['./child.cjs','--other']);",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    def test_module_loader_factories_and_results_cannot_escape(self) -> None:
        cases = (
            "const r=module['require'];r('./hidden.cjs');",
            "const r=module.require;r('./hidden.cjs');",
            "import M from'node:module';const cr=M['createRequire'];const r=cr(import.meta.url);r('./hidden.cjs');",
            "import{createRequire}from'node:module';const cr=createRequire;const r=cr(import.meta.url);r('./hidden.cjs');",
            "import{_load as go}from'node:module';go('./hidden.cjs');",
            "consume(require('node:module'));",
            "const M=require('node:module');consume(M);",
            "import M from'node:module';const r=M.createRequire(import.meta.url);r('./hidden.cjs');",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    def test_direct_inline_module_factory_binds_its_immediate_load(self) -> None:
        self.write('scripts/hidden.cjs', "require('./nested.cjs');")
        self.write('scripts/nested.cjs', 'module.exports=42;')
        for source in (
            "require('node:module').createRequire(__filename)('./hidden.cjs');",
            "module['require']('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                snapshot = self.snapshot(source)
                self.assertIn('scripts/hidden.cjs', snapshot)
                self.assertIn('scripts/nested.cjs', snapshot)

    def test_runtime_launch_configuration_cannot_be_mutated_or_transferred(self) -> None:
        cases = (
            "process.chdir('/tmp');", "const chdir=process.chdir;",
            "process.execArgv.push('--require','./hidden.cjs');",
            "const argv=process.execArgv;", "export const env=process.env;",
            "process.env.NODE_OPTIONS='--require ./hidden.cjs';",
            "process['env']['NODE_OPTIONS'] ||= '--require ./hidden.cjs';",
            "process.env.NODE_OPTIONS <<= 1;", "delete process.env.NODE_OPTIONS;",
            "process.execPath='./hidden.sh';", "process.cwd=()=>'/tmp';",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)
        self.snapshot("const a=process.env.AGENTIC_OS_PROBE_ID;const cwd=process.cwd();const node=process.execPath;")

    @unittest.skipUnless(shutil.which('node'), 'requires Node for resolution parity')
    def test_fork_entrypoint_is_relative_to_launch_cwd_not_importer(self) -> None:
        self.write('package.json', '{"name":"fixture","type":"module"}')
        self.write('scripts/entry.mjs', "import{fork}from'node:child_process';fork('./child.cjs');")
        self.write('scripts/child.cjs', "console.log('DECOY');")
        self.write('child.cjs', "require('./nested.cjs');")
        self.write('nested.cjs', "console.log('BOUND_CHILD');")
        snapshot = self.snapshot("import './entry.mjs';")
        self.assertIn('child.cjs', snapshot)
        self.assertIn('nested.cjs', snapshot)
        self.assertNotIn('scripts/child.cjs', snapshot)
        result = subprocess.run([shutil.which('node'), 'scripts/entry.mjs'], cwd=self.root,
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(result.stdout.strip(), 'BOUND_CHILD')

    def test_child_entrypoints_cannot_be_stdin_or_cli_options(self) -> None:
        for source in (
            "import{spawnSync}from'node:child_process';spawnSync(process.execPath,['-']);",
            "import{fork}from'node:child_process';fork('--eval');",
        ):
            with self.subTest(source=source), self.assertRaises(SOURCE.RuntimeSourceContractError):
                self.snapshot(source)

    @unittest.skipUnless(shutil.which('node'), 'requires Node for unknown-extension parity')
    def test_commonjs_unknown_extensions_are_transitively_scanned(self) -> None:
        self.write('scripts/entry.cjs', "require('./bridge.data');")
        self.write('scripts/bridge.data', "require('./hidden.cjs');")
        self.write('scripts/hidden.cjs', "console.log('BOUND_UNKNOWN_EXTENSION');")
        snapshot = self.snapshot("require('./entry.cjs');")
        self.assertIn('scripts/bridge.data', snapshot)
        self.assertIn('scripts/hidden.cjs', snapshot)
        result = subprocess.run([shutil.which('node'), 'scripts/entry.cjs'], cwd=self.root,
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(result.stdout.strip(), 'BOUND_UNKNOWN_EXTENSION')


class RuntimePreloadInstallationRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.node = self.root / "bin/node"
        self.node.parent.mkdir()
        self.node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.node.chmod(0o755)
        self.modules = self.root / "node_modules"
        self.loader = self.modules / "tsx/dist/loader.mjs"
        self.loader.parent.mkdir(parents=True)
        self.loader.write_text("import 'helper';\n", encoding="utf-8")
        (self.modules / "tsx/package.json").write_text('{"name":"tsx"}\n', encoding="utf-8")
        self.helper = self.modules / "helper/index.mjs"
        self.helper.parent.mkdir()
        self.helper.write_text("export default 1;\n", encoding="utf-8")
        (self.helper.parent / "package.json").write_text('{"name":"helper","main":"index.mjs"}', encoding="utf-8")

    def bindings(self):
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=self.loader):
            return PROBE._runtime_launch_bindings(self.root, {"PATH": str(self.node.parent)})

    def test_sibling_preload_dependency_mutation_changes_launch_binding(self) -> None:
        before = self.bindings()
        self.helper.write_text("export default 2;\n", encoding="utf-8")
        after = self.bindings()
        self.assertNotEqual(before, after)
        unchanged_labels = {"runtime-launcher:node", "runtime-preload:tsx", "runtime-preload-package:tsx"}
        self.assertEqual([r for r in before[2] if r["path"] in unchanged_labels],
                         [r for r in after[2] if r["path"] in unchanged_labels])
        self.assertNotIn(str(self.root), json.dumps(after[2]))

    def test_nested_metadata_native_helpers_and_file_set_changes_are_bound(self) -> None:
        for relative in ("helper/node_modules/nested/package.json", "helper/native.node", "helper/extra.cjs"):
            with self.subTest(relative=relative):
                before = self.bindings()
                path = self.modules / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture-one")
                added = self.bindings()
                self.assertNotEqual(before, added)
                path.write_bytes(b"fixture-two")
                self.assertNotEqual(added, self.bindings())
                path.unlink()
                self.assertNotEqual(added, self.bindings())

    def test_executable_mode_changes_are_bound(self) -> None:
        before = self.bindings()
        self.helper.chmod(0o755)
        self.assertNotEqual(before, self.bindings())

    def test_internal_symlink_retargeting_is_bound_even_for_identical_bytes(self) -> None:
        other = self.helper.parent / "other.mjs"
        other.write_bytes(self.helper.read_bytes())
        link = self.modules / "linked"
        link.symlink_to(self.helper)
        before = self.bindings()
        link.unlink()
        link.symlink_to(other)
        self.assertNotEqual(before, self.bindings())

    def test_pnpm_style_contained_package_links_are_supported(self) -> None:
        store = self.modules / ".pnpm/helper/node_modules/helper"
        store.mkdir(parents=True)
        (store / "index.mjs").write_text("export default 1;", encoding="utf-8")
        (self.modules / "linked-helper").symlink_to(store, target_is_directory=True)
        before = self.bindings()
        (store / "index.mjs").write_text("export default 2;", encoding="utf-8")
        self.assertNotEqual(before, self.bindings())

    def test_escaping_and_dangling_installation_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "helper.mjs"
            outside.write_text("export default 1;", encoding="utf-8")
            link = self.modules / "external"
            for target in (outside, self.modules / "missing"):
                with self.subTest(target=target):
                    link.symlink_to(target)
                    with self.assertRaises(PROBE.ProbeError):
                        self.bindings()
                    link.unlink()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX special files")
    def test_special_dependency_files_are_rejected_without_opening_them(self) -> None:
        os.mkfifo(self.modules / "pipe")
        with self.assertRaisesRegex(PROBE.ProbeError, "unsupported file type"):
            self.bindings()

    def test_missing_duplicate_and_unknown_launch_records_are_rejected(self) -> None:
        valid = self.bindings()[2]
        self.assertEqual(PROBE._validate_runtime_launch_sources(valid), valid)
        variants = (valid[:-1], valid + [valid[0]], valid + [dict(valid[0], path="unexpected")])
        for invalid in variants:
            with self.subTest(invalid=invalid), self.assertRaises(PROBE.ProbeError):
                PROBE._validate_runtime_launch_sources(invalid)


if __name__ == "__main__":
    unittest.main()
