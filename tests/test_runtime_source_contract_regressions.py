"""Adversarial regressions for PR45's execution and source-binding boundary.

These fixtures prove either a complete static binding or explicit rejection;
none may silently drop an executable input. They do not enable the disabled
persistent lifecycle launcher or manufacture production runtime evidence.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("source_closure_regression_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
CONTRACT = PROBE.runtime_source_contract
ERROR = CONTRACT.RuntimeSourceContractError


class RuntimeSourceContractRegressionTests(unittest.TestCase):
    def write(self, root: Path, files: dict[str, str]) -> None:
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

    def fixture(self, root: Path, files: dict[str, str]) -> None:
        sources = {
            path: "export const fixture = true;\n"
            for path in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS
        }
        sources["package.json"] = '{"name":"fixture","type":"module"}\n'
        sources.update(files)
        self.write(root, sources)

    def assert_rejected(self, source: str) -> None:
        with self.assertRaisesRegex(ERROR, "unsupported|ambiguous"):
            CONTRACT.import_specifiers(source)

    def test_worker_capability_transfers_fail_closed(self) -> None:
        prefix = "import {Worker} from 'node:worker_threads';\n"
        cases = (
            "const W = Worker; new W(new URL('./hidden.mjs',import.meta.url));",
            "const W = (((Worker))); new W(new URL('./hidden.mjs',import.meta.url));",
            "let W; W = Worker; new W(new URL('./hidden.mjs',import.meta.url));",
            "const box = { W: Worker }; new box.W('./hidden.mjs');",
            "const box = [Worker]; new box[0]('./hidden.mjs');",
            "function get() { return Worker; } new (get())('./hidden.mjs');",
            "((W) => new W('./hidden.mjs'))(Worker);",
            "Reflect.construct(Worker, ['./hidden.mjs']);",
            "const W = Worker.bind(null); new W('./hidden.mjs');",
            "export {Worker as W};",
            "export default Worker;",
            "const W = true ? Worker : null; new W('./hidden.mjs');",
            "`${ (() => { const W=Worker; return new W('./hidden.mjs'); })() }`;",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rejected(prefix + source)

    def test_worker_namespace_transfers_fail_closed(self) -> None:
        for access in ("wt.Worker", "wt['Worker']", 'wt["Worker"]', "wt[`Worker`]", "(((wt)))['Worker']"):
            with self.subTest(access=access):
                self.assert_rejected(
                    "import * as wt from 'node:worker_threads';\n"
                    f"const W = {access}; new W('./hidden.mjs');"
                )
        for source in (
            "import * as wt from 'node:worker_threads'; const ns=wt; new ns.Worker('./hidden.mjs');",
            "const {Worker:W}=require('node:worker_threads'); const X=W; new X('./hidden.mjs');",
            "const {Worker:W}=await import('node:worker_threads'); new W('./hidden.mjs');",
            "export { Worker as W } from 'node:worker_threads';",
            "export * from 'node:worker_threads';",
            "new (require('node:worker_threads').Worker)('./hidden.mjs');",
            "const { [key]: W } = require('node:worker_threads'); new W('./hidden.mjs');",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_direct_worker_bindings_remain_supported(self) -> None:
        cases = (
            ("import {Worker as W} from 'node:worker_threads';", "W"),
            ("import wt, {Worker as W} from 'node:worker_threads';", "W"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("import wt from 'node:worker_threads';", "wt['Worker']"),
            ("const {Worker:W} = require('node:worker_threads');", "W"),
        )
        for declaration, constructor in cases:
            for invocation in (
                f"new {constructor}(new URL('./worker.mjs',import.meta.url));",
                f"`${{new {constructor}(new URL('./worker.mjs',import.meta.url))}}`;",
            ):
                with self.subTest(declaration=declaration, invocation=invocation):
                    self.assertIn(
                        ("./worker.mjs", True, "import"),
                        CONTRACT.import_specifiers(declaration + invocation),
                    )

    def test_child_process_capability_transfers_fail_closed(self) -> None:
        methods = ("spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync", "fork")
        for method in methods:
            for member in (f"cp.{method}", f"cp['{method}']", f"cp[`{method}`]", f"(((cp)))['{method}']"):
                with self.subTest(member=member):
                    self.assert_rejected(
                        "import * as cp from 'node:child_process';\n"
                        f"const go = {member}; go('./hidden.sh');"
                    )
            for use in (
                "const again = go; again('./hidden.sh');",
                "const box = { go }; box.go('./hidden.sh');",
                "Reflect.apply(go,null,['./hidden.sh']);",
                "((run) => run('./hidden.sh'))(go);",
                "export {go};",
                "`${ (() => { const later=go; return later('./hidden.sh'); })() }`;",
            ):
                with self.subTest(method=method, use=use):
                    self.assert_rejected(f"import {{ {method} as go }} from 'node:child_process';\n" + use)

    def test_child_process_import_escape_variants_fail_closed(self) -> None:
        cases = (
            "import * as cp from 'node:child_process'; const ns=cp; ns.spawnSync('./hidden.sh');",
            "const cp=require('node:child_process'); const {spawnSync:go}=cp; go('./hidden.sh');",
            "const {[name]:go}=require('node:child_process'); go('./hidden.sh');",
            "const {...cp}=require('node:child_process'); cp.spawnSync('./hidden.sh');",
            "export {spawnSync as go} from 'node:child_process';",
            "export * from 'node:child_process';",
            "const r=require; const cp=r('node:child_process'); cp.spawnSync('./hidden.sh');",
            "import {createRequire} from 'node:module'; const r=createRequire(import.meta.url); const cp=r('node:child_process'); cp.spawnSync('./hidden.sh');",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_direct_child_process_node_entrypoints_remain_supported(self) -> None:
        for method in ("spawn", "spawnSync", "execFile", "execFileSync"):
            with self.subTest(method=method):
                self.assertIn(
                    ("./child.mjs", True, "import"),
                    CONTRACT.import_specifiers(
                        f"import {{{method} as launch}} from 'node:child_process';\n"
                        "launch(process.execPath, ['./child.mjs']);"
                    ),
                )

    def test_arbitrarily_grouped_require_aliases_bind_the_source(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32):
            for gap in ("", " /*group*/ ", "\n"):
                expression = ("(" + gap) * depth + "require" + (gap + ")") * depth
                for terminator in (";", "\n", "\r", "\u2028", "\u2029"):
                    with self.subTest(depth=depth, gap=gap, terminator=terminator):
                        self.assertIn(
                            ("./hidden.cjs", True, "require"),
                            CONTRACT.import_specifiers(f"const r = {expression}{terminator}r('./hidden.cjs');"),
                        )

    def test_untracked_require_transfers_fail_closed(self) -> None:
        for source in (
            "let r; r=((require)); r('./hidden.cjs');",
            "const dummy=0, r=((require)); r('./hidden.cjs');",
            "const r=module.require; r('./hidden.cjs');",
            "const {require:r}=module; r('./hidden.cjs');",
            "const r=globalThis['require']; r('./hidden.cjs');",
            "const r=globalThis[`require`]; r('./hidden.cjs');",
            "const box=[require]; box[0]('./hidden.cjs');",
            "((r)=>r('./hidden.cjs'))(require);",
            "const r=((require)); const again=r; again('./hidden.cjs');",
            "const r=((require)).bind(null); r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_escaped_require_identifier_is_not_ignored(self) -> None:
        for token in (r"requ\u0069re", r"requ\u{69}re"):
            with self.subTest(token=token):
                self.assertIn(
                    ("./hidden.cjs", True, "require"),
                    CONTRACT.import_specifiers(f"const r=(({token})); r('./hidden.cjs');"),
                )

    def test_node_comment_forms_cannot_hide_executable_imports(self) -> None:
        for line_end in ("\n", "\r", "\u2028", "\u2029"):
            for prefix in (
                '#!/usr/bin/env node "', '<!-- "', '--> "',
                ' \t--> "', '\ufeff--> "', '/* ordinary */ --> "',
                f'const x=1; /*{line_end}multiline */ --> "',
                '/* nested-looking /* opener */ --> "',
            ):
                with self.subTest(line_end=line_end, prefix=prefix):
                    source = prefix + line_end + "require('./hidden.cjs');" + line_end + '// "'
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
                    masked = CONTRACT.strip_source_comments(source)
                    self.assertEqual(len(masked), len(source))
                    self.assertEqual(
                        [i for i,c in enumerate(source) if CONTRACT._is_js_line_terminator(c)],
                        [i for i,c in enumerate(masked) if CONTRACT._is_js_line_terminator(c)],
                    )

    def test_html_comment_marker_inside_an_expression_is_not_a_comment(self) -> None:
        self.assertIn(
            ("./hidden.cjs", True, "require"),
            CONTRACT.import_specifiers("let n=2; n--> require('./hidden.cjs');"),
        )

    def test_template_expression_comments_use_the_same_lexer(self) -> None:
        for expression in (
            "\n/*comment*/ --> \"\nrequire('./hidden.cjs')\n",
            "\n<!-- \"\nrequire('./hidden.cjs')\n",
            "`nested ${require('./hidden.cjs')}`",
            "(/}/.test('}') && require('./hidden.cjs'))",
        ):
            with self.subTest(expression=expression):
                self.assertIn(
                    ("./hidden.cjs", True, "require"),
                    CONTRACT.import_specifiers("`inert text ${" + expression + "} inert text`"),
                )

    def test_literal_data_neither_introduces_bindings_nor_dependencies(self) -> None:
        for source in (
            'const data = "<!-- \\\" require(\'./hidden.cjs\')";',
            "const data = `<!-- require('./hidden.cjs') new Worker('./hidden.mjs')`;",
            "const data = /<!--|require|Worker/;",
            "const data = `import {Worker} from 'node:worker_threads'; const W=Worker;`;",
            "const data = `import * as cp from 'node:child_process'; cp['spawnSync']('./hidden.sh');`;",
            "export const data = 'node:child_process';",
        ):
            with self.subTest(source=source):
                self.assertEqual(CONTRACT.import_specifiers(source), [])

    @unittest.skipUnless(shutil.which("node"), "Node is unavailable for the lexical differential fixture")
    def test_comment_fixtures_agree_with_node_commonjs_execution(self) -> None:
        for prefix in ('#!/usr/bin/env node "', '<!-- "', '/*x*/ --> "', 'let x=1; /*\n*/ --> "', '\ufeff--> "'):
            source = prefix + '\nconsole.log(require("node:path").basename("/safe/bound"));\n// "'
            with self.subTest(prefix=prefix):
                result = subprocess.run(
                    [shutil.which("node"), "--input-type=commonjs", "-e", source],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "bound")
                self.assertIn(("node:path", True, "require"), CONTRACT.import_specifiers(source))

    def test_relative_sources_bind_their_controlling_package_scope(self) -> None:
        for kind, source in (("import", "import './nested/input.js';"), ("require", "require('./nested/input.js');")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, {
                    CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: source,
                    "scripts/nested/input.js": "export const value = 1;",
                    "scripts/nested/package.json": '{"type":"module"}',
                })
                before = CONTRACT.runtime_source_digest_snapshot(root)
                self.assertIn("scripts/nested/package.json", before)
                self.write(root, {"scripts/nested/package.json": '{"type":"commonjs"}'})
                self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_package_export_subdirectory_scope_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import 'dep';",
                "node_modules/dep/package.json": '{"name":"dep","exports":"./sub/entry.js"}',
                "node_modules/dep/sub/package.json": '{"type":"module"}',
                "node_modules/dep/sub/entry.js": "export const value=1;",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("node_modules/dep/sub/package.json", before)
            self.write(root, {"node_modules/dep/sub/package.json": '{"type":"commonjs"}'})
            self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_added_nearer_package_scope_changes_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import './nested/input.js';",
                "scripts/nested/input.js": "export const value=1;",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.write(root, {"scripts/nested/package.json": '{"type":"commonjs"}'})
            self.assertNotEqual(before, CONTRACT.runtime_source_digest_snapshot(root))

    def test_package_imports_do_not_fall_through_an_empty_nearer_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                "package.json": '{"name":"fixture","imports":{"#hidden":"./decoy.mjs"}}',
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import './nested/input.mjs';",
                "scripts/nested/package.json": '{}',
                "scripts/nested/input.mjs": "import '#hidden';",
                "decoy.mjs": "export const decoy=1;",
            })
            with self.assertRaisesRegex(ERROR, "could not be resolved|scope"):
                CONTRACT.runtime_source_digest_snapshot(root)

    def test_nearest_scope_blocks_parent_package_self_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                "package.json": '{"name":"parent","exports":"./decoy.mjs"}',
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import './nested/input.mjs';",
                "scripts/nested/package.json": '{"name":"nested"}',
                "scripts/nested/input.mjs": "import 'parent';",
                "decoy.mjs": "export const decoy=1;",
                "node_modules/parent/package.json": '{"name":"parent","exports":"./real.mjs"}',
                "node_modules/parent/real.mjs": "export const real=1;",
            })
            snapshot = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("node_modules/parent/real.mjs", snapshot)
            self.assertNotIn("decoy.mjs", snapshot)

    def test_package_scope_cannot_escape_the_candidate_root_via_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self.fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import './nested/input.js';",
                "scripts/nested/input.js": "export const value=1;",
            })
            external = Path(outside) / "package.json"
            external.write_text('{"type":"module"}', encoding="utf-8")
            (root / "scripts/nested/package.json").symlink_to(external)
            with self.assertRaisesRegex(ERROR, "escapes"):
                CONTRACT.runtime_source_digest_snapshot(root)

    def launch_fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        self.write(root, {
            "package.json": '{"name":"fixture","type":"module"}',
            "bin/node": "#!/bin/sh\nexit 0\n",
            "node_modules/tsx/package.json": '{"name":"tsx","type":"module"}',
            "node_modules/tsx/dist/loader.mjs": "import '../../helper.mjs'; import '../../../preload-helper.mjs';",
            "preload-helper.mjs": "export const preload=1;",
            "node_modules/helper.mjs": "import 'dep'; export const helper=1;",
            "node_modules/dep/package.json": '{"name":"dep","exports":"./index.mjs"}',
            "node_modules/dep/index.mjs": "export const value=1;",
        })
        (root / "bin/node").chmod(0o755)
        return root / "node_modules/tsx/dist/loader.mjs", {"PATH": str(root / "bin")}

    def launch_bindings(self, root: Path, loader: Path, env: dict[str, str]):
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            return PROBE._runtime_launch_bindings(root, env)

    def test_preload_closure_binds_siblings_and_transitive_package_dependencies(self) -> None:
        for target, replacement in (
            ("node_modules/helper.mjs", "import 'dep'; export const helper=2;"),
            ("preload-helper.mjs", "export const preload=2;"),
            ("node_modules/dep/index.mjs", "export const value=2;"),
            ("node_modules/dep/package.json", '{"name":"dep","type":"module","exports":"./index.mjs"}'),
            ("package.json", '{"name":"fixture","type":"commonjs"}'),
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                loader, env = self.launch_fixture(root)
                original = self.launch_bindings(root, loader, env)
                package_before = PROBE._directory_tree_sha256(loader.parents[1])
                self.write(root, {target: replacement})
                self.assertEqual(package_before, PROBE._directory_tree_sha256(loader.parents[1]))
                current = self.launch_bindings(root, loader, env)
                self.assertNotEqual(original[2], current[2])
                self.assertNotIn(str(root), json.dumps(current[2]))
                with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                    with self.assertRaisesRegex(PROBE.ProbeError, "source binding changed"):
                        PROBE._assert_runtime_launch_sources_still_bound(
                            openclaw_root=root, runner_env=env,
                            expected_node_executable=original[0],
                            expected_tsx_preload_specifier=original[1], expected_sources=original[2],
                        )

    def test_preload_closure_fails_closed_for_unresolved_dynamic_or_escaping_inputs(self) -> None:
        for source in ("import './missing.mjs';", "import(selected);", "import '../../../../outside.mjs';"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                loader, env = self.launch_fixture(root)
                loader.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(PROBE.ProbeError, "preload dependency closure"):
                    self.launch_bindings(root, loader, env)

    def test_preload_dependencies_in_a_pnpm_style_layout_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader, env = self.launch_fixture(root)
            store = root / "node_modules/.pnpm/tsx/node_modules/tsx"
            store.parent.mkdir(parents=True)
            (root / "node_modules/tsx").rename(store)
            (root / "node_modules/tsx").symlink_to(store, target_is_directory=True)
            real_loader = loader.resolve()
            real_loader.write_text("import 'dep';", encoding="utf-8")
            original = self.launch_bindings(root, real_loader, env)
            self.write(root, {"node_modules/dep/index.mjs": "export const value=2;"})
            self.assertNotEqual(original[2], self.launch_bindings(root, real_loader, env)[2])


if __name__ == "__main__":
    unittest.main()
