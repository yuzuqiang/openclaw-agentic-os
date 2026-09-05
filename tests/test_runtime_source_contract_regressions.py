"""Adversarial regressions for PR45's executable-source identity boundary.

These tests do not bypass the trusted-launcher gate or execute candidate code.
Node subprocesses below run only the small, locally constructed test fixtures.
"""
from __future__ import annotations

import hashlib
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
NODE = shutil.which("node")


class RuntimeSourceContractRegressionTests(unittest.TestCase):
    def fixture(self, root: Path, files: dict[str, str]) -> None:
        probe_tests.RealGatewayProbeTests._write_runtime_source_fixture(self, root, files)

    def assert_bound(self, source: str, target: str = "./hidden.cjs") -> None:
        self.assertIn(target, [record[0] for record in SOURCE.import_specifiers(source)])

    def assert_rejected(self, source: str) -> None:
        with self.assertRaises(SOURCE.RuntimeSourceContractError):
            SOURCE.import_specifiers(source)

    def test_worker_constructor_transfers_are_not_silently_accepted(self) -> None:
        declarations = (
            ("import {Worker as W} from 'node:worker_threads';", "W"),
            ("import * as wt from 'node:worker_threads';", "wt.Worker"),
            ("import wt from 'node:worker_threads';", "wt['Worker']"),
            ("const {Worker:W}=require('worker_threads');", "W"),
            ("const wt=require('worker_threads');", "wt[`Worker`]"),
        )
        transfers = (
            "const Other=CAP; new Other(new URL('./hidden.mjs',import.meta.url));",
            "const holder={cap:CAP}; new holder.cap('./hidden.cjs');",
            "const [Other]=[CAP]; new Other('./hidden.cjs');",
            "Reflect.construct(CAP,['./hidden.cjs']);",
            "accept(CAP);",
            "const text=`result ${CAP}`;",
        )
        for declaration, capability in declarations:
            for transfer in transfers:
                with self.subTest(declaration=declaration, transfer=transfer):
                    self.assert_rejected(declaration + transfer.replace("CAP", capability))
            for depth in range(1, 17):
                with self.subTest(declaration=declaration, depth=depth):
                    self.assert_rejected(
                        declaration + "const Other=" + "(" * depth + capability
                        + ")" * depth + ";new Other('./hidden.cjs');"
                    )

    def test_child_process_member_transfers_and_reflection_fail_closed(self) -> None:
        for method in ("fork", "spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync"):
            for member in (f"cp.{method}", f"cp['{method}']", f"cp[`{method}`]", f"cp?.{method}"):
                declaration = "import * as cp from 'node:child_process';"
                for expression in (
                    f"const go={member};go('./hidden.sh');",
                    f"Reflect.apply({member},null,['./hidden.sh']);",
                    f"const go=(({member}));go.call(null,'./hidden.sh');",
                    f"function get(){{return {member};}}get()('./hidden.sh');",
                ):
                    with self.subTest(method=method, expression=expression):
                        self.assert_rejected(declaration + expression)
            for indirect in ("go.call(null,'./hidden.sh')", "go.apply(null,['./hidden.sh'])", "go?.('./hidden.sh')", "((go))('./hidden.sh')"):
                with self.subTest(method=method, indirect=indirect):
                    self.assert_rejected(f"import {{{method} as go}} from 'child_process';{indirect}")

    def test_unrecognized_namespace_acquisition_is_rejected(self) -> None:
        for module in ("worker_threads", "child_process"):
            for source in (
                f"const load=require;const ns=load('{module}');consume(ns);",
                f"import {{createRequire}} from 'module';const load=createRequire(import.meta.url);const ns=load('{module}');consume(ns);",
                f"const ns=await import('node:{module}');consume(ns);",
                f"consume(require('node:{module}'));",
                f"export * from 'node:{module}';",
            ):
                with self.subTest(source=source):
                    self.assert_rejected(source)

    def test_module_constructor_and_factory_result_transfers_fail_closed(self) -> None:
        for declaration, capability in (
            ("const M=require('node:module');", "M"),
            ("import M from 'node:module';", "M"),
            ("import{Module as M}from'node:module';", "M"),
            ("import{default as M}from'node:module';", "M"),
            ("import*as M from'node:module';", "M.Module"),
        ):
            for depth in range(9):
                with self.subTest(declaration=declaration, depth=depth):
                    self.assert_rejected(
                        declaration + "const N=" + "(" * depth + capability + ")" * depth
                        + ";new N().load('./hidden.cjs');"
                    )
        for depth in range(1, 17):
            with self.subTest(factory_result_depth=depth):
                self.assert_rejected(
                    "const {createRequire}=require('node:module');const r="
                    + "(" * depth + "createRequire(__filename)" + ")" * depth
                    + ";r('./hidden.cjs');"
                )
        for source in (
            "const r=require;const M=r('node:module');const N=M;new N().load('./hidden.cjs');",
            "const {createRequire}=require('node:module');const holder={r:createRequire(__filename)};holder.r('./hidden.cjs');",
            "const M=require('module');const holder={ctor:M};new holder.ctor().load('./hidden.cjs');",
            "import{createRequire as make}from'node:module';const s=`${(()=>{const r=(make(import.meta.url));return r('./hidden.cjs')})()}`;",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_grouped_require_reference_transfer_is_rejected_at_every_depth(self) -> None:
        for spelling in ("require", r"requ\u0069re", r"requ\u{69}re"):
            for depth in range(2, 33):
                with self.subTest(spelling=spelling, depth=depth):
                    self.assert_rejected(
                        "const r=" + "(" * depth + spelling + ")" * depth
                        + ";r('./hidden.cjs');"
                    )
        for source in (
            "const r=/* comment */((require));r('./hidden.cjs');",
            "const t=`${(()=>{const r=((require));return r('./hidden.cjs')})()}`;",
            "Reflect.apply(require,null,['./hidden.cjs']);",
            "const holder={r:require};holder.r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_direct_static_loads_remain_supported(self) -> None:
        for source in (
            "require('./hidden.cjs');",
            "const r=require;r('./hidden.cjs');",
            "const r=(require);r('./hidden.cjs');",
            "const text=`${require('./hidden.cjs')}`;",
            "import{createRequire}from'node:module';const r=createRequire(import.meta.url);r('./hidden.cjs');",
            "import * as wt from 'node:worker_threads';new wt.Worker(new URL('./hidden.cjs',import.meta.url));",
            "import wt,* as threads from 'node:worker_threads';new threads.Worker(new URL('./hidden.cjs',import.meta.url));",
            "import wt,{Worker as W} from 'node:worker_threads';new W(new URL('./hidden.cjs',import.meta.url));",
            "import{spawnSync as run}from'node:child_process';run(process.execPath,['./hidden.cjs']);",
        ):
            with self.subTest(source=source):
                self.assert_bound(source)
        self.assertEqual(SOURCE.import_specifiers("console.log(typeof require);"), [])
        self.assertEqual(
            SOURCE.import_specifiers("import * as wt from 'node:worker_threads';console.log(wt.isMainThread,wt.workerData);"),
            [("node:worker_threads", True, "import")],
        )

    def test_hashbang_html_and_slash_comments_share_line_terminators(self) -> None:
        for newline in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for comment in ("#! ignored \"", "<!-- \"", "// \"", "--> \""):
                source = comment + newline + "require('./hidden.cjs');" + newline + "// \""
                with self.subTest(newline=repr(newline), comment=comment):
                    self.assert_bound(source)
            self.assert_bound("const a=`${1 /* } */ + " + newline + "<!-- \"" + newline + "require('./hidden.cjs')}`;")

    def test_literal_data_does_not_create_capability_bindings(self) -> None:
        snippets = (
            "const doc=\"import {Worker} from 'node:worker_threads';\";const Worker=1;",
            "const doc=\"require('node:child_process').execFileSync(\";",
            "const doc=`require('node:child_process')['spawnSync']`;",
            "const regexp=/import'not-a-package'/;",
            "const comment=/[/*]/;",
            "const doc=\"new Worker(new URL(\";",
            "const doc=\"spawnSync(process.execPath,[\";",
            "const doc=\"fork(\";",
            "const string='<!--';const template=`#! \" ${1}`;",
        )
        for source in snippets:
            with self.subTest(source=source):
                self.assertEqual(SOURCE.import_specifiers(source), [])
        self.assert_bound("const r=/[/*]/;require('./hidden.cjs');")
        self.assert_bound("const r=/[}']/;const s=`${require('./hidden.cjs')}`;")

    @unittest.skipUnless(NODE, "Node is required for JavaScript runtime differential tests")
    def test_node_executes_hashbang_and_html_dependencies_that_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text("console.log('bound-fixture');", encoding="utf-8")
            for prefix in ("<!-- \"", "#! ignored \"", "--> \""):
                source = prefix + "\nrequire('./hidden.cjs');\n// \""
                entry = root / "entry.cjs"
                entry.write_text(source, encoding="utf-8")
                with self.subTest(prefix=prefix):
                    result = subprocess.run([NODE, str(entry)], text=True, capture_output=True, timeout=10, check=True)
                    self.assertEqual(result.stdout.strip(), "bound-fixture")
                    self.assert_bound(source)

    def test_relative_and_seed_module_package_scopes_are_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = "node_modules/pkg/sub/package.json"
            self.fixture(root, {
                PROBE.PERSISTENT_LIFECYCLE_RUNNER: "import '../node_modules/pkg/sub/file.js';",
                "node_modules/pkg/package.json": '{"name":"pkg"}',
                scope: '{"type":"module"}',
                "node_modules/pkg/sub/file.js": "console.log(typeof require);",
                "src/gateway/package.json": '{"type":"module"}',
            })
            before = SOURCE.runtime_source_digest_snapshot(root)
            self.assertIn(scope, before)
            self.assertIn("src/gateway/package.json", before)
            (root / scope).write_text('{"type":"commonjs"}', encoding="utf-8")
            after = SOURCE.runtime_source_digest_snapshot(root)
            self.assertNotEqual(before, after)
            self.assertEqual(set(before), set(after))
            self.assertEqual([key for key in before if before[key] != after[key]], [scope])

    @unittest.skipUnless(NODE, "Node is required for package-scope differential tests")
    def test_node_package_type_changes_are_not_invisible_to_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                PROBE.PERSISTENT_LIFECYCLE_RUNNER: "import '../node_modules/pkg/sub/file.js';",
                "node_modules/pkg/package.json": '{"name":"pkg"}',
                "node_modules/pkg/sub/file.js": "console.log(typeof require);",
                "node_modules/pkg/sub/package.json": '{"type":"module"}',
            })
            snapshots, outputs = [], []
            for kind in ("module", "commonjs"):
                (root / "node_modules/pkg/sub/package.json").write_text(json.dumps({"type": kind}), encoding="utf-8")
                snapshots.append(SOURCE.runtime_source_digest_snapshot(root))
                result = subprocess.run([NODE, str(root / "node_modules/pkg/sub/file.js")], capture_output=True, text=True, timeout=10, check=True)
                outputs.append(result.stdout.strip())
            self.assertEqual(outputs, ["undefined", "function"])
            self.assertNotEqual(snapshots[0], snapshots[1])

    def test_package_scope_does_not_fall_through_nearer_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                "package.json": '{"name":"outer","exports":{".":"./outer.mjs"},"imports":{"#x":"./outer.mjs"}}',
                "outer.mjs": "export {};",
                "nested/package.json": '{"name":"inner"}',
                "nested/file.js": "export {};",
                "node_modules/no-manifest/file.js": "export {};",
            })
            importer = root / "nested/file.js"
            self.assertIsNone(SOURCE._nearest_package_self_reference(root, importer, "outer"))
            self.assertIsNone(SOURCE._nearest_package_imports_scope(root, importer))
            self.assertIsNone(SOURCE._runtime_package_scope(root, root / "node_modules/no-manifest/file.js"))
            with self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.resolve_import(root=root, importer=importer, specifier="#x", required=True, import_kind="import")

    def test_preload_sibling_and_configuration_changes_change_launch_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                "node_modules/tsx/package.json": '{"name":"tsx","type":"module"}',
                "node_modules/tsx/dist/loader.mjs": "import '../../helper/index.mjs';",
                "node_modules/helper/index.mjs": "export const value=1;",
                "node_modules/helper/package.json": '{"name":"helper","type":"module"}',
                "tsconfig.json": '{"compilerOptions":{}}',
                "node_modules/helper/native.so": "fixture-not-an-executable",
            })
            node = root / "node"
            node.write_text("fixture-not-an-executable", encoding="utf-8")
            loader = root / "node_modules/tsx/dist/loader.mjs"
            with mock.patch.object(PROBE.shutil, "which", return_value=str(node)), mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                before = PROBE._runtime_launch_bindings(root, {})
                for path in ("node_modules/helper/index.mjs", "node_modules/helper/package.json", "tsconfig.json", "node_modules/helper/native.so"):
                    target = root / path
                    original = target.read_bytes()
                    target.write_bytes(original + b"\n ")
                    with self.subTest(path=path):
                        after = PROBE._runtime_launch_bindings(root, {})
                        self.assertNotEqual(before[2], after[2])
                        with self.assertRaisesRegex(PROBE.ProbeError, "source binding changed"):
                            PROBE._assert_runtime_launch_sources_still_bound(openclaw_root=root, runner_env={}, expected_node_executable=before[0], expected_tsx_preload_specifier=before[1], expected_sources=before[2])
                    target.write_bytes(original)
                self.assertEqual(before, PROBE._runtime_launch_bindings(root, {}))

    @unittest.skipUnless(NODE, "Node is required for preload differential tests")
    def test_node_preload_sibling_behavior_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, {
                "node_modules/tsx/package.json": '{"name":"tsx","type":"module"}',
                "node_modules/tsx/dist/loader.mjs": "import '../../helper/index.mjs';",
                "node_modules/helper/index.mjs": "console.log('first');",
            })
            loader = root / "node_modules/tsx/dist/loader.mjs"
            bindings, outputs = [], []
            for label in ("first", "second"):
                (root / "node_modules/helper/index.mjs").write_text(f"console.log('{label}');", encoding="utf-8")
                with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
                    bindings.append(PROBE._runtime_launch_bindings(root, {"PATH": str(Path(NODE).parent)})[2])
                result = subprocess.run([NODE, "--import", loader.as_uri(), "--eval", ""], cwd=root, capture_output=True, text=True, timeout=10, check=True)
                outputs.append(result.stdout.strip())
            self.assertEqual(outputs, ["first", "second"])
            self.assertNotEqual(bindings[0], bindings[1])

    def test_installation_binding_includes_additions_modes_and_link_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"same bytes")
            (root / "b").write_bytes(b"same bytes")
            link = root / "link"
            link.symlink_to("a")
            first = PROBE._runtime_installation_binding(root)
            link.unlink()
            link.symlink_to("b")
            second = PROBE._runtime_installation_binding(root)
            self.assertNotEqual(first, second)
            (root / "a").chmod(0o700)
            third = PROBE._runtime_installation_binding(root)
            self.assertNotEqual(second, third)
            (root / "empty").mkdir()
            fourth = PROBE._runtime_installation_binding(root)
            self.assertNotEqual(third, fourth)
            (root / "empty").rmdir()
            self.assertEqual(third, PROBE._runtime_installation_binding(root))
            self.assertNotIn(str(root), json.dumps(first))

    def test_installation_binding_rejects_escaping_broken_links_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            root = outer / "root"
            root.mkdir()
            (outer / "outside").write_bytes(b"not code")
            link = root / "link"
            for target in ("../outside", "missing", "link"):
                link.symlink_to(target)
                with self.subTest(target=target):
                    with self.assertRaises(PROBE.ProbeError):
                        PROBE._runtime_installation_binding(root)
                link.unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "fifo")
                with self.assertRaisesRegex(PROBE.ProbeError, "special file"):
                    PROBE._runtime_installation_binding(root)

    def test_launch_binding_schema_rejects_legacy_and_duplicate_records(self) -> None:
        records = probe_tests.RealGatewayProbeTests._valid_runtime_launch_sources(self)
        self.assertEqual(PROBE._validate_runtime_launch_sources(records), records)
        for invalid in (records[:-1], records + [records[0]], records + [{"path": "unknown"}], records + [None]):
            with self.subTest(invalid=invalid):
                with self.assertRaises(PROBE.ProbeError):
                    PROBE._validate_runtime_launch_sources(invalid)

    def test_trusted_launcher_gate_is_still_mandatory(self) -> None:
        with self.assertRaises(PROBE.ProbeError):
            PROBE._require_trusted_persistent_lifecycle_boundary()


if __name__ == "__main__":
    unittest.main()
