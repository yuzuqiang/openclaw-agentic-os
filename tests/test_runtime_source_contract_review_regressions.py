"""PR45 review reproductions and adversarial neighbours, not runtime attestation."""
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

SPEC = importlib.util.spec_from_file_location("review_regression_probe", SCRIPTS / "openclaw-real-gateway-contract-probe.py")
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class SourceContractReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(relative, '{"name":"fixture"}' if relative == "package.json" else "export {};\n")
        self.write("scripts/hidden.cjs", "module.exports = 1;\n")
        self.write("scripts/hidden.mjs", "export const n = 1;\n")

    def write(self, relative: str, text: str) -> Path:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def snapshot(self, source: str) -> dict[str, str]:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        return CONTRACT.runtime_source_digest_snapshot(self.root)

    def assert_bound_or_rejected(self, source: str, path: str) -> None:
        try:
            snapshot = self.snapshot(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(path, snapshot, source)

    def test_worker_capability_transfers(self) -> None:
        sources = (
            "import {Worker} from 'node:worker_threads'; const W=Worker;",
            "import {Worker as T} from 'worker_threads'; const W=(((T)));",
            "import * as wt from 'worker_threads'; const W=wt['Worker'];",
            "import wt from 'worker_threads'; const ns=wt; const W=ns.Worker;",
            "import wt, {Worker as W} from 'worker_threads';",
            "import {default as wt} from 'worker_threads'; const W=wt.Worker;",
            "import wt, * as other from 'worker_threads'; const W=other.Worker;",
            "const {Worker: T}=require('worker_threads'); const W=T;",
            "import {Worker} from 'worker_threads'; const W=[Worker][0];",
            "import {Worker} from 'worker_threads'; const box={W:Worker}; const W=box.W;",
            "import {Worker} from 'worker_threads'; let W; W=Worker;",
            "const W=require('worker_threads').Worker;",
            "const {Worker: W}=await import('worker_threads');",
            "import {Worker} from 'worker_threads'; const W=((value)=>value)(Worker);",
            "import {Worker} from 'worker_threads'; const W=Worker.bind(null);",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source + "new W(new URL('./hidden.mjs',import.meta.url));", "scripts/hidden.mjs")

    def test_child_process_transfer_spellings(self) -> None:
        for member in ("spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync", "fork"):
            for rhs in (f"cp.{member}", f"cp['{member}']", f"cp[`{member}`]", f"((cp))['{member}']"):
                source = f"import * as cp from 'child_process'; const go={rhs}; go('./hidden.sh');"
                with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot(source)

    def test_container_callback_and_namespace_transfers(self) -> None:
        for suffix in (
            "const ns=cp; ns.spawnSync('./hidden.sh');",
            "const {spawnSync:go}=cp; go('./hidden.sh');",
            "Reflect.apply(cp['spawnSync'],null,['./hidden.sh']);",
            "((go)=>go('./hidden.sh'))(cp.spawnSync);",
            "const box={go:cp.spawnSync}; box.go('./hidden.sh');",
            "new cp.ChildProcess().spawn({file:'./hidden.sh'});",
            "const key='spawnSync'; cp[key]('./hidden.sh');",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot("import * as cp from 'child_process';" + suffix)

    def test_grouped_require_aliases(self) -> None:
        for depth in (0, 1, 2, 3, 8, 32, 64):
            with self.subTest(depth=depth):
                source = 'const r=' + '(' * depth + 'require' + ')' * depth + ";r('./hidden.cjs');"
                self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_unaccounted_require_transfers(self) -> None:
        for source in (
            "let r;r=((require));r('./hidden.cjs');",
            "const r=[require][0];r('./hidden.cjs');",
            "const box={r:require};box.r('./hidden.cjs');",
            "((r)=>r('./hidden.cjs'))(require);",
            "const r=true?require:null;r('./hidden.cjs');",
            "const r=require.bind(null);r('./hidden.cjs');",
            "const r=module.require;r('./hidden.cjs');",
            "const r=module['require'];r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.cjs")

    def test_quote_bearing_hashbang_and_html_comments(self) -> None:
        for newline in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            for opener, closer in (('#!/usr/bin/node "', '// "'), ('<!-- "', '<!-- "'), ('--> "', '--> "'), ('/* trivia */ --> "', '// "')):
                with self.subTest(newline=repr(newline), opener=opener):
                    self.assert_bound_or_rejected(opener+newline+"require('./hidden.cjs');"+newline+closer, "scripts/hidden.cjs")

    def test_template_and_literal_boundaries(self) -> None:
        for source in (
            "const s=\"<!-- require(unknown)\";require('./hidden.cjs');",
            "const s=`<!-- require(unknown)`;require('./hidden.cjs');",
            "const s=/<!-- require(unknown)/;require('./hidden.cjs');",
            "const s=`raw ${require('./hidden.cjs')} tail`;",
            "const s=`raw ${`nested ${require('./hidden.cjs')}`} tail`;",
            "const s=`raw ${/[}]/.test('}') ? require('./hidden.cjs') : null}`;",
        ):
            with self.subTest(source=source):
                self.assertIn("scripts/hidden.cjs", self.snapshot(source))

    def test_module_scope_metadata_for_relative_file(self) -> None:
        self.write("node_modules/pkg/sub/file.js", "console.log(42);")
        self.write("node_modules/pkg/package.json", '{"name":"pkg"}')
        path = self.write("node_modules/pkg/sub/package.json", '{"type":"module"}')
        source = "import '../node_modules/pkg/sub/file.js';"
        before = self.snapshot(source)
        self.assertIn("node_modules/pkg/sub/package.json", before)
        path.write_text('{"type":"commonjs"}', encoding="utf-8")
        self.assertNotEqual(before, self.snapshot(source))
        path.unlink()
        self.assertNotEqual(before, self.snapshot(source))

    def test_entrypoint_scope_and_new_scope_insertion(self) -> None:
        self.write("scripts/package.json", '{"type":"module"}')
        self.write("scripts/sub/file.js", "console.log(42);")
        source = "import './sub/file.js';"
        before = self.snapshot(source)
        self.assertIn("scripts/package.json", before)
        self.write("scripts/sub/package.json", '{"type":"module"}')
        self.assertNotEqual(before, self.snapshot(source))

    def test_preload_transitive_source_and_metadata_drift(self) -> None:
        node = self.write("bin/node", "#!/bin/sh\nexit 0\n")
        node.chmod(0o755)
        self.write("node_modules/tsx/package.json", '{"name":"tsx","type":"module"}')
        loader = self.write("node_modules/tsx/dist/loader.mjs", "import 'helper';")
        metadata = self.write("node_modules/helper/package.json", '{"name":"helper","main":"index.mjs"}')
        helper = self.write("node_modules/helper/index.mjs", "export const n=1;")
        env = {"PATH":str(node.parent)}
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            executable, preload, before = PROBE._runtime_launch_bindings(self.root, env)
            helper.write_text("export const n=2;", encoding="utf-8")
            self.assertNotEqual(before, PROBE._runtime_launch_bindings(self.root, env)[2])
            with self.assertRaises(PROBE.ProbeError):
                PROBE._assert_runtime_launch_sources_still_bound(openclaw_root=self.root,runner_env=env,expected_node_executable=executable,expected_tsx_preload_specifier=preload,expected_sources=before)
            before = PROBE._runtime_launch_bindings(self.root, env)[2]
            metadata.write_text('{"name":"helper","main":"index.mjs","type":"module"}', encoding="utf-8")
            self.assertNotEqual(before, PROBE._runtime_launch_bindings(self.root, env)[2])

    def test_create_require_factory_and_result_transfers(self) -> None:
        for source in (
            "import {createRequire} from 'module';const cr=createRequire;const r=cr(import.meta.url);r('./hidden.cjs');",
            "import {createRequire} from 'module';const cr=((createRequire));const r=cr(import.meta.url);r('./hidden.cjs');",
            "import * as mod from 'module';const cr=mod.createRequire;const r=cr(import.meta.url);r('./hidden.cjs');",
            "import * as mod from 'module';const cr=mod['createRequire'];const r=cr(import.meta.url);r('./hidden.cjs');",
            "import {createRequire} from 'module';const box=[createRequire(import.meta.url)];box[0]('./hidden.cjs');",
            "import {createRequire} from 'module';((r)=>r('./hidden.cjs'))(createRequire(import.meta.url));",
            "import * as mod from 'module';const r=mod.createRequire(import.meta.url);r('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.cjs")

    def test_unbound_launch_options_are_rejected(self) -> None:
        for source in (
            "import {Worker} from 'worker_threads';new Worker(new URL('./hidden.mjs',import.meta.url),{execArgv:['--import','./other.mjs']});",
            "import {spawnSync} from 'child_process';spawnSync(process.execPath,['./hidden.mjs'],{env:{NODE_OPTIONS:'--import ./other.mjs'}});",
            "import {fork} from 'child_process';fork('./hidden.cjs',[],{execArgv:['--require','./other.cjs']});",
        ):
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot(source)

    def test_nearest_package_scope_does_not_inherit_outer_imports(self) -> None:
        self.write("package.json", '{"name":"fixture","imports":{"#hidden":"./scripts/hidden.mjs"}}')
        self.write("scripts/sub/package.json", '{"type":"module"}')
        self.write("scripts/sub/entry.mjs", "import '#hidden';")
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("import './sub/entry.mjs';")

    def test_malformed_and_out_of_root_scope_metadata_fail_closed(self) -> None:
        self.write("scripts/sub/entry.js", "console.log(42);")
        scope = self.write("scripts/sub/package.json", "{")
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("import './sub/entry.js';")
        scope.unlink()
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external) / "package.json"
            outside.write_text('{"type":"module"}', encoding="utf-8")
            scope.symlink_to(outside)
            with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot("import './sub/entry.js';")

    def test_unsupported_preload_dependency_does_not_fall_back_to_package_hash(self) -> None:
        node = self.write("bin/node", "#!/bin/sh\nexit 0\n")
        node.chmod(0o755)
        self.write("node_modules/tsx/package.json", '{"name":"tsx","type":"module"}')
        loader = self.write("node_modules/tsx/loader.mjs", "import(process.argv[2]);")
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            with self.assertRaisesRegex(PROBE.ProbeError, "preload dependency closure"):
                PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})

    def test_inert_capability_declarations_do_not_cross_statements(self) -> None:
        self.write("scripts/plain.mjs", "export const value=1;")
        for text in (
            "import {Worker as W} from 'worker_threads';",
            "import {spawnSync} from 'child_process';",
            "import {createRequire} from 'module';",
        ):
            source = 'import {value} from "./plain.mjs"; const text=' + json.dumps(text) + ';'
            with self.subTest(text=text):
                self.assertIn("scripts/plain.mjs", self.snapshot(source))

    def test_capability_acquisition_variants_cannot_hide_entries(self) -> None:
        for source in (
            "const r=require; const wt=r('worker_threads');new wt.Worker(new URL('./hidden.mjs',import.meta.url));",
            "import {createRequire} from 'module';const r=createRequire(import.meta.url);const wt=r('worker_threads');new wt.Worker(new URL('./hidden.mjs',import.meta.url));",
            "import {default as wt} from 'worker_threads';new wt.Worker(new URL('./hidden.mjs',import.meta.url));",
            "import wt, * as wt2 from 'worker_threads';new wt2.Worker(new URL('./hidden.mjs',import.meta.url));",
            "import {'Worker' as W} from 'worker_threads'; const T=W;new T(new URL('./hidden.mjs',import.meta.url));",
            "import {Worker} from 'worker_threads'; const doc=\"new Worker(new URL('./hidden.mjs', import.meta.url))\";const T=Worker;new T(new URL('./hidden.mjs',import.meta.url));",
            "const doc=\"import {Worker as W} from 'worker_threads'\";const {Worker: W}=require('worker_threads');const T=W;new T(new URL('./hidden.mjs',import.meta.url));",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.mjs")

    def test_template_capability_transfers_and_grouped_aliases(self) -> None:
        for source in (
            "import {Worker} from 'worker_threads';const s=`${(()=>{const W=Worker;return new W(new URL('./hidden.mjs',import.meta.url));})()}`;",
            "const s=`${(()=>{const r=((require));return r('./hidden.cjs');})()}`;",
            "const s=`${`nested ${(()=>{const r=((require));return r('./hidden.cjs');})()}`}`;",
        ):
            with self.subTest(source=source):
                self.assert_bound_or_rejected(source, "scripts/hidden.mjs" if "Worker" in source else "scripts/hidden.cjs")

    def test_pnpm_style_preload_sibling_resolution_is_bound(self) -> None:
        node = self.write("bin/node", "#!/bin/sh\nexit 0\n")
        node.chmod(0o755)
        package = "node_modules/.pnpm/tsx@1/node_modules/tsx"
        helper = "node_modules/.pnpm/helper@1/node_modules/helper"
        self.write(package + "/package.json", '{"name":"tsx","type":"module"}')
        loader = self.write(package + "/dist/loader.mjs", "import 'helper';")
        self.write(helper + "/package.json", '{"name":"helper","main":"index.mjs"}')
        implementation = self.write(helper + "/index.mjs", "export const n=1;")
        (self.root / "node_modules/tsx").symlink_to(self.root / package, target_is_directory=True)
        (self.root / "node_modules/.pnpm/tsx@1/node_modules/helper").symlink_to(self.root / helper, target_is_directory=True)
        with mock.patch.object(PROBE, "_resolve_node_import_path", return_value=loader):
            before = PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})[2]
            implementation.write_text("export const n=2;", encoding="utf-8")
            self.assertNotEqual(before, PROBE._runtime_launch_bindings(self.root, {"PATH": str(node.parent)})[2])

    @unittest.skipUnless(shutil.which("node"), "Node is needed as a syntax/execution oracle")
    def test_node_executes_review_reproductions(self) -> None:
        self.write("scripts/hidden.cjs", "console.log('hidden-loaded');")
        for source in (
            '<!-- "\nrequire("./hidden.cjs");\n<!-- "',
            '#!/usr/bin/node "\nrequire("./hidden.cjs");\n// "',
            'const r=((require));r("./hidden.cjs");',
        ):
            with self.subTest(source=source):
                entry = self.write("scripts/oracle.cjs", source)
                result = subprocess.run([shutil.which("node"),str(entry)],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn("hidden-loaded",result.stdout)
                self.assert_bound_or_rejected(source,"scripts/hidden.cjs")


if __name__ == "__main__":
    unittest.main()
