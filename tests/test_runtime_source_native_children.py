"""Loader-mode and inherited startup-state regression witnesses for PR45."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_launch_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


class NativeChildSourceClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(name, '{"name":"openclaw"}\n' if name == "package.json" else "export {};\n")

    def write(self, relative: str, source: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def snapshot(self, source: str) -> dict[str, str]:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        return CONTRACT.runtime_source_digest_snapshot(self.root)

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


    def test_parent_fork_keeps_tsx_resolution_and_supported_calls_bind(self) -> None:
        self.write("forked.cjs", "require('./dependency');")
        self.write("dependency.ts", "export const value = 1;")
        self.write("dependency.js", "module.exports = 1;")
        snapshot = self.snapshot("import {fork} from 'child_process';fork('./forked.cjs');")
        self.assertIn("dependency.ts", snapshot)
        self.assertNotIn("dependency.js", snapshot)
        for name in ("spawn", "spawnSync", "execFile", "execFileSync"):
            with self.subTest(name=name):
                source = f"import {{{name}}} from 'child_process';{name}(process.execPath,['./forked.cjs']);"
                snapshot = self.snapshot(source)
                self.assertIn("dependency.js", snapshot)
                self.assertNotIn("dependency.ts", snapshot)

    @unittest.skipUnless(NODE, "requires Node for native child resolution witness")
    def test_real_node_child_and_transitive_fork_execute_native_dependency(self) -> None:
        self.write("plain.cjs", "const {fork}=require('node:child_process');fork('./nested.cjs');")
        self.write("nested.cjs", "require('./dependency');")
        self.write("dependency.ts", "throw new Error('TSX_DECOY');")
        self.write("dependency.js", "require('./actual.cjs');")
        self.write("actual.cjs", "console.log('NATIVE_DEPENDENCY_EXECUTED');")
        source = (
            "const {spawnSync}=require('node:child_process');"
            "const result=spawnSync(process.execPath,['./plain.cjs']);"
            "process.stdout.write(result.stdout);process.exit(result.status);"
        )
        entry = self.write("scripts/oracle.cjs", source)
        result = subprocess.run([NODE, str(entry)], cwd=self.root, text=True,
                                capture_output=True, check=True, timeout=15)
        self.assertEqual(result.stdout.strip(), "NATIVE_DEPENDENCY_EXECUTED")
        snapshot = self.snapshot(source)
        self.assertIn("dependency.js", snapshot)
        self.assertIn("actual.cjs", snapshot)
        self.assertNotIn("dependency.ts", snapshot)

    @unittest.skipUnless(NODE, "requires Node for inherited preload witness")
    def test_real_node_inherited_environment_changes_child_startup(self) -> None:
        self.write("scripts/state.cjs", "process.env.NODE_OPTIONS='--require ./injected.cjs';")
        self.write("injected.cjs", "console.log('INHERITED_PRELOAD_EXECUTED');")
        self.write("child.cjs", "module.exports = 1;")
        source = (
            "require('./state.cjs');const {spawnSync}=require('node:child_process');"
            "const result=spawnSync(process.execPath,['./child.cjs']);"
            "process.stdout.write(result.stdout);process.exit(result.status);"
        )
        entry = self.write("scripts/oracle.cjs", source)
        result = subprocess.run([NODE, str(entry)], cwd=self.root, text=True,
                                capture_output=True, check=True, timeout=15)
        self.assertEqual(result.stdout.strip(), "INHERITED_PRELOAD_EXECUTED")
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot(source)
