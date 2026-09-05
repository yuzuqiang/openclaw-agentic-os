"""Nested direct invocations are not transfers of their loader capabilities.

All execution witnesses use isolated temporary files. The production launcher
boundary is not mocked out or relaxed by these tests.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nested_direct_call_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


def fixture(root: Path, files: dict[str, str]) -> None:
    defaults = {
        path: "export const fixture = true;\n"
        for path in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS
    }
    defaults["package.json"] = '{"name":"fixture","type":"module"}\n'
    defaults.update(files)
    for relative, content in defaults.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class RuntimeNestedDirectCallTests(unittest.TestCase):
    def test_child_calls_nested_in_other_expressions_remain_bound(self) -> None:
        for member in ("spawnSync", "execFileSync", "spawn", "execFile"):
            for declaration in (
                f"import {{{member} as runNode}} from 'node:child_process';",
                f"const {{{member}: runNode}} = require('node:child_process');",
            ):
                invocation = "runNode(process.execPath, ['./hidden.cjs'])"
                for expression in (
                    f"use({invocation});",
                    f"String({invocation}.stdout);",
                    f"outer(inner({invocation}));",
                    f"const results = [{invocation}];",
                    f"const result = {{child: {invocation}}};",
                ):
                    with self.subTest(member=member, declaration=declaration, expression=expression):
                        self.assertIn(
                            ("./hidden.cjs", True, "spawn"),
                            CONTRACT.import_specifiers(declaration + expression),
                        )

    def test_grouped_and_transferred_child_callables_still_fail_closed(self) -> None:
        prefix = "import {spawnSync as runNode} from 'node:child_process';"
        uses = (
            "(runNode)(process.execPath, ['./hidden.cjs']);",
            "((runNode))(process.execPath, ['./hidden.cjs']);",
            "(0, runNode)(process.execPath, ['./hidden.cjs']);",
            "const f = true ? runNode : null; f(process.execPath, ['./hidden.cjs']);",
            "Reflect.apply(runNode, null, [process.execPath, ['./hidden.cjs']]);",
            "wrap(runNode)(process.execPath, ['./hidden.cjs']);",
            "const f = [runNode][0]; f(process.execPath, ['./hidden.cjs']);",
        )
        for use in uses:
            with self.subTest(use=use), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(prefix + use)

    def test_direct_require_in_invoked_functions_remains_bound(self) -> None:
        sources = (
            "const value = (() => require('./hidden.cjs'))();",
            "const value = (function () { return require('./hidden.cjs'); })();",
            "const value = (() => { return (() => require('./hidden.cjs'))(); })();",
            "const value = `${(() => { return require('./hidden.cjs'); })()}`;",
            "const value = `${(function () { return require('./hidden.cjs'); })()}`;",
            "const value = `${`${(() => require('./hidden.cjs'))()}`}`;",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    def test_invoked_function_literals_do_not_manufacture_dependencies(self) -> None:
        sources = (
            '''const value = (() => "require('./missing.cjs')")();''',
            "const value = (() => { return /require/; })();",
            "const value = (() => `require('./missing.cjs')`)();",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual([], CONTRACT.import_specifiers(source))

    def test_require_returned_or_transferred_by_invoked_functions_is_rejected(self) -> None:
        sources = (
            "(() => require)()('./hidden.cjs');",
            "(function () { return require; })()('./hidden.cjs');",
            "(() => [require][0])()('./hidden.cjs');",
            "(() => (0, require))()('./hidden.cjs');",
            "(() => true ? require : null)()('./hidden.cjs');",
            "((0, require))('./hidden.cjs');",
            "require.call(null, './hidden.cjs');",
            "Reflect.apply(require, null, ['./hidden.cjs']);",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_nested_require_dependency_changes_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: "import './entry.cjs';",
                "scripts/entry.cjs": "module.exports = `${(() => require('./hidden.cjs'))()}`;",
                "scripts/hidden.cjs": "module.exports = 'first';",
            })
            before = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertIn("scripts/hidden.cjs", before)
            (root / "scripts/hidden.cjs").write_text("module.exports = 'second';", encoding="utf-8")
            after = CONTRACT.runtime_source_digest_snapshot(root)
            self.assertNotEqual(before["scripts/hidden.cjs"], after["scripts/hidden.cjs"])

    @unittest.skipUnless(NODE, "Node is required for the independent require execution witness")
    def test_node_executes_nested_direct_require_but_transfers_are_rejected(self) -> None:
        for expression, accepted in (
            ("`${(() => { return require('./hidden.cjs'); })()}`", True),
            ("(function () { return require('./hidden.cjs'); })()", True),
            ("(() => require)()('./hidden.cjs')", False),
            ("(function () { return require; })()('./hidden.cjs')", False),
        ):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = f"console.log({expression});"
                (root / "entry.cjs").write_text(source, encoding="utf-8")
                (root / "hidden.cjs").write_text("module.exports = 'witness';", encoding="utf-8")
                env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
                result = subprocess.run(
                    [NODE, str(root / "entry.cjs")], cwd=root, env=env,
                    capture_output=True, text=True, check=True, timeout=10,
                )
                self.assertEqual("witness", result.stdout.strip())
                if accepted:
                    self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))
                else:
                    with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                        CONTRACT.import_specifiers(source)

    @unittest.skipUnless(NODE, "Node is required for the independent child-process witness")
    def test_node_nested_direct_child_call_uses_launch_cwd_not_importer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = (
                "import {spawnSync as runNode} from 'node:child_process';"
                "process.stdout.write(runNode(process.execPath, ['./hidden.cjs']).stdout);"
            )
            fixture(root, {
                CONTRACT.PERSISTENT_LIFECYCLE_RUNNER: source,
                "scripts/entry.mjs": source,
                "hidden.cjs": "console.log('launch-root');",
                "scripts/hidden.cjs": "console.log('wrong-importer');",
            })
            env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
            result = subprocess.run(
                [NODE, str(root / "scripts/entry.mjs")], cwd=root, env=env,
                capture_output=True, text=True, check=True, timeout=10,
            )
            self.assertEqual("launch-root", result.stdout.strip())
            paths = CONTRACT.runtime_source_paths(root)
            self.assertIn("hidden.cjs", paths)
            self.assertNotIn("scripts/hidden.cjs", paths)


if __name__ == "__main__":
    unittest.main()
