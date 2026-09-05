"""Package-scope lookup regressions, including an independent Node witness."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "runtime_scope_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert _SPEC is not None and _SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


class RuntimePackageScopeBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(name, "{}" if name.endswith(".json") else "export {};\n")

    def write(self, name: str, content: str | bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def snapshot(self, source: str) -> dict[str, str]:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        return CONTRACT.runtime_source_digest_snapshot(self.root)

    def test_nearest_manifest_without_imports_does_not_inherit_outer_map(self) -> None:
        self.write("package.json", '{"imports":{"#hidden":"./decoy.mjs"}}')
        self.write("decoy.mjs", "export {};\n")
        for metadata in ("{}", '{"name":"inner"}', '{"imports":null}', '{"imports":{}}'):
            with self.subTest(metadata=metadata):
                self.write("scripts/package.json", metadata)
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("import '#hidden';")

    def test_nearest_manifest_without_matching_self_reference_uses_installed_package(self) -> None:
        self.write("package.json", '{"name":"fixture","exports":"./decoy.mjs"}')
        self.write("decoy.mjs", "console.log('DECOY_EXECUTED');")
        self.write("node_modules/fixture/package.json", '{"name":"fixture","exports":"./actual.mjs"}')
        self.write("node_modules/fixture/actual.mjs", "console.log('ACTUAL_EXECUTED');")
        for metadata in ("{}", '{"name":"inner"}', '{"name":"fixture"}', '{"name":"fixture","exports":null}'):
            with self.subTest(metadata=metadata):
                self.write("scripts/package.json", metadata)
                paths = self.snapshot("import 'fixture';")
                self.assertIn("node_modules/fixture/actual.mjs", paths)
                self.assertNotIn("decoy.mjs", paths)

    def test_scope_lookup_stops_before_node_modules_manifest(self) -> None:
        self.write("package.json", '{"imports":{"#hidden":"./root-decoy.mjs"}}')
        self.write("root-decoy.mjs", "export {};\n")
        self.write("node_modules/package.json", '{"imports":{"#hidden":"./decoy.mjs"}}')
        self.write("node_modules/decoy.mjs", "export {};\n")
        self.write("node_modules/no-manifest/entry.mjs", "import '#hidden';")
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("import '../node_modules/no-manifest/entry.mjs';")

    def test_controlling_manifest_is_validated_without_a_package_import(self) -> None:
        for metadata in (b"{", b"[]", b"null", b"false", b'"module"', b'\xff', b'{"name":NaN}'):
            with self.subTest(metadata=metadata):
                self.write("scripts/package.json", metadata)
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("export {};\n")

    def test_controlling_manifest_non_regular_or_unresolvable_fails_closed(self) -> None:
        scope = self.root / "scripts/package.json"
        scope.mkdir()
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            self.snapshot("export {};\n")
        scope.rmdir()
        for target in ("missing.json", "package.json"):
            scope.symlink_to(target)
            try:
                with self.subTest(target=target), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    self.snapshot("export {};\n")
            finally:
                scope.unlink()

    def test_symlinked_manifest_keeps_the_lexical_scope_base(self) -> None:
        target = self.write("metadata/package.json", '{"imports":{"#dep":"./dep.cjs"}}')
        self.write("metadata/dep.cjs", "module.exports='decoy';")
        self.write("scripts/dep.cjs", "module.exports='actual';")
        (self.root / "scripts/package.json").symlink_to(target)
        paths = self.snapshot("require('#dep');")
        self.assertIn("scripts/dep.cjs", paths)
        self.assertIn("metadata/package.json", paths)
        self.assertNotIn("metadata/dep.cjs", paths)

    def test_nearest_scope_metadata_and_creation_are_bound(self) -> None:
        before = self.snapshot("export {};\n")
        scope = self.write("scripts/package.json", '{"type":"module"}')
        after = self.snapshot("export {};\n")
        self.assertIn("scripts/package.json", after)
        self.assertNotEqual(before, after)
        scope.write_text('{"type":"commonjs"}', encoding="utf-8")
        self.assertNotEqual(after, self.snapshot("export {};\n"))
        scope.unlink()
        self.assertEqual(before, self.snapshot("export {};\n"))

    def test_enclosing_imports_and_self_reference_remain_supported(self) -> None:
        self.write("scripts/package.json", '{"name":"fixture","exports":"./dep.mjs","imports":{"#dep":"./dep.mjs"}}')
        self.write("scripts/dep.mjs", "export {};\n")
        paths = self.snapshot("import '#dep'; import 'fixture';")
        self.assertIn("scripts/dep.mjs", paths)
        self.assertIn("scripts/package.json", paths)

    @unittest.skipUnless(NODE, "Node is required for the independent execution witness")
    def test_node_executes_installed_package_not_outer_scope_decoy(self) -> None:
        self.write("package.json", '{"name":"fixture","exports":"./decoy.mjs"}')
        self.write("decoy.mjs", "console.log('DECOY_EXECUTED');")
        self.write("scripts/package.json", "{}")
        self.write("node_modules/fixture/package.json", '{"name":"fixture","exports":"./actual.mjs"}')
        self.write("node_modules/fixture/actual.mjs", "console.log('ACTUAL_EXECUTED');")
        entry = self.write("scripts/scope-witness.mjs", "import 'fixture';")
        env = {key: value for key, value in os.environ.items() if not key.startswith("NODE_")}
        result = subprocess.run([NODE, str(entry)], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(result.stdout.strip(), "ACTUAL_EXECUTED")
        paths = self.snapshot("import './scope-witness.mjs';")
        self.assertIn("node_modules/fixture/actual.mjs", paths)
        self.assertNotIn("decoy.mjs", paths)
