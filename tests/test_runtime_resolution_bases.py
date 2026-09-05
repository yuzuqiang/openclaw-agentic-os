"""Literal source paths must use accounted-for, unmodified resolution bases."""
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
    "resolution_base_contract", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")

WORKER = "import {Worker} from 'node:worker_threads';"
LAUNCH = "new Worker(new URL('./bound.mjs', import.meta.url));"
FACTORY = "import {createRequire} from 'node:module';"
CREATE_REQUIRE = "const load=createRequire(import.meta.url); load('./payload.cjs');"


class RuntimeResolutionBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for path in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(path, '{"name":"openclaw"}\n' if path == "package.json" else "export {};\n")
        self.write("scripts/bound.mjs", "export {};\n")
        self.write("scripts/payload.cjs", "module.exports=1;\n")
        self.write("scripts/hidden.mjs", "import {writeFileSync} from 'node:fs'; writeFileSync(process.cwd()+'/marker', 'hidden');\n")
        self.write("scripts/other/payload.cjs", "require('node:fs').writeFileSync(process.cwd()+'/marker', 'hidden');\n")

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def assert_closed(self, source: str) -> None:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.runtime_source_paths(self.root)

    def node_witness(self, source: str, *, suffix: str = "mjs") -> None:
        assert NODE is not None
        marker = self.root / "marker"
        marker.unlink(missing_ok=True)
        self.write(f"scripts/witness.{suffix}", source)
        environment = {key: value for key, value in os.environ.items() if key not in {"NODE_OPTIONS", "NODE_PATH"}}
        result = subprocess.run(
            [NODE, f"scripts/witness.{suffix}"], cwd=self.root,
            env=environment, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("hidden", marker.read_text(encoding="utf-8"))

    def test_worker_url_constructor_cannot_be_shadowed_or_transferred(self) -> None:
        for declaration in (
            "const URL=Fake;", "let URL; URL=Fake;", "var URL=Fake;",
            "function URL() {}", "class URL {}", "const {URL}=holder;",
            "function launch(URL){" + LAUNCH + "} launch(Fake);",
            "const alias=URL; alias.prototype.pathname='other';",
            "import {URL} from './replacement.mjs';",
        ):
            with self.subTest(declaration=declaration):
                self.assert_closed(WORKER + declaration + LAUNCH)

    def test_import_meta_cannot_escape_or_be_reassigned_when_used_as_a_loader_base(self) -> None:
        mutations = (
            "import.meta.url='file:///other/base.mjs';",
            "import.meta['url']='file:///other/base.mjs';",
            "import.meta.url += '/other';", "delete import.meta.url;",
            "Object.assign(import.meta,{url:'file:///other/base.mjs'});",
            "Object.defineProperty(import.meta,'url',{value:'file:///other/base.mjs'});",
            "const meta=import.meta; meta.url='file:///other/base.mjs';",
            "const meta=((import.meta)); mutate(meta);",
            "mutate(import.meta);",
            "[import.meta.url]=['file:///other/base.mjs'];",
        )
        for mutation in mutations:
            for loader in (FACTORY + CREATE_REQUIRE, WORKER + LAUNCH):
                with self.subTest(mutation=mutation, loader=loader):
                    self.assert_closed(mutation + loader)

    def test_commonjs_filename_base_cannot_be_rebound_in_other_syntax_or_scope(self) -> None:
        factory = "const {createRequire}=require('node:module');"
        load = "const load=createRequire(__filename); load('./payload.cjs');"
        for mutation in (
            "__filename='other/base.cjs';", "__filename += '/other';",
            "[__filename]=['other/base.cjs'];",
            "({value:__filename}=holder);", "var __filename='other/base.cjs';",
            "function run(__filename){" + load + "} run('other/base.cjs');",
            "const run=(__filename)=>{" + load + "}; run('other/base.cjs');",
        ):
            with self.subTest(mutation=mutation):
                self.assert_closed(factory + mutation + load)

    def test_ordinary_non_loader_url_and_metadata_usage_is_unchanged(self) -> None:
        for source in (
            "const u=new URL('/health', 'https://example.invalid'); console.log(u.pathname);",
            "console.log(import.meta.url);", "console.log(__filename);",
            "import {URL as NativeURL} from 'node:url'; const u=new NativeURL('https://example.invalid');",
        ):
            with self.subTest(source=source):
                CONTRACT.import_specifiers(source)

    def test_direct_supported_bases_and_readonly_url_utility_imports_still_bind(self) -> None:
        for declaration in (
            "", "import {URL} from 'node:url';",
            "import {fileURLToPath, URL} from 'url';",
            "import {'URL' as URL} from 'node:url';",
            "const {URL}=require('node:url');",
            "import {type URL as URLType, fileURLToPath} from 'node:url';",
            "import type {URL} from 'node:url';",
        ):
            with self.subTest(declaration=declaration):
                source = WORKER + declaration + LAUNCH
                self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
                self.assertIn("scripts/bound.mjs", CONTRACT.runtime_source_paths(self.root))
        for source in (
            FACTORY + CREATE_REQUIRE,
            "const {createRequire}=require('node:module'); const load=createRequire(__filename); load('./payload.cjs');",
            FACTORY + "createRequire(import.meta.url)('./payload.cjs');",
        ):
            with self.subTest(source=source):
                self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
                self.assertIn("scripts/payload.cjs", CONTRACT.runtime_source_paths(self.root))

    def test_inert_names_and_metadata_do_not_taint_loader_bases(self) -> None:
        for inert in (
            "const example='URL = fake; import.meta.url = fake; __filename = fake;';",
            "/* URL = fake; import.meta.url = fake; __filename = fake; */",
            "const example=`URL = fake; import.meta.url = fake; __filename = fake;`;",
            "const example=/URL|__filename|import.meta.url/;",
        ):
            with self.subTest(inert=inert):
                self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, inert + WORKER + LAUNCH + FACTORY + CREATE_REQUIRE)
                paths = CONTRACT.runtime_source_paths(self.root)
                self.assertIn("scripts/bound.mjs", paths)
                self.assertIn("scripts/payload.cjs", paths)

    def test_url_constructor_aliases_and_namespaces_in_transitive_modules_are_accounted_for(self) -> None:
        for mutation in (
            "import {URL as NativeURL} from 'node:url'; change(NativeURL.prototype);",
            "import * as url from 'node:url'; change(url.URL.prototype);",
            "import type from 'node:url'; change(type.URL.prototype);",
            "const {URL:NativeURL}=require('node:url'); change(NativeURL.prototype);",
            "const url=require('node:url'); change(url.URL.prototype);",
            "const make=require; change(make('node:url').URL.prototype);",
            "const url=await import('node:url'); change(url.URL.prototype);",
        ):
            with self.subTest(mutation=mutation):
                self.write("scripts/mutator.mjs", mutation)
                self.assert_closed("import './mutator.mjs';" + WORKER + LAUNCH)

    def test_inline_factory_results_record_literal_target_for_named_and_aliased_factories(self) -> None:
        for declaration, call in (
            (FACTORY, "createRequire(import.meta.url)"),
            ("import {createRequire as make} from 'node:module';", "make(import.meta.url)"),
            ("const {createRequire}=require('node:module');", "createRequire(__filename)"),
            ("const {createRequire:make}=require('node:module');", "make(__filename)"),
        ):
            with self.subTest(declaration=declaration):
                source = declaration + call + "('./payload.cjs');"
                self.assertIn(("./payload.cjs", True, "require"), CONTRACT.import_specifiers(source))
                self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
                self.assertIn("scripts/payload.cjs", CONTRACT.runtime_source_paths(self.root))
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(declaration + call + "(dynamicTarget);")

    @unittest.skipUnless(NODE, "Node is required for real execution witnesses")
    def test_node_executes_unbound_files_when_url_or_module_local_base_is_replaced(self) -> None:
        cases = (
            ("mjs", WORKER + "import {URL as RealURL} from 'node:url'; const URL=function(){return new RealURL('./hidden.mjs',import.meta.url);};" + LAUNCH),
            ("mjs", WORKER + "import {URL as RealURL} from 'node:url'; function run(URL){" + LAUNCH + "} run(function(){return new RealURL('./hidden.mjs',import.meta.url);});"),
            ("mjs", FACTORY + "import.meta.url=new URL('./other/base.mjs',import.meta.url).href;" + CREATE_REQUIRE),
            ("mjs", FACTORY + "const meta=import.meta; meta.url=new URL('./other/base.mjs',import.meta.url).href;" + CREATE_REQUIRE),
            ("cjs", "const {createRequire}=require('node:module'); __filename=process.cwd()+'/scripts/other/base.cjs'; const load=createRequire(__filename); load('./payload.cjs');"),
            ("cjs", "const {createRequire}=require('node:module'); function run(__filename){const load=createRequire(__filename); load('./payload.cjs');} run(process.cwd()+'/scripts/other/base.cjs');"),
        )
        for suffix, source in cases:
            with self.subTest(source=source):
                self.node_witness(source, suffix=suffix)
                self.assert_closed(source)

    @unittest.skipUnless(NODE, "Node is required for real execution witnesses")
    def test_node_worker_redirected_by_url_prototype_mutation_in_imported_module(self) -> None:
        mutation = (
            "import {URL as NativeURL} from 'node:url';"
            "Object.defineProperty(NativeURL.prototype,'pathname',{get(){return process.cwd()+'/scripts/hidden.mjs';}});"
        )
        self.write("scripts/mutator.mjs", mutation)
        source = "import './mutator.mjs';" + WORKER + LAUNCH
        self.node_witness(source)
        self.assert_closed(source)


if __name__ == "__main__":
    unittest.main()
