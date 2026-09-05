"""Exact-head review regressions plus adjacent provenance/loader boundaries."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_openclaw_real_gateway_contract_probe import MODULE

CONTRACT = MODULE.runtime_source_contract
NODE = shutil.which("node")


class ReviewCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for relative in CONTRACT.PERSISTENT_RUNTIME_SOURCE_ENTRYPOINTS:
            self.write(relative, '{"name":"openclaw"}\n' if relative == "package.json" else "export {};\n")

    def write(self, relative: str, source: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def snapshot(self, source: str) -> dict[str, str]:
        self.write(CONTRACT.PERSISTENT_LIFECYCLE_RUNNER, source)
        return CONTRACT.runtime_source_digest_snapshot(self.root)

    def assert_bound_or_rejected(self, source: str) -> None:
        try:
            specifiers = CONTRACT.import_specifiers(source)
        except CONTRACT.RuntimeSourceContractError:
            return
        self.assertIn(("./hidden.cjs", True, "require"), specifiers)

    def test_class_heritage_regex_cannot_hide_later_loads(self) -> None:
        for quote in ("'", '"'):
            for regex in (f"/{quote}/", f"/[{quote}]/"):
                for trivia in (" ", "\n", "/*heritage*/"):
                    source = f"class C extends{trivia}{regex}.constructor {{}};require('./hidden.cjs');//{quote}"
                    with self.subTest(source=source):
                        self.assert_bound_or_rejected(source)

    def test_extends_property_is_still_division(self) -> None:
        self.assertIn(
            ("./hidden.cjs", True, "require"),
            CONTRACT.import_specifiers("const obj={extends:2};obj.extends / require('./hidden.cjs');"),
        )

    @unittest.skipUnless(NODE, "requires Node execution witness")
    def test_real_node_executes_require_after_heritage_regex(self) -> None:
        self.write("hidden.cjs", "console.log('BOUND_HERITAGE_WITNESS');")
        script = self.write("heritage.cjs", "class C extends /'/.constructor {};require('./hidden.cjs');//'")
        proc = subprocess.run([NODE, str(script)], cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("BOUND_HERITAGE_WITNESS", proc.stdout)
        self.assert_bound_or_rejected(script.read_text())

    def test_type_only_worker_and_child_imports_do_not_create_runtime_capabilities(self) -> None:
        for source in (
            "import type {Worker} from 'node:worker_threads';type W=Worker;",
            "import type {Worker as W} from 'node:worker_threads';type T=W;",
            "import type * as wt from 'node:worker_threads';type T=wt.Worker;",
            "import {type Worker,isMainThread} from 'node:worker_threads';type T=Worker;",
            "import {type Worker as W,isMainThread} from 'node:worker_threads';type T=W;",
            "import type {ChildProcess} from 'node:child_process';type T=ChildProcess;",
            "import {type ChildProcess,spawnSync} from 'node:child_process';type T=ChildProcess;",
        ):
            with self.subTest(source=source):
                CONTRACT.import_specifiers(source)
                bindings, _declarations, _loads = CONTRACT._execution_capability_bindings(source)
                self.assertNotIn("Worker", bindings)
                self.assertNotIn("W", bindings)
                self.assertNotIn("wt", bindings)
                self.assertNotIn("ChildProcess", bindings)

    def test_type_keyword_does_not_erase_real_default_or_mixed_runtime_binding(self) -> None:
        for source in (
            "import type from 'node:worker_threads';const W=type.Worker;",
            "import type,{isMainThread} from 'node:worker_threads';const W=type.Worker;",
            "import {type ChildProcess,spawnSync as run} from 'node:child_process';const f=run;",
            "import {type Worker,Worker as W} from 'node:worker_threads';const f=W;",
        ):
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_type_declarations_do_not_exempt_following_executable_transfers(self) -> None:
        for erased in (
            "interface Shape {} ",
            "interface Shape { value: string }\n",
            "type Shape = {}\n",
            "type Shape = { value: string };",
        ):
            source = (
                "import {Worker} from 'node:worker_threads';"
                + erased
                + "const Alias=Worker;new Alias(new URL('./hidden.mjs',import.meta.url));"
            )
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_module_metadata_cannot_transfer_loader_authority(self) -> None:
        for base in ("module", "(module)", "((module))"):
            for expression in (".parent.require", "['parent']['require']", ".children[0].require", "?.['children'][0]['require']", ".paths"):
                with self.subTest(base=base, expression=expression), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(f"const r={base}{expression};r('./hidden.cjs');")

    def test_url_constructor_shadowing_and_metadata_changes_reject_worker_closure(self) -> None:
        self.write("scripts/bound.cjs", "module.exports={};")
        self.write("scripts/hidden.cjs", "module.exports={};")
        worker = "import {Worker} from 'node:worker_threads';new Worker(new URL('./bound.cjs',import.meta.url));"
        cases = (
            "import{URL as RealURL}from'node:url';const URL=function(){return new RealURL('./hidden.cjs',import.meta.url)};",
            "const URL=globalThis.URL;",
            "import.meta.url='file:///tmp/unbound/entry.mjs';",
            "const meta=import.meta;meta.url='file:///tmp/unbound/entry.mjs';",
            "Object.assign(import.meta,{url:'file:///tmp/unbound/entry.mjs'});",
            "new URL('http://example.invalid',(import.meta.url='file:///tmp/unbound/entry.mjs'));",
            "new URL('http://example.invalid',Object.assign(import.meta,{url:'file:///tmp/unbound/entry.mjs'}));",
        )
        for mutation in cases:
            with self.subTest(mutation=mutation), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                self.snapshot(mutation + worker)

    def test_worker_inherits_unbound_startup_state_from_transitive_source(self) -> None:
        self.write("scripts/bound.cjs", "module.exports={};")
        self.write("scripts/ambient.mjs", "process.execArgv.push('--require','./hidden.cjs');")
        with self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "ambient launch state"):
            self.snapshot("import './ambient.mjs';import {Worker} from 'node:worker_threads';new Worker(new URL('./bound.cjs',import.meta.url));")

    def test_valid_worker_url_constructors_and_relative_resolution_remain_bound(self) -> None:
        self.write("scripts/bound.cjs", "module.exports={};")
        self.write("bound.cjs", "throw new Error('wrong cwd');")
        for declaration in (
            "", "import {URL} from 'node:url';", "const {URL}=require('node:url');",
            "import type {URL} from 'node:url';type Address=URL;",
            "import {type URL} from 'node:url';type Address=URL;",
        ):
            with self.subTest(declaration=declaration):
                snapshot = self.snapshot(declaration + "import {Worker} from 'node:worker_threads';new Worker(new URL('./bound.cjs',import.meta.url));")
                self.assertIn("scripts/bound.cjs", snapshot)
                self.assertNotIn("bound.cjs", snapshot)

    def test_unknown_executable_suffix_is_not_opaque_data(self) -> None:
        for filename in ("hidden", "hidden.txt", "hidden.bin"):
            self.write("scripts/" + filename, "require('./omitted.cjs');")
            with self.subTest(filename=filename), self.assertRaisesRegex(CONTRACT.RuntimeSourceContractError, "unsupported executable file suffix"):
                self.snapshot(f"require('./{filename}');")
        self.write("scripts/data.json", '{"safe":true}')
        self.assertIn("scripts/data.json", self.snapshot("require('./data.json');"))

    def test_node_modules_directory_is_not_an_extra_package_search_level(self) -> None:
        self.write("node_modules/outer/package.json", '{"name":"outer","main":"index.cjs"}')
        self.write("node_modules/outer/index.cjs", "require('selected');")
        for relative, marker in (("node_modules/selected", "actual"), ("node_modules/node_modules/selected", "decoy")):
            self.write(relative + "/package.json", json.dumps({"name":"selected", "main":"index.cjs"}))
            self.write(relative + "/index.cjs", f"module.exports='{marker}';")
        snapshot = self.snapshot("require('outer');")
        self.assertIn("node_modules/selected/index.cjs", snapshot)
        self.assertNotIn("node_modules/node_modules/selected/index.cjs", snapshot)


if __name__ == "__main__":
    unittest.main()
