"""Independent regression witnesses for capability escapes found at bb160fb."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_transfer_crosscheck", ROOT / "scripts/agentic_os_runtime_source_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
NODE = shutil.which("node")


class RuntimeCapabilityTransferCrosschecks(unittest.TestCase):
    def assert_closed(self, source: str) -> None:
        with self.assertRaises(CONTRACT.RuntimeSourceContractError):
            CONTRACT.import_specifiers(source)

    def test_spread_operands_are_not_mistaken_for_dot_property_names(self) -> None:
        for declaration, name in (
            ("import * as wt from 'node:worker_threads';", "wt"),
            ("import * as cp from 'node:child_process';", "cp"),
            ("import * as M from 'node:module';", "M"),
            ("const M=require('node:module');", "M"),
        ):
            for gap in ("", " ", "/* comment */", "\n"):
                with self.subTest(declaration=declaration, gap=gap):
                    self.assert_closed(declaration + "const holder={..." + gap + name + "};consume(holder);")

    def test_module_namespace_and_constructor_transfers_are_accounted_for(self) -> None:
        declarations = (
            "const M=require('node:module');",
            "import M from 'node:module';",
            "import {default as M} from 'node:module';",
            "import * as M from 'node:module';",
            "import {Module as M} from 'node:module';",
        )
        uses = (
            "const N=M;new N().load('./hidden.cjs');",
            "const N=((M));new N().load('./hidden.cjs');",
            "const box={value:M};new box.value().load('./hidden.cjs');",
            "const box=[M];new box[0]().load('./hidden.cjs');",
            "const get=()=>M;new (get())().load('./hidden.cjs');",
            "Reflect.construct(M,[]).load('./hidden.cjs');",
            "`${M}`;",
        )
        for declaration in declarations:
            for use in uses:
                with self.subTest(declaration=declaration, use=use):
                    self.assert_closed(declaration + use)

    def test_require_and_create_require_loaders_cannot_escape_via_spread(self) -> None:
        for declaration, name in (
            ("", "require"),
            ("const r=require;", "r"),
            ("const {createRequire}=require('node:module');const r=createRequire(__filename);", "r"),
        ):
            for gap in ("", " ", "/* comment */", "\n"):
                with self.subTest(declaration=declaration, gap=gap):
                    self.assert_closed(declaration + "const holder={..." + gap + name + "};consume(holder);")

    def test_supported_module_factories_and_inert_members_still_work(self) -> None:
        for source in (
            "const {createRequire}=require('node:module');const r=createRequire(__filename);r('./hidden.cjs');",
            "require('node:module').createRequire(__filename)('./hidden.cjs');",
            "import * as M from 'node:module';console.log(M.builtinModules);require('./hidden.cjs');",
            "import * as M from 'node:module';M.isBuiltin('fs');require('./hidden.cjs');",
            "import * as M from 'node:module';const data={};data.M=1;require('./hidden.cjs');",
            "const data={.../x/};require('./hidden.cjs');",
        ):
            with self.subTest(source=source):
                self.assertIn(("./hidden.cjs", True, "require"), CONTRACT.import_specifiers(source))

    @unittest.skipUnless(NODE, "Node is required for execution witnesses")
    def test_real_node_executes_the_previously_unbound_dependency(self) -> None:
        sources = {
            "worker.mjs": "import * as wt from 'node:worker_threads';const holder={...wt};new holder.Worker(new URL('./hidden.cjs',import.meta.url));",
            "module.cjs": "const M=require('node:module');const N=M;new N().load(__dirname+'/hidden.cjs');",
            "module-spread.cjs": "const M=require('node:module');const holder={...M};new holder.Module().load(__dirname+'/hidden.cjs');",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hidden.cjs").write_text("console.log('HIDDEN_EXECUTED');\n", encoding="utf-8")
            for name, source in sources.items():
                with self.subTest(name=name):
                    self.assert_closed(source)
                    main = root / name
                    main.write_text(source, encoding="utf-8")
                    result = subprocess.run(
                        [NODE, str(main)], cwd=root, capture_output=True,
                        text=True, timeout=15, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "HIDDEN_EXECUTED")


if __name__ == "__main__":
    unittest.main()
