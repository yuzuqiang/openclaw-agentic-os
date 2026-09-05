"""Independent origin-accounting regressions for node:module capabilities."""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_module_origin_probe", ROOT / "scripts/openclaw-real-gateway-contract-probe.py"
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
CONTRACT = PROBE.runtime_source_contract


class RuntimeModuleOriginRegressions(unittest.TestCase):
    def test_module_constructor_and_namespace_values_cannot_escape(self) -> None:
        origins = (
            "import M from 'node:module';",
            "import * as M from 'node:module';",
            "import {Module as M} from 'module';",
            "import {'Module' as M} from 'node:module';",
            "import {'default' as M} from 'node:module';",
            "const M = require('node:module');",
            "const {Module: M} = require('module');",
        )
        transfers = (
            "const N=M; new N().load('./hidden.cjs');",
            "const N=((M)); new N().load('./hidden.cjs');",
            "const N=M.Module; new N().load('./hidden.cjs');",
            "const N=M['Module']; new N().load('./hidden.cjs');",
            "const box={N:M}; new box.N().load('./hidden.cjs');",
            "const [N]=[M]; new N().load('./hidden.cjs');",
            "consume(M);",
            "export {M};",
            "const value=`${consume(M)}`;",
        )
        for origin in origins:
            for transfer in transfers:
                source = origin + transfer
                with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(source)

    def test_indirect_module_acquisition_is_not_an_untracked_origin(self) -> None:
        sources = (
            "const r=require; const M=r('node:module'); const N=M; new N().load('./hidden.cjs');",
            "import {createRequire} from 'module'; const r=createRequire(import.meta.url); const M=r('module'); new M().load('./hidden.cjs');",
            "const M=(require('module')); const N=M; new N().load('./hidden.cjs');",
            "const N=require('module')['Module']; new N().load('./hidden.cjs');",
            "consume(require('node:module'));",
            "const box={M:require('module')}; new box.M().load('./hidden.cjs');",
            "const M = await import('node:module'); new M.Module().load('./hidden.cjs');",
            "export {Module as M} from 'node:module';",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaises(CONTRACT.RuntimeSourceContractError):
                CONTRACT.import_specifiers(source)

    def test_supported_create_require_and_data_exports_remain_available(self) -> None:
        sources = (
            "import {createRequire} from 'node:module'; const r=createRequire(import.meta.url); r('./hidden.cjs');",
            "const {createRequire: make} = require('node:module'); const r=make(__filename); r('./hidden.cjs');",
            "require('node:module').createRequire(__filename)('./hidden.cjs');",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(('./hidden.cjs', True, 'require'), CONTRACT.import_specifiers(source))
        for source in (
            "import M from 'node:module'; const names=M.builtinModules; M.isBuiltin('node:fs');",
            "const M=require('module'); const names=M.builtinModules; M.isBuiltin('fs');",
            "import {builtinModules,isBuiltin} from 'module'; isBuiltin('fs');",
            "const names=require('module').builtinModules;",
            "const yes=require('module').isBuiltin('fs');",
        ):
            with self.subTest(source=source):
                CONTRACT.import_specifiers(source)

    @unittest.skipUnless(shutil.which('node'), 'requires Node for execution witness')
    def test_node_witness_proves_transferred_module_constructor_loads_code(self) -> None:
        sources = (
            ('.mjs', "import M from 'node:module'; const N=M; new N().load('./hidden.cjs');"),
            ('.mjs', "import * as M from 'node:module'; const N=M.Module; new N().load('./hidden.cjs');"),
            ('.cjs', "const M=require('node:module'); const N=((M)); new N().load('./hidden.cjs');"),
        )
        for suffix, source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'hidden.cjs').write_text("console.log('MODULE_TRANSFER_EXECUTED');\n")
                witness = root / ('witness' + suffix)
                witness.write_text(source)
                result = subprocess.run([shutil.which('node'), str(witness)], cwd=root,
                                        text=True, capture_output=True, check=True, timeout=10)
                self.assertEqual(result.stdout.strip(), 'MODULE_TRANSFER_EXECUTED')
                with self.assertRaises(CONTRACT.RuntimeSourceContractError):
                    CONTRACT.import_specifiers(source)
