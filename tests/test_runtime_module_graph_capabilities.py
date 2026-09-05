"""CommonJS module graph/search-path capabilities must not bypass provenance."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_openclaw_real_gateway_contract_probe import MODULE

SOURCE = MODULE.runtime_source_contract


class RuntimeModuleGraphCapabilityTests(unittest.TestCase):
    def test_module_graph_and_search_path_references_fail_closed(self) -> None:
        for base in ("module", "(module)", "((module))"):
            for member in ("parent", "children", "paths"):
                for accessor in (f".{member}", f"['{member}']", f"?.['{member}']"):
                    source = f"const ref={base}{accessor};consume(ref);"
                    with self.subTest(source=source):
                        with self.assertRaises(SOURCE.RuntimeSourceContractError):
                            SOURCE.import_specifiers(source)
        for source in (
            "const r=module['parent']['require'];r('./hidden.cjs');",
            "require('./bound.cjs');const r=module['children'][0]['require'];r('./hidden.cjs');",
            "module['paths'].unshift('./alternate');require('fixture');",
        ):
            with self.subTest(source=source):
                with self.assertRaises(SOURCE.RuntimeSourceContractError):
                    SOURCE.import_specifiers(source)

    def test_module_exports_metadata_and_unrelated_properties_remain_supported(self) -> None:
        for source in (
            "module.exports={ok:true};",
            "module['exports']={ok:true};",
            "const id=module.id;const filename=module.filename;const loaded=module.loaded;",
            "const object={parent:1,children:[],paths:[]};console.log(object.parent);",
            "const text=\"module['parent']['require']('./hidden.cjs')\";",
            "// module.paths.push('./hidden');\nmodule.exports=1;",
        ):
            with self.subTest(source=source):
                self.assertEqual(SOURCE.import_specifiers(source), [])

    @unittest.skipUnless(shutil.which("node"), "Node is required for execution witnesses")
    def test_real_node_module_graph_and_paths_can_execute_unbound_source(self) -> None:
        cases = {
            "parent": "const r=module['parent']['require'];r('./hidden.cjs');",
            "children": "require('./bound.cjs');const r=module['children'][0]['require'];r('./hidden.cjs');",
            "paths": "module['paths'].unshift('./alternate');require('fixture');",
        }
        for name, source in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "main.cjs").write_text("require('./middle.cjs');", encoding="utf-8")
                (root / "middle.cjs").write_text(source, encoding="utf-8")
                (root / "bound.cjs").write_text("module.exports=1;", encoding="utf-8")
                (root / "hidden.cjs").write_text("console.log('GRAPH_SOURCE_EXECUTED');", encoding="utf-8")
                for folder, content in (
                    ("alternate/fixture", "console.log('GRAPH_SOURCE_EXECUTED');"),
                    ("node_modules/fixture", "console.log('DECOY_SOURCE_EXECUTED');"),
                ):
                    target = root / folder
                    target.mkdir(parents=True)
                    (target / "index.js").write_text(content, encoding="utf-8")
                completed = subprocess.run(
                    [shutil.which("node"), str(root / "main.cjs")], cwd=root,
                    capture_output=True, text=True, check=True, timeout=15,
                )
                self.assertIn("GRAPH_SOURCE_EXECUTED", completed.stdout)
                self.assertNotIn("DECOY_SOURCE_EXECUTED", completed.stdout)
                with self.assertRaises(SOURCE.RuntimeSourceContractError):
                    SOURCE.import_specifiers(source)


    def test_module_scalar_metadata_cannot_be_an_assignment_target(self) -> None:
        for member in ("filename", "id", "path", "loaded"):
            for access in (f"module.{member}", f"module['{member}']", f"module[`{member}`]", f"((module)).{member}"):
                for mutation in (
                    f"{access}='./alternate/base.cjs';",
                    f"({access})='./alternate/base.cjs';",
                    f"{access} += './alternate/base.cjs';",
                    f"{access} ||= './alternate/base.cjs';",
                    f"[{access}, ignored]=values;",
                    f"({{x: {access}, y: ignored}}=value);",
                    f"for ({access} of values) {{}}",
                    f"for ([{access}] of values) {{}}",
                    f"delete ({access});",
                    f"++({access});",
                    f"({access})--;",
                ):
                    with self.subTest(mutation=mutation), self.assertRaises(SOURCE.RuntimeSourceContractError):
                        SOURCE.import_specifiers(mutation + "require('./payload.cjs');")

    def test_module_metadata_read_positions_do_not_become_mutations(self) -> None:
        for source in (
            "const filename=module.filename; require('./payload.cjs');",
            "const same=module.filename === 'file'; const next=module.id != 'x';",
            "cache[module.filename]=1;",
            "read(module.filename).value=1;",
            "[value=module.filename]=values;",
            "({[module.filename]: value}=object);",
            "for(let i=0; module.id in object; ++i){}",
        ):
            with self.subTest(source=source):
                SOURCE.import_specifiers(source)

    @unittest.skipUnless(shutil.which("node"), "Node is required for execution witnesses")
    def test_real_node_filename_reassignment_redirects_literal_require(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root / "alternate").mkdir()
            (root / "payload.cjs").write_text("console.log('DECOY');", encoding="utf-8")
            (root / "alternate/payload.cjs").write_text("console.log('REDIRECTED_SOURCE');", encoding="utf-8")
            source="module.filename=__dirname+'/alternate/base.cjs';require('./payload.cjs');"
            (root / "main.cjs").write_text(source, encoding="utf-8")
            result=subprocess.run([shutil.which("node"), str(root / "main.cjs")], cwd=root,
                capture_output=True, text=True, timeout=15, check=True)
            self.assertEqual(result.stdout.strip(), "REDIRECTED_SOURCE")
            with self.assertRaises(SOURCE.RuntimeSourceContractError):
                SOURCE.import_specifiers(source)
