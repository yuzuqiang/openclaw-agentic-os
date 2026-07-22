from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "openclaw-real-gateway-contract-probe.py"
SPEC = importlib.util.spec_from_file_location("real_gateway_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real Gateway probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RealGatewayProbeTests(unittest.TestCase):
    def test_rejects_raw_session_identity(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw field"):
            MODULE._walk_evidence({"child_session_key": "agent:worker:subagent:raw"})

    def test_rejects_local_absolute_path_value(self) -> None:
        with self.assertRaisesRegex(MODULE.ProbeError, "forbidden raw value"):
            MODULE._walk_evidence({"error": "/Users/example/private"})

    def test_candidate_validation_requires_clean_exact_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"openclaw"}\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ProbeError, "real Gateway E2E"):
                MODULE.validate_candidate_root(root)


if __name__ == "__main__":
    unittest.main()
