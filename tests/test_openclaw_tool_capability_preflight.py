from __future__ import annotations

import json
import subprocess
import sys
import unittest

from agentic_os.migrations import repository_root


SCRIPT = repository_root() / "scripts/openclaw-tool-capability-preflight.py"


VALID_CATALOG = {
    "tools": [
        {
            "name": "subagents.allowLease.acquire",
            "inputSchema": {
                "properties": {
                    "client_lease_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "run_id": {"type": "string"},
                    "phase": {"type": "string"},
                    "transition_id": {"type": "string"},
                    "agent_id": {"type": "string"},
                    "requester_agent_id": {"type": "string"},
                    "ttl_ms": {"type": "integer"},
                }
            },
        },
        {
            "name": "subagents.allowLease.status",
            "inputSchema": {"properties": {}},
        },
        {
            "name": "subagents.allowLease.release",
            "inputSchema": {
                "properties": {
                    "client_lease_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "run_id": {"type": "string"},
                    "phase": {"type": "string"},
                    "transition_id": {"type": "string"},
                    "agent_id": {"type": "string"},
                    "requester_agent_id": {"type": "string"},
                    "gateway_lease_id": {"type": "string"},
                }
            },
        },
        {
            "name": "sessions_spawn",
            "inputSchema": {
                "properties": {
                    "client_request_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "metadata": {"type": "object"},
                }
            },
        },
        {"name": "sessions_list", "inputSchema": {"properties": {}}},
        {
            "name": "sessions_status",
            "inputSchema": {"properties": {"session_key": {"type": "string"}}},
        },
        {
            "name": "sessions_history",
            "inputSchema": {
                "properties": {
                    "sessionKey": {"type": "string"},
                    "limit": {"type": "integer"},
                    "includeTools": {"type": "boolean"},
                }
            },
        },
    ]
}


class OpenClawToolCapabilityPreflightTests(unittest.TestCase):
    def test_documented_preflight_path_exists(self) -> None:
        self.assertTrue(SCRIPT.exists())

    def test_preflight_accepts_required_session_tool_catalog(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--catalog-json",
                json.dumps(VALID_CATALOG),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"status": "pass"})

    def test_preflight_rejects_session_only_catalog_without_allow_lease_tools(
        self,
    ) -> None:
        catalog = {
            "tools": [
                tool
                for tool in VALID_CATALOG["tools"]
                if not tool["name"].startswith("subagents.allowLease.")
            ]
        }
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--catalog-json",
                json.dumps(catalog),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("subagents.allowLease.acquire", payload["error"])

    def test_preflight_rejects_missing_required_parameter(self) -> None:
        catalog = json.loads(json.dumps(VALID_CATALOG))
        spawn_tool = next(
            tool for tool in catalog["tools"] if tool["name"] == "sessions_spawn"
        )
        del spawn_tool["inputSchema"]["properties"]["metadata"]
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--catalog-json",
                json.dumps(catalog),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("metadata", payload["error"])


if __name__ == "__main__":
    unittest.main()
