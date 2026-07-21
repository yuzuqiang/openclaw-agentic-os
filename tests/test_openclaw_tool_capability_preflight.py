from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agentic_os.migrations import repository_root


SCRIPT = repository_root() / "scripts/openclaw-tool-capability-preflight.py"


def load_preflight_module():
    spec = importlib.util.spec_from_file_location("openclaw_tool_preflight", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load preflight script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def test_preflight_reports_all_live_contract_gaps(self) -> None:
        catalog = {
            "tools": [
                {
                    "name": "subagents.allowLease.acquire",
                    "parameters": ["agentId", "requesterAgentId", "ttlMs"],
                },
                {"name": "subagents.allowLease.status", "parameters": ["requesterAgentId"]},
                {"name": "subagents.allowLease.release", "parameters": ["leaseId"]},
                {
                    "name": "sessions_spawn",
                    "parameters": ["task", "taskName", "agentId", "runtime"],
                },
                {"name": "sessions_list", "parameters": []},
                {"name": "session_status", "parameters": ["sessionKey"]},
                {
                    "name": "sessions_history",
                    "parameters": ["sessionKey", "limit", "includeTools"],
                },
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
        self.assertIn("client_lease_id", payload["error"])
        self.assertIn("idempotency_key", payload["error"])
        self.assertIn("sessions_status", payload["error"])
        self.assertIn("metadata", payload["error"])

    def test_live_installed_openclaw_catalog_is_sanitized_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            install = tempfile.TemporaryDirectory()
            self.addCleanup(install.cleanup)
            install_root = install.name
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "tool-display-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "sessions_spawn:{detailKeys:[`label`,`task`,`agentId`]},"
                    "sessions_history:{detailKeys:[`sessionKey`,`limit`,`includeTools`]},"
                    "session_status:{detailKeys:[`sessionKey`,`model`]},"
                    "sessions_list:{detailKeys:[`limit`]}"
                )
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(params){\n"
                    " const schema = {\n"
                    "  task: Type.String(),\n"
                    "  taskName: Type.Optional(Type.String()),\n"
                    "  agentId: Type.Optional(Type.String()),\n"
                    "  runtime: optionalStringEnum([\"subagent\"]),\n"
                    " };\n"
                    " return Type.Object(schema);\n"
                    "}\n"
                    "function resolveAcpUnavailableMessage(opts){}\n"
                    "name: \"sessions_spawn\""
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => { params?.requesterAgentId },'
                    '"subagents.allowLease.acquire": ({ params }) => { params?.agentId; params?.requesterAgentId; params?.ttlMs },'
                    '"subagents.allowLease.release": ({ params }) => { params?.leaseId },'
                )
            with open(os.path.join(dist, "core-descriptors-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    'name: "subagents.allowLease.status", name: "subagents.allowLease.acquire", '
                    'name: "subagents.allowLease.release"'
                )
            evidence = os.path.join(directory, "evidence.json")
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--live-installed-openclaw",
                    "--json",
                    "--write-evidence",
                    evidence,
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["catalog"]["openclaw_version"], "2026.test")
            self.assertEqual(payload["catalog"]["install_root_basename"], os.path.basename(install_root))
            self.assertIn("client_lease_id", payload["error"])
            self.assertIn("sessions_history", payload["error"])
            spawn_tool = next(
                tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
            )
            self.assertNotIn("label", spawn_tool["parameters"])
            source_paths = [item["path"] for item in payload["catalog"]["sources"]]
            self.assertTrue(all(not path.startswith("/") for path in source_paths))
            with open(evidence, encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.read()), payload)

    def test_live_installed_openclaw_missing_runtime_writes_failure_evidence(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as directory:
            evidence = os.path.join(directory, "missing-runtime.json")
            output = io.StringIO()
            with mock.patch.object(
                module,
                "live_installed_openclaw_catalog",
                side_effect=module.AdapterContractError("runtime missing"),
            ), contextlib.redirect_stdout(output):
                status = module.main(
                    [
                        "--live-installed-openclaw",
                        "--json",
                        "--write-evidence",
                        evidence,
                    ]
                )

            self.assertEqual(status, 1)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload, {"error": "runtime missing", "status": "fail"})
            with open(evidence, encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.read()), payload)

    def test_live_installed_openclaw_catalog_rejects_display_only_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "tool-display-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "sessions_spawn:{detailKeys:[`client_request_id`,`idempotency_key`,`metadata`]},"
                    "sessions_history:{detailKeys:[`sessionKey`,`limit`,`includeTools`]}"
                )
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write('name: "sessions_spawn", name: "sessions_history"')

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--live-installed-openclaw",
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("sessions_spawn", payload["error"])
        self.assertIn("client_request_id", payload["error"])


if __name__ == "__main__":
    unittest.main()
