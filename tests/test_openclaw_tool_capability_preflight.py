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


ACTIVE_TOOL_IDS = [
    "subagents.allowLease.acquire",
    "subagents.allowLease.status",
    "subagents.allowLease.release",
    "sessions_spawn",
    "sessions_list",
    "sessions_history",
    "sessions_status",
]


def active_tool_entry(tool_id):
    source = next((tool for tool in VALID_CATALOG["tools"] if tool["name"] == tool_id), {})
    entry = {"id": tool_id, "label": tool_id}
    if "inputSchema" in source:
        entry["inputSchema"] = json.loads(json.dumps(source["inputSchema"]))
    return entry


def write_contract_candidate_dist(install_root):
    dist = os.path.join(install_root, "dist")
    os.makedirs(dist, exist_ok=True)
    with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
        json.dump({"name": "openclaw", "version": "2026.candidate"}, handle)
    with open(os.path.join(dist, "openclaw-tools-candidate.js"), "w", encoding="utf-8") as handle:
        handle.write(
            "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
            "function createSessionsListToolSchema(){return Type.Object({});}\n"
            "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
            "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
            'name: "sessions_spawn", name: "sessions_list", '
            'name: "sessions_history", name: "sessions_status"'
        )
    with open(os.path.join(dist, "server-methods-candidate.js"), "w", encoding="utf-8") as handle:
        handle.write(
            '"subagents.allowLease.status": ({ params }) => {},'
            '"subagents.allowLease.acquire": ({ params }) => { '
            "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
            "params?.phase; params?.transition_id; params?.agent_id; "
            "params?.requester_agent_id; params?.ttl_ms },"
            '"subagents.allowLease.release": ({ params }) => { '
            "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
            "params?.phase; params?.transition_id; params?.agent_id; "
            "params?.requester_agent_id; params?.gateway_lease_id },"
        )


def add_fake_openclaw_to_env(
    env,
    directory,
    *,
    active_tool_ids=None,
    active_tool_entries=None,
):
    bin_dir = os.path.join(directory, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    executable = os.path.join(bin_dir, "openclaw")
    entries = active_tool_entries
    if entries is None:
        entries = [active_tool_entry(tool_id) for tool_id in (active_tool_ids or ACTIVE_TOOL_IDS)]
    catalog = {"groups": [{"id": "unit", "tools": entries}]}
    with open(executable, "w", encoding="utf-8") as handle:
        handle.write(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import sys\n"
            "if sys.argv[1:4] == ['gateway', 'call', 'tools.catalog']:\n"
            f"    print(json.dumps({catalog!r}, sort_keys=True))\n"
            "    raise SystemExit(0)\n"
            "print(json.dumps({'ok': False, 'error': 'unexpected fake openclaw call'}))\n"
            "raise SystemExit(1)\n"
        )
    os.chmod(executable, 0o755)
    env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return executable


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

    def test_active_tool_entry_rejects_conflicting_schema_forms(self) -> None:
        module = load_preflight_module()
        entry = {
            "parameters": {
                "properties": {
                    "client_request_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "metadata": {"type": "object"},
                }
            },
            "inputSchema": {
                "properties": {
                    "client_request_id": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                }
            },
        }

        with self.assertRaisesRegex(module.AdapterContractError, "conflicting schema forms"):
            module._active_entry_parameters(entry)

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
            add_fake_openclaw_to_env(env, install_root)
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

    def test_isolated_candidate_openclaw_catalog_passes_and_records_target(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--isolated-candidate-openclaw",
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["catalog"]["runtime_target"], "isolated_candidate")
        self.assertEqual(
            payload["catalog"]["required_canonical_session_status_method"],
            "sessions_status",
        )
        status_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_status"
        )
        self.assertEqual(status_tool["parameters"], ["session_key"])

    def test_isolated_candidate_openclaw_requires_explicit_install_root(self) -> None:
        env = dict(os.environ)
        env.pop("OPENCLAW_INSTALL_ROOT", None)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--isolated-candidate-openclaw",
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
        self.assertIn("OPENCLAW_INSTALL_ROOT", payload["error"])

    def test_installed_openclaw_negative_baseline_fails_for_2026_7_1(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package_root = os.path.join(directory, "openclaw")
            dist = os.path.join(package_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(package_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.7.1"}, handle)
            with open(os.path.join(dist, "openclaw-tools-baseline.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", name: "sessions_history"'
                )
            with open(os.path.join(dist, "server-methods-baseline.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )
            env = dict(os.environ)
            env.pop("OPENCLAW_INSTALL_ROOT", None)
            add_fake_openclaw_to_env(
                env,
                package_root,
                active_tool_ids=[
                    tool_id for tool_id in ACTIVE_TOOL_IDS if tool_id != "sessions_status"
                ],
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--installed-openclaw-negative-baseline",
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
        self.assertEqual(
            payload["catalog"]["runtime_target"],
            "installed_openclaw_negative_baseline",
        )
        self.assertEqual(payload["catalog"]["openclaw_version"], "2026.7.1")
        self.assertIn("runtime tool catalog is missing sessions_status", payload["error"])

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

    def test_live_tools_catalog_failure_evidence_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write(
                    "#!/usr/bin/env python3\n"
                    "import json\n"
                    "print(json.dumps({'status':'error','error':'secret-runtime-path-token'}))\n"
                    "raise SystemExit(1)\n"
                )
            os.chmod(executable, 0o755)
            evidence = os.path.join(install_root, "evidence.json")
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
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
            with open(evidence, encoding="utf-8") as handle:
                evidence_payload = json.loads(handle.read())

            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            serialized = json.dumps(payload, sort_keys=True)
            self.assertIn("active OpenClaw tool catalog failed", payload["error"])
            self.assertIn("payload_sha256", payload["error"])
            self.assertNotIn("secret-runtime-path-token", serialized)
            self.assertEqual(evidence_payload, payload)

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
            add_fake_openclaw_to_env(env, install_root)
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

    def test_live_catalog_rejects_active_schema_missing_required_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )
            active_spawn = active_tool_entry("sessions_spawn")
            del active_spawn["inputSchema"]["properties"]["metadata"]

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(
                env,
                install_root,
                active_tool_entries=[
                    active_spawn,
                    *[
                        active_tool_entry(tool_id)
                        for tool_id in ACTIVE_TOOL_IDS
                        if tool_id != "sessions_spawn"
                    ],
                ],
            )
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
        self.assertIn("metadata", payload["error"])
        spawn_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
        )
        self.assertNotIn("metadata", spawn_tool["parameters"])
        self.assertNotIn("metadata", spawn_tool["active_parameters"])

    def test_live_installed_openclaw_requires_matching_active_executable_root(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as install_root:
            os.makedirs(os.path.join(install_root, "dist"))
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, directory)
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(module.AdapterContractError) as raised:
                    module.live_installed_openclaw_catalog()

        self.assertIn("does not match", str(raised.exception))

    def test_live_active_catalog_ignores_display_labels_as_method_identity(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(
                env,
                install_root,
                active_tool_entries=[
                    {"id": "legacy_sessions_spawn", "label": "sessions_spawn"},
                    *[
                        {"id": tool_id, "label": tool_id}
                        for tool_id in ACTIVE_TOOL_IDS
                        if tool_id != "sessions_spawn"
                    ],
                ],
            )
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
        self.assertIn("sessions_spawn", payload["error"])
        self.assertNotIn(
            "sessions_spawn", {tool["name"] for tool in payload["catalog"]["tools"]}
        )

    def test_live_schema_parser_preserves_quoted_typebox_property_names(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({\"client_request_id\": Type.String(), \"idempotency_key\": Type.String(), \"metadata\": Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({\"sessionKey\": Type.String(), \"limit\": Type.Number(), \"includeTools\": Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({\"session_key\": Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        spawn_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
        )
        self.assertEqual(
            spawn_tool["parameters"],
            ["client_request_id", "idempotency_key", "metadata"],
        )

    def test_live_schema_parser_rejects_nested_non_input_parameter_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){\n"
                    " const schema = {\n"
                    "  task: Type.String(),\n"
                    "  output: Type.Object({\n"
                    "   client_request_id: Type.String(),\n"
                    "   idempotency_key: Type.String(),\n"
                    "   metadata: Type.Object({run_id: Type.String()}),\n"
                    "  }),\n"
                    " };\n"
                    " return Type.Object(schema);\n"
                    "}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        spawn_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
        )
        self.assertNotIn("client_request_id", spawn_tool["parameters"])
        self.assertEqual(spawn_tool["parameters"], [])
        self.assertIn("client_request_id", spawn_tool["active_parameters"])

    def test_live_schema_parser_does_not_union_across_tool_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-current.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String()});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "openclaw-tools-stale.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        spawn_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
        )
        self.assertEqual(spawn_tool["parameters"], [])
        source_paths = {item["path"] for item in payload["catalog"]["sources"]}
        self.assertIn("dist/openclaw-tools-current.js", source_paths)
        self.assertIn("dist/openclaw-tools-stale.js", source_paths)

    def test_live_schema_parser_ignores_commented_or_stringified_schema_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "// function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "const stale = `function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}`;\n"
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String()});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        spawn_tool = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_spawn"
        )
        self.assertEqual(spawn_tool["parameters"], ["client_request_id"])
        self.assertIn("metadata", payload["error"])

    def test_live_schema_params_require_exposed_tool_name(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_list", name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        self.assertNotIn(
            "sessions_spawn", {tool["name"] for tool in payload["catalog"]["tools"]}
        )

    def test_live_catalog_requires_active_registered_tool_name(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(
                env,
                install_root,
                active_tool_ids=[
                    tool_id for tool_id in ACTIVE_TOOL_IDS if tool_id != "sessions_spawn"
                ],
            )
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
        self.assertNotIn(
            "sessions_spawn", {tool["name"] for tool in payload["catalog"]["tools"]}
        )

    def test_live_gateway_param_parser_does_not_union_across_handler_files(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-current.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id },"
                )
            with open(os.path.join(dist, "server-methods-stale.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        acquire_tool = next(
            tool
            for tool in payload["catalog"]["tools"]
            if tool["name"] == "subagents.allowLease.acquire"
        )
        self.assertEqual(acquire_tool["parameters"], [])
        source_paths = {item["path"] for item in payload["catalog"]["sources"]}
        self.assertIn("dist/server-methods-current.js", source_paths)
        self.assertIn("dist/server-methods-stale.js", source_paths)

    def test_live_gateway_param_parser_ignores_comments_and_strings(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsListToolSchema(){return Type.Object({});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_list", '
                    'name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "// params?.client_lease_id params?.idempotency_key params?.run_id\n"
                    "const dead = 'params?.phase params?.transition_id params?.agent_id';"
                    "const template = `params?.requester_agent_id params?.ttl_ms`;"
                    "return params?.requesterAgentId },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "/* params?.client_lease_id params?.idempotency_key params?.run_id "
                    "params?.phase params?.transition_id params?.agent_id "
                    "params?.requester_agent_id params?.gateway_lease_id */"
                    "return params?.leaseId },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        acquire_tool = next(
            tool
            for tool in payload["catalog"]["tools"]
            if tool["name"] == "subagents.allowLease.acquire"
        )
        self.assertEqual(acquire_tool["parameters"], [])
        self.assertIn("requester_agent_id", acquire_tool["active_parameters"])
        self.assertIn("client_lease_id", payload["error"])

    def test_live_declared_zero_param_tools_ignore_comments_and_dead_strings(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    "// name: \"sessions_list\"\n"
                    "const stale = 'name: \"sessions_list\"';\n"
                    'name: "sessions_spawn", name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '// "subagents.allowLease.status": ({ params }) => {},\n'
                    'const stale = "\\"subagents.allowLease.status\\": ({ params }) => {}";\n'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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
        self.assertIn("subagents.allowLease.status", payload["error"])
        self.assertIn("sessions_list", payload["error"])
        catalog_names = {tool["name"] for tool in payload["catalog"]["tools"]}
        self.assertNotIn("subagents.allowLease.status", catalog_names)
        self.assertNotIn("sessions_list", catalog_names)

    def test_live_declared_tool_scanner_accepts_quoted_name_properties(self) -> None:
        module = load_preflight_module()

        names = module._scan_js_declared_tool_names(
            '{"name": "sessions_spawn"}, {"id": "sessions_list"}'
        )

        self.assertIn("sessions_spawn", names)
        self.assertIn("sessions_list", names)

    def test_live_catalog_hashes_sources_for_zero_parameter_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            dist = os.path.join(install_root, "dist")
            os.makedirs(dist)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            with open(os.path.join(dist, "openclaw-tools-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    "function createSessionsSpawnToolSchema(){return Type.Object({client_request_id: Type.String(), idempotency_key: Type.String(), metadata: Type.Object({})});}\n"
                    "function createSessionsHistoryToolSchema(){return Type.Object({sessionKey: Type.String(), limit: Type.Number(), includeTools: Type.Boolean()});}\n"
                    "function createSessionsStatusToolSchema(){return Type.Object({session_key: Type.String()});}\n"
                    'name: "sessions_spawn", name: "sessions_history", name: "sessions_status"'
                )
            with open(os.path.join(dist, "core-descriptors-test.js"), "w", encoding="utf-8") as handle:
                handle.write('name: "sessions_list"')
            with open(os.path.join(dist, "server-methods-test.js"), "w", encoding="utf-8") as handle:
                handle.write(
                    '"subagents.allowLease.status": ({ params }) => {},'
                    '"subagents.allowLease.acquire": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.ttl_ms },"
                    '"subagents.allowLease.release": ({ params }) => { '
                    "params?.client_lease_id; params?.idempotency_key; params?.run_id; "
                    "params?.phase; params?.transition_id; params?.agent_id; "
                    "params?.requester_agent_id; params?.gateway_lease_id },"
                )

            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(env, install_root)
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

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "pass")
        source_paths = {item["path"] for item in payload["catalog"]["sources"]}
        self.assertIn("dist/core-descriptors-test.js", source_paths)
        sessions_list = next(
            tool for tool in payload["catalog"]["tools"] if tool["name"] == "sessions_list"
        )
        self.assertEqual(sessions_list["parameters"], [])


if __name__ == "__main__":
    unittest.main()
