from __future__ import annotations

import contextlib
import hashlib
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
                    "release_idempotency_key": {"type": "string"},
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
            "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
            "params?.phase; params?.transition_id; params?.agent_id; "
            "params?.requester_agent_id; params?.gateway_lease_id },"
        )


def add_fake_openclaw_to_env(
    env,
    directory,
    *,
    active_tool_ids=None,
    active_tool_entries=None,
    catalog_override=None,
):
    bin_dir = os.path.join(directory, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    executable = os.path.join(bin_dir, "openclaw")
    if catalog_override is None:
        entries = active_tool_entries
        if entries is None:
            entries = [active_tool_entry(tool_id) for tool_id in (active_tool_ids or ACTIVE_TOOL_IDS)]
        catalog = {"groups": [{"id": "unit", "tools": entries}]}
    else:
        catalog = catalog_override
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


def add_env_sensitive_fake_openclaw_to_env(env, directory):
    bin_dir = os.path.join(directory, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    executable = os.path.join(bin_dir, "openclaw")
    baseline_entries = [
        active_tool_entry(tool_id)
        for tool_id in ACTIVE_TOOL_IDS
        if tool_id != "sessions_status"
    ]
    candidate_entries = [active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS]
    with open(executable, "w", encoding="utf-8") as handle:
        handle.write(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "if sys.argv[1:4] == ['gateway', 'call', 'tools.catalog']:\n"
            "    entries = "
            f"{candidate_entries!r} if os.environ.get('OPENCLAW_INSTALL_ROOT') else {baseline_entries!r}\n"
            "    print(json.dumps({'groups': [{'id': 'unit', 'tools': entries}]}, sort_keys=True))\n"
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
        self.assertIn("release_idempotency_key", payload["error"])
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

    def test_isolated_candidate_openclaw_rejects_invalid_override_without_path_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid_runtime = os.path.join(directory, "valid-openclaw")
            invalid_runtime = os.path.join(directory, "invalid-openclaw")
            os.makedirs(invalid_runtime)
            write_contract_candidate_dist(valid_runtime)
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = invalid_runtime
            add_fake_openclaw_to_env(env, valid_runtime)
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
        self.assertIn("valid OpenClaw runtime bundle", payload["error"])
        self.assertEqual(payload["catalog"]["runtime_target"], "isolated_candidate")
        self.assertIn("install_root_resolution_error", payload["catalog"])
        self.assertEqual(
            payload["catalog"]["catalog_capture"]["status"],
            "catalog_unavailable_before_contract_validation",
        )

    def test_isolated_candidate_openclaw_rejects_non_openclaw_package_name(self) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "not-openclaw", "version": "2026.candidate"}, handle)
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

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("valid OpenClaw runtime bundle", payload["error"])
        self.assertEqual(payload["catalog"]["runtime_target"], "isolated_candidate")
        self.assertIn("install_root_resolution_error", payload["catalog"])
        self.assertEqual(
            payload["catalog"]["catalog_capture"]["status"],
            "catalog_unavailable_before_contract_validation",
        )

    def test_committed_isolated_runtime_evidence_is_target_bound(self) -> None:
        evidence_dir = repository_root() / "docs" / "runtime-evidence"
        isolated_files = sorted(evidence_dir.glob("*isolated*.json"))
        self.assertTrue(isolated_files)
        for path in isolated_files:
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                catalog = payload.get("catalog")
                if catalog is None:
                    catalog = payload.get("preflight", {}).get("catalog")
                self.assertIsInstance(catalog, dict)
                self.assertEqual(catalog.get("runtime_target"), "isolated_candidate")
                if payload.get("status") == "pass":
                    release_tool = next(
                        tool
                        for tool in catalog.get("tools", [])
                        if tool.get("name") == "subagents.allowLease.release"
                    )
                    self.assertIn(
                        "release_idempotency_key",
                        release_tool.get("parameters", []),
                    )
                elif path.name == "phase233549-round2-isolated-candidate-preflight.json":
                    self.assertIn("release_idempotency_key", payload.get("error", ""))
                if path.name.endswith("-live-probe.json") and payload.get("status") == "pass":
                    history = payload.get("session_read_structured_evidence", {}).get(
                        "sessions_history",
                        {},
                    )
                    self.assertGreater(history.get("history_items_identity_checked", 0), 0)

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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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

    def test_installed_openclaw_negative_baseline_scrubs_candidate_override_for_catalog(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_root = os.path.join(directory, "openclaw")
            candidate_root = os.path.join(directory, "candidate-openclaw")
            write_contract_candidate_dist(baseline_root)
            write_contract_candidate_dist(candidate_root)
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = candidate_root
            add_env_sensitive_fake_openclaw_to_env(env, baseline_root)
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
            self.assertEqual(payload["error"], "runtime missing")
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
            self.assertEqual(
                payload["catalog"]["catalog_capture"]["status"],
                "catalog_unavailable_before_contract_validation",
            )
            with open(evidence, encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.read()), payload)

    def test_live_runtime_failure_evidence_records_unreadable_executable_digest(
        self,
    ) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            os.makedirs(os.path.join(install_root, "dist"))
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.test"}, handle)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 1\n")
            evidence = os.path.join(install_root, "evidence.json")
            original_file_digest = module._file_digest

            def file_digest_or_permission_error(path):
                if path == module.Path(executable).resolve():
                    raise PermissionError("execute-only launcher")
                return original_file_digest(path)

            output = io.StringIO()
            with mock.patch.object(
                module,
                "live_installed_openclaw_catalog",
                side_effect=module.AdapterContractError("catalog unavailable"),
            ), mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_file_digest",
                side_effect=file_digest_or_permission_error,
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
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
            self.assertEqual(payload["catalog"]["openclaw_version"], "2026.test")
            self.assertEqual(
                payload["catalog"]["active_executable_sha256_error"],
                "PermissionError",
            )
            self.assertNotIn("active_executable_sha256", payload["catalog"])
            self.assertIn("preflight_evidence_binding", payload)
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
            self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
            self.assertEqual(payload["catalog"]["openclaw_package_name"], "openclaw")
            self.assertEqual(payload["catalog"]["openclaw_version"], "2026.test")
            self.assertEqual(
                payload["catalog"]["catalog_capture"]["status"],
                "catalog_unavailable_before_contract_validation",
            )
            self.assertIn("active_executable_sha256", payload["catalog"])
            self.assertIn("install_root_path_sha256", payload["catalog"])
            self.assertNotIn("secret-runtime-path-token", serialized)
            self.assertNotIn(install_root, serialized)
            self.assertEqual(evidence_payload, payload)

    def test_live_tools_catalog_failure_uses_prelaunch_runtime_identity(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as directory:
            initial_root = os.path.join(directory, "openclaw")
            os.makedirs(os.path.join(initial_root, "bin"), exist_ok=True)
            with open(os.path.join(initial_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"name": "openclaw", "version": "2026.initial"}, handle)
            initial_executable = os.path.join(initial_root, "bin", "openclaw")
            with open(initial_executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(1)\n")
            os.chmod(initial_executable, 0o755)
            with open(initial_executable, "rb") as handle:
                expected_initial_executable_sha256 = hashlib.sha256(handle.read()).hexdigest()

            def fail_catalog(*_args, **kwargs):
                raise module.RuntimeEvidenceError(
                    "catalog failed",
                    catalog=kwargs.get("failure_catalog"),
                    catalog_failure={"runtime_provenance_preserved": True},
                )

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(initial_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(initial_executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                side_effect=fail_catalog,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(catalog["openclaw_version"], "2026.initial")
        self.assertEqual(catalog["active_executable_sha256"], expected_initial_executable_sha256)

    def test_live_tools_catalog_failure_uses_one_executable_snapshot(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(1)\n")
            executable_path = module.Path(executable).resolve()
            original_file_digest = module._file_digest
            expected_executable_sha256 = original_file_digest(executable_path)
            executable_digest_reads = 0

            def counting_file_digest(path):
                nonlocal executable_digest_reads
                if path == executable_path:
                    executable_digest_reads += 1
                return original_file_digest(path)

            def fail_catalog(*_args, **kwargs):
                raise module.RuntimeEvidenceError(
                    "catalog failed",
                    catalog=kwargs.get("failure_catalog"),
                    catalog_failure={"runtime_provenance_preserved": True},
                )

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=executable_path,
            ), mock.patch.object(
                module,
                "_file_digest",
                side_effect=counting_file_digest,
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                side_effect=fail_catalog,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(executable_digest_reads, 1)
        self.assertEqual(catalog["active_executable_sha256"], expected_executable_sha256)

    def test_live_positive_evidence_rejects_unreadable_executable_digest(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            original_file_digest = module._file_digest

            def file_digest_or_permission_error(path):
                if path == module.Path(executable).resolve():
                    raise PermissionError("execute-only launcher")
                return original_file_digest(path)

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_file_digest",
                side_effect=file_digest_or_permission_error,
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
            ) as run_catalog, self.assertRaises(module.AdapterContractError) as raised:
                module.live_installed_openclaw_catalog()

        self.assertIn("active OpenClaw executable could not be hashed", str(raised.exception))
        self.assertFalse(run_catalog.called)

    def test_successful_catalog_rejects_runtime_identity_change(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            with open(executable, "rb") as handle:
                expected_initial_executable_sha256 = hashlib.sha256(handle.read()).hexdigest()

            def replace_launcher_after_catalog(*_args, **_kwargs):
                with open(executable, "w", encoding="utf-8") as handle:
                    handle.write("#!/usr/bin/env python3\nraise SystemExit(42)\n")
                return {"groups": [{"id": "unit", "tools": [active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS]}]}

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                side_effect=replace_launcher_after_catalog,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(catalog["active_executable_sha256"], expected_initial_executable_sha256)
        self.assertEqual(
            catalog["active_catalog"]["status"],
            "runtime_identity_changed_after_catalog_capture",
        )
        self.assertEqual(
            catalog["active_catalog"]["validation_stage"],
            "runtime_identity_binding",
        )

    def test_successful_catalog_rejects_runtime_identity_change_after_source_scan(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            with open(executable, "rb") as handle:
                expected_initial_executable_sha256 = hashlib.sha256(handle.read()).hexdigest()
            original_extract_model_tool_schemas = module._extract_model_tool_schemas

            def replace_launcher_during_source_scan(root):
                with open(executable, "w", encoding="utf-8") as handle:
                    handle.write("#!/usr/bin/env python3\nraise SystemExit(43)\n")
                return original_extract_model_tool_schemas(root)

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                return_value={
                    "groups": [
                        {
                            "id": "unit",
                            "tools": [
                                active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS
                            ],
                        }
                    ]
                },
            ), mock.patch.object(
                module,
                "_extract_model_tool_schemas",
                side_effect=replace_launcher_during_source_scan,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(catalog["active_executable_sha256"], expected_initial_executable_sha256)
        self.assertEqual(
            catalog["active_catalog"]["status"],
            "runtime_identity_changed_after_catalog_capture",
        )
        self.assertEqual(
            catalog["active_catalog"]["validation_stage"],
            "runtime_identity_binding",
        )

    def test_successful_catalog_rejects_runtime_source_change_after_capture(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            os.chmod(executable, 0o755)
            source_path = os.path.join(install_root, "dist", "openclaw-tools-candidate.js")

            def replace_source_after_catalog(*_args, **_kwargs):
                with open(source_path, "a", encoding="utf-8") as handle:
                    handle.write("\n// same-version reinstall after tools.catalog\n")
                return {
                    "groups": [
                        {
                            "id": "unit",
                            "tools": [
                                active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS
                            ],
                        }
                    ]
                }

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                side_effect=replace_source_after_catalog,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(
            catalog["active_catalog"]["status"],
            "runtime_sources_changed_after_catalog_capture",
        )
        self.assertEqual(
            catalog["active_catalog"]["validation_stage"],
            "runtime_source_binding",
        )
        source_binding = catalog["runtime_source_binding"]
        self.assertIn("dist/openclaw-tools-candidate.js", source_binding["expected_sources"])
        self.assertIn("dist/openclaw-tools-candidate.js", source_binding["observed_sources"])
        self.assertNotEqual(
            source_binding["expected_sources"]["dist/openclaw-tools-candidate.js"],
            source_binding["observed_sources"]["dist/openclaw-tools-candidate.js"],
        )

    def test_successful_catalog_rejects_runtime_source_change_during_final_identity_check(
        self,
    ) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            os.chmod(executable, 0o755)
            source_path = os.path.join(install_root, "dist", "openclaw-tools-candidate.js")

            def replace_source_during_final_identity_check(**_kwargs):
                with open(source_path, "a", encoding="utf-8") as handle:
                    handle.write("\n// same-version reinstall during final identity CAS\n")

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                return_value={
                    "groups": [
                        {
                            "id": "unit",
                            "tools": [
                                active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS
                            ],
                        }
                    ]
                },
            ), mock.patch.object(
                module,
                "_require_runtime_identity_unchanged_after_catalog",
                side_effect=replace_source_during_final_identity_check,
            ), self.assertRaises(module.RuntimeEvidenceError) as raised:
                module.live_installed_openclaw_catalog()

            catalog = raised.exception.catalog

        self.assertIsNotNone(catalog)
        self.assertEqual(
            catalog["active_catalog"]["status"],
            "runtime_sources_changed_after_catalog_capture",
        )
        self.assertEqual(
            catalog["active_catalog"]["validation_stage"],
            "runtime_source_binding",
        )
        source_binding = catalog["runtime_source_binding"]
        self.assertIn("dist/openclaw-tools-candidate.js", source_binding["expected_sources"])
        self.assertIn("dist/openclaw-tools-candidate.js", source_binding["observed_sources"])
        self.assertNotEqual(
            source_binding["expected_sources"]["dist/openclaw-tools-candidate.js"],
            source_binding["observed_sources"]["dist/openclaw-tools-candidate.js"],
        )

    def test_source_scan_oserror_writes_fail_closed_evidence(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            os.chmod(executable, 0o755)
            evidence = os.path.join(install_root, "evidence.json")

            def scan_raises_oserror(_root):
                raise PermissionError("runtime source disappeared")

            output = io.StringIO()
            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_run_gateway_tools_catalog",
                return_value={
                    "groups": [
                        {
                            "id": "unit",
                            "tools": [
                                active_tool_entry(tool_id) for tool_id in ACTIVE_TOOL_IDS
                            ],
                        }
                    ]
                },
            ), mock.patch.object(
                module,
                "_extract_model_tool_schemas",
                side_effect=scan_raises_oserror,
            ), mock.patch.object(
                module,
                "_capture_evidence_binding",
                return_value={"test": "binding"},
            ), mock.patch.object(
                module,
                "_require_same_evidence_binding",
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
            self.assertEqual(payload["status"], "fail")
            self.assertIn(
                "active OpenClaw runtime sources could not be scanned",
                payload["error"],
            )
            self.assertEqual(
                payload["catalog"]["active_catalog"]["status"],
                "runtime_source_scan_failed",
            )
            self.assertEqual(
                payload["catalog"]["active_catalog"]["validation_stage"],
                "runtime_source_binding",
            )
            self.assertEqual(
                payload["catalog"]["active_catalog"]["source_verification_error"],
                "PermissionError",
            )
            self.assertIn(
                "raw_response_sha256",
                payload["catalog"]["active_catalog"],
            )
            with open(evidence, encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.read()), payload)

    def test_identity_snapshot_error_writes_fail_closed_evidence(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            with open(os.path.join(install_root, "package.json"), "w", encoding="utf-8") as handle:
                handle.write("{")
            bin_dir = os.path.join(install_root, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
            evidence = os.path.join(install_root, "evidence.json")
            output = io.StringIO()

            with mock.patch.object(
                module,
                "_resolve_install_root",
                return_value=module.Path(install_root),
            ), mock.patch.object(
                module,
                "_resolve_openclaw_executable",
                return_value=module.Path(executable).resolve(),
            ), mock.patch.object(
                module,
                "_capture_evidence_binding",
                return_value={"test": "binding"},
            ), mock.patch.object(
                module,
                "_require_same_evidence_binding",
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
            self.assertEqual(payload["status"], "fail")
            self.assertIn("runtime identity could not be snapshotted", payload["error"])
            self.assertEqual(
                payload["catalog"]["catalog_capture"]["status"],
                "runtime_identity_snapshot_failed",
            )
            self.assertEqual(
                payload["catalog"]["catalog_capture"]["validation_stage"],
                "runtime_identity_snapshot",
            )
            self.assertEqual(
                payload["catalog"]["catalog_capture"]["identity_verification_error"],
                "JSONDecodeError",
            )
            with open(evidence, encoding="utf-8") as handle:
                self.assertEqual(json.loads(handle.read()), payload)

    def test_successful_catalog_validation_failure_preserves_catalog_provenance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            evidence = os.path.join(install_root, "evidence.json")
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            duplicate_spawn = active_tool_entry("sessions_spawn")
            add_fake_openclaw_to_env(
                env,
                install_root,
                active_tool_entries=[duplicate_spawn, duplicate_spawn],
            )
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

            self.assertEqual(result.returncode, 1, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn("duplicate sessions_spawn", payload["error"])
            self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
            self.assertEqual(
                payload["catalog"]["active_catalog"]["status"],
                "contract_validation_failed",
            )
            self.assertEqual(
                payload["catalog"]["active_catalog"]["validation_stage"],
                "active_tool_parameters",
            )
            self.assertRegex(
                payload["catalog"]["active_catalog"]["raw_response_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertNotIn("catalog_failure", payload)
            self.assertEqual(evidence_payload, payload)

    def test_successful_non_object_catalog_preserves_catalog_provenance(self) -> None:
        catalog = []
        with tempfile.TemporaryDirectory() as install_root:
            write_contract_candidate_dist(install_root)
            evidence = os.path.join(install_root, "evidence.json")
            env = dict(os.environ)
            env["OPENCLAW_INSTALL_ROOT"] = install_root
            add_fake_openclaw_to_env(
                env,
                install_root,
                catalog_override=catalog,
            )
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

        expected_sha = hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        payload = json.loads(result.stdout)
        serialized = json.dumps(payload, sort_keys=True)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("must be a JSON object", payload["error"])
        self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
        self.assertEqual(
            payload["catalog"]["active_catalog"]["status"],
            "contract_validation_failed",
        )
        self.assertEqual(
            payload["catalog"]["active_catalog"]["validation_stage"],
            "active_catalog_shape",
        )
        self.assertEqual(
            payload["catalog"]["active_catalog"]["raw_response_sha256"],
            expected_sha,
        )
        self.assertEqual(payload["catalog"]["active_catalog"]["observed_json_type"], "list")
        self.assertNotIn("catalog_capture", payload["catalog"])
        self.assertNotIn("catalog_unavailable_before_contract_validation", serialized)
        self.assertNotIn("catalog_failure", payload)
        self.assertEqual(evidence_payload, payload)

    def test_successful_catalog_with_no_required_tools_preserves_catalog_provenance(
        self,
    ) -> None:
        cases = {
            "empty_object": {},
            "unrelated_tool": {
                "groups": [
                    {
                        "id": "unit",
                        "tools": [
                            {
                                "id": "unrelated.tool",
                                "inputSchema": {"properties": {"token": {"type": "string"}}},
                            }
                        ],
                    }
                ]
            },
        }
        for name, catalog in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as install_root:
                write_contract_candidate_dist(install_root)
                evidence = os.path.join(install_root, "evidence.json")
                env = dict(os.environ)
                env["OPENCLAW_INSTALL_ROOT"] = install_root
                add_fake_openclaw_to_env(
                    env,
                    install_root,
                    catalog_override=catalog,
                )
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

                expected_sha = hashlib.sha256(
                    json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                payload = json.loads(result.stdout)
                serialized = json.dumps(payload, sort_keys=True)

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("did not expose required tools", payload["error"])
                self.assertEqual(payload["catalog"]["runtime_target"], "live_installed_openclaw")
                self.assertEqual(
                    payload["catalog"]["active_catalog"]["status"],
                    "contract_validation_failed",
                )
                self.assertEqual(
                    payload["catalog"]["active_catalog"]["validation_stage"],
                    "active_tool_parameters",
                )
                self.assertEqual(
                    payload["catalog"]["active_catalog"]["raw_response_sha256"],
                    expected_sha,
                )
                self.assertEqual(
                    payload["catalog"]["active_catalog"]["required_tool_names"],
                    [],
                )
                self.assertIn("active_executable_sha256", payload["catalog"])
                self.assertNotIn("catalog_capture", payload["catalog"])
                self.assertNotIn("catalog_unavailable_before_contract_validation", serialized)
                self.assertNotIn("catalog_failure", payload)
                self.assertEqual(evidence_payload, payload)

    def test_evidence_binding_redacts_inline_catalog_json(self) -> None:
        private_marker = "sk-private-inline-catalog-token"
        catalog = json.loads(json.dumps(VALID_CATALOG))
        catalog["private_runtime_metadata"] = {"token": private_marker}
        catalog_json = json.dumps(catalog, sort_keys=True)
        expected_digest = hashlib.sha256(catalog_json.encode("utf-8")).hexdigest()
        expected_catalog_digest = hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        cases = (
            (
                "separate",
                ["--catalog-json", catalog_json],
                ["--catalog-json", f"<redacted:--catalog-json:sha256:{expected_digest}>"],
            ),
            (
                "equals",
                [f"--catalog-json={catalog_json}"],
                [f"--catalog-json=<redacted:sha256:{expected_digest}>"],
            ),
        )
        for name, catalog_args, expected_items in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                evidence_path = os.path.join(directory, "evidence.json")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        *catalog_args,
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with open(evidence_path, encoding="utf-8") as handle:
                    evidence_payload = json.loads(handle.read())

                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload, evidence_payload)
                argv = payload["preflight_evidence_binding"]["invocation"]["argv"]
                serialized_argv = json.dumps(argv, sort_keys=True)
                for item in expected_items:
                    self.assertIn(item, argv)
                self.assertNotIn(catalog_json, serialized_argv)
                self.assertNotIn(private_marker, serialized_argv)
                serialized_payload = json.dumps(payload, sort_keys=True)
                self.assertEqual(
                    payload["catalog"]["catalog_kind"],
                    "sanitized_caller_tool_catalog",
                )
                self.assertEqual(
                    payload["catalog"]["raw_catalog_sha256"],
                    expected_catalog_digest,
                )
                self.assertEqual(
                    payload["catalog"]["required_tool_names"],
                    sorted(ACTIVE_TOOL_IDS),
                )
                self.assertNotIn(catalog_json, serialized_payload)
                self.assertNotIn(private_marker, serialized_payload)

    def test_write_evidence_sanitizes_catalog_json_file_payload(self) -> None:
        private_marker = "sk-private-file-catalog-token"
        catalog = json.loads(json.dumps(VALID_CATALOG))
        catalog["private_runtime_metadata"] = {
            "token": private_marker,
            "path": "/private/customer/runtime",
        }
        expected_digest = hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            catalog_path = os.path.join(directory, "catalog.json")
            evidence_path = os.path.join(directory, "evidence.json")
            with open(catalog_path, "w", encoding="utf-8") as handle:
                json.dump(catalog, handle, sort_keys=True)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--catalog-json-file",
                    catalog_path,
                    "--json",
                    "--write-evidence",
                    evidence_path,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            with open(evidence_path, encoding="utf-8") as handle:
                evidence_payload = json.loads(handle.read())

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload, evidence_payload)
        serialized_payload = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["catalog"]["catalog_kind"], "sanitized_caller_tool_catalog")
        self.assertEqual(payload["catalog"]["raw_catalog_sha256"], expected_digest)
        self.assertEqual(payload["catalog"]["tool_entry_count"], len(VALID_CATALOG["tools"]))
        self.assertNotIn(private_marker, serialized_payload)
        self.assertNotIn("/private/customer/runtime", serialized_payload)

    def test_write_evidence_sanitizes_mapping_catalog_payloads(self) -> None:
        def mapping_catalog() -> dict[str, dict[str, object]]:
            return {
                tool["name"]: {
                    key: json.loads(json.dumps(value))
                    for key, value in tool.items()
                    if key != "name"
                }
                for tool in VALID_CATALOG["tools"]
            }

        cases = {
            "tools_mapping": {"tools": mapping_catalog()},
            "root_mapping": mapping_catalog(),
        }
        for name, catalog in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                evidence_path = os.path.join(directory, "evidence.json")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--catalog-json",
                        json.dumps(catalog),
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with open(evidence_path, encoding="utf-8") as handle:
                    evidence_payload = json.loads(handle.read())

                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload, evidence_payload)
                self.assertEqual(payload["catalog"]["catalog_kind"], "sanitized_caller_tool_catalog")
                self.assertEqual(payload["catalog"]["tool_entry_count"], len(VALID_CATALOG["tools"]))
                self.assertEqual(
                    payload["catalog"]["required_tool_names"],
                    sorted(ACTIVE_TOOL_IDS),
                )

    def test_write_evidence_uses_mapping_keys_over_value_identity_aliases(self) -> None:
        private_marker = "sk-private-mapping-alias-token"
        preflight = load_preflight_module()

        def mapping_catalog() -> dict[str, dict[str, object]]:
            catalog: dict[str, dict[str, object]] = {}
            for tool in VALID_CATALOG["tools"]:
                entry = {
                    key: json.loads(json.dumps(value))
                    for key, value in tool.items()
                    if key != "name"
                }
                entry["name"] = "sessions_list"
                entry["id"] = "sessions_list"
                entry["method"] = "sessions_list"
                entry["private_runtime_metadata"] = private_marker
                catalog[tool["name"]] = entry
            return catalog

        cases = {
            "tools_mapping": {"tools": mapping_catalog()},
            "root_mapping": mapping_catalog(),
        }
        for name, catalog in cases.items():
            with self.subTest(name=name):
                payload = preflight._sanitize_caller_catalog_for_evidence(catalog)
                self.assertEqual(
                    payload["catalog_kind"],
                    "sanitized_caller_tool_catalog",
                )
                self.assertEqual(
                    payload["raw_catalog_sha256"],
                    hashlib.sha256(
                        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode(
                            "utf-8"
                        )
                    ).hexdigest(),
                )
                self.assertEqual(
                    payload["tool_entry_count"],
                    len(VALID_CATALOG["tools"]),
                )
                self.assertEqual(
                    payload["required_tool_names"],
                    sorted(ACTIVE_TOOL_IDS),
                )
                serialized_payload = json.dumps(payload, sort_keys=True)
                self.assertNotIn(private_marker, serialized_payload)
                self.assertNotIn(json.dumps(catalog), serialized_payload)

    def test_write_evidence_summarizes_method_only_catalog_entries(self) -> None:
        catalog = {
            "tools": [
                {
                    **{
                        key: json.loads(json.dumps(value))
                        for key, value in tool.items()
                        if key != "name"
                    },
                    "method": tool["name"],
                }
                for tool in VALID_CATALOG["tools"]
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = os.path.join(directory, "evidence.json")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--catalog-json",
                    json.dumps(catalog),
                    "--json",
                    "--write-evidence",
                    evidence_path,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            with open(evidence_path, encoding="utf-8") as handle:
                evidence_payload = json.loads(handle.read())

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload, evidence_payload)
        self.assertEqual(payload["catalog"]["catalog_kind"], "sanitized_caller_tool_catalog")
        self.assertEqual(payload["catalog"]["tool_entry_count"], len(VALID_CATALOG["tools"]))
        self.assertEqual(
            payload["catalog"]["required_tool_names"],
            sorted(ACTIVE_TOOL_IDS),
        )

    def test_evidence_binding_sanitizes_path_option_forms(self) -> None:
        preflight = load_preflight_module()
        root = repository_root()
        cases = (
            (
                "catalog_equals",
                "sk-private-customer-catalog-equals.json",
                "sk-private-customer-evidence-separate.json",
            ),
            (
                "write_equals",
                "sk-private-customer-catalog-separate.json",
                "sk-private-customer-evidence-equals.json",
            ),
        )
        for name, catalog_name, evidence_name in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                private_dir = os.path.join(directory, "private-user-path")
                os.makedirs(private_dir)
                catalog_path = os.path.join(private_dir, catalog_name)
                evidence_path = os.path.join(private_dir, evidence_name)
                redacted_catalog_path = preflight._display_path(root, catalog_path)
                redacted_evidence_path = preflight._display_path(root, evidence_path)
                with open(catalog_path, "w", encoding="utf-8") as handle:
                    json.dump(VALID_CATALOG, handle)

                if name == "catalog_equals":
                    args = [
                        f"--catalog-json-file={catalog_path}",
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ]
                    expected_catalog_arg = f"--catalog-json-file={redacted_catalog_path}"
                    expected_evidence_items = ["--write-evidence", redacted_evidence_path]
                else:
                    args = [
                        "--catalog-json-file",
                        catalog_path,
                        "--json",
                        f"--write-evidence={evidence_path}",
                    ]
                    expected_catalog_arg = redacted_catalog_path
                    expected_evidence_items = [f"--write-evidence={redacted_evidence_path}"]

                result = subprocess.run(
                    [sys.executable, str(SCRIPT), *args],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with open(evidence_path, encoding="utf-8") as handle:
                    evidence_payload = json.loads(handle.read())

                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload, evidence_payload)
                argv = payload["preflight_evidence_binding"]["invocation"]["argv"]
                serialized = json.dumps(argv, sort_keys=True)
                self.assertIn(expected_catalog_arg, argv)
                for item in expected_evidence_items:
                    self.assertIn(item, argv)
                self.assertNotIn(private_dir, serialized)
                self.assertNotIn(directory, serialized)
                self.assertNotIn(catalog_name, serialized)
                self.assertNotIn(evidence_name, serialized)

    def test_write_evidence_rejects_abbreviated_path_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_dir = os.path.join(directory, "private-user-path")
            os.makedirs(private_dir)
            catalog_path = os.path.join(private_dir, "catalog.json")
            evidence_path = os.path.join(private_dir, "evidence.json")
            with open(catalog_path, "w", encoding="utf-8") as handle:
                json.dump(VALID_CATALOG, handle)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    f"--catalog-json-f={catalog_path}",
                    "--json",
                    "--write-e",
                    evidence_path,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unrecognized arguments", result.stderr)
            self.assertFalse(os.path.exists(evidence_path))

    def test_write_evidence_refuses_dirty_worktree_before_git_binding(self) -> None:
        root = repository_root()
        dirty_path = root / ".preflight-dirty-worktree-test"
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = os.path.join(directory, "evidence.json")
            try:
                dirty_path.write_text("dirty\n", encoding="utf-8")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--catalog-json",
                        json.dumps(VALID_CATALOG),
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            finally:
                with contextlib.suppress(FileNotFoundError):
                    dirty_path.unlink()

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "refusing to write exact-head evidence from a dirty Git worktree",
                result.stderr,
            )
            self.assertFalse(os.path.exists(evidence_path))

    def test_write_evidence_refuses_missing_git_revisions(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = os.path.join(directory, "evidence.json")
            output = io.StringIO()

            with mock.patch.object(
                module,
                "_git_rev_parse",
                return_value=None,
            ), mock.patch.object(
                module,
                "_git_status_porcelain",
                return_value="",
            ), mock.patch.object(
                module,
                "_file_digest",
                return_value="d" * 64,
            ), contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                module.main(
                    [
                        "--catalog-json",
                        json.dumps(VALID_CATALOG),
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ]
                )

            self.assertIn("cannot verify Git revision HEAD", str(raised.exception))
            self.assertFalse(os.path.exists(evidence_path))

    def test_write_evidence_refuses_git_identity_change_before_write(self) -> None:
        module = load_preflight_module()
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = os.path.join(directory, "evidence.json")
            output = io.StringIO()
            head_values = iter(("a" * 40, "b" * 40))
            tree_values = iter(("c" * 40, "c" * 40))

            def changed_rev_parse(_root, revision):
                if revision == "HEAD":
                    return next(head_values)
                if revision == "HEAD^{tree}":
                    return next(tree_values)
                raise AssertionError(f"unexpected revision {revision}")

            with mock.patch.object(
                module,
                "_git_rev_parse",
                side_effect=changed_rev_parse,
            ), mock.patch.object(
                module,
                "_git_status_porcelain",
                return_value="",
            ), mock.patch.object(
                module,
                "_file_digest",
                return_value="d" * 64,
            ), contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                module.main(
                    [
                        "--catalog-json",
                        json.dumps(VALID_CATALOG),
                        "--json",
                        "--write-evidence",
                        evidence_path,
                    ]
                )

            self.assertIn("Git identity changed", str(raised.exception))
            self.assertFalse(os.path.exists(evidence_path))

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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id },"
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
                    "params?.client_lease_id; params?.release_idempotency_key; params?.run_id; "
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
