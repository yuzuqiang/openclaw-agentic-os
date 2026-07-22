from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentic_os.migrations import repository_root


SCRIPT = repository_root() / "scripts/openclaw-live-accepted-session-probe.py"


def load_probe_module():
    spec = importlib.util.spec_from_file_location("openclaw_live_probe", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load live probe script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args(**overrides):
    values = {
        "probe_id": "unit",
        "agent_id": "technical-writer",
        "requester_agent_id": "main",
        "ttl_ms": 60_000,
        "gateway_timeout_ms": 10_000,
        "agent_timeout_seconds": 120,
        "execute_session_spawn": False,
        "evidence_file": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def run_probe(module, probe_args):
    with mock.patch.object(module, "_validated_openclaw_executable", return_value="openclaw"):
        return module.run_probe(probe_args)


def contains_value(value, target):
    if value == target:
        return True
    if isinstance(value, dict):
        return any(contains_value(item, target) for item in value.values())
    if isinstance(value, list):
        return any(contains_value(item, target) for item in value)
    return False


def acquire_owner(**overrides):
    values = {
        "client_lease_id": "issue35-unit",
        "idempotency_key": "issue35-acquire-unit",
        "run_id": "issue35-run-unit",
        "phase": "B",
        "transition_id": "issue35-transition-unit",
        "agent_id": "technical-writer",
        "requester_agent_id": "main",
        "ttl_ms": 60_000,
    }
    values.update(overrides)
    return values


def status_lease(gateway_lease_id="lease-unit", **overrides):
    values = {**acquire_owner(), "gateway_lease_id": gateway_lease_id, **overrides}
    return {**values, **metadata_contract(values)}


def release_response(params, *, released=True, **overrides):
    values = {**dict(params), **overrides}
    return {"released": released, **values, **metadata_contract(values)}


def metadata_contract(values):
    return {
        "metadata": {
            "metadata_contract_version": "v1",
            "external_metadata": dict(values),
            "raw_metadata_json": json.dumps(
                dict(values), sort_keys=True, separators=(",", ":")
            ),
        }
    }


def lease_acquire_response(gateway_lease_id="lease-unit", **overrides):
    values = {**acquire_owner(), "gateway_lease_id": gateway_lease_id, **overrides}
    return {"gateway_lease_id": gateway_lease_id, **metadata_contract(values)}


def spawn_response(params, *, session_key="session-unit"):
    metadata = dict(params["metadata"])
    return {
        "session": {
            "session_key": session_key,
            "spawn_request_session_key": session_key,
            "metadata_echo": metadata,
            "metadata": {
                "metadata_contract_version": "v1",
                "external_metadata": metadata,
                "raw_metadata_json": json.dumps(
                    metadata, sort_keys=True, separators=(",", ":")
                ),
            },
        },
        "external_id": session_key,
    }


def session_read_response(metadata, *, session_key="session-unit", wrapper="sessions"):
    session = {
        "session_key": session_key,
        "metadata": {
            "metadata_contract_version": "v1",
            "external_metadata": dict(metadata),
            "raw_metadata_json": json.dumps(
                dict(metadata), sort_keys=True, separators=(",", ":")
            ),
        },
    }
    if wrapper == "session":
        return {"session": session}
    if wrapper == "result_sessions":
        return {"result": {"sessions": [session]}}
    return {"sessions": [session]}


def isolated_preflight_payload(**catalog):
    return {
        "status": "pass",
        "catalog": {"runtime_target": "isolated_candidate", **catalog},
    }


class OpenClawLiveAcceptedSessionProbeTests(unittest.TestCase):
    def test_package_root_executable_matches_preflight_install_root(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "openclaw"
            executable = package_root / "bin" / "openclaw"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)

            candidate_shas = {
                module._path_sha256(candidate)
                for candidate in module._candidate_roots_for_executable(executable)
                if candidate.exists()
            }

        self.assertIn(module._path_sha256(package_root), candidate_shas)

    def test_top_level_response_id_is_not_a_gateway_lease_alias(self) -> None:
        module = load_probe_module()
        response = {
            "gateway_lease_id": "lease-unit",
            "id": "transport-correlation-id",
        }

        self.assertEqual(module._lease_id_from_response(response), "lease-unit")
        self.assertEqual(module._lease_ids_from_response(response), ["lease-unit"])

    def test_preflight_failure_fails_closed_before_any_rpc(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            return_value=(False, {"status": "fail", "error": "missing metadata"}),
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_failed")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        self.assertEqual(payload["rpc_attempted"], [])
        gateway.assert_not_called()

    def test_preflight_command_targets_isolated_candidate_runtime(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_run_json",
            return_value=(
                0,
                {
                    "status": "pass",
                    "catalog": {
                        "runtime_target": "isolated_candidate",
                        "tools": [{"name": "sessions_status"}],
                    },
                },
            ),
        ) as run_json:
            ok, payload = module._preflight()

        self.assertTrue(ok)
        self.assertEqual(payload["catalog"]["runtime_target"], "isolated_candidate")
        command = run_json.call_args.args[0]
        self.assertIn("--isolated-candidate-openclaw", command)
        self.assertNotIn("--live-installed-openclaw", command)

    def test_wrong_preflight_target_fails_closed_before_any_rpc(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            return_value=(
                True,
                {
                    "status": "pass",
                    "catalog": {
                        "runtime_target": "live_installed_openclaw",
                        "tools": [{"name": "sessions_status"}],
                    },
                },
            ),
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_target_mismatch")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        self.assertEqual(payload["rpc_attempted"], [])
        gateway.assert_not_called()

    def test_missing_preflight_target_fails_closed_before_any_rpc(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            return_value=(True, {"status": "pass", "catalog": {"tools": []}}),
        ), mock.patch.object(module, "_validated_openclaw_executable") as validated, mock.patch.object(
            module, "_gateway_call"
        ) as gateway:
            payload = module.run_probe(args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_target_mismatch")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        self.assertEqual(payload["rpc_attempted"], [])
        validated.assert_not_called()
        gateway.assert_not_called()

    def test_missing_preflight_binding_hashes_fail_closed_before_any_rpc(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "openclaw"
            executable = package_root / "bin" / "openclaw"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            required = {
                "install_root_path_sha256": module._path_sha256(package_root),
                "active_executable_path_sha256": module._path_sha256(executable),
                "active_executable_sha256": module._file_sha256(executable),
            }
            cases = {
                "install root": "install_root_path_sha256",
                "executable path": "active_executable_path_sha256",
                "executable content": "active_executable_sha256",
            }
            for label, omitted_key in cases.items():
                with self.subTest(omitted=omitted_key):
                    catalog = {
                        "runtime_target": "isolated_candidate",
                        **{
                            key: value
                            for key, value in required.items()
                            if key != omitted_key
                        },
                    }
                    with mock.patch.object(
                        module,
                        "_preflight",
                        return_value=(True, {"status": "pass", "catalog": catalog}),
                    ), mock.patch.object(
                        module.shutil, "which", return_value=str(executable)
                    ), mock.patch.object(module, "_gateway_call") as gateway:
                        result = module.run_probe(args())

                    self.assertEqual(result["status"], "fail_closed")
                    self.assertEqual(
                        result["reason"], "capability_preflight_executable_mismatch"
                    )
                    self.assertIn(f"{label} hash is required", result["error"])
                    self.assertEqual(result["released"], "not_required")
                    self.assertEqual(result["rpc_attempted"], [])
                    gateway.assert_not_called()

    def test_session_status_alias_is_not_canonical_for_agentic_os_probe(self) -> None:
        module = load_probe_module()
        with self.assertRaisesRegex(RuntimeError, "sessions_status"):
            module._session_status_method(
                {"catalog": {"tools": [{"name": "session_status"}]}}
            )

    def test_db_authority_enabled_fails_closed_before_preflight(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module.agentic_os, "DB_AUTHORITY_ENABLED", True
        ), mock.patch.object(module, "_preflight") as preflight, mock.patch.object(
            module, "_gateway_call"
        ) as gateway:
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "db_authority_enabled")
        self.assertTrue(payload["db_authority_enabled"])
        self.assertEqual(payload["released"], "not_required")
        preflight.assert_not_called()
        gateway.assert_not_called()

    def test_preflight_timeout_writes_fail_closed_probe_payload(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module,
            "_preflight",
            side_effect=subprocess.TimeoutExpired(cmd=["preflight"], timeout=30),
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "capability_preflight_timed_out")
        self.assertEqual(payload["preflight"]["status"], "fail")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], "not_required")
        gateway.assert_not_called()

    def test_preflighted_install_root_must_match_path_openclaw_executable(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(bin_dir)
            executable = os.path.join(bin_dir, "openclaw")
            with open(executable, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(executable, 0o755)
            payload = {
                "status": "pass",
                "catalog": {
                    "runtime_target": "isolated_candidate",
                    "install_root_path_sha256": "not-the-path-openclaw-root",
                },
            }
            with mock.patch.object(
                module, "_preflight", return_value=(True, payload)
            ), mock.patch.object(
                module.shutil, "which", return_value=executable
            ), mock.patch.object(module, "_gateway_call") as gateway:
                result = module.run_probe(args())

        self.assertEqual(result["status"], "fail_closed")
        self.assertEqual(result["reason"], "capability_preflight_executable_mismatch")
        self.assertIn("does not match PATH openclaw executable", result["error"])
        self.assertEqual(result["released"], "not_required")
        gateway.assert_not_called()

    def test_explicit_isolated_root_matches_arbitrary_candidate_directory(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "candidate-runtime"
            executable = package_root / "bin" / "openclaw"
            source = package_root / "dist" / "openclaw-tools-test.js"
            executable.parent.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            source.write_text("catalog source\n", encoding="utf-8")
            payload = {
                "status": "pass",
                "catalog": {
                    "runtime_target": "isolated_candidate",
                    "install_root_path_sha256": module._path_sha256(package_root),
                    "active_executable_path_sha256": module._path_sha256(executable),
                    "active_executable_sha256": module._file_sha256(executable),
                    "sources": [
                        {
                            "path": "dist/openclaw-tools-test.js",
                            "sha256": module._file_sha256(source),
                        }
                    ],
                },
            }
            with mock.patch.object(
                module.shutil, "which", return_value=str(executable)
            ), mock.patch.dict(os.environ, {"OPENCLAW_INSTALL_ROOT": str(package_root)}):
                result = module._validated_openclaw_executable(payload)

        self.assertEqual(result, str(executable.resolve()))

    def test_preflighted_executable_hash_must_match_path_openclaw_executable(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "openclaw"
            executable = package_root / "bin" / "openclaw"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            payload = {
                "status": "pass",
                "catalog": {
                    "runtime_target": "isolated_candidate",
                    "install_root_path_sha256": module._path_sha256(package_root),
                    "active_executable_path_sha256": "not-the-active-executable",
                },
            }
            with mock.patch.object(
                module, "_preflight", return_value=(True, payload)
            ), mock.patch.object(
                module.shutil, "which", return_value=str(executable)
            ), mock.patch.object(module, "_gateway_call") as gateway:
                result = module.run_probe(args())

        self.assertEqual(result["status"], "fail_closed")
        self.assertEqual(result["reason"], "capability_preflight_executable_mismatch")
        self.assertIn("executable does not match", result["error"])
        self.assertEqual(result["released"], "not_required")
        gateway.assert_not_called()

    def test_preflighted_executable_content_hash_must_match_before_rpc(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "openclaw"
            executable = package_root / "bin" / "openclaw"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            payload = {
                "status": "pass",
                "catalog": {
                    "runtime_target": "isolated_candidate",
                    "install_root_path_sha256": module._path_sha256(package_root),
                    "active_executable_path_sha256": module._path_sha256(executable),
                    "active_executable_sha256": "not-the-active-executable-content",
                },
            }
            with mock.patch.object(
                module, "_preflight", return_value=(True, payload)
            ), mock.patch.object(
                module.shutil, "which", return_value=str(executable)
            ), mock.patch.object(module, "_gateway_call") as gateway:
                result = module.run_probe(args())

        self.assertEqual(result["status"], "fail_closed")
        self.assertEqual(result["reason"], "capability_preflight_executable_mismatch")
        self.assertIn("executable content does not match", result["error"])
        self.assertEqual(result["released"], "not_required")
        gateway.assert_not_called()

    def test_preflighted_source_hashes_must_match_before_rpc(self) -> None:
        module = load_probe_module()
        with tempfile.TemporaryDirectory() as directory:
            package_root = Path(directory) / "openclaw"
            executable = package_root / "bin" / "openclaw"
            source = package_root / "dist" / "openclaw-tools-test.js"
            executable.parent.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            source.write_text("old catalog source\n", encoding="utf-8")
            payload = {
                "status": "pass",
                "catalog": {
                    "runtime_target": "isolated_candidate",
                    "install_root_path_sha256": module._path_sha256(package_root),
                    "active_executable_path_sha256": module._path_sha256(executable),
                    "active_executable_sha256": module._file_sha256(executable),
                    "sources": [
                        {
                            "path": "dist/openclaw-tools-test.js",
                            "sha256": module._file_sha256(source),
                        }
                    ],
                },
            }
            source.write_text("new catalog source\n", encoding="utf-8")
            with mock.patch.object(
                module, "_preflight", return_value=(True, payload)
            ), mock.patch.object(
                module.shutil, "which", return_value=str(executable)
            ), mock.patch.object(module, "_gateway_call") as gateway:
                result = module.run_probe(args())

        self.assertEqual(result["status"], "fail_closed")
        self.assertEqual(result["reason"], "capability_preflight_executable_mismatch")
        self.assertIn("source content does not match", result["error"])
        self.assertEqual(result["released"], "not_required")
        gateway.assert_not_called()

    def test_invalid_probe_metadata_fails_before_acquire_rpc(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call") as gateway:
            payload = run_probe(module, args(agent_id="", ttl_ms=0))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["rpc_attempted"], [])
        gateway.assert_not_called()

    def test_acquired_lease_is_released_when_session_execution_is_disabled(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "session_spawn_execution_disabled")
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "subagents.allowLease.release",
            ],
        )

    def test_duplicate_acquire_failure_still_releases_first_acquired_lease(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []
        acquire_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                if acquire_calls == 1:
                    return lease_acquire_response()
                raise RuntimeError("duplicate acquire timed out")
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(
            payload["allow_lease"]["gateway_lease_id_sha256"],
            module._identity_sha256("lease-unit"),
        )
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.release",
            ],
        )

    def test_first_acquire_timeout_is_not_reported_as_cleanup_not_required(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                raise RuntimeError("first acquire timed out")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertFalse(payload["lease_acquired"])
        self.assertTrue(payload["allow_lease_acquire_outcome_unknown"])
        self.assertFalse(payload["released"])
        self.assertIn("no lease identity available", payload["release_error"])

    def test_first_acquire_must_expose_raw_allow_lease_metadata(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {"gateway_lease_id": "lease-unit"}
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("acquire proof did not expose raw allowLease metadata", payload["error"])
        self.assertEqual(released_ids, ["lease-unit"])
        self.assertTrue(payload["released"])

    def test_allow_lease_metadata_rejects_conflicting_normalized_aliases(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                response = lease_acquire_response()
                response["metadata"]["normalized"] = {}
                return response
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting allowLease acquire proof normalized metadata", payload["error"])
        self.assertEqual(released_ids, ["lease-unit"])
        self.assertEqual(payload["released"], True)

    def test_first_acquire_conflicting_aliases_are_queued_for_cleanup(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return {
                    "gateway_lease_id": "lease-unit",
                    "leaseId": "lease-alias",
                    **metadata_contract({**acquire_owner(), "gateway_lease_id": "lease-unit"}),
                }
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting gateway lease identity aliases", payload["error"])
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(released_ids, ["lease-unit", "lease-alias"])
        self.assertEqual(payload["released"], True)

    def test_acquired_lease_aliases_are_recorded_for_cleanup(self) -> None:
        module = load_probe_module()
        metadata = metadata_contract({**acquire_owner(), "gateway_lease_id": "lease-unit"})
        for acquire_response in (
            {"external_id": "lease-unit", **metadata},
            {"lease": {"lease_id": "lease-unit", **metadata}},
            {"result": {"gateway_lease_id": "lease-unit", **metadata}},
            {"output": {"lease": {"gateway_lease_id": "lease-unit", **metadata}}},
        ):
            with self.subTest(acquire_response=acquire_response):
                released_ids: list[str] = []
                acquire_calls = 0

                def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
                    nonlocal acquire_calls
                    if method == "subagents.allowLease.acquire":
                        acquire_calls += 1
                        if acquire_calls == 1:
                            return acquire_response
                        raise RuntimeError("duplicate acquire timed out")
                    if method == "subagents.allowLease.release":
                        released_ids.append(params["gateway_lease_id"])
                        return release_response(params)
                    raise AssertionError(method)

                with mock.patch.object(
                    module, "_preflight", return_value=(True, isolated_preflight_payload())
                ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
                    payload = run_probe(module, args())

                self.assertEqual(payload["status"], "fail_closed")
                self.assertEqual(payload["reason"], "live_probe_contract_failed")
                self.assertEqual(
                    payload["allow_lease"]["gateway_lease_id_sha256"],
                    module._identity_sha256("lease-unit"),
                )
                self.assertEqual(released_ids, ["lease-unit"])
                self.assertEqual(payload["released"], True)

    def test_non_idempotent_duplicate_acquire_releases_both_observed_leases(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []
        acquire_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                return lease_acquire_response(
                    "lease-unit" if acquire_calls == 1 else "lease-duplicate"
                )
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("different lease identity", payload["error"])
        self.assertEqual(released_ids, ["lease-unit", "lease-duplicate"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_conflicting_aliases_are_queued_for_cleanup(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []
        acquire_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                if acquire_calls == 1:
                    return lease_acquire_response("lease-unit")
                return {
                    "gateway_lease_id": "lease-unit",
                    "leaseId": "lease-duplicate",
                    **metadata_contract({**acquire_owner(), "gateway_lease_id": "lease-unit"}),
                }
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting gateway lease identity aliases", payload["error"])
        self.assertEqual(released_ids, ["lease-unit", "lease-duplicate"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_must_echo_owner_metadata(self) -> None:
        module = load_probe_module()
        acquire_calls = 0

        def sequenced_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                return lease_acquire_response(
                    "lease-unit",
                    run_id="issue35-run-unit" if acquire_calls == 1 else "other-run",
                )
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=sequenced_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("duplicate allowLease acquire proof", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_cleanup_attempts_every_observed_lease(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []
        acquire_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                return lease_acquire_response(
                    "lease-unit" if acquire_calls == 1 else "lease-duplicate"
                )
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                if params["gateway_lease_id"] == "lease-unit":
                    raise RuntimeError("first release failed")
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertEqual(payload["prior_reason"], "live_probe_contract_failed")
        self.assertEqual(released_ids, ["lease-unit", "lease-duplicate"])
        self.assertFalse(payload["released"])

    def test_status_must_observe_acquired_lease_before_probe_can_pass(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [{"gateway_lease_id": "other-lease"}]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("status did not observe", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_status_rejects_and_releases_extra_lease_with_duplicate_owner_metadata(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease(), status_lease("lease-extra")]}
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("extra lease with duplicate acquire metadata", payload["error"])
        self.assertEqual(released_ids, ["lease-unit", "lease-extra"])
        self.assertEqual(payload["released"], True)

    def test_status_rejects_duplicate_owner_metadata_without_lease_identity(self) -> None:
        module = load_probe_module()
        released_ids: list[str] = []

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                duplicate_owner_without_identity = {
                    **metadata_contract(acquire_owner()),
                }
                return {"leases": [status_lease(), duplicate_owner_without_identity]}
            if method == "subagents.allowLease.release":
                released_ids.append(params["gateway_lease_id"])
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("duplicate owner metadata without lease identity", payload["error"])
        self.assertEqual(released_ids, ["lease-unit"])
        self.assertEqual(payload["released"], True)

    def test_status_must_echo_owner_metadata_for_acquired_lease(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease(run_id="other-run")]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("raw allowLease metadata contract invalid", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_status_metadata_must_belong_to_observed_lease_object(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {
                    "request_echo": status_lease(),
                    "leases": [{"gateway_lease_id": "lease-unit"}],
                }
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("did not expose raw allowLease metadata", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_acquire_must_report_lease_identity(self) -> None:
        module = load_probe_module()
        acquire_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal acquire_calls
            if method == "subagents.allowLease.acquire":
                acquire_calls += 1
                if acquire_calls == 1:
                    return lease_acquire_response()
                return {"status": "already_acquired"}
            if method == "subagents.allowLease.release":
                return release_response(params)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("duplicate allowLease acquire did not report", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_release_false_fails_closed_even_when_identity_matches(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params, released=False)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn("MetadataContractError", payload["release_error"])

    def test_release_must_echo_owner_metadata(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params, run_id="other-run")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn(
            "MetadataContractError",
            payload["release_error"],
        )

    def test_result_wrapped_release_success_is_accepted(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return {"result": {"lease": release_response(params)}}
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "session_spawn_execution_disabled")
        self.assertTrue(payload["released"])
        self.assertEqual(
            payload["allow_lease_release"]["gateway_lease_id_sha256"],
            module._identity_sha256("lease-unit"),
        )

    def test_release_metadata_must_belong_to_released_lease_object(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return {
                    **dict(params),
                    "lease": {
                        "gateway_lease_id": params["gateway_lease_id"],
                        "released": True,
                    },
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn(
            "MetadataContractError",
            payload["release_error"],
        )

    def test_spawn_timeout_is_recorded_as_attempted_and_releases_lease(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                raise RuntimeError("spawn timed out")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["spawn_attempted"])
        self.assertIn("sessions_spawn", payload["rpc_attempted"])
        self.assertEqual(payload["released"], True)

    def test_duplicate_session_identity_mismatch_fails_closed_and_releases(self) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []
        spawn_calls = 0

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_calls
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                session = "session-a" if spawn_calls == 0 else "session-b"
                spawn_calls += 1
                return spawn_response(params, session_key=session)
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertTrue(payload["spawn_attempted"])
        self.assertTrue(payload["lease_acquired"])
        self.assertEqual(payload["released"], True)
        self.assertIn("duplicate spawn", payload["error"])
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "sessions_spawn",
                "sessions_spawn",
                "subagents.allowLease.release",
            ],
        )

    def test_duplicate_session_identity_pass_binds_structured_spawn_responses(
        self,
    ) -> None:
        module = load_probe_module()
        calls: list[tuple[str, dict[str, object]]] = []
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            calls.append((method, dict(params)))
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return {**spawn_response(params), "accepted": True}
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                return session_read_response(spawn_metadata_seen, wrapper="result_sessions")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(
            payload["accepted_session_identity_sha256"],
            module._identity_sha256("session-unit"),
        )
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            set(payload["accepted_session_identity_parity"].values()),
            {module._identity_sha256("session-unit")},
        )
        structured = payload["sessions_spawn_structured_evidence"]
        self.assertEqual(
            structured["first"]["identity"]["session_key"]["sha256"],
            module._identity_sha256("session-unit"),
        )
        self.assertEqual(
            structured["first"]["metadata_echo"]["run_id"],
            "issue35-run-unit",
        )
        self.assertIn("raw_response_sha256", structured["first"])
        spawn_params = [params for method, params in calls if method == "sessions_spawn"]
        self.assertTrue(spawn_params)
        self.assertTrue(all(params["gateway_lease_id"] == "lease-unit" for params in spawn_params))
        self.assertTrue(
            all("gateway_lease_id" not in params["metadata"] for params in spawn_params)
        )
        self.assertFalse(contains_value(payload, "lease-unit"))
        self.assertFalse(contains_value(payload, "session-unit"))
        self.assertEqual(
            payload["session_read_structured_evidence"]["sessions_history"][
                "history_items_identity_checked"
            ],
            1,
        )
        self.assertEqual(
            [method for method, _ in calls],
            [
                "subagents.allowLease.acquire",
                "subagents.allowLease.acquire",
                "subagents.allowLease.status",
                "sessions_spawn",
                "sessions_spawn",
                "sessions_list",
                "sessions_status",
                "sessions_history",
                "subagents.allowLease.release",
            ],
        )
        release_params = [
            params for method, params in calls if method == "subagents.allowLease.release"
        ]
        self.assertTrue(release_params)
        self.assertTrue(
            all("release_idempotency_key" in params for params in release_params)
        )
        self.assertTrue(all("idempotency_key" not in params for params in release_params))

    def test_result_wrapped_session_spawn_response_is_accepted(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return {"result": spawn_response(params)}
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                return session_read_response(spawn_metadata_seen, wrapper="result_sessions")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(
            payload["accepted_session_identity_sha256"],
            module._identity_sha256("session-unit"),
        )
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            payload["sessions_spawn_structured_evidence"]["first"]["metadata_echo"][
                "run_id"
            ],
            "issue35-run-unit",
        )

    def test_metadata_contract_only_session_spawn_response_is_accepted(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                session = spawn_response(params)["session"]
                session.pop("metadata_echo")
                return {"session": session, "external_id": "session-unit"}
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                return session_read_response(spawn_metadata_seen, wrapper="result_sessions")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(
            payload["accepted_session_identity_sha256"],
            module._identity_sha256("session-unit"),
        )
        self.assertEqual(
            payload["sessions_spawn_structured_evidence"]["first"]["metadata_echo"][
                "run_id"
            ],
            "issue35-run-unit",
        )

    def test_session_read_apis_must_expose_metadata_before_probe_passes(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return spawn_response(params)
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                return {"sessions": [{"session_key": "session-unit"}]}
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("sessions_history response", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_sessions_history_rejects_mismatched_sibling_history_item(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return spawn_response(params)
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                matching = session_read_response(spawn_metadata_seen)["sessions"][0]
                other = session_read_response(
                    spawn_metadata_seen,
                    session_key="other-session",
                )["sessions"][0]
                return {"sessions": [matching, other]}
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("another session", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_sessions_history_rejects_mismatched_spawn_request_alias(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return spawn_response(params)
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                matching = session_read_response(spawn_metadata_seen)["sessions"][0]
                return {
                    "history": [
                        matching,
                        {"spawnRequestSessionKey": "other-session"},
                    ]
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("another session", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_sessions_history_accepts_history_shaped_metadata_item(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return spawn_response(params)
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                history_item = session_read_response(spawn_metadata_seen)["sessions"][0]
                return {"history": [history_item]}
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["released"], True)
        self.assertEqual(
            payload["session_read_structured_evidence"]["sessions_history"][
                "history_items_identity_checked"
            ],
            1,
        )

    def test_release_failure_downgrades_otherwise_passing_probe(self) -> None:
        module = load_probe_module()
        spawn_metadata_seen: dict[str, object] = {}

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            nonlocal spawn_metadata_seen
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                raise RuntimeError("release refused")
            if method == "sessions_spawn":
                spawn_metadata_seen = dict(params["metadata"])
                return spawn_response(params)
            if method == "sessions_list":
                return session_read_response(spawn_metadata_seen)
            if method == "sessions_status":
                return session_read_response(spawn_metadata_seen, wrapper="session")
            if method == "sessions_history":
                return session_read_response(spawn_metadata_seen, wrapper="result_sessions")
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "lease_release_failed")
        self.assertFalse(payload["released"])
        self.assertIn("runtime_error", payload["release_error"])
        self.assertEqual(
            payload["accepted_session_identity_sha256"],
            module._identity_sha256("session-unit"),
        )

    def test_spawn_response_must_echo_request_metadata(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                        "metadata_echo": {**params["metadata"], "run_id": "other-run"},
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "raw session metadata contract",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_spawn_response_must_expose_raw_session_metadata_contract(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                        "metadata_echo": dict(params["metadata"]),
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("raw session metadata contract", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_session_metadata_rejects_conflicting_normalized_aliases(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                response = spawn_response(params)
                response["session"]["metadata"]["normalized"] = {}
                return response
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting sessions_spawn response normalized metadata", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_spawn_response_rejects_conflicting_session_identity_aliases(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "external_id": "session-unit",
                    "session_key": "session-unit",
                    "spawn_request_session_key": "session-unit",
                    "session": {
                        "session_key": "other-session",
                        "metadata_echo": dict(params["metadata"]),
                    },
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn("conflicting session identity aliases", payload["error"])
        self.assertEqual(payload["released"], True)

    def test_spawn_metadata_echo_must_be_bound_to_created_session(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "request_echo": {"metadata": dict(params["metadata"])},
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "did not expose raw session metadata contract",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_top_level_spawn_metadata_echo_is_not_session_proof(self) -> None:
        module = load_probe_module()

        def fake_gateway(_openclaw_executable, method, params, *, timeout_ms):
            if method == "subagents.allowLease.acquire":
                return lease_acquire_response()
            if method == "subagents.allowLease.status":
                return {"leases": [status_lease()]}
            if method == "subagents.allowLease.release":
                return release_response(params)
            if method == "sessions_spawn":
                return {
                    "metadata_echo": dict(params["metadata"]),
                    "session": {
                        "session_key": "session-unit",
                        "spawn_request_session_key": "session-unit",
                    },
                    "external_id": "session-unit",
                }
            raise AssertionError(method)

        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(module, "_gateway_call", side_effect=fake_gateway):
            payload = run_probe(module, args(execute_session_spawn=True))

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertIn(
            "did not expose raw session metadata contract",
            payload["error"],
        )
        self.assertEqual(payload["released"], True)

    def test_missing_openclaw_cli_fails_closed_instead_of_traceback(self) -> None:
        module = load_probe_module()
        with mock.patch.object(
            module, "_preflight", return_value=(True, isolated_preflight_payload())
        ), mock.patch.object(
            module.subprocess,
            "run",
            side_effect=FileNotFoundError("openclaw missing"),
        ):
            payload = run_probe(module, args())

        self.assertEqual(payload["status"], "fail_closed")
        self.assertEqual(payload["reason"], "live_probe_contract_failed")
        self.assertFalse(payload["spawn_attempted"])
        self.assertFalse(payload["lease_acquired"])
        self.assertEqual(payload["released"], False)
        self.assertIn("no lease identity available", payload["release_error"])
        self.assertEqual(payload["error"], "gateway call subagents.allowLease.acquire failed")
        self.assertEqual(payload["error_class"], "LiveRpcError")
        self.assertIn("external_error_sha256", payload)

    def test_run_json_wraps_non_object_json_without_type_error(self) -> None:
        module = load_probe_module()
        completed = subprocess.CompletedProcess(
            args=["openclaw"], returncode=1, stdout='["bad-secret"]', stderr=""
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            code, payload = module._run_json(["openclaw"], timeout=1)

        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error"], "command returned non-object JSON output")
        self.assertEqual(payload["json_type"], "list")
        self.assertIn("stdout_sha256", payload)
        self.assertNotIn("bad-secret", json.dumps(payload))
        self.assertNotIn("stdout_prefix", payload)

    def test_run_json_uses_hash_only_error_when_command_lacks_structured_error(self) -> None:
        module = load_probe_module()
        completed = subprocess.CompletedProcess(
            args=["openclaw"],
            returncode=2,
            stdout='{"status":"fail","details":"bounded"}',
            stderr="private-token-like-stderr",
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            code, payload = module._run_json(["openclaw"], timeout=1)

        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "command failed without structured error")
        self.assertIn("stdout_sha256", payload)
        self.assertIn("stderr_sha256", payload)
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn("private-token-like-stderr", serialized)
        self.assertNotIn("bounded", serialized)

    def test_gateway_call_rejects_non_object_json_success_output(self) -> None:
        module = load_probe_module()
        completed = subprocess.CompletedProcess(
            args=["openclaw"], returncode=0, stdout='"ok"', stderr=""
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "gateway call"):
                module._gateway_call(
                    "openclaw",
                    "subagents.allowLease.status",
                    {},
                    timeout_ms=1000,
                )


if __name__ == "__main__":
    unittest.main()
