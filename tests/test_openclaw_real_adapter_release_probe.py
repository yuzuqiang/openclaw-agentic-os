from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agentic_os.metadata import (
    MetadataContractError,
    validate_allow_lease_release_observation,
)
from agentic_os.openclaw_adapter import MetadataObservation, OpenClawAdapter
from tests.openclaw_adapter_test_harness import CannedOpenClawAdapter


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "openclaw-real-adapter-release-probe.py"
)
SPEC = importlib.util.spec_from_file_location("real_adapter_release_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load real adapter release probe")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


CATALOG = {
    "tools": [
        {
            "name": "subagents.allowLease.acquire",
            "parameters": [
                "client_lease_id",
                "idempotency_key",
                "run_id",
                "phase",
                "transition_id",
                "agent_id",
                "requester_agent_id",
                "ttl_ms",
            ],
        },
        {"name": "subagents.allowLease.status", "parameters": []},
        {
            "name": "subagents.allowLease.release",
            "parameters": [
                "client_lease_id",
                "release_idempotency_key",
                "run_id",
                "phase",
                "transition_id",
                "agent_id",
                "requester_agent_id",
                "gateway_lease_id",
            ],
        },
        {
            "name": "sessions_spawn",
            "parameters": [
                "client_request_id",
                "idempotency_key",
                "metadata",
                "gateway_lease_id",
            ],
        },
        {"name": "sessions_list", "parameters": []},
        {"name": "session_status", "parameters": ["sessionKey"]},
        {
            "name": "sessions_history",
            "parameters": ["sessionKey", "limit", "includeTools"],
        },
    ]
}
RELEASE_PARAMS = {
    "client_lease_id": "client-lease:test",
    "release_idempotency_key": "release-key",
    "run_id": "run:test",
    "phase": "phase-b",
    "transition_id": "transition:test",
    "agent_id": "agent:worker",
    "requester_agent_id": "agent:main",
}


class FakeTransport:
    def __init__(self) -> None:
        self.active = False
        self.release_calls: list[dict[str, Any]] = []
        self.release_response: dict[str, Any] | None = None
        self.status_response: dict[str, Any] | None = None

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        if method == "subagents.allowLease.acquire":
            self.active = True
            return self._response(params, "gateway-lease:test")
        if method == "subagents.allowLease.release":
            self.release_calls.append(dict(params))
            self.active = False
            if self.release_response is None:
                self.release_response = self._response(
                    params, "gateway-lease:test", released=True
                )
            return self.release_response
        if method == "subagents.allowLease.status":
            if self.status_response is not None:
                return self.status_response
            return {
                "leases": [self._response({}, "gateway-lease:test")]
                if self.active
                else []
            }
        raise AssertionError(f"unexpected method: {method}")

    @staticmethod
    def _response(
        params: Mapping[str, Any], external_id: str, *, released: bool | None = None
    ) -> dict[str, Any]:
        normalized = dict(params)
        response: dict[str, Any] = {
            "external_id": external_id,
            "metadata": {
                "metadata_contract_version": "v1",
                "normalized": normalized,
                "raw_json": json.dumps(normalized, sort_keys=True),
            },
        }
        if released is not None:
            response["released"] = released
        return response


def _validated_release_metadata(
    observation: MetadataObservation, expected: Mapping[str, Any]
) -> Mapping[str, Any]:
    try:
        return validate_allow_lease_release_observation(
            local=expected,
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
    except MetadataContractError as exc:
        raise MODULE.ProbeError(
            "release response metadata does not match request"
        ) from exc


def _matches_released_lease(
    observation: MetadataObservation,
    *,
    acquired_external_id: str,
    release_params: Mapping[str, Any],
) -> bool:
    if observation.external_id == acquired_external_id:
        return True
    normalized = observation.normalized
    if not isinstance(normalized, Mapping):
        return False
    return (
        normalized.get("gateway_lease_id") == acquired_external_id
        or normalized.get("client_lease_id") == release_params.get("client_lease_id")
    )


def _reject_visible_post_release_lease(
    observation: MetadataObservation,
    *,
    acquired_external_id: str,
    release_params: Mapping[str, Any],
) -> None:
    if not _matches_released_lease(
        observation,
        acquired_external_id=acquired_external_id,
        release_params=release_params,
    ):
        return
    if (
        observation.metadata_contract_version is None
        or observation.raw_json is None
        or observation.external_id is None
    ):
        raise MODULE.ProbeError(
            "released lease remains visible with incomplete metadata"
        )
    raise MODULE.ProbeError("released lease remains visible")


def _require_release_request_fields(release_params: Mapping[str, Any]) -> None:
    required = (
        "client_lease_id",
        "release_idempotency_key",
        "run_id",
        "phase",
        "transition_id",
        "agent_id",
        "requester_agent_id",
        "gateway_lease_id",
    )
    missing = [
        field
        for field in required
        if not isinstance(release_params.get(field), str) or not release_params.get(field)
    ]
    if missing:
        raise MODULE.ProbeError(f"release request is missing required fields: {missing}")


def _release_metadata(observation: MetadataObservation) -> Mapping[str, Any]:
    normalized = observation.normalized
    if not isinstance(normalized, Mapping):
        raise MODULE.ProbeError("release response lacks normalized metadata")
    if "idempotency_key" in normalized:
        raise MODULE.ProbeError(
            "release response exposes legacy idempotency_key metadata"
        )
    key = normalized.get("release_idempotency_key")
    if not isinstance(key, str) or not key:
        raise MODULE.ProbeError(
            "release response lacks release_idempotency_key metadata"
        )
    return normalized


def _path_value(value: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _validate_release_succeeded(observation: MetadataObservation) -> None:
    if not observation.raw_response_json:
        raise MODULE.ProbeError("release response lacks success confirmation")
    try:
        response = json.loads(observation.raw_response_json)
    except json.JSONDecodeError as exc:
        raise MODULE.ProbeError("release response raw JSON is invalid") from exc
    if not isinstance(response, Mapping):
        raise MODULE.ProbeError("release response raw JSON must be an object")
    for path in (
        ("released",),
        ("lease", "released"),
        ("result", "released"),
        ("result", "lease", "released"),
        ("output", "released"),
        ("output", "lease", "released"),
    ):
        value = _path_value(response, path)
        if value is not None:
            if value is True:
                return
            raise MODULE.ProbeError("release response did not report success")
    for path in (
        ("status",),
        ("result",),
        ("lease", "status"),
        ("result", "status"),
        ("result", "lease", "status"),
        ("output", "status"),
        ("output", "lease", "status"),
    ):
        value = _path_value(response, path)
        if isinstance(value, str) and value.lower() in {
            "released",
            "success",
            "ok",
            "pass",
        }:
            return
    raise MODULE.ProbeError("release response lacks success confirmation")


def run_release_probe_for_offline_tests(
    *,
    transport: Any,
    acquire_params: Mapping[str, Any],
    release_params: Mapping[str, Any],
) -> dict[str, bool]:
    """Test-only canned release semantics; never creates production authority."""

    adapter = CannedOpenClawAdapter(transport)
    acquired = adapter.allow_lease_acquire(acquire_params)
    if not acquired.external_id:
        raise MODULE.ProbeError("acquire response lacks an external lease identity")
    canonical_release = dict(release_params)
    canonical_release["gateway_lease_id"] = acquired.external_id
    _require_release_request_fields(canonical_release)
    first = adapter.allow_lease_release(canonical_release)
    second = adapter.allow_lease_release(canonical_release)
    _release_metadata(first)
    _release_metadata(second)
    _validate_release_succeeded(first)
    _validate_release_succeeded(second)
    first_metadata = _validated_release_metadata(first, canonical_release)
    second_metadata = _validated_release_metadata(second, canonical_release)
    if (
        first.external_id != acquired.external_id
        or second.external_id != acquired.external_id
    ):
        raise MODULE.ProbeError("release response lease identity does not match acquire")
    if first_metadata != second_metadata:
        raise MODULE.ProbeError("duplicate release metadata differs")
    if first.raw_response_json != second.raw_response_json:
        raise MODULE.ProbeError("duplicate release response differs")
    for lease in adapter.allow_lease_list():
        _reject_visible_post_release_lease(
            lease,
            acquired_external_id=acquired.external_id,
            release_params=canonical_release,
        )
    return {
        "agentic_adapter_live_catalog": True,
        "agentic_adapter_release_succeeded": True,
        "agentic_adapter_duplicate_release_parity": True,
        "agentic_adapter_release_metadata_parity": True,
        "agentic_adapter_post_release_absent": True,
    }


class RealAdapterReleaseProbeTests(unittest.TestCase):
    def test_canned_release_harness_exists_only_in_tests(self) -> None:
        root = SCRIPT.parents[1]
        production = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in (root / "src", root / "scripts")
            for path in directory.rglob("*.py")
        )
        self.assertNotIn("run_release_probe_for_offline_tests", production)
        self.assertNotIn("_from_unverified_transport_for_tests", production)

    def test_unverified_in_process_adapter_refuses_before_any_rpc(self) -> None:
        transport = FakeTransport()
        adapter = CannedOpenClawAdapter(transport)

        with self.assertRaisesRegex(MODULE.ProbeError, "exact OpenClawAdapter"):
            MODULE.run_release_probe(
                adapter=adapter,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

        self.assertFalse(transport.active)
        self.assertEqual(transport.release_calls, [])

    def test_forged_exact_adapter_refuses_before_any_rpc(self) -> None:
        transport = FakeTransport()
        adapter = object.__new__(OpenClawAdapter)
        adapter.__dict__.update(
            {
                "_transport": transport,
                "_authority_mode": "verified_runtime",
                "_verified_runtime_authority": True,
            }
        )

        with self.assertRaisesRegex(MODULE.ProbeError, "verified in-process"):
            MODULE.run_release_probe(
                adapter=adapter,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

        self.assertFalse(transport.active)
        self.assertEqual(transport.release_calls, [])

    def test_cross_process_unsigned_catalog_refuses_before_any_rpc(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(
                {
                    "acquire_params": {"idempotency_key": "acquire-key"},
                    "catalog": CATALOG,
                    "release_params": RELEASE_PARAMS,
                },
                sort_keys=True,
            )
            + "\n",
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        messages = [json.loads(line) for line in result.stdout.splitlines() if line]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["type"], "error")
        self.assertIn("unsigned cross-process catalog", messages[0]["error"])
        self.assertIn(MODULE.DISABLED_PROOF_STATUS, messages[0]["error"])
        self.assertNotIn('"type": "rpc"', result.stdout)

    def test_production_probe_declares_disabled_future_contract_status(self) -> None:
        self.assertEqual(
            MODULE.DISABLED_PROOF_STATUS,
            "disabled_future_contract_not_authoritative",
        )
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(
                {
                    "acquire_params": {"idempotency_key": "acquire-key"},
                    "release_params": RELEASE_PARAMS,
                },
                sort_keys=True,
            )
            + "\n",
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        messages = [json.loads(line) for line in result.stdout.splitlines() if line]
        self.assertEqual(len(messages), 1)
        self.assertIn(MODULE.DISABLED_PROOF_STATUS, messages[0]["error"])

    def test_canonical_release_replays_and_disappears(self) -> None:
        transport = FakeTransport()
        result = run_release_probe_for_offline_tests(
            transport=transport,
            acquire_params={"idempotency_key": "acquire-key"},
            release_params=RELEASE_PARAMS,
        )

        self.assertTrue(all(result.values()))
        self.assertEqual(len(transport.release_calls), 2)
        self.assertEqual(
            transport.release_calls[0]["release_idempotency_key"], "release-key"
        )
        self.assertNotIn("idempotency_key", transport.release_calls[0])
        self.assertEqual(
            transport.release_calls[0]["gateway_lease_id"], "gateway-lease:test"
        )

    def test_rejects_legacy_release_metadata(self) -> None:
        transport = FakeTransport()
        transport.release_response = transport._response(
            {"idempotency_key": "legacy"}, "gateway-lease:test"
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "legacy idempotency_key"):
            run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_release_metadata_that_does_not_match_request(self) -> None:
        transport = FakeTransport()
        wrong = dict(RELEASE_PARAMS)
        wrong["agent_id"] = "agent:other"
        wrong["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(
            wrong, "gateway-lease:test", released=True
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "does not match request"):
            run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_explicit_unsuccessful_release_response(self) -> None:
        transport = FakeTransport()
        release = dict(RELEASE_PARAMS)
        release["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(
            release, "gateway-lease:test", released=False
        )
        with self.assertRaisesRegex(MODULE.ProbeError, "did not report success"):
            run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_release_response_without_success_confirmation(self) -> None:
        transport = FakeTransport()
        release = dict(RELEASE_PARAMS)
        release["gateway_lease_id"] = "gateway-lease:test"
        transport.release_response = transport._response(release, "gateway-lease:test")
        with self.assertRaisesRegex(MODULE.ProbeError, "lacks success confirmation"):
            run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )

    def test_rejects_visible_post_release_lease_with_incomplete_metadata(self) -> None:
        transport = FakeTransport()
        transport.status_response = {
            "leases": [
                {
                    "gateway_lease_id": "gateway-lease:test",
                }
            ]
        }
        with self.assertRaisesRegex(MODULE.ProbeError, "incomplete metadata"):
            run_release_probe_for_offline_tests(
                transport=transport,
                acquire_params={"idempotency_key": "acquire-key"},
                release_params=RELEASE_PARAMS,
            )


if __name__ == "__main__":
    unittest.main()
