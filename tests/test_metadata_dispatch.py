from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from agentic_os.metadata import MetadataContractError
from agentic_os.metadata_dispatch import (
    AllowLeaseIntent,
    AllowLeaseReleaseIntent,
    MetadataDispatchProbe,
    MetadataObservation,
    ScriptedMetadataDispatchAdapter,
    SessionSpawnIntent,
)


FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "metadata_dispatch"
    / "positive_contract.json"
)


def fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def lease_intent(data: dict[str, Any]) -> AllowLeaseIntent:
    lease = data["allow_lease"]
    return AllowLeaseIntent(
        client_lease_id=lease["client_lease_id"],
        idempotency_key=lease["idempotency_key"],
        run_id=lease["run_id"],
        phase=lease["phase"],
        transition_id=lease["transition_id"],
        agent_id=lease["agent_id"],
        requester_agent_id=lease["requester_agent_id"],
        ttl_ms=lease["ttl_ms"],
    )


def release_intent(data: dict[str, Any]) -> AllowLeaseReleaseIntent:
    release = data["allow_lease_release"]
    return AllowLeaseReleaseIntent(
        client_lease_id=release["client_lease_id"],
        idempotency_key=release["idempotency_key"],
        run_id=release["run_id"],
        phase=release["phase"],
        transition_id=release["transition_id"],
        agent_id=release["agent_id"],
        requester_agent_id=release["requester_agent_id"],
        gateway_lease_id=release["gateway_lease_id"],
    )


def session_intent(data: dict[str, Any]) -> SessionSpawnIntent:
    session = data["session"]
    return SessionSpawnIntent(
        run_id=session["run_id"],
        transition_id=session["transition_id"],
        client_request_id=session["client_request_id"],
        idempotency_key=session["idempotency_key"],
        phase=session["phase"],
        agent_id=session["agent_id"],
        task_digest=session["task_digest"],
    )


def observation(
    metadata: dict[str, Any],
    *,
    version: str,
    raw: dict[str, Any] | str | None = None,
    normalized: dict[str, Any] | None = None,
    identity: str | None = None,
) -> MetadataObservation:
    if raw is None:
        raw = dict(metadata)
    raw_json = raw if isinstance(raw, str) else json.dumps(raw)
    return MetadataObservation(
        normalized=dict(metadata) if normalized is None else normalized,
        raw_json=raw_json,
        metadata_contract_version=version,
        external_id=identity,
        spawn_request_session_key=identity,
        session_key=identity,
    )


def positive_script(data: dict[str, Any]) -> dict[str, list[MetadataObservation]]:
    version = data["metadata_contract_version"]
    lease = data["allow_lease"]
    release = data["allow_lease_release"]
    session_key = data["session"]["session_key"]
    session_metadata = {
        key: value for key, value in data["session"].items() if key != "session_key"
    }
    return {
        "allow_lease_acquire": [observation(lease, version=version)],
        "allow_lease_status": [observation(lease, version=version)],
        "allow_lease_release": [observation(release, version=version)],
        "session_spawn": [
            observation(session_metadata, version=version, identity=session_key)
        ],
        "session_status": [
            observation(session_metadata, version=version, identity=session_key)
        ],
        "session_list": [
            observation(session_metadata, version=version, identity=session_key)
        ],
        "session_result": [
            observation(session_metadata, version=version, identity=session_key)
        ],
    }


class RecordingScriptedMetadataDispatchAdapter(ScriptedMetadataDispatchAdapter):
    def __init__(self, script: dict[str, list[MetadataObservation]]) -> None:
        super().__init__(script)
        self.calls: list[str] = []

    def allow_lease_acquire(self, intent: AllowLeaseIntent) -> MetadataObservation:
        self.calls.append("allow_lease_acquire")
        return super().allow_lease_acquire(intent)

    def allow_lease_release(self, intent: AllowLeaseReleaseIntent) -> MetadataObservation:
        self.calls.append("allow_lease_release")
        return super().allow_lease_release(intent)

    def session_spawn(self, intent: SessionSpawnIntent) -> MetadataObservation:
        self.calls.append("session_spawn")
        return super().session_spawn(intent)


class MetadataDispatchTests(unittest.TestCase):
    def test_positive_probe_covers_lease_and_session_lifecycle(self) -> None:
        data = fixture()
        probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(positive_script(data)))
        lease = lease_intent(data)
        session = session_intent(data)
        gateway_lease_id = data["allow_lease"]["gateway_lease_id"]
        session_key = data["session"]["session_key"]

        self.assertEqual(probe.acquire_allow_lease(lease), gateway_lease_id)
        self.assertEqual(probe.status_allow_lease(lease, gateway_lease_id), gateway_lease_id)
        self.assertEqual(probe.spawn_session(session), session_key)
        self.assertEqual(probe.status_session(session, session_key), session_key)
        self.assertEqual(probe.list_session(session, session_key), session_key)
        self.assertEqual(probe.result_session(session, session_key), session_key)
        self.assertEqual(probe.release_allow_lease(release_intent(data)), gateway_lease_id)

    def test_version_only_metadata_fails_closed(self) -> None:
        data = fixture()
        script = positive_script(data)
        script["allow_lease_acquire"] = [
            MetadataObservation(
                normalized=None,
                raw_json=None,
                metadata_contract_version=data["metadata_contract_version"],
            )
        ]
        probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(script))
        with self.assertRaisesRegex(MetadataContractError, "metadata"):
            probe.acquire_allow_lease(lease_intent(data))

    def test_status_raw_normalized_local_mismatch_fails_closed(self) -> None:
        data = fixture()
        script = positive_script(data)
        wrong = dict(data["allow_lease"])
        wrong["requester_agent_id"] = "other-requester"
        script["allow_lease_status"] = [
            observation(
                data["allow_lease"],
                version=data["metadata_contract_version"],
                normalized=wrong,
            )
        ]
        probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(script))
        lease = lease_intent(data)
        gateway_lease_id = probe.acquire_allow_lease(lease)
        with self.assertRaisesRegex(MetadataContractError, "do not match"):
            probe.status_allow_lease(lease, gateway_lease_id)

    def test_release_identity_must_match_acquired_lease(self) -> None:
        data = fixture()
        probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(positive_script(data)))
        gateway_lease_id = probe.acquire_allow_lease(lease_intent(data))
        wrong = replace(release_intent(data), run_id="other-run")
        with self.assertRaisesRegex(MetadataContractError, "does not match acquired"):
            probe.release_allow_lease(wrong)

    def test_release_owner_metadata_must_match_acquired_lease(self) -> None:
        data = fixture()
        adapter = RecordingScriptedMetadataDispatchAdapter(positive_script(data))
        probe = MetadataDispatchProbe(adapter)
        gateway_lease_id = probe.acquire_allow_lease(lease_intent(data))
        wrong = replace(
            release_intent(data),
            client_lease_id="other-client-lease",
            gateway_lease_id=gateway_lease_id,
        )

        with self.assertRaisesRegex(MetadataContractError, "owner metadata"):
            probe.release_allow_lease(wrong)
        self.assertEqual(adapter.calls, ["allow_lease_acquire"])

    def test_duplicate_acquire_returning_different_gateway_id_fails_closed(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        lease = data["allow_lease"]
        replay = dict(lease)
        replay["gateway_lease_id"] = "gateway-lease-2"
        probe = MetadataDispatchProbe(
            ScriptedMetadataDispatchAdapter(
                {
                    "allow_lease_acquire": [
                        observation(lease, version=version),
                        observation(replay, version=version),
                    ]
                }
            )
        )
        intent = lease_intent(data)
        self.assertEqual(probe.acquire_allow_lease(intent), lease["gateway_lease_id"])
        with self.assertRaisesRegex(MetadataContractError, "different lease identity"):
            probe.acquire_allow_lease(intent)

    def test_reused_gateway_id_for_different_acquire_intent_fails_closed(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        lease_1 = data["allow_lease"]
        lease_2 = dict(lease_1)
        lease_2.update(
            {
                "client_lease_id": "client-lease-2",
                "idempotency_key": "allow-lease-acquire-idempotency-key-2",
            }
        )
        probe = MetadataDispatchProbe(
            ScriptedMetadataDispatchAdapter(
                {
                    "allow_lease_acquire": [
                        observation(lease_1, version=version),
                        observation(lease_2, version=version),
                    ]
                }
            )
        )
        intent_1 = lease_intent(data)
        intent_2 = replace(
            intent_1,
            client_lease_id=lease_2["client_lease_id"],
            idempotency_key=lease_2["idempotency_key"],
        )

        self.assertEqual(probe.acquire_allow_lease(intent_1), lease_1["gateway_lease_id"])
        with self.assertRaisesRegex(MetadataContractError, "already bound"):
            probe.acquire_allow_lease(intent_2)

    def test_changed_acquire_replay_identity_is_rejected_before_adapter_call(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        lease = data["allow_lease"]
        changed_observation = dict(lease)
        changed_observation["client_lease_id"] = "client-lease-2"
        adapter = RecordingScriptedMetadataDispatchAdapter(
            {
                "allow_lease_acquire": [
                    observation(lease, version=version),
                    observation(changed_observation, version=version),
                ]
            }
        )
        probe = MetadataDispatchProbe(adapter)
        intent = lease_intent(data)
        changed_intent = replace(intent, client_lease_id="client-lease-2")

        self.assertEqual(probe.acquire_allow_lease(intent), lease["gateway_lease_id"])
        with self.assertRaisesRegex(MetadataContractError, "duplicate acquire identity changed"):
            probe.acquire_allow_lease(changed_intent)
        self.assertEqual(adapter.calls, ["allow_lease_acquire"])

    def test_changed_release_replay_identity_is_rejected_before_adapter_call(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        lease_1 = data["allow_lease"]
        release_1 = data["allow_lease_release"]
        lease_2 = dict(lease_1)
        lease_2.update(
            {
                "client_lease_id": "client-lease-2",
                "idempotency_key": "allow-lease-acquire-idempotency-key-2",
                "run_id": "run-2",
                "transition_id": "transition-2",
                "gateway_lease_id": "gateway-lease-2",
            }
        )
        release_2 = dict(release_1)
        release_2.update(
            {
                "client_lease_id": lease_2["client_lease_id"],
                "run_id": lease_2["run_id"],
                "phase": lease_2["phase"],
                "transition_id": lease_2["transition_id"],
                "agent_id": lease_2["agent_id"],
                "requester_agent_id": lease_2["requester_agent_id"],
                "gateway_lease_id": lease_2["gateway_lease_id"],
            }
        )
        adapter = RecordingScriptedMetadataDispatchAdapter(
            {
                "allow_lease_acquire": [
                    observation(lease_1, version=version),
                    observation(lease_2, version=version),
                ],
                "allow_lease_release": [
                    observation(release_1, version=version),
                    observation(release_2, version=version),
                ],
            }
        )
        probe = MetadataDispatchProbe(adapter)
        lease_intent_1 = lease_intent(data)
        lease_intent_2 = replace(
            lease_intent_1,
            client_lease_id=lease_2["client_lease_id"],
            idempotency_key=lease_2["idempotency_key"],
            run_id=lease_2["run_id"],
            transition_id=lease_2["transition_id"],
        )
        release_intent_1 = release_intent(data)
        release_intent_2 = replace(
            release_intent_1,
            client_lease_id=release_2["client_lease_id"],
            run_id=release_2["run_id"],
            phase=release_2["phase"],
            transition_id=release_2["transition_id"],
            agent_id=release_2["agent_id"],
            requester_agent_id=release_2["requester_agent_id"],
            gateway_lease_id=release_2["gateway_lease_id"],
        )

        self.assertEqual(probe.acquire_allow_lease(lease_intent_1), lease_1["gateway_lease_id"])
        self.assertEqual(probe.acquire_allow_lease(lease_intent_2), lease_2["gateway_lease_id"])
        self.assertEqual(probe.release_allow_lease(release_intent_1), lease_1["gateway_lease_id"])
        with self.assertRaisesRegex(MetadataContractError, "release replay identity changed"):
            probe.release_allow_lease(release_intent_2)
        self.assertEqual(
            adapter.calls,
            ["allow_lease_acquire", "allow_lease_acquire", "allow_lease_release"],
        )

    def test_duplicate_session_spawn_returning_different_key_fails_closed(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        session_key = data["session"]["session_key"]
        metadata = {
            key: value for key, value in data["session"].items() if key != "session_key"
        }
        probe = MetadataDispatchProbe(
            ScriptedMetadataDispatchAdapter(
                {
                    "session_spawn": [
                        observation(metadata, version=version, identity=session_key),
                        observation(metadata, version=version, identity="session-key-2"),
                    ]
                }
            )
        )
        intent = session_intent(data)
        self.assertEqual(probe.spawn_session(intent), session_key)
        with self.assertRaisesRegex(MetadataContractError, "different session identity"):
            probe.spawn_session(intent)

    def test_reused_session_key_for_different_spawn_intent_fails_closed(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        session_key = data["session"]["session_key"]
        metadata_1 = {
            key: value for key, value in data["session"].items() if key != "session_key"
        }
        metadata_2 = dict(metadata_1)
        metadata_2.update(
            {
                "client_request_id": "client-request-2",
                "idempotency_key": "session-spawn-idem-2",
            }
        )
        probe = MetadataDispatchProbe(
            ScriptedMetadataDispatchAdapter(
                {
                    "session_spawn": [
                        observation(metadata_1, version=version, identity=session_key),
                        observation(metadata_2, version=version, identity=session_key),
                    ]
                }
            )
        )
        intent_1 = session_intent(data)
        intent_2 = replace(
            intent_1,
            client_request_id=metadata_2["client_request_id"],
            idempotency_key=metadata_2["idempotency_key"],
        )

        self.assertEqual(probe.spawn_session(intent_1), session_key)
        with self.assertRaisesRegex(MetadataContractError, "already bound"):
            probe.spawn_session(intent_2)

    def test_changed_spawn_replay_identity_is_rejected_before_adapter_call(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        session_key = data["session"]["session_key"]
        metadata = {
            key: value for key, value in data["session"].items() if key != "session_key"
        }
        changed_metadata = dict(metadata)
        changed_metadata["client_request_id"] = "client-request-2"
        adapter = RecordingScriptedMetadataDispatchAdapter(
            {
                "session_spawn": [
                    observation(metadata, version=version, identity=session_key),
                    observation(changed_metadata, version=version, identity="session-key-2"),
                ]
            }
        )
        probe = MetadataDispatchProbe(adapter)
        intent = session_intent(data)
        changed_intent = replace(intent, client_request_id="client-request-2")

        self.assertEqual(probe.spawn_session(intent), session_key)
        with self.assertRaisesRegex(MetadataContractError, "duplicate spawn identity changed"):
            probe.spawn_session(changed_intent)
        self.assertEqual(adapter.calls, ["session_spawn"])

    def test_session_list_absent_or_duplicate_match_fails_closed(self) -> None:
        data = fixture()
        version = data["metadata_contract_version"]
        session_key = data["session"]["session_key"]
        metadata = {
            key: value for key, value in data["session"].items() if key != "session_key"
        }
        cases = (
            ("absent", []),
            (
                "duplicate_identity",
                [
                    observation(metadata, version=version, identity=session_key),
                    observation(metadata, version=version, identity=session_key),
                ],
            ),
            (
                "duplicate_metadata",
                [
                    observation(metadata, version=version, identity=session_key),
                    observation(metadata, version=version, identity="session-key-2"),
                ],
            ),
        )
        for name, listed in cases:
            with self.subTest(name=name):
                script = positive_script(data)
                script["session_list"] = listed
                probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(script))
                intent = session_intent(data)
                self.assertEqual(probe.spawn_session(intent), session_key)
                with self.assertRaisesRegex(MetadataContractError, "exactly one"):
                    probe.list_session(intent, session_key)

    def test_duplicate_raw_json_keys_fail_closed_for_session_result(self) -> None:
        data = fixture()
        script = positive_script(data)
        version = data["metadata_contract_version"]
        session_key = data["session"]["session_key"]
        metadata = {
            key: value for key, value in data["session"].items() if key != "session_key"
        }
        raw_pairs = [f'"{key}":{json.dumps(value)}' for key, value in metadata.items()]
        raw_pairs.append(f'"run_id":{json.dumps(metadata["run_id"])}')
        script["session_result"] = [
            observation(
                metadata,
                version=version,
                raw="{" + ",".join(raw_pairs) + "}",
                identity=session_key,
            )
        ]
        probe = MetadataDispatchProbe(ScriptedMetadataDispatchAdapter(script))
        intent = session_intent(data)
        self.assertEqual(probe.spawn_session(intent), session_key)
        with self.assertRaisesRegex(MetadataContractError, "duplicate key"):
            probe.result_session(intent, session_key)


if __name__ == "__main__":
    unittest.main()
