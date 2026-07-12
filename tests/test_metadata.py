from __future__ import annotations

import json
import unittest

from agentic_os.metadata import (
    ALLOW_LEASE_FIELDS,
    SESSION_FIELDS,
    MetadataContractError,
    validate_accepted_lease_identity,
    validate_accepted_session_identity,
    validate_allow_lease_observation,
    validate_session_observation,
)


def values(fields: tuple[str, ...]) -> dict[str, str]:
    return {field: f"{field}-value" for field in fields}


def allow_values() -> dict[str, object]:
    result: dict[str, object] = values(ALLOW_LEASE_FIELDS[:-1])
    result["ttl_ms"] = 60_000
    return result


class MetadataTests(unittest.TestCase):
    def test_session_exact_triple_positive_control(self) -> None:
        local = values(SESSION_FIELDS)
        observed = validate_session_observation(
            local=local,
            normalized=dict(local),
            raw_json=json.dumps(local),
            metadata_contract_version="v1",
        )
        self.assertEqual(observed, local)

    def test_allow_lease_exact_triple_positive_control(self) -> None:
        local = allow_values()
        raw = dict(local)
        raw["metadata_contract_version"] = "v1"
        self.assertEqual(
            validate_allow_lease_observation(
                local=local,
                normalized=dict(local),
                raw_json=json.dumps(raw),
                metadata_contract_version="v1",
            ),
            local,
        )

    def test_allow_lease_version_only_or_mismatch_is_rejected(self) -> None:
        local = allow_values()
        with self.assertRaises(MetadataContractError):
            validate_allow_lease_observation(
                local=local,
                normalized=None,
                raw_json=None,
                metadata_contract_version="v1",
            )
        wrong = dict(local)
        wrong["requester_agent_id"] = "other-requester"
        with self.assertRaises(MetadataContractError):
            validate_allow_lease_observation(
                local=local,
                normalized=wrong,
                raw_json=json.dumps(local),
                metadata_contract_version="v1",
            )

    def test_allow_lease_ttl_type_range_and_equality_are_fail_closed(self) -> None:
        local = allow_values()
        maximum = dict(local)
        maximum["ttl_ms"] = 31_536_000_000
        self.assertEqual(
            validate_allow_lease_observation(
                local=maximum,
                normalized=dict(maximum),
                raw_json=json.dumps(maximum),
                metadata_contract_version="v1",
            )["ttl_ms"],
            31_536_000_000,
        )
        for bad_ttl in (True, "60000", 60_000.0, 0, -1, 31_536_000_001):
            wrong = dict(local)
            wrong["ttl_ms"] = bad_ttl
            with self.subTest(ttl_ms=bad_ttl), self.assertRaises(MetadataContractError):
                validate_allow_lease_observation(
                    local=local,
                    normalized=wrong,
                    raw_json=json.dumps(local),
                    metadata_contract_version="v1",
                )
        raw_wrong = dict(local)
        raw_wrong["ttl_ms"] = 60_001
        with self.assertRaises(MetadataContractError):
            validate_allow_lease_observation(
                local=local,
                normalized=dict(local),
                raw_json=json.dumps(raw_wrong),
                metadata_contract_version="v1",
            )

    def test_accepted_lease_duplicate_identity(self) -> None:
        self.assertEqual(
            validate_accepted_lease_identity(
                gateway_lease_id="lease-1", duplicate_acquire_lease_id="lease-1"
            ),
            "lease-1",
        )
        for accepted, duplicate in (("", None), (None, None), ("lease-1", "lease-2")):
            with self.subTest(values=(accepted, duplicate)), self.assertRaises(
                MetadataContractError
            ):
                validate_accepted_lease_identity(
                    gateway_lease_id=accepted,
                    duplicate_acquire_lease_id=duplicate,
                )

    def test_null_or_version_only_metadata_is_rejected(self) -> None:
        local = values(SESSION_FIELDS)
        cases = (
            {"normalized": None, "raw_json": None, "metadata_contract_version": None},
            {"normalized": None, "raw_json": None, "metadata_contract_version": "v1"},
            {"normalized": local, "raw_json": None, "metadata_contract_version": "v1"},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(MetadataContractError):
                validate_session_observation(local=local, **case)

    def test_raw_extra_fields_are_allowed_when_identity_subset_matches(self) -> None:
        local = values(SESSION_FIELDS)
        raw = dict(local)
        raw.update({"metadata_contract_version": "v1", "session_key": "session-1"})
        self.assertEqual(
            validate_session_observation(
                local=local,
                normalized=dict(local),
                raw_json=json.dumps(raw),
                metadata_contract_version="v1",
            ),
            local,
        )

    def test_raw_and_normalized_mismatch_or_missing_field_is_rejected(self) -> None:
        local = values(SESSION_FIELDS)
        wrong = dict(local)
        wrong["run_id"] = "other-run"
        missing = dict(local)
        del missing["task_digest"]
        cases = (
            (wrong, json.dumps(local)),
            (local, json.dumps(wrong)),
            (local, json.dumps(missing)),
            (local, "not-json"),
        )
        for normalized, raw in cases:
            with self.subTest(raw=raw), self.assertRaises(MetadataContractError):
                validate_session_observation(
                    local=local,
                    normalized=normalized,
                    raw_json=raw,
                    metadata_contract_version="v1",
                )

    def test_duplicate_raw_metadata_keys_are_rejected(self) -> None:
        local = values(SESSION_FIELDS)
        pairs = [f'"{key}":{json.dumps(value)}' for key, value in local.items()]
        pairs.append(f'"run_id":{json.dumps(local["run_id"])}')
        raw = "{" + ",".join(pairs) + "}"
        with self.assertRaisesRegex(MetadataContractError, "duplicate key: run_id"):
            validate_session_observation(
                local=local,
                normalized=dict(local),
                raw_json=raw,
                metadata_contract_version="v1",
            )

        lease = allow_values()
        lease_pairs = [f'"{key}":{json.dumps(value)}' for key, value in lease.items()]
        lease_pairs.append(f'"ttl_ms":{lease["ttl_ms"]}')
        with self.assertRaisesRegex(MetadataContractError, "duplicate key: ttl_ms"):
            validate_allow_lease_observation(
                local=lease,
                normalized=dict(lease),
                raw_json="{" + ",".join(lease_pairs) + "}",
                metadata_contract_version="v1",
            )

    def test_empty_field_is_rejected(self) -> None:
        local = values(SESSION_FIELDS)
        local["task_digest"] = ""
        with self.assertRaises(MetadataContractError):
            validate_session_observation(
                local=local,
                normalized=local,
                raw_json=json.dumps(local),
                metadata_contract_version="v1",
            )

    def test_accepted_session_identity_positive_and_duplicate_control(self) -> None:
        self.assertEqual(
            validate_accepted_session_identity(
                external_id="session-1",
                spawn_request_session_key="session-1",
                session_key="session-1",
                duplicate_spawn_session_key="session-1",
            ),
            "session-1",
        )

    def test_accepted_session_identity_must_be_nonempty_equal_and_stable(self) -> None:
        cases = (
            (None, "session-1", "session-1", None),
            ("", "session-1", "session-1", None),
            ("session-1", "session-2", "session-1", None),
            ("session-1", "session-1", "session-1", "session-2"),
        )
        for external, spawn, session, duplicate in cases:
            with self.subTest(values=(external, spawn, session, duplicate)):
                with self.assertRaises(MetadataContractError):
                    validate_accepted_session_identity(
                        external_id=external,
                        spawn_request_session_key=spawn,
                        session_key=session,
                        duplicate_spawn_session_key=duplicate,
                    )


if __name__ == "__main__":
    unittest.main()
