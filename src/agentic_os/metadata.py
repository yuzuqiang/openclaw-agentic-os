"""External metadata and accepted-session identity probes.

These validators prove observation shape only. They are not OpenClaw runtime
adapters and do not make external calls.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


class MetadataContractError(ValueError):
    """External metadata is absent, ambiguous, or mismatched."""


SESSION_FIELDS = (
    "run_id",
    "transition_id",
    "client_request_id",
    "idempotency_key",
    "phase",
    "agent_id",
    "task_digest",
)

ALLOW_LEASE_IDENTITY_FIELDS = (
    "client_lease_id",
    "idempotency_key",
    "run_id",
    "phase",
    "transition_id",
    "agent_id",
    "requester_agent_id",
)

ALLOW_LEASE_FIELDS = ALLOW_LEASE_IDENTITY_FIELDS + ("ttl_ms",)
ALLOW_LEASE_OBSERVED_FIELDS = ALLOW_LEASE_FIELDS + ("gateway_lease_id",)
ALLOW_LEASE_RELEASE_FIELDS = (
    "client_lease_id",
    "release_idempotency_key",
    "run_id",
    "phase",
    "transition_id",
    "agent_id",
    "requester_agent_id",
    "gateway_lease_id",
)
MAX_LEASE_TTL_MS = 31_536_000_000


def _exact_nonempty_fields(
    value: Mapping[str, Any], fields: tuple[str, ...], label: str
) -> dict[str, str]:
    if set(value) != set(fields):
        raise MetadataContractError(
            f"{label} must contain exactly {list(fields)}, found {sorted(value)}"
        )
    normalized: dict[str, str] = {}
    for field in fields:
        item = value[field]
        if not isinstance(item, str) or not item:
            raise MetadataContractError(f"{label}.{field} must be a non-empty string")
        normalized[field] = item
    return normalized


def _raw_json_object(raw_json: str) -> dict[str, Any]:
    if not isinstance(raw_json, str) or not raw_json:
        raise MetadataContractError("raw external metadata is required")
    try:
        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise MetadataContractError(
                        f"raw external metadata contains duplicate key: {key}"
                    )
                value[key] = item
            return value

        def reject_nonstandard_constant(constant: str) -> None:
            raise MetadataContractError(
                f"raw external metadata contains non-standard JSON constant: {constant}"
            )

        value = json.loads(
            raw_json,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except MetadataContractError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise MetadataContractError("raw external metadata is invalid JSON") from exc
    if not isinstance(value, dict):
        raise MetadataContractError("raw external metadata must be a JSON object")
    return value


def _raw_object(raw_json: str, fields: tuple[str, ...]) -> dict[str, str]:
    value = _raw_json_object(raw_json)
    missing = [field for field in fields if field not in value]
    if missing:
        raise MetadataContractError(
            f"raw external metadata is missing required fields: {missing}"
        )
    # Raw runtime evidence may legitimately include contract/session fields in
    # addition to the seven identity paths. Only the required identity subset
    # participates in the exact triple comparison.
    required = {field: value[field] for field in fields}
    return _exact_nonempty_fields(required, fields, "raw external metadata")


def validate_metadata_observation(
    *,
    local: Mapping[str, Any],
    normalized: Mapping[str, Any] | None,
    raw_json: str | None,
    metadata_contract_version: str | None,
    fields: tuple[str, ...],
) -> dict[str, str]:
    if not isinstance(metadata_contract_version, str) or not metadata_contract_version:
        raise MetadataContractError("metadata contract version is absent")
    if normalized is None or raw_json is None:
        raise MetadataContractError("normalized and raw external metadata are required")
    local_values = _exact_nonempty_fields(local, fields, "local intent")
    observed_values = _exact_nonempty_fields(normalized, fields, "normalized metadata")
    raw_values = _raw_object(raw_json, fields)
    if not (local_values == observed_values == raw_values):
        raise MetadataContractError("local, normalized, and raw metadata do not match")
    return observed_values


def validate_session_observation(**kwargs: Any) -> dict[str, str]:
    return validate_metadata_observation(fields=SESSION_FIELDS, **kwargs)


def validate_allow_lease_observation(**kwargs: Any) -> dict[str, Any]:
    local = kwargs.get("local")
    normalized = kwargs.get("normalized")
    raw_json = kwargs.get("raw_json")
    version = kwargs.get("metadata_contract_version")
    if not isinstance(version, str) or not version:
        raise MetadataContractError("metadata contract version is absent")
    if not isinstance(local, Mapping) or not isinstance(normalized, Mapping):
        raise MetadataContractError("normalized and raw external metadata are required")
    if raw_json is None:
        raise MetadataContractError("normalized and raw external metadata are required")

    def allow_values(value: Mapping[str, Any], label: str, *, exact: bool) -> dict[str, Any]:
        if exact and set(value) != set(ALLOW_LEASE_OBSERVED_FIELDS):
            raise MetadataContractError(
                f"{label} must contain exactly {list(ALLOW_LEASE_OBSERVED_FIELDS)}"
            )
        missing = [field for field in ALLOW_LEASE_OBSERVED_FIELDS if field not in value]
        if missing:
            raise MetadataContractError(f"{label} is missing required fields: {missing}")
        identity = _exact_nonempty_fields(
            {field: value[field] for field in ALLOW_LEASE_IDENTITY_FIELDS},
            ALLOW_LEASE_IDENTITY_FIELDS,
            label,
        )
        ttl_ms = value["ttl_ms"]
        if type(ttl_ms) is not int or not 1 <= ttl_ms <= MAX_LEASE_TTL_MS:
            raise MetadataContractError(
                f"{label}.ttl_ms must be an integer in [1,{MAX_LEASE_TTL_MS}]"
            )
        gateway_lease_id = value["gateway_lease_id"]
        if not isinstance(gateway_lease_id, str) or not gateway_lease_id:
            raise MetadataContractError(f"{label}.gateway_lease_id must be a non-empty string")
        return {**identity, "ttl_ms": ttl_ms, "gateway_lease_id": gateway_lease_id}

    local_values = allow_values(local, "local intent", exact=True)
    observed_values = allow_values(normalized, "normalized metadata", exact=True)
    raw_values = allow_values(
        _raw_json_object(raw_json), "raw external metadata", exact=False
    )
    if not (local_values == observed_values == raw_values):
        raise MetadataContractError("local, normalized, and raw metadata do not match")
    return observed_values


def _release_values(value: Mapping[str, Any], label: str, *, exact: bool) -> dict[str, str]:
    if exact and set(value) != set(ALLOW_LEASE_RELEASE_FIELDS):
        raise MetadataContractError(
            f"{label} must contain exactly {list(ALLOW_LEASE_RELEASE_FIELDS)}"
        )
    missing = [field for field in ALLOW_LEASE_RELEASE_FIELDS if field not in value]
    if missing:
        raise MetadataContractError(f"{label} is missing required fields: {missing}")
    external = _exact_nonempty_fields(
        {field: value[field] for field in ALLOW_LEASE_RELEASE_FIELDS},
        ALLOW_LEASE_RELEASE_FIELDS,
        label,
    )
    release_idem = external.pop("release_idempotency_key")
    legacy_idem = value.get("idempotency_key")
    if legacy_idem is not None:
        if not isinstance(legacy_idem, str) or not legacy_idem:
            raise MetadataContractError(
                f"{label}.idempotency_key must be a non-empty string"
            )
        if legacy_idem != release_idem:
            raise MetadataContractError(
                f"{label}.idempotency_key conflicts with release_idempotency_key"
            )
    external["idempotency_key"] = release_idem
    return external


def validate_allow_lease_release_observation(**kwargs: Any) -> dict[str, str]:
    local = kwargs.get("local")
    normalized = kwargs.get("normalized")
    raw_json = kwargs.get("raw_json")
    version = kwargs.get("metadata_contract_version")
    if not isinstance(version, str) or not version:
        raise MetadataContractError("metadata contract version is absent")
    if not isinstance(local, Mapping) or not isinstance(normalized, Mapping):
        raise MetadataContractError("normalized and raw external metadata are required")
    if raw_json is None:
        raise MetadataContractError("normalized and raw external metadata are required")
    local_values = _release_values(local, "local intent", exact=True)
    observed_values = _release_values(normalized, "normalized metadata", exact=True)
    raw_values = _release_values(
        _raw_json_object(raw_json), "raw external metadata", exact=False
    )
    if not (local_values == observed_values == raw_values):
        raise MetadataContractError("local, normalized, and raw metadata do not match")
    return observed_values


def validate_accepted_lease_identity(
    *, gateway_lease_id: str | None, duplicate_acquire_lease_id: str | None = None
) -> str:
    if not isinstance(gateway_lease_id, str) or not gateway_lease_id:
        raise MetadataContractError("accepted gateway lease identity must be non-empty")
    if duplicate_acquire_lease_id is not None:
        if not duplicate_acquire_lease_id or duplicate_acquire_lease_id != gateway_lease_id:
            raise MetadataContractError(
                "duplicate allowLease acquire returned a different lease identity"
            )
    return gateway_lease_id


def validate_accepted_session_identity(
    *,
    external_id: str | None,
    spawn_request_session_key: str | None,
    session_key: str | None,
    duplicate_spawn_session_key: str | None = None,
) -> str:
    values = (external_id, spawn_request_session_key, session_key)
    if any(not isinstance(value, str) or not value for value in values):
        raise MetadataContractError("accepted session identity must be stable and non-empty")
    if len(set(values)) != 1:
        raise MetadataContractError("accepted session identity tuple does not match")
    if duplicate_spawn_session_key is not None:
        if not duplicate_spawn_session_key or duplicate_spawn_session_key != external_id:
            raise MetadataContractError("duplicate spawn returned a different session identity")
    return external_id
