"""Pure metadata dispatch probes for fake adapter contract tests.

This module does not call OpenClaw, mutate Gateway state, or enable database
authority. It only drives an injected adapter and validates that the observed
metadata is sufficient for a future production adapter to fail closed.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from agentic_os.metadata import (
    MetadataContractError,
    validate_accepted_lease_identity,
    validate_accepted_session_identity,
    validate_allow_lease_observation,
    validate_allow_lease_release_observation,
    validate_session_observation,
)


@dataclass(frozen=True)
class MetadataObservation:
    """One fake adapter observation with normalized and raw runtime metadata."""

    normalized: Mapping[str, Any] | None
    raw_json: str | None
    metadata_contract_version: str | None
    external_id: str | None = None
    spawn_request_session_key: str | None = None
    session_key: str | None = None


@dataclass(frozen=True)
class AllowLeaseIntent:
    client_lease_id: str
    idempotency_key: str
    run_id: str
    phase: str
    transition_id: str
    agent_id: str
    requester_agent_id: str
    ttl_ms: int

    def metadata(self, *, gateway_lease_id: str) -> dict[str, Any]:
        return {
            "client_lease_id": self.client_lease_id,
            "idempotency_key": self.idempotency_key,
            "run_id": self.run_id,
            "phase": self.phase,
            "transition_id": self.transition_id,
            "agent_id": self.agent_id,
            "requester_agent_id": self.requester_agent_id,
            "ttl_ms": self.ttl_ms,
            "gateway_lease_id": gateway_lease_id,
        }


@dataclass(frozen=True)
class AllowLeaseReleaseIntent:
    run_id: str
    transition_id: str
    idempotency_key: str
    gateway_lease_id: str

    def metadata(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "transition_id": self.transition_id,
            "idempotency_key": self.idempotency_key,
            "gateway_lease_id": self.gateway_lease_id,
        }


@dataclass(frozen=True)
class SessionSpawnIntent:
    run_id: str
    transition_id: str
    client_request_id: str
    idempotency_key: str
    phase: str
    agent_id: str
    task_digest: str

    def metadata(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "transition_id": self.transition_id,
            "client_request_id": self.client_request_id,
            "idempotency_key": self.idempotency_key,
            "phase": self.phase,
            "agent_id": self.agent_id,
            "task_digest": self.task_digest,
        }


class MetadataDispatchAdapter(Protocol):
    """Fakeable adapter surface for metadata contract probes."""

    def allow_lease_acquire(self, intent: AllowLeaseIntent) -> MetadataObservation:
        raise NotImplementedError

    def allow_lease_status(self, gateway_lease_id: str) -> MetadataObservation:
        raise NotImplementedError

    def allow_lease_release(self, intent: AllowLeaseReleaseIntent) -> MetadataObservation:
        raise NotImplementedError

    def session_spawn(self, intent: SessionSpawnIntent) -> MetadataObservation:
        raise NotImplementedError

    def session_status(self, session_key: str) -> MetadataObservation:
        raise NotImplementedError

    def session_list(self, intent: SessionSpawnIntent) -> Sequence[MetadataObservation]:
        raise NotImplementedError

    def session_result(self, session_key: str) -> MetadataObservation:
        raise NotImplementedError


class ScriptedMetadataDispatchAdapter:
    """Deterministic fake adapter used by contract fixtures and tests."""

    def __init__(self, script: Mapping[str, Sequence[MetadataObservation]]) -> None:
        self._script = {
            name: deque(observations) for name, observations in script.items()
        }

    def _next(self, name: str) -> MetadataObservation:
        queue = self._script.get(name)
        if not queue:
            raise MetadataContractError(f"fake adapter has no scripted {name} observation")
        return queue.popleft()

    def allow_lease_acquire(self, intent: AllowLeaseIntent) -> MetadataObservation:
        return self._next("allow_lease_acquire")

    def allow_lease_status(self, gateway_lease_id: str) -> MetadataObservation:
        return self._next("allow_lease_status")

    def allow_lease_release(self, intent: AllowLeaseReleaseIntent) -> MetadataObservation:
        return self._next("allow_lease_release")

    def session_spawn(self, intent: SessionSpawnIntent) -> MetadataObservation:
        return self._next("session_spawn")

    def session_status(self, session_key: str) -> MetadataObservation:
        return self._next("session_status")

    def session_list(self, intent: SessionSpawnIntent) -> Sequence[MetadataObservation]:
        observations: list[MetadataObservation] = []
        while self._script.get("session_list"):
            observations.append(self._next("session_list"))
        return observations

    def session_result(self, session_key: str) -> MetadataObservation:
        return self._next("session_result")


class MetadataDispatchProbe:
    """Validate exact metadata and replay stability from an injected adapter."""

    def __init__(self, adapter: MetadataDispatchAdapter) -> None:
        self._adapter = adapter
        self._lease_by_acquire_key: dict[str, tuple[AllowLeaseIntent, str]] = {}
        self._lease_by_gateway_id: dict[str, AllowLeaseIntent] = {}
        self._release_by_key: dict[str, tuple[AllowLeaseReleaseIntent, str]] = {}
        self._session_by_spawn_key: dict[str, tuple[SessionSpawnIntent, str]] = {}
        self._session_intent_by_key: dict[str, SessionSpawnIntent] = {}

    def acquire_allow_lease(self, intent: AllowLeaseIntent) -> str:
        observation = self._adapter.allow_lease_acquire(intent)
        gateway_lease_id = self._gateway_lease_id(observation)
        observed = validate_allow_lease_observation(
            local=intent.metadata(gateway_lease_id=gateway_lease_id),
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
        accepted = validate_accepted_lease_identity(
            gateway_lease_id=observed["gateway_lease_id"],
            duplicate_acquire_lease_id=self._lease_by_acquire_key.get(
                intent.idempotency_key, (intent, None)
            )[1],
        )
        self._remember_lease_acquire(intent, accepted)
        return accepted

    def status_allow_lease(self, intent: AllowLeaseIntent, gateway_lease_id: str) -> str:
        self._require_acquired_lease(intent, gateway_lease_id)
        observation = self._adapter.allow_lease_status(gateway_lease_id)
        observed = validate_allow_lease_observation(
            local=intent.metadata(gateway_lease_id=gateway_lease_id),
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
        return validate_accepted_lease_identity(
            gateway_lease_id=observed["gateway_lease_id"],
            duplicate_acquire_lease_id=gateway_lease_id,
        )

    def release_allow_lease(self, intent: AllowLeaseReleaseIntent) -> str:
        acquired = self._lease_by_gateway_id.get(intent.gateway_lease_id)
        if acquired is None:
            raise MetadataContractError("release references an unknown gateway lease")
        if (
            intent.run_id != acquired.run_id
            or intent.transition_id != acquired.transition_id
        ):
            raise MetadataContractError("release identity does not match acquired lease")
        observation = self._adapter.allow_lease_release(intent)
        observed = validate_allow_lease_release_observation(
            local=intent.metadata(),
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
        released = validate_accepted_lease_identity(
            gateway_lease_id=observed["gateway_lease_id"],
            duplicate_acquire_lease_id=intent.gateway_lease_id,
        )
        prior = self._release_by_key.get(intent.idempotency_key)
        if prior is not None:
            prior_intent, prior_gateway_id = prior
            if prior_intent != intent:
                raise MetadataContractError("release replay identity changed")
            if prior_gateway_id != released:
                raise MetadataContractError("release replay returned a different lease identity")
        self._release_by_key[intent.idempotency_key] = (intent, released)
        return released

    def spawn_session(self, intent: SessionSpawnIntent) -> str:
        observation = self._adapter.session_spawn(intent)
        session_key = self._validate_session_observation(intent, observation)
        prior = self._session_by_spawn_key.get(intent.idempotency_key)
        duplicate_session_key = prior[1] if prior is not None else None
        accepted = validate_accepted_session_identity(
            external_id=observation.external_id,
            spawn_request_session_key=observation.spawn_request_session_key,
            session_key=observation.session_key,
            duplicate_spawn_session_key=duplicate_session_key,
        )
        if session_key != accepted:
            raise MetadataContractError("session metadata identity does not match accepted identity")
        self._remember_session_spawn(intent, accepted)
        return accepted

    def status_session(self, intent: SessionSpawnIntent, session_key: str) -> str:
        self._require_spawned_session(intent, session_key)
        observation = self._adapter.session_status(session_key)
        return self._validate_session_observation(intent, observation, expected=session_key)

    def list_session(self, intent: SessionSpawnIntent, session_key: str) -> str:
        self._require_spawned_session(intent, session_key)
        matches = [
            observation
            for observation in self._adapter.session_list(intent)
            if observation.session_key == session_key or observation.external_id == session_key
        ]
        if len(matches) != 1:
            raise MetadataContractError("session list must expose exactly one matching session")
        return self._validate_session_observation(intent, matches[0], expected=session_key)

    def result_session(self, intent: SessionSpawnIntent, session_key: str) -> str:
        self._require_spawned_session(intent, session_key)
        observation = self._adapter.session_result(session_key)
        return self._validate_session_observation(intent, observation, expected=session_key)

    def _gateway_lease_id(self, observation: MetadataObservation) -> str:
        normalized = observation.normalized
        if not isinstance(normalized, Mapping):
            raise MetadataContractError("normalized and raw external metadata are required")
        gateway_lease_id = normalized.get("gateway_lease_id")
        if not isinstance(gateway_lease_id, str) or not gateway_lease_id:
            raise MetadataContractError("accepted gateway lease identity must be non-empty")
        return gateway_lease_id

    def _remember_lease_acquire(self, intent: AllowLeaseIntent, gateway_lease_id: str) -> None:
        prior = self._lease_by_acquire_key.get(intent.idempotency_key)
        if prior is not None:
            prior_intent, prior_gateway_id = prior
            if prior_intent != intent:
                raise MetadataContractError("duplicate acquire identity changed")
            if prior_gateway_id != gateway_lease_id:
                raise MetadataContractError(
                    "duplicate allowLease acquire returned a different lease identity"
                )
        self._lease_by_acquire_key[intent.idempotency_key] = (intent, gateway_lease_id)
        self._lease_by_gateway_id[gateway_lease_id] = intent

    def _require_acquired_lease(
        self, intent: AllowLeaseIntent, gateway_lease_id: str
    ) -> None:
        acquired = self._lease_by_gateway_id.get(gateway_lease_id)
        if acquired != intent:
            raise MetadataContractError("status identity does not match acquired lease")

    def _validate_session_observation(
        self,
        intent: SessionSpawnIntent,
        observation: MetadataObservation,
        *,
        expected: str | None = None,
    ) -> str:
        validate_session_observation(
            local=intent.metadata(),
            normalized=observation.normalized,
            raw_json=observation.raw_json,
            metadata_contract_version=observation.metadata_contract_version,
        )
        session_key = validate_accepted_session_identity(
            external_id=observation.external_id,
            spawn_request_session_key=observation.spawn_request_session_key,
            session_key=observation.session_key,
            duplicate_spawn_session_key=expected,
        )
        return session_key

    def _remember_session_spawn(self, intent: SessionSpawnIntent, session_key: str) -> None:
        prior = self._session_by_spawn_key.get(intent.idempotency_key)
        if prior is not None:
            prior_intent, prior_session_key = prior
            if prior_intent != intent:
                raise MetadataContractError("duplicate spawn identity changed")
            if prior_session_key != session_key:
                raise MetadataContractError("duplicate spawn returned a different session identity")
        self._session_by_spawn_key[intent.idempotency_key] = (intent, session_key)
        self._session_intent_by_key[session_key] = intent

    def _require_spawned_session(self, intent: SessionSpawnIntent, session_key: str) -> None:
        spawned = self._session_intent_by_key.get(session_key)
        if spawned != intent:
            raise MetadataContractError("session identity does not match spawned request")
