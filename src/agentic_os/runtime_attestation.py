"""Transport-bound OpenClaw runtime attestation.

The attestor deliberately does not trust a catalog JSON file.  It accepts only a
fresh challenge response signed by a configured verifier and binds the result to
the exact Python process and transport object that completed the challenge.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol


class RuntimeAttestationError(ValueError):
    """Runtime attestation is absent, stale, replayed, or has drifted."""


class AttestableOpenClawTransport(Protocol):
    """Application transport plus its challenge-bound identity snapshot."""

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        ...

    def request_runtime_attestation(
        self, *, challenge: str, client_process_id: str
    ) -> Mapping[str, Any]:
        ...

    def runtime_identity_snapshot(self) -> Mapping[str, Any]:
        ...


class RuntimeSignatureVerifier(Protocol):
    def verify(
        self, *, payload: bytes, signature: str, algorithm: str
    ) -> bool:
        ...


class HmacSha256Verifier:
    """Verify isolated-runtime attestations with an Agentic-owned ephemeral key."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise RuntimeAttestationError("runtime attestation HMAC key must be 32 bytes")
        self._key = bytes(key)

    @classmethod
    def from_key_file(cls, path: str | os.PathLike[str]) -> "HmacSha256Verifier":
        key_path = os.fspath(path)
        mode = os.stat(key_path).st_mode & 0o777
        if mode != 0o600:
            raise RuntimeAttestationError("runtime attestation HMAC key file must be mode 0600")
        with open(key_path, "rb") as handle:
            return cls(handle.read())

    def verify(self, *, payload: bytes, signature: str, algorithm: str) -> bool:
        if algorithm != "hmac-sha256":
            return False
        expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class GatewayCliAttestedTransport:
    """One exact CLI/Gateway transport used by preflight and the live adapter."""

    def __init__(self, executable: str, *, executable_sha256: str, catalog_sha256: str,
                 timeout_ms: int = 10_000) -> None:
        resolved_executable = Path(shutil.which(executable) or executable).resolve()
        if not resolved_executable.is_file():
            raise RuntimeAttestationError("OpenClaw executable is not a regular file")
        actual_executable_sha256 = hashlib.sha256(
            resolved_executable.read_bytes()
        ).hexdigest()
        if actual_executable_sha256 != _sha256(
            executable_sha256, "expected OpenClaw executable digest"
        ):
            raise RuntimeAttestationError("OpenClaw executable digest does not match")
        self.executable = str(resolved_executable)
        self.executable_sha256 = executable_sha256
        self.executable_path_sha256 = hashlib.sha256(
            str(resolved_executable).encode("utf-8")
        ).hexdigest()
        self.catalog_sha256 = _sha256(
            catalog_sha256, "expected OpenClaw catalog digest"
        )
        self.timeout_ms = timeout_ms
        self._attested_snapshot: Mapping[str, Any] | None = None

    def _gateway_call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        proc = subprocess.run(
            [self.executable, "gateway", "call", method, "--json", "--timeout",
             str(self.timeout_ms), "--params", json.dumps(dict(params), sort_keys=True)],
            check=False, capture_output=True, text=True,
            timeout=max(5, self.timeout_ms // 1000 + 5),
        )
        if proc.returncode != 0:
            raise RuntimeAttestationError(f"{method} failed")
        value = json.loads(proc.stdout or "{}")
        if isinstance(value, Mapping) and isinstance(value.get("result"), Mapping):
            value = value["result"]
        if not isinstance(value, Mapping):
            raise RuntimeAttestationError(f"{method} response must be an object")
        return value

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._gateway_call(method, params)

    def request_runtime_attestation(self, *, challenge: str, client_process_id: str) -> Mapping[str, Any]:
        envelope = self._gateway_call("agenticOs.runtime.attest", {
            "challenge": challenge,
            "client_process_id": client_process_id,
            "expected_executable_sha256": self.executable_sha256,
            "expected_catalog_sha256": self.catalog_sha256,
        })
        payload = envelope.get("signed_payload")
        if isinstance(payload, Mapping):
            binding = _mapping(payload.get("binding"), "signed transport binding")
            executable = _mapping(
                binding.get("executable"), "signed executable binding"
            )
            catalog = _mapping(binding.get("catalog"), "signed catalog binding")
            if (
                executable.get("content_sha256") != self.executable_sha256
                or executable.get("path_sha256") != self.executable_path_sha256
                or catalog.get("sha256") != self.catalog_sha256
            ):
                raise RuntimeAttestationError(
                    "signed runtime binding does not match the local executable/catalog target"
                )
            self._attested_snapshot = {
                "binding": payload.get("binding"),
                "method_bindings": payload.get("method_bindings"),
            }
        return envelope

    def runtime_identity_snapshot(self) -> Mapping[str, Any]:
        if self._attested_snapshot is None:
            raise RuntimeAttestationError("runtime identity snapshot is unavailable before challenge")
        if hashlib.sha256(Path(self.executable).read_bytes()).hexdigest() != self.executable_sha256:
            raise RuntimeAttestationError("OpenClaw executable drifted after runtime challenge")
        return self._attested_snapshot


@dataclass(frozen=True)
class TransportMethodBinding:
    method: str
    parameter_names: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedRuntimeAttestation:
    """An opaque-to-callers, short-lived binding returned by the attestor."""

    payload_sha256: str
    identity_sha256: str
    issued_at_epoch_ms: int
    expires_at_epoch_ms: int
    local_process_id: int
    transport_object_id: int
    transport_identity: str
    gateway_endpoint: str
    gateway_build_id: str
    method_bindings: Mapping[str, TransportMethodBinding]


_REQUIRED_LOGICAL_METHODS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "allow_lease_acquire": (
        "subagents.allowLease.acquire",
        (
            "client_lease_id",
            "idempotency_key",
            "run_id",
            "phase",
            "transition_id",
            "agent_id",
            "requester_agent_id",
            "ttl_ms",
        ),
    ),
    "allow_lease_status": ("subagents.allowLease.status", ()),
    "allow_lease_release": (
        "subagents.allowLease.release",
        (
            "client_lease_id",
            "release_idempotency_key",
            "run_id",
            "phase",
            "transition_id",
            "agent_id",
            "requester_agent_id",
            "gateway_lease_id",
        ),
    ),
    "sessions_spawn": (
        "sessions_spawn",
        (
            "task",
            "taskName",
            "runtime",
            "mode",
            "agentId",
            "cleanup",
            "context",
            "lightContext",
            "client_request_id",
            "idempotency_key",
            "gateway_lease_id",
            "metadata",
        ),
    ),
    "sessions_list": ("sessions_list", ()),
    # This is the installed 2026.7.1 model-callable surface.  A plural alias is
    # neither inferred nor accepted: a later runtime needs a new reviewed contract.
    "session_status": ("session_status", ("sessionKey",)),
    "sessions_history": (
        "sessions_history",
        ("sessionKey", "limit", "includeTools"),
    ),
}

_BINDING_KEYS = frozenset(
    ("executable", "install", "sources", "catalog", "gateway", "transport")
)
_ENVELOPE_KEYS = frozenset(
    ("runtime_identity_token", "signature_algorithm", "signature", "signed_payload")
)
_SIGNED_KEYS = frozenset(
    (
        "schema_version",
        "online",
        "challenge",
        "nonce",
        "issued_at_epoch_ms",
        "expires_at_epoch_ms",
        "client_process_id",
        "runtime_identity_token_sha256",
        "owner_scope_id",
        "binding",
        "method_bindings",
    )
)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        _assert_json_object_keys(value, "runtime attestation")
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except RuntimeAttestationError:
        raise
    except (TypeError, ValueError) as exc:
        raise RuntimeAttestationError(
            "runtime attestation must be canonical JSON"
        ) from exc


def _assert_json_object_keys(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RuntimeAttestationError(
                    f"{label} object keys must be strings"
                )
            _assert_json_object_keys(item, f"{label}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for index, item in enumerate(value):
            _assert_json_object_keys(item, f"{label}[{index}]")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeAttestationError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise RuntimeAttestationError(
            f"{label} keys must be exactly {sorted(expected)}, found {sorted(value)}"
        )


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeAttestationError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _nonempty(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise RuntimeAttestationError(f"{label} must be a lowercase SHA-256")
    return text


def _validate_binding(value: Any) -> tuple[Mapping[str, Any], str, str, str, str]:
    binding = _mapping(value, "runtime binding")
    _exact_keys(binding, _BINDING_KEYS, "runtime binding")

    executable = _mapping(binding["executable"], "runtime executable binding")
    _exact_keys(executable, frozenset(("path_sha256", "content_sha256")), "runtime executable binding")
    _sha256(executable["path_sha256"], "runtime executable path digest")
    _sha256(executable["content_sha256"], "runtime executable digest")

    install = _mapping(binding["install"], "runtime install binding")
    _exact_keys(
        install,
        frozenset(("root_sha256", "package_json_sha256", "package_name", "version")),
        "runtime install binding",
    )
    _sha256(install["root_sha256"], "runtime install root digest")
    for key in ("package_name", "version"):
        _nonempty(install[key], f"runtime install {key}")
    _sha256(install["package_json_sha256"], "runtime package digest")

    sources = binding["sources"]
    if not isinstance(sources, Sequence) or isinstance(sources, (str, bytes, bytearray)):
        raise RuntimeAttestationError("runtime source binding must be a non-empty list")
    if not sources:
        raise RuntimeAttestationError("runtime source binding must be a non-empty list")
    source_paths: set[str] = set()
    for index, item in enumerate(sources):
        source = _mapping(item, f"runtime source binding {index}")
        _exact_keys(source, frozenset(("path", "sha256")), f"runtime source binding {index}")
        path = _nonempty(source["path"], f"runtime source binding {index} path")
        if path in source_paths:
            raise RuntimeAttestationError("runtime source binding paths must be unique")
        source_paths.add(path)
        _sha256(source["sha256"], f"runtime source binding {index} digest")

    catalog = _mapping(binding["catalog"], "runtime catalog binding")
    _exact_keys(
        catalog,
        frozenset(("authority", "sha256", "contract_vector_sha256")),
        "runtime catalog binding",
    )
    _nonempty(catalog["authority"], "runtime catalog authority")
    _sha256(catalog["sha256"], "runtime catalog digest")
    contract_vector_sha256 = _sha256(
        catalog["contract_vector_sha256"], "runtime contract vector digest"
    )

    gateway = _mapping(binding["gateway"], "Gateway binding")
    _exact_keys(
        gateway,
        frozenset(("endpoint", "version", "build_id", "process_identity")),
        "Gateway binding",
    )
    gateway_endpoint = _nonempty(gateway["endpoint"], "Gateway endpoint")
    _nonempty(gateway["version"], "Gateway version")
    gateway_build_id = _nonempty(gateway["build_id"], "Gateway build identity")
    _nonempty(gateway["process_identity"], "Gateway process identity")

    transport = _mapping(binding["transport"], "transport binding")
    _exact_keys(transport, frozenset(("kind", "identity")), "transport binding")
    _nonempty(transport["kind"], "transport kind")
    transport_identity = _nonempty(transport["identity"], "transport identity")
    return (
        binding,
        transport_identity,
        gateway_endpoint,
        gateway_build_id,
        contract_vector_sha256,
    )


def _contract_vector_sha256(
    methods: Mapping[str, TransportMethodBinding],
) -> str:
    runtime_methods = [
        {
            "name": methods[logical_name].method,
            "parameters": list(methods[logical_name].parameter_names),
        }
        for logical_name in _REQUIRED_LOGICAL_METHODS
    ]
    method_bindings = {
        logical_name: {
            "method": methods[logical_name].method,
            "parameter_names": list(methods[logical_name].parameter_names),
        }
        for logical_name in _REQUIRED_LOGICAL_METHODS
    }
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "agentic-os.runtime-contract-vector.v1",
                "runtime_methods": runtime_methods,
                "method_bindings": method_bindings,
            }
        )
    ).hexdigest()


def _validate_method_bindings(value: Any) -> Mapping[str, TransportMethodBinding]:
    raw = _mapping(value, "runtime method bindings")
    if set(raw) != set(_REQUIRED_LOGICAL_METHODS):
        raise RuntimeAttestationError(
            "runtime method bindings must contain the exact reviewed logical surface"
        )
    result: dict[str, TransportMethodBinding] = {}
    for logical_name, (required_method, required_parameters) in _REQUIRED_LOGICAL_METHODS.items():
        item = _mapping(raw[logical_name], f"runtime method binding {logical_name}")
        _exact_keys(
            item,
            frozenset(("method", "parameter_names")),
            f"runtime method binding {logical_name}",
        )
        method = _nonempty(item["method"], f"runtime method binding {logical_name} method")
        parameters = item["parameter_names"]
        if not isinstance(parameters, Sequence) or isinstance(
            parameters, (str, bytes, bytearray)
        ) or any(not isinstance(parameter, str) or not parameter for parameter in parameters):
            raise RuntimeAttestationError(
                f"runtime method binding {logical_name} parameters must be strings"
            )
        if len(set(parameters)) != len(parameters):
            raise RuntimeAttestationError(
                f"runtime method binding {logical_name} parameters must be unique"
            )
        if method != required_method:
            raise RuntimeAttestationError(
                f"runtime method binding {logical_name} must use {required_method}"
            )
        if tuple(parameters) != required_parameters:
            raise RuntimeAttestationError(
                f"runtime method binding {logical_name} parameter schema must match the exact reviewed set"
            )
        result[logical_name] = TransportMethodBinding(
            method=method, parameter_names=tuple(parameters)
        )
    return result


class TransportBoundRuntimeAttestor:
    """Verify a fresh signed challenge and bind it to one exact transport."""

    def __init__(
        self,
        verifier: RuntimeSignatureVerifier,
        *,
        clock_ms: Callable[[], int] | None = None,
        nonce_factory: Callable[[], str] | None = None,
        max_lifetime_ms: int = 300_000,
        max_clock_skew_ms: int = 30_000,
    ) -> None:
        if type(max_lifetime_ms) is not int or max_lifetime_ms <= 0:
            raise RuntimeAttestationError("max_lifetime_ms must be positive")
        if type(max_clock_skew_ms) is not int or max_clock_skew_ms < 0:
            raise RuntimeAttestationError("max_clock_skew_ms must be non-negative")
        self._verifier = verifier
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))
        self._max_lifetime_ms = max_lifetime_ms
        self._max_clock_skew_ms = max_clock_skew_ms

    @property
    def clock_ms(self) -> Callable[[], int]:
        return self._clock_ms

    def attest(
        self, transport: AttestableOpenClawTransport
    ) -> VerifiedRuntimeAttestation:
        challenge = _nonempty(self._nonce_factory(), "runtime challenge")
        local_pid = os.getpid()
        envelope = _mapping(
            transport.request_runtime_attestation(
                challenge=challenge, client_process_id=str(local_pid)
            ),
            "runtime attestation envelope",
        )
        _exact_keys(envelope, _ENVELOPE_KEYS, "runtime attestation envelope")
        runtime_identity_token = _nonempty(
            envelope["runtime_identity_token"], "runtime identity token"
        )
        algorithm = _nonempty(
            envelope["signature_algorithm"], "runtime signature algorithm"
        )
        signature = _nonempty(envelope["signature"], "runtime signature")
        signed_payload = _mapping(envelope["signed_payload"], "signed runtime payload")
        signed_bytes = canonical_json_bytes(signed_payload)
        if not self._verifier.verify(
            payload=signed_bytes, signature=signature, algorithm=algorithm
        ):
            raise RuntimeAttestationError("runtime attestation signature is invalid")

        _exact_keys(signed_payload, _SIGNED_KEYS, "signed runtime payload")
        if signed_payload["schema_version"] != "agentic-os.openclaw-attestation.v1":
            raise RuntimeAttestationError("runtime attestation schema version is unsupported")
        if signed_payload["online"] is not True:
            raise RuntimeAttestationError("offline runtime attestation is forbidden")
        if signed_payload["challenge"] != challenge or signed_payload["nonce"] != challenge:
            raise RuntimeAttestationError("runtime challenge/nonce does not match")
        if signed_payload["client_process_id"] != str(local_pid):
            raise RuntimeAttestationError("runtime attestation was issued to another process")
        token_sha256 = _sha256(
            signed_payload["runtime_identity_token_sha256"],
            "runtime identity token digest",
        )
        if hashlib.sha256(runtime_identity_token.encode("utf-8")).hexdigest() != token_sha256:
            raise RuntimeAttestationError("runtime identity token digest does not match")
        _sha256(signed_payload["owner_scope_id"], "runtime owner scope")

        issued = signed_payload["issued_at_epoch_ms"]
        expires = signed_payload["expires_at_epoch_ms"]
        if type(issued) is not int or type(expires) is not int:
            raise RuntimeAttestationError("runtime attestation times must be integer epoch ms")
        now = self._clock_ms()
        if issued > now + self._max_clock_skew_ms:
            raise RuntimeAttestationError("runtime attestation issue time is in the future")
        if now < issued - self._max_clock_skew_ms or now >= expires:
            raise RuntimeAttestationError("runtime attestation is stale or expired")
        if expires <= issued or expires - issued > self._max_lifetime_ms:
            raise RuntimeAttestationError("runtime attestation lifetime is invalid")

        (
            binding,
            transport_identity,
            endpoint,
            build_id,
            contract_vector_sha256,
        ) = _validate_binding(
            signed_payload["binding"]
        )
        methods = _validate_method_bindings(signed_payload["method_bindings"])
        if _contract_vector_sha256(methods) != contract_vector_sha256:
            raise RuntimeAttestationError(
                "runtime contract vector digest does not match signed method bindings"
            )
        expected_snapshot = {
            "binding": binding,
            "method_bindings": signed_payload["method_bindings"],
        }
        actual_snapshot = _mapping(
            transport.runtime_identity_snapshot(), "runtime identity snapshot"
        )
        if canonical_json_bytes(actual_snapshot) != canonical_json_bytes(expected_snapshot):
            raise RuntimeAttestationError(
                "runtime source/catalog/endpoint/build/transport identity drifted during attestation"
            )
        identity_sha256 = hashlib.sha256(
            canonical_json_bytes(expected_snapshot)
        ).hexdigest()
        return VerifiedRuntimeAttestation(
            payload_sha256=hashlib.sha256(signed_bytes).hexdigest(),
            identity_sha256=identity_sha256,
            issued_at_epoch_ms=issued,
            expires_at_epoch_ms=expires,
            local_process_id=local_pid,
            transport_object_id=id(transport),
            transport_identity=transport_identity,
            gateway_endpoint=endpoint,
            gateway_build_id=build_id,
            method_bindings=MappingProxyType(dict(methods)),
        )


def assert_attestation_current(
    transport: AttestableOpenClawTransport,
    attestation: VerifiedRuntimeAttestation,
    *,
    clock_ms: Callable[[], int],
) -> None:
    """Reject replay or identity drift before an application RPC is attempted."""

    if os.getpid() != attestation.local_process_id:
        raise RuntimeAttestationError("cross-process runtime attestation replay is forbidden")
    if id(transport) != attestation.transport_object_id:
        raise RuntimeAttestationError("runtime attestation belongs to another transport")
    if clock_ms() >= attestation.expires_at_epoch_ms:
        raise RuntimeAttestationError("runtime attestation is expired")
    snapshot = _mapping(
        transport.runtime_identity_snapshot(), "runtime identity snapshot"
    )
    if hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest() != attestation.identity_sha256:
        raise RuntimeAttestationError(
            "runtime source/catalog/endpoint/build/transport identity drifted"
        )
