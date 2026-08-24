#!/usr/bin/env python3
"""Restart-safe local Heartbeat file-authority shadow soak monitor."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_os.heartbeat_shadow import (  # noqa: E402
    HeartbeatShadowError,
    RUNTIME_AUTHORITY_COUNT_KEYS,
    append_heartbeat_soak_sample,
    force_heartbeat_file_authority_rollback,
    heartbeat_parity_sample,
    new_heartbeat_soak_receipt,
    persist_heartbeat_soak_receipt,
    run_heartbeat_file_shadow_cycle,
    snapshot_heartbeat_runtime_authority_database,
    validate_heartbeat_soak_receipt,
    _runtime_authority_counts,
)


SCHEMA_CONFIG = "p03-heartbeat-shadow-monitor-config.v1"
SCHEMA_ENVELOPE = "p03-heartbeat-shadow-monitor-envelope.v1"
SCHEMA_SNAPSHOTS = "p03-heartbeat-shadow-runtime-snapshot-receipts.v1"
SCHEMA_STOP = "p03-heartbeat-shadow-monitor-stop-request.v1"
SCHEMA_START_RESERVATION = "p03-heartbeat-shadow-monitor-start-reservation.v1"
SCHEMA_AUTHORITY_INPUT_PATH_BINDING = (
    "p03-heartbeat-shadow-monitor-authority-input-path-binding.v1"
)
SCHEMA_CORE_RECEIPT_AUTHENTICATION = (
    "p03-heartbeat-shadow-core-receipt-authentication.v1"
)
SCHEMA_SAMPLE_AUTHENTICATION = (
    "p03-heartbeat-shadow-monitor-sample-authentication.v1"
)
SCHEMA_ROLLBACK_AUTHENTICATION_INTENT = (
    "p03-heartbeat-shadow-rollback-authentication-intent.v2"
)
INDEPENDENT_VALIDATION_SUBJECT_SCHEME = (
    "git-tree-with-excluded-validation-evidence-sha256.v1"
)
DEFAULT_DURATION_HOURS = 24
DEFAULT_INTERVAL_SECONDS = 300
DAEMON_READY_TIMEOUT_SECONDS = 2.0
EXPECTED_LIFECYCLE_SHA256 = (
    "60245f0148a5dc5d7c55cbd42de17eb343d9a2544863d56b7b4c3ffac40276a8"
)
EXPECTED_RUNTIME_HEAD = "ff180d08bde60ff42bd39147f339d3a590639778"
EXPECTED_AGENTIC_OS_EVIDENCE_HEAD = "21f0bde95beeedabd22f870d14eaa6fe98dbcf74"
EXPECTED_IMPLEMENTATION_BASE = "bf06585a9b8603001050a47af2840586d38c0a8d"
INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV = (
    "AGENTIC_OS_INDEPENDENT_VALIDATION_ANCHOR_HMAC_KEY"
)
MONITOR_HMAC_ENV = "AGENTIC_OS_HEARTBEAT_SHADOW_MONITOR_HMAC_KEY"
HMAC_MIN_BYTES = 32
_ACTIVE_SIGNAL_CONFIG: Mapping[str, Any] | None = None


class MonitorError(RuntimeError):
    """The local monitor failed closed before or during the soak."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _epoch_ms() -> int:
    return time.time_ns() // 1_000_000


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _anchor_signature_payload(record: Mapping[str, Any]) -> bytes:
    payload = dict(record)
    payload.pop("authentication", None)
    return _canonical_json(payload)


def _validate_anchor_signature(record: Mapping[str, Any]) -> None:
    authentication = record.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("independent validation authenticated record signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("independent validation authenticated record signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("independent validation authenticated record signature scheme is invalid")
    if authentication.get("key_env") != INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV:
        raise MonitorError("independent validation authenticated record key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("independent validation authenticated record signature is invalid")
    secret_bytes = _hmac_secret_bytes(
        INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV,
        "independent validation authenticated record signature key",
    )
    expected = hmac.new(
        secret_bytes,
        _anchor_signature_payload(record),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("independent validation authenticated record signature mismatch")


def _hmac_secret_bytes(env_name: str, label: str) -> bytes:
    secret = os.environ.get(env_name)
    if not secret:
        raise MonitorError(f"{label} is unavailable")
    secret_bytes = secret.encode("utf-8")
    if len(secret_bytes) < HMAC_MIN_BYTES:
        raise MonitorError(f"{label} is too weak")
    return secret_bytes


def _monitor_hmac_secret_bytes(label: str) -> bytes:
    secret_bytes = _hmac_secret_bytes(MONITOR_HMAC_ENV, label)
    anchor_secret = os.environ.get(INDEPENDENT_VALIDATION_ANCHOR_HMAC_ENV)
    if anchor_secret and hmac.compare_digest(secret_bytes, anchor_secret.encode("utf-8")):
        raise MonitorError(
            f"{label} must not reuse independent validation anchor key"
        )
    return secret_bytes


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> str:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical_json(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MonitorError(f"unreadable JSON: {path}") from exc
    if not isinstance(value, dict):
        raise MonitorError(f"JSON object required: {path}")
    return value


def _assert_status_read_paths_safe(state_dir: Path) -> Path:
    raw_state_dir = state_dir.expanduser()
    if raw_state_dir.is_symlink():
        raise MonitorError("status state_dir must not be a symlink")
    resolved_state_dir = _resolve_inside_repo(
        raw_state_dir,
        REPO_ROOT.resolve(),
        "status state_dir",
    )
    if not resolved_state_dir.is_dir():
        raise MonitorError("status state_dir is missing")
    envelope_path = raw_state_dir / "monitor-envelope.json"
    if envelope_path.is_symlink():
        raise MonitorError("status monitor envelope must not be a symlink")
    resolved_envelope = resolved_state_dir / "monitor-envelope.json"
    if not resolved_envelope.exists():
        raise MonitorError("status monitor envelope is missing")
    return resolved_state_dir


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.expanduser().resolve().open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _resolve_inside_repo(path: Path, repo_root: Path, label: str) -> Path:
    target = path.expanduser().resolve()
    try:
        target.relative_to(repo_root)
    except ValueError:
        raise MonitorError(f"{label} must stay inside the Agentic OS worktree") from None
    return target


def _git_text(repo_root: Path, args: list[str], label: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise MonitorError(f"git {label} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _git_check(repo_root: Path, args: list[str]) -> bool:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _repo_relative_path(repo_root: Path, path: Path, label: str) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise MonitorError(f"{label} must be repo-bound") from exc


def _validation_subject_excluded_paths(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> list[str]:
    repo_root = _repo_root_from_config(config)
    validation_path = _path_from_config(config, "independent_validation_path")
    anchor = validation.get("authenticated_record")
    if not isinstance(anchor, Mapping):
        raise MonitorError("independent validation authenticated record is missing")
    raw_anchor_path = anchor.get("path")
    if not isinstance(raw_anchor_path, str) or not raw_anchor_path:
        raise MonitorError("independent validation authenticated record path is missing")
    anchor_path = Path(raw_anchor_path)
    if not anchor_path.is_absolute():
        anchor_path = repo_root / anchor_path
    return sorted(
        {
            _repo_relative_path(
                repo_root,
                validation_path,
                "independent validation receipt path",
            ),
            _repo_relative_path(
                repo_root,
                anchor_path,
                "independent validation authenticated record path",
            ),
        }
    )


def _git_tracked_tree_subject_sha256(
    repo_root: Path, excluded_paths: Sequence[str]
) -> str:
    excluded = set(excluded_paths)
    result = subprocess.run(
        ["git", "ls-tree", "-rz", "HEAD"],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise MonitorError(
            f"git validation subject tree failed: {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    digest = hashlib.sha256()
    observed_exclusions: set[str] = set()
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            _metadata, raw_path = raw_entry.split(b"\t", 1)
        except ValueError as exc:
            raise MonitorError("git validation subject tree entry is malformed") from exc
        path = raw_path.decode("utf-8", "surrogateescape")
        if path in excluded:
            observed_exclusions.add(path)
            continue
        digest.update(raw_entry)
        digest.update(b"\0")
    if observed_exclusions != excluded:
        raise MonitorError("independent validation subject exclusion is not tracked")
    return digest.hexdigest()


def _assert_start_git_contract(config: Mapping[str, Any]) -> None:
    repo_root = Path(str(config["repo_root"])).resolve()
    status = _git_text(repo_root, ["status", "--porcelain=v1"], "status")
    if status:
        raise MonitorError("worktree must be clean before starting heartbeat soak monitor")
    exact_heads = config.get("exact_heads")
    if not isinstance(exact_heads, Mapping):
        raise MonitorError("monitor exact head contract is missing")
    head = _git_text(repo_root, ["rev-parse", "HEAD"], "rev-parse HEAD")
    if head != exact_heads.get("monitor_implementation_head"):
        raise MonitorError("monitor implementation head does not match Git HEAD")
    _git_text(
        repo_root,
        ["cat-file", "-e", f"{head}^{{commit}}"],
        "monitor implementation head",
    )
    implementation_base = str(exact_heads["implementation_base"])
    if _git_check(
        repo_root,
        [
            "merge-base",
            "--is-ancestor",
            implementation_base,
            head,
        ],
    ):
        return
    raise MonitorError(
        "implementation base must be an ancestor of the monitor implementation head"
    )


def _validate_receipt_config_binding(
    config: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    if receipt.get("run_id") != config.get("run_id"):
        raise MonitorError("core receipt run_id does not match monitor config")
    if receipt.get("authority_input_digest") != config.get("authority_input_digest"):
        raise MonitorError("core receipt authority digest does not match monitor config")
    if receipt.get("duration_hours") != config.get("duration_hours"):
        raise MonitorError("core receipt duration does not match monitor config")
    if receipt.get("sample_interval_seconds") != config.get("sample_interval_seconds"):
        raise MonitorError("core receipt sample interval does not match monitor config")
    timing = _soak_timing_payload(config)
    for key in (
        "started_at_epoch_ms",
        "started_at_monotonic_ms",
        "deadline_epoch_ms",
        "deadline_monotonic_ms",
        "duration_hours",
        "sample_interval_seconds",
    ):
        if receipt.get(key) != timing.get(key):
            raise MonitorError(f"core receipt {key} does not match authenticated run timing")


def _bind_soak_timing_config(
    config: dict[str, Any], receipt: Mapping[str, Any]
) -> None:
    config["soak_timing"] = {
        "started_at_epoch_ms": receipt.get("started_at_epoch_ms"),
        "started_at_monotonic_ms": receipt.get("started_at_monotonic_ms"),
        "deadline_epoch_ms": receipt.get("deadline_epoch_ms"),
        "deadline_monotonic_ms": receipt.get("deadline_monotonic_ms"),
        "duration_hours": receipt.get("duration_hours"),
        "sample_interval_seconds": receipt.get("sample_interval_seconds"),
    }


def _soak_timing_payload(config: Mapping[str, Any]) -> dict[str, Any]:
    timing = config.get("soak_timing")
    if not isinstance(timing, Mapping):
        raise MonitorError("monitor authenticated run timing is missing")
    expected = {
        "started_at_epoch_ms",
        "started_at_monotonic_ms",
        "deadline_epoch_ms",
        "deadline_monotonic_ms",
        "duration_hours",
        "sample_interval_seconds",
    }
    if set(timing) != expected:
        raise MonitorError("monitor authenticated run timing shape is invalid")
    payload = {key: timing.get(key) for key in expected}
    if any(type(value) is not int or value <= 0 for value in payload.values()):
        raise MonitorError("monitor authenticated run timing values are invalid")
    if payload["duration_hours"] != config.get("duration_hours"):
        raise MonitorError("monitor authenticated run duration mismatch")
    if payload["sample_interval_seconds"] != config.get("sample_interval_seconds"):
        raise MonitorError("monitor authenticated run interval mismatch")
    expected_epoch_deadline = (
        payload["started_at_epoch_ms"] + payload["duration_hours"] * 3_600_000
    )
    expected_monotonic_deadline = (
        payload["started_at_monotonic_ms"] + payload["duration_hours"] * 3_600_000
    )
    if payload["deadline_epoch_ms"] != expected_epoch_deadline:
        raise MonitorError("monitor authenticated epoch deadline mismatch")
    if payload["deadline_monotonic_ms"] != expected_monotonic_deadline:
        raise MonitorError("monitor authenticated monotonic deadline mismatch")
    return payload


def _path_identity(path: Path) -> dict[str, str]:
    resolved = path.expanduser().resolve()
    path_text = resolved.as_posix()
    return {
        "path": path_text,
        "path_sha256": _sha256_text(path_text),
    }


def _relative_to_repo(path: Path) -> str:
    return path.expanduser().resolve().relative_to(REPO_ROOT).as_posix()


def _authority_input_path_identities(
    *,
    baseline_path: Path,
    heartbeat_file: Path,
    live_config_path: Path,
) -> dict[str, dict[str, str]]:
    return {
        "baseline_path": _path_identity(baseline_path),
        "heartbeat_file": _path_identity(heartbeat_file),
        "live_config_path": _path_identity(live_config_path),
    }


def _authority_input_path_binding_payload(config: Mapping[str, Any]) -> dict[str, Any]:
    saved = config.get("authority_input_paths")
    if not isinstance(saved, Mapping):
        raise MonitorError("monitor authority input path identity is missing")
    return {
        "schema_version": SCHEMA_AUTHORITY_INPUT_PATH_BINDING,
        "run_id": config.get("run_id"),
        "repo_root": config.get("repo_root"),
        "authority_input_paths": dict(saved),
    }


def _authority_input_path_authentication(config: Mapping[str, Any]) -> dict[str, str]:
    signature = hmac.new(
        _monitor_hmac_secret_bytes(
            "monitor authority input path identity signature key"
        ),
        _canonical_json(_authority_input_path_binding_payload(config)),
        hashlib.sha256,
    ).hexdigest()
    return {
        "scheme": "hmac-sha256-env",
        "key_env": MONITOR_HMAC_ENV,
        "signature": signature,
    }


def _validate_authority_input_path_authentication(config: Mapping[str, Any]) -> None:
    authentication = config.get("authority_input_paths_authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("monitor authority input path identity signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("monitor authority input path identity signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("monitor authority input path identity signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("monitor authority input path identity signature key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("monitor authority input path identity signature is invalid")
    expected = hmac.new(
        _monitor_hmac_secret_bytes(
            "monitor authority input path identity signature key"
        ),
        _canonical_json(_authority_input_path_binding_payload(config)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("monitor authority input path identity signature mismatch")


def _validate_authority_input_path_identity(config: Mapping[str, Any]) -> None:
    saved = config.get("authority_input_paths")
    if not isinstance(saved, Mapping):
        raise MonitorError("monitor authority input path identity is missing")
    for key in ("baseline_path", "heartbeat_file", "live_config_path"):
        record = saved.get(key)
        if not isinstance(record, Mapping):
            raise MonitorError(f"monitor authority input path identity missing: {key}")
        observed = _path_from_config(config, key).as_posix()
        expected = record.get("path")
        expected_sha = record.get("path_sha256")
        if expected != observed or expected_sha != _sha256_text(observed):
            raise MonitorError(f"monitor authority input path identity mismatch: {key}")
    _validate_authority_input_path_authentication(config)


def _core_receipt_authentication_payload(config: Mapping[str, Any]) -> dict[str, Any]:
    receipt_path = _path_from_config(config, "core_soak_receipt_path")
    snapshot_receipts_path = _path_from_config(config, "runtime_snapshot_receipts_path")
    sample_authentication_path = _path_from_config(config, "sample_authentication_path")
    return {
        "schema_version": SCHEMA_CORE_RECEIPT_AUTHENTICATION,
        "run_id": config["run_id"],
        "authority": "file_artifacts",
        "authority_mode": "file_authority_shadow",
        "exact_heads": dict(config["exact_heads"]),
        "authority_input_digest": config["authority_input_digest"],
        "core_soak_receipt_sha256": _sha256_file(receipt_path),
        "runtime_snapshot_receipts_sha256": _sha256_file(snapshot_receipts_path),
        "sample_authentication_sha256": _sha256_file(sample_authentication_path),
    }


def _core_receipt_authentication(config: Mapping[str, Any]) -> dict[str, str]:
    signature = hmac.new(
        _monitor_hmac_secret_bytes("core soak receipt terminal signature key"),
        _canonical_json(_core_receipt_authentication_payload(config)),
        hashlib.sha256,
    ).hexdigest()
    return {
        "scheme": "hmac-sha256-env",
        "key_env": MONITOR_HMAC_ENV,
        "signature": signature,
    }


def _rollback_receipt_authentication_payload(config: Mapping[str, Any]) -> dict[str, Any]:
    rollback_receipt_path = _path_from_config(config, "rollback_receipt_path")
    return {
        "schema_version": "p03-heartbeat-shadow-rollback-receipt-authentication.v1",
        "run_id": config["run_id"],
        "authority_input_digest": config["authority_input_digest"],
        "rollback_receipt_path": _relative_to_repo(rollback_receipt_path),
        "rollback_receipt_sha256": _sha256_file(rollback_receipt_path),
    }


def _rollback_authentication_intent_path(config: Mapping[str, Any]) -> Path:
    return _path_from_config(config, "state_dir") / "rollback-authentication-intent.json"


def _rollback_authentication_intent_payload(
    config: Mapping[str, Any],
    rollback_id: str,
    rollback_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_ROLLBACK_AUTHENTICATION_INTENT,
        "run_id": config["run_id"],
        "authority_input_digest": config["authority_input_digest"],
        "rollback_id": rollback_id,
        "rollback_receipt_path": _relative_to_repo(
            _path_from_config(config, "rollback_receipt_path")
        ),
        "rollback_receipt_authentication_path": _relative_to_repo(
            _path_from_config(config, "rollback_receipt_authentication_path")
        ),
    }
    if rollback_receipt_sha256 is not None:
        payload["rollback_receipt_sha256"] = rollback_receipt_sha256
    return payload


def _rollback_authentication_intent_signature(
    payload: Mapping[str, Any]
) -> dict[str, str]:
    signature = hmac.new(
        _monitor_hmac_secret_bytes("rollback authentication recovery intent key"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    return {
        "scheme": "hmac-sha256-env",
        "key_env": MONITOR_HMAC_ENV,
        "signature": signature,
    }


def _write_rollback_authentication_intent(
    config: Mapping[str, Any],
    rollback_id: str,
    rollback_receipt_sha256: str | None = None,
) -> None:
    payload = _rollback_authentication_intent_payload(
        config, rollback_id, rollback_receipt_sha256
    )
    _atomic_write_json(
        _rollback_authentication_intent_path(config),
        {**payload, "authentication": _rollback_authentication_intent_signature(payload)},
    )


def _validate_rollback_authentication_intent(
    config: Mapping[str, Any],
    intent: Mapping[str, Any],
    rollback_id: str | None = None,
    *,
    require_receipt_hash: bool = False,
) -> tuple[str, str | None]:
    observed_rollback_id = intent.get("rollback_id")
    if not isinstance(observed_rollback_id, str) or not observed_rollback_id:
        raise MonitorError("rollback authentication recovery intent rollback_id is invalid")
    if rollback_id is not None and observed_rollback_id != rollback_id:
        raise MonitorError("rollback authentication recovery intent rollback_id mismatch")
    observed_receipt_sha256 = intent.get("rollback_receipt_sha256")
    if observed_receipt_sha256 is not None and not _is_sha256(observed_receipt_sha256):
        raise MonitorError("rollback authentication recovery intent receipt hash is invalid")
    if require_receipt_hash and observed_receipt_sha256 is None:
        raise MonitorError("rollback authentication recovery intent receipt hash is missing")
    payload = _rollback_authentication_intent_payload(
        config,
        observed_rollback_id,
        str(observed_receipt_sha256) if observed_receipt_sha256 is not None else None,
    )
    if {key: intent.get(key) for key in payload} != payload:
        raise MonitorError("rollback authentication recovery intent payload mismatch")
    authentication = intent.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("rollback authentication recovery intent signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("rollback authentication recovery intent signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("rollback authentication recovery intent signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("rollback authentication recovery intent key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("rollback authentication recovery intent signature is invalid")
    expected = _rollback_authentication_intent_signature(payload)["signature"]
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("rollback authentication recovery intent signature mismatch")
    return observed_rollback_id, (
        str(observed_receipt_sha256) if observed_receipt_sha256 is not None else None
    )


def _rollback_receipt_authentication(config: Mapping[str, Any]) -> dict[str, str]:
    signature = hmac.new(
        _monitor_hmac_secret_bytes("rollback receipt terminal signature key"),
        _canonical_json(_rollback_receipt_authentication_payload(config)),
        hashlib.sha256,
    ).hexdigest()
    return {
        "scheme": "hmac-sha256-env",
        "key_env": MONITOR_HMAC_ENV,
        "signature": signature,
    }


def _write_rollback_receipt_authentication(config: Mapping[str, Any]) -> None:
    payload = _rollback_receipt_authentication_payload(config)
    _atomic_write_json(
        _path_from_config(config, "rollback_receipt_authentication_path"),
        {**payload, "authentication": _rollback_receipt_authentication(config)},
    )


def _validate_rollback_receipt_authentication(config: Mapping[str, Any]) -> None:
    path = _path_from_config(config, "rollback_receipt_authentication_path")
    if not path.exists():
        raise MonitorError("rollback receipt terminal signature is missing")
    record = _read_json(path)
    payload = _rollback_receipt_authentication_payload(config)
    if {key: record.get(key) for key in payload} != payload:
        raise MonitorError("rollback receipt terminal signature payload mismatch")
    authentication = record.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("rollback receipt terminal signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("rollback receipt terminal signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("rollback receipt terminal signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("rollback receipt terminal signature key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("rollback receipt terminal signature is invalid")
    expected = hmac.new(
        _monitor_hmac_secret_bytes("rollback receipt terminal signature key"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("rollback receipt terminal signature mismatch")


def _write_core_receipt_authentication(config: Mapping[str, Any]) -> None:
    payload = _core_receipt_authentication_payload(config)
    _atomic_write_json(
        _path_from_config(config, "core_soak_receipt_authentication_path"),
        {**payload, "authentication": _core_receipt_authentication(config)},
    )


def _validate_core_receipt_authentication(config: Mapping[str, Any]) -> None:
    authentication_path = _path_from_config(
        config, "core_soak_receipt_authentication_path"
    )
    if not authentication_path.exists():
        raise MonitorError("core soak receipt terminal signature is missing")
    record = _read_json(authentication_path)
    payload = _core_receipt_authentication_payload(config)
    observed_payload = {key: record.get(key) for key in payload}
    if observed_payload != payload:
        raise MonitorError("core soak receipt terminal signature payload mismatch")
    authentication = record.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("core soak receipt terminal signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("core soak receipt terminal signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("core soak receipt terminal signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("core soak receipt terminal signature key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("core soak receipt terminal signature is invalid")
    expected = hmac.new(
        _monitor_hmac_secret_bytes("core soak receipt terminal signature key"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("core soak receipt terminal signature mismatch")


def _require_core_receipt_authentication(config: Mapping[str, Any]) -> None:
    authentication_path = _path_from_config(
        config, "core_soak_receipt_authentication_path"
    )
    if authentication_path.exists():
        _validate_core_receipt_authentication(config)
        return
    raise MonitorError(
        "core soak receipt terminal signature is missing; reconstructed terminal "
        "evidence must not be authenticated during recovery"
    )


def _sample_authentication_path(config: Mapping[str, Any]) -> Path:
    return _path_from_config(config, "sample_authentication_path")


def _sample_authentication_payload(
    config: Mapping[str, Any],
    *,
    sample_index: int,
    sample: Mapping[str, Any],
    previous_signature: str | None,
    runtime_snapshot: object,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_SAMPLE_AUTHENTICATION,
        "run_id": config["run_id"],
        "authority": "file_artifacts",
        "authority_mode": "file_authority_shadow",
        "exact_heads": dict(config["exact_heads"]),
        "authority_input_digest": config["authority_input_digest"],
        "soak_timing": _soak_timing_payload(config),
        "sample_index": sample_index,
        "sample_sha256": _sha256_text(
            json.dumps(
                dict(sample),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        ),
        "runtime_snapshot": runtime_snapshot,
        "previous_signature": previous_signature,
    }


def _sample_authentication_signature(payload: Mapping[str, Any]) -> str:
    return hmac.new(
        _monitor_hmac_secret_bytes("sample authentication chain signature key"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _load_sample_authentication_entries(
    config: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    path = _sample_authentication_path(config)
    if not path.exists():
        return []
    record = _read_json(path)
    if record.get("schema_version") != SCHEMA_SAMPLE_AUTHENTICATION:
        raise MonitorError("sample authentication journal schema is invalid")
    if record.get("run_id") != config.get("run_id"):
        raise MonitorError("sample authentication journal run_id mismatch")
    if record.get("authority_input_digest") != config.get("authority_input_digest"):
        raise MonitorError("sample authentication journal authority digest mismatch")
    entries = record.get("entries")
    if not isinstance(entries, list):
        raise MonitorError("sample authentication journal entries are invalid")
    return entries


def _write_sample_authentication_entries(
    config: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]
) -> str:
    return _atomic_write_json(
        _sample_authentication_path(config),
        {
            "schema_version": SCHEMA_SAMPLE_AUTHENTICATION,
            "run_id": config["run_id"],
            "authority_input_digest": config["authority_input_digest"],
            "entries": [dict(entry) for entry in entries],
        },
    )


def _validate_sample_authentication_entry(
    config: Mapping[str, Any],
    entry: Mapping[str, Any],
    *,
    sample_index: int,
    sample: Mapping[str, Any] | None,
    previous_signature: str | None,
) -> str:
    if sample is None:
        payload_keys = set(
            _sample_authentication_payload(
                config,
                sample_index=sample_index,
                sample={},
                previous_signature=previous_signature,
                runtime_snapshot=entry.get("runtime_snapshot"),
            )
        )
        payload = {key: entry.get(key) for key in payload_keys}
        if payload.get("sample_index") != sample_index:
            raise MonitorError("sample authentication journal payload mismatch")
        if payload.get("previous_signature") != previous_signature:
            raise MonitorError("sample authentication journal payload mismatch")
    else:
        payload = _sample_authentication_payload(
            config,
            sample_index=sample_index,
            sample=sample,
            previous_signature=previous_signature,
            runtime_snapshot=_sample_runtime_snapshot_binding(config, sample),
        )
        observed_payload = {key: entry.get(key) for key in payload}
        if observed_payload != payload:
            raise MonitorError("sample authentication journal payload mismatch")
    authentication = entry.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("sample authentication journal signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("sample authentication journal signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("sample authentication journal signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("sample authentication journal key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("sample authentication journal signature is invalid")
    expected = _sample_authentication_signature(payload)
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("sample authentication journal signature mismatch")
    return signature


def _validate_sample_authentication_entries(
    config: Mapping[str, Any], samples: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    entries = _load_sample_authentication_entries(config)
    if len(entries) == len(samples) + 1:
        previous_signature: str | None = None
        for index, (entry, sample) in enumerate(zip(entries, samples), start=1):
            if not isinstance(entry, Mapping):
                raise MonitorError("sample authentication journal entry is invalid")
            previous_signature = _validate_sample_authentication_entry(
                config,
                entry,
                sample_index=index,
                sample=sample,
                previous_signature=previous_signature,
            )
        trailing = entries[-1]
        if not isinstance(trailing, Mapping):
            raise MonitorError("sample authentication journal entry is invalid")
        _validate_sample_authentication_entry(
            config,
            trailing,
            sample_index=len(samples) + 1,
            sample=_read_json(
                _path_from_config(config, "sample_dir")
                / f"sample-{len(samples) + 1:04d}.json"
            ),
            previous_signature=previous_signature,
        )
        raise MonitorError(
            "sample authentication journal contains authenticated sample missing "
            "from core receipt"
        )
    if len(entries) != len(samples):
        raise MonitorError("sample authentication journal does not cover core samples")
    previous_signature: str | None = None
    for index, (entry, sample) in enumerate(zip(entries, samples), start=1):
        if not isinstance(entry, Mapping):
            raise MonitorError("sample authentication journal entry is invalid")
        previous_signature = _validate_sample_authentication_entry(
            config,
            entry,
            sample_index=index,
            sample=sample,
            previous_signature=previous_signature,
        )
    return entries


def _append_sample_authentication(
    config: Mapping[str, Any], sample_index: int, sample: Mapping[str, Any]
) -> None:
    entries = list(_load_sample_authentication_entries(config))
    if len(entries) != sample_index - 1:
        raise MonitorError("sample authentication journal append point is invalid")
    previous_signature = None
    if entries:
        authentication = entries[-1].get("authentication")
        if not isinstance(authentication, Mapping):
            raise MonitorError("sample authentication journal signature is missing")
        previous_signature = authentication.get("signature")
        if not isinstance(previous_signature, str):
            raise MonitorError("sample authentication journal signature is invalid")
    payload = _sample_authentication_payload(
        config,
        sample_index=sample_index,
        sample=sample,
        previous_signature=previous_signature,
        runtime_snapshot=_sample_runtime_snapshot_binding(config, sample),
    )
    entries.append(
        {
            **payload,
            "authentication": {
                "scheme": "hmac-sha256-env",
                "key_env": MONITOR_HMAC_ENV,
                "signature": _sample_authentication_signature(payload),
            },
        }
    )
    _write_sample_authentication_entries(config, entries)


def _validate_core_sample_authentication(
    config: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    samples = receipt.get("samples")
    if not isinstance(samples, list):
        raise MonitorError("core receipt samples are invalid")
    _validate_sample_authentication_entries(config, samples)


def _stop_request_payload(
    config: Mapping[str, Any], *, requested_at: str, reason: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_STOP,
        "status": "requested",
        "run_id": config["run_id"],
        "authority_input_digest": config["authority_input_digest"],
        "exact_heads": dict(config["exact_heads"]),
        "requested_at": requested_at,
        "reason": reason,
        "scope": "local_artifact_monitor_only",
    }


def _stop_request_authentication(payload: Mapping[str, Any]) -> dict[str, str]:
    signature = hmac.new(
        _monitor_hmac_secret_bytes("stop request signature key"),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    return {"scheme": "hmac-sha256-env", "key_env": MONITOR_HMAC_ENV, "signature": signature}


def _validate_stop_request(config: Mapping[str, Any], request: Mapping[str, Any]) -> None:
    requested_at = request.get("requested_at")
    reason = request.get("reason")
    if not isinstance(requested_at, str) or not requested_at:
        raise MonitorError("stop request timestamp is invalid")
    if not isinstance(reason, str):
        raise MonitorError("stop request reason is invalid")
    payload = _stop_request_payload(config, requested_at=requested_at, reason=reason)
    observed_payload = {key: request.get(key) for key in payload}
    if observed_payload != payload:
        raise MonitorError("stop request payload mismatch")
    authentication = request.get("authentication")
    if not isinstance(authentication, Mapping):
        raise MonitorError("stop request signature is missing")
    if set(authentication) != {"scheme", "key_env", "signature"}:
        raise MonitorError("stop request signature shape is invalid")
    if authentication.get("scheme") != "hmac-sha256-env":
        raise MonitorError("stop request signature scheme is invalid")
    if authentication.get("key_env") != MONITOR_HMAC_ENV:
        raise MonitorError("stop request signature key authority is invalid")
    signature = authentication.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise MonitorError("stop request signature is invalid")
    expected = _stop_request_authentication(payload)["signature"]
    if not hmac.compare_digest(signature, expected):
        raise MonitorError("stop request signature mismatch")


def _validate_rollback_receipt_config_binding(
    config: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    require_authentication: bool = True,
) -> None:
    if receipt.get("schema_version") != "p03-heartbeat-forced-rollback-receipt.v1":
        raise MonitorError("rollback receipt schema is invalid")
    if receipt.get("status") != "pass":
        raise MonitorError("rollback receipt status is not pass")
    if receipt.get("workflow") != "heartbeat":
        raise MonitorError("rollback receipt workflow mismatch")
    if receipt.get("authority") != "file_artifacts":
        raise MonitorError("rollback receipt authority mismatch")
    if receipt.get("db_authority_enabled") is not False:
        raise MonitorError("rollback receipt db authority state mismatch")
    if receipt.get("authority_input_digest") != config.get("authority_input_digest"):
        raise MonitorError("rollback receipt authority digest does not match monitor config")
    if receipt.get("monitor_run_id") != config.get("run_id"):
        raise MonitorError("rollback receipt run_id does not match monitor config")
    if receipt.get("file_authority_view_recreated") is not True:
        raise MonitorError("rollback receipt did not recreate file authority")
    if receipt.get("shadow_database_removed") is not True:
        raise MonitorError("rollback receipt did not remove the shadow database")
    if receipt.get("recoverable_local_backup_created") is not True:
        raise MonitorError("rollback receipt did not create a recoverable backup")
    if receipt.get("parity_percent") != 100:
        raise MonitorError("rollback receipt parity percent is not 100")
    parity = receipt.get("parity")
    if not isinstance(parity, Mapping) or parity.get("status") != "pass":
        raise MonitorError("rollback receipt parity proof is invalid")
    if parity.get("percent") != 100 or parity.get("mismatch_count") != 0:
        raise MonitorError("rollback receipt parity proof is not exact")
    root = _path_from_config(config, "repo_root")
    backup_path = receipt.get("recoverable_local_backup_path")
    backup_sha = receipt.get("recoverable_local_backup_sha256")
    if not isinstance(backup_path, str) or not _is_sha256(backup_sha):
        raise MonitorError("rollback receipt backup proof is invalid")
    backup = _resolve_inside_repo(root / backup_path, root, "rollback backup path")
    if not backup.is_file() or _sha256_file(backup) != backup_sha:
        raise MonitorError("rollback receipt backup hash mismatch")
    snapshot_path = receipt.get("audit_snapshot_database")
    snapshot_sha = receipt.get("audit_snapshot_sha256")
    if not isinstance(snapshot_path, str) or not _is_sha256(snapshot_sha):
        raise MonitorError("rollback receipt audit snapshot proof is invalid")
    snapshot = _resolve_inside_repo(root / snapshot_path, root, "rollback audit snapshot path")
    if not snapshot.is_file() or _sha256_file(snapshot) != snapshot_sha:
        raise MonitorError("rollback receipt audit snapshot hash mismatch")
    _assert_shadow_database_absent(config)
    if require_authentication:
        _validate_rollback_receipt_authentication(config)


def _recover_rollback_receipt_authentication(
    config: Mapping[str, Any], rollback_id: str | None = None
) -> dict[str, Any]:
    intent_path = _rollback_authentication_intent_path(config)
    if not intent_path.exists():
        raise MonitorError("rollback authentication recovery intent is missing")
    observed_rollback_id, expected_receipt_sha256 = _validate_rollback_authentication_intent(
        config,
        _read_json(intent_path),
        rollback_id=rollback_id,
        require_receipt_hash=True,
    )
    receipt_path = _path_from_config(config, "rollback_receipt_path")
    if not receipt_path.exists():
        raise MonitorError("rollback receipt is missing")
    if _sha256_file(receipt_path) != expected_receipt_sha256:
        raise MonitorError("rollback authentication recovery intent receipt hash mismatch")
    receipt = _read_json(receipt_path)
    if receipt.get("rollback_id") != observed_rollback_id:
        raise MonitorError("rollback receipt recovery intent rollback_id mismatch")
    _validate_rollback_receipt_config_binding(
        config, receipt, require_authentication=False
    )
    _write_rollback_receipt_authentication(config)
    _validate_rollback_receipt_config_binding(config, receipt)
    return dict(receipt)


def _bind_and_authenticate_persisted_rollback_receipt(
    config: Mapping[str, Any], rollback_id: str
) -> None:
    receipt_sha256 = _sha256_file(_path_from_config(config, "rollback_receipt_path"))
    _write_rollback_authentication_intent(
        config,
        rollback_id,
        rollback_receipt_sha256=receipt_sha256,
    )
    _write_rollback_receipt_authentication(config)


def _sqlite_related_paths(database: Path) -> tuple[Path, ...]:
    return (
        database,
        database.with_name(f"{database.name}-wal"),
        database.with_name(f"{database.name}-shm"),
        database.with_name(f"{database.name}-journal"),
    )


def _assert_shadow_database_absent(config: Mapping[str, Any]) -> None:
    database = _path_from_config(config, "database_path")
    existing = [path for path in _sqlite_related_paths(database) if path.exists()]
    if existing:
        raise MonitorError("rollback receipt is stale because the shadow database exists")


def _require_sha256(label: str, value: str) -> None:
    if not _is_sha256(value):
        raise MonitorError(f"{label} must be a full lowercase SHA-256")


def _require_git_sha(label: str, value: str) -> None:
    if not _is_git_sha(value):
        raise MonitorError(f"{label} must be a full lowercase Git commit hash")


def _load_config(state_dir: Path) -> dict[str, Any]:
    config = _read_json(state_dir / "monitor-config.json")
    if config.get("schema_version") != SCHEMA_CONFIG:
        raise MonitorError("unsupported monitor config schema")
    return config


def _load_validated_resume_config(state_dir: Path) -> dict[str, Any]:
    config = _load_config(state_dir)
    _validate_resume_config_paths(state_dir, config)
    _validate_authority_input_path_identity(config)
    return config


def _validate_resume_config_paths(state_dir: Path, config: Mapping[str, Any]) -> None:
    repo_root = REPO_ROOT.resolve()
    safe_state_dir = _resolve_inside_repo(state_dir, repo_root, "state_dir")
    run_id = config.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise MonitorError("resume monitor config run_id is invalid")
    script_path = Path(__file__).resolve()
    expected_paths = {
        "repo_root": repo_root,
        "state_dir": safe_state_dir,
        "script_path": script_path,
        "database_path": repo_root / "state/agentic-os/control.db",
        "manifest_path": safe_state_dir / "heartbeat-authority-manifest.json",
        "file_shadow_cycle_receipt_path": safe_state_dir
        / "file-shadow-cycle-receipt.json",
        "core_soak_receipt_path": safe_state_dir / "core-soak-receipt.json",
        "core_soak_receipt_authentication_path": safe_state_dir
        / "core-soak-receipt-authentication.json",
        "sample_authentication_path": safe_state_dir / "sample-authentication.json",
        "first_sample_path": safe_state_dir / "first-sample.json",
        "monitor_envelope_path": safe_state_dir / "monitor-envelope.json",
        "stop_request_path": safe_state_dir / "stop-request.json",
        "rollback_receipt_path": safe_state_dir / "rollback-receipt.json",
        "rollback_receipt_authentication_path": safe_state_dir
        / "rollback-receipt-authentication.json",
        "pidfile_path": safe_state_dir / "monitor.pid",
        "daemon_log_path": safe_state_dir / "monitor-daemon.log",
        "sample_dir": safe_state_dir / "samples",
        "runtime_snapshot_dir": repo_root
        / "state/agentic-os/backups/heartbeat-shadow-soak"
        / run_id,
        "runtime_snapshot_receipts_path": safe_state_dir
        / "runtime-snapshot-receipts.json",
    }
    for key, expected in expected_paths.items():
        observed = config.get(key)
        if not isinstance(observed, str) or Path(observed).expanduser().resolve() != expected:
            raise MonitorError(f"resume monitor config path mismatch: {key}")
    if config.get("run_argv") != _command(script_path, "run", safe_state_dir):
        raise MonitorError("resume monitor config command mismatch")


def _path_from_config(config: Mapping[str, Any], key: str) -> Path:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise MonitorError(f"config missing path: {key}")
    return Path(value).expanduser().resolve()


def _assert_start_output_paths_available(config: Mapping[str, Any]) -> None:
    state_dir = _path_from_config(config, "state_dir")
    output_paths = {
        "monitor_config_path": state_dir / "monitor-config.json",
        "manifest_path": _path_from_config(config, "manifest_path"),
        "file_shadow_cycle_receipt_path": _path_from_config(
            config, "file_shadow_cycle_receipt_path"
        ),
        "core_soak_receipt_path": _path_from_config(config, "core_soak_receipt_path"),
        "sample_authentication_path": _path_from_config(
            config, "sample_authentication_path"
        ),
        "first_sample_path": _path_from_config(config, "first_sample_path"),
        "monitor_envelope_path": _path_from_config(config, "monitor_envelope_path"),
        "stop_request_path": _path_from_config(config, "stop_request_path"),
        "rollback_receipt_path": _path_from_config(config, "rollback_receipt_path"),
        "pidfile_path": _path_from_config(config, "pidfile_path"),
        "daemon_log_path": _path_from_config(config, "daemon_log_path"),
        "sample_dir": _path_from_config(config, "sample_dir"),
        "runtime_snapshot_receipts_path": _path_from_config(
            config, "runtime_snapshot_receipts_path"
        ),
        "runtime_snapshot_orphans_path": _runtime_snapshot_orphans_path(config),
    }
    for key, path in output_paths.items():
        raw_path = Path(str(config.get(key, path))).expanduser()
        if path.exists() or raw_path.is_symlink():
            raise MonitorError(f"start output path already exists: {key}")


def _command(script: Path, subcommand: str, state_dir: Path) -> list[str]:
    return [sys.executable, str(script), subcommand, "--state-dir", str(state_dir)]


def _command_text(argv: list[str]) -> str:
    return shlex.join(argv)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _load_pid(pidfile: Path) -> int | None:
    try:
        raw = pidfile.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _assert_rollback_monitor_inactive(
    config: Mapping[str, Any], pid: int | None, allow_running: bool
) -> None:
    if allow_running:
        return
    if pid is not None and _pid_alive(pid):
        raise MonitorError("refusing rollback while monitor process is active")
    try:
        envelope = _read_json(_path_from_config(config, "monitor_envelope_path"))
    except MonitorError:
        envelope = {}
    if envelope.get("status") != "running":
        return
    if pid is None:
        raise MonitorError(
            "refusing rollback while running monitor process identity is unavailable"
        )
    monitor_doc = envelope.get("monitor")
    envelope_pid = monitor_doc.get("pid") if isinstance(monitor_doc, Mapping) else None
    if not isinstance(envelope_pid, int) or envelope_pid <= 0:
        raise MonitorError(
            "refusing rollback while running monitor process identity is unavailable"
        )
    if envelope_pid != pid or not _pid_alive(pid):
        raise MonitorError(
            "refusing rollback while running monitor process identity is ambiguous"
        )


def _verified_predecessor_summary(config: Mapping[str, Any]) -> dict[str, Any]:
    lifecycle_path = _path_from_config(config, "lifecycle_receipt_path")
    validation_path = _path_from_config(config, "independent_validation_path")
    lifecycle_sha = _sha256_file(lifecycle_path)
    validation_sha = _sha256_file(validation_path)
    expected_lifecycle = str(config["expected_lifecycle_sha256"])
    expected_validation = str(config["expected_independent_validation_sha256"])
    if lifecycle_sha != expected_lifecycle:
        raise MonitorError("lifecycle receipt SHA-256 does not match Phase A contract")
    if validation_sha != expected_validation:
        raise MonitorError("independent validation SHA-256 does not match Phase A contract")

    lifecycle = _read_json(lifecycle_path)
    validation = _read_json(validation_path)
    if lifecycle.get("status") != "pass":
        raise MonitorError("predecessor lifecycle receipt is not PASS")
    rollback = lifecycle.get("rollback")
    immutable = lifecycle.get("immutable_inputs")
    soak = lifecycle.get("soak")
    if not isinstance(rollback, Mapping) or rollback.get("status") != "pass":
        raise MonitorError("predecessor rollback receipt is not PASS")
    if not isinstance(immutable, Mapping):
        raise MonitorError("predecessor immutable inputs are missing")
    if immutable.get("runtime_head") != config["exact_heads"]["runtime_head"]:
        raise MonitorError("predecessor runtime head mismatch")
    if immutable.get("db_authority_enabled_required") is not False:
        raise MonitorError("predecessor did not require DB_AUTHORITY_ENABLED=false")
    if not isinstance(soak, Mapping) or soak.get("production_cron_mutated") is not False:
        raise MonitorError("predecessor soak preparation mutated production Cron")
    db_authority = rollback.get("db_authority")
    if not isinstance(db_authority, Mapping) or db_authority.get("DB_AUTHORITY_ENABLED") is not False:
        raise MonitorError("predecessor DB authority state is ambiguous")
    if validation.get("status") != "pass" or validation.get("receipt_sha256") != lifecycle_sha:
        raise MonitorError("independent validation does not bind the lifecycle receipt")
    _validate_independent_validation_provenance(config, validation)

    return {
        "lifecycle": {
            "path": str(lifecycle_path),
            "sha256": lifecycle_sha,
            "status": lifecycle.get("status"),
            "token_material_copied": False,
        },
        "independent_validation": {
            "path": str(validation_path),
            "sha256": validation_sha,
            "status": validation.get("status"),
            "verifier_identity": validation["verifier"]["identity"],
            "implementation_head": validation.get("implementation_head"),
            "implementation_subject": validation.get("implementation_subject"),
        },
    }


def _validate_resume_predecessor_receipts(config: Mapping[str, Any]) -> None:
    expected = config.get("predecessor_receipts")
    if not isinstance(expected, Mapping):
        raise MonitorError("saved predecessor receipt summary is missing")
    current = _verified_predecessor_summary(config)
    if current != dict(expected):
        raise MonitorError("saved predecessor receipt summary mismatch")


def _validate_independent_validation_provenance(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> None:
    verifier = validation.get("verifier")
    if not isinstance(verifier, Mapping):
        raise MonitorError("independent validation verifier provenance is missing")
    for key in ("identity", "role"):
        value = verifier.get(key)
        if not isinstance(value, str) or not value:
            raise MonitorError(f"independent validation verifier {key} is missing")
    _verifier_session_key_sha256(verifier, "independent validation verifier")
    if verifier.get("identity") == "lifecycle_producer":
        raise MonitorError("independent validation must not be self-produced")
    if isinstance(validation.get("implementation_subject"), Mapping):
        _validate_independent_validation_implementation_subject(config, validation)
    else:
        implementation_head = validation.get("implementation_head")
        _validate_independent_validation_implementation_head(config, implementation_head)
    invocation = validation.get("invocation")
    if not isinstance(invocation, Mapping):
        raise MonitorError("independent validation invocation provenance is missing")
    for key in ("command", "completed_at"):
        value = invocation.get(key)
        if not isinstance(value, str) or not value:
            raise MonitorError(f"independent validation invocation {key} is missing")
    _validate_independent_validation_anchor(config, validation)


def _verifier_session_key_sha256(verifier: Mapping[str, Any], label: str) -> str:
    digest = verifier.get("session_key_sha256")
    if _is_sha256(digest):
        return str(digest)
    if "session_key" in verifier:
        raise MonitorError(f"{label} must redact session_key to session_key_sha256")
    raise MonitorError(f"{label} session_key_sha256 is missing")


def _independent_validation_implementation_head(config: Mapping[str, Any]) -> str:
    exact_heads = config.get("exact_heads")
    if not isinstance(exact_heads, Mapping):
        raise MonitorError("independent validation exact head contract is missing")
    head = exact_heads.get("monitor_implementation_head")
    if not _is_git_sha(head):
        raise MonitorError("independent validation target implementation head is missing")
    return str(head)


def _repo_root_from_config(config: Mapping[str, Any]) -> Path:
    raw = config.get("repo_root")
    return Path(str(raw)).resolve() if isinstance(raw, str) and raw else REPO_ROOT.resolve()


def _validate_independent_validation_implementation_head(
    config: Mapping[str, Any], implementation_head: Any
) -> str:
    if not _is_git_sha(implementation_head):
        raise MonitorError("independent validation implementation head mismatch")
    implementation = str(implementation_head)
    target = _independent_validation_implementation_head(config)
    if implementation == target:
        return implementation
    raise MonitorError("independent validation implementation head mismatch")


def _validate_independent_validation_implementation_subject(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> str:
    subject = validation.get("implementation_subject")
    if not isinstance(subject, Mapping):
        raise MonitorError("independent validation implementation subject is missing")
    if subject.get("scheme") != INDEPENDENT_VALIDATION_SUBJECT_SCHEME:
        raise MonitorError("independent validation implementation subject scheme mismatch")
    tree_sha = subject.get("tree_sha256")
    if not _is_sha256(tree_sha):
        raise MonitorError("independent validation implementation subject hash mismatch")
    excluded_paths = subject.get("excluded_paths")
    if (
        not isinstance(excluded_paths, list)
        or not excluded_paths
        or any(not isinstance(path, str) or not path for path in excluded_paths)
    ):
        raise MonitorError("independent validation implementation subject exclusions mismatch")
    expected_exclusions = _validation_subject_excluded_paths(config, validation)
    if sorted(excluded_paths) != expected_exclusions:
        raise MonitorError("independent validation implementation subject exclusions mismatch")
    synthetic_commit = subject.get("reviewed_synthetic_commit")
    if synthetic_commit is not None and not _is_git_sha(synthetic_commit):
        raise MonitorError("independent validation reviewed synthetic commit is invalid")
    reviewed_head = subject.get("reviewed_head")
    if reviewed_head is not None and not _is_git_sha(reviewed_head):
        raise MonitorError("independent validation reviewed head is invalid")
    current = _git_tracked_tree_subject_sha256(
        _repo_root_from_config(config),
        expected_exclusions,
    )
    if not hmac.compare_digest(str(tree_sha), current):
        raise MonitorError("independent validation implementation subject mismatch")
    return str(tree_sha)


def _validate_independent_validation_anchor(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> None:
    repo_root = _repo_root_from_config(config)
    anchor = validation.get("authenticated_record")
    if not isinstance(anchor, Mapping):
        raise MonitorError("independent validation authenticated record is missing")
    raw_path = anchor.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise MonitorError("independent validation authenticated record path is missing")
    anchor_path = Path(raw_path)
    if not anchor_path.is_absolute():
        anchor_path = (repo_root / anchor_path).resolve()
    else:
        anchor_path = anchor_path.resolve()
    try:
        anchor_path.relative_to(repo_root)
    except ValueError as exc:
        raise MonitorError(
            "independent validation authenticated record must be repo-bound"
        ) from exc
    expected_sha = str(anchor.get("sha256", ""))
    if _sha256_file(anchor_path) != expected_sha:
        raise MonitorError("independent validation authenticated record hash mismatch")
    record = _read_json(anchor_path)
    if record.get("schema_version") != "agentic-os.independent-validation-anchor.v1":
        raise MonitorError("independent validation authenticated record schema mismatch")
    _validate_anchor_signature(record)
    if record.get("record_authority") == "lifecycle_producer":
        raise MonitorError("independent validation authenticated record is self-produced")
    if record.get("validation_verdict") != "pass":
        raise MonitorError("independent validation authenticated record is not PASS")
    if record.get("receipt_sha256") != validation.get("receipt_sha256"):
        raise MonitorError("independent validation authenticated record receipt mismatch")
    if isinstance(validation.get("implementation_subject"), Mapping):
        if record.get("implementation_subject") != validation.get("implementation_subject"):
            raise MonitorError(
                "independent validation authenticated record implementation mismatch"
            )
    elif record.get("implementation_head") != validation.get("implementation_head"):
        raise MonitorError(
            "independent validation authenticated record implementation mismatch"
        )
    verifier = validation["verifier"]
    record_verifier = record.get("verifier")
    if not isinstance(record_verifier, Mapping):
        raise MonitorError("independent validation authenticated record verifier missing")
    for key in ("identity", "role"):
        if record_verifier.get(key) != verifier.get(key):
            raise MonitorError(
                f"independent validation authenticated record verifier {key} mismatch"
            )
    record_session_digest = _verifier_session_key_sha256(
        record_verifier,
        "independent validation authenticated record verifier",
    )
    validation_session_digest = _verifier_session_key_sha256(
        verifier,
        "independent validation verifier",
    )
    if record_session_digest != validation_session_digest:
        raise MonitorError(
            "independent validation authenticated record verifier session digest mismatch"
        )


def _envelope(
    *,
    config: Mapping[str, Any],
    status: str,
    violation: str | None = None,
    violations: Sequence[str] | None = None,
    sample: Mapping[str, Any] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    state_dir = _path_from_config(config, "state_dir")
    script_path = _path_from_config(config, "script_path")
    pidfile = _path_from_config(config, "pidfile_path")
    core_receipt_path = _path_from_config(config, "core_soak_receipt_path")
    snapshot_receipts_path = _path_from_config(config, "runtime_snapshot_receipts_path")
    receipt: dict[str, Any] | None = None
    if status == "complete" and not core_receipt_path.exists():
        raise MonitorError("terminal monitor status requires core receipt")
    rollback_receipt_path = _path_from_config(config, "rollback_receipt_path")
    if status == "rolled_back":
        if not rollback_receipt_path.exists():
            raise MonitorError("terminal monitor status requires rollback receipt")
        rollback_receipt = _read_json(rollback_receipt_path)
        try:
            _validate_rollback_receipt_config_binding(config, rollback_receipt)
        except MonitorError as exc:
            if "terminal signature is missing" not in str(exc):
                raise
            rollback_receipt = _recover_rollback_receipt_authentication(config)
    if core_receipt_path.exists():
        try:
            receipt = _read_json(core_receipt_path)
            validate_heartbeat_soak_receipt(receipt)
            _validate_receipt_config_binding(config, receipt)
            if status == "complete" and receipt.get("status") != "complete":
                raise MonitorError("terminal monitor status requires complete core receipt")
            if status == "complete" and not snapshot_receipts_path.exists():
                raise MonitorError("terminal monitor status requires runtime snapshot ledger")
            if status in {"running", "complete", "first_sample_pass"}:
                _validate_core_sample_authentication(config, receipt)
        except (HeartbeatShadowError, MonitorError):
            if status != "failed_closed":
                raise
            receipt = None
    snapshot_doc: dict[str, Any] | None = None
    if snapshot_receipts_path.exists():
        try:
            snapshot_doc = _read_json(snapshot_receipts_path)
        except MonitorError:
            if status != "failed_closed":
                raise
            snapshot_doc = None
    samples = receipt.get("samples", []) if receipt else []
    if snapshot_doc:
        try:
            snapshots = _validate_runtime_snapshot_receipts(
                config,
                snapshot_doc,
                samples=samples if receipt else None,
                allow_trailing=status != "complete",
            )
        except MonitorError:
            if status != "failed_closed":
                raise
            snapshots = []
    else:
        snapshots = []
    if status == "complete":
        _validate_core_receipt_authentication(config)
    first_sample = samples[0] if samples else None
    latest_sample = sample if sample is not None else (samples[-1] if samples else None)
    last_sampled_at = (
        latest_sample.get("sampled_at_epoch_ms")
        if isinstance(latest_sample, Mapping)
        else None
    )
    last_sampled_monotonic = (
        latest_sample.get("sampled_at_monotonic_ms")
        if isinstance(latest_sample, Mapping)
        else None
    )
    interval_ms = int(config["sample_interval_seconds"]) * 1000
    next_due = last_sampled_at + interval_ms if isinstance(last_sampled_at, int) else None
    allowed_latest = (
        last_sampled_at + interval_ms * 2 if isinstance(last_sampled_at, int) else None
    )
    next_due_monotonic = (
        last_sampled_monotonic + interval_ms
        if isinstance(last_sampled_monotonic, int)
        else None
    )
    allowed_latest_monotonic = (
        last_sampled_monotonic + interval_ms * 2
        if isinstance(last_sampled_monotonic, int)
        else None
    )
    current_pid = os.getpid()
    loaded_pid = _load_pid(pidfile)
    pid = loaded_pid if loaded_pid is not None else current_pid
    terminal_status = status in {"complete", "failed_closed", "rolled_back", "stopped"}
    no_daemon_status = status == "first_sample_pass"
    process_alive = _pid_alive(pid) if loaded_pid is not None else False
    if (terminal_status or no_daemon_status) and pid == current_pid:
        process_alive = False
    argv = list(config.get("run_argv", [])) or _command(script_path, "run", state_dir)
    stop_argv = _command(script_path, "stop", state_dir)
    rollback_argv = _command(script_path, "rollback", state_dir)
    status_argv = _command(script_path, "status", state_dir)
    violations_list = (
        [str(item) for item in violations]
        if violations is not None
        else ([] if violation is None else [violation])
    )
    monitor_doc = {
        "pid": pid,
        "pidfile": str(pidfile),
        "process_identity_observed_at": _utc_now(),
        "terminal_status_expected_after_write": terminal_status,
        "script_path": str(script_path),
        "script_sha256": _sha256_file(script_path),
        "argv": argv,
        "argv_sha256": _sha256_text(_command_text(argv)),
        "python_executable": sys.executable,
        "run_command": _command_text(argv),
        "stop_command": _command_text(stop_argv),
        "rollback_command": _command_text(rollback_argv),
        "status_command": _command_text(status_argv),
        "sample_interval_seconds": config["sample_interval_seconds"],
        "duration_hours": config["duration_hours"],
        "deadline_epoch_ms": receipt.get("deadline_epoch_ms") if receipt else None,
    }
    if not no_daemon_status:
        monitor_doc["process_alive"] = process_alive
    envelope = {
        "schema_version": SCHEMA_ENVELOPE,
        "status": status,
        "workflow": "heartbeat",
        "run_id": config["run_id"],
        "authority": "file_artifacts",
        "authority_mode": "file_authority_shadow",
        "scope": "artifact_worktree_only",
        "db_authority_enabled": False,
        "production_config_mutated": False,
        "production_cron_mutated": False,
        "production_gateway_mutated": False,
        "updated_at": _utc_now(),
        "exact_heads": config["exact_heads"],
        "predecessor_receipts": config["predecessor_receipts"],
        "monitor": monitor_doc,
        "receipts": {
            "state_dir": str(state_dir),
            "baseline_path": config["baseline_path"],
            "heartbeat_file": config["heartbeat_file"],
            "live_config_path": config["live_config_path"],
            "manifest_path": config["manifest_path"],
            "file_shadow_cycle_receipt_path": config["file_shadow_cycle_receipt_path"],
            "core_soak_receipt_path": config["core_soak_receipt_path"],
            "core_soak_receipt_authentication_path": config[
                "core_soak_receipt_authentication_path"
            ],
            "sample_authentication_path": config["sample_authentication_path"],
            "first_sample_path": config["first_sample_path"],
            "monitor_envelope_path": config["monitor_envelope_path"],
            "runtime_snapshot_receipts_path": config["runtime_snapshot_receipts_path"],
            "stop_request_path": config["stop_request_path"],
            "rollback_receipt_path": config["rollback_receipt_path"],
        },
        "runtime_snapshots": {
            "receipts_path": str(snapshot_receipts_path),
            "snapshots_count": len(snapshots),
            "latest_snapshot": snapshots[-1] if snapshots else None,
            "local_recovery_only": True,
            "packaging_retrieval_denied": True,
        },
        "coverage": {
            "samples_count": len(samples),
            "last_sampled_at_epoch_ms": last_sampled_at,
            "last_sampled_at_monotonic_ms": last_sampled_monotonic,
            "next_due_epoch_ms": next_due,
            "next_due_monotonic_ms": next_due_monotonic,
            "allowed_latest_epoch_ms": allowed_latest,
            "allowed_latest_monotonic_ms": allowed_latest_monotonic,
            "coverage_gap_detected": "coverage_gap" in violations_list,
        },
        "first_sample": first_sample,
        "latest_sample": latest_sample,
        "stop_rollback_contract": {
            "pre_phase_c_contract": "command_availability_only_while_soak_running",
            "stop_request_receipt_required_after_explicit_stop": True,
            "rollback_receipt_required_after_monitor_stopped": True,
            "stop_request_exists": _path_from_config(config, "stop_request_path").exists(),
            "rollback_receipt_exists": _path_from_config(config, "rollback_receipt_path").exists(),
        },
        "violations": violations_list,
        "note": note,
    }
    return envelope


def _persist_envelope(
    config: Mapping[str, Any],
    *,
    status: str,
    violation: str | None = None,
    sample: Mapping[str, Any] | None = None,
    note: str | None = None,
) -> str:
    envelope = _envelope(
        config=config,
        status=status,
        violation=violation,
        sample=sample,
        note=note,
    )
    return _atomic_write_json(_path_from_config(config, "monitor_envelope_path"), envelope)


def _running_status_failure(envelope: Mapping[str, Any]) -> tuple[str, str] | None:
    if envelope.get("status") != "running":
        return None
    monitor = envelope.get("monitor")
    if not isinstance(monitor, Mapping) or monitor.get("process_alive") is not True:
        return ("monitor_process_dead", "running monitor process is not alive")
    coverage = envelope.get("coverage")
    if isinstance(coverage, Mapping):
        allowed_latest = coverage.get("allowed_latest_epoch_ms")
        if isinstance(allowed_latest, int) and _epoch_ms() > allowed_latest:
            return ("coverage_gap", "running monitor sample window is overdue")
        last_monotonic = coverage.get("last_sampled_at_monotonic_ms")
        allowed_latest_monotonic = coverage.get("allowed_latest_monotonic_ms")
        if not isinstance(last_monotonic, int) or not isinstance(
            allowed_latest_monotonic, int
        ):
            return (
                "coverage_gap",
                "running monitor sample monotonic deadline is missing",
            )
        now_monotonic = time.monotonic_ns() // 1_000_000
        if now_monotonic < last_monotonic:
            return (
                "coverage_gap",
                "running monitor monotonic clock moved backward or rebooted",
            )
        if now_monotonic > allowed_latest_monotonic:
            return (
                "coverage_gap",
                "running monitor sample monotonic window is overdue",
            )
    return None


def _write_pidfile(config: Mapping[str, Any]) -> None:
    pidfile = _path_from_config(config, "pidfile_path")
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text(f"{os.getpid()}\n", encoding="utf-8")


def _wait_for_daemon_ready(config: Mapping[str, Any], process: subprocess.Popen[bytes]) -> None:
    envelope_path = _path_from_config(config, "monitor_envelope_path")
    deadline = time.monotonic() + DAEMON_READY_TIMEOUT_SECONDS
    last_status = None
    while time.monotonic() < deadline:
        if envelope_path.exists():
            try:
                envelope = _read_json(envelope_path)
            except MonitorError:
                envelope = {}
            last_status = envelope.get("status")
            if last_status == "failed_closed":
                raise MonitorError("monitor daemon failed closed before readiness")
            monitor = envelope.get("monitor")
            if (
                last_status == "running"
                and isinstance(monitor, Mapping)
                and monitor.get("pid") == process.pid
                and process.poll() is None
            ):
                return
        exit_code = process.poll()
        if exit_code is not None:
            raise MonitorError(f"monitor daemon exited before readiness: {exit_code}")
        time.sleep(0.05)
    raise MonitorError(
        f"monitor daemon did not report readiness; last_status={last_status!r}"
    )


def _assert_no_active_monitor(state_dir: Path) -> None:
    pidfile = state_dir / "monitor.pid"
    pid = _load_pid(pidfile)
    if pid is not None and _pid_alive(pid):
        raise MonitorError(f"monitor already active with pid {pid}")
    if (state_dir / "stop-request.json").exists():
        raise MonitorError("stale stop request blocks monitor start")
    if (state_dir / "monitor-start-reservation.json").exists():
        raise MonitorError("monitor start reservation already exists")


def _resolve_start_state_dir(state_dir: Path, repo_root: Path) -> Path:
    raw = state_dir.expanduser()
    if raw.is_symlink():
        raise MonitorError("state_dir must not be a symlink")
    return _resolve_inside_repo(raw, repo_root, "state_dir")


def _reserve_monitor_state(state_dir: Path) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    reservation = state_dir / "monitor-start-reservation.json"
    payload = _canonical_json(
        {
            "schema_version": SCHEMA_START_RESERVATION,
            "status": "reserved",
            "reserved_at": _utc_now(),
            "pid": os.getpid(),
        }
    )
    try:
        fd = os.open(str(reservation), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise MonitorError("monitor start reservation already exists") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    except Exception:
        try:
            reservation.unlink()
        finally:
            raise
    return reservation


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=DAEMON_READY_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _build_config(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = REPO_ROOT.resolve()
    state_dir = _resolve_inside_repo(args.state_dir, repo_root, "state_dir")
    script_path = Path(__file__).resolve()
    interval = args.interval_seconds
    duration = args.duration_hours
    if not 60 <= interval <= 3600:
        raise MonitorError("interval must be within 60-3600 seconds")
    if not 24 <= duration <= 72:
        raise MonitorError("duration must be within 24-72 hours")
    for label, value in (
        ("runtime_head", args.runtime_head),
        ("agentic_os_evidence_head", args.agentic_os_evidence_head),
        ("implementation_base", args.implementation_base),
        ("monitor_implementation_head", args.monitor_implementation_head),
    ):
        _require_git_sha(label, value)
    for label, value in (
        ("expected_lifecycle_sha256", args.expected_lifecycle_sha256),
        (
            "expected_independent_validation_sha256",
            args.expected_independent_validation_sha256,
        ),
    ):
        _require_sha256(label, value)
    baseline = _resolve_inside_repo(args.baseline_path, repo_root, "baseline_path")
    heartbeat = _resolve_inside_repo(args.heartbeat_file, repo_root, "heartbeat_file")
    live_config = _resolve_inside_repo(args.live_config_path, repo_root, "live_config_path")
    lifecycle = _resolve_inside_repo(
        args.lifecycle_receipt_path, repo_root, "lifecycle_receipt_path"
    )
    validation = _resolve_inside_repo(
        args.independent_validation_path,
        repo_root,
        "independent_validation_path",
    )
    config = {
        "schema_version": SCHEMA_CONFIG,
        "run_id": args.run_id,
        "repo_root": str(repo_root),
        "state_dir": str(state_dir),
        "script_path": str(script_path),
        "baseline_path": str(baseline),
        "heartbeat_file": str(heartbeat),
        "live_config_path": str(live_config),
        "database_path": str(repo_root / "state/agentic-os/control.db"),
        "manifest_path": str(state_dir / "heartbeat-authority-manifest.json"),
        "file_shadow_cycle_receipt_path": str(state_dir / "file-shadow-cycle-receipt.json"),
        "core_soak_receipt_path": str(state_dir / "core-soak-receipt.json"),
        "core_soak_receipt_authentication_path": str(
            state_dir / "core-soak-receipt-authentication.json"
        ),
        "sample_authentication_path": str(state_dir / "sample-authentication.json"),
        "first_sample_path": str(state_dir / "first-sample.json"),
        "monitor_envelope_path": str(state_dir / "monitor-envelope.json"),
        "stop_request_path": str(state_dir / "stop-request.json"),
        "rollback_receipt_path": str(state_dir / "rollback-receipt.json"),
        "rollback_receipt_authentication_path": str(
            state_dir / "rollback-receipt-authentication.json"
        ),
        "pidfile_path": str(state_dir / "monitor.pid"),
        "daemon_log_path": str(state_dir / "monitor-daemon.log"),
        "sample_dir": str(state_dir / "samples"),
        "runtime_snapshot_dir": str(
            repo_root / "state/agentic-os/backups/heartbeat-shadow-soak" / args.run_id
        ),
        "runtime_snapshot_receipts_path": str(state_dir / "runtime-snapshot-receipts.json"),
        "duration_hours": duration,
        "sample_interval_seconds": interval,
        "file_shadow_run_id": f"{args.run_id}-file-shadow",
        "expected_lifecycle_sha256": args.expected_lifecycle_sha256,
        "expected_independent_validation_sha256": (
            args.expected_independent_validation_sha256
        ),
        "lifecycle_receipt_path": str(lifecycle),
        "independent_validation_path": str(validation),
        "authority_input_paths": _authority_input_path_identities(
            baseline_path=baseline,
            heartbeat_file=heartbeat,
            live_config_path=live_config,
        ),
        "exact_heads": {
            "runtime_head": args.runtime_head,
            "agentic_os_evidence_head": args.agentic_os_evidence_head,
            "implementation_base": args.implementation_base,
            "monitor_implementation_head": args.monitor_implementation_head,
        },
        "run_argv": _command(script_path, "run", state_dir),
    }
    config["authority_input_paths_authentication"] = (
        _authority_input_path_authentication(config)
    )
    config["predecessor_receipts"] = _verified_predecessor_summary(config)
    return config


def _sample(config: Mapping[str, Any], sampled_at_epoch_ms: int) -> dict[str, Any]:
    _validate_authority_input_path_identity(config)
    sampled_at_monotonic_ms = time.monotonic_ns() // 1_000_000
    snapshot_path = _runtime_snapshot_path(config, sampled_at_epoch_ms)
    try:
        snapshot = snapshot_heartbeat_runtime_authority_database(
            source_database=_path_from_config(config, "database_path"),
            snapshot_database=snapshot_path,
            repo_root_path=REPO_ROOT,
        )
        _append_runtime_snapshot_receipt(config, snapshot)
    except (HeartbeatShadowError, MonitorError, OSError):
        return _failed_runtime_observation_sample(
            config,
            sampled_at_epoch_ms,
            sampled_at_monotonic_ms,
        )
    return heartbeat_parity_sample(
        baseline_path=_path_from_config(config, "baseline_path"),
        heartbeat_file=_path_from_config(config, "heartbeat_file"),
        live_config_path=_path_from_config(config, "live_config_path"),
        projected_artifact=_path_from_config(config, "manifest_path"),
        run_id=str(config["file_shadow_run_id"]),
        authority_input_digest=str(config["authority_input_digest"]),
        authority_mode="file_authority_shadow",
        database=_path_from_config(config, "database_path"),
        runtime_audit_database=snapshot_path,
        sampled_at_epoch_ms=sampled_at_epoch_ms,
        sampled_at_monotonic_ms=sampled_at_monotonic_ms,
        repo_root_path=REPO_ROOT,
    )


def _runtime_snapshot_path(config: Mapping[str, Any], sampled_at_epoch_ms: int) -> Path:
    snapshot_dir = _path_from_config(config, "runtime_snapshot_dir")
    return snapshot_dir / f"sample-{sampled_at_epoch_ms}.db"


def _snapshot_epoch(snapshot_database: object) -> int:
    if not isinstance(snapshot_database, str) or "/" not in snapshot_database:
        raise MonitorError("runtime snapshot database path is invalid")
    name = Path(snapshot_database).name
    if not name.startswith("sample-") or not name.endswith(".db"):
        raise MonitorError("runtime snapshot database path is not sample-bound")
    try:
        return int(name.removeprefix("sample-").removesuffix(".db"))
    except ValueError as exc:
        raise MonitorError("runtime snapshot database epoch is invalid") from exc


def _validate_runtime_snapshot_entry(
    config: Mapping[str, Any],
    entry: object,
    *,
    sample: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        raise MonitorError("runtime snapshot entry must be an object")
    if entry.get("schema_version") != "p03-heartbeat-runtime-authority-snapshot.v1":
        raise MonitorError("runtime snapshot entry schema is invalid")
    if (
        entry.get("status") != "pass"
        or entry.get("authority") != "file_artifacts"
        or entry.get("db_authority_enabled") is not False
        or entry.get("source_database") != "state/agentic-os/control.db"
        or entry.get("snapshot_sidecars_present") is not False
        or entry.get("local_recovery_only") is not True
        or entry.get("packaging_retrieval_denied") is not True
    ):
        raise MonitorError("runtime snapshot entry contract is invalid")
    snapshot_database = entry.get("snapshot_database")
    epoch = _snapshot_epoch(snapshot_database)
    if sample is not None and sample.get("sampled_at_epoch_ms") != epoch:
        raise MonitorError("runtime snapshot entry does not match its sample")
    expected_path = _runtime_snapshot_path(config, epoch).resolve()
    raw_path = Path(str(snapshot_database))
    observed_path = _resolve_inside_repo(
        raw_path if raw_path.is_absolute() else REPO_ROOT / raw_path,
        REPO_ROOT,
        "runtime snapshot",
    )
    if observed_path != expected_path:
        raise MonitorError("runtime snapshot path does not match the monitor config")
    if not observed_path.is_file() or observed_path.is_symlink():
        raise MonitorError("runtime snapshot file is missing or unsafe")
    if entry.get("snapshot_sha256") != _sha256_file(observed_path):
        raise MonitorError("runtime snapshot file hash mismatch")
    try:
        observed_counts = _runtime_authority_counts(observed_path)
    except HeartbeatShadowError as exc:
        raise MonitorError("runtime snapshot authority counts are invalid") from exc
    if entry.get("runtime_authority_counts") != observed_counts:
        raise MonitorError("runtime snapshot authority counts mismatch")
    if (
        sample is not None
        and sample.get("runtime_authority_counts_observed") is True
        and sample.get("runtime_authority_counts") != observed_counts
    ):
        raise MonitorError("runtime snapshot counts do not match its sample")
    return dict(entry)


def _sample_runtime_snapshot_binding(
    config: Mapping[str, Any], sample: Mapping[str, Any]
) -> dict[str, Any] | None:
    if sample.get("runtime_authority_counts_observed") is not True:
        return None
    sampled_at = sample.get("sampled_at_epoch_ms")
    if type(sampled_at) is not int or sampled_at <= 0:
        raise MonitorError("runtime snapshot sample epoch is invalid")
    path = _path_from_config(config, "runtime_snapshot_receipts_path")
    if not path.exists():
        raise MonitorError("runtime snapshot receipt is missing for authenticated sample")
    document = _read_json(path)
    if document.get("schema_version") != SCHEMA_SNAPSHOTS:
        raise MonitorError("unsupported runtime snapshot receipt schema")
    if document.get("run_id") != config.get("run_id"):
        raise MonitorError("runtime snapshot receipts run_id mismatch")
    raw_snapshots = document.get("snapshots")
    if not isinstance(raw_snapshots, list):
        raise MonitorError("runtime snapshot receipts must be a list")
    matches: list[dict[str, Any]] = []
    for raw_entry in raw_snapshots:
        if not isinstance(raw_entry, Mapping):
            raise MonitorError("runtime snapshot entry must be an object")
        try:
            if _snapshot_epoch(raw_entry.get("snapshot_database")) == sampled_at:
                matches.append(
                    _validate_runtime_snapshot_entry(config, raw_entry, sample=sample)
                )
        except MonitorError:
            raise
    if len(matches) != 1:
        raise MonitorError("runtime snapshot receipt does not match authenticated sample")
    entry = matches[0]
    counts = entry.get("runtime_authority_counts")
    if not isinstance(counts, Mapping) or set(counts) != set(RUNTIME_AUTHORITY_COUNT_KEYS):
        raise MonitorError("runtime snapshot authority counts are invalid")
    return {
        "schema_version": "p03-heartbeat-runtime-snapshot-sample-binding.v1",
        "snapshot_database": entry["snapshot_database"],
        "snapshot_sha256": entry["snapshot_sha256"],
        "runtime_authority_counts": dict(counts),
    }


def _validate_runtime_snapshot_receipts(
    config: Mapping[str, Any],
    document: Mapping[str, Any],
    *,
    samples: Sequence[Mapping[str, Any]] | None = None,
    allow_trailing: bool = True,
) -> list[dict[str, Any]]:
    if document.get("schema_version") != SCHEMA_SNAPSHOTS:
        raise MonitorError("unsupported runtime snapshot receipt schema")
    if document.get("run_id") != config.get("run_id"):
        raise MonitorError("runtime snapshot receipts run_id mismatch")
    if document.get("scope") != "local_recovery_only":
        raise MonitorError("runtime snapshot receipts scope is invalid")
    raw_snapshots = document.get("snapshots")
    if not isinstance(raw_snapshots, list):
        raise MonitorError("runtime snapshot receipts must be a list")
    trailing_snapshot: object | None = None
    if samples is not None and len(raw_snapshots) == len(samples) + 1:
        if not allow_trailing:
            raise MonitorError("runtime snapshot trailing receipt is unreconciled")
        trailing_snapshot = raw_snapshots[-1]
        raw_snapshots = raw_snapshots[:-1]
    if samples is not None and len(raw_snapshots) != len(samples):
        raise MonitorError("runtime snapshot receipts do not match sample count")
    snapshots: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for index, raw_entry in enumerate(raw_snapshots):
        sample = samples[index] if samples is not None else None
        entry = _validate_runtime_snapshot_entry(config, raw_entry, sample=sample)
        snapshot_database = str(entry["snapshot_database"])
        if snapshot_database in seen_paths:
            raise MonitorError("duplicate runtime snapshot receipt path")
        seen_paths.add(snapshot_database)
        snapshots.append(entry)
    if trailing_snapshot is not None:
        entry = _validate_runtime_snapshot_entry(config, trailing_snapshot)
        snapshot_database = str(entry["snapshot_database"])
        if snapshot_database in seen_paths:
            raise MonitorError("duplicate runtime snapshot receipt path")
        if samples:
            latest_sampled_at = samples[-1].get("sampled_at_epoch_ms")
            if (
                isinstance(latest_sampled_at, int)
                and _snapshot_epoch(entry["snapshot_database"]) <= latest_sampled_at
            ):
                raise MonitorError("runtime snapshot trailing receipt is not newer than samples")
    return snapshots


def _runtime_snapshot_orphans_path(config: Mapping[str, Any]) -> Path:
    return _path_from_config(config, "runtime_snapshot_receipts_path").with_name(
        "runtime-snapshot-orphans.json"
    )


def _archive_runtime_snapshot_orphan(
    config: Mapping[str, Any],
    entry: Mapping[str, Any],
    *,
    reason: str,
) -> None:
    path = _runtime_snapshot_orphans_path(config)
    if path.is_symlink():
        raise MonitorError("runtime snapshot orphan archive path must not be a symlink")
    if path.exists():
        document = _read_json(path)
        if document.get("schema_version") != f"{SCHEMA_SNAPSHOTS}.orphans":
            raise MonitorError("runtime snapshot orphan archive schema is invalid")
        if document.get("run_id") != config.get("run_id"):
            raise MonitorError("runtime snapshot orphan archive run_id mismatch")
        orphans = document.get("orphans")
        if not isinstance(orphans, list):
            raise MonitorError("runtime snapshot orphan archive must be a list")
    else:
        document = {
            "schema_version": f"{SCHEMA_SNAPSHOTS}.orphans",
            "run_id": config["run_id"],
            "scope": "local_recovery_only",
            "orphans": [],
        }
        orphans = document["orphans"]
    snapshot_database = str(entry.get("snapshot_database"))
    snapshot_sha256 = str(entry.get("snapshot_sha256"))
    for orphan in orphans:
        if not isinstance(orphan, Mapping):
            raise MonitorError("runtime snapshot orphan archive entry is invalid")
        archived = orphan.get("snapshot")
        if not isinstance(archived, Mapping):
            raise MonitorError("runtime snapshot orphan archive entry is invalid")
        if (
            orphan.get("reason") == reason
            and archived.get("snapshot_database") == snapshot_database
            and archived.get("snapshot_sha256") == snapshot_sha256
        ):
            document["updated_at"] = _utc_now()
            _atomic_write_json(path, document)
            return
    orphans.append(
        {
            "reason": reason,
            "archived_at": _utc_now(),
            "snapshot": dict(entry),
        }
    )
    document["updated_at"] = _utc_now()
    _atomic_write_json(path, document)


def _core_samples_for_snapshot_reconciliation(
    config: Mapping[str, Any],
) -> list[Mapping[str, Any]] | None:
    core_receipt_path = _path_from_config(config, "core_soak_receipt_path")
    if not core_receipt_path.exists():
        return None
    receipt = _read_json(core_receipt_path)
    validate_heartbeat_soak_receipt(receipt)
    _validate_receipt_config_binding(config, receipt)
    samples = receipt.get("samples")
    if not isinstance(samples, list):
        raise MonitorError("core receipt samples are invalid")
    return samples


def _append_runtime_snapshot_receipt(
    config: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> None:
    path = _path_from_config(config, "runtime_snapshot_receipts_path")
    if path.exists():
        document = _read_json(path)
        samples = _core_samples_for_snapshot_reconciliation(config)
        snapshots = _validate_runtime_snapshot_receipts(
            config,
            document,
            samples=samples,
        )
        raw_snapshots = document.get("snapshots")
        if (
            samples is not None
            and isinstance(raw_snapshots, list)
            and len(raw_snapshots) == len(samples) + 1
        ):
            trailing = _validate_runtime_snapshot_entry(config, raw_snapshots[-1])
            _archive_runtime_snapshot_orphan(
                config,
                trailing,
                reason="unmatched_trailing_before_append",
            )
            document["snapshots"] = snapshots
    else:
        document = {
            "schema_version": SCHEMA_SNAPSHOTS,
            "run_id": config["run_id"],
            "scope": "local_recovery_only",
            "snapshots": [],
        }
        snapshots = document["snapshots"]
    snapshots.append(dict(snapshot))
    document["snapshots"] = snapshots
    _validate_runtime_snapshot_receipts(config, document)
    document["updated_at"] = _utc_now()
    _atomic_write_json(path, document)


def _failed_runtime_observation_sample(
    config: Mapping[str, Any],
    sampled_at_epoch_ms: int,
    sampled_at_monotonic_ms: int,
) -> dict[str, Any]:
    counts = {
        "lease_rows": 0,
        "spawn_request_rows": 0,
        "session_rows": 0,
        "lifecycle_rpc_intent_rows": 0,
        "duplicate_spawn_identity_groups": 0,
    }
    return {
        "sampled_at_epoch_ms": sampled_at_epoch_ms,
        "sampled_at_monotonic_ms": sampled_at_monotonic_ms,
        "status": "fail",
        "authority_mode": "file_authority_shadow",
        "expected_authority_input_digest": str(config["authority_input_digest"]),
        "observed_authority_input_digest": str(config["authority_input_digest"]),
        "parity_status": "fail",
        "parity_percent": 0,
        "db_authority_enabled": False,
        "runtime_authority_counts": counts,
        "runtime_authority_counts_observed": False,
        "observation_error": "runtime_authority_audit_error",
        "counters": {
            "duplicate_spawn": 0,
            "orphan_lease": 0,
            "unknown_or_unowned_session": 1,
            "privacy_violation": 0,
            "projection_drift": 0,
        },
    }


def _persist_sample(config: Mapping[str, Any], index: int, sample: Mapping[str, Any]) -> None:
    sample_dir = _path_from_config(config, "sample_dir")
    _atomic_write_json(sample_dir / f"sample-{index:04d}.json", sample)


def _first_sample(config: dict[str, Any]) -> dict[str, Any]:
    state_dir = _path_from_config(config, "state_dir")
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "samples").mkdir(parents=True, exist_ok=True)
    started = _epoch_ms()
    started_monotonic = time.monotonic_ns() // 1_000_000
    cycle = run_heartbeat_file_shadow_cycle(
        baseline_path=_path_from_config(config, "baseline_path"),
        heartbeat_file=_path_from_config(config, "heartbeat_file"),
        live_config_path=_path_from_config(config, "live_config_path"),
        manifest_path=_path_from_config(config, "manifest_path"),
        run_id=str(config["file_shadow_run_id"]),
        database=_path_from_config(config, "database_path"),
        repo_root_path=REPO_ROOT,
        observed_at_epoch_ms=started,
    )
    _atomic_write_json(_path_from_config(config, "file_shadow_cycle_receipt_path"), cycle)
    config["authority_input_digest"] = cycle["authority_input_digest"]
    receipt = new_heartbeat_soak_receipt(
        run_id=str(config["run_id"]),
        authority_input_digest=str(config["authority_input_digest"]),
        started_at_epoch_ms=started,
        started_at_monotonic_ms=started_monotonic,
        duration_hours=int(config["duration_hours"]),
        sample_interval_seconds=int(config["sample_interval_seconds"]),
    )
    _bind_soak_timing_config(config, receipt)
    _atomic_write_json(state_dir / "monitor-config.json", config)
    first = _sample(config, _epoch_ms())
    receipt = append_heartbeat_soak_sample(receipt, first)
    persist_heartbeat_soak_receipt(
        _path_from_config(config, "core_soak_receipt_path"),
        receipt,
        repo_root_path=REPO_ROOT,
    )
    _atomic_write_json(_path_from_config(config, "first_sample_path"), first)
    _persist_sample(config, 1, first)
    _append_sample_authentication(config, 1, first)
    if first.get("status") != "pass":
        _persist_envelope(config, status="failed_closed", violation="first_sample_failed", sample=first)
        raise MonitorError("first sample failed closed")
    return first


def start(args: argparse.Namespace) -> int:
    state_dir = _resolve_start_state_dir(args.state_dir, REPO_ROOT.resolve())
    _assert_no_active_monitor(state_dir)
    reservation = _reserve_monitor_state(state_dir)
    process: subprocess.Popen[bytes] | None = None
    log: Any | None = None
    try:
        config = _build_config(args)
        _assert_start_output_paths_available(config)
        _assert_start_git_contract(config)
        first = _first_sample(config)
        if args.no_daemon:
            _persist_envelope(
                config,
                status="first_sample_pass",
                sample=first,
                note="daemon not started",
            )
            print(
                json.dumps(
                    {"status": "first_sample_pass", "daemon_started": False},
                    sort_keys=True,
                )
            )
            reservation.unlink(missing_ok=True)
            return 0

        log_path = _path_from_config(config, "daemon_log_path")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = log_path.open("ab")
        process = subprocess.Popen(
            list(config["run_argv"]),
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log.close()
        log = None
        _path_from_config(config, "pidfile_path").write_text(
            f"{process.pid}\n", encoding="utf-8"
        )
    except Exception:
        if log is not None:
            log.close()
        if process is not None:
            _terminate_process(process)
        reservation.unlink(missing_ok=True)
        raise
    reservation.unlink(missing_ok=True)
    try:
        _wait_for_daemon_ready(config, process)
    except MonitorError as exc:
        _terminate_process(process)
        raise MonitorError("monitor daemon did not become ready") from exc
    print(
        json.dumps(
            {
                "status": "started",
                "pid": process.pid,
                "state_dir": str(_path_from_config(config, "state_dir")),
                "first_sample_status": first.get("status"),
                "monitor_envelope": config["monitor_envelope_path"],
                "core_soak_receipt": config["core_soak_receipt_path"],
            },
            sort_keys=True,
        )
    )
    return 0


def _stop_requested(config: Mapping[str, Any]) -> bool:
    path = _path_from_config(config, "stop_request_path")
    if not path.exists():
        return False
    request = _read_json(path)
    _validate_stop_request(config, request)
    return True


def _handle_signal(signum: int, frame: object) -> None:
    del frame
    exit_code = 2
    state_dir = Path(os.environ.get("HEARTBEAT_SHADOW_MONITOR_STATE_DIR", ""))
    if state_dir:
        try:
            config = (
                _ACTIVE_SIGNAL_CONFIG
                if _ACTIVE_SIGNAL_CONFIG is not None
                else _load_validated_resume_config(state_dir)
            )
            try:
                requested_stop = _stop_requested(config)
            except (HeartbeatShadowError, MonitorError) as exc:
                _persist_envelope(
                    config,
                    status="failed_closed",
                    violation="stop_request_invalid",
                    note=str(exc),
                )
                raise SystemExit(2) from exc
            status = "stopped" if requested_stop else "failed_closed"
            violation = None if status == "stopped" else f"signal_{signum}"
            exit_code = 0 if status == "stopped" else 2
            _persist_envelope(config, status=status, violation=violation)
        except Exception:
            pass
    raise SystemExit(exit_code)


def run(args: argparse.Namespace) -> int:
    global _ACTIVE_SIGNAL_CONFIG
    state_dir = args.state_dir.expanduser().resolve()
    os.environ["HEARTBEAT_SHADOW_MONITOR_STATE_DIR"] = str(state_dir)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        config = _load_validated_resume_config(state_dir)
    except MonitorError:
        return 2
    _ACTIVE_SIGNAL_CONFIG = config
    try:
        _assert_start_git_contract(config)
    except MonitorError as exc:
        _persist_envelope(
            config,
            status="failed_closed",
            violation="monitor_git_identity_invalid",
            note=str(exc),
        )
        return 2
    try:
        _validate_resume_predecessor_receipts(config)
    except MonitorError as exc:
        _persist_envelope(
            config,
            status="failed_closed",
            violation="monitor_resume_identity_invalid",
            note=str(exc),
        )
        return 2
    _write_pidfile(config)
    try:
        _persist_envelope(config, status="running", note="daemon_active")
    except (HeartbeatShadowError, MonitorError) as exc:
        _persist_envelope(
            config,
            status="failed_closed",
            violation="core_receipt_invalid",
            note=str(exc),
        )
        return 2
    while True:
        receipt_path = _path_from_config(config, "core_soak_receipt_path")
        try:
            receipt = _read_json(receipt_path)
            validate_heartbeat_soak_receipt(receipt)
            _validate_receipt_config_binding(config, receipt)
            _validate_core_sample_authentication(config, receipt)
        except (HeartbeatShadowError, MonitorError) as exc:
            _persist_envelope(
                config,
                status="failed_closed",
                violation="core_receipt_invalid",
                note=str(exc),
            )
            return 2
        if receipt["status"] == "complete":
            try:
                _require_core_receipt_authentication(config)
            except (HeartbeatShadowError, MonitorError) as exc:
                _persist_envelope(
                    config,
                    status="failed_closed",
                    violation="core_receipt_authentication_recovery_failed",
                    note=str(exc),
                )
                return 2
            _persist_envelope(config, status="complete", note="core_receipt_complete")
            return 0
        if receipt["status"] == "failed":
            _persist_envelope(config, status="failed_closed", violation="core_receipt_failed")
            return 2
        try:
            requested_stop = _stop_requested(config)
        except (HeartbeatShadowError, MonitorError) as exc:
            _persist_envelope(
                config,
                status="failed_closed",
                violation="stop_request_invalid",
                note=str(exc),
            )
            return 2
        if requested_stop:
            _persist_envelope(config, status="stopped", note="stop_request_observed")
            return 0
        samples = receipt["samples"]
        if not samples:
            _persist_envelope(config, status="failed_closed", violation="missing_first_sample")
            return 2
        interval_ms = int(config["sample_interval_seconds"]) * 1000
        last_sampled_epoch = samples[-1]["sampled_at_epoch_ms"]
        last_sampled_monotonic = samples[-1]["sampled_at_monotonic_ms"]
        due = last_sampled_epoch + interval_ms
        due_monotonic = last_sampled_monotonic + interval_ms
        latest = last_sampled_epoch + interval_ms * 2
        latest_monotonic = last_sampled_monotonic + interval_ms * 2
        now = _epoch_ms()
        now_monotonic = time.monotonic_ns() // 1_000_000
        if now > latest or now_monotonic > latest_monotonic:
            _persist_envelope(config, status="failed_closed", violation="coverage_gap")
            return 2
        while now < due or now_monotonic < due_monotonic:
            try:
                requested_stop = _stop_requested(config)
            except (HeartbeatShadowError, MonitorError) as exc:
                _persist_envelope(
                    config,
                    status="failed_closed",
                    violation="stop_request_invalid",
                    note=str(exc),
                )
                return 2
            if requested_stop:
                _persist_envelope(config, status="stopped", note="stop_request_observed")
                return 0
            waits = [
                max(0, due - now),
                max(0, due_monotonic - now_monotonic),
                max(0, latest_monotonic - now_monotonic),
            ]
            positive_waits = [item for item in waits if item > 0]
            wait_ms = min(positive_waits) if positive_waits else 100
            time.sleep(min(5.0, max(0.1, wait_ms / 1000)))
            now = _epoch_ms()
            now_monotonic = time.monotonic_ns() // 1_000_000
            if now > latest or now_monotonic > latest_monotonic:
                _persist_envelope(config, status="failed_closed", violation="coverage_gap")
                return 2
        sample = _sample(config, now)
        try:
            updated = append_heartbeat_soak_sample(receipt, sample)
        except HeartbeatShadowError as exc:
            _persist_envelope(
                config,
                status="failed_closed",
                violation="sample_append_rejected",
                sample=sample,
                note=str(exc),
            )
            return 2
        _persist_sample(config, len(updated["samples"]), sample)
        _append_sample_authentication(config, len(updated["samples"]), sample)
        persist_heartbeat_soak_receipt(receipt_path, updated, repo_root_path=REPO_ROOT)
        if updated["status"] == "failed":
            _persist_envelope(config, status="failed_closed", violation="sample_failed", sample=sample)
            return 2
        if updated["status"] == "complete":
            _write_core_receipt_authentication(config)
            _persist_envelope(config, status="complete", sample=sample)
            return 0
        _persist_envelope(config, status="running", sample=sample)


def stop(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    config = _load_validated_resume_config(state_dir)
    payload = _stop_request_payload(config, requested_at=_utc_now(), reason=args.reason)
    request = {**payload, "authentication": _stop_request_authentication(payload)}
    _atomic_write_json(_path_from_config(config, "stop_request_path"), request)
    deadline = time.monotonic() + args.wait_seconds
    pid = _load_pid(_path_from_config(config, "pidfile_path"))
    while pid and _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.25)
    envelope = _read_json(_path_from_config(config, "monitor_envelope_path"))
    print(
        json.dumps(
            {
                "status": "stop_requested",
                "pid": pid,
                "process_alive": bool(pid and _pid_alive(pid)),
                "envelope_status": envelope.get("status"),
            },
            sort_keys=True,
        )
    )
    return 0


def status(args: argparse.Namespace) -> int:
    state_dir = _assert_status_read_paths_safe(args.state_dir)
    envelope = _read_json(state_dir / "monitor-envelope.json")
    try:
        config = _load_validated_resume_config(state_dir)
        refreshed_status = str(envelope.get("status", "unknown"))
        existing_violations = envelope.get("violations")
        violations = (
            [str(item) for item in existing_violations]
            if isinstance(existing_violations, list)
            else []
        )
        note = envelope.get("note") if isinstance(envelope.get("note"), str) else None
        latest_sample = envelope.get("latest_sample")
        sample = latest_sample if isinstance(latest_sample, Mapping) else None
        envelope = _envelope(
            config=config,
            status=refreshed_status,
            violations=violations,
            sample=sample,
            note=note,
        )
        running_failure = _running_status_failure(envelope)
        if running_failure is not None:
            violation, failure_note = running_failure
            if violation not in violations:
                violations.append(violation)
            envelope = _envelope(
                config=config,
                status="failed_closed",
                violations=violations,
                sample=sample,
                note=note or failure_note,
            )
        _atomic_write_json(state_dir / "monitor-envelope.json", envelope)
    except (HeartbeatShadowError, MonitorError) as exc:
        current_status = str(envelope.get("status", "unknown"))
        if current_status in {"running", "complete", "rolled_back", "first_sample_pass"}:
            existing_violations = envelope.get("violations")
            violations = (
                [str(item) for item in existing_violations]
                if isinstance(existing_violations, list)
                else []
            )
            terminal_violation = (
                "terminal_rollback_receipt_invalid"
                if current_status == "rolled_back"
                else "terminal_core_receipt_invalid"
            )
            violation = (
                "monitor_state_unreadable"
                if current_status in {"running", "first_sample_pass"}
                else terminal_violation
            )
            if violation not in violations:
                violations.append(violation)
            envelope = {
                **dict(envelope),
                "status": "failed_closed",
                "violations": violations,
                "note": f"{current_status} monitor state is unreadable: {exc}",
            }
            _atomic_write_json(state_dir / "monitor-envelope.json", envelope)
            print(json.dumps(envelope, sort_keys=True, indent=2))
            return 2
    print(json.dumps(envelope, sort_keys=True, indent=2))
    return 0


def rollback(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    config = _load_validated_resume_config(state_dir)
    pid = _load_pid(_path_from_config(config, "pidfile_path"))
    _assert_rollback_monitor_inactive(config, pid, args.allow_running)
    receipt = _read_json(_path_from_config(config, "core_soak_receipt_path"))
    validate_heartbeat_soak_receipt(receipt)
    rollback_receipt_path = _path_from_config(config, "rollback_receipt_path")
    rollback_authentication_path = _path_from_config(
        config, "rollback_receipt_authentication_path"
    )
    if rollback_receipt_path.exists():
        if not rollback_authentication_path.exists():
            result = _recover_rollback_receipt_authentication(
                config, rollback_id=args.rollback_id
            )
        else:
            result = _read_json(rollback_receipt_path)
            _validate_rollback_receipt_config_binding(config, result)
        _persist_envelope(
            config,
            status="rolled_back",
            note="local shadow db rollback complete",
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    _write_rollback_authentication_intent(config, args.rollback_id)

    def receipt_persisted(_receipt: Mapping[str, Any]) -> None:
        _bind_and_authenticate_persisted_rollback_receipt(config, args.rollback_id)

    result = force_heartbeat_file_authority_rollback(
        baseline_path=_path_from_config(config, "baseline_path"),
        heartbeat_file=_path_from_config(config, "heartbeat_file"),
        live_config_path=_path_from_config(config, "live_config_path"),
        database=_path_from_config(config, "database_path"),
        authority_input_digest=str(receipt["authority_input_digest"]),
        rollback_id=args.rollback_id,
        receipt_path=rollback_receipt_path,
        monitor_run_id=str(config["run_id"]),
        repo_root_path=REPO_ROOT,
        rollback_receipt_persisted_callback=receipt_persisted,
    )
    _persist_envelope(config, status="rolled_back", note="local shadow db rollback complete")
    print(json.dumps(result, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="heartbeat-shadow-soak-monitor")
    subcommands = result.add_subparsers(dest="command", required=True)

    start_cmd = subcommands.add_parser("start")
    start_cmd.add_argument("--state-dir", type=Path, required=True)
    start_cmd.add_argument("--run-id", required=True)
    start_cmd.add_argument("--baseline-path", type=Path, required=True)
    start_cmd.add_argument("--heartbeat-file", type=Path, required=True)
    start_cmd.add_argument("--live-config-path", type=Path, required=True)
    start_cmd.add_argument(
        "--lifecycle-receipt-path",
        type=Path,
        default=REPO_ROOT
        / "docs/runtime-evidence/phase-b-p03-isolated-candidate-lifecycle-20260814T032902Z.json",
    )
    start_cmd.add_argument(
        "--independent-validation-path",
        type=Path,
        required=True,
    )
    start_cmd.add_argument("--runtime-head", default=EXPECTED_RUNTIME_HEAD)
    start_cmd.add_argument(
        "--agentic-os-evidence-head",
        default=EXPECTED_AGENTIC_OS_EVIDENCE_HEAD,
    )
    start_cmd.add_argument("--implementation-base", default=EXPECTED_IMPLEMENTATION_BASE)
    start_cmd.add_argument("--monitor-implementation-head", required=True)
    start_cmd.add_argument(
        "--expected-lifecycle-sha256", default=EXPECTED_LIFECYCLE_SHA256
    )
    start_cmd.add_argument(
        "--expected-independent-validation-sha256",
        required=True,
    )
    start_cmd.add_argument("--duration-hours", type=int, default=DEFAULT_DURATION_HOURS)
    start_cmd.add_argument(
        "--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS
    )
    start_cmd.add_argument("--no-daemon", action="store_true")
    start_cmd.set_defaults(func=start)

    run_cmd = subcommands.add_parser("run")
    run_cmd.add_argument("--state-dir", type=Path, required=True)
    run_cmd.set_defaults(func=run)

    status_cmd = subcommands.add_parser("status")
    status_cmd.add_argument("--state-dir", type=Path, required=True)
    status_cmd.set_defaults(func=status)

    stop_cmd = subcommands.add_parser("stop")
    stop_cmd.add_argument("--state-dir", type=Path, required=True)
    stop_cmd.add_argument("--reason", default="explicit_local_stop")
    stop_cmd.add_argument("--wait-seconds", type=float, default=10.0)
    stop_cmd.set_defaults(func=stop)

    rollback_cmd = subcommands.add_parser("rollback")
    rollback_cmd.add_argument("--state-dir", type=Path, required=True)
    rollback_cmd.add_argument("--rollback-id", default="phase-b-local-rollback")
    rollback_cmd.add_argument("--allow-running", action="store_true")
    rollback_cmd.set_defaults(func=rollback)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (HeartbeatShadowError, MonitorError) as exc:
        print(json.dumps({"status": "failed_closed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
