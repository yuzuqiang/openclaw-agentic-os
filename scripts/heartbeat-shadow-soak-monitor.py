#!/usr/bin/env python3
"""Restart-safe local Heartbeat file-authority shadow soak monitor."""

from __future__ import annotations

import argparse
import hashlib
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
    append_heartbeat_soak_sample,
    force_heartbeat_file_authority_rollback,
    heartbeat_parity_sample,
    new_heartbeat_soak_receipt,
    persist_heartbeat_soak_receipt,
    run_heartbeat_file_shadow_cycle,
    snapshot_heartbeat_runtime_authority_database,
    validate_heartbeat_soak_receipt,
)


SCHEMA_CONFIG = "p03-heartbeat-shadow-monitor-config.v1"
SCHEMA_ENVELOPE = "p03-heartbeat-shadow-monitor-envelope.v1"
SCHEMA_SNAPSHOTS = "p03-heartbeat-shadow-runtime-snapshot-receipts.v1"
SCHEMA_STOP = "p03-heartbeat-shadow-monitor-stop-request.v1"
DEFAULT_DURATION_HOURS = 24
DEFAULT_INTERVAL_SECONDS = 300
DAEMON_READY_TIMEOUT_SECONDS = 2.0
EXPECTED_LIFECYCLE_SHA256 = (
    "60245f0148a5dc5d7c55cbd42de17eb343d9a2544863d56b7b4c3ffac40276a8"
)
EXPECTED_INDEPENDENT_VALIDATION_SHA256 = (
    "ddcc4f0f5df6a794885d3dba7055c3e840f5354909dfcc0c0144532403001536"
)
EXPECTED_RUNTIME_HEAD = "ff180d08bde60ff42bd39147f339d3a590639778"
EXPECTED_AGENTIC_OS_EVIDENCE_HEAD = "21f0bde95beeedabd22f870d14eaa6fe98dbcf74"
EXPECTED_IMPLEMENTATION_BASE = "7e285f405edf9c3aa008ce555fefc1e2640cc2f4"


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
    for key in (
        "agentic_os_evidence_head",
        "implementation_base",
        "monitor_implementation_head",
    ):
        commit = str(exact_heads.get(key, ""))
        _git_text(repo_root, ["cat-file", "-e", f"{commit}^{{commit}}"], key)
    _git_text(
        repo_root,
        [
            "merge-base",
            "--is-ancestor",
            str(exact_heads["implementation_base"]),
            str(exact_heads["monitor_implementation_head"]),
        ],
        "implementation ancestry",
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


def _path_from_config(config: Mapping[str, Any], key: str) -> Path:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise MonitorError(f"config missing path: {key}")
    return Path(value).expanduser().resolve()


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
            "implementation_head": validation["implementation_head"],
        },
    }


def _validate_independent_validation_provenance(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> None:
    verifier = validation.get("verifier")
    if not isinstance(verifier, Mapping):
        raise MonitorError("independent validation verifier provenance is missing")
    for key in ("identity", "role", "session_key"):
        value = verifier.get(key)
        if not isinstance(value, str) or not value:
            raise MonitorError(f"independent validation verifier {key} is missing")
    if verifier.get("identity") == "lifecycle_producer":
        raise MonitorError("independent validation must not be self-produced")
    implementation_head = validation.get("implementation_head")
    if implementation_head != config["exact_heads"]["implementation_base"]:
        raise MonitorError("independent validation implementation head mismatch")
    invocation = validation.get("invocation")
    if not isinstance(invocation, Mapping):
        raise MonitorError("independent validation invocation provenance is missing")
    for key in ("command", "completed_at"):
        value = invocation.get(key)
        if not isinstance(value, str) or not value:
            raise MonitorError(f"independent validation invocation {key} is missing")
    _validate_independent_validation_anchor(config, validation)


def _validate_independent_validation_anchor(
    config: Mapping[str, Any], validation: Mapping[str, Any]
) -> None:
    anchor = validation.get("authenticated_record")
    if not isinstance(anchor, Mapping):
        raise MonitorError("independent validation authenticated record is missing")
    raw_path = anchor.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise MonitorError("independent validation authenticated record path is missing")
    anchor_path = Path(raw_path)
    if not anchor_path.is_absolute():
        anchor_path = (REPO_ROOT / anchor_path).resolve()
    else:
        anchor_path = anchor_path.resolve()
    try:
        anchor_path.relative_to(REPO_ROOT.resolve())
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
    if record.get("record_authority") == "lifecycle_producer":
        raise MonitorError("independent validation authenticated record is self-produced")
    if record.get("validation_verdict") != "pass":
        raise MonitorError("independent validation authenticated record is not PASS")
    if record.get("receipt_sha256") != validation.get("receipt_sha256"):
        raise MonitorError("independent validation authenticated record receipt mismatch")
    if record.get("implementation_head") != config["exact_heads"]["implementation_base"]:
        raise MonitorError(
            "independent validation authenticated record implementation mismatch"
        )
    verifier = validation["verifier"]
    record_verifier = record.get("verifier")
    if not isinstance(record_verifier, Mapping):
        raise MonitorError("independent validation authenticated record verifier missing")
    for key in ("identity", "role", "session_key"):
        if record_verifier.get(key) != verifier.get(key):
            raise MonitorError(
                f"independent validation authenticated record verifier {key} mismatch"
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
    if core_receipt_path.exists():
        try:
            receipt = _read_json(core_receipt_path)
            validate_heartbeat_soak_receipt(receipt)
        except (HeartbeatShadowError, MonitorError):
            if status != "failed_closed":
                raise
            receipt = None
    snapshot_doc: dict[str, Any] | None = None
    if snapshot_receipts_path.exists():
        try:
            snapshot_doc = _read_json(snapshot_receipts_path)
            if snapshot_doc.get("schema_version") != SCHEMA_SNAPSHOTS:
                raise MonitorError("unsupported runtime snapshot receipt schema")
        except MonitorError:
            if status != "failed_closed":
                raise
            snapshot_doc = None

    samples = receipt.get("samples", []) if receipt else []
    snapshots = snapshot_doc.get("snapshots", []) if snapshot_doc else []
    first_sample = samples[0] if samples else None
    latest_sample = sample if sample is not None else (samples[-1] if samples else None)
    last_sampled_at = (
        latest_sample.get("sampled_at_epoch_ms")
        if isinstance(latest_sample, Mapping)
        else None
    )
    interval_ms = int(config["sample_interval_seconds"]) * 1000
    next_due = last_sampled_at + interval_ms if isinstance(last_sampled_at, int) else None
    allowed_latest = (
        last_sampled_at + interval_ms * 2 if isinstance(last_sampled_at, int) else None
    )
    current_pid = os.getpid()
    pid = _load_pid(pidfile) or current_pid
    terminal_status = status in {"complete", "failed_closed", "rolled_back", "stopped"}
    no_daemon_status = status == "first_sample_pass"
    process_alive = _pid_alive(pid)
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
            "next_due_epoch_ms": next_due,
            "allowed_latest_epoch_ms": allowed_latest,
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
        "first_sample_path": str(state_dir / "first-sample.json"),
        "monitor_envelope_path": str(state_dir / "monitor-envelope.json"),
        "stop_request_path": str(state_dir / "stop-request.json"),
        "rollback_receipt_path": str(state_dir / "rollback-receipt.json"),
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
        "exact_heads": {
            "runtime_head": args.runtime_head,
            "agentic_os_evidence_head": args.agentic_os_evidence_head,
            "implementation_base": args.implementation_base,
            "monitor_implementation_head": args.monitor_implementation_head,
        },
        "run_argv": _command(script_path, "run", state_dir),
    }
    config["predecessor_receipts"] = _verified_predecessor_summary(config)
    return config


def _sample(config: Mapping[str, Any], sampled_at_epoch_ms: int) -> dict[str, Any]:
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


def _append_runtime_snapshot_receipt(
    config: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> None:
    path = _path_from_config(config, "runtime_snapshot_receipts_path")
    if path.exists():
        document = _read_json(path)
        if document.get("schema_version") != SCHEMA_SNAPSHOTS:
            raise MonitorError("unsupported runtime snapshot receipt schema")
        snapshots = document.get("snapshots")
        if not isinstance(snapshots, list):
            raise MonitorError("runtime snapshot receipts must be a list")
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
    _atomic_write_json(state_dir / "monitor-config.json", config)
    receipt = new_heartbeat_soak_receipt(
        run_id=str(config["run_id"]),
        authority_input_digest=str(config["authority_input_digest"]),
        started_at_epoch_ms=started,
        started_at_monotonic_ms=started_monotonic,
        duration_hours=int(config["duration_hours"]),
        sample_interval_seconds=int(config["sample_interval_seconds"]),
    )
    first = _sample(config, _epoch_ms())
    receipt = append_heartbeat_soak_sample(receipt, first)
    persist_heartbeat_soak_receipt(
        _path_from_config(config, "core_soak_receipt_path"),
        receipt,
        repo_root_path=REPO_ROOT,
    )
    _atomic_write_json(_path_from_config(config, "first_sample_path"), first)
    _persist_sample(config, 1, first)
    if first.get("status") != "pass":
        _persist_envelope(config, status="failed_closed", violation="first_sample_failed", sample=first)
        raise MonitorError("first sample failed closed")
    return first


def start(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    _assert_no_active_monitor(state_dir)
    config = _build_config(args)
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
    _path_from_config(config, "pidfile_path").write_text(f"{process.pid}\n", encoding="utf-8")
    try:
        _wait_for_daemon_ready(config, process)
    except MonitorError as exc:
        if process.poll() is None:
            process.terminate()
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
    return _path_from_config(config, "stop_request_path").exists()


def _handle_signal(signum: int, frame: object) -> None:
    del frame
    exit_code = 2
    state_dir = Path(os.environ.get("HEARTBEAT_SHADOW_MONITOR_STATE_DIR", ""))
    if state_dir:
        try:
            config = _load_config(state_dir)
            status = "stopped" if _stop_requested(config) else "failed_closed"
            violation = None if status == "stopped" else f"signal_{signum}"
            exit_code = 0 if status == "stopped" else 2
            _persist_envelope(config, status=status, violation=violation)
        except Exception:
            pass
    raise SystemExit(exit_code)


def run(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    os.environ["HEARTBEAT_SHADOW_MONITOR_STATE_DIR"] = str(state_dir)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    config = _load_config(state_dir)
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
        except (HeartbeatShadowError, MonitorError) as exc:
            _persist_envelope(
                config,
                status="failed_closed",
                violation="core_receipt_invalid",
                note=str(exc),
            )
            return 2
        if receipt["status"] == "complete":
            _persist_envelope(config, status="complete", note="core_receipt_complete")
            return 0
        if receipt["status"] == "failed":
            _persist_envelope(config, status="failed_closed", violation="core_receipt_failed")
            return 2
        if _stop_requested(config):
            _persist_envelope(config, status="stopped", note="stop_request_observed")
            return 0
        samples = receipt["samples"]
        if not samples:
            _persist_envelope(config, status="failed_closed", violation="missing_first_sample")
            return 2
        interval_ms = int(config["sample_interval_seconds"]) * 1000
        last_sampled = samples[-1]["sampled_at_epoch_ms"]
        due = last_sampled + interval_ms
        latest = last_sampled + interval_ms * 2
        now = _epoch_ms()
        if now > latest:
            _persist_envelope(config, status="failed_closed", violation="coverage_gap")
            return 2
        while now < due:
            if _stop_requested(config):
                _persist_envelope(config, status="stopped", note="stop_request_observed")
                return 0
            time.sleep(min(5.0, max(0.1, (due - now) / 1000)))
            now = _epoch_ms()
            if now > latest:
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
        persist_heartbeat_soak_receipt(receipt_path, updated, repo_root_path=REPO_ROOT)
        _persist_sample(config, len(updated["samples"]), sample)
        if updated["status"] == "failed":
            _persist_envelope(config, status="failed_closed", violation="sample_failed", sample=sample)
            return 2
        if updated["status"] == "complete":
            _persist_envelope(config, status="complete", sample=sample)
            return 0
        _persist_envelope(config, status="running", sample=sample)


def stop(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    config = _load_config(state_dir)
    request = {
        "schema_version": SCHEMA_STOP,
        "status": "requested",
        "requested_at": _utc_now(),
        "reason": args.reason,
        "scope": "local_artifact_monitor_only",
    }
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
    state_dir = args.state_dir.expanduser().resolve()
    envelope = _read_json(state_dir / "monitor-envelope.json")
    try:
        config = _load_config(state_dir)
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
        _atomic_write_json(state_dir / "monitor-envelope.json", envelope)
    except MonitorError:
        pass
    print(json.dumps(envelope, sort_keys=True, indent=2))
    return 0


def rollback(args: argparse.Namespace) -> int:
    state_dir = args.state_dir.expanduser().resolve()
    config = _load_config(state_dir)
    pid = _load_pid(_path_from_config(config, "pidfile_path"))
    if pid and _pid_alive(pid) and not args.allow_running:
        raise MonitorError("refusing rollback while monitor process is active")
    receipt = _read_json(_path_from_config(config, "core_soak_receipt_path"))
    validate_heartbeat_soak_receipt(receipt)
    result = force_heartbeat_file_authority_rollback(
        baseline_path=_path_from_config(config, "baseline_path"),
        heartbeat_file=_path_from_config(config, "heartbeat_file"),
        live_config_path=_path_from_config(config, "live_config_path"),
        database=_path_from_config(config, "database_path"),
        authority_input_digest=str(receipt["authority_input_digest"]),
        rollback_id=args.rollback_id,
        receipt_path=_path_from_config(config, "rollback_receipt_path"),
        repo_root_path=REPO_ROOT,
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
        default=REPO_ROOT
        / "docs/runtime-evidence/phase-b-p03-independent-validation-20260814T032902Z.json",
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
        default=EXPECTED_INDEPENDENT_VALIDATION_SHA256,
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
