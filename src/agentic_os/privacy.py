"""Fail-closed privacy preflight and raw-state denylist."""

from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


class PrivacyPreflightError(RuntimeError):
    """Local database state is not proven private."""


PREFLIGHT_PATHS = (
    "state/agentic-os/control.db",
    "state/agentic-os/control.db-wal",
    "state/agentic-os/control.db-shm",
    "state/agentic-os/backups/example.db",
)

RAW_STATE_PATTERNS = (
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.db-journal",
    "*.db-*",
    "*.db.backup*",
    "*.db.bak*",
    "*.sqlite",
    "*.sqlite-*",
)


@dataclass(frozen=True)
class PrivacyPreflightResult:
    repo_root: Path
    ignored_paths: tuple[str, ...]


def is_raw_state_denied(path: str | Path) -> bool:
    normalized = str(path).replace("\\", "/").lstrip("./")
    pure = PurePosixPath(normalized)
    name = pure.name
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in RAW_STATE_PATTERNS):
        return True
    parts = pure.parts
    return any(
        parts[index : index + 3] == ("state", "agentic-os", "backups")
        for index in range(max(0, len(parts) - 2))
    )


def assert_paths_retrievable(
    paths: Iterable[str | Path], *, local_recovery: bool = False
) -> None:
    """Fail if packaging/retrieval includes raw state.

    `local_recovery=True` is an explicit local-only escape hatch. Callers must
    never use it for packaging, reporting, upload, or remote retrieval.
    """

    denied = [str(path) for path in paths if is_raw_state_denied(path)]
    if denied and not local_recovery:
        raise PrivacyPreflightError(f"raw database state is denied: {denied}")


def assert_privacy_preflight(repo_root: Path) -> PrivacyPreflightResult:
    root = Path(repo_root).resolve()
    if not (root / ".git").exists():
        raise PrivacyPreflightError(f"not a Git worktree: {root}")
    command = ["git", "check-ignore", "--no-index", "-v", *PREFLIGHT_PATHS]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise PrivacyPreflightError(f"cannot execute git check-ignore: {exc}") from exc
    matched = {
        line.rsplit("\t", 1)[-1].strip()
        for line in result.stdout.splitlines()
        if "\t" in line
    }
    missing = [path for path in PREFLIGHT_PATHS if path not in matched]
    if result.returncode != 0 or missing:
        detail = result.stderr.strip() or f"not ignored: {missing}"
        raise PrivacyPreflightError(f"privacy preflight failed closed: {detail}")
    # The same paths must be rejected by packaging/retrieval. This is the
    # expected denylist outcome, not an attempt to retrieve them.
    not_denied = [path for path in PREFLIGHT_PATHS if not is_raw_state_denied(path)]
    if not_denied:
        raise PrivacyPreflightError(
            f"packaging/retrieval denylist is incomplete: {not_denied}"
        )
    return PrivacyPreflightResult(root, tuple(PREFLIGHT_PATHS))
