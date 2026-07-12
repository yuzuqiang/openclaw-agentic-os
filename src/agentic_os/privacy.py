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
    "state/agentic-os/control.db-journal",
    "state/agentic-os/backups/example.db",
)

RAW_STATE_PATTERNS = (
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.db-journal",
    "*.db-*",
    "*.db.tar*",
    "*.db.backup*",
    "*.db.bak*",
    "*.sqlite",
    "*.sqlite-*",
    "*.sqlite.tar*",
    "*.sqlite.backup*",
    "*.sqlite.bak*",
    "*.sqlite3",
    "*.sqlite3-*",
    "*.sqlite3.tar*",
    "*.sqlite3.backup*",
    "*.sqlite3.bak*",
)

COMPRESSED_STATE_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".tzst",
    ".gz",
    ".zip",
    ".zst",
    ".xz",
    ".bz2",
    ".lz4",
    ".tar",
)


@dataclass(frozen=True)
class PrivacyPreflightResult:
    repo_root: Path
    ignored_paths: tuple[str, ...]


def is_raw_state_denied(path: str | Path) -> bool:
    normalized = str(path).replace("\\", "/").lstrip("./")
    pure = PurePosixPath(normalized)
    name = pure.name
    candidate_names = [name]
    stripped = name
    while True:
        suffix = next(
            (
                suffix
                for suffix in COMPRESSED_STATE_SUFFIXES
                if stripped.endswith(suffix) and stripped != suffix
            ),
            None,
        )
        if suffix is None:
            break
        stripped = stripped[: -len(suffix)]
        candidate_names.append(stripped)
    if any(
        fnmatch.fnmatchcase(candidate, pattern)
        for candidate in candidate_names
        for pattern in RAW_STATE_PATTERNS
    ):
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


def _repo_relative_paths(repo_root: Path, paths: Iterable[Path]) -> tuple[str, ...]:
    relative: list[str] = []
    for path in paths:
        resolved = Path(path).expanduser().resolve()
        try:
            item = resolved.relative_to(repo_root).as_posix()
        except ValueError:
            raise PrivacyPreflightError(
                f"database path is outside checked worktree: {resolved}"
            ) from None
        relative.extend((item, f"{item}-wal", f"{item}-shm", f"{item}-journal"))
    return tuple(dict.fromkeys(relative))


def assert_privacy_preflight(
    repo_root: Path, *, database_paths: Iterable[Path] = ()
) -> PrivacyPreflightResult:
    root = Path(repo_root).resolve()
    if not (root / ".git").exists():
        raise PrivacyPreflightError(f"not a Git worktree: {root}")
    checked_paths = tuple(
        dict.fromkeys((*PREFLIGHT_PATHS, *_repo_relative_paths(root, database_paths)))
    )
    tracked_command = ["git", "ls-files", "-z"]
    command = ["git", "check-ignore", "-v", "--", *checked_paths]
    try:
        tracked = subprocess.run(
            tracked_command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
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
    if tracked.returncode != 0:
        raise PrivacyPreflightError(
            "privacy preflight failed closed: cannot inspect tracked paths: "
            f"{tracked.stderr.strip()}"
        )
    tracked_runtime_paths = [
        path for path in tracked.stdout.split("\0") if path and is_raw_state_denied(path)
    ]
    if tracked_runtime_paths:
        raise PrivacyPreflightError(
            "privacy preflight failed closed: tracked runtime paths: "
            f"{tracked_runtime_paths}"
        )
    matched = {
        line.rsplit("\t", 1)[-1].strip()
        for line in result.stdout.splitlines()
        if "\t" in line
    }
    missing = [path for path in checked_paths if path not in matched]
    if result.returncode != 0 or missing:
        detail = result.stderr.strip() or f"not ignored: {missing}"
        raise PrivacyPreflightError(f"privacy preflight failed closed: {detail}")
    # The same paths must be rejected by packaging/retrieval. This is the
    # expected denylist outcome, not an attempt to retrieve them.
    not_denied = [path for path in checked_paths if not is_raw_state_denied(path)]
    if not_denied:
        raise PrivacyPreflightError(
            f"packaging/retrieval denylist is incomplete: {not_denied}"
        )
    return PrivacyPreflightResult(root, checked_paths)
