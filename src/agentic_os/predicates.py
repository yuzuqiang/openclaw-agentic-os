"""Fail-closed in-process Standing Goal predicate evaluator.

This module implements only the audited ``agentic_predicate_inproc_v1`` subset.
It is intentionally pure and read-only: callers provide immutable JSON and
command evidence, and file adapters are bounded to the repository root.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from stat import S_ISREG
from typing import Any

from .privacy import PrivacyPreflightError, assert_paths_retrievable


INPROC_PREDICATE_BACKEND = "agentic_predicate_inproc_v1"
MAX_PREDICATE_DEPTH = 32
MAX_PREDICATE_LIST_LENGTH = 64
MAX_JSON_PATH_LENGTH = 32
MAX_STRING_LENGTH = 4096
MAX_FILE_EVIDENCE_BYTES = 8 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CREDENTIAL_FILE_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".docker",
        ".env",
        ".envrc",
        ".git",
        ".gcloud",
        ".gnupg",
        ".kube",
        ".netrc",
        ".ssh",
        ".npmrc",
        ".pypirc",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    }
)
_CREDENTIAL_NAME_TOKENS = frozenset(
    {
        "credential",
        "credentials",
        "private",
        "secret",
        "secrets",
        "token",
        "tokens",
    }
)
_CREDENTIAL_FILE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


class PredicateContractError(ValueError):
    """Predicate input is unsupported, ambiguous, or outside the safe subset."""


@dataclass(frozen=True)
class PredicateContext:
    """Caller-supplied read-only evidence for in-process predicates."""

    repo_root: Path | str
    json_documents: Mapping[str, Any] = field(default_factory=dict)
    command_results: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)


def evaluate_predicate_document(
    document: Mapping[str, Any], context: PredicateContext
) -> bool:
    """Evaluate a backend-tagged predicate document.

    The document must contain exactly ``backend`` and ``predicate``. Unsupported
    backends, extra keys, malformed adapters, and unsafe paths raise
    :class:`PredicateContractError` so callers can route the run to human review.
    """

    if not isinstance(document, Mapping):
        raise PredicateContractError("predicate document must be a JSON object")
    _require_keys(document, ("backend", "predicate"), "predicate document")
    backend = document["backend"]
    if backend != INPROC_PREDICATE_BACKEND:
        raise PredicateContractError(f"unsupported predicate backend: {backend!r}")
    repo_root = _normalize_repo_root(context.repo_root)
    safe_context = PredicateContext(
        repo_root=repo_root,
        json_documents=context.json_documents,
        command_results=context.command_results,
    )
    return _evaluate(document["predicate"], safe_context, depth=0)


def _evaluate(predicate: Any, context: PredicateContext, *, depth: int) -> bool:
    if depth > MAX_PREDICATE_DEPTH:
        raise PredicateContractError("predicate nesting exceeds safe limit")
    if not isinstance(predicate, Mapping):
        raise PredicateContractError("predicate must be a JSON object")
    op = predicate.get("op")
    if not isinstance(op, str) or not op:
        raise PredicateContractError("predicate op must be a non-empty string")
    if op == "literal":
        _require_keys(predicate, ("op", "value"), "literal predicate")
        value = predicate["value"]
        if type(value) is not bool:
            raise PredicateContractError("literal predicate value must be boolean")
        return value
    if op == "all":
        _require_keys(predicate, ("op", "predicates"), "all predicate")
        results = [
            _evaluate(item, context, depth=depth + 1)
            for item in _predicate_list(predicate["predicates"], "all predicates")
        ]
        return all(results)
    if op == "any":
        _require_keys(predicate, ("op", "predicates"), "any predicate")
        results = [
            _evaluate(item, context, depth=depth + 1)
            for item in _predicate_list(predicate["predicates"], "any predicates")
        ]
        return any(results)
    if op == "not":
        _require_keys(predicate, ("op", "predicate"), "not predicate")
        return not _evaluate(predicate["predicate"], context, depth=depth + 1)
    if op == "file_exists":
        _require_keys(predicate, ("op", "path"), "file_exists predicate")
        return _repo_path_stat(
            _repo_path(context.repo_root, predicate["path"]),
            "file_exists evidence",
        ) is not None
    if op == "file_sha256":
        _require_keys(predicate, ("op", "path", "sha256"), "file_sha256 predicate")
        expected = predicate["sha256"]
        if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
            raise PredicateContractError("file_sha256 expected hash must be lowercase SHA-256")
        path = _repo_path(context.repo_root, predicate["path"])
        path_stat = _repo_path_stat(path, "file_sha256 evidence")
        if path_stat is None or not S_ISREG(path_stat.st_mode):
            raise PredicateContractError("file_sha256 evidence must be a regular file")
        _raise_if_multi_link_file(path_stat, "file_sha256 evidence")
        actual_hash = _sha256_file(path, path_stat)
        return actual_hash == expected
    if op == "json_equals":
        _require_keys(predicate, ("op", "document", "path", "value"), "json_equals predicate")
        document_name = _bounded_string(predicate["document"], "json document name")
        json_documents = _evidence_mapping(context.json_documents, "JSON evidence map")
        if document_name not in json_documents:
            raise PredicateContractError(f"missing JSON evidence document: {document_name}")
        expected = _json_scalar(predicate["value"], "json_equals value")
        actual = _json_path_lookup(
            json_documents[document_name],
            predicate["path"],
        )
        return _json_scalar_equals(actual, expected, "json_equals resolved value")
    if op == "command_result_equals":
        _require_keys(
            predicate,
            ("op", "id", "field", "value"),
            "command_result_equals predicate",
        )
        result_id = _bounded_string(predicate["id"], "command result id")
        field_name = _bounded_string(predicate["field"], "command result field")
        command_results = _evidence_mapping(
            context.command_results, "command result evidence map"
        )
        if result_id not in command_results:
            raise PredicateContractError(f"missing command result evidence: {result_id}")
        result = command_results[result_id]
        if not isinstance(result, Mapping):
            raise PredicateContractError("command result evidence must be an object")
        if field_name not in result:
            raise PredicateContractError(
                f"command result evidence is missing field: {field_name}"
            )
        expected = _json_scalar(predicate["value"], "command_result_equals value")
        actual = _json_scalar(result[field_name], "command result field value")
        return _json_scalar_equals(actual, expected, "command result field value")
    raise PredicateContractError(f"unsupported predicate op: {op!r}")


def _require_keys(value: Mapping[str, Any], keys: tuple[str, ...], label: str) -> None:
    if set(value) != set(keys):
        raise PredicateContractError(
            f"{label} must contain exactly {list(keys)}, found {_sorted_key_names(value)}"
        )


def _sorted_key_names(value: Mapping[str, Any]) -> list[str]:
    return sorted(str(key) for key in value)


def _predicate_list(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise PredicateContractError(f"{label} must be a JSON array")
    if not 1 <= len(value) <= MAX_PREDICATE_LIST_LENGTH:
        raise PredicateContractError(
            f"{label} length must be in [1,{MAX_PREDICATE_LIST_LENGTH}]"
        )
    return value


def _normalize_repo_root(repo_root: Path | str) -> Path:
    try:
        root_path = Path(repo_root)
    except TypeError as exc:
        raise PredicateContractError("repo root must be a filesystem path") from exc
    try:
        root = root_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PredicateContractError("repo root must exist") from exc
    if not root.is_dir():
        raise PredicateContractError("repo root must be a directory")
    _require_git_worktree_top_level(root)
    return root


def _require_git_worktree_top_level(root: Path) -> None:
    try:
        git_entry = root / ".git"
        if not git_entry.exists():
            raise PredicateContractError("repo root must be a Git worktree top level")
        if git_entry.is_dir():
            if not (
                (git_entry / "HEAD").is_file()
                and (git_entry / "objects").is_dir()
                and (git_entry / "refs").is_dir()
            ):
                raise PredicateContractError(
                    "repo root must contain valid Git metadata"
                )
            return
        if git_entry.is_file():
            stat_result = git_entry.stat()
            if stat_result.st_size > MAX_STRING_LENGTH:
                raise PredicateContractError("repo root .git file is outside safe bounds")
            content = git_entry.read_text(encoding="utf-8", errors="strict").strip()
            prefix = "gitdir:"
            if not content.startswith(prefix):
                raise PredicateContractError(
                    "repo root must contain valid Git metadata"
                )
            git_dir = Path(content[len(prefix) :].strip())
            if not git_dir.is_absolute():
                git_dir = (root / git_dir).resolve(strict=False)
            if not git_dir.is_dir() or not (git_dir / "HEAD").is_file():
                raise PredicateContractError(
                    "repo root must contain valid Git metadata"
                )
            return
        raise PredicateContractError("repo root must contain a valid .git entry")
    except OSError as exc:
        raise PredicateContractError("repo root Git metadata cannot be inspected") from exc


def _repo_path(repo_root: Path, raw_path: Any) -> Path:
    relative = _bounded_string(raw_path, "repo-relative path")
    candidate_input = Path(relative)
    if candidate_input.is_absolute():
        raise PredicateContractError("repo-relative path must not be absolute")
    try:
        candidate = (repo_root / candidate_input).resolve(strict=False)
        resolved_relative = candidate.relative_to(repo_root).as_posix()
    except (OSError, ValueError) as exc:
        raise PredicateContractError("repo-relative path escapes repo root") from exc
    _assert_predicate_path_allowed(relative, resolved_relative)
    return candidate


def _assert_predicate_path_allowed(*relative_paths: str) -> None:
    for relative in relative_paths:
        try:
            assert_paths_retrievable(relative)
        except PrivacyPreflightError as exc:
            raise PredicateContractError(
                "repo-relative path targets private raw state"
            ) from exc
        if _is_credential_path_denied(relative):
            raise PredicateContractError(
                "repo-relative path targets private credentials or artifacts"
            )


def _is_credential_path_denied(relative: str) -> bool:
    pure = PurePosixPath(relative.replace("\\", "/"))
    parts = tuple(part.casefold() for part in pure.parts)
    for part in parts:
        stem = part.split(".", 1)[0]
        tokenized = set(re.split(r"[^a-z0-9]+", part))
        if part in _CREDENTIAL_FILE_NAMES or stem in _CREDENTIAL_FILE_NAMES:
            return True
        if part.startswith(".env."):
            return True
        if tokenized & _CREDENTIAL_NAME_TOKENS:
            return True
        if part.endswith(_CREDENTIAL_FILE_SUFFIXES):
            return True
    return False


def _repo_path_stat(path: Path, label: str) -> Any:
    try:
        path_stat = path.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PredicateContractError(f"{label} cannot be inspected") from exc
    if S_ISREG(path_stat.st_mode):
        _raise_if_multi_link_file(path_stat, label)
    return path_stat


def _raise_if_multi_link_file(path_stat: Any, label: str) -> None:
    if int(getattr(path_stat, "st_nlink", 1) or 1) > 1:
        raise PredicateContractError(f"{label} cannot use hard-linked file aliases")


def _sha256_file(path: Path, path_stat: Any) -> str:
    size = int(getattr(path_stat, "st_size", 0) or 0)
    if size > MAX_FILE_EVIDENCE_BYTES:
        raise PredicateContractError("file_sha256 evidence exceeds safe size limit")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PredicateContractError("file_sha256 evidence cannot be read") from exc
    return digest.hexdigest()


def _evidence_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PredicateContractError(f"{label} must be an object")
    return value


def _bounded_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PredicateContractError(f"{label} must be a non-empty string")
    if "\x00" in value or len(value) > MAX_STRING_LENGTH:
        raise PredicateContractError(f"{label} is outside safe bounds")
    return value


def _json_scalar(value: Any, label: str) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (str, int, float)):
        if isinstance(value, str):
            _bounded_string(value, label)
        if isinstance(value, float) and not math.isfinite(value):
            raise PredicateContractError(f"{label} must be finite")
        return value
    raise PredicateContractError(f"{label} must be a JSON scalar")


def _json_scalar_kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    raise PredicateContractError("internal non-scalar comparison")


def _json_scalar_equals(actual: Any, expected: Any, label: str) -> bool:
    actual_kind = _json_scalar_kind(actual)
    expected_kind = _json_scalar_kind(expected)
    if actual_kind != expected_kind:
        raise PredicateContractError(
            f"{label} type mismatch: expected {expected_kind}, found {actual_kind}"
        )
    return actual == expected


def _json_path_lookup(document: Any, path: Any) -> Any:
    if not isinstance(path, list):
        raise PredicateContractError("json_equals path must be a JSON array")
    if not 1 <= len(path) <= MAX_JSON_PATH_LENGTH:
        raise PredicateContractError(
            f"json_equals path length must be in [1,{MAX_JSON_PATH_LENGTH}]"
        )
    current = document
    for segment in path:
        if isinstance(segment, str):
            _bounded_string(segment, "json path segment")
            if not isinstance(current, Mapping) or segment not in current:
                raise PredicateContractError("json_equals evidence path is missing")
            current = current[segment]
        elif type(segment) is int:
            if not isinstance(current, list) or segment < 0 or segment >= len(current):
                raise PredicateContractError("json_equals evidence path is missing")
            current = current[segment]
        else:
            raise PredicateContractError("json path segments must be strings or integers")
    return _json_scalar(current, "json_equals resolved value")
