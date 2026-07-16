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
from pathlib import Path
from typing import Any


INPROC_PREDICATE_BACKEND = "agentic_predicate_inproc_v1"
MAX_PREDICATE_DEPTH = 32
MAX_PREDICATE_LIST_LENGTH = 64
MAX_JSON_PATH_LENGTH = 32
MAX_STRING_LENGTH = 4096
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
        return all(
            _evaluate(item, context, depth=depth + 1)
            for item in _predicate_list(predicate["predicates"], "all predicates")
        )
    if op == "any":
        _require_keys(predicate, ("op", "predicates"), "any predicate")
        return any(
            _evaluate(item, context, depth=depth + 1)
            for item in _predicate_list(predicate["predicates"], "any predicates")
        )
    if op == "not":
        _require_keys(predicate, ("op", "predicate"), "not predicate")
        return not _evaluate(predicate["predicate"], context, depth=depth + 1)
    if op == "file_exists":
        _require_keys(predicate, ("op", "path"), "file_exists predicate")
        return _repo_path(context.repo_root, predicate["path"]).exists()
    if op == "file_sha256":
        _require_keys(predicate, ("op", "path", "sha256"), "file_sha256 predicate")
        expected = predicate["sha256"]
        if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
            raise PredicateContractError("file_sha256 expected hash must be lowercase SHA-256")
        path = _repo_path(context.repo_root, predicate["path"])
        if not path.is_file():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == expected
    if op == "json_equals":
        _require_keys(predicate, ("op", "document", "path", "value"), "json_equals predicate")
        document_name = _bounded_string(predicate["document"], "json document name")
        if document_name not in context.json_documents:
            raise PredicateContractError(f"missing JSON evidence document: {document_name}")
        expected = _json_scalar(predicate["value"], "json_equals value")
        actual = _json_path_lookup(
            context.json_documents[document_name],
            predicate["path"],
        )
        return actual == expected
    if op == "command_result_equals":
        _require_keys(
            predicate,
            ("op", "id", "field", "value"),
            "command_result_equals predicate",
        )
        result_id = _bounded_string(predicate["id"], "command result id")
        field_name = _bounded_string(predicate["field"], "command result field")
        if result_id not in context.command_results:
            raise PredicateContractError(f"missing command result evidence: {result_id}")
        result = context.command_results[result_id]
        if not isinstance(result, Mapping):
            raise PredicateContractError("command result evidence must be an object")
        if field_name not in result:
            raise PredicateContractError(
                f"command result evidence is missing field: {field_name}"
            )
        expected = _json_scalar(predicate["value"], "command_result_equals value")
        actual = _json_scalar(result[field_name], "command result field value")
        return actual == expected
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
    return root


def _repo_path(repo_root: Path, raw_path: Any) -> Path:
    relative = _bounded_string(raw_path, "repo-relative path")
    candidate_input = Path(relative)
    if candidate_input.is_absolute():
        raise PredicateContractError("repo-relative path must not be absolute")
    try:
        candidate = (repo_root / candidate_input).resolve(strict=False)
        candidate.relative_to(repo_root)
    except (OSError, ValueError) as exc:
        raise PredicateContractError("repo-relative path escapes repo root") from exc
    return candidate


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
                return _MISSING
            current = current[segment]
        elif type(segment) is int:
            if not isinstance(current, list) or segment < 0 or segment >= len(current):
                return _MISSING
            current = current[segment]
        else:
            raise PredicateContractError("json path segments must be strings or integers")
    if current is _MISSING:
        return _MISSING
    return _json_scalar(current, "json_equals resolved value")


class _Missing:
    pass


_MISSING = _Missing()
