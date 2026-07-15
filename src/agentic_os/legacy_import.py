"""Fail-closed legacy money import into authoritative budget settlements."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

from .budgets import (
    BudgetAmounts,
    BudgetConflict,
    BudgetError,
    _LIMITS,
    _connect,
    _dedupe_hash,
    _selected_binding,
    _settle_budget_on_connection,
    _verify_schema_identity,
)


LEGACY_SOURCE_SCHEMA_VERSION = "legacy_budget_terminal_usage_v1"
LEGACY_SOURCE_TABLE = "legacy_budget_terminal_usage_v1"
LEGACY_SOURCE_UNIT = "usd_decimal"
_MONEY_SCALE = Decimal("1000000")
_MAX_MONEY_MICROUSD = _LIMITS["cost_microusd"]
_MAX_MONEY_MICROUSD_ADJUSTED = len(str(_MAX_MONEY_MICROUSD)) - 1
_TEXT_FIELDS = (
    "legacy_row_id",
    "run_id",
    "transition_id",
    "spawn_request_id",
    "idempotency_key",
    "dedupe_key",
    "source",
    "clock_context_id",
    "usage_confidence",
    "source_unit",
)
_INTEGER_FIELDS = {
    "actual_time_seconds": _LIMITS["time_seconds"],
    "actual_input_tokens": _LIMITS["input_tokens"],
    "actual_output_tokens": _LIMITS["output_tokens"],
    "actual_retry_units": _LIMITS["retry_units"],
    "actual_human_attention_units": _LIMITS["human_attention_units"],
}
LEGACY_SOURCE_COLUMNS = (
    *_TEXT_FIELDS[:-1],
    "actual_time_seconds",
    "actual_input_tokens",
    "actual_output_tokens",
    "actual_cost_usd",
    "actual_retry_units",
    "actual_human_attention_units",
    "source_unit",
)


class LegacyMoneyImportError(BudgetError):
    """Legacy money import failed closed."""


class LegacyMoneyImportConflict(BudgetConflict, LegacyMoneyImportError):
    """A batch, idempotency key, or dedupe identity conflicts with prior payload."""


@dataclass(frozen=True)
class LegacyMoneyImportResult:
    batch_id: str
    status: Literal["promoted", "quarantined"]
    row_count: int
    promoted_count: int
    quarantine_count: int
    replayed: bool


@dataclass(frozen=True)
class _SourceCell:
    value: object
    storage_type: str
    quoted: str


@dataclass(frozen=True)
class _LegacyRow:
    source_row_ordinal: int
    legacy_row_id: str
    run_id: str
    transition_id: str
    spawn_request_id: str
    idempotency_key: str
    dedupe_key: str
    source: str
    clock_context_id: str
    usage_confidence: Literal["known", "estimated"]
    actual_usage: BudgetAmounts
    row_payload_hash: str


@dataclass(frozen=True)
class _Quarantine:
    source_row_ordinal: int
    legacy_row_id: str
    source_column: str
    source_type: str
    source_unit: str | None
    source_value_text: str | None
    reason_code: str
    reason_detail: str
    row_payload_hash: str


def legacy_terminal_usage_schema_sql() -> str:
    columns = ",\n  ".join(LEGACY_SOURCE_COLUMNS)
    return f"CREATE TABLE {LEGACY_SOURCE_TABLE} (\n  {columns}\n);"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _required_text_cell(
    cells: dict[str, _SourceCell],
    field: str,
    problems: list[_Quarantine],
    row_hash: str,
    source_row_ordinal: int,
) -> str | None:
    cell = cells[field]
    if cell.storage_type != "text" or not isinstance(cell.value, str) or not cell.value.strip():
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column=field,
                source_type=cell.storage_type,
                source_unit=_unit_for_quarantine(cells),
                source_value_text=cell.quoted,
                reason_code="invalid_text",
                reason_detail=f"{field} must be stored as non-empty SQLite TEXT",
                row_payload_hash=row_hash,
            )
        )
        return None
    return cell.value.strip()


def _unit_for_quarantine(cells: dict[str, _SourceCell]) -> str | None:
    cell = cells.get("source_unit")
    return cell.value if cell and isinstance(cell.value, str) else None


def _decimal_to_integral_microusd(decimal_value: Decimal) -> tuple[int | None, str | None]:
    sign, digits, exponent = decimal_value.as_tuple()
    if sign:
        return None, "money_out_of_range"
    if decimal_value.is_zero():
        return 0, None
    if decimal_value.adjusted() + 6 > _MAX_MONEY_MICROUSD_ADJUSTED:
        return None, "money_out_of_range"
    scale_exponent = exponent + 6
    if scale_exponent >= 0:
        coefficient = int("".join(str(digit) for digit in digits))
        microusd = coefficient * (10 ** scale_exponent)
    else:
        required_trailing_zeros = -scale_exponent
        trailing_zeros = 0
        for digit in reversed(digits):
            if digit != 0:
                break
            trailing_zeros += 1
        if trailing_zeros < required_trailing_zeros:
            return None, "fractional_microusd"
        integral_digits = digits[: len(digits) - required_trailing_zeros]
        if not integral_digits:
            return 0, None
        if any(digit != 0 for digit in digits[len(digits) - required_trailing_zeros :]):
            return None, "fractional_microusd"
        microusd = int("".join(str(digit) for digit in integral_digits))
    if microusd > _MAX_MONEY_MICROUSD:
        return None, "money_out_of_range"
    return microusd, None


def _integer_cell(
    cells: dict[str, _SourceCell],
    field: str,
    maximum: int,
    problems: list[_Quarantine],
    row_hash: str,
    source_row_ordinal: int,
) -> int:
    cell = cells[field]
    if cell.storage_type != "integer" or type(cell.value) is not int:
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column=field,
                source_type=cell.storage_type,
                source_unit=_unit_for_quarantine(cells),
                source_value_text=cell.quoted,
                reason_code="invalid_integer",
                reason_detail=f"{field} must be stored as SQLite INTEGER",
                row_payload_hash=row_hash,
            )
        )
        return 0
    if not 0 <= cell.value <= maximum:
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column=field,
                source_type=cell.storage_type,
                source_unit=_unit_for_quarantine(cells),
                source_value_text=cell.quoted,
                reason_code="integer_out_of_range",
                reason_detail=f"{field} must be in [0,{maximum}]",
                row_payload_hash=row_hash,
            )
        )
        return 0
    return cell.value


def _money_to_microusd(
    cells: dict[str, _SourceCell],
    problems: list[_Quarantine],
    row_hash: str,
    source_row_ordinal: int,
) -> int:
    unit = cells["source_unit"]
    money = cells["actual_cost_usd"]
    if unit.storage_type != "text" or unit.value != LEGACY_SOURCE_UNIT:
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="source_unit",
                source_type=unit.storage_type,
                source_unit=unit.value if isinstance(unit.value, str) else None,
                source_value_text=unit.quoted,
                reason_code="invalid_source_unit",
                reason_detail=f"source_unit must be exactly {LEGACY_SOURCE_UNIT!r}",
                row_payload_hash=row_hash,
            )
        )
        return 0
    if money.storage_type == "real" and isinstance(money.value, float) and not math.isfinite(money.value):
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="non_finite_money",
                reason_detail="actual_cost_usd must be finite",
                row_payload_hash=row_hash,
            )
        )
        return 0
    try:
        if money.storage_type == "text":
            if not isinstance(money.value, str) or not money.value.strip():
                raise InvalidOperation
            decimal_value = Decimal(money.value.strip())
        elif money.storage_type == "integer" and type(money.value) is int:
            decimal_value = Decimal(money.value)
        elif money.storage_type == "real" and isinstance(money.value, float):
            if not math.isfinite(money.value) or not money.value.is_integer():
                raise InvalidOperation
            decimal_value = Decimal(int(money.value))
        else:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="invalid_money",
                reason_detail=(
                    "actual_cost_usd must be TEXT decimal, INTEGER dollars, "
                    "or integral finite REAL dollars"
                ),
                row_payload_hash=row_hash,
            )
        )
        return 0
    if not decimal_value.is_finite():
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="non_finite_money",
                reason_detail="actual_cost_usd must be finite",
                row_payload_hash=row_hash,
            )
        )
        return 0
    value, conversion_error = _decimal_to_integral_microusd(decimal_value)
    if conversion_error == "money_out_of_range":
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="money_out_of_range",
                reason_detail=f"converted microusd must be in [0,{_LIMITS['cost_microusd']}]",
                row_payload_hash=row_hash,
            )
        )
        return 0
    if conversion_error == "fractional_microusd":
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="fractional_microusd",
                reason_detail="USD decimal does not convert to an integer microusd amount",
                row_payload_hash=row_hash,
            )
        )
        return 0
    if value is None or not 0 <= value <= _LIMITS["cost_microusd"]:
        problems.append(
            _Quarantine(
                source_row_ordinal=source_row_ordinal,
                legacy_row_id=str(cells.get("legacy_row_id", _SourceCell("", "", "")).value or "<missing>"),
                source_column="actual_cost_usd",
                source_type=money.storage_type,
                source_unit=LEGACY_SOURCE_UNIT,
                source_value_text=money.quoted,
                reason_code="money_out_of_range",
                reason_detail=f"converted microusd must be in [0,{_LIMITS['cost_microusd']}]",
                row_payload_hash=row_hash,
            )
        )
        return 0
    return value


def _read_source_rows(source_database: Path) -> tuple[list[_LegacyRow], list[_Quarantine], str]:
    source_path = Path(source_database).expanduser().resolve()
    uri = source_path.as_uri() + "?mode=ro"
    raw_rows: list[dict[str, Any]] = []
    rows: list[_LegacyRow] = []
    quarantines: list[_Quarantine] = []
    try:
        with sqlite3.connect(uri, uri=True) as source:
            source_object = source.execute(
                "SELECT type,sql FROM sqlite_schema WHERE name=? AND tbl_name=?",
                (LEGACY_SOURCE_TABLE, LEGACY_SOURCE_TABLE),
            ).fetchone()
            source_object_type = source_object[0] if source_object is not None else "missing"
            source_object_sql = source_object[1] if source_object is not None else None
            source_object_kind = source_object_type
            normalized_source_sql = " ".join(str(source_object_sql or "").lower().split())
            if (
                source_object_type == "table"
                and normalized_source_sql.startswith("create virtual table")
            ):
                source_object_kind = "virtual_table"
            if source_object_kind != "table":
                detail = (
                    f"expected {LEGACY_SOURCE_TABLE!r} to be a real SQLite table, "
                    f"found {source_object_kind!r}"
                )
                row_hash = _sha256_json(
                    {
                        "schema_object_type": source_object_kind,
                        "schema_object_sql": source_object_sql,
                        "source_path": str(source_path),
                    }
                )
                quarantines.append(
                    _Quarantine(
                        source_row_ordinal=0,
                        legacy_row_id="__schema__",
                        source_column="__schema__",
                        source_type=str(source_object_kind),
                        source_unit=None,
                        source_value_text=LEGACY_SOURCE_TABLE,
                        reason_code="invalid_source_schema",
                        reason_detail=detail,
                        row_payload_hash=row_hash,
                    )
                )
                return [], quarantines, _sha256_json(
                    {
                        "schema_object_type": source_object_kind,
                        "schema_object_sql": source_object_sql,
                        "source_path": str(source_path),
                    }
                )
            columns = [
                item[1]
                for item in source.execute(f"PRAGMA table_info({LEGACY_SOURCE_TABLE})")
            ]
            if columns != list(LEGACY_SOURCE_COLUMNS):
                detail = f"expected columns {list(LEGACY_SOURCE_COLUMNS)!r}, found {columns!r}"
                row_hash = _sha256_json({"schema_columns": columns})
                quarantines.append(
                    _Quarantine(
                        source_row_ordinal=0,
                        legacy_row_id="__schema__",
                        source_column="__schema__",
                        source_type="schema",
                        source_unit=None,
                        source_value_text=str(columns),
                        reason_code="invalid_source_schema",
                        reason_detail=detail,
                        row_payload_hash=row_hash,
                    )
                )
                return [], quarantines, _sha256_json({"schema_error": columns})
            select_parts = []
            for column in LEGACY_SOURCE_COLUMNS:
                select_parts.extend(
                    [
                        column,
                        f"typeof({column}) AS {column}__type",
                        f"quote({column}) AS {column}__quote",
                    ]
                )
            query = (
                "SELECT "
                + ",".join(select_parts)
                + f" FROM {LEGACY_SOURCE_TABLE} ORDER BY rowid"
            )
            for source_row_ordinal, record in enumerate(source.execute(query).fetchall(), start=1):
                cells: dict[str, _SourceCell] = {}
                offset = 0
                for column in LEGACY_SOURCE_COLUMNS:
                    cells[column] = _SourceCell(
                        record[offset],
                        str(record[offset + 1]),
                        str(record[offset + 2]),
                    )
                    offset += 3
                raw_payload = {
                    column: {
                        "value": cells[column].value,
                        "type": cells[column].storage_type,
                        "quote": cells[column].quoted,
                    }
                    for column in LEGACY_SOURCE_COLUMNS
                }
                row_hash = _sha256_json(raw_payload)
                raw_rows.append(
                    {
                        "source_row_ordinal": source_row_ordinal,
                        "row_payload_hash": row_hash,
                        "payload": raw_payload,
                    }
                )
                problems: list[_Quarantine] = []
                text_values = {
                    field: _required_text_cell(
                        cells, field, problems, row_hash, source_row_ordinal
                    )
                    for field in _TEXT_FIELDS
                }
                integer_values = {
                    field: _integer_cell(
                        cells, field, maximum, problems, row_hash, source_row_ordinal
                    )
                    for field, maximum in _INTEGER_FIELDS.items()
                }
                cost_microusd = _money_to_microusd(
                    cells, problems, row_hash, source_row_ordinal
                )
                usage_confidence = text_values["usage_confidence"]
                if usage_confidence not in {"known", "estimated"}:
                    problems.append(
                        _Quarantine(
                            source_row_ordinal=source_row_ordinal,
                            legacy_row_id=str(text_values["legacy_row_id"] or "<missing>"),
                            source_column="usage_confidence",
                            source_type=cells["usage_confidence"].storage_type,
                            source_unit=_unit_for_quarantine(cells),
                            source_value_text=cells["usage_confidence"].quoted,
                            reason_code="invalid_usage_confidence",
                            reason_detail="usage_confidence must be 'known' or 'estimated'",
                            row_payload_hash=row_hash,
                        )
                    )
                if problems:
                    quarantines.extend(problems)
                    continue
                rows.append(
                    _LegacyRow(
                        source_row_ordinal=source_row_ordinal,
                        legacy_row_id=text_values["legacy_row_id"] or "",
                        run_id=text_values["run_id"] or "",
                        transition_id=text_values["transition_id"] or "",
                        spawn_request_id=text_values["spawn_request_id"] or "",
                        idempotency_key=text_values["idempotency_key"] or "",
                        dedupe_key=text_values["dedupe_key"] or "",
                        source=text_values["source"] or "",
                        clock_context_id=text_values["clock_context_id"] or "",
                        usage_confidence=usage_confidence,  # type: ignore[arg-type]
                        actual_usage=BudgetAmounts(
                            time_seconds=integer_values["actual_time_seconds"],
                            input_tokens=integer_values["actual_input_tokens"],
                            output_tokens=integer_values["actual_output_tokens"],
                            cost_microusd=cost_microusd,
                            retry_units=integer_values["actual_retry_units"],
                            human_attention_units=integer_values[
                                "actual_human_attention_units"
                            ],
                        ),
                        row_payload_hash=row_hash,
                    )
                )
    except sqlite3.Error as exc:
        row_hash = _sha256_json({"sqlite_error": str(exc)})
        raw_rows.append(
            {
                "source_read_failed": {
                    "source_path": str(source_path),
                    "sqlite_error": str(exc),
                },
                "row_payload_hash": row_hash,
            }
        )
        quarantines.append(
            _Quarantine(
                source_row_ordinal=0,
                legacy_row_id="__source__",
                source_column="__source__",
                source_type="sqlite",
                source_unit=None,
                source_value_text=str(source_path),
                reason_code="source_read_failed",
                reason_detail=str(exc),
                row_payload_hash=row_hash,
            )
        )
    return rows, quarantines, _sha256_json(raw_rows)


def _quarantine_id(batch_id: str, quarantine: _Quarantine) -> str:
    return "legacy-quarantine-" + _sha256_json(
        {
            "batch_id": batch_id,
            "source_row_ordinal": quarantine.source_row_ordinal,
            "legacy_row_id": quarantine.legacy_row_id,
            "source_column": quarantine.source_column,
            "reason_code": quarantine.reason_code,
            "row_payload_hash": quarantine.row_payload_hash,
        }
    )


def _insert_batch(
    connection: sqlite3.Connection,
    *,
    batch_id: str,
    payload_hash: str,
    status: Literal["promoted", "quarantined"],
    row_count: int,
    quarantine_count: int,
    promoted_count: int,
    failure_reason: str | None,
    timestamp: str,
) -> None:
    connection.execute(
        "INSERT INTO legacy_money_import_batches("
        "batch_id,source_schema_version,source_table,source_unit,payload_hash,"
        "status,row_count,quarantine_count,promoted_count,created_at,completed_at,"
        "failure_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            batch_id,
            LEGACY_SOURCE_SCHEMA_VERSION,
            LEGACY_SOURCE_TABLE,
            LEGACY_SOURCE_UNIT,
            payload_hash,
            status,
            row_count,
            quarantine_count,
            promoted_count,
            timestamp,
            timestamp,
            failure_reason,
        ),
    )


def _source_row_count(rows: list[_LegacyRow], quarantines: list[_Quarantine]) -> int:
    source_rows = {item.source_row_ordinal for item in rows if item.source_row_ordinal > 0}
    source_rows.update(
        item.source_row_ordinal for item in quarantines if item.source_row_ordinal > 0
    )
    non_row_evidence = {
        item.legacy_row_id
        for item in quarantines
        if item.source_row_ordinal == 0
    }
    return len(source_rows) + len(non_row_evidence)


def _reject_changed_legacy_payload_replay(
    connection: sqlite3.Connection, rows: list[_LegacyRow]
) -> None:
    for row in rows:
        existing_hashes = [
            item[0]
            for item in connection.execute(
                "SELECT lip.row_payload_hash FROM legacy_money_import_promotions lip "
                "JOIN budget_settlements bs ON bs.settlement_id=lip.settlement_id "
                "WHERE bs.settlement_idempotency_key=? OR bs.settlement_dedupe_hash=?",
                (row.idempotency_key, _dedupe_hash(row.dedupe_key)),
            ).fetchall()
        ]
        if any(existing_hash != row.row_payload_hash for existing_hash in existing_hashes):
            raise LegacyMoneyImportConflict(
                "legacy import identity was reused with another raw payload"
            )


def _incoming_identity_conflict_quarantines(rows: list[_LegacyRow]) -> list[_Quarantine]:
    identity_rows: dict[tuple[str, str], list[_LegacyRow]] = {}
    for row in rows:
        identity_rows.setdefault(("idempotency_key", row.idempotency_key), []).append(row)
        identity_rows.setdefault(("dedupe_hash", _dedupe_hash(row.dedupe_key)), []).append(row)

    conflicted: dict[int, _LegacyRow] = {}
    for members in identity_rows.values():
        if len({member.row_payload_hash for member in members}) > 1:
            for member in members:
                conflicted[member.source_row_ordinal] = member

    return [
        _Quarantine(
            source_row_ordinal=row.source_row_ordinal,
            legacy_row_id=row.legacy_row_id,
            source_column="__identity__",
            source_type="runtime",
            source_unit=LEGACY_SOURCE_UNIT,
            source_value_text=row.idempotency_key,
            reason_code="incoming_identity_conflict",
            reason_detail=(
                "incoming legacy rows reuse an idempotency or dedupe identity "
                "with different raw payloads"
            ),
            row_payload_hash=row.row_payload_hash,
        )
        for row in sorted(
            conflicted.values(), key=lambda item: item.source_row_ordinal
        )
    ]


def _record_quarantine_batch(
    database: Path,
    *,
    batch_id: str,
    payload_hash: str,
    rows: list[_LegacyRow],
    quarantines: list[_Quarantine],
    failure_reason: str,
) -> LegacyMoneyImportResult:
    connection = _connect(Path(database))
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            existing = connection.execute(
                "SELECT payload_hash,status,row_count,promoted_count,quarantine_count "
                "FROM legacy_money_import_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload_hash:
                    raise LegacyMoneyImportConflict(
                        "legacy import batch_id was reused with another payload"
                    )
                connection.execute("COMMIT")
                return LegacyMoneyImportResult(
                    batch_id=batch_id,
                    status=existing[1],
                    row_count=existing[2],
                    promoted_count=existing[3],
                    quarantine_count=existing[4],
                    replayed=True,
                )
            timestamp = _utc_now()
            for quarantine in quarantines:
                connection.execute(
                    "INSERT INTO legacy_money_import_quarantine("
                    "quarantine_id,batch_id,source_row_ordinal,legacy_row_id,"
                    "source_column,source_type,"
                    "source_unit,source_value_text,reason_code,reason_detail,"
                    "row_payload_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        _quarantine_id(batch_id, quarantine),
                        batch_id,
                        quarantine.source_row_ordinal,
                        quarantine.legacy_row_id,
                        quarantine.source_column,
                        quarantine.source_type,
                        quarantine.source_unit,
                        quarantine.source_value_text,
                        quarantine.reason_code,
                        quarantine.reason_detail,
                        quarantine.row_payload_hash,
                        timestamp,
                    ),
                )
            _insert_batch(
                connection,
                batch_id=batch_id,
                payload_hash=payload_hash,
                status="quarantined",
                row_count=_source_row_count(rows, quarantines),
                quarantine_count=len(quarantines),
                promoted_count=0,
                failure_reason=failure_reason,
                timestamp=timestamp,
            )
            connection.execute("COMMIT")
            return LegacyMoneyImportResult(
                batch_id=batch_id,
                status="quarantined",
                row_count=_source_row_count(rows, quarantines),
                promoted_count=0,
                quarantine_count=len(quarantines),
                replayed=False,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    finally:
        connection.close()


def import_legacy_terminal_usage(
    database: Path,
    legacy_database: Path,
    *,
    batch_id: str,
) -> LegacyMoneyImportResult:
    """Import explicit v1 legacy USD-decimal terminal usage rows.

    The legacy schema is ``legacy_budget_terminal_usage_v1`` and the only
    accepted money unit is ``usd_decimal``.  Any quarantined row leaves the
    authoritative budget tables untouched for the whole batch.
    """

    if not isinstance(batch_id, str) or not batch_id.strip():
        raise LegacyMoneyImportError("batch_id must be a non-empty string")
    batch_id = batch_id.strip()
    rows, quarantines, payload_hash = _read_source_rows(Path(legacy_database))
    if quarantines:
        return _record_quarantine_batch(
            database,
            batch_id=batch_id,
            payload_hash=payload_hash,
            rows=rows,
            quarantines=quarantines,
            failure_reason="source validation failed",
        )
    incoming_identity_conflicts = _incoming_identity_conflict_quarantines(rows)
    if incoming_identity_conflicts:
        return _record_quarantine_batch(
            database,
            batch_id=batch_id,
            payload_hash=payload_hash,
            rows=rows,
            quarantines=incoming_identity_conflicts,
            failure_reason="incoming identity conflict",
        )

    connection = _connect(Path(database))
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            existing = connection.execute(
                "SELECT payload_hash,status,row_count,promoted_count,quarantine_count "
                "FROM legacy_money_import_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload_hash:
                    raise LegacyMoneyImportConflict(
                        "legacy import batch_id was reused with another payload"
                    )
                connection.execute("COMMIT")
                return LegacyMoneyImportResult(
                    batch_id=batch_id,
                    status=existing[1],
                    row_count=existing[2],
                    promoted_count=existing[3],
                    quarantine_count=existing[4],
                    replayed=True,
                )
            _reject_changed_legacy_payload_replay(connection, rows)
            results = []
            for row in rows:
                selection = _selected_binding(
                    connection,
                    run_id=row.run_id,
                    transition_id=row.transition_id,
                    allow_unknown_usage=True,
                )
                results.append(
                    _settle_budget_on_connection(
                        connection,
                        run_id=row.run_id,
                        transition_id=row.transition_id,
                        selection=selection,
                        actual_usage=row.actual_usage,
                        idempotency_key=row.idempotency_key,
                        dedupe_key=row.dedupe_key,
                        source=row.source,
                        spawn_request_id=row.spawn_request_id,
                        clock_context_id=row.clock_context_id,
                        usage_confidence=row.usage_confidence,
                        schema_verified=True,
                    )
                )
            timestamp = _utc_now()
            for row, result in zip(rows, results):
                connection.execute(
                    "INSERT INTO legacy_money_import_promotions("
                    "batch_id,legacy_row_id,row_payload_hash,settlement_id,promoted_at"
                    ") VALUES(?,?,?,?,?)",
                    (
                        batch_id,
                        row.legacy_row_id,
                        row.row_payload_hash,
                        result.settlement_id,
                        timestamp,
                    ),
                )
            _insert_batch(
                connection,
                batch_id=batch_id,
                payload_hash=payload_hash,
                status="promoted",
                row_count=len(rows),
                quarantine_count=0,
                promoted_count=len(rows),
                failure_reason=None,
                timestamp=timestamp,
            )
            connection.execute("COMMIT")
            return LegacyMoneyImportResult(
                batch_id=batch_id,
                status="promoted",
                row_count=len(rows),
                promoted_count=len(rows),
                quarantine_count=0,
                replayed=False,
            )
        except (BudgetError, sqlite3.Error) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            quarantine_rows = [
                _Quarantine(
                    source_row_ordinal=row.source_row_ordinal,
                    legacy_row_id=row.legacy_row_id,
                    source_column="__promotion__",
                    source_type="runtime",
                    source_unit=LEGACY_SOURCE_UNIT,
                    source_value_text=row.idempotency_key,
                    reason_code="promotion_failed",
                    reason_detail=str(exc),
                    row_payload_hash=row.row_payload_hash,
                )
                for row in rows
            ]
            return _record_quarantine_batch(
                database,
                batch_id=batch_id,
                payload_hash=payload_hash,
                rows=rows,
                quarantines=quarantine_rows,
                failure_reason="promotion failed",
            )
    finally:
        connection.close()
