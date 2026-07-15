"""Fail-closed transactional budget ledger operations.

The SQLite ``budget_events`` table is authoritative.  ``run_budgets`` counters
are updated in the same ``BEGIN IMMEDIATE`` transaction and are never repaired
implicitly when a write cannot be proven safe.
"""

from __future__ import annotations

import hashlib
import stat
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from .migrations import (
    _database_checks,
    _verify_schema,
    _verify_slo_queries,
    MigrationError,
    load_migrations,
    repository_root,
)
from .privacy import PrivacyPreflightError, assert_privacy_preflight
from .slo_contracts import SLO_QUERY_CONTRACTS


class BudgetError(RuntimeError):
    """A budget mutation could not be proven safe."""


class BudgetConflict(BudgetError):
    """An idempotency or dedupe identity was reused for different work."""


class BudgetExceeded(BudgetError):
    """A mutation exceeded the selected budget or outstanding reservation."""


_LIMITS = {
    "time_seconds": 31_536_000,
    "input_tokens": 1_000_000_000,
    "output_tokens": 1_000_000_000,
    "cost_microusd": 100_000_000_000,
    "retry_units": 1_000_000,
    "human_attention_units": 1_000_000,
}
_MAX_EVENT_SEQUENCE = 1_000_000
_MAX_EPOCH_MS = 253_402_300_799_999
_USAGE_CONFIDENCE = {"known", "estimated"}
_POST_DISPATCH_USAGE_CONFIDENCE = {"known", "estimated", "unknown"}
_BUDGET_INVARIANT_QUERIES = {
    "Duplicate live dispatch blocked",
    "Accepted `sessions_spawn` without exact accepted session identity",
    "Unknown usage blocks auto-local",
    "Model cost registry numeric bounds",
    "Endpoint-bound budget event cost row blocks dispatch",
    "Run budget selected cost row mismatch",
    "`sessions_spawn` intent without exact strict prior reserve",
    "Invalid zero-reserve policy",
    "Meaningless `sessions_spawn` reserve",
    "Budget event amount malformed or out of range",
    "Budget counters outside selected budget",
    "Budget ledger reconciles to counters and budgets",
    "Budget prefix over-release or over-restore",
    "Duplicate or replayed budget events",
    "Budget event count bounded for SUM safety",
}
_BUDGET_MUTATION_RUN_STATES = {"candidate"}
_POST_DISPATCH_RUN_STATES = {
    "dispatched",
    "first_output_waiting",
    "running",
    "child_completed",
    "child_failed",
    "aggregation_completed",
}
_FINAL_SETTLEMENT_RUN_STATES = {
    "child_completed",
    "child_failed",
    "aggregation_completed",
}


@dataclass(frozen=True)
class BudgetAmounts:
    time_seconds: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_microusd: int = 0
    retry_units: int = 0
    human_attention_units: int = 0

    def __post_init__(self) -> None:
        for field, maximum in _LIMITS.items():
            value = getattr(self, field)
            if type(value) is not int or not 0 <= value <= maximum:
                raise BudgetError(
                    f"{field} must be an integer in [0,{maximum}], found {value!r}"
                )

    def is_zero(self) -> bool:
        return not any(asdict(self).values())


@dataclass(frozen=True)
class BudgetSelection:
    provider: str
    model: str
    endpoint_binding_id: str
    capability_class: str
    cost_registry_id: str
    cost_effective_at: str
    cost_registry_hash: str
    cost_confidence: Literal["known", "estimated"]
    input_cost_microusd_per_million: int
    output_cost_microusd_per_million: int


@dataclass(frozen=True)
class BudgetEventResult:
    budget_event_id: str
    event_sequence: int
    replayed: bool


@dataclass(frozen=True)
class BudgetSettlementResult:
    settlement_id: str
    events: tuple[BudgetEventResult, ...]
    released: BudgetAmounts
    replayed: bool


def _required_text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BudgetError(f"{label} must be a non-empty string")
    return value.strip()


def _event_id(idempotency_key: str) -> str:
    digest = hashlib.sha256(
        f"agentic-os-budget-event\0{idempotency_key}".encode("utf-8")
    ).hexdigest()
    return f"budget-{digest}"


def _dedupe_hash(dedupe_key: str) -> str:
    return hashlib.sha256(
        f"agentic-os-budget-dedupe\0{dedupe_key}".encode("utf-8")
    ).hexdigest()


def _settlement_id(idempotency_key: str) -> str:
    digest = hashlib.sha256(
        f"agentic-os-budget-settlement\0{idempotency_key}".encode("utf-8")
    ).hexdigest()
    return f"settlement-{digest}"


def _created_at(epoch_ms: int) -> str:
    if type(epoch_ms) is not int or not 1 <= epoch_ms <= _MAX_EPOCH_MS:
        raise BudgetError(
            f"created_at_epoch_ms must be an integer in [1,{_MAX_EPOCH_MS}]"
        )
    return (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(milliseconds=epoch_ms)
    ).isoformat()


def _trusted_created_at(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    transition_id: str,
    clock_context_id: str,
) -> tuple[str, int]:
    row = connection.execute(
        "SELECT c.now_epoch_ms FROM gate_clock_context c "
        "JOIN gate_runs g ON g.gate_run_id=c.gate_run_id "
        " AND g.clock_context_id=c.clock_context_id "
        " AND g.run_id=c.run_id AND g.transition_id=c.transition_id "
        "WHERE c.clock_context_id=? AND c.run_id=? AND c.transition_id=? "
        " AND c.gate_run_id=c.consumed_by_gate_run_id "
        " AND c.bound_at_epoch_ms=c.now_epoch_ms "
        " AND c.consumed_at_epoch_ms=c.now_epoch_ms "
        " AND c.trusted_clock_source_hash<>'' AND c.gate_nonce<>'' "
        " AND g.decision='pass' AND g.completed_at_epoch_ms=c.now_epoch_ms",
        (clock_context_id, run_id, transition_id),
    ).fetchone()
    if row is None:
        raise BudgetError(
            "budget event requires a trusted same-run, same-transition "
            "gate/order clock context"
        )
    epoch_ms = row[0]
    return _created_at(epoch_ms), epoch_ms


def _connect(database: Path) -> sqlite3.Connection:
    path = Path(database).expanduser().resolve()
    try:
        assert_privacy_preflight(repository_root(), database_paths=(path,))
    except PrivacyPreflightError as exc:
        raise BudgetError("budget database privacy preflight failed") from exc
    if not path.is_file():
        raise BudgetError("budget database must already exist and be a regular file")
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    file_mode = stat.S_IMODE(path.stat().st_mode)
    if parent_mode != 0o700 or file_mode != 0o600:
        raise BudgetError(
            "budget database requires a 0700 directory and 0600 database file"
        )
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() and stat.S_IMODE(sidecar.stat().st_mode) != 0o600:
            raise BudgetError(f"budget database sidecar must have mode 0600: {sidecar}")
    database_uri = path.as_uri() + "?mode=rw"
    try:
        connection = sqlite3.connect(database_uri, uri=True, isolation_level=None)
    except sqlite3.Error as exc:
        raise BudgetError("budget database must already exist and be writable") from exc
    connection.execute("PRAGMA busy_timeout=10000")
    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    actual_journal_mode = journal_mode[0] if journal_mode else None
    if str(actual_journal_mode).casefold() != "wal":
        connection.close()
        raise BudgetError(
            "SQLite WAL journal mode is unavailable: "
            f"requested WAL, got {actual_journal_mode!r}"
        )
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
        connection.close()
        raise BudgetError("SQLite foreign key enforcement is unavailable")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() and stat.S_IMODE(sidecar.stat().st_mode) != 0o600:
            connection.close()
            raise BudgetError(f"budget database sidecar must have mode 0600: {sidecar}")
    return connection


def _verify_schema_identity(connection: sqlite3.Connection) -> None:
    migrations = load_migrations()
    expected = [(item.version, item.name, item.sha256) for item in migrations]
    try:
        actual = connection.execute(
            "SELECT version,name,sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
    except sqlite3.Error as exc:
        raise BudgetError("budget database is not migrated") from exc
    if actual != expected:
        raise BudgetError("budget database migration identity does not match pinned schema")
    try:
        _verify_schema(connection, migrations)
        _verify_slo_queries(connection, migrations)
        _database_checks(connection)
    except (MigrationError, sqlite3.Error) as exc:
        raise BudgetError("budget database schema verification failed") from exc


def _selected_binding(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    transition_id: str,
    allow_unknown_usage: bool = False,
) -> BudgetSelection:
    usage_clause = "" if allow_unknown_usage else (
        " AND rb.usage_confidence IN ('known','estimated')"
    )
    row = connection.execute(
        "SELECT rb.selected_provider,rb.selected_model,"
        "rb.selected_endpoint_binding_id,rb.capability_class,"
        "rb.selected_cost_registry_id,rb.selected_cost_effective_at,"
        "rb.selected_cost_registry_hash,rb.selected_cost_confidence,"
        "m.input_cost_microusd_per_million,m.output_cost_microusd_per_million "
        "FROM run_budgets rb "
        "JOIN runs r ON r.run_id=rb.run_id AND r.workflow=rb.workflow "
        "JOIN transitions t ON t.transition_id=rb.selected_reserve_transition_id "
        " AND t.run_id=rb.run_id "
        "JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id "
        " AND m.provider=rb.selected_provider "
        " AND m.model=rb.selected_model "
        " AND m.endpoint_binding_id=rb.selected_endpoint_binding_id "
        " AND m.capability_class=rb.capability_class "
        " AND m.effective_at=rb.selected_cost_effective_at "
        " AND m.registry_row_hash=rb.selected_cost_registry_hash "
        " AND m.confidence=rb.selected_cost_confidence "
        "WHERE rb.run_id=? AND rb.selected_reserve_transition_id=? "
        " AND rb.selected_cost_confidence IN ('known','estimated') "
        + usage_clause,
        (run_id, transition_id),
    ).fetchone()
    if row is None:
        raise BudgetError(
            "run budget is absent, unknown, or not exactly bound to the transition/cost row"
        )
    return BudgetSelection(*row)


def _required_cost(selection: BudgetSelection, amounts: BudgetAmounts) -> int:
    def rounded_up(tokens: int, price: int) -> int:
        if type(price) is not int or not 0 <= price <= 100_000_000_000:
            raise BudgetError("selected registry price is malformed")
        return (tokens * price + 999_999) // 1_000_000

    required = rounded_up(
        amounts.input_tokens, selection.input_cost_microusd_per_million
    ) + rounded_up(
        amounts.output_tokens, selection.output_cost_microusd_per_million
    )
    if required > _LIMITS["cost_microusd"]:
        raise BudgetExceeded("selected token reservation cost exceeds fixed-point limit")
    return required


def _assert_budget_invariants(connection: sqlite3.Connection) -> None:
    unknown_usage = connection.execute(
        "SELECT be.budget_event_id FROM budget_events be "
        "JOIN runs r ON r.run_id=be.run_id "
        "LEFT JOIN run_budgets rb ON rb.run_id=be.run_id "
        "WHERE be.usage_confidence='unknown' AND ("
        "rb.run_id IS NULL OR rb.usage_confidence IS NOT 'unknown' OR "
        "r.state IN ('gate_passed','release_pending','finalized') OR NOT ("
        "be.event_type='consume' AND be.time_seconds=0 AND be.input_tokens=0 "
        "AND be.output_tokens=0 AND be.cost_microusd=0 "
        "AND be.retry_units=0 AND be.human_attention_units=0)) LIMIT 1"
    ).fetchone()
    if unknown_usage is not None:
        raise BudgetError("unknown usage confidence already exists in budget ledger")
    contracts = {
        item.query_name: item.sql_text
        for item in SLO_QUERY_CONTRACTS
        if item.query_name in _BUDGET_INVARIANT_QUERIES
    }
    missing = _BUDGET_INVARIANT_QUERIES - set(contracts)
    if missing:
        raise BudgetError(f"required budget SLO contracts are missing: {sorted(missing)}")
    for query_name in sorted(contracts):
        if connection.execute(contracts[query_name]).fetchone() is not None:
            raise BudgetError(f"budget invariant failed: {query_name}")
    invalid_binding = connection.execute(
        "SELECT be.budget_event_id FROM budget_events be "
        "LEFT JOIN spawn_requests sr ON sr.spawn_request_id=be.spawn_request_id "
        " AND sr.run_id=be.run_id AND sr.transition_id=be.transition_id "
        "LEFT JOIN run_budgets rb ON rb.run_id=be.run_id "
        "WHERE be.event_type IN ('reserve','consume','release',"
        "'retry_decrement','retry_restore') AND ("
        "be.spawn_request_id IS NULL OR sr.spawn_request_id IS NULL "
        "OR rb.run_id IS NULL OR be.provider<>rb.selected_provider "
        "OR be.transition_id<>rb.selected_reserve_transition_id "
        "OR be.model<>rb.selected_model "
        "OR be.endpoint_binding_id<>rb.selected_endpoint_binding_id "
        "OR be.capability_class<>rb.capability_class "
        "OR be.cost_registry_id<>rb.selected_cost_registry_id "
        "OR be.cost_effective_at<>rb.selected_cost_effective_at "
        "OR be.cost_registry_hash<>rb.selected_cost_registry_hash "
        "OR be.cost_confidence<>rb.selected_cost_confidence) LIMIT 1"
    ).fetchone()
    if invalid_binding is not None:
        raise BudgetError("budget event is not composite-bound to its spawn and cost row")
    has_settlements = connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='budget_settlements'"
    ).fetchone()
    if has_settlements is not None:
        invalid_settlement = connection.execute(
            "SELECT bs.settlement_id FROM budget_settlements bs WHERE "
            "((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 "
            "OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) "
            "IS NOT (SELECT COUNT(*)=1 FROM budget_events be "
            "WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume')) "
            "OR ((bs.actual_retry_units>0) IS NOT (SELECT COUNT(*)=1 "
            "FROM budget_events be WHERE be.settlement_id=bs.settlement_id "
            "AND be.event_type='retry_decrement')) "
            "OR ((bs.actual_human_attention_units>0) IS NOT (SELECT COUNT(*)=1 "
            "FROM budget_events be WHERE be.settlement_id=bs.settlement_id "
            "AND be.event_type='human_attention')) "
            "OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 "
            "OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 "
            "OR bs.released_retry_units>0 OR bs.released_human_attention_units>0) "
            "IS NOT (SELECT COUNT(*)=1 FROM budget_events be "
            "WHERE be.settlement_id=bs.settlement_id AND be.event_type='release')) "
            "OR EXISTS (SELECT 1 FROM budget_events be "
            "WHERE be.settlement_id=bs.settlement_id "
            "AND be.event_type NOT IN ('consume','retry_decrement',"
            "'human_attention','release')) LIMIT 1"
        ).fetchone()
        if invalid_settlement is not None:
            raise BudgetError("atomic final settlement ledger is incomplete or malformed")
    invalid_spawn_prefix = connection.execute(
        "WITH ordered AS ("
        "SELECT budget_event_id,"
        "SUM(CASE WHEN event_type='reserve' THEN time_seconds "
        "WHEN event_type IN ('consume','release') THEN -time_seconds ELSE 0 END) "
        "OVER ledger_window AS net_time,"
        "SUM(CASE WHEN event_type='reserve' THEN input_tokens "
        "WHEN event_type IN ('consume','release') THEN -input_tokens ELSE 0 END) "
        "OVER ledger_window AS net_input,"
        "SUM(CASE WHEN event_type='reserve' THEN output_tokens "
        "WHEN event_type IN ('consume','release') THEN -output_tokens ELSE 0 END) "
        "OVER ledger_window AS net_output,"
        "SUM(CASE WHEN event_type='reserve' THEN cost_microusd "
        "WHEN event_type IN ('consume','release') THEN -cost_microusd ELSE 0 END) "
        "OVER ledger_window AS net_cost,"
        "SUM(CASE WHEN event_type='reserve' THEN retry_units "
        "WHEN event_type IN ('release','retry_decrement') THEN -retry_units "
        "WHEN event_type='retry_restore' THEN retry_units ELSE 0 END) "
        "OVER ledger_window AS net_retry,"
        "SUM(CASE WHEN event_type='retry_decrement' THEN retry_units "
        "WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END) "
        "OVER ledger_window AS net_consumed_retry,"
        "SUM(CASE WHEN event_type='reserve' THEN human_attention_units "
        "WHEN event_type IN ('release','human_attention') "
        "THEN -human_attention_units ELSE 0 END) "
        "OVER ledger_window AS net_human "
        "FROM budget_events "
        "WHERE event_type IN ('reserve','consume','release','retry_decrement',"
        "'retry_restore','human_attention') "
        "WINDOW ledger_window AS (PARTITION BY run_id,transition_id,"
        "spawn_request_id,capability_class "
        "ORDER BY event_sequence,budget_event_id ROWS BETWEEN UNBOUNDED PRECEDING "
        "AND CURRENT ROW)) "
        "SELECT budget_event_id FROM ordered WHERE net_time<0 OR net_input<0 "
        "OR net_output<0 OR net_cost<0 OR net_retry<0 OR net_consumed_retry<0 "
        "OR net_human<0 LIMIT 1"
    ).fetchone()
    if invalid_spawn_prefix is not None:
        raise BudgetError("per-spawn budget ledger prefix over-releases a reservation")


def _spawn_outstanding(
    connection: sqlite3.Connection,
    *,
    spawn_request_id: str,
    run_id: str,
    transition_id: str,
    selection: BudgetSelection,
) -> BudgetAmounts:
    row = connection.execute(
        "SELECT "
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN time_seconds "
        "WHEN event_type IN ('consume','release') THEN -time_seconds ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN input_tokens "
        "WHEN event_type IN ('consume','release') THEN -input_tokens ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN output_tokens "
        "WHEN event_type IN ('consume','release') THEN -output_tokens ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN cost_microusd "
        "WHEN event_type IN ('consume','release') THEN -cost_microusd ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN retry_units "
        "WHEN event_type IN ('release','retry_decrement') THEN -retry_units "
        "WHEN event_type='retry_restore' THEN retry_units ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='reserve' THEN human_attention_units "
        "WHEN event_type IN ('release','human_attention') "
        "THEN -human_attention_units ELSE 0 END),0) "
        "FROM budget_events WHERE spawn_request_id=? AND run_id=? AND transition_id=? "
        "AND ((event_type='human_attention' AND capability_class=?) OR ("
        "event_type<>'human_attention' AND provider=? AND model=? "
        "AND endpoint_binding_id=? AND capability_class=? AND cost_registry_id=? "
        "AND cost_effective_at=? AND cost_registry_hash=? AND cost_confidence=?))",
        (
            spawn_request_id,
            run_id,
            transition_id,
            selection.capability_class,
            selection.provider,
            selection.model,
            selection.endpoint_binding_id,
            selection.capability_class,
            selection.cost_registry_id,
            selection.cost_effective_at,
            selection.cost_registry_hash,
            selection.cost_confidence,
        ),
    ).fetchone()
    try:
        return BudgetAmounts(*row)
    except BudgetError as exc:
        raise BudgetError("spawn request has an invalid outstanding reservation") from exc


def _zero_policy_hash(
    connection: sqlite3.Connection,
    *,
    zero_reserve_policy_id: str | None,
    selection: BudgetSelection,
) -> str | None:
    if zero_reserve_policy_id is None:
        return None
    policy_id = _required_text("zero_reserve_policy_id", zero_reserve_policy_id)
    row = connection.execute(
        "SELECT policy_hash FROM endpoint_zero_reserve_policies "
        "WHERE zero_reserve_policy_id=? AND endpoint_binding_id=? "
        "AND capability_class=?",
        (policy_id, selection.endpoint_binding_id, selection.capability_class),
    ).fetchone()
    if row is None:
        raise BudgetError("zero-reserve policy does not match the selected endpoint")
    return row[0]


_EVENT_COMPARE_COLUMNS = (
    "budget_event_id,event_dedupe_hash,run_id,transition_id,spawn_request_id,"
    "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
    "cost_effective_at,cost_registry_hash,cost_confidence,zero_reserve_policy_id,"
    "zero_reserve_policy_hash,event_type,time_seconds,input_tokens,output_tokens,"
    "cost_microusd,human_attention_units,retry_units,usage_confidence,source,"
    "created_at,created_at_epoch_ms,clock_context_id"
)


def _existing_event(
    connection: sqlite3.Connection,
    *,
    idempotency_key: str,
    expected: tuple[object, ...],
) -> BudgetEventResult | None:
    row = connection.execute(
        f"SELECT {_EVENT_COMPARE_COLUMNS},event_sequence FROM budget_events "
        "WHERE event_idempotency_key=?",
        (idempotency_key,),
    ).fetchone()
    if row is None:
        return None
    if row[:-1] != expected:
        raise BudgetConflict("budget event idempotency key was reused with another payload")
    return BudgetEventResult(row[0], row[-1], True)


def _update_counters(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    run_id: str,
    amounts: BudgetAmounts,
    usage_confidence: str,
    updated_at: str,
) -> None:
    values = (
        amounts.time_seconds,
        amounts.input_tokens,
        amounts.output_tokens,
        amounts.cost_microusd,
        amounts.retry_units,
        amounts.human_attention_units,
    )
    if event_type == "reserve":
        sql = (
            "UPDATE run_budgets SET "
            "reserved_time_seconds=reserved_time_seconds+?,"
            "reserved_input_tokens=reserved_input_tokens+?,"
            "reserved_output_tokens=reserved_output_tokens+?,"
            "reserved_cost_microusd=reserved_cost_microusd+?,"
            "reserved_retries=reserved_retries+?,"
            "reserved_human_attention=reserved_human_attention+?,"
            "usage_confidence=CASE WHEN usage_confidence='known' AND ?='estimated' "
            "THEN 'estimated' ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? "
            "AND reserved_time_seconds+consumed_time_seconds+?<=time_budget_seconds "
            "AND reserved_input_tokens+consumed_input_tokens+?<=input_token_budget "
            "AND reserved_output_tokens+consumed_output_tokens+?<=output_token_budget "
            "AND reserved_cost_microusd+consumed_cost_microusd+?<=cost_budget_microusd "
            "AND reserved_retries+consumed_retries+?<=retry_budget "
            "AND reserved_human_attention+consumed_human_attention+?<=human_attention_budget"
        )
        parameters = (*values, usage_confidence, updated_at, run_id, *values)
    else:
        sql = (
            "UPDATE run_budgets SET "
            "reserved_time_seconds=reserved_time_seconds-?,"
            "reserved_input_tokens=reserved_input_tokens-?,"
            "reserved_output_tokens=reserved_output_tokens-?,"
            "reserved_cost_microusd=reserved_cost_microusd-?,"
            "reserved_retries=reserved_retries-?,"
            "reserved_human_attention=reserved_human_attention-?,"
            "usage_confidence=CASE WHEN usage_confidence='known' AND ?='estimated' "
            "THEN 'estimated' ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? AND reserved_time_seconds>=? "
            "AND reserved_input_tokens>=? AND reserved_output_tokens>=? "
            "AND reserved_cost_microusd>=? AND reserved_retries>=? "
            "AND reserved_human_attention>=?"
        )
        parameters = (*values, usage_confidence, updated_at, run_id, *values)
    cursor = connection.execute(sql, parameters)
    if cursor.rowcount != 1:
        raise BudgetExceeded(
            f"{event_type} exceeds the selected budget or outstanding reservation"
        )


def record_budget_event(
    database: Path,
    *,
    event_type: Literal["reserve", "release"],
    run_id: str,
    transition_id: str,
    selection: BudgetSelection,
    amounts: BudgetAmounts,
    idempotency_key: str,
    dedupe_key: str,
    source: str,
    usage_confidence: Literal["known", "estimated"] = "known",
    spawn_request_id: str,
    zero_reserve_policy_id: str | None = None,
    clock_context_id: str | None = None,
) -> BudgetEventResult:
    """Record one authoritative event and update its counter cache atomically."""

    if event_type not in {"reserve", "release"}:
        raise BudgetError(f"unsupported budget event type: {event_type!r}")
    run_id = _required_text("run_id", run_id)
    transition_id = _required_text("transition_id", transition_id)
    idempotency_key = _required_text("idempotency_key", idempotency_key)
    dedupe_key = _required_text("dedupe_key", dedupe_key)
    source = _required_text("source", source)
    spawn_request_id = _required_text("spawn_request_id", spawn_request_id)
    clock_context_id = _required_text("clock_context_id", clock_context_id)
    if usage_confidence not in _USAGE_CONFIDENCE:
        raise BudgetError("unknown usage confidence blocks budget mutation")
    if amounts.is_zero():
        raise BudgetError(f"{event_type} event must carry a non-zero amount")
    zero_token_cost = (
        amounts.input_tokens == amounts.output_tokens == amounts.cost_microusd == 0
    )
    if event_type == "reserve" and zero_token_cost != (
        zero_reserve_policy_id is not None
    ):
        raise BudgetError(
            "zero token/cost reserve requires exactly one zero-reserve policy"
        )
    if event_type != "reserve" and zero_reserve_policy_id is not None:
        raise BudgetError("zero-reserve policy is valid only for reserve events")

    connection = _connect(Path(database))
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            actual_selection = _selected_binding(
                connection, run_id=run_id, transition_id=transition_id
            )
            if actual_selection != selection:
                raise BudgetConflict(
                    "requested budget selection differs from persisted selected cost row"
                )
            spawn_identity = connection.execute(
                "SELECT sr.state,r.state FROM spawn_requests sr "
                "JOIN runs r ON r.run_id=sr.run_id "
                "WHERE sr.spawn_request_id=? "
                "AND sr.run_id=? AND sr.transition_id=?",
                (spawn_request_id, run_id, transition_id),
            ).fetchone()
            if spawn_identity is None:
                raise BudgetError(
                    "budget event requires an exact same-run, same-transition spawn request"
                )
            created_at, created_at_epoch_ms = _trusted_created_at(
                connection,
                run_id=run_id,
                transition_id=transition_id,
                clock_context_id=clock_context_id,
            )
            required_cost = _required_cost(selection, amounts)
            if event_type == "reserve" and amounts.cost_microusd < required_cost:
                raise BudgetExceeded(
                    "recorded cost is below the selected registry price for token amounts"
                )
            policy_hash = _zero_policy_hash(
                connection,
                zero_reserve_policy_id=zero_reserve_policy_id,
                selection=selection,
            )
            event_dedupe_hash = _dedupe_hash(dedupe_key)
            budget_event_id = _event_id(idempotency_key)
            expected = (
                budget_event_id,
                event_dedupe_hash,
                run_id,
                transition_id,
                spawn_request_id,
                selection.provider,
                selection.model,
                selection.endpoint_binding_id,
                selection.capability_class,
                selection.cost_registry_id,
                selection.cost_effective_at,
                selection.cost_registry_hash,
                selection.cost_confidence,
                zero_reserve_policy_id,
                policy_hash,
                event_type,
                amounts.time_seconds,
                amounts.input_tokens,
                amounts.output_tokens,
                amounts.cost_microusd,
                amounts.human_attention_units,
                amounts.retry_units,
                usage_confidence,
                source,
                created_at,
                created_at_epoch_ms,
                None,
            )
            replay = _existing_event(
                connection, idempotency_key=idempotency_key, expected=expected
            )
            if replay is not None:
                _assert_budget_invariants(connection)
                connection.execute("COMMIT")
                return replay
            if spawn_identity[0] != "pending":
                raise BudgetError(
                    f"{event_type} requires a pending pre-RPC spawn request"
                )
            if spawn_identity[1] not in _BUDGET_MUTATION_RUN_STATES:
                raise BudgetError(
                    f"{event_type} requires an owning run in pre-dispatch state"
                )
            if event_type in {"reserve", "release"}:
                prior_intent = connection.execute(
                    "SELECT intent_id FROM external_rpc_intents "
                    "WHERE rpc_kind='sessions_spawn' AND run_id=? "
                    "AND transition_id=? AND spawn_request_id=? LIMIT 1",
                    (run_id, transition_id, spawn_request_id),
                ).fetchone()
                if prior_intent is not None:
                    raise BudgetError(
                        f"{event_type} requires no existing sessions_spawn intent "
                        "for the spawn request"
                    )
            if event_type == "release":
                outstanding = _spawn_outstanding(
                    connection,
                    spawn_request_id=spawn_request_id,
                    run_id=run_id,
                    transition_id=transition_id,
                    selection=selection,
                )
                for field in _LIMITS:
                    if getattr(amounts, field) > getattr(outstanding, field):
                        raise BudgetExceeded(
                            f"{event_type} exceeds outstanding reservation for "
                            f"spawn_request_id={spawn_request_id} dimension={field}"
                        )
                remaining = BudgetAmounts(
                    **{
                        field: getattr(outstanding, field) - getattr(amounts, field)
                        for field in _LIMITS
                    }
                )
                if remaining.cost_microusd < _required_cost(selection, remaining):
                    raise BudgetExceeded(
                        "release would underfund the remaining per-spawn token reservation"
                    )
            sequence = connection.execute(
                "SELECT COALESCE(MAX(event_sequence),0)+1 FROM budget_events "
                "WHERE run_id=?",
                (run_id,),
            ).fetchone()[0]
            if type(sequence) is not int or not 1 <= sequence <= _MAX_EVENT_SEQUENCE:
                raise BudgetExceeded("budget event sequence limit reached")
            connection.execute(
                "INSERT INTO budget_events("
                "budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,"
                "run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
                "cost_confidence,zero_reserve_policy_id,zero_reserve_policy_hash,event_type,"
                "time_seconds,input_tokens,output_tokens,cost_microusd,human_attention_units,"
                "retry_units,usage_confidence,source,created_at,created_at_epoch_ms,"
                "clock_context_id"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    budget_event_id,
                    idempotency_key,
                    event_dedupe_hash,
                    sequence,
                    *expected[2:],
                ),
            )
            _update_counters(
                connection,
                event_type=event_type,
                run_id=run_id,
                amounts=amounts,
                usage_confidence=usage_confidence,
                updated_at=created_at,
            )
            _assert_budget_invariants(connection)
            connection.execute("COMMIT")
            return BudgetEventResult(budget_event_id, sequence, False)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise BudgetConflict(f"budget event violates ledger contract: {exc}") from exc
    except sqlite3.Error as exc:
        raise BudgetError(f"budget transaction failed: {exc}") from exc
    finally:
        connection.close()


def reserve_budget(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_budget_event(database, event_type="reserve", **kwargs)  # type: ignore[arg-type]


def release_budget(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_budget_event(database, event_type="release", **kwargs)  # type: ignore[arg-type]


def _update_post_dispatch_counters(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    run_id: str,
    amounts: BudgetAmounts,
    usage_confidence: str,
    updated_at: str,
) -> None:
    if event_type == "consume":
        values = (
            amounts.time_seconds,
            amounts.input_tokens,
            amounts.output_tokens,
            amounts.cost_microusd,
        )
        cursor = connection.execute(
            "UPDATE run_budgets SET "
            "reserved_time_seconds=reserved_time_seconds-?,"
            "reserved_input_tokens=reserved_input_tokens-?,"
            "reserved_output_tokens=reserved_output_tokens-?,"
            "reserved_cost_microusd=reserved_cost_microusd-?,"
            "consumed_time_seconds=consumed_time_seconds+?,"
            "consumed_input_tokens=consumed_input_tokens+?,"
            "consumed_output_tokens=consumed_output_tokens+?,"
            "consumed_cost_microusd=consumed_cost_microusd+?,"
            "usage_confidence=CASE WHEN ?='unknown' THEN 'unknown' "
            "WHEN usage_confidence='known' AND ?='estimated' THEN 'estimated' "
            "ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? AND reserved_time_seconds>=? "
            "AND reserved_input_tokens>=? AND reserved_output_tokens>=? "
            "AND reserved_cost_microusd>=? "
            "AND consumed_time_seconds+?<=time_budget_seconds "
            "AND consumed_input_tokens+?<=input_token_budget "
            "AND consumed_output_tokens+?<=output_token_budget "
            "AND consumed_cost_microusd+?<=cost_budget_microusd",
            (
                *values,
                *values,
                usage_confidence,
                usage_confidence,
                updated_at,
                run_id,
                *values,
                *values,
            ),
        )
    elif event_type == "retry_decrement":
        cursor = connection.execute(
            "UPDATE run_budgets SET reserved_retries=reserved_retries-?,"
            "consumed_retries=consumed_retries+?,"
            "usage_confidence=CASE WHEN usage_confidence='known' AND ?='estimated' "
            "THEN 'estimated' ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? AND reserved_retries>=? "
            "AND consumed_retries+?<=retry_budget",
            (
                amounts.retry_units,
                amounts.retry_units,
                usage_confidence,
                updated_at,
                run_id,
                amounts.retry_units,
                amounts.retry_units,
            ),
        )
    elif event_type == "retry_restore":
        cursor = connection.execute(
            "UPDATE run_budgets SET reserved_retries=reserved_retries+?,"
            "consumed_retries=consumed_retries-?,"
            "usage_confidence=CASE WHEN usage_confidence='known' AND ?='estimated' "
            "THEN 'estimated' ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? AND consumed_retries>=? "
            "AND reserved_retries+?<=retry_budget",
            (
                amounts.retry_units,
                amounts.retry_units,
                usage_confidence,
                updated_at,
                run_id,
                amounts.retry_units,
                amounts.retry_units,
            ),
        )
    else:
        cursor = connection.execute(
            "UPDATE run_budgets SET "
            "reserved_human_attention=reserved_human_attention-?,"
            "consumed_human_attention=consumed_human_attention+?,"
            "usage_confidence=CASE WHEN usage_confidence='known' AND ?='estimated' "
            "THEN 'estimated' ELSE usage_confidence END,updated_at=? "
            "WHERE run_id=? AND reserved_human_attention>=? "
            "AND consumed_human_attention+?<=human_attention_budget",
            (
                amounts.human_attention_units,
                amounts.human_attention_units,
                usage_confidence,
                updated_at,
                run_id,
                amounts.human_attention_units,
                amounts.human_attention_units,
            ),
        )
    if cursor.rowcount != 1:
        raise BudgetExceeded(
            f"{event_type} exceeds the selected budget or outstanding reservation"
        )


def record_post_dispatch_event(
    database: Path,
    *,
    event_type: Literal[
        "consume", "retry_decrement", "retry_restore", "human_attention"
    ],
    run_id: str,
    transition_id: str,
    selection: BudgetSelection,
    amounts: BudgetAmounts,
    idempotency_key: str,
    dedupe_key: str,
    source: str,
    spawn_request_id: str,
    clock_context_id: str,
    usage_confidence: Literal["known", "estimated", "unknown"] = "known",
) -> BudgetEventResult:
    """Record one accepted-spawn usage, retry, or human-attention event."""

    if event_type not in {
        "consume",
        "retry_decrement",
        "retry_restore",
        "human_attention",
    }:
        raise BudgetError(f"unsupported post-dispatch event type: {event_type!r}")
    run_id = _required_text("run_id", run_id)
    transition_id = _required_text("transition_id", transition_id)
    idempotency_key = _required_text("idempotency_key", idempotency_key)
    dedupe_key = _required_text("dedupe_key", dedupe_key)
    source = _required_text("source", source)
    spawn_request_id = _required_text("spawn_request_id", spawn_request_id)
    clock_context_id = _required_text("clock_context_id", clock_context_id)
    if usage_confidence not in _POST_DISPATCH_USAGE_CONFIDENCE:
        raise BudgetError("invalid post-dispatch usage confidence")
    if event_type == "consume":
        if amounts.retry_units or amounts.human_attention_units:
            raise BudgetError("consume cannot carry retry or human-attention units")
        if usage_confidence == "unknown":
            if not amounts.is_zero():
                raise BudgetError("unknown usage must use a zero-amount classification")
        elif amounts.is_zero():
            raise BudgetError("known or estimated usage must carry a non-zero amount")
    elif event_type in {"retry_decrement", "retry_restore"}:
        if amounts != BudgetAmounts(retry_units=amounts.retry_units) or not amounts.retry_units:
            raise BudgetError(f"{event_type} must carry retry units only")
        if usage_confidence == "unknown":
            raise BudgetError("retry events require known or estimated usage")
    else:
        if amounts != BudgetAmounts(
            human_attention_units=amounts.human_attention_units
        ) or not amounts.human_attention_units:
            raise BudgetError("human_attention must carry human-attention units only")
        if usage_confidence == "unknown":
            raise BudgetError("human-attention events require known or estimated usage")

    connection = _connect(Path(database))
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            actual_selection = _selected_binding(
                connection,
                run_id=run_id,
                transition_id=transition_id,
                allow_unknown_usage=True,
            )
            if actual_selection != selection:
                raise BudgetConflict(
                    "requested budget selection differs from persisted selected cost row"
                )
            proof = connection.execute(
                "SELECT sr.state,r.state,i.accepted_at_epoch_ms,"
                "i.requested_at_epoch_ms FROM spawn_requests sr "
                "JOIN runs r ON r.run_id=sr.run_id "
                "JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' "
                "AND i.state IN ('accepted','reconciled') "
                "AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id "
                "AND i.transition_id=sr.transition_id "
                "AND i.client_request_id=sr.client_request_id "
                "AND i.idempotency_key=sr.spawn_idempotency_key "
                "AND i.phase=sr.phase AND i.agent_id=sr.agent_id "
                "AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key "
                "JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id "
                "AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id "
                "AND s.client_request_id=sr.client_request_id "
                "AND s.spawn_idempotency_key=sr.spawn_idempotency_key "
                "AND s.phase=sr.phase AND s.agent_id=sr.agent_id "
                "AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key "
                "WHERE sr.spawn_request_id=? AND sr.run_id=? AND sr.transition_id=? "
                "AND sr.state IN ('accepted','completed') "
                "AND (?<>'consume' OR (sr.state='completed' "
                "AND s.state='completed' "
                "AND s.completed_at IS NOT NULL AND s.completed_at<>''))",
                (spawn_request_id, run_id, transition_id, event_type),
            ).fetchone()
            if proof is None:
                raise BudgetError(
                    "post-dispatch budget event requires exact accepted session proof"
                )
            created_at, created_at_epoch_ms = _trusted_created_at(
                connection,
                run_id=run_id,
                transition_id=transition_id,
                clock_context_id=clock_context_id,
            )
            accepted_at_epoch_ms = proof[2]
            requested_at_epoch_ms = proof[3]
            if (
                type(requested_at_epoch_ms) is not int
                or requested_at_epoch_ms < 1
                or requested_at_epoch_ms > _MAX_EPOCH_MS
                or type(accepted_at_epoch_ms) is not int
                or accepted_at_epoch_ms <= requested_at_epoch_ms
                or created_at_epoch_ms <= accepted_at_epoch_ms
                or created_at_epoch_ms <= requested_at_epoch_ms
            ):
                raise BudgetError(
                    "post-dispatch budget event requires a fresh clock after "
                    "the sessions_spawn request and accepted session proof"
                )
            if event_type == "consume" and usage_confidence != "unknown":
                if amounts.cost_microusd < _required_cost(selection, amounts):
                    raise BudgetExceeded(
                        "usage cost is below the selected registry price for token amounts"
                    )
            event_dedupe_hash = _dedupe_hash(dedupe_key)
            budget_event_id = _event_id(idempotency_key)
            expected = (
                budget_event_id,
                event_dedupe_hash,
                run_id,
                transition_id,
                spawn_request_id,
                selection.provider,
                selection.model,
                selection.endpoint_binding_id,
                selection.capability_class,
                selection.cost_registry_id,
                selection.cost_effective_at,
                selection.cost_registry_hash,
                selection.cost_confidence,
                None,
                None,
                event_type,
                amounts.time_seconds,
                amounts.input_tokens,
                amounts.output_tokens,
                amounts.cost_microusd,
                amounts.human_attention_units,
                amounts.retry_units,
                usage_confidence,
                source,
                created_at,
                created_at_epoch_ms,
                clock_context_id,
            )
            replay = _existing_event(
                connection, idempotency_key=idempotency_key, expected=expected
            )
            if replay is not None:
                _assert_budget_invariants(connection)
                connection.execute("COMMIT")
                return replay
            poisoned_usage = connection.execute(
                "SELECT 1 FROM run_budgets rb "
                "WHERE rb.run_id=? AND rb.usage_confidence='unknown' "
                "UNION ALL "
                "SELECT 1 FROM budget_events be "
                "WHERE be.run_id=? AND be.usage_confidence='unknown' LIMIT 1",
                (run_id, run_id),
            ).fetchone()
            if poisoned_usage is not None:
                raise BudgetError(
                    "unknown usage confidence blocks post-dispatch budget mutation"
                )
            usage_row = connection.execute(
                "SELECT usage_confidence FROM run_budgets WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if usage_row is None or usage_row[0] == "unknown":
                raise BudgetError(
                    "unknown usage confidence blocks post-dispatch budget mutation"
                )
            if proof[1] not in _POST_DISPATCH_RUN_STATES:
                raise BudgetError(
                    "post-dispatch budget event requires an active post-dispatch run"
                )
            _assert_budget_invariants(connection)
            outstanding = _spawn_outstanding(
                connection,
                spawn_request_id=spawn_request_id,
                run_id=run_id,
                transition_id=transition_id,
                selection=selection,
            )
            if event_type == "consume":
                for field in ("time_seconds", "input_tokens", "output_tokens", "cost_microusd"):
                    if getattr(amounts, field) > getattr(outstanding, field):
                        raise BudgetExceeded(
                            f"consume exceeds outstanding reservation dimension={field}"
                        )
                remaining = BudgetAmounts(
                    **{
                        field: getattr(outstanding, field) - getattr(amounts, field)
                        for field in _LIMITS
                    }
                )
                if remaining.cost_microusd < _required_cost(selection, remaining):
                    raise BudgetExceeded(
                        "consume would underfund the remaining per-spawn token reservation"
                    )
            elif event_type == "retry_decrement" and (
                amounts.retry_units > outstanding.retry_units
            ):
                raise BudgetExceeded("retry_decrement exceeds outstanding reservation")
            elif event_type == "human_attention" and (
                amounts.human_attention_units > outstanding.human_attention_units
            ):
                raise BudgetExceeded("human_attention exceeds outstanding reservation")
            sequence = connection.execute(
                "SELECT COALESCE(MAX(event_sequence),0)+1 FROM budget_events WHERE run_id=?",
                (run_id,),
            ).fetchone()[0]
            if type(sequence) is not int or not 1 <= sequence <= _MAX_EVENT_SEQUENCE:
                raise BudgetExceeded("budget event sequence limit reached")
            connection.execute(
                "INSERT INTO budget_events("
                "budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,"
                "run_id,transition_id,spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
                "cost_confidence,zero_reserve_policy_id,zero_reserve_policy_hash,event_type,"
                "time_seconds,input_tokens,output_tokens,cost_microusd,human_attention_units,"
                "retry_units,usage_confidence,source,created_at,created_at_epoch_ms,"
                "clock_context_id"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (budget_event_id, idempotency_key, event_dedupe_hash, sequence, *expected[2:]),
            )
            _update_post_dispatch_counters(
                connection,
                event_type=event_type,
                run_id=run_id,
                amounts=amounts,
                usage_confidence=usage_confidence,
                updated_at=created_at,
            )
            _assert_budget_invariants(connection)
            connection.execute("COMMIT")
            return BudgetEventResult(budget_event_id, sequence, False)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise BudgetConflict(f"post-dispatch event violates ledger contract: {exc}") from exc
    except sqlite3.Error as exc:
        raise BudgetError(f"post-dispatch budget transaction failed: {exc}") from exc
    finally:
        connection.close()


def consume_budget(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_post_dispatch_event(database, event_type="consume", **kwargs)  # type: ignore[arg-type]


def decrement_retry_budget(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_post_dispatch_event(database, event_type="retry_decrement", **kwargs)  # type: ignore[arg-type]


def restore_retry_budget(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_post_dispatch_event(database, event_type="retry_restore", **kwargs)  # type: ignore[arg-type]


def consume_human_attention(database: Path, **kwargs: object) -> BudgetEventResult:
    return record_post_dispatch_event(database, event_type="human_attention", **kwargs)  # type: ignore[arg-type]


def settle_budget(
    database: Path,
    *,
    run_id: str,
    transition_id: str,
    selection: BudgetSelection,
    actual_usage: BudgetAmounts,
    idempotency_key: str,
    dedupe_key: str,
    source: str,
    spawn_request_id: str,
    clock_context_id: str,
    usage_confidence: Literal["known", "estimated"] = "known",
) -> BudgetSettlementResult:
    """Atomically consume terminal usage and release one spawn's remainder.

    ``actual_usage`` is the terminal usage not already represented by earlier
    post-dispatch events.  The exact remaining reservation is split between
    this usage and a linked release inside one ``BEGIN IMMEDIATE`` transaction.
    """

    run_id = _required_text("run_id", run_id)
    transition_id = _required_text("transition_id", transition_id)
    idempotency_key = _required_text("idempotency_key", idempotency_key)
    dedupe_key = _required_text("dedupe_key", dedupe_key)
    source = _required_text("source", source)
    spawn_request_id = _required_text("spawn_request_id", spawn_request_id)
    clock_context_id = _required_text("clock_context_id", clock_context_id)
    if usage_confidence not in _USAGE_CONFIDENCE:
        raise BudgetError("final settlement requires known or estimated usage")

    connection = _connect(Path(database))
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _verify_schema_identity(connection)
            actual_selection = _selected_binding(
                connection,
                run_id=run_id,
                transition_id=transition_id,
                allow_unknown_usage=True,
            )
            if actual_selection != selection:
                raise BudgetConflict(
                    "requested budget selection differs from persisted selected cost row"
                )
            proof = connection.execute(
                "SELECT sr.state,r.state,i.accepted_at_epoch_ms,"
                "i.requested_at_epoch_ms FROM spawn_requests sr "
                "JOIN runs r ON r.run_id=sr.run_id "
                "JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' "
                "AND i.state IN ('accepted','reconciled') "
                "AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id "
                "AND i.transition_id=sr.transition_id "
                "AND i.client_request_id=sr.client_request_id "
                "AND i.idempotency_key=sr.spawn_idempotency_key "
                "AND i.phase=sr.phase AND i.agent_id=sr.agent_id "
                "AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key "
                "JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id "
                "AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id "
                "AND s.client_request_id=sr.client_request_id "
                "AND s.spawn_idempotency_key=sr.spawn_idempotency_key "
                "AND s.phase=sr.phase AND s.agent_id=sr.agent_id "
                "AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key "
                "WHERE sr.spawn_request_id=? AND sr.run_id=? AND sr.transition_id=? "
                "AND sr.state='completed' AND s.state='completed' "
                "AND s.completed_at IS NOT NULL AND s.completed_at<>''",
                (spawn_request_id, run_id, transition_id),
            ).fetchone()
            if proof is None:
                raise BudgetError(
                    "final settlement requires exact completed session proof"
                )
            created_at, created_at_epoch_ms = _trusted_created_at(
                connection,
                run_id=run_id,
                transition_id=transition_id,
                clock_context_id=clock_context_id,
            )
            requested_at_epoch_ms = proof[3]
            accepted_at_epoch_ms = proof[2]
            if (
                type(requested_at_epoch_ms) is not int
                or requested_at_epoch_ms < 1
                or type(accepted_at_epoch_ms) is not int
                or accepted_at_epoch_ms <= requested_at_epoch_ms
                or created_at_epoch_ms <= accepted_at_epoch_ms
            ):
                raise BudgetError(
                    "final settlement requires a trusted clock after request acceptance"
                )
            if (
                actual_usage.input_tokens
                or actual_usage.output_tokens
                or actual_usage.cost_microusd
            ) and actual_usage.cost_microusd < _required_cost(selection, actual_usage):
                raise BudgetExceeded(
                    "final usage cost is below the selected registry price"
                )

            settlement_id = _settlement_id(idempotency_key)
            settlement_dedupe_hash = _dedupe_hash(dedupe_key)
            expected_replay = (
                settlement_id,
                settlement_dedupe_hash,
                run_id,
                transition_id,
                spawn_request_id,
                selection.provider,
                selection.model,
                selection.endpoint_binding_id,
                selection.capability_class,
                selection.cost_registry_id,
                selection.cost_effective_at,
                selection.cost_registry_hash,
                selection.cost_confidence,
                actual_usage.time_seconds,
                actual_usage.input_tokens,
                actual_usage.output_tokens,
                actual_usage.cost_microusd,
                actual_usage.retry_units,
                actual_usage.human_attention_units,
                usage_confidence,
                source,
                created_at,
                created_at_epoch_ms,
                clock_context_id,
            )
            replay = connection.execute(
                "SELECT settlement_id,settlement_dedupe_hash,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "actual_time_seconds,actual_input_tokens,actual_output_tokens,"
                "actual_cost_microusd,actual_retry_units,actual_human_attention_units,"
                "usage_confidence,source,created_at,created_at_epoch_ms,clock_context_id,"
                "released_time_seconds,released_input_tokens,released_output_tokens,"
                "released_cost_microusd,released_retry_units,"
                "released_human_attention_units FROM budget_settlements "
                "WHERE settlement_idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if replay is not None:
                if replay[: len(expected_replay)] != expected_replay:
                    raise BudgetConflict(
                        "settlement idempotency key was reused with another payload"
                    )
                _assert_budget_invariants(connection)
                events = tuple(
                    BudgetEventResult(row[0], row[1], True)
                    for row in connection.execute(
                        "SELECT budget_event_id,event_sequence FROM budget_events "
                        "WHERE settlement_id=? ORDER BY event_sequence",
                        (settlement_id,),
                    ).fetchall()
                )
                released = BudgetAmounts(*replay[len(expected_replay) :])
                connection.execute("COMMIT")
                return BudgetSettlementResult(
                    settlement_id, events, released, True
                )

            if proof[1] not in _FINAL_SETTLEMENT_RUN_STATES:
                raise BudgetError(
                    "final settlement requires a completed post-dispatch run state"
                )
            poisoned_usage = connection.execute(
                "SELECT 1 FROM run_budgets rb "
                "WHERE rb.run_id=? AND rb.usage_confidence='unknown' "
                "UNION ALL SELECT 1 FROM budget_events be "
                "WHERE be.run_id=? AND be.usage_confidence='unknown' LIMIT 1",
                (run_id, run_id),
            ).fetchone()
            if poisoned_usage is not None:
                raise BudgetError("unknown usage confidence blocks final settlement")
            _assert_budget_invariants(connection)
            outstanding = _spawn_outstanding(
                connection,
                spawn_request_id=spawn_request_id,
                run_id=run_id,
                transition_id=transition_id,
                selection=selection,
            )
            if outstanding.is_zero():
                raise BudgetError("final settlement requires an outstanding reservation")
            for field in _LIMITS:
                if getattr(actual_usage, field) > getattr(outstanding, field):
                    raise BudgetExceeded(
                        f"final usage exceeds outstanding reservation dimension={field}"
                    )
            released = BudgetAmounts(
                **{
                    field: getattr(outstanding, field) - getattr(actual_usage, field)
                    for field in _LIMITS
                }
            )
            values = (
                settlement_id,
                idempotency_key,
                settlement_dedupe_hash,
                run_id,
                transition_id,
                spawn_request_id,
                selection.provider,
                selection.model,
                selection.endpoint_binding_id,
                selection.capability_class,
                selection.cost_registry_id,
                selection.cost_effective_at,
                selection.cost_registry_hash,
                selection.cost_confidence,
                actual_usage.time_seconds,
                actual_usage.input_tokens,
                actual_usage.output_tokens,
                actual_usage.cost_microusd,
                actual_usage.retry_units,
                actual_usage.human_attention_units,
                released.time_seconds,
                released.input_tokens,
                released.output_tokens,
                released.cost_microusd,
                released.retry_units,
                released.human_attention_units,
                usage_confidence,
                source,
                created_at,
                created_at_epoch_ms,
                clock_context_id,
            )
            connection.execute(
                "INSERT INTO budget_settlements("
                "settlement_id,settlement_idempotency_key,settlement_dedupe_hash,"
                "run_id,transition_id,spawn_request_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,"
                "actual_time_seconds,actual_input_tokens,actual_output_tokens,"
                "actual_cost_microusd,actual_retry_units,"
                "actual_human_attention_units,released_time_seconds,"
                "released_input_tokens,released_output_tokens,"
                "released_cost_microusd,released_retry_units,"
                "released_human_attention_units,usage_confidence,source,"
                "created_at,created_at_epoch_ms,clock_context_id"
                ") VALUES(" + ",".join("?" for _ in values) + ")",
                values,
            )

            event_results: list[BudgetEventResult] = []

            def insert_event(event_type: str, amounts: BudgetAmounts) -> None:
                if amounts.is_zero():
                    return
                sequence = connection.execute(
                    "SELECT COALESCE(MAX(event_sequence),0)+1 FROM budget_events "
                    "WHERE run_id=?",
                    (run_id,),
                ).fetchone()[0]
                if type(sequence) is not int or not 1 <= sequence <= _MAX_EVENT_SEQUENCE:
                    raise BudgetExceeded("budget event sequence limit reached")
                event_idempotency_key = f"{idempotency_key}\0{event_type}"
                budget_event_id = _event_id(event_idempotency_key)
                connection.execute(
                    "INSERT INTO budget_events("
                    "budget_event_id,event_idempotency_key,event_dedupe_hash,"
                    "event_sequence,run_id,transition_id,spawn_request_id,provider,"
                    "model,endpoint_binding_id,capability_class,cost_registry_id,"
                    "cost_effective_at,cost_registry_hash,cost_confidence,"
                    "zero_reserve_policy_id,zero_reserve_policy_hash,event_type,"
                    "time_seconds,input_tokens,output_tokens,cost_microusd,"
                    "human_attention_units,retry_units,usage_confidence,source,"
                    "created_at,created_at_epoch_ms,clock_context_id,settlement_id"
                    ") VALUES(" + ",".join("?" for _ in range(30)) + ")",
                    (
                        budget_event_id,
                        event_idempotency_key,
                        _dedupe_hash(f"{dedupe_key}\0{event_type}"),
                        sequence,
                        run_id,
                        transition_id,
                        spawn_request_id,
                        selection.provider,
                        selection.model,
                        selection.endpoint_binding_id,
                        selection.capability_class,
                        selection.cost_registry_id,
                        selection.cost_effective_at,
                        selection.cost_registry_hash,
                        selection.cost_confidence,
                        None,
                        None,
                        event_type,
                        amounts.time_seconds,
                        amounts.input_tokens,
                        amounts.output_tokens,
                        amounts.cost_microusd,
                        amounts.human_attention_units,
                        amounts.retry_units,
                        usage_confidence,
                        source,
                        created_at,
                        created_at_epoch_ms,
                        clock_context_id,
                        settlement_id,
                    ),
                )
                if event_type == "release":
                    _update_counters(
                        connection,
                        event_type="release",
                        run_id=run_id,
                        amounts=amounts,
                        usage_confidence=usage_confidence,
                        updated_at=created_at,
                    )
                else:
                    _update_post_dispatch_counters(
                        connection,
                        event_type=event_type,
                        run_id=run_id,
                        amounts=amounts,
                        usage_confidence=usage_confidence,
                        updated_at=created_at,
                    )
                event_results.append(
                    BudgetEventResult(budget_event_id, sequence, False)
                )

            insert_event(
                "consume",
                BudgetAmounts(
                    time_seconds=actual_usage.time_seconds,
                    input_tokens=actual_usage.input_tokens,
                    output_tokens=actual_usage.output_tokens,
                    cost_microusd=actual_usage.cost_microusd,
                ),
            )
            insert_event(
                "retry_decrement",
                BudgetAmounts(retry_units=actual_usage.retry_units),
            )
            insert_event(
                "human_attention",
                BudgetAmounts(
                    human_attention_units=actual_usage.human_attention_units
                ),
            )
            insert_event("release", released)
            _assert_budget_invariants(connection)
            connection.execute("COMMIT")
            return BudgetSettlementResult(
                settlement_id, tuple(event_results), released, False
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except sqlite3.IntegrityError as exc:
        raise BudgetConflict(f"final settlement violates ledger contract: {exc}") from exc
    except sqlite3.Error as exc:
        raise BudgetError(f"final settlement transaction failed: {exc}") from exc
    finally:
        connection.close()
