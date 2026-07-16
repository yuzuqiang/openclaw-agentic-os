from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from agentic_os.budgets import (
    BudgetAmounts,
    BudgetConflict,
    BudgetError,
    BudgetExceeded,
    BudgetSelection,
    _BUDGET_INVARIANT_QUERIES,
    _required_cost,
    consume_budget,
    consume_human_attention,
    decrement_retry_budget,
    release_budget,
    reserve_budget,
    restore_retry_budget,
    settle_budget,
)
from agentic_os.legacy_import import (
    LEGACY_SOURCE_COLUMNS,
    LEGACY_SOURCE_TABLE,
    LegacyMoneyImportConflict,
    import_legacy_terminal_usage,
    legacy_terminal_usage_schema_sql,
)
from agentic_os.migrations import apply_migrations, repository_root
from agentic_os.slo_contracts import SLO_QUERY_CONTRACTS


class BudgetRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = repository_root() / "state/agentic-os"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._cleanup_state_root)
        self.temporary = tempfile.TemporaryDirectory(dir=self.state_root)
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"
        apply_migrations(self.database)
        self.selection = BudgetSelection(
            provider="provider",
            model="model",
            endpoint_binding_id="endpoint",
            capability_class="capability",
            cost_registry_id="cost-row",
            cost_effective_at="effective",
            cost_registry_hash="cost-hash",
            cost_confidence="known",
            input_cost_microusd_per_million=100,
            output_cost_microusd_per_million=200,
        )
        self._seed_budget()

    def _cleanup_state_root(self) -> None:
        try:
            self.state_root.rmdir()
            self.state_root.parent.rmdir()
        except OSError:
            pass

    def _seed_budget(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO workflow_authority(workflow,mode,updated_at) "
                "VALUES('workflow','file_authority','now')"
            )
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'run','prepare','workflow','file_authority','candidate','R1','R1',"
                "'now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('transition','run','before',"
                "'after','dispatch','spawn','R1','transition-idem',0,'now')"
            )
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
                "VALUES('cost-row','provider','model','endpoint','capability',100,200,"
                "'known','effective','cost-hash')"
            )
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn','run','phase','agent','transition',"
                "'client','spawn-idem','task','pending','now','now')"
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
                "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
                "selected_cost_effective_at,selected_cost_registry_hash,"
                "selected_cost_confidence,selected_reserve_transition_id,time_budget_seconds,"
                "input_token_budget,output_token_budget,cost_budget_microusd,retry_budget,"
                "human_attention_budget,usage_confidence,updated_at) VALUES('run','workflow',"
                "'capability','provider','model','endpoint','cost-row','effective','cost-hash',"
                "'known','transition',100,1000,1000,10000,10,10,'known','now')"
            )
            evidence_hash = "budget-runtime-evidence"
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
                "context_hash,evidence_hash,independence_class,"
                "independence_proof_json,completed_at) VALUES("
                "'verifier','run','worker-agent','verifier-agent','provider','model',"
                "'prompt-hash','context-hash',?,'independent',"
                "'{\"reviewer_session\":\"budget-runtime-fixture\"}','now')",
                (evidence_hash,),
            )
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('gate','run','transition','clock','verifier','pass','now',"
                "1800000000123,'v1','gate-query','migration-sha',?,'R1','now')",
                (evidence_hash,),
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES('clock','gate','gate','run',"
                "'transition','nonce',1800000000123,1800000000123,"
                "'budget-runtime','trusted-clock-hash',1800000000123)"
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES(?,"
                "'run','budget-runtime-evidence.json','sha256',1,"
                "'application/json','none','run','verifier','gate','now')",
                (evidence_hash,),
            )

    def _kwargs(
        self,
        *,
        idempotency_key: str,
        dedupe_key: str,
        amounts: BudgetAmounts,
    ) -> dict[str, object]:
        return {
            "run_id": "run",
            "transition_id": "transition",
            "selection": self.selection,
            "amounts": amounts,
            "idempotency_key": idempotency_key,
            "dedupe_key": dedupe_key,
            "source": "test",
            "spawn_request_id": "spawn",
            "clock_context_id": "clock",
        }

    def _budget_row(self) -> tuple[object, ...]:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            return connection.execute(
                "SELECT reserved_time_seconds,reserved_input_tokens,"
                "reserved_output_tokens,reserved_cost_microusd,reserved_retries,"
                "reserved_human_attention,consumed_time_seconds,consumed_input_tokens,"
                "consumed_output_tokens,consumed_cost_microusd FROM run_budgets "
                "WHERE run_id='run'"
            ).fetchone()

    def _event_count(self) -> int:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            return connection.execute("SELECT COUNT(*) FROM budget_events").fetchone()[0]

    def _seed_runtime_dispatch_binding(
        self, reserve_budget_event_id: str = "reserve"
    ) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES('lease','run','phase','transition','agent',"
                "'requester','acquire_pending','client-lease','acquire-idem',"
                "'release-idem',60000,'now','later',1800000060124)"
            )
            connection.execute(
                "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
                "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
                "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
                "spawn_idempotency_key,reserve_budget_event_id,created_at) VALUES('spawn','lease','run','transition',"
                "'phase','agent','requester','task','client-lease','acquire-idem',"
                "'release-idem','client','spawn-idem',?,'now')",
                (reserve_budget_event_id,),
            )

    def _settlement_count(self) -> int:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            return connection.execute(
                "SELECT COUNT(*) FROM budget_settlements"
            ).fetchone()[0]

    def _accept_spawn(self, reserve_event_id: str, *, completed: bool) -> None:
        external_metadata = (
            '{"run_id":"run","transition_id":"transition",'
            '"client_request_id":"client","idempotency_key":"spawn-idem",'
            '"phase":"phase","agent_id":"agent","task_digest":"task"}'
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "UPDATE runs SET state=? WHERE run_id='run'",
                ("child_completed" if completed else "running",),
            )
            connection.execute(
                "UPDATE spawn_requests SET session_key='session-key' "
                "WHERE spawn_request_id='spawn'"
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
                "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
                "task_digest,state,spawned_at,completed_at) VALUES('session','spawn',"
                "'run','transition','phase','agent','client','spawn-idem','session-key',"
                "'task',?,'now',?)",
                ("completed" if completed else "running", "now" if completed else None),
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES('lease','run','phase','transition','agent',"
                "'requester','acquire_pending','client-lease','acquire-idem',"
                "'release-idem',60000,'now','later',1800000060124)"
            )
            connection.execute(
                "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
                "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
                "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
                "spawn_idempotency_key,reserve_budget_event_id,created_at) VALUES('spawn','lease','run','transition',"
                "'phase','agent','requester','task','client-lease','acquire-idem',"
                "'release-idem','client','spawn-idem',?,'now')",
                (reserve_event_id,),
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "spawn_request_id,reserve_budget_event_id,client_request_id,idempotency_key,"
                "phase,agent_id,task_digest,metadata_contract_version,metadata_json,"
                "external_metadata_json,external_run_id,external_transition_id,"
                "external_client_request_id,external_idempotency_key,external_phase,"
                "external_agent_id,external_task_digest,state,external_id,requested_at,"
                "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
                "'intent','run','transition','sessions_spawn','spawn',?,'client',"
                "'spawn-idem','phase','agent','task','v1',? ,?,'run','transition',"
                "'client','spawn-idem','phase','agent','task','accepted','session-key',"
                "'now',1800000000124,'now',1800000000125)",
                (reserve_event_id, external_metadata, external_metadata),
            )
            connection.execute(
                "UPDATE spawn_requests SET state=? WHERE spawn_request_id='spawn'",
                ("completed" if completed else "accepted",),
            )
            connection.execute(
                "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,"
                "worker_agent_id,verifier_agent_id,provider,model,prompt_hash,"
                "context_hash,evidence_hash,independence_class,"
                "independence_proof_json,completed_at) VALUES("
                "'post-verifier','run','worker-agent','post-verifier-agent',"
                "'provider','model','post-prompt-hash','post-context-hash',"
                "'budget-runtime-post-evidence','independent',"
                "'{\"reviewer_session\":\"post-dispatch-clock\"}','now')"
            )
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,"
                "clock_context_id,verifier_run_id,decision,completed_at,"
                "completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('post-gate','run','transition','post-clock','post-verifier',"
                "'pass','now',1800000000126,'v1','post-gate-query',"
                "'migration-sha','budget-runtime-post-evidence','R1','now')"
            )
            connection.execute(
                "INSERT INTO gate_clock_context(clock_context_id,gate_run_id,"
                "consumed_by_gate_run_id,run_id,transition_id,gate_nonce,"
                "now_epoch_ms,bound_at_epoch_ms,bound_by,trusted_clock_source_hash,"
                "consumed_at_epoch_ms) VALUES('post-clock','post-gate','post-gate',"
                "'run','transition','post-nonce',1800000000126,1800000000126,"
                "'budget-runtime','trusted-post-clock-hash',1800000000126)"
            )
            connection.execute(
                "INSERT INTO evidence_hashes(evidence_hash,run_id,path,sha256,"
                "size_bytes,content_type,redaction_status,producer_run_id,"
                "verifier_run_id,gate_run_id,captured_at) VALUES("
                "'budget-runtime-post-evidence','run','budget-runtime-post-evidence.json',"
                "'post-sha256',1,'application/json','none','run','post-verifier',"
                "'post-gate','now')"
            )

    def _post_kwargs(
        self,
        *,
        idempotency_key: str,
        amounts: BudgetAmounts,
    ) -> dict[str, object]:
        return {
            **self._kwargs(
                idempotency_key=idempotency_key,
                dedupe_key=f"dedupe-{idempotency_key}",
                amounts=amounts,
            ),
            "source": "usage-import",
            "clock_context_id": "post-clock",
        }

    def _slo_rows(self, query_name: str) -> list[tuple[object, ...]]:
        sql = next(
            item.sql_text for item in SLO_QUERY_CONTRACTS if item.query_name == query_name
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            return connection.execute(sql).fetchall()

    def _legacy_source(
        self, rows: list[tuple[object, ...]], *, name: str = "legacy.db"
    ) -> Path:
        source = Path(self.temporary.name) / name
        with closing(sqlite3.connect(source)) as connection, connection:
            connection.execute(legacy_terminal_usage_schema_sql())
            placeholders = ",".join("?" for _ in LEGACY_SOURCE_COLUMNS)
            connection.executemany(
                f"INSERT INTO {LEGACY_SOURCE_TABLE}("
                + ",".join(LEGACY_SOURCE_COLUMNS)
                + f") VALUES({placeholders})",
                rows,
            )
        return source

    def _legacy_row(
        self,
        legacy_row_id: str,
        *,
        actual_cost_usd: object,
        idempotency_key: str | None = None,
        dedupe_key: str | None = None,
        source_unit: object = "usd_decimal",
        actual_time_seconds: object = 0,
        actual_input_tokens: object = 0,
        actual_output_tokens: object = 0,
        actual_retry_units: object = 0,
        actual_human_attention_units: object = 0,
        usage_confidence: object = "known",
    ) -> tuple[object, ...]:
        return (
            legacy_row_id,
            "run",
            "transition",
            "spawn",
            idempotency_key or f"legacy-final-{legacy_row_id}",
            dedupe_key or f"legacy-dedupe-{legacy_row_id}",
            "legacy-money-import",
            "post-clock",
            usage_confidence,
            actual_time_seconds,
            actual_input_tokens,
            actual_output_tokens,
            actual_cost_usd,
            actual_retry_units,
            actual_human_attention_units,
            source_unit,
        )

    def test_reserve_is_atomic_and_idempotent(self) -> None:
        amounts = BudgetAmounts(
            time_seconds=2,
            input_tokens=10,
            output_tokens=5,
            cost_microusd=100,
            retry_units=1,
        )
        kwargs = self._kwargs(
            idempotency_key="reserve-idem", dedupe_key="usage-reserve-1", amounts=amounts
        )
        first = reserve_budget(self.database, **kwargs)
        replay = reserve_budget(self.database, **kwargs)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.budget_event_id, first.budget_event_id)
        self.assertEqual(replay.event_sequence, first.event_sequence)
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (2, 10, 5, 100, 1, 0, 0, 0, 0, 0))

    def test_idempotent_replay_refuses_preexisting_counter_drift(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="reserve-idem",
            dedupe_key="usage-reserve-1",
            amounts=BudgetAmounts(input_tokens=10, cost_microusd=5),
        )
        reserve_budget(self.database, **kwargs)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=11 WHERE run_id='run'"
            )
        with self.assertRaisesRegex(BudgetError, "Budget ledger reconciles"):
            reserve_budget(self.database, **kwargs)
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 11, 0, 5, 0, 0, 0, 0, 0, 0))

    def test_idempotent_replay_survives_later_spawn_state_change(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="reserve-idem",
            dedupe_key="usage-reserve-1",
            amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
        )
        reserve_budget(self.database, **kwargs)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE spawn_requests SET state='failed' WHERE spawn_request_id='spawn'"
            )
        replay = reserve_budget(self.database, **kwargs)
        self.assertTrue(replay.replayed)
        self.assertEqual(self._event_count(), 1)

    def test_conflicting_idempotency_and_dedupe_replays_roll_back(self) -> None:
        original = BudgetAmounts(input_tokens=10, cost_microusd=5)
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-idem",
                dedupe_key="source-event",
                amounts=original,
            ),
        )
        with self.assertRaises(BudgetConflict):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="reserve-idem",
                    dedupe_key="source-event",
                    amounts=BudgetAmounts(input_tokens=11, cost_microusd=5),
                ),
            )
        with self.assertRaises(BudgetConflict):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="another-idem",
                    dedupe_key="source-event",
                    amounts=BudgetAmounts(input_tokens=12, cost_microusd=5),
                ),
            )
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 10, 0, 5, 0, 0, 0, 0, 0, 0))

    def test_over_budget_reserve_rolls_back_ledger_insert(self) -> None:
        before = self._budget_row()
        with self.assertRaises(BudgetExceeded):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="too-large",
                    dedupe_key="too-large",
                    amounts=BudgetAmounts(input_tokens=1001, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 0)
        self.assertEqual(self._budget_row(), before)

    def test_concurrent_reservations_cannot_oversubscribe_budget(self) -> None:
        def reserve(index: int) -> str:
            try:
                reserve_budget(
                    self.database,
                    **self._kwargs(
                        idempotency_key=f"concurrent-{index}",
                        dedupe_key=f"concurrent-{index}",
                        amounts=BudgetAmounts(input_tokens=600, cost_microusd=1),
                    ),
                )
                return "reserved"
            except BudgetExceeded:
                return "blocked"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = sorted(executor.map(reserve, (1, 2)))
        self.assertEqual(results, ["blocked", "reserved"])
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 600, 0, 1, 0, 0, 0, 0, 0, 0))

    def test_wrong_transition_or_selected_cost_binding_fails_closed(self) -> None:
        common = self._kwargs(
            idempotency_key="wrong-binding",
            dedupe_key="wrong-binding",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        common["transition_id"] = "wrong-transition"
        with self.assertRaises(BudgetError):
            reserve_budget(self.database, **common)
        common["transition_id"] = "transition"
        common["selection"] = replace(self.selection, endpoint_binding_id="other")
        with self.assertRaises(BudgetConflict):
            reserve_budget(self.database, **common)
        common["selection"] = self.selection
        common["spawn_request_id"] = "missing-spawn"
        with self.assertRaisesRegex(BudgetError, "same-run, same-transition"):
            reserve_budget(self.database, **common)
        self.assertEqual(self._event_count(), 0)

    def test_selected_registry_price_is_a_conservative_cost_floor(self) -> None:
        with self.assertRaisesRegex(BudgetExceeded, "below the selected registry price"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="underpriced",
                    dedupe_key="underpriced",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=0),
                ),
            )
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="rounded",
                dedupe_key="rounded",
                amounts=BudgetAmounts(
                    input_tokens=1, output_tokens=1, cost_microusd=2
                ),
            ),
        )
        self.assertEqual(
            _required_cost(
                self.selection,
                BudgetAmounts(input_tokens=1, output_tokens=1, cost_microusd=2),
            ),
            2,
        )
        expensive = replace(
            self.selection,
            input_cost_microusd_per_million=100_000_000_000,
        )
        with self.assertRaisesRegex(BudgetExceeded, "fixed-point limit"):
            _required_cost(expensive, BudgetAmounts(input_tokens=1_000_000_000))

    def test_runtime_uses_trusted_order_context_for_event_time(self) -> None:
        for index in (1, 2):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key=f"clock-{index}",
                    dedupe_key=f"clock-{index}",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            epochs = connection.execute(
                "SELECT created_at_epoch_ms FROM budget_events ORDER BY event_sequence"
            ).fetchall()
        self.assertEqual(epochs, [(1_800_000_000_123,), (1_800_000_000_123,)])

    def test_budget_writer_restores_wal_journal_mode(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        self.assertEqual(str(mode).casefold(), "delete")

        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="wal-restore",
                dedupe_key="wal-restore",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )

        with closing(sqlite3.connect(self.database)) as connection, connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(str(mode).casefold(), "wal")

    def test_missing_trusted_order_context_blocks_without_writes(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="missing-clock",
            dedupe_key="missing-clock",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        kwargs["clock_context_id"] = "missing-clock"
        with self.assertRaisesRegex(BudgetError, "trusted.*clock context"):
            reserve_budget(self.database, **kwargs)
        self.assertEqual(self._event_count(), 0)

    def test_new_reserve_after_spawn_intent_fails_closed(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="pre-rpc-reserve",
            dedupe_key="pre-rpc-reserve",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        reserve = reserve_budget(self.database, **kwargs)
        self._seed_runtime_dispatch_binding(reserve.budget_event_id)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES('intent','run',"
                "'transition','sessions_spawn','spawn',?,'client',"
                "'spawn-idem','phase','agent','task','{}','pending','now',"
                "1800000000124)",
                (reserve.budget_event_id,),
            )
        replay = reserve_budget(self.database, **kwargs)
        self.assertTrue(replay.replayed)
        with self.assertRaisesRegex(BudgetError, "existing sessions_spawn intent"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="post-rpc-reserve",
                    dedupe_key="post-rpc-reserve",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_release_after_spawn_intent_fails_closed(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="reserve-before-release-intent",
            dedupe_key="reserve-before-release-intent",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        reserve = reserve_budget(self.database, **kwargs)
        self._seed_runtime_dispatch_binding(reserve.budget_event_id)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES('intent','run',"
                "'transition','sessions_spawn','spawn',?,'client',"
                "'spawn-idem','phase','agent','task','{}','pending','now',"
                "1800000000124)",
                (reserve.budget_event_id,),
            )
        with self.assertRaisesRegex(BudgetError, "existing sessions_spawn intent"):
            release_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="release-after-intent",
                    dedupe_key="release-after-intent",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_direct_reserve_import_after_spawn_intent_fails_closed(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-before-direct-import",
                dedupe_key="reserve-before-direct-import",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._seed_runtime_dispatch_binding(reserve.budget_event_id)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES('intent','run',"
                "'transition','sessions_spawn','spawn',?,'client',"
                "'spawn-idem','phase','agent','task','{}','pending','now',"
                "1800000000124)",
                (reserve.budget_event_id,),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "reserve/release"):
                connection.execute(
                    "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                    "event_dedupe_hash,event_sequence,run_id,transition_id,"
                    "spawn_request_id,provider,model,endpoint_binding_id,"
                    "capability_class,cost_registry_id,cost_effective_at,"
                    "cost_registry_hash,cost_confidence,event_type,time_seconds,"
                    "input_tokens,output_tokens,cost_microusd,human_attention_units,"
                    "retry_units,usage_confidence,source,created_at,"
                    "created_at_epoch_ms) VALUES('late-reserve','late-reserve-idem',"
                    "'late-reserve-dedupe',2,'run','transition','spawn','provider',"
                    "'model','endpoint','capability','cost-row','effective',"
                    "'cost-hash','known','reserve',0,1,0,1,0,0,'known',"
                    "'repair','now',1800000000125)"
                )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,time_seconds,"
                "input_tokens,output_tokens,cost_microusd,human_attention_units,"
                "retry_units,usage_confidence,source,created_at,created_at_epoch_ms) "
                "VALUES('repair-event','repair-event-idem','repair-event-dedupe',"
                "2,'run','transition','spawn','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known','consume',"
                "0,1,0,1,0,0,'known','repair','now',1800000000125)"
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "reserve/release"):
                connection.execute(
                    "UPDATE budget_events SET event_type='reserve' "
                    "WHERE budget_event_id='repair-event'"
                )
        self.assertEqual(self._event_count(), 2)

    def test_release_cannot_use_another_spawn_reservation(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn-2','run','phase','agent','transition',"
                "'client-2','spawn-idem-2','task','pending','now','now')"
            )
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="spawn-1-reserve",
                dedupe_key="spawn-1-reserve",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        kwargs = self._kwargs(
            idempotency_key="cross-release",
            dedupe_key="cross-release",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        kwargs["spawn_request_id"] = "spawn-2"
        with self.assertRaisesRegex(BudgetExceeded, "spawn_request_id=spawn-2"):
            release_budget(self.database, **kwargs)
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 10, 0, 1, 0, 0, 0, 0, 0, 0))

    def test_human_attention_cannot_overconsume_per_spawn(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn-2','run','phase','agent','transition',"
                "'client-2','spawn-idem-2','task','pending','now','now')"
            )
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="spawn-1-human-reserve",
                dedupe_key="spawn-1-human-reserve",
                amounts=BudgetAmounts(
                    input_tokens=1, cost_microusd=1, human_attention_units=1
                ),
            ),
        )
        spawn_2 = self._kwargs(
            idempotency_key="spawn-2-human-reserve",
            dedupe_key="spawn-2-human-reserve",
            amounts=BudgetAmounts(
                input_tokens=1, cost_microusd=1, human_attention_units=1
            ),
        )
        spawn_2["spawn_request_id"] = "spawn-2"
        reserve_budget(self.database, **spawn_2)
        self._accept_spawn(reserve.budget_event_id, completed=False)
        consume_human_attention(
            self.database,
            **self._post_kwargs(
                idempotency_key="human-consumed",
                amounts=BudgetAmounts(human_attention_units=1),
            ),
        )
        with self.assertRaisesRegex(BudgetExceeded, "outstanding reservation"):
            consume_human_attention(
                self.database,
                **self._post_kwargs(
                    idempotency_key="double-consume-human",
                    amounts=BudgetAmounts(human_attention_units=1),
                ),
            )
        self.assertEqual(self._event_count(), 3)

    def test_cross_spawn_over_release_contamination_blocks_reserve(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn-2','run','phase','agent','transition',"
                "'client-2','spawn-idem-2','task','pending','now','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('reserve-a','reserve-a-idem',"
                "'reserve-a-dedupe',1,'run','transition','spawn','provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash','known',"
                "'reserve',1,1,'known','legacy','now',1000)"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('release-b','release-b-idem',"
                "'release-b-dedupe',2,'run','transition','spawn-2','provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash','known',"
                "'release',1,1,'known','legacy','now',1001)"
            )
        with self.assertRaisesRegex(BudgetError, "Budget prefix|per-spawn"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="blocked-cross-spawn",
                    dedupe_key="blocked-cross-spawn",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 2)
        self.assertEqual(self._budget_row(), (0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def test_release_reconciles_authoritative_ledger(self) -> None:
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve",
                dedupe_key="reserve",
                amounts=BudgetAmounts(
                    time_seconds=10,
                    input_tokens=50,
                    output_tokens=20,
                    cost_microusd=100,
                    retry_units=2,
                    human_attention_units=1,
                ),
            ),
        )
        release_budget(
            self.database,
            **self._kwargs(
                idempotency_key="release",
                dedupe_key="release",
                amounts=BudgetAmounts(
                    time_seconds=10,
                    input_tokens=50,
                    output_tokens=20,
                    cost_microusd=100,
                    retry_units=2,
                    human_attention_units=1,
                ),
            ),
        )
        self.assertEqual(self._budget_row(), (0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(
            self._slo_rows("Budget ledger reconciles to counters and budgets"), []
        )
        self.assertEqual(self._slo_rows("Budget prefix over-release or over-restore"), [])

    def test_release_without_reserve_and_over_release_are_atomic_failures(self) -> None:
        release = self._kwargs(
            idempotency_key="release",
            dedupe_key="release",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        with self.assertRaises(BudgetExceeded):
            release_budget(self.database, **release)
        self.assertEqual(self._event_count(), 0)
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve",
                dedupe_key="reserve",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        release["amounts"] = BudgetAmounts(input_tokens=3, cost_microusd=2)
        with self.assertRaises(BudgetExceeded):
            release_budget(self.database, **release)
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 2, 0, 2, 0, 0, 0, 0, 0, 0))

    def test_release_cannot_underfund_remaining_token_reservation(self) -> None:
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-cost-floor",
                dedupe_key="reserve-cost-floor",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=1),
            ),
        )
        with self.assertRaisesRegex(BudgetExceeded, "underfund"):
            release_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="release-cost-only",
                    dedupe_key="release-cost-only",
                    amounts=BudgetAmounts(cost_microusd=1),
                ),
            )
        release_budget(
            self.database,
            **self._kwargs(
                idempotency_key="release-one-token",
                dedupe_key="release-one-token",
                amounts=BudgetAmounts(input_tokens=1),
            ),
        )
        self.assertEqual(self._budget_row(), (0, 1, 0, 1, 0, 0, 0, 0, 0, 0))

    def test_consume_cannot_underfund_remaining_token_reservation(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-consume-cost-floor",
                dedupe_key="reserve-consume-cost-floor",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with self.assertRaisesRegex(BudgetExceeded, "underfund"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="consume-cost-only",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._budget_row(), (0, 10, 0, 1, 0, 0, 0, 0, 0, 0))

    def test_reserve_and_release_require_pending_spawn_state(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE spawn_requests SET state='failed' WHERE spawn_request_id='spawn'"
            )
        for operation in (reserve_budget, release_budget):
            with self.assertRaisesRegex(BudgetError, "pending pre-RPC"):
                operation(
                    self.database,
                    **self._kwargs(
                        idempotency_key=f"state-{operation.__name__}",
                        dedupe_key=f"state-{operation.__name__}",
                        amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                    ),
                )

    def test_budget_mutations_require_pre_dispatch_run_state(self) -> None:
        for state in ("human_review_required", "rolled_back", "finalized"):
            with self.subTest(state=state):
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute(
                        "UPDATE runs SET state=? WHERE run_id='run'",
                        (state,),
                    )
                for operation in (reserve_budget, release_budget):
                    with self.assertRaisesRegex(BudgetError, "pre-dispatch state"):
                        operation(
                            self.database,
                            **self._kwargs(
                                idempotency_key=f"run-state-{state}-{operation.__name__}",
                                dedupe_key=f"run-state-{state}-{operation.__name__}",
                                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                            ),
                        )
                self.assertEqual(self._event_count(), 0)

    def test_composite_spawn_binding_antijoin_blocks_legacy_contamination(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) VALUES("
                "'run-2','prepare-2','workflow','file_authority','candidate','R1','R1',"
                "'now','now')"
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('transition-2','run-2','before',"
                "'after','dispatch','spawn','R1','transition-idem-2',0,'now')"
            )
            connection.execute(
                "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
                "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
                "selected_cost_effective_at,selected_cost_registry_hash,"
                "selected_cost_confidence,selected_reserve_transition_id,time_budget_seconds,"
                "input_token_budget,output_token_budget,cost_budget_microusd,retry_budget,"
                "human_attention_budget,reserved_input_tokens,reserved_cost_microusd,"
                "usage_confidence,updated_at) VALUES('run-2','workflow','capability',"
                "'provider','model','endpoint','cost-row','effective','cost-hash','known',"
                "'transition-2',100,1000,1000,10000,10,10,1,1,'known','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "cost_microusd,usage_confidence,source,created_at,created_at_epoch_ms) VALUES("
                "'legacy-bad','legacy-bad-idem','legacy-bad-dedupe',1,'run-2',"
                "'transition-2','spawn','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','reserve',1,1,'known','legacy','now',1)"
            )
        with self.assertRaisesRegex(BudgetError, "composite-bound"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="blocked-by-legacy",
                    dedupe_key="blocked-by-legacy",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def test_wrong_transition_ledger_event_blocks_selected_reserve(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES('transition-other','run',"
                "'before','after','dispatch','spawn','R1','transition-other-idem',0,'now')"
            )
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES('spawn-other','run','phase','agent',"
                "'transition-other','client-other','spawn-idem-other','task','pending',"
                "'now','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('wrong-transition','wrong-transition-idem',"
                "'wrong-transition-dedupe',1,'run','transition-other','spawn-other',"
                "'provider','model','endpoint','capability','cost-row','effective',"
                "'cost-hash','known','reserve',1,1,'known','legacy','now',1000)"
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=1,"
                "reserved_cost_microusd=1 WHERE run_id='run'"
            )
        with self.assertRaisesRegex(BudgetError, "composite-bound"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="blocked-wrong-transition",
                    dedupe_key="blocked-wrong-transition",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), (0, 1, 0, 1, 0, 0, 0, 0, 0, 0))

    def test_retry_event_without_accepted_session_proof_fails_closed(self) -> None:
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="retry-proof-reserve",
                dedupe_key="retry-proof-reserve",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE runs SET state='running' WHERE run_id='run'")
        with self.assertRaisesRegex(BudgetError, "accepted session proof"):
            decrement_retry_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="retry-without-proof",
                    amounts=BudgetAmounts(retry_units=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_runtime_runs_all_pinned_blocking_budget_slos(self) -> None:
        self.assertTrue(
            {
                "Duplicate live dispatch blocked",
                "Model cost registry numeric bounds",
                "`sessions_spawn` intent without exact strict prior reserve",
                "Meaningless `sessions_spawn` reserve",
            }.issubset(_BUDGET_INVARIANT_QUERIES)
        )

    def test_model_cost_registry_slo_blocks_budget_commit(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,"
                "registry_row_hash) VALUES('bad-cost','bad-provider','bad-model',"
                "'bad-endpoint','bad-capability',1,1,'unknown','bad-effective',"
                "'bad-cost-hash')"
            )
        with self.assertRaisesRegex(BudgetError, "Model cost registry numeric bounds"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="blocked-bad-cost-registry",
                    dedupe_key="blocked-bad-cost-registry",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 0)

    def test_zero_reserve_requires_exact_policy_and_minima(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO endpoint_zero_reserve_policies("
                "zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,"
                "enabled,min_retry_units,min_time_seconds,min_human_attention_units,"
                "effective_from_epoch_ms,effective_until_epoch_ms) VALUES("
                "'zero-policy','endpoint','capability','zero-hash',1,1,2,0,1,"
                "253402300799999)"
            )
        valid = self._kwargs(
            idempotency_key="zero-valid",
            dedupe_key="zero-valid",
            amounts=BudgetAmounts(time_seconds=2, retry_units=1),
        )
        with self.assertRaises(BudgetError):
            reserve_budget(self.database, **valid)
        valid["zero_reserve_policy_id"] = "zero-policy"
        reserve_budget(self.database, **valid)
        invalid = self._kwargs(
            idempotency_key="zero-invalid",
            dedupe_key="zero-invalid",
            amounts=BudgetAmounts(time_seconds=1, retry_units=1),
        )
        invalid["zero_reserve_policy_id"] = "zero-policy"
        with self.assertRaises(BudgetConflict):
            reserve_budget(self.database, **invalid)
        self.assertEqual(self._event_count(), 1)

    def test_unknown_selected_usage_confidence_blocks_without_writes(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE run_budgets SET usage_confidence='unknown' WHERE run_id='run'"
            )
        with self.assertRaises(BudgetError):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="unknown",
                    dedupe_key="unknown",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 0)

    def test_unknown_non_classification_event_blocks_new_writes(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,cost_registry_id,"
                "cost_effective_at,cost_registry_hash,cost_confidence,event_type,"
                "input_tokens,cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('unknown-usage','unknown-usage-idem',"
                "'unknown-usage-dedupe',1,'run','transition','spawn','provider','model',"
                "'endpoint','capability','cost-row','effective','cost-hash','known',"
                "'reserve',1,1,'unknown','legacy','now',1000)"
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=1,"
                "reserved_cost_microusd=1 WHERE run_id='run'"
            )
        with self.assertRaisesRegex(BudgetError, "unknown usage"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="blocked-unknown",
                    dedupe_key="blocked-unknown",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_estimated_event_conservatively_downgrades_usage_confidence(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="estimated",
            dedupe_key="estimated",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        kwargs["usage_confidence"] = "estimated"
        reserve_budget(self.database, **kwargs)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            confidence = connection.execute(
                "SELECT usage_confidence FROM run_budgets WHERE run_id='run'"
            ).fetchone()[0]
        self.assertEqual(confidence, "estimated")

    def test_completed_spawn_usage_consumes_reserved_amounts(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-consume",
                dedupe_key="reserve-for-consume",
                amounts=BudgetAmounts(
                    time_seconds=10,
                    input_tokens=10,
                    output_tokens=5,
                    cost_microusd=10,
                ),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="consume-usage",
                amounts=BudgetAmounts(
                    time_seconds=4,
                    input_tokens=4,
                    output_tokens=2,
                    cost_microusd=2,
                ),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE runs SET state='finalized' WHERE run_id='run'")
        replay = consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="consume-usage",
                amounts=BudgetAmounts(
                    time_seconds=4,
                    input_tokens=4,
                    output_tokens=2,
                    cost_microusd=2,
                ),
            ),
        )
        self.assertFalse(result.replayed)
        self.assertTrue(replay.replayed)
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_time_seconds,reserved_input_tokens,"
                "reserved_output_tokens,reserved_cost_microusd,consumed_time_seconds,"
                "consumed_input_tokens,consumed_output_tokens,consumed_cost_microusd "
                "FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (6, 6, 3, 8, 4, 4, 2, 2))

    def test_referenced_spawn_counter_drift_requires_ledger_backing(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-trigger",
                dedupe_key="reserve-for-trigger",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "ledger-backed"):
                connection.execute(
                    "UPDATE run_budgets SET reserved_input_tokens=11 "
                    "WHERE run_id='run'"
                )
        consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="ledger-backed-consume",
                amounts=BudgetAmounts(input_tokens=4, cost_microusd=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_input_tokens,consumed_input_tokens "
                "FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (6, 4))

    def test_unknown_completed_usage_is_durable_and_blocks_more_budget_work(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-unknown",
                dedupe_key="reserve-for-unknown",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        kwargs = self._post_kwargs(
            idempotency_key="unknown-usage",
            amounts=BudgetAmounts(),
        )
        kwargs["usage_confidence"] = "unknown"
        consume_budget(self.database, **kwargs)
        consume_budget(self.database, **kwargs)
        with self.assertRaisesRegex(BudgetError, "unknown usage confidence"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="blocked-after-unknown",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        with closing(sqlite3.connect(self.database)) as connection:
            confidence = connection.execute(
                "SELECT usage_confidence FROM run_budgets WHERE run_id='run'"
            ).fetchone()[0]
            event = connection.execute(
                "SELECT event_type,usage_confidence,input_tokens,cost_microusd "
                "FROM budget_events WHERE event_idempotency_key='unknown-usage'"
            ).fetchone()
        self.assertEqual(confidence, "unknown")
        self.assertEqual(event, ("consume", "unknown", 0, 0))

    def test_zero_unknown_usage_row_must_poison_run_budget(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-drifted-unknown",
                dedupe_key="reserve-for-drifted-unknown",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,"
                "event_type,usage_confidence,source,created_at,created_at_epoch_ms) "
                "VALUES('drifted-unknown','drifted-unknown-idem',"
                "'drifted-unknown-dedupe',2,'run','transition','spawn','provider',"
                "'model','endpoint','capability','cost-row','effective','cost-hash',"
                "'known','consume','unknown','legacy-import','now',1800000000125)"
            )
        with self.assertRaisesRegex(BudgetError, "unknown usage confidence"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="blocked-after-drifted-unknown",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 2)

    def test_post_dispatch_budget_mutation_rejects_manual_review_run(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-manual-review",
                dedupe_key="reserve-for-manual-review",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE runs SET state='human_review_required' WHERE run_id='run'"
            )
        with self.assertRaisesRegex(BudgetError, "active post-dispatch run"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="manual-review-consume",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )

    def test_post_dispatch_budget_mutation_requires_post_acceptance_clock(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-stale-clock",
                dedupe_key="reserve-for-stale-clock",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        kwargs = self._post_kwargs(
            idempotency_key="stale-clock-consume",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        kwargs["clock_context_id"] = "clock"
        with self.assertRaisesRegex(BudgetError, "fresh clock"):
            consume_budget(self.database, **kwargs)

    def test_accepted_spawn_timing_is_immutable_after_acceptance(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-bad-accepted-clock",
                dedupe_key="reserve-for-bad-accepted-clock",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            for assignment in (
                "requested_at_epoch_ms=1800000000126",
                "accepted_at_epoch_ms=1800000000126",
            ):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "external intent proof"):
                    connection.execute(
                        f"UPDATE external_rpc_intents SET {assignment} "
                        "WHERE intent_id='intent'"
                    )
        self.assertEqual(self._event_count(), 1)

    def test_referenced_reserve_clock_context_and_replay_keys_are_immutable(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-referenced-clock",
                dedupe_key="reserve-for-referenced-clock",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            for assignment in (
                "clock_context_id='post-clock'",
                "event_idempotency_key='rewritten-reserve-key'",
                "event_dedupe_hash='rewritten-reserve-hash'",
            ):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "reserve is immutable"):
                    connection.execute(
                        f"UPDATE budget_events SET {assignment} WHERE budget_event_id=?",
                        (reserve.budget_event_id,),
                    )
        replay = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-referenced-clock",
                dedupe_key="reserve-for-referenced-clock",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self.assertTrue(replay.replayed)

    def test_consume_requires_completed_session_state(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-running-session",
                dedupe_key="reserve-for-running-session",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE sessions SET state='running' WHERE session_id='session'")
        with self.assertRaisesRegex(BudgetError, "accepted session proof"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="running-session-consume",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )

    def test_retry_decrement_debits_reserved_retry_unit_at_budget_limit(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE run_budgets SET retry_budget=1 WHERE run_id='run'")
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-single-retry",
                dedupe_key="reserve-single-retry",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1, retry_units=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=False)
        decrement_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="single-retry-decrement",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_retries,consumed_retries "
                "FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (0, 1))
        restore_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="single-retry-restore",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_retries,consumed_retries "
                "FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (1, 0))

    def test_retry_decrement_requires_this_spawn_retry_reservation(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-without-retry",
                dedupe_key="reserve-without-retry",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=False)
        with self.assertRaisesRegex(BudgetExceeded, "outstanding reservation"):
            decrement_retry_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="retry-without-reservation",
                    amounts=BudgetAmounts(retry_units=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_retry_and_human_attention_events_update_exact_counters(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-runtime-events",
                dedupe_key="reserve-for-runtime-events",
                amounts=BudgetAmounts(
                    input_tokens=1,
                    cost_microusd=1,
                    retry_units=1,
                    human_attention_units=2,
                ),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=False)
        decrement_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="retry-decrement",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_retries,consumed_retries "
                "FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (0, 1))
        consume_human_attention(
            self.database,
            **self._post_kwargs(
                idempotency_key="human-attention",
                amounts=BudgetAmounts(human_attention_units=1),
            ),
        )
        restore_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="retry-restore",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT reserved_retries,consumed_retries,reserved_human_attention,"
                "consumed_human_attention FROM run_budgets WHERE run_id='run'"
            ).fetchone()
        self.assertEqual(row, (1, 0, 1, 1))

    def test_post_dispatch_event_without_accepted_session_proof_fails_closed(self) -> None:
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-without-proof",
                dedupe_key="reserve-without-proof",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE runs SET state='running' WHERE run_id='run'")
        with self.assertRaisesRegex(BudgetError, "accepted session proof"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="consume-without-proof",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

    def test_duplicate_live_dispatch_blocks_post_dispatch_budget_write(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-before-duplicate-dispatch",
                dedupe_key="reserve-before-duplicate-dispatch",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        duplicate_metadata = (
            '{"run_id":"run","transition_id":"transition",'
            '"client_request_id":"client-duplicate",'
            '"idempotency_key":"spawn-idem-duplicate",'
            '"phase":"phase","agent_id":"agent","task_digest":"task-duplicate"}'
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,"
                "state,session_key,created_at,updated_at) VALUES("
                "'spawn-duplicate','run','phase','agent','transition',"
                "'client-duplicate','spawn-idem-duplicate','task-duplicate',"
                "'pending','session-key-duplicate','now','now')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,time_seconds,"
                "input_tokens,output_tokens,cost_microusd,human_attention_units,"
                "retry_units,usage_confidence,source,created_at,created_at_epoch_ms) "
                "VALUES('duplicate-reserve','duplicate-reserve-idem',"
                "'duplicate-reserve-dedupe',2,'run','transition','spawn-duplicate',"
                "'provider','model','endpoint','capability','cost-row','effective',"
                "'cost-hash','known','reserve',0,1,0,1,0,0,'known','repair',"
                "'now',1800000000123)"
            )
            connection.execute(
                "UPDATE run_budgets SET reserved_input_tokens=11,"
                "reserved_cost_microusd=2 WHERE run_id='run'"
            )
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,"
                "release_idempotency_key,ttl_ms,acquire_requested_at,expires_at,"
                "expires_at_epoch_ms) VALUES('lease-duplicate','run','phase','transition',"
                "'agent','requester','acquire_pending','client-lease-duplicate',"
                "'acquire-idem-duplicate','release-idem-duplicate',60000,'now','later',"
                "1800000060124)"
            )
            connection.execute(
                "INSERT INTO runtime_dispatch_bindings(spawn_request_id,lease_id,run_id,"
                "transition_id,phase,agent_id,requester_agent_id,task_digest,client_lease_id,"
                "acquire_idempotency_key,release_idempotency_key,spawn_client_request_id,"
                "spawn_idempotency_key,reserve_budget_event_id,created_at) VALUES('spawn-duplicate',"
                "'lease-duplicate','run','transition','phase','agent','requester',"
                "'task-duplicate','client-lease-duplicate','acquire-idem-duplicate',"
                "'release-idem-duplicate','client-duplicate','spawn-idem-duplicate','duplicate-reserve','now')"
            )
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,"
                "rpc_kind,spawn_request_id,reserve_budget_event_id,client_request_id,"
                "idempotency_key,phase,agent_id,task_digest,metadata_contract_version,"
                "metadata_json,external_metadata_json,external_run_id,"
                "external_transition_id,external_client_request_id,"
                "external_idempotency_key,external_phase,external_agent_id,"
                "external_task_digest,state,external_id,requested_at,"
                "requested_at_epoch_ms,accepted_at,accepted_at_epoch_ms) VALUES("
                "'intent-duplicate','run','transition','sessions_spawn',"
                "'spawn-duplicate','duplicate-reserve','client-duplicate',"
                "'spawn-idem-duplicate','phase','agent','task-duplicate','v1',"
                "? ,?,'run','transition','client-duplicate','spawn-idem-duplicate',"
                "'phase','agent','task-duplicate','accepted','session-key-duplicate',"
                "'now',1800000000124,'now',1800000000125)",
                (duplicate_metadata, duplicate_metadata),
            )
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,"
                "phase,agent_id,client_request_id,spawn_idempotency_key,session_key,"
                "task_digest,state,spawned_at,completed_at) VALUES("
                "'session-duplicate','spawn-duplicate','run','transition','phase',"
                "'agent','client-duplicate','spawn-idem-duplicate',"
                "'session-key-duplicate','task-duplicate','running','now',NULL)"
            )
            connection.execute(
                "UPDATE spawn_requests SET state='accepted' "
                "WHERE spawn_request_id='spawn-duplicate'"
            )
        with self.assertRaisesRegex(BudgetError, "Duplicate live dispatch blocked"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="consume-with-duplicate-dispatch",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 2)

    def test_post_dispatch_event_persists_clock_context_and_is_immutable(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-post-clock",
                dedupe_key="reserve-for-post-clock",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="clock-bound-consume",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT clock_context_id FROM budget_events WHERE budget_event_id=?",
                (result.budget_event_id,),
            ).fetchone()
            self.assertEqual(row, ("post-clock",))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE budget_events SET source='repair' WHERE budget_event_id=?",
                    (result.budget_event_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE budget_events SET event_idempotency_key='rewritten-key' "
                    "WHERE budget_event_id=?",
                    (result.budget_event_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE budget_events SET event_dedupe_hash='rewritten-hash' "
                    "WHERE budget_event_id=?",
                    (result.budget_event_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "DELETE FROM budget_events WHERE budget_event_id=?",
                    (result.budget_event_id,),
                )

    def test_final_settlement_atomically_consumes_and_releases_all_dimensions(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-final-settlement",
                dedupe_key="reserve-for-final-settlement",
                amounts=BudgetAmounts(
                    time_seconds=5,
                    input_tokens=20,
                    output_tokens=10,
                    cost_microusd=100,
                    retry_units=2,
                    human_attention_units=3,
                ),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        kwargs = {
            "run_id": "run",
            "transition_id": "transition",
            "selection": self.selection,
            "actual_usage": BudgetAmounts(
                time_seconds=3,
                input_tokens=8,
                output_tokens=4,
                cost_microusd=10,
                retry_units=1,
                human_attention_units=2,
            ),
            "idempotency_key": "final-settlement",
            "dedupe_key": "final-settlement-source",
            "source": "terminal-usage-import",
            "spawn_request_id": "spawn",
            "clock_context_id": "post-clock",
        }
        first = settle_budget(self.database, **kwargs)
        replay = settle_budget(self.database, **kwargs)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.settlement_id, replay.settlement_id)
        self.assertEqual(len(first.events), 4)
        self.assertTrue(all(event.replayed for event in replay.events))
        self.assertEqual(
            first.released,
            BudgetAmounts(
                time_seconds=2,
                input_tokens=12,
                output_tokens=6,
                cost_microusd=90,
                retry_units=1,
                human_attention_units=1,
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            budget = connection.execute(
                "SELECT reserved_time_seconds,reserved_input_tokens,"
                "reserved_output_tokens,reserved_cost_microusd,reserved_retries,"
                "reserved_human_attention,consumed_time_seconds,"
                "consumed_input_tokens,consumed_output_tokens,consumed_cost_microusd,"
                "consumed_retries,consumed_human_attention FROM run_budgets "
                "WHERE run_id='run'"
            ).fetchone()
            self.assertEqual(budget, (0, 0, 0, 0, 0, 0, 3, 8, 4, 10, 1, 2))
            linked = connection.execute(
                "SELECT event_type FROM budget_events WHERE settlement_id=? "
                "ORDER BY event_sequence",
                (first.settlement_id,),
            ).fetchall()
            self.assertEqual(
                linked,
                [
                    ("consume",),
                    ("retry_decrement",),
                    ("human_attention",),
                    ("release",),
                ],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE budget_settlements SET source='repair' "
                    "WHERE settlement_id=?",
                    (first.settlement_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "DELETE FROM budget_events WHERE settlement_id=? "
                    "AND event_type='release'",
                    (first.settlement_id,),
                )

    def test_final_settlement_blocks_retry_restore_after_terminal_usage(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-terminal-retry",
                dedupe_key="reserve-for-terminal-retry",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1, retry_units=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(retry_units=1),
            idempotency_key="final-terminal-retry",
            dedupe_key="final-terminal-retry",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        self.assertEqual(
            [event.event_sequence for event in result.events],
            [2, 3],
        )
        with self.assertRaisesRegex(BudgetConflict, "final settlement is terminal"):
            restore_retry_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="restore-after-terminal-final",
                    amounts=BudgetAmounts(retry_units=1),
                ),
            )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(
                connection.execute(
                    "SELECT reserved_retries,consumed_retries FROM run_budgets "
                    "WHERE run_id='run'"
                ).fetchone(),
                (0, 1),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "final settlement"):
                connection.execute(
                    "INSERT INTO budget_events("
                    "budget_event_id,event_idempotency_key,event_dedupe_hash,"
                    "event_sequence,run_id,transition_id,spawn_request_id,"
                    "provider,model,endpoint_binding_id,capability_class,"
                    "cost_registry_id,cost_effective_at,cost_registry_hash,"
                    "cost_confidence,event_type,retry_units,usage_confidence,"
                    "source,created_at,created_at_epoch_ms,clock_context_id"
                    ") VALUES('direct-retry-restore-after-final',"
                    "'direct-retry-restore-after-final-idem',"
                    "'direct-retry-restore-after-final-dedupe',4,'run',"
                    "'transition','spawn','provider','model','endpoint',"
                    "'capability','cost-row','effective','cost-hash','known',"
                    "'retry_restore',1,'known','usage-import','now',"
                    "1800000000127,'post-clock')"
                )
            connection.execute(
                "DROP TRIGGER budget_events_reject_after_final_settlement_insert"
            )
            connection.execute(
                "INSERT INTO budget_events("
                "budget_event_id,event_idempotency_key,event_dedupe_hash,"
                "event_sequence,run_id,transition_id,spawn_request_id,"
                "provider,model,endpoint_binding_id,capability_class,"
                "cost_registry_id,cost_effective_at,cost_registry_hash,"
                "cost_confidence,event_type,retry_units,usage_confidence,"
                "source,created_at,created_at_epoch_ms,clock_context_id"
                ") VALUES('bypassed-retry-restore-after-final',"
                "'bypassed-retry-restore-after-final-idem',"
                "'bypassed-retry-restore-after-final-dedupe',4,'run',"
                "'transition','spawn','provider','model','endpoint',"
                "'capability','cost-row','effective','cost-hash','known',"
                "'retry_restore',1,'known','usage-import','now',"
                "1800000000127,'post-clock')"
            )
        rows = self._slo_rows("Budget event amount malformed or out of range")
        self.assertIn((result.settlement_id,), rows)

    def test_final_settlement_allows_zero_outstanding_terminal_proof(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-zero-outstanding-final",
                dedupe_key="reserve-for-zero-outstanding-final",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1, retry_units=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="consume-before-zero-outstanding-final",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        decrement_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="retry-before-zero-outstanding-final",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        result = settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(),
            idempotency_key="zero-outstanding-final",
            dedupe_key="zero-outstanding-final",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        self.assertEqual(result.released, BudgetAmounts())
        self.assertEqual([event.event_sequence for event in result.events], [4])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(
                connection.execute(
                    "SELECT event_type,input_tokens,cost_microusd,retry_units "
                    "FROM budget_events WHERE settlement_id=?",
                    (result.settlement_id,),
                ).fetchall(),
                [("release", 0, 0, 0)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT reserved_input_tokens,reserved_cost_microusd,"
                    "reserved_retries,consumed_input_tokens,consumed_cost_microusd,"
                    "consumed_retries FROM run_budgets WHERE run_id='run'"
                ).fetchone(),
                (0, 0, 0, 1, 1, 1),
            )
        with self.assertRaisesRegex(BudgetConflict, "final settlement is terminal"):
            restore_retry_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="restore-after-zero-outstanding-final",
                    amounts=BudgetAmounts(retry_units=1),
                ),
            )
        self.assertNotIn(
            (result.settlement_id,),
            self._slo_rows("Budget event amount malformed or out of range"),
        )

    def test_final_settlement_blocks_updates_into_unlinked_usage_events(self) -> None:
        reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="extra-reserve-before-terminal-update-guard",
                dedupe_key="extra-reserve-before-terminal-update-guard",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        released = release_budget(
            self.database,
            **self._kwargs(
                idempotency_key="pre-intent-release-before-final",
                dedupe_key="pre-intent-release-before-final",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-before-terminal-update-guard",
                dedupe_key="reserve-before-terminal-update-guard",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
            idempotency_key="final-before-update-guard",
            dedupe_key="final-before-update-guard",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "final settlement is terminal|accepted post-dispatch",
            ):
                connection.execute(
                    "UPDATE budget_events SET event_type='consume',"
                    "usage_confidence='known',source='usage-import',"
                    "created_at='now',created_at_epoch_ms=1800000000126,"
                    "clock_context_id='post-clock' WHERE budget_event_id=?",
                    (released.budget_event_id,),
                )
        self.assertNotIn(
            (result.settlement_id,),
            self._slo_rows("Budget event amount malformed or out of range"),
        )

    def test_post_dispatch_replay_survives_later_final_settlement(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-pre-final-replay",
                dedupe_key="reserve-for-pre-final-replay",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1, retry_units=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        decrement = decrement_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="pre-final-retry-decrement",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(),
            idempotency_key="final-after-pre-replay",
            dedupe_key="final-after-pre-replay",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        replay = decrement_retry_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="pre-final-retry-decrement",
                amounts=BudgetAmounts(retry_units=1),
            ),
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.budget_event_id, decrement.budget_event_id)

    def test_final_settlement_conflict_and_overage_roll_back_atomically(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-final-conflict",
                dedupe_key="reserve-for-final-conflict",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=10),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        before = self._budget_row()
        with self.assertRaisesRegex(BudgetExceeded, "registry price"):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=1),
                idempotency_key="underpriced-final",
                dedupe_key="underpriced-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )
        with self.assertRaises(BudgetExceeded):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=11, cost_microusd=10),
                idempotency_key="over-final",
                dedupe_key="over-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )
        self.assertEqual(self._settlement_count(), 0)
        self.assertEqual(self._event_count(), 1)
        self.assertEqual(self._budget_row(), before)
        settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(input_tokens=5, cost_microusd=5),
            idempotency_key="valid-final",
            dedupe_key="valid-final",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        with self.assertRaises(BudgetConflict):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=4, cost_microusd=4),
                idempotency_key="valid-final",
                dedupe_key="valid-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )
        self.assertEqual(self._settlement_count(), 1)

    def test_unknown_usage_blocks_final_settlement(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-unknown-final",
                dedupe_key="reserve-for-unknown-final",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        consume_budget(
            self.database,
            **self._post_kwargs(
                idempotency_key="unknown-before-final",
                amounts=BudgetAmounts(),
            ),
            usage_confidence="unknown",
        )
        with self.assertRaisesRegex(BudgetError, "unknown usage"):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
                idempotency_key="blocked-final",
                dedupe_key="blocked-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )
        self.assertEqual(self._settlement_count(), 0)

    def test_final_settlement_requires_completed_session_and_post_accept_clock(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-final-proof",
                dedupe_key="reserve-for-final-proof",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=False)
        common = {
            "run_id": "run",
            "transition_id": "transition",
            "selection": self.selection,
            "actual_usage": BudgetAmounts(input_tokens=1, cost_microusd=1),
            "idempotency_key": "proof-final",
            "dedupe_key": "proof-final",
            "source": "terminal-usage-import",
            "spawn_request_id": "spawn",
            "clock_context_id": "post-clock",
        }
        with self.assertRaisesRegex(BudgetError, "completed session proof"):
            settle_budget(self.database, **common)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE runs SET state='child_completed' WHERE run_id='run'")
            connection.execute(
                "UPDATE spawn_requests SET state='completed' "
                "WHERE spawn_request_id='spawn'"
            )
            connection.execute(
                "UPDATE sessions SET state='completed',completed_at='now' "
                "WHERE session_id='session'"
            )
        with self.assertRaisesRegex(BudgetError, "after request acceptance"):
            settle_budget(self.database, **{**common, "clock_context_id": "clock"})
        self.assertEqual(self._settlement_count(), 0)

    def test_final_settlement_slo_revalidates_completed_session_after_drift(
        self,
    ) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-session-drift-final",
                dedupe_key="reserve-for-session-drift-final",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(),
            idempotency_key="release-only-session-drift-final",
            dedupe_key="release-only-session-drift-final",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        self.assertEqual(len(result.events), 1)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable completed-session proof"
            ):
                connection.execute(
                    "UPDATE sessions SET state='running',completed_at=NULL "
                    "WHERE session_id='session'"
                )
            connection.execute(
                "DROP TRIGGER sessions_preserve_settlement_completed_proof_update"
            )
            connection.execute(
                "UPDATE sessions SET state='running',completed_at=NULL "
                "WHERE session_id='session'"
            )
        rows = self._slo_rows("Budget event amount malformed or out of range")
        self.assertIn((result.settlement_id,), rows)
        with self.assertRaisesRegex(BudgetError, "schema verification failed"):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(),
                idempotency_key="release-only-session-drift-final",
                dedupe_key="release-only-session-drift-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )

    def test_final_settlement_slo_revalidates_linked_event_amounts(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-linked-amount-drift",
                dedupe_key="reserve-for-linked-amount-drift",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        result = settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
            idempotency_key="linked-amount-drift-final",
            dedupe_key="linked-amount-drift-final",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DROP TRIGGER budget_events_reject_settlement_link_update")
            connection.execute(
                "DROP TRIGGER budget_events_preserve_accepted_post_dispatch_update"
            )
            connection.execute(
                "UPDATE budget_events SET input_tokens=2,cost_microusd=2 "
                "WHERE settlement_id=? AND event_type='consume'",
                (result.settlement_id,),
            )
            connection.execute(
                "UPDATE budget_events SET input_tokens=0,cost_microusd=0 "
                "WHERE settlement_id=? AND event_type='release'",
                (result.settlement_id,),
            )
            connection.execute(
                "UPDATE run_budgets SET consumed_input_tokens=2,"
                "consumed_cost_microusd=2 WHERE run_id='run'"
            )
        rows = self._slo_rows("Budget event amount malformed or out of range")
        self.assertIn((result.settlement_id,), rows)

    def test_final_settlement_slo_remains_valid_after_run_finalization(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-finalized-proof",
                dedupe_key="reserve-for-finalized-proof",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        common = {
            "run_id": "run",
            "transition_id": "transition",
            "selection": self.selection,
            "actual_usage": BudgetAmounts(),
            "idempotency_key": "finalized-proof-final",
            "dedupe_key": "finalized-proof-final",
            "source": "terminal-usage-import",
            "spawn_request_id": "spawn",
            "clock_context_id": "post-clock",
        }
        result = settle_budget(self.database, **common)
        for state in ("gate_passed", "release_pending", "finalized"):
            with closing(sqlite3.connect(self.database)) as connection, connection:
                connection.execute(
                    "UPDATE runs SET state=?,updated_at='later' WHERE run_id='run'",
                    (state,),
                )
            self.assertNotIn(
                (result.settlement_id,),
                self._slo_rows("Budget event amount malformed or out of range"),
            )
            replay = settle_budget(self.database, **common)
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.settlement_id, result.settlement_id)

    def test_direct_final_settlement_rejects_new_row_after_gate_passed(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-before-gate-passed-direct",
                dedupe_key="reserve-before-gate-passed-direct",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        insert_sql = (
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
            "created_at,created_at_epoch_ms,clock_context_id) VALUES("
            "'gate-passed-direct-settlement','gate-passed-direct-idem',"
            "'gate-passed-direct-dedupe','run','transition','spawn','provider',"
            "'model','endpoint','capability','cost-row','effective','cost-hash',"
            "'known',0,0,0,0,0,0,0,1,0,1,0,0,'known','direct-import',"
            "'now',1800000000126,'post-clock')"
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "UPDATE runs SET state='gate_passed' WHERE run_id='run'"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "final settlement requires exact completed-session",
            ):
                connection.execute(insert_sql)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_settlements"
                ).fetchone()[0],
                0,
            )
            connection.execute(
                "UPDATE runs SET state='child_completed' WHERE run_id='run'"
            )
            connection.execute(insert_sql)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_settlements"
                ).fetchone()[0],
                1,
            )
            connection.commit()

    def test_final_settlement_rejects_outstanding_from_unselected_cost_row(
        self,
    ) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-selected-before-final",
                dedupe_key="reserve-selected-before-final",
                amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
            ),
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
                "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
                "output_cost_microusd_per_million,confidence,effective_at,"
                "registry_row_hash) VALUES('cost-row-other','other-provider',"
                "'other-model','endpoint','capability',100,200,'known','effective',"
                "'cost-hash-other')"
            )
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,"
                "spawn_request_id,provider,model,endpoint_binding_id,"
                "capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,event_type,input_tokens,"
                "cost_microusd,usage_confidence,source,created_at,"
                "created_at_epoch_ms) VALUES('wrong-cost-reserve',"
                "'wrong-cost-reserve-idem','wrong-cost-reserve-dedupe',2,'run',"
                "'transition','spawn','other-provider','other-model','endpoint',"
                "'capability','cost-row-other','effective','cost-hash-other',"
                "'known','reserve',1,1,'known','test','now',1800000000123)"
            )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "final settlement requires exact completed-session",
            ):
                connection.execute(
                    "INSERT INTO budget_settlements("
                    "settlement_id,settlement_idempotency_key,"
                    "settlement_dedupe_hash,run_id,transition_id,"
                    "spawn_request_id,provider,model,endpoint_binding_id,"
                    "capability_class,cost_registry_id,cost_effective_at,"
                    "cost_registry_hash,cost_confidence,actual_time_seconds,"
                    "actual_input_tokens,actual_output_tokens,actual_cost_microusd,"
                    "actual_retry_units,actual_human_attention_units,"
                    "released_time_seconds,released_input_tokens,"
                    "released_output_tokens,released_cost_microusd,"
                    "released_retry_units,released_human_attention_units,"
                    "usage_confidence,source,created_at,created_at_epoch_ms,"
                    "clock_context_id) VALUES('wrong-cost-settlement',"
                    "'wrong-cost-settlement-idem','wrong-cost-settlement-dedupe',"
                    "'run','transition','spawn','provider','model','endpoint',"
                    "'capability','cost-row','effective','cost-hash','known',"
                    "0,0,0,0,0,0,0,2,0,2,0,0,'known','imported','now',"
                    "1800000000126,'post-clock')"
                )
        self.assertEqual(self._settlement_count(), 0)

    def test_final_settlement_source_dedupe_is_shared_with_budget_events(
        self,
    ) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-settlement-dedupe",
                dedupe_key="reserve-for-settlement-dedupe",
                amounts=BudgetAmounts(input_tokens=3, cost_microusd=3),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        consumed = consume_budget(
            self.database,
            **{
                **self._post_kwargs(
                    idempotency_key="consume-before-final-dedupe",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
                "dedupe_key": "shared-terminal-source",
            },
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            event_hash = connection.execute(
                "SELECT event_dedupe_hash FROM budget_events WHERE budget_event_id=?",
                (consumed.budget_event_id,),
            ).fetchone()[0]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "source dedupe"):
                connection.execute(
                    "INSERT INTO budget_settlements("
                    "settlement_id,settlement_idempotency_key,"
                    "settlement_dedupe_hash,run_id,transition_id,"
                    "spawn_request_id,provider,model,endpoint_binding_id,"
                    "capability_class,cost_registry_id,cost_effective_at,"
                    "cost_registry_hash,cost_confidence,actual_time_seconds,"
                    "actual_input_tokens,actual_output_tokens,actual_cost_microusd,"
                    "actual_retry_units,actual_human_attention_units,"
                    "released_time_seconds,released_input_tokens,"
                    "released_output_tokens,released_cost_microusd,"
                    "released_retry_units,released_human_attention_units,"
                    "usage_confidence,source,created_at,created_at_epoch_ms,"
                    "clock_context_id) VALUES('direct-reused-dedupe-settlement',"
                    "'direct-reused-dedupe-idem',?,'run','transition','spawn',"
                    "'provider','model','endpoint','capability','cost-row',"
                    "'effective','cost-hash','known',0,0,0,0,0,0,0,2,0,2,0,0,"
                    "'known','imported','now',1800000000126,'post-clock')",
                    (event_hash,),
                )
        with self.assertRaisesRegex(BudgetConflict, "budget event"):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
                idempotency_key="final-reuses-consume-source",
                dedupe_key="shared-terminal-source",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )
        settle_budget(
            self.database,
            run_id="run",
            transition_id="transition",
            selection=self.selection,
            actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
            idempotency_key="final-owns-source",
            dedupe_key="final-owned-source",
            source="terminal-usage-import",
            spawn_request_id="spawn",
            clock_context_id="post-clock",
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            settlement_hash = connection.execute(
                "SELECT settlement_dedupe_hash FROM budget_settlements "
                "WHERE settlement_idempotency_key='final-owns-source'"
            ).fetchone()[0]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "source dedupe"):
                connection.execute(
                    "INSERT INTO budget_events("
                    "budget_event_id,event_idempotency_key,event_dedupe_hash,"
                    "event_sequence,run_id,transition_id,spawn_request_id,"
                    "provider,model,endpoint_binding_id,capability_class,"
                    "cost_registry_id,cost_effective_at,cost_registry_hash,"
                    "cost_confidence,event_type,input_tokens,cost_microusd,"
                    "usage_confidence,source,created_at,created_at_epoch_ms"
                    ") VALUES('direct-reused-settlement-dedupe-event',"
                    "'direct-reused-settlement-dedupe-idem',?,99,'run',"
                    "'transition','spawn','provider','model','endpoint',"
                    "'capability','cost-row','effective','cost-hash','known',"
                    "'consume',1,1,'known','imported','now',1800000000130)",
                    (settlement_hash,),
                )
        with self.assertRaisesRegex(BudgetConflict, "final settlement"):
            consume_budget(
                self.database,
                **{
                    **self._post_kwargs(
                        idempotency_key="consume-reuses-final-source",
                        amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                    ),
                    "dedupe_key": "final-owned-source",
                },
            )

    def test_concurrent_final_settlements_create_exactly_one_terminal_proof(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-concurrent-final",
                dedupe_key="reserve-for-concurrent-final",
                amounts=BudgetAmounts(input_tokens=10, cost_microusd=10),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)

        def settle(index: int) -> str:
            try:
                settle_budget(
                    self.database,
                    run_id="run",
                    transition_id="transition",
                    selection=self.selection,
                    actual_usage=BudgetAmounts(input_tokens=5, cost_microusd=5),
                    idempotency_key=f"concurrent-final-{index}",
                    dedupe_key=f"concurrent-final-{index}",
                    source="terminal-usage-import",
                    spawn_request_id="spawn",
                    clock_context_id="post-clock",
                )
                return "settled"
            except BudgetError:
                return "blocked"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = sorted(executor.map(settle, range(2)))
        self.assertEqual(outcomes, ["blocked", "settled"])
        self.assertEqual(self._settlement_count(), 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_events WHERE settlement_id IS NOT NULL"
                ).fetchone(),
                (2,),
            )

    def test_incomplete_direct_settlement_is_blocking_slo_evidence(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-imported-final",
                dedupe_key="reserve-for-imported-final",
                amounts=BudgetAmounts(input_tokens=2, cost_microusd=2),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
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
                "created_at,created_at_epoch_ms,clock_context_id) VALUES("
                "'imported-settlement','imported-idem','imported-dedupe','run',"
                "'transition','spawn','provider','model','endpoint','capability',"
                "'cost-row','effective','cost-hash','known',0,1,0,1,0,0,"
                "0,1,0,1,0,0,'known','imported','now',1800000000126,'post-clock')"
            )
        rows = self._slo_rows("Budget event amount malformed or out of range")
        self.assertIn(("imported-settlement",), rows)
        with self.assertRaisesRegex(
            BudgetError, "Budget event amount malformed or out of range"
        ):
            settle_budget(
                self.database,
                run_id="run",
                transition_id="transition",
                selection=self.selection,
                actual_usage=BudgetAmounts(input_tokens=1, cost_microusd=1),
                idempotency_key="another-final",
                dedupe_key="another-final",
                source="terminal-usage-import",
                spawn_request_id="spawn",
                clock_context_id="post-clock",
            )

    def test_legacy_money_import_promotes_usd_decimal_batch_and_replays_exactly(
        self,
    ) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-legacy-money",
                dedupe_key="reserve-for-legacy-money",
                amounts=BudgetAmounts(cost_microusd=2000),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        source = self._legacy_source(
            [
                self._legacy_row(
                    "row-text",
                    actual_cost_usd="0.001234",
                    idempotency_key="legacy-terminal",
                    dedupe_key="legacy-terminal-source",
                )
            ]
        )

        first = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-batch"
        )
        replay = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-batch"
        )

        self.assertEqual(
            (first.status, first.row_count, first.promoted_count, first.quarantine_count),
            ("promoted", 1, 1, 0),
        )
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT actual_cost_microusd,released_cost_microusd "
                    "FROM budget_settlements WHERE settlement_idempotency_key=?",
                    ("legacy-terminal",),
                ).fetchone(),
                (1234, 766),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_events "
                    "WHERE settlement_id IS NULL AND source='legacy-money-import'"
                ).fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM legacy_money_import_promotions "
                    "WHERE batch_id='legacy-batch'"
                ).fetchone(),
                (1,),
            )

    def test_legacy_money_import_accepts_integral_real_after_type_validation(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE run_budgets SET cost_budget_microusd=2000000 "
                "WHERE run_id='run'"
            )
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-legacy-real",
                dedupe_key="reserve-for-legacy-real",
                amounts=BudgetAmounts(cost_microusd=1_000_000),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        source = self._legacy_source(
            [
                self._legacy_row(
                    "row-real",
                    actual_cost_usd=1.0,
                    idempotency_key="legacy-real-terminal",
                    dedupe_key="legacy-real-terminal-source",
                )
            ],
            name="legacy-real.db",
        )

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-real-batch"
        )

        self.assertEqual(result.status, "promoted")
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT actual_cost_microusd FROM budget_settlements "
                    "WHERE settlement_idempotency_key='legacy-real-terminal'"
                ).fetchone(),
                (1_000_000,),
            )

    def test_legacy_money_import_quarantines_bad_money_without_authoritative_writes(
        self,
    ) -> None:
        before_events = self._event_count()
        bad_rows = [
            self._legacy_row("null", actual_cost_usd=None),
            self._legacy_row("nan", actual_cost_usd=float("nan")),
            self._legacy_row("negative", actual_cost_usd="-0.01"),
            self._legacy_row("signed-zero", actual_cost_usd="-0.00"),
            self._legacy_row("inf", actual_cost_usd=float("inf")),
            self._legacy_row("overflow", actual_cost_usd="1e20"),
            self._legacy_row("huge-exponent", actual_cost_usd="1e999999999"),
            self._legacy_row("over-precision", actual_cost_usd="0." + ("1" * 5000)),
            self._legacy_row(
                "context-round",
                actual_cost_usd="0.0000010000000000000000000000000000000000000001",
            ),
            self._legacy_row("tiny-exponent", actual_cost_usd="1e-1000000000"),
            self._legacy_row("fraction", actual_cost_usd="0.0000001"),
            self._legacy_row("rounding", actual_cost_usd="0.0000015"),
            self._legacy_row("bad-unit", actual_cost_usd="0.01", source_unit="microusd"),
            self._legacy_row("bad-int", actual_cost_usd="0.01", actual_input_tokens="1"),
        ]
        source = self._legacy_source(bad_rows, name="legacy-bad.db")

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-bad-batch"
        )

        self.assertEqual(result.status, "quarantined")
        self.assertEqual(result.row_count, len(bad_rows))
        self.assertEqual(result.promoted_count, 0)
        self.assertEqual(self._event_count(), before_events)
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            reasons = {
                row[0]
                for row in connection.execute(
                    "SELECT reason_code FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-bad-batch'"
                )
            }
            self.assertIn("invalid_money", reasons)
            self.assertIn("non_finite_money", reasons)
            self.assertIn("money_out_of_range", reasons)
            self.assertIn("fractional_microusd", reasons)
            self.assertIn("invalid_source_unit", reasons)
            self.assertIn("invalid_integer", reasons)
            self.assertEqual(
                connection.execute(
                    "SELECT legacy_row_id,reason_code FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-bad-batch' "
                    "AND legacy_row_id IN ('signed-zero','over-precision') "
                    "ORDER BY legacy_row_id"
                ).fetchall(),
                [
                    ("over-precision", "fractional_microusd"),
                    ("signed-zero", "money_out_of_range"),
                ],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "DELETE FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-bad-batch'"
                )

    def test_legacy_money_import_quarantines_duplicate_missing_row_ids(
        self,
    ) -> None:
        before_events = self._event_count()
        duplicate = self._legacy_row(None, actual_cost_usd="0.01")  # type: ignore[arg-type]
        source = self._legacy_source([duplicate, duplicate], name="legacy-duplicate-null.db")

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-duplicate-null-batch"
        )

        self.assertEqual(
            (result.status, result.row_count, result.promoted_count, result.quarantine_count),
            ("quarantined", 2, 0, 2),
        )
        self.assertEqual(self._event_count(), before_events)
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,row_count,quarantine_count,promoted_count "
                    "FROM legacy_money_import_batches WHERE batch_id=?",
                    ("legacy-duplicate-null-batch",),
                ).fetchone(),
                ("quarantined", 2, 2, 0),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT source_row_ordinal,legacy_row_id,source_column,reason_code "
                    "FROM legacy_money_import_quarantine WHERE batch_id=? "
                    "ORDER BY source_row_ordinal",
                    ("legacy-duplicate-null-batch",),
                ).fetchall(),
                [
                    (1, "<missing>", "legacy_row_id", "invalid_text"),
                    (2, "<missing>", "legacy_row_id", "invalid_text"),
                ],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_settlements"
                ).fetchone(),
                (0,),
            )

    def test_legacy_money_import_quarantines_incoming_identity_conflicts(
        self,
    ) -> None:
        source = self._legacy_source(
            [
                self._legacy_row(
                    "incoming-a",
                    actual_cost_usd="0.001000",
                    idempotency_key="incoming-conflict-terminal",
                    dedupe_key="incoming-conflict-source",
                ),
                self._legacy_row(
                    "incoming-b",
                    actual_cost_usd="0.0010",
                    idempotency_key="incoming-conflict-terminal",
                    dedupe_key="incoming-conflict-source",
                ),
            ],
            name="legacy-incoming-conflict.db",
        )

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-incoming-conflict-batch"
        )

        self.assertEqual(
            (result.status, result.row_count, result.promoted_count, result.quarantine_count),
            ("quarantined", 2, 0, 2),
        )
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT legacy_row_id,source_column,reason_code "
                    "FROM legacy_money_import_quarantine WHERE batch_id=? "
                    "ORDER BY source_row_ordinal",
                    ("legacy-incoming-conflict-batch",),
                ).fetchall(),
                [
                    ("incoming-a", "__identity__", "incoming_identity_conflict"),
                    ("incoming-b", "__identity__", "incoming_identity_conflict"),
                ],
            )

    def test_legacy_money_import_read_failure_hash_is_not_empty_replay(self) -> None:
        missing = Path(self.temporary.name) / "missing-legacy.db"

        result = import_legacy_terminal_usage(
            self.database, missing, batch_id="legacy-missing-source-batch"
        )
        empty_source = self._legacy_source([], name="legacy-empty.db")

        self.assertEqual(
            (result.status, result.row_count, result.promoted_count, result.quarantine_count),
            ("quarantined", 1, 0, 1),
        )
        self.assertFalse(missing.exists())
        with self.assertRaises(LegacyMoneyImportConflict):
            import_legacy_terminal_usage(
                self.database, empty_source, batch_id="legacy-missing-source-batch"
            )
        with closing(sqlite3.connect(self.database)) as connection:
            missing_hash = connection.execute(
                "SELECT payload_hash FROM legacy_money_import_batches "
                "WHERE batch_id='legacy-missing-source-batch'"
            ).fetchone()[0]
        empty = import_legacy_terminal_usage(
            self.database, empty_source, batch_id="legacy-empty-source-batch"
        )
        self.assertEqual(
            (empty.status, empty.row_count, empty.promoted_count, empty.quarantine_count),
            ("promoted", 0, 0, 0),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            empty_hash = connection.execute(
                "SELECT payload_hash FROM legacy_money_import_batches "
                "WHERE batch_id='legacy-empty-source-batch'"
            ).fetchone()[0]
        self.assertNotEqual(missing_hash, empty_hash)

    def test_legacy_money_import_requires_real_source_table(self) -> None:
        source = Path(self.temporary.name) / "legacy-view.db"
        raw_table = "legacy_budget_terminal_usage_raw"
        row = self._legacy_row("view-row", actual_cost_usd="0.001")
        with closing(sqlite3.connect(source)) as connection, connection:
            connection.execute(
                legacy_terminal_usage_schema_sql().replace(
                    LEGACY_SOURCE_TABLE, raw_table, 1
                )
            )
            placeholders = ",".join("?" for _ in LEGACY_SOURCE_COLUMNS)
            connection.execute(
                f"INSERT INTO {raw_table}("
                + ",".join(LEGACY_SOURCE_COLUMNS)
                + f") VALUES({placeholders})",
                row,
            )
            connection.execute(
                f"CREATE VIEW {LEGACY_SOURCE_TABLE} AS SELECT "
                + ",".join(LEGACY_SOURCE_COLUMNS)
                + f" FROM {raw_table}"
            )

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-view-batch"
        )

        self.assertEqual(
            (result.status, result.row_count, result.promoted_count, result.quarantine_count),
            ("quarantined", 1, 0, 1),
        )
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT legacy_row_id,source_type,reason_code "
                    "FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-view-batch'"
                ).fetchall(),
                [("__schema__", "view", "invalid_source_schema")],
            )

    def test_legacy_money_import_rejects_virtual_source_table(self) -> None:
        source = Path(self.temporary.name) / "legacy-virtual.db"
        with closing(sqlite3.connect(source)) as connection, connection:
            try:
                connection.execute(
                    f"CREATE VIRTUAL TABLE {LEGACY_SOURCE_TABLE} USING fts5("
                    + ",".join(LEGACY_SOURCE_COLUMNS)
                    + ")"
                )
            except sqlite3.OperationalError as exc:
                if "no such module" in str(exc):
                    self.skipTest(f"SQLite FTS5 module unavailable: {exc}")
                raise
            placeholders = ",".join("?" for _ in LEGACY_SOURCE_COLUMNS)
            connection.execute(
                f"INSERT INTO {LEGACY_SOURCE_TABLE}("
                + ",".join(LEGACY_SOURCE_COLUMNS)
                + f") VALUES({placeholders})",
                self._legacy_row("virtual-row", actual_cost_usd="0.001"),
            )

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-virtual-batch"
        )

        self.assertEqual(
            (result.status, result.row_count, result.promoted_count, result.quarantine_count),
            ("quarantined", 1, 0, 1),
        )
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT legacy_row_id,source_type,reason_code "
                    "FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-virtual-batch'"
                ).fetchall(),
                [("__schema__", "virtual_table", "invalid_source_schema")],
            )

    def test_legacy_money_import_rejects_changed_batch_or_payload_conflict(
        self,
    ) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-legacy-conflict",
                dedupe_key="reserve-for-legacy-conflict",
                amounts=BudgetAmounts(cost_microusd=2000),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        source = self._legacy_source(
            [
                self._legacy_row(
                    "row-conflict",
                    actual_cost_usd="0.001",
                    idempotency_key="legacy-conflict-terminal",
                    dedupe_key="legacy-conflict-source",
                )
            ],
            name="legacy-conflict.db",
        )
        import_legacy_terminal_usage(self.database, source, batch_id="legacy-conflict")
        changed_source = self._legacy_source(
            [
                self._legacy_row(
                    "row-conflict",
                    actual_cost_usd="0.0011",
                    idempotency_key="legacy-conflict-terminal",
                    dedupe_key="legacy-conflict-source",
                )
            ],
            name="legacy-conflict-changed.db",
        )

        with self.assertRaises(LegacyMoneyImportConflict):
            import_legacy_terminal_usage(
                self.database, changed_source, batch_id="legacy-conflict"
            )
        result = import_legacy_terminal_usage(
            self.database,
            changed_source,
            batch_id="legacy-conflict-new-batch",
        )
        self.assertEqual(result.status, "quarantined")
        self.assertEqual(result.row_count, 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT row_count FROM legacy_money_import_batches "
                    "WHERE batch_id='legacy-conflict-new-batch'"
                ).fetchone(),
                (1,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_settlements "
                    "WHERE settlement_idempotency_key='legacy-conflict-terminal'"
                ).fetchone(),
                (1,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT reason_code FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-conflict-new-batch'"
                ).fetchall(),
                [("promotion_failed",)],
            )

    def test_legacy_money_import_rejects_changed_raw_payload_replay(self) -> None:
        reserve = reserve_budget(
            self.database,
            **self._kwargs(
                idempotency_key="reserve-for-legacy-raw-conflict",
                dedupe_key="reserve-for-legacy-raw-conflict",
                amounts=BudgetAmounts(cost_microusd=2000),
            ),
        )
        self._accept_spawn(reserve.budget_event_id, completed=True)
        source = self._legacy_source(
            [
                self._legacy_row(
                    "row-raw-conflict",
                    actual_cost_usd="0.001000",
                    idempotency_key="legacy-raw-conflict-terminal",
                    dedupe_key="legacy-raw-conflict-source",
                )
            ],
            name="legacy-raw-conflict.db",
        )
        first = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-raw-conflict-first"
        )
        changed_source = self._legacy_source(
            [
                self._legacy_row(
                    "row-raw-conflict",
                    actual_cost_usd="0.0010",
                    idempotency_key="legacy-raw-conflict-terminal",
                    dedupe_key="legacy-raw-conflict-source",
                )
            ],
            name="legacy-raw-conflict-changed.db",
        )

        changed = import_legacy_terminal_usage(
            self.database,
            changed_source,
            batch_id="legacy-raw-conflict-changed",
        )

        self.assertEqual(
            (first.status, first.promoted_count, changed.status, changed.row_count),
            ("promoted", 1, "quarantined", 1),
        )
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM budget_settlements "
                    "WHERE settlement_idempotency_key='legacy-raw-conflict-terminal'"
                ).fetchone(),
                (1,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM legacy_money_import_promotions "
                    "WHERE batch_id='legacy-raw-conflict-changed'"
                ).fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT reason_code FROM legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-raw-conflict-changed'"
                ).fetchall(),
                [("promotion_failed",)],
            )

    def test_legacy_money_import_quarantines_malformed_source_schema(self) -> None:
        source = Path(self.temporary.name) / "legacy-malformed.db"
        with closing(sqlite3.connect(source)) as connection, connection:
            connection.execute("CREATE TABLE legacy_budget_terminal_usage_v1 (bad ANY)")

        result = import_legacy_terminal_usage(
            self.database, source, batch_id="legacy-malformed-batch"
        )

        self.assertEqual(result.status, "quarantined")
        self.assertEqual(result.promoted_count, 0)
        self.assertEqual(self._settlement_count(), 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT legacy_row_id,reason_code FROM "
                    "legacy_money_import_quarantine "
                    "WHERE batch_id='legacy-malformed-batch'"
                ).fetchall(),
                [("__schema__", "invalid_source_schema")],
            )

    def test_missing_database_is_not_created(self) -> None:
        missing = Path(self.temporary.name) / "missing.db"
        with self.assertRaises(BudgetError):
            reserve_budget(
                missing,
                **self._kwargs(
                    idempotency_key="missing",
                    dedupe_key="missing",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertFalse(missing.exists())

    def test_runtime_refuses_non_private_database_mode(self) -> None:
        self.database.chmod(0o644)
        self.addCleanup(self.database.chmod, 0o600)
        with self.assertRaisesRegex(BudgetError, "0700 directory and 0600"):
            reserve_budget(
                self.database,
                **self._kwargs(
                    idempotency_key="public-mode",
                    dedupe_key="public-mode",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 0)


if __name__ == "__main__":
    unittest.main()
