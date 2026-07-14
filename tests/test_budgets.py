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

    def test_post_dispatch_budget_mutation_rejects_accepted_before_request(self) -> None:
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
            connection.execute(
                "UPDATE external_rpc_intents SET accepted_at_epoch_ms=1800000000123 "
                "WHERE intent_id='intent'"
            )
        with self.assertRaisesRegex(BudgetError, "sessions_spawn request"):
            consume_budget(
                self.database,
                **self._post_kwargs(
                    idempotency_key="bad-accepted-clock-consume",
                    amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                ),
            )
        self.assertEqual(self._event_count(), 1)

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
