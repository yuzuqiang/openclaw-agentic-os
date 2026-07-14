from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock

from agentic_os.budgets import (
    BudgetAmounts,
    BudgetConflict,
    BudgetError,
    BudgetExceeded,
    BudgetSelection,
    _required_cost,
    release_budget,
    reserve_budget,
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
        with sqlite3.connect(self.database) as connection:
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
        }

    def _budget_row(self) -> tuple[object, ...]:
        with sqlite3.connect(self.database) as connection:
            return connection.execute(
                "SELECT reserved_time_seconds,reserved_input_tokens,"
                "reserved_output_tokens,reserved_cost_microusd,reserved_retries,"
                "reserved_human_attention,consumed_time_seconds,consumed_input_tokens,"
                "consumed_output_tokens,consumed_cost_microusd FROM run_budgets "
                "WHERE run_id='run'"
            ).fetchone()

    def _event_count(self) -> int:
        with sqlite3.connect(self.database) as connection:
            return connection.execute("SELECT COUNT(*) FROM budget_events").fetchone()[0]

    def _slo_rows(self, query_name: str) -> list[tuple[object, ...]]:
        sql = next(
            item.sql_text for item in SLO_QUERY_CONTRACTS if item.query_name == query_name
        )
        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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

    def test_runtime_allocates_monotonic_ordering_time_inside_transaction(self) -> None:
        fixed_ns = 1_800_000_000_123_000_000
        with mock.patch("agentic_os.budgets.time.time_ns", return_value=fixed_ns):
            for index in (1, 2):
                reserve_budget(
                    self.database,
                    **self._kwargs(
                        idempotency_key=f"clock-{index}",
                        dedupe_key=f"clock-{index}",
                        amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
                    ),
                )
        with sqlite3.connect(self.database) as connection:
            epochs = connection.execute(
                "SELECT created_at_epoch_ms FROM budget_events ORDER BY event_sequence"
            ).fetchall()
        self.assertEqual(epochs, [(1_800_000_000_123,), (1_800_000_000_124,)])

    def test_release_cannot_use_another_spawn_reservation(self) -> None:
        with sqlite3.connect(self.database) as connection:
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

    def test_reserve_and_release_require_pending_spawn_state(self) -> None:
        with sqlite3.connect(self.database) as connection:
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

    def test_composite_spawn_binding_antijoin_blocks_legacy_contamination(self) -> None:
        with sqlite3.connect(self.database) as connection:
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

    def test_zero_reserve_requires_exact_policy_and_minima(self) -> None:
        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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

    def test_estimated_event_conservatively_downgrades_usage_confidence(self) -> None:
        kwargs = self._kwargs(
            idempotency_key="estimated",
            dedupe_key="estimated",
            amounts=BudgetAmounts(input_tokens=1, cost_microusd=1),
        )
        kwargs["usage_confidence"] = "estimated"
        reserve_budget(self.database, **kwargs)
        with sqlite3.connect(self.database) as connection:
            confidence = connection.execute(
                "SELECT usage_confidence FROM run_budgets WHERE run_id='run'"
            ).fetchone()[0]
        self.assertEqual(confidence, "estimated")

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
