from __future__ import annotations

import json
import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentic_os import DB_AUTHORITY_ENABLED
from agentic_os.migrations import (
    MigrationError,
    MigrationHashDrift,
    apply_migrations,
    repository_root,
    verify_database,
)


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.db"

    def test_authority_remains_disabled(self) -> None:
        self.assertIs(DB_AUTHORITY_ENABLED, False)

    def test_complete_schema_and_idempotent_apply(self) -> None:
        self.assertEqual(apply_migrations(self.database), (1,))
        self.assertEqual(apply_migrations(self.database), ())
        with sqlite3.connect(self.database) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            self.assertEqual(len(tables), 27)
            row = connection.execute(
                "SELECT version,name,sha256 FROM schema_migrations"
            ).fetchone()
            self.assertEqual(row[0:2], (1, "minimum_contract"))
            self.assertEqual(
                row[2],
                hashlib.sha256(
                    (repository_root() / "migrations/0001_minimum_contract.sql").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_verify_is_read_only_and_creates_no_sidecars(self) -> None:
        apply_migrations(self.database)
        verify_target = Path(self.temporary.name) / "readonly.db"
        # SQLite backup establishes a migrated, checkpointed baseline with no
        # sidecars. verify_database must not change it or create any.
        with sqlite3.connect(self.database) as source, sqlite3.connect(verify_target) as target:
            source.backup(target)
        wal = Path(f"{verify_target}-wal")
        shm = Path(f"{verify_target}-shm")
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        before = hashlib.sha256(verify_target.read_bytes()).hexdigest()
        before_mtime = verify_target.stat().st_mtime_ns
        self.assertEqual(verify_database(verify_target), (1,))
        self.assertEqual(hashlib.sha256(verify_target.read_bytes()).hexdigest(), before)
        self.assertEqual(verify_target.stat().st_mtime_ns, before_mtime)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())

    def test_verify_refuses_sidecar_without_changing_any_file(self) -> None:
        apply_migrations(self.database)
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                verify_target = Path(self.temporary.name) / f"sidecar{suffix}.db"
                with sqlite3.connect(self.database) as source, sqlite3.connect(
                    verify_target
                ) as target:
                    source.backup(target)
                sidecar = Path(f"{verify_target}{suffix}")
                sidecar.write_bytes(b"sidecar-sentinel")
                database_before = (
                    hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                    verify_target.stat().st_mtime_ns,
                )
                sidecar_before = (sidecar.read_bytes(), sidecar.stat().st_mtime_ns)
                with self.assertRaisesRegex(
                    MigrationError, "requires an offline checkpointed snapshot"
                ):
                    verify_database(verify_target)
                self.assertEqual(
                    (
                        hashlib.sha256(verify_target.read_bytes()).hexdigest(),
                        verify_target.stat().st_mtime_ns,
                    ),
                    database_before,
                )
                self.assertEqual(
                    (sidecar.read_bytes(), sidecar.stat().st_mtime_ns), sidecar_before
                )
                for other_suffix in ("-wal", "-shm", "-journal"):
                    other = Path(f"{verify_target}{other_suffix}")
                    self.assertEqual(other.exists(), other_suffix == suffix)

    def test_foreign_keys_are_enforced(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('r','p','missing','file_authority','candidate','R0','R0','t','t')"
            )

    def test_migration_file_hash_drift_is_refused_before_database_creation(self) -> None:
        migration_dir = Path(self.temporary.name) / "migrations"
        shutil.copytree(repository_root() / "migrations", migration_dir)
        migration = migration_dir / "0001_minimum_contract.sql"
        migration.write_text(migration.read_text() + "\n-- drift\n", encoding="utf-8")
        drift_database = Path(self.temporary.name) / "drift.db"
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(drift_database, migration_dir=migration_dir)
        self.assertFalse(drift_database.exists())

    def test_recorded_hash_drift_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE schema_migrations SET sha256=?", ("0" * 64,))
        with self.assertRaises(MigrationHashDrift):
            apply_migrations(self.database)

    def test_forged_migration_ledger_without_schema_is_refused(self) -> None:
        migration = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )["migrations"][0]
        for operation in (verify_database, apply_migrations):
            database = Path(self.temporary.name) / f"forged-{operation.__name__}.db"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE schema_migrations (version ANY PRIMARY KEY,name TEXT NOT NULL,"
                    "sha256 TEXT NOT NULL,applied_at TEXT NOT NULL,"
                    "CHECK(typeof(version)='integer' AND version>0)) STRICT"
                )
                connection.execute(
                    "INSERT INTO schema_migrations VALUES(?,?,?,?)",
                    (migration["version"], migration["name"], migration["sha256"], "now"),
                )
            with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                MigrationHashDrift, "schema differs"
            ):
                operation(database)

    def test_schema_object_definition_drift_is_refused(self) -> None:
        apply_migrations(self.database)
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE workflow_authority ADD COLUMN forged TEXT")
        verify_target = Path(self.temporary.name) / "schema-drift-readonly.db"
        with sqlite3.connect(self.database) as source, sqlite3.connect(verify_target) as target:
            source.backup(target)
        with self.assertRaisesRegex(MigrationHashDrift, "schema differs"):
            verify_database(verify_target)
        with self.assertRaisesRegex(MigrationHashDrift, "schema differs"):
            apply_migrations(self.database)

    def test_database_authority_requires_cutover_evidence(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        for mode in ("db_authority_canary", "db_authority"):
            with self.subTest(mode=mode), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO workflow_authority(workflow,mode,updated_at) VALUES(?,?,?)",
                    (mode, mode, "now"),
                )
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,cutover_approved_by,"
            "cutover_evidence_hash,rollback_deadline,last_parity_audit_hash,updated_at) "
            "VALUES('valid','db_authority','river','evidence','deadline','parity','now')"
        )

    def test_run_authority_mode_must_match_workflow_authority(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,"
                "state,risk_class,risk_dominance,created_at,updated_at) "
                "VALUES('r','prepare','w','db_authority','candidate','R1','R1','now','now')"
            )

    def test_approval_transition_requires_bound_gate_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('r','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        values = (
            "t", "r", "before", "after", "mutate", "write", "file", "id", "hash",
            "scope", 1, "approval", "channel", "source", "text", "R1", "idem", 0, None,
            "now",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,target_type,target_id,target_hash,target_scope,"
                "approval_required,approval_id,approval_channel,approval_source_digest,"
                "approval_text_digest,risk_dominance,idempotency_key,guard_version_before,"
                "gate_run_id,created_at) VALUES(" + ",".join("?" for _ in values) + ")",
                values,
            )

    def test_lease_external_metadata_is_required_and_exact(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        base = (
            "lease", "run", "phase", "transition", "agent", "requester", "acquired",
            "gateway", "client", "idem", 60000, "expires", 2000000000000,
        )
        statement = (
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,requester_agent_id,"
            "state,gateway_lease_id,client_lease_id,acquire_idempotency_key,ttl_ms,expires_at,"
            "expires_at_epoch_ms) VALUES(" + ",".join("?" for _ in base) + ")"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(statement, base)
        metadata = {
            "client_lease_id": "client",
            "idempotency_key": "idem-valid",
            "run_id": "run",
            "phase": "phase",
            "transition_id": "transition",
            "agent_id": "agent",
            "requester_agent_id": "requester",
            "ttl_ms": 60000,
        }
        valid = (
            "lease-valid", "run", "phase", "transition", "agent", "requester",
            "acquired", "gateway", "client-valid", "idem-valid", 60000, "v1", "now",
            json.dumps({**metadata, "client_lease_id": "client-valid"}), "client-valid",
            "idem-valid", "run", "phase", "transition", "agent", "requester", 60000,
            "expires", 2000000000000,
        )
        connection.execute(
            "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
            "requester_agent_id,state,gateway_lease_id,client_lease_id,"
            "acquire_idempotency_key,ttl_ms,metadata_contract_version,"
            "metadata_observed_at,external_metadata_json,external_client_lease_id,"
            "external_idempotency_key,external_run_id,external_phase,"
            "external_transition_id,external_agent_id,external_requester_agent_id,"
            "external_ttl_ms,expires_at,expires_at_epoch_ms) VALUES("
            + ",".join("?" for _ in valid) + ")",
            valid,
        )

    def test_sqlite_boundary_rejects_duplicate_raw_metadata_keys(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        duplicate = '{"run_id":"expected","run_id":"other"}'
        with self.assertRaisesRegex(sqlite3.IntegrityError, "duplicate external metadata"):
            connection.execute(
                "INSERT INTO external_rpc_intents(intent_id,run_id,transition_id,rpc_kind,"
                "client_request_id,idempotency_key,metadata_json,external_metadata_json,state,"
                "requested_at,requested_at_epoch_ms) VALUES("
                "'intent','run','transition','allow_lease_acquire','client','idem','{}',?,"
                "'pending','now',1)",
                (duplicate,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "duplicate external metadata"):
            connection.execute(
                "INSERT INTO leases(lease_id,run_id,phase,transition_id,agent_id,"
                "requester_agent_id,state,client_lease_id,acquire_idempotency_key,ttl_ms,"
                "external_metadata_json,expires_at,expires_at_epoch_ms) VALUES("
                "'lease','run','phase','transition','agent','requester','acquire_pending',"
                "'client-lease','lease-idem',60000,?,'expires',2000000000000)",
                (duplicate,),
            )

    def test_session_key_must_match_accepted_spawn_request(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) "
            "VALUES('r','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'t','r','before','after','dispatch','spawn','R1','transition-idem',0,'now')"
        )
        connection.execute(
            "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,transition_id,"
            "client_request_id,spawn_idempotency_key,task_digest,state,session_key,created_at,"
            "updated_at) VALUES('spawn','r','phase','agent','t','client','spawn-idem','task',"
            "'accepted','accepted-session','now','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO sessions(session_id,spawn_request_id,run_id,transition_id,phase,"
                "agent_id,client_request_id,spawn_idempotency_key,session_key,task_digest,state) "
                "VALUES('session','spawn','r','t','phase','agent','client','spawn-idem',"
                "'wrong-session','task','running')"
            )

    def test_spawn_request_transition_must_belong_to_same_run(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','dispatch','spawn','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO spawn_requests(spawn_request_id,run_id,phase,agent_id,"
                "transition_id,client_request_id,spawn_idempotency_key,task_digest,state,"
                "created_at,updated_at) VALUES("
                "'spawn','run-a','phase','agent','transition-run-b','client','spawn-idem',"
                "'task','pending','now','now')"
            )

    def test_pass_gate_requires_same_run_transition_and_verifier_evidence(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        for run_id in ("run-a", "run-b"):
            connection.execute(
                "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
                "risk_class,risk_dominance,created_at,updated_at) VALUES(?,?,"
                "'w','file_authority','candidate','R1','R1','now','now')",
                (run_id, f"prepare-{run_id}"),
            )
            connection.execute(
                "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
                "transition_type,action_type,risk_dominance,idempotency_key,"
                "guard_version_before,created_at) VALUES(?,?,"
                "'before','after','gate','check','R1',?,0,'now')",
                (f"transition-{run_id}", run_id, f"transition-idem-{run_id}"),
            )
        connection.execute(
            "INSERT INTO judge_verifier_runs(verifier_run_id,worker_run_id,worker_agent_id,"
            "verifier_agent_id,provider,model,prompt_hash,context_hash,evidence_hash,"
            "independence_class,independence_proof_json,completed_at) VALUES("
            "'verifier-b','run-b','worker','verifier','provider','model','prompt','context',"
            "'evidence-b','independent','{}','now')"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "verifier_run_id,decision,completed_at,completed_at_epoch_ms,gate_version,"
                "gate_query_hash,migration_sha256,evidence_hash,risk_dominance,created_at) "
                "VALUES('gate-verifier','run-a','transition-run-a','clock-verifier',"
                "'verifier-b','pass','now',1000,'v1','query','migration','evidence-b','R1','now')"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO gate_runs(gate_run_id,run_id,transition_id,clock_context_id,"
                "decision,completed_at,completed_at_epoch_ms,gate_version,gate_query_hash,"
                "migration_sha256,risk_dominance,created_at) VALUES("
                "'gate-transition','run-a','transition-run-b','clock-transition','fail','now',"
                "1000,'v1','query','migration','R1','now')"
            )

    def test_predicate_backend_is_allowlisted(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
                "schema_hash,sandbox_required,sandbox_enforced,created_at) "
                "VALUES('plugin','unsafe','1','shell','schema',0,0,'now')"
            )
        connection.execute(
            "INSERT INTO predicate_plugins(predicate_plugin_hash,name,version,backend,"
            "schema_hash,sandbox_required,sandbox_enforced,created_at) VALUES("
            "'safe-plugin','safe','1','agentic_predicate_inproc_v1','schema',0,1,'now')"
        )

    def test_zero_reserve_policy_minima_are_enforced_at_sqlite_boundary(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO endpoint_zero_reserve_policies(zero_reserve_policy_id,"
            "endpoint_binding_id,capability_class,policy_hash,min_retry_units,"
            "effective_from_epoch_ms,effective_until_epoch_ms) "
            "VALUES('policy','endpoint','capability','policy-hash',1,1,2000)"
        )

        def insert_event(
            identifier: str, retry_units: int, sequence: int, created_at_epoch_ms: int = 1000
        ) -> None:
            connection.execute(
                "INSERT INTO budget_events(budget_event_id,event_idempotency_key,"
                "event_dedupe_hash,event_sequence,run_id,transition_id,provider,model,"
                "endpoint_binding_id,capability_class,cost_registry_id,cost_effective_at,"
                "cost_registry_hash,cost_confidence,zero_reserve_policy_id,"
                "zero_reserve_policy_hash,event_type,retry_units,usage_confidence,source,"
                "created_at,created_at_epoch_ms) VALUES(?,?,?,?,"
                "'run','transition','provider','model','endpoint','capability','cost-row',"
                "'effective','cost-hash','known','policy','policy-hash','reserve',?,'known',"
                "'test','now',?)",
                (
                    identifier,
                    f"idem-{identifier}",
                    f"dedupe-{identifier}",
                    sequence,
                    retry_units,
                    created_at_epoch_ms,
                ),
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "minima not met"):
            insert_event("bad", 0, 1)
        insert_event("good", 1, 2)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "mismatch"):
            insert_event("expired-boundary", 1, 3, 2000)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "mismatch"):
            connection.execute(
                "UPDATE budget_events SET created_at_epoch_ms=2000 "
                "WHERE budget_event_id='good'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE endpoint_zero_reserve_policies SET min_retry_units=2 "
                "WHERE zero_reserve_policy_id='policy'"
            )

    def test_readme_migration_example_uses_private_test_database(self) -> None:
        readme = (repository_root() / "README.md").read_text(encoding="utf-8")
        self.assertIn("agentic_os.cli migrate --test-db", readme)
        self.assertNotIn("agentic_os.cli migrate --db /tmp", readme)

    def test_slo_audit_must_match_current_query_identity(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        status_query = (
            "WITH blocking(query_name) AS ("
            "SELECT q.query_name FROM slo_queries q LEFT JOIN slo_audits a "
            "ON a.query_name=q.query_name AND a.schema_version=q.schema_version "
            "AND a.migration_sha256=q.migration_sha256 AND a.query_hash=q.query_hash "
            "WHERE a.slo_audit_id IS NULL OR a.status<>'pass' "
            "UNION ALL SELECT '__slo_registry_count__' "
            "WHERE (SELECT COUNT(*) FROM slo_queries)<>30) "
            "SELECT query_name FROM blocking"
        )
        self.assertEqual(
            connection.execute(status_query).fetchall(),
            [("__slo_registry_count__",)],
        )
        migration_hash = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )["migrations"][0]["sha256"]
        query_hash = "c" * 64
        connection.execute(
            "INSERT INTO slo_queries VALUES('q',1,?,?,'SELECT 1','pass','pass','now')",
            (migration_hash, query_hash),
        )
        blocking = connection.execute(status_query).fetchall()
        self.assertEqual(blocking, [("q",), ("__slo_registry_count__",)])
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO slo_audits VALUES('a','q',1,?,?,0,'pass','pass','pass',?,"
                "'now')",
                (migration_hash, "d" * 64, "e" * 64),
            )
        connection.execute(
            "INSERT INTO slo_audits VALUES('a-valid','q',1,?,?,0,'pass','pass','pass',?,"
            "'now')",
            (migration_hash, query_hash, "e" * 64),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE slo_queries SET sql_text='SELECT 2' WHERE query_name='q'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE slo_queries SET query_hash=? WHERE query_name='q'",
                ("f" * 64,),
            )

    def test_type_preserving_money_bounds(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        base = ("p", "m", "e", "c", "known", "2026-01-01", "h")

        def insert(identifier: str, input_price: object, output_price: object) -> None:
            connection.execute(
                "INSERT INTO model_cost_registry("
                "cost_registry_id,provider,model,endpoint_binding_id,capability_class,"
                "input_cost_microusd_per_million,output_cost_microusd_per_million,"
                "confidence,effective_at,registry_row_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (identifier, *base[:4], input_price, output_price, *base[4:6], identifier),
            )

        insert("max", 100_000_000_000, 100_000_000_000)
        for identifier, value in (
            ("max-plus-one", 100_000_000_001),
            ("numeric-text", "1500"),
            ("integral-real", 1500.0),
            ("negative", -1),
        ):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError):
                insert(identifier, value, 0)

    def test_referenced_model_cost_registry_is_immutable(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO workflow_authority(workflow,mode,updated_at) "
            "VALUES('w','file_authority','now')"
        )
        connection.execute(
            "INSERT INTO runs(run_id,prepare_idempotency_key,workflow,authority_mode,state,"
            "risk_class,risk_dominance,created_at,updated_at) VALUES("
            "'run','prepare','w','file_authority','candidate','R1','R1','now','now')"
        )
        connection.execute(
            "INSERT INTO transitions(transition_id,run_id,state_before,state_after,"
            "transition_type,action_type,risk_dominance,idempotency_key,"
            "guard_version_before,created_at) VALUES("
            "'transition','run','before','after','dispatch','spawn','R1','transition-idem',"
            "0,'now')"
        )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row','provider','model','endpoint','capability',1,1,'known',"
            "'effective','cost-hash')"
        )
        connection.execute(
            "INSERT INTO run_budgets(run_id,workflow,capability_class,selected_provider,"
            "selected_model,selected_endpoint_binding_id,selected_cost_registry_id,"
            "selected_cost_effective_at,selected_cost_registry_hash,selected_cost_confidence,"
            "selected_reserve_transition_id,time_budget_seconds,input_token_budget,"
            "output_token_budget,cost_budget_microusd,retry_budget,human_attention_budget,"
            "usage_confidence,updated_at) VALUES("
            "'run','w','capability','provider','model','endpoint','cost-row','effective',"
            "'cost-hash','known','transition',10,10,10,10,1,1,'known','now')"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE model_cost_registry SET input_cost_microusd_per_million=2 "
                "WHERE cost_registry_id='cost-row'"
            )
        connection.execute(
            "INSERT INTO model_cost_registry(cost_registry_id,provider,model,"
            "endpoint_binding_id,capability_class,input_cost_microusd_per_million,"
            "output_cost_microusd_per_million,confidence,effective_at,registry_row_hash) "
            "VALUES('cost-row-event','provider','model','endpoint','capability',1,1,'known',"
            "'effective-2','cost-hash-event')"
        )
        connection.execute(
            "INSERT INTO budget_events(budget_event_id,event_idempotency_key,event_dedupe_hash,"
            "event_sequence,run_id,transition_id,provider,model,endpoint_binding_id,"
            "capability_class,cost_registry_id,cost_effective_at,cost_registry_hash,"
            "cost_confidence,event_type,input_tokens,usage_confidence,source,created_at,"
            "created_at_epoch_ms) VALUES('event','event-idem','event-dedupe',1,'run',"
            "'transition','provider','model','endpoint','capability','cost-row-event',"
            "'effective-2','cost-hash-event','known','consume',1,'known','test','now',1000)"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE model_cost_registry SET output_cost_microusd_per_million=2 "
                "WHERE cost_registry_id='cost-row-event'"
            )

    def test_manifest_is_machine_readable_and_has_one_pinned_migration(self) -> None:
        manifest = json.loads(
            (repository_root() / "migrations/manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["migrations"]), 1)
        self.assertEqual(manifest["migrations"][0]["version"], 1)

    def test_migration_is_exact_accepted_ddl_block(self) -> None:
        design = (repository_root() / "docs/agentic-os-production-adaptation.md").read_text(
            encoding="utf-8"
        )
        contract = design.split("## Minimum Database Contracts", 1)[1]
        ddl = contract.split("```sql\n", 1)[1].split("\n```", 1)[0] + "\n"
        migration = (repository_root() / "migrations/0001_minimum_contract.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(migration, ddl)

    def test_schema_migration_version_preserves_numeric_type(self) -> None:
        apply_migrations(self.database)
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        for version in ("2", 2.0):
            with self.subTest(version=version), self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,sha256,applied_at) "
                    "VALUES(?,?,?,?)",
                    (version, "bad", "0" * 64, "now"),
                )


if __name__ == "__main__":
    unittest.main()
