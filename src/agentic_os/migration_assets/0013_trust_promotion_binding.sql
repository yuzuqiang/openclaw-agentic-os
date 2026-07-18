CREATE TEMP TABLE trust_promotion_legacy_guard (
  violation INTEGER NOT NULL
    CONSTRAINT trust_promotion_legacy_active_unbound CHECK (violation=0)
);

INSERT INTO trust_promotion_legacy_guard(violation)
SELECT 1
FROM trust_observations
WHERE invalidated_at IS NULL;

DROP TABLE trust_promotion_legacy_guard;

ALTER TABLE trust_observations ADD COLUMN run_id TEXT REFERENCES runs(run_id);
ALTER TABLE trust_observations ADD COLUMN goal_run_id TEXT REFERENCES goal_runs(goal_run_id);
ALTER TABLE trust_observations ADD COLUMN evidence_hash TEXT;
ALTER TABLE trust_observations ADD COLUMN evidence_run_id TEXT REFERENCES runs(run_id);
ALTER TABLE trust_observations ADD COLUMN transition_id TEXT REFERENCES transitions(transition_id);
ALTER TABLE trust_observations ADD COLUMN approval_id TEXT REFERENCES approvals(approval_id);
ALTER TABLE trust_observations ADD COLUMN approval_hash TEXT;
ALTER TABLE trust_observations ADD COLUMN schema_version ANY;
ALTER TABLE trust_observations ADD COLUMN migration_sha256 TEXT;
ALTER TABLE trust_observations ADD COLUMN blocking_slo_query_count ANY;
ALTER TABLE trust_observations ADD COLUMN blocking_slo_pass_audit_count ANY;
ALTER TABLE trust_observations ADD COLUMN blocking_slo_bundle_hash TEXT;
ALTER TABLE trust_observations ADD COLUMN clock_context_id TEXT REFERENCES gate_clock_context(clock_context_id);
ALTER TABLE trust_observations ADD COLUMN gate_clock_epoch_ms ANY;
ALTER TABLE trust_observations ADD COLUMN trusted_clock_source_hash TEXT;
ALTER TABLE trust_observations ADD COLUMN run_authority_mode TEXT;
ALTER TABLE trust_observations ADD COLUMN workflow_authority_mode TEXT;
ALTER TABLE trust_observations ADD COLUMN selected_cost_registry_id TEXT REFERENCES model_cost_registry(cost_registry_id);
ALTER TABLE trust_observations ADD COLUMN selected_cost_registry_hash TEXT;
ALTER TABLE trust_observations ADD COLUMN cost_confidence TEXT;

CREATE UNIQUE INDEX trust_observations_run_goal_idx
ON trust_observations(run_id,goal_run_id,evidence_hash)
WHERE invalidated_at IS NULL;

CREATE VIEW trust_promotion_bound_evidence AS
SELECT
  r.run_id,
  gr.goal_run_id,
  e.evidence_hash,
  e.run_id AS evidence_run_id,
  e.path AS evidence_path,
  e.sha256 AS evidence_sha256,
  e.size_bytes AS evidence_size_bytes,
  e.content_type AS evidence_content_type,
  e.redaction_status AS evidence_redaction_status,
  e.captured_at AS evidence_captured_at,
  e.verifier_run_id,
  e.gate_run_id,
  g.transition_id,
  r.workflow AS promoted_scope,
  gr.severity AS promoted_severity,
  t.approval_id,
  a.approval_hash,
  g.clock_context_id,
  c.now_epoch_ms AS gate_clock_epoch_ms,
  c.trusted_clock_source_hash,
  m.version AS schema_version,
  m.sha256 AS migration_sha256,
  g.run_authority_mode,
  g.workflow_authority_mode,
  rb.selected_cost_registry_id,
  rb.selected_cost_registry_hash,
  rb.selected_cost_confidence,
  rb.usage_confidence,
  mc.confidence AS cost_confidence,
  (SELECT COUNT(*) FROM slo_queries current_q
   WHERE current_q.schema_version=m.version
     AND current_q.migration_sha256=m.sha256) AS current_slo_query_count
FROM goal_runs gr
JOIN evidence_hashes e
  ON e.evidence_hash=gr.evidence_hash
 AND e.sha256=e.evidence_hash
 AND e.run_id=gr.run_id
 AND e.producer_run_id=gr.run_id
JOIN judge_verifier_runs j
  ON j.verifier_run_id=e.verifier_run_id
 AND j.worker_run_id=e.run_id
 AND j.evidence_hash=e.evidence_hash
JOIN gate_runs g
  ON g.gate_run_id=e.gate_run_id
 AND g.evidence_hash=e.evidence_hash
 AND g.run_id=e.run_id
 AND g.verifier_run_id=e.verifier_run_id
JOIN runs r
  ON r.run_id=g.run_id
JOIN workflow_authority w
  ON w.workflow=r.workflow
JOIN transitions t
  ON t.transition_id=g.transition_id
 AND t.run_id=g.run_id
 AND t.gate_run_id=g.gate_run_id
 AND t.evidence_hash=g.evidence_hash
JOIN gate_clock_context c
  ON c.clock_context_id=g.clock_context_id
 AND c.gate_run_id=g.gate_run_id
 AND c.consumed_by_gate_run_id=g.gate_run_id
 AND c.run_id=g.run_id
 AND c.transition_id=t.transition_id
JOIN approvals a
  ON a.approval_id=t.approval_id
 AND a.run_id=t.run_id
 AND a.approved_action_type=t.action_type
 AND a.target_type=t.target_type
 AND a.target_id=t.target_id
 AND a.target_hash=t.target_hash
 AND a.target_scope=t.target_scope
 AND a.channel=t.approval_channel
 AND a.source_message_digest=t.approval_source_digest
 AND a.approval_text_digest=t.approval_text_digest
 AND a.consumed_by_transition_id=t.transition_id
 AND a.consumed_by_gate_run_id=g.gate_run_id
JOIN schema_migrations m
  ON m.sha256=g.migration_sha256
JOIN slo_queries q
  ON q.schema_version=m.version
 AND q.migration_sha256=m.sha256
 AND q.query_name='Completion gate before done for R2+'
 AND q.query_hash=g.gate_query_hash
JOIN run_budgets rb
  ON rb.run_id=r.run_id
JOIN model_cost_registry mc
  ON mc.cost_registry_id=rb.selected_cost_registry_id
WHERE gr.run_id IS NOT NULL
  AND gr.run_id=r.run_id
  AND length(e.evidence_hash)=64
  AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
  AND e.path<>''
  AND e.content_type<>''
  AND e.redaction_status<>''
  AND e.captured_at<>''
  AND r.authority_mode='file_authority'
  AND w.mode='file_authority'
  AND g.run_authority_mode='file_authority'
  AND g.workflow_authority_mode='file_authority'
  AND g.run_authority_mode=r.authority_mode
  AND g.workflow_authority_mode=w.mode
  AND g.decision='pass'
  AND g.requires_same_run=1
  AND m.version=(SELECT MAX(version) FROM schema_migrations)
  AND g.completed_at_epoch_ms=c.now_epoch_ms
  AND c.bound_at_epoch_ms=c.now_epoch_ms
  AND c.consumed_at_epoch_ms=c.now_epoch_ms
  AND c.trusted_clock_source_hash=agentic_trusted_clock_source_hash(c.now_epoch_ms,c.bound_by)
  AND t.approval_required=1
  AND j.independence_class='independent'
  AND j.verifier_run_id<>j.worker_run_id
  AND j.verifier_run_id<>e.run_id
  AND j.worker_agent_id<>j.verifier_agent_id
  AND j.same_worker_context=0
  AND a.single_use=1
  AND length(a.source_message_digest)=64
  AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
  AND length(a.approval_text_digest)=64
  AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
  AND length(a.approval_hash)=64
  AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
  AND a.approver<>''
  AND a.channel<>''
  AND a.approved_at<>''
  AND a.expires_at_epoch_ms > c.now_epoch_ms
  AND CASE a.approved_risk_ceiling
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END >= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END
  AND rb.selected_provider=mc.provider
  AND rb.selected_model=mc.model
  AND rb.selected_endpoint_binding_id=mc.endpoint_binding_id
  AND rb.capability_class=mc.capability_class
  AND rb.selected_cost_effective_at=mc.effective_at
  AND rb.selected_cost_registry_hash=mc.registry_row_hash
  AND rb.selected_cost_confidence='known'
  AND rb.selected_cost_confidence=mc.confidence
  AND rb.usage_confidence='known'
  AND mc.confidence='known'
  AND NOT EXISTS (
    SELECT 1 FROM budget_events be
    WHERE be.run_id=r.run_id
      AND (
        be.usage_confidence<>'known'
        OR (
          be.event_type<>'human_attention'
          AND (be.cost_confidence IS NULL OR be.cost_confidence<>'known')
        )
      )
  )
  AND NOT EXISTS (
    SELECT 1 FROM budget_settlements bs
    WHERE bs.run_id=r.run_id
      AND (bs.usage_confidence<>'known' OR bs.cost_confidence<>'known')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM slo_queries current_q
    WHERE current_q.schema_version=m.version
      AND current_q.migration_sha256=m.sha256
      AND NOT EXISTS (
        SELECT 1
        FROM slo_audits sa
        WHERE sa.query_name=current_q.query_name
          AND sa.schema_version=current_q.schema_version
          AND sa.migration_sha256=current_q.migration_sha256
          AND sa.query_hash=current_q.query_hash
          AND sa.result_count=0
          AND sa.status='pass'
          AND sa.empty_db_status='pass'
          AND sa.fixture_db_status='pass'
          AND sa.evidence_hash=e.evidence_hash
          AND sa.evidence_run_id=e.run_id
          AND sa.verifier_run_id=e.verifier_run_id
          AND sa.gate_run_id=e.gate_run_id
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(be.created_at_epoch_ms)
            FROM budget_events be
            WHERE be.run_id=r.run_id
          ),0)
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(bs.created_at_epoch_ms)
            FROM budget_settlements bs
            WHERE bs.run_id=r.run_id
          ),0)
          AND sa.slo_audit_id=(
            SELECT latest.slo_audit_id
            FROM slo_audits latest
            WHERE latest.query_name=current_q.query_name
              AND latest.schema_version=current_q.schema_version
              AND latest.migration_sha256=current_q.migration_sha256
              AND latest.query_hash=current_q.query_hash
            ORDER BY latest.run_at_epoch_ms DESC, latest.slo_audit_id DESC
            LIMIT 1
          )
      )
  );

CREATE TRIGGER trust_observations_validate_bound_insert
BEFORE INSERT ON trust_observations
WHEN NEW.invalidated_at IS NULL AND NOT EXISTS (
  SELECT 1
  FROM trust_promotion_bound_evidence b
  WHERE b.run_id=NEW.run_id
    AND b.goal_run_id=NEW.goal_run_id
    AND b.evidence_hash=NEW.evidence_hash
    AND b.evidence_run_id=NEW.evidence_run_id
    AND b.verifier_run_id=NEW.verifier_run_id
    AND b.gate_run_id=NEW.gate_run_id
    AND b.transition_id=NEW.transition_id
    AND b.promoted_scope=NEW.scope
    AND b.promoted_severity=NEW.severity
    AND b.approval_id=NEW.approval_id
    AND b.approval_hash=NEW.approval_hash
    AND b.clock_context_id=NEW.clock_context_id
    AND b.gate_clock_epoch_ms=NEW.gate_clock_epoch_ms
    AND b.trusted_clock_source_hash=NEW.trusted_clock_source_hash
    AND b.schema_version=NEW.schema_version
    AND b.migration_sha256=NEW.migration_sha256
    AND b.run_authority_mode=NEW.run_authority_mode
    AND b.workflow_authority_mode=NEW.workflow_authority_mode
    AND b.selected_cost_registry_id=NEW.selected_cost_registry_id
    AND b.selected_cost_registry_hash=NEW.selected_cost_registry_hash
    AND b.selected_cost_confidence=NEW.cost_confidence
    AND b.cost_confidence=NEW.cost_confidence
    AND b.usage_confidence=NEW.usage_confidence
    AND b.current_slo_query_count=NEW.blocking_slo_query_count
    AND b.current_slo_query_count=NEW.blocking_slo_pass_audit_count
    AND agentic_evidence_snapshot_current(
      b.evidence_path,
      b.evidence_sha256,
      b.evidence_size_bytes,
      b.evidence_content_type,
      b.evidence_redaction_status,
      b.evidence_captured_at
    )=1
    AND NEW.scope<>''
    AND NEW.severity<>''
    AND NEW.status='promoted'
    AND NEW.effective_group_id<>''
    AND NEW.usage_confidence='known'
    AND NEW.cost_confidence='known'
    AND NEW.bounded_at IS NOT NULL
    AND NEW.bounded_at<>''
    AND typeof(NEW.schema_version)='integer'
    AND NEW.schema_version>0
    AND typeof(NEW.blocking_slo_query_count)='integer'
    AND NEW.blocking_slo_query_count>0
    AND typeof(NEW.blocking_slo_pass_audit_count)='integer'
    AND NEW.blocking_slo_pass_audit_count=NEW.blocking_slo_query_count
    AND typeof(NEW.gate_clock_epoch_ms)='integer'
    AND NEW.gate_clock_epoch_ms BETWEEN 1 AND 253402300799999
    AND length(NEW.migration_sha256)=64
    AND NEW.migration_sha256 NOT GLOB '*[^0-9a-f]*'
    AND length(NEW.evidence_hash)=64
    AND NEW.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND length(NEW.approval_hash)=64
    AND NEW.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND length(NEW.trusted_clock_source_hash)=64
    AND NEW.trusted_clock_source_hash NOT GLOB '*[^0-9a-f]*'
    AND length(NEW.blocking_slo_bundle_hash)=64
    AND NEW.blocking_slo_bundle_hash NOT GLOB '*[^0-9a-f]*'
    AND NEW.blocking_slo_bundle_hash=agentic_trust_binding_hash(
      NEW.run_id,
      NEW.goal_run_id,
      NEW.evidence_hash,
      NEW.verifier_run_id,
      NEW.gate_run_id,
      NEW.schema_version,
      NEW.migration_sha256,
      NEW.blocking_slo_query_count
    )
    AND NEW.effective_group_id=NEW.blocking_slo_bundle_hash
)
BEGIN
  SELECT RAISE(ABORT,'trust promotion requires complete bound evidence');
END;

CREATE TRIGGER trust_observations_validate_bound_update
BEFORE UPDATE ON trust_observations
WHEN OLD.invalidated_at IS NULL
  AND NOT (
    NEW.invalidated_at IS NOT NULL
    AND NEW.invalidated_at<>''
    AND NEW.observation_id IS OLD.observation_id
    AND NEW.scope IS OLD.scope
    AND NEW.severity IS OLD.severity
    AND NEW.status IS OLD.status
    AND NEW.effective_group_id IS OLD.effective_group_id
    AND NEW.verifier_run_id IS OLD.verifier_run_id
    AND NEW.gate_run_id IS OLD.gate_run_id
    AND NEW.usage_confidence IS OLD.usage_confidence
    AND NEW.bounded_at IS OLD.bounded_at
    AND NEW.created_at IS OLD.created_at
    AND NEW.run_id IS OLD.run_id
    AND NEW.goal_run_id IS OLD.goal_run_id
    AND NEW.evidence_hash IS OLD.evidence_hash
    AND NEW.evidence_run_id IS OLD.evidence_run_id
    AND NEW.transition_id IS OLD.transition_id
    AND NEW.approval_id IS OLD.approval_id
    AND NEW.approval_hash IS OLD.approval_hash
    AND NEW.schema_version IS OLD.schema_version
    AND NEW.migration_sha256 IS OLD.migration_sha256
    AND NEW.blocking_slo_query_count IS OLD.blocking_slo_query_count
    AND NEW.blocking_slo_pass_audit_count IS OLD.blocking_slo_pass_audit_count
    AND NEW.blocking_slo_bundle_hash IS OLD.blocking_slo_bundle_hash
    AND NEW.clock_context_id IS OLD.clock_context_id
    AND NEW.gate_clock_epoch_ms IS OLD.gate_clock_epoch_ms
    AND NEW.trusted_clock_source_hash IS OLD.trusted_clock_source_hash
    AND NEW.run_authority_mode IS OLD.run_authority_mode
    AND NEW.workflow_authority_mode IS OLD.workflow_authority_mode
    AND NEW.selected_cost_registry_id IS OLD.selected_cost_registry_id
    AND NEW.selected_cost_registry_hash IS OLD.selected_cost_registry_hash
    AND NEW.cost_confidence IS OLD.cost_confidence
  )
BEGIN
  SELECT RAISE(ABORT,'active trust observation is immutable');
END;

CREATE TRIGGER budget_events_preserve_active_trust_insert
BEFORE INSERT ON budget_events
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.run_id=NEW.run_id
    AND trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER budget_events_preserve_active_trust_update
BEFORE UPDATE ON budget_events
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (trust.run_id=OLD.run_id OR trust.run_id=NEW.run_id)
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER budget_events_preserve_active_trust_delete
BEFORE DELETE ON budget_events
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.run_id=OLD.run_id
    AND trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER run_budgets_preserve_active_trust_update
BEFORE UPDATE ON run_budgets
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (trust.run_id=OLD.run_id OR trust.run_id=NEW.run_id)
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before selected budget changes');
END;

CREATE TRIGGER run_budgets_preserve_active_trust_delete
BEFORE DELETE ON run_budgets
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.run_id=OLD.run_id
    AND trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before selected budget changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_insert
BEFORE INSERT ON budget_settlements
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.run_id=NEW.run_id
    AND trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_update
BEFORE UPDATE ON budget_settlements
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (trust.run_id=OLD.run_id OR trust.run_id=NEW.run_id)
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_delete
BEFORE DELETE ON budget_settlements
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.run_id=OLD.run_id
    AND trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER slo_audits_preserve_active_trust_insert
BEFORE INSERT ON slo_audits
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND trust.schema_version=NEW.schema_version
    AND trust.migration_sha256=NEW.migration_sha256
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO audit changes');
END;

CREATE TRIGGER slo_audits_preserve_active_trust_update
BEFORE UPDATE ON slo_audits
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (
      (trust.schema_version=OLD.schema_version
       AND trust.migration_sha256=OLD.migration_sha256)
      OR
      (trust.schema_version=NEW.schema_version
       AND trust.migration_sha256=NEW.migration_sha256)
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO audit changes');
END;

CREATE TRIGGER slo_audits_preserve_active_trust_delete
BEFORE DELETE ON slo_audits
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND trust.schema_version=OLD.schema_version
    AND trust.migration_sha256=OLD.migration_sha256
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO audit changes');
END;

CREATE TRIGGER schema_migrations_preserve_active_trust_insert
BEFORE INSERT ON schema_migrations
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before schema changes');
END;

CREATE TRIGGER schema_migrations_preserve_active_trust_update
BEFORE UPDATE ON schema_migrations
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before schema changes');
END;

CREATE TRIGGER schema_migrations_preserve_active_trust_delete
BEFORE DELETE ON schema_migrations
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before schema changes');
END;

CREATE TRIGGER slo_queries_preserve_active_trust_insert
BEFORE INSERT ON slo_queries
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO registry changes');
END;

CREATE TRIGGER slo_queries_preserve_active_trust_update
BEFORE UPDATE ON slo_queries
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO registry changes');
END;

CREATE TRIGGER slo_queries_preserve_active_trust_delete
BEFORE DELETE ON slo_queries
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before SLO registry changes');
END;

CREATE TRIGGER trust_observations_validate_bound_reactivate_update
BEFORE UPDATE ON trust_observations
WHEN OLD.invalidated_at IS NOT NULL AND NEW.invalidated_at IS NULL
BEGIN
  SELECT RAISE(ABORT,'trust observations cannot be reactivated');
END;

CREATE TRIGGER trust_observations_validate_bound_delete
BEFORE DELETE ON trust_observations
WHEN OLD.invalidated_at IS NULL
BEGIN
  SELECT RAISE(ABORT,'active trust observation is immutable');
END;

SELECT 'trust_promotion_binding';
