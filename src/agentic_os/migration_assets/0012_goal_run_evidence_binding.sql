CREATE TEMP TABLE gate_authority_snapshot_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT gate_authority_snapshot_invalid CHECK (violation=0)
);

INSERT INTO gate_authority_snapshot_migration_guard(violation)
SELECT 1
FROM gate_runs g
JOIN runs r ON r.run_id=g.run_id
JOIN workflow_authority w ON w.workflow=r.workflow
WHERE (g.run_authority_mode IS NOT NULL OR g.workflow_authority_mode IS NOT NULL)
  AND (
    g.run_authority_mode IS NULL
    OR g.workflow_authority_mode IS NULL
    OR g.run_authority_mode<>r.authority_mode
    OR g.workflow_authority_mode<>w.mode
  );

DROP TABLE gate_authority_snapshot_migration_guard;

CREATE TRIGGER gate_runs_validate_authority_snapshot_insert
AFTER INSERT ON gate_runs
WHEN (NEW.run_authority_mode IS NOT NULL OR NEW.workflow_authority_mode IS NOT NULL)
  AND NOT EXISTS (
    SELECT 1
    FROM runs r
    JOIN workflow_authority w ON w.workflow=r.workflow
    WHERE r.run_id=NEW.run_id
      AND NEW.run_authority_mode=r.authority_mode
      AND NEW.workflow_authority_mode=w.mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot must match run and workflow authority');
END;

CREATE TRIGGER gate_runs_validate_authority_snapshot_update
AFTER UPDATE OF run_id, run_authority_mode, workflow_authority_mode ON gate_runs
WHEN (NEW.run_authority_mode IS NOT NULL OR NEW.workflow_authority_mode IS NOT NULL)
  AND NOT EXISTS (
    SELECT 1
    FROM runs r
    JOIN workflow_authority w ON w.workflow=r.workflow
    WHERE r.run_id=NEW.run_id
      AND NEW.run_authority_mode=r.authority_mode
      AND NEW.workflow_authority_mode=w.mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot must match run and workflow authority');
END;

CREATE TRIGGER gate_runs_freeze_authority_snapshot_update
BEFORE UPDATE OF run_authority_mode, workflow_authority_mode ON gate_runs
WHEN OLD.run_authority_mode IS NOT NULL
  AND OLD.workflow_authority_mode IS NOT NULL
  AND (
    NEW.run_authority_mode IS NOT OLD.run_authority_mode
    OR NEW.workflow_authority_mode IS NOT OLD.workflow_authority_mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot is immutable');
END;

CREATE TEMP TABLE goal_run_evidence_binding_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT goal_run_evidence_binding_legacy_invalid CHECK (violation=0)
);

INSERT INTO goal_run_evidence_binding_migration_guard(violation)
SELECT 1
FROM goal_runs gr
WHERE gr.evidence_hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM evidence_hashes e
    JOIN judge_verifier_runs j
      ON j.verifier_run_id=e.verifier_run_id
     AND j.worker_run_id=e.run_id
     AND j.evidence_hash=e.evidence_hash
    JOIN gate_runs g
      ON g.gate_run_id=e.gate_run_id
     AND g.evidence_hash=e.evidence_hash
     AND g.run_id=e.run_id
     AND g.verifier_run_id=e.verifier_run_id
    JOIN transitions t
      ON t.transition_id=g.transition_id
     AND t.run_id=g.run_id
     AND t.gate_run_id=g.gate_run_id
     AND t.evidence_hash=g.evidence_hash
    JOIN gate_clock_context c
      ON c.gate_run_id=g.gate_run_id
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
    WHERE gr.run_id IS NOT NULL
      AND e.evidence_hash=gr.evidence_hash
      AND e.sha256=e.evidence_hash
      AND length(e.evidence_hash)=64
      AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
      AND e.run_id=gr.run_id
      AND e.producer_run_id=gr.run_id
      AND e.verifier_run_id IS NOT NULL
      AND e.gate_run_id IS NOT NULL
      AND g.run_authority_mode='file_authority'
      AND g.workflow_authority_mode='file_authority'
      AND g.decision='pass'
      AND g.requires_same_run=1
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
      AND CASE a.approved_risk_ceiling
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
      END >= CASE t.risk_dominance
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
      END
      AND a.expires_at_epoch_ms > c.now_epoch_ms
  );

DROP TABLE goal_run_evidence_binding_migration_guard;

CREATE TRIGGER goal_runs_validate_evidence_binding_insert
AFTER INSERT ON goal_runs
WHEN NEW.evidence_hash IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN judge_verifier_runs j
    ON j.verifier_run_id=e.verifier_run_id
   AND j.worker_run_id=e.run_id
   AND j.evidence_hash=e.evidence_hash
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  JOIN gate_clock_context c
    ON c.gate_run_id=g.gate_run_id
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
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.decision='pass'
    AND g.requires_same_run=1
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
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.expires_at_epoch_ms > c.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence requires same-run independent pass-gate evidence');
END;

CREATE TRIGGER goal_runs_validate_evidence_binding_update
AFTER UPDATE OF run_id, evidence_hash ON goal_runs
WHEN NEW.evidence_hash IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN judge_verifier_runs j
    ON j.verifier_run_id=e.verifier_run_id
   AND j.worker_run_id=e.run_id
   AND j.evidence_hash=e.evidence_hash
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  JOIN gate_clock_context c
    ON c.gate_run_id=g.gate_run_id
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
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.decision='pass'
    AND g.requires_same_run=1
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
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.expires_at_epoch_ms > c.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence requires same-run independent pass-gate evidence');
END;

CREATE TRIGGER goal_runs_validate_required_approval_current_insert
AFTER INSERT ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM approvals a
  WHERE a.approval_id=NEW.approval_id
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST(strftime('%s','now') AS INTEGER) * 1000
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires unexpired SHA-256 approval binding');
END;

CREATE TRIGGER goal_runs_validate_required_approval_current_update
AFTER UPDATE OF goal_id, run_id, severity, predicate_plugin_hash, backend, approval_id, created_at_epoch_ms ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM approvals a
  WHERE a.approval_id=NEW.approval_id
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST(strftime('%s','now') AS INTEGER) * 1000
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires unexpired SHA-256 approval binding');
END;

CREATE TRIGGER approvals_preserve_goal_run_digest_update
BEFORE UPDATE OF channel, source_message_digest, approval_text_digest, approval_hash ON approvals
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  JOIN goal_manifests gm
    ON gm.goal_id=gr.goal_id
   AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
   AND gm.backend=gr.backend
  WHERE gm.approval_required=1
    AND gr.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER goal_runs_freeze_evidence_binding_update
BEFORE UPDATE OF goal_id, run_id, severity, predicate_plugin_hash, backend, evidence_hash ON goal_runs
WHEN OLD.evidence_hash IS NOT NULL
  AND (
    NEW.goal_id IS NOT OLD.goal_id
    OR NEW.run_id IS NOT OLD.run_id
    OR NEW.severity IS NOT OLD.severity
    OR NEW.predicate_plugin_hash IS NOT OLD.predicate_plugin_hash
    OR NEW.backend IS NOT OLD.backend
    OR NEW.evidence_hash IS NOT OLD.evidence_hash
  )
BEGIN
  SELECT RAISE(ABORT,'goal run evidence binding is immutable');
END;

CREATE TRIGGER goal_runs_freeze_evidence_binding_delete
BEFORE DELETE ON goal_runs
WHEN OLD.evidence_hash IS NOT NULL
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence cannot be deleted');
END;
