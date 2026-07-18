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
    WHERE gr.run_id IS NOT NULL
      AND e.evidence_hash=gr.evidence_hash
      AND e.sha256=e.evidence_hash
      AND length(e.evidence_hash)=64
      AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
      AND e.run_id=gr.run_id
      AND e.producer_run_id=gr.run_id
      AND e.verifier_run_id IS NOT NULL
      AND e.gate_run_id IS NOT NULL
      AND r.authority_mode='file_authority'
      AND w.mode='file_authority'
      AND g.run_authority_mode='file_authority'
      AND g.workflow_authority_mode='file_authority'
      AND g.run_authority_mode=r.authority_mode
      AND g.workflow_authority_mode=w.mode
      AND g.decision='pass'
      AND g.requires_same_run=1
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
      AND CASE a.approved_risk_ceiling
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
      END >= CASE t.risk_dominance
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
      END
      AND a.approver<>''
      AND a.channel<>''
      AND a.approved_at<>''
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
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND r.authority_mode='file_authority'
    AND w.mode='file_authority'
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.run_authority_mode=r.authority_mode
    AND g.workflow_authority_mode=w.mode
    AND g.decision='pass'
    AND g.requires_same_run=1
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
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
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
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND r.authority_mode='file_authority'
    AND w.mode='file_authority'
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.run_authority_mode=r.authority_mode
    AND g.workflow_authority_mode=w.mode
    AND g.decision='pass'
    AND g.requires_same_run=1
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
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
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
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
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
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires unexpired SHA-256 approval binding');
END;

CREATE TRIGGER goal_manifests_validate_required_approval_current_update
AFTER UPDATE OF owner, severity, manifest_hash, predicate_plugin_hash, backend, approval_required, enabled ON goal_manifests
WHEN NEW.approval_required=1 AND EXISTS (
  SELECT 1
  FROM goal_runs gr
  LEFT JOIN approvals a ON a.approval_id=gr.approval_id
  WHERE gr.goal_id=NEW.goal_id
    AND gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
    AND (
      gr.run_id IS NULL
      OR a.approval_id IS NULL
      OR a.run_id<>gr.run_id
      OR a.approved_action_type<>'goal_run'
      OR a.target_type<>'goal'
      OR a.target_id<>gr.goal_id
      OR a.target_hash<>NEW.manifest_hash
      OR a.target_scope<>NEW.owner
      OR a.single_use<>1
      OR a.consumed_by_goal_run_id<>gr.goal_run_id
      OR a.approver=''
      OR a.channel=''
      OR a.approved_at=''
      OR length(a.source_message_digest)<>64
      OR a.source_message_digest GLOB '*[^0-9a-f]*'
      OR length(a.approval_text_digest)<>64
      OR a.approval_text_digest GLOB '*[^0-9a-f]*'
      OR length(a.approval_hash)<>64
      OR a.approval_hash GLOB '*[^0-9a-f]*'
      OR a.expires_at_epoch_ms<=CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
      OR CASE a.approved_risk_ceiling
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
      END < CASE NEW.severity
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
      END
    )
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires current SHA-256 approval binding');
END;

CREATE TRIGGER approvals_preserve_goal_run_digest_update
BEFORE UPDATE OF approver, channel, source_message_digest, approval_text_digest, approval_hash, approved_at ON approvals
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  JOIN goal_manifests gm
    ON gm.goal_id=gr.goal_id
   AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
   AND gm.backend=gr.backend
  WHERE gm.approval_required=1
    AND gr.approval_id=OLD.approval_id
)
OR EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  WHERE gr.evidence_hash IS NOT NULL
    AND t.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER runs_preserve_goal_run_file_authority_update
BEFORE UPDATE OF workflow, authority_mode ON runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.run_id=OLD.run_id
)
AND (
  NEW.workflow IS NOT OLD.workflow
  OR NEW.authority_mode IS NOT OLD.authority_mode
)
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence requires file-authority run');
END;

CREATE TRIGGER workflow_authority_preserve_goal_run_file_authority_update
BEFORE UPDATE OF mode ON workflow_authority
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN runs r
    ON r.run_id=e.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND r.workflow=OLD.workflow
)
AND NEW.mode IS NOT OLD.mode
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence requires file-authority workflow');
END;

CREATE TRIGGER gate_clock_context_preserve_goal_run_bound_clock_update
BEFORE UPDATE OF bound_by ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND g.clock_context_id=OLD.clock_context_id
    AND g.gate_run_id=OLD.gate_run_id
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence clock signer is immutable');
END;

CREATE TRIGGER judge_verifier_runs_preserve_goal_run_proof_update
BEFORE UPDATE OF verifier_run_id, worker_run_id, worker_agent_id, verifier_agent_id, provider, model, prompt_hash, context_hash, evidence_hash, independence_class, independence_proof_json ON judge_verifier_runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.verifier_run_id=OLD.verifier_run_id
    AND e.run_id=OLD.worker_run_id
    AND e.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'goal run verifier proof is immutable');
END;

CREATE TRIGGER judge_verifier_runs_preserve_goal_run_proof_delete
BEFORE DELETE ON judge_verifier_runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.verifier_run_id=OLD.verifier_run_id
    AND e.run_id=OLD.worker_run_id
    AND e.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'goal run verifier proof is immutable');
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
