CREATE TEMP TABLE strict_prior_reserve_slo_identity_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT strict_prior_reserve_active_trust CHECK (violation=0)
) STRICT;

INSERT INTO strict_prior_reserve_slo_identity_migration_guard(violation)
SELECT 1
FROM trust_observations
WHERE invalidated_at IS NULL
LIMIT 1;

DROP TABLE strict_prior_reserve_slo_identity_migration_guard;

DROP TRIGGER external_rpc_intents_validate_prior_reserve_insert;
DROP TRIGGER external_rpc_intents_validate_prior_reserve_update;

CREATE TRIGGER external_rpc_intents_validate_prior_reserve_insert
BEFORE INSERT ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn'
  AND NOT EXISTS (
  SELECT 1
  FROM budget_events b
  JOIN run_budgets rb ON rb.run_id=NEW.run_id
  JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.transition_id IS rb.selected_reserve_transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND rb.selected_provider=m.provider
    AND rb.selected_model=m.model
    AND rb.selected_endpoint_binding_id=m.endpoint_binding_id
    AND rb.capability_class=m.capability_class
    AND rb.selected_cost_effective_at=m.effective_at
    AND rb.selected_cost_registry_hash=m.registry_row_hash
    AND rb.selected_cost_confidence=m.confidence
    AND m.confidence<>'unknown'
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.provider=m.provider
    AND b.model=m.model
    AND b.endpoint_binding_id=m.endpoint_binding_id
    AND b.capability_class=m.capability_class
    AND b.cost_registry_id=m.cost_registry_id
    AND b.cost_effective_at=m.effective_at
    AND b.cost_registry_hash=m.registry_row_hash
    AND b.cost_confidence=m.confidence
    AND b.time_seconds <= rb.time_budget_seconds
    AND b.input_tokens <= rb.input_token_budget
    AND b.output_tokens <= rb.output_token_budget
    AND b.cost_microusd <= rb.cost_budget_microusd
    AND b.retry_units <= rb.retry_budget
    AND b.human_attention_units <= rb.human_attention_budget
    AND rb.reserved_time_seconds >= b.time_seconds
    AND rb.reserved_input_tokens >= b.input_tokens
    AND rb.reserved_output_tokens >= b.output_tokens
    AND rb.reserved_cost_microusd >= b.cost_microusd
    AND rb.reserved_retries >= b.retry_units
    AND rb.reserved_human_attention >= b.human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn requires strict prior reserve budget event');
END;

CREATE TRIGGER external_rpc_intents_validate_prior_reserve_update
BEFORE UPDATE OF rpc_kind, reserve_budget_event_id, run_id, transition_id, spawn_request_id, requested_at_epoch_ms ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn'
  AND NOT EXISTS (
  SELECT 1
  FROM budget_events b
  JOIN run_budgets rb ON rb.run_id=NEW.run_id
  JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.transition_id IS rb.selected_reserve_transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND rb.selected_provider=m.provider
    AND rb.selected_model=m.model
    AND rb.selected_endpoint_binding_id=m.endpoint_binding_id
    AND rb.capability_class=m.capability_class
    AND rb.selected_cost_effective_at=m.effective_at
    AND rb.selected_cost_registry_hash=m.registry_row_hash
    AND rb.selected_cost_confidence=m.confidence
    AND m.confidence<>'unknown'
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.provider=m.provider
    AND b.model=m.model
    AND b.endpoint_binding_id=m.endpoint_binding_id
    AND b.capability_class=m.capability_class
    AND b.cost_registry_id=m.cost_registry_id
    AND b.cost_effective_at=m.effective_at
    AND b.cost_registry_hash=m.registry_row_hash
    AND b.cost_confidence=m.confidence
    AND b.time_seconds <= rb.time_budget_seconds
    AND b.input_tokens <= rb.input_token_budget
    AND b.output_tokens <= rb.output_token_budget
    AND b.cost_microusd <= rb.cost_budget_microusd
    AND b.retry_units <= rb.retry_budget
    AND b.human_attention_units <= rb.human_attention_budget
    AND rb.reserved_time_seconds >= b.time_seconds
    AND rb.reserved_input_tokens >= b.input_tokens
    AND rb.reserved_output_tokens >= b.output_tokens
    AND rb.reserved_cost_microusd >= b.cost_microusd
    AND rb.reserved_retries >= b.retry_units
    AND rb.reserved_human_attention >= b.human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn requires strict prior reserve budget event');
END;

DROP TRIGGER trust_observations_validate_bound_insert;

DROP VIEW trust_promotion_bound_evidence;

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
JOIN goal_manifests gm
  ON gm.goal_id=gr.goal_id
 AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
 AND gm.backend=gr.backend
JOIN predicate_plugins p
  ON p.predicate_plugin_hash=gr.predicate_plugin_hash
 AND p.backend=gr.backend
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
JOIN risk_assessments ra
  ON ra.run_id=t.run_id
 AND ra.transition_id=t.transition_id
 AND ra.risk_dominance=t.risk_dominance
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
 AND rb.workflow=r.workflow
 AND rb.selected_reserve_transition_id=t.transition_id
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
  AND gm.enabled=1
  AND gm.severity=gr.severity
  AND gm.manifest_hash<>''
  AND p.schema_hash<>''
  AND (p.sensitive=0 OR (p.approved_at IS NOT NULL AND p.approved_at<>''))
  AND p.disabled_at IS NULL
  AND p.sandbox_enforced=gr.sandbox_enforced
  AND (p.sandbox_required=0 OR gr.sandbox_enforced=1)
  AND ra.assessed_at<>''
  AND ra.action_risk<>''
  AND ra.target_risk<>''
  AND ra.data_risk<>''
  AND ra.side_effect_risk<>''
  AND ra.permission_risk<>''
  AND ra.irreversibility_risk<>''
  AND CASE gr.severity
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END >= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END
  AND CASE gr.severity
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END >= CASE r.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END
  AND CASE ra.action_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND CASE ra.target_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND CASE ra.data_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND CASE ra.side_effect_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND CASE ra.permission_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND CASE ra.irreversibility_risk
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
  END <= CASE t.risk_dominance
    WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
    WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
  END
  AND NOT EXISTS (
    SELECT 1
    FROM risk_assessments ra_conflict
    WHERE ra_conflict.run_id=t.run_id
      AND ra_conflict.transition_id=t.transition_id
      AND (
        ra_conflict.risk_dominance<>t.risk_dominance
        OR ra_conflict.assessed_at=''
        OR ra_conflict.action_risk=''
        OR ra_conflict.target_risk=''
        OR ra_conflict.data_risk=''
        OR ra_conflict.side_effect_risk=''
        OR ra_conflict.permission_risk=''
        OR ra_conflict.irreversibility_risk=''
        OR CASE ra_conflict.action_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
        OR CASE ra_conflict.target_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
        OR CASE ra_conflict.data_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
        OR CASE ra_conflict.side_effect_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
        OR CASE ra_conflict.permission_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
        OR CASE ra_conflict.irreversibility_risk
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
        END > CASE t.risk_dominance
          WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
          WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
        END
      )
  )
  AND g.decision='pass'
  AND g.requires_same_run=1
  AND m.version=(SELECT MAX(version) FROM schema_migrations)
  AND m.version=15
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
  AND a.approval_hash=agentic_approval_hash(
    a.approval_id,
    a.run_id,
    t.transition_id,
    g.gate_run_id,
    t.action_type,
    t.target_type,
    t.target_id,
    t.target_hash,
    t.target_scope,
    a.channel,
    a.source_message_digest,
    a.approval_text_digest,
    a.approved_risk_ceiling,
    a.expires_at_epoch_ms
  )
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
    SELECT 1
    FROM budget_events be
    JOIN runs be_run ON be_run.run_id=be.run_id
    LEFT JOIN run_budgets be_rb
      ON be_rb.run_id=be.run_id
    LEFT JOIN model_cost_registry be_mc
      ON be_mc.cost_registry_id=be.cost_registry_id
     AND be_mc.provider=be.provider
     AND be_mc.model=be.model
     AND be_mc.endpoint_binding_id=be.endpoint_binding_id
     AND be_mc.capability_class=be.capability_class
     AND be_mc.effective_at=be.cost_effective_at
     AND be_mc.registry_row_hash=be.cost_registry_hash
     AND be_mc.confidence=be.cost_confidence
    WHERE be_run.workflow=r.workflow
      AND (
        be.usage_confidence<>'known'
        OR (
          be.event_type<>'human_attention'
          AND (be.cost_confidence IS NULL OR be.cost_confidence<>'known')
        )
        OR (
          be.event_type<>'human_attention'
          AND (
            be_rb.run_id IS NULL
            OR be.provider IS NOT be_rb.selected_provider
            OR be.model IS NOT be_rb.selected_model
            OR be.endpoint_binding_id IS NOT be_rb.selected_endpoint_binding_id
            OR be.capability_class IS NOT be_rb.capability_class
            OR be.cost_registry_id IS NOT be_rb.selected_cost_registry_id
            OR be.cost_effective_at IS NOT be_rb.selected_cost_effective_at
            OR be.cost_registry_hash IS NOT be_rb.selected_cost_registry_hash
            OR be.cost_confidence IS NOT be_rb.selected_cost_confidence
            OR be_mc.cost_registry_id IS NULL
            OR be_mc.confidence<>'known'
          )
        )
      )
  )
  AND NOT EXISTS (
    SELECT 1 FROM budget_settlements bs
    JOIN runs settlement_run ON settlement_run.run_id=bs.run_id
    WHERE settlement_run.workflow=r.workflow
      AND (bs.usage_confidence<>'known' OR bs.cost_confidence<>'known')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM run_budgets current_rb
    LEFT JOIN runs current_run ON current_run.run_id=current_rb.run_id
    LEFT JOIN model_cost_registry current_mc
      ON current_mc.cost_registry_id=current_rb.selected_cost_registry_id
     AND current_mc.provider=current_rb.selected_provider
     AND current_mc.model=current_rb.selected_model
     AND current_mc.endpoint_binding_id=current_rb.selected_endpoint_binding_id
     AND current_mc.capability_class=current_rb.capability_class
     AND current_mc.effective_at=current_rb.selected_cost_effective_at
     AND current_mc.registry_row_hash=current_rb.selected_cost_registry_hash
     AND current_mc.confidence=current_rb.selected_cost_confidence
    WHERE (current_run.run_id IS NULL OR current_run.workflow=r.workflow)
      AND (
        current_rb.usage_confidence<>'known'
        OR current_rb.selected_cost_confidence<>'known'
        OR current_mc.cost_registry_id IS NULL
        OR current_mc.confidence<>'known'
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM run_budgets current_rb
    LEFT JOIN runs current_run ON current_run.run_id=current_rb.run_id
    LEFT JOIN (
      SELECT
        be.run_id,
        SUM(CASE WHEN be.event_type='reserve' THEN be.time_seconds
                 WHEN be.event_type IN ('release','consume') THEN -be.time_seconds
                 ELSE 0 END) AS net_reserved_time,
        SUM(CASE WHEN be.event_type='reserve' THEN be.input_tokens
                 WHEN be.event_type IN ('release','consume') THEN -be.input_tokens
                 ELSE 0 END) AS net_reserved_input,
        SUM(CASE WHEN be.event_type='reserve' THEN be.output_tokens
                 WHEN be.event_type IN ('release','consume') THEN -be.output_tokens
                 ELSE 0 END) AS net_reserved_output,
        SUM(CASE WHEN be.event_type='reserve' THEN be.cost_microusd
                 WHEN be.event_type IN ('release','consume') THEN -be.cost_microusd
                 ELSE 0 END) AS net_reserved_cost,
        SUM(CASE WHEN be.event_type='reserve' THEN be.retry_units
                 WHEN be.event_type IN ('release','retry_decrement') THEN -be.retry_units
                 WHEN be.event_type='retry_restore' THEN be.retry_units
                 ELSE 0 END) AS net_reserved_retries,
        SUM(CASE WHEN be.event_type='reserve' THEN be.human_attention_units
                 WHEN be.event_type IN ('release','human_attention') THEN -be.human_attention_units
                 ELSE 0 END) AS net_reserved_human,
        SUM(CASE WHEN be.event_type='consume' THEN be.time_seconds ELSE 0 END) AS consumed_time,
        SUM(CASE WHEN be.event_type='consume' THEN be.input_tokens ELSE 0 END) AS consumed_input,
        SUM(CASE WHEN be.event_type='consume' THEN be.output_tokens ELSE 0 END) AS consumed_output,
        SUM(CASE WHEN be.event_type='consume' THEN be.cost_microusd ELSE 0 END) AS consumed_cost,
        SUM(CASE WHEN be.event_type='retry_decrement' THEN be.retry_units
                 WHEN be.event_type='retry_restore' THEN -be.retry_units
                 ELSE 0 END) AS consumed_retries,
        SUM(CASE WHEN be.event_type='human_attention' THEN be.human_attention_units ELSE 0 END) AS consumed_human
      FROM budget_events be
      GROUP BY be.run_id
    ) budget_sums ON budget_sums.run_id=current_rb.run_id
    WHERE (current_run.run_id IS NULL OR current_run.workflow=r.workflow)
      AND (
        COALESCE(budget_sums.net_reserved_time,0)<0
        OR COALESCE(budget_sums.net_reserved_input,0)<0
        OR COALESCE(budget_sums.net_reserved_output,0)<0
        OR COALESCE(budget_sums.net_reserved_cost,0)<0
        OR COALESCE(budget_sums.net_reserved_retries,0)<0
        OR COALESCE(budget_sums.net_reserved_human,0)<0
        OR COALESCE(budget_sums.net_reserved_time,0)<>current_rb.reserved_time_seconds
        OR COALESCE(budget_sums.net_reserved_input,0)<>current_rb.reserved_input_tokens
        OR COALESCE(budget_sums.net_reserved_output,0)<>current_rb.reserved_output_tokens
        OR COALESCE(budget_sums.net_reserved_cost,0)<>current_rb.reserved_cost_microusd
        OR COALESCE(budget_sums.net_reserved_retries,0)<>current_rb.reserved_retries
        OR COALESCE(budget_sums.net_reserved_human,0)<>current_rb.reserved_human_attention
        OR COALESCE(budget_sums.consumed_time,0)<>current_rb.consumed_time_seconds
        OR COALESCE(budget_sums.consumed_input,0)<>current_rb.consumed_input_tokens
        OR COALESCE(budget_sums.consumed_output,0)<>current_rb.consumed_output_tokens
        OR COALESCE(budget_sums.consumed_cost,0)<>current_rb.consumed_cost_microusd
        OR COALESCE(budget_sums.consumed_retries,0)<>current_rb.consumed_retries
        OR COALESCE(budget_sums.consumed_human,0)<>current_rb.consumed_human_attention
      )
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
          AND (
            (
              current_q.query_name<>'SLO query fixture status'
              AND sa.empty_db_status='pass'
              AND sa.fixture_db_status='pass'
            )
            OR (
              current_q.query_name='SLO query fixture status'
              AND sa.empty_db_status='self_bootstrap_empty'
              AND sa.fixture_db_status='pass'
            )
          )
          AND sa.evidence_hash=e.evidence_hash
          AND sa.evidence_run_id=e.run_id
          AND sa.verifier_run_id=e.verifier_run_id
          AND sa.gate_run_id=e.gate_run_id
          AND sa.writer_provenance_hash=agentic_slo_audit_writer_hash(
            sa.slo_audit_id,
            sa.query_name,
            sa.schema_version,
            sa.migration_sha256,
            sa.query_hash,
            sa.result_count,
            sa.status,
            sa.empty_db_status,
            sa.fixture_db_status,
            sa.evidence_hash,
            sa.evidence_run_id,
            sa.verifier_run_id,
            sa.gate_run_id,
            sa.run_at_epoch_ms
          )
          AND sa.run_at_epoch_ms >= c.now_epoch_ms
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(be.created_at_epoch_ms)
            FROM budget_events be
            JOIN runs be_run ON be_run.run_id=be.run_id
            WHERE be_run.workflow=r.workflow
          ),0)
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(bs.created_at_epoch_ms)
            FROM budget_settlements bs
            JOIN runs bs_run ON bs_run.run_id=bs.run_id
            WHERE bs_run.workflow=r.workflow
          ),0)
          AND COALESCE((
            SELECT MAX(audit_event.event_id)
            FROM slo_evidence_events audit_event
            WHERE audit_event.event_kind='slo_audit'
              AND audit_event.source_table='slo_audits'
              AND audit_event.source_id=sa.slo_audit_id
              AND audit_event.schema_version=sa.schema_version
              AND audit_event.migration_sha256=sa.migration_sha256
              AND audit_event.query_name=sa.query_name
          ),0) > COALESCE((
            SELECT MAX(input_event.event_id)
            FROM slo_evidence_events input_event
            WHERE input_event.event_kind='slo_input'
              AND input_event.source_table IN (
                'budget_events',
                'budget_settlements',
                'external_rpc_intents',
                'leases',
                'run_budgets',
                'runs',
                'sessions',
                'spawn_requests'
              )
          ),-1)
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(
              MAX(
                eri.requested_at_epoch_ms,
                COALESCE(eri.accepted_at_epoch_ms,0),
                COALESCE(eri.resolved_at_epoch_ms,0)
              )
            )
            FROM external_rpc_intents eri
            JOIN runs eri_run ON eri_run.run_id=eri.run_id
            WHERE eri_run.workflow=r.workflow
          ),0)
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(r2.finalized_at_epoch_ms)
            FROM runs r2
            WHERE r2.workflow=r.workflow
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
    AND b.schema_version=15
    AND b.current_slo_query_count=30
    AND b.current_slo_query_count=NEW.blocking_slo_query_count
    AND b.current_slo_query_count=NEW.blocking_slo_pass_audit_count
    AND agentic_trust_promotion_current_slos_pass(
      b.schema_version,b.migration_sha256
    )=1
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
    AND NEW.created_at IS NOT NULL
    AND NEW.created_at<>''
    AND typeof(NEW.schema_version)='integer'
    AND NEW.schema_version=15
    AND typeof(NEW.blocking_slo_query_count)='integer'
    AND NEW.blocking_slo_query_count=30
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
