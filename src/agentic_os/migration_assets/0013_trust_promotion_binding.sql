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
  AND m.version=13
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
          AND sa.empty_db_status='pass'
          AND sa.fixture_db_status='pass'
          AND sa.evidence_hash=e.evidence_hash
          AND sa.evidence_run_id=e.run_id
          AND sa.verifier_run_id=e.verifier_run_id
          AND sa.gate_run_id=e.gate_run_id
          AND sa.run_at_epoch_ms >= c.now_epoch_ms
          AND sa.run_at_epoch_ms >= COALESCE((
            SELECT MAX(be.created_at_epoch_ms)
            FROM budget_events be
            JOIN runs be_run ON be_run.run_id=be.run_id
            WHERE be_run.workflow=r.workflow
          ),0)
          AND sa.rowid > COALESCE((
            SELECT MAX(be.rowid)
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
          AND sa.rowid > COALESCE((
            SELECT MAX(bs.rowid)
            FROM budget_settlements bs
            JOIN runs bs_run ON bs_run.run_id=bs.run_id
            WHERE bs_run.workflow=r.workflow
          ),0)
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
            SELECT MAX(l.expires_at_epoch_ms)
            FROM leases l
            JOIN runs lease_run ON lease_run.run_id=l.run_id
            WHERE lease_run.workflow=r.workflow
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
    AND b.schema_version=13
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
    AND NEW.schema_version=13
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

CREATE TRIGGER trust_observations_validate_bound_update
BEFORE UPDATE ON trust_observations
WHEN NOT (
    OLD.invalidated_at IS NULL
    AND
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
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER budget_events_preserve_active_trust_update
BEFORE UPDATE ON budget_events
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER budget_events_preserve_active_trust_delete
BEFORE DELETE ON budget_events
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before budget event changes');
END;

CREATE TRIGGER run_budgets_preserve_active_trust_insert
BEFORE INSERT ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
      OR trusted_run.workflow=NEW.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before selected budget changes');
END;

CREATE TRIGGER run_budgets_preserve_active_trust_update
BEFORE UPDATE ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
      OR trusted_run.workflow=OLD.workflow
      OR trusted_run.workflow=NEW.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before selected budget changes');
END;

CREATE TRIGGER run_budgets_preserve_active_trust_delete
BEFORE DELETE ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
      OR trusted_run.workflow=OLD.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before selected budget changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_insert
BEFORE INSERT ON budget_settlements
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_update
BEFORE UPDATE ON budget_settlements
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER budget_settlements_preserve_active_trust_delete
BEFORE DELETE ON budget_settlements
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before settlement changes');
END;

CREATE TRIGGER external_rpc_intents_preserve_active_trust_insert
BEFORE INSERT ON external_rpc_intents
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before external RPC intent changes');
END;

CREATE TRIGGER external_rpc_intents_preserve_active_trust_update
BEFORE UPDATE ON external_rpc_intents
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before external RPC intent changes');
END;

CREATE TRIGGER external_rpc_intents_preserve_active_trust_delete
BEFORE DELETE ON external_rpc_intents
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before external RPC intent changes');
END;

CREATE TRIGGER leases_preserve_active_trust_insert
BEFORE INSERT ON leases
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before lease changes');
END;

CREATE TRIGGER leases_preserve_active_trust_update
BEFORE UPDATE ON leases
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before lease changes');
END;

CREATE TRIGGER leases_preserve_active_trust_delete
BEFORE DELETE ON leases
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before lease changes');
END;

CREATE TRIGGER spawn_requests_preserve_active_trust_insert
BEFORE INSERT ON spawn_requests
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before spawn request changes');
END;

CREATE TRIGGER spawn_requests_preserve_active_trust_update
BEFORE UPDATE ON spawn_requests
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before spawn request changes');
END;

CREATE TRIGGER spawn_requests_preserve_active_trust_delete
BEFORE DELETE ON spawn_requests
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before spawn request changes');
END;

CREATE TRIGGER sessions_preserve_active_trust_insert
BEFORE INSERT ON sessions
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  LEFT JOIN spawn_requests changed_spawn
    ON changed_spawn.spawn_request_id=NEW.spawn_request_id
  LEFT JOIN runs spawn_run ON spawn_run.run_id=changed_spawn.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
      OR changed_spawn.spawn_request_id IS NULL
      OR spawn_run.run_id IS NULL
      OR trusted_run.workflow=spawn_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before session changes');
END;

CREATE TRIGGER sessions_preserve_active_trust_update
BEFORE UPDATE ON sessions
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  LEFT JOIN spawn_requests old_changed_spawn
    ON old_changed_spawn.spawn_request_id=OLD.spawn_request_id
  LEFT JOIN spawn_requests new_changed_spawn
    ON new_changed_spawn.spawn_request_id=NEW.spawn_request_id
  LEFT JOIN runs old_spawn_run ON old_spawn_run.run_id=old_changed_spawn.run_id
  LEFT JOIN runs new_spawn_run ON new_spawn_run.run_id=new_changed_spawn.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
      OR old_changed_spawn.spawn_request_id IS NULL
      OR new_changed_spawn.spawn_request_id IS NULL
      OR old_spawn_run.run_id IS NULL
      OR new_spawn_run.run_id IS NULL
      OR trusted_run.workflow=old_spawn_run.workflow
      OR trusted_run.workflow=new_spawn_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before session changes');
END;

CREATE TRIGGER sessions_preserve_active_trust_delete
BEFORE DELETE ON sessions
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  LEFT JOIN spawn_requests changed_spawn
    ON changed_spawn.spawn_request_id=OLD.spawn_request_id
  LEFT JOIN runs spawn_run ON spawn_run.run_id=changed_spawn.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
      OR changed_spawn.spawn_request_id IS NULL
      OR spawn_run.run_id IS NULL
      OR trusted_run.workflow=spawn_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before session changes');
END;

CREATE TRIGGER runs_preserve_active_trust_update
BEFORE UPDATE ON runs
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before run changes');
END;

CREATE TRIGGER runs_preserve_active_trust_insert
BEFORE INSERT ON runs
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before run changes');
END;

CREATE TRIGGER runs_preserve_active_trust_delete
BEFORE DELETE ON runs
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before run changes');
END;

CREATE TRIGGER model_cost_registry_preserve_active_trust_insert
BEFORE INSERT ON model_cost_registry
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before model cost registry changes');
END;

CREATE TRIGGER model_cost_registry_preserve_active_trust_update
BEFORE UPDATE ON model_cost_registry
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before model cost registry changes');
END;

CREATE TRIGGER model_cost_registry_preserve_active_trust_delete
BEFORE DELETE ON model_cost_registry
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before model cost registry changes');
END;

CREATE TRIGGER endpoint_zero_reserve_policies_preserve_active_trust_insert
BEFORE INSERT ON endpoint_zero_reserve_policies
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before zero reserve policy changes');
END;

CREATE TRIGGER endpoint_zero_reserve_policies_preserve_active_trust_update
BEFORE UPDATE ON endpoint_zero_reserve_policies
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before zero reserve policy changes');
END;

CREATE TRIGGER endpoint_zero_reserve_policies_preserve_active_trust_delete
BEFORE DELETE ON endpoint_zero_reserve_policies
WHEN EXISTS (SELECT 1 FROM trust_observations trust WHERE trust.invalidated_at IS NULL)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before zero reserve policy changes');
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

CREATE TRIGGER gate_clock_context_preserve_active_trust_insert
BEFORE INSERT ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (
      trust.clock_context_id=NEW.clock_context_id
      OR trust.gate_run_id=NEW.gate_run_id
      OR trust.run_id=NEW.run_id
      OR trust.transition_id=NEW.transition_id
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before gate clock changes');
END;

CREATE TRIGGER gate_clock_context_preserve_active_trust_update
BEFORE UPDATE ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (
      trust.clock_context_id IN (OLD.clock_context_id,NEW.clock_context_id)
      OR trust.gate_run_id IN (OLD.gate_run_id,NEW.gate_run_id)
      OR trust.run_id IN (OLD.run_id,NEW.run_id)
      OR trust.transition_id IN (OLD.transition_id,NEW.transition_id)
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before gate clock changes');
END;

CREATE TRIGGER gate_clock_context_preserve_active_trust_delete
BEFORE DELETE ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND (
      trust.clock_context_id=OLD.clock_context_id
      OR trust.gate_run_id=OLD.gate_run_id
      OR trust.run_id=OLD.run_id
      OR trust.transition_id=OLD.transition_id
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before gate clock changes');
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

CREATE TRIGGER predicate_plugins_preserve_goal_run_metadata_update
BEFORE UPDATE OF predicate_plugin_hash, name, version, backend, schema_hash, sandbox_required, sandbox_enforced, sensitive, approved_at, disabled_at, created_at ON predicate_plugins
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  WHERE gr.predicate_plugin_hash=OLD.predicate_plugin_hash
    AND gr.backend=OLD.backend
) OR EXISTS (
  SELECT 1 FROM goal_runs gr
  WHERE gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
)
BEGIN
  SELECT RAISE(ABORT,'referenced predicate plugin metadata is immutable');
END;

CREATE TRIGGER predicate_plugins_preserve_goal_run_metadata_delete
BEFORE DELETE ON predicate_plugins
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  WHERE gr.predicate_plugin_hash=OLD.predicate_plugin_hash
    AND gr.backend=OLD.backend
)
BEGIN
  SELECT RAISE(ABORT,'referenced predicate plugin metadata is immutable');
END;

CREATE TRIGGER goal_manifests_preserve_goal_run_identity_update
BEFORE UPDATE OF goal_id, owner, severity, manifest_hash, predicate_plugin_hash, backend, approval_required, enabled ON goal_manifests
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  WHERE (
      gr.goal_id=OLD.goal_id
      AND gr.predicate_plugin_hash=OLD.predicate_plugin_hash
      AND gr.backend=OLD.backend
    )
    OR (
      gr.goal_id=NEW.goal_id
      AND gr.predicate_plugin_hash=NEW.predicate_plugin_hash
      AND gr.backend=NEW.backend
    )
)
BEGIN
  SELECT RAISE(ABORT,'referenced goal manifest identity is immutable');
END;

CREATE TRIGGER goal_manifests_preserve_active_trust_update
BEFORE UPDATE OF goal_id, owner, severity, manifest_hash, predicate_plugin_hash, backend, approval_required, enabled ON goal_manifests
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN goal_runs gr ON gr.goal_run_id=trust.goal_run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      gr.goal_id=OLD.goal_id
      OR gr.goal_id=NEW.goal_id
      OR (
        gr.predicate_plugin_hash=OLD.predicate_plugin_hash
        AND gr.backend=OLD.backend
      )
      OR (
        gr.predicate_plugin_hash=NEW.predicate_plugin_hash
        AND gr.backend=NEW.backend
      )
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before goal manifest changes');
END;

CREATE TRIGGER goal_manifests_preserve_active_trust_delete
BEFORE DELETE ON goal_manifests
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN goal_runs gr ON gr.goal_run_id=trust.goal_run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      gr.goal_id=OLD.goal_id
      OR (
        gr.predicate_plugin_hash=OLD.predicate_plugin_hash
        AND gr.backend=OLD.backend
      )
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before goal manifest changes');
END;

CREATE TRIGGER risk_assessments_preserve_active_trust_insert
BEFORE INSERT ON risk_assessments
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before risk assessment changes');
END;

CREATE TRIGGER risk_assessments_preserve_active_trust_update
BEFORE UPDATE ON risk_assessments
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs old_changed_run ON old_changed_run.run_id=OLD.run_id
  LEFT JOIN runs new_changed_run ON new_changed_run.run_id=NEW.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      old_changed_run.run_id IS NULL
      OR new_changed_run.run_id IS NULL
      OR trusted_run.workflow=old_changed_run.workflow
      OR trusted_run.workflow=new_changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before risk assessment changes');
END;

CREATE TRIGGER risk_assessments_preserve_active_trust_delete
BEFORE DELETE ON risk_assessments
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  LEFT JOIN runs changed_run ON changed_run.run_id=OLD.run_id
  WHERE trust.invalidated_at IS NULL
    AND (
      changed_run.run_id IS NULL
      OR trusted_run.workflow=changed_run.workflow
    )
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before risk assessment changes');
END;

CREATE TRIGGER goal_runs_preserve_active_trust_update
BEFORE UPDATE ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND trust.goal_run_id IN (OLD.goal_run_id,NEW.goal_run_id)
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before goal run changes');
END;

CREATE TRIGGER goal_runs_preserve_active_trust_delete
BEFORE DELETE ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM trust_observations trust
  WHERE trust.invalidated_at IS NULL
    AND trust.goal_run_id=OLD.goal_run_id
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before goal run changes');
END;

CREATE TRIGGER workflow_authority_preserve_active_trust_update
BEFORE UPDATE ON workflow_authority
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  WHERE trust.invalidated_at IS NULL
    AND trusted_run.workflow IN (OLD.workflow,NEW.workflow)
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before workflow authority changes');
END;

CREATE TRIGGER workflow_authority_preserve_active_trust_delete
BEFORE DELETE ON workflow_authority
WHEN EXISTS (
  SELECT 1
  FROM trust_observations trust
  JOIN runs trusted_run ON trusted_run.run_id=trust.run_id
  WHERE trust.invalidated_at IS NULL
    AND trusted_run.workflow=OLD.workflow
)
BEGIN
  SELECT RAISE(ABORT,'active trust requires invalidation before workflow authority changes');
END;

CREATE TRIGGER trust_observations_validate_bound_reactivate_update
BEFORE UPDATE ON trust_observations
WHEN OLD.invalidated_at IS NOT NULL AND NEW.invalidated_at IS NULL
BEGIN
  SELECT RAISE(ABORT,'trust observations cannot be reactivated');
END;

CREATE TRIGGER trust_observations_validate_bound_delete
BEFORE DELETE ON trust_observations
BEGIN
  SELECT RAISE(ABORT,'active trust observation is immutable');
END;

SELECT 'trust_promotion_binding';
