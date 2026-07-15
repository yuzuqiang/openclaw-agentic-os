CREATE TABLE budget_settlements (
  settlement_id TEXT PRIMARY KEY,
  settlement_idempotency_key TEXT NOT NULL UNIQUE,
  settlement_dedupe_hash TEXT NOT NULL UNIQUE,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT NOT NULL,
  spawn_request_id TEXT NOT NULL REFERENCES spawn_requests(spawn_request_id),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  endpoint_binding_id TEXT NOT NULL,
  capability_class TEXT NOT NULL,
  cost_registry_id TEXT NOT NULL REFERENCES model_cost_registry(cost_registry_id),
  cost_effective_at TEXT NOT NULL,
  cost_registry_hash TEXT NOT NULL,
  cost_confidence TEXT NOT NULL CHECK (cost_confidence IN ('known','estimated')),
  actual_time_seconds ANY NOT NULL,
  actual_input_tokens ANY NOT NULL,
  actual_output_tokens ANY NOT NULL,
  actual_cost_microusd ANY NOT NULL,
  actual_retry_units ANY NOT NULL,
  actual_human_attention_units ANY NOT NULL,
  released_time_seconds ANY NOT NULL,
  released_input_tokens ANY NOT NULL,
  released_output_tokens ANY NOT NULL,
  released_cost_microusd ANY NOT NULL,
  released_retry_units ANY NOT NULL,
  released_human_attention_units ANY NOT NULL,
  usage_confidence TEXT NOT NULL CHECK (usage_confidence IN ('known','estimated')),
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_at_epoch_ms ANY NOT NULL,
  clock_context_id TEXT NOT NULL REFERENCES gate_clock_context(clock_context_id),
  CHECK (settlement_id<>'' AND settlement_idempotency_key<>'' AND settlement_dedupe_hash<>''),
  CHECK (provider<>'' AND model<>'' AND endpoint_binding_id<>'' AND capability_class<>''),
  CHECK (cost_registry_id<>'' AND cost_effective_at<>'' AND cost_registry_hash<>''),
  CHECK (source<>'' AND created_at<>''),
  CHECK (typeof(created_at_epoch_ms)='integer' AND created_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(actual_time_seconds)='integer' AND actual_time_seconds BETWEEN 0 AND 31536000),
  CHECK (typeof(actual_input_tokens)='integer' AND actual_input_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(actual_output_tokens)='integer' AND actual_output_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(actual_cost_microusd)='integer' AND actual_cost_microusd BETWEEN 0 AND 100000000000),
  CHECK (typeof(actual_retry_units)='integer' AND actual_retry_units BETWEEN 0 AND 1000000),
  CHECK (typeof(actual_human_attention_units)='integer' AND actual_human_attention_units BETWEEN 0 AND 1000000),
  CHECK (typeof(released_time_seconds)='integer' AND released_time_seconds BETWEEN 0 AND 31536000),
  CHECK (typeof(released_input_tokens)='integer' AND released_input_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(released_output_tokens)='integer' AND released_output_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(released_cost_microusd)='integer' AND released_cost_microusd BETWEEN 0 AND 100000000000),
  CHECK (typeof(released_retry_units)='integer' AND released_retry_units BETWEEN 0 AND 1000000),
  CHECK (typeof(released_human_attention_units)='integer' AND released_human_attention_units BETWEEN 0 AND 1000000),
  UNIQUE(run_id,transition_id,spawn_request_id),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

ALTER TABLE budget_events
ADD COLUMN settlement_id TEXT REFERENCES budget_settlements(settlement_id);

CREATE UNIQUE INDEX budget_events_settlement_type_unique
ON budget_events(settlement_id,event_type)
WHERE settlement_id IS NOT NULL;

CREATE INDEX budget_settlements_spawn_idx
ON budget_settlements(run_id,transition_id,spawn_request_id);

CREATE TRIGGER budget_settlements_reject_event_dedupe_insert
BEFORE INSERT ON budget_settlements
WHEN EXISTS (
  SELECT 1 FROM budget_events be
  WHERE be.event_dedupe_hash=NEW.settlement_dedupe_hash
)
BEGIN
  SELECT RAISE(ABORT,'final settlement source dedupe key was already used by a budget event');
END;

CREATE TRIGGER budget_settlements_validate_insert
BEFORE INSERT ON budget_settlements
WHEN NOT EXISTS (
  SELECT 1
  FROM spawn_requests sr
  JOIN runs r ON r.run_id=sr.run_id
  JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id
    AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id
    AND s.client_request_id=sr.client_request_id
    AND s.spawn_idempotency_key=sr.spawn_idempotency_key
    AND s.phase=sr.phase AND s.agent_id=sr.agent_id
    AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key
  JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn'
    AND i.state IN ('accepted','reconciled')
    AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id
    AND i.transition_id=sr.transition_id
    AND i.client_request_id=sr.client_request_id
    AND i.idempotency_key=sr.spawn_idempotency_key
    AND i.phase=sr.phase AND i.agent_id=sr.agent_id
    AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key
  JOIN run_budgets rb ON rb.run_id=sr.run_id
  JOIN model_cost_registry m ON m.cost_registry_id=NEW.cost_registry_id
    AND m.provider=NEW.provider AND m.model=NEW.model
    AND m.endpoint_binding_id=NEW.endpoint_binding_id
    AND m.capability_class=NEW.capability_class
    AND m.effective_at=NEW.cost_effective_at
    AND m.registry_row_hash=NEW.cost_registry_hash
    AND m.confidence=NEW.cost_confidence
  JOIN gate_clock_context c ON c.clock_context_id=NEW.clock_context_id
    AND c.run_id=sr.run_id AND c.transition_id=sr.transition_id
  JOIN gate_runs g ON g.gate_run_id=c.gate_run_id
    AND g.clock_context_id=c.clock_context_id
    AND g.run_id=c.run_id AND g.transition_id=c.transition_id
  WHERE sr.spawn_request_id=NEW.spawn_request_id
    AND sr.run_id=NEW.run_id AND sr.transition_id=NEW.transition_id
    AND sr.state='completed' AND s.state='completed'
    AND s.completed_at IS NOT NULL AND s.completed_at<>''
    AND r.state IN ('child_completed','child_failed','aggregation_completed')
    AND rb.selected_reserve_transition_id=NEW.transition_id
    AND rb.selected_provider=NEW.provider AND rb.selected_model=NEW.model
    AND rb.selected_endpoint_binding_id=NEW.endpoint_binding_id
    AND rb.capability_class=NEW.capability_class
    AND rb.selected_cost_registry_id=NEW.cost_registry_id
    AND rb.selected_cost_effective_at=NEW.cost_effective_at
    AND rb.selected_cost_registry_hash=NEW.cost_registry_hash
    AND rb.selected_cost_confidence=NEW.cost_confidence
    AND rb.usage_confidence IN ('known','estimated')
    AND NEW.actual_cost_microusd >=
      (NEW.actual_input_tokens / 1000000) * m.input_cost_microusd_per_million
      + (((NEW.actual_input_tokens % 1000000)
        * m.input_cost_microusd_per_million + 999999) / 1000000)
      + (NEW.actual_output_tokens / 1000000)
        * m.output_cost_microusd_per_million
      + (((NEW.actual_output_tokens % 1000000)
        * m.output_cost_microusd_per_million + 999999) / 1000000)
    AND i.requested_at_epoch_ms<i.accepted_at_epoch_ms
    AND i.accepted_at_epoch_ms<NEW.created_at_epoch_ms
    AND c.gate_run_id=c.consumed_by_gate_run_id
    AND c.bound_at_epoch_ms=c.now_epoch_ms
    AND c.consumed_at_epoch_ms=c.now_epoch_ms
    AND c.now_epoch_ms=NEW.created_at_epoch_ms
    AND c.trusted_clock_source_hash<>'' AND c.gate_nonce<>''
    AND g.decision='pass' AND g.completed_at_epoch_ms=c.now_epoch_ms
    AND NOT EXISTS (
      SELECT 1 FROM budget_events poison
      WHERE poison.run_id=NEW.run_id AND poison.usage_confidence='unknown'
    )
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN time_seconds
        WHEN event_type IN ('consume','release') THEN -time_seconds ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_time_seconds+NEW.released_time_seconds
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN input_tokens
        WHEN event_type IN ('consume','release') THEN -input_tokens ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_input_tokens+NEW.released_input_tokens
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN output_tokens
        WHEN event_type IN ('consume','release') THEN -output_tokens ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_output_tokens+NEW.released_output_tokens
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN cost_microusd
        WHEN event_type IN ('consume','release') THEN -cost_microusd ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_cost_microusd+NEW.released_cost_microusd
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN retry_units
        WHEN event_type IN ('release','retry_decrement') THEN -retry_units
        WHEN event_type='retry_restore' THEN retry_units ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_retry_units+NEW.released_retry_units
    AND (
      SELECT COALESCE(SUM(CASE WHEN event_type='reserve' THEN human_attention_units
        WHEN event_type IN ('release','human_attention') THEN -human_attention_units
        ELSE 0 END),0)
      FROM budget_events be WHERE be.run_id=NEW.run_id
        AND be.transition_id=NEW.transition_id
        AND be.spawn_request_id=NEW.spawn_request_id
        AND be.provider=NEW.provider AND be.model=NEW.model
        AND be.endpoint_binding_id=NEW.endpoint_binding_id
        AND be.capability_class=NEW.capability_class
        AND be.cost_registry_id=NEW.cost_registry_id
        AND be.cost_effective_at=NEW.cost_effective_at
        AND be.cost_registry_hash=NEW.cost_registry_hash
        AND be.cost_confidence=NEW.cost_confidence
    )=NEW.actual_human_attention_units+NEW.released_human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'final settlement requires exact completed-session, clock, selection, and outstanding proof');
END;

CREATE TRIGGER budget_settlements_preserve_update
BEFORE UPDATE ON budget_settlements
BEGIN
  SELECT RAISE(ABORT,'accepted final settlement is immutable');
END;

CREATE TRIGGER budget_settlements_preserve_delete
BEFORE DELETE ON budget_settlements
BEGIN
  SELECT RAISE(ABORT,'accepted final settlement is immutable');
END;

CREATE TRIGGER sessions_preserve_settlement_completed_proof_update
BEFORE UPDATE OF state, completed_at ON sessions
WHEN EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE bs.run_id=OLD.run_id
    AND bs.transition_id=OLD.transition_id
    AND bs.spawn_request_id=OLD.spawn_request_id
    AND bs.created_at_epoch_ms>0
)
AND (NEW.state<>OLD.state OR NEW.completed_at IS NOT OLD.completed_at)
BEGIN
  SELECT RAISE(ABORT,'final settlement requires immutable completed-session proof');
END;

CREATE TRIGGER budget_events_reject_settlement_dedupe_insert
BEFORE INSERT ON budget_events
WHEN EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE bs.settlement_dedupe_hash=NEW.event_dedupe_hash
)
BEGIN
  SELECT RAISE(ABORT,'budget event source dedupe key was already used by a final settlement');
END;

CREATE TRIGGER budget_events_reject_after_final_settlement_insert
BEFORE INSERT ON budget_events
WHEN NEW.settlement_id IS NULL
AND NEW.event_type IN (
  'reserve','consume','release','retry_decrement','retry_restore','human_attention'
)
AND NOT EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE bs.settlement_dedupe_hash=NEW.event_dedupe_hash
)
AND EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE bs.run_id=NEW.run_id
    AND bs.transition_id=NEW.transition_id
    AND bs.spawn_request_id=NEW.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'final settlement is terminal for this spawn budget ledger');
END;

CREATE TRIGGER budget_events_reject_after_final_settlement_update
BEFORE UPDATE ON budget_events
WHEN (OLD.settlement_id IS NULL OR NEW.settlement_id IS NULL)
AND (
  OLD.event_type IN (
    'reserve','consume','release','retry_decrement','retry_restore','human_attention'
  )
  OR NEW.event_type IN (
    'reserve','consume','release','retry_decrement','retry_restore','human_attention'
  )
)
AND EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE (
    bs.run_id=OLD.run_id
    AND bs.transition_id=OLD.transition_id
    AND bs.spawn_request_id=OLD.spawn_request_id
  )
  OR (
    bs.run_id=NEW.run_id
    AND bs.transition_id=NEW.transition_id
    AND bs.spawn_request_id=NEW.spawn_request_id
  )
)
BEGIN
  SELECT RAISE(ABORT,'final settlement is terminal for this spawn budget ledger');
END;

CREATE TRIGGER budget_events_validate_settlement_link_insert
BEFORE INSERT ON budget_events
WHEN NEW.settlement_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM budget_settlements bs
  WHERE bs.settlement_id=NEW.settlement_id
    AND bs.run_id=NEW.run_id AND bs.transition_id=NEW.transition_id
    AND bs.spawn_request_id=NEW.spawn_request_id
    AND bs.provider=NEW.provider AND bs.model=NEW.model
    AND bs.endpoint_binding_id=NEW.endpoint_binding_id
    AND bs.capability_class=NEW.capability_class
    AND bs.cost_registry_id=NEW.cost_registry_id
    AND bs.cost_effective_at=NEW.cost_effective_at
    AND bs.cost_registry_hash=NEW.cost_registry_hash
    AND bs.cost_confidence=NEW.cost_confidence
    AND bs.usage_confidence=NEW.usage_confidence
    AND bs.source=NEW.source AND bs.created_at=NEW.created_at
    AND bs.created_at_epoch_ms=NEW.created_at_epoch_ms
    AND bs.clock_context_id=NEW.clock_context_id
    AND (
      (NEW.event_type='consume'
        AND NEW.time_seconds=bs.actual_time_seconds
        AND NEW.input_tokens=bs.actual_input_tokens
        AND NEW.output_tokens=bs.actual_output_tokens
        AND NEW.cost_microusd=bs.actual_cost_microusd
        AND NEW.retry_units=0 AND NEW.human_attention_units=0)
      OR (NEW.event_type='retry_decrement'
        AND NEW.time_seconds=0 AND NEW.input_tokens=0
        AND NEW.output_tokens=0 AND NEW.cost_microusd=0
        AND NEW.retry_units=bs.actual_retry_units
        AND NEW.human_attention_units=0)
      OR (NEW.event_type='human_attention'
        AND NEW.time_seconds=0 AND NEW.input_tokens=0
        AND NEW.output_tokens=0 AND NEW.cost_microusd=0
        AND NEW.retry_units=0
        AND NEW.human_attention_units=bs.actual_human_attention_units)
      OR (NEW.event_type='release'
        AND NEW.time_seconds=bs.released_time_seconds
        AND NEW.input_tokens=bs.released_input_tokens
        AND NEW.output_tokens=bs.released_output_tokens
        AND NEW.cost_microusd=bs.released_cost_microusd
        AND NEW.retry_units=bs.released_retry_units
        AND NEW.human_attention_units=bs.released_human_attention_units)
    )
)
BEGIN
  SELECT RAISE(ABORT,'settlement budget event does not match immutable settlement proof');
END;

CREATE TRIGGER budget_events_reject_settlement_link_update
BEFORE UPDATE ON budget_events
WHEN NEW.settlement_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT,'settlement budget events must be inserted atomically');
END;

DROP TRIGGER budget_events_reject_pre_dispatch_event_after_spawn_intent_insert;
DROP TRIGGER budget_events_reject_pre_dispatch_event_after_spawn_intent_update;

CREATE TRIGGER budget_events_reject_pre_dispatch_event_after_spawn_intent_insert
BEFORE INSERT ON budget_events
WHEN NEW.event_type IN ('reserve','release')
AND EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=NEW.run_id AND i.transition_id=NEW.transition_id
    AND i.spawn_request_id=NEW.spawn_request_id
)
AND (NEW.event_type='reserve' OR NEW.settlement_id IS NULL)
BEGIN
  SELECT RAISE(ABORT,'post-intent reserve/release requires exact final settlement proof');
END;

CREATE TRIGGER budget_events_reject_pre_dispatch_event_after_spawn_intent_update
BEFORE UPDATE OF event_type, run_id, transition_id, spawn_request_id, settlement_id
  ON budget_events
WHEN NEW.event_type IN ('reserve','release')
AND EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=NEW.run_id AND i.transition_id=NEW.transition_id
    AND i.spawn_request_id=NEW.spawn_request_id
)
AND (NEW.event_type='reserve' OR NEW.settlement_id IS NULL)
BEGIN
  SELECT RAISE(ABORT,'post-intent reserve/release requires exact final settlement proof');
END;

DROP TRIGGER budget_events_preserve_accepted_post_dispatch_delete;
DROP TRIGGER budget_events_preserve_accepted_post_dispatch_update;

CREATE TRIGGER budget_events_preserve_accepted_post_dispatch_delete
BEFORE DELETE ON budget_events
WHEN (
  OLD.event_type IN ('consume','retry_decrement','retry_restore','human_attention')
  OR OLD.settlement_id IS NOT NULL
)
AND EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn' AND i.state IN ('accepted','reconciled')
    AND i.run_id=OLD.run_id AND i.transition_id=OLD.transition_id
    AND i.spawn_request_id=OLD.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'accepted post-dispatch budget event is immutable');
END;

CREATE TRIGGER budget_events_preserve_accepted_post_dispatch_update
BEFORE UPDATE OF budget_event_id, event_type, event_sequence, run_id,
  transition_id, spawn_request_id, event_idempotency_key, event_dedupe_hash,
  provider, model, endpoint_binding_id, capability_class, cost_registry_id,
  cost_effective_at, cost_registry_hash, cost_confidence,
  zero_reserve_policy_id, zero_reserve_policy_hash, time_seconds,
  input_tokens, output_tokens, cost_microusd, human_attention_units,
  retry_units, usage_confidence, source, created_at, created_at_epoch_ms,
  clock_context_id, settlement_id ON budget_events
WHEN (
  OLD.event_type IN ('consume','retry_decrement','retry_restore','human_attention')
  OR NEW.event_type IN ('consume','retry_decrement','retry_restore','human_attention')
  OR OLD.settlement_id IS NOT NULL
  OR NEW.settlement_id IS NOT NULL
)
AND EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn' AND i.state IN ('accepted','reconciled')
    AND i.run_id=OLD.run_id AND i.transition_id=OLD.transition_id
    AND i.spawn_request_id=OLD.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'accepted post-dispatch budget event is immutable');
END;

SELECT 'budget_atomic_final_settlement';
