ALTER TABLE budget_events
ADD COLUMN clock_context_id TEXT REFERENCES gate_clock_context(clock_context_id);

CREATE INDEX budget_events_clock_context_idx
ON budget_events(clock_context_id)
WHERE clock_context_id IS NOT NULL;

DROP TRIGGER budget_events_preserve_accepted_post_dispatch_delete;
DROP TRIGGER budget_events_preserve_accepted_post_dispatch_update;
DROP TRIGGER external_rpc_intents_preserve_spawn_acceptance_update;

CREATE TRIGGER budget_events_preserve_accepted_post_dispatch_delete
BEFORE DELETE ON budget_events
WHEN OLD.event_type IN ('consume','retry_decrement','retry_restore','human_attention')
AND EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.state IN ('accepted','reconciled')
    AND i.run_id=OLD.run_id
    AND i.transition_id=OLD.transition_id
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
  clock_context_id ON budget_events
WHEN OLD.event_type IN ('consume','retry_decrement','retry_restore','human_attention')
AND EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.state IN ('accepted','reconciled')
    AND i.run_id=OLD.run_id
    AND i.transition_id=OLD.transition_id
    AND i.spawn_request_id=OLD.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'accepted post-dispatch budget event is immutable');
END;

CREATE TRIGGER external_rpc_intents_preserve_spawn_acceptance_update
BEFORE UPDATE OF rpc_kind, state, spawn_request_id, run_id, transition_id,
  client_request_id, idempotency_key, phase, agent_id, task_digest,
  external_id, requested_at_epoch_ms, accepted_at_epoch_ms
  ON external_rpc_intents
WHEN OLD.rpc_kind='sessions_spawn'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM spawn_requests sr
    WHERE sr.state IN ('accepted','completed')
      AND sr.spawn_request_id=OLD.spawn_request_id
      AND sr.run_id=OLD.run_id
      AND sr.transition_id=OLD.transition_id
      AND sr.client_request_id=OLD.client_request_id
      AND sr.spawn_idempotency_key=OLD.idempotency_key
      AND sr.phase=OLD.phase
      AND sr.agent_id=OLD.agent_id
      AND sr.task_digest=OLD.task_digest
      AND sr.session_key=OLD.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires external intent proof');
END;

SELECT 'budget_post_dispatch_clock_identity';
