ALTER TABLE budget_events
ADD COLUMN clock_context_id TEXT REFERENCES gate_clock_context(clock_context_id);

CREATE INDEX budget_events_clock_context_idx
ON budget_events(clock_context_id)
WHERE clock_context_id IS NOT NULL;

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
  transition_id, spawn_request_id, provider, model, endpoint_binding_id,
  capability_class, cost_registry_id, cost_effective_at, cost_registry_hash,
  cost_confidence, zero_reserve_policy_id, zero_reserve_policy_hash,
  time_seconds, input_tokens, output_tokens, cost_microusd,
  human_attention_units, retry_units, usage_confidence, source, created_at,
  created_at_epoch_ms, clock_context_id ON budget_events
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

SELECT 'budget_post_dispatch_clock_identity';
