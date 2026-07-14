DROP TRIGGER run_budgets_preserve_spawn_prior_reserve_update;

CREATE TRIGGER run_budgets_preserve_spawn_prior_reserve_update
BEFORE UPDATE OF selected_provider, selected_model, selected_endpoint_binding_id,
  capability_class, selected_cost_registry_id, selected_cost_effective_at,
  selected_cost_registry_hash, selected_cost_confidence, time_budget_seconds,
  input_token_budget, output_token_budget, cost_budget_microusd, retry_budget,
  human_attention_budget, reserved_time_seconds, reserved_input_tokens,
  reserved_output_tokens, reserved_cost_microusd, reserved_retries,
  reserved_human_attention, consumed_time_seconds, consumed_input_tokens,
  consumed_output_tokens, consumed_cost_microusd, consumed_retries,
  consumed_human_attention ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
AND (
  NEW.selected_provider IS NOT OLD.selected_provider
  OR NEW.selected_model IS NOT OLD.selected_model
  OR NEW.selected_endpoint_binding_id IS NOT OLD.selected_endpoint_binding_id
  OR NEW.capability_class IS NOT OLD.capability_class
  OR NEW.selected_cost_registry_id IS NOT OLD.selected_cost_registry_id
  OR NEW.selected_cost_effective_at IS NOT OLD.selected_cost_effective_at
  OR NEW.selected_cost_registry_hash IS NOT OLD.selected_cost_registry_hash
  OR NEW.selected_cost_confidence IS NOT OLD.selected_cost_confidence
  OR NEW.time_budget_seconds IS NOT OLD.time_budget_seconds
  OR NEW.input_token_budget IS NOT OLD.input_token_budget
  OR NEW.output_token_budget IS NOT OLD.output_token_budget
  OR NEW.cost_budget_microusd IS NOT OLD.cost_budget_microusd
  OR NEW.retry_budget IS NOT OLD.retry_budget
  OR NEW.human_attention_budget IS NOT OLD.human_attention_budget
  OR NOT EXISTS (
    SELECT 1
    FROM (
      SELECT
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN time_seconds
          WHEN event_type IN ('consume','release') THEN -time_seconds
          ELSE 0 END),0) AS reserved_time_seconds,
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN input_tokens
          WHEN event_type IN ('consume','release') THEN -input_tokens
          ELSE 0 END),0) AS reserved_input_tokens,
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN output_tokens
          WHEN event_type IN ('consume','release') THEN -output_tokens
          ELSE 0 END),0) AS reserved_output_tokens,
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN cost_microusd
          WHEN event_type IN ('consume','release') THEN -cost_microusd
          ELSE 0 END),0) AS reserved_cost_microusd,
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN retry_units
          WHEN event_type IN ('release','retry_decrement') THEN -retry_units
          WHEN event_type='retry_restore' THEN retry_units ELSE 0 END),0)
          AS reserved_retries,
        COALESCE(SUM(CASE WHEN event_type='reserve' THEN human_attention_units
          WHEN event_type IN ('release','human_attention') THEN -human_attention_units
          ELSE 0 END),0) AS reserved_human_attention,
        COALESCE(SUM(CASE WHEN event_type='consume' THEN time_seconds
          ELSE 0 END),0) AS consumed_time_seconds,
        COALESCE(SUM(CASE WHEN event_type='consume' THEN input_tokens
          ELSE 0 END),0) AS consumed_input_tokens,
        COALESCE(SUM(CASE WHEN event_type='consume' THEN output_tokens
          ELSE 0 END),0) AS consumed_output_tokens,
        COALESCE(SUM(CASE WHEN event_type='consume' THEN cost_microusd
          ELSE 0 END),0) AS consumed_cost_microusd,
        COALESCE(SUM(CASE WHEN event_type='retry_decrement' THEN retry_units
          WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END),0)
          AS consumed_retries,
        COALESCE(SUM(CASE WHEN event_type='human_attention'
          THEN human_attention_units ELSE 0 END),0)
          AS consumed_human_attention
      FROM budget_events
      WHERE run_id=OLD.run_id
    ) ledger
    WHERE ledger.reserved_time_seconds=NEW.reserved_time_seconds
      AND ledger.reserved_input_tokens=NEW.reserved_input_tokens
      AND ledger.reserved_output_tokens=NEW.reserved_output_tokens
      AND ledger.reserved_cost_microusd=NEW.reserved_cost_microusd
      AND ledger.reserved_retries=NEW.reserved_retries
      AND ledger.reserved_human_attention=NEW.reserved_human_attention
      AND ledger.consumed_time_seconds=NEW.consumed_time_seconds
      AND ledger.consumed_input_tokens=NEW.consumed_input_tokens
      AND ledger.consumed_output_tokens=NEW.consumed_output_tokens
      AND ledger.consumed_cost_microusd=NEW.consumed_cost_microusd
      AND ledger.consumed_retries=NEW.consumed_retries
      AND ledger.consumed_human_attention=NEW.consumed_human_attention
  )
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve budget selection is immutable; counters require ledger-backed updates');
END;

CREATE TRIGGER budget_events_reject_release_after_spawn_intent_insert
BEFORE INSERT ON budget_events
WHEN NEW.event_type='release'
AND EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=NEW.run_id
    AND i.transition_id=NEW.transition_id
    AND i.spawn_request_id=NEW.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'release cannot drain referenced sessions_spawn reserve');
END;

CREATE TRIGGER budget_events_reject_release_after_spawn_intent_update
BEFORE UPDATE OF event_type, run_id, transition_id, spawn_request_id ON budget_events
WHEN NEW.event_type='release'
AND EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=NEW.run_id
    AND i.transition_id=NEW.transition_id
    AND i.spawn_request_id=NEW.spawn_request_id
)
BEGIN
  SELECT RAISE(ABORT,'release cannot drain referenced sessions_spawn reserve');
END;

CREATE INDEX budget_events_spawn_sequence_idx
ON budget_events(run_id,transition_id,spawn_request_id,event_sequence);

SELECT 'budget_post_dispatch_mutations';
