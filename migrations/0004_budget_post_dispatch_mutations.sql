DROP TRIGGER run_budgets_preserve_spawn_prior_reserve_update;

CREATE TRIGGER run_budgets_preserve_spawn_prior_reserve_update
BEFORE UPDATE OF selected_provider, selected_model, selected_endpoint_binding_id,
  capability_class, selected_cost_registry_id, selected_cost_effective_at,
  selected_cost_registry_hash, selected_cost_confidence, time_budget_seconds,
  input_token_budget, output_token_budget, cost_budget_microusd, retry_budget,
  human_attention_budget ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve budget selection is immutable');
END;

CREATE INDEX budget_events_spawn_sequence_idx
ON budget_events(run_id,transition_id,spawn_request_id,event_sequence);

SELECT 'budget_post_dispatch_mutations';
