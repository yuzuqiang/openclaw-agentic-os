PRAGMA foreign_keys=ON;

INSERT INTO workflow_authority(workflow,mode,updated_at)
VALUES('fixture-budget-ledger','file_authority','fixture');

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-ledger-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability',1,1,'known','fixture-effective','fixture-ledger-cost-hash'
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-ledger-drift','fixture-ledger-prepare','fixture-budget-ledger',
  'file_authority','candidate','R1','R1','fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-ledger-transition','fixture-ledger-drift','before','after',
  'budget','reserve','R1','fixture-ledger-transition-idem',0,'fixture'
);

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  usage_confidence,updated_at
) VALUES(
  'fixture-ledger-drift','fixture-budget-ledger','fixture-capability',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known',
  'fixture-ledger-transition',10,10,10,10,1,1,'known','fixture'
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-ledger-reserve','fixture-ledger-reserve-idem',
  'fixture-ledger-reserve-dedupe',1,'fixture-ledger-drift',
  'fixture-ledger-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known',
  'reserve',3,'known','fixture','fixture',1000
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-consume-over-budget','fixture-consume-over-budget-prepare',
  'fixture-budget-ledger','file_authority','candidate','R1','R1',
  'fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-consume-over-budget-transition','fixture-consume-over-budget',
  'before','after','budget','consume','R1',
  'fixture-consume-over-budget-transition-idem',0,'fixture'
);

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  usage_confidence,updated_at
) VALUES(
  'fixture-consume-over-budget','fixture-budget-ledger','fixture-capability',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known',
  'fixture-consume-over-budget-transition',10,5,10,10,1,1,'known',
  'fixture'
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-consume-over-budget-event','fixture-consume-over-budget-idem',
  'fixture-consume-over-budget-dedupe',1,'fixture-consume-over-budget',
  'fixture-consume-over-budget-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known','consume',6,
  'known','fixture','fixture',1000
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-duplicate-replay','fixture-duplicate-replay-prepare',
  'fixture-budget-ledger','file_authority','candidate','R1','R1',
  'fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-duplicate-replay-transition','fixture-duplicate-replay',
  'before','after','budget','reserve','R1',
  'fixture-duplicate-replay-transition-idem',0,'fixture'
);

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  reserved_input_tokens,usage_confidence,updated_at
) VALUES(
  'fixture-duplicate-replay','fixture-budget-ledger','fixture-capability',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known',
  'fixture-duplicate-replay-transition',10,10,10,10,1,1,2,'known',
  'fixture'
);

ALTER TABLE budget_events RENAME TO budget_events_constrained;
CREATE TABLE budget_events AS SELECT * FROM budget_events_constrained;

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES
(
  'fixture-duplicate-replay-a','fixture-duplicate-replay-a-idem',
  'fixture-duplicate-replay-dedupe',1,'fixture-duplicate-replay',
  'fixture-duplicate-replay-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known','reserve',1,
  'known','fixture','fixture',1000
),
(
  'fixture-duplicate-replay-b','fixture-duplicate-replay-b-idem',
  'fixture-duplicate-replay-dedupe',2,'fixture-duplicate-replay',
  'fixture-duplicate-replay-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-ledger-cost',
  'fixture-effective','fixture-ledger-cost-hash','known','reserve',1,
  'known','fixture','fixture',1001
);
