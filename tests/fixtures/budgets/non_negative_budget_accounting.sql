PRAGMA foreign_keys=ON;

INSERT INTO workflow_authority(workflow,mode,updated_at)
VALUES('fixture-budget-non-negative','file_authority','fixture');

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-non-negative-cost','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability',1,1,'known','fixture-effective',
  'fixture-non-negative-cost-hash'
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-negative-net-reserve','fixture-non-negative-prepare',
  'fixture-budget-non-negative','file_authority','candidate','R1','R1',
  'fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-non-negative-transition','fixture-negative-net-reserve',
  'before','after','budget','release','R1',
  'fixture-non-negative-transition-idem',0,'fixture'
);

PRAGMA ignore_check_constraints=ON;

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  reserved_input_tokens,
  usage_confidence,updated_at
) VALUES(
  'fixture-negative-net-reserve','fixture-budget-non-negative',
  'fixture-capability','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-non-negative-cost','fixture-effective',
  'fixture-non-negative-cost-hash','known','fixture-non-negative-transition',
  10,10,10,10,1,1,-3,'known','fixture'
);

PRAGMA ignore_check_constraints=OFF;

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-over-release','fixture-over-release-idem',
  'fixture-over-release-dedupe',1,'fixture-negative-net-reserve',
  'fixture-non-negative-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-non-negative-cost',
  'fixture-effective','fixture-non-negative-cost-hash','known',
  'release',3,'known','fixture','fixture',1000
);
