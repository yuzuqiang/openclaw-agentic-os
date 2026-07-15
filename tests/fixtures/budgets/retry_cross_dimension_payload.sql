PRAGMA foreign_keys=ON;

INSERT INTO workflow_authority(workflow,mode,updated_at)
VALUES('fixture-budget-retry','file_authority','fixture');

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-retry-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability',1,1,'known','fixture-effective','fixture-retry-cost-hash'
);

INSERT INTO endpoint_zero_reserve_policies(
  zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,
  min_retry_units,effective_from_epoch_ms,effective_until_epoch_ms
) VALUES(
  'fixture-retry-zero-policy','fixture-endpoint','fixture-capability',
  'fixture-retry-zero-policy-hash',1,1,2000
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-retry-cross-dimension','fixture-retry-prepare',
  'fixture-budget-retry','file_authority','candidate','R1','R1',
  'fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-retry-transition','fixture-retry-cross-dimension','before','after',
  'budget','retry','R1','fixture-retry-transition-idem',0,'fixture'
);

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  reserved_retries,usage_confidence,updated_at
) VALUES(
  'fixture-retry-cross-dimension','fixture-budget-retry','fixture-capability',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-retry-cost',
  'fixture-effective','fixture-retry-cost-hash','known',
  'fixture-retry-transition',10,10,10,10,2,1,2,'known','fixture'
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  zero_reserve_policy_id,zero_reserve_policy_hash,event_type,retry_units,
  usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-retry-reserve','fixture-retry-reserve-idem',
  'fixture-retry-reserve-dedupe',1,'fixture-retry-cross-dimension',
  'fixture-retry-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-retry-cost',
  'fixture-effective','fixture-retry-cost-hash','known',
  'fixture-retry-zero-policy','fixture-retry-zero-policy-hash','reserve',
  2,'known','fixture','fixture',1000
);

PRAGMA ignore_check_constraints=ON;

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,retry_units,usage_confidence,source,created_at,
  created_at_epoch_ms
) VALUES(
  'fixture-consume-carries-retry','fixture-consume-carries-retry-idem',
  'fixture-consume-carries-retry-dedupe',2,
  'fixture-retry-cross-dimension','fixture-retry-transition',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-capability',
  'fixture-retry-cost','fixture-effective','fixture-retry-cost-hash',
  'known','consume',1,1,'known','fixture','fixture',1001
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,retry_units,usage_confidence,source,created_at,
  created_at_epoch_ms
) VALUES(
  'fixture-retry-decrement-cross-payload',
  'fixture-retry-decrement-cross-payload-idem',
  'fixture-retry-decrement-cross-payload-dedupe',3,
  'fixture-retry-cross-dimension','fixture-retry-transition',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-capability',
  'fixture-retry-cost','fixture-effective','fixture-retry-cost-hash',
  'known','retry_decrement',1,1,'known','fixture','fixture',1002
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,human_attention_units,retry_units,usage_confidence,source,
  created_at,created_at_epoch_ms
) VALUES(
  'fixture-retry-restore-cross-payload',
  'fixture-retry-restore-cross-payload-idem',
  'fixture-retry-restore-cross-payload-dedupe',4,
  'fixture-retry-cross-dimension','fixture-retry-transition',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-capability',
  'fixture-retry-cost','fixture-effective','fixture-retry-cost-hash',
  'known','retry_restore',1,1,'known','fixture','fixture',1003
);

PRAGMA ignore_check_constraints=OFF;
