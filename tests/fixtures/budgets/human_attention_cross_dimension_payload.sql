PRAGMA foreign_keys=ON;

INSERT INTO workflow_authority(workflow,mode,updated_at)
VALUES('fixture-budget-human','file_authority','fixture');

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-human-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability',1,1,'known','fixture-effective','fixture-human-cost-hash'
);

INSERT INTO endpoint_zero_reserve_policies(
  zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,
  min_human_attention_units,effective_from_epoch_ms,effective_until_epoch_ms
) VALUES(
  'fixture-human-zero-policy','fixture-endpoint','fixture-capability',
  'fixture-human-zero-policy-hash',1,1,2000
);

INSERT INTO runs(
  run_id,prepare_idempotency_key,workflow,authority_mode,state,
  risk_class,risk_dominance,created_at,updated_at
) VALUES(
  'fixture-human-cross-dimension','fixture-human-prepare',
  'fixture-budget-human','file_authority','candidate','R1','R1',
  'fixture','fixture'
);

INSERT INTO transitions(
  transition_id,run_id,state_before,state_after,transition_type,action_type,
  risk_dominance,idempotency_key,guard_version_before,created_at
) VALUES(
  'fixture-human-transition','fixture-human-cross-dimension','before','after',
  'budget','human_attention','R1','fixture-human-transition-idem',0,'fixture'
);

INSERT INTO run_budgets(
  run_id,workflow,capability_class,selected_provider,selected_model,
  selected_endpoint_binding_id,selected_cost_registry_id,
  selected_cost_effective_at,selected_cost_registry_hash,
  selected_cost_confidence,selected_reserve_transition_id,
  time_budget_seconds,input_token_budget,output_token_budget,
  cost_budget_microusd,retry_budget,human_attention_budget,
  consumed_human_attention,usage_confidence,updated_at
) VALUES(
  'fixture-human-cross-dimension','fixture-budget-human','fixture-capability',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-human-cost',
  'fixture-effective','fixture-human-cost-hash','known',
  'fixture-human-transition',10,10,10,10,1,1,1,'known','fixture'
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  zero_reserve_policy_id,zero_reserve_policy_hash,event_type,
  human_attention_units,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-human-reserve','fixture-human-reserve-idem',
  'fixture-human-reserve-dedupe',1,'fixture-human-cross-dimension',
  'fixture-human-transition','fixture-provider','fixture-model',
  'fixture-endpoint','fixture-capability','fixture-human-cost',
  'fixture-effective','fixture-human-cost-hash','known',
  'fixture-human-zero-policy','fixture-human-zero-policy-hash','reserve',
  1,'known','fixture','fixture',1000
);

PRAGMA ignore_check_constraints=ON;

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,capability_class,event_type,input_tokens,
  human_attention_units,usage_confidence,source,created_at,created_at_epoch_ms
) VALUES(
  'fixture-human-cross-payload','fixture-human-cross-payload-idem',
  'fixture-human-cross-payload-dedupe',2,'fixture-human-cross-dimension',
  'fixture-human-transition','fixture-capability','human_attention',1,1,
  'known','fixture','fixture',1001
);

INSERT INTO budget_events(
  budget_event_id,event_idempotency_key,event_dedupe_hash,event_sequence,
  run_id,transition_id,provider,model,endpoint_binding_id,capability_class,
  cost_registry_id,cost_effective_at,cost_registry_hash,cost_confidence,
  event_type,input_tokens,human_attention_units,usage_confidence,source,created_at,
  created_at_epoch_ms
) VALUES(
  'fixture-consume-carries-human-attention',
  'fixture-consume-carries-human-attention-idem',
  'fixture-consume-carries-human-attention-dedupe',3,
  'fixture-human-cross-dimension','fixture-human-transition',
  'fixture-provider','fixture-model','fixture-endpoint','fixture-capability',
  'fixture-human-cost','fixture-effective','fixture-human-cost-hash',
  'known','consume',1,1,'known','fixture','fixture',1002
);

PRAGMA ignore_check_constraints=OFF;
