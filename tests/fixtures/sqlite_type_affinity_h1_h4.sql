PRAGMA foreign_keys=ON;

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-exact-max-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability',100000000000,100000000000,'known',
  'fixture-effective-max','fixture-exact-max-cost-hash'
);

PRAGMA ignore_check_constraints=ON;

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-numeric-text-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability','1500',0,'known','fixture-effective-text',
  'fixture-numeric-text-cost-hash'
);

INSERT INTO model_cost_registry(
  cost_registry_id,provider,model,endpoint_binding_id,capability_class,
  input_cost_microusd_per_million,output_cost_microusd_per_million,
  confidence,effective_at,registry_row_hash
) VALUES(
  'fixture-integral-real-cost','fixture-provider','fixture-model','fixture-endpoint',
  'fixture-capability',1500.0,0,'known','fixture-effective-real',
  'fixture-integral-real-cost-hash'
);

PRAGMA ignore_check_constraints=OFF;
