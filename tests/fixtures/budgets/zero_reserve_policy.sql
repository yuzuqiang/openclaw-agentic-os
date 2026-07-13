PRAGMA foreign_keys=ON;
PRAGMA ignore_check_constraints=ON;

INSERT INTO endpoint_zero_reserve_policies(
  zero_reserve_policy_id,endpoint_binding_id,capability_class,policy_hash,
  enabled,min_retry_units,min_time_seconds,min_human_attention_units,
  effective_from_epoch_ms,effective_until_epoch_ms
) VALUES(
  'fixture-invalid-zero-policy','fixture-endpoint','fixture-capability',
  'fixture-invalid-zero-policy-hash',1,0,0,0,1,2000
);

PRAGMA ignore_check_constraints=OFF;
