CREATE UNIQUE INDEX leases_runtime_dispatch_binding_identity_unique
ON leases(
  lease_id,
  run_id,
  transition_id,
  phase,
  agent_id,
  requester_agent_id,
  client_lease_id,
  acquire_idempotency_key,
  release_idempotency_key
);

CREATE TABLE runtime_dispatch_bindings (
  spawn_request_id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL UNIQUE,
  run_id TEXT NOT NULL,
  transition_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  requester_agent_id TEXT NOT NULL,
  task_digest TEXT NOT NULL,
  client_lease_id TEXT NOT NULL UNIQUE,
  acquire_idempotency_key TEXT NOT NULL UNIQUE,
  release_idempotency_key TEXT NOT NULL UNIQUE,
  spawn_client_request_id TEXT NOT NULL UNIQUE,
  spawn_idempotency_key TEXT NOT NULL UNIQUE,
  reserve_budget_event_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (
    spawn_request_id <> ''
    AND lease_id <> ''
    AND run_id <> ''
    AND transition_id <> ''
    AND phase <> ''
    AND agent_id <> ''
    AND requester_agent_id <> ''
    AND task_digest <> ''
    AND client_lease_id <> ''
    AND acquire_idempotency_key <> ''
    AND release_idempotency_key <> ''
    AND spawn_client_request_id <> ''
    AND spawn_idempotency_key <> ''
    AND reserve_budget_event_id <> ''
    AND created_at <> ''
  ),
  FOREIGN KEY (
    spawn_request_id,
    run_id,
    transition_id,
    spawn_client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest
  ) REFERENCES spawn_requests(
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest
  ),
  FOREIGN KEY (
    lease_id,
    run_id,
    transition_id,
    phase,
    agent_id,
    requester_agent_id,
    client_lease_id,
    acquire_idempotency_key,
    release_idempotency_key
  ) REFERENCES leases(
    lease_id,
    run_id,
    transition_id,
    phase,
    agent_id,
    requester_agent_id,
    client_lease_id,
    acquire_idempotency_key,
    release_idempotency_key
  )
) STRICT;

CREATE TEMP TABLE runtime_dispatch_binding_upgrade_candidates AS
SELECT
  i.intent_id AS spawn_intent_id,
  sr.spawn_request_id,
  l.lease_id,
  i.run_id,
  i.transition_id,
  i.phase,
  i.agent_id,
  l.requester_agent_id,
  i.task_digest,
  l.client_lease_id,
  l.acquire_idempotency_key,
  l.release_idempotency_key,
  i.client_request_id AS spawn_client_request_id,
  i.idempotency_key AS spawn_idempotency_key,
  i.reserve_budget_event_id,
  i.requested_at AS created_at
FROM external_rpc_intents i
JOIN spawn_requests sr
  ON sr.spawn_request_id=i.spawn_request_id
  AND sr.run_id=i.run_id
  AND sr.transition_id=i.transition_id
  AND sr.phase=i.phase
  AND sr.agent_id=i.agent_id
  AND sr.task_digest=i.task_digest
  AND sr.client_request_id=i.client_request_id
  AND sr.spawn_idempotency_key=i.idempotency_key
JOIN leases l
  ON l.run_id=i.run_id
  AND l.transition_id=i.transition_id
  AND l.phase=i.phase
  AND l.agent_id=i.agent_id
  AND l.release_idempotency_key IS NOT NULL
  AND l.release_idempotency_key<>''
JOIN external_rpc_intents acquire
  ON acquire.rpc_kind='allow_lease_acquire'
  AND acquire.run_id=l.run_id
  AND acquire.transition_id=l.transition_id
  AND acquire.phase=l.phase
  AND acquire.agent_id=l.agent_id
  AND acquire.requester_agent_id=l.requester_agent_id
  AND acquire.client_request_id=l.client_lease_id
  AND acquire.idempotency_key=l.acquire_idempotency_key
  AND acquire.ttl_ms=l.ttl_ms
  AND acquire.requested_at=i.requested_at
  AND acquire.requested_at_epoch_ms=i.requested_at_epoch_ms
WHERE i.rpc_kind='sessions_spawn';

CREATE TEMP TABLE runtime_dispatch_binding_upgrade_guard (
  valid INTEGER NOT NULL CHECK(valid=1)
);

INSERT INTO runtime_dispatch_binding_upgrade_guard(valid)
SELECT 0
WHERE EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND (SELECT COUNT(*) FROM runtime_dispatch_binding_upgrade_candidates c
         WHERE c.spawn_intent_id=i.intent_id)<>1
)
OR EXISTS (
  SELECT 1
  FROM runtime_dispatch_binding_upgrade_candidates c
  GROUP BY c.lease_id
  HAVING COUNT(*)<>1
);

INSERT INTO runtime_dispatch_bindings(
  spawn_request_id,
  lease_id,
  run_id,
  transition_id,
  phase,
  agent_id,
  requester_agent_id,
  task_digest,
  client_lease_id,
  acquire_idempotency_key,
  release_idempotency_key,
  spawn_client_request_id,
  spawn_idempotency_key,
  reserve_budget_event_id,
  created_at
)
SELECT
  spawn_request_id,
  lease_id,
  run_id,
  transition_id,
  phase,
  agent_id,
  requester_agent_id,
  task_digest,
  client_lease_id,
  acquire_idempotency_key,
  release_idempotency_key,
  spawn_client_request_id,
  spawn_idempotency_key,
  reserve_budget_event_id,
  created_at
FROM runtime_dispatch_binding_upgrade_candidates;

DROP TABLE runtime_dispatch_binding_upgrade_guard;
DROP TABLE runtime_dispatch_binding_upgrade_candidates;

CREATE TRIGGER external_rpc_intents_require_runtime_dispatch_binding_insert
AFTER INSERT ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn' AND NOT EXISTS (
  SELECT 1 FROM runtime_dispatch_bindings b
  WHERE b.spawn_request_id=NEW.spawn_request_id
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.phase=NEW.phase
    AND b.agent_id=NEW.agent_id
    AND b.task_digest=NEW.task_digest
    AND b.reserve_budget_event_id=NEW.reserve_budget_event_id
    AND b.spawn_client_request_id=NEW.client_request_id
    AND b.spawn_idempotency_key=NEW.idempotency_key
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn intent requires runtime dispatch binding');
END;

CREATE TRIGGER external_rpc_intents_require_runtime_dispatch_binding_update
AFTER UPDATE OF rpc_kind, spawn_request_id, reserve_budget_event_id, run_id, transition_id, phase, agent_id, task_digest, client_request_id, idempotency_key ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn' AND NOT EXISTS (
  SELECT 1 FROM runtime_dispatch_bindings b
  WHERE b.spawn_request_id=NEW.spawn_request_id
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.phase=NEW.phase
    AND b.agent_id=NEW.agent_id
    AND b.task_digest=NEW.task_digest
    AND b.reserve_budget_event_id=NEW.reserve_budget_event_id
    AND b.spawn_client_request_id=NEW.client_request_id
    AND b.spawn_idempotency_key=NEW.idempotency_key
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn intent requires runtime dispatch binding');
END;

CREATE TRIGGER runtime_dispatch_bindings_immutable_update
BEFORE UPDATE ON runtime_dispatch_bindings
BEGIN
  SELECT RAISE(ABORT,'runtime dispatch binding is immutable');
END;

CREATE TRIGGER runtime_dispatch_bindings_immutable_delete
BEFORE DELETE ON runtime_dispatch_bindings
BEGIN
  SELECT RAISE(ABORT,'runtime dispatch binding is immutable');
END;
