CREATE TABLE schema_migrations (
  version ANY PRIMARY KEY,
  name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  CHECK (typeof(version)='integer' AND version > 0),
  UNIQUE(version,sha256)
) STRICT;

CREATE TABLE gate_clock_context (
  clock_context_id TEXT PRIMARY KEY,
  gate_run_id TEXT NOT NULL UNIQUE REFERENCES gate_runs(gate_run_id) DEFERRABLE INITIALLY DEFERRED,
  consumed_by_gate_run_id TEXT NOT NULL UNIQUE REFERENCES gate_runs(gate_run_id) DEFERRABLE INITIALLY DEFERRED,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT NOT NULL REFERENCES transitions(transition_id),
  gate_nonce TEXT NOT NULL UNIQUE,
  now_epoch_ms ANY NOT NULL,
  bound_at_epoch_ms ANY NOT NULL,
  bound_by TEXT NOT NULL,
  trusted_clock_source_hash TEXT NOT NULL,
  consumed_at_epoch_ms ANY NOT NULL,
  CHECK (typeof(now_epoch_ms)='integer' AND now_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(bound_at_epoch_ms)='integer' AND bound_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (bound_at_epoch_ms = now_epoch_ms),
  CHECK (typeof(consumed_at_epoch_ms)='integer' AND consumed_at_epoch_ms = now_epoch_ms),
  CHECK (gate_run_id = consumed_by_gate_run_id),
  CHECK (clock_context_id <> '' AND gate_run_id <> '' AND run_id <> '' AND transition_id <> ''),
  CHECK (gate_nonce <> '' AND bound_by <> '' AND trusted_clock_source_hash <> ''),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TABLE workflow_authority (
  workflow TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK (mode IN (
    'file_authority',
    'file_authority_shadow',
    'dual_write_shadow',
    'db_authority_canary',
    'db_authority',
    'rollback_to_file_authority'
  )),
  cutover_approved_by TEXT,
  cutover_evidence_hash TEXT,
  rollback_deadline TEXT,
  last_parity_audit_hash TEXT,
  open_file_authority_runs ANY NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  CHECK (typeof(open_file_authority_runs)='integer' AND open_file_authority_runs >= 0),
  CHECK (
    mode NOT IN ('db_authority_canary','db_authority') OR (
      cutover_approved_by IS NOT NULL AND cutover_approved_by <> ''
      AND cutover_evidence_hash IS NOT NULL AND cutover_evidence_hash <> ''
      AND rollback_deadline IS NOT NULL AND rollback_deadline <> ''
      AND last_parity_audit_hash IS NOT NULL AND last_parity_audit_hash <> ''
      AND open_file_authority_runs = 0
    )
  ),
  UNIQUE(workflow,mode)
) STRICT;

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  prepare_idempotency_key TEXT NOT NULL UNIQUE,
  workflow TEXT NOT NULL REFERENCES workflow_authority(workflow),
  authority_mode TEXT NOT NULL,
  state TEXT NOT NULL,
  state_version ANY NOT NULL DEFAULT 0,
  risk_class TEXT NOT NULL,
  risk_dominance TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finalized_at TEXT,
  finalized_at_epoch_ms ANY,
  CHECK (typeof(state_version)='integer' AND state_version >= 0),
  CHECK (finalized_at_epoch_ms IS NULL OR (typeof(finalized_at_epoch_ms)='integer' AND finalized_at_epoch_ms BETWEEN 1 AND 253402300799999)),
  CHECK (state IN (
    'candidate',
    'triaged',
    'planned',
    'prepared',
    'dispatch_ready',
    'lease_not_required',
    'lease_acquire_pending',
    'lease_acquired',
    'lease_unavailable',
    'spawn_pending',
    'spawn_requested',
    'spawn_unknown',
    'dispatched',
    'first_output_waiting',
    'running',
    'child_completed',
    'child_failed',
    'child_skipped',
    'handshake_timeout',
    'aggregation_completed',
    'judge_verifier_completed',
    'judge_verifier_failed',
    'gate_passed',
    'gate_failed',
    'human_review_required',
    'release_pending',
    'finalized',
    'rolled_back',
    'rejected'
  )),
  CHECK (authority_mode IN (
    'file_authority',
    'file_authority_shadow',
    'dual_write_shadow',
    'db_authority_canary',
    'db_authority',
    'rollback_to_file_authority'
  )),
  CHECK (risk_dominance IN ('R0','R1','R2','R3','R4'))
) STRICT;

CREATE TRIGGER runs_validate_db_authority_insert
BEFORE INSERT ON runs
WHEN NEW.authority_mode IN ('db_authority_canary','db_authority')
  AND NOT EXISTS (
    SELECT 1 FROM workflow_authority w
    WHERE w.workflow=NEW.workflow
      AND w.mode=NEW.authority_mode
      AND w.cutover_approved_by IS NOT NULL AND w.cutover_approved_by <> ''
      AND w.cutover_evidence_hash IS NOT NULL AND w.cutover_evidence_hash <> ''
      AND w.rollback_deadline IS NOT NULL AND w.rollback_deadline <> ''
      AND w.last_parity_audit_hash IS NOT NULL AND w.last_parity_audit_hash <> ''
      AND w.open_file_authority_runs = 0
  )
BEGIN
  SELECT RAISE(ABORT,'db authority run requires active workflow cutover evidence');
END;

CREATE TRIGGER runs_validate_db_authority_update
BEFORE UPDATE OF workflow, authority_mode ON runs
WHEN NEW.authority_mode IN ('db_authority_canary','db_authority')
  AND NOT EXISTS (
    SELECT 1 FROM workflow_authority w
    WHERE w.workflow=NEW.workflow
      AND w.mode=NEW.authority_mode
      AND w.cutover_approved_by IS NOT NULL AND w.cutover_approved_by <> ''
      AND w.cutover_evidence_hash IS NOT NULL AND w.cutover_evidence_hash <> ''
      AND w.rollback_deadline IS NOT NULL AND w.rollback_deadline <> ''
      AND w.last_parity_audit_hash IS NOT NULL AND w.last_parity_audit_hash <> ''
      AND w.open_file_authority_runs = 0
  )
BEGIN
  SELECT RAISE(ABORT,'db authority run requires active workflow cutover evidence');
END;

CREATE TABLE transitions (
  transition_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  state_before TEXT NOT NULL,
  state_after TEXT NOT NULL,
  transition_type TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  target_hash TEXT,
  target_scope TEXT,
  approval_required ANY NOT NULL DEFAULT 0,
  approval_id TEXT UNIQUE REFERENCES approvals(approval_id),
  approval_channel TEXT,
  approval_source_digest TEXT,
  approval_text_digest TEXT,
  risk_dominance TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  guard_version_before ANY NOT NULL,
  gate_run_id TEXT REFERENCES gate_runs(gate_run_id) DEFERRABLE INITIALLY DEFERRED,
  evidence_hash TEXT,
  created_at TEXT NOT NULL,
  CHECK (typeof(approval_required)='integer' AND approval_required IN (0,1)),
  CHECK (typeof(guard_version_before)='integer' AND guard_version_before >= 0),
  CHECK (
    approval_required = 0 OR (
      approval_id IS NOT NULL
      AND action_type <> ''
      AND target_type IS NOT NULL AND target_type <> ''
      AND target_id IS NOT NULL AND target_id <> ''
      AND target_hash IS NOT NULL AND target_hash <> ''
      AND target_scope IS NOT NULL AND target_scope <> ''
      AND approval_channel IS NOT NULL AND approval_channel <> ''
      AND approval_source_digest IS NOT NULL AND approval_source_digest <> ''
      AND approval_text_digest IS NOT NULL AND approval_text_digest <> ''
      AND gate_run_id IS NOT NULL AND gate_run_id <> ''
    )
  ),
  UNIQUE(transition_id,run_id),
  FOREIGN KEY(
    approval_id,
    run_id,
    action_type,
    target_type,
    target_id,
    target_hash,
    target_scope,
    approval_channel,
    approval_source_digest,
    approval_text_digest,
    transition_id,
    gate_run_id
  ) REFERENCES approvals(
    approval_id,
    run_id,
    approved_action_type,
    target_type,
    target_id,
    target_hash,
    target_scope,
    channel,
    source_message_digest,
    approval_text_digest,
    consumed_by_transition_id,
    consumed_by_gate_run_id
  ) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE external_rpc_intents (
  intent_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT NOT NULL,
  rpc_kind TEXT NOT NULL CHECK (rpc_kind IN ('allow_lease_acquire','allow_lease_release','sessions_spawn')),
  spawn_request_id TEXT,
  reserve_budget_event_id TEXT REFERENCES budget_events(budget_event_id),
  client_request_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL UNIQUE,
  phase TEXT,
  agent_id TEXT,
  task_digest TEXT,
  metadata_contract_version TEXT,
  metadata_json TEXT NOT NULL,
  external_metadata_json TEXT,
  external_run_id TEXT,
  external_transition_id TEXT,
  external_client_request_id TEXT,
  external_idempotency_key TEXT,
  external_phase TEXT,
  external_agent_id TEXT,
  external_task_digest TEXT,
  state TEXT NOT NULL CHECK (state IN ('pending','accepted','unknown','failed','reconciled','human_review_required')),
  external_id TEXT,
  requested_at TEXT NOT NULL,
  requested_at_epoch_ms ANY NOT NULL,
  accepted_at TEXT,
  accepted_at_epoch_ms ANY,
  resolved_at TEXT,
  resolved_at_epoch_ms ANY,
  CHECK (typeof(requested_at_epoch_ms)='integer' AND requested_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (accepted_at_epoch_ms IS NULL OR (typeof(accepted_at_epoch_ms)='integer' AND accepted_at_epoch_ms BETWEEN 1 AND 253402300799999)),
  CHECK (resolved_at_epoch_ms IS NULL OR (typeof(resolved_at_epoch_ms)='integer' AND resolved_at_epoch_ms BETWEEN 1 AND 253402300799999)),
  CHECK (
    rpc_kind <> 'sessions_spawn' OR (
      spawn_request_id IS NOT NULL
      AND reserve_budget_event_id IS NOT NULL
      AND phase IS NOT NULL AND phase <> ''
      AND agent_id IS NOT NULL AND agent_id <> ''
      AND task_digest IS NOT NULL AND task_digest <> ''
    )
  ),
  CHECK (
    rpc_kind <> 'sessions_spawn'
    OR state IN ('pending','unknown','failed','human_review_required')
    OR (
      metadata_contract_version IS NOT NULL AND metadata_contract_version <> ''
      AND external_metadata_json IS NOT NULL AND json_valid(external_metadata_json)
      AND external_id IS NOT NULL AND external_id <> ''
      AND external_run_id = run_id
      AND external_transition_id = transition_id
      AND external_client_request_id = client_request_id
      AND external_idempotency_key = idempotency_key
      AND external_phase = phase
      AND external_agent_id = agent_id
      AND external_task_digest = task_digest
    )
  ),
  CHECK (
    rpc_kind <> 'sessions_spawn'
    OR external_metadata_json IS NULL
    OR CASE
      WHEN json_valid(external_metadata_json) THEN CASE
        WHEN json_type(external_metadata_json,'$.run_id')='text'
          AND json_type(external_metadata_json,'$.transition_id')='text'
          AND json_type(external_metadata_json,'$.client_request_id')='text'
          AND json_type(external_metadata_json,'$.idempotency_key')='text'
          AND json_type(external_metadata_json,'$.phase')='text'
          AND json_type(external_metadata_json,'$.agent_id')='text'
          AND json_type(external_metadata_json,'$.task_digest')='text'
          AND json_extract(external_metadata_json,'$.run_id') = run_id
          AND json_extract(external_metadata_json,'$.transition_id') = transition_id
          AND json_extract(external_metadata_json,'$.client_request_id') = client_request_id
          AND json_extract(external_metadata_json,'$.idempotency_key') = idempotency_key
          AND json_extract(external_metadata_json,'$.phase') = phase
          AND json_extract(external_metadata_json,'$.agent_id') = agent_id
          AND json_extract(external_metadata_json,'$.task_digest') = task_digest
          AND external_run_id = run_id
          AND external_transition_id = transition_id
          AND external_client_request_id = client_request_id
          AND external_idempotency_key = idempotency_key
          AND external_phase = phase
          AND external_agent_id = agent_id
          AND external_task_digest = task_digest
        THEN 1 ELSE 0 END
      ELSE 0 END
  ),
  CHECK (
    rpc_kind <> 'allow_lease_release'
    OR state IN ('pending','unknown','failed','human_review_required')
    OR (
      metadata_contract_version IS NOT NULL AND metadata_contract_version <> ''
      AND external_metadata_json IS NOT NULL AND json_valid(external_metadata_json)
      AND external_id IS NOT NULL AND external_id <> ''
      AND external_run_id = run_id
      AND external_transition_id = transition_id
      AND external_idempotency_key = idempotency_key
    )
  ),
  CHECK (
    rpc_kind <> 'allow_lease_release'
    OR external_metadata_json IS NULL
    OR CASE
      WHEN json_valid(external_metadata_json) THEN CASE
        WHEN json_type(external_metadata_json,'$.run_id')='text'
          AND json_type(external_metadata_json,'$.transition_id')='text'
          AND json_type(external_metadata_json,'$.idempotency_key')='text'
          AND json_type(external_metadata_json,'$.gateway_lease_id')='text'
          AND json_extract(external_metadata_json,'$.run_id') <> ''
          AND json_extract(external_metadata_json,'$.transition_id') <> ''
          AND json_extract(external_metadata_json,'$.idempotency_key') <> ''
          AND json_extract(external_metadata_json,'$.gateway_lease_id') <> ''
          AND json_extract(external_metadata_json,'$.run_id') = run_id
          AND json_extract(external_metadata_json,'$.transition_id') = transition_id
          AND json_extract(external_metadata_json,'$.idempotency_key') = idempotency_key
          AND json_extract(external_metadata_json,'$.gateway_lease_id') = external_id
          AND external_run_id = run_id
          AND external_transition_id = transition_id
          AND external_idempotency_key = idempotency_key
        THEN 1 ELSE 0 END
      ELSE 0 END
  ),
  CHECK (external_metadata_json IS NULL OR json_valid(external_metadata_json)=1),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id),
  FOREIGN KEY (
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    idempotency_key,
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
  )
) STRICT;

CREATE TABLE leases (
  lease_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  transition_id TEXT NOT NULL REFERENCES transitions(transition_id),
  agent_id TEXT NOT NULL,
  requester_agent_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('acquire_pending','acquired','release_pending','released','release_not_required','expired','human_review_required')),
  gateway_lease_id TEXT,
  client_lease_id TEXT NOT NULL UNIQUE,
  acquire_idempotency_key TEXT NOT NULL UNIQUE,
  release_idempotency_key TEXT UNIQUE,
  ttl_ms ANY NOT NULL,
  metadata_contract_version TEXT,
  metadata_observed_at TEXT,
  external_metadata_json TEXT,
  external_client_lease_id TEXT,
  external_idempotency_key TEXT,
  external_run_id TEXT,
  external_phase TEXT,
  external_transition_id TEXT,
  external_agent_id TEXT,
  external_requester_agent_id TEXT,
  external_ttl_ms ANY,
  acquire_requested_at TEXT,
  acquired_at TEXT,
  release_requested_at TEXT,
  released_at TEXT,
  expires_at TEXT NOT NULL,
  expires_at_epoch_ms ANY NOT NULL,
  reconciliation_status TEXT NOT NULL DEFAULT 'not_needed',
  CHECK (typeof(ttl_ms)='integer' AND ttl_ms BETWEEN 1 AND 31536000000),
  CHECK (typeof(expires_at_epoch_ms)='integer' AND expires_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (external_ttl_ms IS NULL OR (typeof(external_ttl_ms)='integer' AND external_ttl_ms BETWEEN 1 AND 31536000000)),
  CHECK (
    lease_id <> ''
    AND run_id <> ''
    AND phase <> ''
    AND transition_id <> ''
    AND agent_id <> ''
    AND requester_agent_id <> ''
    AND client_lease_id <> ''
    AND acquire_idempotency_key <> ''
  ),
  CHECK (external_metadata_json IS NULL OR json_valid(external_metadata_json)=1),
  CHECK (
    state NOT IN ('acquired','release_pending','released') OR COALESCE((
      gateway_lease_id IS NOT NULL AND gateway_lease_id <> ''
      AND metadata_contract_version IS NOT NULL AND metadata_contract_version <> ''
      AND metadata_observed_at IS NOT NULL AND metadata_observed_at <> ''
      AND external_metadata_json IS NOT NULL
      AND json_valid(external_metadata_json)=1
      AND external_client_lease_id IS NOT NULL AND external_client_lease_id <> ''
      AND external_idempotency_key IS NOT NULL AND external_idempotency_key <> ''
      AND external_run_id IS NOT NULL AND external_run_id <> ''
      AND external_phase IS NOT NULL AND external_phase <> ''
      AND external_transition_id IS NOT NULL AND external_transition_id <> ''
      AND external_agent_id IS NOT NULL AND external_agent_id <> ''
      AND external_requester_agent_id IS NOT NULL AND external_requester_agent_id <> ''
      AND external_client_lease_id=client_lease_id
      AND external_idempotency_key=acquire_idempotency_key
      AND external_run_id=run_id
      AND external_phase=phase
      AND external_transition_id=transition_id
      AND external_agent_id=agent_id
      AND external_requester_agent_id=requester_agent_id
      AND external_ttl_ms=ttl_ms
      AND json_type(external_metadata_json,'$.client_lease_id')='text'
      AND json_type(external_metadata_json,'$.idempotency_key')='text'
      AND json_type(external_metadata_json,'$.run_id')='text'
      AND json_type(external_metadata_json,'$.phase')='text'
      AND json_type(external_metadata_json,'$.transition_id')='text'
      AND json_type(external_metadata_json,'$.agent_id')='text'
      AND json_type(external_metadata_json,'$.requester_agent_id')='text'
      AND json_type(external_metadata_json,'$.ttl_ms')='integer'
      AND json_extract(external_metadata_json,'$.client_lease_id') <> ''
      AND json_extract(external_metadata_json,'$.idempotency_key') <> ''
      AND json_extract(external_metadata_json,'$.run_id') <> ''
      AND json_extract(external_metadata_json,'$.phase') <> ''
      AND json_extract(external_metadata_json,'$.transition_id') <> ''
      AND json_extract(external_metadata_json,'$.agent_id') <> ''
      AND json_extract(external_metadata_json,'$.requester_agent_id') <> ''
      AND json_extract(external_metadata_json,'$.client_lease_id')=client_lease_id
      AND json_extract(external_metadata_json,'$.idempotency_key')=acquire_idempotency_key
      AND json_extract(external_metadata_json,'$.run_id')=run_id
      AND json_extract(external_metadata_json,'$.phase')=phase
      AND json_extract(external_metadata_json,'$.transition_id')=transition_id
      AND json_extract(external_metadata_json,'$.agent_id')=agent_id
      AND json_extract(external_metadata_json,'$.requester_agent_id')=requester_agent_id
      AND json_extract(external_metadata_json,'$.ttl_ms')=ttl_ms
    ),0)=1
  ),
  CHECK (
    state NOT IN ('release_pending','released') OR (
      release_idempotency_key IS NOT NULL AND release_idempotency_key <> ''
      AND release_requested_at IS NOT NULL AND release_requested_at <> ''
    )
  ),
  CHECK (
    state <> 'released' OR (
      released_at IS NOT NULL AND released_at <> ''
    )
  ),
  CHECK (
    state <> 'release_not_required' OR (
      gateway_lease_id IS NULL
      AND release_idempotency_key IS NULL
      AND release_requested_at IS NULL
      AND released_at IS NULL
    )
  ),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE UNIQUE INDEX leases_live_gateway_lease_id_unique
ON leases(gateway_lease_id)
WHERE gateway_lease_id IS NOT NULL AND state IN ('acquired','release_pending');

CREATE TRIGGER external_rpc_intents_reject_duplicate_metadata_insert
BEFORE INSERT ON external_rpc_intents
WHEN NEW.external_metadata_json IS NOT NULL AND EXISTS (
  SELECT 1 FROM json_each(NEW.external_metadata_json) GROUP BY key HAVING COUNT(*) > 1
)
BEGIN
  SELECT RAISE(ABORT,'duplicate external metadata key');
END;

CREATE TRIGGER external_rpc_intents_reject_duplicate_metadata_update
BEFORE UPDATE OF external_metadata_json ON external_rpc_intents
WHEN NEW.external_metadata_json IS NOT NULL AND EXISTS (
  SELECT 1 FROM json_each(NEW.external_metadata_json) GROUP BY key HAVING COUNT(*) > 1
)
BEGIN
  SELECT RAISE(ABORT,'duplicate external metadata key');
END;

CREATE TRIGGER leases_reject_duplicate_metadata_insert
BEFORE INSERT ON leases
WHEN NEW.external_metadata_json IS NOT NULL AND EXISTS (
  SELECT 1 FROM json_each(NEW.external_metadata_json) GROUP BY key HAVING COUNT(*) > 1
)
BEGIN
  SELECT RAISE(ABORT,'duplicate external metadata key');
END;

CREATE TRIGGER leases_reject_duplicate_metadata_update
BEFORE UPDATE OF external_metadata_json ON leases
WHEN NEW.external_metadata_json IS NOT NULL AND EXISTS (
  SELECT 1 FROM json_each(NEW.external_metadata_json) GROUP BY key HAVING COUNT(*) > 1
)
BEGIN
  SELECT RAISE(ABORT,'duplicate external metadata key');
END;

CREATE TRIGGER external_rpc_intents_preserve_released_lease_delete
BEFORE DELETE ON external_rpc_intents
WHEN OLD.rpc_kind='allow_lease_release'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state='released'
      AND l.run_id=OLD.run_id
      AND l.transition_id=OLD.transition_id
      AND l.release_idempotency_key=OLD.idempotency_key
      AND l.gateway_lease_id=OLD.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'released lease requires release intent proof');
END;

CREATE TRIGGER external_rpc_intents_preserve_released_lease_update
BEFORE UPDATE OF rpc_kind, state, run_id, transition_id, idempotency_key, external_id ON external_rpc_intents
WHEN OLD.rpc_kind='allow_lease_release'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state='released'
      AND l.run_id=OLD.run_id
      AND l.transition_id=OLD.transition_id
      AND l.release_idempotency_key=OLD.idempotency_key
      AND l.gateway_lease_id=OLD.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'released lease requires release intent proof');
END;

CREATE TABLE spawn_requests (
  spawn_request_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  transition_id TEXT NOT NULL REFERENCES transitions(transition_id),
  client_request_id TEXT NOT NULL UNIQUE,
  spawn_idempotency_key TEXT NOT NULL UNIQUE,
  task_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','accepted','unknown','failed','human_review_required','completed')),
  session_key TEXT,
  dispatch_run_id TEXT,
  metadata_contract_version TEXT,
  metadata_observed_at TEXT,
  external_metadata_json TEXT,
  ambiguity_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(session_key),
  CHECK (state NOT IN ('accepted','completed') OR (session_key IS NOT NULL AND session_key <> '')),
  UNIQUE(
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest
  ),
  UNIQUE(
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest,
    session_key
  ),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  spawn_request_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  client_request_id TEXT NOT NULL UNIQUE,
  spawn_idempotency_key TEXT NOT NULL,
  session_key TEXT NOT NULL UNIQUE,
  task_digest TEXT NOT NULL,
  status_metadata_json TEXT,
  first_output_hash TEXT,
  state TEXT NOT NULL,
  spawned_at TEXT,
  first_output_at TEXT,
  completed_at TEXT,
  CHECK (session_id <> '' AND spawn_request_id <> '' AND run_id <> '' AND transition_id <> ''),
  CHECK (phase <> '' AND agent_id <> '' AND client_request_id <> '' AND spawn_idempotency_key <> ''),
  CHECK (session_key <> '' AND task_digest <> ''),
  FOREIGN KEY (
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest,
    session_key
  ) REFERENCES spawn_requests(
    spawn_request_id,
    run_id,
    transition_id,
    client_request_id,
    spawn_idempotency_key,
    phase,
    agent_id,
    task_digest,
    session_key
  ) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER spawn_requests_validate_acceptance_insert
AFTER INSERT ON spawn_requests
WHEN NEW.state IN ('accepted','completed') AND (
  NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='sessions_spawn'
      AND eri.state IN ('accepted','reconciled')
      AND eri.spawn_request_id=NEW.spawn_request_id
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.client_request_id=NEW.client_request_id
      AND eri.idempotency_key=NEW.spawn_idempotency_key
      AND eri.phase=NEW.phase
      AND eri.agent_id=NEW.agent_id
      AND eri.task_digest=NEW.task_digest
      AND eri.external_id=NEW.session_key
  )
  OR NOT EXISTS (
    SELECT 1 FROM sessions s
    WHERE s.spawn_request_id=NEW.spawn_request_id
      AND s.run_id=NEW.run_id
      AND s.transition_id=NEW.transition_id
      AND s.client_request_id=NEW.client_request_id
      AND s.spawn_idempotency_key=NEW.spawn_idempotency_key
      AND s.phase=NEW.phase
      AND s.agent_id=NEW.agent_id
      AND s.task_digest=NEW.task_digest
      AND s.session_key=NEW.session_key
  )
)
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires external intent and session proof');
END;

CREATE TRIGGER spawn_requests_validate_acceptance_update
AFTER UPDATE OF state, session_key, run_id, transition_id, client_request_id, spawn_idempotency_key, phase, agent_id, task_digest ON spawn_requests
WHEN NEW.state IN ('accepted','completed') AND (
  NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='sessions_spawn'
      AND eri.state IN ('accepted','reconciled')
      AND eri.spawn_request_id=NEW.spawn_request_id
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.client_request_id=NEW.client_request_id
      AND eri.idempotency_key=NEW.spawn_idempotency_key
      AND eri.phase=NEW.phase
      AND eri.agent_id=NEW.agent_id
      AND eri.task_digest=NEW.task_digest
      AND eri.external_id=NEW.session_key
  )
  OR NOT EXISTS (
    SELECT 1 FROM sessions s
    WHERE s.spawn_request_id=NEW.spawn_request_id
      AND s.run_id=NEW.run_id
      AND s.transition_id=NEW.transition_id
      AND s.client_request_id=NEW.client_request_id
      AND s.spawn_idempotency_key=NEW.spawn_idempotency_key
      AND s.phase=NEW.phase
      AND s.agent_id=NEW.agent_id
      AND s.task_digest=NEW.task_digest
      AND s.session_key=NEW.session_key
  )
)
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires external intent and session proof');
END;

CREATE TRIGGER sessions_preserve_spawn_acceptance_delete
BEFORE DELETE ON sessions
WHEN EXISTS (
  SELECT 1 FROM spawn_requests sr
  WHERE sr.state IN ('accepted','completed')
    AND sr.spawn_request_id=OLD.spawn_request_id
    AND sr.run_id=OLD.run_id
    AND sr.transition_id=OLD.transition_id
    AND sr.client_request_id=OLD.client_request_id
    AND sr.spawn_idempotency_key=OLD.spawn_idempotency_key
    AND sr.phase=OLD.phase
    AND sr.agent_id=OLD.agent_id
    AND sr.task_digest=OLD.task_digest
    AND sr.session_key=OLD.session_key
)
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires session proof');
END;

CREATE TRIGGER sessions_preserve_spawn_acceptance_update
BEFORE UPDATE OF spawn_request_id, run_id, transition_id, client_request_id, spawn_idempotency_key, phase, agent_id, task_digest, session_key ON sessions
WHEN EXISTS (
  SELECT 1 FROM spawn_requests sr
  WHERE sr.state IN ('accepted','completed')
    AND sr.spawn_request_id=OLD.spawn_request_id
    AND sr.run_id=OLD.run_id
    AND sr.transition_id=OLD.transition_id
    AND sr.client_request_id=OLD.client_request_id
    AND sr.spawn_idempotency_key=OLD.spawn_idempotency_key
    AND sr.phase=OLD.phase
    AND sr.agent_id=OLD.agent_id
    AND sr.task_digest=OLD.task_digest
    AND sr.session_key=OLD.session_key
)
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires session proof');
END;

CREATE TRIGGER external_rpc_intents_preserve_spawn_acceptance_delete
BEFORE DELETE ON external_rpc_intents
WHEN OLD.rpc_kind='sessions_spawn'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM spawn_requests sr
    WHERE sr.state IN ('accepted','completed')
      AND sr.spawn_request_id=OLD.spawn_request_id
      AND sr.run_id=OLD.run_id
      AND sr.transition_id=OLD.transition_id
      AND sr.client_request_id=OLD.client_request_id
      AND sr.spawn_idempotency_key=OLD.idempotency_key
      AND sr.phase=OLD.phase
      AND sr.agent_id=OLD.agent_id
      AND sr.task_digest=OLD.task_digest
      AND sr.session_key=OLD.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires external intent proof');
END;

CREATE TRIGGER external_rpc_intents_preserve_spawn_acceptance_update
BEFORE UPDATE OF rpc_kind, state, spawn_request_id, run_id, transition_id, client_request_id, idempotency_key, phase, agent_id, task_digest, external_id ON external_rpc_intents
WHEN OLD.rpc_kind='sessions_spawn'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM spawn_requests sr
    WHERE sr.state IN ('accepted','completed')
      AND sr.spawn_request_id=OLD.spawn_request_id
      AND sr.run_id=OLD.run_id
      AND sr.transition_id=OLD.transition_id
      AND sr.client_request_id=OLD.client_request_id
      AND sr.spawn_idempotency_key=OLD.idempotency_key
      AND sr.phase=OLD.phase
      AND sr.agent_id=OLD.agent_id
      AND sr.task_digest=OLD.task_digest
      AND sr.session_key=OLD.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request requires external intent proof');
END;

CREATE TRIGGER leases_validate_release_proof_insert
AFTER INSERT ON leases
WHEN NEW.state='released' AND NOT EXISTS (
  SELECT 1 FROM external_rpc_intents eri
  WHERE eri.rpc_kind='allow_lease_release'
    AND eri.state IN ('accepted','reconciled')
    AND eri.run_id=NEW.run_id
    AND eri.transition_id=NEW.transition_id
    AND eri.idempotency_key=NEW.release_idempotency_key
    AND eri.external_id=NEW.gateway_lease_id
)
BEGIN
  SELECT RAISE(ABORT,'released lease requires release intent proof');
END;

CREATE TRIGGER leases_validate_release_proof_update
AFTER UPDATE OF state, run_id, transition_id, release_idempotency_key, gateway_lease_id ON leases
WHEN NEW.state='released' AND NOT EXISTS (
  SELECT 1 FROM external_rpc_intents eri
  WHERE eri.rpc_kind='allow_lease_release'
    AND eri.state IN ('accepted','reconciled')
    AND eri.run_id=NEW.run_id
    AND eri.transition_id=NEW.transition_id
    AND eri.idempotency_key=NEW.release_idempotency_key
    AND eri.external_id=NEW.gateway_lease_id
)
BEGIN
  SELECT RAISE(ABORT,'released lease requires release intent proof');
END;

CREATE TRIGGER leases_reject_live_release_not_required_update
BEFORE UPDATE OF state, gateway_lease_id ON leases
WHEN NEW.state='release_not_required'
  AND (OLD.state IN ('acquired','release_pending','released')
    OR (OLD.gateway_lease_id IS NOT NULL AND OLD.gateway_lease_id <> ''))
BEGIN
  SELECT RAISE(ABORT,'live lease cannot be marked release_not_required');
END;

CREATE TABLE run_budgets (
  run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  workflow TEXT NOT NULL,
  capability_class TEXT NOT NULL,
  selected_provider TEXT NOT NULL,
  selected_model TEXT NOT NULL,
  selected_endpoint_binding_id TEXT NOT NULL,
  selected_cost_registry_id TEXT NOT NULL REFERENCES model_cost_registry(cost_registry_id),
  selected_cost_effective_at TEXT NOT NULL,
  selected_cost_registry_hash TEXT NOT NULL,
  selected_cost_confidence TEXT NOT NULL CHECK (selected_cost_confidence IN ('known','estimated','unknown')),
  selected_reserve_transition_id TEXT NOT NULL,
  time_budget_seconds ANY NOT NULL,
  input_token_budget ANY NOT NULL,
  output_token_budget ANY NOT NULL,
  cost_budget_microusd ANY NOT NULL,
  retry_budget ANY NOT NULL,
  human_attention_budget ANY NOT NULL,
  reserved_time_seconds ANY NOT NULL DEFAULT 0,
  reserved_input_tokens ANY NOT NULL DEFAULT 0,
  reserved_output_tokens ANY NOT NULL DEFAULT 0,
  reserved_cost_microusd ANY NOT NULL DEFAULT 0,
  reserved_retries ANY NOT NULL DEFAULT 0,
  reserved_human_attention ANY NOT NULL DEFAULT 0,
  consumed_time_seconds ANY NOT NULL DEFAULT 0,
  consumed_input_tokens ANY NOT NULL DEFAULT 0,
  consumed_output_tokens ANY NOT NULL DEFAULT 0,
  consumed_cost_microusd ANY NOT NULL DEFAULT 0,
  consumed_retries ANY NOT NULL DEFAULT 0,
  consumed_human_attention ANY NOT NULL DEFAULT 0,
  usage_confidence TEXT NOT NULL CHECK (usage_confidence IN ('known','estimated','unknown')),
  updated_at TEXT NOT NULL,
  CHECK (typeof(time_budget_seconds)='integer' AND time_budget_seconds BETWEEN 0 AND 31536000),
  CHECK (typeof(input_token_budget)='integer' AND input_token_budget BETWEEN 0 AND 1000000000),
  CHECK (typeof(output_token_budget)='integer' AND output_token_budget BETWEEN 0 AND 1000000000),
  CHECK (typeof(cost_budget_microusd)='integer' AND cost_budget_microusd BETWEEN 0 AND 100000000000),
  CHECK (typeof(retry_budget)='integer' AND retry_budget BETWEEN 0 AND 1000000),
  CHECK (typeof(human_attention_budget)='integer' AND human_attention_budget BETWEEN 0 AND 1000000),
  CHECK (typeof(reserved_time_seconds)='integer' AND reserved_time_seconds >= 0 AND reserved_time_seconds <= time_budget_seconds),
  CHECK (typeof(reserved_input_tokens)='integer' AND reserved_input_tokens >= 0 AND reserved_input_tokens <= input_token_budget),
  CHECK (typeof(reserved_output_tokens)='integer' AND reserved_output_tokens >= 0 AND reserved_output_tokens <= output_token_budget),
  CHECK (typeof(reserved_cost_microusd)='integer' AND reserved_cost_microusd >= 0 AND reserved_cost_microusd <= cost_budget_microusd),
  CHECK (typeof(reserved_retries)='integer' AND reserved_retries >= 0 AND reserved_retries <= retry_budget),
  CHECK (typeof(reserved_human_attention)='integer' AND reserved_human_attention >= 0 AND reserved_human_attention <= human_attention_budget),
  CHECK (typeof(consumed_time_seconds)='integer' AND consumed_time_seconds >= 0 AND consumed_time_seconds <= time_budget_seconds),
  CHECK (typeof(consumed_input_tokens)='integer' AND consumed_input_tokens >= 0 AND consumed_input_tokens <= input_token_budget),
  CHECK (typeof(consumed_output_tokens)='integer' AND consumed_output_tokens >= 0 AND consumed_output_tokens <= output_token_budget),
  CHECK (typeof(consumed_cost_microusd)='integer' AND consumed_cost_microusd >= 0 AND consumed_cost_microusd <= cost_budget_microusd),
  CHECK (typeof(consumed_retries)='integer' AND consumed_retries >= 0 AND consumed_retries <= retry_budget),
  CHECK (typeof(consumed_human_attention)='integer' AND consumed_human_attention >= 0 AND consumed_human_attention <= human_attention_budget),
  FOREIGN KEY(selected_reserve_transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TABLE endpoint_zero_reserve_policies (
  zero_reserve_policy_id TEXT PRIMARY KEY,
  endpoint_binding_id TEXT NOT NULL,
  capability_class TEXT NOT NULL,
  policy_hash TEXT NOT NULL UNIQUE,
  enabled ANY NOT NULL DEFAULT 1,
  min_retry_units ANY NOT NULL DEFAULT 0,
  min_time_seconds ANY NOT NULL DEFAULT 0,
  min_human_attention_units ANY NOT NULL DEFAULT 0,
  effective_from_epoch_ms ANY NOT NULL,
  effective_until_epoch_ms ANY NOT NULL DEFAULT 253402300799999,
  CHECK (endpoint_binding_id <> '' AND capability_class <> '' AND policy_hash <> ''),
  CHECK (typeof(enabled)='integer' AND enabled IN (0,1)),
  CHECK (typeof(min_retry_units)='integer' AND min_retry_units BETWEEN 0 AND 1000000),
  CHECK (typeof(min_time_seconds)='integer' AND min_time_seconds BETWEEN 0 AND 31536000),
  CHECK (typeof(min_human_attention_units)='integer' AND min_human_attention_units BETWEEN 0 AND 1000000),
  CHECK (min_retry_units > 0 OR min_time_seconds > 0 OR min_human_attention_units > 0),
  CHECK (typeof(effective_from_epoch_ms)='integer' AND effective_from_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(effective_until_epoch_ms)='integer' AND effective_until_epoch_ms > effective_from_epoch_ms AND effective_until_epoch_ms <= 253402300799999)
) STRICT;

CREATE TABLE budget_events (
  budget_event_id TEXT PRIMARY KEY,
  event_idempotency_key TEXT NOT NULL UNIQUE,
  event_dedupe_hash TEXT NOT NULL UNIQUE,
  event_sequence ANY NOT NULL,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT NOT NULL,
  spawn_request_id TEXT REFERENCES spawn_requests(spawn_request_id),
  provider TEXT,
  model TEXT,
  endpoint_binding_id TEXT,
  capability_class TEXT NOT NULL,
  cost_registry_id TEXT REFERENCES model_cost_registry(cost_registry_id),
  cost_effective_at TEXT,
  cost_registry_hash TEXT,
  cost_confidence TEXT CHECK (cost_confidence IN ('known','estimated','unknown')),
  zero_reserve_policy_id TEXT REFERENCES endpoint_zero_reserve_policies(zero_reserve_policy_id),
  zero_reserve_policy_hash TEXT,
  event_type TEXT NOT NULL CHECK (event_type IN ('reserve','consume','release','retry_decrement','retry_restore','human_attention')),
  time_seconds ANY DEFAULT 0,
  input_tokens ANY DEFAULT 0,
  output_tokens ANY DEFAULT 0,
  cost_microusd ANY DEFAULT 0,
  human_attention_units ANY DEFAULT 0,
  retry_units ANY NOT NULL DEFAULT 0,
  usage_confidence TEXT NOT NULL CHECK (usage_confidence IN ('known','estimated','unknown')),
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_at_epoch_ms ANY NOT NULL,
  UNIQUE(run_id, event_sequence),
  CHECK (typeof(event_sequence)='integer' AND event_sequence BETWEEN 1 AND 1000000),
  CHECK (typeof(created_at_epoch_ms)='integer' AND created_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(time_seconds)='integer' AND time_seconds BETWEEN 0 AND 31536000),
  CHECK (typeof(input_tokens)='integer' AND input_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(output_tokens)='integer' AND output_tokens BETWEEN 0 AND 1000000000),
  CHECK (typeof(cost_microusd)='integer' AND cost_microusd BETWEEN 0 AND 100000000000),
  CHECK (typeof(human_attention_units)='integer' AND human_attention_units BETWEEN 0 AND 1000000),
  CHECK (typeof(retry_units)='integer' AND retry_units BETWEEN 0 AND 1000000),
  CHECK (
    event_type <> 'reserve'
    OR input_tokens > 0 OR output_tokens > 0 OR cost_microusd > 0
    OR zero_reserve_policy_id IS NOT NULL
  ),
  CHECK (event_type <> 'retry_decrement' OR retry_units > 0),
  CHECK (event_type <> 'retry_restore' OR retry_units > 0),
  CHECK (event_type <> 'consume' OR (retry_units = 0 AND human_attention_units = 0)),
  CHECK (
    event_type <> 'human_attention'
    OR (
      time_seconds = 0
      AND input_tokens = 0
      AND output_tokens = 0
      AND cost_microusd = 0
      AND retry_units = 0
      AND human_attention_units > 0
    )
  ),
  CHECK (
    event_type NOT IN ('retry_decrement','retry_restore')
    OR (
      time_seconds = 0
      AND input_tokens = 0
      AND output_tokens = 0
      AND cost_microusd = 0
      AND human_attention_units = 0
    )
  ),
  CHECK (zero_reserve_policy_id IS NULL OR (zero_reserve_policy_hash IS NOT NULL AND zero_reserve_policy_hash <> '')),
  CHECK (zero_reserve_policy_id IS NULL OR event_type='reserve'),
  CHECK (zero_reserve_policy_id IS NULL OR (input_tokens=0 AND output_tokens=0 AND cost_microusd=0)),
  CHECK (
    event_type = 'human_attention' OR (
      provider IS NOT NULL AND provider <> ''
      AND model IS NOT NULL AND model <> ''
      AND endpoint_binding_id IS NOT NULL AND endpoint_binding_id <> ''
      AND cost_registry_id IS NOT NULL AND cost_registry_id <> ''
      AND cost_effective_at IS NOT NULL AND cost_effective_at <> ''
      AND cost_registry_hash IS NOT NULL AND cost_registry_hash <> ''
      AND cost_confidence IS NOT NULL AND cost_confidence <> 'unknown'
    )
  ),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TRIGGER budget_events_validate_zero_reserve_insert
BEFORE INSERT ON budget_events
WHEN NEW.zero_reserve_policy_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM endpoint_zero_reserve_policies p
  WHERE p.zero_reserve_policy_id=NEW.zero_reserve_policy_id
    AND p.policy_hash=NEW.zero_reserve_policy_hash
    AND p.endpoint_binding_id=NEW.endpoint_binding_id
    AND p.capability_class=NEW.capability_class
    AND p.enabled=1
    AND NEW.created_at_epoch_ms >= p.effective_from_epoch_ms
    AND NEW.created_at_epoch_ms < p.effective_until_epoch_ms
    AND NEW.retry_units>=p.min_retry_units
    AND NEW.time_seconds>=p.min_time_seconds
    AND NEW.human_attention_units>=p.min_human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'zero reserve policy mismatch or minima not met');
END;

CREATE TRIGGER budget_events_validate_zero_reserve_update
BEFORE UPDATE ON budget_events
WHEN NEW.zero_reserve_policy_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM endpoint_zero_reserve_policies p
  WHERE p.zero_reserve_policy_id=NEW.zero_reserve_policy_id
    AND p.policy_hash=NEW.zero_reserve_policy_hash
    AND p.endpoint_binding_id=NEW.endpoint_binding_id
    AND p.capability_class=NEW.capability_class
    AND p.enabled=1
    AND NEW.created_at_epoch_ms >= p.effective_from_epoch_ms
    AND NEW.created_at_epoch_ms < p.effective_until_epoch_ms
    AND NEW.retry_units>=p.min_retry_units
    AND NEW.time_seconds>=p.min_time_seconds
    AND NEW.human_attention_units>=p.min_human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'zero reserve policy mismatch or minima not met');
END;

CREATE TRIGGER external_rpc_intents_validate_prior_reserve_insert
BEFORE INSERT ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn' AND NOT EXISTS (
  SELECT 1
  FROM budget_events b
  JOIN run_budgets rb ON rb.run_id=NEW.run_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.time_seconds <= rb.time_budget_seconds
    AND b.input_tokens <= rb.input_token_budget
    AND b.output_tokens <= rb.output_token_budget
    AND b.cost_microusd <= rb.cost_budget_microusd
    AND b.retry_units <= rb.retry_budget
    AND b.human_attention_units <= rb.human_attention_budget
    AND rb.reserved_time_seconds >= b.time_seconds
    AND rb.reserved_input_tokens >= b.input_tokens
    AND rb.reserved_output_tokens >= b.output_tokens
    AND rb.reserved_cost_microusd >= b.cost_microusd
    AND rb.reserved_retries >= b.retry_units
    AND rb.reserved_human_attention >= b.human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn requires strict prior reserve budget event');
END;

CREATE TRIGGER external_rpc_intents_validate_prior_reserve_update
BEFORE UPDATE OF rpc_kind, reserve_budget_event_id, run_id, transition_id, spawn_request_id, requested_at_epoch_ms ON external_rpc_intents
WHEN NEW.rpc_kind='sessions_spawn' AND NOT EXISTS (
  SELECT 1
  FROM budget_events b
  JOIN run_budgets rb ON rb.run_id=NEW.run_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.time_seconds <= rb.time_budget_seconds
    AND b.input_tokens <= rb.input_token_budget
    AND b.output_tokens <= rb.output_token_budget
    AND b.cost_microusd <= rb.cost_budget_microusd
    AND b.retry_units <= rb.retry_budget
    AND b.human_attention_units <= rb.human_attention_budget
    AND rb.reserved_time_seconds >= b.time_seconds
    AND rb.reserved_input_tokens >= b.input_tokens
    AND rb.reserved_output_tokens >= b.output_tokens
    AND rb.reserved_cost_microusd >= b.cost_microusd
    AND rb.reserved_retries >= b.retry_units
    AND rb.reserved_human_attention >= b.human_attention_units
)
BEGIN
  SELECT RAISE(ABORT,'sessions_spawn requires strict prior reserve budget event');
END;

CREATE TRIGGER budget_events_preserve_spawn_prior_reserve_delete
BEFORE DELETE ON budget_events
WHEN EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.reserve_budget_event_id=OLD.budget_event_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve is immutable');
END;

CREATE TRIGGER budget_events_preserve_spawn_prior_reserve_update
BEFORE UPDATE OF budget_event_id, event_type, event_sequence, run_id, transition_id, spawn_request_id, provider, model, endpoint_binding_id, capability_class, cost_registry_id, cost_effective_at, cost_registry_hash, cost_confidence, zero_reserve_policy_id, zero_reserve_policy_hash, time_seconds, input_tokens, output_tokens, cost_microusd, human_attention_units, retry_units, usage_confidence, source, created_at, created_at_epoch_ms ON budget_events
WHEN EXISTS (
  SELECT 1 FROM external_rpc_intents i
  WHERE i.rpc_kind='sessions_spawn'
    AND i.reserve_budget_event_id=OLD.budget_event_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve is immutable');
END;

CREATE TRIGGER run_budgets_preserve_spawn_prior_reserve_update
BEFORE UPDATE OF selected_provider, selected_model, selected_endpoint_binding_id, capability_class, selected_cost_registry_id, selected_cost_effective_at, selected_cost_registry_hash, selected_cost_confidence ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve cost binding is immutable');
END;

CREATE TRIGGER endpoint_zero_reserve_policies_reject_referenced_update
BEFORE UPDATE ON endpoint_zero_reserve_policies
WHEN EXISTS (
  SELECT 1 FROM budget_events WHERE zero_reserve_policy_id=OLD.zero_reserve_policy_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced zero reserve policy is immutable');
END;

CREATE TABLE model_cost_registry (
  cost_registry_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  endpoint_binding_id TEXT NOT NULL,
  capability_class TEXT NOT NULL,
  input_cost_microusd_per_million ANY NOT NULL,
  output_cost_microusd_per_million ANY NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('known','estimated','unknown')),
  effective_at TEXT NOT NULL,
  registry_row_hash TEXT NOT NULL UNIQUE,
  CHECK (provider <> '' AND model <> '' AND endpoint_binding_id <> '' AND capability_class <> ''),
  CHECK (typeof(input_cost_microusd_per_million)='integer' AND input_cost_microusd_per_million BETWEEN 0 AND 100000000000),
  CHECK (typeof(output_cost_microusd_per_million)='integer' AND output_cost_microusd_per_million BETWEEN 0 AND 100000000000),
  UNIQUE(provider, model, endpoint_binding_id, capability_class, effective_at)
) STRICT;

CREATE TRIGGER model_cost_registry_reject_referenced_update
BEFORE UPDATE ON model_cost_registry
WHEN EXISTS (
  SELECT 1 FROM run_budgets WHERE selected_cost_registry_id=OLD.cost_registry_id
) OR EXISTS (
  SELECT 1 FROM budget_events WHERE cost_registry_id=OLD.cost_registry_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced model cost registry row is immutable');
END;

CREATE TABLE predicate_plugins (
  predicate_plugin_hash TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  backend TEXT NOT NULL CHECK (backend='agentic_predicate_inproc_v1'),
  schema_hash TEXT NOT NULL,
  sandbox_required ANY NOT NULL,
  sandbox_enforced ANY NOT NULL,
  sensitive ANY NOT NULL DEFAULT 0,
  approved_at TEXT,
  disabled_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (typeof(sandbox_required)='integer' AND sandbox_required IN (0,1)),
  CHECK (typeof(sandbox_enforced)='integer' AND sandbox_enforced IN (0,1)),
  CHECK (typeof(sensitive)='integer' AND sensitive IN (0,1)),
  CHECK (sandbox_required=0 OR sandbox_enforced=1),
  CHECK (sensitive=0 OR (approved_at IS NOT NULL AND approved_at <> '')),
  UNIQUE(predicate_plugin_hash,backend)
) STRICT;

CREATE TABLE goal_manifests (
  goal_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  severity TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  predicate_plugin_hash TEXT NOT NULL REFERENCES predicate_plugins(predicate_plugin_hash),
  backend TEXT NOT NULL,
  approval_required ANY NOT NULL,
  enabled ANY NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (typeof(approval_required)='integer' AND approval_required IN (0,1)),
  CHECK (typeof(enabled)='integer' AND enabled IN (0,1)),
  UNIQUE(goal_id,predicate_plugin_hash,backend),
  FOREIGN KEY(predicate_plugin_hash,backend)
    REFERENCES predicate_plugins(predicate_plugin_hash,backend)
) STRICT;

CREATE TABLE goal_runs (
  goal_run_id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL REFERENCES goal_manifests(goal_id),
  run_id TEXT REFERENCES runs(run_id),
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  triaged_at TEXT,
  predicate_plugin_hash TEXT NOT NULL REFERENCES predicate_plugins(predicate_plugin_hash),
  backend TEXT NOT NULL,
  sandbox_enforced ANY NOT NULL,
  sandbox_proof_hash TEXT,
  approval_id TEXT,
  evidence_hash TEXT,
  created_at TEXT NOT NULL,
  CHECK (typeof(sandbox_enforced)='integer' AND sandbox_enforced IN (0,1)),
  FOREIGN KEY(goal_id,predicate_plugin_hash,backend)
    REFERENCES goal_manifests(goal_id,predicate_plugin_hash,backend),
  FOREIGN KEY(predicate_plugin_hash,backend)
    REFERENCES predicate_plugins(predicate_plugin_hash,backend)
) STRICT;

CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  approver TEXT NOT NULL,
  channel TEXT NOT NULL,
  source_message_id TEXT,
  source_message_digest TEXT NOT NULL,
  approval_text_digest TEXT NOT NULL,
  approved_action_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_hash TEXT NOT NULL,
  target_scope TEXT NOT NULL,
  approved_risk_ceiling TEXT NOT NULL,
  expires_at_epoch_ms ANY NOT NULL,
  expires_at_display TEXT,
  single_use ANY NOT NULL DEFAULT 1,
  approval_hash TEXT NOT NULL UNIQUE,
  consumed_by_transition_id TEXT UNIQUE REFERENCES transitions(transition_id) DEFERRABLE INITIALLY DEFERRED,
  consumed_by_gate_run_id TEXT UNIQUE REFERENCES gate_runs(gate_run_id) DEFERRABLE INITIALLY DEFERRED,
  approved_at TEXT NOT NULL,
  CHECK (run_id <> ''),
  CHECK (approved_action_type <> ''),
  CHECK (target_type <> '' AND target_id <> '' AND target_hash <> '' AND target_scope <> ''),
  CHECK (approved_risk_ceiling IN ('R0','R1','R2','R3','R4')),
  CHECK (typeof(expires_at_epoch_ms)='integer' AND expires_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(single_use)='integer' AND single_use IN (0,1)),
  UNIQUE(
    approval_id,
    run_id,
    approved_action_type,
    target_type,
    target_id,
    target_hash,
    target_scope,
    channel,
    source_message_digest,
    approval_text_digest,
    consumed_by_transition_id,
    consumed_by_gate_run_id
  )
) STRICT;

CREATE TRIGGER transitions_validate_approval_insert
AFTER INSERT ON transitions
WHEN NEW.approval_required=1 AND NOT EXISTS (
  SELECT 1 FROM approvals a
  LEFT JOIN gate_clock_context c ON c.gate_run_id=NEW.gate_run_id
  WHERE a.approval_id=NEW.approval_id
    AND a.run_id=NEW.run_id
    AND a.approved_action_type=NEW.action_type
    AND a.target_type=NEW.target_type
    AND a.target_id=NEW.target_id
    AND a.target_hash=NEW.target_hash
    AND a.target_scope=NEW.target_scope
    AND a.channel=NEW.approval_channel
    AND a.source_message_digest=NEW.approval_source_digest
    AND a.approval_text_digest=NEW.approval_text_digest
    AND a.consumed_by_transition_id=NEW.transition_id
    AND a.consumed_by_gate_run_id=NEW.gate_run_id
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE NEW.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND (c.clock_context_id IS NULL OR a.expires_at_epoch_ms > c.now_epoch_ms)
)
BEGIN
  SELECT RAISE(ABORT,'approval does not exactly authorize transition');
END;

CREATE TRIGGER transitions_validate_approval_update
AFTER UPDATE OF approval_required, approval_id, run_id, action_type, target_type, target_id, target_hash, target_scope, approval_channel, approval_source_digest, approval_text_digest, transition_id, gate_run_id, risk_dominance ON transitions
WHEN NEW.approval_required=1 AND NOT EXISTS (
  SELECT 1 FROM approvals a
  LEFT JOIN gate_clock_context c ON c.gate_run_id=NEW.gate_run_id
  WHERE a.approval_id=NEW.approval_id
    AND a.run_id=NEW.run_id
    AND a.approved_action_type=NEW.action_type
    AND a.target_type=NEW.target_type
    AND a.target_id=NEW.target_id
    AND a.target_hash=NEW.target_hash
    AND a.target_scope=NEW.target_scope
    AND a.channel=NEW.approval_channel
    AND a.source_message_digest=NEW.approval_source_digest
    AND a.approval_text_digest=NEW.approval_text_digest
    AND a.consumed_by_transition_id=NEW.transition_id
    AND a.consumed_by_gate_run_id=NEW.gate_run_id
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE NEW.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND (c.clock_context_id IS NULL OR a.expires_at_epoch_ms > c.now_epoch_ms)
)
BEGIN
  SELECT RAISE(ABORT,'approval does not exactly authorize transition');
END;

CREATE TRIGGER approvals_reject_expired_binding_insert
AFTER INSERT ON approvals
WHEN EXISTS (
  SELECT 1
  FROM transitions t
  JOIN gate_clock_context c ON c.gate_run_id=NEW.consumed_by_gate_run_id
  WHERE t.approval_required=1
    AND t.transition_id=NEW.consumed_by_transition_id
    AND t.gate_run_id=NEW.consumed_by_gate_run_id
    AND NEW.expires_at_epoch_ms <= c.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'approval expired before gate clock');
END;

CREATE TRIGGER approvals_reject_expired_binding_update
AFTER UPDATE OF expires_at_epoch_ms, consumed_by_transition_id, consumed_by_gate_run_id ON approvals
WHEN EXISTS (
  SELECT 1
  FROM transitions t
  JOIN gate_clock_context c ON c.gate_run_id=NEW.consumed_by_gate_run_id
  WHERE t.approval_required=1
    AND t.transition_id=NEW.consumed_by_transition_id
    AND t.gate_run_id=NEW.consumed_by_gate_run_id
    AND NEW.expires_at_epoch_ms <= c.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'approval expired before gate clock');
END;

CREATE TABLE judge_verifier_runs (
  verifier_run_id TEXT PRIMARY KEY,
  worker_run_id TEXT NOT NULL REFERENCES runs(run_id),
  worker_agent_id TEXT NOT NULL,
  verifier_agent_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  model_version TEXT,
  prompt_hash TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  independence_class TEXT NOT NULL,
  independence_proof_json TEXT NOT NULL,
  same_worker_context ANY NOT NULL DEFAULT 0,
  completed_at TEXT NOT NULL,
  CHECK (typeof(same_worker_context)='integer' AND same_worker_context IN (0,1)),
  CHECK (independence_class='independent'),
  CHECK (worker_agent_id <> verifier_agent_id AND same_worker_context=0),
  CHECK (prompt_hash <> context_hash),
  UNIQUE(verifier_run_id,worker_run_id,evidence_hash)
) STRICT;

CREATE TABLE gate_runs (
  gate_run_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  transition_id TEXT NOT NULL REFERENCES transitions(transition_id),
  clock_context_id TEXT NOT NULL UNIQUE REFERENCES gate_clock_context(clock_context_id) DEFERRABLE INITIALLY DEFERRED,
  verifier_run_id TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('pass','fail','human_review_required')),
  completed_at TEXT NOT NULL,
  completed_at_epoch_ms ANY NOT NULL,
  requires_same_run ANY NOT NULL DEFAULT 1,
  gate_version TEXT NOT NULL,
  gate_query_hash TEXT NOT NULL,
  migration_sha256 TEXT NOT NULL,
  evidence_hash TEXT,
  risk_dominance TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (typeof(completed_at_epoch_ms)='integer' AND completed_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(requires_same_run)='integer' AND requires_same_run IN (0,1)),
  CHECK (decision <> 'pass' OR (verifier_run_id IS NOT NULL AND evidence_hash IS NOT NULL AND evidence_hash <> '')),
  UNIQUE(gate_run_id,evidence_hash),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id),
  FOREIGN KEY(verifier_run_id,run_id,evidence_hash)
    REFERENCES judge_verifier_runs(verifier_run_id,worker_run_id,evidence_hash),
  FOREIGN KEY(gate_run_id,evidence_hash,run_id,verifier_run_id)
    REFERENCES evidence_hashes(gate_run_id,evidence_hash,run_id,verifier_run_id)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TRIGGER gate_runs_validate_clock_context_insert
AFTER INSERT ON gate_runs
WHEN EXISTS (
  SELECT 1 FROM gate_clock_context c WHERE c.clock_context_id=NEW.clock_context_id
) AND NOT EXISTS (
  SELECT 1 FROM gate_clock_context c
  WHERE c.clock_context_id=NEW.clock_context_id
    AND c.gate_run_id=NEW.gate_run_id
    AND c.consumed_by_gate_run_id=NEW.gate_run_id
    AND c.run_id=NEW.run_id
    AND c.transition_id=NEW.transition_id
    AND c.now_epoch_ms=NEW.completed_at_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'gate completion does not match clock context');
END;

CREATE TRIGGER gate_runs_validate_clock_context_update
AFTER UPDATE OF run_id, transition_id, clock_context_id, completed_at_epoch_ms ON gate_runs
WHEN EXISTS (
  SELECT 1 FROM gate_clock_context c WHERE c.clock_context_id=NEW.clock_context_id
) AND NOT EXISTS (
  SELECT 1 FROM gate_clock_context c
  WHERE c.clock_context_id=NEW.clock_context_id
    AND c.gate_run_id=NEW.gate_run_id
    AND c.consumed_by_gate_run_id=NEW.gate_run_id
    AND c.run_id=NEW.run_id
    AND c.transition_id=NEW.transition_id
    AND c.now_epoch_ms=NEW.completed_at_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'gate completion does not match clock context');
END;

CREATE TRIGGER gate_clock_context_validate_gate_insert
AFTER INSERT ON gate_clock_context
WHEN EXISTS (
  SELECT 1 FROM gate_runs g WHERE g.gate_run_id=NEW.gate_run_id
) AND NOT EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.gate_run_id=NEW.gate_run_id
    AND g.clock_context_id=NEW.clock_context_id
    AND g.run_id=NEW.run_id
    AND g.transition_id=NEW.transition_id
    AND g.completed_at_epoch_ms=NEW.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'clock context does not match gate completion');
END;

CREATE TRIGGER gate_clock_context_validate_gate_update
AFTER UPDATE OF gate_run_id, consumed_by_gate_run_id, run_id, transition_id, now_epoch_ms ON gate_clock_context
WHEN EXISTS (
  SELECT 1 FROM gate_runs g WHERE g.gate_run_id=NEW.gate_run_id
) AND NOT EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.gate_run_id=NEW.gate_run_id
    AND g.clock_context_id=NEW.clock_context_id
    AND g.run_id=NEW.run_id
    AND g.transition_id=NEW.transition_id
    AND g.completed_at_epoch_ms=NEW.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'clock context does not match gate completion');
END;

CREATE TRIGGER gate_clock_context_reject_expired_approval_insert
AFTER INSERT ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM transitions t
  JOIN approvals a ON a.approval_id=t.approval_id
  WHERE t.approval_required=1
    AND t.gate_run_id=NEW.gate_run_id
    AND t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND a.consumed_by_transition_id=t.transition_id
    AND a.consumed_by_gate_run_id=NEW.gate_run_id
    AND a.expires_at_epoch_ms <= NEW.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'approval expired before gate clock');
END;

CREATE TRIGGER gate_clock_context_reject_expired_approval_update
AFTER UPDATE OF gate_run_id, consumed_by_gate_run_id, run_id, transition_id, now_epoch_ms ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM transitions t
  JOIN approvals a ON a.approval_id=t.approval_id
  WHERE t.approval_required=1
    AND t.gate_run_id=NEW.gate_run_id
    AND t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND a.consumed_by_transition_id=t.transition_id
    AND a.consumed_by_gate_run_id=NEW.gate_run_id
    AND a.expires_at_epoch_ms <= NEW.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'approval expired before gate clock');
END;

CREATE TABLE risk_assessments (
  assessment_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  transition_id TEXT,
  action_risk TEXT NOT NULL,
  target_risk TEXT NOT NULL,
  data_risk TEXT NOT NULL,
  side_effect_risk TEXT NOT NULL,
  permission_risk TEXT NOT NULL,
  irreversibility_risk TEXT NOT NULL,
  risk_dominance TEXT NOT NULL,
  assessed_at TEXT NOT NULL,
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TABLE trust_observations (
  observation_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  effective_group_id TEXT NOT NULL,
  verifier_run_id TEXT REFERENCES judge_verifier_runs(verifier_run_id),
  gate_run_id TEXT REFERENCES gate_runs(gate_run_id),
  usage_confidence TEXT NOT NULL,
  bounded_at TEXT,
  invalidated_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE artifact_projections (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  UNIQUE(path, sha256)
) STRICT;

CREATE TABLE evidence_hashes (
  evidence_hash TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes ANY NOT NULL,
  content_type TEXT NOT NULL,
  redaction_status TEXT NOT NULL,
  producer_run_id TEXT REFERENCES runs(run_id),
  verifier_run_id TEXT REFERENCES judge_verifier_runs(verifier_run_id),
  gate_run_id TEXT REFERENCES gate_runs(gate_run_id),
  captured_at TEXT NOT NULL,
  UNIQUE(path, sha256),
  UNIQUE(gate_run_id,evidence_hash,run_id,verifier_run_id),
  CHECK (typeof(size_bytes)='integer' AND size_bytes >= 0),
  CHECK (
    gate_run_id IS NULL OR (
      producer_run_id IS NOT NULL
      AND verifier_run_id IS NOT NULL
      AND run_id=producer_run_id
    )
  ),
  FOREIGN KEY(gate_run_id,evidence_hash) REFERENCES gate_runs(gate_run_id,evidence_hash)
) STRICT;

CREATE TABLE reconciliation_jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(run_id),
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  external_contract_status TEXT NOT NULL CHECK (external_contract_status IN ('metadata_present','metadata_missing','ambiguous','expired','human_review_required')),
  reason TEXT NOT NULL,
  attempts ANY NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (typeof(attempts)='integer' AND attempts >= 0)
) STRICT;

CREATE TABLE outbox_events (
  event_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  transition_id TEXT REFERENCES transitions(transition_id),
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  delivered_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE slo_queries (
  query_name TEXT PRIMARY KEY,
  schema_version ANY NOT NULL REFERENCES schema_migrations(version),
  migration_sha256 TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  sql_text TEXT NOT NULL,
  empty_db_expected_status TEXT NOT NULL,
  fixture_db_expected_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (typeof(schema_version)='integer' AND schema_version > 0),
  CHECK (length(migration_sha256)=64 AND length(query_hash)=64 AND sql_text<>''),
  UNIQUE(query_name,schema_version,migration_sha256,query_hash),
  FOREIGN KEY(schema_version,migration_sha256)
    REFERENCES schema_migrations(version,sha256)
) STRICT;

CREATE TABLE slo_audits (
  slo_audit_id TEXT PRIMARY KEY,
  query_name TEXT NOT NULL,
  schema_version ANY NOT NULL,
  migration_sha256 TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  result_count ANY NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','compile_error','not_run')),
  empty_db_status TEXT NOT NULL,
  fixture_db_status TEXT NOT NULL,
  evidence_hash TEXT,
  run_at TEXT NOT NULL,
  run_at_epoch_ms ANY NOT NULL,
  CHECK (typeof(schema_version)='integer' AND schema_version > 0),
  CHECK (typeof(result_count)='integer' AND result_count >= 0),
  CHECK (typeof(run_at_epoch_ms)='integer' AND run_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (status<>'pass' OR (
    result_count=0
    AND empty_db_status='pass'
    AND fixture_db_status='pass'
    AND evidence_hash IS NOT NULL AND evidence_hash<>''
  )),
  FOREIGN KEY(query_name,schema_version,migration_sha256,query_hash)
    REFERENCES slo_queries(query_name,schema_version,migration_sha256,query_hash)
) STRICT;

CREATE TRIGGER slo_queries_reject_update
BEFORE UPDATE ON slo_queries
BEGIN
  SELECT RAISE(ABORT,'SLO query registry is immutable');
END;

CREATE TRIGGER slo_queries_reject_delete
BEFORE DELETE ON slo_queries
BEGIN
  SELECT RAISE(ABORT,'SLO query registry is immutable');
END;

CREATE TRIGGER slo_queries_reject_pass_audited_update
BEFORE UPDATE ON slo_queries
WHEN EXISTS (
  SELECT 1 FROM slo_audits
  WHERE query_name=OLD.query_name
    AND schema_version=OLD.schema_version
    AND migration_sha256=OLD.migration_sha256
    AND query_hash=OLD.query_hash
    AND status='pass'
)
BEGIN
  SELECT RAISE(ABORT,'pass-audited SLO query is immutable');
END;
