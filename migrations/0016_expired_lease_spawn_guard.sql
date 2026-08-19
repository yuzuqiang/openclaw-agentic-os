DROP TRIGGER IF EXISTS leases_validate_terminal_gateway_release_proof_insert;
DROP TRIGGER IF EXISTS leases_validate_terminal_gateway_release_proof_update;
DROP TRIGGER IF EXISTS leases_preserve_live_gateway_state_update;

CREATE TRIGGER leases_validate_terminal_gateway_release_proof_insert
AFTER INSERT ON leases
WHEN NEW.state IN ('expired','human_review_required')
  AND NEW.gateway_lease_id IS NOT NULL
  AND NEW.gateway_lease_id <> ''
  AND NOT (
    NEW.state='expired'
    AND typeof(NEW.expires_at_epoch_ms)='integer'
    AND NEW.expires_at_epoch_ms <= CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
  )
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=NEW.run_id
      AND eri.phase=NEW.phase
      AND eri.transition_id=NEW.transition_id
      AND eri.agent_id=NEW.agent_id
      AND eri.requester_agent_id=NEW.requester_agent_id
      AND eri.external_client_request_id=NEW.client_lease_id
      AND eri.idempotency_key=NEW.release_idempotency_key
      AND eri.external_id=NEW.gateway_lease_id
  )
BEGIN
  SELECT RAISE(ABORT,'terminal lease with gateway ownership requires release intent proof');
END;

CREATE TRIGGER leases_validate_terminal_gateway_release_proof_update
AFTER UPDATE OF state, run_id, phase, transition_id, agent_id, requester_agent_id, client_lease_id, release_idempotency_key, gateway_lease_id ON leases
WHEN NEW.state IN ('expired','human_review_required')
  AND (
    (
      NEW.gateway_lease_id IS NOT NULL
      AND NEW.gateway_lease_id <> ''
      AND NOT (
        NEW.state='expired'
        AND typeof(NEW.expires_at_epoch_ms)='integer'
        AND NEW.expires_at_epoch_ms <= CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
      )
      AND NOT EXISTS (
        SELECT 1 FROM external_rpc_intents eri
        WHERE eri.rpc_kind='allow_lease_release'
          AND eri.state IN ('accepted','reconciled')
          AND eri.run_id=NEW.run_id
          AND eri.phase=NEW.phase
          AND eri.transition_id=NEW.transition_id
          AND eri.agent_id=NEW.agent_id
          AND eri.requester_agent_id=NEW.requester_agent_id
          AND eri.external_client_request_id=NEW.client_lease_id
          AND eri.idempotency_key=NEW.release_idempotency_key
          AND eri.external_id=NEW.gateway_lease_id
      )
    )
    OR (
      OLD.gateway_lease_id IS NOT NULL
      AND OLD.gateway_lease_id <> ''
      AND OLD.gateway_lease_id<>COALESCE(NEW.gateway_lease_id,'')
      AND NOT (
        NEW.state='expired'
        AND typeof(NEW.expires_at_epoch_ms)='integer'
        AND NEW.expires_at_epoch_ms <= CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
      )
      AND NOT EXISTS (
        SELECT 1 FROM external_rpc_intents eri
        WHERE eri.rpc_kind='allow_lease_release'
          AND eri.state IN ('accepted','reconciled')
          AND eri.run_id=OLD.run_id
          AND eri.phase=OLD.phase
          AND eri.transition_id=OLD.transition_id
          AND eri.agent_id=OLD.agent_id
          AND eri.requester_agent_id=OLD.requester_agent_id
          AND eri.external_client_request_id=OLD.client_lease_id
          AND eri.idempotency_key=OLD.release_idempotency_key
          AND eri.external_id=OLD.gateway_lease_id
      )
    )
  )
BEGIN
  SELECT RAISE(ABORT,'terminal lease with gateway ownership requires release intent proof');
END;

CREATE TRIGGER leases_preserve_live_gateway_state_update
BEFORE UPDATE OF state, run_id, phase, transition_id, agent_id, requester_agent_id, client_lease_id, release_idempotency_key, gateway_lease_id ON leases
WHEN OLD.state IN ('acquired','release_pending')
  AND OLD.gateway_lease_id IS NOT NULL
  AND OLD.gateway_lease_id <> ''
  AND (
    NEW.state NOT IN ('acquired','release_pending')
    OR NEW.run_id<>OLD.run_id
    OR NEW.phase<>OLD.phase
    OR NEW.transition_id<>OLD.transition_id
    OR NEW.agent_id<>OLD.agent_id
    OR NEW.requester_agent_id<>OLD.requester_agent_id
    OR NEW.client_lease_id<>OLD.client_lease_id
    OR NEW.release_idempotency_key<>OLD.release_idempotency_key
    OR NEW.gateway_lease_id IS NULL
    OR NEW.gateway_lease_id<>OLD.gateway_lease_id
  )
  AND NOT (
    NEW.state='expired'
    AND typeof(NEW.expires_at_epoch_ms)='integer'
    AND NEW.expires_at_epoch_ms <= CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
  )
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=OLD.run_id
      AND eri.phase=OLD.phase
      AND eri.transition_id=OLD.transition_id
      AND eri.agent_id=OLD.agent_id
      AND eri.requester_agent_id=OLD.requester_agent_id
      AND eri.external_client_request_id=OLD.client_lease_id
      AND eri.idempotency_key=OLD.release_idempotency_key
      AND eri.external_id=OLD.gateway_lease_id
  )
BEGIN
  SELECT RAISE(ABORT,'live lease requires release proof before leaving live state');
END;
