CREATE TRIGGER goal_runs_validate_evidence_binding_insert
AFTER INSERT ON goal_runs
WHEN NEW.evidence_hash IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN judge_verifier_runs j
    ON j.verifier_run_id=e.verifier_run_id
   AND j.worker_run_id=e.run_id
   AND j.evidence_hash=e.evidence_hash
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  JOIN approvals a
    ON a.run_id=g.run_id
   AND a.consumed_by_gate_run_id=g.gate_run_id
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND g.decision='pass'
    AND g.requires_same_run=1
    AND j.independence_class='independent'
    AND j.worker_agent_id<>j.verifier_agent_id
    AND j.same_worker_context=0
    AND a.single_use=1
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence requires same-run independent pass-gate evidence');
END;

CREATE TRIGGER goal_runs_validate_evidence_binding_update
AFTER UPDATE OF run_id, evidence_hash ON goal_runs
WHEN NEW.evidence_hash IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN judge_verifier_runs j
    ON j.verifier_run_id=e.verifier_run_id
   AND j.worker_run_id=e.run_id
   AND j.evidence_hash=e.evidence_hash
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  JOIN approvals a
    ON a.run_id=g.run_id
   AND a.consumed_by_gate_run_id=g.gate_run_id
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND g.decision='pass'
    AND g.requires_same_run=1
    AND j.independence_class='independent'
    AND j.worker_agent_id<>j.verifier_agent_id
    AND j.same_worker_context=0
    AND a.single_use=1
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence requires same-run independent pass-gate evidence');
END;

CREATE TRIGGER goal_runs_freeze_evidence_binding_update
BEFORE UPDATE OF run_id, evidence_hash ON goal_runs
WHEN OLD.evidence_hash IS NOT NULL
  AND (NEW.evidence_hash IS NOT OLD.evidence_hash OR NEW.run_id IS NOT OLD.run_id)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence binding is immutable');
END;
