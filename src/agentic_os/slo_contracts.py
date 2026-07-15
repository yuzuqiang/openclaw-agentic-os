"""Pinned blocking SLO query identities for the minimum contract."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SloQueryContract:
    query_name: str
    sql_text: str
    empty_db_expected_status: str = "pass"
    fixture_db_expected_status: str = "pass"


def slo_query_hash(sql_text: str) -> str:
    return hashlib.sha256(sql_text.encode("utf-8")).hexdigest()


_BUDGET_LEDGER_RECONCILES_NAME = "Budget ledger reconciles to counters and budgets"
_BUDGET_PREFIX_NAME = "Budget prefix over-release or over-restore"
_BUDGET_LEDGER_RECONCILES_LEGACY_V1_V2_HASH = (
    "229ffe243ba24944c0da458e2d0986ea46de1471025cf95f9604bbe6a4dd9f7b"
)


SLO_QUERY_CONTRACTS: tuple[SloQueryContract, ...] = (
    SloQueryContract('Metadata-missing external RPC not auto-repaired', "SELECT intent_id FROM external_rpc_intents WHERE state IN ('pending','unknown','accepted','reconciled') AND run_id NOT IN (SELECT run_id FROM runs WHERE state='human_review_required') AND (metadata_contract_version IS NULL OR metadata_contract_version='' OR external_metadata_json IS NULL OR json_valid(external_metadata_json)=0);"),
    SloQueryContract('Duplicate live dispatch blocked', "SELECT run_id, phase, agent_id, COUNT(*) FROM spawn_requests WHERE state IN ('accepted','completed') GROUP BY run_id, phase, agent_id HAVING COUNT(*) > 1;"),
    SloQueryContract('`sessions_spawn` intent without exact spawn request binding', "SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN spawn_requests sr ON sr.spawn_request_id=eri.spawn_request_id AND sr.run_id=eri.run_id AND sr.transition_id=eri.transition_id AND sr.client_request_id=eri.client_request_id AND sr.spawn_idempotency_key=eri.idempotency_key AND sr.phase=eri.phase AND sr.agent_id=eri.agent_id AND sr.task_digest=eri.task_digest WHERE eri.rpc_kind='sessions_spawn' AND (eri.spawn_request_id IS NULL OR eri.phase IS NULL OR eri.phase='' OR eri.agent_id IS NULL OR eri.agent_id='' OR eri.task_digest IS NULL OR eri.task_digest='' OR sr.spawn_request_id IS NULL);"),
    SloQueryContract('`sessions_spawn` external metadata exact match', "SELECT intent_id FROM external_rpc_intents WHERE rpc_kind='sessions_spawn' AND state IN ('pending','accepted','unknown','reconciled') AND CASE WHEN metadata_contract_version IS NULL OR metadata_contract_version='' OR external_metadata_json IS NULL OR json_valid(external_metadata_json)=0 THEN 1 WHEN json_type(external_metadata_json,'$.run_id') IS NOT 'text' OR json_type(external_metadata_json,'$.transition_id') IS NOT 'text' OR json_type(external_metadata_json,'$.client_request_id') IS NOT 'text' OR json_type(external_metadata_json,'$.idempotency_key') IS NOT 'text' OR json_type(external_metadata_json,'$.phase') IS NOT 'text' OR json_type(external_metadata_json,'$.agent_id') IS NOT 'text' OR json_type(external_metadata_json,'$.task_digest') IS NOT 'text' OR json_extract(external_metadata_json,'$.run_id') IS NOT run_id OR json_extract(external_metadata_json,'$.transition_id') IS NOT transition_id OR json_extract(external_metadata_json,'$.client_request_id') IS NOT client_request_id OR json_extract(external_metadata_json,'$.idempotency_key') IS NOT idempotency_key OR json_extract(external_metadata_json,'$.phase') IS NOT phase OR json_extract(external_metadata_json,'$.agent_id') IS NOT agent_id OR json_extract(external_metadata_json,'$.task_digest') IS NOT task_digest OR external_run_id IS NOT run_id OR external_transition_id IS NOT transition_id OR external_client_request_id IS NOT client_request_id OR external_idempotency_key IS NOT idempotency_key OR external_phase IS NOT phase OR external_agent_id IS NOT agent_id OR external_task_digest IS NOT task_digest OR (state IN ('accepted','reconciled') AND (external_id IS NULL OR external_id='')) THEN 1 ELSE 0 END;"),
    SloQueryContract('Accepted `sessions_spawn` without exact accepted session identity', "SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN spawn_requests sr ON sr.spawn_request_id=eri.spawn_request_id AND sr.run_id=eri.run_id AND sr.transition_id=eri.transition_id AND sr.client_request_id=eri.client_request_id AND sr.spawn_idempotency_key=eri.idempotency_key AND sr.phase=eri.phase AND sr.agent_id=eri.agent_id AND sr.task_digest=eri.task_digest LEFT JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id AND s.client_request_id=sr.client_request_id AND s.spawn_idempotency_key=sr.spawn_idempotency_key AND s.phase=sr.phase AND s.agent_id=sr.agent_id AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key AND s.session_key=eri.external_id WHERE eri.rpc_kind='sessions_spawn' AND eri.state IN ('accepted','reconciled') AND (eri.external_id IS NULL OR eri.external_id='' OR sr.spawn_request_id IS NULL OR sr.state NOT IN ('accepted','completed') OR sr.session_key IS NULL OR sr.session_key='' OR sr.session_key<>eri.external_id OR s.session_id IS NULL);"),
    SloQueryContract('`sessions` row without exact spawn request same-row binding', "SELECT s.session_id FROM sessions s LEFT JOIN spawn_requests sr ON sr.spawn_request_id=s.spawn_request_id AND sr.run_id=s.run_id AND sr.transition_id=s.transition_id AND sr.client_request_id=s.client_request_id AND sr.spawn_idempotency_key=s.spawn_idempotency_key AND sr.phase=s.phase AND sr.agent_id=s.agent_id AND sr.task_digest=s.task_digest AND sr.session_key=s.session_key WHERE sr.spawn_request_id IS NULL OR s.session_key IS NULL OR s.session_key='';"),
    SloQueryContract('Lease leak after terminal state', "SELECT l.lease_id FROM leases l JOIN runs r USING(run_id) WHERE r.state IN ('finalized','rolled_back','rejected') AND l.state NOT IN ('released','release_not_required');"),
    SloQueryContract('Unknown usage blocks auto-local', "SELECT rb.run_id FROM run_budgets rb JOIN runs r ON r.run_id=rb.run_id WHERE r.state IN ('gate_passed','release_pending','finalized') AND rb.usage_confidence='unknown' UNION SELECT be.run_id FROM budget_events be JOIN runs r ON r.run_id=be.run_id WHERE r.state IN ('gate_passed','release_pending','finalized') AND be.usage_confidence='unknown';"),
    SloQueryContract('Model cost registry numeric bounds', "SELECT cost_registry_id FROM model_cost_registry WHERE typeof(input_cost_microusd_per_million)<>'integer' OR input_cost_microusd_per_million<0 OR input_cost_microusd_per_million>100000000000 OR typeof(output_cost_microusd_per_million)<>'integer' OR output_cost_microusd_per_million<0 OR output_cost_microusd_per_million>100000000000 OR provider='' OR model='' OR endpoint_binding_id='' OR capability_class='' OR confidence='unknown';"),
    SloQueryContract('Endpoint-bound budget event cost row blocks dispatch', "SELECT be.budget_event_id FROM budget_events be LEFT JOIN model_cost_registry m ON m.cost_registry_id=be.cost_registry_id AND m.provider=be.provider AND m.model=be.model AND m.endpoint_binding_id=be.endpoint_binding_id AND m.capability_class=be.capability_class AND m.effective_at=be.cost_effective_at AND m.registry_row_hash=be.cost_registry_hash WHERE be.event_type<>'human_attention' AND (be.provider IS NULL OR be.provider='' OR be.model IS NULL OR be.model='' OR be.endpoint_binding_id IS NULL OR be.endpoint_binding_id='' OR be.cost_registry_id IS NULL OR be.cost_registry_id='' OR be.cost_effective_at IS NULL OR be.cost_effective_at='' OR be.cost_registry_hash IS NULL OR be.cost_registry_hash='' OR m.cost_registry_id IS NULL OR m.confidence='unknown' OR be.cost_confidence IS NULL OR be.cost_confidence='unknown' OR be.cost_confidence<>m.confidence);"),
    SloQueryContract('Run budget selected cost row mismatch', "SELECT rb.run_id FROM run_budgets rb LEFT JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id WHERE m.cost_registry_id IS NULL OR rb.selected_provider<>m.provider OR rb.selected_model<>m.model OR rb.selected_endpoint_binding_id<>m.endpoint_binding_id OR rb.capability_class<>m.capability_class OR rb.selected_cost_effective_at<>m.effective_at OR rb.selected_cost_registry_hash<>m.registry_row_hash OR rb.selected_cost_confidence<>m.confidence OR m.confidence='unknown' OR typeof(m.input_cost_microusd_per_million)<>'integer' OR typeof(m.output_cost_microusd_per_million)<>'integer';"),
    SloQueryContract('`sessions_spawn` intent without exact strict prior reserve', "SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN run_budgets rb ON rb.run_id=eri.run_id LEFT JOIN budget_events be ON be.budget_event_id=eri.reserve_budget_event_id LEFT JOIN model_cost_registry m ON m.cost_registry_id=be.cost_registry_id AND m.provider=be.provider AND m.model=be.model AND m.endpoint_binding_id=be.endpoint_binding_id AND m.capability_class=be.capability_class AND m.effective_at=be.cost_effective_at AND m.registry_row_hash=be.cost_registry_hash WHERE eri.rpc_kind='sessions_spawn' AND (rb.run_id IS NULL OR eri.reserve_budget_event_id IS NULL OR be.budget_event_id IS NULL OR be.run_id IS NOT eri.run_id OR be.transition_id IS NOT eri.transition_id OR be.spawn_request_id IS NOT eri.spawn_request_id OR be.event_type<>'reserve' OR be.provider IS NOT rb.selected_provider OR be.model IS NOT rb.selected_model OR be.endpoint_binding_id IS NOT rb.selected_endpoint_binding_id OR be.capability_class IS NOT rb.capability_class OR be.cost_registry_id IS NOT rb.selected_cost_registry_id OR be.cost_effective_at IS NOT rb.selected_cost_effective_at OR be.cost_registry_hash IS NOT rb.selected_cost_registry_hash OR be.cost_confidence IS NOT rb.selected_cost_confidence OR typeof(be.created_at_epoch_ms)<>'integer' OR be.created_at_epoch_ms<1 OR be.created_at_epoch_ms>253402300799999 OR typeof(eri.requested_at_epoch_ms)<>'integer' OR eri.requested_at_epoch_ms<1 OR eri.requested_at_epoch_ms>253402300799999 OR be.created_at_epoch_ms>=eri.requested_at_epoch_ms OR m.cost_registry_id IS NULL OR m.confidence='unknown' OR be.cost_confidence IS NULL OR be.cost_confidence='unknown' OR be.cost_confidence<>m.confidence);"),
    SloQueryContract('Invalid zero-reserve policy', "SELECT zero_reserve_policy_id FROM endpoint_zero_reserve_policies WHERE typeof(enabled)<>'integer' OR enabled NOT IN (0,1) OR typeof(min_retry_units)<>'integer' OR min_retry_units<0 OR min_retry_units>1000000 OR typeof(min_time_seconds)<>'integer' OR min_time_seconds<0 OR min_time_seconds>31536000 OR typeof(min_human_attention_units)<>'integer' OR min_human_attention_units<0 OR min_human_attention_units>1000000 OR typeof(effective_from_epoch_ms)<>'integer' OR effective_from_epoch_ms<1 OR effective_from_epoch_ms>253402300799999 OR (effective_until_epoch_ms IS NOT NULL AND (typeof(effective_until_epoch_ms)<>'integer' OR effective_until_epoch_ms<=effective_from_epoch_ms OR effective_until_epoch_ms>253402300799999)) OR (enabled=1 AND min_retry_units<=0 AND min_time_seconds<=0 AND min_human_attention_units<=0);"),
    SloQueryContract('Meaningless `sessions_spawn` reserve', "SELECT eri.intent_id FROM external_rpc_intents eri JOIN budget_events be ON be.budget_event_id=eri.reserve_budget_event_id LEFT JOIN endpoint_zero_reserve_policies zp ON zp.zero_reserve_policy_id=be.zero_reserve_policy_id WHERE eri.rpc_kind='sessions_spawn' AND be.event_type='reserve' AND ((be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.zero_reserve_policy_id IS NULL) OR (be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.time_seconds=0 AND be.human_attention_units=0 AND be.retry_units=0) OR (be.zero_reserve_policy_id IS NOT NULL AND (zp.zero_reserve_policy_id IS NULL OR zp.enabled<>1 OR zp.endpoint_binding_id<>be.endpoint_binding_id OR zp.capability_class<>be.capability_class OR zp.policy_hash<>be.zero_reserve_policy_hash OR be.created_at_epoch_ms<zp.effective_from_epoch_ms OR (zp.effective_until_epoch_ms IS NOT NULL AND be.created_at_epoch_ms>=zp.effective_until_epoch_ms) OR (zp.min_retry_units<=0 AND zp.min_time_seconds<=0 AND zp.min_human_attention_units<=0) OR (zp.min_retry_units>0 AND be.retry_units<zp.min_retry_units) OR (zp.min_time_seconds>0 AND be.time_seconds<zp.min_time_seconds) OR (zp.min_human_attention_units>0 AND be.human_attention_units<zp.min_human_attention_units))));"),
    SloQueryContract('Budget event amount malformed or out of range', "SELECT budget_event_id FROM budget_events WHERE typeof(event_sequence)<>'integer' OR event_sequence<1 OR event_sequence>1000000 OR typeof(created_at_epoch_ms)<>'integer' OR created_at_epoch_ms<1 OR created_at_epoch_ms>253402300799999 OR typeof(time_seconds)<>'integer' OR time_seconds<0 OR time_seconds>31536000 OR typeof(input_tokens)<>'integer' OR input_tokens<0 OR input_tokens>1000000000 OR typeof(output_tokens)<>'integer' OR output_tokens<0 OR output_tokens>1000000000 OR typeof(cost_microusd)<>'integer' OR cost_microusd<0 OR cost_microusd>100000000000 OR typeof(human_attention_units)<>'integer' OR human_attention_units<0 OR human_attention_units>1000000 OR typeof(retry_units)<>'integer' OR retry_units<0 OR retry_units>1000000 OR (event_type='consume' AND (retry_units<>0 OR human_attention_units<>0)) OR (event_type='human_attention' AND (time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR retry_units<>0 OR human_attention_units<=0)) OR (event_type='retry_decrement' AND (retry_units=0 OR time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR human_attention_units<>0)) OR (event_type='retry_restore' AND (retry_units=0 OR time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR human_attention_units<>0));"),
    SloQueryContract('Budget counters outside selected budget', "SELECT run_id FROM run_budgets WHERE typeof(time_budget_seconds)<>'integer' OR time_budget_seconds<0 OR time_budget_seconds>31536000 OR typeof(input_token_budget)<>'integer' OR input_token_budget<0 OR input_token_budget>1000000000 OR typeof(output_token_budget)<>'integer' OR output_token_budget<0 OR output_token_budget>1000000000 OR typeof(cost_budget_microusd)<>'integer' OR cost_budget_microusd<0 OR cost_budget_microusd>100000000000 OR typeof(retry_budget)<>'integer' OR retry_budget<0 OR retry_budget>1000000 OR typeof(human_attention_budget)<>'integer' OR human_attention_budget<0 OR human_attention_budget>1000000 OR typeof(reserved_time_seconds)<>'integer' OR reserved_time_seconds<0 OR reserved_time_seconds>time_budget_seconds OR typeof(reserved_input_tokens)<>'integer' OR reserved_input_tokens<0 OR reserved_input_tokens>input_token_budget OR typeof(reserved_output_tokens)<>'integer' OR reserved_output_tokens<0 OR reserved_output_tokens>output_token_budget OR typeof(reserved_cost_microusd)<>'integer' OR reserved_cost_microusd<0 OR reserved_cost_microusd>cost_budget_microusd OR typeof(reserved_retries)<>'integer' OR reserved_retries<0 OR reserved_retries>retry_budget OR typeof(reserved_human_attention)<>'integer' OR reserved_human_attention<0 OR reserved_human_attention>human_attention_budget OR typeof(consumed_time_seconds)<>'integer' OR consumed_time_seconds<0 OR consumed_time_seconds>time_budget_seconds OR typeof(consumed_input_tokens)<>'integer' OR consumed_input_tokens<0 OR consumed_input_tokens>input_token_budget OR typeof(consumed_output_tokens)<>'integer' OR consumed_output_tokens<0 OR consumed_output_tokens>output_token_budget OR typeof(consumed_cost_microusd)<>'integer' OR consumed_cost_microusd<0 OR consumed_cost_microusd>cost_budget_microusd OR typeof(consumed_retries)<>'integer' OR consumed_retries<0 OR consumed_retries>retry_budget OR typeof(consumed_human_attention)<>'integer' OR consumed_human_attention<0 OR consumed_human_attention>human_attention_budget OR reserved_time_seconds+consumed_time_seconds>time_budget_seconds OR reserved_input_tokens+consumed_input_tokens>input_token_budget OR reserved_output_tokens+consumed_output_tokens>output_token_budget OR reserved_cost_microusd+consumed_cost_microusd>cost_budget_microusd OR reserved_retries+consumed_retries>retry_budget OR reserved_human_attention+consumed_human_attention>human_attention_budget;"),
    SloQueryContract('Budget ledger reconciles to counters and budgets', "WITH event_sums AS (SELECT run_id, SUM(CASE WHEN event_type='reserve' THEN time_seconds WHEN event_type IN ('release','consume') THEN -time_seconds ELSE 0 END) AS net_reserved_time, SUM(CASE WHEN event_type='reserve' THEN input_tokens WHEN event_type IN ('release','consume') THEN -input_tokens ELSE 0 END) AS net_reserved_input, SUM(CASE WHEN event_type='reserve' THEN output_tokens WHEN event_type IN ('release','consume') THEN -output_tokens ELSE 0 END) AS net_reserved_output, SUM(CASE WHEN event_type='reserve' THEN cost_microusd WHEN event_type IN ('release','consume') THEN -cost_microusd ELSE 0 END) AS net_reserved_cost, SUM(CASE WHEN event_type='reserve' THEN retry_units WHEN event_type IN ('release','retry_decrement') THEN -retry_units WHEN event_type='retry_restore' THEN retry_units ELSE 0 END) AS net_reserved_retries, SUM(CASE WHEN event_type='reserve' THEN human_attention_units WHEN event_type IN ('release','human_attention') THEN -human_attention_units ELSE 0 END) AS net_reserved_human, SUM(CASE WHEN event_type='consume' THEN time_seconds ELSE 0 END) AS consumed_time, SUM(CASE WHEN event_type='consume' THEN input_tokens ELSE 0 END) AS consumed_input, SUM(CASE WHEN event_type='consume' THEN output_tokens ELSE 0 END) AS consumed_output, SUM(CASE WHEN event_type='consume' THEN cost_microusd ELSE 0 END) AS consumed_cost, SUM(CASE WHEN event_type='retry_decrement' THEN retry_units WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END) AS consumed_retries, SUM(CASE WHEN event_type='human_attention' THEN human_attention_units ELSE 0 END) AS consumed_human FROM budget_events GROUP BY run_id), missing_budgets AS (SELECT DISTINCT be.run_id FROM budget_events be LEFT JOIN run_budgets rb ON rb.run_id=be.run_id WHERE rb.run_id IS NULL) SELECT run_id FROM missing_budgets UNION SELECT rb.run_id FROM run_budgets rb LEFT JOIN event_sums s USING(run_id) WHERE COALESCE(s.net_reserved_time,0)<0 OR COALESCE(s.net_reserved_input,0)<0 OR COALESCE(s.net_reserved_output,0)<0 OR COALESCE(s.net_reserved_cost,0)<0 OR COALESCE(s.net_reserved_retries,0)<0 OR COALESCE(s.net_reserved_human,0)<0 OR (COALESCE(s.net_reserved_time,0)>=0 AND COALESCE(s.net_reserved_time,0)<>rb.reserved_time_seconds) OR (COALESCE(s.net_reserved_input,0)>=0 AND COALESCE(s.net_reserved_input,0)<>rb.reserved_input_tokens) OR (COALESCE(s.net_reserved_output,0)>=0 AND COALESCE(s.net_reserved_output,0)<>rb.reserved_output_tokens) OR (COALESCE(s.net_reserved_cost,0)>=0 AND COALESCE(s.net_reserved_cost,0)<>rb.reserved_cost_microusd) OR (COALESCE(s.net_reserved_retries,0)>=0 AND COALESCE(s.net_reserved_retries,0)<>rb.reserved_retries) OR (COALESCE(s.net_reserved_human,0)>=0 AND COALESCE(s.net_reserved_human,0)<>rb.reserved_human_attention) OR COALESCE(s.consumed_time,0)<>rb.consumed_time_seconds OR COALESCE(s.consumed_input,0)<>rb.consumed_input_tokens OR COALESCE(s.consumed_output,0)<>rb.consumed_output_tokens OR COALESCE(s.consumed_cost,0)<>rb.consumed_cost_microusd OR COALESCE(s.consumed_retries,0)<>rb.consumed_retries OR COALESCE(s.consumed_human,0)<>rb.consumed_human_attention OR COALESCE(s.net_reserved_time,0)>rb.time_budget_seconds OR COALESCE(s.net_reserved_input,0)>rb.input_token_budget OR COALESCE(s.net_reserved_output,0)>rb.output_token_budget OR COALESCE(s.net_reserved_cost,0)>rb.cost_budget_microusd OR COALESCE(s.net_reserved_retries,0)>rb.retry_budget OR COALESCE(s.net_reserved_human,0)>rb.human_attention_budget OR COALESCE(s.consumed_time,0)>rb.time_budget_seconds OR COALESCE(s.consumed_input,0)>rb.input_token_budget OR COALESCE(s.consumed_output,0)>rb.output_token_budget OR COALESCE(s.consumed_cost,0)>rb.cost_budget_microusd OR COALESCE(s.consumed_retries,0)>rb.retry_budget OR COALESCE(s.consumed_human,0)>rb.human_attention_budget OR COALESCE(s.net_reserved_time,0)+COALESCE(s.consumed_time,0)>rb.time_budget_seconds OR COALESCE(s.net_reserved_input,0)+COALESCE(s.consumed_input,0)>rb.input_token_budget OR COALESCE(s.net_reserved_output,0)+COALESCE(s.consumed_output,0)>rb.output_token_budget OR COALESCE(s.net_reserved_cost,0)+COALESCE(s.consumed_cost,0)>rb.cost_budget_microusd OR COALESCE(s.net_reserved_retries,0)+COALESCE(s.consumed_retries,0)>rb.retry_budget OR COALESCE(s.net_reserved_human,0)+COALESCE(s.consumed_human,0)>rb.human_attention_budget;"),
    SloQueryContract(
        'Budget prefix over-release or over-restore',
        "WITH ordered AS (SELECT budget_event_id, run_id, event_sequence, SUM(CASE WHEN event_type='reserve' THEN time_seconds WHEN event_type IN ('release','consume') THEN -time_seconds ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_time, SUM(CASE WHEN event_type='reserve' THEN input_tokens WHEN event_type IN ('release','consume') THEN -input_tokens ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_input, SUM(CASE WHEN event_type='reserve' THEN output_tokens WHEN event_type IN ('release','consume') THEN -output_tokens ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_output, SUM(CASE WHEN event_type='reserve' THEN cost_microusd WHEN event_type IN ('release','consume') THEN -cost_microusd ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_cost, SUM(CASE WHEN event_type='reserve' THEN retry_units WHEN event_type IN ('release','retry_decrement') THEN -retry_units WHEN event_type='retry_restore' THEN retry_units ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_reserved_retry, SUM(CASE WHEN event_type='retry_decrement' THEN retry_units WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_retry_consumed, SUM(CASE WHEN event_type='reserve' THEN human_attention_units WHEN event_type IN ('release','human_attention') THEN -human_attention_units ELSE 0 END) OVER (PARTITION BY run_id ORDER BY event_sequence) AS net_human FROM budget_events) SELECT o.budget_event_id FROM ordered o LEFT JOIN run_budgets rb ON rb.run_id=o.run_id WHERE rb.run_id IS NULL OR o.net_time<0 OR o.net_input<0 OR o.net_output<0 OR o.net_cost<0 OR o.net_reserved_retry<0 OR o.net_retry_consumed<0 OR o.net_human<0 OR o.net_time>rb.time_budget_seconds OR o.net_input>rb.input_token_budget OR o.net_output>rb.output_token_budget OR o.net_cost>rb.cost_budget_microusd OR o.net_reserved_retry>rb.retry_budget OR o.net_retry_consumed>rb.retry_budget OR o.net_human>rb.human_attention_budget;",
    ),
    SloQueryContract('Duplicate or replayed budget events', 'SELECT event_dedupe_hash FROM budget_events GROUP BY event_dedupe_hash HAVING COUNT(*)>1;'),
    SloQueryContract('Budget event count bounded for SUM safety', 'SELECT run_id FROM budget_events GROUP BY run_id HAVING COUNT(*)>1000000 OR MIN(event_sequence)<1 OR MAX(event_sequence)>1000000;'),
    SloQueryContract('Completion gate before done for R2+', "SELECT r.run_id FROM runs r WHERE r.risk_dominance IN ('R2','R3','R4') AND r.state='finalized' AND (r.finalized_at IS NULL OR r.finalized_at='' OR r.finalized_at_epoch_ms IS NULL OR typeof(r.finalized_at_epoch_ms)<>'integer' OR r.finalized_at_epoch_ms<1 OR r.finalized_at_epoch_ms>253402300799999 OR NOT EXISTS (SELECT 1 FROM transitions t JOIN gate_runs g ON g.run_id=t.run_id AND g.transition_id=t.transition_id AND g.decision='pass' WHERE t.run_id=r.run_id AND t.state_after='finalized' AND g.completed_at_epoch_ms IS NOT NULL AND typeof(g.completed_at_epoch_ms)='integer' AND g.completed_at_epoch_ms BETWEEN 1 AND 253402300799999 AND g.completed_at_epoch_ms <= r.finalized_at_epoch_ms));"),
    SloQueryContract('Passing gate without verifier row', "SELECT g.gate_run_id FROM gate_runs g LEFT JOIN judge_verifier_runs v ON v.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND (g.verifier_run_id IS NULL OR v.verifier_run_id IS NULL);"),
    SloQueryContract('Passing gate wrong-run or non-independent verifier', "SELECT g.gate_run_id FROM gate_runs g JOIN judge_verifier_runs v ON v.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND (v.worker_run_id<>g.run_id OR v.same_worker_context=1 OR v.verifier_agent_id=v.worker_agent_id OR v.prompt_hash=v.context_hash OR v.independence_class IN ('self','same_worker','same_context','correlated','unknown') OR json_valid(v.independence_proof_json)<>1 OR json_type(v.independence_proof_json)<>'object' OR json(v.independence_proof_json)='{}');"),
    SloQueryContract('Gate evidence bound to same run', "SELECT g.gate_run_id FROM gate_runs g LEFT JOIN evidence_hashes e ON e.gate_run_id=g.gate_run_id AND e.evidence_hash=g.evidence_hash AND e.run_id=g.run_id AND e.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND g.requires_same_run=1 AND (e.evidence_hash IS NULL OR e.producer_run_id IS NULL OR e.producer_run_id<>g.run_id OR e.verifier_run_id IS NULL OR e.verifier_run_id<>g.verifier_run_id);"),
    SloQueryContract('Gate clock context exact one-use binding', "SELECT g.gate_run_id FROM gate_runs g LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id WHERE g.decision='pass' AND (c.clock_context_id IS NULL OR c.gate_run_id<>g.gate_run_id OR c.consumed_by_gate_run_id<>g.gate_run_id OR c.run_id<>g.run_id OR c.transition_id<>g.transition_id OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR typeof(c.bound_at_epoch_ms)<>'integer' OR c.bound_at_epoch_ms<1 OR c.bound_at_epoch_ms>253402300799999 OR c.bound_at_epoch_ms<>c.now_epoch_ms OR typeof(c.consumed_at_epoch_ms)<>'integer' OR c.consumed_at_epoch_ms<1 OR c.consumed_at_epoch_ms>253402300799999 OR typeof(g.completed_at_epoch_ms)<>'integer' OR g.completed_at_epoch_ms<1 OR g.completed_at_epoch_ms>253402300799999 OR g.completed_at_epoch_ms<>c.now_epoch_ms OR c.consumed_at_epoch_ms<>c.now_epoch_ms OR c.trusted_clock_source_hash IS NULL OR c.trusted_clock_source_hash='' OR c.gate_nonce IS NULL OR c.gate_nonce='');"),
    SloQueryContract('Broad or expired approvals', "SELECT a.approval_id FROM transitions t JOIN gate_runs g ON g.gate_run_id=t.gate_run_id LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id LEFT JOIN approvals a ON a.approval_id=t.approval_id WHERE g.decision='pass' AND t.approval_required=1 AND (c.clock_context_id IS NULL OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR a.approval_id IS NULL OR typeof(a.expires_at_epoch_ms)<>'integer' OR a.expires_at_epoch_ms<1 OR a.expires_at_epoch_ms>253402300799999 OR a.expires_at_epoch_ms<=c.now_epoch_ms OR a.approved_action_type='' OR a.approved_risk_ceiling='' OR a.target_type IS NULL OR a.target_type='' OR a.target_id IS NULL OR a.target_id='' OR a.target_hash IS NULL OR a.target_hash='' OR a.target_scope IS NULL OR a.target_scope='');"),
    SloQueryContract('Exact mutating approval binding', "SELECT t.transition_id FROM transitions t JOIN gate_runs g ON g.gate_run_id=t.gate_run_id LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id LEFT JOIN approvals a ON a.approval_id=t.approval_id LEFT JOIN risk_assessments ra ON ra.transition_id=t.transition_id AND ra.run_id=t.run_id WHERE g.decision='pass' AND t.approval_required=1 AND (g.run_id<>t.run_id OR g.transition_id<>t.transition_id OR c.clock_context_id IS NULL OR c.gate_run_id<>g.gate_run_id OR c.run_id<>g.run_id OR c.transition_id<>t.transition_id OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR typeof(g.completed_at_epoch_ms)<>'integer' OR g.completed_at_epoch_ms<1 OR g.completed_at_epoch_ms>253402300799999 OR g.completed_at_epoch_ms<>c.now_epoch_ms OR a.approval_id IS NULL OR a.run_id IS NULL OR a.run_id<>t.run_id OR a.run_id<>g.run_id OR typeof(a.expires_at_epoch_ms)<>'integer' OR a.expires_at_epoch_ms<1 OR a.expires_at_epoch_ms>253402300799999 OR a.expires_at_epoch_ms<=c.now_epoch_ms OR a.single_use<>1 OR a.consumed_by_transition_id IS NULL OR a.consumed_by_transition_id<>t.transition_id OR a.consumed_by_gate_run_id IS NULL OR a.consumed_by_gate_run_id<>g.gate_run_id OR a.approved_action_type<>t.action_type OR a.target_type<>t.target_type OR a.target_id<>t.target_id OR a.target_hash<>t.target_hash OR a.target_scope<>t.target_scope OR a.channel<>t.approval_channel OR a.source_message_digest<>t.approval_source_digest OR a.approval_text_digest<>t.approval_text_digest OR ra.assessment_id IS NULL OR ra.risk_dominance<>t.risk_dominance OR CASE a.approved_risk_ceiling WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1 END < CASE t.risk_dominance WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99 END);"),
    SloQueryContract('Reused approval id', 'SELECT approval_id FROM transitions WHERE approval_id IS NOT NULL GROUP BY approval_id HAVING COUNT(*)>1;'),
    SloQueryContract('Non-independent verifier row', "SELECT verifier_run_id FROM judge_verifier_runs WHERE same_worker_context=1 OR verifier_agent_id=worker_agent_id OR prompt_hash=context_hash OR worker_run_id IS NULL OR independence_class IN ('self','same_worker','same_context','correlated','unknown') OR json_valid(independence_proof_json)<>1 OR json_type(independence_proof_json)<>'object' OR json(independence_proof_json)='{}';"),
    SloQueryContract('SLO query fixture status', "WITH required(query_name) AS (VALUES ('Metadata-missing external RPC not auto-repaired'),('Duplicate live dispatch blocked'),('`sessions_spawn` intent without exact spawn request binding'),('`sessions_spawn` external metadata exact match'),('Accepted `sessions_spawn` without exact accepted session identity'),('`sessions` row without exact spawn request same-row binding'),('Lease leak after terminal state'),('Unknown usage blocks auto-local'),('Model cost registry numeric bounds'),('Endpoint-bound budget event cost row blocks dispatch'),('Run budget selected cost row mismatch'),('`sessions_spawn` intent without exact strict prior reserve'),('Invalid zero-reserve policy'),('Meaningless `sessions_spawn` reserve'),('Budget event amount malformed or out of range'),('Budget counters outside selected budget'),('Budget ledger reconciles to counters and budgets'),('Budget prefix over-release or over-restore'),('Duplicate or replayed budget events'),('Budget event count bounded for SUM safety'),('Completion gate before done for R2+'),('Passing gate without verifier row'),('Passing gate wrong-run or non-independent verifier'),('Gate evidence bound to same run'),('Gate clock context exact one-use binding'),('Broad or expired approvals'),('Exact mutating approval binding'),('Reused approval id'),('Non-independent verifier row'),('SLO query fixture status')), audit_required(query_name) AS (SELECT query_name FROM required WHERE query_name<>'SLO query fixture status'), current_schema(schema_version,migration_sha256) AS (SELECT version,sha256 FROM schema_migrations ORDER BY version DESC LIMIT 1), blocking(query_name) AS (SELECT r.query_name FROM audit_required r CROSS JOIN current_schema cs LEFT JOIN slo_queries q ON q.query_name=r.query_name AND q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256 LEFT JOIN slo_audits a ON a.slo_audit_id=(SELECT a2.slo_audit_id FROM slo_audits a2 WHERE a2.query_name=q.query_name AND a2.schema_version=q.schema_version AND a2.migration_sha256=q.migration_sha256 AND a2.query_hash=q.query_hash ORDER BY a2.run_at_epoch_ms DESC,a2.slo_audit_id DESC LIMIT 1) LEFT JOIN evidence_hashes e ON e.gate_run_id=a.gate_run_id AND e.evidence_hash=a.evidence_hash AND e.run_id=a.evidence_run_id AND e.verifier_run_id=a.verifier_run_id LEFT JOIN gate_runs g ON g.gate_run_id=a.gate_run_id AND g.evidence_hash=a.evidence_hash AND g.run_id=a.evidence_run_id AND g.verifier_run_id=a.verifier_run_id AND g.decision='pass' WHERE q.query_name IS NULL OR a.slo_audit_id IS NULL OR a.status<>'pass' OR a.empty_db_status<>'pass' OR a.fixture_db_status<>'pass' OR a.schema_version<>q.schema_version OR a.migration_sha256<>q.migration_sha256 OR a.query_hash<>q.query_hash OR a.evidence_hash IS NULL OR a.evidence_run_id IS NULL OR a.verifier_run_id IS NULL OR a.gate_run_id IS NULL OR e.evidence_hash IS NULL OR e.producer_run_id<>a.evidence_run_id OR e.run_id<>a.evidence_run_id OR e.verifier_run_id<>a.verifier_run_id OR e.gate_run_id<>a.gate_run_id OR g.gate_run_id IS NULL UNION ALL SELECT q.query_name FROM slo_queries q JOIN current_schema cs ON q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256 LEFT JOIN required r ON r.query_name=q.query_name WHERE r.query_name IS NULL UNION ALL SELECT '__slo_registry_count__' WHERE (SELECT COUNT(*) FROM slo_queries q JOIN current_schema cs ON q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256)<>(SELECT COUNT(*) FROM required)) SELECT query_name FROM blocking;"),
)

SLO_QUERY_COUNT = len(SLO_QUERY_CONTRACTS)


def _contract_by_name(query_name: str) -> SloQueryContract:
    for contract in SLO_QUERY_CONTRACTS:
        if contract.query_name == query_name:
            return contract
    raise RuntimeError(f"missing required SLO query contract: {query_name}")


def _legacy_retry_reservation_sql(sql_text: str) -> str:
    return sql_text.replace(
        "SUM(CASE WHEN event_type='reserve' THEN retry_units "
        "WHEN event_type IN ('release','retry_decrement') THEN -retry_units "
        "WHEN event_type='retry_restore' THEN retry_units ELSE 0 END)",
        "SUM(CASE WHEN event_type='reserve' THEN retry_units "
        "WHEN event_type='release' THEN -retry_units ELSE 0 END)",
    )


def _legacy_budget_ledger_reconciles_sql() -> str:
    sql_text = _legacy_retry_reservation_sql(
        _contract_by_name(_BUDGET_LEDGER_RECONCILES_NAME).sql_text
    )
    for column in (
        "reserved_time_seconds",
        "reserved_input_tokens",
        "reserved_output_tokens",
        "reserved_cost_microusd",
        "reserved_retries",
        "reserved_human_attention",
    ):
        stem = {
            "reserved_time_seconds": "time",
            "reserved_input_tokens": "input",
            "reserved_output_tokens": "output",
            "reserved_cost_microusd": "cost",
            "reserved_retries": "retries",
            "reserved_human_attention": "human",
        }[column]
        sql_text = sql_text.replace(
            f"OR (COALESCE(s.net_reserved_{stem},0)>=0 "
            f"AND COALESCE(s.net_reserved_{stem},0)<>rb.{column})",
            f"OR COALESCE(s.net_reserved_{stem},0)<>rb.{column}",
        )
    actual_hash = slo_query_hash(sql_text)
    if actual_hash != _BUDGET_LEDGER_RECONCILES_LEGACY_V1_V2_HASH:
        raise RuntimeError(
            "legacy v1/v2 budget ledger SLO hash drift: "
            f"expected {_BUDGET_LEDGER_RECONCILES_LEGACY_V1_V2_HASH}, found {actual_hash}"
        )
    return sql_text


def _legacy_retry_reservation_contract(query_name: str) -> SloQueryContract:
    contract = _contract_by_name(query_name)
    return SloQueryContract(
        contract.query_name,
        _legacy_retry_reservation_sql(contract.sql_text),
        contract.empty_db_expected_status,
        contract.fixture_db_expected_status,
    )


def _post_dispatch_session_proof_contract(
    *,
    require_accepted_timing: bool = False,
    require_selected_cost: bool = False,
    require_selected_transition: bool = False,
    require_trusted_clock: bool = False,
) -> SloQueryContract:
    contract = _contract_by_name(
        'Accepted `sessions_spawn` without exact accepted session identity'
    )
    base_sql = contract.sql_text.rstrip()
    if base_sql.endswith(";"):
        base_sql = base_sql[:-1]
    timing_predicate = (
        "OR typeof(eri.accepted_at_epoch_ms)<>'integer' "
        "OR eri.accepted_at_epoch_ms<1 "
        "OR eri.accepted_at_epoch_ms>253402300799999 "
        "OR typeof(eri.requested_at_epoch_ms)<>'integer' "
        "OR eri.requested_at_epoch_ms<1 "
        "OR eri.requested_at_epoch_ms>253402300799999 "
        "OR eri.accepted_at_epoch_ms<=eri.requested_at_epoch_ms "
        "OR typeof(be.created_at_epoch_ms)<>'integer' "
        "OR be.created_at_epoch_ms<1 "
        "OR be.created_at_epoch_ms>253402300799999 "
        "OR be.created_at_epoch_ms<=eri.accepted_at_epoch_ms "
        "OR be.created_at_epoch_ms<=eri.requested_at_epoch_ms "
        if require_accepted_timing
        else ""
    )
    selected_transition_predicate = (
        "OR be.transition_id IS NOT rb.selected_reserve_transition_id "
        if require_selected_transition
        else ""
    )
    selected_cost_predicate = (
        "OR rb.run_id IS NULL OR be.provider IS NOT rb.selected_provider "
        "OR be.model IS NOT rb.selected_model "
        "OR be.endpoint_binding_id IS NOT rb.selected_endpoint_binding_id "
        "OR be.capability_class IS NOT rb.capability_class "
        "OR be.cost_registry_id IS NOT rb.selected_cost_registry_id "
        "OR be.cost_effective_at IS NOT rb.selected_cost_effective_at "
        "OR be.cost_registry_hash IS NOT rb.selected_cost_registry_hash "
        "OR be.cost_confidence IS NOT rb.selected_cost_confidence "
        f"{selected_transition_predicate}"
        if require_selected_cost
        else ""
    )
    selected_cost_join = (
        "LEFT JOIN run_budgets rb ON rb.run_id=be.run_id "
        if require_selected_cost
        else ""
    )
    trusted_clock_join = (
        "LEFT JOIN gate_clock_context c ON c.clock_context_id=be.clock_context_id "
        "AND c.run_id=be.run_id AND c.transition_id=be.transition_id "
        "LEFT JOIN gate_runs g ON g.gate_run_id=c.gate_run_id "
        "AND g.clock_context_id=c.clock_context_id "
        "AND g.run_id=c.run_id AND g.transition_id=c.transition_id "
        if require_trusted_clock
        else ""
    )
    trusted_clock_predicate = (
        "OR be.clock_context_id IS NULL OR be.clock_context_id='' "
        "OR c.clock_context_id IS NULL "
        "OR c.gate_run_id IS NULL OR c.consumed_by_gate_run_id IS NULL "
        "OR c.consumed_by_gate_run_id IS NOT c.gate_run_id "
        "OR typeof(c.now_epoch_ms)<>'integer' "
        "OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 "
        "OR typeof(c.bound_at_epoch_ms)<>'integer' "
        "OR c.bound_at_epoch_ms<1 "
        "OR c.bound_at_epoch_ms>253402300799999 "
        "OR c.bound_at_epoch_ms IS NOT c.now_epoch_ms "
        "OR typeof(c.consumed_at_epoch_ms)<>'integer' "
        "OR c.consumed_at_epoch_ms<1 "
        "OR c.consumed_at_epoch_ms>253402300799999 "
        "OR c.consumed_at_epoch_ms IS NOT c.now_epoch_ms "
        "OR c.trusted_clock_source_hash IS NULL "
        "OR c.trusted_clock_source_hash='' "
        "OR c.gate_nonce IS NULL OR c.gate_nonce='' "
        "OR g.gate_run_id IS NULL OR g.decision<>'pass' "
        "OR typeof(g.completed_at_epoch_ms)<>'integer' "
        "OR g.completed_at_epoch_ms<1 "
        "OR g.completed_at_epoch_ms>253402300799999 "
        "OR g.completed_at_epoch_ms IS NOT c.now_epoch_ms "
        "OR be.created_at_epoch_ms IS NOT c.now_epoch_ms "
        if require_trusted_clock
        else ""
    )
    post_dispatch_sql = (
        " UNION SELECT be.budget_event_id FROM budget_events be "
        "LEFT JOIN spawn_requests sr ON sr.spawn_request_id=be.spawn_request_id "
        "AND sr.run_id=be.run_id AND sr.transition_id=be.transition_id "
        "LEFT JOIN external_rpc_intents eri ON eri.rpc_kind='sessions_spawn' "
        "AND eri.state IN ('accepted','reconciled') "
        "AND eri.spawn_request_id=sr.spawn_request_id AND eri.run_id=sr.run_id "
        "AND eri.transition_id=sr.transition_id "
        "AND eri.client_request_id=sr.client_request_id "
        "AND eri.idempotency_key=sr.spawn_idempotency_key "
        "AND eri.phase=sr.phase AND eri.agent_id=sr.agent_id "
        "AND eri.task_digest=sr.task_digest AND eri.external_id=sr.session_key "
        "LEFT JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id "
        "AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id "
        "AND s.client_request_id=sr.client_request_id "
        "AND s.spawn_idempotency_key=sr.spawn_idempotency_key "
        "AND s.phase=sr.phase AND s.agent_id=sr.agent_id "
        "AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key "
        "AND s.session_key=eri.external_id "
        f"{trusted_clock_join}"
        f"{selected_cost_join}"
        "WHERE be.event_type IN ('consume','retry_decrement','retry_restore',"
        "'human_attention') AND (be.spawn_request_id IS NULL "
        "OR sr.spawn_request_id IS NULL OR sr.state NOT IN ('accepted','completed') "
        "OR sr.session_key IS NULL OR sr.session_key='' "
        "OR eri.intent_id IS NULL OR eri.external_id IS NULL OR eri.external_id='' "
        f"{timing_predicate}"
        f"{trusted_clock_predicate}"
        f"{selected_cost_predicate}"
        "OR s.session_id IS NULL OR (be.event_type='consume' "
        "AND (sr.state<>'completed' OR s.state<>'completed' "
        "OR s.completed_at IS NULL OR s.completed_at='')))"
    )
    return SloQueryContract(
        contract.query_name,
        base_sql + post_dispatch_sql,
        contract.empty_db_expected_status,
        contract.fixture_db_expected_status,
    )


def _spawn_partition_budget_prefix_contract() -> SloQueryContract:
    contract = _contract_by_name(_BUDGET_PREFIX_NAME)
    old_window = "OVER (PARTITION BY run_id ORDER BY event_sequence)"
    new_window = (
        "OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class "
        "ORDER BY event_sequence)"
    )
    if contract.sql_text.count(old_window) != 7:
        raise RuntimeError("budget prefix SLO partition replacement count changed")
    sql_text = contract.sql_text.replace(old_window, new_window)
    return SloQueryContract(
        contract.query_name,
        sql_text,
        contract.empty_db_expected_status,
        contract.fixture_db_expected_status,
    )


def _consume_confidence_amount_contract() -> SloQueryContract:
    contract = _contract_by_name("Budget event amount malformed or out of range")
    sql_text = contract.sql_text.rstrip()
    if sql_text.endswith(";"):
        sql_text = sql_text[:-1]
    sql_text += (
        " OR (event_type='consume' AND usage_confidence='unknown' "
        "AND (time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 "
        "OR cost_microusd<>0)) "
        "OR (event_type='consume' AND usage_confidence IN ('known','estimated') "
        "AND time_seconds=0 AND input_tokens=0 AND output_tokens=0 "
        "AND cost_microusd=0);"
    )
    return SloQueryContract(
        contract.query_name,
        sql_text,
        contract.empty_db_expected_status,
        contract.fixture_db_expected_status,
    )


def _atomic_final_settlement_contract(
    contract: SloQueryContract,
) -> SloQueryContract:
    sql_text = contract.sql_text.rstrip()
    if sql_text.endswith(";"):
        sql_text = sql_text[:-1]
    sql_text += (
        " UNION ALL SELECT bs.settlement_id FROM budget_settlements bs WHERE "
        "((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 "
        "OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) "
        "IS NOT (SELECT COUNT(*)=1 FROM budget_events be "
        "WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume')) "
        "OR ((bs.actual_retry_units>0) IS NOT (SELECT COUNT(*)=1 "
        "FROM budget_events be WHERE be.settlement_id=bs.settlement_id "
        "AND be.event_type='retry_decrement')) "
        "OR ((bs.actual_human_attention_units>0) IS NOT (SELECT COUNT(*)=1 "
        "FROM budget_events be WHERE be.settlement_id=bs.settlement_id "
        "AND be.event_type='human_attention')) "
        "OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 "
        "OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 "
        "OR bs.released_retry_units>0 OR bs.released_human_attention_units>0) "
        "IS NOT (SELECT COUNT(*)=1 FROM budget_events be "
        "WHERE be.settlement_id=bs.settlement_id AND be.event_type='release')) "
        "OR EXISTS (SELECT 1 FROM budget_events be "
        "WHERE be.settlement_id=bs.settlement_id "
        "AND be.event_type NOT IN ('consume','retry_decrement',"
        "'human_attention','release')) "
        "OR EXISTS (SELECT 1 FROM budget_events be "
        "WHERE be.settlement_id IS NULL AND be.run_id=bs.run_id "
        "AND be.transition_id=bs.transition_id "
        "AND be.spawn_request_id=bs.spawn_request_id "
        "AND be.event_type IN ('consume','retry_decrement',"
        "'retry_restore','human_attention') "
        "AND be.event_sequence>(SELECT COALESCE(MAX(linked.event_sequence),0) "
        "FROM budget_events linked WHERE linked.settlement_id=bs.settlement_id)) "
        "OR NOT EXISTS (SELECT 1 FROM spawn_requests sr "
        "JOIN runs r ON r.run_id=sr.run_id "
        "JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id "
        "AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id "
        "AND s.client_request_id=sr.client_request_id "
        "AND s.spawn_idempotency_key=sr.spawn_idempotency_key "
        "AND s.phase=sr.phase AND s.agent_id=sr.agent_id "
        "AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key "
        "JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' "
        "AND i.state IN ('accepted','reconciled') "
        "AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id "
        "AND i.transition_id=sr.transition_id "
        "AND i.client_request_id=sr.client_request_id "
        "AND i.idempotency_key=sr.spawn_idempotency_key "
        "AND i.phase=sr.phase AND i.agent_id=sr.agent_id "
        "AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key "
        "JOIN run_budgets rb ON rb.run_id=sr.run_id "
        "JOIN gate_clock_context c ON c.clock_context_id=bs.clock_context_id "
        "AND c.run_id=sr.run_id AND c.transition_id=sr.transition_id "
        "JOIN gate_runs g ON g.gate_run_id=c.gate_run_id "
        "AND g.clock_context_id=c.clock_context_id "
        "AND g.run_id=c.run_id AND g.transition_id=c.transition_id "
        "WHERE sr.spawn_request_id=bs.spawn_request_id "
        "AND sr.run_id=bs.run_id AND sr.transition_id=bs.transition_id "
        "AND sr.state='completed' AND s.state='completed' "
        "AND s.completed_at IS NOT NULL AND s.completed_at<>'' "
        "AND r.state IN ('child_completed','child_failed',"
        "'aggregation_completed') "
        "AND rb.selected_reserve_transition_id=bs.transition_id "
        "AND rb.selected_provider=bs.provider AND rb.selected_model=bs.model "
        "AND rb.selected_endpoint_binding_id=bs.endpoint_binding_id "
        "AND rb.capability_class=bs.capability_class "
        "AND rb.selected_cost_registry_id=bs.cost_registry_id "
        "AND rb.selected_cost_effective_at=bs.cost_effective_at "
        "AND rb.selected_cost_registry_hash=bs.cost_registry_hash "
        "AND rb.selected_cost_confidence=bs.cost_confidence "
        "AND rb.usage_confidence IN ('known','estimated') "
        "AND i.requested_at_epoch_ms<i.accepted_at_epoch_ms "
        "AND i.accepted_at_epoch_ms<bs.created_at_epoch_ms "
        "AND c.gate_run_id=c.consumed_by_gate_run_id "
        "AND c.bound_at_epoch_ms=c.now_epoch_ms "
        "AND c.consumed_at_epoch_ms=c.now_epoch_ms "
        "AND c.now_epoch_ms=bs.created_at_epoch_ms "
        "AND c.trusted_clock_source_hash<>'' AND c.gate_nonce<>'' "
        "AND g.decision='pass' AND g.completed_at_epoch_ms=c.now_epoch_ms);"
    )
    return SloQueryContract(
        contract.query_name,
        sql_text,
        contract.empty_db_expected_status,
        contract.fixture_db_expected_status,
    )


def _replace_contract(
    contracts: tuple[SloQueryContract, ...],
    replacement: SloQueryContract,
) -> tuple[SloQueryContract, ...]:
    return tuple(
        replacement if contract.query_name == replacement.query_name else contract
        for contract in contracts
    )


_SLO_QUERY_CONTRACTS_V3 = _replace_contract(
    _replace_contract(
        SLO_QUERY_CONTRACTS,
        _legacy_retry_reservation_contract(_BUDGET_LEDGER_RECONCILES_NAME),
    ),
    _legacy_retry_reservation_contract(_BUDGET_PREFIX_NAME),
)

_SLO_QUERY_CONTRACTS_V1_V2 = _replace_contract(
    _replace_contract(
        SLO_QUERY_CONTRACTS,
        SloQueryContract(
            _BUDGET_LEDGER_RECONCILES_NAME,
            _legacy_budget_ledger_reconciles_sql(),
        ),
    ),
    _legacy_retry_reservation_contract(_BUDGET_PREFIX_NAME),
)

_SLO_QUERY_CONTRACTS_V4 = SLO_QUERY_CONTRACTS
_SLO_QUERY_CONTRACTS_V5 = _replace_contract(
    _replace_contract(
        SLO_QUERY_CONTRACTS,
        _spawn_partition_budget_prefix_contract(),
    ),
    _post_dispatch_session_proof_contract(),
)
_SLO_QUERY_CONTRACTS_V6 = _replace_contract(
    _replace_contract(
        _SLO_QUERY_CONTRACTS_V5,
        _post_dispatch_session_proof_contract(
            require_accepted_timing=True, require_selected_cost=True
        ),
    ),
    _consume_confidence_amount_contract(),
)
_SLO_QUERY_CONTRACTS_V7 = _replace_contract(
    _SLO_QUERY_CONTRACTS_V6,
    _post_dispatch_session_proof_contract(
        require_accepted_timing=True,
        require_selected_cost=True,
        require_selected_transition=True,
        require_trusted_clock=True,
    ),
)
SLO_QUERY_CONTRACTS = _replace_contract(
    _SLO_QUERY_CONTRACTS_V7,
    _atomic_final_settlement_contract(
        next(
            contract
            for contract in _SLO_QUERY_CONTRACTS_V7
            if contract.query_name == "Budget event amount malformed or out of range"
        )
    ),
)

_SLO_QUERY_CONTRACTS_BY_SCHEMA_VERSION = {
    1: _SLO_QUERY_CONTRACTS_V1_V2,
    2: _SLO_QUERY_CONTRACTS_V1_V2,
    3: _SLO_QUERY_CONTRACTS_V3,
    4: _SLO_QUERY_CONTRACTS_V4,
    5: _SLO_QUERY_CONTRACTS_V5,
    6: _SLO_QUERY_CONTRACTS_V6,
    7: _SLO_QUERY_CONTRACTS_V7,
}


def slo_query_contracts_for_schema_version(
    schema_version: int,
) -> tuple[SloQueryContract, ...]:
    return _SLO_QUERY_CONTRACTS_BY_SCHEMA_VERSION.get(
        schema_version,
        SLO_QUERY_CONTRACTS,
    )
