# Agentic OS Production Adaptation for OpenClaw

## Executive Decision and Scope/Non-Goals

Decision: adapt the nine Agentic OS workflows as an OpenClaw control-plane layer through a compatibility migration. Current OpenClaw file artifacts remain operational authority until each workflow is cut over. The target end state is repo-local SQLite at `/Users/zuqiangyu/clawd/state/agentic-os/control.db` as the single desired-state authority, with JSON, JSONL, Markdown, and run bundles becoming projections and evidence only after the cutover for that workflow.

The previous big-bang authority claim is withdrawn. This document is a corrected production design, not a production implementation receipt. No P0/P1 runtime implementation is claimed complete. Round 10 independent review found unresolved High design gaps; this Round 11 single-writer correction requires fresh independent revalidation before any design PASS claim.

Scope:

- Define the production design for Heartbeat, Orchestrator-Workers, Executor-Advisor, Trust Ledger, Standing Goals, Quorum, Sparring, Compost, and Ratchet.
- Preserve OpenClaw's current hard boundary: temporary supervisor authorization uses in-memory allowLease only; config mutation and Gateway restart are forbidden in an in-flight dispatch path.
- Specify external runtime metadata contracts, database contracts, transaction algorithms, budget gates, predicate execution, approvals, SLOs, migration, rollback, and acceptance fixtures.
- Make automation local, measured, reversible, risk-dominance bounded, and tied to deterministic gates.

Non-goals:

- No runtime, Gateway, Cron, service, live skill, agent, script, `.gitignore`, or external-system change is made by this document.
- No claim that current Gateway/session APIs satisfy the new metadata contract.
- No automatic reconciliation when external ownership metadata is missing.
- No arbitrary shell Standing Goal predicates.
- No vendor-bound "cheap model" or hard-coded provider dependency.

## Delivery Change Log

- 2026-07-18: Added the local fail-closed trust promotion writer and migration v13 binding overlay:
  - Corrections: active `trust_observations` now require known usage/cost across the trusted workflow, complete local-writer SLO PASS audit rows at or after the bound gate clock, append-only SLO evidence events after all runtime SLO inputs, same-run goal evidence, current risk-assessment binding, approval-bound PASS-gate evidence with immutable approval hashes, an independent verifier, trusted gate clock, immutable referenced goal-manifest and predicate-plugin metadata, gate-time file-authority snapshots, and deterministic trust binding hash equality. Active legacy unbound trust rows abort migration, and raw direct SQL without the registered local functions fails closed instead of granting trust. Runtime production behavior remains unproven.
- 2026-07-12: Applied GitHub Codex review hardening to the P0 foundation:
  - Corrections: privacy preflight now checks the rollback journal sentinel and rejects actual database paths outside the checked worktree; packaging/retrieval denylist rejects SQLite3 and compressed SQLite snapshots; accepted/completed `spawn_requests` require matching accepted external intent identity plus an exact `sessions` row; active DB-authority workflow bindings cannot be rolled back while matching DB-authority runs are open; live Gateway leases cannot be deleted before release proof; `release_not_required` cannot hide an accepted acquire intent with a Gateway lease identity; approval IDs must be non-empty; live lease terminal states require release proof or no external gateway lease; accepted acquire-pending leases with Gateway ownership cannot be deleted or hidden before release proof; zero input/output/cost reserves require enabled zero-reserve policy proof even when retry/time/human-attention units are positive; pass gates and their referenced transitions are immutable; verifier independence proof evidence must be a non-empty JSON object; R2+ completion gates must bind to the finalizing transition.
  - DDL, migration manifest, README evidence status, and adversarial unit tests are updated. Runtime production behavior remains unproven.
- 2026-07-12: Applied Round 11 single-writer correction after Round 10 independent review found unresolved High gaps:
  - Frozen Round 10 input SHA-256 before this correction: `a6b93a7bc1357cf037833b75ffc09938ca1d1d4b0ababab129ea5595a666ffdc`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round10-main-independent.md` found wrong-run approval authorization and `consume`-carried human-attention accounting loopholes. `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round10-ai-engineer.md` returned a conflicting PASS, so this revision treats the concrete failing fixtures as mandatory corrections.
  - Corrections: approvals now require non-NULL exact run/gate/transition binding; `consume` cannot carry `human_attention_units`; human-attention consumption authority is only `event_type='human_attention'`; DDL, SLOs, fixtures, rollback, residual risks, backlog, and conclusion are updated. Runtime production behavior remains unproven.
- 2026-07-12: Applied Round 9 single-writer correction after both Round 8 independent reviewers returned `VERDICT_FAIL`:
  - Frozen failing document SHA-256 before this correction: `b8af21960680b58e25a45fbef5c2336e90859ac450a53cac0c637cd33cfd9b2f`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round8-main-independent.md` found Critical/High executable gaps in raw `external_metadata_json` equality, accepted session identity, gate-clock freshness, and `human_attention` dimensional accounting.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round8-ai-engineer.md` independently found the High `sessions` same-row binding gap and noted the raw-JSON mismatch hardening issue.
  - Corrections: exact `json_extract` equality between raw JSON, normalized observed fields, and local intent fields; non-empty accepted session identity across `external_rpc_intents`, `spawn_requests`, and `sessions`; composite `sessions` -> `spawn_requests` identity binding including transition/idempotency/session identity; executable gate-clock snapshot equality; pure-dimension `human_attention` events; updated DDL, SLOs, fixtures, rollback, residual risks, backlog, and conclusion. Runtime production behavior remains unproven.
- 2026-07-12: Applied Round 7 single-writer correction after both Round 6 independent reviewers returned `VERDICT_FAIL`:
  - Frozen failing document SHA-256 before this correction: `243402369c37a897f5ba26060524269c2c823df3d6ce0c52f2a48107f965c76a`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round6-ai-engineer.md` found a High retry-ledger bypass: `consume` could carry `retry_units`, reduce outstanding retry reservation, and avoid `consumed_retries`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round6-software-architect.md` found Critical/High external `sessions_spawn` gaps: version-only metadata spoofing, missing exact runtime metadata proof, and orphan external intents not bound to a concrete `spawn_requests` row.
  - Corrections: event-type dimensional closure for retry ledger semantics; normalized `sessions_spawn` intent fields, exact `spawn_request_id`/client/idempotency/phase/agent/task binding, exact external metadata fields, and JSON validity checks; zero-reserve prose aligned with every configured positive minimum; updated DDL, SLOs, fixtures, rollback, residual risks, backlog, and conclusion. Runtime production behavior remains unproven.
- 2026-07-12: Reopened the Round 5 remediation after parent verification found SQLite type-affinity coercion was still unsafe:
  - Frozen failing document SHA-256 before this single-writer correction: `da81392510bb87186a4feb05364188a5828ede7cb2f9a4035163a40a8c775d04`.
  - Concrete failure: SQLite applied `INTEGER` affinity before `CHECK`, so numeric text such as `'1500'` for `gate_clock_context.now_epoch_ms` or `'100'` for `model_cost_registry.*_cost_microusd_per_million` could be stored as integer and pass `typeof(...)='integer'`.
  - Correction: every bounded gate-critical money/token/time/retry/human-attention/epoch field is represented as `ANY` inside a `STRICT` table, with explicit storage-class and range checks. Numeric text, integral `REAL`, `NULL`, negative, max+1, `Inf`, `NaN`, and `1e999` fail by DDL or migration quarantine; exact integer maxima pass.
  - Updated DDL, SLOs, H1-H4 fixture expectations, migration, rollback, residual risks, backlog, and conclusion without changing runtime state or weakening Round 1-5 closures.
- 2026-07-12: Applied mandatory Round 5 remediation into this design document only:
  - Frozen failing document SHA-256 before Round 5 remediation: `a9c70b274014ccdfca08d4849b8c33fec0263b07a30b5c45442dca4f6f1fbdc4`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round5-ai-engineer.md`, SHA-256 `8ea80d8235808fbe38cf3bb058a5e93c9190e571dcac7a4613f21f8a0fbe2406`, found four High gaps: reusable singleton gate clock, budget ledger/counter divergence, invalid zero-reserve policies, and unbounded/non-finite monetary `REAL` authority.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round5-software-architect.md`, SHA-256 `898b493f676e4d1e6daae04ef49f9a763561aa138af47796d4d3a70bee5e367a`, independently found the same four High gaps.
  - Corrections: per-gate one-use trusted clock context bound to gate/run/transition/nonce; authoritative `budget_events` ledger with guarded counter updates and aggregate reconciliation; zero-reserve policies with positive minima and exact endpoint/capability/hash/effective-window binding; bounded fixed-scale `microusd` integer cost representation; updated DDL, transaction algorithms, SLOs, fixtures, migration, rollback, residual risks, backlog, and conclusion.
- 2026-07-12: Applied mandatory Round 4 remediation into this design document only:
  - Frozen failing document SHA-256 before Round 4 remediation: `876b6c8aed8ff8b9072d5f1e9ed7c25b32d6429bc94cdd11ee4537293d4dbf69`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round4-ai-engineer.md`, SHA-256 `81ace3658a40ef11286ba5603327dc5bb4cfbda3c48d7dc83ef4cd190afbb89b`, found three High gaps: same-second post-RPC reserve false-negative, second-floor approval expiry, and negative/meaningless budget accounting.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round4-software-architect.md`, SHA-256 `f7a35c477bb5fe6bd314222ea563d3b7570b9e1ed711284b7ff220035d048e56`, independently found the reserve ordering and approval expiry High gaps.
  - Corrections: exact `sessions_spawn` reserve pointer plus strict persisted epoch-ms reserve-before-intent authority, trusted fixtureable gate clock context for millisecond approval expiry, non-negative/meaningful budget accounting, updated SLOs, fixtures, residual risks, backlog, and conclusion.
- 2026-07-12: Applied mandatory Round 3 AI review remediation into this design document only:
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round3-ai-engineer.md`, SHA-256 `4f3b8476c3d3568dc08658b5409e3535beac5c5405b6634c62d83d111cdecbdf`.
  - Frozen failing document SHA-256 before Round 3 remediation: `99dbd363d40344cca4df1cf517ea1d25e15b6bad4d4bb20c810ea03d362072e5`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round3-software-architect.md`, SHA-256 `ed2aa80f2f5e45739598e3b4e645c4f8de207a76c9f202941690a03305bad56d`, remains PASS evidence, but the AI review found two High semantic bugs requiring this correction.
  - Corrections: endpoint-bound model cost registry/SLOs/fixture contract, and canonical approval expiry by integer epoch milliseconds instead of raw text timestamp comparison.
- 2026-07-12: Applied mandatory Round 2 review closures into this design document only:
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round2-ai-engineer.md`, SHA-256 `aeec986fb8e14423c916b18e102810c1080e1a661e31331250a45ca1d07bdfb0`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round2-software-architect.md`, SHA-256 `48a32cb639100eb03ae34a34c0c10c28143695698f398749ae74f37b172c89d6`.
  - Frozen failing document SHA-256 before Round 2 remediation: `89db1227bb921931238f589372b32f848e1f2c12c8f00d16c0e76a37e4ff5504`.
- 2026-07-12: Applied both mandatory Round 1 remediation proposals into this design document:
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round1-ai-engineer-remediation.md`, SHA-256 `0a04afeca99af5d705131b0776bb76719bf76d8f872f5e70ea8afd5d4ccde971`.
  - `/Users/zuqiangyu/clawd/artifacts/agentic-os-dual-review/round1-software-architect-remediation.md`, SHA-256 `9d7eac1d84cf163598159395a6d4dbe9a0da05bd901765235a14cc68509fe3d6`.
- Round 1 baseline document SHA-256 before remediation: `1a68cfd42563d984dc7057cf3354351809e3b194c488ec6f9fec78e3491cc0c7`.
- Delivery status: design-only Round 11 correction applied after Round 10 failed. Runtime production behavior remains unproven and fresh independent revalidation is still required.

## Current-State Evidence Boundary

Current OpenClaw mechanisms to preserve and migrate around:

- `scripts/simple-orchestrator.py` and `scripts/phase-runtime.py` produce phase run bundles, prompt bundles, `dispatch-ready.json`, and `workspace-events.jsonl`.
- `scripts/orchestrator-dispatch-next.py` consumes run bundles, acquires/releases allowLease, emits `sessions_spawn` templates, and records completion.
- `scripts/subagent-allowlist-lease.py` uses Gateway allowLease and fails closed when allowLease RPCs are absent.
- `scripts/delegation-guard.py`, `scripts/openclaw-completion-gate.sh`, `scripts/independent-verifier-pass.sh`, `scripts/deploy-verification-loop.sh`, and `scripts/guardrails-learning-loop.py` provide current dispatch guard, verification, deploy observation, and learning-loop receipts.
- Existing JSON/JSONL/Markdown artifacts are useful evidence, but they are not yet database projections.

Current-vs-proposed truth:

- Current file artifacts remain operational authority.
- Current OpenClaw is below the required external runtime metadata contract. Gateway allowLease and session status do not yet prove exact run/idempotency ownership across post-RPC/pre-DB crashes.
- Current P0 foundation adds ignored migration artifacts and fail-closed probes, but does not create production `control.db`, does not enable DB-authority dispatch, and does not prove runtime adapter behavior.
- Current Issue 7 implementation adds only a synthetic/local
  `db_authority_canary` artifact fixture writer. It records one local R1 canary
  run, proves prepared-DB to artifact-write crash recovery, proves rollback to
  `rollback_to_file_authority`, and regenerates projection identity from the
  local artifact. It explicitly rejects real session-control rows and does not
  call OpenClaw/Gateway/Cron or enable production database authority.
- Proposed DB authority begins only after privacy preflight, metadata contract probes, schema fixtures, shadow backfill, dual-write parity, one low-risk canary, drain, rollback drill, and per-workflow cutover.

## Design Principles and Operational Confidence Definition

Principles:

1. Current files are authority until a workflow is explicitly cut over; `control.db` is target authority after compatibility migration.
2. External runtime facts are not transactionally inside SQLite. Gateway leases and child sessions must be represented as pending intents and reconciled only through exact external metadata.
3. Automatic reconciliation requires exact external run/idempotency metadata. Otherwise the run fails closed to `human_review_required`.
4. No auto-bind by agent id, requester id, timestamp proximity, prompt text, path proximity, or run directory name.
5. No automatic `sessions_spawn` retry after an unknown RPC outcome.
6. Lease TTLs are bounded; the scanner releases only leases it can prove are owned by the same run.
7. Budget reservation happens before any external RPC; consumption/import happens after completion. Unknown usage or cost blocks `auto-local` and trust promotion.
8. Every mutating workflow follows Aggregator -> independent Judge/Verifier -> deterministic Gate.
9. Self-validation cannot raise trust.
10. Standing Goals use a named safe predicate substrate, not arbitrary code.
11. Human attention is reserved for high-risk, ambiguous, irreversible, sensitive, version-invalidated, or external-side-effect decisions.

Operational design gate:

- This document can pass only a static design gate after fresh Round 11 independent revalidation.
- Production proof requires implemented migrations, contract probes, crash fixtures, privacy guards, SQL SLO fixtures, reconciliation scanner, budget importer, predicate runner, gates, and rollout drills.

## Unified Target Architecture and External Runtime Metadata Contract

Target flow:

```text
signals/current file artifacts
  -> aggregator writes candidate rows
  -> risk assessment and budget reservation
  -> transition/intents committed before external RPC
  -> Gateway/tool RPC boundary
  -> metadata-based reconciliation or human_review_required
  -> child evidence hashes
  -> independent judge/verifier
  -> deterministic gate
  -> trust observation
  -> redacted projections and human packets
```

Authoritative target database:

- Path: `/Users/zuqiangyu/clawd/state/agentic-os/control.db`.
- Directory mode: `0700`; DB, WAL, SHM, and backups: `0600`.
- Every connection sets `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;`.
- Every migration records name, migration hash, and applied timestamp.
- Every state transition uses `BEGIN IMMEDIATE` and an expected-state/version guard.

VCS/privacy P0 prerequisite:

- DB creation and any `db_authority_canary` are blocked until future `.gitignore` rules and packaging denylist checks pass.
- Required future ignore patterns:

```gitignore
state/agentic-os/*.db
state/agentic-os/*.db-*
state/agentic-os/*.sqlite
state/agentic-os/*.sqlite-*
state/agentic-os/backups/
```

- Required preflights before creating DB state:

```bash
git check-ignore -v state/agentic-os/control.db
git check-ignore -v state/agentic-os/control.db-wal
git check-ignore -v state/agentic-os/control.db-shm
git check-ignore -v state/agentic-os/control.db-journal
git check-ignore -v state/agentic-os/backups/example.db
```

- Packaging/reporting denylist refuses raw `*.db`, `*.db-wal`, `*.db-shm`, `*.db-journal`, `*.sqlite`, `*.sqlite-*`, `*.sqlite3`, SQLite sidecars/backups, dot-suffixed database copies such as `.db.old` and `.sqlite.copy`, compressed SQLite snapshots such as `.gz`, `.zip`, and `.zst`, and `state/agentic-os/backups/**` unless an explicit local recovery mode is used.

External runtime metadata contract is a P0 prerequisite:

- `subagents.allowLease.acquire` must accept `client_lease_id`, `idempotency_key`, `run_id`, `phase`, `transition_id`, `agent_id`, `requester_agent_id`, and `ttl_ms`.
- Duplicate allowLease acquire with the same idempotency key must return the same live lease identity and must not create another lease.
- `subagents.allowLease.status` must expose all caller metadata for every live lease.
- `subagents.allowLease.release` must be idempotent on `release_idempotency_key` and must refuse to release a lease whose owner metadata does not match the caller, except through explicit human review.
- Release observations must echo `client_lease_id`, release `idempotency_key`, `run_id`, `phase`, `transition_id`, `agent_id`, `requester_agent_id`, and `gateway_lease_id`; `run_id` plus `transition_id` alone is not owner proof.
- A local lease row cannot move to `released` or `release_pending` without a non-empty release idempotency key and release request evidence; `release_not_required` is valid only when no external Gateway lease identity exists.
- `sessions_spawn` or its tool-layer wrapper must accept `client_request_id`, `idempotency_key`, and `metadata={run_id, phase, agent_id, transition_id, task_digest}`.
- Session list/status/history-backed result APIs must expose that metadata and the accepted session identity. A non-null `metadata_contract_version` is only a version label; it is never proof by itself.
- Runtime session-tool catalog preflight must fail closed unless
  `sessions_spawn` declares `client_request_id`, `idempotency_key`, and
  `metadata`; a spawn surface that cannot carry caller metadata is not valid
  runtime evidence for reconciliation.
- For `sessions_spawn`, SQLite authority is normalized and raw evidence must agree with it: `external_rpc_intents.spawn_request_id`, `run_id`, `transition_id`, `client_request_id`, `idempotency_key`, `phase`, `agent_id`, and `task_digest` must match one concrete `spawn_requests` row through foreign keys. Whenever a `sessions_spawn` row carries `external_metadata_json`, DDL requires `json_valid(...)` and requires `json_extract(...,'$.run_id')`, `$.transition_id`, `$.client_request_id`, `$.idempotency_key`, `$.phase`, `$.agent_id`, and `$.task_digest` to match both the normalized observed fields and the local intent fields exactly. Accepted/reconciled rows additionally require a non-empty accepted external session identity in `external_id`. Pre-RPC `pending` rows may exist without external JSON because the external call has not returned; the blocking SLO rejects pending/unknown/accepted/reconciled rows from auto-repair or gate trust unless the raw JSON, normalized observed fields, and local intent fields are an exact triple match.
- Accepted session identity has one source of truth tuple: `external_rpc_intents.external_id`, `spawn_requests.session_key`, and `sessions.session_key` must be non-empty and equal for accepted/reconciled or accepted/completed spawn state. The `sessions` row must bind to the same `spawn_requests` row by `spawn_request_id`, `run_id`, `transition_id`, `client_request_id`, `spawn_idempotency_key`, `phase`, `agent_id`, and `task_digest`; a session may not point at a real `spawn_request_id` while carrying another run, phase, agent, client, idempotency, or task identity. Accepted/reconciled replay must re-read this local tuple and fail closed if the local spawn/session proof is missing or mismatched.
- Post-dispatch budget events must additionally bind to the selected `run_budgets` provider/model/endpoint/capability/cost row and to strict `requested_at_epoch_ms < accepted_at_epoch_ms < budget_events.created_at_epoch_ms` ordering.
- Duplicate session spawn with the same idempotency key must return the original session identity and must not create another child.
- Child prompt first line includes `run_id`, `phase`, `agent_id`, and `task_digest`; child echo is a secondary handshake and cannot replace runtime metadata.
- The current implementation includes a pure fake-adapter metadata dispatch
  probe plus an injectable OpenClaw adapter boundary for this contract. These
  validate allowLease acquire/status/release and session spawn/status/list/result
  observations. The OpenClaw adapter boundary now includes a runtime catalog
  preflight helper that fails closed unless the installed transport exposes the
  exact session tools and parameter names it calls, including the
  `sessions_spawn` caller `metadata` parameter and the history-backed result
  surface. `sessions_history` responses are accepted only when the top-level
  accepted identity and any history item identity match the requested session;
  production integration must run that preflight before treating the adapter as
  runtime evidence. It does not enable
  production database authority. Runtime reconciliation remains bounded to the
  implemented scanner paths.

Fail-closed rule:

- If allowLease metadata is absent, `lease_acquire_pending` cannot auto-bind a live lease; scanner writes `human_review_required`.
- If session metadata is absent, `spawn_pending` after a crash becomes `spawn_unknown`/`human_review_required`; the adapter must not retry `sessions_spawn`.
- If the bound allowLease acquire has not accepted or reconciled into the exact acquired local lease with a non-empty Gateway lease identity, `spawn_pending`/`spawn_unknown` cannot auto-reconcile from session metadata and must move to `human_review_required`.
- If ownership cannot be proven, ambiguous leases are left to bounded TTL or human review; no other run's lease is released.

## Minimum Database Contracts

The following DDL is the current minimum contract after applying the migration
manifest through version 2. SLO SQL or gates cannot be authoritative until this
post-migration schema exists. Later migrations may add indexes and constraints,
but these fields are not optional.

Safe numeric bounds are part of the schema contract. They intentionally fit well below SQLite signed 64-bit integer overflow even when a run reaches the maximum event count: `MAX_BUDGET_EVENTS_PER_RUN=1000000`, `MAX_RUN_TIME_SECONDS=31536000`, `MAX_RUN_TIME_MS=31536000000`, `MAX_RUN_INPUT_TOKENS=1000000000`, `MAX_RUN_OUTPUT_TOKENS=1000000000`, `MAX_RUN_COST_MICROUSD=100000000000`, `MAX_RUN_RETRY_UNITS=1000000`, `MAX_RUN_HUMAN_ATTENTION_UNITS=1000000`, `MAX_PRICE_MICROUSD_PER_MILLION=100000000000`, and `MAX_EPOCH_MS=253402300799999`.

SQLite type preservation is mandatory, not optional. Every table that stores bounded gate-critical numeric authority is `STRICT`, and every bounded gate-critical money/token/time/retry/human-attention/epoch field uses `ANY` plus an explicit `typeof(field)='integer'` range check. `ANY` in a `STRICT` table preserves the input storage class before `CHECK`, so numeric text such as `'1500'` and integral `REAL` values such as `1500.0` remain wrong-type and fail. Plain `INTEGER` affinity is forbidden for those fields because it can coerce numeric text before the check executes.

Money is represented only as fixed-scale integer micro-USD (`microusd`) in gate-critical tables; any legacy migration must convert from the explicit `usd_decimal` source unit to microusd with Python `Decimal` after validating the original SQLite storage class, and fail-closed to quarantine on `NULL`, `NaN`, `Inf`, `1e999`, negative, fractional-microusd ambiguity, mixed units, or max+1 values. Direct authority tables still reject numeric text and `REAL`; the legacy importer accepts only text decimals, integer-dollar storage, or finite integral `REAL` dollars before conversion.

```sql
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
      AND NOT EXISTS (
        SELECT 1 FROM runs open_run
        WHERE open_run.workflow=NEW.workflow
          AND open_run.authority_mode='file_authority'
          AND open_run.state NOT IN ('finalized','rolled_back','rejected')
      )
  )
BEGIN
  SELECT RAISE(ABORT,'db authority run requires active workflow cutover evidence');
END;

CREATE TRIGGER runs_validate_db_authority_update
BEFORE UPDATE OF workflow, authority_mode, state ON runs
WHEN NEW.authority_mode IN ('db_authority_canary','db_authority')
  AND (
    NEW.state NOT IN ('finalized','rolled_back','rejected')
    OR NEW.workflow<>OLD.workflow
    OR NEW.authority_mode<>OLD.authority_mode
  )
  AND NOT EXISTS (
    SELECT 1 FROM workflow_authority w
    WHERE w.workflow=NEW.workflow
      AND w.mode=NEW.authority_mode
      AND w.cutover_approved_by IS NOT NULL AND w.cutover_approved_by <> ''
      AND w.cutover_evidence_hash IS NOT NULL AND w.cutover_evidence_hash <> ''
      AND w.rollback_deadline IS NOT NULL AND w.rollback_deadline <> ''
      AND w.last_parity_audit_hash IS NOT NULL AND w.last_parity_audit_hash <> ''
      AND w.open_file_authority_runs = 0
      AND NOT EXISTS (
        SELECT 1 FROM runs open_run
        WHERE open_run.workflow=NEW.workflow
          AND open_run.authority_mode='file_authority'
          AND open_run.state NOT IN ('finalized','rolled_back','rejected')
      )
  )
BEGIN
  SELECT RAISE(ABORT,'db authority run requires active workflow cutover evidence');
END;

CREATE TRIGGER workflow_authority_validate_db_drain_insert
BEFORE INSERT ON workflow_authority
WHEN NEW.mode IN ('db_authority_canary','db_authority')
  AND EXISTS (
    SELECT 1 FROM runs open_run
    WHERE open_run.workflow=NEW.workflow
      AND open_run.authority_mode='file_authority'
      AND open_run.state NOT IN ('finalized','rolled_back','rejected')
  )
BEGIN
  SELECT RAISE(ABORT,'db authority requires drained file-authority runs');
END;

CREATE TRIGGER workflow_authority_validate_db_drain_update
BEFORE UPDATE OF workflow, mode ON workflow_authority
WHEN NEW.mode IN ('db_authority_canary','db_authority')
  AND EXISTS (
    SELECT 1 FROM runs open_run
    WHERE open_run.workflow=NEW.workflow
      AND open_run.authority_mode='file_authority'
      AND open_run.state NOT IN ('finalized','rolled_back','rejected')
  )
BEGIN
  SELECT RAISE(ABORT,'db authority requires drained file-authority runs');
END;

CREATE TRIGGER workflow_authority_preserve_active_db_binding_update
BEFORE UPDATE OF workflow, mode ON workflow_authority
WHEN OLD.mode IN ('db_authority_canary','db_authority')
  AND (NEW.workflow<>OLD.workflow OR NEW.mode<>OLD.mode)
  AND EXISTS (
    SELECT 1 FROM runs open_run
    WHERE open_run.workflow=OLD.workflow
      AND open_run.authority_mode=OLD.mode
      AND open_run.state NOT IN ('finalized','rolled_back','rejected')
  )
BEGIN
  SELECT RAISE(ABORT,'active db authority runs require active workflow authority binding');
END;

CREATE TRIGGER runs_reject_open_file_authority_during_db_insert
BEFORE INSERT ON runs
WHEN NEW.authority_mode='file_authority'
  AND NEW.state NOT IN ('finalized','rolled_back','rejected')
  AND EXISTS (
    SELECT 1 FROM workflow_authority w
    WHERE w.workflow=NEW.workflow
      AND w.mode IN ('db_authority_canary','db_authority')
  )
BEGIN
  SELECT RAISE(ABORT,'open file authority run conflicts with db authority');
END;

CREATE TRIGGER runs_reject_open_file_authority_during_db_update
BEFORE UPDATE OF workflow, authority_mode, state ON runs
WHEN NEW.authority_mode='file_authority'
  AND NEW.state NOT IN ('finalized','rolled_back','rejected')
  AND EXISTS (
    SELECT 1 FROM workflow_authority w
    WHERE w.workflow=NEW.workflow
      AND w.mode IN ('db_authority_canary','db_authority')
  )
BEGIN
  SELECT RAISE(ABORT,'open file authority run conflicts with db authority');
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
  CHECK (risk_dominance IN ('R0','R1','R2','R3','R4')),
  CHECK (risk_dominance NOT IN ('R3','R4') OR approval_required=1),
  CHECK (
    approval_required = 0 OR (
      approval_id IS NOT NULL
      AND approval_id <> ''
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

CREATE TRIGGER transitions_bind_run_risk_insert
AFTER INSERT ON transitions
WHEN NOT EXISTS (
  SELECT 1 FROM runs r
  WHERE r.run_id=NEW.run_id
    AND r.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'transition risk dominance must match run risk dominance');
END;

CREATE TRIGGER transitions_bind_run_risk_update
AFTER UPDATE OF run_id, risk_dominance ON transitions
WHEN NOT EXISTS (
  SELECT 1 FROM runs r
  WHERE r.run_id=NEW.run_id
    AND r.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'transition risk dominance must match run risk dominance');
END;

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
  requester_agent_id TEXT,
  ttl_ms ANY,
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
  external_requester_agent_id TEXT,
  external_ttl_ms ANY,
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
  CHECK (ttl_ms IS NULL OR (typeof(ttl_ms)='integer' AND ttl_ms BETWEEN 1 AND 31536000000)),
  CHECK (external_ttl_ms IS NULL OR (typeof(external_ttl_ms)='integer' AND external_ttl_ms BETWEEN 1 AND 31536000000)),
  CHECK (
    intent_id <> ''
    AND run_id <> ''
    AND transition_id <> ''
    AND client_request_id <> ''
    AND idempotency_key <> ''
  ),
  CHECK (
    rpc_kind <> 'sessions_spawn' OR (
      spawn_request_id IS NOT NULL AND spawn_request_id <> ''
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
    rpc_kind <> 'allow_lease_acquire'
    OR state IN ('pending','unknown','failed','human_review_required')
    OR (
      metadata_contract_version IS NOT NULL AND metadata_contract_version <> ''
      AND external_metadata_json IS NOT NULL AND json_valid(external_metadata_json)
      AND external_id IS NOT NULL AND external_id <> ''
      AND phase IS NOT NULL AND phase <> ''
      AND agent_id IS NOT NULL AND agent_id <> ''
      AND requester_agent_id IS NOT NULL AND requester_agent_id <> ''
      AND ttl_ms IS NOT NULL
      AND external_run_id IS run_id
      AND external_transition_id IS transition_id
      AND external_client_request_id IS client_request_id
      AND external_idempotency_key IS idempotency_key
      AND external_phase IS phase
      AND external_agent_id IS agent_id
      AND external_requester_agent_id IS requester_agent_id
      AND external_ttl_ms IS ttl_ms
    )
  ),
  CHECK (
    rpc_kind <> 'allow_lease_acquire'
    OR external_metadata_json IS NULL
    OR CASE
      WHEN json_valid(external_metadata_json) THEN CASE
        WHEN json_type(external_metadata_json,'$.client_lease_id')='text'
          AND json_type(external_metadata_json,'$.idempotency_key')='text'
          AND json_type(external_metadata_json,'$.run_id')='text'
          AND json_type(external_metadata_json,'$.phase')='text'
          AND json_type(external_metadata_json,'$.transition_id')='text'
          AND json_type(external_metadata_json,'$.agent_id')='text'
          AND json_type(external_metadata_json,'$.requester_agent_id')='text'
          AND json_type(external_metadata_json,'$.ttl_ms')='integer'
          AND json_type(external_metadata_json,'$.gateway_lease_id')='text'
          AND json_extract(external_metadata_json,'$.client_lease_id') <> ''
          AND json_extract(external_metadata_json,'$.idempotency_key') <> ''
          AND json_extract(external_metadata_json,'$.run_id') <> ''
          AND json_extract(external_metadata_json,'$.phase') <> ''
          AND json_extract(external_metadata_json,'$.transition_id') <> ''
          AND json_extract(external_metadata_json,'$.agent_id') <> ''
          AND json_extract(external_metadata_json,'$.requester_agent_id') <> ''
          AND json_extract(external_metadata_json,'$.ttl_ms') BETWEEN 1 AND 31536000000
          AND json_extract(external_metadata_json,'$.gateway_lease_id') <> ''
          AND json_extract(external_metadata_json,'$.client_lease_id') = client_request_id
          AND json_extract(external_metadata_json,'$.idempotency_key') = idempotency_key
          AND json_extract(external_metadata_json,'$.run_id') = run_id
          AND json_extract(external_metadata_json,'$.phase') = phase
          AND json_extract(external_metadata_json,'$.transition_id') = transition_id
          AND json_extract(external_metadata_json,'$.agent_id') = agent_id
          AND json_extract(external_metadata_json,'$.requester_agent_id') = requester_agent_id
          AND json_extract(external_metadata_json,'$.ttl_ms') = ttl_ms
          AND json_extract(external_metadata_json,'$.gateway_lease_id') = external_id
          AND external_run_id IS run_id
          AND external_transition_id IS transition_id
          AND external_client_request_id IS client_request_id
          AND external_idempotency_key IS idempotency_key
          AND external_phase IS phase
          AND external_agent_id IS agent_id
          AND external_requester_agent_id IS requester_agent_id
          AND external_ttl_ms IS ttl_ms
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
      AND json_type(external_metadata_json,'$.gateway_lease_id')='text'
      AND json_extract(external_metadata_json,'$.client_lease_id') <> ''
      AND json_extract(external_metadata_json,'$.idempotency_key') <> ''
      AND json_extract(external_metadata_json,'$.run_id') <> ''
      AND json_extract(external_metadata_json,'$.phase') <> ''
      AND json_extract(external_metadata_json,'$.transition_id') <> ''
      AND json_extract(external_metadata_json,'$.agent_id') <> ''
      AND json_extract(external_metadata_json,'$.requester_agent_id') <> ''
      AND json_extract(external_metadata_json,'$.gateway_lease_id') <> ''
      AND json_extract(external_metadata_json,'$.client_lease_id')=client_lease_id
      AND json_extract(external_metadata_json,'$.idempotency_key')=acquire_idempotency_key
      AND json_extract(external_metadata_json,'$.run_id')=run_id
      AND json_extract(external_metadata_json,'$.phase')=phase
      AND json_extract(external_metadata_json,'$.transition_id')=transition_id
      AND json_extract(external_metadata_json,'$.agent_id')=agent_id
      AND json_extract(external_metadata_json,'$.requester_agent_id')=requester_agent_id
      AND json_extract(external_metadata_json,'$.ttl_ms')=ttl_ms
      AND json_extract(external_metadata_json,'$.gateway_lease_id')=gateway_lease_id
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
    WHERE l.state IN ('released','expired','human_review_required')
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
    WHERE l.state IN ('released','expired','human_review_required')
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

CREATE TRIGGER spawn_requests_preserve_accepted_state_update
BEFORE UPDATE OF state ON spawn_requests
WHEN (OLD.state='accepted' AND NEW.state NOT IN ('accepted','completed'))
  OR (OLD.state='completed' AND NEW.state<>'completed')
BEGIN
  SELECT RAISE(ABORT,'accepted spawn request state is immutable');
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

CREATE TRIGGER leases_validate_acquire_proof_insert
AFTER INSERT ON leases
WHEN NEW.state IN ('acquired','release_pending') AND NOT EXISTS (
  SELECT 1 FROM external_rpc_intents eri
  WHERE eri.rpc_kind='allow_lease_acquire'
    AND eri.state IN ('accepted','reconciled')
    AND eri.run_id=NEW.run_id
    AND eri.transition_id=NEW.transition_id
    AND eri.phase=NEW.phase
    AND eri.agent_id=NEW.agent_id
    AND eri.requester_agent_id=NEW.requester_agent_id
    AND eri.ttl_ms=NEW.ttl_ms
    AND eri.client_request_id=NEW.client_lease_id
    AND eri.idempotency_key=NEW.acquire_idempotency_key
    AND eri.external_id=NEW.gateway_lease_id
    AND eri.external_phase=NEW.phase
    AND eri.external_agent_id=NEW.agent_id
    AND eri.external_requester_agent_id=NEW.requester_agent_id
    AND eri.external_ttl_ms=NEW.ttl_ms
)
BEGIN
  SELECT RAISE(ABORT,'live lease requires acquire intent proof');
END;

CREATE TRIGGER leases_validate_acquire_proof_update
AFTER UPDATE OF state, run_id, phase, transition_id, agent_id, requester_agent_id, client_lease_id, acquire_idempotency_key, ttl_ms, gateway_lease_id ON leases
WHEN NEW.state IN ('acquired','release_pending') AND NOT EXISTS (
  SELECT 1 FROM external_rpc_intents eri
  WHERE eri.rpc_kind='allow_lease_acquire'
    AND eri.state IN ('accepted','reconciled')
    AND eri.run_id=NEW.run_id
    AND eri.transition_id=NEW.transition_id
    AND eri.phase=NEW.phase
    AND eri.agent_id=NEW.agent_id
    AND eri.requester_agent_id=NEW.requester_agent_id
    AND eri.ttl_ms=NEW.ttl_ms
    AND eri.client_request_id=NEW.client_lease_id
    AND eri.idempotency_key=NEW.acquire_idempotency_key
    AND eri.external_id=NEW.gateway_lease_id
    AND eri.external_phase=NEW.phase
    AND eri.external_agent_id=NEW.agent_id
    AND eri.external_requester_agent_id=NEW.requester_agent_id
    AND eri.external_ttl_ms=NEW.ttl_ms
)
BEGIN
  SELECT RAISE(ABORT,'live lease requires acquire intent proof');
END;

CREATE TRIGGER external_rpc_intents_preserve_live_lease_acquire_delete
BEFORE DELETE ON external_rpc_intents
WHEN OLD.rpc_kind='allow_lease_acquire'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state IN ('acquire_pending','acquired','release_pending','release_not_required')
      AND l.run_id=OLD.run_id
      AND l.transition_id=OLD.transition_id
      AND l.phase=OLD.phase
      AND l.agent_id=OLD.agent_id
      AND l.requester_agent_id=OLD.requester_agent_id
      AND l.ttl_ms=OLD.ttl_ms
      AND l.client_lease_id=OLD.client_request_id
      AND l.acquire_idempotency_key=OLD.idempotency_key
      AND (
        l.state IN ('acquire_pending','release_not_required')
        OR l.gateway_lease_id=OLD.external_id
      )
  )
BEGIN
  SELECT RAISE(ABORT,'live lease requires acquire intent proof');
END;

CREATE TRIGGER external_rpc_intents_preserve_live_lease_acquire_update
BEFORE UPDATE OF rpc_kind, state, run_id, transition_id, phase, agent_id, requester_agent_id, ttl_ms, client_request_id, idempotency_key, external_id, external_phase, external_agent_id, external_requester_agent_id, external_ttl_ms ON external_rpc_intents
WHEN OLD.rpc_kind='allow_lease_acquire'
  AND OLD.state IN ('accepted','reconciled')
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state IN ('acquire_pending','acquired','release_pending','release_not_required')
      AND l.run_id=OLD.run_id
      AND l.transition_id=OLD.transition_id
      AND l.phase=OLD.phase
      AND l.agent_id=OLD.agent_id
      AND l.requester_agent_id=OLD.requester_agent_id
      AND l.ttl_ms=OLD.ttl_ms
      AND l.client_lease_id=OLD.client_request_id
      AND l.acquire_idempotency_key=OLD.idempotency_key
      AND (
        l.state IN ('acquire_pending','release_not_required')
        OR l.gateway_lease_id=OLD.external_id
      )
  )
BEGIN
  SELECT RAISE(ABORT,'live lease requires acquire intent proof');
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

CREATE TRIGGER leases_validate_terminal_gateway_release_proof_insert
AFTER INSERT ON leases
WHEN NEW.state IN ('expired','human_review_required')
  AND NEW.gateway_lease_id IS NOT NULL
  AND NEW.gateway_lease_id <> ''
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.idempotency_key=NEW.release_idempotency_key
      AND eri.external_id=NEW.gateway_lease_id
  )
BEGIN
  SELECT RAISE(ABORT,'terminal lease with gateway ownership requires release intent proof');
END;

CREATE TRIGGER leases_validate_terminal_gateway_release_proof_update
AFTER UPDATE OF state, run_id, transition_id, release_idempotency_key, gateway_lease_id ON leases
WHEN NEW.state IN ('expired','human_review_required')
  AND COALESCE(NULLIF(OLD.gateway_lease_id,''), NULLIF(NEW.gateway_lease_id,'')) IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.idempotency_key=NEW.release_idempotency_key
      AND eri.external_id=COALESCE(NULLIF(OLD.gateway_lease_id,''), NULLIF(NEW.gateway_lease_id,''))
  )
BEGIN
  SELECT RAISE(ABORT,'terminal lease with gateway ownership requires release intent proof');
END;

CREATE TRIGGER leases_preserve_live_gateway_delete
BEFORE DELETE ON leases
WHEN OLD.state IN ('acquired','release_pending')
  AND OLD.gateway_lease_id IS NOT NULL
  AND OLD.gateway_lease_id <> ''
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=OLD.run_id
      AND eri.transition_id=OLD.transition_id
      AND eri.idempotency_key=OLD.release_idempotency_key
      AND eri.external_id=OLD.gateway_lease_id
  )
BEGIN
  SELECT RAISE(ABORT,'live gateway lease requires release proof before deletion');
END;

CREATE TRIGGER leases_preserve_live_gateway_state_update
BEFORE UPDATE OF state, run_id, transition_id, gateway_lease_id ON leases
WHEN OLD.state IN ('acquired','release_pending')
  AND OLD.gateway_lease_id IS NOT NULL
  AND OLD.gateway_lease_id <> ''
  AND (
    NEW.state NOT IN ('acquired','release_pending')
    OR NEW.run_id<>OLD.run_id
    OR NEW.transition_id<>OLD.transition_id
    OR NEW.gateway_lease_id IS NULL
    OR NEW.gateway_lease_id<>OLD.gateway_lease_id
  )
  AND NOT EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_release'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=OLD.run_id
      AND eri.transition_id=OLD.transition_id
      AND eri.idempotency_key=OLD.release_idempotency_key
      AND eri.external_id=OLD.gateway_lease_id
  )
BEGIN
  SELECT RAISE(ABORT,'live lease requires release proof before leaving live state');
END;

CREATE TRIGGER leases_preserve_accepted_acquire_pending_delete
BEFORE DELETE ON leases
WHEN OLD.state='acquire_pending'
  AND EXISTS (
    SELECT 1 FROM external_rpc_intents acquire
    WHERE acquire.rpc_kind='allow_lease_acquire'
      AND acquire.state IN ('accepted','reconciled')
      AND acquire.run_id=OLD.run_id
      AND acquire.transition_id=OLD.transition_id
      AND acquire.phase=OLD.phase
      AND acquire.agent_id=OLD.agent_id
      AND acquire.requester_agent_id=OLD.requester_agent_id
      AND acquire.ttl_ms=OLD.ttl_ms
      AND acquire.client_request_id=OLD.client_lease_id
      AND acquire.idempotency_key=OLD.acquire_idempotency_key
      AND acquire.external_id IS NOT NULL
      AND acquire.external_id <> ''
  )
  AND NOT EXISTS (
    SELECT 1
    FROM external_rpc_intents release
    JOIN external_rpc_intents acquire
      ON acquire.rpc_kind='allow_lease_acquire'
     AND acquire.state IN ('accepted','reconciled')
     AND acquire.run_id=OLD.run_id
     AND acquire.transition_id=OLD.transition_id
     AND acquire.phase=OLD.phase
     AND acquire.agent_id=OLD.agent_id
     AND acquire.requester_agent_id=OLD.requester_agent_id
     AND acquire.ttl_ms=OLD.ttl_ms
     AND acquire.client_request_id=OLD.client_lease_id
     AND acquire.idempotency_key=OLD.acquire_idempotency_key
     AND acquire.external_id IS NOT NULL
     AND acquire.external_id <> ''
    WHERE release.rpc_kind='allow_lease_release'
      AND release.state IN ('accepted','reconciled')
      AND release.run_id=OLD.run_id
      AND release.transition_id=OLD.transition_id
      AND release.idempotency_key=OLD.release_idempotency_key
      AND release.external_id=acquire.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire-pending lease requires release proof before deletion');
END;

CREATE TRIGGER leases_preserve_accepted_acquire_pending_state_update
BEFORE UPDATE OF state, run_id, phase, transition_id, agent_id, requester_agent_id, client_lease_id, acquire_idempotency_key, ttl_ms, gateway_lease_id ON leases
WHEN OLD.state='acquire_pending'
  AND EXISTS (
    SELECT 1 FROM external_rpc_intents acquire
    WHERE acquire.rpc_kind='allow_lease_acquire'
      AND acquire.state IN ('accepted','reconciled')
      AND acquire.run_id=OLD.run_id
      AND acquire.transition_id=OLD.transition_id
      AND acquire.phase=OLD.phase
      AND acquire.agent_id=OLD.agent_id
      AND acquire.requester_agent_id=OLD.requester_agent_id
      AND acquire.ttl_ms=OLD.ttl_ms
      AND acquire.client_request_id=OLD.client_lease_id
      AND acquire.idempotency_key=OLD.acquire_idempotency_key
      AND acquire.external_id IS NOT NULL
      AND acquire.external_id <> ''
  )
  AND NOT (
    NEW.state IN ('acquired','release_pending')
    AND NEW.run_id=OLD.run_id
    AND NEW.phase=OLD.phase
    AND NEW.transition_id=OLD.transition_id
    AND NEW.agent_id=OLD.agent_id
    AND NEW.requester_agent_id=OLD.requester_agent_id
    AND NEW.ttl_ms=OLD.ttl_ms
    AND NEW.client_lease_id=OLD.client_lease_id
    AND NEW.acquire_idempotency_key=OLD.acquire_idempotency_key
    AND EXISTS (
      SELECT 1 FROM external_rpc_intents acquire
      WHERE acquire.rpc_kind='allow_lease_acquire'
        AND acquire.state IN ('accepted','reconciled')
        AND acquire.run_id=OLD.run_id
        AND acquire.transition_id=OLD.transition_id
        AND acquire.phase=OLD.phase
        AND acquire.agent_id=OLD.agent_id
        AND acquire.requester_agent_id=OLD.requester_agent_id
        AND acquire.ttl_ms=OLD.ttl_ms
        AND acquire.client_request_id=OLD.client_lease_id
        AND acquire.idempotency_key=OLD.acquire_idempotency_key
        AND acquire.external_id=NEW.gateway_lease_id
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM external_rpc_intents release
    JOIN external_rpc_intents acquire
      ON acquire.rpc_kind='allow_lease_acquire'
     AND acquire.state IN ('accepted','reconciled')
     AND acquire.run_id=OLD.run_id
     AND acquire.transition_id=OLD.transition_id
     AND acquire.phase=OLD.phase
     AND acquire.agent_id=OLD.agent_id
     AND acquire.requester_agent_id=OLD.requester_agent_id
     AND acquire.ttl_ms=OLD.ttl_ms
     AND acquire.client_request_id=OLD.client_lease_id
     AND acquire.idempotency_key=OLD.acquire_idempotency_key
     AND acquire.external_id IS NOT NULL
     AND acquire.external_id <> ''
    WHERE release.rpc_kind='allow_lease_release'
      AND release.state IN ('accepted','reconciled')
      AND release.run_id=OLD.run_id
      AND release.transition_id=OLD.transition_id
      AND release.idempotency_key=OLD.release_idempotency_key
      AND release.external_id=acquire.external_id
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire-pending lease requires release proof before leaving pending ownership');
END;

CREATE TRIGGER leases_preserve_terminal_gateway_identity_update
BEFORE UPDATE OF state, gateway_lease_id ON leases
WHEN NEW.state IN ('expired','human_review_required')
  AND OLD.gateway_lease_id IS NOT NULL
  AND OLD.gateway_lease_id <> ''
  AND (NEW.gateway_lease_id IS NULL OR NEW.gateway_lease_id <> OLD.gateway_lease_id)
BEGIN
  SELECT RAISE(ABORT,'terminal lease must preserve gateway lease identity');
END;

CREATE TRIGGER leases_reject_live_release_not_required_update
BEFORE UPDATE OF state, gateway_lease_id ON leases
WHEN NEW.state='release_not_required'
  AND (OLD.state IN ('acquired','release_pending','released')
    OR (OLD.gateway_lease_id IS NOT NULL AND OLD.gateway_lease_id <> ''))
BEGIN
  SELECT RAISE(ABORT,'live lease cannot be marked release_not_required');
END;

CREATE TRIGGER leases_reject_acquired_release_not_required_insert
AFTER INSERT ON leases
WHEN NEW.state='release_not_required'
  AND EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_acquire'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.phase=NEW.phase
      AND eri.agent_id=NEW.agent_id
      AND eri.requester_agent_id=NEW.requester_agent_id
      AND eri.ttl_ms=NEW.ttl_ms
      AND eri.client_request_id=NEW.client_lease_id
      AND eri.idempotency_key=NEW.acquire_idempotency_key
      AND eri.external_id IS NOT NULL
      AND eri.external_id <> ''
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire intent cannot be marked release_not_required');
END;

CREATE TRIGGER leases_reject_acquired_release_not_required_update
AFTER UPDATE OF state, run_id, phase, transition_id, agent_id, requester_agent_id, client_lease_id, acquire_idempotency_key, ttl_ms ON leases
WHEN NEW.state='release_not_required'
  AND EXISTS (
    SELECT 1 FROM external_rpc_intents eri
    WHERE eri.rpc_kind='allow_lease_acquire'
      AND eri.state IN ('accepted','reconciled')
      AND eri.run_id=NEW.run_id
      AND eri.transition_id=NEW.transition_id
      AND eri.phase=NEW.phase
      AND eri.agent_id=NEW.agent_id
      AND eri.requester_agent_id=NEW.requester_agent_id
      AND eri.ttl_ms=NEW.ttl_ms
      AND eri.client_request_id=NEW.client_lease_id
      AND eri.idempotency_key=NEW.acquire_idempotency_key
      AND eri.external_id IS NOT NULL
      AND eri.external_id <> ''
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire intent cannot be marked release_not_required');
END;

CREATE TRIGGER external_rpc_intents_reject_release_not_required_acquire_insert
AFTER INSERT ON external_rpc_intents
WHEN NEW.rpc_kind='allow_lease_acquire'
  AND NEW.state IN ('accepted','reconciled')
  AND NEW.external_id IS NOT NULL
  AND NEW.external_id <> ''
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state='release_not_required'
      AND l.run_id=NEW.run_id
      AND l.transition_id=NEW.transition_id
      AND l.phase=NEW.phase
      AND l.agent_id=NEW.agent_id
      AND l.requester_agent_id=NEW.requester_agent_id
      AND l.ttl_ms=NEW.ttl_ms
      AND l.client_lease_id=NEW.client_request_id
      AND l.acquire_idempotency_key=NEW.idempotency_key
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire intent cannot back release_not_required lease');
END;

CREATE TRIGGER external_rpc_intents_reject_release_not_required_acquire_update
AFTER UPDATE OF rpc_kind, state, run_id, transition_id, phase, agent_id, requester_agent_id, ttl_ms, client_request_id, idempotency_key, external_id ON external_rpc_intents
WHEN NEW.rpc_kind='allow_lease_acquire'
  AND NEW.state IN ('accepted','reconciled')
  AND NEW.external_id IS NOT NULL
  AND NEW.external_id <> ''
  AND EXISTS (
    SELECT 1 FROM leases l
    WHERE l.state='release_not_required'
      AND l.run_id=NEW.run_id
      AND l.transition_id=NEW.transition_id
      AND l.phase=NEW.phase
      AND l.agent_id=NEW.agent_id
      AND l.requester_agent_id=NEW.requester_agent_id
      AND l.ttl_ms=NEW.ttl_ms
      AND l.client_lease_id=NEW.client_request_id
      AND l.acquire_idempotency_key=NEW.idempotency_key
  )
BEGIN
  SELECT RAISE(ABORT,'accepted acquire intent cannot back release_not_required lease');
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
  CHECK (reserved_time_seconds + consumed_time_seconds <= time_budget_seconds),
  CHECK (reserved_input_tokens + consumed_input_tokens <= input_token_budget),
  CHECK (reserved_output_tokens + consumed_output_tokens <= output_token_budget),
  CHECK (reserved_cost_microusd + consumed_cost_microusd <= cost_budget_microusd),
  CHECK (reserved_retries + consumed_retries <= retry_budget),
  CHECK (reserved_human_attention + consumed_human_attention <= human_attention_budget),
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
  JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND rb.selected_provider=m.provider
    AND rb.selected_model=m.model
    AND rb.selected_endpoint_binding_id=m.endpoint_binding_id
    AND rb.capability_class=m.capability_class
    AND rb.selected_cost_effective_at=m.effective_at
    AND rb.selected_cost_registry_hash=m.registry_row_hash
    AND rb.selected_cost_confidence=m.confidence
    AND m.confidence<>'unknown'
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.provider=m.provider
    AND b.model=m.model
    AND b.endpoint_binding_id=m.endpoint_binding_id
    AND b.capability_class=m.capability_class
    AND b.cost_registry_id=m.cost_registry_id
    AND b.cost_effective_at=m.effective_at
    AND b.cost_registry_hash=m.registry_row_hash
    AND b.cost_confidence=m.confidence
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
  JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id
  WHERE b.budget_event_id=NEW.reserve_budget_event_id
    AND b.event_type='reserve'
    AND b.run_id=NEW.run_id
    AND b.transition_id=NEW.transition_id
    AND b.spawn_request_id=NEW.spawn_request_id
    AND b.created_at_epoch_ms < NEW.requested_at_epoch_ms
    AND rb.selected_provider=m.provider
    AND rb.selected_model=m.model
    AND rb.selected_endpoint_binding_id=m.endpoint_binding_id
    AND rb.capability_class=m.capability_class
    AND rb.selected_cost_effective_at=m.effective_at
    AND rb.selected_cost_registry_hash=m.registry_row_hash
    AND rb.selected_cost_confidence=m.confidence
    AND m.confidence<>'unknown'
    AND b.provider=rb.selected_provider
    AND b.model=rb.selected_model
    AND b.endpoint_binding_id=rb.selected_endpoint_binding_id
    AND b.capability_class=rb.capability_class
    AND b.cost_registry_id=rb.selected_cost_registry_id
    AND b.cost_effective_at=rb.selected_cost_effective_at
    AND b.cost_registry_hash=rb.selected_cost_registry_hash
    AND b.cost_confidence=rb.selected_cost_confidence
    AND b.provider=m.provider
    AND b.model=m.model
    AND b.endpoint_binding_id=m.endpoint_binding_id
    AND b.capability_class=m.capability_class
    AND b.cost_registry_id=m.cost_registry_id
    AND b.cost_effective_at=m.effective_at
    AND b.cost_registry_hash=m.registry_row_hash
    AND b.cost_confidence=m.confidence
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
BEFORE UPDATE OF selected_provider, selected_model, selected_endpoint_binding_id, capability_class, selected_cost_registry_id, selected_cost_effective_at, selected_cost_registry_hash, selected_cost_confidence, time_budget_seconds, input_token_budget, output_token_budget, cost_budget_microusd, retry_budget, human_attention_budget, reserved_time_seconds, reserved_input_tokens, reserved_output_tokens, reserved_cost_microusd, reserved_retries, reserved_human_attention ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve budget row is immutable');
END;

CREATE TRIGGER run_budgets_preserve_spawn_prior_reserve_delete
BEFORE DELETE ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve budget row is immutable');
END;

CREATE TRIGGER run_budgets_preserve_spawn_prior_reserve_run_update
BEFORE UPDATE OF run_id ON run_budgets
WHEN EXISTS (
  SELECT 1
  FROM external_rpc_intents i
  JOIN budget_events b ON b.budget_event_id=i.reserve_budget_event_id
  WHERE i.rpc_kind='sessions_spawn'
    AND i.run_id=OLD.run_id
    AND b.run_id=OLD.run_id
)
BEGIN
  SELECT RAISE(ABORT,'referenced sessions_spawn reserve budget row is immutable');
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
  approval_id TEXT REFERENCES approvals(approval_id),
  evidence_hash TEXT,
  created_at TEXT NOT NULL,
  created_at_epoch_ms ANY NOT NULL,
  CHECK (typeof(sandbox_enforced)='integer' AND sandbox_enforced IN (0,1)),
  CHECK (typeof(created_at_epoch_ms)='integer' AND created_at_epoch_ms BETWEEN 1 AND 253402300799999),
  FOREIGN KEY(goal_id,predicate_plugin_hash,backend)
    REFERENCES goal_manifests(goal_id,predicate_plugin_hash,backend),
  FOREIGN KEY(predicate_plugin_hash,backend)
    REFERENCES predicate_plugins(predicate_plugin_hash,backend)
) STRICT;

CREATE TRIGGER goal_runs_validate_sandbox_insert
AFTER INSERT ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM predicate_plugins p
  WHERE p.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND p.backend=NEW.backend
    AND p.sandbox_required=1
    AND (
      NEW.sandbox_enforced<>1
      OR NEW.sandbox_proof_hash IS NULL
      OR NEW.sandbox_proof_hash=''
    )
)
BEGIN
  SELECT RAISE(ABORT,'sandbox-required goal run requires enforced sandbox proof');
END;

CREATE TRIGGER goal_runs_validate_sandbox_update
AFTER UPDATE OF predicate_plugin_hash, backend, sandbox_enforced, sandbox_proof_hash ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM predicate_plugins p
  WHERE p.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND p.backend=NEW.backend
    AND p.sandbox_required=1
    AND (
      NEW.sandbox_enforced<>1
      OR NEW.sandbox_proof_hash IS NULL
      OR NEW.sandbox_proof_hash=''
    )
)
BEGIN
  SELECT RAISE(ABORT,'sandbox-required goal run requires enforced sandbox proof');
END;

CREATE TRIGGER goal_runs_validate_manifest_plugin_insert
AFTER INSERT ON goal_runs
WHEN NOT EXISTS (
  SELECT 1
  FROM goal_manifests gm
  JOIN predicate_plugins p
    ON p.predicate_plugin_hash=gm.predicate_plugin_hash
   AND p.backend=gm.backend
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.severity=NEW.severity
    AND gm.enabled=1
    AND p.disabled_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'goal run requires enabled manifest and plugin with matching severity');
END;

CREATE TRIGGER goal_runs_validate_manifest_plugin_update
AFTER UPDATE OF goal_id, severity, predicate_plugin_hash, backend ON goal_runs
WHEN NOT EXISTS (
  SELECT 1
  FROM goal_manifests gm
  JOIN predicate_plugins p
    ON p.predicate_plugin_hash=gm.predicate_plugin_hash
   AND p.backend=gm.backend
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.severity=NEW.severity
    AND gm.enabled=1
    AND p.disabled_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT,'goal run requires enabled manifest and plugin with matching severity');
END;

CREATE TRIGGER predicate_plugins_validate_referenced_goal_runs_update
AFTER UPDATE OF sandbox_required, predicate_plugin_hash, backend ON predicate_plugins
WHEN NEW.sandbox_required=1 AND EXISTS (
  SELECT 1 FROM goal_runs gr
  WHERE gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
    AND (
      gr.sandbox_enforced<>1
      OR gr.sandbox_proof_hash IS NULL
      OR gr.sandbox_proof_hash=''
    )
)
BEGIN
  SELECT RAISE(ABORT,'sandbox-required plugin has goal runs without sandbox proof');
END;

CREATE TRIGGER predicate_plugins_reject_disable_with_goal_runs_update
AFTER UPDATE OF disabled_at, predicate_plugin_hash, backend ON predicate_plugins
WHEN NEW.disabled_at IS NOT NULL AND EXISTS (
  SELECT 1 FROM goal_runs gr
  WHERE gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
)
BEGIN
  SELECT RAISE(ABORT,'referenced predicate plugin cannot be disabled while goal runs exist');
END;

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
  consumed_by_goal_run_id TEXT UNIQUE REFERENCES goal_runs(goal_run_id) DEFERRABLE INITIALLY DEFERRED,
  approved_at TEXT NOT NULL,
  CHECK (approval_id <> ''),
  CHECK (run_id <> ''),
  CHECK (approved_action_type <> ''),
  CHECK (target_type <> '' AND target_id <> '' AND target_hash <> '' AND target_scope <> ''),
  CHECK (approved_risk_ceiling IN ('R0','R1','R2','R3','R4')),
  CHECK (typeof(expires_at_epoch_ms)='integer' AND expires_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(single_use)='integer' AND single_use IN (0,1)),
  CHECK (
    (
      consumed_by_transition_id IS NULL
      AND consumed_by_gate_run_id IS NULL
      AND consumed_by_goal_run_id IS NULL
    )
    OR (
      consumed_by_transition_id IS NOT NULL
      AND consumed_by_gate_run_id IS NOT NULL
      AND consumed_by_goal_run_id IS NULL
    )
    OR (
      consumed_by_transition_id IS NULL
      AND consumed_by_gate_run_id IS NULL
      AND consumed_by_goal_run_id IS NOT NULL
    )
  ),
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
    AND a.single_use=1
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
    AND a.single_use=1
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

CREATE TRIGGER approvals_preserve_transition_binding_delete
BEFORE DELETE ON approvals
WHEN EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.approval_required=1
    AND t.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required transition requires exact approval binding');
END;

CREATE TRIGGER approvals_preserve_transition_binding_update
BEFORE UPDATE OF approval_id, run_id, approved_action_type, target_type, target_id, target_hash, target_scope, channel, source_message_digest, approval_text_digest, approved_risk_ceiling, expires_at_epoch_ms, single_use, consumed_by_transition_id, consumed_by_gate_run_id ON approvals
WHEN EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.approval_required=1
    AND t.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required transition requires exact approval binding');
END;

CREATE TRIGGER goal_runs_validate_required_approval_insert
AFTER INSERT ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM goal_manifests gm
  JOIN approvals a ON a.approval_id=NEW.approval_id
  WHERE a.approval_id=NEW.approval_id
    AND NEW.run_id IS NOT NULL
    AND a.run_id=NEW.run_id
    AND gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
    AND gm.enabled=1
    AND a.approved_action_type='goal_run'
    AND a.target_type='goal'
    AND a.target_id=NEW.goal_id
    AND a.target_hash=gm.manifest_hash
    AND a.target_scope=gm.owner
    AND a.single_use=1
    AND a.consumed_by_goal_run_id=NEW.goal_run_id
    AND a.expires_at_epoch_ms > NEW.created_at_epoch_ms
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE gm.severity
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER goal_runs_validate_required_approval_update
AFTER UPDATE OF goal_id, run_id, severity, predicate_plugin_hash, backend, approval_id, created_at_epoch_ms ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM goal_manifests gm
  JOIN approvals a ON a.approval_id=NEW.approval_id
  WHERE a.approval_id=NEW.approval_id
    AND NEW.run_id IS NOT NULL
    AND a.run_id=NEW.run_id
    AND gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
    AND gm.enabled=1
    AND a.approved_action_type='goal_run'
    AND a.target_type='goal'
    AND a.target_id=NEW.goal_id
    AND a.target_hash=gm.manifest_hash
    AND a.target_scope=gm.owner
    AND a.single_use=1
    AND a.consumed_by_goal_run_id=NEW.goal_run_id
    AND a.expires_at_epoch_ms > NEW.created_at_epoch_ms
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE gm.severity
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER goal_manifests_validate_referenced_goal_runs_update
AFTER UPDATE OF owner, severity, manifest_hash, predicate_plugin_hash, backend, approval_required, enabled ON goal_manifests
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  LEFT JOIN predicate_plugins p
    ON p.predicate_plugin_hash=NEW.predicate_plugin_hash
   AND p.backend=NEW.backend
  LEFT JOIN approvals a ON a.approval_id=gr.approval_id
  WHERE gr.goal_id=NEW.goal_id
    AND gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
    AND (
      NEW.enabled<>1
      OR p.predicate_plugin_hash IS NULL
      OR p.disabled_at IS NOT NULL
      OR gr.severity<>NEW.severity
      OR (
        NEW.approval_required=1
        AND (
          gr.run_id IS NULL
          OR a.approval_id IS NULL
          OR a.run_id<>gr.run_id
          OR a.approved_action_type<>'goal_run'
          OR a.target_type<>'goal'
          OR a.target_id<>gr.goal_id
          OR a.target_hash<>NEW.manifest_hash
          OR a.target_scope<>NEW.owner
          OR a.single_use<>1
          OR a.consumed_by_goal_run_id<>gr.goal_run_id
          OR a.expires_at_epoch_ms<=gr.created_at_epoch_ms
          OR CASE a.approved_risk_ceiling
            WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
            WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
          END < CASE NEW.severity
            WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
            WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
          END
        )
      )
    )
)
BEGIN
  SELECT RAISE(ABORT,'referenced goal runs must keep enabled manifest, plugin, severity, and approval binding');
END;

CREATE TRIGGER approvals_preserve_goal_run_binding_delete
BEFORE DELETE ON approvals
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  JOIN goal_manifests gm
    ON gm.goal_id=gr.goal_id
   AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
   AND gm.backend=gr.backend
  WHERE gm.approval_required=1
    AND gr.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER approvals_preserve_goal_run_binding_update
BEFORE UPDATE OF approval_id, run_id, approved_action_type, target_type, target_id, target_hash, target_scope, approved_risk_ceiling, expires_at_epoch_ms, single_use, consumed_by_goal_run_id ON approvals
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  JOIN goal_manifests gm
    ON gm.goal_id=gr.goal_id
   AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
   AND gm.backend=gr.backend
  WHERE gm.approval_required=1
    AND gr.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
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
  CHECK (
    independence_proof_json <> ''
    AND CASE
      WHEN json_valid(independence_proof_json)=1
      THEN json_type(independence_proof_json)='object'
        AND json(independence_proof_json) <> '{}'
      ELSE 0
    END
  ),
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
  run_authority_mode TEXT,
  workflow_authority_mode TEXT,
  CHECK (typeof(completed_at_epoch_ms)='integer' AND completed_at_epoch_ms BETWEEN 1 AND 253402300799999),
  CHECK (typeof(requires_same_run)='integer' AND requires_same_run IN (0,1)),
  CHECK (risk_dominance IN ('R0','R1','R2','R3','R4')),
  CHECK (decision <> 'pass' OR (verifier_run_id IS NOT NULL AND evidence_hash IS NOT NULL AND evidence_hash <> '')),
  UNIQUE(gate_run_id,evidence_hash),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id),
  FOREIGN KEY(verifier_run_id,run_id,evidence_hash)
    REFERENCES judge_verifier_runs(verifier_run_id,worker_run_id,evidence_hash),
  FOREIGN KEY(gate_run_id,evidence_hash,run_id,verifier_run_id)
    REFERENCES evidence_hashes(gate_run_id,evidence_hash,run_id,verifier_run_id)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

-- Migration v11 adds gate_runs.run_authority_mode and
-- gate_runs.workflow_authority_mode as immutable gate-time authority snapshots.
-- Executable SLO audit PASS evidence must require both snapshot values to be
-- the exact non-NULL value file_authority; upgraded rows with NULL snapshots
-- and rows containing restored/current authority state but missing gate-time
-- snapshots fail closed.

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

CREATE TRIGGER gate_runs_validate_risk_binding_insert
AFTER INSERT ON gate_runs
WHEN NOT EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND t.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'gate risk dominance must match transition risk dominance');
END;

CREATE TRIGGER gate_runs_validate_risk_binding_update
AFTER UPDATE OF run_id, transition_id, risk_dominance ON gate_runs
WHEN NOT EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND t.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'gate risk dominance must match transition risk dominance');
END;

CREATE TRIGGER gate_runs_freeze_pass_update
BEFORE UPDATE ON gate_runs
WHEN OLD.decision='pass'
BEGIN
  SELECT RAISE(ABORT,'pass gate is immutable');
END;

CREATE TRIGGER gate_runs_freeze_pass_delete
BEFORE DELETE ON gate_runs
WHEN OLD.decision='pass'
BEGIN
  SELECT RAISE(ABORT,'pass gate is immutable');
END;

CREATE TRIGGER transitions_freeze_pass_gate_update
BEFORE UPDATE ON transitions
WHEN EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.decision='pass'
    AND g.run_id=OLD.run_id
    AND g.transition_id=OLD.transition_id
)
BEGIN
  SELECT RAISE(ABORT,'pass-gated transition is immutable');
END;

CREATE TRIGGER transitions_freeze_pass_gate_delete
BEFORE DELETE ON transitions
WHEN EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.decision='pass'
    AND g.run_id=OLD.run_id
    AND g.transition_id=OLD.transition_id
)
BEGIN
  SELECT RAISE(ABORT,'pass-gated transition is immutable');
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
AFTER UPDATE OF gate_run_id, consumed_by_gate_run_id, run_id, transition_id, now_epoch_ms, bound_at_epoch_ms, consumed_at_epoch_ms, gate_nonce, trusted_clock_source_hash ON gate_clock_context
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

CREATE TRIGGER gate_clock_context_preserve_consumed_identity_update
BEFORE UPDATE OF gate_nonce, trusted_clock_source_hash ON gate_clock_context
WHEN EXISTS (
  SELECT 1 FROM gate_runs g WHERE g.gate_run_id=OLD.gate_run_id
)
BEGIN
  SELECT RAISE(ABORT,'consumed gate clock identity is immutable');
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
  CHECK (risk_dominance IN ('R0','R1','R2','R3','R4')),
  FOREIGN KEY(transition_id,run_id) REFERENCES transitions(transition_id,run_id)
) STRICT;

CREATE TRIGGER risk_assessments_bind_transition_risk_insert
AFTER INSERT ON risk_assessments
WHEN NEW.transition_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND t.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'risk assessment must match transition risk dominance');
END;

CREATE TRIGGER risk_assessments_bind_transition_risk_update
AFTER UPDATE OF run_id, transition_id, risk_dominance ON risk_assessments
WHEN NEW.transition_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.transition_id=NEW.transition_id
    AND t.run_id=NEW.run_id
    AND t.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'risk assessment must match transition risk dominance');
END;

CREATE TRIGGER risk_assessments_bind_run_risk_insert
AFTER INSERT ON risk_assessments
WHEN NOT EXISTS (
  SELECT 1 FROM runs r
  WHERE r.run_id=NEW.run_id
    AND r.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'risk assessment must match run risk dominance');
END;

CREATE TRIGGER risk_assessments_bind_run_risk_update
AFTER UPDATE OF run_id, risk_dominance ON risk_assessments
WHEN NOT EXISTS (
  SELECT 1 FROM runs r
  WHERE r.run_id=NEW.run_id
    AND r.risk_dominance=NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'risk assessment must match run risk dominance');
END;

CREATE TRIGGER transitions_bind_existing_risk_assessment_insert
AFTER INSERT ON transitions
WHEN EXISTS (
  SELECT 1 FROM risk_assessments r
  WHERE r.transition_id=NEW.transition_id
    AND r.run_id=NEW.run_id
    AND r.risk_dominance<>NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'transition risk dominance must match assessment');
END;

CREATE TRIGGER transitions_bind_existing_risk_assessment_update
AFTER UPDATE OF run_id, risk_dominance ON transitions
WHEN EXISTS (
  SELECT 1 FROM risk_assessments r
  WHERE r.transition_id=NEW.transition_id
    AND r.run_id=NEW.run_id
    AND r.risk_dominance<>NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'transition risk dominance must match assessment');
END;

CREATE TRIGGER runs_bind_existing_risk_records_update
AFTER UPDATE OF risk_dominance ON runs
WHEN EXISTS (
  SELECT 1 FROM transitions t
  WHERE t.run_id=NEW.run_id
    AND t.risk_dominance<>NEW.risk_dominance
) OR EXISTS (
  SELECT 1 FROM risk_assessments r
  WHERE r.run_id=NEW.run_id
    AND r.risk_dominance<>NEW.risk_dominance
)
BEGIN
  SELECT RAISE(ABORT,'run risk dominance must match transition risk records');
END;

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
  UNIQUE(run_id, path, source_authority)
) STRICT;

CREATE TABLE artifact_projection_history (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  retained_projection_id TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  archive_reason TEXT NOT NULL
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

CREATE TRIGGER evidence_hashes_freeze_pass_gate_update
BEFORE UPDATE ON evidence_hashes
WHEN EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.decision='pass'
    AND g.gate_run_id=OLD.gate_run_id
    AND g.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'pass-gate evidence is immutable');
END;

CREATE TRIGGER evidence_hashes_freeze_pass_gate_delete
BEFORE DELETE ON evidence_hashes
WHEN EXISTS (
  SELECT 1 FROM gate_runs g
  WHERE g.decision='pass'
    AND g.gate_run_id=OLD.gate_run_id
    AND g.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'pass-gate evidence is immutable');
END;

-- v12 additive migration: goal-run evidence binding.
CREATE TEMP TABLE gate_authority_snapshot_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT gate_authority_snapshot_invalid CHECK (violation=0)
);

INSERT INTO gate_authority_snapshot_migration_guard(violation)
SELECT 1
FROM gate_runs g
JOIN runs r ON r.run_id=g.run_id
JOIN workflow_authority w ON w.workflow=r.workflow
WHERE (g.run_authority_mode IS NOT NULL OR g.workflow_authority_mode IS NOT NULL)
  AND (
    g.run_authority_mode IS NULL
    OR g.workflow_authority_mode IS NULL
    OR g.run_authority_mode<>r.authority_mode
    OR g.workflow_authority_mode<>w.mode
  );

DROP TABLE gate_authority_snapshot_migration_guard;

CREATE TRIGGER gate_runs_validate_authority_snapshot_insert
AFTER INSERT ON gate_runs
WHEN (NEW.run_authority_mode IS NOT NULL OR NEW.workflow_authority_mode IS NOT NULL)
  AND NOT EXISTS (
    SELECT 1
    FROM runs r
    JOIN workflow_authority w ON w.workflow=r.workflow
    WHERE r.run_id=NEW.run_id
      AND NEW.run_authority_mode=r.authority_mode
      AND NEW.workflow_authority_mode=w.mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot must match run and workflow authority');
END;

CREATE TRIGGER gate_runs_validate_authority_snapshot_update
AFTER UPDATE OF run_id, run_authority_mode, workflow_authority_mode ON gate_runs
WHEN (NEW.run_authority_mode IS NOT NULL OR NEW.workflow_authority_mode IS NOT NULL)
  AND NOT EXISTS (
    SELECT 1
    FROM runs r
    JOIN workflow_authority w ON w.workflow=r.workflow
    WHERE r.run_id=NEW.run_id
      AND NEW.run_authority_mode=r.authority_mode
      AND NEW.workflow_authority_mode=w.mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot must match run and workflow authority');
END;

CREATE TRIGGER gate_runs_freeze_authority_snapshot_update
BEFORE UPDATE OF run_authority_mode, workflow_authority_mode ON gate_runs
WHEN OLD.run_authority_mode IS NOT NULL
  AND OLD.workflow_authority_mode IS NOT NULL
  AND (
    NEW.run_authority_mode IS NOT OLD.run_authority_mode
    OR NEW.workflow_authority_mode IS NOT OLD.workflow_authority_mode
  )
BEGIN
  SELECT RAISE(ABORT,'gate authority snapshot is immutable');
END;

CREATE TEMP TABLE goal_run_evidence_binding_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT goal_run_evidence_binding_legacy_invalid CHECK (violation=0)
);

INSERT INTO goal_run_evidence_binding_migration_guard(violation)
SELECT 1
FROM goal_runs gr
WHERE gr.evidence_hash IS NOT NULL
  AND NOT EXISTS (
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
    JOIN runs r
      ON r.run_id=g.run_id
    JOIN workflow_authority w
      ON w.workflow=r.workflow
    JOIN transitions t
      ON t.transition_id=g.transition_id
     AND t.run_id=g.run_id
     AND t.gate_run_id=g.gate_run_id
     AND t.evidence_hash=g.evidence_hash
    JOIN gate_clock_context c
      ON c.clock_context_id=g.clock_context_id
     AND c.gate_run_id=g.gate_run_id
     AND c.consumed_by_gate_run_id=g.gate_run_id
     AND c.run_id=g.run_id
     AND c.transition_id=t.transition_id
    JOIN approvals a
      ON a.approval_id=t.approval_id
     AND a.run_id=t.run_id
     AND a.approved_action_type=t.action_type
     AND a.target_type=t.target_type
     AND a.target_id=t.target_id
     AND a.target_hash=t.target_hash
     AND a.target_scope=t.target_scope
     AND a.channel=t.approval_channel
     AND a.source_message_digest=t.approval_source_digest
     AND a.approval_text_digest=t.approval_text_digest
     AND a.consumed_by_transition_id=t.transition_id
     AND a.consumed_by_gate_run_id=g.gate_run_id
    JOIN schema_migrations m
      ON m.sha256=g.migration_sha256
    JOIN slo_queries q
      ON q.schema_version=m.version
     AND q.migration_sha256=m.sha256
     AND q.query_name='Completion gate before done for R2+'
     AND q.query_hash=g.gate_query_hash
    WHERE gr.run_id IS NOT NULL
      AND e.evidence_hash=gr.evidence_hash
      AND e.sha256=e.evidence_hash
      AND length(e.evidence_hash)=64
      AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
      AND e.path<>''
      AND e.content_type<>''
      AND e.redaction_status<>''
      AND e.captured_at<>''
      AND e.run_id=gr.run_id
      AND e.producer_run_id=gr.run_id
      AND e.verifier_run_id IS NOT NULL
      AND e.gate_run_id IS NOT NULL
      AND r.authority_mode='file_authority'
      AND w.mode='file_authority'
      AND g.run_authority_mode='file_authority'
      AND g.workflow_authority_mode='file_authority'
      AND g.run_authority_mode=r.authority_mode
      AND g.workflow_authority_mode=w.mode
      AND g.decision='pass'
      AND g.requires_same_run=1
      AND m.version=(SELECT MAX(version) FROM schema_migrations)
      AND g.completed_at_epoch_ms=c.now_epoch_ms
      AND c.bound_at_epoch_ms=c.now_epoch_ms
      AND c.consumed_at_epoch_ms=c.now_epoch_ms
      AND c.trusted_clock_source_hash=agentic_trusted_clock_source_hash(c.now_epoch_ms,c.bound_by)
      AND t.approval_required=1
      AND j.independence_class='independent'
      AND j.verifier_run_id<>j.worker_run_id
      AND j.verifier_run_id<>e.run_id
      AND j.worker_agent_id<>j.verifier_agent_id
      AND j.same_worker_context=0
      AND a.single_use=1
      AND length(a.source_message_digest)=64
      AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
      AND length(a.approval_text_digest)=64
      AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
      AND length(a.approval_hash)=64
      AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
      AND CASE a.approved_risk_ceiling
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
      END >= CASE t.risk_dominance
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
      END
      AND a.approver<>''
      AND a.channel<>''
      AND a.approved_at<>''
      AND a.expires_at_epoch_ms > c.now_epoch_ms
  );

DROP TABLE goal_run_evidence_binding_migration_guard;

CREATE TEMP TABLE goal_run_required_approval_migration_guard (
  violation INTEGER NOT NULL
    CONSTRAINT goal_run_required_approval_legacy_invalid CHECK (violation=0)
);

INSERT INTO goal_run_required_approval_migration_guard(violation)
SELECT 1
FROM goal_runs gr
JOIN goal_manifests gm
  ON gm.goal_id=gr.goal_id
 AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
 AND gm.backend=gr.backend
LEFT JOIN approvals a
  ON a.approval_id=gr.approval_id
WHERE gm.approval_required=1
  AND (
    gr.run_id IS NULL
    OR a.approval_id IS NULL
    OR a.run_id<>gr.run_id
    OR a.approved_action_type<>'goal_run'
    OR a.target_type<>'goal'
    OR a.target_id<>gr.goal_id
    OR a.target_hash<>gm.manifest_hash
    OR a.target_scope<>gm.owner
    OR a.single_use<>1
    OR a.consumed_by_goal_run_id<>gr.goal_run_id
    OR a.approver=''
    OR a.channel=''
    OR a.approved_at=''
    OR length(a.source_message_digest)<>64
    OR a.source_message_digest GLOB '*[^0-9a-f]*'
    OR length(a.approval_text_digest)<>64
    OR a.approval_text_digest GLOB '*[^0-9a-f]*'
    OR length(a.approval_hash)<>64
    OR a.approval_hash GLOB '*[^0-9a-f]*'
    OR a.expires_at_epoch_ms<=CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
    OR CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END < CASE gr.severity
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
  );

DROP TABLE goal_run_required_approval_migration_guard;

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
  JOIN runs r
    ON r.run_id=g.run_id
  JOIN workflow_authority w
    ON w.workflow=r.workflow
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  JOIN gate_clock_context c
    ON c.clock_context_id=g.clock_context_id
   AND c.gate_run_id=g.gate_run_id
   AND c.consumed_by_gate_run_id=g.gate_run_id
   AND c.run_id=g.run_id
   AND c.transition_id=t.transition_id
  JOIN approvals a
    ON a.approval_id=t.approval_id
   AND a.run_id=t.run_id
   AND a.approved_action_type=t.action_type
   AND a.target_type=t.target_type
   AND a.target_id=t.target_id
   AND a.target_hash=t.target_hash
   AND a.target_scope=t.target_scope
   AND a.channel=t.approval_channel
   AND a.source_message_digest=t.approval_source_digest
   AND a.approval_text_digest=t.approval_text_digest
   AND a.consumed_by_transition_id=t.transition_id
   AND a.consumed_by_gate_run_id=g.gate_run_id
  JOIN schema_migrations m
    ON m.sha256=g.migration_sha256
  JOIN slo_queries q
    ON q.schema_version=m.version
   AND q.migration_sha256=m.sha256
   AND q.query_name='Completion gate before done for R2+'
   AND q.query_hash=g.gate_query_hash
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.path<>''
    AND e.content_type<>''
    AND e.redaction_status<>''
    AND e.captured_at<>''
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND r.authority_mode='file_authority'
    AND w.mode='file_authority'
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.run_authority_mode=r.authority_mode
    AND g.workflow_authority_mode=w.mode
    AND g.decision='pass'
    AND g.requires_same_run=1
    AND m.version=(SELECT MAX(version) FROM schema_migrations)
    AND g.completed_at_epoch_ms=c.now_epoch_ms
    AND c.bound_at_epoch_ms=c.now_epoch_ms
    AND c.consumed_at_epoch_ms=c.now_epoch_ms
    AND c.trusted_clock_source_hash=agentic_trusted_clock_source_hash(c.now_epoch_ms,c.bound_by)
    AND t.approval_required=1
    AND j.independence_class='independent'
    AND j.verifier_run_id<>j.worker_run_id
    AND j.verifier_run_id<>e.run_id
    AND j.worker_agent_id<>j.verifier_agent_id
    AND j.same_worker_context=0
    AND a.single_use=1
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND a.expires_at_epoch_ms > c.now_epoch_ms
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
  JOIN runs r
    ON r.run_id=g.run_id
  JOIN workflow_authority w
    ON w.workflow=r.workflow
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  JOIN gate_clock_context c
    ON c.clock_context_id=g.clock_context_id
   AND c.gate_run_id=g.gate_run_id
   AND c.consumed_by_gate_run_id=g.gate_run_id
   AND c.run_id=g.run_id
   AND c.transition_id=t.transition_id
  JOIN approvals a
    ON a.approval_id=t.approval_id
   AND a.run_id=t.run_id
   AND a.approved_action_type=t.action_type
   AND a.target_type=t.target_type
   AND a.target_id=t.target_id
   AND a.target_hash=t.target_hash
   AND a.target_scope=t.target_scope
   AND a.channel=t.approval_channel
   AND a.source_message_digest=t.approval_source_digest
   AND a.approval_text_digest=t.approval_text_digest
   AND a.consumed_by_transition_id=t.transition_id
   AND a.consumed_by_gate_run_id=g.gate_run_id
  JOIN schema_migrations m
    ON m.sha256=g.migration_sha256
  JOIN slo_queries q
    ON q.schema_version=m.version
   AND q.migration_sha256=m.sha256
   AND q.query_name='Completion gate before done for R2+'
   AND q.query_hash=g.gate_query_hash
  WHERE NEW.run_id IS NOT NULL
    AND e.evidence_hash=NEW.evidence_hash
    AND e.sha256=e.evidence_hash
    AND length(e.evidence_hash)=64
    AND e.evidence_hash NOT GLOB '*[^0-9a-f]*'
    AND e.path<>''
    AND e.content_type<>''
    AND e.redaction_status<>''
    AND e.captured_at<>''
    AND e.run_id=NEW.run_id
    AND e.producer_run_id=NEW.run_id
    AND e.verifier_run_id IS NOT NULL
    AND e.gate_run_id IS NOT NULL
    AND r.authority_mode='file_authority'
    AND w.mode='file_authority'
    AND g.run_authority_mode='file_authority'
    AND g.workflow_authority_mode='file_authority'
    AND g.run_authority_mode=r.authority_mode
    AND g.workflow_authority_mode=w.mode
    AND g.decision='pass'
    AND g.requires_same_run=1
    AND m.version=(SELECT MAX(version) FROM schema_migrations)
    AND g.completed_at_epoch_ms=c.now_epoch_ms
    AND c.bound_at_epoch_ms=c.now_epoch_ms
    AND c.consumed_at_epoch_ms=c.now_epoch_ms
    AND c.trusted_clock_source_hash=agentic_trusted_clock_source_hash(c.now_epoch_ms,c.bound_by)
    AND t.approval_required=1
    AND j.independence_class='independent'
    AND j.verifier_run_id<>j.worker_run_id
    AND j.verifier_run_id<>e.run_id
    AND j.worker_agent_id<>j.verifier_agent_id
    AND j.same_worker_context=0
    AND a.single_use=1
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND CASE a.approved_risk_ceiling
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
    END >= CASE t.risk_dominance
      WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
      WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
    END
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND a.expires_at_epoch_ms > c.now_epoch_ms
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence requires same-run independent pass-gate evidence');
END;

CREATE TRIGGER goal_runs_validate_required_approval_current_insert
AFTER INSERT ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM approvals a
  WHERE a.approval_id=NEW.approval_id
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires unexpired SHA-256 approval binding');
END;

CREATE TRIGGER goal_runs_validate_required_approval_current_update
AFTER UPDATE OF goal_id, run_id, severity, predicate_plugin_hash, backend, approval_id, created_at_epoch_ms ON goal_runs
WHEN EXISTS (
  SELECT 1 FROM goal_manifests gm
  WHERE gm.goal_id=NEW.goal_id
    AND gm.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gm.backend=NEW.backend
    AND gm.approval_required=1
) AND NOT EXISTS (
  SELECT 1
  FROM approvals a
  WHERE a.approval_id=NEW.approval_id
    AND a.approver<>''
    AND a.channel<>''
    AND a.approved_at<>''
    AND length(a.source_message_digest)=64
    AND a.source_message_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_text_digest)=64
    AND a.approval_text_digest NOT GLOB '*[^0-9a-f]*'
    AND length(a.approval_hash)=64
    AND a.approval_hash NOT GLOB '*[^0-9a-f]*'
    AND a.expires_at_epoch_ms > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires unexpired SHA-256 approval binding');
END;

CREATE TRIGGER goal_manifests_validate_required_approval_current_update
AFTER UPDATE OF owner, severity, manifest_hash, predicate_plugin_hash, backend, approval_required, enabled ON goal_manifests
WHEN NEW.approval_required=1 AND EXISTS (
  SELECT 1
  FROM goal_runs gr
  LEFT JOIN approvals a ON a.approval_id=gr.approval_id
  WHERE gr.goal_id=NEW.goal_id
    AND gr.predicate_plugin_hash=NEW.predicate_plugin_hash
    AND gr.backend=NEW.backend
    AND (
      gr.run_id IS NULL
      OR a.approval_id IS NULL
      OR a.run_id<>gr.run_id
      OR a.approved_action_type<>'goal_run'
      OR a.target_type<>'goal'
      OR a.target_id<>gr.goal_id
      OR a.target_hash<>NEW.manifest_hash
      OR a.target_scope<>NEW.owner
      OR a.single_use<>1
      OR a.consumed_by_goal_run_id<>gr.goal_run_id
      OR a.approver=''
      OR a.channel=''
      OR a.approved_at=''
      OR length(a.source_message_digest)<>64
      OR a.source_message_digest GLOB '*[^0-9a-f]*'
      OR length(a.approval_text_digest)<>64
      OR a.approval_text_digest GLOB '*[^0-9a-f]*'
      OR length(a.approval_hash)<>64
      OR a.approval_hash GLOB '*[^0-9a-f]*'
      OR a.expires_at_epoch_ms<=CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
      OR CASE a.approved_risk_ceiling
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1
      END < CASE NEW.severity
        WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2
        WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99
      END
    )
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires current SHA-256 approval binding');
END;

CREATE TRIGGER approvals_preserve_goal_run_digest_update
BEFORE UPDATE OF approver, channel, source_message_digest, approval_text_digest, approval_hash, approved_at ON approvals
WHEN EXISTS (
  SELECT 1 FROM goal_runs gr
  JOIN goal_manifests gm
    ON gm.goal_id=gr.goal_id
   AND gm.predicate_plugin_hash=gr.predicate_plugin_hash
   AND gm.backend=gr.backend
  WHERE gm.approval_required=1
    AND gr.approval_id=OLD.approval_id
)
OR EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
  JOIN transitions t
    ON t.transition_id=g.transition_id
   AND t.run_id=g.run_id
   AND t.gate_run_id=g.gate_run_id
   AND t.evidence_hash=g.evidence_hash
  WHERE gr.evidence_hash IS NOT NULL
    AND t.approval_id=OLD.approval_id
)
BEGIN
  SELECT RAISE(ABORT,'approval-required goal run requires exact approval binding');
END;

CREATE TRIGGER runs_preserve_goal_run_file_authority_update
BEFORE UPDATE OF workflow, authority_mode ON runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.run_id=OLD.run_id
)
AND (
  NEW.workflow IS NOT OLD.workflow
  OR NEW.authority_mode IS NOT OLD.authority_mode
)
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence requires file-authority run');
END;

CREATE TRIGGER workflow_authority_preserve_goal_run_file_authority_update
BEFORE UPDATE OF mode ON workflow_authority
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN runs r
    ON r.run_id=e.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND r.workflow=OLD.workflow
)
AND NEW.mode IS NOT OLD.mode
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence requires file-authority workflow');
END;

CREATE TRIGGER gate_clock_context_preserve_goal_run_bound_clock_update
BEFORE UPDATE OF bound_by ON gate_clock_context
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND g.clock_context_id=OLD.clock_context_id
    AND g.gate_run_id=OLD.gate_run_id
)
BEGIN
  SELECT RAISE(ABORT,'goal run evidence clock signer is immutable');
END;

CREATE TRIGGER judge_verifier_runs_preserve_goal_run_proof_update
BEFORE UPDATE OF verifier_run_id, worker_run_id, worker_agent_id, verifier_agent_id, provider, model, model_version, prompt_hash, context_hash, evidence_hash, independence_class, independence_proof_json, completed_at ON judge_verifier_runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.verifier_run_id=OLD.verifier_run_id
    AND e.run_id=OLD.worker_run_id
    AND e.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'goal run verifier proof is immutable');
END;

CREATE TRIGGER judge_verifier_runs_preserve_goal_run_proof_delete
BEFORE DELETE ON judge_verifier_runs
WHEN EXISTS (
  SELECT 1
  FROM goal_runs gr
  JOIN evidence_hashes e
    ON e.evidence_hash=gr.evidence_hash
   AND e.run_id=gr.run_id
  WHERE gr.evidence_hash IS NOT NULL
    AND e.verifier_run_id=OLD.verifier_run_id
    AND e.run_id=OLD.worker_run_id
    AND e.evidence_hash=OLD.evidence_hash
)
BEGIN
  SELECT RAISE(ABORT,'goal run verifier proof is immutable');
END;

CREATE TRIGGER goal_runs_freeze_evidence_binding_update
BEFORE UPDATE OF goal_id, run_id, severity, predicate_plugin_hash, backend, evidence_hash ON goal_runs
WHEN OLD.evidence_hash IS NOT NULL
  AND (
    NEW.goal_id IS NOT OLD.goal_id
    OR NEW.run_id IS NOT OLD.run_id
    OR NEW.severity IS NOT OLD.severity
    OR NEW.predicate_plugin_hash IS NOT OLD.predicate_plugin_hash
    OR NEW.backend IS NOT OLD.backend
    OR NEW.evidence_hash IS NOT OLD.evidence_hash
  )
BEGIN
  SELECT RAISE(ABORT,'goal run evidence binding is immutable');
END;

CREATE TRIGGER goal_runs_freeze_evidence_binding_delete
BEFORE DELETE ON goal_runs
WHEN OLD.evidence_hash IS NOT NULL
BEGIN
  SELECT RAISE(ABORT,'bound goal run evidence cannot be deleted');
END;

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
  query_name TEXT NOT NULL,
  schema_version ANY NOT NULL REFERENCES schema_migrations(version),
  migration_sha256 TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  sql_text TEXT NOT NULL,
  empty_db_expected_status TEXT NOT NULL,
  fixture_db_expected_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(query_name,schema_version,migration_sha256,query_hash),
  CHECK (typeof(schema_version)='integer' AND schema_version > 0),
  CHECK (length(migration_sha256)=64 AND length(query_hash)=64 AND sql_text<>''),
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
  evidence_run_id TEXT,
  verifier_run_id TEXT,
  gate_run_id TEXT,
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
    AND evidence_run_id IS NOT NULL AND evidence_run_id<>''
    AND verifier_run_id IS NOT NULL AND verifier_run_id<>''
    AND gate_run_id IS NOT NULL AND gate_run_id<>''
  )),
  FOREIGN KEY(query_name,schema_version,migration_sha256,query_hash)
    REFERENCES slo_queries(query_name,schema_version,migration_sha256,query_hash),
  FOREIGN KEY(gate_run_id,evidence_hash,evidence_run_id,verifier_run_id)
    REFERENCES evidence_hashes(gate_run_id,evidence_hash,run_id,verifier_run_id)
) STRICT;

CREATE TRIGGER slo_audits_validate_pass_evidence_insert
AFTER INSERT ON slo_audits
WHEN NEW.status='pass' AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  WHERE e.gate_run_id=NEW.gate_run_id
    AND e.evidence_hash=NEW.evidence_hash
    AND e.run_id=NEW.evidence_run_id
    AND e.producer_run_id=NEW.evidence_run_id
    AND e.verifier_run_id=NEW.verifier_run_id
    AND g.decision='pass'
)
BEGIN
  SELECT RAISE(ABORT,'passing SLO audit requires pass-gate evidence');
END;

CREATE TRIGGER slo_audits_validate_pass_evidence_update
AFTER UPDATE OF status, evidence_hash, evidence_run_id, verifier_run_id, gate_run_id ON slo_audits
WHEN NEW.status='pass' AND NOT EXISTS (
  SELECT 1
  FROM evidence_hashes e
  JOIN gate_runs g
    ON g.gate_run_id=e.gate_run_id
   AND g.evidence_hash=e.evidence_hash
   AND g.run_id=e.run_id
   AND g.verifier_run_id=e.verifier_run_id
  WHERE e.gate_run_id=NEW.gate_run_id
    AND e.evidence_hash=NEW.evidence_hash
    AND e.run_id=NEW.evidence_run_id
    AND e.producer_run_id=NEW.evidence_run_id
    AND e.verifier_run_id=NEW.verifier_run_id
    AND g.decision='pass'
)
BEGIN
  SELECT RAISE(ABORT,'passing SLO audit requires pass-gate evidence');
END;

CREATE TRIGGER slo_audits_preserve_pass_update
BEFORE UPDATE ON slo_audits
WHEN OLD.status='pass'
BEGIN
  SELECT RAISE(ABORT,'SLO audit row is immutable');
END;

CREATE TRIGGER slo_audits_preserve_pass_delete
BEFORE DELETE ON slo_audits
WHEN OLD.status='pass'
BEGIN
  SELECT RAISE(ABORT,'SLO audit row is immutable');
END;

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
```

Current migration v2 shadow projection identity:

`0002_shadow_projection_identity.sql` upgrades version-1 databases to the
current contract shown in the main DDL block. The accepted post-migration
projection identity is:

```sql
CREATE TABLE artifact_projections (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  UNIQUE(run_id, path, source_authority)
) STRICT;

CREATE TABLE artifact_projection_history (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  retained_projection_id TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  archive_reason TEXT NOT NULL
) STRICT;
```

Current migration v3 budget ledger SLO identity:

`0003_budget_ledger_slo_identity.sql` records the revised
`Budget ledger reconciles to counters and budgets` query as a new immutable
schema-versioned SLO row. Schema versions 1 and 2 keep their historical query
hashes; version 3 and later use the stricter negative-net ledger isolation
contract.

Current migration v7 budget post-dispatch clock identity:

`0007_budget_post_dispatch_clock_identity.sql` adds nullable
`budget_events.clock_context_id` for post-dispatch usage, retry, and
human-attention rows written after an accepted `sessions_spawn` proof. Current
SLO rows require those post-dispatch events to bind to the run budget's
`selected_reserve_transition_id`, exact selected cost row, accepted/requested
clock ordering, and a persisted one-use trusted gate clock context whose
`now_epoch_ms` exactly matches the budget event timestamp. The migration also
freezes accepted post-dispatch budget events against update/delete, including
replay keys, and freezes accepted `sessions_spawn` request/accepted epoch
timing so counter rewrites cannot erase or retroactively reshape the
authoritative usage ledger. Schema version 6 keeps its historical SLO query
hashes; version 7 and later use this stricter proof.

Current migration v8 atomic final settlement:

`0008_budget_atomic_final_settlement.sql` adds immutable
`budget_settlements` proof rows and links their generated ledger events through
`budget_events.settlement_id`. A completed spawn may be settled exactly once.
The proof binds the same run, selected reserve transition, spawn request,
accepted `sessions_spawn` intent, completed session, selected endpoint/cost
row, and trusted post-accept clock. The settlement atomically records any
remaining terminal `consume`, `retry_decrement`, and `human_attention` usage
and releases every unused reserved dimension in the same `BEGIN IMMEDIATE`
transaction. Post-intent `release` remains rejected unless it carries this
exact settlement proof. Settlement rows and linked events are immutable, and the
database rejects cross-table source dedupe reuse, freezes the completed session
proof once referenced by a settlement, rejects fresh settlement rows after the
run has advanced beyond `child_completed` / `child_failed` /
`aggregation_completed`, and rejects unlinked post-settlement budget events for
the same spawn. The current amount/SLO contract blocks incomplete,
amount-mismatched, binding-mismatched, or extra linked event sets and
revalidates completed-session proof after normal `gate_passed` /
`release_pending` / `finalized` progression even if a malicious fixture bypasses
runtime triggers.
Schema version 7 keeps its historical SLO query hashes; version 8 and later use
the atomic-settlement completeness contract.

Current migration v9 legacy money import quarantine:

`0009_legacy_money_import_quarantine.sql` adds immutable
`legacy_money_import_batches`, `legacy_money_import_quarantine`, and
`legacy_money_import_promotions` evidence tables. The only supported source
schema is a real SQLite table named `legacy_budget_terminal_usage_v1`; the only
supported source unit is `usd_decimal`. Import validation rejects views before
trusting `typeof()` / `quote()` storage-class evidence, reads the original SQLite
storage class before conversion, and converts Python `Decimal` values into
integer microusd without default-context rounding. Read failures, schema
failures, and malformed rows all become durable quarantine evidence and
payload-hash input, and any quarantine promotes zero authoritative rows for the
whole batch. Quarantine records include a deterministic source-row ordinal in
their identity so byte-identical malformed rows with missing or non-text legacy
identifiers remain separately durable. The evidence child tables use deferred
batch references so the immutable parent batch row can be inserted only after
the exact final quarantine or promotion child count already exists in the same
transaction; later child evidence appends remain blocked by the batch status and
count guards. Clean batches promote through the same atomic final-settlement
runtime path, so imports cannot create unlinked settlement or budget events.
Exact batch replay is idempotent; reused batch, idempotency, or dedupe identity
with changed raw legacy payload fails closed.
This slice does not enable production database authority.

Current migration v10 runtime dispatch binding:

`0010_runtime_dispatch_binding.sql` adds the immutable
`runtime_dispatch_bindings` relation. Each row binds one spawn request to one
lease using the complete persisted dispatch identity: run, transition, phase,
agent, requester, task digest, client lease, acquire key, release key, spawn
client request, and spawn idempotency key. Composite foreign keys require the
same row to match both the existing `spawn_requests` identity and the existing
`leases` identity; unique identity columns reject cross-dispatch reuse, and
update/delete triggers preserve the binding as reconciliation evidence. The
runtime writes this relation in the same `BEGIN IMMEDIATE` transaction as both
pending external RPC intents. After v10, direct/import writers cannot create or
reshape a `sessions_spawn` external RPC intent unless the exact binding already
exists; the trigger and current SLO both treat an unbound spawn intent as
non-contract state. During v9-to-v10 upgrade, bindings are backfilled
only when one spawn intent and one lease/acquire intent have exact durable
run/transition/phase/agent identity and equal persisted request text and epoch
milliseconds. Zero-candidate, multi-candidate, or lease-reuse cases abort the
whole migration; legacy runtime work is never silently omitted. Reconciliation
joins only through this relation,
so a spawn proven blocked before the external call can release its owned lease
without pairing another dispatch on the same run/transition. Crash-left,
zero-observation, and ambiguous spawn outcomes retain the lease for human
review because session discovery cannot prove the external spawn did not
succeed. Before inserting a new
pending dispatch, the same immediate transaction rejects an older potentially
live run/phase/agent spawn intent in `pending`, `unknown`, `accepted`, or
`reconciled` state, plus unresolved human-review outcomes. Only a terminal
pre-spawn allow-lease failure is excluded. Exact replay is decided before this
arbitration. Competing or post-timeout attempts therefore fail before any new
lease or spawn RPC, while external RPC remains outside the SQLite transaction.
The acceptance transaction repeats the guard as defense in depth. Runtime
authority remains disabled.

Current migration v13 trust promotion binding:

`0013_trust_promotion_binding.sql` keeps historical invalidated
`trust_observations` inert, but any active row must bind exactly to one run, one
goal run, one evidence hash, one independent verifier, one approval-bound PASS
gate, one gate clock, the accepted v13 schema/migration identity, the exact
current 30-query SLO contract set, one complete current latest SLO PASS audit
set, one file-authority gate snapshot, one known selected cost row, current
goal-manifest and predicate-plugin metadata, and the exact proven run/goal risk
boundary plus current risk-assessment row. Conflicting risk-assessment rows for
the same transition fail closed, and goal-run severity cannot downgrade below
the bound transition/run risk. Migration aborts if active legacy trust rows exist without those
bindings. The active-row trigger
accepts only `status='promoted'`, `usage_confidence='known'`,
`cost_confidence='known'`, non-empty `bounded_at` and `created_at`, complete current latest SLO PASS coverage, exact
scope/severity equality with the bound evidence, and a deterministic
`agentic_trust_binding_hash(...)` over the run/goal/evidence binding. The same
binding hash is the required effective group, and duplicate active bindings for
the same run/goal/evidence are rejected. Raw SQLite clients that do not register
the local SQL functions fail closed, and clients that do register them must pass
an immediate `agentic_evidence_snapshot_current(...)` artifact re-hash. The
binding view rejects unknown or estimated usage/cost across trusted-workflow run budgets,
non-human budget events, final settlements, and selected model cost registry
rows; rejects database-authority current or gate-time snapshots; and rejects
run budgets whose workflow or selected reserve transition does not exactly match
the bound run/transition. Trusted-workflow non-human budget events must also
match the run's selected provider/model/endpoint/capability/cost registry row.
self-verifier, wrong-run, non-PASS, stale gate identity, stale trusted clock,
malformed evidence, missing same-run goal evidence, any older PASS SLO audit
shadowed by newer audit evidence, SLO audit rows older than the bound gate clock
or mutable runtime evidence, forged PASS SLO audits, mutable SLO evidence events,
mutated PASS-gate approval hashes, and missing current risk-assessment binding.
Direct SQL insertion is pinned to v13 plus the
accepted 30-query SLO count, so fake later schema or SLO rows cannot become the
trust contract. Predicate-plugin metadata referenced by a goal run is immutable
before promotion, including sensitive-plugin approval timestamps; goal-manifest
identity is immutable once referenced by a goal run. Post-promotion bound
goal-run sandbox evidence, budget, settlement, runtime SLO inputs
(`external_rpc_intents`, `leases`, `spawn_requests`, `sessions`, `runs`), model
cost registry, zero-reserve policy, SLO audit, schema, SLO registry, and
predicate-plugin metadata, same-workflow settlements, workflow authority,
unbound runtime rows, risk assessments, bound gate-clock context rows, and all run-row mutations cannot change while trust is active; callers must invalidate
the trust row first. Active trust rows are immutable except for setting
`invalidated_at` to retire stale trust, and invalidated rows cannot be
reactivated. The local writer derives all authority fields under `BEGIN
IMMEDIATE`, reruns the current blocking SLO contracts under the write lock, and
rechecks the evidence artifact before commit; it performs no OpenClaw/Gateway/Cron
or production-authority calls.

The v8 executable overlay for `Budget event amount malformed or out of range`
adds this settlement proof check to the baseline amount query:

```sql
UNION ALL SELECT bs.settlement_id FROM budget_settlements bs WHERE ((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume')) OR ((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=bs.actual_time_seconds AND be.input_tokens=bs.actual_input_tokens AND be.output_tokens=bs.actual_output_tokens AND be.cost_microusd=bs.actual_cost_microusd AND be.retry_units=0 AND be.human_attention_units=0)) OR ((bs.actual_retry_units>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='retry_decrement')) OR ((bs.actual_retry_units>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='retry_decrement' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=0 AND be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.retry_units=bs.actual_retry_units AND be.human_attention_units=0)) OR ((bs.actual_human_attention_units>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='human_attention')) OR ((bs.actual_human_attention_units>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='human_attention' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=0 AND be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.retry_units=0 AND be.human_attention_units=bs.actual_human_attention_units)) OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 OR bs.released_retry_units>0 OR bs.released_human_attention_units>0 OR (bs.actual_time_seconds=0 AND bs.actual_input_tokens=0 AND bs.actual_output_tokens=0 AND bs.actual_cost_microusd=0 AND bs.actual_retry_units=0 AND bs.actual_human_attention_units=0 AND bs.released_time_seconds=0 AND bs.released_input_tokens=0 AND bs.released_output_tokens=0 AND bs.released_cost_microusd=0 AND bs.released_retry_units=0 AND bs.released_human_attention_units=0)) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='release')) OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 OR bs.released_retry_units>0 OR bs.released_human_attention_units>0 OR (bs.actual_time_seconds=0 AND bs.actual_input_tokens=0 AND bs.actual_output_tokens=0 AND bs.actual_cost_microusd=0 AND bs.actual_retry_units=0 AND bs.actual_human_attention_units=0 AND bs.released_time_seconds=0 AND bs.released_input_tokens=0 AND bs.released_output_tokens=0 AND bs.released_cost_microusd=0 AND bs.released_retry_units=0 AND bs.released_human_attention_units=0)) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='release' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=bs.released_time_seconds AND be.input_tokens=bs.released_input_tokens AND be.output_tokens=bs.released_output_tokens AND be.cost_microusd=bs.released_cost_microusd AND be.retry_units=bs.released_retry_units AND be.human_attention_units=bs.released_human_attention_units)) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type NOT IN ('consume','retry_decrement','human_attention','release')) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.event_dedupe_hash=bs.settlement_dedupe_hash) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id IS NULL AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.event_type IN ('reserve','consume','release','retry_decrement','retry_restore','human_attention') AND be.event_sequence>(SELECT COALESCE(MAX(linked.event_sequence),0) FROM budget_events linked WHERE linked.settlement_id=bs.settlement_id)) OR NOT EXISTS (SELECT 1 FROM spawn_requests sr JOIN runs r ON r.run_id=sr.run_id JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id AND s.client_request_id=sr.client_request_id AND s.spawn_idempotency_key=sr.spawn_idempotency_key AND s.phase=sr.phase AND s.agent_id=sr.agent_id AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' AND i.state IN ('accepted','reconciled') AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id AND i.transition_id=sr.transition_id AND i.client_request_id=sr.client_request_id AND i.idempotency_key=sr.spawn_idempotency_key AND i.phase=sr.phase AND i.agent_id=sr.agent_id AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key JOIN run_budgets rb ON rb.run_id=sr.run_id JOIN gate_clock_context c ON c.clock_context_id=bs.clock_context_id AND c.run_id=sr.run_id AND c.transition_id=sr.transition_id JOIN gate_runs g ON g.gate_run_id=c.gate_run_id AND g.clock_context_id=c.clock_context_id AND g.run_id=c.run_id AND g.transition_id=c.transition_id WHERE sr.spawn_request_id=bs.spawn_request_id AND sr.run_id=bs.run_id AND sr.transition_id=bs.transition_id AND sr.state='completed' AND s.state='completed' AND s.completed_at IS NOT NULL AND s.completed_at<>'' AND r.state IN ('child_completed','child_failed','aggregation_completed','gate_passed','release_pending','finalized') AND rb.selected_reserve_transition_id=bs.transition_id AND rb.selected_provider=bs.provider AND rb.selected_model=bs.model AND rb.selected_endpoint_binding_id=bs.endpoint_binding_id AND rb.capability_class=bs.capability_class AND rb.selected_cost_registry_id=bs.cost_registry_id AND rb.selected_cost_effective_at=bs.cost_effective_at AND rb.selected_cost_registry_hash=bs.cost_registry_hash AND rb.selected_cost_confidence=bs.cost_confidence AND rb.usage_confidence IN ('known','estimated') AND i.requested_at_epoch_ms<i.accepted_at_epoch_ms AND i.accepted_at_epoch_ms<bs.created_at_epoch_ms AND c.gate_run_id=c.consumed_by_gate_run_id AND c.bound_at_epoch_ms=c.now_epoch_ms AND c.consumed_at_epoch_ms=c.now_epoch_ms AND c.now_epoch_ms=bs.created_at_epoch_ms AND c.trusted_clock_source_hash<>'' AND c.gate_nonce<>'' AND g.decision='pass' AND g.completed_at_epoch_ms=c.now_epoch_ms);
```

Gate-critical time authority:

- Approval expiry authority is `approvals.expires_at_epoch_ms` only. It is stored in a `STRICT` table `ANY` column, must have integer storage class by `typeof(...)= 'integer'`, and is compared only to the trusted gate-context integer `gate_clock_context.now_epoch_ms`.
- The gate transaction creates exactly one per-gate `gate_clock_context` row before approval selection. It is keyed by `clock_context_id`, `gate_run_id`, `run_id`, `transition_id`, and a one-use `gate_nonce`; it records `trusted_clock_source_hash` and is consumed by exactly the same `gate_run_id`.
- The executable freshness invariant is exact snapshot equality inside the same gate transaction: `gate_clock_context.bound_at_epoch_ms = gate_clock_context.now_epoch_ms = gate_clock_context.consumed_at_epoch_ms = gate_runs.completed_at_epoch_ms`. Old or future `bound_at_epoch_ms`, stale/future `now_epoch_ms` relative to the persisted gate completion, wrong-run contexts, wrong-transition contexts, reused nonces, missing trusted source hashes, and mismatched completion times fail closed. The database does not re-read wall-clock time in SLO SQL; the persisted trusted snapshot is the only authorization clock authority.
- Raw `strftime('%s')*1000`, text comparison, reusable global clock rows, and human-readable timestamp parsing are forbidden in gate-critical approval SQL.
- Any human-readable approval expiry string, including `expires_at_display`, is a projection for audit packets only; it is never authorization authority.
- Reserve-before-RPC ordering uses persisted type-preserving epoch-millisecond columns: `budget_events.created_at_epoch_ms` and `external_rpc_intents.requested_at_epoch_ms`. Each is a `STRICT` table `ANY` value whose storage class must be integer before range comparison. For `sessions_spawn`, `external_rpc_intents.reserve_budget_event_id` must point to the exact reserve event, and the reserve event must satisfy `reserve.created_at_epoch_ms < intent.requested_at_epoch_ms`.
- Equal epoch milliseconds are ambiguous and fail closed unless a future migration adds a persisted monotonic transaction/sequence authority proving strict reserve-before-intent. This design deliberately does not pretend the external RPC is transactional with SQLite; the proof is the committed reserve row and committed intent row before crossing the external boundary.
- Other gate-critical timestamp comparisons use paired epoch-millisecond columns, such as `leases.expires_at_epoch_ms`, `runs.finalized_at_epoch_ms`, and `gate_runs.completed_at_epoch_ms`. Raw `TEXT` ordering and SQLite wall-clock functions are not gate-critical authority.

Cost registry row-hash authority:

- `model_cost_registry.registry_row_hash` is computed over provider, model, endpoint binding id, capability class, effective timestamp, bounded integer `input_cost_microusd_per_million`, bounded integer `output_cost_microusd_per_million`, and confidence.
- A budget event or run budget may not treat provider/model/capability/effective timestamp as sufficient identity; endpoint binding id and row hash must match the referenced registry row.
- Gate-critical monetary values are bounded fixed-scale integers in microusd stored through type-preserving `STRICT`/`ANY` columns. Registry prices are non-negative bounded integer storage-class values; `NULL`, numeric text, integral `REAL`, wrong-type, negative, non-finite legacy conversions, and max+1 values fail DDL or migration quarantine.
- `budget_events` is the authoritative ledger. Budget event token, `cost_microusd`, time, human-attention, and retry columns are unsigned amounts interpreted by `event_type`; reserve and consume events cannot create budget credit. `consume` cannot carry `retry_units` or `human_attention_units`; `retry_decrement` and `retry_restore` cannot carry time, token, cost, or human-attention amounts. `human_attention` is the only human-attention consumption authority and remains pure-dimension: it must carry `human_attention_units > 0` and zero `input_tokens`, `output_tokens`, `cost_microusd`, `time_seconds`, and `retry_units`. Any token/cost/time usage associated with the same operator episode must be recorded as a separate endpoint-bound `consume` event, not hidden on the human-attention row. Counter columns in `run_budgets` are a cache that must reconcile exactly to signed semantic ledger sums.
- Zero input/output/cost reserve is valid only when `zero_reserve_policy_id` and `zero_reserve_policy_hash` point to an enabled endpoint policy for the same endpoint/capability, the event timestamp is inside the policy effective window, the policy defines at least one positive minimum, and the event satisfies every configured positive minimum for retry, time, and human attention.

## State Machine and Projection Contract

Run states:

```text
candidate
  -> triaged
  -> planned
  -> prepared
  -> dispatch_ready
  -> lease_not_required | lease_acquire_pending
  -> lease_acquired | lease_unavailable
  -> spawn_pending
  -> spawn_requested | spawn_unknown
  -> dispatched
  -> first_output_waiting
  -> running
  -> child_completed | child_failed | child_skipped | handshake_timeout
  -> aggregation_completed
  -> judge_verifier_completed | judge_verifier_failed
  -> gate_passed | gate_failed | human_review_required
  -> release_pending
  -> finalized | rolled_back
```

Projection events are generated from database rows only after the workflow has entered DB authority. During `file_authority_shadow` and `dual_write_shadow`, projection rows are parity evidence, not authority.

## Mapping and Production Design for the Nine Workflows

Every workflow has an Aggregator -> independent Judge/Verifier -> deterministic Gate path.

| Workflow | Production design | Aggregator | Independent Judge/Verifier | Deterministic Gate |
|---|---|---|---|---|
| Heartbeat | Select at most one actionable candidate or return `HEARTBEAT_OK`. | Candidate selector writes one candidate row. | Verifier checks evidence hash, next action, cadence, and no mutation. | SQL gate permits one open candidate and `risk_dominance <= R1`. |
| Orchestrator-Workers | Domain route, phase plan, single writer, read-only reviewers, no-restart allowLease. | Phase coordinator writes proposal and dispatch rows. | Verifier checks dispatch contract, metadata contract, lease state, first-output handshake, evidence hashes, and changed artifacts. | Gate requires terminal child state, same-run verifier, exact selected-model budget row, released/no-required lease, and projection parity. |
| Executor-Advisor | Executor moves within budget; advisor wakes on risk, uncertainty, budget burn, stall, or goal violation. | Executor writes progress rows. | Advisor is read-only; verifier checks scope and budget. | Gate blocks promotion when advisor trigger is unresolved or risk dominance increased. |
| Trust Ledger | Autonomy derives from scope-specific evidence, not a global toggle. | Trust aggregator groups observations. | Judge binds observation to verifier identity, model/provider/version, gate, usage confidence, and evidence hash. | SQL applies Wilson thresholds, correlation grouping, severity downgrades, and version invalidation. |
| Standing Goals | Declarative predicates on cadence; failures alert and name suspects, never self-repair. | Goal runner writes goal-run rows. | Predicate verifier checks backend, schema hash, sandbox proof, approval, and evidence hash. | Gate rejects unsupported backend, arbitrary shell, sensitive unapproved predicates, and missing sandbox proof. |
| Quorum | Independent low-cost triagers decide whether to wake expensive review; quorum never overrides gates. | Collector stores each vote separately. | Independence verifier checks provider/model/version/prompt/context diversity and correlation grouping. | Gate treats non-independent quorum as one advisory vote. |
| Sparring | Breaker writes failing check; builder fixes; verifier ensures builder did not weaken the check. | Session aggregator records breaker, builder, patch, and evidence. | Verifier compares breaker hash before/after and runs the check. | Gate requires failing-before/passing-after and unchanged-or-approved breaker hash. |
| Compost | Weekly failure/stale-work/goal review proposes at most three mechanism changes. | Compost aggregator ranks guardrail events, failed gates, stale runs, and goal violations. | Judge checks evidence, non-duplication, and Skill Workshop routing for durable skill changes. | Gate caps proposals at three and forbids live apply without explicit human approval. |
| Ratchet | One metric, one change, re-measure, rollback on regression, promote only after proof. | Ratchet runner records baseline, candidate, after-measurement, and rollback path. | Verifier checks same metric definition and comparable environment. | Gate requires baseline/change/after hashes and no Critical/High regression. |

## Transaction Algorithms, Budgets, Retries, and Reconciliation

Prepare:

1. `BEGIN IMMEDIATE`.
2. Insert/fetch `runs` by `prepare_idempotency_key`; duplicate key with a different run identity fails closed.
3. Compute risk dominance from action, target, data, side effect, permission, and irreversibility.
4. Insert `transitions` with action, target type/id/hash/scope, risk dominance, approval fields when required, and the expected state/version guard.
5. Insert `risk_assessments`, selected-model `run_budgets`, evidence hashes, and outbox rows.
6. `COMMIT`.

Budget reserve before external RPC:

1. Select exact provider, model, endpoint/binding id, capability class, and one effective `model_cost_registry` row for the dispatch timestamp; the registry row itself must carry the same endpoint binding id.
2. Persist the selected provider, selected model, endpoint/binding id, capability class, cost-registry row identity, effective timestamp, endpoint-bound row hash, confidence, bounded integer registry prices, and spawn/request transition before RPC.
3. Estimate worst-case or configured input/output/cost/time/human-attention/retry reservation from that exact cost row and endpoint policy. Money is calculated as integer microusd with checked arithmetic; multiplication or aggregation overflow blocks before any external boundary.
4. Start `BEGIN IMMEDIATE`. Insert `budget_events(event_type='reserve')` with non-NULL provider/model/endpoint/cost-row binding, unsigned bounded amount columns, `event_idempotency_key`, `event_dedupe_hash`, bounded per-run `event_sequence`, and `created_at_epoch_ms` from the gate/order authority.
5. In the same transaction, update `run_budgets.reserved_*` with guarded conditional updates, for example `reserved_input_tokens + :n <= input_token_budget` and `reserved_cost_microusd + :n <= cost_budget_microusd`; `changes()`/rowcount must be exactly 1 for every touched dimension. A failed guarded update rolls back the ledger insert and writes no external intent.
6. Retry use is explicit: `retry_decrement` consumes retry budget before the RPC by moving units from reserved retry budget to consumed retry budget; `retry_restore` restores unused retry units only up to prior effective decrements by moving those units back to reserved retry budget. `consume` must have `retry_units=0` and `human_attention_units=0`; `retry_decrement` and `retry_restore` must have every non-retry amount dimension set to zero. Release events reduce outstanding reservation only up to prior effective reservations after prior releases/consumes; outstanding retry reservation is reduced by `release` and by `retry_decrement`, restored by `retry_restore`, and consumed retry authority is derived only from `retry_decrement - retry_restore`. Prefix-sum SLOs must detect over-release, over-restore, retry decrement without reservation, or cross-dimensional retry payloads even if final aggregates happen to look non-negative.
7. A zero input/output/cost reserve is accepted only when the event references an enabled `endpoint_zero_reserve_policies` row for the exact endpoint/capability/hash/effective window, that policy defines at least one positive minimum, and the event satisfies every configured positive minimum for retry, time, and human attention. A disabled, stale, mismatched, all-zero-minima, or partially unsatisfied policy blocks.
8. If reservation exceeds remaining budget, a counter update rowcount is not 1, ledger/counter reconciliation mismatches, an aggregate ledger sum exceeds the selected budget, a release/restore exceeds prior effective amount, duplicate/replayed events exist, any limit/counter/event amount is negative/malformed/out of range, selected endpoint-bound cost row is missing, selected cost row confidence is `unknown`, usage confidence is already `unknown`, or the reservation cannot bind to the exact spawn/request transition, block dispatch to `human_review_required` with no external RPC and no trust promotion.

Human attention accounting and consumption authority use explicit `budget_events(event_type='human_attention')`; only that event type may carry consumed `human_attention_units`, and only that event type may omit model provider/model/cost-row fields because it is pure human-attention. It must carry zero token, cost, time, and retry dimensions. `consume` rows must carry `human_attention_units=0`. Human-attention events still use unsigned bounded amount columns and cannot be used as budget credit.

Acquire lease:

1. Transaction A inserts `external_rpc_intents(rpc_kind='allow_lease_acquire')`, `leases(state='acquire_pending')`, and transition `dispatch_ready -> lease_acquire_pending`.
2. External boundary calls metadata-capable allowLease acquire.
3. Transaction B records `gateway_lease_id`, observed metadata, and transition to `lease_acquired`; failure records `lease_unavailable`.
4. Crash after external success but before Transaction B is auto-repaired only when status exposes exact `client_lease_id` and idempotency metadata. Otherwise write `human_review_required`.

Spawn:

1. Transaction A inserts `spawn_requests(state='pending')`, then `external_rpc_intents(rpc_kind='sessions_spawn')`, and transition to `spawn_pending`. The intent must include `spawn_request_id`, `client_request_id`, `idempotency_key`, `phase`, `agent_id`, and `task_digest` matching the exact `spawn_requests` row, plus `reserve_budget_event_id` pointing to the exact prior reserve event and `requested_at_epoch_ms` strictly greater than the reserve event's `created_at_epoch_ms`.
2. Transaction A commits before the external boundary. External runtime execution is not transactional with SQLite; the only durable ordering proof is the committed reserve row plus committed intent row before the call.
3. External boundary calls metadata-capable `sessions_spawn`.
4. Transaction B records accepted session and transition to `dispatched` only when the accepted runtime session identity is non-empty and consistent across `external_rpc_intents.external_id`, `spawn_requests.session_key`, and one exact `sessions` row bound to the full spawn tuple.
5. Unknown result becomes `spawn_unknown`. The adapter must not retry spawn automatically. Reconciliation may bind only when the external session exposes exact normalized metadata matching `run_id`, `transition_id`, `client_request_id`, `idempotency_key`, `phase`, `agent_id`, and `task_digest`, and the raw `external_metadata_json` paths for those seven fields match the same normalized/local values.
6. Missing `spawn_request_id`, orphan or mismatched spawn request binding, missing accepted session identity, missing exact sessions row, sessions same-row identity mismatch, missing reserve pointer, malformed epoch authority, reserve from the wrong run/transition/provider/model/endpoint/capability/cost row, equal-millisecond ambiguity, reserve created after the intent, NULL/free-form-only/version-only external metadata, invalid external metadata JSON, raw-JSON/normalized/local metadata mismatch, or mismatched external metadata becomes `human_review_required` with no automatic retry or bind.

First-output handshake:

- Child output must echo `run_id`, `phase`, `agent_id`, and `task_digest`.
- DB enters `running` only when the echo and runtime metadata match.
- Timeout records `handshake_timeout`, opens the breaker, and enters compensation/release.

Complete:

- Child completion is persisted before release.
- Evidence hashes are captured, usage is consumed/imported through `budget_events(event_type='consume')` with unsigned non-negative amount columns, and missing usage sets `usage_confidence='unknown'`.
- Unknown usage/cost can finalize only as manual review/degraded trust, never as automated success.

Aggregate, judge, gate:

- Aggregator writes evidence and summary rows.
- Independent Judge/Verifier writes `judge_verifier_runs` with worker run, worker agent, verifier agent/provider/model/version, prompt hash, context hash, evidence hash, and independence proof.
- Deterministic gate begins a transaction, creates a per-gate `gate_clock_context` from a trusted fixtureable clock with unique `clock_context_id`, one-use `gate_nonce`, and exact `bound_at_epoch_ms = now_epoch_ms`, reads approvals and SLO rows by joining the candidate gate's own context, then writes `gate_runs.clock_context_id` and `gate_runs.completed_at_epoch_ms` from that same `now_epoch_ms`.
- A `pass` gate requires a non-NULL `gate_runs.verifier_run_id`, an existing `judge_verifier_runs` row whose `worker_run_id` equals the same `run_id`, and gate-bound evidence whose producer and verifier are both non-NULL and match the same run/verifier.
- A `pass` gate also requires exactly one gate context, exact `gate_run_id`/`run_id`/`transition_id` binding, `bound_at_epoch_ms = now_epoch_ms = consumed_at_epoch_ms = completed_at_epoch_ms`, non-empty `trusted_clock_source_hash`, and no reused nonce or consumed context.
- Same-worker, same-context, missing-verifier, wrong-run verifier, missing producer/verifier evidence, or failed independence proof forces `human_review_required` or `fail`.
- Self-validation cannot raise trust.

Release:

1. Transaction A records `release_pending` and an `external_rpc_intents(rpc_kind='allow_lease_release')`.
2. External boundary calls metadata-capable release.
3. Transaction B marks released only when Gateway status proves matching owned lease is gone.
4. If ownership cannot be proven, wait for TTL or human review.

Reconciliation scanner:

- Scans `lease_acquire_pending`, `spawn_pending`, `spawn_unknown`, `release_pending`, expired leases, terminal runs with active leases, stale outbox rows, budget ambiguity, and projection drift.
- Never mutates runtime config and never restarts Gateway.
- Automatic repair is allowed only for exact metadata matches.
- Missing metadata, corrupted metadata, version-only metadata, raw-JSON/normalized/local metadata mismatch, mismatched normalized metadata, orphan or mismatched `sessions_spawn` request binding, missing accepted session identity, missing exact sessions row, sessions same-row identity mismatch, duplicate candidates, endpoint-unbound selected-model budget ambiguity, missing/malformed/wrong/post-RPC reserve, negative or meaningless budget accounting, ledger/counter mismatch, negative net reservation, consume over budget, retry or human-attention cross-dimensional event payloads, over-release/restore, duplicate/replayed budget event, stale/future/reused/wrong-run/wrong-transition gate clock context, mismatched gate completion time, broad or mismatched approvals, expired or malformed approval expiry authority, pass gates without bound same-run verifier evidence, unknown usage, or unsupported predicate backend become `human_review_required`.

## Predicate Substrate and Standing Goal Safety

Default predicate substrate: `agentic_predicate_inproc_v1`.

`agentic_predicate_inproc_v1` is a declarative audited safe subset:

- Predicates are typed JSON/YAML over whitelisted adapters such as file-exists, file-hash-match, JSON-field comparison, read-only SQL query against `control.db`, command-result reference lookup, and time-window check.
- No dynamic code, no dynamic imports, no `eval`, no `exec`, no subprocess, no shell interpolation, no network, no arbitrary path traversal, no raw environment inheritance, and no writes.
- File reads are mediated by allowlisted adapters and path policies.
- Sensitive adapters for Gateway, Cron, config, credentials, private data, or external systems require approval before first use and after manifest/plugin hash changes.

Optional future substrate: `agentic_predicate_external_sandbox_v1`.

- It may be used only after a named backend proves read-only workspace bindings, denied network, scrubbed environment, fixed cwd, bounded stdout/stderr, bounded timeout, deny-by-default filesystem policy, and emitted `sandbox_proof_json`.
- Unsupported backend, missing sandbox proof, changed plugin hash, or sensitive unapproved predicate means `human_review_required`.
- Existing subprocess-based goal loops are not acceptable automatic Standing Goal predicate backends.

## Security, Privacy, Supply Chain, and Approval Boundaries

Raw operational DB, WAL, SHM, and backup files are private local state. They must not be committed, summarized, retrieved, or packaged by default.

Security rules:

- Redact secret/token/password/API-key patterns before writing projections.
- Store compact summaries, local refs, hashes, and sizes rather than raw logs by default.
- Never paste credentials from config, keychains, service banners, or logs into reports.
- Raw PII or private context must not be sent to cloud models unless the human explicitly approves.
- Evidence hashes are tamper-evident, not tamper-proof; future signing or immutable backup is backlog work.

Approval binding:

- Mutating approvals use non-NULL exact `run_id` plus exact target fields: `target_type`, `target_id`, `target_hash`, and `target_scope`; nullable run/path/hash broad approvals are not valid.
- An approval row must bind exact run id, action type, target tuple, channel, source digest, approval text digest, risk ceiling, `expires_at_epoch_ms`, single-use consumed transition, and consumed gate run.
- The deterministic gate compares the actual transition run id, gate run id, action, target tuple, target hash, channel, source digest, text digest, risk dominance, `expires_at_epoch_ms`, `consumed_by_transition_id`, and `consumed_by_gate_run_id` against exactly one approval row using the candidate gate's own per-gate `gate_clock_context.now_epoch_ms` and one-use nonce context.
- Approval for one run, gate, transition, action, target, hash, channel, source digest, or risk ceiling cannot authorize another.
- Expired by epoch-millisecond authority (`expires_at_epoch_ms <= now_epoch_ms`), malformed/null expiry authority, missing/stale/reused/wrong-run/wrong-gate/wrong-transition gate clock context, mismatched gate completion time, broad, target-mismatched, hash-mismatched, channel-mismatched, source-mismatched, reused, wrong-run, wrong-gate, wrong-transition, or lower-ceiling approval fails closed.
- R3/R4 mutation requires exact approval every time.

Supply-chain boundaries:

- Skills remain pending proposals unless explicitly applied by the human through the approved Skill Workshop lifecycle.
- Predicate plugins and scripts record SHA-256 hashes when used as trust evidence.
- Model/provider/tool/schema changes invalidate affected trust scopes.

## Observability, SLO SQL, Audit, and Lineage

SLO SQL is authoritative only after its DDL exists and each query is versioned by migration hash and query hash. Every SLO query must compile and pass on both empty and fixture DBs before a gate can rely on it.

Example SLO query contracts:

| SLO | Required zero/blocking query |
|---|---|
| Metadata-missing external RPC not auto-repaired | `SELECT intent_id FROM external_rpc_intents WHERE state IN ('pending','unknown','accepted','reconciled') AND run_id NOT IN (SELECT run_id FROM runs WHERE state='human_review_required') AND (metadata_contract_version IS NULL OR metadata_contract_version='' OR external_metadata_json IS NULL OR json_valid(external_metadata_json)=0);` |
| Duplicate live dispatch blocked | `SELECT run_id, phase, agent_id, COUNT(*) FROM spawn_requests WHERE state IN ('accepted','completed') GROUP BY run_id, phase, agent_id HAVING COUNT(*) > 1;` |
| `sessions_spawn` intent without exact spawn request binding | `SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN spawn_requests sr ON sr.spawn_request_id=eri.spawn_request_id AND sr.run_id=eri.run_id AND sr.transition_id=eri.transition_id AND sr.client_request_id=eri.client_request_id AND sr.spawn_idempotency_key=eri.idempotency_key AND sr.phase=eri.phase AND sr.agent_id=eri.agent_id AND sr.task_digest=eri.task_digest WHERE eri.rpc_kind='sessions_spawn' AND (eri.spawn_request_id IS NULL OR eri.phase IS NULL OR eri.phase='' OR eri.agent_id IS NULL OR eri.agent_id='' OR eri.task_digest IS NULL OR eri.task_digest='' OR sr.spawn_request_id IS NULL);` |
| `sessions_spawn` external metadata exact match | `SELECT intent_id FROM external_rpc_intents WHERE rpc_kind='sessions_spawn' AND state IN ('pending','accepted','unknown','reconciled') AND CASE WHEN metadata_contract_version IS NULL OR metadata_contract_version='' OR external_metadata_json IS NULL OR json_valid(external_metadata_json)=0 THEN 1 WHEN json_type(external_metadata_json,'$.run_id') IS NOT 'text' OR json_type(external_metadata_json,'$.transition_id') IS NOT 'text' OR json_type(external_metadata_json,'$.client_request_id') IS NOT 'text' OR json_type(external_metadata_json,'$.idempotency_key') IS NOT 'text' OR json_type(external_metadata_json,'$.phase') IS NOT 'text' OR json_type(external_metadata_json,'$.agent_id') IS NOT 'text' OR json_type(external_metadata_json,'$.task_digest') IS NOT 'text' OR json_extract(external_metadata_json,'$.run_id') IS NOT run_id OR json_extract(external_metadata_json,'$.transition_id') IS NOT transition_id OR json_extract(external_metadata_json,'$.client_request_id') IS NOT client_request_id OR json_extract(external_metadata_json,'$.idempotency_key') IS NOT idempotency_key OR json_extract(external_metadata_json,'$.phase') IS NOT phase OR json_extract(external_metadata_json,'$.agent_id') IS NOT agent_id OR json_extract(external_metadata_json,'$.task_digest') IS NOT task_digest OR external_run_id IS NOT run_id OR external_transition_id IS NOT transition_id OR external_client_request_id IS NOT client_request_id OR external_idempotency_key IS NOT idempotency_key OR external_phase IS NOT phase OR external_agent_id IS NOT agent_id OR external_task_digest IS NOT task_digest OR (state IN ('accepted','reconciled') AND (external_id IS NULL OR external_id='')) THEN 1 ELSE 0 END;` |
| Accepted `sessions_spawn` without exact accepted session identity | `SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN spawn_requests sr ON sr.spawn_request_id=eri.spawn_request_id AND sr.run_id=eri.run_id AND sr.transition_id=eri.transition_id AND sr.client_request_id=eri.client_request_id AND sr.spawn_idempotency_key=eri.idempotency_key AND sr.phase=eri.phase AND sr.agent_id=eri.agent_id AND sr.task_digest=eri.task_digest LEFT JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id AND s.client_request_id=sr.client_request_id AND s.spawn_idempotency_key=sr.spawn_idempotency_key AND s.phase=sr.phase AND s.agent_id=sr.agent_id AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key AND s.session_key=eri.external_id WHERE eri.rpc_kind='sessions_spawn' AND eri.state IN ('accepted','reconciled') AND (eri.external_id IS NULL OR eri.external_id='' OR sr.spawn_request_id IS NULL OR sr.state NOT IN ('accepted','completed') OR sr.session_key IS NULL OR sr.session_key='' OR sr.session_key<>eri.external_id OR s.session_id IS NULL) UNION SELECT be.budget_event_id FROM budget_events be LEFT JOIN spawn_requests sr ON sr.spawn_request_id=be.spawn_request_id AND sr.run_id=be.run_id AND sr.transition_id=be.transition_id LEFT JOIN external_rpc_intents eri ON eri.rpc_kind='sessions_spawn' AND eri.state IN ('accepted','reconciled') AND eri.spawn_request_id=sr.spawn_request_id AND eri.run_id=sr.run_id AND eri.transition_id=sr.transition_id AND eri.client_request_id=sr.client_request_id AND eri.idempotency_key=sr.spawn_idempotency_key AND eri.phase=sr.phase AND eri.agent_id=sr.agent_id AND eri.task_digest=sr.task_digest AND eri.external_id=sr.session_key LEFT JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id AND s.client_request_id=sr.client_request_id AND s.spawn_idempotency_key=sr.spawn_idempotency_key AND s.phase=sr.phase AND s.agent_id=sr.agent_id AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key AND s.session_key=eri.external_id LEFT JOIN gate_clock_context c ON c.clock_context_id=be.clock_context_id AND c.run_id=be.run_id AND c.transition_id=be.transition_id LEFT JOIN gate_runs g ON g.gate_run_id=c.gate_run_id AND g.clock_context_id=c.clock_context_id AND g.run_id=c.run_id AND g.transition_id=c.transition_id LEFT JOIN run_budgets rb ON rb.run_id=be.run_id WHERE be.event_type IN ('consume','retry_decrement','retry_restore','human_attention') AND (be.spawn_request_id IS NULL OR sr.spawn_request_id IS NULL OR sr.state NOT IN ('accepted','completed') OR sr.session_key IS NULL OR sr.session_key='' OR eri.intent_id IS NULL OR eri.external_id IS NULL OR eri.external_id='' OR typeof(eri.accepted_at_epoch_ms)<>'integer' OR eri.accepted_at_epoch_ms<1 OR eri.accepted_at_epoch_ms>253402300799999 OR typeof(eri.requested_at_epoch_ms)<>'integer' OR eri.requested_at_epoch_ms<1 OR eri.requested_at_epoch_ms>253402300799999 OR eri.accepted_at_epoch_ms<=eri.requested_at_epoch_ms OR typeof(be.created_at_epoch_ms)<>'integer' OR be.created_at_epoch_ms<1 OR be.created_at_epoch_ms>253402300799999 OR be.created_at_epoch_ms<=eri.accepted_at_epoch_ms OR be.created_at_epoch_ms<=eri.requested_at_epoch_ms OR be.clock_context_id IS NULL OR be.clock_context_id='' OR c.clock_context_id IS NULL OR c.gate_run_id IS NULL OR c.consumed_by_gate_run_id IS NULL OR c.consumed_by_gate_run_id IS NOT c.gate_run_id OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR typeof(c.bound_at_epoch_ms)<>'integer' OR c.bound_at_epoch_ms<1 OR c.bound_at_epoch_ms>253402300799999 OR c.bound_at_epoch_ms IS NOT c.now_epoch_ms OR typeof(c.consumed_at_epoch_ms)<>'integer' OR c.consumed_at_epoch_ms<1 OR c.consumed_at_epoch_ms>253402300799999 OR c.consumed_at_epoch_ms IS NOT c.now_epoch_ms OR c.trusted_clock_source_hash IS NULL OR c.trusted_clock_source_hash='' OR c.gate_nonce IS NULL OR c.gate_nonce='' OR g.gate_run_id IS NULL OR g.decision<>'pass' OR typeof(g.completed_at_epoch_ms)<>'integer' OR g.completed_at_epoch_ms<1 OR g.completed_at_epoch_ms>253402300799999 OR g.completed_at_epoch_ms IS NOT c.now_epoch_ms OR be.created_at_epoch_ms IS NOT c.now_epoch_ms OR rb.run_id IS NULL OR be.provider IS NOT rb.selected_provider OR be.model IS NOT rb.selected_model OR be.endpoint_binding_id IS NOT rb.selected_endpoint_binding_id OR be.capability_class IS NOT rb.capability_class OR be.cost_registry_id IS NOT rb.selected_cost_registry_id OR be.cost_effective_at IS NOT rb.selected_cost_effective_at OR be.cost_registry_hash IS NOT rb.selected_cost_registry_hash OR be.cost_confidence IS NOT rb.selected_cost_confidence OR be.transition_id IS NOT rb.selected_reserve_transition_id OR s.session_id IS NULL OR (be.event_type='consume' AND (sr.state<>'completed' OR s.state<>'completed' OR s.completed_at IS NULL OR s.completed_at='')))` |
| `sessions` row without exact spawn request same-row binding | `SELECT s.session_id FROM sessions s LEFT JOIN spawn_requests sr ON sr.spawn_request_id=s.spawn_request_id AND sr.run_id=s.run_id AND sr.transition_id=s.transition_id AND sr.client_request_id=s.client_request_id AND sr.spawn_idempotency_key=s.spawn_idempotency_key AND sr.phase=s.phase AND sr.agent_id=s.agent_id AND sr.task_digest=s.task_digest AND sr.session_key=s.session_key WHERE sr.spawn_request_id IS NULL OR s.session_key IS NULL OR s.session_key='';` |
| Lease leak after terminal state | `SELECT l.lease_id FROM leases l JOIN runs r USING(run_id) WHERE r.state IN ('finalized','rolled_back','rejected') AND l.state NOT IN ('released','release_not_required');` |
| Unknown usage blocks auto-local | `SELECT rb.run_id FROM run_budgets rb JOIN runs r ON r.run_id=rb.run_id WHERE r.state IN ('gate_passed','release_pending','finalized') AND rb.usage_confidence='unknown' UNION SELECT be.run_id FROM budget_events be JOIN runs r ON r.run_id=be.run_id WHERE r.state IN ('gate_passed','release_pending','finalized') AND be.usage_confidence='unknown';` |
| Model cost registry numeric bounds | `SELECT cost_registry_id FROM model_cost_registry WHERE typeof(input_cost_microusd_per_million)<>'integer' OR input_cost_microusd_per_million<0 OR input_cost_microusd_per_million>100000000000 OR typeof(output_cost_microusd_per_million)<>'integer' OR output_cost_microusd_per_million<0 OR output_cost_microusd_per_million>100000000000 OR provider='' OR model='' OR endpoint_binding_id='' OR capability_class='' OR confidence='unknown';` |
| Endpoint-bound budget event cost row blocks dispatch | `SELECT be.budget_event_id FROM budget_events be LEFT JOIN model_cost_registry m ON m.cost_registry_id=be.cost_registry_id AND m.provider=be.provider AND m.model=be.model AND m.endpoint_binding_id=be.endpoint_binding_id AND m.capability_class=be.capability_class AND m.effective_at=be.cost_effective_at AND m.registry_row_hash=be.cost_registry_hash WHERE be.event_type<>'human_attention' AND (be.provider IS NULL OR be.provider='' OR be.model IS NULL OR be.model='' OR be.endpoint_binding_id IS NULL OR be.endpoint_binding_id='' OR be.cost_registry_id IS NULL OR be.cost_registry_id='' OR be.cost_effective_at IS NULL OR be.cost_effective_at='' OR be.cost_registry_hash IS NULL OR be.cost_registry_hash='' OR m.cost_registry_id IS NULL OR m.confidence='unknown' OR be.cost_confidence IS NULL OR be.cost_confidence='unknown' OR be.cost_confidence<>m.confidence);` |
| Run budget selected cost row mismatch | `SELECT rb.run_id FROM run_budgets rb LEFT JOIN model_cost_registry m ON m.cost_registry_id=rb.selected_cost_registry_id WHERE m.cost_registry_id IS NULL OR rb.selected_provider<>m.provider OR rb.selected_model<>m.model OR rb.selected_endpoint_binding_id<>m.endpoint_binding_id OR rb.capability_class<>m.capability_class OR rb.selected_cost_effective_at<>m.effective_at OR rb.selected_cost_registry_hash<>m.registry_row_hash OR rb.selected_cost_confidence<>m.confidence OR m.confidence='unknown' OR typeof(m.input_cost_microusd_per_million)<>'integer' OR typeof(m.output_cost_microusd_per_million)<>'integer';` |
| `sessions_spawn` intent without exact strict prior reserve | `SELECT eri.intent_id FROM external_rpc_intents eri LEFT JOIN run_budgets rb ON rb.run_id=eri.run_id LEFT JOIN budget_events be ON be.budget_event_id=eri.reserve_budget_event_id LEFT JOIN model_cost_registry m ON m.cost_registry_id=be.cost_registry_id AND m.provider=be.provider AND m.model=be.model AND m.endpoint_binding_id=be.endpoint_binding_id AND m.capability_class=be.capability_class AND m.effective_at=be.cost_effective_at AND m.registry_row_hash=be.cost_registry_hash WHERE eri.rpc_kind='sessions_spawn' AND (rb.run_id IS NULL OR eri.reserve_budget_event_id IS NULL OR be.budget_event_id IS NULL OR be.run_id IS NOT eri.run_id OR be.transition_id IS NOT eri.transition_id OR be.spawn_request_id IS NOT eri.spawn_request_id OR be.event_type<>'reserve' OR be.provider IS NOT rb.selected_provider OR be.model IS NOT rb.selected_model OR be.endpoint_binding_id IS NOT rb.selected_endpoint_binding_id OR be.capability_class IS NOT rb.capability_class OR be.cost_registry_id IS NOT rb.selected_cost_registry_id OR be.cost_effective_at IS NOT rb.selected_cost_effective_at OR be.cost_registry_hash IS NOT rb.selected_cost_registry_hash OR be.cost_confidence IS NOT rb.selected_cost_confidence OR typeof(be.created_at_epoch_ms)<>'integer' OR be.created_at_epoch_ms<1 OR be.created_at_epoch_ms>253402300799999 OR typeof(eri.requested_at_epoch_ms)<>'integer' OR eri.requested_at_epoch_ms<1 OR eri.requested_at_epoch_ms>253402300799999 OR be.created_at_epoch_ms>=eri.requested_at_epoch_ms OR m.cost_registry_id IS NULL OR m.confidence='unknown' OR be.cost_confidence IS NULL OR be.cost_confidence='unknown' OR be.cost_confidence<>m.confidence);` |
| Invalid zero-reserve policy | `SELECT zero_reserve_policy_id FROM endpoint_zero_reserve_policies WHERE typeof(enabled)<>'integer' OR enabled NOT IN (0,1) OR typeof(min_retry_units)<>'integer' OR min_retry_units<0 OR min_retry_units>1000000 OR typeof(min_time_seconds)<>'integer' OR min_time_seconds<0 OR min_time_seconds>31536000 OR typeof(min_human_attention_units)<>'integer' OR min_human_attention_units<0 OR min_human_attention_units>1000000 OR typeof(effective_from_epoch_ms)<>'integer' OR effective_from_epoch_ms<1 OR effective_from_epoch_ms>253402300799999 OR (effective_until_epoch_ms IS NOT NULL AND (typeof(effective_until_epoch_ms)<>'integer' OR effective_until_epoch_ms<=effective_from_epoch_ms OR effective_until_epoch_ms>253402300799999)) OR (enabled=1 AND min_retry_units<=0 AND min_time_seconds<=0 AND min_human_attention_units<=0);` |
| Meaningless `sessions_spawn` reserve | `SELECT eri.intent_id FROM external_rpc_intents eri JOIN budget_events be ON be.budget_event_id=eri.reserve_budget_event_id LEFT JOIN endpoint_zero_reserve_policies zp ON zp.zero_reserve_policy_id=be.zero_reserve_policy_id WHERE eri.rpc_kind='sessions_spawn' AND be.event_type='reserve' AND ((be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.zero_reserve_policy_id IS NULL) OR (be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.time_seconds=0 AND be.human_attention_units=0 AND be.retry_units=0) OR (be.zero_reserve_policy_id IS NOT NULL AND (zp.zero_reserve_policy_id IS NULL OR zp.enabled<>1 OR zp.endpoint_binding_id<>be.endpoint_binding_id OR zp.capability_class<>be.capability_class OR zp.policy_hash<>be.zero_reserve_policy_hash OR be.created_at_epoch_ms<zp.effective_from_epoch_ms OR (zp.effective_until_epoch_ms IS NOT NULL AND be.created_at_epoch_ms>=zp.effective_until_epoch_ms) OR (zp.min_retry_units<=0 AND zp.min_time_seconds<=0 AND zp.min_human_attention_units<=0) OR (zp.min_retry_units>0 AND be.retry_units<zp.min_retry_units) OR (zp.min_time_seconds>0 AND be.time_seconds<zp.min_time_seconds) OR (zp.min_human_attention_units>0 AND be.human_attention_units<zp.min_human_attention_units))));` |
| Budget event amount malformed or out of range | `SELECT budget_event_id FROM budget_events WHERE typeof(event_sequence)<>'integer' OR event_sequence<1 OR event_sequence>1000000 OR typeof(created_at_epoch_ms)<>'integer' OR created_at_epoch_ms<1 OR created_at_epoch_ms>253402300799999 OR typeof(time_seconds)<>'integer' OR time_seconds<0 OR time_seconds>31536000 OR typeof(input_tokens)<>'integer' OR input_tokens<0 OR input_tokens>1000000000 OR typeof(output_tokens)<>'integer' OR output_tokens<0 OR output_tokens>1000000000 OR typeof(cost_microusd)<>'integer' OR cost_microusd<0 OR cost_microusd>100000000000 OR typeof(human_attention_units)<>'integer' OR human_attention_units<0 OR human_attention_units>1000000 OR typeof(retry_units)<>'integer' OR retry_units<0 OR retry_units>1000000 OR (event_type='consume' AND (retry_units<>0 OR human_attention_units<>0)) OR (event_type='human_attention' AND (time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR retry_units<>0 OR human_attention_units<=0)) OR (event_type='retry_decrement' AND (retry_units=0 OR time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR human_attention_units<>0)) OR (event_type='retry_restore' AND (retry_units=0 OR time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0 OR human_attention_units<>0)) OR (event_type='consume' AND usage_confidence='unknown' AND (time_seconds<>0 OR input_tokens<>0 OR output_tokens<>0 OR cost_microusd<>0)) OR (event_type='consume' AND usage_confidence IN ('known','estimated') AND time_seconds=0 AND input_tokens=0 AND output_tokens=0 AND cost_microusd=0) UNION ALL SELECT bs.settlement_id FROM budget_settlements bs WHERE ((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume')) OR ((bs.actual_time_seconds>0 OR bs.actual_input_tokens>0 OR bs.actual_output_tokens>0 OR bs.actual_cost_microusd>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='consume' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=bs.actual_time_seconds AND be.input_tokens=bs.actual_input_tokens AND be.output_tokens=bs.actual_output_tokens AND be.cost_microusd=bs.actual_cost_microusd AND be.retry_units=0 AND be.human_attention_units=0)) OR ((bs.actual_retry_units>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='retry_decrement')) OR ((bs.actual_retry_units>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='retry_decrement' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=0 AND be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.retry_units=bs.actual_retry_units AND be.human_attention_units=0)) OR ((bs.actual_human_attention_units>0) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='human_attention')) OR ((bs.actual_human_attention_units>0) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='human_attention' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=0 AND be.input_tokens=0 AND be.output_tokens=0 AND be.cost_microusd=0 AND be.retry_units=0 AND be.human_attention_units=bs.actual_human_attention_units)) OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 OR bs.released_retry_units>0 OR bs.released_human_attention_units>0 OR (bs.actual_time_seconds=0 AND bs.actual_input_tokens=0 AND bs.actual_output_tokens=0 AND bs.actual_cost_microusd=0 AND bs.actual_retry_units=0 AND bs.actual_human_attention_units=0 AND bs.released_time_seconds=0 AND bs.released_input_tokens=0 AND bs.released_output_tokens=0 AND bs.released_cost_microusd=0 AND bs.released_retry_units=0 AND bs.released_human_attention_units=0)) IS NOT (SELECT COUNT(*)=1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='release')) OR ((bs.released_time_seconds>0 OR bs.released_input_tokens>0 OR bs.released_output_tokens>0 OR bs.released_cost_microusd>0 OR bs.released_retry_units>0 OR bs.released_human_attention_units>0 OR (bs.actual_time_seconds=0 AND bs.actual_input_tokens=0 AND bs.actual_output_tokens=0 AND bs.actual_cost_microusd=0 AND bs.actual_retry_units=0 AND bs.actual_human_attention_units=0 AND bs.released_time_seconds=0 AND bs.released_input_tokens=0 AND bs.released_output_tokens=0 AND bs.released_cost_microusd=0 AND bs.released_retry_units=0 AND bs.released_human_attention_units=0)) AND NOT EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type='release' AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.provider=bs.provider AND be.model=bs.model AND be.endpoint_binding_id=bs.endpoint_binding_id AND be.capability_class=bs.capability_class AND be.cost_registry_id=bs.cost_registry_id AND be.cost_effective_at=bs.cost_effective_at AND be.cost_registry_hash=bs.cost_registry_hash AND be.cost_confidence=bs.cost_confidence AND be.usage_confidence=bs.usage_confidence AND be.source=bs.source AND be.created_at=bs.created_at AND be.created_at_epoch_ms=bs.created_at_epoch_ms AND be.clock_context_id=bs.clock_context_id AND be.time_seconds=bs.released_time_seconds AND be.input_tokens=bs.released_input_tokens AND be.output_tokens=bs.released_output_tokens AND be.cost_microusd=bs.released_cost_microusd AND be.retry_units=bs.released_retry_units AND be.human_attention_units=bs.released_human_attention_units)) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id=bs.settlement_id AND be.event_type NOT IN ('consume','retry_decrement','human_attention','release')) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.event_dedupe_hash=bs.settlement_dedupe_hash) OR EXISTS (SELECT 1 FROM budget_events be WHERE be.settlement_id IS NULL AND be.run_id=bs.run_id AND be.transition_id=bs.transition_id AND be.spawn_request_id=bs.spawn_request_id AND be.event_type IN ('reserve','consume','release','retry_decrement','retry_restore','human_attention') AND be.event_sequence>(SELECT COALESCE(MAX(linked.event_sequence),0) FROM budget_events linked WHERE linked.settlement_id=bs.settlement_id)) OR NOT EXISTS (SELECT 1 FROM spawn_requests sr JOIN runs r ON r.run_id=sr.run_id JOIN sessions s ON s.spawn_request_id=sr.spawn_request_id AND s.run_id=sr.run_id AND s.transition_id=sr.transition_id AND s.client_request_id=sr.client_request_id AND s.spawn_idempotency_key=sr.spawn_idempotency_key AND s.phase=sr.phase AND s.agent_id=sr.agent_id AND s.task_digest=sr.task_digest AND s.session_key=sr.session_key JOIN external_rpc_intents i ON i.rpc_kind='sessions_spawn' AND i.state IN ('accepted','reconciled') AND i.spawn_request_id=sr.spawn_request_id AND i.run_id=sr.run_id AND i.transition_id=sr.transition_id AND i.client_request_id=sr.client_request_id AND i.idempotency_key=sr.spawn_idempotency_key AND i.phase=sr.phase AND i.agent_id=sr.agent_id AND i.task_digest=sr.task_digest AND i.external_id=sr.session_key JOIN run_budgets rb ON rb.run_id=sr.run_id JOIN gate_clock_context c ON c.clock_context_id=bs.clock_context_id AND c.run_id=sr.run_id AND c.transition_id=sr.transition_id JOIN gate_runs g ON g.gate_run_id=c.gate_run_id AND g.clock_context_id=c.clock_context_id AND g.run_id=c.run_id AND g.transition_id=c.transition_id WHERE sr.spawn_request_id=bs.spawn_request_id AND sr.run_id=bs.run_id AND sr.transition_id=bs.transition_id AND sr.state='completed' AND s.state='completed' AND s.completed_at IS NOT NULL AND s.completed_at<>'' AND r.state IN ('child_completed','child_failed','aggregation_completed','gate_passed','release_pending','finalized') AND rb.selected_reserve_transition_id=bs.transition_id AND rb.selected_provider=bs.provider AND rb.selected_model=bs.model AND rb.selected_endpoint_binding_id=bs.endpoint_binding_id AND rb.capability_class=bs.capability_class AND rb.selected_cost_registry_id=bs.cost_registry_id AND rb.selected_cost_effective_at=bs.cost_effective_at AND rb.selected_cost_registry_hash=bs.cost_registry_hash AND rb.selected_cost_confidence=bs.cost_confidence AND rb.usage_confidence IN ('known','estimated') AND i.requested_at_epoch_ms<i.accepted_at_epoch_ms AND i.accepted_at_epoch_ms<bs.created_at_epoch_ms AND c.gate_run_id=c.consumed_by_gate_run_id AND c.bound_at_epoch_ms=c.now_epoch_ms AND c.consumed_at_epoch_ms=c.now_epoch_ms AND c.now_epoch_ms=bs.created_at_epoch_ms AND c.trusted_clock_source_hash<>'' AND c.gate_nonce<>'' AND g.decision='pass' AND g.completed_at_epoch_ms=c.now_epoch_ms);` |
| Budget counters outside selected budget | `SELECT run_id FROM run_budgets WHERE typeof(time_budget_seconds)<>'integer' OR time_budget_seconds<0 OR time_budget_seconds>31536000 OR typeof(input_token_budget)<>'integer' OR input_token_budget<0 OR input_token_budget>1000000000 OR typeof(output_token_budget)<>'integer' OR output_token_budget<0 OR output_token_budget>1000000000 OR typeof(cost_budget_microusd)<>'integer' OR cost_budget_microusd<0 OR cost_budget_microusd>100000000000 OR typeof(retry_budget)<>'integer' OR retry_budget<0 OR retry_budget>1000000 OR typeof(human_attention_budget)<>'integer' OR human_attention_budget<0 OR human_attention_budget>1000000 OR typeof(reserved_time_seconds)<>'integer' OR reserved_time_seconds<0 OR reserved_time_seconds>time_budget_seconds OR typeof(reserved_input_tokens)<>'integer' OR reserved_input_tokens<0 OR reserved_input_tokens>input_token_budget OR typeof(reserved_output_tokens)<>'integer' OR reserved_output_tokens<0 OR reserved_output_tokens>output_token_budget OR typeof(reserved_cost_microusd)<>'integer' OR reserved_cost_microusd<0 OR reserved_cost_microusd>cost_budget_microusd OR typeof(reserved_retries)<>'integer' OR reserved_retries<0 OR reserved_retries>retry_budget OR typeof(reserved_human_attention)<>'integer' OR reserved_human_attention<0 OR reserved_human_attention>human_attention_budget OR typeof(consumed_time_seconds)<>'integer' OR consumed_time_seconds<0 OR consumed_time_seconds>time_budget_seconds OR typeof(consumed_input_tokens)<>'integer' OR consumed_input_tokens<0 OR consumed_input_tokens>input_token_budget OR typeof(consumed_output_tokens)<>'integer' OR consumed_output_tokens<0 OR consumed_output_tokens>output_token_budget OR typeof(consumed_cost_microusd)<>'integer' OR consumed_cost_microusd<0 OR consumed_cost_microusd>cost_budget_microusd OR typeof(consumed_retries)<>'integer' OR consumed_retries<0 OR consumed_retries>retry_budget OR typeof(consumed_human_attention)<>'integer' OR consumed_human_attention<0 OR consumed_human_attention>human_attention_budget OR reserved_time_seconds+consumed_time_seconds>time_budget_seconds OR reserved_input_tokens+consumed_input_tokens>input_token_budget OR reserved_output_tokens+consumed_output_tokens>output_token_budget OR reserved_cost_microusd+consumed_cost_microusd>cost_budget_microusd OR reserved_retries+consumed_retries>retry_budget OR reserved_human_attention+consumed_human_attention>human_attention_budget;` |
| Budget ledger reconciles to counters and budgets | `WITH event_sums AS (SELECT run_id, SUM(CASE WHEN event_type='reserve' THEN time_seconds WHEN event_type IN ('release','consume') THEN -time_seconds ELSE 0 END) AS net_reserved_time, SUM(CASE WHEN event_type='reserve' THEN input_tokens WHEN event_type IN ('release','consume') THEN -input_tokens ELSE 0 END) AS net_reserved_input, SUM(CASE WHEN event_type='reserve' THEN output_tokens WHEN event_type IN ('release','consume') THEN -output_tokens ELSE 0 END) AS net_reserved_output, SUM(CASE WHEN event_type='reserve' THEN cost_microusd WHEN event_type IN ('release','consume') THEN -cost_microusd ELSE 0 END) AS net_reserved_cost, SUM(CASE WHEN event_type='reserve' THEN retry_units WHEN event_type IN ('release','retry_decrement') THEN -retry_units WHEN event_type='retry_restore' THEN retry_units ELSE 0 END) AS net_reserved_retries, SUM(CASE WHEN event_type='reserve' THEN human_attention_units WHEN event_type IN ('release','human_attention') THEN -human_attention_units ELSE 0 END) AS net_reserved_human, SUM(CASE WHEN event_type='consume' THEN time_seconds ELSE 0 END) AS consumed_time, SUM(CASE WHEN event_type='consume' THEN input_tokens ELSE 0 END) AS consumed_input, SUM(CASE WHEN event_type='consume' THEN output_tokens ELSE 0 END) AS consumed_output, SUM(CASE WHEN event_type='consume' THEN cost_microusd ELSE 0 END) AS consumed_cost, SUM(CASE WHEN event_type='retry_decrement' THEN retry_units WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END) AS consumed_retries, SUM(CASE WHEN event_type='human_attention' THEN human_attention_units ELSE 0 END) AS consumed_human FROM budget_events GROUP BY run_id), missing_budgets AS (SELECT DISTINCT be.run_id FROM budget_events be LEFT JOIN run_budgets rb ON rb.run_id=be.run_id WHERE rb.run_id IS NULL) SELECT run_id FROM missing_budgets UNION SELECT rb.run_id FROM run_budgets rb LEFT JOIN event_sums s USING(run_id) WHERE COALESCE(s.net_reserved_time,0)<0 OR COALESCE(s.net_reserved_input,0)<0 OR COALESCE(s.net_reserved_output,0)<0 OR COALESCE(s.net_reserved_cost,0)<0 OR COALESCE(s.net_reserved_retries,0)<0 OR COALESCE(s.net_reserved_human,0)<0 OR (COALESCE(s.net_reserved_time,0)>=0 AND COALESCE(s.net_reserved_time,0)<>rb.reserved_time_seconds) OR (COALESCE(s.net_reserved_input,0)>=0 AND COALESCE(s.net_reserved_input,0)<>rb.reserved_input_tokens) OR (COALESCE(s.net_reserved_output,0)>=0 AND COALESCE(s.net_reserved_output,0)<>rb.reserved_output_tokens) OR (COALESCE(s.net_reserved_cost,0)>=0 AND COALESCE(s.net_reserved_cost,0)<>rb.reserved_cost_microusd) OR (COALESCE(s.net_reserved_retries,0)>=0 AND COALESCE(s.net_reserved_retries,0)<>rb.reserved_retries) OR (COALESCE(s.net_reserved_human,0)>=0 AND COALESCE(s.net_reserved_human,0)<>rb.reserved_human_attention) OR COALESCE(s.consumed_time,0)<>rb.consumed_time_seconds OR COALESCE(s.consumed_input,0)<>rb.consumed_input_tokens OR COALESCE(s.consumed_output,0)<>rb.consumed_output_tokens OR COALESCE(s.consumed_cost,0)<>rb.consumed_cost_microusd OR COALESCE(s.consumed_retries,0)<>rb.consumed_retries OR COALESCE(s.consumed_human,0)<>rb.consumed_human_attention OR COALESCE(s.net_reserved_time,0)>rb.time_budget_seconds OR COALESCE(s.net_reserved_input,0)>rb.input_token_budget OR COALESCE(s.net_reserved_output,0)>rb.output_token_budget OR COALESCE(s.net_reserved_cost,0)>rb.cost_budget_microusd OR COALESCE(s.net_reserved_retries,0)>rb.retry_budget OR COALESCE(s.net_reserved_human,0)>rb.human_attention_budget OR COALESCE(s.consumed_time,0)>rb.time_budget_seconds OR COALESCE(s.consumed_input,0)>rb.input_token_budget OR COALESCE(s.consumed_output,0)>rb.output_token_budget OR COALESCE(s.consumed_cost,0)>rb.cost_budget_microusd OR COALESCE(s.consumed_retries,0)>rb.retry_budget OR COALESCE(s.consumed_human,0)>rb.human_attention_budget OR COALESCE(s.net_reserved_time,0)+COALESCE(s.consumed_time,0)>rb.time_budget_seconds OR COALESCE(s.net_reserved_input,0)+COALESCE(s.consumed_input,0)>rb.input_token_budget OR COALESCE(s.net_reserved_output,0)+COALESCE(s.consumed_output,0)>rb.output_token_budget OR COALESCE(s.net_reserved_cost,0)+COALESCE(s.consumed_cost,0)>rb.cost_budget_microusd OR COALESCE(s.net_reserved_retries,0)+COALESCE(s.consumed_retries,0)>rb.retry_budget OR COALESCE(s.net_reserved_human,0)+COALESCE(s.consumed_human,0)>rb.human_attention_budget;` |
| Budget prefix over-release or over-restore | `WITH ordered AS (SELECT budget_event_id, run_id, event_sequence, SUM(CASE WHEN event_type='reserve' THEN time_seconds WHEN event_type IN ('release','consume') THEN -time_seconds ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_time, SUM(CASE WHEN event_type='reserve' THEN input_tokens WHEN event_type IN ('release','consume') THEN -input_tokens ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_input, SUM(CASE WHEN event_type='reserve' THEN output_tokens WHEN event_type IN ('release','consume') THEN -output_tokens ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_output, SUM(CASE WHEN event_type='reserve' THEN cost_microusd WHEN event_type IN ('release','consume') THEN -cost_microusd ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_cost, SUM(CASE WHEN event_type='reserve' THEN retry_units WHEN event_type IN ('release','retry_decrement') THEN -retry_units WHEN event_type='retry_restore' THEN retry_units ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_reserved_retry, SUM(CASE WHEN event_type='retry_decrement' THEN retry_units WHEN event_type='retry_restore' THEN -retry_units ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_retry_consumed, SUM(CASE WHEN event_type='reserve' THEN human_attention_units WHEN event_type IN ('release','human_attention') THEN -human_attention_units ELSE 0 END) OVER (PARTITION BY run_id,transition_id,spawn_request_id,capability_class ORDER BY event_sequence) AS net_human FROM budget_events) SELECT o.budget_event_id FROM ordered o LEFT JOIN run_budgets rb ON rb.run_id=o.run_id WHERE rb.run_id IS NULL OR o.net_time<0 OR o.net_input<0 OR o.net_output<0 OR o.net_cost<0 OR o.net_reserved_retry<0 OR o.net_retry_consumed<0 OR o.net_human<0 OR o.net_time>rb.time_budget_seconds OR o.net_input>rb.input_token_budget OR o.net_output>rb.output_token_budget OR o.net_cost>rb.cost_budget_microusd OR o.net_reserved_retry>rb.retry_budget OR o.net_retry_consumed>rb.retry_budget OR o.net_human>rb.human_attention_budget;` |
| Duplicate or replayed budget events | `SELECT event_dedupe_hash FROM budget_events GROUP BY event_dedupe_hash HAVING COUNT(*)>1;` |
| Budget event count bounded for SUM safety | `SELECT run_id FROM budget_events GROUP BY run_id HAVING COUNT(*)>1000000 OR MIN(event_sequence)<1 OR MAX(event_sequence)>1000000;` |
| Completion gate before done for R2+ | `SELECT r.run_id FROM runs r WHERE r.risk_dominance IN ('R2','R3','R4') AND r.state='finalized' AND (r.finalized_at IS NULL OR r.finalized_at='' OR r.finalized_at_epoch_ms IS NULL OR typeof(r.finalized_at_epoch_ms)<>'integer' OR r.finalized_at_epoch_ms<1 OR r.finalized_at_epoch_ms>253402300799999 OR NOT EXISTS (SELECT 1 FROM transitions t JOIN gate_runs g ON g.run_id=t.run_id AND g.transition_id=t.transition_id AND g.decision='pass' WHERE t.run_id=r.run_id AND t.state_after='finalized' AND g.completed_at_epoch_ms IS NOT NULL AND typeof(g.completed_at_epoch_ms)='integer' AND g.completed_at_epoch_ms BETWEEN 1 AND 253402300799999 AND g.completed_at_epoch_ms <= r.finalized_at_epoch_ms));` |
| Passing gate without verifier row | `SELECT g.gate_run_id FROM gate_runs g LEFT JOIN judge_verifier_runs v ON v.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND (g.verifier_run_id IS NULL OR v.verifier_run_id IS NULL);` |
| Passing gate wrong-run or non-independent verifier | `SELECT g.gate_run_id FROM gate_runs g JOIN judge_verifier_runs v ON v.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND (v.worker_run_id<>g.run_id OR v.same_worker_context=1 OR v.verifier_agent_id=v.worker_agent_id OR v.prompt_hash=v.context_hash OR v.independence_class IN ('self','same_worker','same_context','correlated','unknown') OR json_valid(v.independence_proof_json)<>1 OR json_type(v.independence_proof_json)<>'object' OR json(v.independence_proof_json)='{}');` |
| Gate evidence bound to same run | `SELECT g.gate_run_id FROM gate_runs g LEFT JOIN evidence_hashes e ON e.gate_run_id=g.gate_run_id AND e.evidence_hash=g.evidence_hash AND e.run_id=g.run_id AND e.verifier_run_id=g.verifier_run_id WHERE g.decision='pass' AND g.requires_same_run=1 AND (e.evidence_hash IS NULL OR e.producer_run_id IS NULL OR e.producer_run_id<>g.run_id OR e.verifier_run_id IS NULL OR e.verifier_run_id<>g.verifier_run_id);` |
| Gate clock context exact one-use binding | `SELECT g.gate_run_id FROM gate_runs g LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id WHERE g.decision='pass' AND (c.clock_context_id IS NULL OR c.gate_run_id<>g.gate_run_id OR c.consumed_by_gate_run_id<>g.gate_run_id OR c.run_id<>g.run_id OR c.transition_id<>g.transition_id OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR typeof(c.bound_at_epoch_ms)<>'integer' OR c.bound_at_epoch_ms<1 OR c.bound_at_epoch_ms>253402300799999 OR c.bound_at_epoch_ms<>c.now_epoch_ms OR typeof(c.consumed_at_epoch_ms)<>'integer' OR c.consumed_at_epoch_ms<1 OR c.consumed_at_epoch_ms>253402300799999 OR typeof(g.completed_at_epoch_ms)<>'integer' OR g.completed_at_epoch_ms<1 OR g.completed_at_epoch_ms>253402300799999 OR g.completed_at_epoch_ms<>c.now_epoch_ms OR c.consumed_at_epoch_ms<>c.now_epoch_ms OR c.trusted_clock_source_hash IS NULL OR c.trusted_clock_source_hash='' OR c.gate_nonce IS NULL OR c.gate_nonce='');` |
| Broad or expired approvals | `SELECT a.approval_id FROM transitions t JOIN gate_runs g ON g.gate_run_id=t.gate_run_id LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id LEFT JOIN approvals a ON a.approval_id=t.approval_id WHERE g.decision='pass' AND t.approval_required=1 AND (c.clock_context_id IS NULL OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR a.approval_id IS NULL OR typeof(a.expires_at_epoch_ms)<>'integer' OR a.expires_at_epoch_ms<1 OR a.expires_at_epoch_ms>253402300799999 OR a.expires_at_epoch_ms<=c.now_epoch_ms OR a.approved_action_type='' OR a.approved_risk_ceiling='' OR a.target_type IS NULL OR a.target_type='' OR a.target_id IS NULL OR a.target_id='' OR a.target_hash IS NULL OR a.target_hash='' OR a.target_scope IS NULL OR a.target_scope='');` |
| Exact mutating approval binding | `SELECT t.transition_id FROM transitions t JOIN gate_runs g ON g.gate_run_id=t.gate_run_id LEFT JOIN gate_clock_context c ON c.clock_context_id=g.clock_context_id LEFT JOIN approvals a ON a.approval_id=t.approval_id LEFT JOIN risk_assessments ra ON ra.transition_id=t.transition_id AND ra.run_id=t.run_id WHERE g.decision='pass' AND t.approval_required=1 AND (g.run_id<>t.run_id OR g.transition_id<>t.transition_id OR c.clock_context_id IS NULL OR c.gate_run_id<>g.gate_run_id OR c.run_id<>g.run_id OR c.transition_id<>t.transition_id OR typeof(c.now_epoch_ms)<>'integer' OR c.now_epoch_ms<1 OR c.now_epoch_ms>253402300799999 OR typeof(g.completed_at_epoch_ms)<>'integer' OR g.completed_at_epoch_ms<1 OR g.completed_at_epoch_ms>253402300799999 OR g.completed_at_epoch_ms<>c.now_epoch_ms OR a.approval_id IS NULL OR a.run_id IS NULL OR a.run_id<>t.run_id OR a.run_id<>g.run_id OR typeof(a.expires_at_epoch_ms)<>'integer' OR a.expires_at_epoch_ms<1 OR a.expires_at_epoch_ms>253402300799999 OR a.expires_at_epoch_ms<=c.now_epoch_ms OR a.single_use<>1 OR a.consumed_by_transition_id IS NULL OR a.consumed_by_transition_id<>t.transition_id OR a.consumed_by_gate_run_id IS NULL OR a.consumed_by_gate_run_id<>g.gate_run_id OR a.approved_action_type<>t.action_type OR a.target_type<>t.target_type OR a.target_id<>t.target_id OR a.target_hash<>t.target_hash OR a.target_scope<>t.target_scope OR a.channel<>t.approval_channel OR a.source_message_digest<>t.approval_source_digest OR a.approval_text_digest<>t.approval_text_digest OR ra.assessment_id IS NULL OR ra.risk_dominance<>t.risk_dominance OR CASE a.approved_risk_ceiling WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE -1 END < CASE t.risk_dominance WHEN 'R0' THEN 0 WHEN 'R1' THEN 1 WHEN 'R2' THEN 2 WHEN 'R3' THEN 3 WHEN 'R4' THEN 4 ELSE 99 END);` |
| Reused approval id | `SELECT approval_id FROM transitions WHERE approval_id IS NOT NULL GROUP BY approval_id HAVING COUNT(*)>1;` |
| Non-independent verifier row | `SELECT verifier_run_id FROM judge_verifier_runs WHERE same_worker_context=1 OR verifier_agent_id=worker_agent_id OR prompt_hash=context_hash OR worker_run_id IS NULL OR independence_class IN ('self','same_worker','same_context','correlated','unknown') OR json_valid(independence_proof_json)<>1 OR json_type(independence_proof_json)<>'object' OR json(independence_proof_json)='{}';` |
| SLO query fixture status | `WITH required(query_name) AS (VALUES ('Metadata-missing external RPC not auto-repaired'),('Duplicate live dispatch blocked'),('`sessions_spawn` intent without exact spawn request binding'),('`sessions_spawn` external metadata exact match'),('Accepted `sessions_spawn` without exact accepted session identity'),('`sessions` row without exact spawn request same-row binding'),('Lease leak after terminal state'),('Unknown usage blocks auto-local'),('Model cost registry numeric bounds'),('Endpoint-bound budget event cost row blocks dispatch'),('Run budget selected cost row mismatch'),('`sessions_spawn` intent without exact strict prior reserve'),('Invalid zero-reserve policy'),('Meaningless `sessions_spawn` reserve'),('Budget event amount malformed or out of range'),('Budget counters outside selected budget'),('Budget ledger reconciles to counters and budgets'),('Budget prefix over-release or over-restore'),('Duplicate or replayed budget events'),('Budget event count bounded for SUM safety'),('Completion gate before done for R2+'),('Passing gate without verifier row'),('Passing gate wrong-run or non-independent verifier'),('Gate evidence bound to same run'),('Gate clock context exact one-use binding'),('Broad or expired approvals'),('Exact mutating approval binding'),('Reused approval id'),('Non-independent verifier row'),('SLO query fixture status')), audit_required(query_name) AS (SELECT query_name FROM required WHERE query_name<>'SLO query fixture status'), current_schema(schema_version,migration_sha256) AS (SELECT version,sha256 FROM schema_migrations ORDER BY version DESC LIMIT 1), blocking(query_name) AS (SELECT r.query_name FROM audit_required r CROSS JOIN current_schema cs LEFT JOIN slo_queries q ON q.query_name=r.query_name AND q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256 LEFT JOIN slo_audits a ON a.slo_audit_id=(SELECT a2.slo_audit_id FROM slo_audits a2 WHERE a2.query_name=q.query_name AND a2.schema_version=q.schema_version AND a2.migration_sha256=q.migration_sha256 AND a2.query_hash=q.query_hash ORDER BY a2.run_at_epoch_ms DESC,a2.slo_audit_id DESC LIMIT 1) LEFT JOIN evidence_hashes e ON e.gate_run_id=a.gate_run_id AND e.evidence_hash=a.evidence_hash AND e.run_id=a.evidence_run_id AND e.verifier_run_id=a.verifier_run_id LEFT JOIN gate_runs g ON g.gate_run_id=a.gate_run_id AND g.evidence_hash=a.evidence_hash AND g.run_id=a.evidence_run_id AND g.verifier_run_id=a.verifier_run_id AND g.decision='pass' WHERE q.query_name IS NULL OR a.slo_audit_id IS NULL OR a.status<>'pass' OR a.empty_db_status<>'pass' OR a.fixture_db_status<>'pass' OR a.schema_version<>q.schema_version OR a.migration_sha256<>q.migration_sha256 OR a.query_hash<>q.query_hash OR a.evidence_hash IS NULL OR a.evidence_run_id IS NULL OR a.verifier_run_id IS NULL OR a.gate_run_id IS NULL OR e.evidence_hash IS NULL OR e.producer_run_id<>a.evidence_run_id OR e.run_id<>a.evidence_run_id OR e.verifier_run_id<>a.verifier_run_id OR e.gate_run_id<>a.gate_run_id OR g.gate_run_id IS NULL UNION ALL SELECT q.query_name FROM slo_queries q JOIN current_schema cs ON q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256 LEFT JOIN required r ON r.query_name=q.query_name WHERE r.query_name IS NULL UNION ALL SELECT '__slo_registry_count__' WHERE (SELECT COUNT(*) FROM slo_queries q JOIN current_schema cs ON q.schema_version=cs.schema_version AND q.migration_sha256=cs.migration_sha256)<>(SELECT COUNT(*) FROM required)) SELECT query_name FROM blocking;` |


Lineage rule: every final decision packet includes `run_id`, `authority_mode`, `transition_id`, `external_rpc_intent_id`, `budget_event_id`, `verifier_run_id`, `gate_run_id`, evidence hashes, changed artifacts/projections, approval id if any, residual risks, and rollback path.

## Human Review Scaling

Human review packets compress decisions without hiding evidence. They include decision, action, target hash, risk dominance, authority mode, budget status, external metadata status, verifier/gate lineage, checks, rollback path, residual risk, and requested approval.

Escalate to `human_review_required` when:

- External runtime metadata is missing, ambiguous, invalid, version-only, or mismatched against normalized run/transition/client/idempotency/phase/agent/task identity.
- Unknown usage/cost exists.
- Budget reservation would exceed remaining budget.
- Budget limits, counters, or event amounts are negative, malformed, out of fixed bounds, over budget, unreconciled against the authoritative ledger, duplicate/replayed, over-released/restored, cross-dimensional for retry or human-attention semantics, or semantically meaningless.
- A `sessions_spawn` intent is missing the exact `spawn_request_id` binding, has mismatched client/idempotency/phase/agent/task identity, has raw-JSON/normalized/local metadata mismatch, is missing the accepted session identity or exact sessions row after acceptance, is missing the exact `reserve_budget_event_id`, points to a reserve from the wrong run/transition/provider/model/endpoint/capability/cost row, has equal/ambiguous epoch-ms ordering, or points to a reserve created after the intent request.
- Selected provider/model/endpoint cost registry binding is missing, endpoint-mismatched, capability-only, stale, hash-mismatched, or confidence is unknown.
- Predicate backend is unsupported or sandbox proof is missing.
- Approval is broad, expired by `expires_at_epoch_ms <= gate_clock_context.now_epoch_ms`, mismatched, hash-stale, wrong-channel, wrong-source, wrong-transition, lower-ceiling, reused, already consumed, or evaluated without exactly one per-gate trusted clock context bound to the same gate/run/transition where `bound_at_epoch_ms = now_epoch_ms = consumed_at_epoch_ms = completed_at_epoch_ms`.
- Verifier row is absent, wrong-run, same-worker/context, evidence-unbound, or self-validation is the only evidence.
- Risk dominance increased before mutation without an approval covering the higher class.
- R3/R4 mutation, credential/private data handling, Gateway/Cron/service/config mutation, or external send is involved.

## Compatibility Migration Plan

Phase 0 - file authority and preflight guards:

- Authority: existing JSON/JSONL/Markdown artifacts.
- Add future `.gitignore` rules, packaging denylist, `git check-ignore` preflight, metadata contract probes, and no-runtime-change scope.
- Block DB creation and `db_authority_canary` until VCS/privacy checks pass.

Phase 1 - read-only shadow backfill:

- Authority: files.
- Create the `STRICT`/`ANY` type-preserving schema only after privacy preflight.
- Apply a compatibility migration that changes `artifact_projections`
  identity from content-level uniqueness to `UNIQUE(run_id, path,
  source_authority)`, preserving version-1 databases instead of repinning
  version 1.
- Treat the post-v2 `artifact_projections` and
  `artifact_projection_history` DDL in `Minimum Database Contracts` as the
  accepted schema contract; v1 duplicate run/path/source rows are collapsed only
  with canonical timestamp evidence, archived with retained deterministic
  projection IDs, or rejected fail-closed when the timestamp ordering is
  ambiguous.
- Backfill current artifacts into rows marked `file_authority_shadow`.
- No dispatch adapter reads from DB for decisions.
- Parity audit compares semantic fields and content hashes.

Phase 2 - dual-write shadow:

- Authority: files.
- New workflows may write both files and DB rows marked `dual_write_shadow` only
  with explicit new-workflow proof and no prior run evidence for that workflow.
- Promotion from `file_authority_shadow` requires a fresh parity rehash of all
  existing shadow projections for the workflow, no nonterminal file-authority
  runs, no positive `open_file_authority_runs` counter, and R1 shadow evidence only.
- First dual-write runs create their file artifact atomically and reject
  pre-existing files unless matching dual-write evidence already exists. New
  writes finalize only after durable prepared run/projection evidence exists, so
  exact retry can recover an interrupted file write without orphaning authority.
- Exact replay and audit count all same-run projection rows across authorities;
  any extra or cross-authority projection fails closed.
- JSON/JSONL remains operational authority; DB rows are parity evidence.
- Endpoint-bound selected provider/model cost-row reservation, exact reserve-before-`sessions_spawn` pointer/order authority, raw-JSON/normalized/local metadata equality, accepted session identity and exact sessions row binding, authoritative bounded fixed-scale budget ledger with guarded counters, pure-dimension human-attention rows, exact approval target binding, per-gate trusted clock context with snapshot equality, type-preserving `STRICT`/`ANY` numeric storage for every bounded gate-critical numeric field, pass-gate verifier invariants, predicate backend fields, and SLO fixture tables exist before any canary.

Phase 3 - one low-risk DB-authority canary:

- Authority: DB only for one low-risk workflow in `db_authority_canary`.
- Prerequisites: metadata contract probes with raw JSON equality, accepted session identity and exact sessions-row fixtures, endpoint-bound selected provider/model budget gates, strict prior-reserve `sessions_spawn` gates, bounded microusd numeric fixtures including numeric-text and integral-REAL rejection, authoritative ledger/counter reconciliation with pure human-attention fixtures, zero-reserve policy fixtures, exact approval gates with per-gate trusted epoch-millisecond snapshot-equality authority, independent verifier/gate evidence gates, predicate substrate acceptance if used, SLO compile/pass on empty and fixture DBs, VCS/privacy guard, parity audit, and crash fixtures.
- Existing file-authority runs are drained, not converted.

Phase 4 - per-workflow cutover, drain, and rollback:

- Cut over one workflow at a time.
- Never migrate an in-flight run.
- Drain open file-authority runs before flipping authority.
- Keep rollback flag and deadline per workflow.
- On rollback, new runs return to file authority and DB remains audit/shadow.

Phase 5 - steady DB authority:

- Only after all cutovers and rollback drills pass may the design claim DB is sole desired-state authority for enabled workflows.
- Projections are regenerated from DB outbox.
- Emergency rollback remains per workflow, not Gateway restart or config mutation.

## Test and Acceptance Matrix

Current document-only verification:

| Area | Check command | Acceptance |
|---|---|---|
| Document non-empty | `test -s docs/agentic-os-production-adaptation.md` | pass |
| Required remediation tokens | `rg -n "external_rpc_intents|spawn_request_id|external_run_id|external_transition_id|external_client_request_id|external_idempotency_key|external_phase|external_agent_id|external_task_digest|json_extract|external_id|session_key|spawn_idempotency_key|workflow_authority|run_budgets|budget_events|model_cost_registry|endpoint_binding_id|expires_at_epoch_ms|created_at_epoch_ms|requested_at_epoch_ms|reserve_budget_event_id|gate_clock_context|clock_context_id|gate_nonce|bound_at_epoch_ms|trusted_clock_source_hash|cost_microusd|endpoint_zero_reserve_policies|agentic_predicate_inproc_v1|file_authority_shadow|dual_write_shadow|db_authority_canary|human_review_required|git check-ignore|gate_without_verifier|selected_model_registry_binding|selected_model_endpoint_binding|exact_approval_binding|exact_approval_expiry_timestamp|STRICT|ANY|numeric text|integral REAL|Round 15" docs/agentic-os-production-adaptation.md` | every token appears |
| Confidence questions | `rg -o "对这个策略有100%的把握吗？" docs/agentic-os-production-adaptation.md | wc -l` | at least 12 |
| Current-vs-proposed truth | `rg -n "No P0/P1 runtime implementation is claimed complete|Runtime production behavior remains unproven|Current OpenClaw is below|fresh independent revalidation" docs/agentic-os-production-adaptation.md` | all appear |
| SQL compile and adversarial fixture suite | Extract the complete DDL and every documented SLO `SELECT`, compile in `sqlite3 :memory:`, then run Round 5 plus reopened H1-H4 fixtures, Round 6 regression fixtures, Round 9 corrective fixtures, and Round 11 corrective fixtures for per-gate clock, model-cost registry, run budgets, budget events, external-intent epoch ordering, approval expiry, exact approval run/gate/transition binding, ledger reconciliation, zero-reserve policy validity, fixed-point numeric bounds, retry-ledger cross-dimensional payloads, raw-JSON/normalized/local metadata equality, accepted session identity, sessions same-row binding, gate-clock freshness, human-attention dimensional closure, `consume` human-attention contamination, metadata version spoofing, NULL/mismatched external metadata, orphan spawn intents, and mismatched spawn-request identity. | DDL compiles, every SLO compiles, valid controls return zero blocking rows, exact integer maxima pass, and numeric text, integral `REAL`, `NULL`, negative, max+1, `Inf`, `NaN`, `1e999`, retry `consume` bypass, `consume` with `human_attention_units`, cross-dimensional retry decrement/restore, raw JSON mismatch, missing accepted `external_id`/`session_key`/session row, sessions same-row mismatch, stale/future gate clock values, human-attention token/cost/time/retry payloads, version-only metadata, NULL/mismatched external metadata, orphan spawn intent, mismatched spawn-request binding, wrong/null approval run, and wrong approval gate/transition fixtures return blocking rows or fail DDL before gates can rely on them. |

Future fixture groups:

| Fixture group | Acceptance |
|---|---|
| `vcs_privacy/` | `git check-ignore` matches DB/WAL/SHM/backups; packaging denylist refuses raw DB files. |
| `migration_file_authority/` | Pre-existing file-authority run survives schema creation and shadow backfill. |
| `dual_write_parity/` | DB rows and JSON projections match semantically. |
| `gateway_metadata/` | Metadata-present bind succeeds; metadata-absent fails to `human_review_required` with no release of another run's lease. |
| `session_metadata/` | Metadata-present spawn binds only when `spawn_request_id`, `client_request_id`, idempotency key, phase, agent, task digest, raw JSON paths, normalized observed fields, local intent fields, accepted `external_id`, accepted `session_key`, and exact `sessions` row match exactly; metadata-absent, version-only, NULL, invalid JSON, raw-JSON mismatch, missing accepted identity, missing session row, sessions same-row mismatch, or orphan-intent cases do not retry spawn and go to `human_review_required`. |
| `crash_boundaries/` | Crash before/after acquire, spawn, first output, complete, release has no duplicate spawn or leaked owned lease. |
| `budgets/selected_model_registry_binding.sql` | Missing selected-model registry row, unknown confidence, capability-only false match, NULL provider/model reserve/consume events, duplicate/replayed events, concurrent reservation oversubscription, negative/out-of-range reserve/consume amounts, numeric-text and integral-REAL registry prices, fixed-point max+1, and negative counters all block to `human_review_required`; exact provider/model/endpoint/capability/effective row with exact integer maxima passes. |
| `budgets/selected_model_endpoint_binding.sql` | Two rows for the same provider/model/capability/effective timestamp but different endpoint bindings must not collapse; same-second-after reserve, same-ms ambiguity, wrong transition, wrong endpoint, wrong hash, missing reserve, numeric-text/integral-REAL `created_at_epoch_ms`, and numeric-text/integral-REAL `requested_at_epoch_ms` all block; prior exact same-run/same-transition/provider/model/endpoint/capability/cost-row reserve with integer epoch-ms values passes. |
| `budgets/ledger_reconciliation.sql` | Counter drift, numeric-text or integral-REAL counters/events, negative net reserve, consume greater than budget, retry units or human-attention units on consume, non-retry dimensions on retry_decrement/retry_restore, token/cost/time/retry dimensions on `human_attention`, release greater than prior effective reserve, restore greater than prior retry decrement, duplicate/replayed event hash, concurrent over-reservation, and per-run event count overflow attempts all block; exact reserve/release/consume/retry-decrement/restore and pure `human_attention` consumption controls pass. |
| `budgets/human_attention_cross_dimension_payload.sql` | `human_attention` rows carrying input tokens, output tokens, cost, time, or retry units and `consume` rows carrying `human_attention_units` block by DDL or SLO; a pure row with only `human_attention_units > 0` passes, reduces outstanding human-attention reservation, and reconciles to `consumed_human_attention`. |
| `budgets/non_negative_budget_accounting.sql` | Negative reserve, negative consume, negative counter, over-budget counter, exhausted retry, numeric text, integral `REAL`, `1e999`, Inf, NaN/NULL conversion, max+1, multiplication/aggregation overflow attempt, and concurrent reserve fixtures block; exact maximum fixed-point values and positive exact reserve/consume controls pass. |
| `budgets/zero_reserve_policy.sql` | All-zero minima, disabled policy, stale effective window, endpoint/capability/hash mismatch, and event not satisfying every positive policy minimum block; zero input/output/cost reserve passes only with an enabled exact endpoint/capability/hash/effective-window policy and required retry/time/human-attention minima satisfied. |
| `sqlite_type_affinity_h1_h4.sql` | H1 `gate_clock_context.now_epoch_ms`, H2 `model_cost_registry.*_cost_microusd_per_million`, H3 `run_budgets` and `budget_events` money/token/time/retry/human-attention fields, and H4 `external_rpc_intents.requested_at_epoch_ms` plus `approvals.expires_at_epoch_ms` reject numeric text, integral `REAL`, `NULL`, negative, max+1, `Inf`, `NaN`, and `1e999`; exact integer maxima pass. |
| `predicate_sandbox/` | Attempts at dynamic import, eval, subprocess, shell, network, credential path read, write, symlink traversal, and oversize output fail closed. |
| `sql_slo/` | All SLO SQL compiles and passes on empty and fixture DBs with query hash/migration hash recorded. |
| `approvals_independence/gate_without_verifier.sql` | Pass gates with NULL verifier, absent verifier row, wrong-run verifier, same-worker/context verifier, NULL evidence producer, NULL evidence verifier, or independence failure fail closed. |
| `approvals_independence/exact_approval_binding.sql` | Wrong or NULL run id, wrong gate, wrong target, NULL target/hash, stale hash, wrong channel/source digest, expired epoch authority, reused approval, wrong transition, and lower risk ceiling fail closed; only exact run/gate/transition/action/target/hash/channel/source/text/risk/expiry/single-use binding passes. |
| `approvals_independence/exact_approval_expiry_timestamp.sql` | With trusted per-gate `gate_clock_context`, stale/future `bound_at_epoch_ms`, stale/future `now_epoch_ms` relative to persisted gate completion, reused/wrong-run/wrong-gate/wrong-transition/mismatched-completion contexts fail; expired-by-1ms, equal-to-now, malformed, NULL, numeric-text, integral-REAL, or non-integer `expires_at_epoch_ms` fails by DDL or SLO; future-by-1ms integer expiry bound to the exact gate/run/transition/action/target/channel/source/text/risk passes; malformed display text is ignored as projection-only and cannot authorize. |
| `cutover_rollback/` | Canary cutover, drain, rollback to file authority, and projection regeneration work. |

## Rollback and Recovery Plan

Document-only rollback:

- Revert or patch only `/Users/zuqiangyu/clawd/docs/agentic-os-production-adaptation.md`.
- No runtime state is modified by this document.

Future runtime rollback:

1. Set affected workflow to `rollback_to_file_authority`.
2. Stop new DB-authority dispatch for that workflow.
3. Let open file-authority runs complete; do not convert them mid-flight.
4. Checkpoint WAL, run `PRAGMA integrity_check`, run `PRAGMA foreign_key_check`, and create a verified backup before migration rollback.
5. Release only leases whose exact metadata proves ownership by the run; otherwise wait for TTL or human review.
6. Mark ambiguous sessions as `human_review_required`; do not spawn a replacement automatically.
7. Regenerate projections from the last valid authority.
8. Invalidate trust observations produced by weak/version-only/mismatched metadata, raw-JSON/normalized/local metadata mismatch, orphan or mismatched spawn-request binding, missing accepted session identity, missing exact sessions row, sessions same-row identity mismatch, missing/wrong/post-RPC reserve ordering, endpoint-unbound selected-model budget ambiguity, ledger/counter drift, negative net reservation, retry or human-attention cross-dimensional event payloads including `consume` with human-attention units, over-release/restore, duplicate/replayed budget events, numeric-text or integral-REAL gate-critical numeric storage, non-finite legacy monetary conversion, invalid zero-reserve policy, broad or mismatched approvals, wrong-run/wrong-gate approval binding, expired or malformed approval expiry authority, stale/future/reused/wrong-run/wrong-gate/wrong-transition gate clock context, mismatched gate completion time, pass gates without a bound independent verifier, unknown usage, or unsupported predicate backend.
9. R3/R4 and Critical/High failures require explicit human approval before retry.

## Red-Team and Confidence-Loop Rounds

### Round 1 - Temporary Agent Dispatch

Question: 对这个策略有100%的把握吗？

Answer: No. The initial design assumed supervisor dispatch remained available after upgrades. Correction: no config mutation or Gateway restart in the in-flight path; missing allowLease is `lease_unavailable`/`human_review_required`.

### Round 2 - Provider-Bound Model Assumptions

Question: 对这个策略有100%的把握吗？

Answer: No. Vendor/model names are not stable safety semantics, but budget enforcement still must bind the selected provider/model. Correction: route by capability class, persist the selected provider/model/endpoint/effective cost row before RPC, and invalidate trust when provider, model, sampling, prompt, endpoint, or tool schema changes.

### Round 3 - Trust Ledger Overconfidence

Question: 对这个策略有100%的把握吗？

Answer: No. Raw pass rate and small samples create false confidence. Correction: Wilson lower bounds, correlation grouping, severity downgrade, version invalidation, and same-run independent verifier binding.

### Round 4 - Event Privacy and Audit Leakage

Question: 对这个策略有100%的把握吗？

Answer: No. Event ledgers can leak private text, tokens, and local context. Correction: compact redacted projections, refs and hashes by default, raw DB/package denylist, and future signing/backups.

### Round 5 - Transactional Authority, Goals, SLOs, and Gates

Question: 对这个策略有100%的把握吗？

Answer: No. JSON/JSONL state, weak idempotency, shell predicates, and loose SLOs were insufficient. Correction: guarded DB transitions, `UNIQUE(idempotency_key)`, structured predicate substrate, and SQL SLO lineage.

### Round 6 - Final Convergence Attempt

Question: 对这个策略有100%的把握吗？

Answer: No. The design still had hidden High issues after convergence. Correction: keep design-gate claims provisional and require independent review after every material correction.

### Round 7 - Line-Level Closure Attempt

Question: 对这个策略有100%的把握吗？

Answer: No. Protected state path, prepare idempotency, NULL-safe evidence joins, and risk-dominance SLOs needed explicit correction. Correction: put authority under `state/`, add `prepare_idempotency_key`, make evidence queries NULL-safe, and gate on risk dominance.

### Round 8 - Round 1 Remediation Consolidation

Question: 对这个策略有100%的把握吗？

Answer: No. The two Round 1 remediation proposals identified six consolidated blockers that make any 100% claim false until implementation and revalidation:

1. External runtime metadata is missing. Correction: make the metadata contract a P0 prerequisite; current OpenClaw is below contract; automatic reconciliation only with exact run/idempotency metadata; otherwise `human_review_required`.
2. Budgets were prose, not enforceable state. Correction: add `run_budgets`, `budget_events`, and endpoint-bound `model_cost_registry`; bind reservation to exact selected provider/model/endpoint/effective cost row; reserve and decrement retry before RPC; unknown usage/cost blocks `auto-local` and trust promotion.
3. Standing Goal predicate safety lacked an enforcing substrate. Correction: default to `agentic_predicate_inproc_v1`; optional external sandbox only after a named backend proves enforcement; unsupported backend means human review.
4. Authority migration was too big-bang. Correction: file authority -> `file_authority_shadow` -> `dual_write_shadow` -> one low-risk `db_authority_canary` -> per-workflow cutover/drain/rollback -> steady DB authority; never migrate in-flight runs.
5. Gate, judge, approval, trust, and SLO schemas were under-bound. Correction: include concrete DDL, exact normalized approval binding, pass-gate verifier invariants, NULL-safe evidence binding, and SLO SQL versioned by migration/query hash with empty/fixture DB tests.
6. VCS/privacy guards were missing. Correction: require future `.gitignore` patterns, `git check-ignore` preflight, and packaging denylist before DB creation or canary.

Reassessment: the design now documents corrections, not production proof. At that stage, Round 3 independent revalidation was still required.

### Round 9 - Round 2 Remediation Closure

Question: 对这个策略有100%的把握吗？

Answer: No. The two Round 2 reviews found three remaining blocking design gaps: pass gates could be recorded without a real same-run independent verifier, selected provider/model budget checks could false-negative through capability-only cost matches, and approval targets were nullable/broad rather than exact. Correction: add a `gate_runs` PASS invariant and NULL-safe evidence SLOs, require a real `judge_verifier_runs` row bound to the same run and gate evidence, persist the exact selected provider/model/endpoint/effective cost row before RPC, make model-backed budget events non-NULL except explicit `human_attention`, enforce normalized non-NULL approval targets, and add the named fixtures `approvals_independence/gate_without_verifier.sql`, `budgets/selected_model_registry_binding.sql`, and `approvals_independence/exact_approval_binding.sql`.

Reassessment: the prior six Round 1 closures remain intact at design level: external metadata fail-closed behavior, enforceable budgets, safe predicate substrate, staged compatibility migration, concrete schema/SLO gates, and VCS/privacy preflight. At that stage, the document still proved only a corrected design; production behavior was not proven and Round 3 independent revalidation was required.

### Round 10 - Round 3 Semantic Bug Closure

Question: 对这个策略有100%的把握吗？

Answer: No. The Round 3 AI review found two High semantic bugs despite the Software Architect PASS: cost registry rows were not endpoint-bound, and approval expiry used raw text ordering that could miss expired RFC3339 approvals. Correction: add `endpoint_binding_id` to `model_cost_registry`, make registry uniqueness and row hashes endpoint-bound, add run-budget and `sessions_spawn` prior-reserve SLOs for exact provider/model/endpoint/cost-row binding, replace approval expiry authority with `expires_at_epoch_ms`, compare expiry only to integer current epoch milliseconds, and add the named fixtures `budgets/selected_model_endpoint_binding.sql` and `approvals_independence/exact_approval_expiry_timestamp.sql`.

Reassessment at that stage: all prior Round 1 and Round 2 closures remained preserved at design level. The document still proved only a corrected design; production behavior was not proven and Round 4 independent revalidation was required. Later corrections superseded that status.

### Round 11 - Round 4 Remediation Closure

Question: 对这个策略有100%的把握吗？

Answer: No. The Round 4 AI Engineer review and independent Software Architect review found gate-critical High gaps that make any 100% claim false: `sessions_spawn` prior-reserve proof used second-granularity text timestamps and could accept a same-second post-RPC reserve; approval expiry claimed epoch milliseconds but used `strftime('%s')*1000`, allowing recently expired approvals; and budget accounting allowed negative or meaningless reserves/consumes/counters. Correction: add strict integer epoch-ms authority columns, require `external_rpc_intents.reserve_budget_event_id` for `sessions_spawn`, require exact same-run/same-transition/provider/model/endpoint/capability/cost-row reserve binding with `reserve.created_at_epoch_ms < intent.requested_at_epoch_ms`, bind approvals to a trusted fixtureable `gate_clock_context.now_epoch_ms`, reject expiry at `expires_at_epoch_ms <= now_epoch_ms`, add non-negative budget constraints and `[0,budget]` SLOs, require meaningful reserve amounts, and allow zero input/output/cost reserve only through an explicit enabled endpoint zero-reserve policy.

Reassessment: Round 1-3 closures remain preserved at design level, but this document is still a design artifact, not production proof. Runtime behavior remains unproven and Round 5 independent revalidation is required.

### Round 12 - Round 5 High Closure

Question: 对这个策略有100%的把握吗？

Answer: No. The Round 5 AI Engineer review (`8ea80d8235808fbe38cf3bb058a5e93c9190e571dcac7a4613f21f8a0fbe2406`) and Software Architect review (`898b493f676e4d1e6daae04ef49f9a763561aa138af47796d4d3a70bee5e367a`) independently found four High gaps after the Round 4 remediation: a reusable singleton gate clock could authorize an expired approval, mutable budget counters could diverge from the event ledger and hide concurrent over-reservation or over-release, all-zero zero-reserve policies could authorize meaningless reservations, and monetary `REAL` values could admit Inf/NaN/1e999 or negative registry prices. Correction: replace the singleton clock with one-use per-gate context keyed to gate/run/transition/nonce and trusted source hash; make `budget_events` the authoritative bounded ledger with guarded counter cache updates and reconciliation SLOs; require exact enabled zero-reserve policy endpoint/capability/hash/effective-window binding with positive minima satisfied; and replace gate-critical monetary `REAL` authority with bounded integer microusd across budgets, events, registry rows, SLOs, and fixtures.

Reassessment: Round 1-4 closures remain preserved at design level. This document still proves only a corrected design. Runtime behavior remained unproven and fresh independent revalidation was required at that stage.

### Round 13 - Round 5 Reopen for SQLite Type Preservation

Question: 对这个策略有100%的把握吗？

Answer: No. Parent verification found the Round 5 DDL still relied on `INTEGER` affinity plus `typeof(...)='integer'`, which SQLite can satisfy after coercing numeric text. That allowed wrong-type gate-critical values such as `'1500'` in `gate_clock_context.now_epoch_ms` and `'100'` in `model_cost_registry.*_cost_microusd_per_million` to pass. Correction: use `STRICT` tables with `ANY` columns for every bounded gate-critical money/token/time/retry/human-attention/epoch field, keep explicit storage-class/range checks, and require H1-H4 fixtures proving numeric text, integral `REAL`, `NULL`, negative, max+1, `Inf`, `NaN`, and `1e999` fail while exact integer maxima pass.

Reassessment: Round 1-5 closures remain preserved at design level, with the Round 5 numeric closure narrowed to a type-preserving SQLite representation. This document still proves only a corrected design. Runtime behavior remained unproven and fresh independent revalidation was required at that stage.

### Round 14 - Round 6 Failure Closure

Question: 对这个策略有100%的把握吗？

Answer: No. Round 6 independent review found three remaining Critical/High design defects: retry units could be smuggled through `consume`, `metadata_contract_version` could spoof absent external `sessions_spawn` metadata, and a `sessions_spawn` external intent could pass without a concrete `spawn_requests` row. Correction: close retry event dimensions in DDL/SLOs, make outstanding retry reservation subtract `release` only, require normalized same-row spawn-request binding, require valid exact external metadata fields for `sessions_spawn`, and add acceptance fixtures for retry consume bypass, cross-dimensional retry payloads, version spoofing, NULL/mismatched metadata, orphan intents, and mismatched spawn-request identity.

Reassessment: Round 1-6 closures are preserved at design level after this correction. This document still proves only a corrected design. Runtime behavior remains unproven and fresh independent revalidation is required.

### Round 15 - Round 8 Corrective Closure

Question: 对这个策略有100%的把握吗？

Answer: No. Round 8 independent review found remaining executable Critical/High gaps: raw `external_metadata_json` could contradict normalized/local `sessions_spawn` identity, accepted spawns could lose session identity, `sessions` could point at a real `spawn_request_id` while carrying another run/phase/agent/client/task identity, gate-clock freshness was claimed but not executable, and `human_attention` rows could hide token/cost/time/retry dimensions. Correction: require `json_extract` equality for the seven metadata fields, require non-empty accepted identity across `external_id`, `session_key`, and exact `sessions` rows, add composite `sessions` -> `spawn_requests` same-row binding, require `bound_at_epoch_ms = now_epoch_ms = consumed_at_epoch_ms = completed_at_epoch_ms`, and make `human_attention` a pure-dimension event.

Reassessment: Round 1-8 closures are preserved at design level after this correction. This document still proves only a corrected design. Runtime behavior remains unproven and fresh independent revalidation is required.

### Round 16 - Round 10 Corrective Closure

Question: 对这个策略有100%的把握吗？

Answer: No. Round 10 independent review found two remaining High design gaps: a mutating approval with `run_id` from another run could authorize the candidate transition, and `consume` could carry `human_attention_units` while the ledger counted it as human-attention consumption. Correction: make approval `run_id` non-NULL, bind approvals exactly to the same transition run, gate run, consumed transition, and consumed gate, reject wrong/null-run and wrong-gate approval fixtures, make `consume` require both `retry_units=0` and `human_attention_units=0`, and make `event_type='human_attention'` the only human-attention consumption authority in DDL, SLOs, and fixtures.

Reassessment: Round 1-10 closures are preserved at design level after this correction. This document still proves only a corrected design. Runtime behavior remains unproven and fresh independent revalidation is required.

## Final Residual-Risk Register

| Risk | Severity | Owner | Detection | Mitigation | Rollback | Acceptance rule |
|---|---|---|---|---|---|---|
| External RPC succeeds but metadata is missing, version-only, raw-JSON-mismatched, or normalized-mismatched | Critical | Gateway/session contract owner | contract probe, pending intent age, exact normalized metadata SLO, `json_extract` raw-JSON equality SLO | fail closed, no proximity bind, no spawn retry, bounded TTL | mark `human_review_required`; release only provably owned leases | accept only after metadata-present exact triple, metadata-absent, version-spoof, NULL, invalid JSON, raw-JSON mismatch, and normalized mismatch fixtures pass |
| DB/WAL/backup files leak through git, packaging, or retrieval | High | Security/privacy owner | `git check-ignore`, ignored-status, packaging denylist tests | ignore rules, denylist, redacted projections | unstage/quarantine, incident review, rotate if exposed | accept only when DB creation preflight passes |
| Selected provider/model/endpoint budget binding is wrong/missing | High | Budget owner | endpoint-bound cost-row anti-join, selected run-budget row SLO, exact reserve pointer SLO, unknown usage SLO, retry budget SLO, reservation oversubscription SLO | persist selected provider/model/endpoint/effective cost row before RPC; bind registry uniqueness and row hash to endpoint id plus bounded integer price/confidence inputs; reserve before RPC; consume/import after; block unknowns | release reservations or downgrade to manual review | accept only after `budgets/selected_model_registry_binding.sql` and `budgets/selected_model_endpoint_binding.sql` pass |
| `sessions_spawn` request/session binding or reserve ordering is missing, ambiguous, or post-RPC | High | Dispatch/budget owner | `spawn_request_id` anti-join, exact client/idempotency/phase/agent/task SLO, accepted session identity SLO, sessions same-row binding SLO, `reserve_budget_event_id` anti-join, strict epoch-ms order SLO, same-second-after/same-ms/wrong-transition fixtures | commit exact spawn request and reserve row first, commit spawn intent with same-row spawn-request FK and reserve pointer second, require non-empty accepted session identity and exact `sessions` row, require `reserve.created_at_epoch_ms < intent.requested_at_epoch_ms`, no proximity binding | mark spawn `human_review_required`; do not retry or auto-bind | accept only after orphan intent, mismatched spawn-request/session identity, accepted-without-session-identity, same-second-after, prior reserve, same-ms ambiguity, wrong transition/endpoint/hash, and missing reserve fixtures pass |
| Budget ledger diverges, over-releases/restores, or creates meaningless/cross-dimensional events | High | Budget owner | authoritative ledger reconciliation, guarded-update rowcount, event-type dimensional SLO, prefix-sum over-release/restore SLO, duplicate/replayed event SLO, zero-reserve policy fixture, concurrent reserve fixture | `budget_events` is authority; counter cache updates happen in one `BEGIN IMMEDIATE` transaction with guarded conditional updates; `consume` carries no retry or human-attention units; retry decrement/restore carry only retry units; `human_attention` is pure-dimension and is the only human-attention consumption authority; zero-reserve policy requires exact endpoint/capability/hash/window and every configured positive minimum satisfied | invalidate budget/trust rows and return dispatch to manual review before any external RPC | accept only after ledger drift, negative net reserve, consume over budget, retry consume bypass, `consume` human-attention bypass, cross-dimensional retry/human-attention payload, over-release/restore, duplicate/replay, zero-reserve policy, concurrent reserve, and positive exact controls pass |
| Fixed-point numeric/type bound is violated or legacy money conversion is unsafe | High | Budget owner | `STRICT`/`ANY` DDL storage-class/range checks, registry price SLO, H1-H4 numeric-text/integral-REAL fixtures, max+1/1e999/Inf/NaN fixtures, aggregate bound fixtures | money is integer microusd only; every bounded gate-critical numeric field preserves input type before `CHECK`; per-value maxima plus bounded event sequence keep `SUM` below signed 64-bit; legacy `REAL` conversion validates source type/range and quarantines before insertion | quarantine converted rows and block trust promotion | accept only after exact integer maxima pass and numeric text, integral `REAL`, max+1, non-finite, multiplication, and aggregation overflow attempts fail closed |
| Predicate substrate is bypassed or unsupported | Critical | Standing Goals owner | backend audit, sandbox proof, malicious fixtures | `agentic_predicate_inproc_v1`, disable unsupported backend | disable plugin, mark goals human review | accept only after escape fixtures fail closed |
| File/DB split-brain during migration | Critical | Control-plane migration owner | parity audit, open file-authority run query, projection drift | staged authority, dual-write shadow, canary, drain | rollback workflow to file authority | accept only after cutover/rollback fixtures pass |
| Approval authorizes wrong run, gate, action, target, or expired mutation | High | Approval/security owner | exact approval binding SLO, per-gate trusted clock context SLO, epoch-expiry SLO, stale/future/reused/wrong-run/wrong-gate/wrong-transition/mismatched-completion fixtures, and expired/equal/future-by-1ms controls | bind run id, gate run id, transition id, action, target type/id/hash/scope, channel, source digest, text digest, risk ceiling, `expires_at_epoch_ms`, single-use transition, one-use nonce, trusted clock source hash, and exact `bound_at_epoch_ms = now_epoch_ms = consumed_at_epoch_ms = completed_at_epoch_ms` gate/run/transition context | invalidate approval and affected gate/trust rows | accept only after exact-run positive, wrong/null-run negative, wrong-gate/wrong-transition, `approvals_independence/exact_approval_binding.sql`, and `approvals_independence/exact_approval_expiry_timestamp.sql` pass |
| Passing gate lacks bound independent verifier | Critical | Verifier/gate owner | PASS invariant, missing-verifier SLO, NULL-safe evidence SLO, worker/verifier/context/prompt/model hash audit | require real same-run `judge_verifier_runs` row and gate evidence producer/verifier binding; self-validation cannot promote trust | downgrade gate/trust observations and return run to manual review | accept only after `approvals_independence/gate_without_verifier.sql` passes |
| SLO SQL drifts from schema | High | Observability owner | compile/pass on empty and fixture DBs, query hash mismatch | version SLOs by migration/query hash | block gates/trust promotion and return to manual review | accept only after SLO fixture suite passes |
| Trust ledger overfits correlated evidence | High | Trust owner | correlation grouping, version invalidation, Wilson thresholds | group correlated trials, severity downgrade, require known usage | downgrade scope to draft/queue | accept only with trust fixtures and no unresolved High/Critical |
| Human review queue grows unbounded | Medium | Operator | unresolved review age and count | risk-prioritized packets and Compost cap of three | defer/archive low-risk proposals | accept if high-risk queue remains visible and bounded |

## Implementation Backlog Prioritized P0/P1/P2

P0.0 - privacy and external contract preflight:

- Add future `.gitignore` rules for `state/agentic-os/` DB/WAL/SHM/backups.
- Add migration startup `git check-ignore` checks and packaging/retrieval denylist.
- Add allowLease metadata contract probe.
- Add sessions metadata/idempotency contract probe that proves exact external `run_id`, `transition_id`, `client_request_id`, `idempotency_key`, `phase`, `agent_id`, and `task_digest` in both normalized fields and raw `external_metadata_json` paths; a version string alone is not proof.
- Add accepted session identity probe that proves duplicate spawn returns the same non-empty accepted session identity and can be persisted consistently as `external_rpc_intents.external_id`, `spawn_requests.session_key`, and `sessions.session_key`.
- Define fail-closed behavior for absent metadata.

P0.1 - minimum schema:

- Implement migrations for `workflow_authority`, `runs`, `transitions`, `external_rpc_intents`, `leases`, `spawn_requests`, `sessions`, `reconciliation_jobs`, `evidence_hashes`, and `outbox_events`.
- Implement `gate_clock_context` as a per-gate one-use context keyed to `clock_context_id`, `gate_run_id`, `run_id`, `transition_id`, and `gate_nonce`; bind trusted fixtureable `now_epoch_ms` once per gate transaction for both approval selection and gate commit with executable snapshot equality across `bound_at_epoch_ms`, `now_epoch_ms`, `consumed_at_epoch_ms`, and `gate_runs.completed_at_epoch_ms`.
- Implement every table that stores bounded gate-critical numeric authority as `STRICT`, and represent money/token/time/retry/human-attention/epoch authority columns as `ANY` plus `typeof(...)='integer'` range checks so SQLite cannot coerce numeric text before validation.
- Implement `run_budgets`, authoritative `budget_events`, `endpoint_zero_reserve_policies`, and endpoint-bound `model_cost_registry` with bounded type-preserved integer microusd prices, selected provider/model/endpoint/effective cost-row binding, and row hash over endpoint id, price, and confidence inputs.
- Implement `approvals`, `risk_assessments`, `judge_verifier_runs`, `gate_runs`, `predicate_plugins`, `goal_manifests`, `goal_runs`, `trust_observations`, `artifact_projections`, `slo_queries`, and `slo_audits`.
- Enforce `gate_runs` PASS verifier invariant, per-gate clock/run/transition/completion binding with snapshot equality, approval run/gate/transition and target non-null fields, approval `expires_at_epoch_ms` type-preserved integer authority, model-backed budget-event non-null fields, pure-dimension `human_attention`, `external_rpc_intents.spawn_request_id` plus `reserve_budget_event_id` for `sessions_spawn`, strict type-preserved integer `created_at_epoch_ms/requested_at_epoch_ms` ordering, exact normalized and raw-JSON external metadata fields, accepted session identity, exact sessions same-row binding, bounded non-negative budget limits/counters/events, retry and human-attention event-type dimensional closure, zero-reserve positive minima, and gate-bound evidence producer/verifier binding.
- Add migration hash checks and `PRAGMA foreign_key_check`.

P0.2 - file-authority shadow and fixture foundations:

- Backfill from existing artifacts as `file_authority_shadow`.
- Add semantic parity audit.
- Add VCS/privacy, schema compile, and SLO fixture harnesses.

P1.0 - dual-write and enforceable budgets:

- Dual-write new runs as `dual_write_shadow` while files remain authority.
- Enforce exact selected provider/model/endpoint/effective cost-row reservation and retry decrement before external RPC.
- Enforce that every `sessions_spawn` external RPC intent has one concrete matching `spawn_requests` row by `spawn_request_id`, client request id, idempotency key, phase, agent id, and task digest; accepted/reconciled intent rows also require exact raw-JSON/normalized/local metadata equality, non-empty accepted session identity, and one exact `sessions` row bound by the full composite spawn tuple. Also require a prior same-run/same-transition reserve event bound by `reserve_budget_event_id` to the exact selected provider/model/endpoint/capability/cost registry row with `reserve.created_at_epoch_ms < intent.requested_at_epoch_ms`; equal-millisecond ambiguity fails closed until a persisted sequence authority exists.
- Enforce non-negative bounded budget amounts and counters, `[0,budget]` invariants, authoritative ledger/counter reconciliation, guarded `BEGIN IMMEDIATE` counter updates with rowcount=1, `consume retry_units=0`, `consume human_attention_units=0`, retry decrement/restore non-retry dimensions equal zero, `human_attention` as the only human-attention consumption authority, over-release/restore prefix checks, meaningful reserves, and explicit zero-cost/no-token endpoint policy rules.
- Enforce fixed-scale microusd conversion for any legacy money source with deterministic rounding, source-type validation, range validation, and fail-closed quarantine before insertion into `STRICT`/`ANY` authority columns.
- Import usage after completion and classify unknown usage.
- Add `budgets/selected_model_registry_binding.sql` for missing rows, unknown confidence, capability-only false matches, NULL provider/model events, concurrent reservation oversubscription, and negative budget values.
- Add `budgets/selected_model_endpoint_binding.sql` for mismatched endpoint/hash, exact endpoint/hash match, same-second-after reserve, same-ms ambiguity, wrong transition/endpoint/hash, missing reserve, and prior exact reserve controls.
- Initial executable fixtures now exist under `tests/fixtures/budgets/` and `tests/fixtures/sqlite_type_affinity_h1_h4.sql`; `MigrationTests.test_p1_budget_sql_fixture_pack_exercises_blocking_slos` applies them to fresh migrated databases and proves the targeted blocking SLOs fire for ledger/counter drift, invalid zero-reserve policies, negative net reserve/over-release, numeric text, integral `REAL`, exact integer maximum positive control, post-dispatch consume over budget, consume carrying retry units, `consume` carrying human-attention units, cross-dimensional retry decrement/restore payloads, duplicate/replayed budget events, selected model/cost-row binding mismatches, and max+1 fixed-point cost values. Concurrent reserve oversubscription remains an explicit runtime concurrency test, and non-finite legacy conversion remains pinned by the runtime legacy-import quarantine test rather than a fake static SQL fixture.

P1.1 - metadata-based dispatch and reconciliation:

- Implement metadata-capable allowLease acquire/status/release or keep dispatch workflows fail-closed.
- Implement metadata-capable session spawn/status/list/result with exact normalized field exposure, valid raw external metadata JSON whose seven identity paths match normalized/local fields, and stable accepted session identity exposure, or keep spawn workflows fail-closed.
- Add reconciliation scanner only after metadata fixtures exist.

P1.2 - predicate runner, approvals, gates, and trust:

- Implement `agentic_predicate_inproc_v1` and malicious fixture suite.
- Add exact approval run/gate/transition binding checks, per-gate clock-context-backed epoch-millisecond approval expiry checks, stale/future `bound_at_epoch_ms`, stale/future `now_epoch_ms`, reused/wrong-run/wrong-gate/wrong-transition/mismatched-completion fixtures, pass-gate verifier checks, and independence fixtures.
- Add `approvals_independence/gate_without_verifier.sql` and `approvals_independence/exact_approval_binding.sql`.
- Add `approvals_independence/exact_approval_expiry_timestamp.sql` for expired-by-1ms, equal-to-now, future-by-1ms, malformed, NULL, non-integer authority cases, and malformed display text projection-only cases.
- Add SLO SQL fixture suite and gate writers.
- Add trust promotion only for known usage and independent verifier evidence.

P1.3 - canary DB authority:

- Enable one low-risk workflow in `db_authority_canary`.
- Crash-test every external boundary.
- Run rollback drill and projection regeneration.

P2 - per-workflow expansion:

- Drain file-authority runs per workflow.
- Cut over workflow by workflow.
- Keep R3/R4 human-required.
- Move to steady DB authority only after every cutover and rollback fixture passes.

## Factual Conclusion

This document is a corrected design artifact. It applies the two mandatory Round 1 remediation proposals, the two mandatory Round 2 review closures, the mandatory Round 3 AI review remediation, the mandatory Round 4 High closures, the mandatory Round 5 High closures reopened to fix SQLite type-affinity coercion, the Round 6 Critical/High failure closures, the Round 8 Critical/High corrective closures, and the Round 10 High corrective closures. The hidden prerequisites are explicit: external runtime metadata with exact raw-JSON/normalized/local `sessions_spawn` proof, concrete spawn-request binding, accepted session identity and sessions same-row binding, endpoint-bound selected provider/model budget binding, exact strict reserve-before-`sessions_spawn` authority, authoritative bounded budget ledger with guarded counter caches and retry plus human-attention event-type dimensional closure, valid zero-reserve policy minima, type-preserving `STRICT`/`ANY` numeric storage, fixed-scale microusd money, safe predicate substrate, compatibility migration, concrete DDL/SLO contracts, exact approvals with non-NULL run/gate/transition binding and per-gate trusted epoch-millisecond snapshot equality, bound independent verifier gates, and VCS/privacy preflight.

No P0/P1 runtime implementation is claimed complete. Current OpenClaw is below the external metadata contract. DB creation and canary authority must remain blocked until `git check-ignore`, packaging denylist, schema, SLO, raw-JSON/normalized/local metadata exact-match, accepted session identity, sessions same-row binding, strict prior-reserve spawn ordering, endpoint-bound selected-model budget, ledger reconciliation including retry, `consume` human-attention, and pure human-attention fixtures, zero-reserve policy, fixed-point numeric and SQLite type-preservation H1-H4 fixtures, predicate, exact approval run/gate/transition plus per-gate clock approval-expiry and snapshot-freshness fixtures, bound verifier independence, crash, parity, and rollback fixtures exist and pass.

Production behavior proven: not yet. Design status: Round 11 corrective revision applied; fresh independent revalidation required.
