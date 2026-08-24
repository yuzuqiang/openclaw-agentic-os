# OpenClaw Agentic OS

Production-oriented control-plane design and implementation workspace for OpenClaw's Agentic OS workflows.

## Current status

The accepted repository design artifact is the PR #39 artifact at head
`53c9555cacb8e1906bc7cb6e252c0b91a73a8141`. That accepted repository state
passed exact-head Phase C, received a clean Codex review for that head, and
merged to `main` as
`b48a7cba8c6671b5dd33a369fb4f59f57d159739`. This is repository/design
acceptance only; later documentation corrections are recorded separately in
`docs/project-status.json`. It does not prove production runtime behavior. The
repository has accumulated bounded local/synthetic P0/P1/P2 implementation slices with
executable tests; those slices are evidence of local control-plane contracts,
not evidence of production OpenClaw authority.

- Design: [`docs/agentic-os-production-adaptation.md`](docs/agentic-os-production-adaptation.md)
- Project status contract: [`docs/project-status.json`](docs/project-status.json)
- Accepted-head repository design artifact SHA-256: `c2d30fdbc8b6cc55873fc76446efbb5bad2c20e0cb85f2c9bb2723b86427e997`
- Current corrected design artifact SHA-256: `57ed45c818d0b60e6a53c7410fb75fe8bf3de68fa63edfa831546a8968fc70ef`
- Accepted PR: [`yuzuqiang/openclaw-agentic-os#39`](https://github.com/yuzuqiang/openclaw-agentic-os/pull/39)
- Historical revalidation evidence, superseded by the accepted PR #39 successor:
  [`docs/runtime-evidence/phase-b-revalidation-20260809.json`](docs/runtime-evidence/phase-b-revalidation-20260809.json)
- Current installed-runtime evidence lineage and Issue #44 candidate snapshot:
  [`docs/runtime-evidence/phase-b-20260811-evidence-index.json`](docs/runtime-evidence/phase-b-20260811-evidence-index.json)
- Local OpenClaw dependency/evidence contract for the tsgo evidence-reuse
  adaptation (deterministic fake-Crabbox harness PASS; live Blacksmith N/A):
  [`docs/runtime-evidence/phase-b-20260813-local-openclaw-tsgo-evidence-reuse.json`](docs/runtime-evidence/phase-b-20260813-local-openclaw-tsgo-evidence-reuse.json)
- Historical installed-runtime negative baseline, retained byte-for-byte:
  [`docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json`](docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json)
- Base DDL migration SHA-256: `2a06f894952629523a4c1671148ce47dd7345a2340128713143fdff904486a01`
- Current latest migration SHA-256: `41cf8c9806f61c1f0b4798a292ac905120ff21f3c5f0d9b48fafe1f02d6bc25f`
- Current migration manifest SHA-256: `089367d09eff784707f80b070d0c9934f79fff3055c6021157b5d3191b4f3c46`
- Design contract: 27 baseline SQLite tables plus one compatibility archive table, one settlement proof table, three legacy import evidence tables, one runtime dispatch binding table, one trust-promotion binding overlay, one canary rollback proof table, one canary binding immutability overlay, and 30 executable SLO queries
- Completed bounded slices: privacy preflight, package/retrieval denylist,
  migration/package parity, file-authority shadow, dual-write shadow, synthetic
  DB-authority canary and rollback, one controlled synthetic expansion path,
  read-only predicate evaluation, approval/pass-gate/SLO audit/goal-run/trust
  binding writers, budget fixture/runtime slices, and injectable metadata
  dispatch/reconciliation probes, a transport/object/process/expiry-bound
  OpenClaw attestor contract, and a Heartbeat-only file-authority shadow pilot
  with deterministic parity, forced rollback, and bounded soak receipts.
- Remaining unproven production scope: live OpenClaw/Gateway/Cron/session RPC
  metadata/attestation contracts against the local downstream OpenClaw
  candidate, production `control.db` or daemon operation, real
  end-to-end session authority, workflow cutover drills, production smoke tests,
  and steady DB-authority operation.

The current P0 foundation materializes the corrected schema and supplies
fail-closed privacy and external-metadata probes. Database authority remains
disabled (`agentic_os.DB_AUTHORITY_ENABLED is False`).
There is no production Agentic OS daemon, no production Agentic OS control
database, and no production session authority in this repository state.

## Foundation commands

The package has no runtime dependencies outside Python's standard library.

```bash
PYTHONPATH=src python3 -m agentic_os.cli preflight
PYTHONPATH=src python3 -m agentic_os.cli migrate --test-db
PYTHONPATH=src python3 -m agentic_os.cli shadow-backfill --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --artifact README.md
PYTHONPATH=src python3 -m agentic_os.cli shadow-audit --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --prepare-idempotency-key file-shadow:shadow-demo --artifact README.md
PYTHONPATH=src python3 -m agentic_os.cli dual-write-shadow --db state/agentic-os/test-control.db --workflow heartbeat --run-id dual-shadow-demo --risk-class R1 --risk-dominance R1 --new-workflow --artifact tmp/dual-shadow-demo.json --content '{"ok":true}'
PYTHONPATH=src python3 -m agentic_os.cli dual-write-shadow-audit --db state/agentic-os/test-control.db --workflow heartbeat --run-id dual-shadow-demo --artifact tmp/dual-shadow-demo.json
PYTHONPATH=src python3 -m agentic_os.cli db-authority-canary --db state/agentic-os/test-control.db --workflow heartbeat --run-id canary-demo --cutover-approved-by local-fixture --cutover-evidence-hash <sha256> --rollback-deadline 2099-01-01T00:00:00+00:00 --last-parity-audit-hash <sha256> --artifact tmp/canary-demo.json --content '{"synthetic":true}'
PYTHONPATH=src python3 -m agentic_os.cli db-authority-canary-rollback --db state/agentic-os/test-control.db --workflow heartbeat --artifact tmp/canary-demo.json
PYTHONPATH=src python3 -m agentic_os.cli db-authority-expansion --db state/agentic-os/test-control.db --workflow local-artifact-canary --run-id expansion-demo --risk-class R1 --risk-dominance R1 --worker-agent-id phase-b-ai-engineer --verifier-agent-id phase-a-security-engineer --verifier-run-id phase-a-boundary-review --eligibility-proof-json '<exact-local-eligibility-proof-json>' --cutover-approved-by local-fixture --cutover-evidence-hash <sha256> --rollback-deadline 2099-01-01T00:00:00+00:00 --last-parity-audit-hash <sha256> --artifact tmp/expansion-demo.json --content '{"synthetic":true}'
PYTHONPATH=src python3 -m agentic_os.cli verify --db state/agentic-os/offline-snapshot.db
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`migrate --test-db` is also available for a deliberately ignored repo-local
test database. Tests use temporary directories and never create
`state/agentic-os/control.db`.

`shadow-backfill` and `shadow-audit` are offline P0.2 tools. They project only
explicit file artifacts into `file_authority_shadow` rows and compare current
file hashes, prepare identity, workflow mode, and deterministic projection IDs
back to those rows; they do not enable database authority or feed dispatch
decisions.

P0.3 adds a local contract, not runtime authority. `OpenClawAdapter` can be
constructed only from a fresh signed challenge bound to the exact transport
object, client process, executable/catalog/source identity, Gateway endpoint
and build, and reviewed singular `session_status(sessionKey)` surface. Invalid
or expired attestations, identity drift, unsigned mappings, cross-process
replay, incomplete metadata, and duplicate acquire/spawn identity drift fail
closed. The default accepted-session probe mode is non-mutating and returns
`status=fail_closed` with `reason=lifecycle_not_authorized`; only explicit
`--execute-lifecycle` permits the bounded acquire/spawn/read/release drill. No
live PASS is current until the local downstream OpenClaw candidate implements
and passes that exact contract.

`src/agentic_os/heartbeat_shadow.py` is Heartbeat-only. It derives one
sanitized manifest from `HEARTBEAT.md` plus `agents.defaults.heartbeat`, writes
only to ignored `state/agentic-os/control.db`, requires 100% file-shadow parity
before `dual_write_shadow`, records zero lease/session authority, rejects soak
coverage gaps and privacy/runtime-observation ambiguity, and moves the shadow
DB to an ignored recoverable backup during forced rollback while re-proving the
exact file-authority digest. The 24-72 hour soak is supported but has not been
run here; file artifacts remain the sole authority throughout.

`dual-write-shadow` is the first executable P1.0 shadow-mode slice. It writes a
single file-authority artifact and records matching `dual_write_shadow` SQLite
projection evidence in the same local operation. An existing `file_authority`
workflow must first pass through `file_authority_shadow` backfill before it can
enter dual-write mode; a brand-new workflow may start directly in
`dual_write_shadow` only when the caller supplies explicit new-workflow proof and
the database has no prior run evidence for that workflow. Exact replay with the same
prepare key, run, artifact path, content, and no additional run projections is a
no-op; changed replay or file/SQLite drift, including workflow-mode drift after
the original write, fails closed and refuses to overwrite file authority. Promotion from
`file_authority_shadow` to `dual_write_shadow` first rehashes every current
file-shadow projection for that workflow; stale or missing backfill artifacts,
non-R1 shadow evidence, any nonterminal file-authority run, or a positive
`open_file_authority_runs` counter blocks the promotion.
A first dual-write must create the file atomically through a fsynced temporary
file and final no-overwrite link; a pre-existing artifact without a matching
dual-write projection is rejected instead of being retroactively stamped as a
successful run. New writes are finalized only after durable prepared run
evidence exists, so an interrupted write can be recovered by an exact retry
without leaving a final file artifact that has no SQLite shadow evidence. Replay
and audit count every projection row for the run, not only `dual_write_shadow`
rows, so extra or cross-authority projection contamination fails closed. The CLI requires explicit `--risk-class R1 --risk-dominance R1`;
higher-risk dual-write runs are rejected until their completion-gate evidence can
be persisted instead of downcast to R1. `--content-file` is subject to the
raw-state denylist before bytes are read, and a post-commit checkpoint failure
must not delete the committed authority file.
This is parity evidence only: it does not create `db_authority_canary` or
`db_authority` runs, does not call OpenClaw or Gateway, and does not claim
canary readiness.

The first Issue 7 canary slice lives in `agentic_os.db_authority_canary`.
It is still synthetic and local-only: the writer records one R1
`db_authority_canary` workflow/run plus one local artifact projection, refuses
to run if `DB_AUTHORITY_ENABLED` is true, and checks that no
`external_rpc_intents`, `leases`, `spawn_requests`, or `sessions` rows exist for
the canary run. It proves the local crash boundary by committing a prepared
SQLite canary before the artifact write, recovering an exact retry after a
simulated post-prepare crash, and finalizing only after the fsynced artifact
digest matches the projection. Rollback moves the workflow to
`rollback_to_file_authority` only after regenerating and matching the projection
identity from the local artifact. This is artifact-only fixture evidence; it
does not enable real production session control or steady DB authority.

The first Issue 29 P2.0 controller slice lives in
`agentic_os.db_authority_controller`. It narrows DB-authority expansion to one
explicit low-risk workflow, `local-artifact-canary`, and delegates only to the
synthetic artifact canary above. It admits only R1/R1, rejects R3/R4 as
human-required, and requires an exact local eligibility proof before the canary
transition can advance. That proof must also have persisted independent
`judge_verifier_runs` evidence whose evidence hash matches the exact synthetic
gate hash. The proof binds the verifier evidence, canary evidence hash,
rollback-regeneration hash, parity audit hash, deterministic projection
identity, workflow isolation, RPC denial flags, and `DB_AUTHORITY_ENABLED=false`.
The raw canary and rollback APIs reject `local-artifact-canary`; controlled
writes recheck workflow-wide no-RPC and projection-set boundaries again under
the finalization lock and do not count retroactive replay as controller proof.
This controller does not prove or call any OpenClaw, Gateway, Cron, or session
RPC and must not be treated as production cutover authority.

The first P1.2 predicate slice lives in `agentic_os.predicates`. It implements
only the read-only `agentic_predicate_inproc_v1` backend: literal booleans,
`all` / `any` / `not`, repo-root-bounded `file_exists` and `file_sha256`,
JSON scalar equality over caller-supplied documents, and command-result scalar
equality over caller-supplied evidence. Unsupported backends, dynamic code,
subprocess/shell/network/environment adapters, SQL/time/Gateway/config adapters,
non-Git-worktree roots, bare or symlinked `.git` metadata, malformed or unsupported
Git metadata, NUL/control-character Git metadata fields, directory `.git` configs whose
`core.worktree` points away from the requested root, symlinked relative or absolute
gitdir pointers, malformed HEAD refs, v0 repositories declaring v1-only extensions,
unsupported Git format extensions, Git config include directives, per-worktree
`config.worktree` bare/worktree drift overlaid on common config,
empty linked-worktree `commondir` files, path traversal, symlink escapes,
raw database state paths, hard-linked file aliases, common credential stores
such as `.git`, `.docker`, and `.kube`, borrowed gitdir metadata whose
`core.worktree` or linked-worktree `gitdir` pointer does not bind the requested root,
credential/private paths, separator-based `.env` backups, backed-up credential filenames,
camelCase credential names, underscore-, tilde-, and copy-suffixed raw database backups,
raw database backup names without separators,
password/API-key JSON and command evidence names including split `api/key` components,
unreadable or unstatable file evidence, symlink evidence before target resolution,
swapped symlink evidence, symlink parent components rechecked at file use,
opened file identity drift, oversized file-hash evidence,
missing or non-regular file-hash evidence, JSON path absence, malformed evidence
maps, JSON scalar type mismatches, writes, missing evidence, and malformed predicate
documents fail closed with
`PredicateContractError`. Boolean composition validates every child before
aggregating results, so unsupported adapters cannot be hidden behind short-circuit
success. Git `core.repositoryformatversion` values `0` and `1` are accepted when
the remaining metadata is valid, and empty strings are valid JSON/command scalar
evidence values. It does not call
OpenClaw, Gateway, Cron, or a production database, and it does not grant trust or
approval authority.

The second P1.2 slice lives in `agentic_os.pass_gates`. It is a local-only
transactional writer for the approval, one-use gate clock, independent verifier,
gate evidence, risk assessment, and PASS `gate_runs` rows required before a
transition can be trusted. `record_approval_pass_gate` updates the existing
transition with an exact approval binding, creates the single-use
`gate_clock_context` from the local writer wall clock after the caller-supplied
epoch/hash pair proves it is current, resamples that trusted clock inside the
write transaction before approval expiry is evaluated, verifies the complete
migration/schema/SLO registry under the same write lock, records a same-run
independent verifier with non-empty independence proof and a verifier run id
that cannot reuse the worker run id, binds bounded evidence to the producer run only
when the evidence path is safe for retrieval, avoids private credential
artifacts, symlinks, and hard-linked aliases, streams artifact hashing under the
same evidence size cap as predicates, and rechecks the no-symlink path plus
identity, SHA-256, and size immediately before commit while storing normalized
repo-relative evidence paths. The writer also requires
the supplied gate identity to match the current registered
`Completion gate before done for R2+` SLO and migration hash, rejects terminal
runs instead of accepting retroactive gates, and checks every blocking runtime
SLO before commit. SQLite runtime sidecars (`-wal`, `-shm`, and rollback
journals) must be non-symlink private files before writing and are enforced back
to `0600` after WAL setup; the control database itself cannot have hard-linked
aliases, and sidecars cannot have hard-linked aliases.
Expired approvals, reused pass-gated transitions, same-worker verifiers, missing
target fields, malformed transition target hashes, stale/fabricated evidence,
stale/fabricated gate clocks, caller-stale approval-expiry clocks, lower risk
ceilings, malformed SHA-256 authorities, unsafe evidence aliases, lax SQLite
sidecars, symlinked sidecars, hard-linked SQLite sidecars, hard-linked control
databases, worker/verifier run id reuse, and
`db_authority_canary` / `db_authority` runs fail closed without granting trust.
The writer does not call OpenClaw, Gateway, Cron, or any production authority
surface.

The third P1.2 slice lives in `agentic_os.slo_audits`. It is a local-only
transactional writer for one named executable `slo_audits` row at a time.
`record_slo_audit` opens an already migrated private SQLite control database,
enters `BEGIN IMMEDIATE`, verifies the complete migration/schema/SLO registry
under the write lock, resolves the exact current `slo_queries` identity for the
requested query name, executes that pinned SQL text, and records `pass` only
when the result set is empty and the audit is bound to an existing approval-bound
PASS `gate_runs` row, matching `evidence_hashes` artifact digest, exact gate
clock context, gate-time file-authority snapshot, and independent
`judge_verifier_runs` row; accepted PASS rows first execute isolated empty and
fixture database probes, and only real PASS probe results are recorded for trust
promotion. Non-empty
pinned-query results are recorded as `fail` without granting trust. Unknown
query names, registry drift, malformed or
far-future audit clocks, missing approval-bound PASS evidence, evidence hash /
artifact digest mismatches, same-worker verifier evidence, and
`db_authority_canary` / `db_authority` evidence or gate-time snapshots fail
closed. This slice does not run every SLO, bind goal runs,
promote trust, call OpenClaw/Gateway/Cron, or enable production database
authority.

The fourth P1.2 slice lives in `agentic_os.goal_runs` plus migration v12. It
records Standing Goal runs through a local-only SQLite writer and binds
`goal_runs.evidence_hash` to existing same-run, approval-bound PASS-gate
evidence with an independent verifier whose verifier run id cannot reuse the
worker run id. Gate-time authority snapshots, current PASS-gate SLO identity,
trusted clock context, artifact digest, and retrievable evidence metadata are
validated before binding; bound verifier proof and evidenced goal rows are
frozen. Required goal-run approvals must carry SHA-256-shaped approval evidence
and still be unexpired against the local writer or SQLite current clock. The
writer rechecks the evidence artifact immediately before commit. Forged evidence
hashes, wrong-run evidence, artifact digest mismatches, stale gate identity,
incomplete evidence metadata, non-PASS or non-independent evidence, missing
`run_id` bindings, database-authority runs, spoofed authority snapshots, expired
or malformed approvals, deletes of evidenced goal runs, and attempts to rewrite
an established goal-run evidence binding fail closed. This slice does not
promote trust, call OpenClaw/Gateway/Cron, or enable production database
authority.

The fifth P1.2 slice lives in `agentic_os.trust_promotion` plus migration v13.
It records active `trust_observations` only through a local-only `BEGIN
IMMEDIATE` writer after the database proves same-run goal evidence, an
approval-bound PASS gate, independent verifier proof, trusted gate clock,
gate-time file-authority snapshots, a current under-lock blocking-SLO recheck,
complete current SLO PASS audit rows with writer provenance, and known-only
usage/cost across the trusted workflow's selected run budgets, selected model
cost rows, non-human budget events, and final settlements. Those PASS audits
must be no older than the bound gate clock and must have append-only write-event
evidence after trusted workflow budget, external RPC, run-budget, settlement,
lease, spawn-request, session, and run lifecycle inputs. Migration v13 aborts on active
legacy unbound trust rows, adds exact binding columns and a deterministic
`agentic_trust_binding_hash(...)`, and rejects direct active inserts unless
those fields match the bound evidence view and the requested scope/severity match
the proven run/goal risk boundary, the effective group equals the binding hash,
the current risk assessment still binds to the trusted transition, and the
registered SQL functions can re-hash the evidence artifact and rerun the
current blocking SLO contracts. Unknown or
estimated usage/cost anywhere in the trusted workflow, self-verifier evidence,
wrong-run evidence, stale or
missing latest SLO audits, forged direct PASS audit rows, database-authority
snapshots, changed evidence artifacts, malformed binding hashes,
mutated PASS-gate approval hashes, mutable SLO evidence events, post-promotion budget/SLO/schema/SLO
registry evidence changes before invalidation, same-workflow budget settlement
changes, runtime SLO input inserts in the trusted workflow, unbound external RPC
intents, leases, spawn requests, sessions, run rows, predicate-plugin identity
or sensitive approval timestamp drift, bound goal-run sandbox drift,
pre/post-promotion goal-manifest identity drift, workflow
authority drift, risk-assessment drift, duplicate active bindings, and active-row rewrites fail
closed without authoritative trust writes. Active rows can still be invalidated
by setting `invalidated_at`, but cannot otherwise be changed or reactivated.
This slice does not call OpenClaw, Gateway, Cron, request external review, or
enable production database authority.

The first P1.0 executable budget fixture pack lives under
`tests/fixtures/budgets/` plus `tests/fixtures/sqlite_type_affinity_h1_h4.sql`.
`MigrationTests.test_p1_budget_sql_fixture_pack_exercises_blocking_slos`
applies each fixture to a fresh migrated database and proves the expected
blocking SLO query fires. The current pack covers the named Issue #4 fixture
matrix slice for post-dispatch consume-over-budget, consume carrying retry or
human-attention units, cross-dimensional retry decrement/restore payloads,
duplicate/replayed budget events, selected model/cost-row binding mismatches,
and max+1 SQLite type-affinity cost bounds. Concurrent reserve oversubscription
and non-finite legacy money conversion remain pinned by runtime tests, not static
SQL fixtures.

`agentic_os.budgets` is the first P1.0 runtime slice. It opens mutating
connections in verified WAL mode, records pre-RPC reserve and release events
under `BEGIN IMMEDIATE`, updates counter caches in the same transaction, pins
the selected transition and endpoint-bound cost row, derives a conservative
integer-microusd cost floor from that registry row, requires an exact
same-run/same-transition spawn request, stamps events only from a persisted
same-run/same-transition trusted gate/order clock context, requires the owning
run to remain in pre-dispatch `candidate` state, refuses prior unknown usage and
post-intent reserve or release writes, and re-runs every pinned blocking budget
SLO, including duplicate live dispatch, plus runtime ledger-contamination checks
before commit. Those contamination checks include per-spawn reserve/release,
retry, and pure `human_attention` bindings.
Release checks outstanding amounts, including pure `human_attention`
consumption rows, and the remaining token-cost floor per spawn request, so one
request cannot release another request's reservation or leave its remaining tokens
underfunded. The API is idempotent on a caller key and separately rejects
reused source dedupe identities. It does not yet claim end-to-end
`sessions_spawn` settlement. Migration v4 keeps the referenced reserve selection
immutable, rejects direct post-intent reserve/release imports, and permits only
ledger-backed atomic counter cache changes for post-dispatch events. The runtime now records `consume`, retry
decrement/restore, and pure
`human_attention` only for an exact accepted session/spawn/intent tuple;
`consume` additionally requires a completed session. These post-dispatch
mutations require an active automatic dispatch state, no duplicate live dispatch,
a fresh trusted clock after both the spawn request and accepted session proof, and
no prior unknown usage poison except for exact idempotent replay. Known and
estimated usage move outstanding
reservations into consumed counters, while unknown completed usage is persisted
only as a zero-amount classification and marks the run budget unknown so later
automatic budget work fails closed. Migration v5 versions the retry prefix SLO
so every reserve/consume/release/retry/human-attention prefix window is scoped
by run, transition, spawn request, and capability; migration v6 versions the
post-dispatch SLO guards for request/accepted timing, selected cost-row binding,
and consume confidence/amount pairing. Migration v7 records the trusted clock
context on post-dispatch budget events, re-freezes referenced reserve identity
including replay and clock keys, freezes accepted post-dispatch usage ledger rows
against update/delete, and versions the current SLO proof so post-dispatch events
must bind to the selected reserve transition and one-use trusted clock. Accepted
post-dispatch replay keys and accepted `sessions_spawn` request/accepted epoch
timing are immutable once they become settlement proof.
Migration v8 adds immutable, exactly-once `budget_settlements` proof. The
`settle_budget` API requires an exact completed session and trusted post-accept
clock, then atomically records remaining terminal usage and releases every
unused reservation dimension under one `BEGIN IMMEDIATE` transaction. Linked
ledger events share a settlement identity; incomplete direct imports are
blocking SLO evidence, selected cost-row outstanding proof is rechecked in the
database trigger, source dedupe identity is shared with post-dispatch events,
completed-session proof is frozen in the database and revalidated by the v8 SLO,
cross-table source dedupe reuse is rejected by the database, fresh direct
settlement rows are rejected after the run advances beyond completed child or
aggregation states, conflicting replays fail closed, and concurrent final
settlements cannot create two terminal proofs.
Migration v9 adds an explicit legacy terminal-usage import contract for
`legacy_budget_terminal_usage_v1` rows whose only money unit is `usd_decimal`.
The migration pins the accepted source version/table on immutable batch rows and
binds child quarantine/promotion evidence inserts to the completed parent
status/counts. The importer requires that source object to be a real SQLite
table, validates each original SQLite storage class before conversion, and
converts Python `Decimal` values into integer microusd without context rounding
or unbounded negative-exponent scaling. Read failures, schema failures, malformed
rows, and incoming duplicate settlement identities with different raw payloads
all become durable quarantine evidence and payload-hash input, and any quarantine
promotes zero authoritative rows for the whole batch. Quarantine identity
includes a deterministic source-row ordinal, so duplicate malformed legacy rows
remain separately durable. Clean batches promote through the v8 final settlement
runtime path, so imported settlements always have linked budget events; exact
replay is idempotent, while reused batch, idempotency, or dedupe identity with
changed raw legacy payload fails closed.

`verify` accepts only an offline, checkpointed SQLite snapshot. It fails closed
if a sibling `-wal`, `-shm`, or `-journal` file exists; use SQLite's backup API
to produce the snapshot instead of copying a live database file.

The packaging/retrieval boundary must call
`agentic_os.privacy.assert_paths_retrievable`. Raw databases, WAL/SHM files,
SQLite files, dot-suffixed database copies, and backup trees are denied unless
an explicit local-recovery caller opts in. External session and allow-lease
integrations must pass the
validators in `agentic_os.metadata`; these validators are probes, not runtime
integration proof.
`agentic_os.metadata_dispatch` adds a pure fake-adapter dispatch probe for the
same boundary. It covers allowLease acquire/status/release and session
spawn/status/list/result metadata, including idempotent replay identity, without
making OpenClaw RPCs, changing Gateway configuration, starting a reconciliation
scanner, or enabling database authority.
`agentic_os.openclaw_adapter`, `agentic_os.runtime_dispatch`, and
`agentic_os.reconciliation` add the next bounded Issue #5 slice: an injectable
metadata-capable adapter contract, a DB-persisted pending-intent runtime
dispatcher, history-backed session result metadata parity, exact accepted
lease/session persistence, owned-lease cleanup on
spawn metadata failure, and a fail-closed scanner that reconciles unknown
or crash-left pending outcomes only from list/status metadata. Normalized
metadata is never promoted to raw evidence; OpenClaw responses must expose raw
metadata JSON from the external boundary. Ambiguous `sessions_spawn` transport
failures are persisted as `human_review_required` instead of adapter retries;
pre-existing crash-left unknown rows remain scanner inputs only. Prior
`pending`, `unknown`, `failed`, or `human_review_required` spawn attempts are
preserved without crossing `sessions_spawn` again. Release-pending leases are
reconciled from exact release metadata. Acquire-only leases are released with
the original release idempotency key only when durable state proves the spawn
was blocked before the external call; crash-left, zero-observation, and
ambiguous spawn outcomes retain the lease for human review. An immutable
schema-backed dispatch relation binds each spawn to its exact
lease/client/acquire/release identity, preventing reconciliation from releasing
another dispatch's lease on the same run/transition. Unknown or pending spawn
reconciliation also requires the bound allowLease acquire intent to be accepted
or reconciled into the exact acquired local lease with a non-empty Gateway lease
identity; otherwise the spawn is moved to human review even when `sessions_list`
contains matching session metadata. Runtime tool catalog preflight fails closed
unless allowLease acquire/status/release are present with owner metadata and
`sessions_spawn` declares the caller `metadata` parameter as well as
`client_request_id`, `idempotency_key`, and `gateway_lease_id`; history-backed
result responses must match the requested session at the top level and in any
history item identity they expose. Live run/phase/agent arbitration occurs in
the initial intent
transaction: prior pending, unknown,
accepted, reconciled, or unresolved human-review attempts block a competing
dispatch before another lease or spawn RPC, while terminal pre-spawn failures do
not permanently occupy the slot. Migration v10 backfills pre-existing bindings
only from an exact one-to-one identity and request-timestamp proof and aborts on
unbound or ambiguous legacy rows rather than silently skipping reconciliation.
Post-v10 `sessions_spawn` intents are rejected unless the exact runtime dispatch
binding already exists, including the bound reserve budget event, and
accepted/reconciled replay requires matching local `spawn_requests` plus
`sessions` proof instead of trusting the external intent row alone.
Unknown or pending `sessions_spawn` outcomes are never retried; zero, ambiguous,
mismatched, or incomplete session-identity observations move to human review.
Migration v15 versions the strict-prior-reserve SLO identity and recreates the
prior-reserve insert/update triggers so `sessions_spawn` intents fail closed
unless the reserve event also matches
`run_budgets.selected_reserve_transition_id`. It aborts before installing the
new SLO identity when active trust rows still exist under the previous bundle.
Schema versions 1 through 14 keep their historical query hashes so already
migrated databases can still verify and upgrade instead of failing closed on
immutable `slo_queries` registry drift.
The same v15 migration preserves the historical v1 DDL hash while adding
forward-only release-owner binding: accepted or reconciled `allow_lease_release`
evidence must echo `client_lease_id`, `release_idempotency_key`, `run_id`,
`phase`, `transition_id`, `agent_id`, `requester_agent_id`, and
`gateway_lease_id`, and release-proof triggers join on that full owner identity
rather than only run/transition/key/gateway. Upgrading v14 databases must also
pass the same full-owner proof for existing `released` leases and terminal
Gateway-owned `expired` / `human_review_required` leases before v15 installs
the forward-only triggers.

Issue #35 adds sanitized live runtime evidence for that boundary. The committed
evidence in `docs/runtime-evidence/issue35-live-openclaw-20260721.json` captures
OpenClaw 2026.7.1 installed catalog source hashes and proves the current runtime
does not satisfy the exact Agentic OS contract. The forward-only correction
index in `docs/runtime-evidence/phase-b-20260811-evidence-index.json`
supersedes the earlier combined-catalog interpretation without rewriting
historical JSON. `tools.catalog` proves model-callable tool names, but the real
response may omit parameter schemas; parameter claims are then either bound
explicitly to hashed installed sources or marked unproven. Installed source
files declare all three allowLease RPC names, while the read-only-request
`subagents.allowLease.status` call proves reachability only for `status`.
Acquire/release reachability and the connected Gateway build identity remain
unproven; `status` may clean expired leases and CLI bootstrap may write local
state. The corrected local candidate binds the TypeScript runtime contract as
provider authority: `subagents.allowLease.status` is an exact empty-parameter
RPC and the Agentic OS `sessions_spawn` surface is the exact 12-field contract
(`task`, `taskName`, `runtime`, `mode`, `agentId`, `cleanup`, `context`,
`lightContext`, `client_request_id`, `idempotency_key`, `gateway_lease_id`, and
`metadata`). The installed singular `session_status(sessionKey)` surface is the
canonical status contract; it is not a readiness blocker by itself.
Issue #44 recaptured installed OpenClaw 2026.7.1 from exact generator head
`b4d1d358382bd03e38829473ba77586033a69a53` in
`docs/runtime-evidence/phase-b-issue44-live-installed-preflight-20260824.json`.
That preflight deliberately used `--skip-live-status-rpc` because the installed
`subagents.allowLease.status` path may perform incidental lease cleanup. It is
therefore a fail-closed, no-production-lease-mutation record: disk source
declarations for allowLease RPCs are preserved, but live reachability, connected
Gateway build identity, model-callable catalog availability, and
`agenticOs.runtime.attest` readiness remain unproven. The plain-catalog path is
deliberately offline-only: it reports
`classification=offline_schema_validation_only` and can never set
`runtime_ready=true`. An unsigned catalog mapping cannot mint
`OpenClawAdapter` runtime authority. Direct construction remains disabled; the
local P0.3 factory requires a fresh signed transport-bound attestation and
rejects missing or extra parameters before every application RPC. The future
CLI subprocess transport remains non-authoritative unless it gains a persistent
attested connection or a follow-up token authorization path; there is no
`agenticOs.runtime.identity` RPC to refresh. That contract is covered only by
synthetic local tests, installed fail-closed preflight, and the local downstream
candidate proof below; it is still not production authority. The
cross-process release-probe entry point likewise rejects unsigned stdin before
invoking transport. The bounded accepted-session
probe in
`docs/runtime-evidence/issue35-live-accepted-session-probe-20260721.json`
therefore fails closed before any Gateway lease or session RPC is attempted.
If a future runtime passes preflight, the probe validates duplicate session
identity plus session-local normalized/raw metadata contract evidence from
direct structured `sessions_spawn` responses and treats any allowLease release
failure as a failed probe.
The 2026-08-09 installed-runtime negative preflight in
`docs/runtime-evidence/phase-b-20260809-installed-negative-baseline.json` also
failed closed before any runtime contract proof was available. Its original
bytes are frozen. The forward index marks its stored generator binding invalid
because the stored script digest does not match the script at its bound head,
and marks its combined-catalog interpretation superseded because it conflated
model-callable `tools.catalog` evidence with Gateway source declarations.
`DB_AUTHORITY_ENABLED` remains `False`.

The current Issue #44 candidate proof for the downstream runtime surface is the
isolated real-Gateway probe. It refuses dirty candidate worktrees, binds
downstream OpenClaw head `06e6e3f424841d738ec18dbe6a1faac663fe2cb6`, adapts to
the candidate's `scripts/agentic-os-persistent-lifecycle-runner.mts` harness
when the legacy E2E file is absent, starts the candidate's token-authenticated
Gateway with isolated runner and Gateway state, and writes hash-only evidence:

```bash
python3 scripts/openclaw-real-gateway-contract-probe.py \
  --openclaw-root /path/to/openclaw-candidate \
  --evidence-file docs/runtime-evidence/phase-b-issue44-downstream-persistent-lifecycle-20260824.json
```

The committed Issue #44 JSON at that path has `status=pass`,
`runtime_ready_candidate_evidence=true`, and `runtime_ready=false`. It proves
the candidate's `agenticOs.runtime.attest`, `tools.catalog` corroboration,
allowLease acquire/status/release, accepted `sessions_spawn`, duplicate spawn
identity parity, `sessions_list`, `session_status`, `sessions_history`, release
cleanup, candidate port closure, production config hash stability, zero
provider-secret environment leakage, and `DB_AUTHORITY_ENABLED=False`. It is
only a sanitized Phase B candidate snapshot until a different-agent Phase C pass
reruns from the exact final head before any review request or production
runtime-readiness claim.

The legacy probe path still exercises the runtime-discovered `tools.catalog`
RPC methods, principal-bound allowLease acquire/duplicate/status/release,
concurrent spawn deduplication, canonical session reads, canonical child
lifecycle transitions, fail-closed authorization, and the real
`spawnSubagentDirect` child runner when the downstream candidate provides the
legacy E2E harness.
`agentic_adapter_*` release proofs are explicitly disabled future-contract
proofs in this repository state: the cross-process adapter release entry point
rejects unsigned input and is not injected into the candidate E2E until a
verified in-process adapter handoff exists. Direct handler imports, hand-written
catalogs, mocked Gateway calls, disabled adapter proofs, and dirty exact-head
evidence are rejected as non-authoritative.

## Version-management policy

- `main` contains reviewed project state.
- Implementation work should use focused branches and pull requests.
- Every PR must wait for a completed GitHub Codex review; any P0/P1 finding blocks merge.
- The required non-vacuous GitHub Actions check identity is `agentic-os-ci`,
  pinned in `.github/agentic-os-ci-contract.json` and covered by
  `tests/test_ci_contract.py`.
- After Codex is clean for the exact current head, the watcher may auto-merge
  only after CAS-checking the reviewed SHA, required checks, and merge state;
  head changes, missing checks, or ambiguous review state fail closed.
- Design changes must preserve executable DDL/SLO validation and adversarial fixtures.
- Production readiness must be backed by runtime evidence, not document-only acceptance.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the enforced review workflow and review guidance.

## License

No open-source license has been granted yet. All rights reserved.
