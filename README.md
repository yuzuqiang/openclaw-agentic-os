# OpenClaw Agentic OS

Production-oriented control-plane design and implementation workspace for OpenClaw's Agentic OS workflows.

## Current status

The initial design artifact passed dual independent design acceptance. The
current corrected design artifact has **not** yet passed fresh independent
revalidation, and neither artifact proves production runtime behavior.

- Design: [`docs/agentic-os-production-adaptation.md`](docs/agentic-os-production-adaptation.md)
- Last independently accepted design artifact SHA-256: `fdbc432dc8ce7bcbc5ced08291503bbd171417fe63217a2b565f5ae31c0f458d`
- Current design artifact SHA-256: `d68b5637c3894fab4f88f275e4146db58e129522f1739d34bf0e8f0e2be54bec`
- Base DDL migration SHA-256: `2a06f894952629523a4c1671148ce47dd7345a2340128713143fdff904486a01`
- Current latest migration SHA-256: `c64915607bd7f671f1e1dcffd1dc25b494f132832561fbb5c6b7855414851a2b`
- Current migration manifest SHA-256: `26d42ac5469cf7c2bd792a941c08ee40f2c44342c99a20a453f10ea987be79cf`
- Design contract: 27 baseline SQLite tables plus one compatibility archive table, one settlement proof table, three legacy import evidence tables, one runtime dispatch binding table, and one trust-promotion binding overlay, 30 executable SLO queries
- Remaining implementation scope: P0/P1 adapters, reconciler, predicate runner integrations, crash fixtures, rollback drills, and production smoke tests

The current P0 foundation materializes the corrected schema and supplies
fail-closed privacy and external-metadata probes. Database authority remains
disabled (`agentic_os.DB_AUTHORITY_ENABLED is False`).

## Foundation commands

The package has no runtime dependencies outside Python's standard library.

```bash
PYTHONPATH=src python3 -m agentic_os.cli preflight
PYTHONPATH=src python3 -m agentic_os.cli migrate --test-db
PYTHONPATH=src python3 -m agentic_os.cli shadow-backfill --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --artifact README.md
PYTHONPATH=src python3 -m agentic_os.cli shadow-audit --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --prepare-idempotency-key file-shadow:shadow-demo --artifact README.md
PYTHONPATH=src python3 -m agentic_os.cli dual-write-shadow --db state/agentic-os/test-control.db --workflow heartbeat --run-id dual-shadow-demo --risk-class R1 --risk-dominance R1 --new-workflow --artifact tmp/dual-shadow-demo.json --content '{"ok":true}'
PYTHONPATH=src python3 -m agentic_os.cli dual-write-shadow-audit --db state/agentic-os/test-control.db --workflow heartbeat --run-id dual-shadow-demo --artifact tmp/dual-shadow-demo.json
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
complete current SLO PASS audit rows, and known-only usage/cost across the
trusted workflow's selected run budgets, selected model cost rows, non-human
budget events, and final settlements. Those PASS audits must be no older than
the bound gate clock. Migration v13 aborts on active
legacy unbound trust rows, adds exact binding columns and a deterministic
`agentic_trust_binding_hash(...)`, and rejects direct active inserts unless
those fields match the bound evidence view and the requested scope/severity match
the proven run/goal risk boundary, the effective group equals the binding hash,
the current risk assessment still binds to the trusted transition, and the
registered SQL functions can re-hash the evidence artifact and rerun the
current blocking SLO contracts. Unknown or
estimated usage/cost anywhere in the trusted workflow, self-verifier evidence,
wrong-run evidence, stale or
missing latest SLO audits, database-authority snapshots, changed evidence
artifacts, malformed binding hashes, post-promotion budget/SLO/schema/SLO
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
metadata JSON from the external boundary. Ambiguous transport failures become
recoverable outcomes for reconciliation instead of adapter retries, and prior
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
contains matching session metadata. Session-tool catalog preflight fails closed
unless `sessions_spawn` declares the caller `metadata` parameter as well as
`client_request_id` and `idempotency_key`; history-backed result responses must
match the requested session at the top level and in any history item identity
they expose. Live run/phase/agent arbitration occurs in the initial intent
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

## Version-management policy

- `main` contains reviewed project state.
- Implementation work should use focused branches and pull requests.
- Every PR must wait for a completed GitHub Codex review; any P0/P1 finding blocks merge.
- After Codex is clean for the exact current head, the watcher may auto-merge
  only after CAS-checking the reviewed SHA, required checks, and merge state;
  head changes, missing checks, or ambiguous review state fail closed.
- Design changes must preserve executable DDL/SLO validation and adversarial fixtures.
- Production readiness must be backed by runtime evidence, not document-only acceptance.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the enforced review workflow and review guidance.

## License

No open-source license has been granted yet. All rights reserved.
