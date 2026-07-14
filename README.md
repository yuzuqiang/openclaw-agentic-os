# OpenClaw Agentic OS

Production-oriented control-plane design and implementation workspace for OpenClaw's Agentic OS workflows.

## Current status

The initial design artifact passed dual independent design acceptance. The
current corrected design artifact has **not** yet passed fresh independent
revalidation, and neither artifact proves production runtime behavior.

- Design: [`docs/agentic-os-production-adaptation.md`](docs/agentic-os-production-adaptation.md)
- Last independently accepted design artifact SHA-256: `fdbc432dc8ce7bcbc5ced08291503bbd171417fe63217a2b565f5ae31c0f458d`
- Current design artifact SHA-256: `69887add0ce8c19b9f9408e7df801a04484186bdd26e5e3e7b7940860c17b19a`
- Base DDL migration SHA-256: `2a06f894952629523a4c1671148ce47dd7345a2340128713143fdff904486a01`
- Current latest migration SHA-256: `770a7d588edb7b578954c01ee85f69cdeca1e3d1a43d43d0df7a941a6da1336c`
- Current migration manifest SHA-256: `dd4a836947a7a2057f9656f6bb6b1bad28a40fc3080c13084674dda2150e4e55`
- Design contract: 27 baseline SQLite tables plus one compatibility archive table, 30 executable SLO queries
- Remaining implementation scope: P0/P1 schema, adapters, reconciler, predicate runner, crash fixtures, rollback drills, and production smoke tests

The current P0 foundation materializes the corrected schema and supplies
fail-closed privacy and external-metadata probes. Database authority remains
disabled (`agentic_os.DB_AUTHORITY_ENABLED is False`), and no OpenClaw runtime
adapter is implemented yet.

## Foundation commands

The package has no runtime dependencies outside Python's standard library.

```bash
PYTHONPATH=src python3 -m agentic_os.cli preflight
PYTHONPATH=src python3 -m agentic_os.cli migrate --test-db
PYTHONPATH=src python3 -m agentic_os.cli shadow-backfill --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --artifact README.md
PYTHONPATH=src python3 -m agentic_os.cli shadow-audit --db state/agentic-os/test-control.db --workflow heartbeat --run-id shadow-demo --prepare-idempotency-key file-shadow:shadow-demo --artifact README.md
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

The first P1.0 executable budget fixture pack lives under
`tests/fixtures/budgets/` plus `tests/fixtures/sqlite_type_affinity_h1_h4.sql`.
`MigrationTests.test_p1_budget_sql_fixture_pack_exercises_blocking_slos`
applies each fixture to a fresh migrated database and proves the expected
blocking SLO query fires.

`agentic_os.budgets` is the first P1.0 runtime slice. It opens mutating
connections in verified WAL mode, records pre-RPC reserve and release events
under `BEGIN IMMEDIATE`, updates counter caches in the same transaction, pins
the selected transition and endpoint-bound cost row, derives a conservative
integer-microusd cost floor from that registry row, requires an exact
same-run/same-transition spawn request, stamps events only from a persisted
same-run/same-transition trusted gate/order clock context, requires the owning
run to remain in pre-dispatch `candidate` state, refuses prior unknown usage or
post-intent reserve writes, and re-runs every pinned blocking budget SLO plus
runtime ledger-contamination checks before commit. Those contamination checks
include per-spawn reserve/release, retry, and pure `human_attention` bindings.
Release checks outstanding amounts, including pure `human_attention`
consumption rows, and the remaining token-cost floor per spawn request, so one
request cannot release another request's reservation or leave its remaining tokens
underfunded. The API is idempotent on a caller key and separately rejects
reused source dedupe identities. It does not yet claim end-to-end
`sessions_spawn` settlement. Migration v4 keeps the referenced reserve selection
immutable while permitting only ledger-backed atomic counter cache changes for
post-dispatch events. The runtime now records `consume`, retry
decrement/restore, and pure
`human_attention` only for an exact accepted session/spawn/intent tuple;
`consume` additionally requires a completed session. These post-dispatch
mutations require an active automatic dispatch state, a fresh trusted clock
after the accepted session proof, and no prior unknown usage poison except for
exact idempotent replay. Known and estimated usage move outstanding
reservations into consumed counters, while unknown completed usage is persisted
only as a zero-amount classification and marks the run budget unknown so later
automatic budget work fails closed. Migration v5 versions the retry prefix SLO
so every reserve/consume/release/retry/human-attention prefix window is scoped
by run, transition, spawn request, and capability. Atomic final settlement of
unused reservation, legacy-money
import conversion, and the remaining adversarial fixture matrix remain open in
Issue #4.

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

## Version-management policy

- `main` contains reviewed project state.
- Implementation work should use focused branches and pull requests.
- Every PR must wait for a completed GitHub Codex review; any P0/P1 finding blocks merge.
- After Codex is clean for the exact current head, the watcher CAS-checks the
  head and required checks, then auto-merges into `main`; ambiguity fails closed.
- Design changes must preserve executable DDL/SLO validation and adversarial fixtures.
- Production readiness must be backed by runtime evidence, not document-only acceptance.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the enforced review workflow and review guidance.

## License

No open-source license has been granted yet. All rights reserved.
