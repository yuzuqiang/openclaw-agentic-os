# OpenClaw Agentic OS

Production-oriented control-plane design and implementation workspace for OpenClaw's Agentic OS workflows.

## Current status

The initial design artifact has passed dual independent design acceptance. This does **not** prove production runtime behavior.

- Design: [`docs/agentic-os-production-adaptation.md`](docs/agentic-os-production-adaptation.md)
- Current design-contract SHA-256: `6fc9b66175bdb622fce591fa096078bd50b3cc631eae5e9de67753bdea898e11`
- Design contract: 27 SQLite tables, 30 executable SLO queries
- Remaining implementation scope: P0/P1 schema, adapters, reconciler, predicate runner, crash fixtures, rollback drills, and production smoke tests

The current P0 foundation materializes the accepted schema and supplies
fail-closed privacy and external-metadata probes. Database authority remains
disabled (`agentic_os.DB_AUTHORITY_ENABLED is False`), and no OpenClaw runtime
adapter is implemented yet.

## Foundation commands

The package has no runtime dependencies outside Python's standard library.

```bash
PYTHONPATH=src python3 -m agentic_os.cli preflight
PYTHONPATH=src python3 -m agentic_os.cli migrate --test-db
PYTHONPATH=src python3 -m agentic_os.cli verify --db state/agentic-os/offline-snapshot.db
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`migrate --test-db` is also available for a deliberately ignored repo-local
test database. Tests use temporary directories and never create
`state/agentic-os/control.db`.

`verify` accepts only an offline, checkpointed SQLite snapshot. It fails closed
if a sibling `-wal`, `-shm`, or `-journal` file exists; use SQLite's backup API
to produce the snapshot instead of copying a live database file.

The packaging/retrieval boundary must call
`agentic_os.privacy.assert_paths_retrievable`. Raw databases, WAL/SHM files,
SQLite files, and backup trees are denied unless an explicit local-recovery
caller opts in. External session and allow-lease integrations must pass the
validators in `agentic_os.metadata`; these validators are probes, not runtime
integration proof.

## Version-management policy

- `main` contains reviewed project state.
- Implementation work should use focused branches and pull requests.
- Every PR must wait for a completed GitHub Codex review; any P0/P1 finding blocks merge.
- After Codex is clean, River performs the final audit and merges into `main`.
- Design changes must preserve executable DDL/SLO validation and adversarial fixtures.
- Production readiness must be backed by runtime evidence, not document-only acceptance.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the enforced review workflow and review guidance.

## License

No open-source license has been granted yet. All rights reserved.
