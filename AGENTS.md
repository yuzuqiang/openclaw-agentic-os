# Repository guidance

This repository implements the current Agentic OS production design contract for OpenClaw.
README tracks the last independently accepted design hash separately from the
current corrected artifact hash.

## Working rules

- Treat `docs/agentic-os-production-adaptation.md` as the design contract.
- Keep production authority disabled until the required P0/P1 evidence passes.
- Use focused branches and pull requests; implementation agents must not merge.
- Preserve fail-closed behavior when external metadata, identity, budget, clock, approval, or verifier evidence is incomplete.
- Never commit runtime databases, WAL/SHM files, backups, credentials, or private artifact payloads.

## Verification

- Run the full project test suite before requesting review.
- Compile migrations with SQLite foreign keys enabled.
- Run privacy, schema, SLO, and adversarial fixtures affected by the change.
- Report exact commands and results in the pull request.

## Review guidelines

- Treat any violation of the accepted DDL/SLO contract as P1 or higher.
- Treat fail-open external metadata, session identity, budget, approval, clock, predicate, or verifier behavior as P1 or higher.
- Treat committed private runtime state, credentials, database files, WAL/SHM files, or backups as P1 or higher.
- Require tests for migration integrity, SQLite type preservation, failure boundaries, and rollback behavior.
- Flag production-readiness claims that lack runtime evidence as P1.
- Ignore cosmetic issues unless they materially weaken correctness or auditability.

## Merge gate

Every pull request must receive a completed GitHub Codex review before merge.
Any Codex P0/P1 finding blocks merge. After fixes, request `@codex review` again
and wait for a clean review of the exact current head. A clean automated review
is necessary but never grants merge authority by itself: merge still requires
separate explicit human authorization. Any watcher automation may only record the
CAS-checked reviewed head and fail closed on head changes, missing checks, or
ambiguous review state. Implementation agents must not merge directly.
