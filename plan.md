# P0.3 — Transport-bound OpenClaw Adapter Attestation + Heartbeat Shadow Pilot

## Objective

Connect `openclaw-agentic-os` to the currently installed OpenClaw/Gateway through a transport-bound, fail-closed runtime adapter, prove one real accepted-session lifecycle, and shadow the Heartbeat workflow without granting database or production authority.

## Baseline

- Repository: `yuzuqiang/openclaw-agentic-os`
- Base: remote `main` at `bf06585a9b8603001050a47af2840586d38c0a8d`
- Worktree: clean isolated worktree; the stale/dirty shared checkout is out of scope
- Installed OpenClaw CLI: `2026.7.1` (`2d2ddc4`)
- Connected Gateway: `2026.7.1`, loopback, connectivity probe `ok`
- Current authority: file artifacts
- Required flag throughout P0.3: `agentic_os.DB_AUTHORITY_ENABLED == False`

## Hard Boundaries

1. Never write to `openclaw/openclaw`.
2. If the installed OpenClaw contract is insufficient, keep any OpenClaw change local/downstream and independently evidenced.
3. Do not mutate OpenClaw config, Gateway service state, Cron, production authority, or file-artifact authority merely to make a probe pass.
4. Do not automatically retry `sessions_spawn` after an unknown outcome.
5. Do not bind leases or sessions by proximity, agent id alone, prompt text, or timestamps.
6. Do not enter `db_authority_canary` or `db_authority` during the first shadow slice.
7. Live external calls require explicit preflight, exact target binding, bounded cleanup, and durable receipts.

## Phase 1 — Exact Runtime Evidence Recapture

- [ ] Capture the exact Agentic OS head/tree and clean-worktree state.
- [ ] Capture the active OpenClaw executable path/content hash, CLI version, install-root/source hashes, Gateway version/build identity, endpoint, and connectivity state.
- [ ] Capture model-callable `tools.catalog` plus source-bound parameter evidence without treating absent schemas as empty schemas.
- [ ] Probe the real installed surfaces for:
  - `subagents.allowLease.acquire`
  - `subagents.allowLease.status`
  - `subagents.allowLease.release`
  - `sessions_spawn`
  - `sessions_list`
  - canonical session status
  - `sessions_history`
- [ ] Rebind `docs/runtime-evidence/phase-b-20260811-evidence-index.json` to an exact clean generator revision and source digest set.

### Gate 1

- Evidence index is no longer `pending_clean_generator_revision_capture`.
- Every reachability/schema/build assertion is proven or explicitly fail-closed.
- No production adapter authority is minted by offline or unsigned evidence.

## Phase 2 — Transport-bound Runtime Contract

- [x] Implement a transport-bound attestor that binds one exact OpenClaw executable/install root, connected Gateway identity, catalog/source evidence, and live challenge result.
- [x] Permit `OpenClawAdapter` construction only from a verified, unexpired attestation for the same exact transport target.
- [x] Prove round-trip support for:
  - `client_request_id`
  - `idempotency_key`
  - `run_id`
  - `phase`
  - `transition_id`
  - `agent_id`
  - `requester_agent_id` where applicable
  - `task_digest`
- [x] Require accepted lease/session responses and list/status/history observations to echo the same normalized and raw metadata plus a non-empty external identity.
- [x] Add focused negative tests for stale build, source drift, endpoint drift, unsigned mapping, missing metadata, mismatched metadata, expired attestation, and cross-process replay.

### Gate 2

- Real runtime capability preflight passes for the exact connected instance.
- `OpenClawAdapter` remains unavailable for all non-attested transports.
- `DB_AUTHORITY_ENABLED` remains `False`.

## Phase 3 — Real Accepted-session Lifecycle

- [ ] Run one bounded real lifecycle:
  1. acquire lease
  2. duplicate acquire with the same idempotency key
  3. status observation
  4. spawn session
  5. duplicate spawn with the same idempotency key
  6. list/status/history identity reconciliation
  7. idempotent release
- [ ] Prove duplicate acquire returns the same lease and creates no additional live lease.
- [ ] Prove duplicate spawn returns the same session and creates no additional child.
- [ ] Prove release ownership and post-release absence.
- [ ] Exercise post-RPC/pre-DB and post-DB/pre-ack crash windows.
- [x] Route unknown spawn outcomes to `human_review_required` with no automatic retry.
- [ ] Persist sanitized receipts, timings, hashes, and cleanup evidence.

### Gate 3

- Accepted-session end-to-end probe passes.
- Idempotent acquire/spawn/release ownership checks pass.
- Zero orphan leases and zero duplicate children remain after cleanup.
- Crash-window recovery fails closed exactly as designed.

## Phase 4 — Heartbeat File-authority Shadow Pilot

- [x] Select only the Heartbeat workflow as the pilot.
- [x] Keep existing Heartbeat files as the sole operational authority.
- [x] Backfill a local ignored shadow `control.db` from the file artifacts.
- [x] Record DB projections and parity evidence without allowing DB rows to control dispatch or decisions.
- [x] Run Heartbeat through `file_authority_shadow`, then `dual_write_shadow` only after parity preflight passes.
- [x] Prove forced rollback recreates the exact file-authority view and leaves no production session/lease authority behind.
- [ ] Start a bounded 24–72 hour soak with periodic parity/SLO receipts.

### Gate 4

- File/DB projection parity is 100% for the full observation window.
- Zero duplicate spawn, orphan lease, unknown/unowned session, privacy violation, or projection drift.
- Rollback to file authority passes.
- `DB_AUTHORITY_ENABLED` remains `False` for the entire pilot.

## Phase 5 — Cutover Decision, Not Global Cutover

- [ ] Independently verify the exact full head, evidence hashes, live receipts, shadow parity, and rollback proof.
- [ ] Keep the PR Draft until Phase C passes the exact head.
- [ ] Request external review only after exact-head Phase C PASS.
- [ ] Define the next separate lifecycle for Heartbeat:
  `dual_write_shadow -> db_authority_canary -> db_authority`.
- [ ] Migrate later workflows one at a time; never batch all workflows into one authority switch.

## Required Artifacts

- `docs/runtime-evidence/` exact-head runtime catalog, build, attestation, lifecycle, cleanup, crash-window, and soak receipts
- Updated forward evidence index with immutable historical evidence preserved
- Focused adapter/attestor and negative-contract tests
- Heartbeat shadow/parity/rollback fixtures and runtime receipts
- Exact-head completion-gate and independent-verifier reports
- A Draft PR in `yuzuqiang/openclaw-agentic-os` only

## Completion Criteria

P0.3 is complete only when all of the following are true:

- [ ] Evidence index is current and exact-head/source bound.
- [ ] Real runtime preflight passes for the connected OpenClaw/Gateway instance.
- [ ] Real accepted-session lifecycle passes end to end.
- [ ] Duplicate acquire/spawn and release ownership proofs pass.
- [ ] Heartbeat shadow soak completes with zero drift or leakage.
- [ ] Forced rollback restores file authority.
- [ ] Independent exact-head validation and configured repository gates pass.
- [ ] `agentic_os.DB_AUTHORITY_ENABLED == False` and production authority remains disabled.

## Key Principle

Prove safe, idempotent control of one real OpenClaw session and one shadowed workflow before granting Agentic OS any production authority.
