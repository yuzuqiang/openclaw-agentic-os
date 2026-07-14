## Summary

## Linked issue

Closes #

## Design contract

- Affected P0/P1 section:
- Fail-closed boundary:

## Verification

- [ ] Full relevant test suite passes
- [ ] SQLite migrations compile with foreign keys enabled
- [ ] Privacy/schema/SLO/adversarial fixtures pass
- [ ] No runtime DB, WAL/SHM, backup, credential, or private payload is committed

Commands and results:

```text
```

## Codex review gate

- [ ] GitHub Codex review requested or automatic review observed
- [ ] Codex review completed for the exact current head
- [ ] All Codex P0/P1 findings resolved; P2 findings resolved or explicitly deferred with a linked follow-up
- [ ] Required checks passed for the exact current head

Do not manually merge while the watcher is active. The watcher CAS-checks the
reviewed head and required checks, then auto-merges; ambiguity fails closed.
