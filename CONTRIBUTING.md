# Contributing

## Pull request workflow

1. Create a focused branch from current `main`.
2. Link the GitHub issue and describe the design-contract scope.
3. Add implementation and adversarial tests.
4. Run all relevant verification and record exact results in the PR.
5. Open the pull request without merging it.
6. Trigger GitHub Codex review with an exact `@codex review` PR comment, unless an automatic review has already started.
7. Wait for Codex to post its GitHub review. Any P0/P1 issue blocks merge.
8. Fix every blocking finding, push the changes, and request `@codex review` again.
9. Repeat until Codex reports no blocking P0/P1 findings.
10. River performs the final audit and merges the PR into `main`.

Implementation agents must not merge their own pull requests. A green local
test suite is necessary but does not replace GitHub Codex review.

## Production evidence

Design-level SQLite checks are not production proof. Production-readiness
claims require implemented runtime probes, crash fixtures, rollback drills,
privacy guards, and observed smoke-test evidence.
