# Runtime source verification boundaries

The persistent lifecycle authority remains disabled. Source inventory and a clean
unit-test run do not supply the external trusted launcher, parent-held signing
keys, or direct parent-owned Gateway RPC capture required by the production
contract. Implementation agents must not remove that guard to make a probe pass.

## Source analysis

The shared Python source-contract helper accepts a conservative subset of
JavaScript and TypeScript loading syntax. It is not a general JavaScript evaluator
or a sandbox. Unsupported syntax must fail closed rather than produce an
apparently complete source closure.

Comment normalization runs before every top-level import analysis. It preserves
source positions and all ECMAScript line terminators, understands an initial
hashbang and legacy script HTML comments, and inspects executable interpolation
bodies without interpreting strings, regex bodies, or template text as code.
Ambiguous slash contexts remain rejected.

A Worker or child-process capability must be used in a complete, directly bound
launch expression. The scanner does not infer arbitrary JavaScript data flow.
Transferring a constructor, namespace, or execution function through assignment,
objects, arrays, returns, exports, callbacks, computed members, or reflection is
rejected. Simple grouped CommonJS require declarations are parsed by balanced
tokens instead of a fixed parenthesis limit; unsupported require transfers are
also rejected. Harmless `typeof require` observations remain supported.

The supported launch signatures are intentionally small: a Worker with one
literal `new URL(..., import.meta.url)` argument, a fork with one literal module
argument, or a Node child process with `process.execPath` and one literal script
argument. Options that can introduce another loader, executable, or environment
(such as `execArgv`, `NODE_OPTIONS`, `shell`, or `eval`) require a separate binding
proof and are not accepted merely because the first argument is a literal.

Every parsed module, including entrypoints and relative imports, binds its nearest
package-scope manifest. Recomputing the closure detects added, removed, changed,
or shadowing manifests. Scope lookup stops at `node_modules`; metadata symlinks
are rejected rather than collapsing a changed lookup path into an existing digest.

## Preload installation identity

Hashing only the `tsx` package directory misses hoisted and pnpm sibling packages.
Launch evidence therefore requires an additional
`runtime-preload-installation:tsx` record for the complete OpenClaw installation
inventory. It binds file bytes, file kinds and modes, directory entries, symlink
text and confined targets, package metadata, configuration, and installed native
tools. It does not execute the candidate loader while constructing the inventory.
External or dangling symlinks and non-regular files fail closed. Inventory labels
must be present exactly once; unknown or duplicate labels are not silently ignored.

The complete installation is expected to be immutable, with run outputs kept in
the separate run root. This deliberately binds more than a minimal import graph.
It is an installation identity check, not proof that arbitrary code cannot read
an external path, use another writable alias, or fabricate a transcript. Those
properties still require the disabled-by-default external trusted-launcher
boundary. A future implementation of that boundary must prove that the entire
executable namespace, including dependencies outside the installation, is either
independently bound and isolated or inaccessible.

## Regression evidence

`tests/test_runtime_source_contract_audit.py` includes the PR45 review examples,
capability-transfer variants, full-call option attacks, lexical differential
checks against Node, package-scope mutation/revalidation, and preload inventory
mutation/revalidation. The existing full suite remains required in addition to
this focused matrix. A completed Codex review of the exact final head and all
required checks remain prerequisites for merging the PR.
