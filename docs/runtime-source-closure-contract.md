# Runtime source identity: supported boundary

This document describes the conservative source recognizer and installation
snapshot used by the persistent-runtime evidence code. It does **not** declare
production readiness or provide a JavaScript sandbox. The production authority
switch and the unconditional trusted-launcher failure boundary remain unchanged.

## Source recognition

`agentic_os_runtime_source_contract.py` builds one lexical scan view before its
non-evaluating dependency recognizers run. Hashbangs, Annex B HTML comments,
ordinary comments, quoted strings, regular expressions, and nested template
expressions share the same boundaries. Executable identifier escapes and Unicode
local names are normalized consistently; literal data is not identifier-decoded.
The scan view is never executed and is never the input to a source-file digest.
Ambiguous JavaScript slash contexts and unsupported loader syntax fail closed.

Every recognized execution capability must remain in an accounted-for import,
CommonJS binding, or supported direct invocation. Moving a Worker constructor,
child-process callable, namespace, or loader factory into another variable,
container, callback, return value, re-export, or reflective invocation is not an
implicit dependency-free operation: unsupported transfers are rejected at the
original reference. This avoids enumerating another set of alias spellings for
each subsequent call.

Supported loader forms include literal static/dynamic imports, direct literal
CommonJS calls, the existing simple `require` alias form, and directly assigned
`createRequire(import.meta.url)` / `createRequire(__filename)` loaders. Factory
results hidden behind grouping, binding, or other result transformations are not
accepted as ordinary direct assignments. The existing supported inline factory
invocations still require a literal module specifier and a local factory base.

Worker URLs constructed from `import.meta.url` resolve relative to the importing
source. In contrast, the supported literal Node CLI and `fork` script paths
resolve relative to the probe's launch working directory: the candidate root.
Those paths must identify actual in-root script files, not directory/package
fallbacks or executable flags. Working-directory mutation is rejected. Child
processes may have literal string argument lists, but computed suffixes, spread
arguments and explicit startup options are rejected: `env`, `execArgv`, `execPath`,
`cwd`, `shell` and `eval` can change which code executes.

Each parseable source contributes its existing in-root ancestor `package.json`
files to the identity snapshot, including initial entrypoints and direct relative
imports. This deliberately conservative superset detects changes to controlling
package scopes as well as newly added or removed nearer manifests.

## Preload installation identity

The `runtime-preload-installation:tsx` record is mandatory alongside the Node
launcher, resolved tsx preload file, and tsx-package records. It hashes the entire
candidate installation, with no file/directory exclusions. This includes sibling
and nested packages, native helpers, package metadata, and files outside the tsx
package that its loader may use. Hashing only tsx's own directory is insufficient.

The installation digest records paths, entry types, file modes, regular-file
content, and symlink topology. Internal pnpm-style links are supported: links are
recorded without recursively walking them, while their in-root physical targets
are hashed as part of the same tree. External or dangling links, unsupported file
types, incomplete reads, duplicate launch-source records, and an out-of-root tsx
preload fail closed. No raw installation paths or source payloads are emitted in
the launch-source records.

This snapshot is supplemental identity evidence, **not** proof that a writable
filesystem is immutable or that a process cannot load code outside it. The
unimplemented trusted external launcher must still enforce the real OS boundary,
immutable runtime sources, key/validator isolation, and independently observed
transport evidence before persistent lifecycle execution can be enabled. No such
execution or production evidence is claimed by the regression tests.

## Regression verification

The focused suite includes the six latest PR45 Codex findings, capability-transfer
matrices, loader-factory result transfers, Unicode aliases, lexical boundary
variants, actual Node comment/package-scope/preload witnesses, and installation
symlink/file-type checks. The Node witnesses use only temporary fixtures and are
skipped explicitly when Node is unavailable; CI must report whether they ran.

```sh
PYTHONPATH=src python -m unittest tests.test_runtime_source_contract_regressions -v
PYTHONPATH=src python -m unittest tests.test_openclaw_real_gateway_contract_probe -k source_closure -v
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m agentic_os.cli preflight
PYTHONPYCACHEPREFIX=/tmp/agentic-os-pycache PYTHONPATH=src python -m compileall -q scripts src tests
```
