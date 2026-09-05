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
This includes contextual `await`/`yield` and TypeScript postfix/type-instantiation
slash contexts; `extends` is recognized as a regular-expression prefix without
confusing a property named `extends` with that keyword. Spread is a single token,
not three property-access dots. Type-only import specifiers do not grant runtime
capabilities; a real default binding named `type` is not erased.

Every recognized execution capability must remain in an accounted-for import,
CommonJS binding, or supported direct invocation. Moving a Worker constructor,
child-process callable, namespace, or loader factory into another variable,
container, callback, return value, re-export, or reflective invocation is not an
implicit dependency-free operation: unsupported transfers are rejected at the
original reference. This also applies to the `node:module` namespace and Module
constructor. CommonJS `parent`, `children`, and `paths` are not treated as harmless
metadata that may transfer loading authority. This avoids enumerating another set
of alias spellings for each subsequent call.

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

A plain Node child does not inherit the parent tsx preload. The closure therefore
tracks both source path and loader mode: plain Node children use native suffix
resolution, fork inherits its parent's mode, and a file reached under both modes
contributes both dependency closures. Calls continue to require explicit in-root
script files; this does not add CLI flags or directory fallback support.

A child-launching closure also rejects access to ambient `process.env`,
`process.execArgv`, `process.chdir`, and `process.loadEnvFile` capabilities, plus
`process.execPath` outside the directly validated executable argument. These
values can be changed or passed indirectly by an imported module before a child
starts; an options-free call alone does not bind that child's startup state.
Workers also inherit startup state, so the same closure-level check applies to
them. Worker closures reject uncertain URL-constructor identity and mutable
`import.meta` transfers: only the documented direct URL/factory inputs are
accepted, not arbitrary expressions containing a metadata write. Ordinary
environment reads in a closure without child execution retain their previous
behavior. These conservative restrictions are not a general sandbox.

Each parseable source contributes its existing in-root ancestor `package.json`
files to the identity snapshot, including initial entrypoints and direct relative
imports. This deliberately conservative superset detects changes to controlling
package scopes as well as newly added or removed nearer manifests. Resolution,
unlike identity overbinding, stops at the first controlling package scope and
never crosses a `node_modules` boundary to inherit an outer self-reference or
`imports` map. Package metadata must be a regular UTF-8 JSON object. An unknown
executable suffix is rejected rather than treated as opaque non-executing data.

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

The focused suite covers the original six PR45 findings and the subsequent
nearest-scope, class-heritage-regexp, and type-only-import findings, plus capability-transfer
matrices, loader-factory result transfers, Unicode aliases, lexical boundary
variants, actual Node comment/package-scope/preload witnesses, and installation
symlink/file-type checks. The Node witnesses use only temporary fixtures and are
skipped explicitly when Node is unavailable; CI must report whether they ran.

```sh
PYTHONPATH=src python -m unittest tests.test_runtime_source_contract_regressions tests.test_runtime_source_native_children tests.test_runtime_module_origin_regressions tests.test_runtime_package_scope_boundaries tests.test_runtime_source_contract_crosscheck tests.test_runtime_review_completion -v
PYTHONPATH=src python -m unittest tests.test_openclaw_real_gateway_contract_probe -k source_closure -v
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m agentic_os.cli preflight
PYTHONPYCACHEPREFIX=/tmp/agentic-os-pycache PYTHONPATH=src python -m compileall -q scripts src tests
```
