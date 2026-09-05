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
This includes contextual `await`/`yield`/`of` uses and TypeScript postfix
assertions/instantiations where the slash cannot safely be classified. Prefix
logical negation remains supported. Regexp literals after heritage, export, and
ASI-sensitive statement keywords retain the following executable code. Private
property names are not treated as those keywords. Simple self-closing intrinsic
JSX tags remain supported; markup with text, attributes or component expressions
is rejected rather than interpreted using JavaScript string/comment rules. This
recognizer is not a general JSX or TypeScript parser.

Every recognized execution capability must remain in an accounted-for import,
CommonJS binding, or supported direct invocation. Moving a Worker constructor,
child-process callable, namespace, or loader factory into another variable,
container, callback, return value, re-export, or reflective invocation is not an
implicit dependency-free operation: unsupported transfers are rejected at the
original reference. This avoids enumerating another set of alias spellings for
each subsequent call. Explicit type-only import/export specifiers do not create
runtime capability origins. A value binding literally named `type`, or a mixed
clause containing actual Worker/child-process/module values, is still audited.
Erased type aliases use bounded declaration syntax and line-terminator checks;
scanning from any variable named `type` to the next semicolon is not a valid way
to exempt subsequent executable references. Type-only imports also do not disable
the ambient Worker audit in value positions.

CommonJS `module.parent`, `module.children`, and `module.paths` are also
unsupported capabilities: the first two expose other modules' loaders, while
changing the search paths can redirect an otherwise literal require. Ordinary
`module.exports` and read-only scalar metadata remain supported. Writes to
`module.filename`, `id`, `path` and scalar loader metadata are rejected, including
grouped/destructuring targets and iteration, update and delete forms. An executed
Node witness demonstrates that changing `module.filename` redirects an otherwise
literal require; computed lookup keys and call-argument reads are positive controls.

Supported loader forms include literal static/dynamic imports, direct literal
CommonJS calls, the existing simple `require` alias form, and directly assigned
`createRequire(import.meta.url)` / `createRequire(__filename)` loaders. Factory
results hidden behind grouping, binding, or other result transformations are not
accepted as ordinary direct assignments. The existing supported inline factory
invocations still require a literal module specifier and a local factory base.

Literal loader paths also require accounted-for resolution bases. A module using
`createRequire(__filename)` or `import.meta.url` as a loader base may not rebind,
shadow, destructure, mutate or pass that base through unaudited references. Worker
URLs require the original URL constructor: constructor/namespace references from
`node:url` are accounted for across the entire closure, not only in the module
that starts the Worker. This catches prototype mutation in an imported module as
well as local constructor shadowing. Direct builtin URL imports and erased type
imports remain supported; ordinary URL/metadata usage in a closure without a
corresponding loader assumption is unchanged. This is deliberately a supported
syntax boundary, not whole-program JavaScript value analysis.

Direct literal calls of a named `createRequire` factory's returned loader are
recorded just like an assigned loader; accepting the call signature alone is not
sufficient without recording the module it executes.

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
Ordinary environment reads in a closure without child execution retain their
previous behavior. This conservative restriction is not a general sandbox.

Each parseable source contributes its existing in-root ancestor `package.json`
files to the identity snapshot, including initial entrypoints and direct relative
imports. This deliberately conservative superset detects changes to controlling
package scopes as well as newly added or removed nearer manifests. This snapshot
superset does not authorize scope inheritance: `imports` and self-reference lookup
stop at the first controlling manifest, even when its map is absent, and never
cross a `node_modules` boundary. Invalid UTF-8/JSON and non-regular, broken or
out-of-root controlling metadata fail closed. An internal manifest symlink is
read at its logical package location, not rebased onto its physical target.

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

Labeled `break` / `continue` statements also terminate at an automatic-semicolon-insertion boundary. A slash following their label is rejected as ambiguous, including when the line terminator occurs in a block comment, rather than being treated as identifier division. Executed Node witnesses cover both forms.
