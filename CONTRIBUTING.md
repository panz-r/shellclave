# Contributing

## Development build

Initialize submodules and prepare the pinned Bash reference:

```sh
git submodule update --init --recursive
reference_bash=$(./scripts/prepare-reference-bash)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --parallel 1
```

The helper downloads the official Bash release and ordered patches using
`scripts/reference-bash.sha256`, then caches its build without replacing the
system shell. It requires curl, patch, make, a C compiler, and flock.
Test builds require Python 3.8+ and the pinned Bash 5.3.20 reference.
`BUILD_TESTING=OFF` selects the library-only path in the
[README](README.md#build-and-install).

For a faster iterative test build with GCC or Clang, use a separate Debug build
with optimization enabled. This keeps assertions enabled and reuses the build
directory on subsequent runs:

```sh
cmake -S . -B build-optimized -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS_DEBUG='-O2 -g' -DCMAKE_CXX_FLAGS_DEBUG='-O2 -g' \
  -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build-optimized --parallel 2
ctest --test-dir build-optimized --output-on-failure --parallel 1
```

Reference upgrades deliberately change the one modeled executor. Update the
manifest, rerun conformance probes, and include all model adaptations in the
same changeset. Contributor options include `SHELLCLAVE_BUILD_TOOLS`,
`SHELLCLAVE_BUILD_FUZZERS`, `SHELLCLAVE_ENABLE_SANITIZERS`,
`SHELLCLAVE_ENABLE_TSAN`, and `SHELLCLAVE_ENABLE_COVERAGE`.
CMake writes `compile_commands.json` for editor and analysis integrations.

## Changes and verification

Changes should build with GCC and Clang under `-Wall -Wextra -Wpedantic`.
Parser or policy fixes need deterministic regression tests. Randomized tests
must print and accept a seed. Do not mask failures, write artifacts into source
directories, add large fuzz corpora, or globally suppress warnings. Run the
ASan/UBSan configuration for changes that touch parsing, memory ownership,
serialization, or concurrency; run TSan for policy/context synchronization.

Reference-shell conformance tests pay process startup and sanitizer costs for
each probe. Cover operand spellings separately from shared operator truth
tables, and cross dimensions where their interaction matters. Check source
framing once per source; vary captured values and reference locales in their
own checks so invariant probe results are not recomputed.

The test-only `shellsplit_graph_fixture` static library provides caller-owned
workspace and graph fixtures for Shellsplit tests. Its limits borrow the owned
workspace; tests may adjust the supplied capacity without changing ownership.
Keep deliberate missing, undersized and misaligned workspace tests explicit.

Differential parser oracles must provide sufficient source workspace to each
compared path. Size strict fast-parser and lexical-iterator storage with
`shell_source_workspace_size()`, and bind scratch for internal syntax and
semantic predicates. Their Boolean results can reflect scratch exhaustion;
check that resource outcome separately before interpreting them as syntax or
support classifications. Dependency-graph fuzz callers must provide both the
fixed graph prefix from `shell_dep_workspace_size()` and the source-sized tail
from `shell_source_workspace_size()`. Keep source operations independent so
cached facts cannot conceal disagreement, and retain deterministic regressions
outside the bounded smoke seeds. Allocate large retained graph results on the
heap in fixed sweeps; sanitizer instrumentation can reserve separate stack
slots for sequential fixture scopes.

Set `TMPDIR` to a writable directory with enough space and inodes for test
fixtures and compiler artifacts. Shellgate policy fixtures and the Shelltype
full-capacity policy test honor this setting. The latter writes a large NFA
export in a private directory under `TMPDIR` (default `/tmp`) and removes that
directory on success or failure. Filesystem quotas can prevent these writes
even when the filesystem reports free space.
Timestamp conformance uses the values stored by the filesystem behind `TMPDIR`;
nanosecond storage precision is not required. The fixtures also exercise
whole-second rounding on filesystems that preserve subsecond timestamps.

Host-locale regressions require `localedef` and the `en_US` and `ISO-8859-1`
locale sources (`locales` on Debian/Ubuntu). Tests generate private locale data
in the build directory and remove it afterward; they do not change system
locale settings. The single-byte host locale tests analysis independence, not
an additional supported Bash executor locale.

Run `cmake --build build --target format` before submitting changes;
`format-check` verifies the result without modifying files. These targets cover
first-party C and C++ sources only and never format the `deps/` submodules.

Before pushing, install the repository pre-push hook once:

```sh
ln -sf ../../scripts/pre-push .git/hooks/pre-push
```

Run the full verification before `git push`:

```sh
./scripts/verify-push
git push
```

Verification runs formatting checks, Clang static analysis, the normal and
sanitizer test suites, and 1000-iteration smoke runs of all three fuzzers. It
leaves its builds in `.pre-push-build/`, which is ignored locally, and signs
the exact verified commit in local Git metadata. The pre-push hook checks that
signature without holding the remote connection open during verification.
Every new commit must be verified again. Untracked top-level files do not
prevent verification, but tracked changes and dirty or mismatched submodules
do.

Public API changes must update headers, README ownership/error guidance, tests,
and applicable migration notes. Keep each commit self-contained, including
transitive fixes and adaptations, and report precise verification results in
the pull request.

## Shellsplit frontend ownership

The implementation owners and private interfaces are:

| Responsibility | Owner and interface |
|---|---|
| Source operations, scratch sizing/storage, lexical indexes and iterator lifetimes | `shell_source_runtime.c`, `shell_source_runtime_internal.h` |
| Whole-source and scoped byte admission | `shell_source_admission.c`, `shell_source_admission_internal.h` |
| Lexical iteration, control/list/draft grammar and borrowed command construction | `shell_tokenizer_full.c`, `shell_tokenizer_full_internal.h`, `shell_source_draft_internal.h` |
| Retained source/draft collection | `shell_source.c` |
| Arithmetic grammar, literal value proofs and conditional scalar-reference analysis | `shell_arithmetic.c`, `shell_arithmetic_internal.h` |
| Conditional framing, ordered operands, predicate properties and truth orchestration | `shell_conditional.c`, `shell_conditional_internal.h` |
| Conditional RHS admission, pattern projection, matching and scratch requirements | `shell_conditional_pattern_impl.h` |
| Conditional arithmetic word projection and direct parameter observation | `shell_conditional_operand_impl.h` |
| Numeric comparison identities and relational operations | `shell_numeric_predicate_internal.h` |
| Filesystem predicate spellings, aliases and semantic ordinals | `shell_file_predicate_internal.h` |
| Builtin test argument-count grammar, admission, bounded grammar-role projection and eager expression evaluation | `shell_test_grammar_internal.h`, `shell_test_admission_internal.h`, `shell_test.c`, `shell_test_projection_impl.h`, `shell_test_internal.h` |
| Shared builtin word projection and scalar cardinality | `shell_builtin_word_internal.h` |
| Whole-word expansion requests, purpose properties, cached values and callback-result validation | `shell_expand.c`, `shell_expand_internal.h` |
| Supported-operation inspection, builtin roles and semantic observers | `shell_semantics.c`, `shell_semantics_internal.h` |
| Word-value operations, scalar identifier checks, public decoding adapters and diagnostic word rendering | `shell_word.c`, `shell_word_internal.h` |
| Heredoc delimiter spelling and printer storage layout | `shell_heredoc.c`, `shell_heredoc_storage_internal.h` |

Shared inline interfaces have narrower responsibilities:

- `shell_token_traits_internal.h` defines lexical token categories. Consumers
  retain their own policy and rendering decisions, including process-substitution
  treatment.
- `shell_token_context_internal.h` shares lexical word, redirect and pipeline
  context helpers between grammar and semantic inspection. Observer state stays
  in the semantic module.
- `shell_token_regions_internal.h` selects borrowed expansion-bearing spans from
  parsed conditional facts or lexer-framed arithmetic. Conditional grammar and
  comments stay outside operand regions. Region selection does not qualify
  syntax, completeness or semantic support.
- `shell_word_fragment_internal.h` owns nonrecursive quote/escape processing,
  ANSI-C decoding, effective fragment values and quote provenance.
- `shell_word_decode_internal.h` supplies sinks and decoding loops for direct
  emission into canonical buffers and conditional arithmetic projection. The
  word implementation, conditional implementation and processor's direct
  emitter include it; declaration-only callers use `shell_word_internal.h`.

Share selection and context facts that consumers interpret identically. Keep
syntax recovery, borrowed-to-owned rebasing, graph execution effects and policy
decisions with their respective owners: these operations have different
contracts even when they inspect the same construct.

The source runtime keeps operation state private. Runtime-only consumers use
its narrow header; tokenizers use iterator scopes rather than storage fields.
Runtime sizing composes the arena bound from the delimiter printer's actual
private layout and the shared value/bookkeeping allowances. The storage header
keeps the printer and sizing calculation in agreement without a runtime query.

Retained collection uses the existing list/draft grammar. Recursive expansion
framing and context-sensitive dynamic-word classification remain with the source
scanners because they need nested lexical facts. Raw binary decoding, effective
shell-word projection and diagnostic rendering preserve their distinct contracts.
Public word APIs remain declared in `shell_processor.h`; their implementation is
in the word module. Descriptor snapshots distinguish body-word expansion after
compound setup from simple-command argv expansion before setup.

Conditional RHS admission uses a source-classifier view that skips quoted
expansions, then checks outer fragments for active pattern syntax in the
conditional module. Value consumers retain full expansion classification:
quoting a runtime expansion does not make its value statically known. Keep
these two views on the same inline word walk so tilde cancellation and escape
rules stay aligned. Complete quote framing remains with the recursive source
scanners; conditional admission uses those boundaries to skip nested syntax.
The expansion module requests and validates whole-word callback values, while
the conditional evaluator consumes those values to determine predicate truth.
Private inline purpose predicates distinguish pathnames from conditional
single-value requests. Keep these protocol properties in the expansion
interface instead of repeating purpose lists in graph consumers.

The conditional pattern and operand fragments share the conditional translation
unit. Pattern admission and evaluation keep their quote-aware projection and
scratch requirements together; common decoding sinks and overall truth
evaluation remain in the including file. Semantic inspection invokes the
conditional-owned operand-admission helper once at its existing traversal
point. It checks skipped numeric operands too; graph reachability is separate.

Variable presence belongs to graph execution state, independently of descriptor
bindings and empty scalar values. Prepare observed names and mutation targets
once, then carry immutable presence facts through the existing outcome and
scope machinery. Conditional parsing supplies static-name queries; builtin test
programs use the same facts while preserving their separate argument grammar.
Private graph implementation fragments group related execution-state operations:
`shell_depgraph_variable_impl.h` owns predefined-variable capabilities and prefix
visibility, `shell_depgraph_test_impl.h` owns predicate observations, filesystem
graph attachment, test lookup and outcome selection, and
`shell_depgraph_presence_impl.h` owns presence facts, epochs and assumptions.
`shell_depgraph_coverage_impl.h` owns semantic coverage recording, recursive
coverage imports and source-position qualification. CWD facts use position
qualification; effect qualification also requires active effects. Owner flags,
presence invalidation and branch/setup reachability remain at their execution
points. The conditional graph fragment owns ordered operand expansion and
predicate evaluation.
They are included at their dependency points in `shell_depgraph.c` and share its
translation unit. They are not independent interfaces or installed headers.
Route storage, mutation ordering, scope publication and recursive observation
remain owned by the graph; the fragments borrow those existing types and lifetimes.
Collect only grammar-selected lookup targets after each complete test expression
has been compiled. The root semantic traversal prepares programs once; graph
snapshots and nested bodies borrow their source-operation values and nodes.
Presence lives in an immutable submap whose root participates in scalar-import
equivalence, preserving epochs and writer identities across recursive imports.
Route-state transforms inherit correlation and sticky truncation metadata through
`dep_route_state_inherit`, including individual versions before a merge and the
completed result. A single surviving root can still carry correlation.
Establish named-allocation presence at the successful setup operation, so later
setup failures inherit that same fact. Prepare implicit and explicit builtin
writes in their actual commit order, or normalize their possible final effects
before graph transfer. In particular, getopts writes its destination and OPTARG
in different orders depending on its option outcome; coalesce an OPTARG
destination with the implicit final presence effect.
Apply each complete explicit mutation bundle within one execution version
before merging results. Dependent writes use that version's immutable entry;
iteration order cannot establish correspondence between rebuilt version sets.
Keep attempted writes to resettable predefined variables in the prepared
effects. Resolve their effective assignment capabilities per execution version
before publishing presence, bindings or writer identity. Ignored assignments
must also leave prefix visibility and recursive RHS overlays unchanged.
`SHELL_VARIABLE_NOASSIGN` is distinct from readonly: successful unset can remove
it for `FUNCNAME` and `GROUPS`, and rejection must not inherit readonly's
input-unit abort behavior. Builtin target failures retain earlier writes and
independent implicit effects according to that builtin's commit rules.
Opaque mutations are ordered effects, not a bundle-wide early return. Classify
them as value writes or possible unsets, and preserve surrounding known effects.
The capability marker stores separate definite and possible despecialization
masks as four positional words. Each `read` write signature stores its low and
high target masks, including the REPLY marker, as two positional words.
Read these snapshots through single-root lookup; route unions deduplicate
equal words and cannot represent their layouts. Resolve uncertain
assignment restrictions into bounded execution versions when needed, retaining
their correlation through read outcomes, prefix visibility and scalar imports.
Determine prefix installation from the immutable command-entry version. Later
effects cannot retroactively create or remove its restoration obligation.
Keep predicate errors distinct during eager Boolean composition. Unresolved
presence is not an unresolved word-expansion result.

Filesystem predicates have one private compile-time definition list. Conditional
lexical recognition and builtin effective-argument recognition expand it through
their own comparisons; quote handling and argument grammar remain separate.
The list also supplies classification cases and masks. Compile-time assertions
keep public conditional ordinals, builtin operations, role bits and graph flags
aligned with the existing shift-based mappings. Boolean connector roles are
placed above the filesystem role range using the predicate count; compile-time
bounds prevent overlap or overflow. Public edge flags use 32-bit storage.
Predicate graph attachment
consumes existing operand-resolution results after ordered substitutions and
preserves unresolved pathname facts.
`shell_test_roles_t` owns the 32-bit grammar-role representation; retained masks,
allocation alignment and scratch calculations use that type. The definition
list and graph implementation fragments add no runtime registry or traversal.
To extend this predicate family, append the public kind and flag, add its private
definition row, and update independent tests and the shell-model reference.
The separate binary-comparison catalog supplies operator spellings and
ordinals for conditional parsing, builtin recognition and comparison-node kind
bits. Binary comparisons do not consume unary predicate roles or edge flags.
Comparison adapters supply their grammar's dynamic and known-empty operand
facts together with existing captured values. The shared graph attachment
checks pathname representation and stores these facts; it must not reclassify
conditional operands as ordinary arguments or apply conditional expansion rules
to builtin arguments.

Shared C/C++ rejection fixtures in `shellsplit/tests/syntax_boundary_cases.h`
own the unsupported regex-comparison sentinel, both operand spans
and the continued operator spelling. Keep these fixtures valid Bash as
predicate coverage grows.
Each harness retains its own API assertions and contextual wrappers. Python
Bash qualification cases and explicit predicate expectations stay independent
of the implementation list.

Conditional framing and precedence live in `shell_conditional.c`; its bounded
postorder tree retains lexical primaries and normalized negation. Comparison
operator admission first recognizes received token prefixes, then uses the
shared whole-word matcher before assigning the operator role. A punctuation
boundary alone is insufficient: attached process substitutions remain part of
the word. Build the
single-primary summary during traversal, including enclosing negation when
parsing stops inside a group. A consumed Boolean connector clears that summary
before its right term is parsed. Final closing delimiters do not determine
whether received primary metadata is available. Word-region
consumers iterate every primary, including those skipped at execution. Partial
parses can retain a forest whose Boolean parents have not yet been emitted;
size operand-region storage for two operands per retained node and the pending
primary, rather than applying the leaf bound for a completed tree. Graph
branch expansion lives in `shell_depgraph_conditional_impl.h`, included after
the word-expansion helpers. It reuses test-program truth and presence facts,
and borrowed descriptor guards for uncertain branches. Keep subtree truth
queries on stable prepared source metadata; avoid copying lazy snapshot state
or reevaluating the entire expression for each primary. The traversal carries
the end offset of each subtree's last primary alongside its truth, including
skipped branches. Release its guard at that boundary, so observation positions remain
nondecreasing within an owner and phase. Equal-position nested completions retain
append order; the replay cursor relies on this order before opening later
process descriptors. Binary file comparisons retain paired operands through
their own graph nodes rather than independent unary FILE_TEST flags.

Shared recursive syntax validation preserves `shell_error_t` resource outcomes
through executable substitutions and heredoc visitors. The typed
`shell_tokenizer_syntax_status` boundary owns that result; Boolean adapters are
only acceptance queries. Syntax exhaustion qualifies no prefix and must reach
graph and gate consumers before semantic inventory or policy evaluation.
Range/output exhaustion after validation can still retain partial products.

Test admission and compilation share the distinct terminal-predicate role and
its numeric/implicit-operand rules. `shell_test_dispatch` owns the 0..4-argument
precedence and recursive negation/parenthesis shortcuts for both consumers.
Admission buffers an opener, at most four interior projected facts and a
candidate closer before selecting a nested small expression. Search from the
second interior argument, as pinned Bash does; larger or ambiguous groups use
the general recognizer. Apply the same dispatch to each primary alternative,
while advancing other paths independently. A proven error on every path also
sets the compiled test outcome without discarding its observed lookups. This
bounded lookahead never decodes source again or
compiles a program for source-only callers. Use global expression arity for
`-t`, even inside a small parenthesized expression. An implicit descriptor leaves
its connector unconsumed and can make the counted group fail before a later
lookup. Preserve checks for lookups already reached, and retain dynamic-role
alternatives when their grammar can still reach an unsupported operation.
Preserve pinned Bash's argument base in small-expression dispatch: posixtest(1)
reads invocation-wide argv[1], while the three-argument parenthesis shortcut
reads the local operand. Compile that reference into the existing prepared word
table; do not copy argument tables or repair reachability in the graph adapter.
Prepare each owner's expression before classifying its construction status,
including literal tests that request no expansion or redirect snapshot. Later
control consumers must see the completed status, not provisional uncertainty.
Semantic variable-name and test-program observers are independently optional.
Either requests compilation; neither adds compilation work for source-only
inspection. Inspection reports unsupported semantics, exhausted workspace and
truncated inventories separately. Callbacks describe completed products, but a
failed inspection can have delivered a partial inventory which must be discarded.

Keep token facts, region initializers and fragment/decoder cores inline. Consume
existing parse facts where available and retain each consumer's source traversal,
resource accounting and ownership rules when extending a syntax family.

`shell_keywords.c` defines keyword spellings and classification facts once.
Its consumers separately interpret grammar eligibility, feature presence, and
nesting counters. Keep the spelling table sorted and preserve those different
projections when extending it. Small continuation, punctuation, and word-boundary
primitives belong to `shell_source_lexical_internal.h`; scan instrumentation
belongs to its own private header. Recursive expansion scanners remain in
`shell_source_internal.h` with their existing nesting accounting.

Keyword callers establish a whole-word start using forward lexical history
and supply a source view covering any adjacent fragments. A token boundary
alone is insufficient: `fi$(printf x)` is one ordinary word. Reuse the
iterator's adjacency facts and the classifier's bounded lookahead; do not
walk expansion bodies again to establish reserved-word eligibility.

Keep these interfaces private and document caller preconditions on them.
Changes to one responsibility should update its owner and the consumer
projections that actually need different behavior. Preserve public result
layouts, resource contracts, and byte offsets during source reorganization.

## Hardening and fuzzing

These commands use the reference path prepared in the development build above.

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DSHELLCLAVE_ENABLE_SANITIZERS=ON \
  -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build-asan --parallel 2
ctest --test-dir build-asan --output-on-failure --parallel 1

cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ -DSHELLCLAVE_BUILD_FUZZERS=ON \
  -DBUILD_TESTING=OFF
cmake --build build-fuzz --target fuzz-smoke --parallel 2
```

Sanitizer and fuzz builds compile UBSan checks as non-recovering: detected
undefined behavior prints its diagnostic and fails the process, even if
`UBSAN_OPTIONS` requests recovery. No environment setting is needed to make
these findings fail CI, pre-push verification, or direct test runs.

The `fuzz-smoke` target runs the unified Shellsplit fuzzer, the Shelltype
canonical-format and policy fuzzer, and the Shellgate fuzzer. The Shellsplit
fuzzer exercises all Shellsplit parser and helper APIs from that single target.
Fuzz builds require Python 3.8 or newer. The shared standard-library supervisor
gives each smoke process a fixed 15-minute deadline, including initialization
and symbolization, in CI and pre-push verification as well as direct target
runs. The per-input limit remains ten seconds. Startup-only tests have a
60-second process deadline. Timeout or cancellation terminates the private
process group, allowing five seconds before killing remaining descendants.
Only disposable generated corpora are removed; selected seeds and crash
artifacts are preserved. Timeout exits with status 124.

Run the Clang Static Analyzer:

```sh
cmake -S . -B build-analyze -DBUILD_TESTING=OFF
cmake --build build-analyze --target clang-analyze
```

The target first verifies analyzer interception with clean and defective C/C++
fixtures, then configures and rebuilds first-party code through `scan-build`
compiler wrappers. Diagnostics fail the target and pre-push verification. Existing
ordinary-compiler caches are migrated automatically. Reports and temporary
analysis files stay under the build directory.

The fixed smoke seed corpora are tracked. Generated fuzzing corpora and
coverage reports stay in build directories and are ignored. Crash artifacts
are deliberately neither ignored nor tracked: a new crash appears in
`git status` for inspection and triage.

Coverage builds select one implementation variant with
`SHELLCLAVE_COVERAGE_VARIANT=tests` (the default) or `production`.
Use separate, fresh build directories for the two profiles. Test executables
and inline-helper tests remain instrumented, but only the selected library
variant emits counters. Allocation/I/O fault seams change compiler block
identities; merging their counters with production produces duplicated,
incompatible branch graphs. CI retains the existing coverage gates for the
test profile and publishes a separate production report from production-linked
parser, policy, persistence, and end-to-end corpus contracts. Both profiles
use gcovr 8.6; production reports are not substituted for the gated test report.

Build and run the production suite in its separate coverage build directory:

```sh
cmake -S . -B build-production -DCMAKE_BUILD_TYPE=Debug \
  -DSHELLCLAVE_ENABLE_COVERAGE=ON -DSHELLCLAVE_COVERAGE_VARIANT=production \
  -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build-production --parallel 2 --target shellclave_production_tests
ctest --test-dir build-production -L '^production$' --no-tests=error --output-on-failure
```

Register production-linked coverage tests with `shellclave_add_production_test()`
in CMake. That helper adds the shipping library's component label, the
`production` label, and the aggregate build dependency together. Tests already
registered with another suite, such as policy-sharing concurrency, use
`shellclave_register_production_test()`; that generic helper adds only production
membership, so its caller must retain the component and other suite labels.
`shellclave_test_suite_contract` checks that build and test memberships agree
and that every production test retains its component label. CI uses the same
aggregate and label, so it builds every executable it selects.

## Documentation and examples

The root README introduces analysis and classification, the result contract,
and the tested gate example. User-visible shell behavior belongs in the
[shell model reference](docs/shell-model.md); exact layouts and preconditions
belong in public headers. Put API removal instructions in
[migration notes](docs/migration.md).

The README's marked C excerpt matches the corresponding section of
`examples/gate_policy.c` byte-for-byte. Update both together. The documentation
contract checks the excerpt, complete example output, and local
Markdown links. Example tests cover policy outcomes, runtime uncertainty,
partial results, and evaluation failures against the shipping library.
Keep public prose organized by caller behavior; implementation history and
private data-structure notes belong in code comments or commit messages.

Numeric conditional operands use arithmetic interpretation; `test`/`[` operands
use prepared decimal integer values. Keep these grammar boundaries separate.
Direct scalar reads have ENV_READ relations, with logical names borrowed from
source or retained graph workspace and no assignment values. The arithmetic
resolver purpose supplies a pure dependency-resolved expression, not shell
execution. Unresolved arithmetic interpretation qualifies incomplete graph
coverage and blocks policy ALLOW; preserve this qualification through nested
imports, early-stop modes and anomaly updates. A coverage boundary retains
later syntax while withholding state-derived effects and CWD proofs. Predicate
and resolver tests must verify both visible dependencies and that qualification.
