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

Shared source operations, scratch storage, lexical indexes, and iterator
workspace lifetimes belong to `shell_source_runtime.c` and its private header.
Runtime-only consumers include that header rather than the recursive scanner.
The runtime keeps the operation state private; tokenizers use its iterator
scopes instead of accessing storage fields.

Source-byte admission belongs to `shell_source_admission.c`. It owns both the
whole-source byte check and scoped admission of words, comments, substitutions,
and heredocs. Retained draft collection remains in `shell_source.c`; lexical
iteration and list grammar retain their own responsibilities.

`shell_conditional.c` owns unary string-condition framing, primary grammar,
operand spans and static emptiness facts. Consumers reuse those facts and the
shared word-expansion primitives. Descriptor snapshots distinguish body-word
expansion after compound setup from simple-command argv expansion before setup.

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
