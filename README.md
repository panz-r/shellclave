<p align="center">
  <img src="shellclave_logo.png" alt="Shellclave logo" width="320">
</p>

# Shellclave

Shellclave is a C11 toolkit for parsing shell command lines and evaluating
command policy.

- **shellsplit** provides bounded, zero-copy parsing plus a richer allocating
  tokenizer, command abstraction, transforms, and dependency graphs.
- **shelltype** learns typed command patterns and evaluates serialized policy.
- **shellgate** combines both libraries into an allow/deny gate with advisory
  lexical violation checks and optional statistical anomaly scoring.

Gate evaluation uses the [documented Bash execution model](shellsplit/README.md),
not executor-neutral shell semantics. Applications must establish its clean
noninteractive startup state before executing accepted source and inspect
and evaluate dynamic content as required by conditional substitution results.
Shellclave itself does not execute commands.

## Requirements and build

The root CMake project requires CMake 3.20+, C11 and C++11 compilers,
pthreads, and libm. Its CI configuration builds GCC and Clang configurations.

```sh
git clone --recurse-submodules https://github.com/panz-r/shellclave.git
cd shellclave
reference_bash=$(./scripts/prepare-reference-bash)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

If the clone already exists, initialize dependencies with
`git submodule update --init --recursive`. CMake builds write
`compile_commands.json` into the build directory for `cppr`, other
static-analysis tools, and editor integrations.

Test builds use one pinned executor, Bash 5.3.20. The helper downloads the
official release and ordered patches using the checksums in
`scripts/reference-bash.sha256`; it caches the build on disk without replacing
the system shell. It requires curl, patch, make, a C compiler, and flock.
`scripts/verify-push` prepares and uses the same reference automatically.
`BUILD_TESTING=OFF` builds the libraries without Bash or network access.
To upgrade the modeled Bash version, update the manifest, rerun every
conformance probe, and include any semantic corrections in the same changeset.
Older and newer Bash versions are not additional supported dialects.

Useful options are `BUILD_TESTING`, `SHELLCLAVE_BUILD_TOOLS`,
`SHELLCLAVE_BUILD_FUZZERS`, `SHELLCLAVE_ENABLE_COVERAGE`,
`SHELLCLAVE_ENABLE_SANITIZERS`, and `SHELLCLAVE_ENABLE_TSAN`.

## Minimal API examples

Parse without allocation:

```c
#include <shell_tokenizer.h>
#include <string.h>

shell_parse_result_t parsed;
shell_limits_t limits = SHELL_LIMITS_DEFAULT;
limits.strict_mode = true;
const char command[] = "printf '%s\\n' ok";
shell_error_t error = shell_parse_fast(command, strlen(command), &limits, &parsed);
```

Use each component directly for the information it owns: Shellsplit's dependency
graph represents groups, background execution, timing, and substitution edges;
Shellgate returns policy verdicts, dynamic-content flags, diagnostics, and I/O
context, not a second graph representation. For policy editors, convert CPL with
`st_netpattern_from_cpl_owned()`, decode once with `st_netpattern_decode_view()`,
and reuse that token array with Shelltype's `st_token_variants_at()`.
Public result fields such as `violation_dropped_count`, `display_text`, and
`has_transformations` are accessed directly. Diagnostic display text is lossy;
use canonical netargv for programmatic command data.

Learn command shapes:

```c
#include <shelltype.h>
#include <stdio.h>
#include <stdlib.h>

st_learner_t *learner = st_learner_new(&(st_learner_config_t){.min_support = 2, .min_confidence = 0.5});
if (learner != NULL) {
    static const char status[] = "3:git,6:status,7:--short,";
    static const char log[] = "3:git,3:log,9:--oneline,";
    (void)st_learner_feed_netargv_view(learner, (st_netargv_view_t){status, sizeof(status) - 1});
    (void)st_learner_feed_netargv_view(learner, (st_netargv_view_t){status, sizeof(status) - 1});
    (void)st_learner_feed_netargv_view(learner, (st_netargv_view_t){log, sizeof(log) - 1});

    size_t count = 0;
    st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
    for (size_t i = 0; i < count; ++i) {
        char *cpl = NULL;
        if (st_netpattern_to_cpl_view((st_netpattern_view_t){suggestions[i].pattern, suggestions[i].pattern_length}, &cpl) == ST_OK) {
            printf("%s (count=%u, confidence=%.2f)\n", cpl,
                   suggestions[i].count, suggestions[i].confidence);
            free(cpl);
        }
    }
    st_suggestion_list_free(suggestions, count);
    st_learner_free(learner);
}
```

Evaluate a gate rule:

```c
#include <shellgate.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

sg_gate_t *gate = sg_gate_new();
st_policy_ctx_t *context = st_policy_ctx_new();
st_policy_t *allow = context ? st_policy_new(context) : NULL;
st_policy_ctx_release(context);
st_netpattern_t pattern = {0};
const char command[] = "git status --short";
sg_result_t result;
if (gate != NULL && allow != NULL) {
    st_error_t policy_error = st_netpattern_from_cpl_owned(
        "git status #opt", &pattern);
    if (policy_error == ST_OK)
        policy_error = st_policy_add_netpattern_view(
            allow, (st_netpattern_view_t){pattern.data, pattern.length});
    if (policy_error == ST_OK) {
        sg_gate_set_allow_policy_owned(gate, allow);
        allow = NULL; /* ownership transferred; installed policies are immutable */
        size_t output_size = sg_gate_evaluate_size_hint(strlen(command));
        char *output = output_size == SIZE_MAX ? NULL : malloc(output_size);
        sg_error_t error = output == NULL ? SG_ERR_MEMORY :
            sg_gate_evaluate(gate, command, strlen(command), output,
                             output_size, &result);
        if (error == SG_OK) {
            printf("verdict: %d\n", result.verdict);
        }
        free(output);
    }
}
st_netpattern_free(&pattern);
st_policy_free(allow);
sg_gate_free(gate);
```

Ownership, destruction, and concurrency contracts are documented in the public
headers.

Use each component directly: Shellsplit parses and constructs dependency graphs,
Shelltype builds and persists policies, and the anomaly API inspects models.
Shellgate combines those capabilities for evaluation; it does not duplicate their
management APIs. Build a replacement policy before installing it. Gates normally
own policies, but `sg_gate_new_with_policies_borrowed()` supports sharing stable
policies without copying. Borrowers must detach and readers finish before the
owner frees or replaces a shared policy. Policy views from Gate are read-only.

## Canonical machine boundaries

Shellclave uses canonical netstrings whenever values cross a machine-facing
API boundary. A `netargv` is a concatenation of netstrings, one per argument;
a `netsequence` is an outer concatenation whose records each represent one
isolated subcommand. This preserves empty arguments, whitespace, punctuation,
and nested per-command type signatures without quoting heuristics.

Shellsplit remains the shell-language boundary: use the binary-safe
`shell_build_netargv_sequence_buffer()`,
`shell_build_command_netseq_buffer()`, or
`shell_build_type_netseq_buffer()` to turn shell source into canonical records
for all canonical transport. Canonical APIs require explicit byte lengths;
the former NUL-free C-string adapters have been removed. Shelltype consumes
`st_netargv_view_t` and `st_netpattern_view_t`, and owns encoded patterns in
`st_netpattern_t`. Build and edit policies through Shelltype using
`st_netpattern_view_t` (or arrays of views for batches). CPL and shell source
remain text interfaces. Initialize owned outputs to `{0}` and use the
documented release function before reusing their storage.
The context-free `st_token_classify(text, length)` also accepts borrowed,
unterminated spans and embedded NULs; NULL is meaningful only for an empty
span. Anomaly n-gram count queries use `sg_anomaly_item_view_t` through the
`*_count_view()` APIs, not C-string adapters. Empty stages represent argv-less
commands and are distinct from missing observations.
Shellsplit's shared `shell_expand_word_netargv_fn` callback consumes an exact
source-word request and returns canonical, explicit-length `netargv`. Requests
identify the argument, redirect-path, or file-substitution-path purpose and the
known execution CWD. Use `shell_dep_graph_parse_resolved()` directly for graph
analysis, or register the same callback with `sg_gate_set_expand_word_netargv()`
for combined evaluation. The request and borrowed CWD are callback-scoped;
returned netargv storage must remain immutable until evaluation returns, or
for the lifetime of a standalone graph that borrows it. Size standalone
resolution workspace with `shell_dep_resolved_workspace_size()`. Shell-state
operands remain protected, including `printf %b` data in `%n`-bearing formats;
assignment-shaped tilde words (`name=~`, `name+=~`, `name=a:~`) are dynamic
arguments and FILE operands, but here-string data does not use that rule.
Unresolved dynamic FILE operands do not have a concrete path identity; spelling
heuristics may still apply. CWD tracking distinguishes actual leading-tilde
expansion from quote-disabled forms such as `~""/child`. Literal relative paths
remain subject to CDPATH, while `./~""/child` is a known literal relative path.
Protected dynamic formats and assignment values still participate in shell-state
analysis; they cannot leave a named-FD binding falsely established.
`unresolved_expansion_flags` distinguish unresolved argv and paths even when a
policy matches their processed source. Aggregate flags cover the retained graph,
including commands omitted by policy early-stop or diagnostic truncation;
per-command flags include inherited group I/O. A truncated graph cannot describe
unretained commands. Its anomaly APIs accept canonical
`netsequence` values. Human-facing CPL conversion remains explicit through
Shelltype in applications and CLI tools. See
[docs/canonical-formats.md](docs/canonical-formats.md) for the wire contracts.

For each `sg_subcommand_result_t`, `netargv` and `netargv_length` are the
authoritative programmatic result. `display_command` is a space-joined
diagnostic display and is deliberately not reparsable; applications must decode the
netargv records with `shell_netstring_iter_t` when they need argument values.

The evaluation-buffer size hint is an initial source-based estimate. Large
resolved path values can require additional private scratch and identity
storage in that same buffer. Insufficient workspace returns `SG_ERR_MEMORY`
with an undetermined verdict; it never silently skips known-path analysis.
Grow the buffer and retry. Failed attempts do not update anomaly learning.
Path-related violation details copy resolved targets into the result buffer as
`resolved "<value>" (source "<spelling>")`, escaping quotes, backslashes, control
bytes and non-ASCII bytes. Source-only details retain their previous spelling.
Long resolved targets can therefore also require additional result space;
insufficient result space returns `SG_ERR_TRUNC`, not an allowed verdict.

Graph construction propagates known command-substitution outcomes separately
from captured bytes. Assignment-only commands normally use the last executed
substitution's status. Bash executes an argv-less command's redirection setup
in a child when any redirect targets fd 0 or a named descriptor; successful
setup then returns success, independent of substitution statuses. Assignment
expansion still belongs to the parent, while redirect expansion errors remain
local to that child. Ordinary commands retain their own execution status.
Known failures suppress impossible conditional effects and callbacks. Runtime
unknown or conditional substitutions retain the possible outcomes; resolving a
pathname does not prove that opening the file will succeed.

Bash descriptor moves (`n>&m-` and `n<&m-`) preserve both the copied route
and the reached source close. Moves can use tracked allocated descriptors
such as `3>&${fd}-`. Scope restoration follows Bash's destination-open and
named-allocation behavior, including later setup failures. Quotation remains
significant: `"3"-` is a move operand, whereas `"3-"` is an ordinary word.
Shellsplit exposes compound moves as one `SHELL_GROUP_IO_MOVE_FD` operation;
static invalid duplication operands use `SHELL_GROUP_IO_FAILED_REDIRECT`.
Self-moves compare physical descriptor identity, including named sources.
Unsaved source closes leave persistent compound-body reopens intact. External
commands reached directly or through chains of `command` wrappers apply
redirects in a child, preserving parent descriptors and named variables.
A reached `builtin` wrapper performs setup in the current shell, even when an
inner `command` executes an external program. Builtins and compound tails apply
redirects in the current shell. Rebinding a named descriptor leaves its earlier
allocations open. Temporary redirects restore the state after any allocations
made earlier in the same setup list.
Restoration reads live physical scratch slots and disposes each save in undo
order. This preserves routes when later moves, allocations, or closes overlap
those slots; compound completion and timing reports use the same unwind rules.
If a saved descriptor has been closed, its failed restoration stops that undo
list, leaving the target unchanged and older saves live. Cleanup diagnostics
do not change the command body's status; enclosing scopes still run their own
independent cleanup lists.

The dependency graph exposes the full command's inherited I/O resources as
`SHELL_NODE_FD` nodes, identified by `node.fd.number`. Ordinary executable
commands have potential stdin, stdout, and stderr routes by default. READ/WRITE
edges carry the command-local descriptor on the execution side and
`SHELL_DEP_FD_NONE` on the boundary-resource side. These describe shell routing,
not a prediction that a particular executable transfers bytes.

`cd` is always an ordinary CMD node with its I/O and CWD relation. Shellsplit
also tracks directory changes for subsequent commands; `cd`'s own arguments
and redirects use its incoming directory. The former `cd_as_cmd` limits field
has been removed in 0.15.0: remove its initialization and rebuild consumers.

For `wc -l file.txt 2>&1`, follow the WRITE edge with `source_fd == 2`: its FD
target has `fd.number == 1`. For the unredirected command that target is 2.
Source order is preserved: `2>&1 >out` still sends stderr to inherited stdout,
whereas `>out 2>&1` sends both outputs to `out`. Nested scopes share the same
full-command boundary; captures and pipes retain their separate identities.
Boundary resources are not internal producer/consumer bridges. They count
toward the documented node/edge limits; missing capacity reports truncation.

Byte-flow edges also retain shell-owned expansion, redirect-setup and undo diagnostics on
the existing CMD/GROUP owner's fd 2. They use stderr at the failure point, even
when the command body does not execute. For example, in
`exec 3>&-; sh -c "$(echo 2>&1 >&3)"`, the setup error enters the substitution
capture and requires inspection. Reordering the redirects leaves that capture
empty. Possible open failures retain alternatives without predicting an OS
failure; closed or read-only stderr supplies no diagnostic bytes.
Argument/RHS expansion diagnostics use incoming stderr, while redirect operands
and expandable heredocs use the reached redirect prefix. Thus
`sh -c "$(exec 2>&1; x=$((1/0)))"` retains a SUBST flow requiring inspection,
including when later redirects close the command's outputs.
Optimized `$(<file)` reads preserve the same diagnostic routes independently
of their file-content flow. Resolving an empty filename removes the content
edge, but its captured open error still marks the outer receiving command for
inspection. A filename resolution callback establishes the filename, not I/O
success.

Successful argv-less assignments such as `$(x=1)` do not produce captured body
output. Their ENV effects, explicit redirect setup, and pipeline connections
remain represented. Known readonly-assignment errors use stderr before the
command's own redirects: `UID=1` aborts its input unit without applying them,
while `UID=1 true` can still run `true`. Thus
`sh -c "$(exec 2>&1; UID=1 true 1>&- 2>&-)"` still requires inspection of the
captured diagnostic, despite the body closing both outputs.
Rejected temporary prefix assignments skip their RHS expressions; assignment-only
and export forms still expand them. Rejected writes do not create effective ENV
edges, while successful neighboring assignments remain represented.
This distinction follows post-expansion argv: in
`UID=$(printf 1) $(true)`, the command word can disappear and the RHS executes
before rejection. Shellsplit retains that possible flow. Quoted empty scalar
words and a later guaranteed argument instead preserve executable dispatch.

Parameter pattern removal, replacement and case-conversion operands may skip
their substitutions for unset or empty values. Their analysis preserves the
incoming status as well as the possible substitution outcome.

## CMake consumption

Embedded use:

```cmake
add_subdirectory(path/to/shellclave)
target_link_libraries(example PRIVATE Shellclave::shellgate)
```

Installed use:

```cmake
find_package(Shellclave CONFIG REQUIRED)
target_link_libraries(example PRIVATE Shellclave::shellgate)
```

The other exported targets are `Shellclave::shellsplit` and
`Shellclave::shelltype`.

## Hardening and fuzzing

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DSHELLCLAVE_ENABLE_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure

cmake -S . -B build
cmake --build build --target clang-analyze

cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ -DSHELLCLAVE_BUILD_FUZZERS=ON \
  -DBUILD_TESTING=OFF
cmake --build build-fuzz --target fuzz-smoke
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
cmake -S . -B build-analyze
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

## Dependencies

Pinned submodules under `deps/` provide draugr and xxHash. Normal builds never
download dependencies. Parent projects may provide existing `draugr`,
`xxhash`, or `xxHash::xxhash` targets before adding Shellclave. Revisions and
licenses are recorded in [THIRD_PARTY.md](THIRD_PARTY.md).

Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md).
