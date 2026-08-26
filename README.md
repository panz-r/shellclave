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

## Requirements and build

The root CMake project requires CMake 3.20+, C11 and C++11 compilers,
pthreads, and libm. Its CI configuration builds GCC and Clang configurations.

```sh
git clone --recurse-submodules https://github.com/panz-r/shellclave.git
cd shellclave
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

If the clone already exists, initialize dependencies with
`git submodule update --init --recursive`. CMake builds write
`compile_commands.json` into the build directory for `cppr`, other
static-analysis tools, and editor integrations.

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

Learn command shapes:

```c
#include <shelltype.h>
#include <stdio.h>

st_learner_t *learner = st_learner_new(&(st_learner_config_t){.min_support = 2, .min_confidence = 0.5});
if (learner != NULL) {
    (void)st_learner_feed_netargv(learner, "3:git,6:status,7:--short,");
    (void)st_learner_feed_netargv(learner, "3:git,6:status,7:--short,");
    (void)st_learner_feed_netargv(learner, "3:git,3:log,9:--oneline,");

    size_t count = 0;
    st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
    for (size_t i = 0; i < count; ++i) {
        printf("%s (count=%u, confidence=%.2f)\n",
               suggestions[i].pattern, suggestions[i].count,
               suggestions[i].confidence);
    }
    st_suggestion_list_free(suggestions, count);
    st_learner_free(learner);
}
```

Evaluate a gate rule:

```c
#include <shellgate.h>
#include <string.h>
#include <stdio.h>

sg_gate_t *gate = sg_gate_new();
const char command[] = "git status --short";
char output[4096];
sg_result_t result;
if (gate != NULL) {
    sg_error_t error = sg_gate_add_allow_cpl(gate, "git status #opt");
    if (error == SG_OK) {
        error = sg_gate_evaluate(gate, command, strlen(command), output,
                        sizeof output, &result);
        if (error == SG_OK) {
            printf("verdict: %d\n", result.verdict);
        }
    }
    sg_gate_free(gate);
}
```

Ownership, destruction, and concurrency contracts are documented in the public
headers.

## Canonical machine boundaries

Shellclave uses canonical netstrings whenever values cross a machine-facing
API boundary. A `netargv` is a concatenation of netstrings, one per argument;
a `netsequence` is an outer concatenation whose records each represent one
isolated subcommand. This preserves empty arguments, whitespace, punctuation,
and nested per-command type signatures without quoting heuristics.

Shellsplit remains the shell-language boundary: use
`shell_build_netargv_sequence()`, `shell_build_command_netseq()`, or
`shell_build_type_netseq()` to turn shell source into canonical records.
Shellgate expansion callbacks consume and return canonical `netargv` values,
and its anomaly APIs accept canonical `netsequence` values. Human-facing CPL
conversion remains explicit at the Shellgate and CLI boundaries. See
[docs/canonical-formats.md](docs/canonical-formats.md) for the wire contracts.

For each `sg_subcommand_result_t`, `netargv` and `netargv_length` are the
authoritative programmatic result. `command` is a space-joined diagnostic
display and is deliberately not reparsable; applications must decode the
netargv records with `shell_netstring_iter_t` when they need argument values.

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

The `fuzz-smoke` target runs the unified Shellsplit fuzzer, the Shelltype
canonical-format and policy fuzzer, and the Shellgate fuzzer. The Shellsplit
fuzzer exercises all Shellsplit parser and helper APIs from that single target.

Run the Clang Static Analyzer:

```sh
cmake -S . -B build-analyze
cmake --build build-analyze --target clang-analyze
```

The fixed smoke seed corpora are tracked. Generated fuzzing corpora and
coverage reports stay in build directories and are ignored. Crash artifacts
are deliberately neither ignored nor tracked: a new crash appears in
`git status` for inspection and triage.

## Dependencies

Pinned submodules under `deps/` provide draugr and xxHash. Normal builds never
download dependencies. Parent projects may provide existing `draugr`,
`xxhash`, or `xxHash::xxhash` targets before adding Shellclave. Revisions and
licenses are recorded in [THIRD_PARTY.md](THIRD_PARTY.md).

Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md).
