# Contributing

Initialize submodules and use an out-of-tree build:

```sh
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Changes should build with GCC and Clang under `-Wall -Wextra -Wpedantic`.
Parser or policy fixes need deterministic regression tests. Randomized tests
must print and accept a seed. Do not mask failures, write artifacts into source
directories, add large fuzz corpora, or globally suppress warnings. Run the
ASan/UBSan configuration for changes that touch parsing, memory ownership,
serialization, or concurrency; run TSan for policy/context synchronization.

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
and the changelog. Keep commits small, imperative, and include a precise test
result in the pull request.
