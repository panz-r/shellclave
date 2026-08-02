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
Public API changes must update headers, README ownership/error guidance, tests,
and the changelog. Keep commits small, imperative, and include a precise test
result in the pull request.
