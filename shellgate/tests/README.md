# Shellgate tests

Shellgate's unit and anomaly tests are part of the root CMake test suite. From
the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

The component redirect is also directly configurable. Its top-level CTest
file discovers the same Shellgate tests:

```sh
cmake -S shellgate -B build-shellgate -DSHELLCLAVE_BUILD_TOOLS=OFF
cmake --build build-shellgate
ctest --test-dir build-shellgate -L shellgate --output-on-failure
```

Build and run the Shellgate fuzz smoke target with Clang and libFuzzer:

```sh
cmake -S . -B build-fuzz \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DSHELLCLAVE_BUILD_FUZZERS=ON \
  -DBUILD_TESTING=OFF
cmake --build build-fuzz --target fuzz-shellgate-smoke
```

The fixed seeds under `shellgate/fuzz/smoke-seeds/` are tracked. Smoke-run
corpora are disposable build outputs. For a managed multi-worker campaign:

```sh
./shellgate/fuzz/run_fuzzing_4h.sh 2 14400
```

The long-running script rebuilds the harness, uses the fixed seeds and
`shell_dict.txt`, and writes findings under `shellgate/fuzz/crashes/` for
manual triage.
