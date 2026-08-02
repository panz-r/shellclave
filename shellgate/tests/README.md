# Shellgate tests

Shellgate's unit and anomaly tests are part of the root CMake test suite:

```sh
cmake -S ../.. -B ../../build
cmake --build ../../build
ctest --test-dir ../../build --output-on-failure
```

The fuzz harness, corpus, dictionary, and long-running helper scripts live in
`shellgate/fuzz/`. Build the harness with Clang and libFuzzer:

```sh
cmake -S ../.. -B ../../build-fuzz \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DSHELLCLAVE_BUILD_FUZZERS=ON
cmake --build ../../build-fuzz --target fuzz_shellgate
../../build-fuzz/fuzz_shellgate ../fuzz/corpus -runs=10000
```

`shellgate/fuzz/run_fuzzing_4h.sh` configures the same root build and runs a
managed, multi-worker session.
