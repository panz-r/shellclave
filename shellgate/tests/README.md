# ShellGate Test Suite

## Running Tests

### Standard Tests

```bash
cd build
make -j4
./test_shellgate
```

Or via CMake:

```bash
cd build
ctest
```

### Valgrind (Memory Checking)

```bash
make valgrind-shellgate
```

### Code Coverage

Requires `lcov` and `genhtml`:

```bash
cd build
cmake -DENABLE_COVERAGE=ON ..
make -j4
make coverage-shellgate
# Report generated at: build/coverage_html/index.html
```

## Test Categories

| Category | Description |
|----------|-------------|
| Lifecycle | Gate creation/destruction, NULL safety |
| Configuration | CWD, stop modes, suggestions |
| Buffer Management | Truncation, overflow, null termination |
| Expansion Callbacks | Variable and glob expansion |
| Violation Scanning | Security violation detection |
| Policy Management | Rule add/remove, save/load |
| Serialization | Policy persistence |

## Fuzzing

Requires libFuzzer:

```bash
cd build
cmake -DENABLE_FUZZING=ON ..
make fuzz_shellgate_corpus
./fuzz_shellgate_corpus -runs=10000 corpus_dir/
```

## Adding Tests

Tests are defined using macros:

```c
TEST(test_name)
{
    // test body
    ASSERT(condition);
}

RUN(test_name);
```

Use `ASSERT_EQ_INT(a, b)` for integer comparison, `ASSERT_STR(a, b)` for strings.

## Coverage Target

The shellgate library (shellgate.c) aims for 90%+ line coverage.
Current coverage: ~83% (some internal static functions are hard to reach without specific error conditions).
