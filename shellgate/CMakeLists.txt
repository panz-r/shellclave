cmake_minimum_required(VERSION 3.16)
project(shellgate C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_COVERAGE "Enable code coverage" OFF)

if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# ── Dependencies ──────────────────────────────────────────────
set(SHELLSPLIT_DIR   ${CMAKE_SOURCE_DIR}/../shellsplit)
set(SHELLTYPE_DIR    ${CMAKE_SOURCE_DIR}/../shelltype)

# shellsplit: fast tokenizer + depgraph (zero alloc) + full tokenizer + abstract
add_library(shellsplit_gate STATIC
    ${SHELLSPLIT_DIR}/src/shell_tokenizer.c
    ${SHELLSPLIT_DIR}/src/shell_depgraph.c
    ${SHELLSPLIT_DIR}/src/shell_tokenizer_full.c
    ${SHELLSPLIT_DIR}/src/shell_abstract.c
)
target_include_directories(shellsplit_gate PUBLIC ${SHELLSPLIT_DIR}/include)

# shelltype: normalize + policy + policy_ctx + filters
add_library(shelltype_gate STATIC
    ${SHELLTYPE_DIR}/src/normalize.c
    ${SHELLTYPE_DIR}/src/policy.c
    ${SHELLTYPE_DIR}/src/policy_ctx.c
    ${SHELLTYPE_DIR}/src/arena.c
    ${SHELLTYPE_DIR}/src/trie.c
    ${SHELLTYPE_DIR}/src/vacuum_filter.c
    ${SHELLTYPE_DIR}/src/filter_hash.c
)
target_include_directories(shelltype_gate PUBLIC ${SHELLTYPE_DIR}/include)
target_link_libraries(shelltype_gate PUBLIC m)

# ── shellgate library ─────────────────────────────────────────
add_library(shellgate STATIC
    src/shellgate.c
    src/sg_anomaly.c
)
target_include_directories(shellgate PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(shellgate PUBLIC shellsplit_gate shelltype_gate)

# ── Tests ─────────────────────────────────────────────────────
enable_testing()

add_executable(test_shellgate
    tests/test_shellgate.c
)
target_link_libraries(test_shellgate PRIVATE shellgate)

add_executable(test_anomaly
    tests/test_anomaly.c
)
target_link_libraries(test_anomaly PRIVATE shellgate)

# ── Tools ─────────────────────────────────────────────────────
add_executable(anomaly_demo
    tools/anomaly_demo.c
)
target_link_libraries(anomaly_demo PRIVATE shellgate)

add_executable(anomaly_calibrate
    tools/anomaly_calibrate.c
)
target_link_libraries(anomaly_calibrate PRIVATE shellgate)

include(CTest)
add_test(NAME shellgate COMMAND test_shellgate)

# Coverage report using lcov
add_custom_target(coverage-shellgate
    COMMAND ${CMAKE_SOURCE_DIR}/../scripts/coverage.sh ${CMAKE_BINARY_DIR}
    COMMENT "Generating coverage report for shellgate"
)

# Valgrind memory check
find_program(VALGRIND valgrind)
if(VALGRIND)
    add_custom_target(valgrind-shellgate
        COMMAND ${VALGRIND} --leak-check=full --error-exitcode=1 ./test_shellgate
        COMMENT "Running shellgate tests under valgrind"
        DEPENDS test_shellgate
    )
endif()

# ── Fuzzing ─────────────────────────────────────────────────────
# Always built alongside other targets to stay in sync.
# With libFuzzer: run as ./fuzz_shellgate -runs=N corpus/
# Without:        echo 'cmd' | ./fuzz_shellgate   (stdin smoke test)

add_executable(fuzz_shellgate tests/fuzz_shellgate.c)
target_link_libraries(fuzz_shellgate PRIVATE shellgate)

# Try to enable libFuzzer (provides FuzzerMain + coverage-guided mutation)
# check_c_compiler_flag fails because it links a stub without LLVMFuzzerTestOneInput,
# so check for the flag directly
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_c_source_compiles("int LLVMFuzzerTestOneInput(const char*d,long s){return 0;}" HAS_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
if(HAS_LIBFUZZER)
    target_compile_options(fuzz_shellgate PRIVATE "-fsanitize=fuzzer")
    target_link_options(fuzz_shellgate PRIVATE "-fsanitize=fuzzer")
    target_compile_definitions(fuzz_shellgate PRIVATE HAS_LIBFUZZER)
    message(STATUS "libFuzzer enabled for fuzz_shellgate")
else()
    message(STATUS "libFuzzer not available — fuzz_shellgate uses stdin driver")
endif()

# Seed corpus: copy tests/corpus/ into build dir for easy access
add_custom_command(TARGET fuzz_shellgate POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/tests/corpus
        ${CMAKE_BINARY_DIR}/corpus
    COMMENT "Copying seed corpus to build directory"
)
