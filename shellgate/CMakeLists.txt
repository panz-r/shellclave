cmake_minimum_required(VERSION 3.16)
project(shellgate C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

# ── Dependencies ──────────────────────────────────────────────
set(SHELLSPLIT_DIR   ${CMAKE_SOURCE_DIR}/../shellsplit)
set(SHELLTYPE_DIR    ${CMAKE_SOURCE_DIR}/../shelltype)

# shellsplit: only the fast tokenizer + depgraph (zero alloc)
add_library(shellsplit_gate STATIC
    ${SHELLSPLIT_DIR}/src/shell_tokenizer.c
    ${SHELLSPLIT_DIR}/src/shell_depgraph.c
)
target_include_directories(shellsplit_gate PUBLIC ${SHELLSPLIT_DIR}/include)

# shelltype: normalize + policy + policy_ctx + filters
add_library(shelltype_gate STATIC
    ${SHELLTYPE_DIR}/src/normalize.c
    ${SHELLTYPE_DIR}/src/policy.c
    ${SHELLTYPE_DIR}/src/policy_ctx.c
    ${SHELLTYPE_DIR}/src/trie.c
    ${SHELLTYPE_DIR}/src/vacuum_filter.c
    ${SHELLTYPE_DIR}/src/filter_hash.c
)
target_include_directories(shelltype_gate PUBLIC ${SHELLTYPE_DIR}/include)
target_link_libraries(shelltype_gate PUBLIC m)

# ── shellgate library ─────────────────────────────────────────
add_library(shellgate STATIC
    src/shellgate.c
)
target_include_directories(shellgate PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(shellgate PUBLIC shellsplit_gate shelltype_gate)

# ── Tests ─────────────────────────────────────────────────────
enable_testing()

add_executable(test_shellgate
    tests/test_shellgate.c
)
target_link_libraries(test_shellgate PRIVATE shellgate)

include(CTest)
add_test(NAME shellgate COMMAND test_shellgate)
