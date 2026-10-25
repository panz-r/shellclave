cmake_minimum_required(VERSION 3.20)
project(Shellclave VERSION 0.17.0 LANGUAGES C CXX)

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
include(cmake/CommandFixtureValidation.cmake)
include(cmake/SmokeSeedManifests.cmake)

option(SHELLCLAVE_BUILD_TOOLS "Build command-line tools" ${PROJECT_IS_TOP_LEVEL})
option(SHELLCLAVE_BUILD_BENCHMARKS "Build micro-benchmarks" OFF)
option(SHELLCLAVE_BUILD_FUZZERS "Build libFuzzer harnesses" OFF)
option(SHELLCLAVE_ENABLE_COVERAGE "Enable GCC/Clang coverage instrumentation" OFF)
set(SHELLCLAVE_COVERAGE_VARIANT "tests" CACHE STRING
    "Coverage implementation variant: tests or production (use separate build directories)")
set_property(CACHE SHELLCLAVE_COVERAGE_VARIANT PROPERTY STRINGS tests production)
if(SHELLCLAVE_ENABLE_COVERAGE AND NOT SHELLCLAVE_COVERAGE_VARIANT MATCHES "^(tests|production)$")
  message(FATAL_ERROR "SHELLCLAVE_COVERAGE_VARIANT must be tests or production")
endif()
if(SHELLCLAVE_ENABLE_COVERAGE AND SHELLCLAVE_COVERAGE_VARIANT STREQUAL "tests" AND NOT BUILD_TESTING)
  message(FATAL_ERROR "The tests coverage variant requires BUILD_TESTING=ON")
endif()
option(SHELLCLAVE_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSanitizer" OFF)
option(SHELLCLAVE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(SHELLCLAVE_ENABLE_SANITIZERS AND SHELLCLAVE_ENABLE_TSAN)
  message(FATAL_ERROR "ASan/UBSan and TSan cannot be enabled together")
endif()

if(BUILD_TESTING OR SHELLCLAVE_BUILD_FUZZERS)
  find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
endif()

find_package(Threads REQUIRED)

set(SHELLCLAVE_PUBLIC_HEADERS
  shellsplit/include/shell_contract.h
  shellsplit/include/env_screener.h
  shellsplit/include/relative_permutation_entropy.h
  shellsplit/include/shell_abstract.h
  shellsplit/include/shell_depgraph.h
  shellsplit/include/shell_expand.h
  shellsplit/include/shell_interop.h
  shellsplit/include/shell_netstring.h
  shellsplit/include/shell_processor.h
  shellsplit/include/shell_sequence.h
  shellsplit/include/shell_source.h
  shellsplit/include/shell_tokenizer.h
  shellsplit/include/shell_tokenizer_full.h
  shellsplit/include/shell_transform.h
  shelltype/include/shelltype.h
  shellgate/include/sg_anomaly.h
  shellgate/include/shellgate.h)

function(shellclave_fatal_ubsan target)
  # A diagnostic must fail verification, including direct executable runs.
  # Compile non-recovering checks rather than relying on UBSAN_OPTIONS.
  target_compile_options(${target} PRIVATE -fno-sanitize-recover=undefined)
endfunction()

function(shellclave_project_target target)
  target_compile_features(${target} PUBLIC c_std_11)
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  if(SHELLCLAVE_ENABLE_COVERAGE)
    # Fault-injection seams change compiler block identities. Their counters
    # cannot be meaningfully merged with the shipping library's CFG. Always
    # instrument test executables (including inline helper tests), but only
    # the selected implementation variant; keep production coverage separate.
    if(NOT (SHELLCLAVE_COVERAGE_VARIANT STREQUAL "tests" AND
            target MATCHES "^(shellsplit|shelltype|shellgate)$") AND
       NOT (SHELLCLAVE_COVERAGE_VARIANT STREQUAL "production" AND
            target MATCHES "^(shellsplit|shelltype|shellgate)_test$"))
      target_compile_options(${target} PRIVATE --coverage)
    endif()
    target_link_options(${target} PRIVATE --coverage)
  endif()
  if(SHELLCLAVE_ENABLE_SANITIZERS)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
  if(SHELLCLAVE_ENABLE_TSAN)
    target_compile_options(${target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=thread)
  endif()
  if(SHELLCLAVE_BUILD_FUZZERS)
    # Coverage-guided fuzzing needs optimized instrumented code, even when
    # verify-push requests Debug. Keep symbols/assertions and every sanitizer;
    # -O0 magnifies recursive predicate bookkeeping instead of exploring inputs.
    target_compile_options(${target} PRIVATE -O2 -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
  if(SHELLCLAVE_ENABLE_SANITIZERS OR SHELLCLAVE_BUILD_FUZZERS)
    shellclave_fatal_ubsan(${target})
  endif()
endfunction()

set(SHELLSPLIT_SOURCES
  shellsplit/src/env_screener.c
  shellsplit/src/relative_permutation_entropy.c
  shellsplit/src/shell_abstract.c
  shellsplit/src/shell_arithmetic.c
  shellsplit/src/shell_conditional.c
  shellsplit/src/shell_depgraph.c
  shellsplit/src/shell_expand.c
  shellsplit/src/shell_heredoc.c
  shellsplit/src/shell_interop.c
  shellsplit/src/shell_keywords.c
  shellsplit/src/shell_netstring.c
  shellsplit/src/shell_processor.c
  shellsplit/src/shell_semantics.c
  shellsplit/src/shell_source.c
  shellsplit/src/shell_source_admission.c
  shellsplit/src/shell_source_runtime.c
  shellsplit/src/shell_tokenizer.c
  shellsplit/src/shell_tokenizer_full.c
  shellsplit/src/shell_transform.c
  shellsplit/src/shell_word.c)
add_library(shellsplit ${SHELLSPLIT_SOURCES})
add_library(Shellclave::shellsplit ALIAS shellsplit)
shellclave_project_target(shellsplit)
target_include_directories(shellsplit PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/shellclave>)
target_link_libraries(shellsplit PRIVATE m)
set_target_properties(shellsplit PROPERTIES EXPORT_NAME shellsplit)

if(BUILD_TESTING)
  add_library(shellsplit_test ${SHELLSPLIT_SOURCES}
    shellsplit/tests/test_allocator.c shellsplit/tests/test_source_scans.c)
  shellclave_project_target(shellsplit_test)
  target_compile_definitions(shellsplit_test PRIVATE
    SHELLSPLIT_TEST_ALLOCATOR SHELLSPLIT_TEST_SOURCE_SCANS)
  target_include_directories(shellsplit_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/src
            ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tests)
  target_link_libraries(shellsplit_test PRIVATE m)
endif()

set(SHELLTYPE_SOURCES
  shelltype/src/arena.c
  shelltype/src/crc32.c
  shelltype/src/filter_hash.c
  shelltype/src/netpattern.c
  shelltype/src/normalize.c
  shelltype/src/policy.c
  shelltype/src/policy_ctx.c
  shelltype/src/trie.c
  shelltype/src/trie_variants.c
  deps/draugr/src/vacuum_filter.c)
add_library(shelltype ${SHELLTYPE_SOURCES})
add_library(Shellclave::shelltype ALIAS shelltype)
shellclave_project_target(shelltype)
target_include_directories(shelltype PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/shelltype/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/shellclave>
  PRIVATE deps/draugr/include)
target_link_libraries(shelltype PRIVATE m PUBLIC Threads::Threads shellsplit)
set_target_properties(shelltype PROPERTIES EXPORT_NAME shelltype)

if(BUILD_TESTING)
  add_library(shelltype_test ${SHELLTYPE_SOURCES}
    shelltype/tests/test_allocator.c shelltype/tests/test_io.c)
  shellclave_project_target(shelltype_test)
  target_compile_definitions(shelltype_test PRIVATE
    SHELLTYPE_TEST_ALLOCATOR SHELLTYPE_TEST_IO)
  target_include_directories(shelltype_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/shelltype/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/shelltype/src
            ${CMAKE_CURRENT_SOURCE_DIR}/shelltype/tests
            deps/draugr/include)
  target_link_libraries(shelltype_test PRIVATE m PUBLIC Threads::Threads shellsplit_test)
endif()

set(SHELLGATE_SOURCES shellgate/src/shellgate.c shellgate/src/sg_anomaly.c)

function(shellclave_configure_shellgate_target target shelltype_target
         shellsplit_target)
  add_library(${target} ${SHELLGATE_SOURCES})
  shellclave_project_target(${target})
  target_include_directories(${target} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/shellgate/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/shellclave>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/src)
  target_link_libraries(${target} PUBLIC ${shellsplit_target} ${shelltype_target} PRIVATE m)

  # Reuse dependency targets supplied by a parent. In a standalone build,
  # compile the pinned private implementations into Shellgate so installed
  # static archives do not expose third-party targets to consumers.
  if(TARGET draugr)
    target_link_libraries(${target} PRIVATE $<BUILD_INTERFACE:draugr>)
  else()
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/draugr/src/ht.c")
      message(FATAL_ERROR
        "deps/draugr is missing; clone with --recurse-submodules")
    endif()
    target_sources(${target} PRIVATE deps/draugr/src/ht.c
      deps/draugr/src/ht_cache.c deps/draugr/src/util.c)
    target_include_directories(${target} PRIVATE deps/draugr/include)
    target_compile_definitions(${target} PRIVATE DRAUGR_USE_MALLOC)
  endif()
  if(TARGET xxHash::xxhash)
    target_link_libraries(${target} PRIVATE $<BUILD_INTERFACE:xxHash::xxhash>)
  elseif(TARGET xxhash)
    target_link_libraries(${target} PRIVATE $<BUILD_INTERFACE:xxhash>)
  else()
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash/xxhash.c")
      message(FATAL_ERROR
        "deps/xxhash is missing; clone with --recurse-submodules")
    endif()
    target_sources(${target} PRIVATE deps/xxhash/xxhash.c)
    target_include_directories(${target} PRIVATE deps/xxhash)
  endif()
endfunction()

shellclave_configure_shellgate_target(shellgate shelltype shellsplit)
add_library(Shellclave::shellgate ALIAS shellgate)
set_target_properties(shellgate PROPERTIES EXPORT_NAME shellgate)

if(BUILD_TESTING)
  shellclave_configure_shellgate_target(shellgate_test shelltype_test shellsplit_test)
  target_sources(shellgate_test PRIVATE shellgate/tests/test_sg_failures.c)
  target_compile_definitions(shellgate_test PRIVATE
    SHELLGATE_TEST_ALLOCATOR SHELLGATE_TEST_ANOMALY_OPS SHELLGATE_TEST_IO
    SHELLSPLIT_TEST_SOURCE_SCANS)
  target_include_directories(shellgate_test PRIVATE shellgate/tests shellsplit/tests)
endif()

function(shellclave_add_test name source library)
  add_executable(${name} ${source})
  shellclave_project_target(${name})
  target_link_libraries(${name} PRIVATE ${library})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

function(shellclave_register_production_test name)
  # Generic registration adds only production-suite membership. Tests that
  # were created through another helper retain responsibility for their
  # component and any other suite labels.
  set_property(TEST ${name} APPEND PROPERTY LABELS production)
  add_dependencies(shellclave_production_tests ${name})
endfunction()

function(shellclave_add_production_test name source library)
  # Shipping-library production tests belong to that component as well as the
  # aggregate production suite. Keep both labels coupled to registration.
  shellclave_add_test(${name} ${source} ${library})
  set_property(TEST ${name} APPEND PROPERTY LABELS ${library})
  shellclave_register_production_test(${name})
endfunction()

function(shellclave_add_concurrency_test name source library)
  shellclave_add_test(${name} ${source} ${library})
  set_property(TEST ${name} APPEND PROPERTY LABELS concurrency)
  add_dependencies(shellclave_concurrency_tests ${name})
endfunction()

if(BUILD_TESTING OR SHELLCLAVE_BUILD_TOOLS)
  add_executable(shellclave_gate_example examples/gate_policy.c)
  shellclave_project_target(shellclave_gate_example)
  target_link_libraries(shellclave_gate_example PRIVATE Shellclave::shellgate)
  add_executable(shellclave_source_example examples/source_admission.c)
  shellclave_project_target(shellclave_source_example)
  target_link_libraries(shellclave_source_example PRIVATE Shellclave::shellsplit)
endif()

if(BUILD_TESTING)
  # One registration controls both the race-detector build and test selection.
  add_custom_target(shellclave_concurrency_tests)
  # The same membership drives production coverage's build and CTest label.
  add_custom_target(shellclave_production_tests)
  find_program(SHELLCLAVE_LOCALEDEF NAMES localedef REQUIRED)
  foreach(variant IN ITEMS tests production)
    if(variant STREQUAL "production")
      set(byte_test shellclave_byte_semantics_production_test)
      set(byte_library shellgate)
    else()
      set(byte_test shellclave_byte_semantics_test)
      set(byte_library shellgate_test)
    endif()
    add_executable(${byte_test} tests/test_byte_semantics.c)
    shellclave_project_target(${byte_test})
    target_link_libraries(${byte_test} PRIVATE ${byte_library})
    add_test(NAME ${byte_test}
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_host_locale.py"
        --probe $<TARGET_FILE:${byte_test}> --localedef "${SHELLCLAVE_LOCALEDEF}"
        --scratch "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(${byte_test} PROPERTIES LABELS "api;shellsplit;shelltype;shellgate"
      TIMEOUT 120)
    if(variant STREQUAL "production")
      shellclave_register_production_test(${byte_test})
    endif()
  endforeach()
  shellclave_add_production_test(shellgate_example_contract
    tests/test_gate_example.c shellgate)
  add_test(NAME shellclave_gate_example COMMAND shellclave_gate_example)
  set_tests_properties(shellclave_gate_example PROPERTIES LABELS "shellgate;example")
  add_test(NAME shellclave_source_example COMMAND shellclave_source_example)
  set_tests_properties(shellclave_source_example PROPERTIES LABELS "shellsplit;example")
  add_test(NAME shellclave_documentation_contract
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_documentation.py"
      --example $<TARGET_FILE:shellclave_gate_example>
      --source-example $<TARGET_FILE:shellclave_source_example>)
  set_tests_properties(shellclave_documentation_contract PROPERTIES LABELS docs)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests/headers")
  shellclave_add_test(shellsplit_abstract_cli_test
    shellsplit/tests/test_abstract_cli.c shellsplit)
  set_tests_properties(shellsplit_abstract_cli_test PROPERTIES
    LABELS "shellsplit;tools")
  set(supervisor_test_arguments
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fuzz_supervisor.py"
    --binary-dir "${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz-supervisor")
  if(SHELLCLAVE_BUILD_FUZZERS)
    list(APPEND supervisor_test_arguments
      --probe $<TARGET_FILE:shellclave_fuzz_startup_probe>)
  endif()
  add_test(NAME shellclave_fuzz_supervisor_test
    COMMAND "${Python3_EXECUTABLE}" ${supervisor_test_arguments})
  set_tests_properties(shellclave_fuzz_supervisor_test PROPERTIES
    LABELS "fuzz;supervisor" TIMEOUT 30)
  if(SHELLCLAVE_ENABLE_SANITIZERS OR SHELLCLAVE_BUILD_FUZZERS)
    foreach(language IN ITEMS c cpp)
      set(probe "shellclave_ubsan_${language}_probe")
      add_executable(${probe} tests/sanitizer_failure_probe.${language})
      shellclave_project_target(${probe})
      if(language STREQUAL "cpp")
        target_compile_features(${probe} PRIVATE cxx_std_11)
      endif()
      add_test(NAME shellclave_ubsan_${language}_fatal
        COMMAND ${CMAKE_COMMAND}
          -DSHELLCLAVE_UBSAN_PROBE=$<TARGET_FILE:${probe}>
          -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_ubsan_fatal.cmake)
      set_tests_properties(shellclave_ubsan_${language}_fatal PROPERTIES
        LABELS sanitizer TIMEOUT 30)
    endforeach()
  endif()
  find_program(SHELLCLAVE_BASH_EXECUTABLE NAMES bash)
  include(cmake/ReferenceBash.cmake)
  shellclave_require_reference_bash("${SHELLCLAVE_BASH_EXECUTABLE}")
  add_test(NAME shellclave_reference_bash_contract
    COMMAND ${CMAKE_COMMAND}
      -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DSHELLCLAVE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
      -DSHELLCLAVE_BASH_EXECUTABLE=${SHELLCLAVE_BASH_EXECUTABLE}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_reference_bash.cmake)
  set_tests_properties(shellclave_reference_bash_contract PROPERTIES LABELS cmake)
  if(SHELLCLAVE_BASH_EXECUTABLE)
    add_test(NAME shellsplit_bash_async_stdin
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_async_stdin.cmake)
    set_tests_properties(shellsplit_bash_async_stdin PROPERTIES
      LABELS shellsplit TIMEOUT 15
      ENVIRONMENT
        "BASH_ENV=${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/bash_env_enable_lastpipe.sh;BASHOPTS=lastpipe;SHELLOPTS=braceexpand:hashall:interactive-comments:monitor;POSIXLY_CORRECT=1;BASH_COMPAT=42;BASH_XTRACEFD=9")
    add_test(NAME shellsplit_bash_descriptor_moves
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_descriptor_moves.cmake)
    set_tests_properties(shellsplit_bash_descriptor_moves PROPERTIES
      LABELS shellsplit TIMEOUT 15)
    add_test(NAME shellsplit_bash_ansi_nul_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_ansi_nul_semantics.cmake)
    set_tests_properties(shellsplit_bash_ansi_nul_semantics PROPERTIES
      LABELS shellsplit)
    add_test(NAME shellsplit_bash_time_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_time_semantics.cmake)
    set_tests_properties(shellsplit_bash_time_semantics PROPERTIES
      LABELS shellsplit)
    add_test(NAME shellsplit_bash_process_pipe_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_process_pipe_semantics.cmake)
    set_tests_properties(shellsplit_bash_process_pipe_semantics PROPERTIES
      LABELS shellsplit TIMEOUT 10)
    # Each trusted read fixture owns one bounded Bash process.  Keep them as
    # independent CTest cases so runtimes and failures cannot accumulate under
    # one outer timeout.
    set(shellsplit_bash_read_fixtures
      read_input
      allocation_correlation
      selector_lifecycle
      read_proofs
      private_read_outcomes
      outcome_transfers)
    foreach(fixture IN LISTS shellsplit_bash_read_fixtures)
      add_test(NAME shellsplit_bash_${fixture}
        COMMAND ${CMAKE_COMMAND}
          -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
          -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_${fixture}.cmake)
      set_tests_properties(shellsplit_bash_${fixture} PROPERTIES
        LABELS shellsplit TIMEOUT 10)
    endforeach()
    add_test(NAME shellsplit_bash_word_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_word_semantics.cmake)
    set_tests_properties(shellsplit_bash_word_semantics PROPERTIES
      LABELS shellsplit)
    add_test(NAME shellsplit_bash_source_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_source_semantics.cmake)
    set_tests_properties(shellsplit_bash_source_semantics PROPERTIES LABELS shellsplit)
    add_test(NAME shellsplit_bash_conditional_commands
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bash_conditional_commands.py"
        --bash "${SHELLCLAVE_BASH_EXECUTABLE}" --probe $<TARGET_FILE:shellsplit_conditional_production_test>)
    set_tests_properties(shellsplit_bash_conditional_commands PROPERTIES LABELS shellsplit TIMEOUT 45)
    add_test(NAME shellsplit_bash_arithmetic_commands
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bash_arithmetic_commands.py"
        --bash "${SHELLCLAVE_BASH_EXECUTABLE}" --probe $<TARGET_FILE:shellsplit_arithmetic_production_test>)
    set_tests_properties(shellsplit_bash_arithmetic_commands PROPERTIES LABELS shellsplit TIMEOUT 45)
    add_test(NAME shellsplit_bash_source_status
      COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bash_source_status.py"
        --bash "${SHELLCLAVE_BASH_EXECUTABLE}"
        --probe $<TARGET_FILE:shellsplit_source_status_production_test>)
    set_tests_properties(shellsplit_bash_source_status PROPERTIES
      LABELS shellsplit TIMEOUT 45)
    if(UNIX)
      add_test(NAME shellsplit_bash_readline_semantics
        COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bash_readline_semantics.py"
          "${SHELLCLAVE_BASH_EXECUTABLE}")
      set_tests_properties(shellsplit_bash_readline_semantics PROPERTIES
        LABELS shellsplit TIMEOUT 45 SKIP_RETURN_CODE 77)
    endif()
    add_test(NAME shellsplit_bash_named_fd_semantics
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_BASH=${SHELLCLAVE_BASH_EXECUTABLE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_bash_named_fd_semantics.cmake)
    set_tests_properties(shellsplit_bash_named_fd_semantics PROPERTIES
      LABELS shellsplit
      ENVIRONMENT
        "BASH_ENV=${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/bash_env_enable_lastpipe.sh;BASHOPTS=lastpipe;SHELLOPTS=braceexpand:hashall:interactive-comments:monitor;POSIXLY_CORRECT=1")
  endif()
  shellclave_add_test(shellsplit_tokenizer_test shellsplit/tests/tokenizer_test.c shellsplit_test)
  shellclave_add_test(shellsplit_depgraph_compare_test
    shellsplit/tests/depgraph_compare_test.c shellsplit)
  set_tests_properties(shellsplit_depgraph_compare_test PROPERTIES LABELS shellsplit)
  shellclave_add_test(shellsplit_source_compare_test
    shellsplit/tests/source_compare_test.c shellsplit)
  set_tests_properties(shellsplit_source_compare_test PROPERTIES LABELS shellsplit)
  shellclave_add_test(shellsplit_fast_parser_test shellsplit/tests/fast_parser_test.c shellsplit_test)
  # Exercise the same public parser contract against the shipping library. The
  # allocation-failure variant above links the instrumented test library;
  # keeping this production variant prevents that build from being the only
  # implementation exercised by the parser regression suite.
  shellclave_add_production_test(shellsplit_fast_parser_production_test shellsplit/tests/fast_parser_test.c shellsplit)
  target_compile_definitions(shellsplit_fast_parser_test PRIVATE
    SHELLSPLIT_TEST_SOURCE_SCANS)
  shellclave_add_test(shellsplit_abstract_test shellsplit/tests/abstract_test.c shellsplit_test)
  # Run identical syntax/codec contracts in both variants. These cases do not
  # use fault hooks, but must cover the test CFG as well as shipping behavior.
  shellclave_add_test(shellsplit_semantics_test
    shellsplit/tests/production_semantics_test.c shellsplit_test)
  target_compile_definitions(shellsplit_semantics_test PRIVATE
    SHELLSPLIT_TEST_SOURCE_SCANS)
  target_include_directories(shellsplit_semantics_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tests)
  shellclave_add_production_test(shellsplit_production_semantics_test
    shellsplit/tests/production_semantics_test.c shellsplit)
  set_property(TEST shellsplit_semantics_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_test(shellsplit_conditional_test shellsplit/tests/conditional_test.c shellsplit_test)
  target_compile_definitions(shellsplit_conditional_test PRIVATE SHELLSPLIT_TEST_SOURCE_SCANS)
  set_property(TEST shellsplit_conditional_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_production_test(shellsplit_conditional_production_test shellsplit/tests/conditional_test.c shellsplit)
  shellclave_add_test(shellsplit_arithmetic_test shellsplit/tests/arithmetic_test.c shellsplit_test)
  target_compile_definitions(shellsplit_arithmetic_test PRIVATE SHELLSPLIT_TEST_SOURCE_SCANS)
  set_property(TEST shellsplit_arithmetic_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_production_test(shellsplit_arithmetic_production_test shellsplit/tests/arithmetic_test.c shellsplit)
  shellclave_add_test(shellsplit_entropy_test shellsplit/tests/entropy_test.c shellsplit_test)
  shellclave_add_test(shellsplit_depgraph_test shellsplit/tests/test_depgraph.c shellsplit_test)
  shellclave_add_test(shellsplit_boundary_test shellsplit/tests/boundary_test.c shellsplit_test)
  shellclave_add_test(shellsplit_source_test shellsplit/tests/source_test.c shellsplit_test)
  target_compile_definitions(shellsplit_source_test PRIVATE SHELLSPLIT_TEST_SOURCE_SCANS SHELLSPLIT_TEST_ALLOCATOR)
  target_include_directories(shellsplit_source_test PRIVATE shellsplit/tests)
  shellclave_add_production_test(shellsplit_source_production_test shellsplit/tests/source_test.c shellsplit)
  set_property(TEST shellsplit_source_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_test(shellsplit_source_status_test
    shellsplit/tests/source_status_test.c shellsplit_test)
  shellclave_add_production_test(shellsplit_source_status_production_test
    shellsplit/tests/source_status_test.c shellsplit)
  target_compile_definitions(shellsplit_boundary_test PRIVATE SHELLSPLIT_TEST_SOURCE_SCANS)
  target_include_directories(shellsplit_boundary_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tests)
  shellclave_add_production_test(shellsplit_boundary_production_test shellsplit/tests/boundary_test.c shellsplit)
  set_property(TEST shellsplit_boundary_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_test(shellsplit_read_input_test
    shellsplit/tests/read_input_test.c shellsplit_test)
  target_compile_definitions(shellsplit_read_input_test PRIVATE
    SHELLSPLIT_TEST_ALLOCATOR SHELLSPLIT_TEST_SOURCE_SCANS)
  shellclave_add_production_test(shellsplit_read_input_production_test
    shellsplit/tests/read_input_test.c shellsplit)
  set_property(TEST shellsplit_read_input_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_test(shellsplit_descriptor_move_test
    shellsplit/tests/descriptor_move_test.c shellsplit_test)
  target_compile_definitions(shellsplit_descriptor_move_test PRIVATE
    SHELLSPLIT_TEST_ALLOCATOR SHELLSPLIT_TEST_SOURCE_SCANS)
  shellclave_add_production_test(shellsplit_descriptor_move_production_test
    shellsplit/tests/descriptor_move_test.c shellsplit)
  target_compile_definitions(shellsplit_depgraph_test PRIVATE
    SHELLSPLIT_TEST_SOURCE_SCANS)
  # The dependency graph has no allocator-test dependency, so run its full
  # public contract against both the fault-injection and shipping builds.
  shellclave_add_production_test(shellsplit_depgraph_production_test shellsplit/tests/test_depgraph.c shellsplit)
  shellclave_add_test(shellsplit_interop_test shellsplit/tests/interop_test.c shellsplit_test)
  shellclave_add_test(shellsplit_netstring_test shellsplit/tests/netstring_test.c shellsplit_test)
  foreach(shellsplit_test_target IN ITEMS shellsplit_tokenizer_test
      shellsplit_fast_parser_test shellsplit_abstract_test shellsplit_entropy_test
      shellsplit_depgraph_test shellsplit_interop_test shellsplit_netstring_test
      shellsplit_fast_parser_production_test shellsplit_depgraph_production_test
      shellsplit_read_input_test shellsplit_read_input_production_test)
    target_include_directories(${shellsplit_test_target} PRIVATE shellsplit/tests)
  endforeach()
  shellclave_add_test(shelltype_token_types_test shelltype/tests/test_token_types.c shelltype_test)
  shellclave_add_test(shelltype_unit_test shelltype/tests/test_shelltype.c shelltype_test)
  shellclave_add_test(shelltype_arena_test shelltype/tests/test_arena.c shelltype_test)
  target_include_directories(shelltype_arena_test PRIVATE shelltype/src shelltype/tests)
  shellclave_add_test(shelltype_policy_test shelltype/tests/test_policy.c shelltype_test)
  # Always compile and exercise the real benchmark caller, even when optional
  # throughput executables are disabled. The test uses bounded iterations.
  shellclave_add_test(shelltype_policy_benchmark_test
    shelltype/tests/test_policy_benchmark.c shelltype_test)
  target_include_directories(shelltype_policy_benchmark_test PRIVATE shelltype/tests)
  set_tests_properties(shelltype_policy_benchmark_test PROPERTIES LABELS "shelltype;benchmark")
  shellclave_add_concurrency_test(shelltype_policy_concurrency_test shelltype/tests/test_policy_concurrency.c shelltype_test)
  shellclave_add_test(shelltype_verify_test shelltype/tests/test_verify.c shelltype_test)
  shellclave_add_test(shelltype_integration_test shelltype/tests/test_shelltype_integration.c shelltype_test)
  foreach(variant IN ITEMS test production)
    if(variant STREQUAL "test")
      set(contract_library shelltype_test)
    else()
      set(contract_library shelltype)
    endif()
    shellclave_add_test(shelltype_public_contract_${variant}
      shelltype/tests/test_public_contract.c ${contract_library})
    set_property(TEST shelltype_public_contract_${variant} APPEND PROPERTY LABELS shelltype)
    if(variant STREQUAL "production")
      shellclave_register_production_test(shelltype_public_contract_${variant})
    else()
      set_property(TEST shelltype_public_contract_${variant} APPEND PROPERTY LABELS test)
    endif()
  endforeach()
  add_executable(processed_subcommand_integration_test
    tests/test_processed_subcommand.c)
  shellclave_project_target(processed_subcommand_integration_test)
  target_link_libraries(processed_subcommand_integration_test PRIVATE
    shellsplit_test shelltype_test)
  add_test(NAME processed_subcommand_integration_test
    COMMAND processed_subcommand_integration_test)
  shellclave_add_test(shelltype_compact_policy_test shelltype/tests/test_policy_compact.c shelltype_test)
  target_include_directories(shelltype_compact_policy_test PRIVATE shelltype/src)
  shellclave_add_test(shelltype_policy_model_test shelltype/tests/test_policy_model.c shelltype_test)
  shellclave_add_test(shelltype_policy_capacity_test shelltype/tests/test_policy_capacity.c shelltype_test)
  set_tests_properties(shelltype_policy_capacity_test PROPERTIES TIMEOUT 300)
  foreach(shelltype_test_target IN ITEMS shelltype_token_types_test shelltype_unit_test
      shelltype_policy_test shelltype_policy_concurrency_test shelltype_verify_test
      shelltype_integration_test shelltype_compact_policy_test)
    target_include_directories(${shelltype_test_target} PRIVATE
      shelltype/src shelltype/tests)
  endforeach()
  shellclave_add_test(shellgate_unit_test shellgate/tests/test_shellgate.c shellgate_test)
  shellclave_add_test(shellgate_anomaly_test shellgate/tests/test_anomaly.c shellgate_test)
  shellclave_add_test(shellgate_io_test shellgate/tests/test_sg_io.c shellgate_test)
  set(shellclave_command_fixture_json
    "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tests/data/coding-agent-commands.json")
  set(shellclave_command_fixture_header
    "${CMAKE_CURRENT_BINARY_DIR}/tests/shellclave_command_corpus_fixtures.h")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${shellclave_command_fixture_json}")
  file(READ "${shellclave_command_fixture_json}" shellclave_command_fixture_data)
  string(JSON shellclave_command_fixture_format ERROR_VARIABLE shellclave_fixture_error
    GET "${shellclave_command_fixture_data}" format)
  if(NOT shellclave_fixture_error STREQUAL "NOTFOUND" OR
      NOT shellclave_command_fixture_format STREQUAL "shellclave-command-fixtures-v1")
    message(FATAL_ERROR "Unsupported command fixture format")
  endif()
  string(JSON shellclave_command_fixture_count ERROR_VARIABLE shellclave_fixture_error
    LENGTH "${shellclave_command_fixture_data}" commands)
  if(NOT shellclave_fixture_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR "Invalid command fixture JSON: ${shellclave_fixture_error}")
  endif()
  if(shellclave_command_fixture_count EQUAL 0)
    message(FATAL_ERROR "Command fixture JSON must not be empty")
  endif()
  file(WRITE "${shellclave_command_fixture_header}"
    "/* Generated from shellsplit/tests/data/coding-agent-commands.json. */\n"
    "#ifndef SHELLCLAVE_COMMAND_CORPUS_FIXTURES_H\n"
    "#define SHELLCLAVE_COMMAND_CORPUS_FIXTURES_H\n"
    "static const char *const shellclave_command_corpus_commands[] = {\n")
  math(EXPR shellclave_command_fixture_last "${shellclave_command_fixture_count} - 1")
  foreach(shellclave_command_fixture_index RANGE 0 ${shellclave_command_fixture_last})
    shellclave_read_command_fixture(shellclave_command_fixture
      "${shellclave_command_fixture_data}" ${shellclave_command_fixture_index})
    shellclave_validate_command_fixture("${shellclave_command_fixture}"
      "${shellclave_command_fixture_index}")
    shellclave_escape_command_fixture(shellclave_command_fixture_c
      "${shellclave_command_fixture}")
    file(APPEND "${shellclave_command_fixture_header}"
      "  \"${shellclave_command_fixture_c}\",\n")
  endforeach()
  file(APPEND "${shellclave_command_fixture_header}"
    "};\n"
    "#define SHELLCLAVE_COMMAND_CORPUS_COUNT ${shellclave_command_fixture_count}u\n"
    "#endif\n")
  # The same sanitized fixture is useful below Shellgate as well: it keeps
  # the public Shellsplit parsing, canonicalization, and graph surfaces in
  # agreement over realistic command shapes without ever executing them.
  shellclave_add_test(shellsplit_corpus_test shellsplit/tests/corpus_test.c shellsplit_test)
  shellclave_add_production_test(shellsplit_corpus_production_test
    shellsplit/tests/corpus_test.c shellsplit)
  target_include_directories(shellsplit_corpus_test PRIVATE
    shellsplit/tests "${CMAKE_CURRENT_BINARY_DIR}/tests")
  target_include_directories(shellsplit_corpus_production_test PRIVATE
    shellsplit/tests "${CMAKE_CURRENT_BINARY_DIR}/tests")
  set_property(TEST shellsplit_corpus_test APPEND PROPERTY LABELS shellsplit)
  shellclave_add_test(shellgate_corpus_test shellgate/tests/test_corpus.c shellgate_test)
  # Shared-policy concurrency uses shipping libraries, not global fault-injection
  # counters. Each thread owns a separate gate and evaluation workspace.
  shellclave_add_concurrency_test(shellgate_policy_sharing_test
    shellgate/tests/test_policy_sharing.c shellgate)
  shellclave_register_production_test(shellgate_policy_sharing_test)
  shellclave_add_test(shellsplit_expand_test
    shellsplit/tests/expand_test.c shellsplit_test)
  set_property(TEST shellgate_policy_sharing_test APPEND PROPERTY LABELS shellgate)
  target_include_directories(shellgate_corpus_test PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
  shellclave_add_production_test(shellgate_corpus_production_test shellgate/tests/test_corpus.c shellgate)
  target_include_directories(shellgate_corpus_production_test PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
  add_test(NAME shellclave_command_fixture_validation
    COMMAND "${CMAKE_COMMAND}" -P
      "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TestCommandFixtureValidation.cmake")
  set_tests_properties(shellclave_command_fixture_validation
    PROPERTIES WILL_FAIL TRUE LABELS "fixtures")
  add_test(NAME shellclave_command_fixture_type
    COMMAND "${CMAKE_COMMAND}" -P
      "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TestCommandFixtureType.cmake")
  set_tests_properties(shellclave_command_fixture_type
    PROPERTIES WILL_FAIL TRUE LABELS "fixtures")
  add_test(NAME shellclave_command_fixture_escaping
    COMMAND "${CMAKE_COMMAND}" -P
      "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TestCommandFixtureEscaping.cmake")
  set_tests_properties(shellclave_command_fixture_escaping
    PROPERTIES LABELS "fixtures")
  add_test(NAME shellsplit_sanitize_command_fixtures
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tests/test_sanitize_command_fixtures.py"
      "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/tools/sanitize_command_fixtures.py"
      "${shellclave_command_fixture_json}")
  set_tests_properties(shellsplit_sanitize_command_fixtures
    PROPERTIES LABELS "fixtures;shellsplit")
  target_compile_definitions(shellgate_io_test PRIVATE
    SHELLGATE_TEST_ALLOCATOR SHELLGATE_TEST_IO)
  target_include_directories(shellgate_io_test PRIVATE
    shellgate/src shellgate/tests)
  target_include_directories(shellgate_unit_test PRIVATE shelltype/tests)
  target_include_directories(shellgate_unit_test PRIVATE shellsplit/tests)
  target_include_directories(shellgate_anomaly_test PRIVATE shellgate/tests)
  set_tests_properties(shellgate_unit_test PROPERTIES LABELS shellgate)
  set_tests_properties(shellgate_anomaly_test PROPERTIES
    LABELS "shellgate;anomaly")
  set_tests_properties(shellgate_io_test PROPERTIES LABELS shellgate)

  foreach(header IN LISTS SHELLCLAVE_PUBLIC_HEADERS)
    get_filename_component(header_name "${header}" NAME)
    get_filename_component(header_stem "${header}" NAME_WE)
    string(REGEX MATCH "^[^/]+" header_library "${header}")

    foreach(language IN ITEMS c cpp)
      set(header_test
        "${CMAKE_CURRENT_BINARY_DIR}/tests/headers/${header_stem}.${language}")
      if(language STREQUAL "c")
        set(main_declaration "int main(void)")
      else()
        set(main_declaration "int main()")
      endif()
      file(GENERATE OUTPUT "${header_test}"
        CONTENT "#include <${header_name}>\n${main_declaration} { return 0; }\n")
      set(target "shellclave_${language}_header_${header_stem}_test")
      add_executable(${target} "${header_test}")
      target_link_libraries(${target} PRIVATE ${header_library})
      if(language STREQUAL "c")
        shellclave_project_target(${target})
      else()
        target_compile_features(${target} PRIVATE cxx_std_11)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
          target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        endif()
      endif()
    endforeach()
  endforeach()

  add_executable(shellsplit_ast_generator_test
    shellsplit/tests/ast_generator_test.c
    shellsplit/tests/generator/shell_ast.c
    shellsplit/tests/generator/shell_ast_generator.c)
  shellclave_project_target(shellsplit_ast_generator_test)
  target_include_directories(shellsplit_ast_generator_test PRIVATE
    shellsplit/tests/generator)
  target_link_libraries(shellsplit_ast_generator_test PRIVATE shellsplit)
  add_test(NAME shellsplit_ast_generator_seed_1 COMMAND shellsplit_ast_generator_test -n 10000 -s 1)
  add_test(NAME shellclave_public_api_names
    COMMAND ${CMAKE_COMMAND}
      -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_public_api_names.cmake)
  set_tests_properties(shellclave_public_api_names PROPERTIES LABELS api)

  # Inspect registrations, not executable existence: this also runs before a
  # selective build. CI's fresh aggregate-only build checks artifact creation.
  add_test(NAME shellclave_test_suite_contract
    COMMAND ${CMAKE_COMMAND}
      -DSHELLCLAVE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
      -DSHELLCLAVE_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
      "-DSHELLCLAVE_PRODUCTION_TARGETS=$<TARGET_PROPERTY:shellclave_production_tests,MANUALLY_ADDED_DEPENDENCIES>"
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_suite_registration.cmake)
  set_tests_properties(shellclave_test_suite_contract PROPERTIES LABELS cmake)

  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_test(NAME shellclave_pointer_contracts
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DSHELLCLAVE_C_COMPILER=${CMAKE_C_COMPILER}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_pointer_contracts.cmake)
    set_tests_properties(shellclave_pointer_contracts PROPERTIES LABELS api)
  endif()

  if(NOT SHELLCLAVE_ENABLE_SANITIZERS AND NOT SHELLCLAVE_ENABLE_TSAN
      AND NOT SHELLCLAVE_ENABLE_COVERAGE AND NOT SHELLCLAVE_BUILD_FUZZERS)
    add_test(NAME shellclave_installed_consumer
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DSHELLCLAVE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -DSHELLCLAVE_GENERATOR=${CMAKE_GENERATOR}
        -DSHELLCLAVE_C_COMPILER=${CMAKE_C_COMPILER}
        -DSHELLCLAVE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DSHELLCLAVE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_installed.cmake)
    add_test(NAME shellclave_embedded_consumer
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DSHELLCLAVE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -DSHELLCLAVE_GENERATOR=${CMAKE_GENERATOR}
        -DSHELLCLAVE_C_COMPILER=${CMAKE_C_COMPILER}
        -DSHELLCLAVE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DSHELLCLAVE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_embedded.cmake)
    if(PROJECT_IS_TOP_LEVEL)
      add_test(NAME shellgate_component_configure
        COMMAND ${CMAKE_COMMAND}
          -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
          -DSHELLCLAVE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
          -DSHELLCLAVE_GENERATOR=${CMAKE_GENERATOR}
          -DSHELLCLAVE_C_COMPILER=${CMAKE_C_COMPILER}
          -DSHELLCLAVE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
          -DSHELLCLAVE_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
          -DSHELLCLAVE_BASH_EXECUTABLE=${SHELLCLAVE_BASH_EXECUTABLE}
          -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_shellgate_component.cmake)
      set_tests_properties(shellgate_component_configure PROPERTIES
        LABELS cmake)
    endif()
  endif()
endif()

if(SHELLCLAVE_BUILD_TOOLS)
  foreach(tool IN ITEMS shell_abstract_cli env_screener_demo relative_entropy_demo)
    add_executable(${tool} shellsplit/tools/${tool}.c)
    shellclave_project_target(${tool})
    target_link_libraries(${tool} PRIVATE shellsplit)
  endforeach()
  add_executable(shelltype_tool shelltype/tools/shelltype-tool.c)
  shellclave_project_target(shelltype_tool)
  target_link_libraries(shelltype_tool PRIVATE shelltype)
  target_include_directories(shelltype_tool PRIVATE shelltype/src)
  if(BUILD_TESTING)
    add_executable(shelltype_tool_binary_input_test
      shelltype/tests/test_tool_binary_input.c)
    shellclave_project_target(shelltype_tool_binary_input_test)
    add_dependencies(shelltype_tool_binary_input_test shelltype_tool)
    add_test(NAME shelltype_tool_binary_input
      COMMAND shelltype_tool_binary_input_test $<TARGET_FILE:shelltype_tool>)
  endif()
  foreach(tool IN ITEMS anomaly_demo anomaly_calibrate)
    add_executable(${tool} shellgate/tools/${tool}.c)
    shellclave_project_target(${tool})
    target_link_libraries(${tool} PRIVATE shellgate)
  endforeach()
  if(BUILD_TESTING)
    add_test(NAME shellgate_anomaly_calibrate_workspace
      COMMAND ${CMAKE_COMMAND}
        -DSHELLCLAVE_ANOMALY_CALIBRATE=$<TARGET_FILE:anomaly_calibrate>
        -DSHELLCLAVE_ANOMALY_CORPUS=${CMAKE_CURRENT_SOURCE_DIR}/shellgate/tests/data/anomaly_calibrate_normal.txt
        -DSHELLCLAVE_ANOMALY_TEMP=${CMAKE_CURRENT_BINARY_DIR}/anomaly-calibrate-test
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_anomaly_calibrate.cmake)
    set_tests_properties(shellgate_anomaly_calibrate_workspace PROPERTIES
      LABELS shellgate)
  endif()
endif()

if(SHELLCLAVE_BUILD_BENCHMARKS)
  add_executable(shelltype_policy_benchmark
    shelltype/benchmarks/policy_benchmark.c)
  shellclave_project_target(shelltype_policy_benchmark)
  target_link_libraries(shelltype_policy_benchmark PRIVATE shelltype)
endif()

if(SHELLCLAVE_BUILD_FUZZERS)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR
      NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
      "SHELLCLAVE_BUILD_FUZZERS requires Clang for both C and C++")
  endif()
  add_executable(fuzz_shellgate shellgate/fuzz/fuzz_shellgate.cpp)
  target_compile_definitions(fuzz_shellgate PRIVATE HAS_LIBFUZZER)
  target_compile_features(fuzz_shellgate PRIVATE cxx_std_17)
  target_include_directories(fuzz_shellgate PRIVATE shellsplit/fuzz)
  target_compile_options(fuzz_shellgate PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_shellgate PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_shellgate PRIVATE shellgate)

  function(shellclave_stage_smoke_seeds fuzzer_name)
    string(TOUPPER "${fuzzer_name}" fuzzer_upper)
    set(manifest "${SHELLCLAVE_${fuzzer_upper}_SMOKE_SEEDS}")
    set(smoke_seed_dir
      "${CMAKE_CURRENT_SOURCE_DIR}/${fuzzer_name}/fuzz/smoke-seeds")
    if(NOT manifest)
      message(FATAL_ERROR "${fuzzer_name} smoke seed manifest is empty")
    endif()
    set(smoke_seed_files)
    foreach(smoke_seed_name IN LISTS manifest)
      if(smoke_seed_name MATCHES "[/\\]" OR
         smoke_seed_name MATCHES "^\\.\\.")
        message(FATAL_ERROR
          "${fuzzer_name} smoke seed manifest contains an unsafe filename: ${smoke_seed_name}")
      endif()
      set(smoke_seed "${smoke_seed_dir}/${smoke_seed_name}")
      if(NOT EXISTS "${smoke_seed}" OR IS_DIRECTORY "${smoke_seed}")
        message(FATAL_ERROR
          "${fuzzer_name} smoke seed manifest entry is not a regular file: ${smoke_seed}")
      endif()
      list(APPEND smoke_seed_files "${smoke_seed}")
    endforeach()
    list(LENGTH smoke_seed_files smoke_seed_count)
    if(smoke_seed_count GREATER 64)
      message(FATAL_ERROR
        "${fuzzer_name} smoke seed set exceeds the 64-file limit")
    endif()
    set(smoke_seed_bytes 0)
    foreach(smoke_seed IN LISTS smoke_seed_files)
      file(SIZE "${smoke_seed}" smoke_seed_size)
      math(EXPR smoke_seed_bytes "${smoke_seed_bytes}+${smoke_seed_size}")
    endforeach()
    if(smoke_seed_bytes GREATER 1048576)
      message(FATAL_ERROR
        "${fuzzer_name} smoke seed set exceeds the 1 MiB size limit")
    endif()
    set(smoke_seed_stage_dir
      "${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-seeds/${fuzzer_name}")
    set(smoke_stage_commands)
    foreach(smoke_seed IN LISTS smoke_seed_files)
      list(APPEND smoke_stage_commands
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${smoke_seed}"
          "${smoke_seed_stage_dir}")
    endforeach()
    add_custom_target(stage-${fuzzer_name}-smoke-seeds
      COMMAND ${CMAKE_COMMAND} -E rm -rf "${smoke_seed_stage_dir}"
      COMMAND ${CMAKE_COMMAND} -E make_directory "${smoke_seed_stage_dir}"
      ${smoke_stage_commands})
    set("SHELLCLAVE_${fuzzer_upper}_SMOKE_STAGE_DIR" "${smoke_seed_stage_dir}"
        PARENT_SCOPE)
  endfunction()

  foreach(fuzzer_name IN ITEMS shellgate shellsplit shelltype)
    shellclave_stage_smoke_seeds("${fuzzer_name}")
  endforeach()

  add_executable(fuzz_shellsplit shellsplit/fuzz/tokenizer_fuzzer.cpp)
  target_compile_features(fuzz_shellsplit PRIVATE cxx_std_11)
  target_include_directories(fuzz_shellsplit PRIVATE shellsplit/tests)
  target_compile_options(fuzz_shellsplit PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_shellsplit PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_shellsplit PRIVATE shellsplit)
  add_executable(fuzz_shelltype shelltype/fuzz/fuzz_shelltype.cpp)
  target_compile_features(fuzz_shelltype PRIVATE cxx_std_11)
  target_include_directories(fuzz_shelltype PRIVATE shelltype/src)
  target_compile_options(fuzz_shelltype PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_shelltype PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_shelltype PRIVATE shelltype)
  foreach(fuzzer IN ITEMS fuzz_shellgate fuzz_shellsplit fuzz_shelltype)
    target_include_directories(${fuzzer} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
    target_compile_options(${fuzzer} PRIVATE -O2 -Wall -Wextra -Wpedantic)
    shellclave_fatal_ubsan(${fuzzer})
  endforeach()

  if(BUILD_TESTING)
    add_executable(shellclave_fuzz_startup_probe tests/fuzz_startup_probe.cpp)
    shellclave_project_target(shellclave_fuzz_startup_probe)
    target_link_options(shellclave_fuzz_startup_probe PRIVATE
      -fsanitize=fuzzer,address,undefined)
    # Startup sweeps have a separate whole-process deadline: they must not
    # consume an individual fuzz input's ten-second timeout budget.
    foreach(component IN ITEMS shellsplit shellgate)
      add_test(NAME ${component}_fuzz_startup_test
        COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.py" startup
          $<TARGET_FILE:fuzz_${component}>
          "${CMAKE_CURRENT_BINARY_DIR}/fuzz-startup-${component}_")
      set_tests_properties(${component}_fuzz_startup_test PROPERTIES
        LABELS "fuzz;startup" TIMEOUT 70)
    endforeach()
  endif()

  set(SHELLCLAVE_FUZZ_RUNS "1000" CACHE STRING
      "Number of libFuzzer smoke-test runs")
  set(SHELLCLAVE_FUZZ_MAX_LEN "8192" CACHE STRING
      "Maximum libFuzzer input length for smoke tests")
  # Smoke tests use only the bounded seed sets below. Generated successful
  # inputs are kept in a disposable per-run corpus by the wrapper.
  add_custom_target(fuzz-shellsplit-smoke
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.py" smoke
      $<TARGET_FILE:fuzz_shellsplit>
      ${SHELLCLAVE_SHELLSPLIT_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellsplit
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellsplit_
    DEPENDS fuzz_shellsplit stage-shellsplit-smoke-seeds
    VERBATIM
    COMMENT "Running the unified Shellsplit fuzzer")
  add_custom_target(fuzz-shellgate-smoke
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.py" smoke
      $<TARGET_FILE:fuzz_shellgate>
      ${SHELLCLAVE_SHELLGATE_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellgate
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellgate_
    DEPENDS fuzz_shellgate stage-shellgate-smoke-seeds
    VERBATIM
    COMMENT "Running the Shellgate fuzzer")
  add_custom_target(fuzz-shelltype-smoke
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.py" smoke
      $<TARGET_FILE:fuzz_shelltype>
      ${SHELLCLAVE_SHELLTYPE_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shelltype
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shelltype_
    DEPENDS fuzz_shelltype stage-shelltype-smoke-seeds
    VERBATIM
    COMMENT "Running the Shelltype fuzzer")
  add_custom_target(fuzz-smoke
    DEPENDS fuzz-shellsplit-smoke fuzz-shellgate-smoke fuzz-shelltype-smoke
    COMMENT "Running all repository fuzz smoke tests")
endif()

if(PROJECT_IS_TOP_LEVEL)
  file(GLOB_RECURSE SHELLCLAVE_FORMAT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/shelltype/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/shelltype/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shelltype/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellgate/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellgate/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shellgate/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
  list(SORT SHELLCLAVE_FORMAT_SOURCES)
  find_program(SHELLCLAVE_CLANG_FORMAT
    NAMES clang-format-21 clang-format-20 clang-format-19 clang-format-18
          clang-format)
  if(SHELLCLAVE_CLANG_FORMAT)
    add_custom_target(format
      COMMAND ${SHELLCLAVE_CLANG_FORMAT} -i ${SHELLCLAVE_FORMAT_SOURCES}
      COMMENT "Formatting first-party C and C++ sources")
    add_custom_target(format-check
      COMMAND ${CMAKE_COMMAND}
        -DCLANG_FORMAT_EXECUTABLE=${SHELLCLAVE_CLANG_FORMAT}
        -DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckClangFormat.cmake
      COMMENT "Checking first-party C and C++ formatting")
  else()
    foreach(target IN ITEMS format format-check)
      add_custom_target(${target}
        COMMAND ${CMAKE_COMMAND} -E echo
          "clang-format was not found; install clang-format"
        COMMAND ${CMAKE_COMMAND} -E false
        COMMENT "clang-format is unavailable")
    endforeach()
  endif()

  find_program(SHELLCLAVE_SCAN_BUILD
    NAMES scan-build scan-build-21 scan-build-20 scan-build-19 scan-build-18)
  find_program(SHELLCLAVE_CLANG NAMES clang clang-21 clang-20 clang-19 clang-18)
  find_program(SHELLCLAVE_CLANGXX
    NAMES clang++ clang++-21 clang++-20 clang++-19 clang++-18)
  if(SHELLCLAVE_SCAN_BUILD AND SHELLCLAVE_CLANG AND SHELLCLAVE_CLANGXX)
    set(analyzer_contract_arguments
      "-DSHELLCLAVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
      "-DSHELLCLAVE_SCAN_BUILD=${SHELLCLAVE_SCAN_BUILD}"
      "-DSHELLCLAVE_CLANG=${SHELLCLAVE_CLANG}"
      "-DSHELLCLAVE_CLANGXX=${SHELLCLAVE_CLANGXX}"
      "-DSHELLCLAVE_ANALYZE_GENERATOR=${CMAKE_GENERATOR}"
      "-DSHELLCLAVE_ANALYZE_TEST_BINARY=${CMAKE_CURRENT_BINARY_DIR}/clang-analyze-contract")
    if(BUILD_TESTING)
      add_test(NAME shellclave_clang_analyzer_contract
        COMMAND ${CMAKE_COMMAND} ${analyzer_contract_arguments}
          -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_clang_analyze.cmake)
      set_tests_properties(shellclave_clang_analyzer_contract PROPERTIES
        LABELS "cmake;analysis" TIMEOUT 120)
    endif()
    add_custom_target(clang-analyze
      COMMAND ${CMAKE_COMMAND} ${analyzer_contract_arguments}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_clang_analyze.cmake
      COMMAND ${CMAKE_COMMAND}
        "-DSHELLCLAVE_SCAN_BUILD=${SHELLCLAVE_SCAN_BUILD}"
        "-DSHELLCLAVE_CLANG=${SHELLCLAVE_CLANG}"
        "-DSHELLCLAVE_CLANGXX=${SHELLCLAVE_CLANGXX}"
        "-DSHELLCLAVE_ANALYZE_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}"
        "-DSHELLCLAVE_ANALYZE_BINARY=${CMAKE_CURRENT_BINARY_DIR}/clang-analyze"
        "-DSHELLCLAVE_ANALYZE_GENERATOR=${CMAKE_GENERATOR}"
        "-DSHELLCLAVE_BASH_EXECUTABLE=${SHELLCLAVE_BASH_EXECUTABLE}"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunClangAnalyze.cmake
      VERBATIM
      USES_TERMINAL
      COMMENT "Running Clang Static Analyzer")
  else()
    add_custom_target(clang-analyze
      COMMAND ${CMAKE_COMMAND} -E echo
        "scan-build and Clang C/C++ compilers are required for analysis"
      COMMAND ${CMAKE_COMMAND} -E false
      COMMENT "Clang Static Analyzer is unavailable")
  endif()
endif()

install(TARGETS shellsplit shelltype shellgate EXPORT ShellclaveTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${SHELLCLAVE_PUBLIC_HEADERS}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/shellclave)
install(EXPORT ShellclaveTargets NAMESPACE Shellclave::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Shellclave)
configure_package_config_file(cmake/ShellclaveConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ShellclaveConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Shellclave)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/ShellclaveConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ShellclaveConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ShellclaveConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Shellclave)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Shellclave)
install(FILES THIRD_PARTY.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Shellclave)
install(FILES deps/draugr/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Shellclave
  RENAME draugr-LICENSE)
install(FILES deps/xxhash/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Shellclave
  RENAME xxhash-LICENSE)
