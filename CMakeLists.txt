cmake_minimum_required(VERSION 3.20)
project(Shellclave VERSION 0.8.0 LANGUAGES C CXX)

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
option(SHELLCLAVE_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSanitizer" OFF)
option(SHELLCLAVE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(SHELLCLAVE_ENABLE_SANITIZERS AND SHELLCLAVE_ENABLE_TSAN)
  message(FATAL_ERROR "ASan/UBSan and TSan cannot be enabled together")
endif()

find_package(Threads REQUIRED)

set(SHELLCLAVE_PUBLIC_HEADERS
  shellsplit/include/env_screener.h
  shellsplit/include/relative_permutation_entropy.h
  shellsplit/include/shell_abstract.h
  shellsplit/include/shell_depgraph.h
  shellsplit/include/shell_interop.h
  shellsplit/include/shell_netstring.h
  shellsplit/include/shell_processor.h
  shellsplit/include/shell_sequence.h
  shellsplit/include/shell_tokenizer.h
  shellsplit/include/shell_tokenizer_full.h
  shellsplit/include/shell_transform.h
  shelltype/include/shelltype.h
  shellgate/include/sg_anomaly.h
  shellgate/include/shellgate.h)

function(shellclave_project_target target)
  target_compile_features(${target} PUBLIC c_std_11)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  if(SHELLCLAVE_ENABLE_COVERAGE)
    target_compile_options(${target} PRIVATE --coverage)
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
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

set(SHELLSPLIT_SOURCES
  shellsplit/src/env_screener.c
  shellsplit/src/relative_permutation_entropy.c
  shellsplit/src/shell_abstract.c
  shellsplit/src/shell_depgraph.c
  shellsplit/src/shell_interop.c
  shellsplit/src/shell_netstring.c
  shellsplit/src/shell_processor.c
  shellsplit/src/shell_tokenizer.c
  shellsplit/src/shell_tokenizer_full.c
  shellsplit/src/shell_transform.c)
add_library(shellsplit ${SHELLSPLIT_SOURCES})
add_library(Shellclave::shellsplit ALIAS shellsplit)
shellclave_project_target(shellsplit)
target_include_directories(shellsplit PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/shellclave>)
target_link_libraries(shellsplit PRIVATE m)
set_target_properties(shellsplit PROPERTIES EXPORT_NAME shellsplit)

if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_library(shellsplit_test ${SHELLSPLIT_SOURCES}
    shellsplit/tests/test_allocator.c)
  shellclave_project_target(shellsplit_test)
  target_compile_definitions(shellsplit_test PRIVATE SHELLSPLIT_TEST_ALLOCATOR)
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
    SHELLGATE_TEST_ALLOCATOR SHELLGATE_TEST_ANOMALY_OPS SHELLGATE_TEST_IO)
  target_include_directories(shellgate_test PRIVATE shellgate/tests)
endif()

function(shellclave_add_test name source library)
  add_executable(${name} ${source})
  shellclave_project_target(${name})
  target_link_libraries(${name} PRIVATE ${library})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

if(BUILD_TESTING)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests/headers")
  shellclave_add_test(shellsplit_tokenizer_test shellsplit/tests/tokenizer_test.c shellsplit_test)
  shellclave_add_test(shellsplit_fast_parser_test shellsplit/tests/fast_parser_test.c shellsplit_test)
  # Exercise the same public parser contract against the shipping library. The
  # allocation-failure variant above links the instrumented test library;
  # keeping this production variant prevents that build from being the only
  # implementation exercised by the parser regression suite.
  shellclave_add_test(shellsplit_fast_parser_production_test shellsplit/tests/fast_parser_test.c shellsplit)
  shellclave_add_test(shellsplit_abstract_test shellsplit/tests/abstract_test.c shellsplit_test)
  shellclave_add_test(shellsplit_production_semantics_test
    shellsplit/tests/production_semantics_test.c shellsplit)
  shellclave_add_test(shellsplit_entropy_test shellsplit/tests/entropy_test.c shellsplit_test)
  shellclave_add_test(shellsplit_depgraph_test shellsplit/tests/test_depgraph.c shellsplit_test)
  # The dependency graph has no allocator-test dependency, so run its full
  # public contract against both the fault-injection and shipping builds.
  shellclave_add_test(shellsplit_depgraph_production_test shellsplit/tests/test_depgraph.c shellsplit)
  shellclave_add_test(shellsplit_interop_test shellsplit/tests/interop_test.c shellsplit_test)
  shellclave_add_test(shellsplit_netstring_test shellsplit/tests/netstring_test.c shellsplit_test)
  foreach(shellsplit_test_target IN ITEMS shellsplit_tokenizer_test
      shellsplit_fast_parser_test shellsplit_abstract_test shellsplit_entropy_test
      shellsplit_depgraph_test shellsplit_interop_test shellsplit_netstring_test
      shellsplit_fast_parser_production_test shellsplit_depgraph_production_test)
    target_include_directories(${shellsplit_test_target} PRIVATE shellsplit/tests)
  endforeach()
  shellclave_add_test(shelltype_token_types_test shelltype/tests/test_token_types.c shelltype_test)
  shellclave_add_test(shelltype_unit_test shelltype/tests/test_shelltype.c shelltype_test)
  shellclave_add_test(shelltype_arena_test shelltype/tests/test_arena.c shelltype_test)
  target_include_directories(shelltype_arena_test PRIVATE shelltype/src shelltype/tests)
  shellclave_add_test(shelltype_policy_test shelltype/tests/test_policy.c shelltype_test)
  shellclave_add_test(shelltype_policy_concurrency_test shelltype/tests/test_policy_concurrency.c shelltype_test)
  shellclave_add_test(shelltype_verify_test shelltype/tests/test_verify.c shelltype_test)
  shellclave_add_test(shelltype_integration_test shelltype/tests/test_shelltype_integration.c shelltype_test)
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
    "${CMAKE_CURRENT_BINARY_DIR}/tests/shellgate_corpus_fixtures.h")
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
    "#ifndef SHELLGATE_CORPUS_FIXTURES_H\n"
    "#define SHELLGATE_CORPUS_FIXTURES_H\n"
    "static const char *const shellgate_corpus_commands[] = {\n")
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
    "#define SHELLGATE_CORPUS_COMMAND_COUNT ${shellclave_command_fixture_count}u\n"
    "#endif\n")
  shellclave_add_test(shellgate_corpus_test shellgate/tests/test_corpus.c shellgate_test)
  target_include_directories(shellgate_corpus_test PRIVATE
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
    target_compile_options(${fuzzer} PRIVATE -Wall -Wextra -Wpedantic)
  endforeach()

  set(SHELLCLAVE_FUZZ_RUNS "1000" CACHE STRING
      "Number of libFuzzer smoke-test runs")
  set(SHELLCLAVE_FUZZ_MAX_LEN "8192" CACHE STRING
      "Maximum libFuzzer input length for smoke tests")
  # Smoke tests use only the bounded seed sets below. Generated successful
  # inputs are kept in a disposable per-run corpus by the wrapper.
  add_custom_target(fuzz-shellsplit-smoke
    COMMAND /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.sh
      $<TARGET_FILE:fuzz_shellsplit>
      ${SHELLCLAVE_SHELLSPLIT_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellsplit
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellsplit_
    DEPENDS fuzz_shellsplit stage-shellsplit-smoke-seeds
    COMMENT "Running the unified Shellsplit fuzzer")
  add_custom_target(fuzz-shellgate-smoke
    COMMAND /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.sh
      $<TARGET_FILE:fuzz_shellgate>
      ${SHELLCLAVE_SHELLGATE_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellgate
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellgate_
    DEPENDS fuzz_shellgate stage-shellgate-smoke-seeds
    COMMENT "Running the Shellgate fuzzer")
  add_custom_target(fuzz-shelltype-smoke
    COMMAND /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.sh
      $<TARGET_FILE:fuzz_shelltype>
      ${SHELLCLAVE_SHELLTYPE_SMOKE_STAGE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shelltype
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shelltype_
    DEPENDS fuzz_shelltype stage-shelltype-smoke-seeds
    COMMENT "Running the Shelltype fuzzer")
  add_custom_target(fuzz-smoke
    DEPENDS fuzz-shellsplit-smoke fuzz-shellgate-smoke fuzz-shelltype-smoke
    COMMENT "Running all repository fuzz smoke tests")
endif()

if(PROJECT_IS_TOP_LEVEL)
  file(GLOB_RECURSE SHELLCLAVE_FORMAT_SOURCES CONFIGURE_DEPENDS
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
  if(SHELLCLAVE_SCAN_BUILD)
    add_custom_target(clang-analyze
      COMMAND ${CMAKE_COMMAND}
        -S ${CMAKE_CURRENT_SOURCE_DIR}
        -B ${CMAKE_CURRENT_BINARY_DIR}/clang-analyze
        -G ${CMAKE_GENERATOR}
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_C_COMPILER=clang
        -DCMAKE_CXX_COMPILER=clang++
      COMMAND ${SHELLCLAVE_SCAN_BUILD} --status-bugs
        ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/clang-analyze
        --clean-first --parallel 2
      USES_TERMINAL
      COMMENT "Running Clang Static Analyzer")
  else()
    add_custom_target(clang-analyze
      COMMAND ${CMAKE_COMMAND} -E echo
        "scan-build was not found; install the Clang Static Analyzer tools"
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
