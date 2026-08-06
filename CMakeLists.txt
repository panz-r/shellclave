cmake_minimum_required(VERSION 3.20)
project(Shellclave VERSION 0.1.0 LANGUAGES C CXX)

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

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
  shellsplit/include/shell_processor.h
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

set(SHELLTYPE_SOURCES
  shelltype/src/arena.c
  shelltype/src/filter_hash.c
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
target_link_libraries(shelltype PRIVATE m PUBLIC Threads::Threads)
set_target_properties(shelltype PROPERTIES EXPORT_NAME shelltype)

set(SHELLGATE_SOURCES shellgate/src/shellgate.c shellgate/src/sg_anomaly.c)
add_library(shellgate ${SHELLGATE_SOURCES})
add_library(Shellclave::shellgate ALIAS shellgate)
shellclave_project_target(shellgate)
target_include_directories(shellgate PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/shellgate/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/shellclave>)
target_link_libraries(shellgate PUBLIC shellsplit shelltype PRIVATE m)
set_target_properties(shellgate PROPERTIES EXPORT_NAME shellgate)

# Reuse dependency targets supplied by a parent. In a standalone build, compile
# the pinned private implementations into shellgate so installed static archives
# do not expose third-party targets to consumers.
if(TARGET draugr)
  target_link_libraries(shellgate PRIVATE $<BUILD_INTERFACE:draugr>)
else()
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/draugr/src/ht.c")
    message(FATAL_ERROR "deps/draugr is missing; clone with --recurse-submodules")
  endif()
  target_sources(shellgate PRIVATE deps/draugr/src/ht.c deps/draugr/src/ht_cache.c deps/draugr/src/util.c)
  target_include_directories(shellgate PRIVATE deps/draugr/include)
  target_compile_definitions(shellgate PRIVATE DRAUGR_USE_MALLOC)
endif()
if(TARGET xxHash::xxhash)
  target_link_libraries(shellgate PRIVATE $<BUILD_INTERFACE:xxHash::xxhash>)
elseif(TARGET xxhash)
  target_link_libraries(shellgate PRIVATE $<BUILD_INTERFACE:xxhash>)
else()
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash/xxhash.c")
    message(FATAL_ERROR "deps/xxhash is missing; clone with --recurse-submodules")
  endif()
  target_sources(shellgate PRIVATE deps/xxhash/xxhash.c)
  target_include_directories(shellgate PRIVATE deps/xxhash)
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
  shellclave_add_test(shellsplit_tokenizer_test shellsplit/tests/tokenizer_test.c shellsplit)
  shellclave_add_test(shellsplit_fast_parser_test shellsplit/tests/fast_parser_test.c shellsplit)
  shellclave_add_test(shellsplit_abstract_test shellsplit/tests/abstract_test.c shellsplit)
  shellclave_add_test(shellsplit_entropy_test shellsplit/tests/entropy_test.c shellsplit)
  shellclave_add_test(shellsplit_depgraph_test shellsplit/tests/test_depgraph.c shellsplit)
  shellclave_add_test(shellsplit_interop_test shellsplit/tests/interop_test.c shellsplit)
  shellclave_add_test(shelltype_token_types_test shelltype/tests/test_token_types.c shelltype)
  shellclave_add_test(shelltype_unit_test shelltype/tests/test_shelltype.c shelltype)
  shellclave_add_test(shelltype_arena_test shelltype/tests/test_arena.c shelltype)
  target_include_directories(shelltype_arena_test PRIVATE shelltype/src)
  shellclave_add_test(shelltype_policy_test shelltype/tests/test_policy.c shelltype)
  shellclave_add_test(shelltype_policy_concurrency_test shelltype/tests/test_policy_concurrency.c shelltype)
  shellclave_add_test(shelltype_verify_test shelltype/tests/test_verify.c shelltype)
  shellclave_add_test(shelltype_integration_test shelltype/tests/test_shelltype_integration.c shelltype)
  shellclave_add_test(shelltype_compact_policy_test shelltype/tests/test_policy_compact.c shelltype)
  shellclave_add_test(shellgate_unit_test shellgate/tests/test_shellgate.c shellgate)
  shellclave_add_test(shellgate_anomaly_test shellgate/tests/test_anomaly.c shellgate)

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
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "SHELLCLAVE_BUILD_FUZZERS requires Clang/libFuzzer")
  endif()
  add_executable(fuzz_shellgate shellgate/fuzz/fuzz_shellgate.cpp)
  target_compile_definitions(fuzz_shellgate PRIVATE HAS_LIBFUZZER)
  target_compile_features(fuzz_shellgate PRIVATE cxx_std_11)
  target_compile_options(fuzz_shellgate PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_shellgate PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_shellgate PRIVATE shellgate)

  foreach(fuzzer_name IN ITEMS shellgate shellsplit)
    set(smoke_seed_dir
      "${CMAKE_CURRENT_SOURCE_DIR}/${fuzzer_name}/fuzz/smoke-seeds")
    file(GLOB smoke_seed_files CONFIGURE_DEPENDS
      "${smoke_seed_dir}/*")
    list(LENGTH smoke_seed_files smoke_seed_count)
    if(smoke_seed_count GREATER 61)
      message(FATAL_ERROR
        "${fuzzer_name} smoke seed set exceeds the 61-file limit")
    endif()
    set(smoke_seed_bytes 0)
    foreach(smoke_seed IN LISTS smoke_seed_files)
      if(NOT IS_DIRECTORY "${smoke_seed}")
        file(SIZE "${smoke_seed}" smoke_seed_size)
        math(EXPR smoke_seed_bytes "${smoke_seed_bytes}+${smoke_seed_size}")
      endif()
    endforeach()
    if(smoke_seed_bytes GREATER 1048576)
      message(FATAL_ERROR
        "${fuzzer_name} smoke seed set exceeds the 1 MiB size limit")
    endif()
  endforeach()

  add_executable(fuzz_shellsplit shellsplit/fuzz/tokenizer_fuzzer.cpp)
  target_compile_features(fuzz_shellsplit PRIVATE cxx_std_11)
  target_compile_options(fuzz_shellsplit PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_shellsplit PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_shellsplit PRIVATE shellsplit)
  foreach(fuzzer IN ITEMS fuzz_shellgate fuzz_shellsplit)
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
      ${CMAKE_CURRENT_SOURCE_DIR}/shellsplit/fuzz/smoke-seeds
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellsplit
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellsplit_
    DEPENDS fuzz_shellsplit
    COMMENT "Running the unified Shellsplit fuzzer")
  add_custom_target(fuzz-shellgate-smoke
    COMMAND /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_fuzz_smoke.sh
      $<TARGET_FILE:fuzz_shellgate>
      ${CMAKE_CURRENT_SOURCE_DIR}/shellgate/fuzz/smoke-seeds
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-smoke-corpus/shellgate
      ${SHELLCLAVE_FUZZ_RUNS}
      ${SHELLCLAVE_FUZZ_MAX_LEN}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/smoke/shellgate_
    DEPENDS fuzz_shellgate
    COMMENT "Running the Shellgate fuzzer")
  add_custom_target(fuzz-smoke
    DEPENDS fuzz-shellsplit-smoke fuzz-shellgate-smoke
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
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
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
