cmake_minimum_required(VERSION 3.20)

set(driver "${SHELLCLAVE_SOURCE_DIR}/cmake/RunClangAnalyze.cmake")
set(fixture "${SHELLCLAVE_SOURCE_DIR}/tests/analyzer")
set(generators "${SHELLCLAVE_ANALYZE_GENERATOR}")
find_program(ninja_program NAMES ninja ninja-build)
find_program(make_program NAMES make gmake)
if(ninja_program)
  list(APPEND generators Ninja)
endif()
if(make_program)
  list(APPEND generators "Unix Makefiles")
endif()
list(REMOVE_DUPLICATES generators)

foreach(generator IN LISTS generators)
  string(MAKE_C_IDENTIFIER "${generator}" generator_id)
  foreach(mode IN ITEMS clean c cpp)
    set(binary "${SHELLCLAVE_ANALYZE_TEST_BINARY}/${generator_id}/${mode}")
    if(NOT mode STREQUAL "clean")
      # Seed a real ordinary-Clang cache and up-to-date object files. The
      # analyzer must replace the compiler selection and recompile the source.
      execute_process(
        COMMAND "${CMAKE_COMMAND}" -S "${fixture}" -B "${binary}"
          -G "${generator}" "-DCMAKE_C_COMPILER=${SHELLCLAVE_CLANG}"
          "-DCMAKE_CXX_COMPILER=${SHELLCLAVE_CLANGXX}"
          "-DSHELLCLAVE_ANALYZER_FIXTURE=${mode}"
        RESULT_VARIABLE configure_status OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
      if(NOT "${configure_status}" STREQUAL "0")
        message(FATAL_ERROR "Fixture configuration failed:\n${output}${error}")
      endif()
      execute_process(COMMAND "${CMAKE_COMMAND}" --build "${binary}"
        --parallel 2 RESULT_VARIABLE build_status
        OUTPUT_VARIABLE output ERROR_VARIABLE error)
      if(NOT "${build_status}" STREQUAL "0")
        message(FATAL_ERROR "Fixture compilation failed:\n${output}${error}")
      endif()
    endif()
    execute_process(
      COMMAND "${CMAKE_COMMAND}"
        "-DSHELLCLAVE_SCAN_BUILD=${SHELLCLAVE_SCAN_BUILD}"
        "-DSHELLCLAVE_CLANG=${SHELLCLAVE_CLANG}"
        "-DSHELLCLAVE_CLANGXX=${SHELLCLAVE_CLANGXX}"
        "-DSHELLCLAVE_ANALYZE_SOURCE=${fixture}"
        "-DSHELLCLAVE_ANALYZE_BINARY=${binary}"
        "-DSHELLCLAVE_ANALYZE_GENERATOR=${generator}"
        "-DSHELLCLAVE_ANALYZE_FIXTURE=${mode}" -P "${driver}"
      RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(mode STREQUAL "clean")
      if(NOT "${status}" STREQUAL "0" OR
         "${output}${error}" MATCHES "core\\.NullDereference")
        message(FATAL_ERROR "Clean analyzer fixture failed:\n${output}${error}")
      endif()
    elseif("${status}" STREQUAL "0" OR
           NOT "${output}${error}" MATCHES "core\\.NullDereference")
      message(FATAL_ERROR
        "${generator} ${mode} defect was not diagnosed:\n${output}${error}")
    endif()
  endforeach()
endforeach()
message(STATUS "Analyzer contract passed for ${generators}")
