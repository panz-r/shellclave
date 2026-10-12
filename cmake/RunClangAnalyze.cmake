# Both the real project and the analyzer contract fixtures use this driver.
# Configuration must run inside scan-build, not just the subsequent build:
# CMake caches compiler paths and ignores later CC/CXX environment overrides.
foreach(required IN ITEMS SHELLCLAVE_ANALYZE_SOURCE SHELLCLAVE_ANALYZE_BINARY
                          SHELLCLAVE_ANALYZE_GENERATOR)
  if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "Missing analyzer argument: ${required}")
  endif()
endforeach()

if(SHELLCLAVE_ANALYZE_INSIDE)
  if("$ENV{CC}" STREQUAL "" OR "$ENV{CXX}" STREQUAL "")
    message(FATAL_ERROR "Analyzer build must run inside scan-build")
  endif()
  file(REAL_PATH "$ENV{CC}" analyzer_c_compiler)
  file(REAL_PATH "$ENV{CXX}" analyzer_cpp_compiler)
  set(compiler_changed FALSE)
  if(EXISTS "${SHELLCLAVE_ANALYZE_BINARY}/CMakeCache.txt")
    foreach(language IN ITEMS C CXX)
      file(STRINGS "${SHELLCLAVE_ANALYZE_BINARY}/CMakeCache.txt" cached_compiler
        REGEX "^CMAKE_${language}_COMPILER:[^=]*=")
      string(REGEX REPLACE "^[^=]*=" "" cached_compiler "${cached_compiler}")
      if(language STREQUAL "C")
        set(desired_compiler "${analyzer_c_compiler}")
      else()
        set(desired_compiler "${analyzer_cpp_compiler}")
      endif()
      if(NOT cached_compiler STREQUAL "" AND
         NOT cached_compiler STREQUAL desired_compiler)
        set(compiler_changed TRUE)
      endif()
    endforeach()
  endif()
  set(configure_arguments
    -S "${SHELLCLAVE_ANALYZE_SOURCE}"
    -B "${SHELLCLAVE_ANALYZE_BINARY}"
    -G "${SHELLCLAVE_ANALYZE_GENERATOR}"
    -DCMAKE_BUILD_TYPE=Debug
    "-DCMAKE_C_COMPILER=${analyzer_c_compiler}"
    "-DCMAKE_CXX_COMPILER=${analyzer_cpp_compiler}"
    -DCMAKE_C_COMPILER_LAUNCHER=
    -DCMAKE_CXX_COMPILER_LAUNCHER=
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
  if(DEFINED SHELLCLAVE_ANALYZE_FIXTURE)
    list(APPEND configure_arguments
      "-DSHELLCLAVE_ANALYZER_FIXTURE=${SHELLCLAVE_ANALYZE_FIXTURE}")
  else()
    list(APPEND configure_arguments
      -DBUILD_TESTING=ON
      -DSHELLCLAVE_BUILD_TOOLS=ON
      -DSHELLCLAVE_BUILD_BENCHMARKS=ON
      -DSHELLCLAVE_BUILD_FUZZERS=OFF
      -DSHELLCLAVE_ENABLE_COVERAGE=OFF
      -DSHELLCLAVE_ENABLE_SANITIZERS=OFF
      -DSHELLCLAVE_ENABLE_TSAN=OFF)
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" ${configure_arguments}
    RESULT_VARIABLE configure_status)
  if(NOT "${configure_status}" STREQUAL "0")
    message(FATAL_ERROR "Analyzer configuration failed (${configure_status})")
  endif()
  if(compiler_changed)
    # CMake resets project cache options when a compiler changes. Reapply the
    # explicit analysis/fixture options after that one-time migration.
    execute_process(COMMAND "${CMAKE_COMMAND}" ${configure_arguments}
      RESULT_VARIABLE configure_status)
    if(NOT "${configure_status}" STREQUAL "0")
      message(FATAL_ERROR "Analyzer migration failed (${configure_status})")
    endif()
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${SHELLCLAVE_ANALYZE_BINARY}"
      --clean-first --parallel 2
    RESULT_VARIABLE build_status)
  if(NOT "${build_status}" STREQUAL "0")
    message(FATAL_ERROR "Analyzer compilation failed (${build_status})")
  endif()
else()
  foreach(required IN ITEMS SHELLCLAVE_SCAN_BUILD SHELLCLAVE_CLANG
                            SHELLCLAVE_CLANGXX)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
      message(FATAL_ERROR "Missing analyzer tool: ${required}")
    endif()
  endforeach()
  # Keep analyzer reports and its temporary files out of /tmp.
  file(MAKE_DIRECTORY "${SHELLCLAVE_ANALYZE_BINARY}/reports"
                      "${SHELLCLAVE_ANALYZE_BINARY}/tmp")
  set(ENV{TMPDIR} "${SHELLCLAVE_ANALYZE_BINARY}/tmp")
  set(driver_arguments
    -DSHELLCLAVE_ANALYZE_INSIDE=ON
    "-DSHELLCLAVE_ANALYZE_SOURCE=${SHELLCLAVE_ANALYZE_SOURCE}"
    "-DSHELLCLAVE_ANALYZE_BINARY=${SHELLCLAVE_ANALYZE_BINARY}"
    "-DSHELLCLAVE_ANALYZE_GENERATOR=${SHELLCLAVE_ANALYZE_GENERATOR}")
  if(DEFINED SHELLCLAVE_ANALYZE_FIXTURE)
    list(APPEND driver_arguments
      "-DSHELLCLAVE_ANALYZE_FIXTURE=${SHELLCLAVE_ANALYZE_FIXTURE}")
  endif()
  set(exclude_arguments)
  if(NOT DEFINED SHELLCLAVE_ANALYZE_FIXTURE)
    # Vendored implementation is upstream-owned, like formatting's scope.
    list(APPEND exclude_arguments --exclude "${SHELLCLAVE_ANALYZE_SOURCE}/deps")
  endif()
  execute_process(
    COMMAND "${SHELLCLAVE_SCAN_BUILD}" --status-bugs
      --use-cc "${SHELLCLAVE_CLANG}" --use-c++ "${SHELLCLAVE_CLANGXX}"
      -o "${SHELLCLAVE_ANALYZE_BINARY}/reports"
      ${exclude_arguments}
      "${CMAKE_COMMAND}" ${driver_arguments}
      -P "${CMAKE_CURRENT_LIST_FILE}"
    RESULT_VARIABLE analysis_status)
  if(NOT "${analysis_status}" STREQUAL "0")
    message(FATAL_ERROR "Clang analysis failed (${analysis_status})")
  endif()
endif()
