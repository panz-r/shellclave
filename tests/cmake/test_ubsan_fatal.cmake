if(NOT DEFINED SHELLCLAVE_UBSAN_PROBE)
  message(FATAL_ERROR "Missing UBSan probe executable")
endif()

# Deliberately request recovery: the compile-time policy must still terminate.
# Leak detection is disabled only for these isolated instrumentation probes.
set(probe_environment
  "ASAN_OPTIONS=detect_leaks=0"
  "LSAN_OPTIONS=detect_leaks=0"
  "UBSAN_OPTIONS=halt_on_error=0:exitcode=86")

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env ${probe_environment}
    "${SHELLCLAVE_UBSAN_PROBE}" --clean
  RESULT_VARIABLE clean_result
  OUTPUT_VARIABLE clean_output ERROR_VARIABLE clean_error
  TIMEOUT 10)
if(NOT "${clean_result}" STREQUAL "0" OR
   clean_error MATCHES "runtime error:")
  message(FATAL_ERROR
    "Clean UBSan probe failed (${clean_result}):\n${clean_output}${clean_error}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env ${probe_environment}
    "${SHELLCLAVE_UBSAN_PROBE}"
  RESULT_VARIABLE overflow_result
  OUTPUT_VARIABLE overflow_output ERROR_VARIABLE overflow_error
  TIMEOUT 10)
if(NOT "${overflow_result}" STREQUAL "86" OR
   NOT overflow_error MATCHES "runtime error: signed integer overflow")
  message(FATAL_ERROR
    "UBSan overflow did not fail as expected (${overflow_result}):\n${overflow_output}${overflow_error}")
endif()
