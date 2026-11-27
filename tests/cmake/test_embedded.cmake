cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/consumer_common.cmake")

set(build "${SHELLCLAVE_BINARY_DIR}/consumer-embedded-build")
file(REMOVE_RECURSE "${build}")
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SHELLCLAVE_SOURCE_DIR}/tests/consumer" -B "${build}"
  -G "${SHELLCLAVE_GENERATOR}" "-DSHELLCLAVE_EMBEDDED_SOURCE=${SHELLCLAVE_SOURCE_DIR}"
  "-DCMAKE_C_COMPILER=${SHELLCLAVE_C_COMPILER}"
  "-DCMAKE_CXX_COMPILER=${SHELLCLAVE_CXX_COMPILER}"
  "-DCMAKE_BUILD_TYPE=${SHELLCLAVE_BUILD_TYPE}"
  RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Embedded consumer configuration failed: ${result}")
endif()
set(build_command "${CMAKE_COMMAND}" --build "${build}")
if(SHELLCLAVE_BUILD_TYPE)
  list(APPEND build_command --config "${SHELLCLAVE_BUILD_TYPE}")
endif()
execute_process(COMMAND ${build_command} RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Embedded consumer build failed: ${result}")
endif()
run_consumers("${build}" "Embedded")
