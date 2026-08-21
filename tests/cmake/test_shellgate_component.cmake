set(build "${SHELLCLAVE_BINARY_DIR}/shellgate-component-configure")
file(REMOVE_RECURSE "${build}")

execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${SHELLCLAVE_SOURCE_DIR}/shellgate"
    -B "${build}" -G "${SHELLCLAVE_GENERATOR}"
    "-DCMAKE_C_COMPILER=${SHELLCLAVE_C_COMPILER}"
    "-DCMAKE_CXX_COMPILER=${SHELLCLAVE_CXX_COMPILER}"
    -DBUILD_TESTING=ON -DSHELLCLAVE_BUILD_TOOLS=OFF
  RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Shellgate component configuration failed: ${result}")
endif()

execute_process(COMMAND "${SHELLCLAVE_CTEST_COMMAND}" --test-dir "${build}" -N
  RESULT_VARIABLE result OUTPUT_VARIABLE tests ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR
    "Shellgate component CTest discovery failed: ${result}\n${errors}")
endif()
foreach(test IN ITEMS shellgate_unit_test shellgate_anomaly_test)
  string(FIND "${tests}" "${test}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR
      "Shellgate component entry point did not register ${test}:\n${tests}")
  endif()
endforeach()
