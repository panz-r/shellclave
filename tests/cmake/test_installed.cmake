set(staging "${SHELLCLAVE_BINARY_DIR}/consumer-install-staging")
set(prefix "${SHELLCLAVE_BINARY_DIR}/consumer install relocated")
set(build "${SHELLCLAVE_BINARY_DIR}/consumer installed build")
file(REMOVE_RECURSE "${staging}" "${prefix}" "${build}")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${SHELLCLAVE_BINARY_DIR}" --prefix "${staging}"
  RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Shellclave installation failed: ${result}")
endif()
file(RENAME "${staging}" "${prefix}")

file(GLOB installed_headers RELATIVE "${prefix}/include/shellclave"
  "${prefix}/include/shellclave/*.h")
set(expected_headers
  env_screener.h
  relative_permutation_entropy.h
  sg_anomaly.h
  shell_abstract.h
  shell_depgraph.h
  shell_interop.h
  shell_processor.h
  shell_tokenizer.h
  shell_tokenizer_full.h
  shell_transform.h
  shellgate.h
  shelltype.h)
list(SORT installed_headers)
list(SORT expected_headers)
if(NOT installed_headers STREQUAL expected_headers)
  message(FATAL_ERROR
    "Installed public headers differ from the expected manifest:\n"
    "  installed: ${installed_headers}\n  expected: ${expected_headers}")
endif()

file(GLOB package_files "${prefix}/*/cmake/Shellclave/*.cmake")
if(NOT package_files)
  message(FATAL_ERROR "Installed CMake package files were not found")
endif()
foreach(package_file IN LISTS package_files)
  file(READ "${package_file}" package_contents)
  string(FIND "${package_contents}" "${SHELLCLAVE_SOURCE_DIR}" source_path)
  string(FIND "${package_contents}" "${SHELLCLAVE_BINARY_DIR}" binary_path)
  if(NOT source_path EQUAL -1 OR NOT binary_path EQUAL -1)
    message(FATAL_ERROR "Installed package contains a build-tree path: ${package_file}")
  endif()
endforeach()
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SHELLCLAVE_SOURCE_DIR}/tests/consumer" -B "${build}"
  -G "${SHELLCLAVE_GENERATOR}" "-DCMAKE_PREFIX_PATH=${prefix}"
  "-DCMAKE_C_COMPILER=${SHELLCLAVE_C_COMPILER}"
  "-DCMAKE_CXX_COMPILER=${SHELLCLAVE_CXX_COMPILER}"
  "-DCMAKE_BUILD_TYPE=${SHELLCLAVE_BUILD_TYPE}" RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Installed consumer configuration failed: ${result}")
endif()
set(build_command "${CMAKE_COMMAND}" --build "${build}")
if(SHELLCLAVE_BUILD_TYPE)
  list(APPEND build_command --config "${SHELLCLAVE_BUILD_TYPE}")
endif()
execute_process(COMMAND ${build_command} RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Installed consumer build failed: ${result}")
endif()
execute_process(COMMAND "${build}/shellclave_consumer" RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Installed consumer execution failed: ${result}")
endif()
execute_process(COMMAND "${build}/shellclave_cpp_consumer" RESULT_VARIABLE result)
if(result)
  message(FATAL_ERROR "Installed C++ consumer execution failed: ${result}")
endif()
