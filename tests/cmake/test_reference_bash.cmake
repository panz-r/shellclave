cmake_minimum_required(VERSION 3.20)

include("${SHELLCLAVE_SOURCE_DIR}/cmake/ReferenceBash.cmake")
set(fixture "${SHELLCLAVE_BINARY_DIR}/reference-bash-contract")
file(MAKE_DIRECTORY "${fixture}")
set(check "${fixture}/check.cmake")
file(WRITE "${check}"
  "cmake_minimum_required(VERSION 3.20)\n"
  "include(\"${SHELLCLAVE_SOURCE_DIR}/cmake/ReferenceBash.cmake\")\n"
  "shellclave_require_reference_bash(\"\${REFERENCE_EXECUTABLE}\")\n")

execute_process(COMMAND "${CMAKE_COMMAND}"
  "-DREFERENCE_EXECUTABLE=${SHELLCLAVE_BASH_EXECUTABLE}" -P "${check}"
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Pinned reference was rejected: ${diagnostic}")
endif()

execute_process(COMMAND "${CMAKE_COMMAND}"
  "-DREFERENCE_EXECUTABLE=${fixture}/missing" -P "${check}"
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
if(status EQUAL 0 OR NOT diagnostic MATCHES "prepare-reference-bash")
  message(FATAL_ERROR "Missing reference did not give an actionable failure")
endif()

if(UNIX)
  # Probe the configuration boundary, not any library runtime. Both older and
  # newer executors must be rejected instead of selecting another dialect.
  foreach(version IN ITEMS 0.0.0 99.0.0)
    set(executable "${fixture}/fake-bash")
    file(WRITE "${executable}" "#!/bin/sh\nprintf '%s' '${version}'\n")
    file(CHMOD "${executable}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
    execute_process(COMMAND "${CMAKE_COMMAND}"
      "-DREFERENCE_EXECUTABLE=${executable}" -P "${check}"
      RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
    if(status EQUAL 0 OR NOT diagnostic MATCHES "prepare-reference-bash" OR
       NOT diagnostic MATCHES "${version}")
      message(FATAL_ERROR "Mismatched reference was not rejected: ${diagnostic}")
    endif()
  endforeach()
endif()

# The literal that failed under CMP0054 must remain data in script mode.
set(value "(")
if(value STREQUAL "!" OR value STREQUAL "(")
  message(STATUS "Pinned Bash and script-policy contract passed")
else()
  message(FATAL_ERROR "Quoted parenthesis was not compared as literal data")
endif()
