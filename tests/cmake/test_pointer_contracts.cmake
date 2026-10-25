cmake_minimum_required(VERSION 3.20)

# Required-pointer failures are compile-time API violations, not runtime tests.
set(source "${SHELLCLAVE_SOURCE_DIR}/tests/consumer/pointer_contracts.c")
foreach(bad RANGE 0 215)
  if(bad EQUAL 186)
    continue()
  endif()
  execute_process(
    COMMAND "${SHELLCLAVE_C_COMPILER}" -std=c11 -fsyntax-only -Werror=nonnull
      "-DTEST_BAD=${bad}"
      "-I${SHELLCLAVE_SOURCE_DIR}/shellsplit/include"
      "-I${SHELLCLAVE_SOURCE_DIR}/shellsplit/src"
      "-I${SHELLCLAVE_SOURCE_DIR}/common"
      "-I${SHELLCLAVE_SOURCE_DIR}/shelltype/include"
      "-I${SHELLCLAVE_SOURCE_DIR}/shellgate/include"
      "-I${SHELLCLAVE_SOURCE_DIR}/deps/xxhash"
      "${source}"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(bad EQUAL 0)
    if(NOT status EQUAL 0)
      message(FATAL_ERROR "Meaningful NULL arguments were rejected:\n${output}${error}")
    endif()
  elseif(status EQUAL 0 OR NOT error MATCHES "nonnull")
    message(FATAL_ERROR "Required-pointer case ${bad} was not diagnosed:\n${output}${error}")
  endif()
endforeach()

# Installed views must not be passed to rule-mutating Shelltype APIs.
execute_process(
  COMMAND "${SHELLCLAVE_C_COMPILER}" -std=c11 -fsyntax-only -Werror
    -DTEST_BAD=186
    "-I${SHELLCLAVE_SOURCE_DIR}/shellsplit/include"
    "-I${SHELLCLAVE_SOURCE_DIR}/shellsplit/src"
    "-I${SHELLCLAVE_SOURCE_DIR}/common"
    "-I${SHELLCLAVE_SOURCE_DIR}/shelltype/include"
    "-I${SHELLCLAVE_SOURCE_DIR}/shellgate/include"
    "-I${SHELLCLAVE_SOURCE_DIR}/deps/xxhash" "${source}"
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(status EQUAL 0 OR NOT error MATCHES "qualifier|incompatible")
  message(FATAL_ERROR "Installed policy mutation was not diagnosed:\n${output}${error}")
endif()
