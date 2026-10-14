# One development reference, not a configurable runtime shell dialect.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../scripts/reference-bash.sha256"
     reference_bash_version_line REGEX "^# version=")
string(REPLACE "# version=" "" SHELLCLAVE_REFERENCE_BASH_VERSION
       "${reference_bash_version_line}")

function(shellclave_require_reference_bash executable)
  if(NOT executable OR NOT EXISTS "${executable}")
    message(FATAL_ERROR
      "Tests require Bash ${SHELLCLAVE_REFERENCE_BASH_VERSION}. Run "
      "./scripts/prepare-reference-bash and configure with "
      "-DSHELLCLAVE_BASH_EXECUTABLE=<its printed path>. "
      "BUILD_TESTING=OFF does not require Bash.")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env --unset=POSIXLY_CORRECT
            --unset=BASH_COMPAT --unset=BASH_XTRACEFD "BASH_ENV=" "ENV="
            "${executable}" --noprofile --norc -p -c
            [=[printf '%s.%s.%s' "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" "${BASH_VERSINFO[2]}"]=]
    RESULT_VARIABLE reference_bash_status
    OUTPUT_VARIABLE reference_bash_version ERROR_VARIABLE reference_bash_error
    TIMEOUT 5)
  if(NOT reference_bash_status EQUAL 0 OR
     NOT reference_bash_version STREQUAL SHELLCLAVE_REFERENCE_BASH_VERSION)
    message(FATAL_ERROR
      "Tests require pinned Bash ${SHELLCLAVE_REFERENCE_BASH_VERSION}, not "
      "'${reference_bash_version}' (${executable}): ${reference_bash_error}\n"
      "Run ./scripts/prepare-reference-bash and configure with "
      "-DSHELLCLAVE_BASH_EXECUTABLE=<its printed path>.")
  endif()
endfunction()
