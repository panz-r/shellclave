# Validate fixture text before it is emitted into a generated C string literal.
# Test corpora intentionally model executable shell source, not arbitrary byte
# streams: each entry must be a non-empty, printable one-line ASCII command.
function(shellclave_read_command_fixture output fixture_data fixture_index)
  string(JSON shellclave_fixture_type ERROR_VARIABLE shellclave_fixture_error
    TYPE "${fixture_data}" commands ${fixture_index})
  if(NOT shellclave_fixture_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR
      "Invalid command fixture ${fixture_index}: ${shellclave_fixture_error}")
  endif()
  if(NOT shellclave_fixture_type STREQUAL "STRING")
    message(FATAL_ERROR
      "Command fixture ${fixture_index} must be a JSON string, got ${shellclave_fixture_type}")
  endif()
  string(JSON shellclave_fixture ERROR_VARIABLE shellclave_fixture_error
    GET "${fixture_data}" commands ${fixture_index})
  if(NOT shellclave_fixture_error STREQUAL "NOTFOUND")
    message(FATAL_ERROR
      "Invalid command fixture ${fixture_index}: ${shellclave_fixture_error}")
  endif()
  set(${output} "${shellclave_fixture}" PARENT_SCOPE)
endfunction()

function(shellclave_validate_command_fixture fixture fixture_index)
  if("${fixture}" STREQUAL "")
    message(FATAL_ERROR "Command fixture ${fixture_index} must not be empty")
  endif()
  string(REGEX MATCH "[^ -~]" shellclave_fixture_invalid_byte "${fixture}")
  if(NOT "${shellclave_fixture_invalid_byte}" STREQUAL "")
    message(FATAL_ERROR
      "Command fixture ${fixture_index} must contain only printable one-line ASCII")
  endif()
endfunction()

# C11 treats several ??x spellings as trigraphs before tokenization. Escape
# every question mark when emitting the already-validated fixture into a C
# string literal so the command text survives verbatim.
function(shellclave_escape_command_fixture output fixture)
  string(REPLACE "\\" "\\\\" shellclave_fixture_escaped "${fixture}")
  string(REPLACE "\"" "\\\"" shellclave_fixture_escaped
    "${shellclave_fixture_escaped}")
  string(REPLACE "?" "\\?" shellclave_fixture_escaped
    "${shellclave_fixture_escaped}")
  set(${output} "${shellclave_fixture_escaped}" PARENT_SCOPE)
endfunction()
