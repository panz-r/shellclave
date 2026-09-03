include("${CMAKE_CURRENT_LIST_DIR}/CommandFixtureValidation.cmake")

shellclave_escape_command_fixture(escaped [=[printf '??=' && echo "?"]=])
set(expected [=[printf '\?\?=' && echo \"\?\"]=])
if(NOT "${escaped}" STREQUAL "${expected}")
  message(FATAL_ERROR
    "Fixture C-string escaping changed command bytes: ${escaped}; expected: ${expected}")
endif()
