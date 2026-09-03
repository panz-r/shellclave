include("${CMAKE_CURRENT_LIST_DIR}/CommandFixtureValidation.cmake")

# This script is expected to fail. CTest marks it WILL_FAIL so a future change
# that accepts a newline cannot generate malformed C source unnoticed.
shellclave_validate_command_fixture("printf one\nprintf two" 7)
