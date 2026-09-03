include("${CMAKE_CURRENT_LIST_DIR}/CommandFixtureValidation.cmake")

# This script is expected to fail. CTest marks it WILL_FAIL so a malformed
# scalar cannot be stringified and emitted as a C command fixture.
set(shellclave_invalid_fixture_json [=[{"commands":[17]}]=])
shellclave_read_command_fixture(shellclave_fixture
  "${shellclave_invalid_fixture_json}" 0)
