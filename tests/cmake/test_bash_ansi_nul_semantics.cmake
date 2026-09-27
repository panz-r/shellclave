if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# These are executor reference cases, not commands submitted to Shellclave.
# In particular, a decoded NUL truncates only its ANSI-C quoted segment.
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "${SHELLCLAVE_BASH}" -p -c [=[
set -e
test "$(e$'val\0x' 'printf executed')" = executed
test x$'y\0z'w = xyw
test "$(cat <<$'E\0F'X
data
EX
)" = data
export $'POSIXLY_CORRECT\0X'=1
test "$POSIXLY_CORRECT" = 1
]=]
  RESULT_VARIABLE status
  ERROR_VARIABLE diagnostic)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash ANSI-C NUL reference failed: ${diagnostic}")
endif()
