if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# Fixed, nonblocking probes: test descriptor identity and duplication without
# reading or writing any pipe payload. No corpus or fuzz input is executed.
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
set(process_pipe_tmpdir
    "${CMAKE_CURRENT_BINARY_DIR}/shellsplit-bash-process-pipe")
file(REMOVE_RECURSE "${process_pipe_tmpdir}")
file(MAKE_DIRECTORY "${process_pipe_tmpdir}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
test -p /dev/fd/0 </dev/null < >(true </dev/null)
test -p /dev/fd/1 >/dev/null > <(printf '')
test -p /dev/fd/1 >/dev/null &> <(printf '')
test -p /dev/fd/2 >/dev/null &>> <(printf '')
{ test -p /dev/fd/0; } </dev/null < >(true </dev/null)
{ test -p /dev/fd/1; } >/dev/null > <(printf '')
exec {fd}< >(true </dev/null)
test -p /dev/fd/$fd
: <&$fd
exec {fd}<&-
exec {fd}> <(printf '')
test -p /dev/fd/$fd
: >&$fd
exec {fd}>&-
exec {fd}<> <(printf '')
test -p /dev/fd/$fd
: <&$fd >&$fd
exec 3>&$fd
exec {fd}>&-
test -p /dev/fd/3
: <&3 >&3
exec 3>&-
exec {fd}<> >(true </dev/null)
test -p /dev/fd/$fd
: <&$fd >&$fd
exec {fd}>&-

# Bash applies the implicit `2>&1` for `|&` after the left command's explicit
# redirects. Closing stdout therefore makes that final setup operation fail;
# the brace body must not run or create its own output.
{ exec 3>"$1/body"; printf unexpected >&3; } 1>&- |& true
test ! -e "$1/body"
]=]
          bash "${process_pipe_tmpdir}"
  RESULT_VARIABLE process_pipe_status
  ERROR_VARIABLE process_pipe_errors
  TIMEOUT 5)
file(REMOVE_RECURSE "${process_pipe_tmpdir}")
if(NOT process_pipe_status EQUAL 0)
  message(FATAL_ERROR "Bash process-pipe contract failed: ${process_pipe_status}\n${process_pipe_errors}")
endif()
