cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# Only this trusted, bounded fixture is evaluated, never corpus/fuzz input.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
(
  exec 3<&- 11<<<inherited
  read -u11 value {fd}<<<payload
  test "$value" = inherited
  test "$fd" != 11
)
(
  exec 3<&- 10<>/dev/null 11<&-
  read -u11 value {fd}<<<payload
  test "$fd" = 11
  test "$value" = payload
)
for probe in \
  'read -u11 -n0 probe' \
  'read -u11 -N0 probe' \
  'read -u11 -u12 -n0 probe' \
  '(read -u11 -n0 probe)' \
  '( (read -u11 -n0 probe) )' \
  ': | read -u11 -n0 probe' \
  ': | { read -u11 -n0 probe; }' \
  '(read -u11 -n0 probe && { exec 11<&-; true; })'; do
  (
    exec 3<&- 11<<<inherited 12<<<other
    eval "$probe" || exit 1
    true 3<&11 || exit 1
    true 3<&12 || exit 1
    read -u11 value {fd}<<<payload
    test "$value" = inherited
    test "$fd" != 11
  )
done
for probe in \
  'read -u11 -n0 probe 11<<<local' \
  '(read -u11 -n0 probe 11<<<local)' \
  '(exec 11<<<local; read -u11 -n0 probe)'; do
  (
    exec 3<&- 11<&-
    eval "$probe" || exit 1
    if true 3<&11 2>/dev/null; then exit 1; fi
  )
done
(
  exec 0<&- 3<&-
  : | read -u0 -n0 probe
  if true 3<&0 2>/dev/null; then exit 1; fi
)
]=]
  RESULT_VARIABLE status
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash read descriptor-proof fixture failed (${status}):\n${output}${error}")
endif()
