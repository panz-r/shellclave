cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# Fixed, nonblocking expressions only. No input from fixtures or fuzzers is run.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
for hole in none 4 9 10 11 12 63; do
  (
    for slot in {4..63}; do eval "exec ${slot}<>/dev/null"; done
    exec 3<&-
    if test "$hole" != none; then eval "exec ${hole}<&-"; fi
    printf -v result '%s|%s' <(:) "$(
      read -u3 -n0 probe || exit 91
      # Retaining original pipe fd 3 proves at most one free high slot.
      # The resource open uses that slot (or a low slot), so the separate
      # named-FD duplication cannot retain any descriptor below 64.
      read -u11 -n0 value {fd}<<<payload 2>/dev/null || :
      test "$fd" -ge 64 || exit 92
      printf checked
    )"
    test "$result" = '/dev/fd/3|checked'
  )
done
(
  for slot in {4..63}; do eval "exec ${slot}<>/dev/null"; done
  exec 3<&- 11<&-
  printf -v result '%s|%s' <(:) "$(
    read -u3 -n0 probe || exit 93
    # A real move frees fd 9. The transient open can use it, leaving the
    # formerly unique high hole available for the named allocation.
    exec 8>&9-
    read -u11 -n0 value {fd}<<<payload || exit 94
    test "$fd" = 11 || exit 95
    printf checked
  )"
  test "$result" = '/dev/fd/3|checked'
)
(
  for slot in {4..63}; do eval "exec ${slot}<>/dev/null"; done
  exec 10<&-
  exec 3<&- 11<>/dev/null && exec {a}<<<first && {
    exec 11<&-
    printf -v result '%s|%s' <(:) "$(
      read -u3 -n0 probe && {
        exec {a}<&-
        read -u11 value {b}<<<payload
        test "$a:$b:$value" = '10:11:payload' || exit 96
        printf checked
      }
    )"
    test "$result" = '/dev/fd/3|checked'
  }
)
(
  for slot in {3..63}; do eval "exec ${slot}<&-"; done
  exec {a}<<<first
  exec {a}<&-
  exec {b}<<<second
  # Closing a does not clear its numeric value. b reuses it; command arguments
  # capture that value before the new redirect rebinds a to another FD.
  read -u"$a" value {a}<<<third
  test "$value" = second
)
(
  unset DIRSTACK
  exec {DIRSTACK}>/dev/null
  original=$DIRSTACK
  unset DIRSTACK
  unset DIRSTACK
  : >&"$original"
  exec {DIRSTACK}>/dev/null
  test "$DIRSTACK" -ne "$original"
)
]=]
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)
if(NOT result STREQUAL "0")
  message(FATAL_ERROR "Bash allocation correlation failed (${result}): ${output}${error}")
endif()
