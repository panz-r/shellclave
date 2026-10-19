cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# Fixed, nonblocking commands only. Each scenario has fresh inline input;
# child reads share an open-file description, even though FD changes are local.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
for hole in 10 11 13 62 63; do
  for scenario in close_a close_b capture_a capture_b; do
    (
      for slot in {3..63}; do eval "exec ${slot}<>/dev/null"; done
      exec 3<&- 63<&-
      eval "exec ${hole}<&-"
      exec {a}<<<first
      exec {a}<&-
      exec {b}<<<second
      test "$a:$b" = "$hole:$hole"
      case "$scenario" in
        close_a)
          result=$(exec {a}<&-; if read -u"$b" child 2>/dev/null;
                   then printf BAD; else printf closed; fi)
          test "$result" = closed
          ;;
        close_b)
          result=$(printf '%s' "$(
            exec {b}<&-
            if read -u"$a" child 2>/dev/null;
            then printf BAD; else printf closed; fi
          )")
          test "$result" = closed
          ;;
        capture_a)
          result=$(read -u"$a" child {a}<<<third &&
                   read -u"$a" rebound
                   printf '%s:%s' "$child" "$rebound")
          test "$result" = second:third
          ;;
        capture_b)
          result=$(printf '%s' "$(
            read -u"$b" child {a}<<<third &&
            read -u"$a" rebound
            printf '%s:%s' "$child" "$rebound"
          )")
          test "$result" = second:third
          ;;
      esac
      # Child close/rebind operations do not alter either parent binding.
      test "$a:$b" = "$hole:$hole"
      read -u"$a" -n0 parent_a
      read -u"$b" -n0 parent_b
    )
  done
done
]=]
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)
if(NOT result STREQUAL "0")
  message(FATAL_ERROR "Bash selector lifecycle failed (${result}): ${output}${error}")
endif()
