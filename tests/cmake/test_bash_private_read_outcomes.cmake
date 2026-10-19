cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# eval expands only this fixed test program, never corpus or fuzz input.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
TIMEFORMAT=
for count_mode in -n0 -N0; do
  for body in \
    ': | read -u63 COUNT probe' \
    ': |& read -u63 COUNT probe' \
    '! : | read -u63 COUNT probe' \
    'time : | read -u63 COUNT probe' \
    ': | { read -u63 COUNT probe; }' \
    ': | (read -u63 COUNT probe)' \
    '(read -u63 COUNT probe)' \
    'time (read -u63 COUNT probe)' \
    '( (read -u63 COUNT probe) )' \
    '{ : | read -u63 COUNT probe; }' \
    ': | { : | read -u63 COUNT probe; }' \
    '{ read -u63 COUNT probe; } | :' \
    '(read -u63 COUNT probe) | :' \
    '{ :; } | read -u63 COUNT probe' \
    'read -u63 COUNT probe | :' \
    'read -u63 COUNT probe | false' \
    'read -u63 COUNT probe | exit 0' \
    'read -u63 COUNT probe | exit 1' \
    'false; read -u63 COUNT probe | exit' \
    'true; read -u63 COUNT probe | exit' \
    'true; ! read -u63 COUNT probe | exit' \
    '{ read -u63 COUNT probe & }' \
    '{ { read -u63 COUNT probe; } & }' \
    '{ true && { read -u63 COUNT probe; } & }' \
    ': | read -u63 COUNT probe 63<<<local' \
    ': | read -u63 COUNT probe 63<&-' \
    '(read -u63 COUNT probe 63<<<local)' \
    '(read -u63 COUNT probe 63<&-)'; do
    expected_success=yes
    case "$body" in
      '! '*|'false; '*|'true; ! '*|*'| false'|*'| exit 1'|*'63<&-'*) expected_success=no ;;
    esac
    body=${body/COUNT/$count_mode}
    for stable in no yes; do
     stable_prefix=
     local_body=$body
     target=63
     if test "$stable" = yes; then
       stable_prefix='exec 62<&63;'
       local_body=${body//63/62}
       target=62
     fi
     for connector in '&&' '||'; do
      for choice in '' yes; do
        (
          exec 3<&- 4<&- 62<&- 63<&-
          expected='|'
          if test "$choice" = yes; then
            expected='/dev/fd/63|'
            if { test "$connector" = '&&' && test "$expected_success" = yes; } ||
               { test "$connector" = '||' && test "$expected_success" = no; }; then
              expected+=payload
            fi
            if test "$stable" = no; then
              case "$body" in
                '{ : | '*|'{ read '* )
                  case "$body" in *'| :') expected='/dev/fd/63|' ;; esac ;;
                *'{'*|*'('*) expected='/dev/fd/63|' ;;
              esac
            fi
          fi
          eval 'printf -v result "%s|%s" ${choice:+<(printf "payload\n")} "$( ' \
               "$stable_prefix $local_body $connector" \
               " { read -u$target second && printf \"%s\" \"\$second\"; } )\"" 2>/dev/null
          if test "$result" != "$expected"; then
            printf 'private outcome mismatch: %s %s, choice=%s: %s != %s\n' \
              "$body" "$connector" "$choice" "$result" "$expected" >&2
            exit 91
          fi
        ) || exit
      done
    done
   done
  done
done
for connector in '&&' '||'; do
  for choice in '' yes; do
    (
      exec 3<&- 4<&- 63<&-
      eval 'printf -v result "%s|%s" ${choice:+<(printf "payload\n")} "$(
        exec {saved}<&63 && : | { read -u"$saved" -n0 probe; }' \
        "$connector" ' read -u"$saved" second && printf "%s" "$second" )"' 2>/dev/null
      expected='|'
      if test "$choice" = yes; then
        expected='/dev/fd/63|'
        if test "$connector" = '&&'; then expected+=payload; fi
      fi
      test "$result" = "$expected" || exit 92
    ) || exit
  done
done
]=]
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)
if(NOT result STREQUAL "0")
  message(FATAL_ERROR "Bash private read outcomes failed (${result}): ${output}${error}")
endif()
