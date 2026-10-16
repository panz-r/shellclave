cmake_minimum_required(VERSION 3.20)

unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
unset(ENV{BASH_COMPAT})
unset(ENV{BASH_XTRACEFD})
set(async_input "${CMAKE_CURRENT_BINARY_DIR}/shellsplit-async-stdin-input")
file(WRITE "${async_input}" "marker")

# Only fixed, nonblocking probes are executed. These are independent of the
# graph implementation, corpus and fuzzer. Job control is off in this shell.
function(check_async source expected)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" --noprofile --norc -p -c "${source}"
    INPUT_FILE "${async_input}"
    OUTPUT_VARIABLE actual ERROR_VARIABLE errors RESULT_VARIABLE status
    TIMEOUT 3)
  string(STRIP "${actual}" actual)
  if(NOT status EQUAL 0 OR NOT actual STREQUAL expected)
    message(FATAL_ERROR "Asynchronous stdin: ${source}\nexpected=${expected} actual=${actual} status=${status}\n${errors}")
  endif()
  if(ARGC GREATER 2)
    if(source MATCHES "^UID=1\n")
      if(NOT errors MATCHES "UID: readonly variable")
        message(FATAL_ERROR "Recovery probe did not produce its expected readonly error")
      endif()
      string(REGEX REPLACE "^[^\n]*UID: readonly variable\n" "" errors "${errors}")
    endif()
    string(STRIP "${errors}" errors)
    if(NOT errors STREQUAL ARGV2)
      message(FATAL_ERROR "Asynchronous expansion phase: ${source}\nexpected stderr=${ARGV2} actual=${errors}")
    endif()
  endif()
endfunction()

check_async("wc -c & wait" "0")
foreach(separator IN ITEMS " " "\n" " # note\n" "\n\n")
  check_async("wc -c &${separator}wait" "0")
  check_async("true | wc -c &${separator}wait" "0")
  check_async("true |& wc -c &${separator}wait" "0")
  check_async("time wc -c &${separator}wait" "0")
  check_async("true && wc -c &${separator}wait" "0")
  check_async("false || wc -c &${separator}wait" "0")
  check_async("{ wc -c; } &${separator}wait" "0")
  check_async("(wc -c) &${separator}wait" "0")
  check_async("printf '%s' \"$(wc -c &${separator}wait)\"" "0")
  check_async("cat <(wc -c &${separator}wait)" "0")
  check_async("exec 0<&- && true &${separator}cat; wait" "marker")
  check_async("cd /; cd /tmp && true &${separator}pwd; wait" "/")
endforeach()
check_async("wc -c &\n" "0")
check_async("wc -c & # end\n\n" "0")
check_async("wc -c 3<<EOF &\nbody\nEOF\nwait" "6")
check_async("wc -c 3<<<body & # note\n\nwait" "6")
check_async("true &&\nwc -c &\nwait" "0")
check_async("false ||\nwc -c &\nwait" "0")
check_async("printf marker |\nwc -c &\nwait" "6")
check_async("UID=1; : &\nwc -c &\nwait" "0")
check_async("UID=1; : & # note\n\nwc -c &\nwait" "0")
check_async("UID=1; { :; } &\nwc -c &\nwait" "0")
check_async("UID=1; time : &\nwc -c &\nwait" "0")
check_async("UID=1; : &\ntrue && wc -c &\nwait" "0")
check_async("UID=1; : & wc -c &\nwait" "")
check_async("exit 0; : &\nwc -c &\nwait" "")
check_async("wc -c <&0 & wait" "6")
check_async("wc -c 3<&0 & wait" "0")
check_async("wc -c 3</dev/null & wait" "6")
check_async("wc -c 0>&0 & wait" "0")
check_async("wc -c 3<&0 0<&3- & wait" "0")
check_async("wc -c 3<&0 0<&\"3\"- & wait" "0")
check_async("wc -c 3<&0 0<&3\\- & wait" "0")
check_async("{ wc -c <&0; } & wait" "0")
check_async("{ wc -c & } & wait" "0")
check_async("{ { wc -c; } & } & wait" "0")
check_async("{ wc -c; } <&0 & wait" "6")
check_async("{ wc -c & wait; } <&0" "6")
check_async("{ :; } <&0; wc -c & wait" "6")
check_async("{ :; } <&0\nwc -c & wait" "6")
check_async("{ :; } <&0; (true); wc -c & wait" "6")
check_async("{ :; } <&0; (wc -c & wait)" "0")
check_async("{ :; } <&0; true | (true); wc -c & wait" "6")
check_async("{ :; } <&0; { :; } 2>&1; wc -c & wait" "0")
check_async("cat <(wc -c)" "6")
check_async("printf '%s' \"$(wc -c)\" & wait" "6")
check_async("! printf '%s' \"$(wc -c)\" & wait" "6")
check_async("printf '%s' \"$(wc -c)\" | cat & wait" "6")
check_async("time printf '%s' \"$(wc -c)\" & wait" "0")
check_async("true && printf '%s' \"$(wc -c)\" & wait" "0")
check_async("false || printf '%s' \"$(wc -c)\" & wait" "0")
check_async("value=$(wc -c >&2) & wait" "" "6")
check_async(": 3>\"$(wc -c >&2; printf /dev/null)\" & wait" "" "0")
check_async("exec {fd}<&0; wc -c <&$fd & wait" "6")
check_async("UID=1\nwc -c & wait" "0")
check_async("UID=1\ntime wc -c & wait" "0")
check_async("UID=1\n{ wc -c; } & wait" "0")
check_async("UID=1\ntrue && wc -c & wait" "0")
check_async("UID=1\nfalse || wc -c & wait" "0")
check_async("UID=1\ntrue && printf '%s' \"$(wc -c)\" & wait" "0")
check_async("UID=1\nvalue=$(wc -c >&2) & wait" "" "6")
check_async("UID=1\n: 3>\"$(wc -c >&2; printf /dev/null)\" & wait" "" "0")
check_async("exit 0\ntime wc -c & wait" "")

# A terminal asynchronous list contributes launch success to its enclosing
# compound. Its child status still controls branches within that list.
function(check_completion source expected expected_status)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" --noprofile --norc -p -c "${source}"
    OUTPUT_VARIABLE actual ERROR_VARIABLE errors RESULT_VARIABLE status
    TIMEOUT 3)
  if(NOT status EQUAL expected_status OR NOT actual STREQUAL expected)
    message(FATAL_ERROR "Asynchronous completion: ${source}\nexpected=${expected} status=${expected_status}; actual=${actual} status=${status}\n${errors}")
  endif()
  if(ARGC GREATER 3 AND NOT errors MATCHES "${ARGV3}")
    message(FATAL_ERROR "Missing expected assignment diagnostic: ${source}\n${errors}")
  endif()
  if(ARGC GREATER 4 AND errors MATCHES "${ARGV4}")
    message(FATAL_ERROR "Unexpected rejected-RHS output: ${source}\n${errors}")
  endif()
endfunction()

foreach(body IN ITEMS "false" "true" "exit 1" "false && true"
                      "false || true" "{ false; }" "(false)"
                      "false | true" "time false" "! true")
  check_completion("{ ${body} & } || printf bad" "" 0)
  check_completion("{ ${body} & } && printf good" "good" 0)
endforeach()
check_completion("{ false & } && true || printf bad" "" 0)
check_completion("(false &) || printf bad" "" 0)
check_completion("(false &) && printf good" "good" 0)
check_completion("{ { false & }; } || printf bad" "" 0)
check_completion("{ (false &); } || printf bad" "" 0)
check_completion("! { false & } && printf bad" "" 1)
check_completion("! { false & } || printf good" "good" 0)
check_completion("time { false & } || printf bad" "" 0)
check_completion("{ false &\n} || printf bad" "" 0)
check_completion("{ false & # note\n\n} || printf bad" "" 0)
check_completion("{ false & } || { printf bad; }" "" 0)
check_completion("echo \"$( { false & } || printf bad )\"" "\n" 0)
check_completion("echo \"$( { false & } && printf good )\"" "good\n" 0)
check_completion("cat <({ false & } || printf bad)" "" 0)
check_completion("{ false; } || printf good" "good" 0)
check_completion("{ true; } || printf bad" "" 0)
check_completion("{ false & true; } || printf bad" "" 0)
check_completion("{ true & false; } || printf good" "good" 0)
check_completion("exit 0; { false & } && printf bad" "" 0)
check_completion("UID=1; { false & } && printf bad" "" 1)

# Error text is captured, never executed. These fixed probes establish that
# shell-owned diagnostics follow their expansion/setup phase's stderr.
function(check_diagnostic_capture body captured)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" --noprofile --norc -p -c
            "unset missing; value=abc; exec 3>&-; printf '[%s]' \"$(${body})\""
    OUTPUT_VARIABLE actual ERROR_VARIABLE errors RESULT_VARIABLE status
    TIMEOUT 3)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "Diagnostic capture failed: ${body}\n${errors}")
  endif()
  if(captured)
    if(NOT actual MATCHES "Bad file descriptor|No such file or directory|cd: too many arguments|readonly variable|expansion-marker|division by 0|ambiguous redirect")
      message(FATAL_ERROR "Missing captured setup diagnostic: ${body}\n${actual}\n${errors}")
    endif()
  elseif(NOT actual STREQUAL "[]")
    message(FATAL_ERROR "Unexpected captured setup diagnostic: ${body}\n${actual}")
  endif()
endfunction()
check_diagnostic_capture("echo 2>&1 >&3" TRUE)
check_diagnostic_capture("echo >&3 2>&1" FALSE)
check_diagnostic_capture("echo >&3" FALSE)
check_diagnostic_capture("echo 2>&- >&3" FALSE)
check_diagnostic_capture("2>&1 >&3" TRUE)
check_diagnostic_capture("{ echo body; } 2>&1 >&3" TRUE)
check_diagnostic_capture("(echo body) 2>&1 >&3" TRUE)
check_diagnostic_capture("echo 2>&1 1>&3-" TRUE)
check_diagnostic_capture("echo 2>&1 {fd}>&3" TRUE)
check_diagnostic_capture("echo 2>&1 >''" TRUE)
check_diagnostic_capture("echo >'' 2>&1" FALSE)
check_diagnostic_capture("false && echo 2>&1 >&3" FALSE)
check_diagnostic_capture("exec 10>&-; { exec 10>&-; } 2>&1" TRUE)
check_diagnostic_capture("exec 10>&-; : 2>&1 10>&- 4>&3" TRUE)
check_diagnostic_capture("exec 2>&1; cd one two" TRUE)
check_diagnostic_capture("exec 1>&- 2>&-; cd one two" FALSE)
check_diagnostic_capture("false && cd one two" FALSE)
check_diagnostic_capture("x=1" FALSE)
check_diagnostic_capture("UID=1 2>&1" FALSE)
check_diagnostic_capture("exec 2>&1; UID=1" TRUE)
check_diagnostic_capture("exec 2>&1; UID=1 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; UID=1 true 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; UID=1 command true 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; UID=1 builtin true 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 1>&- 2>&-; UID=1" FALSE)
check_diagnostic_capture("exec 2>&1; x=$(<'')" TRUE)
check_diagnostic_capture("exec 2>&1; x=$(<\"$missing\")" TRUE)
check_diagnostic_capture("set --; exec 2>&1; x=$(<\"$@\")" TRUE)
check_diagnostic_capture("set -- alpha beta; exec 2>&1; x=$(<\"$@\")" TRUE)
check_diagnostic_capture("exec 2>&-; x=$(<'')" FALSE)
check_diagnostic_capture("exec 2<\"${async_input}\"; x=$(<'')" FALSE)
check_diagnostic_capture("exec 2>&1; x=$(<'') 1>&- 2>&-" TRUE)
check_diagnostic_capture("x=$(<'') 2>&1" FALSE)
check_diagnostic_capture("exec 2>&1; false && x=$(<'')" FALSE)
check_diagnostic_capture(": 2>&1 >$(<'') 1>&- 2>&-" TRUE)
check_diagnostic_capture("x=$(exec 2>&1; y=$(<''))" FALSE)
check_completion("x=$(<''); printf continued" "continued" 0 "No such file or directory")
check_diagnostic_capture("exec 2>&1; x=\${missing:?expansion-marker}" TRUE)
check_diagnostic_capture("exec 2>&1; x=$((1/0))" TRUE)
check_diagnostic_capture("exec 2>&1; x=\${value:1/0}" TRUE)
check_diagnostic_capture("exec 2>&1; x=\${missing:?expansion-marker} 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; : \${missing:?expansion-marker} 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; x=$((1/0)) true 1>&- 2>&-" TRUE)
check_diagnostic_capture("exec 2>&1; export x=\${missing:?expansion-marker} 1>&- 2>&-" TRUE)
check_diagnostic_capture("x=\${missing:?expansion-marker} 2>&1" FALSE)
check_diagnostic_capture("exec 2>&-; x=\${missing:?expansion-marker}" FALSE)
check_diagnostic_capture("exec 2>&1; false && x=\${missing:?expansion-marker}" FALSE)
check_diagnostic_capture("exec 2>&1; true || x=$((1/0))" FALSE)
check_diagnostic_capture("exec 2>&1; x='\${missing:?literal}'" FALSE)
check_diagnostic_capture(": 2>&1 >\${missing:?expansion-marker} 2>&-" TRUE)
check_diagnostic_capture(": >\${missing:?expansion-marker} 2>&1" FALSE)
check_diagnostic_capture(": 2>&- >\${missing:?expansion-marker} 2>&1" FALSE)
check_diagnostic_capture(": 2>&1 <<<$((1/0)) 2>&-" TRUE)
check_diagnostic_capture(": <<<$((1/0)) 2>&1" FALSE)
check_diagnostic_capture(": 2>&1 <<EOF 2>&-\n\${missing:?expansion-marker}\nEOF\n" TRUE)
check_diagnostic_capture(": <<EOF 2>&1\n\${missing:?expansion-marker}\nEOF\n" FALSE)
check_diagnostic_capture("{ :; } 2>&1 >\${missing:?expansion-marker}" TRUE)
check_diagnostic_capture("{ :; } >\${missing:?expansion-marker} 2>&1" FALSE)
check_diagnostic_capture("(x=\${missing:?expansion-marker}) 2>&1" TRUE)
check_completion("UID=1 true; printf good" "good" 0)
check_completion("UID=1; printf bad" "" 1)
check_completion("UID=1 x=kept printenv x" "kept\n" 0 "UID: readonly variable")
check_completion("export -n UID; UID=1 printenv UID" "" 1 "UID: readonly variable")
check_completion("export -n UID; UID+=1 printenv UID" "" 1 "UID: readonly variable")
check_completion("export -n UID; U\\\nID=1 printenv UID" "" 1 "UID: readonly variable")
check_completion("export UID=1 x=kept; printenv x" "kept\n" 0 "UID: readonly variable")
check_completion("export -p UID=1 x=kept; printenv x" "kept\n" 0 "UID: readonly variable")
# export may mark the original readonly value exported even though its new
# assignment is rejected. Verify the value, not absence of that attribute.
check_completion("original_uid=$UID; export 'U''ID=1'; test \"$UID\" = \"$original_uid\" && printf unchanged"
                 "unchanged" 0 "UID: readonly variable")
check_completion("unset x; export -Z x=not_set; printenv x" "" 1)
check_completion("unset x; export -f x=not_set; printenv x" "" 1)
check_completion("UID=$(printf rhs >&2; printf 1) true; printf good" "good" 0
                 "UID: readonly variable" "rhs")
check_completion("UID=$(printf rhs >&2; printf 1); printf bad" "" 1
                 "rhs.*UID: readonly variable")
check_completion("export UID=$(printf rhs >&2; printf 1); printf good" "good" 0
                 "rhs.*UID: readonly variable")
check_completion("export -Z x=$(printf rhs >&2); printf good" "good" 0 "rhs")
check_completion("UID=$(printf rhs-marker >&2; printf 1) $(true); printf bad"
                 "" 1 "rhs-marker.*UID: readonly variable")
check_completion("unset missing; UID=$(printf rhs-marker >&2; printf 1) $missing; printf bad"
                 "" 1 "rhs-marker.*UID: readonly variable")
check_completion("unset missing; UID=$(printf rhs-marker >&2; printf 1) \"$missing\"; printf good"
                 "good" 0 "UID: readonly variable" "rhs-marker")
check_completion("unset missing; UID=$(printf rhs-marker >&2; printf 1) $missing true; printf good"
                 "good" 0 "UID: readonly variable" "rhs-marker")
check_completion("UID=$(printf rhs-marker >&2; printf 1) \"$@\"; printf bad"
                 "" 1 "rhs-marker.*UID: readonly variable")
check_completion("UID=$(printf rhs-marker >&2; printf 1) \"$@\"\"\"; printf good"
                 "good" 0 "UID: readonly variable" "rhs-marker")
check_completion("unset missing; UID=$(printf rhs-marker >&2; printf 1) \"\${missing:-}\"; printf good"
                 "good" 0 "UID: readonly variable" "rhs-marker")
check_completion("UID=$(printf rhs-marker >&2; printf 1) {,}; printf bad"
                 "" 1 "rhs-marker.*UID: readonly variable")
# Presence and exact cardinality are different for defaulted positional lists.
# These trusted probes count expansions instead of executing their values.
foreach(arguments IN ITEMS "set --" "set -- ''" "set -- one two")
  if(arguments STREQUAL "set -- one two")
    set(default_count 2)
    set(list_count 2)
  else()
    set(default_count 1)
    if(arguments STREQUAL "set --")
      set(list_count 0)
    else()
      set(list_count 1)
    endif()
  endif()
  set(counter "${arguments}; count_args() { printf '%s' \"$#\"; };")
  foreach(word IN ITEMS "\"\${@-data}\"" "\"\${@:-data}\""
                        "\"\${@-}\"" "\"\${@:-}\""
                        "\"\${@:-\"$@\"}\"")
    check_completion("${counter} count_args ${word}" "${default_count}" 0)
  endforeach()
  check_completion("${counter} count_args \"$@\"" "${list_count}" 0)
  set(clear_names "unset \"\${!shellclave_count_@}\";")
  check_completion("${counter} ${clear_names} count_args \"\${!shellclave_count_*}\"" "1" 0)
  check_completion("${counter} ${clear_names} count_args \"\${!shellclave_count_@}\"" "0" 0)
  check_completion("${counter} ${clear_names} shellclave_count_a=1; shellclave_count_b=2; count_args \"\${!shellclave_count_*}\"" "1" 0)
  check_completion("${counter} ${clear_names} shellclave_count_a=1; shellclave_count_b=2; count_args \"\${!shellclave_count_@}\"" "2" 0)
endforeach()
foreach(word IN ITEMS "\"\${!shellclave_count_*}\"" "\"\${@-:}\""
                      "\"\${@:-:}\"" "\"\${@-}\"" "\"\${@:-}\"")
  check_completion("set --; unset \"\${!shellclave_count_@}\"; UID=$(printf rhs-marker >&2; printf 1) ${word}; printf good"
                   "good" 0 "UID: readonly variable" "rhs-marker")
endforeach()
check_completion("set --; unset \"\${!shellclave_count_@}\"; UID=$(printf rhs-marker >&2; printf 1) \"\${!shellclave_count_@}\"; printf bad"
                 "" 1 "rhs-marker.*UID: readonly variable")
foreach(operator IN ITEMS "?" ":?")
  check_completion("set --; UID=$(printf rhs-marker >&2; printf 1) \"\${@${operator}parameter-error}\"; printf bad"
                   "" 127 "parameter-error" "rhs-marker")
  check_completion("set -- : :; UID=$(printf rhs-marker >&2; printf 1) \"\${@${operator}parameter-error}\"; printf good"
                   "good" 0 "UID: readonly variable" "rhs-marker")
endforeach()
check_completion("UID=$(printf rhs-marker >&2; printf 1) $(true)\nprintf recovered"
                 "recovered" 0 "rhs-marker.*UID: readonly variable")
check_completion("x=$(printf first >&2) UID=$(printf rhs-marker >&2; printf 1) last=$(printf last >&2) $(true)"
                 "" 1 "firstrhs-marker.*UID: readonly variable" "last")
check_completion("unset missing; UID=\${missing:?rhs-error} $missing; printf bad"
                 "" 127 "rhs-error")
check_completion("UID=\${missing:?rhs-error} true; printf good"
                 "good" 0 "UID: readonly variable" "rhs-error")
check_completion("unset missing; IFS=0123456789 UID=1 $missing 4>&- 5>&4\ntest \"$IFS\" = 0123456789 && printf committed"
                 "committed" 0 "UID: readonly variable")
check_completion("IFS=0123456789 UID=1 true 4>&- 5>&4\ntest \"$IFS\" = 0123456789 || printf unchanged"
                 "unchanged" 0 "Bad file descriptor")
check_completion("cd /; printf '[%s]' \"$(cd /tmp; cd -)\"" "[/]" 0)

# A readonly assignment aborts the current input unit, rather than launching
# background commands later on the same physical line.
execute_process(
  COMMAND "${SHELLCLAVE_BASH}" --noprofile --norc -p -c
          "UID=1; time wc -c & wait"
  INPUT_FILE "${async_input}" OUTPUT_VARIABLE stopped_output
  ERROR_VARIABLE stopped_errors RESULT_VARIABLE stopped_status TIMEOUT 3)
if(stopped_status EQUAL 0 OR NOT stopped_output STREQUAL "" OR
   NOT stopped_errors MATCHES "UID: readonly variable")
  message(FATAL_ERROR "A stopped input unit launched its background command")
endif()

# Validate the literal redirect operand without creating its pathname.
execute_process(COMMAND "${SHELLCLAVE_BASH}" --noprofile --norc -p -n -c
  "{ : >& }; wc; }" RESULT_VARIABLE literal_status TIMEOUT 3)
if(NOT literal_status EQUAL 0)
  message(FATAL_ERROR "Bash rejected the literal brace redirect pathname")
endif()

# Apply descriptor exhaustion in the trusted bootstrap, not in analyzed shell
# syntax. Bash reports the failed open but continues the asynchronous body with
# its incoming descriptor. `read` consumes the fixed input without opening FDs.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c
          "ulimit -n 3; eval \"$1\"" bash
          "{ read -r value; printf '%s' \"$value\"; } & wait"
  INPUT_FILE "${async_input}" OUTPUT_VARIABLE failed_output
  ERROR_VARIABLE failed_errors RESULT_VARIABLE failed_status TIMEOUT 3)
file(REMOVE "${async_input}")
if(NOT failed_status EQUAL 0 OR NOT failed_output STREQUAL "marker" OR
   NOT failed_errors MATCHES "/dev/null:.*Too many open files")
  message(FATAL_ERROR "Implicit-open failure did not preserve stdin: ${failed_status} ${failed_output} ${failed_errors}")
endif()
