if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# Backticks remove one legacy escape layer before the nested shell parses its
# body. These benign references do not access host files or environment values.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
VALUE=expanded
test "`printf %s \`printf nested\``" = nested
test "`printf %s \$VALUE`" = expanded
test "`printf %s "\$VALUE"`" = expanded
test "`printf %s \"two words\"`" = 'two words'
test "`printf '%s' 'a\
b'`" = ab
test `printf %s \"word\"` = '"word"'
test "`printf '%s' '\q'`" = '\q'
test "`printf %s a\ b`" = 'a b'
]=]
  RESULT_VARIABLE backtick_status ERROR_VARIABLE backtick_diagnostic)
if(NOT backtick_status EQUAL 0)
  message(FATAL_ERROR "Bash backtick escape reference failed: ${backtick_diagnostic}")
endif()

# Escapes and expansion closers remain part of a word. Physical line removal
# preserves that boundary; a hash at a genuinely new word still begins a
# comment. These references only emit fixed markers and create ephemeral pipes.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
test "$(printf '%s|' \|# \;# \&# \<# \># \(# \)# \ #)" = '|#|;#|&#|<#|>#|(#|)#| #|'
test "$(printf '%s' x\
#)" = 'x#'
test "$(printf '%s' \
# ignored
)" = ''
test "$(printf '%s' $(printf x)#)" = 'x#'
test "$(printf '%s' $(printf \|#)#)" = '|##'
test "$(printf '%s' $(printf x\
#)#)" = 'x##'
test "$(printf '%s' $((1))#)" = '1#'
test "$(printf '%s' ${unset_variable:-x}#)" = 'x#'
actual=$(printf '%s' <(printf x)#)
case "$actual" in /dev/fd/*'#') :;; *) exit 1;; esac
]=]
  RESULT_VARIABLE comment_status ERROR_VARIABLE comment_diagnostic TIMEOUT 5)
if(NOT comment_status EQUAL 0)
  message(FATAL_ERROR "Bash logical comment-boundary reference failed: ${comment_diagnostic}")
endif()

# Completion deliberately expands stored words a second time. Arithmetic
# expansion runs in this shell, not just in a command-substitution child.
# These fixed references only print markers and open /dev/null.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
test "$(compgen -W '$(printf completion-marker)')" = completion-marker
test "$(compgen -C 'printf callback-marker' ordinary)" = callback-marker
exec {fd}>/dev/null
test "$fd" -ge 10
compgen -W '$((fd=2))' >/dev/null
test "$fd" = 2
]=]
  RESULT_VARIABLE completion_status ERROR_VARIABLE completion_diagnostic
  TIMEOUT 5)
if(NOT completion_status EQUAL 0)
  message(FATAL_ERROR "Bash completion re-evaluation reference failed: ${completion_diagnostic}")
endif()

# getopts' option-letter assignment honors integer attributes and recursively
# evaluates scalar values. Only a fixed diagnostic marker is executed here.
# Locale-quote grammar remains separate from each legacy child body's scope.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
actual=$( { a='x[$(printf getopts-marker >&2)0]' getopts a OPTIND -a; } 2>&1)
test "$actual" = getopts-marker
actual=$( { command builtin getopts -- a ordinary -a; printf %s "$ordinary"; })
test "$actual" = a
actual=$( { getopts a 'target[$(printf hidden-marker >&3)0]' -a 2>/dev/null || :; } 3>&1)
test -z "$actual"
test "`printf '"$"literal"'`" = '"$"literal"'
test "$(echo `printf x # note` $"translated")" = 'x translated'
]=]
  RESULT_VARIABLE writer_scope_status ERROR_VARIABLE writer_scope_diagnostic)
if(NOT writer_scope_status EQUAL 0)
  message(FATAL_ERROR "Bash writer/quote-scope reference failed: ${writer_scope_diagnostic}")
endif()

# ANSI-C Unicode is not a locale-independent byte encoding. Canonical APIs
# reject non-ASCII code points until execution locale is a modeled contract.
foreach(reference_locale IN ITEMS C C.UTF-8)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "LC_ALL=${reference_locale}" locale charmap
    RESULT_VARIABLE locale_status OUTPUT_VARIABLE charmap ERROR_QUIET)
  if(NOT locale_status EQUAL 0)
    message(STATUS "Skipping unavailable Unicode reference locale ${reference_locale}")
    continue()
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=${reference_locale}"
            "${SHELLCLAVE_BASH}" -p -c [=[printf '%s' $'\u00e9']=]
    RESULT_VARIABLE unicode_status OUTPUT_VARIABLE unicode_output)
  string(HEX "${unicode_output}" unicode_hex)
  if(reference_locale STREQUAL "C")
    set(expected_unicode_hex "5c7530304539")
  else()
    set(expected_unicode_hex "c3a9")
  endif()
  if(NOT unicode_status EQUAL 0 OR NOT unicode_hex STREQUAL expected_unicode_hex)
    message(FATAL_ERROR "Bash Unicode locale reference failed (${reference_locale}): ${unicode_hex}")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=${reference_locale}"
            "${SHELLCLAVE_BASH}" -p -c [=[printf '%s' $'\u007f\xE9\351']=]
    RESULT_VARIABLE byte_status OUTPUT_VARIABLE byte_output)
  string(HEX "${byte_output}" byte_hex)
  if(NOT byte_status EQUAL 0 OR NOT byte_hex STREQUAL "7fe9e9")
    message(FATAL_ERROR "Bash locale-independent byte reference failed (${reference_locale}): ${byte_hex}")
  endif()
endforeach()

# Check the independent test inventory against the running reference shell.
# This is test-time evidence, never a release-path subprocess or rescan.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c "set -o"
  RESULT_VARIABLE option_status OUTPUT_VARIABLE option_output)
if(NOT option_status EQUAL 0)
  message(FATAL_ERROR "Cannot read Bash set option inventory")
endif()
string(REGEX MATCHALL "[a-z][a-z-]+[ \t]+(on|off)" option_rows "${option_output}")
set(actual_options)
foreach(row IN LISTS option_rows)
  string(REGEX REPLACE "[ \t]+(on|off)$" "" name "${row}")
  list(APPEND actual_options "${name}")
endforeach()
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../../shellsplit/tests/word_expansion_cases.h"
     expected_rows REGEX "^ *SHELLSPLIT_TEST_NAMED_SET_OPTION")
set(expected_options)
foreach(row IN LISTS expected_rows)
  string(REGEX MATCH "\"([^\"]+)\"" spelling "${row}")
  list(APPEND expected_options "${CMAKE_MATCH_1}")
endforeach()
list(SORT actual_options)
list(SORT expected_options)
if(NOT "${actual_options}" STREQUAL "${expected_options}")
  message(FATAL_ERROR
    "Bash option inventory differs from independent rejection fixtures:\n"
    "actual: ${actual_options}\nexpected: ${expected_options}")
endif()

# Bash also accepts -r without a named selector. Check each short spelling in
# its own shell so -n/-t and option errors cannot mask another inventory entry.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../../shellsplit/tests/word_expansion_cases.h"
     short_rows REGEX "^ *SHELLSPLIT_TEST_SHORT_SET_OPTION")
set(expected_short_options o)
foreach(row IN LISTS short_rows)
  string(REGEX MATCH "\"([^\"]+)\"" spelling "${row}")
  list(APPEND expected_short_options "${CMAKE_MATCH_1}")
endforeach()
set(actual_short_options)
set(alphabet abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ)
foreach(position RANGE 0 51)
  string(SUBSTRING "${alphabet}" ${position} 1 flag)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" -p -c "set -${flag}"
    RESULT_VARIABLE flag_status OUTPUT_QUIET ERROR_QUIET)
  if(flag_status EQUAL 0)
    list(APPEND actual_short_options "${flag}")
  endif()
endforeach()
list(SORT actual_short_options)
list(SORT expected_short_options)
if(NOT "${actual_short_options}" STREQUAL "${expected_short_options}")
  message(FATAL_ERROR
    "Bash short-option inventory differs from independent rejection fixtures:\n"
    "actual: ${actual_short_options}\nexpected: ${expected_short_options}")
endif()

# The rejected forms explicitly re-evaluate stored data. Ordinary expansion
# and non-evaluating transforms must not be conflated with those operators.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
value='$(printf prompt-marker)'
test "$value" = '$(printf prompt-marker)'
test "${value@P}" = prompt-marker
shopt -u promptvars
test "${value@P}" = '$(printf prompt-marker)'
shopt -s promptvars
ref='a[$(printf index-marker >&2)]'
actual=$( { printf '%s' "${!ref}"; } 2>&1 )
test "$actual" = index-marker
actual=$( { PS4='$(printf trace-marker >&2)'; set -o xtrace; :; } 2>&1 )
test "$actual" = 'trace-marker:'
initial_cwd=$PWD
actual=$( { set -r; cd / || :; printf '%s' "$PWD"; } 2>/dev/null )
test "$actual" = "$initial_cwd"
]=]
  RESULT_VARIABLE reevaluation_status ERROR_VARIABLE reevaluation_diagnostic)
if(NOT reevaluation_status EQUAL 0)
  message(FATAL_ERROR "Bash re-evaluation reference failed: ${reevaluation_diagnostic}")
endif()

# Variable-existence tests evaluate a subscript even in a quoted operand, with
# no declared array. String/file operands, and -v used as binary-test data, do
# not. Check the marker and status separately: later syntax errors can occur
# either before or after a lookup has already evaluated its operand.
foreach(expression IN ITEMS
    [=[test -v 'a[$(printf test-marker >&2)]']=]
    [=[[ -v 'a[$(printf test-marker >&2)]' ]]=]
    [=[test ! -v 'a[$(printf test-marker >&2)]']=]
    [=[[ ! -v 'a[$(printf test-marker >&2)]' ]]=]
    [=[command builtin test '(' -v 'a[$(printf test-marker >&2)]' ')']=]
    [=[test -n x -a -v 'a[$(printf test-marker >&2)]']=]
    [=[ref='a[$(printf test-marker >&2)]'; test -v "$ref"]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" -p -c "${expression}"
    RESULT_VARIABLE predicate_status OUTPUT_VARIABLE predicate_output
    ERROR_VARIABLE predicate_error)
  if(NOT (predicate_status EQUAL 0 OR predicate_status EQUAL 1) OR
     NOT predicate_output STREQUAL "" OR NOT predicate_error STREQUAL "test-marker")
    message(FATAL_ERROR "Bash variable-test re-evaluation anchor failed: ${expression}: ${predicate_status}: ${predicate_error}")
  endif()
endforeach()
foreach(expression IN ITEMS
    [=[test -n 'a[$(printf inert-marker >&2)]']=]
    [=[test -f 'a[$(printf inert-marker >&2)]']=]
    [=[test -R 'a[$(printf inert-marker >&2)]']=]
    [=[test -v = 'a[$(printf inert-marker >&2)]']=]
    [=[test -v = 'a[$(printf inert-marker >&2)]' -a x]=]
    [=[test 'a[$(printf inert-marker >&2)]' = -v]=]
    [=[test -n -v -a 'a[$(printf inert-marker >&2)]']=]
    [=[test -v 'a[$(printf inert-marker >&2)]' extra]=]
    [=[test ! -v 'a[$(printf inert-marker >&2)]' extra]=]
    [=[[ -v 'a[$(printf inert-marker >&2)]' missing-close]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" -p -c "${expression}"
    RESULT_VARIABLE predicate_status OUTPUT_QUIET ERROR_VARIABLE predicate_error)
  # An error may quote the literal source containing the marker. Executing it
  # instead writes the marker before any diagnostic, without a newline.
  if(NOT predicate_status MATCHES "^[012]$" OR predicate_error MATCHES "^inert-marker")
    message(FATAL_ERROR "Bash non-evaluating test anchor failed: ${expression}: ${predicate_error}")
  endif()
endforeach()

# Fixed binary comparisons keep an unknown quoted scalar in a data position.
# In these expressions, values that introduce negation/parentheses fail before
# reaching another predicate. Other tails can remain valid after that shift.
foreach(value IN ITEMS release debug "" -v ! "(" [=[a[$(printf dynamic-marker >&2)]]=])
  foreach(expression IN ITEMS
      [=[test "$1" = release -a -c /dev/null]=]
      [=[test -c /dev/null -a "$1" = release]=]
      [=[[ "$1" = release -a -c /dev/null ]]=]
      [=[[ -c /dev/null -a "$1" = release ]]=])
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
              "${SHELLCLAVE_BASH}" -p -c "${expression}" reference "${value}"
      RESULT_VARIABLE predicate_status OUTPUT_QUIET ERROR_VARIABLE predicate_error)
    if(value STREQUAL "release")
      set(expected_status 0)
    elseif(value STREQUAL "!" OR value STREQUAL "(")
      set(expected_status 2)
    else()
      set(expected_status 1)
    endif()
    if(NOT predicate_status EQUAL expected_status OR
       predicate_error MATCHES "^dynamic-marker")
      message(FATAL_ERROR "Bash dynamic comparison anchor failed: ${expression}: ${value}: ${predicate_status}: ${predicate_error}")
    endif()
  endforeach()
endforeach()

# Negation/parentheses shift the first comparison into the following words.
# An error in the ordinary-data interpretation must not hide a reached -v.
foreach(value IN ITEMS ! "(")
  foreach(expression IN ITEMS
      [=[test "$1" = = 'a[$(printf shifted-marker >&2)]' -a -v 'a[$(printf shifted-marker >&2)]']=]
      [=[test "$1" = "$2" 'a[$(printf shifted-marker >&2)]' -a -v 'a[$(printf shifted-marker >&2)]']=]
      [=[[ "$1" = = 'a[$(printf shifted-marker >&2)]' -a -v 'a[$(printf shifted-marker >&2)]' ]]=])
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
              "${SHELLCLAVE_BASH}" -p -c "${expression}" reference "${value}" =
      RESULT_VARIABLE predicate_status OUTPUT_QUIET ERROR_VARIABLE predicate_error)
    if(NOT predicate_status MATCHES "^[12]$" OR
       NOT predicate_error MATCHES "^shifted-marker")
      message(FATAL_ERROR "Bash shifted comparison anchor failed: ${expression}: ${value}: ${predicate_error}")
    endif()
  endforeach()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" -p -c
            [=[test "$1" = release extra -a -v 'a[$(printf inert-marker >&2)]']=]
            reference "${value}"
    RESULT_VARIABLE predicate_status OUTPUT_QUIET ERROR_VARIABLE predicate_error)
  if(NOT predicate_status EQUAL 2 OR predicate_error MATCHES "^inert-marker")
    message(FATAL_ERROR "Bash failed shifted comparison anchor failed: ${value}: ${predicate_error}")
  endif()
endforeach()

# A four-argument general expression can evaluate -v before diagnosing the
# trailing operands, unlike the three-argument error above.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c
          [=[test -v 'a[$(printf reached-marker >&2)]' extra extra]=]
  RESULT_VARIABLE predicate_status OUTPUT_QUIET ERROR_VARIABLE predicate_error)
if(NOT predicate_status EQUAL 2 OR NOT predicate_error MATCHES "^reached-marker")
  message(FATAL_ERROR "Bash test error-order anchor failed: ${predicate_error}")
endif()

# Enumeration cannot abort the group before its unconditional descriptor
# change. Timing output therefore uses stdout only, for both enumeration forms.
foreach(enumeration IN ITEMS [=[${!prefix@}]=] [=["${!prefix*}"]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
            "${SHELLCLAVE_BASH}" -p -c
            "TIMEFORMAT=enumeration-report; time { X=${enumeration}; exec 2>&1; }"
    RESULT_VARIABLE enumeration_status OUTPUT_VARIABLE enumeration_output
    ERROR_VARIABLE enumeration_error)
  if(NOT enumeration_status EQUAL 0 OR
     NOT enumeration_output STREQUAL "enumeration-report\n" OR
     NOT enumeration_error STREQUAL "")
    message(FATAL_ERROR "Bash enumeration timing anchor failed: ${enumeration_output}: ${enumeration_error}")
  endif()
endforeach()

# Only fixed, harmless word-expansion probes reach the reference shell.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -eu
fixture_path=$1
initial_cwd=$PWD
# A readonly assignment aborts its input unit, not the next complete line.
# These probes only change child-shell directories and never create files.
test "$("$BASH" -p -c $'UID=0; cd /\npwd' 2>/dev/null)" = "$initial_cwd"
test "$(false && { cd /; }; pwd)" = "$initial_cwd"
test "$(true || { cd /; }; pwd)" = "$initial_cwd"
test "$(false && { cd /; } || pwd)" = "$initial_cwd"
test "$(false >/dev/null && printf impossible; printf retained)" = retained
test "$( { false; } >/dev/null && printf impossible; printf retained)" = retained
test "$( ! { false; } >/dev/null || printf impossible; printf retained)" = retained
test "$( { { false; }; } >/dev/null && printf impossible; printf retained)" = retained
# An exit in a brace terminates its child shell; it does not return success
# through the brace. Negation never turns shell termination into a return.
test -z "$( { exit 0; } >/dev/null && printf impossible)"
test -z "$( ! { exit 0; } >/dev/null || printf impossible)"
test "$( (exit 0) >/dev/null && printf retained)" = retained
test "$( (exit 1) >/dev/null || printf retained)" = retained
test "$( { cd /; true; } >/dev/null && pwd)" = /
# /dev/null is not a directory: this setup must fail before the body, without
# creating a fixture or changing its CWD. Only fixed harmless syntax runs here.
test "$( { cd /; true; } >/dev/null/shellclave-child || pwd)" = "$initial_cwd"
test "$( ! { cd /; true; } >/dev/null/shellclave-child || pwd)" = "$initial_cwd"
test -z "$( ! { cd /; true; } >/dev/null/shellclave-child && pwd)"
test "$( ! { cd /; true; } >/dev/null || pwd)" = /
test "$( ! { { cd /; true; } >/dev/null/shellclave-child; } && pwd)" = "$initial_cwd"
test "$( ! false >/dev/null/shellclave-child && printf retained)" = retained
test -z "$( ! (exit 0) >/dev/null/shellclave-child && printf impossible)"
test "$( ! (exit 1) >/dev/null/shellclave-child || printf retained)" = retained
test "$(false >/dev/null && echo "$(printf impossible)"; printf retained)" = retained
test "$(true && { cd /; }; pwd)" = /
test "$(false || { cd /; }; pwd)" = /
test "$(false && { cd /; exit 0; }; pwd)" = "$initial_cwd"
test "$(true || { cd /; exit 1; }; pwd)" = "$initial_cwd"
test -z "$(true && { cd /; exit 0; }; pwd)"
test "$(false && { cd /; }; cd /; pwd)" = /
test "$(true && { cd /; true; } && pwd)" = /
test "$(false && { cd /; true; } || true | false || pwd)" = "$initial_cwd"
test -z "$(true && { cd /; true; } || true | false || pwd)"
test "$(false && { cd /; true; } || true | { cd /; false; } || pwd)" = "$initial_cwd"
test "$(false || { cd /; false; }; pwd)" = /
test "$("$BASH" -p -c $'{ cd /; UID=0; }\npwd' 2>/dev/null)" = /
test "$(false && { cd /; { cd /; }; }; pwd)" = "$initial_cwd"
test "$( (cd /); pwd)" = "$initial_cwd"
test "$( { cd /; printf ignored; } | cat >/dev/null; pwd)" = "$initial_cwd"
test "$(false && : >&$(printf should-not-run); printf retained)" = retained
test "$(true || { :; } 2>&$(printf should-not-run); printf retained)" = retained
test "$(echo { { text)" = '{ { text'
test "$({ echo } ; })" = '}'
test "$(printf 'a
#literal' | cat)" = 'a
#literal'
set -- x{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{
test "$#" -eq 1 && test "${#1}" -eq 33
set -- {{1,2}}
test "$#" -eq 2 && test "$1" = '{1}' && test "$2" = '{2}'
set -- {{1,2}
test "$#" -eq 2 && test "$1" = '{1' && test "$2" = '{2'
set -- {1..\
3}
test "$#" -eq 3 && test "$1" = 1 && test "$3" = 3
set -- {1.."2"} {-..2} {bar..baz} {1..3..}
test "$#" -eq 4 && test "$1" = '{1..2}' && test "$4" = '{1..3..}'
value=123
set -- {$value}
test "$#" -eq 1 && test "$1" = '{123}'
[[ a == [$'a'] && a == [$'\x61'] && b == [$'ab'] ]]
[[ ']' == [$']'] && '[' == [$'[]'] ]]
[[ '[]' == [$''] && '[a]' == $'[a]' ]]
[[ a != [$''] && a != $'[a]' ]]
set -- first second
test "$12" = first2 && test "$1abc" = firstabc
set -- one two three four five six seven eight nine ten eleven twelve
test "${12}" = twelve
set -- '*.txt' "*.txt" \*.txt $'*.txt' pre"*"post pre\*post 'a'*'b'
test "$1" = '*.txt' && test "$2" = '*.txt' && test "$3" = '*.txt'
test "$4" = '*.txt' && test "$5" = 'pre*post' && test "$6" = 'pre*post'
# Diagnostic element ownership must not suppress these active expansions.
set -f
VALUE=word
set -- first
test "$(printf %s x$VALUE*)" = 'xword*'
test "$(printf %s x$1*)" = 'xfirst*'
test "$(printf %s x$((1 + 2))*)" = 'x3*'
test "$(printf %s "$VALUE$((1 + 2))")" = 'word3'
unset missing
test "${missing:-'$1'}" = "'first'"
test "${missing:-'$((1 + 2))'}" = "'3'"
unset mutated items
test "${missing:-'$((mutated = 1))'}" = "'1'"
test "$mutated" = 1
items=(7)
test "${missing:-'$((items[0]))'}" = "'7'"
test "${missing:-'$((1 + $((2))))'}" = "'3'"
missing=
test "${missing#'$((mutated = 2))'}" = ''
test "$mutated" = 1
unset missing
test "${missing:-${other:-$((1 + $((2))))}}" = '3'
test "${missing:-'literal}suffix'}" = "'literal}suffix'"
test "${missing:-'a"b'}" = "'ab'"
test "${missing:-'"$(printf x)'}" = "'x'"
test "${missing:-'a}$(printf x)'}" = "'a}x'"
set +f
# Heredoc roots retain quote bytes, but parameter patterns establish quotes.
missing=
actual=$( { cat <<EOF
${missing#'$(printf phantom >&2)'}
${missing#'$(echo &&)'}
${missing%'$((mutated = 2))'}
${missing#'${items[0]}'}
${missing#$'$(printf phantom >&2)'}
EOF
} 2>&1 )
test -z "$actual"
unset missing
actual=$(cat <<EOF
${missing:-'$(printf child)'}
EOF
)
test "$actual" = "'child'"
actual=$(cat <<EOF
$'$(printf child)'
EOF
)
test "$actual" = "\$'child'"
actual=$(cat <<'EOF'
${missing:-'$((mutated = 2))'}
EOF
)
test "$actual" = '${missing:-'"'"'$((mutated = 2))'"'"'}'
# Nested documents retain their own expansion context inside a quoted $().
actual="$(cat <<'EOF'
$(</dev/null)
EOF
)"
test "$actual" = '$(</dev/null)'
actual="$(cat <<EOF
'$(</dev/null)'
EOF
)"
test "$actual" = "''"
unset missing
actual=$(printf '<%s>' ${missing:-<<BOGUS} <<EOF
body
EOF
)
test "$actual" = '<<<BOGUS>'
# Substring offsets and lengths are arithmetic, including ternary colons.
test "$(printf %s ${missing:-)})" = ')'
test "$(printf %s ${missing:-(})" = '('
test "$(printf %s ${missing:-<<BOGUS} <<EOF
body
EOF
)" = '<<BOGUS'
# Explicit fd zero and final list terminators preserve Bash's file shortcut.
# /dev/null is deliberately non-mutating and contains no user/system content.
test -z "$(0</dev/null)"
test -z "$(00</dev/null;)"
test -z "$(# heading
</dev/null)"
# Nonempty repository text distinguishes a file-content shortcut from a
# redirect-only command. The path is an argument, never shell program text.
expected=$(cat -- "$fixture_path")
test -n "$expected"
test "$(0<"$fixture_path")" = "$expected"
test "$(00<"$fixture_path";)" = "$expected"
test "$(# heading
<"$fixture_path")" = "$expected"
test -z "$(1<"$fixture_path")"
test -z "$(<"$fixture_path" 2>/dev/null)"
test "$(<"$fixture_path" printf ok)" = ok
text=abcdef
test "${text:1:2}" = bc && test "${text: -1}" = f
test "${text:1?2:3:1+1}" = cd
test "${text:1:$((1+2))}" = bcd
test "${text::2}" = ab && test "${text: }" = abcdef
test "${text:1:}" = ''
counter=0
test "${text:(counter=2)}" = cdef && test "$counter" = 2
counter=0
test "${text:1:(counter=2)}" = bc && test "$counter" = 2
# Installing a second process-substitution pipe replaces the previous route
# even when its producer redirected stdout away. Only builtin probes execute.
value=unchanged
if IFS= read -r value < <(printf old) < <(printf ignored >/dev/null); then
  exit 1
fi
test -z "$value"
]=] -- "${CMAKE_CURRENT_LIST_DIR}/../../shellsplit/README.md"
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash word reference failed: ${diagnostic}")
endif()

# Fixed option-grammar probes use only builtins and inline input. Each
# mode-sensitive setter runs in a separate Bash process, not on user data.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env --unset=POSIXLY_CORRECT
          --unset=BASH_COMPAT --unset=BASH_XTRACEFD
          "BASH_ENV=" "ENV=" "LC_ALL=C" "${SHELLCLAVE_BASH}" -p -c [=[
set -eu
readonly POSIXLY_CORRECT BASH_COMPAT BASH_XTRACEFD
read -p prompt -a values <<<one
test "${values[0]}" = one
test "$(declare -p values)" = 'declare -a values=([0]="one")'
read -rpName value <<<one
test "$(declare -p value)" = 'declare -- value="one"'
read -p -a value <<<one
test "$value" = one
read -dabc value <<<onea
test "$value" = one
prompt=-a
read -p "$prompt" -r value <<<one
test "$value" = one
read -u0 -t1 -n1 value <<<one
test "$value" = o
# Attached expansions can disappear without dropping their enclosing argv.
prompt=shown
read -p"$prompt" value <<<one
test "$value" = one
prompt=
value=unchanged
read -p"$prompt" value <<<two
test "$value" = unchanged
test "$REPLY" = two
read -p"$(printf shown)" value <<<three
test "$value" = three
read -p"$(printf '')" value <<<four
test "$value" = three
test "$REPLY" = four
read -pX"$prompt" value <<<five
test "$value" = five
read -p"" value <<<six
test "$value" = five
test "$REPLY" = six
# Quoted array targets still invoke the builtin's variable-name grammar.
read "values[1]" <<<two
test "${values[1]}" = two
read left "values[2]" <<<"one three"
test "$left" = one
test "${values[2]}" = three
unset -v "values[1]"
test -z "${values[1]+x}"
# Continuations are removed before recognizing the ANSI-C quote opener.
read values$\
'[3]' <<<continued
test "${values[3]}" = continued
unset -v values$\
'[3]'
test -z "${values[3]+x}"
declare values$\
'[3]=declared'
test "${values[3]}" = declared
printf -v values$\
'[3]' '%s' formatted
test "${values[3]}" = formatted
# printf consumes all -v options before its format and only the last target
# receives output. Incomplete calls and later option errors never assign.
fd=preserved
other=preserved
printf -v fd -vother '%s' changed
test "$fd" = preserved && test "$other" = changed
printf -vother -v fd '%s' changed
test "$fd" = changed
fd=preserved
if printf -v >/dev/null 2>&1; then exit 1; fi
if printf -v fd >/dev/null 2>&1; then exit 1; fi
if printf -vfd >/dev/null 2>&1; then exit 1; fi
if printf -vfd -- >/dev/null 2>&1; then exit 1; fi
if printf -vfd -Z >/dev/null 2>&1; then exit 1; fi
if printf -vfd -v9 '%s' changed >/dev/null 2>&1; then exit 1; fi
test "$fd" = preserved
printf -vfd -- ''
test -z "$fd"
fd=preserved
printf -- -v fd >/dev/null
printf '%s' -v fd >/dev/null
test "$fd" = preserved
printf -v other -v 'values[3]' '%s' repeated
test "${values[3]}" = repeated
# Subshell and pipeline writers do not update the outer shell's variable;
# brace groups do. A dynamic format after -- cannot select a different target.
(printf -vother -vfd '%s' changed)
test "$fd" = preserved
printf -vother -vfd '%s' changed | :
test "$fd" = preserved
format=%s
printf -vother -- "$format" changed
test "$fd" = preserved
{ printf -vother -vfd '%s' changed; }
test "$fd" = changed
# Static declaration errors fail individually; query modes do not assign.
fd=preserved
if declare bad-name >/dev/null 2>&1; then exit 1; fi
if export '' >/dev/null 2>&1; then exit 1; fi
if typeset 'bad-name=changed' >/dev/null 2>&1; then exit 1; fi
if declare 1left=changed >/dev/null 2>&1; then exit 1; fi
for option in -p +p -pr -f -F; do
  if declare "$option" fd=changed >/dev/null 2>&1; then exit 1; fi
  test "$fd" = preserved
done
if declare -Z fd=changed >/dev/null 2>&1; then exit 1; fi
if export -Z fd=changed >/dev/null 2>&1; then exit 1; fi
if export -f fd=changed >/dev/null 2>&1; then exit 1; fi
if local fd=changed >/dev/null 2>&1; then exit 1; fi
if readonly -Z fd=changed >/dev/null 2>&1; then exit 1; fi
readonly -- >/dev/null
test "$fd" = preserved
# Bash accepts -n for readonly despite omitting it from builtin help. It can
# assign a scalar, so the semantic gate must not treat it as an option error.
readonly -n fd=changed
test "$fd" = changed
fd=preserved
if declare bad-name fd=changed >/dev/null 2>&1; then exit 1; fi
test "$fd" = changed
fd=preserved
if declare other -p fd=changed >/dev/null 2>&1; then exit 1; fi
test "$fd" = changed
fd=preserved
declare +f fd=changed
test "$fd" = changed
fd=preserved
export -p fd=changed
test "$fd" = changed
# Invalid read targets stop assignment in argv order, not all-or-nothing.
value=preserved
left=preserved
if read 'bad-name' value <<<one 2>/dev/null; then exit 1; fi
test "$value" = preserved
if read left 'bad-name' value <<<'one two three' 2>/dev/null; then exit 1; fi
test "$left" = one && test "$value" = preserved
if read value 'bad-name' <<<'changed two' 2>/dev/null; then exit 1; fi
test "$value" = changed
prompt=shown
value=preserved
if read -p"$prompt" 'bad-name' value <<<one 2>/dev/null; then exit 1; fi
test "$value" = preserved
prompt=
read -p"$prompt" 'bad-name' value <<<one
test "$value" = one
REPLY=preserved
read -p"$prompt" 'bad-name' <<<two
test "$REPLY" = two
value=preserved
set +e
read left POSIXLY_CORRECT value <<<'one two three' 2>/dev/null
read_status=$?
set -e
test "$read_status" -ne 0
test "$left" = one && test "$value" = preserved
# Numeric option failures occur before any assignment, even with later options.
for option in '-n' '-N' '-u' '-t'; do
  if read "$option" invalid value <<<one 2>/dev/null; then exit 1; fi
  test "$value" = preserved
done
if read -n invalid -n1 value <<<one 2>/dev/null; then exit 1; fi
test "$value" = preserved
if read -t invalid -t1 value <<<one 2>/dev/null; then exit 1; fi
test "$value" = preserved
for number in '' -1 0.0 1e0 '+ 0' 2147483648 99999999999999999999999999; do
  if read -n "$number" value <<<one 2>/dev/null; then exit 1; fi
  test "$value" = preserved
done
for number in -1 ' 0' 1e0 1.2.3 99999999999999999999999999; do
  if read -t "$number" value <<<one 2>/dev/null; then exit 1; fi
  test "$value" = preserved
done
# Polling never assigns, including default REPLY; character-count zero does.
REPLY=preserved
read -t0 value <<<one
test "$value" = preserved
read -t0 <<<one
test "$REPLY" = preserved
for timeout in '' + - . -. +. .0 '-.0' 0.0000001; do
  read -t "$timeout" value <<<one
  test "$value" = preserved
done
read -t0 -t1 value <<<one
test "$value" = one
read -t1 -t0 value <<<two
test "$value" = one
read -n0 value <<<two
test -z "$value"
value=preserved
read -N0 value <<<two
test -z "$value"
read -n ' -0 ' value <<<two
test -z "$value"
# unset ignores a static invalid target for unrelated variables and continues.
value=preserved
unset 'bad-name' 2>/dev/null || :
test "$value" = preserved
unset 'bad-name' value 2>/dev/null || :
test -z "${value+x}"
# These option failures happen before any assignment.
value=preserved
REPLY=preserved
if read -xra value <<<one 2>/dev/null; then exit 1; fi
test "$value" = preserved
test "$REPLY" = preserved
if read -p <<<one 2>/dev/null; then exit 1; fi
test "$REPLY" = preserved
# A fixed literal probe demonstrates why quoting does not sanitize `let`.
let 'values[$(printf 7)]=1'
test "${values[7]}" = 1
# The launcher contract remains an independent runtime mode boundary.
if (set -o nounset -o posix) 2>/dev/null; then
  exit 1
fi
test -z "${POSIXLY_CORRECT+x}"
]=]
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash builtin option reference failed: ${diagnostic}")
endif()

foreach(selector IN ITEMS
    "set -eo posix" "set -oe posix" "set -oo nounset posix"
    "set -oz posix" "set -ooz nounset posix"
    "set -o nounset -o posix" "set +o nounset -o posix"
    "set -o -o posix" "set + -o posix")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env --unset=POSIXLY_CORRECT
            "BASH_ENV=" "ENV=" "LC_ALL=C" "${SHELLCLAVE_BASH}" -p -c
            "${selector}; test -n \"\${POSIXLY_CORRECT+x}\""
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "Bash set option reference failed (${selector}): ${diagnostic}")
  endif()
endforeach()

foreach(selector IN ITEMS
    "set +eo posix" "set -- -o posix" "set - -o posix"
    "set positional -o posix" "set -o nounset positional -o posix"
    "set -o posi -o posix" "set -o unknown -o posix"
    "set +o unknown -o posix" "set -o nounsetX -o posix"
    "set -zo posix" "set -oz nounset -o posix" "set -oz -o posix")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env --unset=POSIXLY_CORRECT
            "BASH_ENV=" "ENV=" "LC_ALL=C" "${SHELLCLAVE_BASH}" -p -c
            "${selector}; test -z \"\${POSIXLY_CORRECT+x}\""
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "Bash positional option reference failed (${selector}): ${diagnostic}")
  endif()
endforeach()
