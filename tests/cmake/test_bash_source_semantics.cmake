cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash")
endif()

# Append a marker inside command substitution so its trailing-LF removal cannot
# disguise the exact heredoc bytes. These commands access no application files.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[
set -e
actual=$(cat <<'EOF'
alpha
EOF
printf X)
test "$actual" = $'alpha\nX'
actual=$(cat <<`日本`
`日本`
printf X)
test "$actual" = X
actual=$(cat <<`x``y`
`x``y`
printf X)
test "$actual" = X
actual=$(cat <<`|`tail
`|`tail
printf X)
test "$actual" = X
actual=$(cat <<`"x y"`tail
`"x y"`tail
printf X)
test "$actual" = X
actual=$(cat <<`a\b`tail
`a\b`tail
printf X)
test "$actual" = X
actual=$(cat <<`$'\x00'`tail
`$'\x00'`tail
printf X)
test "$actual" = X
actual=$(cat <<`"x"`'tail'
$value
`x`tail
printf X)
test "$actual" = $'$value\nX'
actual=$(cat <<`$'\x41'`'tail'
$value
`$\x41`tail
printf X)
test "$actual" = $'$value\nX'
actual=$(cat <<`"`$'\x3a'
``':'
printf 'HIDDEN\n'
``:
:
printf X)
test "$actual" = $'HIDDEN\nX'
actual=$(cat <<`'a\
b'`''
payload
`ab`
printf X)
test "$actual" = $'payload\nX'
actual=$(cat <<`'a\
b'`
payload
`'ab'`
printf X)
test "$actual" = $'payload\nX'
actual=$(cat << \
  EOF
payload
EOF
printf X)
test "$actual" = $'payload\nX'
actual=$(cat <<- \
 	\
 EOF
	payload
	EOF
printf X)
test "$actual" = $'payload\nX'
actual=$(cat <<`"`$'\''
payload
``\'
printf X)
test "$actual" = $'payload\nX'
actual=$(cat <<`"`$'\'\''
payload
``''\'''\'''
printf X)
test "$actual" = $'payload\nX'
selector_value=target
target=abc
test "${#selector_value}" = 6
test "${!selector_value}" = abc
test "${#\
selector_value}" = 6
test "${selector_value\
}" = target
_shellclave_source_selector_probe=abc
test "${!_shellclave_source_selector_*}" = _shellclave_source_selector_probe
test "${!_shellclave_source_selector_*\
}" = _shellclave_source_selector_probe
actual=$(cat <<-'EOF'
	alpha
	EOF
printf X)
test "$actual" = $'alpha\nX'
actual=$(cat <<'EOF'
EOF
printf X)
test "$actual" = X
actual=$(cat <<'日本 語'
日本 語 body
日本 語
printf X)
test "$actual" = $'日本 語 body\nX'
actual=$(cat <<EOF
alpha
E\
OF
printf X)
test "$actual" = $'alpha\nX'
actual=$(cat <<E'O'\F
alpha
EOF
printf X)
test "$actual" = $'alpha\nX'
actual=$(cat <<EO\
F
$(printf expanded)
EOF
printf X)
test "$actual" = $'expanded\nX'
value=abcd
actual=$(cat <<EOF
日本 $((1 + 2)) 語 ${value:1} 文
EOF
printf X)
test "$actual" = $'日本 3 語 bcd 文\nX'
actual=$(cat <<EOF
日本 ${value:-語} ${value#文} $((2))
EOF
printf X)
test "$actual" = $'日本 abcd abcd 2\nX'
actual=$(cat <<EOF
日本 $(( $(cat <<'INNER'
1
INNER
) + 1 )) 文
EOF
printf X)
test "$actual" = $'日本 2 文\nX'
actual=`printf one; cat <<'EOF'
日本
EOF
`
test "$actual" = 'one日本'
actual=$(cat <<$'E\x4fF'
alpha
EOF
printf X)
test "$actual" = $'alpha\nX'
TIMEFORMAT=
# A reserved-word timing pipeline may be empty, including on the right side
# of an AND list. Its real newline ends the complete top-level list unit.
time
time -p
true &&
time
cd /
cd /dev/null 2>/dev/null || test "$PWD" = /
! cd /dev/null 2>/dev/null && test "$PWD" = /
(cd /tmp && test "$PWD" = /tmp)
test "$PWD" = /
OLDPWD=/tmp
cd - >&- 2>/dev/null && exit 91
test "$PWD" = /tmp
test "$OLDPWD" = /
cd /
]=]
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 10)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash source/CWD reference failed: ${status}: ${diagnostic}")
endif()

# Delimiter-only commands are printed, never executed. Keep these at top level
# so the reference checks their declaration rather than an enclosing reparse.
foreach(source IN ITEMS
    [=[cat <<${x:-"EOF"}
payload
${x:-"EOF"}
printf AFTER]=]
    [=[cat <<$(printf   eof)
payload
$(printf eof)
printf AFTER]=]
    [=[cat <<$(a 1>f)
payload
$(a > f)
printf AFTER]=]
    [=[cat <<$(a|&b)
payload
$(a 2>&1 | b)
printf AFTER]=]
    [=[cat <<$((1 + 2))
payload
$((1 + 2))
printf AFTER]=]
    [=[cat <<"`echo "x y"`"
payload
`echo x y`
printf AFTER]=]
    [=[cat <<$((1+<(printf   x)))
payload
$((1+<(printf   x)))
printf AFTER]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
      "${SHELLCLAVE_BASH}" -p -c "${source}"
    RESULT_VARIABLE status OUTPUT_VARIABLE actual ERROR_VARIABLE diagnostic
    TIMEOUT 5)
  if(NOT status EQUAL 0 OR NOT actual STREQUAL "payload\nAFTER" OR diagnostic)
    message(FATAL_ERROR "Bash delimiter fragment reference failed: ${source}: ${status}: ${actual}: ${diagnostic}")
  endif()
endforeach()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[unset x; cat <<${x:-":"}
${x:-":"}
printf 'HIDDEN\n'
${x:-:}
:
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE actual ERROR_VARIABLE diagnostic
  TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT actual STREQUAL "HIDDEN\n" OR diagnostic)
  message(FATAL_ERROR "Bash delimiter quotedness reference failed: ${status}: ${actual}: ${diagnostic}")
endif()

foreach(source IN ITEMS
    [=[echo ok; cat 2>&"${fd:-1}"]=]
    [=[echo ok; cat 2>&"$(printf 1)"]=]
    [=[echo ok; cat <&"$((1 + 1))"]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
      "${SHELLCLAVE_BASH}" -p -n -c "${source}"
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
  if(NOT status EQUAL 0 OR diagnostic)
    message(FATAL_ERROR "Bash completed duplication reference failed: ${source}: ${diagnostic}")
  endif()
endforeach()

# These are completions of recursively unfinished redirect operands. Parse
# only: none of the pathname opens, substitutions or fixture commands execute.
foreach(opening IN ITEMS [=[echo $( ]=] [=[cat <( ]=] [=[cat >( ]=] [=[echo `]=])
  set(closing ")")
  if(opening STREQUAL [=[echo `]=])
    set(closing "`")
  endif()
  foreach(command IN ITEMS "cat 2>existing" "{ :; } 2>existing" "( : ) 2>existing")
    foreach(operand IN ITEMS [=[> <(printf out)]=] [=[> >(printf out)]=]
                             [=[>`printf out`]=])
      if(opening STREQUAL [=[echo `]=] AND operand STREQUAL [=[>`printf out`]=])
        continue() # Nested backticks need an unsupported escape layer.
      endif()
      set(source "echo before; ${opening}${command} ${operand}${closing}")
      execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -n -c "${source}"
        RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
      if(NOT status EQUAL 0 OR diagnostic)
        message(FATAL_ERROR "Bash nested redirect completion failed: ${source}: ${diagnostic}")
      endif()
    endforeach()
  endforeach()
endforeach()

# Keep this operator-adjacency witness at top level: command-substitution
# reserialization changes an unquoted leading dash into the <<- operator.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[cat << \
 -EOF
payload
-EOF
printf X]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE actual ERROR_VARIABLE diagnostic TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT actual STREQUAL "payload\nX" OR diagnostic)
  message(FATAL_ERROR "Bash heredoc adjacency reference failed: ${status}: ${diagnostic}")
endif()

# The substitution's first parse consumes -EOF, but its printed <<-EOF header
# exposes the later printf on the execution-time parse. Keep that unfaithful
# source form rejected by semantic consumers rather than hiding executed code.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[echo "$(cat << -EOF
payload
EOF
printf EXPOSED
-EOF
)"
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE actual ERROR_VARIABLE diagnostic TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT actual STREQUAL "payload\nEXPOSED\n" OR
   NOT diagnostic MATCHES "-EOF: command not found")
  message(FATAL_ERROR "Bash heredoc reserialization reference failed: ${status}: ${diagnostic}")
endif()

# Once an executable child's delimiter has arrived, later word completion
# cannot repair malformed grammar inside that child. Check closed outer forms
# with -n so no fixture commands or substitutions are executed.
foreach(invalid IN ITEMS
    [=[echo before; echo "$(echo &&) tail"]=]
    [=[echo before; cat >"$(echo &&) tail"]=]
    [=[echo before; cat <(echo &&)'tail']=]
    [=[echo before; echo $(cat > <(echo &&) tail)]=]
    [=[echo before; cat <(cat > >(echo &&) tail)]=]
    [=[echo before; echo $( { :; } ordinary'x')]=])
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
      "${SHELLCLAVE_BASH}" -p -n -c "${invalid}"
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
  if(status EQUAL 0)
    message(FATAL_ERROR "Bash accepted malformed closed child: ${invalid}")
  endif()
endforeach()

# Bash diagnoses malformed $() inside a legacy backtick at execution, not
# necessarily with -n or a failing outer-command status. Completing the outer
# backtick cannot repair the already-closed invalid child.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[echo "`echo $(echo &&) tail`"]=]
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
if(NOT diagnostic MATCHES "syntax error")
  message(FATAL_ERROR "Bash missed malformed child inside backtick: ${diagnostic}")
endif()

# A delimiter's literal backticks become executable only when the line is
# confirmed body data instead. Bash may still give the outer cat status zero.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[cat <<EOF
`|`z
EOF
]=]
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic OUTPUT_QUIET TIMEOUT 5)
if(NOT diagnostic MATCHES "syntax error")
  message(FATAL_ERROR "Bash missed malformed heredoc child: ${diagnostic}")
endif()

# Keep these at top level: wrapping them in an active $(...) would add a
# separate Bash print/reparse phase. The alleged old terminators must not hide
# the HIDDEN markers, and words following a raw-NUL word must survive printing.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[
unset x fd
cat <<$(: >&-file)
$(: file 1>&-)
printf 'CLOSE\n'
$(: >&-file)
:
cat <<"${x:-$'\0'}"
${x:-
printf 'NUL\n'
${x:-}
:
cat <<$(a >&$fd-)
$(a 1>&$fd-)
printf 'MOVE\n'
cat <<$(a <&2147483648-)
$(a 0<&2147483648-)
printf 'OVERFLOW\n'
cat <<$(printf "${x:-$'\0'}" tail)
$(printf "${x:- tail)
printf 'WORD\n'
cat <<$({ printf "${x:-$'a &\0'}"; })
$({ printf "${x:-a & })
printf 'BRACE\n'
i\
f true; th\
en printf 'CONTROL\n'; f\
i
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE diagnostic
  TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT output STREQUAL "CLOSE\nNUL\nMOVE\nOVERFLOW\nWORD\nBRACE\nCONTROL\n")
  message(FATAL_ERROR "Bash delimiter word-boundary reference failed: ${output} ${diagnostic}")
endif()

# A removed continuation is not a byte of the parameter selector. In a quoted
# delimiter, mistaking the first special parameter byte for a pattern changes
# ANSI-C protection and can swallow executable lines into the document.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[
cat <<"${\
#x:-$'a'}"
${#x:-a}
printf 'HASH\n'
cat <<"${\
%x:-$'a'}"
${%x:-a}
printf 'PERCENT\n'
cat <<"${\
/x:-$'a'}"
${/x:-a}
printf 'SLASH\n'
cat <<"${\
^x:-$'a'}"
${^x:-a}
printf 'CARET\n'
cat <<"${\
,x:-$'a'}"
${,x:-a}
printf 'COMMA\n'
cat <<"${\
\
#x:-$'a\0b'}"TAIL
${#x:-a
printf 'NUL\n'
cat <<"${\
x\
#$'a\0b'}"TAIL
${x#'a'}TAIL
printf 'PATTERN\n'
cat <<$(>f if)
$(if > f)
printf 'REDIRECT\n'
cat <<$(x=1 then)
$(x=1 then)
printf 'ASSIGNMENT\n'
cat <<$(>f ! echo x)
$(! echo x > f)
printf 'PUNCTUATION\n'
cat <<"${\
#x:-$'a'}"
${#x:-a}
printf 'HIDDEN\n'
exit 0
${#x:-'a'}
:
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE diagnostic
  TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT output STREQUAL
   "HASH\nPERCENT\nSLASH\nCARET\nCOMMA\nNUL\nPATTERN\nREDIRECT\nASSIGNMENT\nPUNCTUATION\nHIDDEN\n")
  message(FATAL_ERROR "Bash continued-selector reference failed: ${status}: ${output} ${diagnostic}")
endif()

# Received EOF does not commit a keyword: an appended suffix can make it an
# ordinary command. These syntax-only probes never execute unknown commands.
foreach(word IN ITEMS if then else elif fi for while until do done case esac
                      select coproc function "[[" in "]]")
  foreach(context IN ITEMS suffix assignment redirect)
    if(context STREQUAL suffix)
      set(probe "echo before; ${word}x")
    elseif(context STREQUAL assignment)
      set(probe "x=1 ${word}")
    else()
      set(probe ">target ${word}")
    endif()
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
        "${SHELLCLAVE_BASH}" -p -n -c "${probe}"
      RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
    if(NOT status EQUAL 0)
      message(FATAL_ERROR "Bash rejected ordinary keyword word ${probe}: ${diagnostic}")
    endif()
  endforeach()
endforeach()
foreach(word IN ITEMS if function "[[" "]]")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
      "${SHELLCLAVE_BASH}" -p -n -c "echo before; ${word}"
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
  if(status EQUAL 0)
    message(FATAL_ERROR "Bash accepted incomplete/misplaced keyword ${word}")
  endif()
endforeach()

# A missing duplication operand can acquire a word only before grammar has
# committed a separator/comment. Syntax-only probes cover simple commands and
# compound tails without opening files or executing substitution producers.
foreach(command IN ITEMS "cat" "{ :; }" "( : )")
  foreach(redirect IN ITEMS ">&" "<&" "2>&" "0<&" "{fd}>&" "{fd}<&")
    foreach(operand IN ITEMS "1" " \"1\"" " $(printf 1)" " <(cat)" " >(cat)"
                             " <\\\n(cat)" " >\\\n(cat)")
      set(probe "echo before; ${command} ${redirect}${operand}")
      execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -n -c "${probe}"
        RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
      if(NOT status EQUAL 0)
        message(FATAL_ERROR "Bash rejected completed redirect ${probe}: ${diagnostic}")
      endif()
    endforeach()
    foreach(ending IN ITEMS "\n" ";" " #comment" " && cat" " | cat" " )"
                            " < " " > " " <\\\n " " >\\\n ")
      set(probe "echo before; ${command} ${redirect}${ending}")
      execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -n -c "${probe}"
        RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
      if(status EQUAL 0)
        message(FATAL_ERROR "Bash accepted committed missing redirect ${probe}")
      endif()
    endforeach()
  endforeach()
endforeach()

# Redirector role is decided only when its adjacent operator arrives. Probe
# continuations and the numeric boundary without opening the named files.
foreach(command IN ITEMS "{ :; }" "( : )" "time { :; }" "{ :; } >existing")
  foreach(redirector IN ITEMS "2" "0002" "2147483647" "{fd}" "{_x9}"
                             "00\\\n02" "{f\\\nd}" "{fd}\\\n" "2\\\n"
                             "{\\\nfd}" "{fd\\\n}")
    set(probe "echo before; ${command} ${redirector}>out")
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
        "${SHELLCLAVE_BASH}" -p -n -c "${probe}"
      RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
    if(NOT status EQUAL 0)
      message(FATAL_ERROR "Bash rejected adjacent redirector ${probe}: ${diagnostic}")
    endif()
  endforeach()
  foreach(tail IN ITEMS "2 >out" "2147483648>out" "'2'>out" "\\2>out"
                        "{9}>out" "{}>out" "{fd-x}>out" "{fd}x>out"
                        "{fd} >out" "{fd}\\ >out" "{fd}\\\\>out"
                        "{fd}''>out" "{f'd'}>out")
    set(probe "echo before; ${command} ${tail}")
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
        "${SHELLCLAVE_BASH}" -p -n -c "${probe}"
      RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
    if(status EQUAL 0)
      message(FATAL_ERROR "Bash accepted non-redirector compound tail ${probe}")
    endif()
  endforeach()
endforeach()

# Anchor the old misclassified conditional fixture to execution semantics as
# well as -n: assignment-prefixed [[ is a program name, not the [[ construct.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
    "${SHELLCLAVE_BASH}" -p -c [=[
unset VALUE
PATH=/dev/null
command_not_found_handle() { printf '%s|%s|%s\n' "$1" "$VALUE" "$#"; }
VALUE=x [[ $VALUE == x ]]
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE diagnostic
  TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT output STREQUAL "[[|x|4\n")
  message(FATAL_ERROR "Bash assignment-prefixed keyword reference failed: ${status}: ${output} ${diagnostic}")
endif()

string(ASCII 13 cr)
# CMake normalizes CRLF in captured output. Compare inside Bash so capture
# normalization cannot hide lost CR bytes or final LF.
set(source "value=$(cat <<'EOF${cr}'\nalpha${cr}\nEOF${cr}\nprintf X)\n"
           "test \"$value\" = $'alpha\\r\\nX'")
string(JOIN "" source ${source})
execute_process(COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
  "${SHELLCLAVE_BASH}" -p -c "${source}"
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash CR heredoc reference failed: ${diagnostic}")
endif()

# A leading dot is not a CDPATH exemption: only complete . and .. components
# are. Use a unique owned fixture under the build tree and always clean it.
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef suffix)
set(fixture "${CMAKE_CURRENT_BINARY_DIR}/bash-source-cwd-${suffix}")
file(MAKE_DIRECTORY "${fixture}/base/.hidden" "${fixture}/search/.hidden"
                    "${fixture}/base/..." "${fixture}/search/...")
execute_process(COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
  "${SHELLCLAVE_BASH}" -p -c [=[
set -e
# Privileged Bash disables CDPATH even when set after startup. Enable ordinary
# lookup only within this controlled fixture, after the clean -p launch.
set +p
cd "$1/base"
CDPATH="$1/search"
cd .hidden >/dev/null
test "$PWD" = "$1/search/.hidden"
cd "$1/base"
cd ... >/dev/null
test "$PWD" = "$1/search/..."
cd "$1/base"
cd .
test "$PWD" = "$1/base"
cd ..
test "$PWD" = "$1"
cd "$1/base"
cd ./.hidden
test "$PWD" = "$1/base/.hidden"
cd "$1/base"
cd .hidden >&- 2>/dev/null && exit 92
test "$PWD" = "$1/search/.hidden"
cd "$1/base"
HOME=.hidden
cd >&- 2>/dev/null && exit 93
test "$PWD" = "$1/search/.hidden"
test "$OLDPWD" = "$1/base"
cd "$1/base"
! cd >&- 2>/dev/null || exit 94
test "$PWD" = "$1/search/.hidden"
test "$OLDPWD" = "$1/base"
]=] source-cwd "${fixture}"
  RESULT_VARIABLE status ERROR_VARIABLE diagnostic TIMEOUT 5)
file(REMOVE_RECURSE "${fixture}")
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash CDPATH component reference failed: ${diagnostic}")
endif()
