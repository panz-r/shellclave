if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# Anchor the reserved-word boundary and empty-pipeline grammar to Bash. Bash's
# `-n` pass accepts a terminal empty `time` inside parenthesized substitutions,
# but the recursive parser rejects it when the substitution is actually
# compiled for execution. Shellclave follows the execution result. These
# probes execute only constant test commands; no submitted source reaches the
# reference shell.
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
set(time_probe_dir "${CMAKE_CURRENT_BINARY_DIR}/shellsplit-bash-time-semantics")
file(REMOVE_RECURSE "${time_probe_dir}")
file(MAKE_DIRECTORY "${time_probe_dir}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "SHELLCLAVE_TIME_PROBE=${time_probe_dir}"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
# Fixed assignment probes anchor the distinction between an indexed
# assignment and a glob-shaped argument after timing/scalar prefixes.
(
  unset A a
  time a[0]=b
  test "$(declare -p a)" = 'declare -a a=([0]="b")'
)
(
  unset A B a
  time -p -- ! A= B+='x y' a[0]=b || :
  test "$(declare -p a)" = 'declare -a a=([0]="b")'
)
(
  unset A a
  A="x y" a[0]=b
  test "$(declare -p a)" = 'declare -a a=([0]="b")'
)
(
  unset A a
  A\
="x y" a[0]=b
  test "$(declare -p a)" = 'declare -a a=([0]="b")'
)
(
  unset A a
  time > /dev/null A= a[0]=b
  test "$(declare -p a)" = 'declare -a a=([0]="b")'
)
(
  unset a
  time printf %s a[0]=b > /dev/null
  if declare -p a >/dev/null 2>&1; then exit 1; fi
)
for valid in \
  'time' \
  'time !' \
  'time --' \
  'time time -p true' \
  'printf value && time' \
  'printf value || time' \
  'time & printf value' \
  '(time;)' \
  'echo "$(time;)"' \
  ': < <(time;)' \
  'echo "$( (time;) )"' \
  'echo "$(time (time;))"' \
  'echo "$( (time;); : )"' \
  ': < <( (time;) )' \
  'printf x > >( (time;) )' \
  '!>/dev/null true' \
  '!2>/dev/null true'
do
  "$BASH" -p -n -c "$valid"
done

for invalid in \
  '(time)' \
  '(time !)' \
  'echo "$(time)"' \
  'cat <(time)' \
  'cat >(time !)' \
  'time && printf value' \
  'time || printf value' \
  'printf x | time { cat; }'
do
  if "$BASH" -p -n -c "$invalid" >/dev/null 2>&1; then
    exit 1
  fi
done

for runtime_invalid in \
  'echo "$(time)"' \
  'echo "$(time;)"' \
  'echo "$(exec 2>&1; time;)"' \
  'cat <(time;)' \
  ': > >(time;)'
do
  if "$BASH" -p -c "$runtime_invalid" >/dev/null 2>&1; then
    exit 1
  fi
done

# These consumers do not read stdin. Use a non-writing producer so a valid
# recursive parse cannot fail incidentally because the consumer exits first
# and the producer receives SIGPIPE.
for runtime_valid in \
  'echo "$(time &)"' \
  'echo "$(time >/dev/null)"' \
  'time (time;)' \
  'echo "$(time { time; })"' \
  'echo "$(time (time; :))"' \
  'echo "$(time (time &))"' \
  ': < <(time; :)' \
  ': > >(time; :)' \
  'echo `time;`'
do
  "$BASH" -p -c "$runtime_valid" >/dev/null 2>&1
done

# An ordinary redirect delimits reserved `!`, while an io_number prefix keeps
# the spelling in the executable word.
if "$BASH" -p -c '!>/dev/null true'; then
  exit 1
fi
"$BASH" -p -c '!>/dev/null false'
if "$BASH" -p -c '!2>/dev/null true' >/dev/null 2>&1; then
  exit 1
else
  test "$?" -eq 127
fi

# Assignment and ordinary-redirection prefixes occupy the command position,
# so a following `time` is an executable name rather than Bash's reserved
# pipeline modifier. Empty PATH makes that distinction deterministic.
if "$BASH" -p -c 'VALUE=x time true' >/dev/null 2>&1; then
  exit 1
else
  test "$?" -eq 127
fi
if "$BASH" -p -c '> /dev/null time true' >/dev/null 2>&1; then
  exit 1
else
  test "$?" -eq 127
fi
if "$BASH" -p -c 'printf x | time cat' >/dev/null 2>&1; then
  exit 1
else
  test "$?" -eq 127
fi

# Documents delimit prefix eligibility without ending the simple command.
# A physical newline does end it; an escaped newline does not.
for ordinary in \
  '<<<one time <<<two printf ignored' \
  '<<<one ! <<<two printf ignored'
do
  if "$BASH" -p -c "$ordinary" >/dev/null 2>&1; then
    exit 1
  else
    test "$?" -eq 127
  fi
done
if "$BASH" -p -c $'<<<one time \\\n<<<two printf ignored' >/dev/null 2>&1; then
  exit 1
else
  test "$?" -eq 127
fi
report=$("$BASH" -p -c $'TIMEFORMAT=MARK; printf one <<<one\ntime <<<two printf two' 2>&1)
test "$report" = onetwoMARK
"$BASH" -p -n -c $'printf one <<<one\n! <<<two printf two'

# Timing the pipeline does not turn a later executable named `time` into
# another reserved prefix, including spellings that would otherwise describe
# an empty timing operation. Each constant probe must attempt that executable
# and emit exactly the outer timer's default report.
for ordinary_time in \
  'time true | time' \
  'time true | time -p' \
  'time true | time --' \
  'time true | time !' \
  'time true |& time' \
  'time true | time | cat'
do
  if report=$("$BASH" -p -c "TIMEFORMAT=MARK; $ordinary_time" 2>&1); then
    exit 1
  else
    test "$?" -eq 127
  fi
  case "$report" in
    *' time: command not found'*$'\nMARK') ;;
    *) exit 1 ;;
  esac
  case "$report" in
    *$'MARK\nMARK') exit 1 ;;
  esac
done

# Bash accepts repeated modifiers and treats `--` as POSIX report formatting.
posix_report=$("$BASH" -p -c 'time -- true' 2>&1)
case "$posix_report" in
  'real '*$'\nuser '*$'\nsys '*) ;;
  *) exit 1 ;;
esac
repeated_posix_report=$("$BASH" -p -c 'time time -p true' 2>&1)
case "$repeated_posix_report" in
  'real '*$'\nuser '*$'\nsys '*) ;;
  *) exit 1 ;;
esac

# A quoted heredoc delimiter suppresses expansion, so command-looking text in
# its body has no syntax. The unquoted counterpart executes only when its
# nested timed pipeline has a real separator.
quoted=$'cat <<\'EOF\'\n$(time)\nEOF\n'
unquoted=$'cat <<EOF\n$(time;)\nEOF\n'
"$BASH" -p -n -c "$quoted"
"$BASH" -p -n -c "$unquoted"

# An ordinary timed command's redirects are restored before Bash writes its
# report, while enclosing and persistent shell descriptor state remains
# active. A sole timed subshell/background group owns the report in that child
# scope, and descriptor-only `exec` can replace the reporting shell's fd 2.
"$BASH" -p -c '
  set -e
  TIMEFORMAT=MARK
  { time>"$1/prefix-output" printf value; } 2>"$1/prefix-report"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/prefix-output")" = value
test "$(<"$SHELLCLAVE_TIME_PROBE/prefix-report")" = MARK

"$BASH" -p -c '
  exec 2>"$1/persistent"
  TIMEFORMAT=MARK
  time { printf CMDERR >&2; } 2>"$1/local"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/persistent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/local")" = CMDERR

"$BASH" -p -c '
  TIMEFORMAT=MARK
  { time true; } 2>"$1/outer"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/outer")" = MARK

"$BASH" -p -c '
  TIMEFORMAT=MARK
  time exec 2>"$1/replaced"
  printf AFTER >&2
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/replaced")" = $'MARK\nAFTER'

"$BASH" -p -c '
  TIMEFORMAT=MARK
  { time (true) 2>"$1/subshell-local"; } 2>"$1/subshell-parent"
  { time { true; } 2>"$1/brace-local"; } 2>"$1/brace-parent"
  { time (true) 2>"$1/pipeline-local" | :; } 2>"$1/pipeline-parent"
  { time true 2>"$1/background-simple-local" & wait; } \
    2>"$1/background-simple-parent"
  { time { true; } 2>"$1/background-group-local" & wait; } \
    2>"$1/background-group-parent"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/subshell-local")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/subshell-parent"
test ! -s "$SHELLCLAVE_TIME_PROBE/brace-local"
test "$(<"$SHELLCLAVE_TIME_PROBE/brace-parent")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/pipeline-local"
test "$(<"$SHELLCLAVE_TIME_PROBE/pipeline-parent")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/background-simple-local"
test "$(<"$SHELLCLAVE_TIME_PROBE/background-simple-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/background-group-local")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/background-group-parent"

"$BASH" -p -c '
  TIMEFORMAT=MARK
  ( true && exec 2>"$1/conditional-taken"; time true )
  ( false && exec 2>"$1/conditional-skipped"; time true ) \
    2>"$1/conditional-parent"
  ( true && exec 3>"$1/indirect-taken"; exec 2>&3; time true ) \
    3>"$1/indirect-parent-unused"
  ( false && exec 3>"$1/indirect-skipped"; exec 2>&3; time true ) \
    3>"$1/indirect-parent"
  ( true && exec 3>"$1/success-chain" && exec 2>&3 && time true )
  ( true && time { exec 2>"$1/group-success-chain"; true; } )
  { time { exec 2>"$1/piped-group-local"; true; } | :; } \
    2>"$1/piped-group-parent"
  captured=$(exec 2>&1; time true)
  test "$captured" = MARK

  ( false || exec 2>"$1/or-taken"; time true ) \
    2>"$1/or-taken-parent"
  ( true || exec 2>"$1/or-skipped"; time true ) \
    2>"$1/or-skipped-parent"
  ( true && exec 2>"$1/mixed-and" || exec 2>"$1/mixed-or-skipped"; time true ) \
    2>"$1/mixed-parent"
  ( false && exec 2>"$1/mixed-and-skipped" || exec 2>"$1/mixed-or"; time true ) \
    2>"$1/mixed-fallback-parent"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/conditional-taken")" = MARK
test ! -e "$SHELLCLAVE_TIME_PROBE/conditional-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/conditional-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/indirect-taken")" = MARK
test ! -e "$SHELLCLAVE_TIME_PROBE/indirect-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/indirect-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/success-chain")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/group-success-chain")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/piped-group-local"
test "$(<"$SHELLCLAVE_TIME_PROBE/piped-group-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/or-taken")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/or-taken-parent"
test ! -e "$SHELLCLAVE_TIME_PROBE/or-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/or-skipped-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/mixed-and")" = MARK
test ! -e "$SHELLCLAVE_TIME_PROBE/mixed-or-skipped"
test ! -s "$SHELLCLAVE_TIME_PROBE/mixed-parent"
test ! -e "$SHELLCLAVE_TIME_PROBE/mixed-and-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/mixed-or")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/mixed-fallback-parent"

# A failed compound setup never enters its body. Successful earlier named
# allocations in the setup still persist when a later redirect fails.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 3>"$1/setup-base" 2>"$1/setup-report-base"
  { exec 3>"$1/setup-body"; true; } >/dev/null/child ||
    printf BASE >&3
  { exec 2>"$1/setup-report-body"; true; } >/dev/null/child || time true
  exec {fd}>"$1/setup-named-base"
  { exec {fd}>"$1/setup-named-body"; true; } >/dev/null/child ||
    printf BASE >&$fd
  { exec {fd}>"$1/partial-body"; true; } \
    {fd}>"$1/partial-setup" >/dev/null/child || printf PARTIAL >&$fd
' _ "$SHELLCLAVE_TIME_PROBE" 2>/dev/null
test "$(<"$SHELLCLAVE_TIME_PROBE/setup-base")" = BASE
test ! -e "$SHELLCLAVE_TIME_PROBE/setup-body"
case "$(<"$SHELLCLAVE_TIME_PROBE/setup-report-base")" in
  *$'\nMARK\n'*) ;;
  *) exit 1 ;;
esac
test ! -e "$SHELLCLAVE_TIME_PROBE/setup-report-body"
test "$(<"$SHELLCLAVE_TIME_PROBE/setup-named-base")" = BASE
test ! -e "$SHELLCLAVE_TIME_PROBE/setup-named-body"
test "$(<"$SHELLCLAVE_TIME_PROBE/partial-setup")" = PARTIAL
test ! -e "$SHELLCLAVE_TIME_PROBE/partial-body"

# Only returning paths reach a later command or timer. A path that exits
# cannot contribute a descriptor mutation or an unset binding to that join.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 3>"$1/terminal-base" 2>"$1/terminal-report-base"
  false && { exec 3>"$1/terminal-body"; exit 0; }
  printf BASE >&3
  false && { exec 2>"$1/terminal-report-body"; exit 0; }
  time true
  exec {fd}>"$1/terminal-named-base"
  false && { unset fd; exit 0; }
  printf BASE >&$fd
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/terminal-base")" = BASE
test "$(<"$SHELLCLAVE_TIME_PROBE/terminal-report-base")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/terminal-named-base")" = BASE
test ! -e "$SHELLCLAVE_TIME_PROBE/terminal-body"
test ! -e "$SHELLCLAVE_TIME_PROBE/terminal-report-body"
"$BASH" -p -c '
  exec 3>"$1/terminal-taken-base"
  true && { exec 3>"$1/terminal-taken-body"; exit 0; }
  printf UNREACHABLE >&3
' _ "$SHELLCLAVE_TIME_PROBE"
test ! -s "$SHELLCLAVE_TIME_PROBE/terminal-taken-base"
test ! -s "$SHELLCLAVE_TIME_PROBE/terminal-taken-body"

# Even a closed descriptor may be duplicated onto itself without failing.
"$BASH" -p -c 'exec 2>&-; { true; } 2>&2'

# Wrapping a status builtin in a compound does not make its status unknown.
# Check both persistent descriptor publication and a later timing report.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/compound-status-old"
  { false; } || { exec 2>"$1/compound-status-new"; } && time true
' _ "$SHELLCLAVE_TIME_PROBE"
test ! -s "$SHELLCLAVE_TIME_PROBE/compound-status-old"
test "$(<"$SHELLCLAVE_TIME_PROBE/compound-status-new")" = MARK
printf 'payload\n' >"$SHELLCLAVE_TIME_PROBE/compound-status-input"
"$BASH" -p -c '
  { { false; }; } || { exec {fd}<"$1/compound-status-input"; } &&
    captured=$(IFS= read -r value <&$fd; printf "%s" "$value")
  test "$captured" = payload
' _ "$SHELLCLAVE_TIME_PROBE"

# A successful unrelated predecessor does not refine an earlier branch.
# Child shells inherit the enclosing group's current, temporarily redirected
# table; their own subsequent changes remain private.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  ( true && exec 2>"$1/prior-taken"; true && time true )
  ( false && exec 2>"$1/prior-skipped"; true && time true ) \
    2>"$1/prior-parent"
  ( true && exec 3>"$1/prior-copy-taken"; true && exec 2>&3; time true )
  ( false && exec 3>"$1/prior-copy-skipped"; true && exec 2>&3; time true ) \
    3>"$1/prior-copy-parent"
  { true && exec 2>"$1/nested-taken"; (time true); } \
    2>"$1/nested-taken-outer"
  { false && exec 2>"$1/nested-skipped"; (time true); } \
    2>"$1/nested-skipped-outer"
  ( true && exec 2>"$1/long-chain" && true && time true )
  { (exec 2>"$1/child-private"; time true); time true; } \
    2>"$1/child-parent"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/prior-taken")" = MARK
test ! -e "$SHELLCLAVE_TIME_PROBE/prior-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/prior-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/prior-copy-taken")" = MARK
test ! -e "$SHELLCLAVE_TIME_PROBE/prior-copy-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/prior-copy-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/nested-taken")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/nested-taken-outer"
test ! -e "$SHELLCLAVE_TIME_PROBE/nested-skipped"
test "$(<"$SHELLCLAVE_TIME_PROBE/nested-skipped-outer")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/long-chain")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/child-private")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/child-parent")" = MARK

# A foreground compound's redirect undo frame restores only the numeric
# slots it actually changed. In-body exec mutations to other slots, aliases
# copied from the temporary table, and named allocations remain persistent.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/restored-old"
  time { exec 2>"$1/restored-new"; } 2>"$1/restored-local"
  time true
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/restored-old")" = $'MARK\nMARK'
test ! -s "$SHELLCLAVE_TIME_PROBE/restored-new"
test ! -s "$SHELLCLAVE_TIME_PROBE/restored-local"

"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/nested-restored-old"
  time { { exec 2>"$1/nested-restored-new"; } 2>"$1/nested-local"; true; }
  time { exec 2>&-; } 2>"$1/closed-local"
  time { true && exec 2>"$1/conditional-local-new"; true; } \
    2>"$1/conditional-local"
  time true
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/nested-restored-old")" = $'MARK\nMARK\nMARK\nMARK'
test ! -s "$SHELLCLAVE_TIME_PROBE/nested-restored-new"
test ! -s "$SHELLCLAVE_TIME_PROBE/nested-local"
test ! -s "$SHELLCLAVE_TIME_PROBE/closed-local"
test ! -s "$SHELLCLAVE_TIME_PROBE/conditional-local-new"

# A numeric self-duplication is a no-op; Bash does not push an undo entry.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  time { exec 2>"$1/self-dup-new"; } 2>&2
  time true
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/self-dup-new")" = $'MARK\nMARK'

"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/copied-parent"
  time { exec 3>&2; } 2>"$1/copied-local"
  time exec 2>&3
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/copied-parent")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/copied-local")" = MARK

"$BASH" -p -c '
  TIMEFORMAT=MARK
  { exec 3>"$1/group-and-keep" 2>"$1/group-and-new"; } \
    2>"$1/group-and-local" && time exec 2>&3
  { exec {log}>"$1/named-keep"; exec 2>&$log; } \
    2>"$1/named-local"
  time exec 2>&$log
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/group-and-keep")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/group-and-new"
test ! -s "$SHELLCLAVE_TIME_PROBE/group-and-local"
test "$(<"$SHELLCLAVE_TIME_PROBE/named-keep")" = MARK

# A cd-only compound supplies its own status and pipeline endpoint. Earlier
# unrelated false/true commands cannot determine its successor.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  false; time { cd "$1"; } && exec 2>"$1/cd-group-and"
  time true
' _ "$SHELLCLAVE_TIME_PROBE" 2>/dev/null
test "$(<"$SHELLCLAVE_TIME_PROBE/cd-group-and")" = MARK
"$BASH" -p -c '
  TIMEFORMAT=MARK
  true; time { cd "$1/missing" 2>/dev/null; } || exec 2>"$1/cd-group-or"
  time true
' _ "$SHELLCLAVE_TIME_PROBE" 2>/dev/null
test "$(<"$SHELLCLAVE_TIME_PROBE/cd-group-or")" = MARK
"$BASH" -p -c '{ cd "$1"; } | test -p /dev/fd/0' _ "$SHELLCLAVE_TIME_PROBE"

# Restoration also governs ordinary command/substitution input, not just
# report routing. A copied temporary input descriptor survives group exit.
"$BASH" -p -c '
  printf OLD >"$1/input-old"
  printf NEW >"$1/input-new"
  printf LOCAL >"$1/input-local"
  exec 0<"$1/input-old"
  { exec 0<"$1/input-new"; } <"$1/input-local"
  IFS= read -r -N3 value
  test "$value" = OLD
  { exec 3<&0; } <"$1/input-local"
  IFS= read -r -N5 value <&3
  test "$value" = LOCAL
  exec 2>"$1/substitution-old"
  { exec 2>"$1/substitution-new"; } 2>"$1/substitution-local" &&
    printf "%s" "$(printf CHILD >&2)"
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/substitution-old")" = CHILD
test ! -s "$SHELLCLAVE_TIME_PROBE/substitution-new"

# Input-style duplication aliases the whole descriptor, including its output
# direction. Both persistent exec and compound-local <& affect reports.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/read-dup-old" 3>"$1/read-dup-new"
  exec 2<&3
  time true
  exec 2>"$1/read-group-old" 3>"$1/read-group-new"
  { time true; } 2<&3
' _ "$SHELLCLAVE_TIME_PROBE"
test ! -s "$SHELLCLAVE_TIME_PROBE/read-dup-old"
test "$(<"$SHELLCLAVE_TIME_PROBE/read-dup-new")" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/read-group-old"
test "$(<"$SHELLCLAVE_TIME_PROBE/read-group-new")" = MARK

# With default varredir_close, ordinary named allocations persist. They may
# rebind an existing variable and copy a command-local numeric descriptor.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec {fd}>"$1/named-rebind-old"
  : {fd}>"$1/named-rebind-new"
  exec 2>&$fd
  time true
  : 3>"$1/named-copy-new" {fd}>&3
  exec 2>&$fd
  time true
  time { true; } {fd}>"$1/named-group-new"
  exec 2>&$fd
  time true
' _ "$SHELLCLAVE_TIME_PROBE"
test ! -s "$SHELLCLAVE_TIME_PROBE/named-rebind-old"
test "$(<"$SHELLCLAVE_TIME_PROBE/named-rebind-new")" = MARK
test "$(<"$SHELLCLAVE_TIME_PROBE/named-copy-new")" = $'MARK\nMARK'
test "$(<"$SHELLCLAVE_TIME_PROBE/named-group-new")" = MARK

named_read_copy=$("$BASH" -p -c '
  TIMEFORMAT=MARK
  exec {fd}>"$1/named-read-old"
  : {fd}<&1
  exec 2>&$fd
  time true
' _ "$SHELLCLAVE_TIME_PROBE")
test "$named_read_copy" = MARK
test ! -s "$SHELLCLAVE_TIME_PROBE/named-read-old"

# A document redirect does not end the timed execution stage. Pipeline exec
# remains private and neither its own nor a later timer uses that redirect.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/document-pipe-parent"
  time exec 2>"$1/document-pipe-local" <<<body | :
  time true
  time exec 2>"$1/heredoc-pipe-local" <<EOF | :
body
EOF
  time true
' _ "$SHELLCLAVE_TIME_PROBE"
test "$(<"$SHELLCLAVE_TIME_PROBE/document-pipe-parent")" = $'MARK\nMARK\nMARK\nMARK'
test ! -s "$SHELLCLAVE_TIME_PROBE/document-pipe-local"
test ! -s "$SHELLCLAVE_TIME_PROBE/heredoc-pipe-local"

# A substitution in a later redirect operand inherits the earlier redirect
# even when that redirect will not feed the outer command. Use only builtins
# so these input-routing probes do not depend on PATH or external programs.
"$BASH" -p -c '
  read -r answer <<< stale <<< "$(read -r value; printf "seen:%s" "$value")"
  test "$answer" = seen:stale
  read -r answer <<A <<B
stale
A
$(read -r value; printf "seen:%s" "$value")
B
  test "$answer" = seen:stale
'

"$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 2>"$1/recursive-old"
  true && exec 2>"$1/recursive-new"
  value=$(time true)
  test ! -s "$1/recursive-old"
  test "$(<"$1/recursive-new")" = MARK
  : >"$1/recursive-old"
  exec 3>"$1/recursive-old"
  value=$(printf CHILD >&3 >"$1/recursive-overwrite")
  test ! -s "$1/recursive-old"
  test "$(<"$1/recursive-overwrite")" = CHILD
' _ "$SHELLCLAVE_TIME_PROBE"

# Descriptor aliases retain stream identity, not just a descriptor number.
# A copy made before command substitution bypasses its newly installed stdout;
# a copy made inside it belongs to that capture. Descriptor-only exec itself
# contributes no captured bytes.
before_capture=$("$BASH" -p -c '
  exec 3>&1
  captured=$(printf BYPASS >&3)
  printf "captured=<%s>" "$captured"
')
test "$before_capture" = 'BYPASScaptured=<>'
inside_capture=$("$BASH" -p -c '
  captured=$(exec 3>&1; printf VALUE >&3)
  printf "captured=<%s>" "$captured"
')
test "$inside_capture" = 'captured=<VALUE>'
before_report=$("$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 3>&1
  captured=$(time exec 2>&3)
  printf "captured=<%s>" "$captured"
')
test "$before_report" = $'MARK\ncaptured=<>'
nested_report=$("$BASH" -p -c '
  TIMEFORMAT=MARK
  exec 3>&1
  printf "inner=<%s>" "$(time exec 2>&3)"
')
test "$nested_report" = $'MARK\ninner=<>'

# Unknown branch outcomes retain alternatives in the graph. Both concrete
# outcomes must obey the same ordinary-I/O and command-capture routing rules.
"$BASH" -p -c '
  printf value
' >"$SHELLCLAVE_TIME_PROBE/input-route"
for outcome in true false; do
  routed=$("$BASH" -p -c '
    "$2" && exec >"$1/ordinary-route"
    printf VALUE
  ' _ "$SHELLCLAVE_TIME_PROBE" "$outcome")
  if test "$outcome" = true; then
    test -z "$routed"
    test "$(<"$SHELLCLAVE_TIME_PROBE/ordinary-route")" = VALUE
  else
    test "$routed" = VALUE
  fi
  captured=$("$BASH" -p -c '
    result=$(exec 3>&1 >"$1/capture-route"; "$2" && exec >&3; printf VALUE)
    printf "%s" "$result"
  ' _ "$SHELLCLAVE_TIME_PROBE" "$outcome")
  if test "$outcome" = true; then
    test "$captured" = VALUE
    test ! -s "$SHELLCLAVE_TIME_PROBE/capture-route"
  else
    test -z "$captured"
    test "$(<"$SHELLCLAVE_TIME_PROBE/capture-route")" = VALUE
  fi
done

# Pipeline input is installed before expansion. Later command-local redirects
# do not alter a command-word substitution's inherited pipeline input.
"$BASH" -p -c '
  printf PAYLOAD | printf "arg=<%s>" \
    "$(IFS= read -r -N7 value; printf "%s" "$value")" \
    <"$1/input-route" >"$1/pipeline-word"
  test "$(<"$1/pipeline-word")" = "arg=<PAYLOAD>"
  printf PAYLOAD > >(printf "%s" \
    "$(IFS= read -r -N7 value; printf "%s" "$value")" >"$1/process-word")
  consumer=$!
  wait "$consumer"
  test "$(<"$1/process-word")" = PAYLOAD
' _ "$SHELLCLAVE_TIME_PROBE"

# Group-level |& is active while the body runs; command-local |& is not yet
# active while that command's words expand. A nested timing report follows the
# former pipeline but the latter enclosing stderr.
group_report=$("$BASH" -p -c '
  TIMEFORMAT=MARK
  { printf "%s" "$(time true)"; } |& { IFS= read -r line; printf "%s" "$line"; }
')
test "$group_report" = MARK
"$BASH" -p -c '
  TIMEFORMAT=MARK
  printf "%s" "$(time true)" |& :
' 2>"$SHELLCLAVE_TIME_PROBE/command-word-report"
test "$(<"$SHELLCLAVE_TIME_PROBE/command-word-report")" = MARK

# The final brace stage is one private shell scope. Persistent descriptor
# aliases and CWD changes survive between body commands, not outside it.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  printf PAYLOAD | { exec 2>"$1/final-report"; time true; }
  test "$(<"$1/final-report")" = MARK
  printf PAYLOAD |& { exec {fd}>"$1/final-named"; exec 2>&$fd; time true; }
  test "$(<"$1/final-named")" = MARK
  printf PAYLOAD | {
    exec 3<&0
    exec <"$1/input-route"
    value=$(IFS= read -r -N7 value <&3; printf "%s" "$value")
    test "$value" = PAYLOAD
  }
  printf PAYLOAD | {
    { exec {fd}<&0; }
    value=$(IFS= read -r -N7 value <&$fd; printf "%s" "$value")
    test "$value" = PAYLOAD
  }
  cd "$1"
  original=$PWD
  printf x | { { cd /; }; printf "%s" "$PWD" >"$1/final-cwd"; }
  test "$(<"$1/final-cwd")" = /
  test "$PWD" = "$original"
  printf x | { cd /; } <"$1/input-route"
  test "$PWD" = "$original"
  { printf x | :; cd /; }
  test "$PWD" = /
' _ "$SHELLCLAVE_TIME_PROBE"

# A leading document is a redirect on the same timed simple command, not an
# empty stage. Later ordinary `time` after a pipe is still an executable name.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  { time <<<body IFS= read -r value; } 2>"$1/leading-report"
  test "$value" = body
  test "$(<"$1/leading-report")" = MARK
  { time 3<<<body IFS= read -r value <&3; } 2>"$1/leading-fd-report"
  test "$value" = body
  if true | time <<<body 2>"$1/ordinary-doc-error"; then
    exit 1
  else
    test "$?" = 127
  fi
  [[ "$(<"$1/ordinary-doc-error")" = *"time: command not found"* ]]
' _ "$SHELLCLAVE_TIME_PROBE"

# Empty timing has no command bytes to capture or input to consume. Its report
# is still real output of the timer when stderr is explicitly captured.
"$BASH" -p -c '
  set -e
  exec 3>"$1/scope-base"
  { { exec 4>&3; exec 3>"$1/scope-changed"; }; } 3>"$1/scope-temporary"
  printf AFTER >&3
  printf SAVED >&4
  test "$(<"$1/scope-base")" = AFTER
  test "$(<"$1/scope-temporary")" = SAVED
  test ! -s "$1/scope-changed"
  TIMEFORMAT=MARK
  exec 2>"$1/scope-report-base"
  time { { exec 5>&2; exec 2>"$1/scope-report-changed"; }; } 2>"$1/scope-report-temporary"
  exec 2>&5
  time true
  test "$(<"$1/scope-report-base")" = MARK
  test "$(<"$1/scope-report-temporary")" = MARK
  test ! -s "$1/scope-report-changed"
' _ "$SHELLCLAVE_TIME_PROBE"

"$BASH" -p -c '
  TIMEFORMAT=MARK
  { captured=$(time; true); } 2>"$1/empty-report"
  test -z "$captured"
  test "$(<"$1/empty-report")" = MARK
  captured=$(exec 2>&1; time; true)
  test "$captured" = MARK
  { printf PAYLOAD > >(time; IFS= read -r -N7 value; printf "%s" "$value" \
    >"$1/empty-process"); } 2>"$1/empty-process-report"
  consumer=$!
  wait "$consumer"
  test "$(<"$1/empty-process")" = PAYLOAD
  test "$(<"$1/empty-process-report")" = MARK
' _ "$SHELLCLAVE_TIME_PROBE"
]=]
  RESULT_VARIABLE status
  ERROR_VARIABLE diagnostic)
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
(
  exec 3>"$1/local-base"
  exec 3>"$1/local-pipe" | :
  printf PIPE >&3
  exec 3>"$1/local-background" &
  wait
  printf BACKGROUND >&3
)
test "$(<"$1/local-base")" = PIPEBACKGROUND
test ! -s "$1/local-pipe"
test ! -s "$1/local-background"
(
  exec {fd}>"$1/local-named"
  unset fd | :
  printf NAMED >&$fd
)
test "$(<"$1/local-named")" = NAMED
(
  TIMEFORMAT=MARK
  exec 2>"$1/local-report"
  exec 2>"$1/local-pipeline-report" | :
  time true
)
test "$(<"$1/local-report")" = MARK
test ! -s "$1/local-pipeline-report"

# A taken conditional invalidation cannot keep using the previous named
# binding. Unset produces an ambiguous redirect; assignment redirects to the
# assigned numeric fd, not the file which the old binding opened.
if "$BASH" -p -c '
  exec {fd}>"$1/conditional-unset"
  test x = x && { unset fd; }
  printf WRONG >&$fd
' _ "$1" 2>"$1/conditional-unset-error"; then
  exit 1
fi
test ! -s "$1/conditional-unset"
[[ "$(<"$1/conditional-unset-error")" = *"ambiguous redirect"* ]]
assigned=$("$BASH" -p -c '
  exec {fd}>"$1/conditional-assignment"
  test x = x && { fd=1; }
  printf ASSIGNED >&$fd
' _ "$1")
test "$assigned" = ASSIGNED
test ! -s "$1/conditional-assignment"
"$BASH" -p -c '
  exec {fd}>"$1/conditional-skip"
  false && { unset fd; }
  printf RETAINED >&$fd
  test x = x && { unset fd; }
  exec {fd}>"$1/conditional-reallocated"
  printf REALLOCATED >&$fd
' _ "$1"
test "$(<"$1/conditional-skip")" = RETAINED
test "$(<"$1/conditional-reallocated")" = REALLOCATED

# CWD transitions use the same process boundaries as descriptor state. A
# pipeline-local cd cannot change its enclosing list, whereas a cd inside an
# isolated compound still changes that compound's following commands.
test "$("$BASH" -p -c 'cd /; ( : | cd /tmp; pwd )')" = /
test "$("$BASH" -p -c 'cd /; cd /tmp <<<body | :; pwd')" = /
test "$("$BASH" -p -c 'cd /; time cd /tmp <<<body | :; pwd' 2>/dev/null)" = /
test "$("$BASH" -p -c 'cd /; { : | cd /tmp; pwd; } & wait')" = /
test "$("$BASH" -p -c 'cd /; time { cd /tmp; pwd; } & wait' 2>/dev/null)" = /tmp
test "$("$BASH" -p -c 'cd /; time { cd /tmp; pwd; } | { read -r value; printf "%s" "$value"; }' 2>/dev/null)" = /tmp
test "$("$BASH" -p -c 'cd /; ( cd /tmp; : | cd /; pwd )')" = /tmp

# A preceding true/false cannot stand in for a conditional cd's own status.
# Both group continuations below execute, but for different cd outcomes.
"$BASH" -p -c '
  TIMEFORMAT=MARK
  false; cd "$1" && { exec 2>"$1/cd-and-report"; }; time true
' _ "$1"
test "$(<"$1/cd-and-report")" = MARK
"$BASH" -p -c '
  TIMEFORMAT=MARK
  true; cd "$1/missing-directory" || { exec 2>"$1/cd-or-report"; }; time true
' _ "$1" 2>/dev/null
test "$(<"$1/cd-or-report")" = MARK

# Numeric self-duplication preserves inherited descriptors as well as explicit
# bindings, including before an operand expansion. Fixed benign commands only.
test "$("$BASH" -p -c 'exec 0<&0 1>&1 2>&2; echo "$(printf value)"')" = value
"$BASH" -p -c '
  exec 3>"$1/self-dup-output"
  exec 3>&3
  printf value >&3
  : 2>&2 >"$(printf "%s/self-dup-operand" "$1")"
' _ "$1"
test "$(<"$1/self-dup-output")" = value
test -f "$1/self-dup-operand"

# Heredoc expansions observe the earlier redirects at their own markers,
# although their bodies are inspected after the later file operand.
printf "old\n" >"$1/checkpoint-old"
printf "new\n" >"$1/checkpoint-new"
printf "last\n" >"$1/checkpoint-last"
"$BASH" -p -c '
  probe() { read -r value <&3; printf "%s" "$value" >&2; }
  exec 3<"$1/checkpoint-old"
  : <<A 3<"$1/checkpoint-new" <<B 3<"$1/checkpoint-last" >"$(probe; printf "%s/checkpoint-result" "$1")"
$(probe)
A
$(probe)
B
' _ "$1" 2>"$1/checkpoint-observed"
test "$(<"$1/checkpoint-observed")" = oldnewlast
]=] _ "${time_probe_dir}"
  RESULT_VARIABLE isolation_status
  ERROR_VARIABLE isolation_diagnostic)
if(NOT isolation_status EQUAL 0)
  message(FATAL_ERROR "Bash local process isolation failed: ${isolation_diagnostic}")
endif()
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash time reference failed (${status}): ${diagnostic}")
endif()
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" -p -c [=[
set -e
cd "$1"
# The source strings are fixed fixtures, never submitted command input.
for source in \
  '! exit 0 >missing-parent/file && exec 1>out; printf payload' \
  'exit 0 >missing-parent/file || exec 1>out; printf payload' \
  '! exec cat <missing-parent/file && exec 1>out; printf payload' \
  '! false && exec 1>out; printf payload' \
  '! true || exec 1>out; printf payload' \
  '(! exit 1; true) || exec 1>out; printf payload' \
  '(UID=0; true) || exec 1>out; printf payload' \
  '(UID=0 >missing-parent/file; true) || exec 1>out; printf payload' \
  '(! (UID=0 >inner; true)) && exec 1>out; printf payload' \
  '(UID=0 true >inner; true) && exec 1>out; printf payload' \
  '( { UID=0; } >missing-parent/file; true) && exec 1>out; printf payload' \
  '(>inner UID=0; true) || exec 1>out; printf payload' \
  '(X=1 >inner UID=0; true) || exec 1>out; printf payload' \
  '(EUID=0; true) || exec 1>out; printf payload' \
  '(PPID=0; true) || exec 1>out; printf payload' \
  '(SHELLOPTS=0; true) || exec 1>out; printf payload' \
  '(BASHOPTS=0; true) || exec 1>out; printf payload' \
  '(BASH_VERSINFO=0; true) || exec 1>out; printf payload' \
  '(UID+=0; true) || exec 1>out; printf payload' \
  '(U\
ID=0; true) || exec 1>out; printf payload' \
  '( { UID=0; true; }; true) || exec 1>out; printf payload' \
  '(! UID=0; true) || exec 1>out; printf payload' \
  '(X=$((1/0)) true) || exec 1>out; printf payload' \
  '(X=${missing?absent} true) || exec 1>out; printf payload' \
  '(printf "${missing?absent}"; true) || exec 1>out; printf payload' \
  '(exit 1; true) || exec 1>out; printf payload' \
  '(exec false; true) || exec 1>out; printf payload' \
  '( { exit 1; }; true) || exec 1>out; printf payload' \
  '(true && exit 1 || true; true) || exec 1>out; printf payload' \
  '(! { exit 1; }; true) || exec 1>out; printf payload'
do
  : >out
  "$BASH" -p -c "$source" 2>/dev/null
  test "$(<out)" = payload
done
for source in \
  '! exit 0 >missing-parent/file || exec 1>out; printf payload' \
  '! exec cat <missing-parent/file || exec 1>out; printf payload' \
  '! true && exec 1>out; printf payload' \
  '! false || exec 1>out; printf payload' \
  '(UID=0; true) && exec 1>out; printf payload' \
  '(UID=0 >missing-parent/file; true) && exec 1>out; printf payload' \
  '(>inner UID=0; true) && exec 1>out; printf payload' \
  '(EUID=0 >inner; true) && exec 1>out; printf payload' \
  '(UID+=0 >inner; true) && exec 1>out; printf payload' \
  '(! UID=0 >inner; true) && exec 1>out; printf payload' \
  '( { UID=0 >inner; true; }; true) && exec 1>out; printf payload' \
  '(UID=0 true; true) || exec 1>out; printf payload' \
  '(! (UID=0); true) || exec 1>out; printf payload' \
  '(exit 0; false) || exec 1>out; printf payload' \
  '(false && exit 1; true) || exec 1>out; printf payload' \
  '(! (exit 1); true) || exec 1>out; printf payload' \
  '(exec 1>inner; true) || exec 1>out; printf payload'
do
  : >out
  test "$("$BASH" -p -c "$source" 2>/dev/null)" = payload
  test ! -s out
done
# A readonly assignment is rejected before this simple command evaluates its
# redirects, even when the redirect is lexically before the assignment.
for source in \
  'UID=0 >"$(printf redirect >readonly-redirect-marker; printf readonly-target)"; printf later >readonly-later-marker' \
  '>"$(printf redirect >readonly-redirect-marker; printf readonly-target)" UID=0; printf later >readonly-later-marker'
do
  if "$BASH" -p -c "$source" 2>/dev/null; then exit 1; fi
  test ! -e readonly-redirect-marker
  test ! -e readonly-target
  test ! -e readonly-later-marker
done
# The rejected assignment's RHS can still expand first.
if "$BASH" -p -c '
  (UID=$(printf rhs >readonly-rhs-marker; printf 0) >"$(printf redirect >readonly-redirect-marker; printf readonly-target)";
   printf later >readonly-later-marker)
' 2>/dev/null; then exit 1; fi
test "$(<readonly-rhs-marker)" = rhs
test ! -e readonly-redirect-marker
test ! -e readonly-target
test ! -e readonly-later-marker
# An enclosing group's redirect is evaluated before execution of its body.
if "$BASH" -p -c '
  { UID=0; } >"$(printf group >readonly-group-marker; printf readonly-group-target)"
' 2>/dev/null; then exit 1; fi
test "$(<readonly-group-marker)" = group
test -e readonly-group-target
# Recoverable failures abort one top-level input unit, not the submitted text.
for source in \
  $'UID=0\nexec 1>out; printf payload' \
  $'! UID=0\nexec 1>out; printf payload' \
  $'{ UID=0; }\nexec 1>out; printf payload' \
  $'X=$((1/0))\nexec 1>out; printf payload' \
  $'X=abc; printf "%s" "${X:1/0}"\nexec 1>out; printf payload' \
  $'X="bad name"; printf "%s" "${!X}"\nexec 1>out; printf payload'
do
  : >out
  "$BASH" -p -c "$source" 2>/dev/null
  test "$(<out)" = payload
done
# Required-parameter errors and exit terminate even across input boundaries.
for source in \
  $'printf "%s" "${missing?absent}"\nprintf payload' \
  $'exit 0\nprintf payload' \
  $'UID=0 &&\nprintf payload' \
  $'{ UID=0;\nprintf payload; }' \
  $'printf "%s" "$(UID=0\nprintf payload)"'
do
  test -z "$("$BASH" -p -c "$source" 2>/dev/null || :)"
done
# Assignment values following rejection must not execute.
if "$BASH" -p -c 'UID=0 X=$(printf never >readonly-next-marker)' 2>/dev/null; then exit 1; fi
test ! -e readonly-next-marker
# Redirect failure returns without publishing the operation that failed.
"$BASH" -p -c '
  exec 3>prefix-base
  true && exec 3>missing-parent/out || printf payload >&3
' 2>/dev/null
test "$(<prefix-base)" = payload
"$BASH" -p -c '
  exec 3>prefix-base
  exec 3>prefix-out 4>missing-parent/out || printf payload >&3
' 2>/dev/null
test "$(<prefix-base)" = payload
test ! -s prefix-out

# Unlike numeric redirects, a completed named allocation survives a later
# failure. A close, whether numeric or named, is rolled back on that failure.
"$BASH" -p -c '
  exec {fd}>prefix-base
  exec {fd}>prefix-out 4>missing-parent/out || printf payload >&$fd
' 2>/dev/null
test ! -s prefix-base
test "$(<prefix-out)" = payload
for source in \
  'exec 3>prefix-base; exec 3>&- 4>missing-parent/out || printf payload >&3' \
  'exec {fd}>prefix-base; exec {fd}>&- 4>missing-parent/out || printf payload >&$fd'
do
  "$BASH" -p -c "$source" 2>/dev/null
  test "$(<prefix-base)" = payload
done

# Failed group setup skips allocation; it does not undo an earlier scalar
# reassignment of the descriptor variable.
"$BASH" -p -c '
  exec 7>prefix-seven
  exec {fd}>prefix-base
  fd=7
  { exec {fd}>prefix-out; true; } >missing-parent/out
  printf payload >&$fd
' 2>/dev/null
test "$(<prefix-seven)" = payload
test ! -s prefix-base

# Resolved status builtins keep their fixed status through wrappers and ignored
# operands. The skipped branch must neither unset the FD nor move the report.
for source in \
  'false ignored &&' \
  'command false &&' \
  'command -p f"a"lse ignored &&' \
  'builtin false ignored &&' \
  'true ignored ||' \
  'builtin true ||' \
  'command -p true ignored ||' \
  'com"mand" : ignored ||' \
  '! builtin true ignored &&' \
  '! command false ignored ||'
do
  "$BASH" -p -c "
    exec {fd}>status-output || exit
    $source unset fd
    printf payload >&\"\$fd\"
    exec 2>status-report || exit
    $source exec 2>status-skipped
    TIMEFORMAT=MARK
    time true
  "
  test "$(<status-output)" = payload
  test "$(<status-report)" = MARK
  test ! -e status-skipped
done

# Numeric exit status is signed decimal, then reduced to the status byte.
# All cases below are static constants; redirects and wrapper words do not
# count as exit operands. A following marker must never execute.
for entry in \
  '2|exit 2' \
  '255|exit -1' \
  '0|exit +0' \
  '0|exit 256' \
  '0|exit 000256' \
  '0|exit -256' \
  '1|exit 257' \
  '0|exit -- 256' \
  '2|command exit 2' \
  '0|command -p exit +0' \
  '0|builtin ex"it" -- -256' \
  '0|exit " 256 "' \
  "0|exit \$'\\t-256\\n'" \
  $'0|exit 2\\\n56' \
  '255|exit 9223372036854775807' \
  '0|exit -9223372036854775808' \
  '2|exit 2 >exit-redirect'
do
  expected=${entry%%|*}
  source=${entry#*|}
  actual=0
  output=$("$BASH" -p -c "$source; printf AFTER" 2>/dev/null) || actual=$?
  test "$actual" = "$expected"
  test -z "$output"
done

# Operandless exit (also after --) transfers the entering list status. A
# subshell returns it; a brace group terminates the current shell with it.
for source in \
  '(false; exit) &&' \
  '(true; exit) ||' \
  '(false; exit --) &&' \
  '(true; command exit) ||' \
  '(false; builtin exit) &&' \
  '(true; ! exit) ||' \
  '(false || exit) &&' \
  '(true && exit) ||' \
  'false; (exit) &&' \
  'true; (exit --) ||' \
  'false; ( { exit; } ) &&' \
  'false; ({ exit; }) &&' \
  'true; ({(exit)}) ||' \
  '(false; exit <<< <(printf "%s" "$(true)")) &&' \
  '(true; exit <<< <(printf "%s" "$(false)")) ||' \
  '(false; exit <<< <(printf "%s" `true`)) &&' \
  '(true; exit <<< >(cat <<<"$(false)")) ||' \
  '(false; exit <<<prefix<(printf "%s" "$(true)")suffix) &&' \
  '(true; <<< <(printf "%s" "$(false)") exit) ||' \
  'true; ({ exit; } <<< <(printf "%s" "$(false)")) ||' \
  'true; ( (exit) ) ||' \
  'false; ! (exit) ||' \
  'true; ! { exit; };' \
  '(exit -- 2 2>&1) &&' \
  '(exit 2 >exit-redirect) &&'
do
  output=$("$BASH" -p -c "$source printf AFTER" 2>/dev/null || :)
  test -z "$output"
done
# A failed redirection prevents exit from running; it does not terminate the
# list. Unknown operand errors are deliberately not assigned one cross-version
# exit behavior: Bash has changed that behavior, unlike valid numeric exits.
test "$("$BASH" -p -c 'exit 2 2>&9; printf AFTER' 9>&- 2>/dev/null)" = AFTER
test "$("$BASH" -p -c 'exit --help >/dev/null; printf AFTER')" = AFTER
# A command substitution during setup can replace $? before exit runs. A
# process substitution does not do so; distinguish it from the later $().
for source in \
  '(true; exit >"$(printf /dev/null; false)") ||' \
  'true; ( { exit; } >"$(printf /dev/null; false)" ) ||' \
  'false; ( { exit; } >"$(printf /dev/null; true)" ) &&' \
  '(true; X="$(false)" exit) ||' \
  '(true; exit <<<"$(false)") ||' \
  '(true; <<<"$(false)" exit) ||' \
  '(true; exit <<<"`false`") ||' \
  '(true; exit <<< <(printf "%s" "$(true)") <<<"$(false)") ||' \
  '(true; exit <<<"$(false)" <<< <(printf "%s" "$(true)")) ||' \
  $'(true; exit <<EOF\n$(false)\nEOF\n) ||' \
  'false; ( { exit; } > >(:) >"$(printf /dev/null; true)" ) &&'
do
  test "$("$BASH" -p -c "$source printf AFTER" 2>/dev/null)" = AFTER
done

# Argv and assignment-value producers run before a simple command applies
# redirects, including when those words appear after the failing operation.
# Later redirect producers do not run. Each probe uses a fresh shell and its
# own markers; wait for standalone process substitutions before inspecting.
for source in \
  'true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" "$(< <(printf argument >argv-out; printf captured))"' \
  'true 9>&- 1>&9 "$(< <(printf argument >argv-out; printf captured))" <<<"$(printf redirect >redirect-out; printf document)"' \
  'true 9>&- 1>&9 >"$(printf redirect >redirect-out; printf target)" "$(< <(printf argument >argv-out; printf captured))"' \
  $'true 9>&- 1>&9 <<EOF "$(< <(printf argument >argv-out; printf captured))"\n$(printf redirect >redirect-out; printf document)\nEOF\n' \
  'true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" "$(printf argument >argv-out; printf captured)"' \
  'true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" "`printf argument >argv-out; printf captured`"' \
  'true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" <(printf argument >argv-out; printf captured)' \
  'true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" >(printf argument >argv-out)' \
  '9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" VALUE="$(printf argument >argv-out; printf captured)" true' \
  '9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" VALUE="$(printf argument >argv-out; printf captured)"' \
  'export 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" VALUE="$(printf argument >argv-out; printf captured)"' \
  'time -p true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" "$(< <(printf argument >argv-out; printf captured))"'
do
  rm -f argv-out redirect-out
  "$BASH" -p -c "$source"$'\n''
    status=$?
    if test -n "${!:-}"; then wait "$!"; fi
    test "$status" = 1
  ' 2>/dev/null || { printf 'unexpected setup status: %s\n' "$source" >&2; exit 1; }
  test -s argv-out || { printf 'missing argv write: %s\n' "$source" >&2; exit 1; }
  test "$(<argv-out)" = argument
  test ! -e redirect-out || { printf 'unexpected redirect write: %s\n' "$source" >&2; exit 1; }
done
for source in \
  'false && true 9>&- 1>&9 <<<"$(printf redirect >redirect-out; printf document)" "$(< <(printf argument >argv-out; printf captured))"' \
  '{ true <<<"$(printf redirect >redirect-out; printf document)" "$(< <(printf argument >argv-out; printf captured))"; } 9>&- 1>&9'
do
  rm -f argv-out redirect-out
  "$BASH" -p -c "$source; test \$? = 1" 2>/dev/null
  test ! -e argv-out
  test ! -e redirect-out
done
# The static file shortcut also expands before the redirect error. A missing
# input diagnoses its read first, regardless of where its argv word appears.
for source in \
  'true 9>&- 1>&9 <<<"$(true)" "$(< missing-argv-input)"' \
  '<<<"$(true)" VALUE="$(< missing-argv-input)" true 9>&- 1>&9' \
  '9>&- 1>&9 <<<"$(true)" VALUE="$(< missing-argv-input)"' \
  'export 9>&- 1>&9 <<<"$(true)" VALUE="$(< missing-argv-input)"'
do
  diagnostic=$("$BASH" -p -c "$source" 2>&1 || :)
  case "$diagnostic" in
    *missing-argv-input*'9: Bad file descriptor'*) ;;
    *) exit 1 ;;
  esac
done

# A failed setup must not erase its completed named allocation when a later
# command substitution imports the descriptor table.
: >input
rm -f argv-out
"$BASH" -p -c '
  true {fd}>argv-out 9>&- 1>&9 <<<"$(true)" "$(< input)"
  echo "$(printf argument >&$fd; printf captured)"
' >/dev/null 2>/dev/null
test "$(<argv-out)" = argument

# A failed numeric duplication suppresses subsequent redirect expansion, even
# when that operand has no command substitution. The shell returns from setup
# failure and still runs the later exec, so the report reaches stdout only.
# Independent argv/RHS expansions run before the simple command's redirects.
for source in \
  'time { true 9>&- 1>&9 <<<"${x:?}"; exec 2>&1; }' \
  'time { false 9>&- 1>&9 >"${x:?}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 >"${x?}"; exec 2>&1; }' \
  $'time { true 9>&- 1>&9 <<EOF\n${x:?}\nEOF\nexec 2>&1; }' \
  'time { true 9>&- 1>&9 >"${outer:-${x:?}}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 <<<"$((1/0))"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 >"$((1/0))"; exec 2>&1; }' \
  $'time { true 9>&- 1>&9 <<EOF\n$((1/0))\nEOF\nexec 2>&1; }' \
  'time { true 9>&- 1>&9 <<<"${x:?}" >"${y:?}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 <<<"$()"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 >"$(true)${x:?}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 <<<"$(<"${x:?}")"; exec 2>&1; }' \
  'time { { true; } 9>&- 1>&9 <<<"${x:?}"; exec 2>&1; }' \
  'time { { true; } 9>&- 1>&9 >"${x:?}"; exec 2>&1; }' \
  $'time { { true; } 9>&- 1>&9 <<EOF\n${x:?}\nEOF\nexec 2>&1; }' \
  'time { false && true >"${x:?}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 >"${x:?}" || exec 2>&1; }' \
  'time { ! true 9>&- 1>&9 <<<"${x:?}" && exec 2>&1; }'
do
  report=$("$BASH" -p -c "unset x y outer; TIMEFORMAT=PHASE; $source" \
    2>phase-error)
  test "$report" = PHASE
  [[ "$(<phase-error)" != *PHASE* ]]
done
report=$("$BASH" -p -c '
  unset x
  TIMEFORMAT=PHASE
  time { time { true 9>&- 1>&9 <<<"${x:?}"; exec 2>&1; }; exec 2>&1; }
' 2>phase-error)
test "$report" = $'PHASE\nPHASE'
[[ "$(<phase-error)" != *PHASE* ]]

# Completed named allocations remain available after the later setup failure.
for source in \
  'time { true {fd}>out 9>&- 1>&9 <<<"${x:?}"; printf payload >&$fd; exec 2>&1; }' \
  'time { true {fd}>out 9>&- 1>&9 >"${x:?}"; printf payload >&$fd; exec 2>&1; }'
do
  report=$("$BASH" -p -c "unset x fd; TIMEFORMAT=PHASE; $source" \
    2>phase-error)
  test "$report" = PHASE
  test "$(<out)" = payload
  [[ "$(<phase-error)" != *PHASE* ]]
done

# The same effects from an earlier redirect or any argv/RHS are not erased
# by the later setup failure. With an unset parameter/division by zero these
# concrete paths abort before exec can move stderr; their report stays there.
for source in \
  'time { true <<<"${x:?}" 9>&- 1>&9; exec 2>&1; }' \
  'time { true >"${x:?}" 9>&- 1>&9; exec 2>&1; }' \
  $'time { true <<EOF 9>&- 1>&9 >"${y:?}"\n${x:?}\nEOF\nexec 2>&1; }' \
  'time { true <<<"$((1/0))" 9>&- 1>&9; exec 2>&1; }' \
  'time { true 9>&- 1>&9 "${x:?}"; exec 2>&1; }' \
  'time { true 9>&- 1>&9 >"${y:?}" "${x:?}"; exec 2>&1; }' \
  'time { 9>&- 1>&9 X="${x:?}" true; exec 2>&1; }' \
  'time { 9>&- 1>&9 X="${x:?}"; exec 2>&1; }' \
  'time { export 9>&- 1>&9 X="${x:?}"; exec 2>&1; }'
do
  report=$("$BASH" -p -c "unset x y; TIMEFORMAT=PHASE; $source" \
    2>phase-error) || :
  test -z "$report"
  [[ "$(<phase-error)" == *$'\nPHASE' ]]
done
# A satisfied required parameter also has a returning path. The graph keeps
# both possibilities rather than unconditionally terminating such a command.
report=$("$BASH" -p -c '
  x=/dev/null
  TIMEFORMAT=PHASE
  time { true >"${x:?}" 9>&- 1>&9; exec 2>&1; }
' 2>phase-error)
test "$report" = PHASE
[[ "$(<phase-error)" != *PHASE* ]]

# A read-only source is live. Duplication succeeds, leaving the timing report
# unwritable rather than falling back to the previous stderr file.
: >prefix-out
: >prefix-input
"$BASH" -p -c '
  exec 2>prefix-base
  exec {fd}>prefix-out
  exec {fd}<prefix-input
  TIMEFORMAT=report
  time exec 2>&$fd
  :
'
test ! -s prefix-base
test ! -s prefix-out
]=] _ "${time_probe_dir}"
  RESULT_VARIABLE outcome_status
  ERROR_VARIABLE outcome_diagnostic)
file(REMOVE_RECURSE "${time_probe_dir}")
if(NOT outcome_status EQUAL 0)
  message(FATAL_ERROR "Bash scope outcome reference failed (${outcome_status}): ${outcome_diagnostic}")
endif()
