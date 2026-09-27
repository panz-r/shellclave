if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# This fixture receives hostile startup state through CTest. Clear it for
# neutral helper launches; the nested probes below pass it explicitly to show
# why the protected launcher has to establish every modeled invariant.
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "${SHELLCLAVE_BASH}" -p -c [=[
test "${BASH_VERSINFO[0]}" -gt 4 || {
  test "${BASH_VERSINFO[0]}" -eq 4 && test "${BASH_VERSINFO[1]}" -ge 1
}
]=]
  RESULT_VARIABLE supports_named_fds)
if(NOT supports_named_fds EQUAL 0)
  message(STATUS "Skipping Bash named-FD conformance: Bash 4.1 or newer is required")
  return()
endif()

# Keep the Shellsplit named-descriptor contract anchored to the executor that
# defines it. This does not execute parsed fixture data; it only verifies the
# small Bash semantics modelled by the graph. The hostile nested children prove
# why privileged startup and a frozen POSIX mode are required before submitted
# source is evaluated.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "${SHELLCLAVE_BASH}" -p -c [=[
set -e
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
test "$(type -t exec)" = builtin
if shopt -q varredir_close || shopt -q lastpipe || shopt -q expand_aliases;
then
  exit 1
fi
if set -o | grep -Eq '^monitor[[:space:]]+on$'; then
  exit 1
fi

# Bash privileged mode still honors a pre-existing POSIXLY_CORRECT. POSIX mode
# changes special-builtin assignment lifetime, so the launcher must remove it
# before startup and freeze the unset variable before submitted source runs.
env POSIXLY_CORRECT=1 "$BASH" -p -c '
  set -o | grep -Eq "^posix[[:space:]]+on$"
'
readonly POSIXLY_CORRECT
test -z "${POSIXLY_CORRECT+x}"
if "$BASH" -p -c 'readonly POSIXLY_CORRECT; POSIXLY_CORRECT=1' 2>/dev/null;
then
  exit 1
fi
"$BASH" -p -c '
  readonly POSIXLY_CORRECT
  set -o posix 2>/dev/null
  ! set -o | grep -Eq "^posix[[:space:]]+on$"
'
test -z "${POSIXLY_CORRECT+x}"
if set -o | grep -Eq '^posix[[:space:]]+on$'; then
  exit 1
fi

# Dynamic operands of declaration/export builtins and an attached `printf -v`
# target can construct POSIXLY_CORRECT at runtime. Shellsplit rejects these
# spellings at its source boundary; the protected launcher independently makes
# the variable readonly so an implementation bypass cannot change shell mode.
for writer in declare typeset export; do
  "$BASH" -c '
    target="POSIXLY_CORRECT=1"
    "$1" "$target"
    set -o | grep -Eq "^posix[[:space:]]+on$"
  ' bash "$writer"
done
# Quote removal does not hide a protected assignment target. Conversely, a
# quoted command substitution in a fixed-name value cannot change its target.
"$BASH" -c '
  unset POSIXLY_CORRECT
  export "POSIXLY_CORRECT=1"
  test "$POSIXLY_CORRECT" = 1
'
"$BASH" -c '
  unset POSIXLY_CORRECT
  export POSIXLY_CORRECT="1"
  test "$POSIXLY_CORRECT" = 1
'
"$BASH" -c '
  export VALUE="$(printf data)"
  test "$VALUE" = data
'
"$BASH" -c '
  target="POSIXLY_CORRECT=1"
  f() {
    local "$target"
    set -o | grep -Eq "^posix[[:space:]]+on$"
  }
  f
'
"$BASH" -c '
  target=POSIXLY_CORRECT
  printf -v"$target" enabled
  set -o | grep -Eq "^posix[[:space:]]+on$"
'
for protected in \
  'target="POSIXLY_CORRECT=1"; declare "$target"' \
  'target="POSIXLY_CORRECT=1"; export "$target"' \
  'target=POSIXLY_CORRECT; printf -v"$target" enabled'; do
  if "$BASH" -p -c "readonly POSIXLY_CORRECT; $protected" 2>/dev/null; then
    exit 1
  fi
done

printf 'shopt -s lastpipe\n' >"$tmpdir/bash-env"

# A normal noninteractive Bash imports both startup options and exported
# functions. Here the imported function shadows `exec`, so numeric descriptor
# setup cannot have the builtin semantics the graph models.
exec() { :; }
export -f exec
env BASH_ENV="$tmpdir/bash-env" BASHOPTS=lastpipe \
  SHELLOPTS=braceexpand:hashall:interactive-comments:monitor \
  "$BASH" -c '
    test "$(type -t exec)" = function
    exec 3>"$1"
    (printf unexpectedly >&3) 2>/dev/null || :
    test ! -s "$1"
    shopt -q lastpipe
    set -o | grep -Eq "^monitor[[:space:]]+on$"
  ' bash "$tmpdir/shadowed"

# `-p` ignores the same startup and function-import channels. Verify the
# builtin route survives before using the protected outer shell as the
# conformance baseline below.
env BASH_ENV="$tmpdir/bash-env" BASHOPTS=lastpipe \
  SHELLOPTS=braceexpand:hashall:interactive-comments:monitor \
  "$BASH" -p -c '
    set -e
    readonly POSIXLY_CORRECT
    test -z "${POSIXLY_CORRECT+x}"
    test "$(type -t exec)" = builtin
    if shopt -q varredir_close || shopt -q lastpipe || shopt -q expand_aliases;
    then
      exit 1
    fi
    if set -o | grep -Eq "^monitor[[:space:]]+on$"; then
      exit 1
    fi
    if set -o | grep -Eq "^posix[[:space:]]+on$"; then
      exit 1
    fi
    exec 3>"$1"
    printf protected >&3
    test "$(cat "$1")" = protected
  ' bash "$tmpdir/protected"
export -n -f exec
unset -f exec
test "$(type -t exec)" = builtin

: {fd}>"$tmpdir/default-lifetime"
printf first >&"$fd"
test "$(cat "$tmpdir/default-lifetime")" = first
exec {proof_fd}>"$tmpdir/quoted-value-route"
export OTHER="$(printf data)"
printf preserved >&"$proof_fd"
test "$(cat "$tmpdir/quoted-value-route")" = preserved

# A right-hand `&&` command runs only after the descriptor setup succeeds, so
# the binding is available within that success continuation. It remains a
# conditional setup for any later unconditional command, which Shellsplit
# deliberately does not promote into its persistent descriptor model.
exec {and_named}>"$tmpdir/and-named" && printf named >&"$and_named"
test "$(cat "$tmpdir/and-named")" = named
exec 3>"$tmpdir/and-numeric" && printf numeric >&3
test "$(cat "$tmpdir/and-numeric")" = numeric
: {and_ordinary}>"$tmpdir/and-ordinary" && printf ordinary >&"$and_ordinary"
test "$(cat "$tmpdir/and-ordinary")" = ordinary

# Physical line continuations are removed before Bash recognizes the brace
# parameter form. The graph must give this the same named-FD meaning as
# `>&${continued}`, rather than its legacy stdout-and-stderr output form.
exec {continued}>"$tmpdir/continued-braced-reference"
printf continued >&$\
{continued}
test "$(cat "$tmpdir/continued-braced-reference")" = continued

exec {shared}>"$tmpdir/inherited"
( printf child >&"$shared" )
printf parent >&"$shared"
test "$(cat "$tmpdir/inherited")" = childparent

# A command-bearing builtin's redirects expand before its variable mutation.
# Assignment-only commands are different: their assignment can determine the
# redirect operand itself. Keep both orderings anchored to Bash.
: >"$tmpdir/input"
"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  exec {fd}>"$1/output"
  unset fd >&$fd
  test -z "${fd+x}"
  exec {fd}>"$1/printf"
  printf -v fd changed >&$fd
  test "$fd" = changed
  exec {fd}<"$1/input"
  read fd <&$fd || test "$?" -eq 1
  test -z "$fd"
  exec {fd}>"$1/old-assignment"
  fd="$1/new-assignment" >&$fd
  test -e "$1/new-assignment"
' bash "$tmpdir"

# Redirect operands are not operands of unset or assignment builtins, even
# when their spelling resembles a descriptor variable or an assignment.
"$BASH" -p -c '
  set -e
  cd "$1"
  exec {fd}>"$1/redirect-operand"
  unset unrelated >&$fd
  unset unrelated >fd
  export OTHER=1 >fd=shadow
  printf retained >&$fd
  test "$(cat "$1/redirect-operand")" = retained
  test -e fd && test -e fd=shadow
' bash "$tmpdir"

{ printf brace-child >&"$brace"; } {brace}>"$tmpdir/brace-group"
printf brace-parent >&"$brace"
test "$(cat "$tmpdir/brace-group")" = brace-childbrace-parent

( printf subshell-child >&"$subshell" ) {subshell}>"$tmpdir/subshell-group"
test "$(cat "$tmpdir/subshell-group")" = subshell-child
test -z "${subshell-}"
if ( printf unexpectedly >&"$subshell" ) 2>/dev/null; then
  exit 1
fi

printf source | { :; } {piped}>"$tmpdir/pipeline-group"
test -z "${piped-}"
if ( printf unexpectedly >&"$piped" ) 2>/dev/null; then
  exit 1
fi

{ :; } {backgrounded}>"$tmpdir/background-group" &
wait
test -z "${backgrounded-}"
if ( printf unexpectedly >&"$backgrounded" ) 2>/dev/null; then
  exit 1
fi

# `lastpipe` makes the final noninteractive pipeline element run in this
# shell. That can promote its named descriptor allocation, so Shellsplit
# rejects explicit mutations of this option instead of modelling both modes.
shopt -s lastpipe
printf source | : {lastpipe}>"$tmpdir/lastpipe-group"
printf lastpipe >&"$lastpipe"
test "$(cat "$tmpdir/lastpipe-group")" = lastpipe
shopt -u lastpipe

# Noninteractive Bash reads BASH_ENV before the submitted command. A caller
# using ordinary Bash can therefore change named-FD scope before source
# validation sees any command text.
BASH_ENV="$tmpdir/bash-env" "$BASH" -c \
  'printf source | : {startup}>"$1"; printf startup >&"$startup"' \
  bash "$tmpdir/startup-group"
test "$(cat "$tmpdir/startup-group")" = startup

exec {closed}>"$tmpdir/closed"
exec {closed}>&-
if ( printf unexpectedly >&"$closed" ) 2>/dev/null; then
  exit 1
fi

# A readonly descriptor variable makes a later `{name}>...` allocation fail,
# but Bash retains the already-open descriptor value. Shellsplit rejects this
# source family instead of pretending the second target received later bytes.
exec {readonly_fd}>"$tmpdir/readonly-first"
readonly readonly_fd
if ( exec {readonly_fd}>"$tmpdir/readonly-second" ) 2>/dev/null; then
  exit 1
fi
printf retained >&"$readonly_fd"
test "$(cat "$tmpdir/readonly-first")" = retained

exec {declared_fd}>"$tmpdir/declare-first"
declare -r declared_fd
if ( exec {declared_fd}>"$tmpdir/declare-second" ) 2>/dev/null; then
  exit 1
fi
printf retained >&"$declared_fd"
test "$(cat "$tmpdir/declare-first")" = retained

exec {typed_fd}>"$tmpdir/typeset-first"
typeset -r typed_fd
if ( exec {typed_fd}>"$tmpdir/typeset-second" ) 2>/dev/null; then
  exit 1
fi
printf retained >&"$typed_fd"
test "$(cat "$tmpdir/typeset-first")" = retained

printf legacy >&"$tmpdir/legacy"
test "$(cat "$tmpdir/legacy")" = legacy
]=]
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "Bash named-FD conformance check failed (${result}): ${error}${output}")
endif()
