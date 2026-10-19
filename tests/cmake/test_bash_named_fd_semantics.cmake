cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing Bash executable")
endif()

# This fixture receives hostile startup state through CTest. Clear it for
# neutral helper launches; the nested probes below pass it explicitly to show
# why the protected launcher has to establish every modeled invariant.
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
unset(ENV{BASH_COMPAT})
unset(ENV{BASH_XTRACEFD})

# Fixed, trusted literal spellings only; these probes never execute corpus or
# fuzz inputs. Compare ordinary and compound setup failures and prove that
# later redirects/allocations cannot run after quote removal yields no filename.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "${SHELLCLAVE_BASH}" -p -c [=[
set -e
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
for empty in "''" '""' "$''" "''\"\""; do
  for redirect in '>' '<' '>>' '<>' '&>' '&>>' '3>' '{fd}>' '{fd}<>'; do
    unset fd
    if eval "true $redirect$empty >\"$tmpdir/later\"" 2>/dev/null; then exit 1; fi
    test ! -e "$tmpdir/later"
    test -z "${fd+x}"
  done
  for prefix in 'true' '{ true; }' '(true)' '! true' '! { true; }' '! (true)'; do
    if eval "$prefix >$empty" 2>/dev/null; then
      test "$prefix" = '! true'
    else
      test "$prefix" != '! true'
    fi
  done
  exec {kept}>"$tmpdir/kept"
  if eval "true >$empty {later}>\"$tmpdir/later\"" 2>/dev/null; then exit 1; fi
  test -z "${later+x}"
  printf retained >&"$kept"
  exec {kept}>&-
  test "$(<"$tmpdir/kept")" = retained
done
test "$(echo "$(<"")" tail 2>/dev/null)" = ' tail'
# Substitution status is distinct from its captured bytes and from failure of
# the enclosing command's setup. Fixed expressions only, never fuzz inputs.
check_status() {
  if (eval "$2") 2>/dev/null; then actual=0; else actual=1; fi
  if test "$actual" != "$1"; then
    printf 'status mismatch: expected=%s actual=%s source=%s\n' "$1" "$actual" "$2" >&2
    return 1
  fi
}
check_status 1 'X="$(<"")"'
check_status 0 'X="$(<"")$(true)"'
check_status 1 'X="$(true)$(<"")"'
check_status 0 'X="$(false)" Y="$(true)"'
check_status 1 'X="$(true)" Y="$(false)"'
check_status 0 'X="$(false)" <<<"$(true)"'
check_status 0 '<<<"$(true)" X="$(false)"'
check_status 0 'X="$(true)" <<<"$(false)"'
check_status 0 'X="$(false)" <<<plain'
check_status 1 'X="$(false)" Y=<(true)'
check_status 0 'X=<(false)'
check_status 0 'true "$(<"")"'
check_status 0 'X="$(exit 0)"'
check_status 1 'X="$(exit 7)"'
check_status 0 'unset MAYBE; X="${MAYBE:+$(false)}"'
check_status 1 'MAYBE=yes; X="${MAYBE:+$(false)}"'
# Pattern removal skips its operand for both unset and null values. Pattern
# replacement/case conversion skip it for unset values, but not null ones.
for operand in '#$(false)' '##$(false)' '%$(false)' '%%$(false)' \
               '/$(false)/x' '//$(false)/x' '/#$(false)/x' '/%$(false)/x' \
               '/x/$(false)' '//x/$(false)' '^$(false)' '^^$(false)' \
               ',$(false)' ',,$(false)'; do
  expression='X="${value'"$operand"'}"'
  check_status 0 "unset value; $expression"
  check_status 1 "value=x; $expression"
  case "$operand" in
    \#*|%*) check_status 0 "value=; $expression";;
    *) check_status 1 "value=; $expression";;
  esac
done
check_status 1 'unset value; X="$(false)${value#$(true)}"'
check_status 0 'value=x; X="$(false)${value#$(true)}"'
check_status 0 'unset value; X="${value#$(false)}$(true)"'
check_status 1 'unset value; X="${value#$(true)}$(false)"'
(
  HOME=/example
  set -- x=~ x+=~ x=y:~ x=~/path x=one\:~ x=""~ "x"=~ x\=~ 1=~ x=~""
  test "$1" = x=/example && test "$2" = x+=/example
  test "$3" = x=y:/example && test "$4" = x=/example/path
  test "$5" = 'x=one:~' && test "$6" = 'x=~' && test "$7" = 'x=~'
  test "$8" = 'x=~' && test "$9" = '1=~' && test "${10}" = 'x=~'
  cd "$tmpdir"
  HOME=expanded
  : >x=~
  test -f x=expanded
  printf payload >x=~
  test "$(<x=~)" = payload
  test "$(cat <<<x=~)" = 'x=~'
  HOME=%n
  fd=10
  printf x=~ fd >/dev/null
  test "$fd" = 2
)
# Quoting anywhere in a tilde prefix disables expansion; quoting after the
# slash does not. Escaped line endings preserve the logical prefix position.
(
  set -- ~""/child ~"/child" "~"/child \~/child ~\/child ~\
""/child ~\
/child \
~/child ~/"child" ~\
$''/child ./~""/child
  test "$1" = '~/child' && test "$2" = '~/child'
  test "$3" = '~/child' && test "$4" = '~/child'
  test "$5" = '~/child' && test "$6" = '~/child'
  test "$7" = "$HOME/child" && test "$8" = "$HOME/child"
  test "$9" = "$HOME/child" && test "${10}" = '~/child'
  test "${11}" = './~/child'
)
# An argv-less command selects its setup child from the complete redirect
# list, not from document kind, direction, or whether an FD actually changes.
for redirect in '</dev/null' '0>/dev/null' '<>/dev/null' '0<&0' '0>&0' \
                '0<&-' '0>&-' '{fd}>/dev/null' '{fd}</dev/null' \
                '{fd}<<<plain' '< <(true)' '0> >(true)'; do
  check_status 0 "X=\"\$(false)\" $redirect"
done
for redirect in '3</dev/null' '>/dev/null' '3<>/dev/null' '3<&0' '3>&-' \
                '3<<<plain' '3< <(true)' '> >(true)'; do
  check_status 1 "X=\"\$(false)\" $redirect"
done
check_status 0 '<<<plain >"$(printf /dev/null; false)"'
check_status 0 '>"$(printf /dev/null; false)" <<<plain'
check_status 1 '3<<<plain >"$(printf /dev/null; false)"'
check_status 1 '3<<<"$(false)" X="$(true)"'
check_status 0 'X="$(false)" 3<<<"$(true)"'
check_status 1 'X="$(false)" 9>&- 0<&9'
check_status 1 'X="$(false)" <""'
check_status 1 '! X="$(false)" 0>&0'
check_status 0 '! X="$(false)" 3<<<plain'
check_status 0 'time X="$(false)" 0>&0'
check_status 0 'X="$(Y="$(false)" 0>&0)"'
test "$("$BASH" -p -c 'unset v; 3<<<"${v:?}" 0>&0; printf reached' 2>/dev/null)" = reached
test "$("$BASH" -p -c 'unset v; 3<<<"${v:?}" 0<<<plain; printf reached' 2>/dev/null)" = reached
test "$("$BASH" -p -c 'unset v; 3<<<"${v:?}" {fd}<<<plain; printf reached' 2>/dev/null)" = reached
test -z "$("$BASH" -p -c 'unset v; X="${v:?}" 0>&0; printf impossible' 2>/dev/null)"
test -z "$("$BASH" -p -c 'unset v; : <<<"${v:?}"; printf impossible' 2>/dev/null)"
# Assignments commit before the setup child; its named binding never escapes.
unset fd
X=kept {fd}>/dev/null
test "$X" = kept && test -z "${fd+x}"
(exec {fd}>/dev/null
 original=$fd
 X=kept {fd}>/dev/null
 test "$fd" = "$original"
 IFS=0123456789 0>&0
 if printf impossible >&$fd 2>/dev/null; then exit 1; fi
 printf retained >&"$fd")
test "$(X="$(<"")" && printf impossible; printf reached)" = reached
]=]
  RESULT_VARIABLE empty_path_status
  ERROR_VARIABLE empty_path_error)
if(NOT empty_path_status EQUAL 0)
  message(FATAL_ERROR "Bash empty pathname setup contract failed: ${empty_path_error}")
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
unset BASH_COMPAT BASH_XTRACEFD
readonly BASH_COMPAT BASH_XTRACEFD

# Empty redirect targets fail before allocating a named descriptor. Redirects
# are processed left-to-right: later opens do not run, but an earlier named
# allocation remains available even when the containing command fails setup.
$BASH -p -c '
  target=
  if true {fd}>"$target"; then exit 1; fi
  test -z "${fd+x}"
  if true >"$target" {later}>"$1/later"; then exit 1; fi
  test -z "${later+x}"
  test ! -e "$1/later"
  if { printf unexpected; } >"$target" {later}>"$1/group-later";
  then exit 1; fi
  test ! -e "$1/group-later"
  if exec {kept}>"$1/kept" >"$target"; then exit 1; fi
  printf retained >&"$kept"
  test "$(cat "$1/kept")" = retained
  if true {both}<>"$target"; then exit 1; fi
  test -z "${both+x}"
' bash "$tmpdir" 2>/dev/null

# Declaration builtins can promote a same-name command prefix into the current
# shell. Export -n and declaration queries do not. This distinction controls
# whether a retained named-descriptor variable remains usable afterwards.
test "$($BASH -p -c '
  exec {fd}>&1
  fd=99 export -n fd
  printf retained >&$fd
')" = retained
for writer in export command builtin declare typeset; do
  output=$($BASH -p -c '
    exec {fd}>&1
    case "$1" in
      export) fd=99 export fd ;;
      command) fd=99 command export fd ;;
      builtin) fd=99 builtin export fd ;;
      declare) fd=99 declare -x fd ;;
      typeset) fd=99 typeset +x -x fd ;;
    esac
    printf unexpected >&$fd
  ' bash "$writer" 2>/dev/null) && exit 1
  test -z "$output"
done
test "$($BASH -p -c '
  exec {fd}>&1
  fd=99 declare -p -x fd >/dev/null
  printf retained >&$fd
')" = retained

# BASH_XTRACEFD owns and closes its descriptor when unset. BASH_COMPAT can
# change compatibility semantics. Both therefore belong to the launcher's
# frozen execution contract rather than the submitted source's mutable state.
$BASH -p -c '
  exec {fd}>"$1/xtrace"
  BASH_XTRACEFD=$fd
  unset BASH_XTRACEFD
  if printf unexpected >&$fd 2>/dev/null; then exit 1; fi
' bash "$tmpdir"
test ! -s "$tmpdir/xtrace"
if $BASH -p -c '
  unset BASH_XTRACEFD BASH_COMPAT
  readonly BASH_XTRACEFD BASH_COMPAT
  BASH_XTRACEFD=9
' 2>/dev/null; then
  exit 1
fi
if $BASH -p -c '
  unset BASH_XTRACEFD BASH_COMPAT
  readonly BASH_XTRACEFD BASH_COMPAT
  BASH_COMPAT=42
' 2>/dev/null; then
  exit 1
fi

# Without execfail, both successful replacement and replacement failure are
# terminal to this noninteractive shell. Enabling execfail demonstrates the
# option-state mutation which Shellsplit rejects at the source boundary.
test "$($BASH -p -c '
  exec -z 9>/dev/null
  if printf unexpected >&9; then exit 1; fi
  printf returned
' 2>/dev/null)" = returned
test "$($BASH -p -c '
  exec -a 9>/dev/null
  if printf unexpected >&9; then exit 1; fi
  printf returned
' 2>/dev/null)" = returned
test "$($BASH -p -c '
  value=; exec $value 9>/dev/null
  printf retained >&9
  printf returned
')" = returned

# A separate quoted -a operand preserves one alias even when empty. An
# attached empty value instead makes -a consume the following word.
for label in '' alternate; do
  test "$($BASH -p -c '
    exec -a "$1" "$2" -p -c "printf replacement"
    printf unexpected
  ' bash "$label" "$BASH")" = replacement
done
test "$($BASH -p -c '
  value=; exec -a"$value" "$1"
  printf descriptor_only
' bash "$BASH")" = descriptor_only
test "$($BASH -p -c '
  value=; exec -a"prefix$value" "$1" -p -c "printf replacement"
  printf unexpected
' bash "$BASH")" = replacement
output=$($BASH -p -c '
  value=; exec -- "$value"
  printf unexpected
' 2>/dev/null) && exit 1
test -z "$output"
test "$($BASH -p -c '
  value=; exec -- $value
  printf descriptor_only
')" = descriptor_only
test "$($BASH -p -c '
  exec -- "$@"; printf descriptor_only
')" = descriptor_only
test "$($BASH -p -c '
  executable=$1; shift
  exec -- "$@" "$executable" -p -c "printf replacement"
  printf unexpected
' bash "$BASH")" = replacement
test "$($BASH -p -c '
  exec {_}>&1
  printf "%s" "$_"
')" = exec
test "$($BASH -p -c '
  unset _; exec {_}>&1
  printf "%s" "$_"
')" = exec

# Temporary read/unset/declaration writes are restored, whereas printf,
# getopts and explicit export assignments write the current shell binding.
for writer in read reply unset declare typeset dynamic_read dynamic_unset; do
  test "$($BASH -p -c '
    exec {fd}>&1
    exec {REPLY}>&1
    target=fd
    case "$1" in
      read) fd=99 read fd <<<value ;;
      reply) REPLY=99 read <<<value; fd=$REPLY ;;
      unset) fd=99 unset fd ;;
      declare) fd=99 declare f"d"=20 ;;
      typeset) fd=99 typeset "fd=20" ;;
      dynamic_read) fd=99 read "$target" <<<value ;;
      dynamic_unset) fd=99 unset "$target" ;;
    esac
    printf retained >&$fd
  ' bash "$writer")" = retained
done
for writer in printf getopts export_unexport declaration_promote; do
  test "$($BASH -p -c '
    fd=10
    case "$1" in
      printf) fd=99 printf -v fd value ;;
      getopts) fd=99 getopts a fd -a ;;
      export_unexport) fd=99 export -n fd=20 ;;
      declaration_promote) fd=99 declare -x +x fd=20 ;;
    esac
    printf "%s" "$fd"
  ' bash "$writer")" != 10
done
test "$($BASH -p -c '
  exec {fd}>&1
  fd=99 read fd {fd}>&1 <<<value
  printf retained >&$fd
')" = retained

# getopts owns only its explicit destination and OPTIND/OPTARG. Its redirects
# use the incoming binding; unrelated temporary prefixes and descriptors are
# preserved. Missing operands and invalid builtin options precede all writes.
for shape in ordinary wrapper prefix missing separator optstring invalid_option invalid_target readonly_target; do
  test "$($BASH -p -c '
    exec {fd}>&1
    case "$1" in
      ordinary) getopts a opt -a >&$fd ;;
      wrapper) command builtin getopts -- a opt -a ;;
      prefix) fd=99 getopts a opt -a ;;
      missing) getopts 2>/dev/null || : ;;
      separator) getopts -- 2>/dev/null || : ;;
      optstring) getopts -- a 2>/dev/null || : ;;
      invalid_option) getopts -x fd -a 2>/dev/null || : ;;
      invalid_target) getopts a bad-name -a 2>/dev/null || : ;;
      readonly_target) getopts a UID -a 2>/dev/null || : ;;
    esac
    printf retained >&$fd
  ' bash "$shape")" = retained
done
for shape in missing optstring invalid_option invalid_target readonly_target temporary_prefix; do
  "$BASH" -p -c '
    OPTIND=7 OPTARG=sentinel
    case "$1" in
      missing) getopts 2>/dev/null || : ;;
      optstring) getopts a 2>/dev/null || : ;;
      invalid_option) getopts -x opt -a 2>/dev/null || : ;;
      invalid_target) OPTIND=1 getopts a bad-name -a 2>/dev/null || : ;;
      readonly_target) OPTIND=1 getopts a UID -a 2>/dev/null || : ;;
      temporary_prefix) OPTIND=1 OPTARG=99 getopts a: opt -a value ;;
    esac
    case "$1" in
      missing|optstring|invalid_option)
        test "$OPTIND:$OPTARG" = 7:sentinel ;;
      invalid_target|readonly_target)
        test "$OPTIND:${OPTARG-unset}" = 2:unset ;;
      temporary_prefix)
        test "$OPTIND:$OPTARG:$opt" = 3:value:a ;;
    esac
  ' bash "$shape"
done
test "$($BASH -p -c '
  exec {fd}>&1
  exec 3>&$fd
  getopts a fd -a
  printf retained >&3
')" = retained
test "$($BASH -p -c '
  getopts a opt -a {fd}>&1
  printf retained >&$fd
')" = retained

# cd consumes duplication operands as redirects, not pathname arguments.
# Verify both attached and separated syntax before/after the pathname and
# through the wrapper/timing forms supported by Shellsplit.
for shape in attached_before attached_after spaced_before spaced_after named wrapper timing; do
  "$BASH" -p -c '
    cd "$2"
    exec {fd}>&1
    case "$1" in
      attached_before) cd 2>&1 / ;;
      attached_after) cd / 2>&1 ;;
      spaced_before) cd 2>& 1 / ;;
      spaced_after) cd / 2>& 1 ;;
      named) cd / 2>&"$fd" ;;
      wrapper) command builtin cd / 2>&1 ;;
      timing) time -p cd / 2>&1 ;;
    esac
    test "$PWD" = /
  ' bash "$shape" "$tmpdir"
done

# Successful cd replaces PWD and OLDPWD, including temporary same-name
# prefixes. A directory/setup failure or an isolated/skipped cd does not.
for shape in ordinary wrapper timing pwd_prefix oldpwd_prefix; do
  "$BASH" -p -c '
    exec {PWD}>/dev/null
    exec {OLDPWD}>/dev/null
    before=$PWD
    case "$1" in
      ordinary) cd / ;;
      wrapper) command builtin cd / ;;
      timing) time -p cd / ;;
      pwd_prefix) PWD=temp cd / ;;
      oldpwd_prefix) OLDPWD=temp cd / ;;
    esac
    test "$PWD" = /
    if test "$1" = pwd_prefix; then
      test "$OLDPWD" = temp
    else
      test "$OLDPWD" = "$before"
    fi
  ' bash "$shape"
done
for shape in invalid_option extra_operand empty_operand empty_after_separator help missing_directory failed_redirect failed_group subshell skipped_and skipped_or; do
  "$BASH" -p -c '
    exec {PWD}>/dev/null
    exec {OLDPWD}>/dev/null
    before=$PWD:$OLDPWD
    case "$1" in
      invalid_option) cd --invalid 2>/dev/null || : ;;
      extra_operand) cd / / 2>/dev/null || : ;;
      empty_operand) cd "" 2>/dev/null || : ;;
      empty_after_separator) cd -- "" 2>/dev/null || : ;;
      help) cd --help >/dev/null || : ;;
      missing_directory) cd /definitely/missing 2>/dev/null || : ;;
      failed_redirect) exec 3>&-; cd / 2>/dev/null 4>&3 || : ;;
      failed_group) { cd /; } 2>/dev/null 4>&- 5>&4 || : ;;
      subshell) (cd /) ;;
      skipped_and) false && cd / ;;
      skipped_or) true || cd / ;;
    esac
    test "$PWD:$OLDPWD" = "$before"
  ' bash "$shape"
done
test "$($BASH -p -c '
  exec {PWD}>&1
  exec 3>&$PWD
  cd / >&$PWD
  printf retained >&3
')" = retained
test "$($BASH -p -c '
  cd / {fd}>&1
  printf retained >&$fd
')" = retained
test "$($BASH -p -c '
  cd --invalid 2>/dev/null {PWD}>&1 || :
  printf retained >&$PWD
')" = retained
test "$($BASH -p -c '
  cd /definitely/missing 2>/dev/null {PWD}>&1 || printf retained >&$PWD
')" = retained

output=$($BASH -p -c 'exec /definitely/missing; printf unexpected' 2>/dev/null) && exit 1
test -z "$output"
output=$($BASH -p -c 'exec /definitely/missing || printf unexpected' 2>/dev/null) && exit 1
test -z "$output"
test "$($BASH -p -c 'shopt -s execfail; exec /definitely/missing || printf recovered' 2>/dev/null)" = recovered

# Assignment RHS snapshots use the allocation before their own commit, while
# an earlier assignment-only commit is visible to a later RHS. Executable
# prefixes expand against the incoming allocation instead.
test "$("$BASH" -p -c 'exec {fd}>&1; fd=$(printf rhs >&$fd)')" = rhs
test "$("$BASH" -p -c 'exec {fd}>&1; X=$(printf earlier >&$fd) fd=7')" = earlier
test "$("$BASH" -p -c 'exec {fd}>&1; fd=7 X=$(printf skipped >&$fd)' 2>/dev/null)" = ''
test "$("$BASH" -p -c 'exec {fd}>&1; fd=7 X=$(printf prefix >&$fd) :')" = prefix
readonly_rhs=$("$BASH" -p -c 'exec {fd}>&1; fd=$(printf rhs >&$fd) UID=0' 2>/dev/null) && exit 1
test "$readonly_rhs" = rhs

# A skipped pipeline does not launch later stages. A readonly abort suppresses
# redirect operand expansion within the same input unit, but a root newline
# permits the following input unit to execute.
test "$("$BASH" -p -c 'false && true | printf skipped')" = ''
test "$("$BASH" -p -c 'false && true | { printf skipped; } || printf recovered')" = recovered
aborted=$("$BASH" -p -c 'UID=0; : >"$(printf unexpected >&2; printf /dev/null)"' 2>&1) && exit 1
case "$aborted" in *unexpected*) exit 1;; esac
test "$("$BASH" -p -c 'UID=0
printf recovered' 2>/dev/null)" = recovered

# Descriptor closes are complete tokens even without following whitespace.
# The adjacent named document redirect allocates a fresh readable descriptor.
test "$(exec {fd}>/dev/null; exec {fd}>&-{out}<<<x; cat <&$out)" = x
test "$(exec 9>/dev/null; exec 9>&-{out}<<EOF; cat <&$out
x
EOF
)" = x
test "$(time (cat <<<body) 2>/dev/null)" = body
test "$(time (cat <<<'a)b') 2>/dev/null)" = 'a)b'

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

# Named variables retain numbers when a temporary close's undo restores the
# underlying slot. A second allocation consumes a different slot, even when
# it reassigns the same variable. Do not assume its exact runtime number.
"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  exec 10>"$1/base"
  true 10>&- {a}>"$1/one" {b}>"$1/two"
  test "$a" -eq 10 && test "$b" -gt 10
  printf first >&$a
  printf second >&$b
  test "$(cat "$1/base")" = first
  test ! -s "$1/one"
  test "$(cat "$1/two")" = second
  true 10>&- {a}>"$1/one" {a}>"$1/two"
  printf last >&$a
  test "$(cat "$1/two")" = last
' bash "$tmpdir"

# Earlier variable assignments survive failed setup, but numeric undo still
# runs. This applies to exec too; a failed setup is not a committed exec.
for setup in true exec; do
  "$BASH" -p -c '
    set -e
    readonly POSIXLY_CORRECT
    exec 9>&-
    exec 10>"$1/base"
    "$2" 10>&- {a}>"$1/one" 4>&9 || printf recovered >&$a
    test "$(cat "$1/base")" = recovered
    test ! -s "$1/one"
  ' bash "$tmpdir" "$setup"
done

# File opens precede numeric undo allocation. With every low fd occupied,
# the temporary open takes 10, stdin is saved in 11, and varredir retains 12.
"$BASH" -p -c '
  set -e
  exec 3>/dev/null 4>/dev/null 5>/dev/null 6>/dev/null 7>/dev/null
  exec 8>/dev/null 9>/dev/null 10>&- 11>&- 12>&-
  true 0>"$1/zero" {a}>"$1/one"
  test "$a" -eq 12
  exec 11>"$1/eleven" 12>"$1/twelve"
  printf ordered >&$a
  test "$(cat "$1/twelve")" = ordered
  test ! -s "$1/one" && test ! -s "$1/eleven"
' bash "$tmpdir"

# A nested command must acquire its own undo frame, even when the surrounding
# compound already saved stdin. Both saves occupy slots during allocation.
"$BASH" -p -c '
  set -e
  exec 10>&- 11>&- 12>&-
  { true 0<&- {a}>"$1/one"; test "$a" -eq 12; } 0>"$1/group"
  exec 12>"$1/twelve"
  printf nested >&$a
  test "$(cat "$1/twelve")" = nested
  test ! -s "$1/one"
' bash "$tmpdir"

# Group-body routes and post-group routes differ. Nested captures inherit the
# restored slot; a later reallocation of the variable must not be restored as
# if it still named the group's original allocation.
"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  exec 10>"$1/base"
  { printf body >&$a; } 10>&- {a}>"$1/one"
  echo "$(printf after >&$a)" >/dev/null
  test "$(cat "$1/one")" = body
  test "$(cat "$1/base")" = after
  { true {a}>"$1/two"; } 10>&- {a}>"$1/one"
  printf rebound >&$a
  test "$(cat "$1/two")" = rebound
  exec {a}>"$1/one"
  { true; } {a}>&-
  printf restored >&$a
  test "$(cat "$1/one")" = restored
' bash "$tmpdir"

# A numeric self-duplication is a no-op even for a closed descriptor. It must
# not create an undo frame that closes the named allocation at cleanup.
"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  exec 10>&-
  true 10>&10 {a}>"$1/one"
  test "$a" -eq 10
  printf selfdup >&$a
  test "$(cat "$1/one")" = selfdup
  exec 9>&-
  exec 10>&-
  exec 1>"$1/one"
  true {a}>&1 4>&9 || true
  test "$a" -eq 10
  true {b}>"$1/two"
  test "$b" -gt 10
  printf second >&$b
  test "$(cat "$1/two")" = second
' bash "$tmpdir"

# A duplicate copies the active route, but its allocated number can itself
# belong to the numeric undo frame. Exercise both low-descriptor occupancies.
"$BASH" -p -c '
  set -e
  exec 3>/dev/null 4>/dev/null 5>/dev/null 6>/dev/null 7>/dev/null
  exec 8>/dev/null 9>/dev/null 10>"$1/base"
  true 10>&- {a}>"$1/one" {b}>&$a
  test "$a" -eq 12 && test "$b" -eq 10
  printf restored >&$b
  test "$(cat "$1/base")" = restored
  test ! -s "$1/one"
' bash "$tmpdir"

# With a free low descriptor, the duplicate uses a different number and keeps
# the copied route through cleanup of the source number.
"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  exec 10>"$1/base"
  true 10>&- {a}>"$1/one" {b}>&$a
  printf copy >&$b
  test "$(cat "$1/one")" = copy
  exec 10>"$1/two"
  printf overwrite >&$a
  test "$(cat "$1/two")" = overwrite
  TIMEFORMAT=report
  true 10>&- {a}>"$1/one" {b}>"$1/two"
  time exec 2>&$b
  test "$(cat "$1/two")" = report
' bash "$tmpdir"

"$BASH" -p -c '
  set -e
  readonly POSIXLY_CORRECT
  printf readable >"$1/base"
  printf fresh >"$1/one"
  exec 10<"$1/base"
  true 10<&- {a}<"$1/one"
  test "$(cat <&$a)" = readable
  exec 10<>"$1/base"
  { true; } 10>&- {a}<>"$1/one"
  test "$(cat <&$a)" = readable
' bash "$tmpdir"

# Integer attributes make both declarations and later ordinary builtin writes
# evaluate arithmetic, including assignments to other variables. These fixed
# harmless scalar probes anchor why attribute installation is unsupported.
"$BASH" -p -c '
  set -e
  route=before
  declare -i scratch="route=2"
  test "$route" = 2 && test "$scratch" = 2
  route=before
  read scratch <<<"route=12"
  test "$route" = 12 && test "$scratch" = 12
  route=before
  printf -v scratch %s "route=7"
  test "$route" = 7 && test "$scratch" = 7
  route=before
  declare +i scratch
  declare -i -p route >/dev/null
  test "$route" = before
  declare -i +i plain="route=3"
  test "$route" = before && test "$plain" = route=3
  declare +i -i other="route=4"
  test "$route" = before && test "$other" = route=4
  if declare -i -Z route 2>/dev/null; then exit 1; fi
  test "$route" = before
  route=before
  declare SECONDS="route=6"
  test "$route" = 6
  route=before
  declare +i SECONDS="route=7"
  test "$route" = before
  declare -p SECONDS >/dev/null
  test "$route" = before
  read OPTIND <<<"route=8"
  test "$route" = 8
  route=before
  printf -v RANDOM %s "route=9"
  test "$route" = 9
  route=before
  printf -v SECONDS %s "route=10"
  test "$route" = 10
  route=before
  printf "%n" OPTIND
  test "$route" = before
'

# Bare integer assignments evaluate arithmetic, but plain command prefixes
# are temporary. Append prefixes still evaluate their arithmetic RHS.
"$BASH" -p -c '
  set -e
  route=before
  OPTIND="route=2"
  test "$route" = 2
  route=before
  OPTIND="route=3" >/dev/null
  test "$route" = 3
  route=before
  OPTIND="route=4" printf ""
  test "$route" = before
  OPTIND+="route=5" printf ""
  test "$route" = 5
  exec {OPTIND}>/dev/null
  printf harmless >&$OPTIND
  exec {OPTIND}>&-
  exec {BASH_COMMAND}>/dev/null
  test "${BASH_COMMAND%% *}" = test
  if "$BASH" -p -c "exec {UID}>/dev/null" 2>/dev/null; then exit 1; fi
'

# %n consumes a scalar target in every format iteration, independently of -v.
# Escaped percent signs, date formats, errors and %b termination must not shift
# that target or manufacture writes to unconsumed operands.
"$BASH" -p -c '
  set +e
  fd=before
  read UID fd <<<"one two" 2>/dev/null; status=$?
  test "$status" = 2 && test "$fd" = before || exit 1
  read EUID fd <<<"one two" 2>/dev/null; status=$?
  test "$status" = 2 && test "$fd" = before || exit 1
  other=before
  read other UID fd <<<"one two three" 2>/dev/null; status=$?
  test "$status" = 2 && test "$other" = one && test "$fd" = before || exit 1
  read fd UID <<<"one two" 2>/dev/null; status=$?
  test "$status" = 1 && test "$fd" = one || exit 1
  fd=before
  declare UID=1 fd=2 2>/dev/null; status=$?
  test "$status" = 1 && test "$fd" = 2 || exit 1
  fd=before
  printf "%n%n" UID fd 2>/dev/null; status=$?
  test "$status" = 0 && test "$fd" = 0 || exit 1
  fd=before
  printf -v UID "%n" fd 2>/dev/null; status=$?
  test "$status" = 1 && test "$fd" = 0 || exit 1
'

"$BASH" -p -c '
  set -e
  first=before second=before
  printf -v rendered "abc%n" first
  test "$first" = 3 && test "$rendered" = abc
  printf -v rendered "%s%n" x first yy second
  test "$first" = 1 && test "$second" = 2
  printf -v rendered "%*.*s%n" 8 2 value first
  test "$first" = 8
  printf -v rendered "%C%S%n" x value first
  test "$first" = 6
  first=before
  printf -v rendered "%%n%s" first
  test "$first" = before && test "$rendered" = %nfirst
  printf -v rendered "\\x25n%s" first
  test "$first" = before && test "$rendered" = %nfirst
  printf -v rendered "%(%n)T%s" 0 first
  test "$first" = before
  printf -v rendered "\\%n" first
  test "$first" = 1 && test "$rendered" = "\\"
  first=before
  printf -v rendered "\\%%n" first
  test "$first" = before && test "$rendered" = "\\%n"
  printf -v rendered "%n%n" "" first
  test "$first" = 0
  first=before
  if printf -v rendered "%n%n" bad-name first 2>/dev/null; then exit 1; fi
  test "$first" = before
  if printf -v rendered "%J%n" first 2>/dev/null; then exit 1; fi
  test "$first" = before
  if printf -v rendered "%n%J%n" second first 2>/dev/null; then exit 1; fi
  test "$first" = before && test "$second" = 0
  printf -v rendered "%b%n" "\\c" first
  test "$first" = before && test -z "$rendered"
  printf -v rendered "%b%n" "\\\\c" first
  test "$first" = 2 && test "$rendered" = "\\c"
  first=before
  printf -v rendered "%s%n" value
  test "$first" = before
'

# A %b data expansion can stop before %n writes, including format reuse.
# This state-controlling operand cannot be expanded independently of the
# descriptor-mutation schedule. Ordinary %s data has no such stop effect.
"$BASH" -p -c '
  set -e
  exec {fd}>"$1/printf-escape-control"
  original=$fd
  value="\\c"
  printf "%b%n" "$value" fd
  test "$fd" = "$original"
  printf retained >&"$fd"
  target=before
  printf "%n%b" other "$value" target literal
  test "$other" = 0 && test "$target" = before
  printf "%s%n" "$value" target >/dev/null
  test "$target" = 2
' bash "$tmpdir"
test "$(cat "$tmpdir/printf-escape-control")" = retained

# ANSI-C NULs terminate their Bash word fragment. A canonical binary target
# cannot be treated as a proved invalid scalar name that preserves this route.
binary_target=before
printf -v rendered '%n' $'binary_target\0suffix'
test "$binary_target" = 0

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

# A raw close marker completes its redirection even without whitespace before
# the next allocator. A dash inside an ordinary word does not have this role.
exec {adjacent}>"$tmpdir/adjacent-first"
exec {adjacent}>&-{adjacent_out}>"$tmpdir/adjacent-out"
printf adjacent >&"$adjacent_out"
test "$(cat "$tmpdir/adjacent-out")" = adjacent
exec {adjacent_out}>&-
printf input >"$tmpdir/adjacent-input"
exec 9<"$tmpdir/adjacent-input"
exec 9<&-{adjacent_in}<"$tmpdir/adjacent-input"
test "$(cat <&"$adjacent_in")" = input
exec {adjacent_in}<&-

# Redirections execute left to right. A known-bad duplication prevents every
# later redirect and the command body from running.
exec 3>"$tmpdir/setup-failure-base"
exec 3>&- 4>&3 2>"$tmpdir/setup-failure-late" &&
  printf unexpected >"$tmpdir/setup-failure-body"
test ! -e "$tmpdir/setup-failure-late"
test ! -e "$tmpdir/setup-failure-body"

exec 3>&-
true >"$tmpdir/setup-before" 4>&3 >"$tmpdir/setup-after" &&
  printf unexpected >"$tmpdir/setup-after-body"
test -e "$tmpdir/setup-before"
test ! -e "$tmpdir/setup-after"
test ! -e "$tmpdir/setup-after-body"

exec 3>&-
true "$(printf early >"$tmpdir/setup-early")" 4>&3 \
  >"$(printf late >"$tmpdir/setup-late"; printf path)" &&
  printf unexpected >"$tmpdir/setup-successor"
test -e "$tmpdir/setup-early"
test ! -e "$tmpdir/setup-late"
test ! -e "$tmpdir/setup-successor"

# Bash saves command-local descriptor changes before applying redirects. A
# named allocation can reuse a just-closed slot; cleanup then restores the old
# route over that allocation while leaving the variable's numeric value set.
exec {reused}>"$tmpdir/reused-base"
true {reused}>&- {reused}>"$tmpdir/reused-fresh" &&
  printf reused >&"$reused"
test "$(cat "$tmpdir/reused-base")" = reused
test ! -s "$tmpdir/reused-fresh"

exec {old_slot}>"$tmpdir/reused-other-base"
true {old_slot}>&- {new_slot}>"$tmpdir/reused-other-fresh" &&
  printf other >&"$new_slot"
test "$old_slot" = "$new_slot"
test "$(cat "$tmpdir/reused-other-base")" = other
test ! -s "$tmpdir/reused-other-fresh"

exec 10>"$tmpdir/reused-numeric-base"
true 10>&- {numeric_slot}>"$tmpdir/reused-numeric-fresh" &&
  printf numeric >&"$numeric_slot"
test "$numeric_slot" = 10
test "$(cat "$tmpdir/reused-numeric-base")" = numeric
test ! -s "$tmpdir/reused-numeric-fresh"

# Closing a binding later in the same redirect list restores the route reached
# immediately before that close, not the variable's command-entry route.
exec {same_list}>"$tmpdir/same-list-base"
true {same_list}>"$tmpdir/same-list-fresh" {same_list}>&- &&
  printf same-list >&"$same_list"
test ! -s "$tmpdir/same-list-base"
test "$(cat "$tmpdir/same-list-fresh")" = same-list

# When every lower descriptor is occupied, opening the operand consumes fd 10
# before Bash chooses the retained varredir slot. Numeric cleanup therefore
# cannot restore the old fd-10 route over the new named allocation.
(
  exec 3>"$tmpdir/occupied" 4>"$tmpdir/occupied" \
    5>"$tmpdir/occupied" 6>"$tmpdir/occupied" \
    7>"$tmpdir/occupied" 8>"$tmpdir/occupied" \
    9>"$tmpdir/occupied" 10>"$tmpdir/occupied-base"
  true 10>&- {occupied_slot}>"$tmpdir/occupied-fresh" &&
    printf occupied >&"$occupied_slot"
  test "$occupied_slot" -gt 10
  test ! -s "$tmpdir/occupied-base"
  test "$(cat "$tmpdir/occupied-fresh")" = occupied
)

# Conditional low-descriptor occupancy produces both concrete outcomes that
# the dependency graph retains. When fd 3 is free, the operand open consumes
# it and the named allocation reuses fd 10 before cleanup restores the old fd
# 10 route. When fd 3 stays occupied, the operand open consumes fd 10 and the
# named allocation uses a fresh descriptor above it.
(
  exec 3>"$tmpdir/conditional-low" 4>"$tmpdir/conditional-low" \
    5>"$tmpdir/conditional-low" 6>"$tmpdir/conditional-low" \
    7>"$tmpdir/conditional-low" 8>"$tmpdir/conditional-low" \
    9>"$tmpdir/conditional-low" 10>"$tmpdir/conditional-true-base"
  true && exec 3>&-
  true 10>&- {conditional_true}>"$tmpdir/conditional-true-fresh" &&
    printf conditional-true >&"$conditional_true"
  test "$conditional_true" = 10
  test "$(cat "$tmpdir/conditional-true-base")" = conditional-true
  test ! -s "$tmpdir/conditional-true-fresh"
)
(
  exec 3>"$tmpdir/conditional-high" 4>"$tmpdir/conditional-high" \
    5>"$tmpdir/conditional-high" 6>"$tmpdir/conditional-high" \
    7>"$tmpdir/conditional-high" 8>"$tmpdir/conditional-high" \
    9>"$tmpdir/conditional-high" 10>"$tmpdir/conditional-false-base"
  false && exec 3>&-
  true 10>&- {conditional_false}>"$tmpdir/conditional-false-fresh" &&
    printf conditional-false >&"$conditional_false"
  test "$conditional_false" -gt 10
  test ! -s "$tmpdir/conditional-false-base"
  test "$(cat "$tmpdir/conditional-false-fresh")" = conditional-false
)

# Closed standard descriptors are part of the same lowest-free search. Keep
# fd 10's original route open before closing stdin so the test isolates the
# later named allocation rather than the setup of that original route.
(
  exec 10>"$tmpdir/standard-low-base"
  exec 0<&-
  exec 3>"$tmpdir/standard-low" 4>"$tmpdir/standard-low" \
    5>"$tmpdir/standard-low" 6>"$tmpdir/standard-low" \
    7>"$tmpdir/standard-low" 8>"$tmpdir/standard-low" \
    9>"$tmpdir/standard-low"
  true 10>&- {standard_low}>"$tmpdir/standard-low-fresh" &&
    printf standard-low >&"$standard_low"
  test "$standard_low" = 10
  test "$(cat "$tmpdir/standard-low-base")" = standard-low
  test ! -s "$tmpdir/standard-low-fresh"
)

exec 3>"$tmpdir/reused-low-base"
true 3>&- {low_slot}>"$tmpdir/reused-low-fresh" &&
  printf low >&"$low_slot"
test "$low_slot" -ge 10
test ! -s "$tmpdir/reused-low-base"
test "$(cat "$tmpdir/reused-low-fresh")" = low

exec 10>&-
true 10>&- {closed_slot}>"$tmpdir/reused-closed-fresh"
test "$closed_slot" = 10
if ( printf unexpected >&"$closed_slot" ) 2>/dev/null; then
  exit 1
fi
test ! -s "$tmpdir/reused-closed-fresh"

exec 10>"$tmpdir/reused-reopened-base"
true 10>&- 10>"$tmpdir/reused-reopened-temporary" \
  {reopened_slot}>"$tmpdir/reused-reopened-fresh"
test "$reopened_slot" -gt 10
printf reopened >&"$reopened_slot"
test ! -s "$tmpdir/reused-reopened-base"
test ! -s "$tmpdir/reused-reopened-temporary"
test "$(cat "$tmpdir/reused-reopened-fresh")" = reopened

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

# Decimal field splitting applies to unquoted symbolic duplication operands.
# Ordinary command prefixes apply after redirect expansion; assignment-only
# prefixes apply before it. Fixed probes never execute dataset commands.
exec {fd}>/dev/null
IFS=0123456789
if printf blocked >&$fd; then exit 91; fi
printf quoted >&"$fd"
printf quoted >&"${fd}"
unset IFS
printf restored >&$fd
if IFS=0123456789 >&$fd; then exit 92; fi
test "$IFS" = 0123456789
IFS=
IFS=0123456789 printf prefix >&$fd
test -z "$IFS"
printf -v IFS 0123456789
if printf blocked >&$fd; then exit 93; fi
unset IFS
( IFS=0123456789 )
printf scope >&$fd
IFS= read IFS <<<literal
printf prefix-read >&$fd
IFS=0123456789
if printf blocked >&$fd && IFS=; then exit 94; fi
test "$IFS" = 0123456789
unset IFS
exec {IFS}>/dev/null
if printf blocked >&$IFS; then exit 95; fi
printf quoted >&"$IFS"
unset IFS

# Assignment-only RHS expansion observes earlier commits, not its own or
# later writes. Executable prefixes keep the incoming expansion environment.
"$BASH" -p -c '
  exec {fd}>"$1/ifs-assignment-prefix" || exit
  IFS=0123456789
  IFS= X=$(printf clear >&$fd)
  test -z "$X" && test -z "$IFS" || exit 101
  if IFS=0123456789 X=$(printf blocked >&$fd); then exit 102; fi
  if IFS=0123456789 X=$(printf blocked >&$fd) IFS=; then exit 103; fi
  test -z "$IFS" || exit 104
  IFS=0
  if IFS+=123456789 X=$(printf blocked >&$fd); then exit 105; fi
  IFS=0123456789
  IFS= X=$(printf blocked >&$fd) :
  test "$IFS" = 0123456789 || exit 106
  IFS= X=<(printf process >&$fd)
  wait "$!"
  unset IFS
  test "$(cat "$1/ifs-assignment-prefix")" = clearprocess || exit 107
' fixture "$tmpdir"

# Named-descriptor identity follows Bash lexical continuation exactly. Only
# backslash-LF is erased; CR remains in the word, and CR before LF leaves that
# word before starting the next command.
unset fd
eval ': {f\
d}>"$tmpdir/lf-name"'
test -n "${fd+x}"
printf joined >&"$fd"
test "$(cat "$tmpdir/lf-name")" = joined
exec {fd}>&-
unset fd

printf -v probe ': {f\\\rd}>"$tmpdir/bare-cr-name"'
eval "$probe"
test -z "${fd+x}" && test -e "$tmpdir/bare-cr-name"

printf -v probe ': {f\\\r\n: d}>"$tmpdir/crlf-name"'
eval "$probe"
test -z "${fd+x}" && test -e "$tmpdir/crlf-name"

(
  cd "$tmpdir"
  unset f
  exec {fd}>named-reference
  printf -v probe 'printf ordinary >&$f\\\rd'
  eval "$probe"
  test ! -s named-reference
  test "$(cat $'\rd')" = ordinary
)

# A parameter assignment is a real shell-state write, not just an expansion
# failure possibility. With fd 10, digit-zero IFS selects stdout instead.
"$BASH" -p -c '
  exec 10>&-
  exec 1>"$1/ifs-parameter-other" || exit
  exec {fd}>"$1/ifs-parameter-out" || exit
  test "$fd" = 10 || exit 108
  unset IFS
  : "${IFS:=0}"
  printf payload >&$fd
  unset IFS
  test ! -s "$1/ifs-parameter-out" || exit 109
  test "$(cat "$1/ifs-parameter-other")" = payload || exit 110
' fixture "$tmpdir"
]=]
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "Bash named-FD conformance check failed (${result}): ${error}${output}")
endif()
