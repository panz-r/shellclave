cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# Only these fixed, nonblocking expressions are executed, never fuzz input.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
# Resettable predefined capabilities are inherited, not recreated by a fork.
# Child-local writes and unsets must not change the parent's variable state.
(
  unset RANDOM BASH_REMATCH
  result=$(read RANDOM <<<payload; printf %s "$RANDOM")
  test "$result" = payload
  test -z "$RANDOM"
  result=`read RANDOM <<<payload; printf %s "$RANDOM"`
  test "$result" = payload
  result=$(nested=$(read BASH_REMATCH <<<payload; printf %s "$BASH_REMATCH");
           printf %s "$nested")
  test "$result" = payload
  read -r result < <(read RANDOM <<<payload; printf '%s\n' "$RANDOM")
  test "$result" = payload
  result=$(read -n0 RANDOM; printf '%s:%s' "$?" "$RANDOM")
  test "$result" = 0:
  result=$(read -p"$RANDOM" -e value <<<payload; printf %s "$value")
  test "$result" = payload
  result=$(printf -v RANDOM %s payload; printf %s "$RANDOM")
  test "$result" = payload
)
(
  result=$(unset RANDOM)
  case "$(declare -p RANDOM)" in 'declare -i '*) ;; *) exit 1 ;; esac
)
# Fixed syntax-only checks: CR after { does not delimit a reserved word.
# These anchor the AST generator's CR/LF templates without executing commands.
if "$BASH" --noprofile --norc -p -n -c $'{\r\n  echo one\r\n}' 2>/dev/null;
then exit 1; fi
"$BASH" --noprofile --norc -p -n -c $'{\r\n echo one }'
"$BASH" --noprofile --norc -p -n -c $'{\n echo one\r\n}'
# $_ is rewritten by Bash after a simple command, including after unset.
# Numeric captures must not retain a stale empty proof for this variable.
(
  unset _
  : 1
  read -n"$_" value <<<payload
  test "$value" = p
)
(
  unset '_'
  builtin : 1
  builtin read -n"${_}" value <<<payload
  test "$value" = p
)
(
  unset _
  : 1
  result=$(read -n"$_" value <<<payload; printf %s "$value")
  test "$result" = p
)
# Empty attached options leave the next complete word pending as an operand.
# Its literal option prefix is still invalid numeric data, regardless of the
# value of its own parameter fragment. Argument errors precede all read I/O
# and target/IFS/REPLY assignments.
for first in n N t u; do
  for second in p d i n N t u; do
    (
      unset fd
      value=kept REPLY=saved IFS=:
      exec 0<<<payload
      if read "-$first$fd" "-$second$fd" value IFS 2>/dev/null;
      then exit 1; fi
      test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
done
(
  unset fd
  REPLY=saved
  exec 0<<<payload
  if read -u"$fd" -n"$fd" 2>/dev/null; then exit 1; fi
  test "$REPLY" = saved
  IFS= read -r remaining
  test "$remaining" = payload
)
for option in n0 N0 t0; do
  (
    unset fd
    value=kept
    exec 0<<<payload
    read "-$option$fd" value || exit 1
    if test "$option" = t0; then test "$value" = kept || exit 1
    else test -z "$value" || exit 1; fi
    IFS= read -r remaining || exit 1
    test "$remaining" = payload || exit 1
  ) || exit 1
done
# Captured allocation digits refine a signed scalar without guessing general
# concatenation/overflow. Negative operands fail before consuming stdin or
# assigning any target, including a predefined arithmetic target.
for option in n N t u; do
  for attached in yes no; do
    (
      exec {fd}<<<saved
      exec 0<<<payload
      value=kept IFS=:
      if test "$attached" = yes; then
        if read "-$option-$fd" value IFS RANDOM 2>/dev/null; then exit 1; fi
      else
        if read "-$option" "-$fd" value IFS RANDOM 2>/dev/null; then exit 1; fi
      fi
      test "$value|$IFS" = 'kept|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
done
# Leading zeroes do not change decimal scalar values or their sign. A known
# allocated FD after -00 remains negative; an empty scalar leaves literal 0.
for option in n N u; do
  for zeros in 0 00 000000; do
    for attached in yes no; do
      (
        exec {fd}<<<saved
        original=$fd
        exec 0<<<payload
        value=kept REPLY=reply IFS=:
        if test "$attached" = yes; then
          if read "-$option-$zeros$fd" value IFS fd 2>/dev/null;
          then exit 1; fi
        else
          if read "-$option" "-$zeros$fd" value IFS fd 2>/dev/null;
          then exit 1; fi
        fi
        test "$value|$REPLY|$IFS|$fd" = "kept|reply|:|$original" || exit 1
        IFS= read -r remaining || exit 1
        test "$remaining" = payload || exit 1
        # Positive zero-prefixed selectors retain the same physical FD.
        if test "$attached" = yes; then read "-u$zeros$fd" value
        else read -u "+$zeros$fd " value; fi
        test "$value" = saved || exit 1
      ) || exit 1
    done
  done
done
(
  unset fd
  read -u0"$fd" value <<<payload
  test "$value" = payload
  read -u "-00$fd " value <<<payload
  test "$value" = payload
  read -u0"$fd" value {fd}<<<other <<<payload
  test "$value" = payload
)
(
  unset fd
  read -u3"$fd" value 3<<<payload
  test "$value" = payload
)
(
  unset empty
  exec 3<<<payload
  if read -- -p"$empty" RANDOM <&3 2>/dev/null; then exit 1; fi
  IFS= read -r remaining <&3
  test "$remaining" = payload
  if read -u4 RANDOM 4<&- 2>/dev/null; then exit 1; fi
)
(
  unset empty
  exec {out}>&1
  original=$out
  IFS=:
  read -n0 other"$empty"
  test "$out|$IFS" = "$original|:"
  exec {input}<<<saved
  read -u"$input" oth"$empty"er
  test "$other|$out|$IFS" = "saved|$original|:"
  read -n0 o"$empty"ut
  test -z "$out"
  read -n0 I"$empty"FS
  test -z "$IFS"
)
(
  unset RANDOM empty
  read -n0 RANDOM"$empty"
  test -z "$RANDOM"
)
# Numeric prefix errors survive unknown suffixes; completed timeout conversion
# ignores them. Only fixed test spellings are passed to eval below.
for option in n N u; do
  for separator in '' ' '; do
    (
      exec {fd}<<<saved
      value=kept REPLY=saved IFS=:
      exec 0<<<payload
      if eval "read -$option$separator-1\"\$fd\" value IFS" 2>/dev/null;
      then exit 1; fi
      test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
done
for suffix in '' 9 invalid; do
  for operand in 0.0000000 0.000000x 4294967296.0000000; do
    (
      value=kept REPLY=saved IFS=:
      exec 0<<<payload
      read -t"$operand$suffix" value IFS || exit 1
      test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
  for operand in -0.0000005 9223372036854775808.0000000; do
    (
      value=kept IFS=:
      exec 0<<<payload
      if read -t"$operand$suffix" value IFS 2>/dev/null; then exit 1; fi
      test "$value|$IFS" = 'kept|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
  for operand in 1.0000000 1.0000005 -18446744073709551615.0000000; do
    (
      value=kept
      read -t"$operand$suffix" value <<<payload || exit 1
      test "$value" = payload || exit 1
    ) || exit 1
  done
done
for target in '$empty~' '${empty}~' '"$empty"~' \
              'pre<(:)' '<(:)suffix' 'pre>(:)' '>(:)suffix' \
              '"$unknown"<(:)' 'pre<(:)"$unknown"'; do
  (
    unset empty unknown
    value=kept REPLY=saved IFS=:
    exec 0<<<payload
    if eval "read -- $target value IFS" 2>/dev/null; then exit 1; fi
    test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
    IFS= read -r remaining || exit 1
    test "$remaining" = payload || exit 1
  ) || exit 1
done
(
  value=kept
  read -p pre<(:) value <<<payload
  test "$value" = payload
  value=kept
  read -t0.0000000<(:) value <<<payload
  test "$value" = kept
)
# Literal suffixes can prove failure without resolving scalar fragments.
for option in n N u; do
  for unknown in '' 0 1 12; do
    (
      value=kept REPLY=saved IFS=:
      exec 0<<<payload
      if eval "read -$option\"\$unknown\"x value IFS" 2>/dev/null;
      then exit 1; fi
      test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
      IFS= read -r remaining || exit 1
      test "$remaining" = payload || exit 1
    ) || exit 1
  done
done
for unknown in '' letters '-p' '[1]'; do
  (
    value=kept IFS=:
    exec 0<<<payload
    if read -- pre"$unknown"- value IFS 2>/dev/null; then exit 1; fi
    test "$value|$IFS" = 'kept|:' || exit 1
    IFS= read -r remaining || exit 1
    test "$remaining" = payload || exit 1
  ) || exit 1
done
for selector in -e -E -a -re -ra; do
  (
    unset fd
    value=kept
    read -p"$fd" "$selector" value <<<payload || exit 1
    test "$value" = payload || exit 1
    exec 0<<<payload
    if read -n"$fd" "$selector" value 2>/dev/null; then exit 1; fi
    IFS= read -r remaining || exit 1
    test "$remaining" = payload || exit 1
  ) || exit 1
done
# A pathname can occur inside an expanded array subscript. This is a negative
# control for failure proofs, not support for evaluating array targets.
(
  open='[1' dev=1 fd=1 value=kept
  read -- "a${open}"<(:)"]" value <<<payload
  test "${a[0]}" = payload
  test -z "$value"
)
# A wholly elided process word is not an exec operand or an exit status.
test "$(exec <() 3>&1; printf kept >&3)" = kept
test "$( (true; exit <()) && printf reached)" = reached
test "$( (false; builtin exit >()) || printf reached)" = reached
test "$( (false; exit <() 0 >()) && printf reached)" = reached
test "$(exec -a <() name >() 3>&1; printf kept >&3)" = kept
test "$( (true; exit -- <()) && printf reached)" = reached
if (true; command exit <() "") 2>/dev/null; then exit 1; fi
# A literal invalid target prefix survives every scalar expansion. With an
# empty capture, invalid suffixes are equally certain. First-target errors
# precede input; later errors retain only assignments before that target.
for target in '-p"$empty"' 'bad-"$empty"' '9"$empty"' \
              '"$empty"-' '"$empty"0' '"$empty"a-'; do
  for mode in '' -n0 -N0 -t0; do
    for earlier in '' first; do
      (
        unset empty
        first=before value=kept REPLY=saved IFS=:
        exec 3<<<payload
        printf -v probe 'read %s -- %s %s value IFS <&3' \
          "$mode" "$earlier" "$target"
        success=no
        if eval "$probe" 2>/dev/null; then success=yes; fi
        test "$value|$REPLY|$IFS" = 'kept|saved|:' || exit 1
        remaining=
        IFS= read -r remaining <&3 || :
        if test "$mode" = -t0; then
          test "$success|$first|$remaining" = 'yes|before|payload' || exit 1
        elif test -z "$earlier"; then
          test "$success|$first|$remaining" = 'no|before|payload' || exit 1
        elif test -z "$mode"; then
          test "$success|$first|$remaining" = 'no|payload|' || exit 1
        else
          test "$success|$first|$remaining" = 'no||payload' || exit 1
        fi
      ) || exit 1
    done
  done
done
# Declaration operands are recognized after empty process fragments vanish.
# These are fixed fixtures; eval exposes the exact source spellings to Bash.
for declaration in export declare typeset; do
  for operand in 'fd<()=anything' '<()fd=anything' 'f>()d=anything' \
                 'f<()>()d=anything'; do
    (
      exec {fd}<<<payload
      eval "$declaration $operand"
      test "$fd" = anything
      if read -u"$fd" value 2>/dev/null; then exit 1; fi
    ) || exit 1
  done
  for operand in 'fd<()+=anything' 'fd+<()=anything'; do
    (
      fd=prefix
      eval "$declaration $operand"
      test "$fd" = prefixanything
    ) || exit 1
  done
done
(
  exec {fd}<<<payload
  original=$fd
  fd=shadow declare f<()d=anything
  test "$fd" = "$original"
  fd=shadow export f<()d=anything
  test "$fd" = anything
)
(
  fd=kept
  if export 'fd<()'=anything 2>/dev/null; then exit 1; fi
  test "$fd" = kept
  if fd<()=anything 2>/dev/null; then exit 1; fi
  test "$fd" = kept
)
(
  # The integer attribute executes arithmetic hidden in a quoted value. The
  # semantic boundary must reject this just like the plain OPTIND spelling.
  observed=$(export OPT<()IND='x[$(printf ARITH >&2)0]' 2>&1)
  test "$observed" = ARITH
  readonly v<()=text
  case $(declare -p v) in 'declare -r v="text"') ;; *) exit 1 ;; esac
)
# A dynamic later target may reject assignment after earlier writes. Zero
# counts isolate this from EOF failures; polling bypasses the target checks.
for mode in -n0 -N0 -t0; do
  for target in middle bad-name locked; do
    (
      readonly locked=kept
      first=old middle=old last=old
      exec 3<<<payload
      # Model the documented executor's default, not this fixture's -e.
      # Bash's readonly-assignment failure otherwise exits this subshell.
      set +e
      read "$mode" -u3 first "$target" last 2>/dev/null
      status=$?
      set -e
      success=no
      if test "$status" = 0; then success=yes; fi
      test "$locked" = kept || exit 1
      if test "$mode" = -t0; then
        test "$success" = yes || exit 1
        test "$first|$middle|$last" = 'old|old|old' || exit 1
      else
        test -z "$first" || exit 1
        if test "$target" = middle; then
          test "$success" = yes || exit 1
          test -z "$middle$last" || exit 1
        else
          test "$success" = no || exit 1
          test "$middle|$last" = 'old|old' || exit 1
        fi
      fi
      IFS= read -ru3 rest || exit 1
      test "$rest" = payload || exit 1
    ) || exit
  done
done
for target in bad-name locked; do
  (
    readonly locked=kept
    exec 3<<<$'first\nsecond'
    set +e
    read -u3 -- "$target" 2>/dev/null
    status=$?
    set -e
    test "$status" != 0 || exit 1
    IFS= read -ru3 rest || exit 1
    # Identifier validation precedes input, readonly assignment follows it.
    if test "$target" = bad-name; then test "$rest" = first || exit 1
    else test "$rest" = second || exit 1; fi
    test "$locked" = kept || exit 1
  ) || exit
done
for mode in -n0 -N0; do
  for target in bad-name locked; do
    (
      readonly locked=kept
      exec {before}<<<earlier {after}<<<saved
      saved=$after
      set +e
      read "$mode" before "$target" after <<<payload 2>/dev/null
      status=$?
      set -e
      test "$status" != 0 || exit 1
      test -z "$before" || exit 1
      test "$after" = "$saved" || exit 1
      IFS= read -r -u"$after" rest || exit 1
      test "$rest" = saved || exit 1
    ) || exit
  done
done
(
  # Even a later argument past a rejecting target expands before read runs.
  exec 3<<<$'first\nsecond'
  if read -n0 first bad-name "$(IFS= read -ru3 consumed)" <<<payload 2>/dev/null;
  then exit 1; fi
  IFS= read -ru3 rest
  test "$rest" = second
)
(
  # Expansion removes empty process fragments before selecting argv[0], but
  # cannot turn a later ordinary word into a lexical assignment prefix.
  <() eval 'printf -v value %s verified'
  test "$value" = verified
  <()printf -v value '%s|' a<()b <()>() ''<() "<()"
  test "$value" = 'ab||<()|'
  unset empty_process_assignment
  if <() empty_process_assignment=literal 2>/dev/null; then exit 1; fi
  test -z "${empty_process_assignment+x}"
  exec 3<<<payload
  <()read -u<()3 value
  test "$value" = payload
  command <() read -n0 value
  test -z "$value"
)
(
  exec 3<&- 4<&- 63<&-
  for choice in '' yes; do
    result=$(printf '%s|' ${choice:+<(:)} "$(
      read -u63 -n0 first 2>/dev/null || {
        read -u63 -n0 second 2>/dev/null && printf BAD
      }
    )")
    case "$result" in *BAD*) exit 1;; esac
  done
)
(
  # If the first input pipe retains fd 3, its other original end is fd 63.
  # Every intermediate high slot must already be occupied.
  for slot in {4..62}; do eval "exec ${slot}<>/dev/null"; done
  exec 3<&- 63<&-
  printf -v result '%s|' <(:) <(:)
  test "$result" = '/dev/fd/3|/dev/fd/63|'
)
(
  # Conditional parameter words also create pipes. With the high range full,
  # the original read end occupies closed stdin; the skipped case creates none.
  for slot in {3..63}; do eval "exec ${slot}<>/dev/null"; done
  exec 0<&-
  unset choice
  value=unchanged
  if path=${choice:+<(printf 'payload\n')} read -r value 2>/dev/null;
  then exit 1; fi
  test "$value" = unchanged
  choice=yes
  path=${choice:+<(printf 'payload\n')} read -r value
  test "$value" = payload
)
(
  # Empty process substitutions produce no filename, including newline/comment
  # bodies. The outer command remains valid syntax; only its file read fails.
  if value=$(< <()); then exit 1; fi
  if value=$(< <( )); then exit 1; fi
  if value=$(< <(
  )); then exit 1; fi
  if value=$(< <(# comment
  )); then exit 1; fi
  if value=$(< <(\
  )); then exit 1; fi
  if value=$(< >()); then exit 1; fi
  if value=$(< >( )); then exit 1; fi
  if value=$(< >(
  )); then exit 1; fi
  if value=$(< >(# comment
  )); then exit 1; fi
  if value=$(< >(\
  )); then exit 1; fi
  success= fallback=
  value=$(< <()) && success=yes || fallback=yes
  test -z "$success"
  test "$fallback" = yes
  printf -v value '%s' "$(< <())"
  test -z "$value"
  value=$(< <(:))
  test -z "$value"
)
(
  exec 3<&- 4<&- 62<&- 63<&-
  unset choice
  value=unchanged
  if path=${choice:+<(:)} read -u63 -n0 value 2>/dev/null;
  then exit 1; fi
  test "$value" = unchanged
  choice=yes
  path=${choice:+<(:)} read -u63 -n0 value
  test -z "$value"
  if read -u63 -t0 value 2>/dev/null; then exit 1; fi
  unset choice
  path=${choice:-<(:)} read -u63 -n0 value
  choice=yes
  if path=${choice:-<(:)} read -u63 -n0 value 2>/dev/null;
  then exit 1; fi
  path=${choice:+<(printf 'first\n')<(printf 'second\n')} read -ru63 value
  test "$value" = first
  result=${choice:+<(:)$(read -u63 -n0 inner || printf BAD)}
  test "$result" = /dev/fd/63
  exec 63<&-
  result=$(printf '%s' "$(</shellclave-missing/<(:))" \
    "$(read -u63 -n0 value || printf FALLBACK)" 2>/dev/null)
  test -z "$result"
  result=$(printf '%s' "$(< <(:))" \
    "$(read -u63 -n0 value || printf FALLBACK)")
  test -z "$result"
  for outer in '' yes; do
    for inner in '' yes; do
      status=0
      path=${outer:+<(:)${inner:+<(:)}} read -u62 -n0 value 2>/dev/null || status=$?
      if test -n "$outer" && test -n "$inner"; then test "$status" = 0
      else test "$status" != 0; fi
    done
  done
)
(
  for slot in {3..63}; do eval "exec ${slot}<>/dev/null"; done
  exec 64<&- 65<&-
  if read -ru64 value <(printf 'payload\n') 2>/dev/null; then exit 1; fi
  test "$value" = payload
)
(
  for slot in {3..63}; do eval "exec ${slot}<>/dev/null"; done
  exec 2>&-
  time { read -ru2 value; } < <(printf 'payload\n')
  test "$value" = payload
  if read -u2 -t0 rest; then exit 1; fi
)
(
  exec 3<&- 4<&- 63<&-
  read -ru63 value > <(printf 'payload\n')
  test "$value" = payload
)
(
  exec 3<&- 4<&- 63<&-
  value=unchanged
  if 63<&- path=<(printf 'payload\n' 2>/dev/null) read -u63 value 2>/dev/null;
  then exit 1; fi
  test "$value" = unchanged
  3</dev/null path=<(printf 'payload\n') read -ru63 value
  test "$value" = payload
)
(
  for slot in {3..61}; do eval "exec ${slot}<>/dev/null"; done
  exec 62<&- 63<&-
  if read -ru62 value <(printf 'payload\n') 2>/dev/null; then exit 1; fi
  test "$value" = payload
)
(
  exec 3<&- 4<&- 63<&-
  value=unchanged
  if read -u63 value <() 2>/dev/null; then exit 1; fi
  test "$value" = unchanged
  read value <() <<<payload
  test "$value" = payload
  read -p >( ) -u3 value <<<payload 3<<<unused
  test "$value" = payload
  value=unchanged
  if read value < <() 2>/dev/null; then exit 1; fi
  test "$value" = unchanged
  if read -u63 value <(exec 1>&-) 2>/dev/null; then exit 1; fi
  test -z "$value"
)
(
  exec 63<&-
  value=unchanged
  if read -ru63 value <(printf 'payload\n') 2>/dev/null; then exit 1; fi
  test "$value" = payload
  if read -u63 value 2>/dev/null; then exit 1; fi
)
(
  exec 63<&-
  read -r -p <(printf 'payload\n') -u63 value
  test "$value" = payload
)
(
  exec 63<<<occupied 62<&-
  if read -ru62 value <(printf 'payload\n') 2>/dev/null; then exit 1; fi
  test "$value" = payload
  read -ru63 other
  test "$other" = occupied
)
(
  exec 63<&-
  { exec 3<&63; } < <(printf 'payload\n')
  read -ru3 value
  test "$value" = payload
  if read -u63 value 2>/dev/null; then exit 1; fi
)
(
  exec 63<&-
  : <(:)
  if read -u63 value 2>/dev/null; then exit 1; fi
)
for descriptor in closed writeonly; do
  for option in normal zero poll; do
    (
      exec {out}>/dev/null
      before=$out
      if test "$descriptor" = closed; then
        exec 0<&-
      else
        exec 3>/dev/null
      fi
      flags=()
      if test "$option" = zero; then flags=(-n0)
      elif test "$option" = poll; then flags=(-t0); fi
      # Closed default stdin reaches the input phase; explicit -u validates
      # existence earlier. A write-only -u slot exists but is not readable.
      if test "$descriptor" = writeonly; then flags+=(-u3); fi
      status=0
      read "${flags[@]}" out 2>/dev/null || status=$?
      if test "$option:$descriptor" = poll:writeonly; then
        test "$status" = 0
      else
        test "$status" != 0
      fi
      if test "$option" = zero; then test -z "$out"
      else test "$out" = "$before"; fi
    )
  done
done
(
  exec 0<<<unused
  { exec 3<<<selected; read -ru3 value; }
  test "$value" = selected
  read -r rest
  test "$rest" = unused
)
(
  exec 0<<<stdin 3<<<selected
  IFS= read -r -u3 value
  IFS= read -r rest
  test "$value:$rest" = selected:stdin
)
(
  exec {fd}<<<old
  IFS= read -r -u "$fd" value {fd}<<<new
  test "$value" = old
  IFS= read -r -u "$fd" value
  test "$value" = new
)
(
  exec 3<&- 4<<<payload
  value=unchanged
  if read -u3 -u4 value 2>/dev/null; then exit 1; fi
  test "$value" = unchanged
  IFS= read -r -u4 rest
  test "$rest" = payload
)
for option in -n0 -N0 -t0; do
  (
    exec 3<<<payload
    value=unchanged
    read "$option" -u3 value
    if test "$option" = -t0; then test "$value" = unchanged
    else test -z "$value"; fi
    IFS= read -r -u3 rest
    test "$rest" = payload
  )
done
(
  exec 3<<<payload
  if read -u3 bad-name 2>/dev/null; then exit 1; fi
  IFS= read -r -u3 rest
  test "$rest" = payload
)
(
  exec 3<<<$'first\nsecond'
  readonly locked=value
  if (read -u3 locked) 2>/dev/null; then exit 1; fi
  IFS= read -r -u3 rest
  test "$rest" = second
)
(
  exec 3<<<first 4<<<last
  IFS= read -r -u3 -u4 value
  test "$value" = last
  IFS= read -r -u ' 3 ' value
  test "$value" = first
)
(
  unset fd
  if { exec {fd}</dev/fd/-1; } 2>/dev/null; then exit 1; fi
  exec 3<<<payload
  IFS= read -r -u"$fd" 3 value
  test "$value" = payload
  exec 3<<<payload
  IFS= read -r -u $fd 3 value
  test "$value" = payload
  exec 3<<<payload
  if read -u "$fd" 3 value 2>/dev/null; then exit 1; fi
  IFS= read -r -u3 value
  test "$value" = payload
)
(
  exec 10<&- 3<<<saved
  IFS= read -r -u10 value 3>/dev/null
  test "$value" = saved
)
(
  exec {fd}<<<payload
  IFS=012 read -r -u $fd value
  test "$value" = payload
)
(
  exec {fd}< <(printf 'payload\n')
  value=$(IFS= read -r -u "$fd" line; printf '%s' "$line")
  test "$value" = payload
)
test "$(printf 'payload\n' | { IFS= read -r line; printf '%s' "$line"; })" = payload
for connector in and or; do
  for choice in yes no; do
    (
      exec 3<&-
      if test "$connector" = and; then
        test "$choice" = yes && exec 3<<<payload
      else
        test "$choice" = yes || exec 3<<<payload
      fi
      value=unchanged
      if read -u3 value 2>/dev/null; then
        test "$value" = payload
        test "$connector:$choice" = and:yes || test "$connector:$choice" = or:no
      else
        test "$value" = unchanged
        test "$connector:$choice" = and:no || test "$connector:$choice" = or:yes
      fi
    )
  done
done
(
  exec 0<<<stdin
  exec {fd}<<<selected && read -r -p"$fd" -u"$fd" value
  test "$value" = selected
  read -r rest
  test "$rest" = stdin
)
for selector in quoted unquoted; do
  (
    exec 0<<<stdin
    exec {fd}<<<selected
    if test "$selector" = quoted; then
      read -r -p"$fd" -u "$fd" value
    else
      read -r -p"$fd" -u $fd value
    fi
    test "$value" = selected
    read -r rest
    test "$rest" = stdin
  )
done
for option in 4294967296 8589934592 4294967296.0000001 +4294967296 \
              18446744073709551616 -18446744073709551616 \
              36893488147419103232.0000001; do
  (
    exec 3<<<payload
    value=unchanged
    read -t"$option" -u3 value
    test "$value" = unchanged
    read -ru3 rest
    test "$rest" = payload
    exec {fd}>/dev/null
    before=$fd
    read -t"$option" fd <<<payload
    test "$fd" = "$before"
    printf x >&"$fd"
    REPLY=unchanged
    read -t"$option" <<<payload
    test "$REPLY" = unchanged
  )
done
(
  read -t4294967296.5 value <<<payload
  test "$value" = payload
  for option in -4294967296 9223372036854775808 18446744073709551615 \
                -9223372036854775808 -18446744073709551616.5 \
                -18446744073709551617.5 18446744073709551617x \
                18446744073709551617.0x; do
    value=unchanged
    if read -t"$option" value <<<payload 2>/dev/null; then exit 1; fi
    test "$value" = unchanged
  done
)
for option in 18446744073709551617 +18446744073709551617 \
              -18446744073709551615 -18446744073709551615.5 \
              36893488147419103233 18446744073709551616.5 \
              9223372036854775807; do
  (
    exec 3<<<payload
    value=unchanged
    read -t"$option" -u3 value
    test "$value" = payload
    if read -ru3 rest; then exit 1; fi
  )
done
for position in first later; do
  (
    exec {input}<<<'one two' {out}>/dev/null
    before=$out
    first=unchanged
    if test "$position" = first; then
      if read -u"$input" -- "$input" first out 2>/dev/null; then exit 1; fi
      test "$first" = unchanged
      IFS= read -ru"$input" rest
      test "$rest" = 'one two'
    else
      if read -u"$input" -- first "$input" out 2>/dev/null; then exit 1; fi
      test "$first" = one
      if read -ru"$input" rest; then exit 1; fi
    fi
    test "$out" = "$before"
    printf x >&"$out"
  )
done
for form in bare quoted prefix suffix; do
  (
    unset empty
    exec {input}<<<payload {out}>/dev/null
    value=unchanged
    case "$form" in
      bare) read -u"$input" -- $empty value; test "$value" = payload ;;
      quoted) if read -u"$input" -- "$empty" value 2>/dev/null; then exit 1; fi ;;
      prefix) if read -u"$input" -- ""$empty value 2>/dev/null; then exit 1; fi ;;
      suffix) if read -u"$input" -- $empty"" value 2>/dev/null; then exit 1; fi ;;
    esac
    if test "$form" != bare; then
      test "$value" = unchanged
      IFS= read -ru"$input" rest
      test "$rest" = payload
    fi
  )
done
for option in -t0 -n0 -N0; do
  (
    exec {input}<<<payload {out}>/dev/null
    before=$out
    if test "$option" = -t0; then
      read "$option" -u"$input" -- "$input" out
    elif read "$option" -u"$input" -- "$input" out 2>/dev/null; then exit 1
    fi
    test "$out" = "$before"
    IFS= read -ru"$input" rest
    test "$rest" = payload
  )
done
for option in -u18446744073709551617 -n18446744073709551617 \
              -N18446744073709551617; do
  (
    value=unchanged
    if read "$option" value <<<payload 2>/dev/null; then exit 1; fi
    test "$value" = unchanged
  )
done
(
  exec {fd}>/dev/null && {
    before=$fd
    if read -p"$fd" -u3 fd 3<&- 2>/dev/null; then exit 1; fi
    test "$fd" = "$before"
    printf x >&"$fd"
  }
)
(
  { time printf 'payload\n'; } 2>&1 | {
    exec {fd}<&0
    read -r -u"$fd" value
    test "$value" = payload
  }
)
(
  exec {out}>/dev/null && {
    before=$out
    unset empty
    exec 9<&-
    if { exec {empty}<&9; } 2>/dev/null; then exit 1; fi
    read -p"$empty" out value <<<payload
    test "$out" = "$before"
    test "$value" = payload
    printf x >&"$out"
  }
)
(
  unset fd
  result=$(read -p"$fd" -e value <<<payload; printf '%s' "$value")
  test "$result" = payload
  result=$(inner=$(read -p"$fd" -e value <<<payload; printf '%s' "$value");
           printf '%s' "$inner")
  test "$result" = payload
)
(
  check_rhs_value() { test "$result" = changed; }
  check_rhs_ifs() { test "$result" = 'a|b'; }
  check_rhs_read() { test "$result" = payload; }
  unset fd
  fd=changed result=$(printf '%s' "$fd") check_rhs_value
  test "${fd-unset}" = unset
  # Argument lookup sees temporary prefixes; redirection expansion and IFS
  # splitting deliberately use Bash's original binding table instead.
  test "$(exec 7>&-; exec {fd}>&1;
          fd=7 X=$(printf payload >&"$fd") :)" = payload
  before_ifs=$IFS
  IFS= result=$(test -z "$IFS"; read first second <<<'a b';
                printf '%s|%s' "$first" "$second") check_rhs_ifs
  test "$IFS" = "$before_ifs"
  exec {fd}<<<old
  fd=changed result=$(exec {fd}<<<payload && read -u"$fd" value;
                     printf '%s' "$value") check_rhs_read
)
]=]
  RESULT_VARIABLE status ERROR_VARIABLE errors TIMEOUT 5)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash read input contract failed: ${status}\n${errors}")
endif()
