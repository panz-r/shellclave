cmake_minimum_required(VERSION 3.20)
if(NOT DEFINED SHELLCLAVE_BASH)
  message(FATAL_ERROR "Missing reference Bash executable")
endif()
unset(ENV{BASHOPTS})
unset(ENV{SHELLOPTS})
unset(ENV{POSIXLY_CORRECT})
# Fixed, nonblocking programs only; no corpus or fuzz input is executed.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "BASH_ENV=" "ENV=" "PATH=" "LC_ALL=C"
          "${SHELLCLAVE_BASH}" --noprofile --norc -p -c [=[
set -e
for count_mode in -n0 -N0; do
  for timeout in 0 1; do
    (
      exec {fd}</dev/null
      saved=$fd
      if read "$count_mode" -t"$timeout" fd 0>/dev/null; then
        test "$timeout" = 0
        test "$fd" = "$saved"
      else
        test "$timeout" = 1
        test -z "$fd"
      fi
    )
  done
done
(
  exec {REPLY}</dev/null
  saved=$REPLY
  read -n0 -t0 0>/dev/null
  test "$REPLY" = "$saved"
)
for probe in \
  'value=$(read -u11 -n0 probe)' \
  'value=$(read -u11 -N0 probe)' \
  'value=$( (read -u11 -n0 probe) )' \
  'value=$(inner=$(read -u11 -n0 probe))' \
  'value=`read -u11 -n0 probe`' \
  'value=$(read -u11 -n0 probe && { exec 11<&-; true; })'; do
  for mode in closed open; do
    (
      exec 3<&- 11<&-
      if test "$mode" = open; then exec 11</dev/null; fi
      if eval "$probe" 2>/dev/null; then
        test "$mode" = open
        true 3<&11
      else
        test "$mode" = closed
      fi
    )
  done
done
(
  exec 3<&- 11<&-
  value=$(read -u11 -n0 probe 11</dev/null)
  if true 3<&11 2>/dev/null; then exit 1; fi
  a=$(read -u11 -n0 probe 2>/dev/null) b=$(true)
  if true 3<&11 2>/dev/null; then exit 1; fi
  unset choice
  value=${choice:+$(read -u11 -n0 probe)}
  if true 3<&11 2>/dev/null; then exit 1; fi
)
# Bad numeric operands stop before the later overriding options or targets.
for option in -n -N -t; do
  for operand in invalid -1 0 1; do
    (
      probe=unchanged
      if read "$option" "$operand" -t1 -n0 -u11 probe 11</dev/null 2>/dev/null; then
        case $operand in 0|1) ;; *) exit 1;; esac
        test -z "$probe"
      else
        case $operand in invalid|-1) ;; *) exit 1;; esac
        test "$probe" = unchanged
      fi
    )
  done
done
for probe in \
  'value=$(read -u1 -n0 probe)' \
  'value=$(read -u1 -N0 probe)' \
  'value=`read -u1 -n0 probe`' \
  'value=$(inner=$(read -u1 -n0 probe))' \
  'value=$( (read -u1 -n0 probe) )' \
  'value=$(exec 11>&1; read -u11 -n0 probe)'; do
  (
    exec 1>&-
    if eval "$probe" 2>/dev/null; then exit 1; fi
    if true 3>&1 2>/dev/null; then exit 1; fi
  )
done
for probe in \
  'value=$(read -u"$fd" -n0 probe)' \
  'value=`read -u"$fd" -n0 probe`' \
  'value=$(inner=$(read -u"$fd" -n0 probe))'; do
  (
    exec {fd}<<<input
    eval "$probe"
    read -u"$fd" result
    test "$result" = input
    exec {fd}<&-
    if eval "$probe" 2>/dev/null; then exit 1; fi
  )
done
(
  exec {fd}<<<input
  if value=$(exec {fd}>/dev/null; read -u"$fd" -n0 probe) 2>/dev/null; then
    exit 1
  fi
  read -u"$fd" result
  test "$result" = input
)
(
  exec {fd}<<<input
  unset choice
  if a=$(false) b=${choice:+$(read -u"$fd" -n0 probe)}; then exit 1; fi
  a=$(true) b=${choice:+$(read -u"$fd" -n0 probe)}
  choice=yes
  a=$(false) b=${choice:+$(read -u"$fd" -n0 probe)}
)
# Blank substitutions and comment-only $() preserve this command's preceding
# substitution status. Comment-only backticks return success instead. A new
# assignment command still starts with success, not the previous command's $?.
for probe in \
  'a=$(false) b=$(\
)' \
  'a=$(false) b=$(\
 # comment
)' \
  'a=$(false) b=$()' \
  'a=$(false) b=$( )' \
  'a=$(false) b=$(# comment
)' \
  'a=$(false) b=``' \
  'a=$(false) b=`
`' \
  'a=$(true) b=$(false) c=$()' \
  'a=$(false) b=${choice:+$()}' \
  'value=$(a=$(false) b=$())' \
  'a=$(true) b=$() >""'; do
  if eval "$probe" 2>/dev/null; then exit 1; fi
done
for probe in \
  'a=$(true) b=$()' \
  'a=$(false) b=$(true) c=$()' \
  'a=$(false) b=$(:)' \
  'a=$(false) b=` # comment
`' \
  'false; value=$()' \
  'false; value=$(# comment
)' \
  'false; value=``' \
  'a=$(true) b=${choice:+$(# comment
)}' \
  'a=$(false) b=$(inner=$())' \
  'a=$(false) b=$(time :)' \
  'true "$(false)$()"'; do
  if ! eval "$probe" 2>/dev/null; then exit 1; fi
done
(
  exec 3<&- 11<&-
  reached=no
  a=$(read -u11 -n0 probe 2>/dev/null) b=$(</dev/null) &&
    { true 3<&11 2>/dev/null || reached=yes; }
  test "$reached" = yes
)
# CR, VT and FF are command bytes, not blank substitution bodies. Construct
# fixed byte-explicit programs here rather than depending on file line endings.
for body in $'\r' $'\r\n' $'\\\r' $'\\\r\n' $'\v' $'\f'; do
  printf -v probe 'value=$(%s)' "$body"
  if eval "$probe" 2>/dev/null; then exit 1; fi
  printf -v probe 'value=`%s`' "$body"
  if eval "$probe" 2>/dev/null; then exit 1; fi
  for format in 'value=$(true;%s)' 'value=`true;%s`' \
                'value=$( (true;%s) )' $'{ true;%s\n}'; do
    printf -v probe "$format" "$body"
    fallback=no
    eval "$probe" 2>/dev/null || fallback=yes
    test "$fallback" = yes
  done
  printf -v probe 'set -- <(%s)' "$body"
  eval "$probe" 2>/dev/null
  test "$#" = 1
done
# Exact byte spellings from the canonical-argv tests. Bash blanks are SP/TAB;
# LF separates commands, and CR/VT/FF stay inside words. No line normalization.
printf -v probe 'set -- a\rb a\vb a\fb'
eval "$probe"
test "$#" = 3
test "$1|$2|$3" = $'a\rb|a\vb|a\fb'
printf -v probe 'set -- <()\\\r'
eval "$probe"
test "$#" = 1 && test "$1" = $'\r'
printf -v probe 'set -- x\\\r\n# comment'
eval "$probe"
test "$#" = 1 && test "$1" = $'x\r'
printf -v probe 'set -- "\\\r"'
eval "$probe"
test "$#" = 1 && test "$1" = $'\\\r'
printf -v probe 'set -- x\\\n#'
eval "$probe"
test "$#" = 1 && test "$1" = 'x#'
printf -v probe 'set -- <(\n# note\rtext\n)tail'
eval "$probe"
test "$#" = 1 && test "$1" = tail
# A CR in the delimiter is significant, not part of an interchangeable CRLF.
printf -v probe 'IFS= read -r line <<EOF\r\nEOF\nEOF\r\n'
eval "$probe"
test "$line" = EOF
printf -v probe 'IFS= read -r line <<EOF\nEOF\r\nEOF\n'
eval "$probe"
test "$line" = $'EOF\r'
exec 3<<<payload
read -u $' \r3\t' -n0 line
test -z "$line"
printf -v probe 'a=$(false) b=$(# comment\rfalse\n)'
if eval "$probe"; then exit 1; fi
printf -v probe 'a=$(false) b=`# comment\rfalse\n`'
eval "$probe"
printf -v probe 'a=$(false) b=$(# comment\r\n)'
if eval "$probe"; then exit 1; fi
printf -v probe 'a=$(true) b=$(# comment\r\n)'
eval "$probe"

# Elisions never consume a printf format/data slot. A dynamic %b containing
# \c can suppress %n writes, whereas %s emits the two bytes literally.
V='\c'
for probe in \
  'printf <() "%b%n" "$V" target' \
  'printf "%b%n" <() "$V" target' \
  'command <() printf <() "%b%n" "$V" <() target' \
  '{ printf <() "%b%n" <() "$V" target; }' \
  'printf <() -v <() result <() -- <() "%b%n" "$V" target'; do
  target=unchanged
  eval "$probe" >/dev/null
  test "$target" = unchanged
done
for probe in \
  'printf <() "%s%n" "$V" target' \
  'printf "%s%n" <() "$V" target' \
  'builtin printf <() "%s%n" "$V" <() target' \
  '{ printf <() "%s%n" <() "$V" target; }' \
  'printf <() -v <() result <() -- <() "%s%n" "$V" target'; do
  target=unchanged
  eval "$probe" >/dev/null
  test "$target" = 2
done
target=unchanged other=unchanged
printf '%b%n' first target <() "$V" other >/dev/null
test "$target" = 5
test "$other" = unchanged
printf '%s%n' first target <() "$V" other >/dev/null
test "$other" = 2

# Every substitution in a conditional operand shares one decision. Nesting
# cannot revive a skipped parent; the last executed completion supplies status.
for mode in absent present; do
  unset choice nested
  if test "$mode" = present; then choice=yes; nested=yes; fi
  a=$(true) b=${choice:+$(false)$(true)}
  if a=$(false) b=${choice:+$(true)$(false)}; then exit 1; fi
  a=$(true) b=${choice:+$(false)${nested:+$(false)}$(true)}
done
(
  exec 3<&- 11<&-
  unset choice
  reached=no
  value=${choice:+$(read -u11 -n0 probe)} &&
    { true 3<&11 2>/dev/null || reached=yes; }
  test "$reached" = yes
  reached=no
  true || read -u11 -n0 probe &&
    { true 3<&11 2>/dev/null || reached=yes; }
  test "$reached" = yes
)
(
  exec 3<&- 11</dev/null
  if a=$(read -u11 -n0 probe) b=$(<"") 2>/dev/null; then exit 1; fi
  true 3<&11
)
]=]
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 5)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Bash outcome transfer fixture failed (${status}):\n${output}${error}")
endif()
