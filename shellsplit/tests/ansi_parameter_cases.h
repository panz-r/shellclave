#ifndef SHELLSPLIT_TEST_ANSI_PARAMETER_CASES_H
#define SHELLSPLIT_TEST_ANSI_PARAMETER_CASES_H

#include "shell_processor.h"

/* Complete parameter words whose ANSI-C decoding can introduce shell syntax.
 * Graph nodes borrow raw source, so these require UNSUPPORTED rather than a
 * successful graph which silently omits the decoded executable source.
 * The processor preserves its boundary distinction: byte-admission rejection
 * is EINPUT; ASCII decoded-syntax rejection is EPARSE. */
static const struct {
  const char *source;
  shell_process_status_t process_status;
} shellsplit_test_ansi_encoded_cases[] = {
    {"echo \"${v:-$'\\444(printf child)'}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v#${u:-$'\\444(printf child)'}}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v/x/${u:+$'\\x24(printf child)'}}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v:-$'日本\\444(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'\\540printf child\\540'}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v:-$'日本\\540printf child\\540'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\534'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\450'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\451'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\474'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\476'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\573'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\575'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\447'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\442'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\x24(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\044(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\u0024(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\U00000024(printf child)'}\"", SHELL_PROCESS_EINPUT},
};

/* Raw fast framing is valid, but the independent executable child's source
 * would change during the enclosing ANSI-C decoding phase. Draft admission
 * classifies these as UNSUPPORTED and semantic consumers reject them. */
static const char *const shellsplit_test_ansi_translated_children[] = {
    "echo \"${v:-$'$(echo \"\\\\$(printf child)\")'}\"",
    "echo \"${v:-$'$(echo \"\\\\\\$(printf child)\")'}\"",
    "echo \"${v#${u:-$'${w:-$(echo \"\\\\\\$(printf child)\")}'}}\"",
    ("cat <<EOF\n${v#${u:-$'${w:-$(echo \"\\\\\\$(printf "
     "child)\")}\\0tail'}}\nEOF\n"),
    "cat <<EOF\n${0#${0:+${0#$'$(echo \"\\\\$(printf child)\")'}}}\nEOF\n",
    "echo \"${0#${0:+$'<(echo \"\\\\$(printf child)\")'}}\"",
    "echo \"${0#${0:+$'<(printf \\n)'}}\"",
    "echo \"${0:+$'$(printf ch\\x69ld >&2)'}\"",
    "echo \"${0#${0:+$'$(printf ch\\x69ld >&2)'}}\"",
    "echo \"${0#${0:+$'`printf ch\\x69ld >&2`'}}\"",
    "cat <<EOF\n${0#${0:+${0#$'$(printf ch\\x69ld >&2)\\0tail'}}}\nEOF\n",
    "cat <<EOF\n${0#${0:+${0#$'`printf ch\\x69ld >&2`\\0tail'}}}\nEOF\n",
};

/* The raw fast parser retains complete shell framing, but a later parameter-
 * word expansion can concatenate ANSI-C values with neighboring text and form
 * syntax that has no contiguous source span. Semantic consumers fail closed
 * instead of omitting the reconstructed expansion from retained products. */
static const char *const shellsplit_test_ansi_translated_joins[] = {
    "echo \"${0:+$'$'(printf child >&2)}\"",
    "echo \"${0#${0:+<$'(printf child >&2)'}}\"",
    "echo \"${0#${0:+>$'(printf child >&2)'}}\"",
    "echo \"${0:+$'$'$'(printf child >&2)'}\"",
    "echo \"${0:+$'$'$''(printf child >&2)}\"",
    "echo \"${0:+$'$'\"\"(printf child >&2)}\"",
    "echo \"${0:+$'$'\"\"\"\"(printf child >&2)}\"",
    "echo \"${0:+$'$'\"\\\n\"(printf child >&2)}\"",
    "echo \"${0#\"${0:+$'$'\"\"(printf child >&2)}\"}\"",
    "echo \"${0:+$'$'\\\n(printf child >&2)}\"",
    "echo \"${0:+$'$'PATH}\"",
    "echo \"${0:+$'$'0}\"",
    "echo \"${0:+$'$'$'{PATH}'}\"",
    "echo \"${0:+$'$'$'((1 + 2))'}\"",
    "echo \"${0#${0:+$'<'$'(printf child >&2)'}}\"",
    "echo \"${0#${0:+$'>'$'(printf child >&2)'}}\"",
    "echo \"${0:+$'${PATH:-'value}}\"",
    ("cat <<EOF\n${0#${0:+$'$\\0ignored'(printf child >&2)}}\n"
     "EOF\n"),
    ("cat <<EOF\n${0#${0:+$'$'$'\\0ignored'(printf child >&2)}}\n"
     "EOF\n"),
};

/* ANSI decoding precedes parameter-word expansion, even across an inner
 * default. Residues 0 and 3 expose the raw command opener in the second pass;
 * residues 1 and 2 leave it literal. Share both directions with graph, policy
 * and fixed-fuzz tests so discovering phantom children is not an acceptable
 * substitute for discovering the executable ones. */
#define SHELLSPLIT_TEST_ANSI_RUNS(prefix, suffix)                              \
  {prefix suffix, 1, false}, {prefix "\\" suffix, 0, false},                   \
      {prefix "\\\\" suffix, 0, false}, {prefix "\\\\\\" suffix, 1, false},    \
      {prefix "\\\\\\\\" suffix, 1, false},                                    \
      {prefix "\\\\\\\\\\" suffix, 0, false},                                  \
      {prefix "\\\\\\\\\\\\" suffix, 0, false},                                \
      {prefix "\\\\\\\\\\\\\\" suffix, 1, false}, {                            \
    prefix "\\\\\\\\\\\\\\\\" suffix, 1, false                                 \
  }
static const struct {
  const char *source;
  unsigned children;
  bool stdout_to_stderr;
} shellsplit_test_ansi_nested_runs[] = {
    SHELLSPLIT_TEST_ANSI_RUNS("echo \"${v:-$'${w:-", "$(printf child)}'}\""),
    SHELLSPLIT_TEST_ANSI_RUNS("echo \"${v#${u:-$'${w:-",
                              "$(printf child)}'}}\""),
    SHELLSPLIT_TEST_ANSI_RUNS("cat <<EOF\n${v#${u:-$'${w:-",
                              "$(printf child)}'}}\nEOF\n"),
    SHELLSPLIT_TEST_ANSI_RUNS("cat <<EOF\n${v#${u:-$'${w:-",
                              "$(printf child)}\\0$(printf phantom)'}}\nEOF\n"),
    SHELLSPLIT_TEST_ANSI_RUNS("cat <<EOF\n${v#${u:-$'${w:-${x:-",
                              "$(printf child)}}\\0tail'}}\nEOF\n"),
    /* Ordinary ANSI-C fragments are data, not re-expanded parameter words. */
    {"echo ${v#${u:-$'${w:-\\\\\\$(printf child)}'}}", 0, false},
    {"echo \"${v#$'${w:-\\\\\\$(printf child)}'}\"", 0, false},
    /* Executable children remain subjects even without a captured stream. */
    {"echo \"${v#${u:-$'${w:-\\\\\\$(printf child >&2)}'}}\"", 1, true},
    {"cat <<EOF\n${v#${u:-$'${w:-\\\\\\$(printf child >&2)}\\0tail'}}\nEOF\n",
     1, true},
};
#undef SHELLSPLIT_TEST_ANSI_RUNS

/* Expansion phases are not quote states. A heredoc default parsed below an
 * unquoted pattern re-expands ANSI-C text in further unquoted patterns.
 * Explicit enclosing quotes stop that deferred phase. Ordinary-word
 * parsing also admits process children in a default below a shell pattern,
 * but an explicit quote and a direct double-quoted default still suppress
 * them. kind is the raw opener byte, not a duplicate semantic enum. */
#define SHELLSPLIT_TEST_PHASE_RUNS(prefix, suffix, kind)                       \
  {prefix suffix, 1, kind, false}, {prefix "\\" suffix, 0, kind, false},       \
      {prefix "\\\\" suffix, 0, kind, false},                                  \
      {prefix "\\\\\\" suffix, 1, kind, false},                                \
      {prefix "\\\\\\\\" suffix, 1, kind, false},                              \
      {prefix "\\\\\\\\\\" suffix, 0, kind, false},                            \
      {prefix "\\\\\\\\\\\\" suffix, 0, kind, false},                          \
      {prefix "\\\\\\\\\\\\\\" suffix, 1, kind, false}, {                      \
    prefix "\\\\\\\\\\\\\\\\" suffix, 1, kind, false                           \
  }
/* Escapes around a raw child are fragment data, not child-body translation.
 * Keep each position independent so either whole-fragment veto is caught. */
#define SHELLSPLIT_TEST_PHASE_DATA(prefix, child, suffix, children, kind)      \
  {prefix "\\n" child suffix, children, kind, false},                          \
      {prefix "\\t" child suffix, children, kind, false},                      \
      {prefix "\\x61" child suffix, children, kind, false},                    \
      {prefix child "\\n" suffix, children, kind, false},                      \
      {prefix child "\\t" suffix, children, kind, false}, {                    \
    prefix child "\\x61" suffix, children, kind, false                         \
  }
/* Empty quotes remain a boundary in ordinary-word and heredoc operands.
 * Each context includes repeated pairs and a quote containing only a physical
 * continuation; all have zero payload bytes without joining an opener. */
#define SHELLSPLIT_TEST_QUOTE_BOUNDARIES(prefix, suffix, kind)                 \
  {prefix "\"\"" suffix, 0, kind, false},                                      \
      {prefix "\"\"\"\"" suffix, 0, kind, false}, {                            \
    prefix "\"\\\n\"" suffix, 0, kind, false                                   \
  }
#define SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN(opener, closer, kind)           \
  {"cat <<EOF\n${0#\"${0:+${0#$'" opener "printf child >&2" closer             \
   "'}}\"}\nEOF\n",                                                            \
   0, kind, false},                                                            \
  {                                                                            \
    "cat <<EOF\n${0#\"${0:+${0#$'" opener "printf child >&2" closer            \
    "\\0tail'}}\"}\nEOF\n",                                                    \
        0, kind, false                                                         \
  }
/* A pattern reached after an ordinary heredoc parameter word must not regain
 * the deferred expansion phase. Cover alternate and default word ancestry,
 * with and without a fragment-local NUL tail. */
#define SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN(opener, closer, kind)             \
  {"cat <<EOF\n${0:+${0#${0:+$'" opener "printf child >&2" closer              \
   "'}}}\nEOF\n",                                                              \
   0, kind, false},                                                            \
  {                                                                            \
    "cat <<EOF\n${u:-${0#${0:+$'" opener "printf child >&2" closer             \
    "\\0tail'}}}\nEOF\n",                                                      \
        0, kind, false                                                         \
  }
/* An explicit quote before a heredoc pattern must not be recovered by a
 * later default. Literal children and NUL tails remain opaque; raw children
 * and a later sibling's independent deferred phase still contribute subjects.
 */
#define SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE(opener, closer, kind)        \
  {"cat <<EOF\n${0:+\"${0#${0:+$'" opener "printf child >&2" closer            \
   "'}}\"}\nEOF\n",                                                            \
   0, kind, false},                                                            \
      {"cat <<EOF\n${0#\"${0%${0:+$'" opener "printf child >&2" closer         \
       "'}}\"}\nEOF\n",                                                        \
       0, kind, false},                                                        \
      {"cat <<EOF\n${0:+\"${0#${0:+$'" opener "printf child >&2" closer        \
       "\\0tail'}}\"}\nEOF\n",                                                 \
       0, kind, false},                                                        \
      {"cat <<EOF\n${0:+\"${0##${0:+${0%${0:+$'" opener                        \
       "printf child >&2" closer "'}}}}\"}\nEOF\n",                            \
       0, kind, false},                                                        \
      {"cat <<EOF\n${0:+\"${0#${0:+" opener "printf child >&2" closer          \
       "}}\"}\nEOF\n",                                                         \
       1, kind, false},                                                        \
  {                                                                            \
    "cat <<EOF\n${0:+\"${0#${0:+$'" opener "printf literal >&2" closer         \
    "'}}\"}${0#${0:+${0#$'" opener "printf child >&2" closer "'}}}\nEOF\n",    \
        1, kind, false                                                         \
  }
/* Immediate quoting still expands command/backtick children. A quote newly
 * introduced after the pattern establishes that context again; process
 * substitutions remain literal inside either explicit quote. */
#define SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY(opener, closer, kind, children)  \
  {"cat <<EOF\n${0#\"${0:+$'" opener "printf child >&2" closer "'}\"}\nEOF\n", \
   children, kind, false},                                                     \
  {                                                                            \
    "cat <<EOF\n${0:+\"${0#\"${0:+$'" opener "printf child >&2" closer         \
    "'}\"}\"}\nEOF\n",                                                         \
        children, kind, false                                                  \
  }
static const struct {
  const char *source;
  unsigned children;
  char kind;
  bool captured_stdout;
} shellsplit_test_ansi_phase_cases[] = {
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("echo \"${0#${0:+$'$'",
                                     "(printf child >&2)}}\"", '$'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("echo \"${0#${0:+$'<'",
                                     "(printf child >&2)}}\"", '<'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("echo \"${0#${0:+$'>'",
                                     "(printf child >&2)}}\"", '>'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("cat <<EOF\n${0#${0:+$'$'",
                                     "(printf child >&2)}}\nEOF\n", '$'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("cat <<EOF\n${0#${0:+$'<'",
                                     "(printf child >&2)}}\nEOF\n", '<'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("cat <<EOF\n${0#${0:+$'>'",
                                     "(printf child >&2)}}\nEOF\n", '>'),
    SHELLSPLIT_TEST_QUOTE_BOUNDARIES("cat <<EOF\n${0#\"${0:+$'$'",
                                     "(printf child >&2)}\"}\nEOF\n", '$'),
    /* An explicit quote stops deferred expansion into a nested pattern.
     * The existing unquoted counterparts below retain the real children. */
    SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN("$(", ")", '$'),
    SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN("`", "`", '`'),
    SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN("<(", ")", '<'),
    SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN(">(", ")", '>'),
    SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN("$(", ")", '$'),
    SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN("`", "`", '`'),
    SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN("<(", ")", '<'),
    SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN(">(", ")", '>'),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE("$(", ")", '$'),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE("`", "`", '`'),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE("<(", ")", '<'),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE(">(", ")", '>'),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY("$(", ")", '$', 1),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY("`", "`", '`', 1),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY("<(", ")", '<', 0),
    SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY(">(", ")", '>', 0),
    /* Cover the primary/nested active-phase transition: a second pattern is
     * literal until another word operand intervenes. A separately blocked
     * subtree must not affect the direct-pattern phase of a later sibling. */
    {"cat <<EOF\n${0:+${0#${0#${0:+$'$(printf child >&2)'}}}}}\nEOF\n", 0, '$',
     false},
    {"cat <<EOF\n${0#${0:+${0#${0#$'$(printf child >&2)'}}}}\nEOF\n", 0, '$',
     false},
    {"cat <<EOF\n${0#${0:+${0:+${0#$'$(printf child >&2)'}}}}\nEOF\n", 0, '$',
     false},
    {"cat <<EOF\n${0#${0:+${0#${0:+$'$(printf child >&2)'}}}}\nEOF\n", 1, '$',
     false},
    {"cat <<EOF\n${0:+${0#${0:+$'$(printf literal >&2)'}}}"
     "${0#${0:+${0#$'$(printf child >&2)'}}}\nEOF\n",
     1, '$', false},
    /* Popping the quoted operand restores deferred heredoc expansion for
     * the sibling; only its distinct child is an executable subject. */
    {"cat <<EOF\n${0#\"${0:+${0#$'$(printf literal >&2)'}}\"}"
     "${0#${0:+${0#$'$(printf child >&2)'}}}\nEOF\n",
     1, '$', false},
    SHELLSPLIT_TEST_PHASE_RUNS("cat <<EOF\n${0#${0:+${0#$'",
                               "$(printf child >&2)'}}}\nEOF\n", '$'),
    SHELLSPLIT_TEST_PHASE_RUNS(
        "cat <<EOF\n${0#${0:+${0#$'",
        "$(printf child >&2)a\\0$(printf phantom >&2)'}}}\nEOF\n", '$'),
    SHELLSPLIT_TEST_PHASE_RUNS("cat <<EOF\n${0#${0:+${0#$'",
                               "<(printf child >&2)'}}}\nEOF\n", '<'),
    SHELLSPLIT_TEST_PHASE_RUNS("cat <<EOF\n${0#${0:+${0#$'",
                               ">(printf child >&2)'}}}\nEOF\n", '>'),
    SHELLSPLIT_TEST_PHASE_RUNS("echo \"${0#${0:+$'", "<(printf child >&2)'}}\"",
                               '<'),
    SHELLSPLIT_TEST_PHASE_RUNS("echo \"${0#${0:+$'", ">(printf child >&2)'}}\"",
                               '>'),
    SHELLSPLIT_TEST_PHASE_RUNS("cat <<EOF\n${0#${0:+${0#$'${0:+",
                               "$(printf child >&2)}\\0tail'}}}\nEOF\n", '$'),
    {"cat <<EOF\n${0#${0:+${0#$'`printf child >&2`'}}}\nEOF\n", 1, '`', false},
    {"cat <<EOF\n${0#${0:+${0#$'$(printf child)'}}}\nEOF\n", 1, '$', true},
    {"cat <<EOF\n${0#${0:+${0#$'`printf child`'}}}\nEOF\n", 1, '`', true},
    {"echo \"${0#${0:+$'<(printf child)'}}\"", 1, '<', true},
    {"echo \"${0#${0:+$'<(printf child >&2)\\n'}}\"", 1, '<', false},
    {"cat <<EOF\n${0%${u:-${0%%$'$(printf child >&2)'}}}\nEOF\n", 1, '$',
     false},
    {"cat <<EOF\n${0#${u-${0/x/$'`printf child >&2`'}}}\nEOF\n", 1, '`', false},
    {"cat <<EOF\n${0#${0+${0^^$'$(printf child >&2)'}}}\nEOF\n", 1, '$', false},
    /* State restoration and literal controls, without depending on variable
     * values to skip an operand. */
    {"echo ${0#${0:+${0#$'$(printf child >&2)'}}}", 0, '$', false},
    {"echo \"${0#${0:+${0#$'$(printf child >&2)'}}}\"", 0, '$', false},
    {"cat <<EOF\n${0#$'$(printf child >&2)'}\nEOF\n", 0, '$', false},
    {"cat <<EOF\n${0#${0#$'$(printf child >&2)'}}\nEOF\n", 0, '$', false},
    {"echo \"${0:+$'<(printf child >&2)'}\"", 0, '<', false},
    {"echo \"${0#$'<(printf child >&2)\\n'}\"", 0, '<', false},
    {"echo \"${0:+$'<(printf child >&2)\\n'}\"", 0, '<', false},
    {"echo \"${0#\"${0:+$'<(printf child >&2)'}\"}\"", 0, '<', false},
    {"echo \"${0#${0:+\"$'<(printf child >&2)'\"}}\"", 0, '<', false},
    {"cat <<EOF\n${0#${0:+${0#$'a\\0$(printf child >&2)'}}}\nEOF\n", 0, '$',
     false},
    /* Ordinary process words inherit parsing context too, without ANSI-C. */
    {"echo \"${0#${0:+<(printf child >&2)}}\"", 1, '<', false},
    {"cat <<EOF\n${0#${0:+>(printf child >&2)}}\nEOF\n", 1, '>', false},
    {"echo \"${0#${0:+$'${0:+<(printf child >&2)}'}}\"", 1, '<', false},
    {"echo \"${0:+$'${0#<(printf child >&2)}'}\"", 1, '<', false},
    {"echo \"${0#${0:+$'${0:+\"<(printf child >&2)\"}'}}\"", 0, '<', false},
    /* Quotes in the re-expanded value suppress process syntax even without
     * an intervening parameter scope. Real children inside that literal text
     * still expand; use a distinct literal marker to check their raw spans. */
    {"echo \"${0#${0:+$'\"<(printf child >&2)\"'}}\"", 0, '<', false},
    {"echo \"${0#${0:+$'\">(printf child >&2)\"'}}\"", 0, '>', false},
    {"echo \"${0#${0:+$'\"\\<(printf child >&2)\"'}}\"", 0, '<', false},
    {"echo \"${0#${0:+$'\"\\\\<(printf child >&2)\"'}}\"", 0, '<', false},
    {"echo \"${0#${0:+$'\"\\\\\\<(printf child >&2)\"'}}\"", 0, '<', false},
    {"echo \"${0#${0:+$'\"\\\\\\\\<(printf child >&2)\"'}}\"", 0, '<', false},
    {"cat <<EOF\n${0#${0:+$'\"<(printf child >&2)\"'}}\nEOF\n", 0, '<', false},
    {"cat <<EOF\n${0#${0:+$'\">(printf child >&2)\"\\0tail'}}\nEOF\n", 0, '>',
     false},
    {"cat <<EOF\n${0#${0:+${0#$'\"<(printf child >&2)\"\\0tail'}}}\nEOF\n", 0,
     '<', false},
    {"echo \"${0#${0:+$'\"<(printf literal $(printf child >&2))\"'}}\"", 1, '$',
     false},
    {"echo \"${0#${0:+$'\">(printf literal `printf child >&2`)\"'}}\"", 1, '`',
     false},
    {"cat <<EOF\n${0#${0:+$'\"<(printf literal $(printf child))\"\\0tail'}}\n"
     "EOF\n",
     1, '$', true},
    {"echo \"${0#${0:+$'\"<(printf literal)\"<(printf child >&2)'}}\"", 1, '<',
     false},
    {"cat <<EOF\n${0#${0:+$'\">(printf literal)\">(printf child >&2)'}}\n"
     "EOF\n",
     1, '>', false},
    {"echo \"${0#${0:+$'\"${0:+<(printf child >&2)}\"'}}\"", 0, '<', false},
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0:+$'", "$(printf child >&2)", "'}\"",
                               1, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0:+$'", "`printf child >&2`", "'}\"",
                               1, '`'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0#${0:+$'", "$(printf child >&2)",
                               "'}}\"", 1, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0#${0:+$'", "`printf child >&2`",
                               "'}}\"", 1, '`'),
    SHELLSPLIT_TEST_PHASE_DATA("cat <<EOF\n${0#${0:+${0#$'",
                               "$(printf child >&2)", "'}}}\nEOF\n", 1, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("cat <<EOF\n${0#${0:+${0#$'",
                               "`printf child >&2`", "'}}}\nEOF\n", 1, '`'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0:+$'", "${0:+$(printf child >&2)}",
                               "'}\"", 1, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0#$'", "$(printf child >&2)", "'}\"",
                               0, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("echo \"${0#$'", "`printf child >&2`", "'}\"", 0,
                               '`'),
    SHELLSPLIT_TEST_PHASE_DATA("echo ${0#${0:+${0#$'", "$(printf child >&2)",
                               "'}}}", 0, '$'),
    SHELLSPLIT_TEST_PHASE_DATA("echo ${0#${0:+${0#$'", "`printf child >&2`",
                               "'}}}", 0, '`'),
    {"echo \"${0:+$'\\n$(printf child)\\t'}\"", 1, '$', true},
    {"cat <<EOF\n${0#${0:+${0#$'\\t`printf child`\\x61'}}}\nEOF\n", 1, '`',
     true},
    /* Protective escaping and whitespace prevent cross-fragment expansion
     * openers and remain ordinary literal parameter-word data. */
    {"echo \"${0:+$'\\$'(printf child >&2)}\"", 0, '$', false},
    {"echo \"${0:+$'$' (printf child >&2)}\"", 0, '$', false},
};
#undef SHELLSPLIT_TEST_PHASE_DATA
#undef SHELLSPLIT_TEST_PHASE_RUNS
#undef SHELLSPLIT_TEST_QUOTE_BOUNDARIES
#undef SHELLSPLIT_TEST_QUOTED_HEREDOC_PATTERN
#undef SHELLSPLIT_TEST_HEREDOC_WORD_PATTERN
#undef SHELLSPLIT_TEST_HEREDOC_QUOTE_INHERITANCE
#undef SHELLSPLIT_TEST_HEREDOC_QUOTE_REENTRY

#endif
