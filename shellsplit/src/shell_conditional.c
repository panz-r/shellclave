#include "shell_conditional_internal.h"
#include "shell_source_internal.h"
#include <string.h>

/* Newlines/comments are grammar trivia before a primary, after lexical !,
 * and after an explicit unary operand. A unary operator needs its operand
 * immediately; a bare operand needs the following token without a newline.
 * Blanks and escaped line continuations are removed in every position. */
static SHELL_NONNULL(1) size_t
    trivia(const char *s, size_t n, size_t p, bool lines) {
  for (;;) {
    p = shell_source_skip_escaped_line_endings(s, n, p);
    if (p == n)
      return p;
    if (shell_source_blank((unsigned char)s[p]) || (lines && s[p] == '\n')) {
      ++p;
      continue;
    }
    if (lines && s[p] == '#') {
      p = shell_source_line_end(s, n, p);
      continue;
    }
    return p;
  }
}

static SHELL_NONNULL(1, 5) bool plain(const char *s, size_t n, size_t p,
                                      size_t end, const char *text) {
  size_t after;
  return shell_source_match_plain_word(s, n, p, text, strlen(text), &after) &&
         after == end;
}

static SHELL_NONNULL(1, 4) bool close_at(const char *s, size_t n, size_t p,
                                         size_t *after) {
  if (!shell_source_match_logical_punctuation(s, n, p, "]]", after))
    return false;
  size_t next = shell_source_skip_escaped_line_endings(s, n, *after);
  return next == n || shell_source_space((unsigned char)s[next]) ||
         strchr(";|&()<>", s[next]);
}

shell_conditional_t shell_conditional_parse(const char *s, size_t n,
                                            size_t start) {
  shell_conditional_t r = {0};
  size_t p;
  if (!shell_source_match_logical_punctuation(s, n, start, "[[", &p))
    return r;
  p = shell_source_skip_escaped_line_endings(s, n, p);
  /* Received [[ can still acquire a suffix and name an ordinary executable. */
  if (p == n ||
      (!shell_source_space((unsigned char)s[p]) && !strchr(";|&()<>", s[p])))
    return r;
  r.content = p;
  r.end = r.after = n;
  r.frame = SHELL_CONDITIONAL_INCOMPLETE;
  p = trivia(s, n, p, true);
  size_t end = p, after;
  while (p < n) {
    if (close_at(s, n, p, &after)) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      r.end = p;
      r.after = after;
      return r;
    }
    if (s[p] == '(') {
      r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
      return r;
    }
    r.operand = p;
    r.operand_length = n - p;
    if (!shell_source_skip_shell_word_impl(s, n, p, &end, true))
      return r;
    if (end == p) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      return r;
    }
    if (!plain(s, n, p, end, "!"))
      break;
    r.operand = r.operand_length = 0;
    r.negated = !r.negated;
    p = trivia(s, n, end, true);
  }
  if (p == n)
    return r;
  bool unary = plain(s, n, p, end, "-n") || plain(s, n, p, end, "-z");
  if (unary) {
    r.empty = plain(s, n, p, end, "-z");
    r.operand = r.operand_length = 0;
    p = trivia(s, n, end, false);
    if (p == n)
      return r;
    if (s[p] == '\n' || s[p] == '#' || close_at(s, n, p, &after)) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      return r;
    }
    r.operand = p;
    r.operand_length = n - p;
    if (!shell_source_skip_shell_word_impl(s, n, p, &end, true))
      return r;
    if (end == p) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      return r;
    }
  } else {
    /* Reserved unary operators use logical spelling too. An escaped newline
     * cannot turn an unsupported predicate into a supported bare string. */
    for (const char *letter = "abcdefghkLoOprRsStuvwxGN"; *letter; ++letter) {
      const char operator_word[] = {'-', *letter, 0};
      if (plain(s, n, p, end, operator_word)) {
        r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
        return r;
      }
    }
  }
  r.operand = p;
  r.operand_length = end - p;
  p = trivia(s, n, end, unary);
  if (p == n)
    return r;
  if (close_at(s, n, p, &after)) {
    r.frame = SHELL_CONDITIONAL_COMPLETE;
    r.end = p;
    r.after = after;
    return r;
  }
  /* Recognized wider grammar has no supported truth judgment. Do not label
   * regex/pattern syntax invalid using the unary string grammar. */
  if (strchr("=&|<>()", s[p]) || s[p] == '!')
    r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
  else if (s[p] == '-' && p + 1 < n)
    r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
  else
    r.frame = SHELL_CONDITIONAL_INVALID;
  return r;
}

static SHELL_NONNULL(2) bool count_byte(unsigned char byte, void *context) {
  (void)byte;
  *(bool *)context = false;
  return true;
}

bool shell_conditional_word_dynamic(const char *word, size_t length) {
  /* The common dynamic-argument classifier also includes pathname and brace
   * expansion. Conditional words instead care only about active expansions
   * and an unquoted leading tilde. */
  shell_source_substitution_scan_t scan = {0};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  while (shell_source_next_executable_substitution(word, length, &scan, &start,
                                                   &after, &kind) ==
         SHELL_SOURCE_SCAN_FOUND)
    return true;
  size_t leading = shell_source_skip_escaped_line_endings(word, length, 0);
  return scan.has_variables || scan.has_arithmetic ||
         (leading < length && word[leading] == '~');
}

bool shell_conditional_static_empty(const char *word, size_t length,
                                    bool *empty) {
  *empty = true;
  return !shell_conditional_word_dynamic(word, length) &&
         shell_source_visit_decoded_word(word, length, count_byte, empty);
}
