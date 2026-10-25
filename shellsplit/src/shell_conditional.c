#include "shell_conditional_internal.h"
#include "shell_source_internal.h"
#include <string.h>

/* Newlines/comments are grammar trivia before a primary, after lexical !,
 * and after an explicit unary or binary predicate. An operator needs its
 * operand immediately; a bare operand needs the following token without a
 * newline. Blanks and escaped line continuations are removed in every position.
 */
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

typedef enum {
  CONDITIONAL_TOKEN_NONE,
  CONDITIONAL_TOKEN_COMPLETE,
  CONDITIONAL_TOKEN_PREFIX,
} conditional_token_t;

/* Match an expected unquoted grammar token at p <= n in immutable s[0..n).
 * after is written only for COMPLETE. Continuations are removed logically;
 * a final backslash may still acquire LF. PREFIX requires received EOF before
 * the expected spelling or its boundary is committed. Blanks, quotes and
 * other mismatching bytes cannot be repaired by appending. The caller owns
 * grammar eligibility and whether this source boundary permits appending. */
static SHELL_NONNULL(1, 4, 5) conditional_token_t
    token_at(const char *s, size_t n, size_t p, const char *expected,
             size_t *after) {
  for (; *expected; ++expected) {
    size_t next = shell_source_skip_escaped_line_endings(s, n, p);
    SHELL_SOURCE_WORD_SCAN(next - p + 1);
    p = next;
    if (p == n || (p + 1 == n && s[p] == '\\'))
      return CONDITIONAL_TOKEN_PREFIX;
    if (s[p++] != *expected)
      return CONDITIONAL_TOKEN_NONE;
  }
  size_t next = shell_source_skip_escaped_line_endings(s, n, p);
  SHELL_SOURCE_WORD_SCAN(next - p + 1);
  if (next + 1 == n && s[next] == '\\')
    return CONDITIONAL_TOKEN_PREFIX;
  if (next == n || shell_source_space((unsigned char)s[next]) ||
      strchr(";|&()<>", s[next])) {
    *after = p;
    return CONDITIONAL_TOKEN_COMPLETE;
  }
  return CONDITIONAL_TOKEN_NONE;
}

/* This increment admits only RHS words made entirely from quoted fragments.
 * Empty quotes count; continuations between fragments contribute no bytes.
 * An unquoted fragment remains outside the model even if it has no wildcard.
 * Framing has already established a complete shell word. */
static SHELL_NONNULL(1) bool quoted_rhs(const char *s, size_t n, size_t p,
                                        size_t end) {
  bool quoted = false;
  while ((p = shell_source_skip_escaped_line_endings(s, end, p)) < end) {
    size_t after;
    if (s[p] == '$' && shell_source_logical_next_is(s, end, p, '\'', NULL)) {
      if (!shell_source_skip_complete_ansi_c_quote(s, n, p, &after))
        return false;
    } else if (s[p] == '\'' || s[p] == '"') {
      if (!shell_source_skip_complete_quoted_text(s, n, p, s[p], &after))
        return false;
    } else
      return false;
    quoted = true;
    p = after;
  }
  return quoted;
}

/* Capture even an unfinished operand so draft collection can retain its
 * received executable children. Successful framing refines its exact span. */
static SHELL_NONNULL(1, 5, 6) bool operand(const char *s, size_t n, size_t p,
                                           unsigned index,
                                           shell_conditional_t *r,
                                           size_t *end) {
  r->operand_count = (uint8_t)(index + 1);
  r->operands[index] = p;
  r->operand_lengths[index] = n - p;
  if (!shell_source_skip_shell_word_impl(s, n, p, end, true))
    return false;
  if (*end == p) {
    r->frame = SHELL_CONDITIONAL_INVALID;
    return false;
  }
  r->operand_lengths[index] = *end - p;
  return true;
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
    if (token_at(s, n, p, "]]", &after) == CONDITIONAL_TOKEN_COMPLETE) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      r.end = p;
      r.after = after;
      return r;
    }
    if (s[p] == '(') {
      r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
      return r;
    }
    if (!operand(s, n, p, 0, &r, &end))
      return r;
    if (!plain(s, n, p, end, "!"))
      break;
    r.operand_count = 0;
    r.operands[0] = r.operand_lengths[0] = 0;
    r.negated = !r.negated;
    p = trivia(s, n, end, true);
  }
  if (p == n)
    return r;
  bool unary = plain(s, n, p, end, "-n") || plain(s, n, p, end, "-z");
  r.predicate = SHELL_CONDITIONAL_STRING_NONEMPTY;
  if (unary) {
    if (plain(s, n, p, end, "-z"))
      r.predicate = SHELL_CONDITIONAL_STRING_EMPTY;
    r.operand_count = 0;
    r.operands[0] = r.operand_lengths[0] = 0;
    p = trivia(s, n, end, false);
    if (p == n)
      return r;
    if (s[p] == '\n' || s[p] == '#' ||
        token_at(s, n, p, "]]", &after) == CONDITIONAL_TOKEN_COMPLETE) {
      r.frame = SHELL_CONDITIONAL_INVALID;
      return r;
    }
    if (!operand(s, n, p, 0, &r, &end))
      return r;
  } else {
    /* Bash gives lexical unary operators precedence over a possible binop. */
    for (const char *letter = "abcdefghkLoOprRsStuvwxGN"; *letter; ++letter) {
      const char operator_word[] = {'-', *letter, 0};
      if (plain(s, n, p, end, operator_word)) {
        r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
        return r;
      }
    }
  }
  p = trivia(s, n, end, unary);
  if (p == n)
    return r;
  conditional_token_t closer = token_at(s, n, p, "]]", &after);
  if (closer == CONDITIONAL_TOKEN_PREFIX)
    return r;
  if (!unary && s[p] != '\n' && s[p] != '#' &&
      closer != CONDITIONAL_TOKEN_COMPLETE) {
    static const char *const operators[] = {"=", "==", "!="};
    for (unsigned op = 0; op < sizeof(operators) / sizeof(operators[0]); ++op) {
      size_t operator_end;
      conditional_token_t operator_token =
          token_at(s, n, p, operators[op], &operator_end);
      if (operator_token == CONDITIONAL_TOKEN_PREFIX)
        return r;
      if (operator_token != CONDITIONAL_TOKEN_COMPLETE)
        continue;
      r.predicate = op == 2 ? SHELL_CONDITIONAL_STRING_NOT_EQUAL
                            : SHELL_CONDITIONAL_STRING_EQUAL;
      p = trivia(s, n, operator_end, false);
      if (p == n)
        return r;
      if (s[p] == '\n' || s[p] == '#' ||
          token_at(s, n, p, "]]", &after) == CONDITIONAL_TOKEN_COMPLETE) {
        r.frame = SHELL_CONDITIONAL_INVALID;
        return r;
      }
      if (!operand(s, n, p, 1, &r, &end))
        return r;
      if (!quoted_rhs(s, n, p, end)) {
        r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
        return r;
      }
      p = trivia(s, n, end, true);
      if (p == n)
        return r;
      closer = token_at(s, n, p, "]]", &after);
      break;
    }
  }
  if (closer == CONDITIONAL_TOKEN_PREFIX)
    return r;
  if (closer == CONDITIONAL_TOKEN_COMPLETE) {
    r.frame = SHELL_CONDITIONAL_COMPLETE;
    r.end = p;
    r.after = after;
    return r;
  }
  /* Wider grammar is unsupported without a Bash-validity judgment. */
  if (strchr("=&|<>()", s[p]) || s[p] == '!' || (s[p] == '-' && p + 1 < n))
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
  return shell_source_word_has_dynamic_syntax_in_context(
      word, length, SHELL_SOURCE_WORD_CONDITIONAL);
}

bool shell_conditional_static_empty(const char *word, size_t length,
                                    bool *empty) {
  *empty = true;
  return !shell_conditional_word_dynamic(word, length) &&
         shell_source_visit_decoded_word(word, length, count_byte, empty);
}

static SHELL_NONNULL(2) bool measure_byte(unsigned char byte, void *context) {
  (void)byte;
  ++*(size_t *)context;
  return true;
}

static SHELL_NONNULL(2) bool write_byte(unsigned char byte, void *context) {
  *(*(unsigned char **)context)++ = byte;
  return true;
}

typedef struct {
  const char *data;
  size_t length, position;
  bool equal;
} comparison_t;

static SHELL_NONNULL(2) bool compare_byte(unsigned char byte, void *context) {
  comparison_t *comparison = context;
  if (comparison->position >= comparison->length ||
      byte != (unsigned char)comparison->data[comparison->position])
    comparison->equal = false;
  ++comparison->position;
  return true;
}

bool shell_conditional_evaluate(const char *source,
                                const shell_conditional_t *condition,
                                const shell_conditional_value_t values[2],
                                bool *truth) {
  bool unary = condition->operand_count == 1;
  if (unary) {
    bool empty;
    if (values[0].known)
      empty = values[0].length == 0;
    else if (!shell_conditional_static_empty(source + condition->operands[0],
                                             condition->operand_lengths[0],
                                             &empty))
      return false;
    *truth =
        (empty == (condition->predicate == SHELL_CONDITIONAL_STRING_EMPTY)) !=
        condition->negated;
    return true;
  }
  for (unsigned i = 0; i < 2; ++i)
    if (!values[i].known &&
        shell_conditional_word_dynamic(source + condition->operands[i],
                                       condition->operand_lengths[i]))
      return false;
  size_t mark = shell_source_scratch_mark();
  unsigned stored = values[0].known ? 0 : 1;
  shell_conditional_value_t value = values[stored];
  if (!value.known) {
    const char *word = source + condition->operands[stored];
    size_t length = condition->operand_lengths[stored];
    value.length = 0;
    if (!shell_source_visit_decoded_word(word, length, measure_byte,
                                         &value.length))
      return false;
    unsigned char *bytes = shell_source_scratch_take(value.length);
    if (!bytes)
      return false;
    value.data = (const char *)bytes;
    if (!shell_source_visit_decoded_word(word, length, write_byte, &bytes)) {
      shell_source_scratch_release(mark);
      return false;
    }
  }
  unsigned other = 1 - stored;
  bool equal;
  if (values[other].known)
    equal = value.length == values[other].length &&
            (!value.length ||
             !memcmp(value.data, values[other].data, value.length));
  else {
    comparison_t comparison = {value.data, value.length, 0, true};
    if (!shell_source_visit_decoded_word(source + condition->operands[other],
                                         condition->operand_lengths[other],
                                         compare_byte, &comparison)) {
      shell_source_scratch_release(mark);
      return false;
    }
    equal = comparison.equal && comparison.position == value.length;
  }
  shell_source_scratch_release(mark);
  *truth =
      (equal != (condition->predicate == SHELL_CONDITIONAL_STRING_NOT_EQUAL)) !=
      condition->negated;
  return true;
}
