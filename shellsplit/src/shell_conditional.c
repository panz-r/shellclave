#include "shell_conditional_internal.h"
#include "shell_source_internal.h"
#include "shell_test_internal.h"
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

/* Keep fully quoted RHSs on their existing admission path. Mixed dynamic
 * words need the additional outer-fragment proof in literal_dynamic_rhs. */
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

typedef struct {
  unsigned char byte;
  bool star;
} pattern_unit_t;

/* Source spelling includes quote/operator delimiters, covering the fixed
 * alignment padding in addition to these per-byte value reservations. */
_Static_assert(sizeof(pattern_unit_t) + sizeof(size_t) + 1 <=
                   SHELL_SOURCE_VALUE_SCRATCH_FACTOR,
               "conditional values must fit source scratch sizing");

/* units is NULL during measurement, which determines the required capacity.
 * Before emission, checked scratch reservations validate allocation arithmetic
 * and available space; units then has room for the measured projection.
 * Adjacent active stars collapse even across empty quoted fragments. */
typedef struct {
  pattern_unit_t *units;
  size_t length, run, max_run;
  bool has_star, previous_star;
} pattern_builder_t;

static SHELL_NONNULL(3) bool pattern_byte(unsigned char byte, bool quoted,
                                          void *context) {
  SHELL_SOURCE_WORD_SCAN(1);
  pattern_builder_t *builder = context;
  bool star = byte == '*' && !quoted;
  if (star && builder->previous_star)
    return true;
  if (builder->units)
    builder->units[builder->length] = (pattern_unit_t){byte, star};
  builder->length++;
  builder->has_star |= star;
  builder->previous_star = star;
  builder->run = star ? 0 : builder->run + 1;
  if (builder->run > builder->max_run)
    builder->max_run = builder->run;
  return true;
}

/* This admission boundary accepts only literal bytes and active stars.
 * Unquoted parentheses belong to wider extglob syntax in a complete word;
 * quoted/escaped pattern metacharacters are ordinary literal bytes. */
static SHELL_NONNULL(3) bool admit_pattern_byte(unsigned char byte, bool quoted,
                                                void *context) {
  if (!quoted && (byte == '?' || byte == '[' || byte == '(' || byte == ')'))
    return false;
  return pattern_byte(byte, quoted, context);
}

/* Admission of a preframed dynamic RHS requires quoted expansions and literal
 * outer fragments. Source classification supplies the expansion fact; this
 * conditional-specific walk excludes active pattern syntax. Skip complete
 * quotes through source framing: quotes and pattern bytes inside a nested
 * parameter/command belong to that expansion, not the outer RHS. Static
 * patterns retain their separate quote-aware projection below. */
static SHELL_NONNULL(1) bool literal_dynamic_rhs(const char *word,
                                                 size_t length) {
  if (shell_source_conditional_unquoted_expansion(word, length))
    return false;
  for (size_t p = 0; p < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    size_t after;
    if (word[p] == '$' &&
        shell_source_logical_next_is(word, length, p, '\'', NULL)) {
      if (!shell_source_skip_complete_ansi_c_quote(word, length, p, &after))
        return false;
      p = after;
    } else if (word[p] == '\'' || word[p] == '"') {
      if (!shell_source_skip_complete_quoted_text(word, length, p, word[p],
                                                  &after))
        return false;
      p = after;
    } else if ((word[p] == '<' || word[p] == '>') &&
               shell_source_empty_process_fragment(word, length, p, &after)) {
      p = after;
    } else {
      char quote = 0;
      unsigned char byte;
      bool protected_byte;
      if (shell_word_literal_step(word, length, &p, &quote, &byte,
                                  &protected_byte) &&
          !protected_byte && strchr("*?[()", byte))
        return false;
    }
  }
  return true;
}

static SHELL_NONNULL(1, 5) bool comparison_rhs(
    const char *s, size_t n, size_t p, size_t end,
    shell_conditional_predicate_t *predicate) {
  if (quoted_rhs(s, n, p, end))
    return true;
  if (shell_conditional_word_dynamic(s + p, end - p))
    return literal_dynamic_rhs(s + p, end - p);
  pattern_builder_t builder = {0};
  if (!shell_source_visit_quoted_word(s + p, end - p, admit_pattern_byte,
                                      &builder))
    return false;
  if (builder.has_star)
    *predicate = *predicate == SHELL_CONDITIONAL_STRING_NOT_EQUAL
                     ? SHELL_CONDITIONAL_PATTERN_NOT_MATCH
                     : SHELL_CONDITIONAL_PATTERN_MATCH;
  return true;
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
  bool variable = plain(s, n, p, end, "-v");
  bool unary =
      variable || plain(s, n, p, end, "-n") || plain(s, n, p, end, "-z");
  r.predicate = SHELL_CONDITIONAL_STRING_NONEMPTY;
  if (unary) {
    if (variable)
      r.predicate = SHELL_CONDITIONAL_VARIABLE_SET;
    else if (plain(s, n, p, end, "-z"))
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
    if (variable) {
      if (!shell_test_static_scalar(s + p, end - p)) {
        r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
        return r;
      }
    }
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
      if (!comparison_rhs(s, n, p, end, &r.predicate)) {
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

/* Precompiled units contain at least one star. prefix has max_run entries.
 * data may be NULL only for an empty subject. Anchored ends reserve disjoint
 * bytes; KMP finds each interior literal run at its earliest remaining match.
 * Each subject byte is searched at most once across runs, with linear KMP
 * fallback work. No locale state, recursion or wildcard backtracking is used.
 */
static SHELL_NONNULL(1, 5) bool match_pattern(const pattern_unit_t *units,
                                              size_t count, const char *data,
                                              size_t length, size_t *prefix) {
  size_t first = 0, last = count;
  while (!units[first].star)
    first++;
  while (!units[last - 1].star)
    last--;
  size_t suffix = count - last;
  if (first > length || suffix > length - first)
    return false;
  for (size_t i = 0; i < first; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (units[i].byte != (unsigned char)data[i])
      return false;
  }
  size_t stop = length - suffix;
  for (size_t i = 0; i < suffix; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (units[last + i].byte != (unsigned char)data[stop + i])
      return false;
  }
  size_t cursor = first;
  for (size_t run = first + 1; run < last - 1;) {
    size_t end = run;
    while (!units[end].star)
      end++;
    size_t size = end - run;
    prefix[0] = 0;
    for (size_t i = 1, matched = 0; i < size; ++i) {
      SHELL_SOURCE_WORD_SCAN(1);
      while (matched && units[run + i].byte != units[run + matched].byte) {
        SHELL_SOURCE_WORD_SCAN(1);
        matched = prefix[matched - 1];
      }
      if (units[run + i].byte == units[run + matched].byte)
        matched++;
      prefix[i] = matched;
    }
    size_t matched = 0;
    while (cursor < stop && matched < size) {
      SHELL_SOURCE_WORD_SCAN(1);
      unsigned char byte = (unsigned char)data[cursor++];
      while (matched && byte != units[run + matched].byte) {
        SHELL_SOURCE_WORD_SCAN(1);
        matched = prefix[matched - 1];
      }
      if (byte == units[run + matched].byte)
        matched++;
    }
    if (matched != size)
      return false;
    run = end + 1;
  }
  return true;
}

/* condition supplies an admitted static star pattern. The enclosing operation
 * releases all temporary storage at its saved mark, including on failure. */
static SHELL_NONNULL(1, 2, 3, 4) bool evaluate_pattern(
    const char *source, const shell_conditional_t *condition,
    const shell_conditional_value_t *left, bool *matched) {
  const char *word = source + condition->operands[1];
  size_t length = condition->operand_lengths[1];
  pattern_builder_t measure = {0};
  if (!shell_source_visit_quoted_word(word, length, pattern_byte, &measure))
    return false;
  /* Check each array reservation before emitting measured units. Callers may
   * supply less scratch than the source workspace's sufficient size bound. */
  pattern_unit_t *units = shell_source_scratch_take_array(
      measure.length, sizeof(pattern_unit_t), _Alignof(pattern_unit_t));
  if (!units)
    return false;
  size_t *prefix = shell_source_scratch_take_array(
      measure.max_run, sizeof(size_t), _Alignof(size_t));
  if (!prefix)
    return false;
  pattern_builder_t build = {.units = units};
  if (!shell_source_visit_quoted_word(word, length, pattern_byte, &build))
    return false;
  shell_conditional_value_t subject = *left;
  if (!subject.known) {
    word = source + condition->operands[0];
    length = condition->operand_lengths[0];
    subject.length = 0;
    if (!shell_source_visit_decoded_word(word, length, measure_byte,
                                         &subject.length))
      return false;
    unsigned char *bytes = shell_source_scratch_take(subject.length);
    if (!bytes)
      return false;
    subject.data = (const char *)bytes;
    if (!shell_source_visit_decoded_word(word, length, write_byte, &bytes))
      return false;
  }
  *matched =
      match_pattern(units, build.length, subject.data, subject.length, prefix);
  return true;
}

bool shell_conditional_evaluate(const char *source,
                                const shell_conditional_t *condition,
                                const shell_conditional_value_t values[2],
                                bool *truth) {
  if (condition->predicate == SHELL_CONDITIONAL_VARIABLE_SET)
    return false; /* Presence is a path-local graph fact, not a string value. */
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
  if (shell_conditional_pattern(condition->predicate)) {
    bool matched;
    bool known = evaluate_pattern(source, condition, &values[0], &matched);
    shell_source_scratch_release(mark);
    if (known)
      *truth = (matched != (condition->predicate ==
                            SHELL_CONDITIONAL_PATTERN_NOT_MATCH)) !=
               condition->negated;
    return known;
  }
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
