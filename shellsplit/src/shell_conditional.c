#include "shell_conditional_internal.h"
#include "shell_source_internal.h"
#include "shell_test_grammar_internal.h"
#include "shell_word_decode_internal.h"
#include "shell_word_internal.h"
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define FILE_ORDINAL(kind, name, ordinal, spelling, alias)                     \
  _Static_assert(SHELL_CONDITIONAL_FILE_##kind ==                              \
                     SHELL_CONDITIONAL_FILE_EXISTS + ordinal,                  \
                 "conditional filesystem predicate ordinal");
SHELL_FILE_PREDICATES(FILE_ORDINAL)
#undef FILE_ORDINAL

#define COMPARISON_ORDINAL(kind, name, ordinal, spelling)                      \
  _Static_assert(SHELL_CONDITIONAL_FILE_##kind ==                              \
                     SHELL_CONDITIONAL_FILE_NEWER + ordinal,                   \
                 "binary filesystem predicate ordinal");
SHELL_FILE_COMPARISONS(COMPARISON_ORDINAL)
#undef COMPARISON_ORDINAL

#define NUMERIC_ORDINAL(kind, spelling)                                        \
  _Static_assert(SHELL_CONDITIONAL_NUMERIC_##kind ==                           \
                     SHELL_CONDITIONAL_NUMERIC_EQUAL + SHELL_NUMERIC_##kind -  \
                         SHELL_NUMERIC_EQUAL,                                  \
                 "conditional numeric comparison mapping");
SHELL_NUMERIC_COMPARISONS(NUMERIC_ORDINAL)
#undef NUMERIC_ORDINAL

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

#define COMPARISON_SPELLING(kind, name, ordinal, spelling) , spelling
static const char *const binary_operators[] = {
    "=", "==",
    "!=" SHELL_FILE_COMPARISONS(COMPARISON_SPELLING)
#define NUMERIC_SPELLING(kind, spelling) , spelling
        SHELL_NUMERIC_COMPARISONS(NUMERIC_SPELLING)
#undef NUMERIC_SPELLING
};
#undef COMPARISON_SPELLING

/* This error boundary follows a primary with no legal supported operator here.
 * Recognize complete supported words with the same lexical rules as admission;
 * quoted words and concatenated substitutions are not lexical operators. Wider
 * grammar remains unsupported without a Bash-validity judgment. */
static SHELL_NONNULL(1) bool misplaced_supported_operator(const char *s,
                                                          size_t n, size_t p) {
  if (s[p] == '(')
    return true;
  size_t end;
  if (!shell_source_skip_shell_word_impl(s, n, p, &end, true))
    return false;
  for (unsigned op = 0;
       op < sizeof(binary_operators) / sizeof(binary_operators[0]); ++op)
    if (plain(s, n, p, end, binary_operators[op]))
      return true;
#define FILE_OPERATOR(kind, name, ordinal, spelling, alias)                    \
  if (plain(s, n, p, end, spelling) ||                                         \
      (spelling[1] != alias[1] && plain(s, n, p, end, alias)))                 \
    return true;
  SHELL_FILE_PREDICATES(FILE_OPERATOR)
#undef FILE_OPERATOR
  return plain(s, n, p, end, "-n") || plain(s, n, p, end, "-z") ||
         plain(s, n, p, end, "-v") || plain(s, n, p, end, "-t") ||
         plain(s, n, p, end, "!");
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

typedef struct {
  shell_arithmetic_reference_fn visitor;
  void *context;
  bool exhausted;
} condition_parameter_visitor_t;

/* name is a borrowed readable span of length bytes. context points to a live
 * collector; its forwarded visitor context retains the visitor's contract. */
static SHELL_NONNULL(1, 3) void condition_parameter(const char *name,
                                                    size_t length,
                                                    void *context) {
  condition_parameter_visitor_t *state = context;
  size_t bytes = 0;
  for (size_t p = 0; p < length;) {
    p = shell_source_skip_escaped_line_endings(name, length, p);
    if (p < length) {
      ++bytes;
      ++p;
    }
  }
  if (bytes != length) {
    char *decoded = shell_source_scratch_take(bytes);
    if (!decoded) {
      state->exhausted = true;
      return;
    }
    size_t written = 0;
    for (size_t p = 0; p < length;) {
      p = shell_source_skip_escaped_line_endings(name, length, p);
      if (p < length)
        decoded[written++] = name[p++];
    }
    name = decoded;
  }
  state->visitor(name, bytes, state->context);
}

bool shell_conditional_visit_parameters(const char *word, size_t length,
                                        shell_arithmetic_reference_fn visitor,
                                        void *context) {
  condition_parameter_visitor_t state = {visitor, context, false};
  shell_source_substitution_scan_t scan = {
      .parameter_visitor = condition_parameter, .parameter_context = &state};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  do {
    status = shell_source_next_word_expansion(word, length, &scan, &start,
                                              &after, &kind);
  } while (status == SHELL_SOURCE_SCAN_FOUND && !state.exhausted);
  return status == SHELL_SOURCE_SCAN_DONE && !state.exhausted;
}

/* Project active literal arithmetic expansions before interpreting the final
 * value. The original fragment cursor owns quote protection; decoded dollars
 * are data and never re-enter expansion recognition. word is a readable span
 * of length bytes; sink is initialized and unknown is writable. A NULL sink
 * destination selects measurement; the sink itself remains required. */
static SHELL_NONNULL(1, 3, 4) bool arithmetic_word(const char *word,
                                                   size_t length,
                                                   decoded_word_sink_t *sink,
                                                   bool *unknown) {
  char quote = 0;
  for (size_t i = 0; i < length;) {
    size_t open, after;
    if (!quote && word[i] == '$' &&
        shell_source_logical_next_is(word, length, i, '\'', NULL)) {
      if (ansi_decode_quote(word, length, &i, sink, SHELL_SOURCE_ANSI_WORD) !=
          SHELL_PROCESS_OK)
        return false;
      continue;
    }
    if (quote != '\'' && word[i] == '$' &&
        shell_source_dollar_arithmetic_open(word, length, i, &open)) {
      if (!shell_source_skip_arithmetic_expansion(word, length, i, &after))
        return false;
      size_t close = after - 2;
      while (close > open + 1 && word[close] != ')')
        --close;
      shell_arithmetic_result_t value =
          shell_arithmetic_analyze(word + open + 1, close - open - 1);
      if (!value.supported)
        return false;
      if (!value.known) {
        *unknown = true;
        return true;
      }
      char number[32];
      int count = snprintf(number, sizeof(number), "%" PRId64, value.value);
      for (int j = 0; j < count; ++j)
        if (decoded_word_emit(sink, (unsigned char)number[j]) !=
            SHELL_PROCESS_OK)
          return false;
      i = after;
      continue;
    }
    if (quote != '\'' &&
        ((word[i] == '$' &&
          (shell_source_skip_variable_expansion(word, length, i, &after) ||
           shell_source_dollar_parentheses_open(word, length, i, &open))) ||
         word[i] == '`')) {
      *unknown = true;
      return true;
    }
    unsigned char byte;
    bool protected_byte;
    if (shell_word_literal_step(word, length, &i, &quote, &byte,
                                &protected_byte) &&
        decoded_word_emit(sink, byte) != SHELL_PROCESS_OK)
      return false;
  }
  return true;
}

shell_arithmetic_scalar_result_t shell_conditional_arithmetic_operand(
    const char *word, size_t length, const char *value, size_t value_length,
    bool resolved, shell_arithmetic_reference_fn visitor, void *context) {
  if (resolved)
    return shell_arithmetic_analyze_scalar(value ? value : "", value_length,
                                           visitor, context);
  /* Tilde expansion precedes arithmetic interpretation. Its raw spelling
   * cannot prove complement or publish guessed scalar reads. */
  if (shell_source_conditional_has_tilde_expansion(word, length))
    return (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                              .unresolved = true};
  bool dynamic = shell_conditional_word_dynamic(word, length);
  size_t mark = shell_source_scratch_mark();
  decoded_word_sink_t measure = {0};
  bool unknown = false;
  if (!arithmetic_word(word, length, &measure, &unknown))
    return (shell_arithmetic_scalar_result_t){0};
  if (unknown) {
    /* A standalone pure expansion still has only numerical uncertainty.
     * Composed unknown text needs whole-operand resolution. */
    size_t open, after;
    const char *body = word;
    size_t size = length;
    if (size >= 2 && body[0] == '"' && body[size - 1] == '"') {
      ++body;
      size -= 2;
    }
    if (shell_source_dollar_arithmetic_open(body, size, 0, &open) &&
        shell_source_skip_arithmetic_expansion(body, size, 0, &after) &&
        after == size)
      return (shell_arithmetic_scalar_result_t){.result = {.supported = true}};
    return (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                              .unresolved = true};
  }
  size_t bytes = measure.output_length;
  char *decoded = shell_source_scratch_take(bytes + 1);
  if (!decoded)
    return (shell_arithmetic_scalar_result_t){0};
  decoded_word_sink_t output = {.destination = decoded,
                                .destination_size = bytes};
  if (!arithmetic_word(word, length, &output, &unknown)) {
    shell_source_scratch_release(mark);
    return (shell_arithmetic_scalar_result_t){0};
  }
  decoded[bytes] = 0;
  /* Publish only identifiers from the composed value: co$((1)) reads co1,
   * while unresolved source fragments above publish no guessed names. */
  shell_arithmetic_scalar_result_t result = shell_arithmetic_analyze_scalar(
      decoded, bytes, dynamic ? NULL : visitor, context);
  /* Known expansion pieces can compose a mutation token. Preserve that
   * rejection instead of weakening it to an opaque runtime interpretation. */
  if (dynamic && !result.result.supported && !result.mutation &&
      !memchr(decoded, '$', bytes) && !memchr(decoded, '\\', bytes))
    result = (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                                .unresolved = true};
  else if (dynamic && visitor && result.references)
    result = shell_arithmetic_analyze_scalar(decoded, bytes, visitor, context);
  /* Only published reference names borrow the decoded operand storage. */
  if (!visitor || !result.references)
    shell_source_scratch_release(mark);
  return result;
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
                                           shell_conditional_primary_t *r,
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

static SHELL_NONNULL(1) bool condition_delimiter(const char *s, size_t n,
                                                 size_t p) {
  size_t after;
  return (p < n && s[p] == ')') ||
         token_at(s, n, p, "]]", &after) == CONDITIONAL_TOKEN_COMPLETE ||
         shell_source_match_logical_punctuation(s, n, p, "&&", NULL) ||
         shell_source_match_logical_punctuation(s, n, p, "||", NULL);
}

/* A received Boolean token can still acquire its second byte, including
 * across an unfinished escaped line ending. Committed mismatches are not
 * prefixes. This is shared by primary and grouped-expression boundaries. */
static SHELL_NONNULL(1) bool condition_join_prefix(const char *s, size_t n,
                                                   size_t p) {
  size_t after;
  return token_at(s, n, p, "&&", &after) == CONDITIONAL_TOKEN_PREFIX ||
         token_at(s, n, p, "||", &after) == CONDITIONAL_TOKEN_PREFIX;
}

static SHELL_NONNULL(1) shell_conditional_primary_t
    parse_primary(const char *s, size_t n, size_t p, bool inside_group) {
  shell_conditional_primary_t r = {0};
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
  bool terminal = plain(s, n, p, end, "-t");
#define FILE_WORD(kind, name, ordinal, spelling, alias)                        \
  bool file_##name = plain(s, n, p, end, spelling) ||                          \
                     (spelling[1] != alias[1] && plain(s, n, p, end, alias));
  SHELL_FILE_PREDICATES(FILE_WORD)
#undef FILE_WORD
#define FILE_UNARY(kind, name, ordinal, spelling, alias) || file_##name
  bool unary = variable || terminal SHELL_FILE_PREDICATES(FILE_UNARY) ||
               plain(s, n, p, end, "-n") || plain(s, n, p, end, "-z");
#undef FILE_UNARY
  r.predicate = SHELL_CONDITIONAL_STRING_NONEMPTY;
  if (unary) {
    if (variable) {
      r.predicate = SHELL_CONDITIONAL_VARIABLE_SET;
    } else if (terminal) {
      r.predicate = SHELL_CONDITIONAL_TERMINAL;
    }
#define FILE_KIND(kind, name, ordinal, spelling, alias)                        \
  else if (file_##name) {                                                      \
    r.predicate = SHELL_CONDITIONAL_FILE_##kind;                               \
  }
    SHELL_FILE_PREDICATES(FILE_KIND)
#undef FILE_KIND
    else if (plain(s, n, p, end, "-z")) {
      r.predicate = SHELL_CONDITIONAL_STRING_EMPTY;
    }
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
      if (!shell_word_static_scalar(s + p, end - p)) {
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
  if (closer == CONDITIONAL_TOKEN_PREFIX) {
    /* Once `]` is received, appending cannot insert a required `)` before it.
     * A lone continuation prefix can still acquire that group closer. */
    if (inside_group && s[p] == ']')
      r.frame = SHELL_CONDITIONAL_INVALID;
    return r;
  }
  if (condition_join_prefix(s, n, p))
    return r;
  if (!unary && s[p] != '\n' && s[p] != '#' && !condition_delimiter(s, n, p)) {
    for (unsigned op = 0;
         op < sizeof(binary_operators) / sizeof(binary_operators[0]); ++op) {
      size_t operator_end;
      conditional_token_t operator_token =
          token_at(s, n, p, binary_operators[op], &operator_end);
      if (operator_token == CONDITIONAL_TOKEN_PREFIX)
        return r;
      if (operator_token != CONDITIONAL_TOKEN_COMPLETE)
        continue;
      /* Punctuation can terminate the spelling without ending its word:
       * -nt<(...) is one word, not a comparison followed by an operand.
       * Keep prefix recovery above, then apply the shared lexical boundary
       * before assigning an operator role or collecting a right operand. */
      if (!shell_source_match_plain_word(s, n, p, binary_operators[op],
                                         strlen(binary_operators[op]),
                                         &operator_end)) {
        r.frame = SHELL_CONDITIONAL_INVALID;
        return r;
      }
      shell_numeric_comparison_t numeric = shell_numeric_comparison(
          binary_operators[op], strlen(binary_operators[op]));
      r.predicate =
          numeric != SHELL_NUMERIC_NONE
              ? SHELL_CONDITIONAL_NUMERIC_EQUAL + numeric - SHELL_NUMERIC_EQUAL
          : op >= 3 ? SHELL_CONDITIONAL_FILE_NEWER + op - 3
          : op == 2 ? SHELL_CONDITIONAL_STRING_NOT_EQUAL
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
      if (op < 3 && !comparison_rhs(s, n, p, end, &r.predicate)) {
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
  if (closer == CONDITIONAL_TOKEN_PREFIX) {
    if (inside_group && s[p] == ']')
      r.frame = SHELL_CONDITIONAL_INVALID;
    return r;
  }
  if (condition_join_prefix(s, n, p))
    return r;
  if (condition_delimiter(s, n, p)) {
    r.frame = SHELL_CONDITIONAL_COMPLETE;
    r.end = p;
    r.after = p;
    return r;
  }
  if (misplaced_supported_operator(s, n, p))
    r.frame = SHELL_CONDITIONAL_INVALID;
  else if (strchr("=<>()", s[p]) || s[p] == '!' || (s[p] == '-' && p + 1 < n))
    r.frame = SHELL_CONDITIONAL_UNSUPPORTED;
  else
    r.frame = SHELL_CONDITIONAL_INVALID;
  return r;
}

typedef struct {
  const char *source;
  size_t length, position;
  shell_conditional_t *result;
  unsigned depth;
  bool compound;
} condition_parser_t;

/* The public single-primary summary follows parsing, including unfinished
 * groups and closers. Consuming a Boolean connector clears it before parsing
 * the right term; even a missing right term makes this a compound expression.
 * Lexical operand storage remains in the tree and pending primary. */
static SHELL_NONNULL(1) void condition_compound(condition_parser_t *p) {
  p->compound = true;
  p->result->predicate = SHELL_CONDITIONAL_PREDICATE_NONE;
  p->result->operand_count = 0;
  p->result->negated = false;
  memset(p->result->operands, 0, sizeof(p->result->operands));
  memset(p->result->operand_lengths, 0, sizeof(p->result->operand_lengths));
}

static SHELL_NONNULL(1) uint16_t
    condition_node(condition_parser_t *p, shell_condition_operation_t operation,
                   uint16_t left, uint16_t right,
                   const shell_conditional_primary_t *primary) {
  shell_conditional_t *r = p->result;
  if (r->count == SHELL_CONDITIONAL_MAX_NODES) {
    r->frame = SHELL_CONDITIONAL_LIMIT;
    return UINT16_MAX;
  }
  uint16_t index = r->count++;
  r->nodes[index] = (shell_condition_node_t){
      .operation = operation, .left = left, .right = right};
  if (primary) {
    r->nodes[index].primary = *primary;
    r->features |= shell_conditional_features(primary->predicate);
  }
  return index;
}

static uint16_t condition_or(condition_parser_t *p, bool inside_group)
    SHELL_NONNULL(1);

static SHELL_NONNULL(1) uint16_t
    condition_term(condition_parser_t *p, bool inside_group) {
  const char *s = p->source;
  size_t n = p->length, after;
  p->position = trivia(s, n, p->position, true);
  size_t start = p->position;
  bool negated = false;
  while (start < n &&
         token_at(s, n, start, "!", &after) == CONDITIONAL_TOKEN_COMPLETE) {
    /* `!(...)` is an extglob word; `!` concatenated with a process
     * substitution is also data. Only a complete standalone lexical word
     * selects negation, as in the primary recognizer. */
    size_t word_end;
    if (!shell_source_skip_shell_word_impl(s, n, start, &word_end, true) ||
        !plain(s, n, start, word_end, "!"))
      break;
    negated = !negated;
    start = p->position = trivia(s, n, after, true);
  }
  if (start == n) {
    p->result->frame = SHELL_CONDITIONAL_INCOMPLETE;
    if (!p->compound)
      p->result->negated = negated;
    return UINT16_MAX;
  }
  if (++p->depth > SHELL_CONDITIONAL_MAX_NODES) {
    p->result->frame = SHELL_CONDITIONAL_LIMIT;
    return UINT16_MAX;
  }
  uint16_t result;
  if (s[start] == '(') {
    p->position++;
    result = condition_or(p, true);
    if (result != UINT16_MAX) {
      p->position = trivia(s, n, p->position, true);
      /* A completed subgroup may still acquire a Boolean connector or an
       * escaped line ending before this group's required `)`. */
      if (p->position == n || condition_join_prefix(s, n, p->position)) {
        p->result->frame = SHELL_CONDITIONAL_INCOMPLETE;
        result = UINT16_MAX;
      } else if (s[p->position] != ')') {
        p->result->frame = SHELL_CONDITIONAL_INVALID;
        result = UINT16_MAX;
      } else
        p->position++;
    }
  } else {
    shell_conditional_primary_t primary =
        parse_primary(s, n, start, inside_group);
    p->position = primary.after;
    if (!p->compound) {
      p->result->predicate = primary.predicate;
      p->result->negated = primary.negated;
      p->result->operand_count = primary.operand_count;
      memcpy(p->result->operands, primary.operands, sizeof(primary.operands));
      memcpy(p->result->operand_lengths, primary.operand_lengths,
             sizeof(primary.operand_lengths));
    }
    if (primary.frame != SHELL_CONDITIONAL_COMPLETE) {
      p->result->frame = primary.frame;
      p->result->pending = primary;
      p->result->features |= shell_conditional_features(primary.predicate);
      result = UINT16_MAX;
    } else
      result = condition_node(p, SHELL_CONDITION_PRIMARY, 0, 0, &primary);
  }
  p->depth--;
  /* Enclosing negation applies to the summary even when the child stopped at
   * received EOF before its group or primary could become a completed node. */
  if (!p->compound && negated)
    p->result->negated = !p->result->negated;
  if (result != UINT16_MAX && negated)
    result = condition_node(p, SHELL_CONDITION_NOT, result, 0, NULL);
  return result;
}

static SHELL_NONNULL(1) uint16_t
    condition_and(condition_parser_t *p, bool inside_group) {
  uint16_t left = condition_term(p, inside_group);
  while (left != UINT16_MAX) {
    size_t after;
    p->position = trivia(p->source, p->length, p->position, true);
    if (!shell_source_match_logical_punctuation(p->source, p->length,
                                                p->position, "&&", &after))
      break;
    p->position = after;
    condition_compound(p);
    uint16_t right = condition_term(p, inside_group);
    if (right == UINT16_MAX)
      return right;
    left = condition_node(p, SHELL_CONDITION_AND, left, right, NULL);
  }
  return left;
}

static uint16_t condition_or(condition_parser_t *p, bool inside_group) {
  uint16_t left = condition_and(p, inside_group);
  while (left != UINT16_MAX) {
    size_t after;
    p->position = trivia(p->source, p->length, p->position, true);
    if (!shell_source_match_logical_punctuation(p->source, p->length,
                                                p->position, "||", &after))
      break;
    p->position = after;
    condition_compound(p);
    uint16_t right = condition_and(p, inside_group);
    if (right == UINT16_MAX)
      return right;
    left = condition_node(p, SHELL_CONDITION_OR, left, right, NULL);
  }
  return left;
}

shell_conditional_t shell_conditional_parse(const char *s, size_t n,
                                            size_t start) {
  shell_conditional_t r = {0};
  size_t p, after;
  if (!shell_source_match_logical_punctuation(s, n, start, "[[", &p))
    return r;
  p = shell_source_skip_escaped_line_endings(s, n, p);
  if (p == n ||
      (!shell_source_space((unsigned char)s[p]) && !strchr(";|&()<>", s[p])))
    return r;
  r.content = p;
  r.end = r.after = n;
  r.frame = SHELL_CONDITIONAL_COMPLETE;
  r.features = SHELL_FEAT_CONDITIONALS;
  condition_parser_t parser = {
      .source = s, .length = n, .position = p, .result = &r};
  r.root = condition_or(&parser, false);
  if (r.root == UINT16_MAX)
    return r;
  p = trivia(s, n, parser.position, true);
  conditional_token_t closer = token_at(s, n, p, "]]", &after);
  if (closer != CONDITIONAL_TOKEN_COMPLETE) {
    r.frame =
        closer == CONDITIONAL_TOKEN_PREFIX || condition_join_prefix(s, n, p)
            ? SHELL_CONDITIONAL_INCOMPLETE
            : SHELL_CONDITIONAL_INVALID;
    return r;
  }
  r.end = p;
  r.after = after;
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
    const char *source, const shell_conditional_primary_t *condition,
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
                                const shell_conditional_primary_t *condition,
                                const shell_conditional_value_t values[2],
                                bool *truth) {
  if (shell_conditional_numeric(condition->predicate)) {
    shell_arithmetic_scalar_result_t operands[2];
    for (unsigned i = 0; i < 2; ++i) {
      operands[i] = shell_conditional_arithmetic_operand(
          source + condition->operands[i], condition->operand_lengths[i],
          values[i].data, values[i].length, values[i].known, NULL, NULL);
      if (!operands[i].result.known)
        return false;
    }
    shell_numeric_comparison_t comparison =
        (shell_numeric_comparison_t)(SHELL_NUMERIC_EQUAL +
                                     condition->predicate -
                                     SHELL_CONDITIONAL_NUMERIC_EQUAL);
    *truth =
        shell_numeric_compare(comparison, operands[0].result.value,
                              operands[1].result.value) != condition->negated;
    return true;
  }
  if (condition->predicate == SHELL_CONDITIONAL_TERMINAL) {
    size_t mark = shell_source_scratch_mark();
    const char *value = values[0].data;
    size_t length = values[0].length;
    if (!values[0].known) {
      const char *word = source + condition->operands[0];
      size_t size = condition->operand_lengths[0];
      if (shell_conditional_word_dynamic(word, size))
        return false;
      if (shell_process_measure_word_value(word, size, &length) !=
          SHELL_PROCESS_OK)
        return false;
      char *decoded = shell_source_scratch_take(length + 1);
      if (!decoded)
        return false;
      size_t written;
      if (shell_process_write_word_value(word, size, decoded, length,
                                         &written) != SHELL_PROCESS_OK) {
        shell_source_scratch_release(mark);
        return false;
      }
      value = decoded;
    }
    shell_test_number_t number = {0};
    for (size_t i = 0; i < length; ++i)
      shell_test_number_byte(&number, (unsigned char)value[i]);
    shell_source_scratch_release(mark);
    if (number.digits && !number.invalid &&
        (!number.negative || number.magnitude == 0) &&
        number.magnitude <= INT_MAX)
      return false; /* The executor's terminal state is a runtime fact. */
    *truth = condition->negated;
    return true;
  }
  if (condition->predicate == SHELL_CONDITIONAL_VARIABLE_SET)
    return false; /* Presence is a path-local graph fact, not a string value. */
  if (condition->predicate >= SHELL_CONDITIONAL_FILE_NEWER &&
      condition->predicate <= SHELL_CONDITIONAL_FILE_SAME) {
    bool empty[2] = {false, false};
    for (unsigned i = 0; i < 2; ++i) {
      if (values[i].known)
        empty[i] = values[i].length == 0;
      else {
        /* Unknown decoding cannot prove emptiness. Check each operand so a
         * known-empty counterpart can still decide the comparison. */
        bool static_empty;
        empty[i] = shell_conditional_static_empty(
                       source + condition->operands[i],
                       condition->operand_lengths[i], &static_empty) &&
                   static_empty;
      }
    }
    bool false_result = condition->predicate == SHELL_CONDITIONAL_FILE_SAME
                            ? empty[0] || empty[1]
                        : condition->predicate == SHELL_CONDITIONAL_FILE_NEWER
                            ? empty[0]
                            : empty[1];
    if (!false_result)
      return false;
    *truth = condition->negated;
    return true;
  }
  if (shell_conditional_file(condition->predicate)) {
    bool empty;
    if (values[0].known)
      empty = values[0].length == 0;
    else if (!shell_conditional_static_empty(source + condition->operands[0],
                                             condition->operand_lengths[0],
                                             &empty))
      return false;
    if (!empty)
      return false;
    *truth = condition->negated;
    return true;
  }
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
