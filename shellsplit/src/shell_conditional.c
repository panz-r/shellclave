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

#include "shell_conditional_operand_impl.h"

static SHELL_NONNULL(1, 5) bool comparison_rhs(
    const char *s, size_t n, size_t p, size_t end,
    shell_conditional_predicate_t *predicate);

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

#include "shell_conditional_pattern_impl.h"

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
