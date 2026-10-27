#include "shell_source_internal.h"
#include "shell_source_runtime_internal.h"
#include "shell_test_internal.h"
#include "shell_word_internal.h"
#include <string.h>

enum {
  TEST_FALSE,
  TEST_NONEMPTY,
  TEST_EMPTY,
  TEST_EQUAL,
  TEST_NOT_EQUAL,
  TEST_PRESENT,
// clang-format off
#define FILE_OPERATION(kind, name, ordinal, spelling, alias) TEST_FILE_##kind,
  SHELL_FILE_PREDICATES(FILE_OPERATION)
#undef FILE_OPERATION
  TEST_TERMINAL,
  TEST_OPAQUE,
  TEST_OPAQUE_ERROR,
  TEST_ERROR,
  TEST_NOT,
  TEST_AND,
  TEST_OR
};
// clang-format on

/* Retain the shift-based conversion without coupling independently edited
 * enum sequences. New predicates must fit the existing role and edge fields. */
#define FILE_MAPPING(kind, name, ordinal, spelling, alias)                     \
  _Static_assert(TEST_FILE_##kind == TEST_FILE_EXISTS + ordinal,               \
                 "builtin filesystem predicate ordinal");                      \
  _Static_assert(SHELL_DEP_EDGE_FLAG_FILE_TEST_##kind ==                       \
                     (SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS << ordinal),        \
                 "filesystem edge flag mapping");                              \
  _Static_assert(SHELL_TEST_FILE_##kind ==                                     \
                     (SHELL_TEST_FILE_EXISTS << ordinal),                      \
                 "filesystem role mapping");
SHELL_FILE_PREDICATES(FILE_MAPPING)
#undef FILE_MAPPING
_Static_assert((SHELL_TEST_FILE_ROLES &
                (SHELL_TEST_AND_JOIN | SHELL_TEST_OR_JOIN)) == 0,
               "filesystem roles do not overlap Boolean connectors");

_Static_assert(SHELL_DEP_MAX_TOKENS * 2u + 2u <= UINT16_MAX,
               "test expression ordinals fit retained private nodes");
_Static_assert(sizeof(shell_test_value_t) + 2 * sizeof(shell_test_node_t) +
                       sizeof(shell_test_roles_t) + 8 +
                       2 * (SHELL_DEP_MAX_TOKENS + 1) *
                           (SHELL_DEP_MAX_TOKENS + 1) / SHELL_DEP_MAX_TOKENS +
                       2 <=
                   SHELL_SOURCE_VALUE_SCRATCH_FACTOR,
               "test values, nodes and bounded projection fit source scratch");
_Static_assert(SHELL_DEP_MAX_TOKENS < 63,
               "projected parenthesis depths fit the bounded bitset");

bool shell_test_prepare_value(const char *source, size_t length,
                              shell_test_value_t *value) {
  *value = (shell_test_value_t){.source = source, .length = length};
  if (shell_source_argument_has_dynamic_syntax(source, length))
    return true;
  size_t bytes;
  if (shell_process_measure_word_value(source, length, &bytes) !=
      SHELL_PROCESS_OK)
    return true;
  char *data = shell_source_scratch_take(bytes + 1);
  if (!data)
    return false;
  size_t written;
  if (shell_process_write_word_value(source, length, data, bytes, &written) !=
      SHELL_PROCESS_OK)
    return true;
  data[bytes] = 0;
  shell_test_set_value(value, data, bytes);
  return true;
}

static SHELL_NONNULL(1, 3) bool is_word(const shell_test_program_t *p,
                                        size_t word, const char *text) {
  const shell_test_value_t *v = &p->words[word];
  return v->known && v->value_length == strlen(text) &&
         !memcmp(v->value, text, v->value_length);
}

static SHELL_NONNULL(1) uint16_t
    node(shell_test_program_t *p, unsigned op, unsigned left, unsigned right) {
  unsigned index = p->count++;
  p->nodes[index] =
      (shell_test_node_t){(uint16_t)left, (uint16_t)right, (uint8_t)op};
  return (uint16_t)index;
}

static SHELL_NONNULL(1) bool unary(const shell_test_program_t *p, size_t i) {
  const shell_test_value_t *v = &p->words[i];
  return v->known && (shell_test_static_roles(v->value, v->value_length) &
                      SHELL_TEST_UNARY);
}

static SHELL_NONNULL(1) bool binary(const shell_test_program_t *p, size_t i) {
  const shell_test_value_t *v = &p->words[i];
  shell_test_roles_t roles =
      v->known ? shell_test_static_roles(v->value, v->value_length) : 0;
  return shell_test_lookahead(roles, !v->known) == SHELL_TEST_LOOKAHEAD_BINARY;
}

static SHELL_NONNULL(1) uint16_t primary(shell_test_program_t *p, size_t op,
                                         size_t left, size_t right, bool two) {
  unsigned kind = TEST_OPAQUE;
  if (two) {
    if (is_word(p, op, "=") || is_word(p, op, "=="))
      kind = TEST_EQUAL;
    else if (is_word(p, op, "!="))
      kind = TEST_NOT_EQUAL;
    else if (p->words[op].value_length == 3 && p->words[op].value[1] != 'n' &&
             p->words[op].value[1] != 'o' && p->words[op].value[1] != 'e')
      kind = TEST_OPAQUE_ERROR;
    /* -eq/-ne also validate integers; -ef/-nt/-ot inspect files. */
    if (is_word(p, op, "-eq") || is_word(p, op, "-ne"))
      kind = TEST_OPAQUE_ERROR;
  } else if (is_word(p, op, "-v")) {
    kind = TEST_PRESENT;
  }
#define FILE_PRIMARY(kind_name, name, ordinal, spelling, alias)                \
  else if (is_word(p, op, spelling) ||                                         \
           (spelling[1] != alias[1] && is_word(p, op, alias))) {               \
    kind = TEST_FILE_##kind_name;                                              \
  }
  SHELL_FILE_PREDICATES(FILE_PRIMARY)
#undef FILE_PRIMARY
  else if (is_word(p, op, "-t")) {
    kind = TEST_TERMINAL;
  }
  else if (is_word(p, op, "-n")) {
    kind = TEST_NONEMPTY;
  }
  else if (is_word(p, op, "-z")) {
    kind = TEST_EMPTY;
  }
  return node(p, kind, left, right);
}

typedef struct {
  shell_test_program_t *program;
  uint16_t close[SHELL_DEP_MAX_TOKENS];
  uint16_t unknown[SHELL_DEP_MAX_TOKENS + 1];
  size_t total_count;
  bool uncertain, failed;
} parser_t;

static SHELL_NONNULL(1, 2) uint16_t
    expression(parser_t *parser, size_t *position, size_t end);
static SHELL_NONNULL(1, 2) uint16_t counted(parser_t *parser, size_t *position,
                                            size_t end, size_t expression_end);

static SHELL_NONNULL(1) uint16_t parse_error(parser_t *parser) {
  parser->failed = true;
  return node(parser->program, TEST_ERROR, 0, 0);
}

static SHELL_NONNULL(1, 2) uint16_t
    term(parser_t *parser, size_t *position, size_t end) {
  shell_test_program_t *p = parser->program;
  size_t i = (*position)++;
  if (i == end) {
    *position = end;
    return parse_error(parser);
  }
  if (!p->words[i].known) {
    parser->uncertain = true;
    *position = end;
    return node(p, TEST_OPAQUE_ERROR, 0, 0);
  }
  if (is_word(p, i, "!")) {
    uint16_t child = term(parser, position, end);
    if (parser->failed)
      return child;
    return node(p, TEST_NOT, child, 0);
  }
  if (is_word(p, i, "(")) {
    size_t close = parser->close[i];
    size_t inspected_end = close < end ? close : end;
    if (i + 2 < inspected_end &&
        parser->unknown[inspected_end] != parser->unknown[i + 2])
      parser->uncertain = true;
    uint16_t child;
    if (close < end && close - i - 1 <= 4) {
      child = counted(parser, position, close, end);
    } else {
      child = expression(parser, position, end);
    }
    if (parser->failed)
      return child;
    if (*position == end || !is_word(p, *position, ")"))
      return parse_error(parser);
    ++*position;
    return child;
  }
  if (i + 2 < end && binary(p, i + 1)) {
    *position = i + 3;
    return primary(p, i + 1, i, i + 2, true);
  }
  if (i + 2 < end && !p->words[i + 1].known)
    parser->uncertain = true;
  if (i + 1 < end && unary(p, i)) {
    if (is_word(p, i, "-t")) {
      const shell_test_value_t *argument = &p->words[i + 1];
      shell_test_roles_t roles =
          argument->known
              ? shell_test_static_roles(argument->value, argument->value_length)
              : 0;
      shell_test_terminal_operand_t operand = shell_test_terminal_operand(
          roles, argument->known, argument->number, parser->total_count >= 4);
      if (operand == SHELL_TEST_TERMINAL_IMPLICIT)
        return node(p, TEST_OPAQUE, 0, 0);
      if (operand == SHELL_TEST_TERMINAL_UNKNOWN)
        parser->uncertain =
            true; /* A connector can change the remaining grammar. */
    }
    *position = i + 2;
    return primary(p, i, i + 1, 0, false);
  }
  if (i + 1 < end && !p->words[i + 1].known) {
    parser->uncertain = true;
    *position = end;
    return node(p, TEST_OPAQUE_ERROR, 0, 0);
  }
  return node(p, TEST_NONEMPTY, i, 0);
}

static SHELL_NONNULL(1, 2) uint16_t
    conjunction(parser_t *parser, size_t *position, size_t end) {
  shell_test_program_t *p = parser->program;
  uint16_t result = term(parser, position, end);
  if (parser->failed)
    return result;
  while (*position < end && is_word(p, *position, "-a")) {
    ++*position;
    uint16_t right = term(parser, position, end);
    if (parser->failed)
      return right;
    result = node(p, TEST_AND, result, right);
  }
  return result;
}

static SHELL_NONNULL(1, 2) uint16_t
    expression(parser_t *parser, size_t *position, size_t end) {
  shell_test_program_t *p = parser->program;
  uint16_t result = conjunction(parser, position, end);
  if (parser->failed)
    return result;
  while (*position < end && is_word(p, *position, "-o")) {
    ++*position;
    uint16_t right = conjunction(parser, position, end);
    if (parser->failed)
      return right;
    result = node(p, TEST_OR, result, right);
  }
  return result;
}

/* Shortcuts consume their counted span. General fallback keeps the enclosing
 * expression end and returns its actual cursor, which may pass the candidate
 * ')' used to choose dispatch. The enclosing group validates that cursor. */
static SHELL_NONNULL(1, 2) uint16_t counted(parser_t *parser, size_t *position,
                                            size_t end, size_t expression_end) {
  shell_test_program_t *p = parser->program;
  size_t begin = *position;
  size_t count = end - begin;
  shell_builtin_test_word_t words[4];
  for (size_t i = 0; i < count && i < 4; ++i) {
    const shell_test_value_t *value = &p->words[begin + i];
    words[i] = (shell_builtin_test_word_t){
        .roles = value->known ? shell_test_static_roles(value->value,
                                                        value->value_length)
                              : 0,
        .dynamic = !value->known,
        .number = value->number};
  }
  shell_test_dispatch_t dispatch =
      shell_test_dispatch(words, count, parser->total_count >= 4);
  size_t local = begin + dispatch.first;
  uint16_t result;
  switch (dispatch.kind) {
  case SHELL_TEST_DISPATCH_FALSE:
    result = node(p, TEST_FALSE, 0, 0);
    break;
  case SHELL_TEST_DISPATCH_GLOBAL_STRING:
    result = node(p, TEST_NONEMPTY, 0, 0);
    break;
  case SHELL_TEST_DISPATCH_LOCAL_STRING:
    result = node(p, TEST_NONEMPTY, local, 0);
    break;
  case SHELL_TEST_DISPATCH_UNARY:
    result = primary(p, local, local + 1, 0, false);
    break;
  case SHELL_TEST_DISPATCH_BINARY:
    result = primary(p, local + 1, local, local + 2, true);
    break;
  case SHELL_TEST_DISPATCH_JOIN: {
    uint16_t left = node(p, TEST_NONEMPTY, local, 0);
    uint16_t right = node(p, TEST_NONEMPTY, local + 2, 0);
    result =
        node(p, is_word(p, local + 1, "-a") ? TEST_AND : TEST_OR, left, right);
    break;
  }
  case SHELL_TEST_DISPATCH_UNKNOWN:
    parser->uncertain = true;
    result = node(p, TEST_OPAQUE_ERROR, 0, 0);
    break;
  case SHELL_TEST_DISPATCH_ERROR:
    return parse_error(parser);
  case SHELL_TEST_DISPATCH_GENERAL:
    return expression(parser, position, expression_end);
  }
  *position = end;
  return dispatch.negated ? node(p, TEST_NOT, result, 0) : result;
}

#include "shell_test_projection_impl.h"

bool shell_test_refresh(shell_test_program_t *program) {
  shell_test_value_t *words = program->words;
  size_t count = program->word_count;
  program->count = 0;
  program->uncertain = false;
  if (count)
    memset(program->operand_roles, 0, count * sizeof(*program->operand_roles));
  if (program->bracket) {
    if (!count || !is_word(program, count - 1, "]")) {
      program->uncertain = count && !words[count - 1].known;
      program->root = node(program,
                           count && !words[count - 1].known ? TEST_OPAQUE_ERROR
                                                            : TEST_ERROR,
                           0, 0);
      return true;
    }
    --count;
  }
  parser_t parser = {.program = program, .total_count = count};
  uint16_t stack[SHELL_DEP_MAX_TOKENS];
  size_t depth = 0;
  for (size_t i = 0; i < count; ++i) {
    parser.close[i] = UINT16_MAX;
    if (is_word(program, i, "("))
      stack[depth++] = (uint16_t)i;
    else if (depth && is_word(program, i, ")"))
      parser.close[stack[--depth]] = (uint16_t)i;
  }
  /* Bash 5.3 scans from the second word inside a group when selecting
   * its 1..4-argument dispatch. Precompute that exact boundary in linear work;
   * general expressions still consume their closing token through grammar. */
  uint16_t next[SHELL_DEP_MAX_TOKENS + 1];
  next[count] = UINT16_MAX;
  for (size_t i = count; i-- > 0;) {
    if (is_word(program, i, ")"))
      next[i] = (uint16_t)i;
    else if (is_word(program, i, "("))
      next[i] = parser.close[i] == UINT16_MAX ? UINT16_MAX
                                              : next[parser.close[i] + 1];
    else
      next[i] = next[i + 1];
  }
  for (size_t i = 0; i < count; ++i) {
    parser.close[i] = i + 2 <= count ? next[i + 2] : UINT16_MAX;
    parser.unknown[i + 1] = parser.unknown[i] + !words[i].known;
  }
  size_t position = 0;
  program->root = counted(&parser, &position, count, count);
  if (!parser.failed && position != count) {
    for (size_t i = position; i < count; ++i)
      if (!words[i].known)
        parser.uncertain = true;
    program->root = parse_error(&parser);
  }
  if (parser.uncertain)
    program->root = node(program, TEST_OPAQUE_ERROR, 0, 0);
  program->uncertain = parser.uncertain;
  return !program->uncertain || project_program(program, count);
}

bool shell_test_compile(shell_test_value_t *words, size_t count, bool bracket,
                        shell_test_program_t *program) {
  *program = (shell_test_program_t){.words = words,
                                    .word_count = (uint16_t)count,
                                    .active = true,
                                    .bracket = bracket};
  /* Each term consumes source words once; successful operators add at most
   * one combining node per word. Definite errors propagate without wrapping
   * or replay. Two extra nodes cover terminal and uncertain-result roots. */
  program->nodes = shell_source_scratch_take_array(
      count * 2 + 2, sizeof(*program->nodes), _Alignof(shell_test_node_t));
  program->operand_roles = shell_source_scratch_take_array(
      count, sizeof(*program->operand_roles), _Alignof(shell_test_roles_t));
  if (!program->nodes || (!program->operand_roles && count))
    return false;
  return shell_test_refresh(program);
}

void shell_test_prove_error(shell_test_program_t *program) {
  program->proven_error = true;
}

bool shell_test_compile_presence(const char *word, size_t length, bool negated,
                                 shell_test_program_t *program) {
  shell_test_value_t *value = shell_source_scratch_take_array(
      1, sizeof(*value), _Alignof(shell_test_value_t));
  shell_test_node_t *nodes = shell_source_scratch_take_array(
      2, sizeof(*nodes), _Alignof(shell_test_node_t));
  if (!value || !nodes || !shell_test_prepare_value(word, length, value))
    return false;
  *program = (shell_test_program_t){
      .words = value, .nodes = nodes, .word_count = 1, .active = true};
  program->root = node(program, TEST_PRESENT, 0, 0);
  if (negated)
    program->root = node(program, TEST_NOT, program->root, 0);
  return true;
}

static SHELL_NONNULL(1, 2, 3,
                     4) unsigned evaluate(const shell_test_program_t *p,
                                          shell_test_lookup_t lookup,
                                          void *context, unsigned *results) {
  for (unsigned i = 0; i < p->count; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    shell_test_node_t n = p->nodes[i];
    unsigned result = 0;
    const shell_test_value_t *a =
        n.operation >= TEST_NONEMPTY && n.operation <= TEST_TERMINAL
            ? &p->words[n.left]
            : NULL;
    switch (n.operation) {
    case TEST_FALSE:
      result = SHELL_TEST_FALSE;
      break;
    case TEST_NONEMPTY:
    case TEST_EMPTY:
      result = !a->known ? 3u
               : (a->value_length != 0) == (n.operation == TEST_NONEMPTY)
                   ? SHELL_TEST_TRUE
                   : SHELL_TEST_FALSE;
      break;
    case TEST_EQUAL:
    case TEST_NOT_EQUAL: {
      const shell_test_value_t *b = &p->words[n.right];
      bool equal =
          a->known && b->known && a->value_length == b->value_length &&
          (!a->value_length || !memcmp(a->value, b->value, a->value_length));
      result = !a->known || !b->known                 ? 3u
               : equal == (n.operation == TEST_EQUAL) ? SHELL_TEST_TRUE
                                                      : SHELL_TEST_FALSE;
      break;
    }
    case TEST_PRESENT:
      result = a->known && shell_word_scalar_name(a->value, a->value_length)
                   ? lookup(a->value, a->value_length, context)
                   : 3u;
      break;
#define FILE_EVALUATE(kind, name, ordinal, spelling, alias)                    \
  case TEST_FILE_##kind:
      SHELL_FILE_PREDICATES(FILE_EVALUATE)
#undef FILE_EVALUATE
      result = a->known && !a->value_length ? SHELL_TEST_FALSE : 3u;
      break;
    case TEST_TERMINAL:
      result = !a->known ? 7u : a->number ? 3u : SHELL_TEST_ERROR_RESULT;
      break;
    case TEST_OPAQUE:
      result = 3u;
      break;
    case TEST_OPAQUE_ERROR:
      result = 7u;
      break;
    case TEST_ERROR:
      result = SHELL_TEST_ERROR_RESULT;
      break;
    case TEST_NOT:
      result = ((results[n.left] & 1u) << 1) | ((results[n.left] & 2u) >> 1) |
               (results[n.left] & SHELL_TEST_ERROR_RESULT);
      break;
    case TEST_AND:
    case TEST_OR: {
      unsigned left = results[n.left], right = results[n.right];
      result = left & SHELL_TEST_ERROR_RESULT;
      if (left & 3u) {
        result |= right & SHELL_TEST_ERROR_RESULT;
        for (unsigned l = 1; l <= 2; ++l)
          for (unsigned r = 1; r <= 2; ++r)
            if ((left & l) && (right & r)) {
              bool truth =
                  n.operation == TEST_AND ? l == 2 && r == 2 : l == 2 || r == 2;
              result |= truth ? SHELL_TEST_TRUE : SHELL_TEST_FALSE;
            }
      }
      break;
    }
    }
    results[i] = result;
  }
  return p->proven_error ? SHELL_TEST_ERROR_RESULT : results[p->root];
}

unsigned shell_test_evaluate(const shell_test_program_t *program,
                             shell_test_lookup_t lookup, void *context) {
  unsigned results[SHELL_DEP_MAX_TOKENS * 2 + 2];
  return evaluate(program, lookup, context, results);
}

void shell_test_observe_files(const shell_test_program_t *program,
                              shell_test_file_observer_t observer,
                              void *context) {
  if (program->proven_error)
    return;
  if (program->uncertain) {
    for (size_t i = 0; i < program->word_count; ++i) {
      shell_test_roles_t roles =
          program->operand_roles[i] & SHELL_TEST_FILE_ROLES;
      if (roles)
        observer(&program->words[i],
                 (roles / SHELL_TEST_FILE_EXISTS) *
                     SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS,
                 context);
    }
    return;
  }
  uint16_t stack[SHELL_DEP_MAX_TOKENS * 2 + 2];
  size_t count = 0;
  stack[count++] = program->root;
  while (count) {
    shell_test_node_t n = program->nodes[stack[--count]];
    if (n.operation >= TEST_FILE_EXISTS &&
        n.operation < TEST_FILE_EXISTS + SHELL_FILE_PREDICATE_COUNT)
      observer(&program->words[n.left],
               SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS
                   << (n.operation - TEST_FILE_EXISTS),
               context);
    else if (n.operation == TEST_NOT)
      stack[count++] = n.left;
    else if (n.operation == TEST_AND || n.operation == TEST_OR) {
      stack[count++] = n.right;
      stack[count++] = n.left;
    }
  }
}

void shell_test_observe_presence(const shell_test_program_t *program,
                                 shell_test_presence_observer_t observer,
                                 void *context) {
  if (program->uncertain) {
    for (size_t i = 0; i < program->word_count; ++i) {
      const shell_test_value_t *word = &program->words[i];
      if ((program->operand_roles[i] & SHELL_TEST_LOOKUP) && word->known &&
          shell_word_scalar_name(word->value, word->value_length))
        observer(word->value, word->value_length, context);
    }
    return;
  }
  uint16_t pending[SHELL_DEP_MAX_TOKENS * 2 + 2];
  unsigned count = 1;
  pending[0] = program->root;
  while (count) {
    shell_test_node_t n = program->nodes[pending[--count]];
    if (n.operation == TEST_PRESENT) {
      const shell_test_value_t *v = &program->words[n.left];
      if (v->known && shell_word_scalar_name(v->value, v->value_length))
        observer(v->value, v->value_length, context);
    } else if (n.operation == TEST_NOT) {
      pending[count++] = n.left;
    } else if (n.operation == TEST_AND || n.operation == TEST_OR) {
      pending[count++] = n.left;
      pending[count++] = n.right;
    }
  }
}

bool shell_test_require(const shell_test_program_t *program, unsigned desired,
                        shell_test_lookup_t lookup, shell_test_assume_t assume,
                        void *context) {
  unsigned results[SHELL_DEP_MAX_TOKENS * 2 + 2];
  unsigned all = evaluate(program, lookup, context, results);
  if (!(all & desired))
    return true;
  if (desired == SHELL_TEST_FALSE && (all & SHELL_TEST_ERROR_RESULT))
    return true;
  struct {
    uint16_t node;
    unsigned wanted;
  } pending[SHELL_DEP_MAX_TOKENS * 2 + 2];
  unsigned count = 1;
  pending[0].node = program->root;
  pending[0].wanted = desired;
  while (count) {
    unsigned index = pending[--count].node, wanted = pending[count].wanted;
    shell_test_node_t n = program->nodes[index];
    if (n.operation == TEST_PRESENT) {
      const shell_test_value_t *v = &program->words[n.left];
      if (v->known && shell_word_scalar_name(v->value, v->value_length) &&
          !assume(v->value, v->value_length, wanted, context))
        return false;
    } else if (n.operation == TEST_NOT) {
      pending[count].node = n.left;
      pending[count++].wanted = wanted == 1 ? 2 : 1;
    } else if (n.operation == TEST_AND || n.operation == TEST_OR) {
      bool both = (n.operation == TEST_AND && wanted == 2) ||
                  (n.operation == TEST_OR && wanted == 1);
      for (unsigned side = 0; side < 2; ++side) {
        unsigned child = side ? n.right : n.left,
                 other = side ? n.left : n.right;
        unsigned neutral = n.operation == TEST_AND ? 2 : 1;
        if (both || results[other] == neutral) {
          pending[count].node = (uint16_t)child;
          pending[count++].wanted = wanted;
        }
      }
    }
  }
  return true;
}
