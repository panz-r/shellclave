#ifndef SHELL_TEST_INTERNAL_H
#define SHELL_TEST_INTERNAL_H

#include "shell_builtin_word_internal.h"
#include "shell_depgraph.h"
#include <stdint.h>

/* `test`/`[` variable-existence operands can re-evaluate an array subscript,
 * even when no array was declared. Classify each complete word once, retaining
 * only operator roles and lookup safety, not copies of source/value strings.
 * Unknown argv cardinality cannot establish expression roles and is rejected.
 * Quoted scalar data still has a known one-word cardinality. */
enum {
  SHELL_TEST_NOT = 1u,
  SHELL_TEST_OPEN = 2u,
  SHELL_TEST_CLOSE = 4u,
  SHELL_TEST_UNARY = 8u,
  SHELL_TEST_LOOKUP = 16u,
  SHELL_TEST_BINARY = 32u,
  SHELL_TEST_JOIN = 64u,
  SHELL_TEST_END = 128u,
  SHELL_TEST_TERMINAL = 256u,
};

/* Bash valid_number accepts signed base-10 intmax_t values with surrounding
 * ASCII whitespace. Keep this projection with test's operand grammar; read's
 * numeric options have different rules. */
typedef struct {
  uintmax_t magnitude;
  unsigned phase;
  bool negative, digits, invalid;
} shell_test_number_t;

static inline SHELL_NONNULL(1) void shell_test_number_byte(
    shell_test_number_t *number, unsigned char byte) {
  if (number->invalid)
    return;
  bool space = byte == ' ' || (byte >= '\t' && byte <= '\r');
  if (!number->phase && space)
    return;
  if (!number->phase && (byte == '+' || byte == '-')) {
    number->negative = byte == '-';
    number->phase = 1;
    return;
  }
  if (byte >= '0' && byte <= '9' && number->phase < 2) {
    uintmax_t limit = (uintmax_t)INTMAX_MAX + number->negative;
    unsigned digit = byte - '0';
    number->invalid = number->magnitude > (limit - digit) / 10;
    if (!number->invalid)
      number->magnitude = number->magnitude * 10 + digit;
    number->digits = true;
    number->phase = 1;
  } else if (space && number->digits)
    number->phase = 2;
  else
    number->invalid = true;
}

typedef enum {
  SHELL_TEST_TERMINAL_CONSUME,
  SHELL_TEST_TERMINAL_IMPLICIT,
  SHELL_TEST_TERMINAL_ERROR,
  SHELL_TEST_TERMINAL_UNKNOWN,
} shell_test_terminal_operand_t;

/* Called only after binary precedence selected unary -t. Global expression
 * arity, rather than a parenthesized subexpression's length, enables fd 1. */
static inline shell_test_terminal_operand_t
shell_test_terminal_operand(unsigned roles, bool known, bool number,
                            bool implicit_allowed) {
  return !known   ? SHELL_TEST_TERMINAL_UNKNOWN
         : number ? SHELL_TEST_TERMINAL_CONSUME
         : implicit_allowed && (roles & SHELL_TEST_JOIN)
             ? SHELL_TEST_TERMINAL_IMPLICIT
             : SHELL_TEST_TERMINAL_ERROR;
}

/* Shared operator vocabulary. test/[ recognize effective argument bytes,
 * independently of their original quote protection. -a/-o have both binary
 * and join roles; argument-count rules choose the actual operation. */
static inline SHELL_NONNULL(1) unsigned shell_test_static_roles(
    const char *spelling, size_t length) {
  unsigned roles = 0;
  if (length == 1)
    return spelling[0] == '!'           ? SHELL_TEST_NOT
           : spelling[0] == '('         ? SHELL_TEST_OPEN
           : spelling[0] == ')'         ? SHELL_TEST_CLOSE
           : spelling[0] == ']'         ? SHELL_TEST_END
           : strchr("=<>", spelling[0]) ? SHELL_TEST_BINARY
                                        : 0;
  if (length == 2) {
    if (spelling[0] == '-' && strchr("abcdefghkLnNoOprRsStuvwxzG", spelling[1]))
      roles |= SHELL_TEST_UNARY;
    if (spelling[0] == '-' && spelling[1] == 'v')
      roles |= SHELL_TEST_LOOKUP;
    if (spelling[0] == '-' && spelling[1] == 't')
      roles |= SHELL_TEST_TERMINAL;
    if ((spelling[0] == '=' || spelling[0] == '!') && spelling[1] == '=')
      roles |= SHELL_TEST_BINARY;
    if (spelling[0] == '-' && (spelling[1] == 'a' || spelling[1] == 'o'))
      roles |= SHELL_TEST_BINARY | SHELL_TEST_JOIN;
  } else if (length == 3 && spelling[0] == '-') {
    if ((!memcmp(spelling, "-eq", 3)) || (!memcmp(spelling, "-ne", 3)) ||
        (!memcmp(spelling, "-lt", 3)) || (!memcmp(spelling, "-le", 3)) ||
        (!memcmp(spelling, "-gt", 3)) || (!memcmp(spelling, "-ge", 3)) ||
        (!memcmp(spelling, "-nt", 3)) || (!memcmp(spelling, "-ot", 3)) ||
        (!memcmp(spelling, "-ef", 3)))
      roles |= SHELL_TEST_BINARY;
  }
  return roles;
}

typedef struct {
  unsigned roles;
  bool dynamic, unsafe_lookup, number;
} shell_builtin_test_word_t;

typedef enum {
  SHELL_TEST_DISPATCH_FALSE,
  SHELL_TEST_DISPATCH_GLOBAL_STRING,
  SHELL_TEST_DISPATCH_LOCAL_STRING,
  SHELL_TEST_DISPATCH_UNARY,
  SHELL_TEST_DISPATCH_BINARY,
  SHELL_TEST_DISPATCH_JOIN,
  SHELL_TEST_DISPATCH_UNKNOWN,
  SHELL_TEST_DISPATCH_ERROR,
  SHELL_TEST_DISPATCH_GENERAL,
} shell_test_dispatch_kind_t;

typedef struct {
  shell_test_dispatch_kind_t kind;
  unsigned first, count;
  bool negated;
} shell_test_dispatch_t;

/* One owner for Bash's 0..4-argument precedence, including recursive !/()
 * shortcuts. words contains min(count, 4) projected arguments. first/count
 * select the remaining local operation; one-argument posixtest instead reads
 * invocation-wide argv[1]. Admission needs the same dispatch as evaluation,
 * without decoded strings, expression nodes or source-operation scratch. */
static inline SHELL_NONNULL(1) shell_test_dispatch_t
    shell_test_dispatch(const shell_builtin_test_word_t *words, size_t count,
                        bool implicit_terminal) {
  shell_test_dispatch_t result = {.kind = SHELL_TEST_DISPATCH_GENERAL};
  if (count > 4)
    return result;
  result.count = (unsigned)count;
  for (;;) {
    const shell_builtin_test_word_t *local = words + result.first;
    if (!result.count) {
      result.kind = SHELL_TEST_DISPATCH_FALSE;
    } else if (result.count == 1) {
      result.kind = SHELL_TEST_DISPATCH_GLOBAL_STRING;
    } else if (result.count == 2) {
      if (local[0].roles & SHELL_TEST_NOT) {
        result.kind = SHELL_TEST_DISPATCH_LOCAL_STRING;
        result.first++;
        result.negated = !result.negated;
      } else if (local[0].roles & SHELL_TEST_UNARY) {
        result.kind = SHELL_TEST_DISPATCH_UNARY;
        if (local[0].roles & SHELL_TEST_TERMINAL) {
          shell_test_terminal_operand_t operand =
              shell_test_terminal_operand(local[1].roles, !local[1].dynamic,
                                          local[1].number, implicit_terminal);
          /* An implicit descriptor leaves its connector unconsumed. A
           * counted dispatch then fails the enclosing ')' or EOF check. */
          if (operand == SHELL_TEST_TERMINAL_ERROR ||
              operand == SHELL_TEST_TERMINAL_IMPLICIT)
            result.kind = SHELL_TEST_DISPATCH_ERROR;
        }
      } else {
        result.kind = local[0].dynamic || local[1].dynamic
                          ? SHELL_TEST_DISPATCH_UNKNOWN
                          : SHELL_TEST_DISPATCH_ERROR;
      }
    } else if (result.count == 3) {
      if (local[1].roles & SHELL_TEST_BINARY) {
        result.kind = local[1].roles & SHELL_TEST_JOIN
                          ? SHELL_TEST_DISPATCH_JOIN
                          : SHELL_TEST_DISPATCH_BINARY;
      } else if (local[0].roles & SHELL_TEST_NOT) {
        result.first++;
        result.count--;
        result.negated = !result.negated;
        continue;
      } else if ((local[0].roles & SHELL_TEST_OPEN) &&
                 (local[2].roles & SHELL_TEST_CLOSE)) {
        result.kind = SHELL_TEST_DISPATCH_LOCAL_STRING;
        result.first++;
      } else {
        result.kind = local[0].dynamic || local[1].dynamic || local[2].dynamic
                          ? SHELL_TEST_DISPATCH_UNKNOWN
                          : SHELL_TEST_DISPATCH_ERROR;
      }
    } else if (local[0].roles & SHELL_TEST_NOT) {
      result.first++;
      result.count--;
      result.negated = !result.negated;
      continue;
    } else if ((local[0].roles & SHELL_TEST_OPEN) &&
               (local[3].roles & SHELL_TEST_CLOSE)) {
      result.first++;
      result.count -= 2;
      continue;
    }
    return result;
  }
}

/* Report only lookups selected by this small-argument dispatch. Unknown
 * operator bytes retain any possible -v role; errors preceding a lookup do
 * not reinterpret its operand. */
static inline SHELL_NONNULL(1) bool shell_test_dispatch_unsupported(
    const shell_builtin_test_word_t *words, shell_test_dispatch_t dispatch) {
  const shell_builtin_test_word_t *local = words + dispatch.first;
  if (dispatch.kind == SHELL_TEST_DISPATCH_UNARY)
    return (local[0].roles & SHELL_TEST_LOOKUP) && local[1].unsafe_lookup;
  if (dispatch.kind != SHELL_TEST_DISPATCH_UNKNOWN)
    return false;
  if (dispatch.count == 2)
    return local[0].dynamic && local[1].unsafe_lookup;
  return local[0].dynamic &&
         (local[1].dynamic || (local[1].roles & SHELL_TEST_LOOKUP)) &&
         local[2].unsafe_lookup;
}

typedef struct {
  char spelling[4];
  size_t length;
  bool dynamic, subscript;
  shell_test_number_t number;
} shell_builtin_test_scan_t;

static inline SHELL_NONNULL(2) bool shell_builtin_test_byte(unsigned char byte,
                                                            void *context) {
  SHELL_SOURCE_WORD_SCAN(1);
  shell_builtin_test_scan_t *scan = context;
  if (scan->length < sizeof(scan->spelling) - 1)
    scan->spelling[scan->length] = (char)byte;
  scan->length++;
  scan->subscript |= byte == '[';
  shell_test_number_byte(&scan->number, byte);
  return true;
}

static inline SHELL_NONNULL(4) void shell_builtin_test_dynamic(const char *word,
                                                               size_t length,
                                                               bool quoted,
                                                               void *context) {
  (void)word;
  (void)length;
  (void)quoted;
  shell_builtin_test_scan_t *scan = context;
  scan->dynamic = true;
}

/* A forward recognizer for the general expression grammar. One-word lookahead
 * distinguishes binary operands from unary operators. A bounded projected-word
 * queue selects nested small-argument dispatch before visiting its predicates.
 * Larger groups need a depth, not a tree or rescanning. Truth and short-circuit
 * values are not inferred: every syntactically reached lookup is checked.
 * Unresolved operator positions remain unsupported. Ordinary unary/binary
 * data has fixed consumption; -t separately retains the possibility that a
 * dynamic operand becomes a connector. */
typedef enum {
  SHELL_TEST_PRIMARY,
  SHELL_TEST_LOOKAHEAD,
  SHELL_TEST_BINARY_VALUE,
  SHELL_TEST_AFTER_PRIMARY,
  SHELL_TEST_ERROR,
} shell_builtin_test_phase_t;

/* An unknown primary followed by a binary operator normally becomes data.
 * If its runtime value is ! or (, Bash instead enters another primary before
 * consuming that operator. Keep those alternatives alive until their grammar
 * fails; an error in the ordinary-data path does not prove they also failed.
 * Bounded role states, each retaining only the largest reachable parenthesis
 * depth, bound both storage and work independently of expression length. */
enum {
  SHELL_TEST_ALT_PRIMARY,
  SHELL_TEST_ALT_STRING,
  SHELL_TEST_ALT_UNARY,
  SHELL_TEST_ALT_LOOKUP,
  SHELL_TEST_ALT_TERMINAL,
  SHELL_TEST_ALT_BINARY_VALUE,
  SHELL_TEST_ALT_AFTER,
  SHELL_TEST_ALT_COUNT,
};

typedef struct {
  unsigned active;
  size_t depth[SHELL_TEST_ALT_COUNT];
} shell_builtin_test_alternatives_t;

static inline SHELL_NONNULL(1) void shell_builtin_test_alternative_add(
    shell_builtin_test_alternatives_t *states, unsigned phase, size_t depth) {
  states->active |= 1u << phase;
  if (depth > states->depth[phase])
    states->depth[phase] = depth;
}

static inline SHELL_NONNULL(1) void shell_builtin_test_alternative_after(
    shell_builtin_test_alternatives_t *next, shell_builtin_test_word_t word,
    size_t depth) {
  if (word.dynamic || (word.roles & SHELL_TEST_JOIN))
    shell_builtin_test_alternative_add(next, SHELL_TEST_ALT_PRIMARY, depth);
  if (depth && (word.dynamic || (word.roles & SHELL_TEST_CLOSE)))
    shell_builtin_test_alternative_add(next, SHELL_TEST_ALT_AFTER, depth - 1);
}

static inline SHELL_NONNULL(1) bool shell_builtin_test_alternatives_word(
    shell_builtin_test_alternatives_t *states, shell_builtin_test_word_t word) {
  shell_builtin_test_alternatives_t next = {0};
  bool unsupported = false;
  for (unsigned phase = 0; phase < SHELL_TEST_ALT_COUNT; phase++) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (!(states->active & (1u << phase)))
      continue;
    size_t depth = states->depth[phase];
    if (phase == SHELL_TEST_ALT_PRIMARY) {
      if (word.dynamic || (word.roles & SHELL_TEST_NOT))
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_PRIMARY,
                                           depth);
      if (word.dynamic || (word.roles & SHELL_TEST_OPEN))
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_PRIMARY,
                                           depth + 1);
      if (word.dynamic || !(word.roles & (SHELL_TEST_NOT | SHELL_TEST_OPEN))) {
        unsigned head = word.roles & SHELL_TEST_TERMINAL
                            ? SHELL_TEST_ALT_TERMINAL
                        : word.roles & SHELL_TEST_LOOKUP ? SHELL_TEST_ALT_LOOKUP
                        : word.roles & SHELL_TEST_UNARY  ? SHELL_TEST_ALT_UNARY
                                                        : SHELL_TEST_ALT_STRING;
        shell_builtin_test_alternative_add(&next, head, depth);
        if (word.dynamic) {
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_LOOKUP,
                                             depth);
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_UNARY,
                                             depth);
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_TERMINAL,
                                             depth);
        }
      }
    } else if (phase == SHELL_TEST_ALT_BINARY_VALUE) {
      shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_AFTER, depth);
    } else if (phase == SHELL_TEST_ALT_AFTER) {
      shell_builtin_test_alternative_after(&next, word, depth);
    } else {
      bool binary = !word.dynamic && (word.roles & SHELL_TEST_BINARY) &&
                    !(word.roles & SHELL_TEST_JOIN);
      if (word.dynamic || binary)
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_BINARY_VALUE,
                                           depth);
      if (!binary) {
        if (phase == SHELL_TEST_ALT_STRING)
          shell_builtin_test_alternative_after(&next, word, depth);
        else if (phase == SHELL_TEST_ALT_TERMINAL) {
          shell_test_terminal_operand_t operand = shell_test_terminal_operand(
              word.roles, !word.dynamic, word.number, true);
          if (operand == SHELL_TEST_TERMINAL_IMPLICIT ||
              operand == SHELL_TEST_TERMINAL_UNKNOWN)
            shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_PRIMARY,
                                               depth);
          if (operand == SHELL_TEST_TERMINAL_CONSUME ||
              operand == SHELL_TEST_TERMINAL_UNKNOWN)
            shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_AFTER,
                                               depth);
        } else {
          unsupported |= phase == SHELL_TEST_ALT_LOOKUP && word.unsafe_lookup;
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_AFTER,
                                             depth);
        }
      }
    }
  }
  *states = next;
  return unsupported;
}

typedef struct {
  shell_builtin_test_word_t first[4], last, head;
  /* An opener, four possible interior words, and their candidate closer. */
  shell_builtin_test_word_t pending[6];
  unsigned pending_count;
  size_t count, depth;
  shell_builtin_test_phase_t phase;
  shell_builtin_test_alternatives_t alternatives;
  bool bracket, have_last, unresolved_arity, unsupported;
} shell_builtin_test_t;

static inline SHELL_NONNULL(1) void shell_builtin_test_expression_word(
    shell_builtin_test_t *state, shell_builtin_test_word_t word) {
  state->unsupported |=
      shell_builtin_test_alternatives_word(&state->alternatives, word);
  for (;;) {
    switch (state->phase) {
    case SHELL_TEST_PRIMARY:
      if (word.roles & SHELL_TEST_NOT)
        return;
      if (word.roles & SHELL_TEST_OPEN) {
        state->depth++;
        return;
      }
      state->head = word;
      state->phase = SHELL_TEST_LOOKAHEAD;
      return;
    case SHELL_TEST_LOOKAHEAD:
      if (!word.dynamic && (word.roles & SHELL_TEST_BINARY) &&
          !(word.roles & SHELL_TEST_JOIN)) {
        /* The ordinary interpretation consumes the saved word as data.
         * A !/( value makes this operator the next primary's first word.
         * Both structural alternatives have a plain head; retain their
         * maximum depth until subsequent words establish their roles. */
        if (state->head.dynamic)
          shell_builtin_test_alternative_add(
              &state->alternatives, SHELL_TEST_ALT_STRING, state->depth + 1);
        state->phase = SHELL_TEST_BINARY_VALUE;
        return;
      }
      if (state->head.dynamic) {
        state->unsupported = true;
        state->phase = SHELL_TEST_ERROR;
        return;
      }
      state->phase = SHELL_TEST_AFTER_PRIMARY;
      if (state->head.roles & SHELL_TEST_TERMINAL) {
        shell_test_terminal_operand_t operand = shell_test_terminal_operand(
            word.roles, !word.dynamic, word.number, true);
        if (operand == SHELL_TEST_TERMINAL_IMPLICIT) {
          state->phase = SHELL_TEST_PRIMARY;
        } else if (operand == SHELL_TEST_TERMINAL_UNKNOWN) {
          /* This word can be a number, a connector or an argument error. */
          shell_builtin_test_alternative_add(
              &state->alternatives, SHELL_TEST_ALT_PRIMARY, state->depth);
        } else if (operand == SHELL_TEST_TERMINAL_ERROR)
          state->phase = SHELL_TEST_ERROR;
        return;
      }
      if (state->head.roles & SHELL_TEST_UNARY) {
        state->unsupported |=
            (state->head.roles & SHELL_TEST_LOOKUP) && word.unsafe_lookup;
        return;
      }
      /* The saved head was a one-word string test. Process this lookahead
       * as its connector/closing delimiter, without revisiting source bytes. */
      break;
    case SHELL_TEST_BINARY_VALUE:
      state->phase = SHELL_TEST_AFTER_PRIMARY;
      return;
    case SHELL_TEST_AFTER_PRIMARY:
      if (word.dynamic)
        state->unsupported = true;
      else if (word.roles & SHELL_TEST_JOIN)
        state->phase = SHELL_TEST_PRIMARY;
      else if ((word.roles & SHELL_TEST_CLOSE) && state->depth)
        state->depth--;
      else
        state->phase = SHELL_TEST_ERROR;
      return;
    case SHELL_TEST_ERROR:
      return;
    }
  }
}

/* Drain projected facts only. Each group examines at most five following
 * words; fallback replays this bounded prefix through the general recognizer.
 * Bash scans for a small group's closer from its second interior word. An
 * unknown word there cannot establish that boundary and keeps the existing
 * conservative general-grammar alternatives. */
static inline SHELL_NONNULL(1) void shell_builtin_test_drain(
    shell_builtin_test_t *state, bool final) {
  while (state->pending_count) {
    unsigned consumed = 1;
    shell_builtin_test_word_t *words = state->pending;
    bool main_group = state->phase == SHELL_TEST_PRIMARY;
    bool alternative_group =
        (state->alternatives.active & (1u << SHELL_TEST_ALT_PRIMARY)) != 0;
    if ((main_group || alternative_group) &&
        (words[0].roles & SHELL_TEST_OPEN)) {
      unsigned depth = 1, close = 0;
      bool dynamic = false;
      for (unsigned i = 2; i < state->pending_count; ++i) {
        SHELL_SOURCE_WORD_SCAN(1);
        if (words[i].dynamic) {
          dynamic = true;
          break;
        }
        if (words[i].roles & SHELL_TEST_OPEN)
          depth++;
        else if ((words[i].roles & SHELL_TEST_CLOSE) && !--depth) {
          close = i;
          break;
        }
      }
      if (!close && !dynamic && state->pending_count < 6 && !final)
        return;
      if (close) {
        shell_test_dispatch_t dispatch =
            shell_test_dispatch(words + 1, close - 1, true);
        if (dispatch.kind != SHELL_TEST_DISPATCH_GENERAL) {
          /* Advance other paths normally. The primary alternatives consume
           * this group using the same counted dispatch as the main path. */
          size_t alternative_depth =
              state->alternatives.depth[SHELL_TEST_ALT_PRIMARY];
          if (alternative_group)
            state->alternatives.active &= ~(1u << SHELL_TEST_ALT_PRIMARY);
          for (unsigned i = 0; i <= close; ++i) {
            if (main_group)
              state->unsupported |= shell_builtin_test_alternatives_word(
                  &state->alternatives, words[i]);
            else
              shell_builtin_test_expression_word(state, words[i]);
          }
          state->unsupported |=
              shell_test_dispatch_unsupported(words + 1, dispatch);
          if (main_group)
            state->phase = dispatch.kind == SHELL_TEST_DISPATCH_ERROR
                               ? SHELL_TEST_ERROR
                               : SHELL_TEST_AFTER_PRIMARY;
          if (alternative_group && dispatch.kind != SHELL_TEST_DISPATCH_ERROR)
            shell_builtin_test_alternative_add(
                &state->alternatives, SHELL_TEST_ALT_AFTER, alternative_depth);
          consumed = close + 1;
        } else
          shell_builtin_test_expression_word(state, words[0]);
      } else
        shell_builtin_test_expression_word(state, words[0]);
    } else
      shell_builtin_test_expression_word(state, words[0]);
    state->pending_count -= consumed;
    memmove(words, words + consumed, state->pending_count * sizeof(words[0]));
  }
}

static inline SHELL_NONNULL(1) void shell_builtin_test_append(
    shell_builtin_test_t *state, shell_builtin_test_word_t word) {
  if (state->count < sizeof(state->first) / sizeof(state->first[0]))
    state->first[state->count] = word;
  state->count++;
  if (!state->pending_count &&
      (!(word.roles & SHELL_TEST_OPEN) ||
       (state->phase != SHELL_TEST_PRIMARY &&
        !(state->alternatives.active & (1u << SHELL_TEST_ALT_PRIMARY))))) {
    shell_builtin_test_expression_word(state, word);
    return;
  }
  state->pending[state->pending_count++] = word;
  shell_builtin_test_drain(state, false);
}

/* State was initialized once for the effective builtin. A bracket form delays
 * its last word so the required closing `]` never becomes an expression word.
 * Finish at the simple-command boundary, not after an arbitrary word: Bash's
 * 0..4-argument disambiguation can make a spelling such as `-v` ordinary data.
 */
static inline SHELL_NONNULL(1, 2) void shell_builtin_test_word(
    shell_builtin_test_t *state, const char *word, size_t length) {
  shell_builtin_test_scan_t scan = {0};
  state->unresolved_arity |= !shell_builtin_visit_single_word(
      word, length, shell_builtin_test_byte, shell_builtin_test_dynamic, &scan);
  shell_builtin_test_word_t classified = {
      .dynamic = scan.dynamic,
      .unsafe_lookup = scan.dynamic || scan.subscript,
      .number = !scan.dynamic && scan.number.digits && !scan.number.invalid,
  };
  if (!scan.dynamic && scan.length < sizeof(scan.spelling)) {
    classified.roles = shell_test_static_roles(scan.spelling, scan.length);
  }
  if (state->bracket) {
    if (state->have_last)
      shell_builtin_test_append(state, state->last);
    state->last = classified;
    state->have_last = true;
  } else
    shell_builtin_test_append(state, classified);
}

static inline SHELL_NONNULL(1) bool shell_builtin_test_unsupported(
    shell_builtin_test_t *state) {
  if (state->unresolved_arity)
    return true;
  if (state->bracket) {
    if (!state->have_last)
      return false;
    if (state->last.dynamic)
      return true;
    if (!(state->last.roles & SHELL_TEST_END))
      return false;
  }
  shell_test_dispatch_t dispatch =
      shell_test_dispatch(state->first, state->count, state->count >= 4);
  if (dispatch.kind != SHELL_TEST_DISPATCH_GENERAL)
    return shell_test_dispatch_unsupported(state->first, dispatch);
  shell_builtin_test_drain(state, true);
  return state->unsupported ||
         (state->phase == SHELL_TEST_LOOKAHEAD && state->head.dynamic);
}

/* Private test evaluation. Words borrow immutable source and operation-owned
 * decoded or callback values. Prepare each complete logical argument once.
 * Programs and their nodes live in source-operation scratch; no heap is used.
 * FALSE/TRUE are Boolean possibilities; ERROR is a builtin argument failure,
 * which remains distinct while composing eagerly evaluated expressions. */
enum {
  SHELL_TEST_FALSE = 1u,
  SHELL_TEST_TRUE = 2u,
  SHELL_TEST_ERROR_RESULT = 4u
};
typedef struct {
  const char *source, *value;
  size_t length, value_length;
  bool known;
  bool number;
  uint32_t token; /* Graph adapter argv ordinal; unused by the evaluator. */
} shell_test_value_t;

/* Install one decoded or validated callback value and prepare numeric facts
 * once, before route-state evaluation can visit the program repeatedly. */
static inline SHELL_NONNULL(1, 2) void shell_test_set_value(
    shell_test_value_t *value, const char *data, size_t length) {
  shell_test_number_t number = {0};
  for (size_t i = 0; i < length; ++i)
    shell_test_number_byte(&number, (unsigned char)data[i]);
  value->value = data;
  value->value_length = length;
  value->known = true;
  value->number = number.digits && !number.invalid;
}
typedef struct {
  uint16_t left, right;
  uint8_t operation;
} shell_test_node_t;
typedef struct shell_test_program {
  shell_test_value_t *words;
  shell_test_node_t *nodes;
  uint16_t count, root, word_count;
  bool active, proven_error;
} shell_test_program_t;
typedef unsigned (*shell_test_lookup_t)(const char *name, size_t length,
                                        void *context);
typedef bool (*shell_test_assume_t)(const char *name, size_t length,
                                    unsigned presence, void *context);
typedef void (*shell_test_presence_observer_t)(const char *name, size_t length,
                                               void *context);
#ifdef __cplusplus
extern "C" {
#endif
/* Returns false only on operation scratch exhaustion. Static scalar names
 * use ASCII identifier rules; this helper never resolves a runtime name. */
bool shell_test_prepare_value(const char *source, size_t length,
                              shell_test_value_t *value) SHELL_NONNULL(1, 3);
bool shell_test_scalar_name(const char *name, size_t length) SHELL_NONNULL(1);
bool shell_test_static_scalar(const char *word, size_t length) SHELL_NONNULL(1);
/* words has count prepared entries, count <= SHELL_DEP_MAX_TOKENS. A NULL
 * words pointer is meaningful only when count is zero. bracket removes its
 * final, statically established ] before applying Bash argument-count rules. */
bool shell_test_compile(shell_test_value_t *words, size_t count, bool bracket,
                        shell_test_program_t *program) SHELL_NONNULL(4);
/* Admission has proved that every grammar path ends in an argument error. */
void shell_test_prove_error(shell_test_program_t *program) SHELL_NONNULL(1);
bool shell_test_compile_presence(const char *word, size_t length, bool negated,
                                 shell_test_program_t *program)
    SHELL_NONNULL(1, 4);
unsigned shell_test_evaluate(const shell_test_program_t *program,
                             shell_test_lookup_t lookup, void *context)
    SHELL_NONNULL(1, 2, 3);
/* Report static scalar lookup targets reachable in the compiled expression.
 * Names borrow decoded program values; orphaned nodes from a failed parse and
 * ordinary string operands are excluded. No source traversal or allocation. */
void shell_test_observe_presence(const shell_test_program_t *program,
                                 shell_test_presence_observer_t observer,
                                 void *context) SHELL_NONNULL(1, 2, 3);
/* Refine only facts implied by the desired Boolean result. Error alternatives
 * prevent false-result refinement. Callbacks own path-local fact storage. */
bool shell_test_require(const shell_test_program_t *program, unsigned desired,
                        shell_test_lookup_t lookup, shell_test_assume_t assume,
                        void *context) SHELL_NONNULL(1, 3, 4, 5);

#ifdef __cplusplus
}
#endif

#endif
