#ifndef SHELL_TEST_GRAMMAR_INTERNAL_H
#define SHELL_TEST_GRAMMAR_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Shared effective-argument roles, numeric facts and argument-count dispatch
 * for test/[ admission and evaluation. Consumers supply projected word facts;
 * source-word scanning and cardinality checks belong to admission. */
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

#endif
