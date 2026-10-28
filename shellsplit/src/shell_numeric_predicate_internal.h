#ifndef SHELL_NUMERIC_PREDICATE_INTERNAL_H
#define SHELL_NUMERIC_PREDICATE_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Shared comparison identities. Operand decoding and numeric interpretation
 * belong to the enclosing conditional or builtin grammar. */
#define SHELL_NUMERIC_COMPARISONS(X)                                           \
  X(EQUAL, "-eq")                                                              \
  X(NOT_EQUAL, "-ne")                                                          \
  X(LESS, "-lt")                                                               \
  X(LESS_EQUAL, "-le")                                                         \
  X(GREATER, "-gt")                                                            \
  X(GREATER_EQUAL, "-ge")

typedef enum {
  SHELL_NUMERIC_NONE,
#define NUMERIC_KIND(kind, spelling) SHELL_NUMERIC_##kind,
  SHELL_NUMERIC_COMPARISONS(NUMERIC_KIND)
#undef NUMERIC_KIND
} shell_numeric_comparison_t;

static inline SHELL_NONNULL(1) shell_numeric_comparison_t
    shell_numeric_comparison(const char *word, size_t length) {
  if (length != 3)
    return SHELL_NUMERIC_NONE;
#define NUMERIC_WORD(kind, spelling)                                           \
  if (!memcmp(word, spelling, 3))                                              \
    return SHELL_NUMERIC_##kind;
  SHELL_NUMERIC_COMPARISONS(NUMERIC_WORD)
#undef NUMERIC_WORD
  return SHELL_NUMERIC_NONE;
}

static inline bool shell_numeric_compare(shell_numeric_comparison_t kind,
                                         intmax_t left, intmax_t right) {
  switch (kind) {
  case SHELL_NUMERIC_EQUAL:
    return left == right;
  case SHELL_NUMERIC_NOT_EQUAL:
    return left != right;
  case SHELL_NUMERIC_LESS:
    return left < right;
  case SHELL_NUMERIC_LESS_EQUAL:
    return left <= right;
  case SHELL_NUMERIC_GREATER:
    return left > right;
  case SHELL_NUMERIC_GREATER_EQUAL:
    return left >= right;
  default:
    return false;
  }
}
#endif
