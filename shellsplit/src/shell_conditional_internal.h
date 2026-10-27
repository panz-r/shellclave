#ifndef SHELL_CONDITIONAL_INTERNAL_H
#define SHELL_CONDITIONAL_INTERNAL_H

#include "shell_contract.h"
#include "shell_tokenizer.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
  SHELL_CONDITIONAL_NONE,
  SHELL_CONDITIONAL_COMPLETE,
  SHELL_CONDITIONAL_INCOMPLETE,
  SHELL_CONDITIONAL_INVALID,
  SHELL_CONDITIONAL_UNSUPPORTED,
} shell_conditional_frame_t;

/* Private recognition boundary for a possible command-position [[. Source is
 * immutable and readable through length; start <= length. Offsets borrow that
 * source. Wider predicates are unsupported without a Bash-validity claim.
 * after advances over every recognized construct, including received EOF.
 * Expected grammar-token prefixes at EOF remain INCOMPLETE; the source layer
 * owns whether this received boundary is still appendable or already closed.
 * Operands exclude those partial grammar tokens. */
typedef struct {
  shell_conditional_frame_t frame;
  size_t content, end, after;
  size_t operands[2], operand_lengths[2];
  uint8_t operand_count;
  shell_conditional_predicate_t predicate;
  bool negated;
} shell_conditional_t;

static inline bool
shell_conditional_pattern(shell_conditional_predicate_t predicate) {
  return predicate == SHELL_CONDITIONAL_PATTERN_MATCH ||
         predicate == SHELL_CONDITIONAL_PATTERN_NOT_MATCH;
}

/* Zero denotes an invalid/no predicate. Arity is a semantic property, not an
 * ordering relationship between public enum values. */
static inline unsigned
shell_conditional_arity(shell_conditional_predicate_t predicate) {
  switch (predicate) {
  case SHELL_CONDITIONAL_STRING_NONEMPTY:
  case SHELL_CONDITIONAL_STRING_EMPTY:
  case SHELL_CONDITIONAL_VARIABLE_SET:
  case SHELL_CONDITIONAL_FILE_EXISTS:
  case SHELL_CONDITIONAL_FILE_REGULAR:
  case SHELL_CONDITIONAL_FILE_DIRECTORY:
  case SHELL_CONDITIONAL_FILE_SYMLINK:
  case SHELL_CONDITIONAL_FILE_NONEMPTY:
  case SHELL_CONDITIONAL_FILE_BLOCK:
  case SHELL_CONDITIONAL_FILE_CHARACTER:
  case SHELL_CONDITIONAL_FILE_FIFO:
  case SHELL_CONDITIONAL_FILE_SOCKET:
    return 1;
  case SHELL_CONDITIONAL_STRING_EQUAL:
  case SHELL_CONDITIONAL_STRING_NOT_EQUAL:
  case SHELL_CONDITIONAL_PATTERN_MATCH:
  case SHELL_CONDITIONAL_PATTERN_NOT_MATCH:
    return 2;
  default:
    return 0;
  }
}

static inline uint32_t
shell_conditional_features(shell_conditional_predicate_t predicate) {
  return SHELL_FEAT_CONDITIONALS |
         (shell_conditional_pattern(predicate) ? SHELL_FEAT_GLOBS : 0);
}

shell_conditional_t shell_conditional_parse(const char *source, size_t length,
                                            size_t start) SHELL_NONNULL(1);

/* Complete conditional operand, without splitting/globbing/brace expansion.
 * Static values use the shared effective fragment decoder. Dynamic values
 * include leading and assignment-shaped tilde expansion and remain unknown;
 * quoted expansions remain dynamic. The source scanner's unquoted-only view
 * is used solely for RHS admission. Neither operation executes expansion. */
bool shell_conditional_static_empty(const char *word, size_t length,
                                    bool *empty) SHELL_NONNULL(1, 3);
bool shell_conditional_word_dynamic(const char *word, size_t length)
    SHELL_NONNULL(1);

/* Resolved values borrow validated NUL-free payloads. data may be NULL only
 * when length is zero; unknown values are obtained from static source or
 * remain unknown. condition is a complete supported parse of source. */
typedef struct {
  const char *data;
  size_t length;
  bool known;
} shell_conditional_value_t;

/* Return whether truth is known. Scratch exhaustion remains observable through
 * the enclosing source operation. Uses operation scratch for one static value,
 * releasing it before return. Static star patterns use projected units and a
 * KMP prefix table with linear matching work. Never executes expansion or
 * allocates a heap. */
bool shell_conditional_evaluate(const char *source,
                                const shell_conditional_t *condition,
                                const shell_conditional_value_t values[2],
                                bool *truth) SHELL_NONNULL(1, 2, 3, 4);

#endif
