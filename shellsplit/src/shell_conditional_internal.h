#ifndef SHELL_CONDITIONAL_INTERNAL_H
#define SHELL_CONDITIONAL_INTERNAL_H

#include "shell_contract.h"
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
 * after advances over every recognized construct, including received EOF. */
typedef struct {
  shell_conditional_frame_t frame;
  size_t content, end, after, operand, operand_length;
  bool empty, negated;
} shell_conditional_t;

shell_conditional_t shell_conditional_parse(const char *source, size_t length,
                                            size_t start) SHELL_NONNULL(1);

/* Complete conditional operand, without splitting/globbing/brace expansion.
 * Static values use the shared effective fragment decoder. Dynamic values
 * remain unknown; this operation never executes shell expansion. */
bool shell_conditional_static_empty(const char *word, size_t length,
                                    bool *empty) SHELL_NONNULL(1, 3);
bool shell_conditional_word_dynamic(const char *word, size_t length)
    SHELL_NONNULL(1);

#endif
