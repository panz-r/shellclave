#ifndef SHELL_TOKENIZER_FULL_INTERNAL_H
#define SHELL_TOKENIZER_FULL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  SHELL_CONTROL_SYNTAX_NONE = 0,
  SHELL_CONTROL_SYNTAX_COMPLETE,
  SHELL_CONTROL_SYNTAX_INCOMPLETE,
} shell_control_syntax_t;

/* Lexer-aware control-flow classification shared by the fast parser,
 * canonical processors, and dependency graph. It recognizes reserved words
 * only where shell grammar permits them, so ordinary arguments remain words. */
shell_control_syntax_t shell_tokenizer_control_syntax(const char *input,
                                                      size_t input_length);

static inline bool
shell_tokenizer_has_unsupported_control(const char *input,
                                        size_t input_length) {
  return shell_tokenizer_control_syntax(input, input_length) !=
         SHELL_CONTROL_SYNTAX_NONE;
}

#endif
