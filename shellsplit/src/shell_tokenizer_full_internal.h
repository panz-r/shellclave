#ifndef SHELL_TOKENIZER_FULL_INTERNAL_H
#define SHELL_TOKENIZER_FULL_INTERNAL_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/* Syntax that remains lexically visible but is outside Shellclave's
 * one-command semantic model. */
bool shell_tokenizer_has_unsupported_semantics(const char *input,
                                               size_t input_length);

/* Validate the shell list operators exposed by the lexer. This is deliberately
 * narrower than complete shell grammar validation: it rejects impossible
 * operator chains while retaining the tokenizer's diagnostic tolerance for an
 * unfinished parenthesized group. */
bool shell_tokenizer_list_syntax_valid(const char *input, size_t input_length);

/* Inspect the contents of one already-delimited arithmetic expansion for
 * array semantics, including nested executable substitutions. */
bool shell_tokenizer_arithmetic_has_array_semantics(const char *input,
                                                    size_t input_length);

/* Report an unescaped parameter expansion anywhere within one lexical token.
 * This includes a variable adjacent to literal word fragments, such as
 * `--limit=${count}`, without treating that one shell word as several argv
 * entries. */
bool shell_tokenizer_token_has_variable(const shell_token_t *token);

/* Tokens borrowing one source buffer belong to the same logical shell word
 * when physically adjacent or separated only by escaped line endings. */
static inline bool
shell_tokenizer_token_continues_word(const shell_token_t *token, size_t end) {
  if (!token)
    return false;
  if (end == token->position)
    return true;
  if (end > token->position)
    return false;
  size_t gap = token->position - end;
  const char *text = token->start - gap;
  for (size_t i = 0; i < gap;) {
    if (text[i] != '\\' || i + 1 >= gap ||
        (text[i + 1] != '\n' && text[i + 1] != '\r'))
      return false;
    i += 2;
    if (text[i - 1] == '\r' && i < gap && text[i] == '\n')
      i++;
  }
  return true;
}

static inline bool
shell_tokenizer_has_unsupported_control(const char *input,
                                        size_t input_length) {
  return shell_tokenizer_control_syntax(input, input_length) !=
         SHELL_CONTROL_SYNTAX_NONE;
}

#endif
