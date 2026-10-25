#ifndef SHELL_TOKEN_TRAITS_INTERNAL_H
#define SHELL_TOKEN_TRAITS_INTERNAL_H

#include "shell_tokenizer_full.h"

/* Lexical type facts only. Consumers retain their own operand, execution and
 * policy roles; a process substitution, for example, is still a word. */
static inline bool shell_token_type_is_redirection(shell_token_type_t type) {
  return type == SHELL_TOKEN_REDIRECT_IN || type == SHELL_TOKEN_REDIRECT_OUT ||
         type == SHELL_TOKEN_REDIRECT_ERR ||
         type == SHELL_TOKEN_REDIRECT_APPEND ||
         type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         type == SHELL_TOKEN_REDIRECT_BOTH ||
         type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         type == SHELL_TOKEN_HEREDOC || type == SHELL_TOKEN_HERESTRING;
}

static inline bool shell_token_type_is_separator(shell_token_type_t type) {
  return type == SHELL_TOKEN_PIPE || type == SHELL_TOKEN_PIPE_BOTH ||
         type == SHELL_TOKEN_SEMICOLON || type == SHELL_TOKEN_AND ||
         type == SHELL_TOKEN_BACKGROUND || type == SHELL_TOKEN_OR;
}

static inline bool
shell_token_type_is_expression_command(shell_token_type_t type) {
  return type == SHELL_TOKEN_ARITHMETIC_COMMAND ||
         type == SHELL_TOKEN_CONDITIONAL_COMMAND;
}

static inline bool shell_token_type_is_syntax(shell_token_type_t type) {
  return shell_token_type_is_separator(type) ||
         shell_token_type_is_redirection(type) ||
         shell_token_type_is_expression_command(type) ||
         type == SHELL_TOKEN_PIPE_NEGATE || type == SHELL_TOKEN_PIPE_TIME ||
         type == SHELL_TOKEN_PIPE_TIME_OPTION ||
         type == SHELL_TOKEN_GROUP_START || type == SHELL_TOKEN_GROUP_END ||
         type == SHELL_TOKEN_SUBSHELL_START || type == SHELL_TOKEN_SUBSHELL_END;
}

#endif
