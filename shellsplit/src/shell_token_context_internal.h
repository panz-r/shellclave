#ifndef SHELL_TOKEN_CONTEXT_INTERNAL_H
#define SHELL_TOKEN_CONTEXT_INTERNAL_H

#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"

/* Pure lexical facts shared by list/control grammar and semantic admission.
 * These helpers do not decide feature support or repeat a root validation. */
typedef struct {
  size_t end;
  bool eligible;
  bool scanned;
  bool has_time;
  bool has_stage;
} semantic_pipeline_prefix_t;

static inline bool control_token_is_word(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_COMMAND ||
         token->type == SHELL_TOKEN_ARGUMENT ||
         token->type == SHELL_TOKEN_ANSI_C_QUOTED ||
         token->type == SHELL_TOKEN_EXTGLOB ||
         token->type == SHELL_TOKEN_GLOB ||
         token->type == SHELL_TOKEN_ARRAY_ASSIGNMENT;
}

static inline bool control_token_starts_function_definition(
    const shell_token_t *token, const char *input, size_t input_length) {
  if (!control_token_is_word(token) || token->position > input_length ||
      token->length > input_length - token->position)
    return false;

  size_t word_end;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end))
    return false;
  return shell_source_function_declarator_after(input, input_length, word_end);
}

/* Source spans include every lexical fragment of a redirect operand. */
static inline size_t full_redirect_end(const char *input, size_t input_length,
                                       const shell_token_t *token) {
  size_t end = shell_source_skip_redirect(input, token->position, input_length);
  return end > token->position ? end : 0;
}

/* A HEREDOC lexical token includes any descriptor prefix and delimiter word.
 * Locate its already-recognized `<<` operator so the shared source helper can
 * traverse the entire FIFO declaration line without treating unrelated `<<`
 * syntax, such as an arithmetic shift, as a document. */
static inline bool heredoc_token_operator_position(const shell_token_t *token,
                                                   size_t *operator_position) {
  if (!token || !token->start || !operator_position ||
      token->type != SHELL_TOKEN_HEREDOC)
    return false;
  for (size_t i = 0; i < token->length; i++) {
    size_t after = 0;
    if (token->start[i] == '<' &&
        shell_source_match_logical_punctuation(token->start, token->length, i,
                                               "<<", &after) &&
        !shell_source_match_logical_punctuation(token->start, token->length, i,
                                                "<<<", NULL)) {
      *operator_position = token->position + i;
      return true;
    }
  }
  return false;
}

static inline semantic_pipeline_prefix_t
semantic_pipeline_prefix_initial(void) {
  return (semantic_pipeline_prefix_t){.eligible = true};
}

/* Control classification and semantic admission consume lexical tokens,
 * whereas reserved `time` and `!` belong to the surrounding pipeline grammar.
 * Recover that grammar from the shared source parser and leave the command-word
 * position open until the first actual stage token. Required token/state
 * storage is owned by the calling scanner; the token borrows its unchanged
 * input source span. */
static inline SHELL_NONNULL(1, 3, 4) bool semantic_token_is_pipeline_prefix(
    const char *input, size_t input_length, const shell_token_t *token,
    semantic_pipeline_prefix_t *state) {
  if (!state->eligible)
    return false;
  if (!state->scanned) {
    shell_source_pipeline_prefix_t prefix = shell_source_parse_pipeline_prefix(
        input, token->position, input_length);
    state->end = prefix.valid && prefix.has_modifier ? prefix.stage_start
                                                     : token->position;
    state->has_time = prefix.valid && prefix.has_modifier &&
                      prefix.time_mode != SHELL_PIPE_TIME_NONE;
    state->scanned = true;
  }
  if (token->position < state->end)
    return true;
  state->eligible = false;
  return false;
}

/* Recognize a conditional opener still exposed as ordinary diagnostic word
 * fragments, including a received final [[. A recognized CONDITIONAL_COMMAND
 * token already has its own framing path. Match raw logical punctuation so
 * quoted spellings and [[literal remain ordinary words. Arithmetic framing
 * belongs to the lexer and is not classified by this fallback. */
static inline bool
token_starts_bash_compound_command(const shell_token_t *token,
                                   const char *input, size_t input_length) {
  if (token && token->type == SHELL_TOKEN_CONDITIONAL_COMMAND)
    return false;
  if (!token || !input || token->position > input_length ||
      token->length == 0 || token->length > input_length - token->position)
    return false;
  if (shell_token_is_literal(token))
    return false;

  size_t position = token->position;
  size_t after = 0;
  /* Bash recognizes `[[` as a conditional command only when the delimiter
   * after it begins the condition. Keep a word such as `[[literal` lexical
   * data instead of rejecting a possible external command name. */
  if (!shell_source_match_logical_punctuation(input, input_length, position,
                                              "[[", &after))
    return false;
  after = shell_source_skip_escaped_line_endings(input, input_length, after);
  return after == input_length ||
         shell_source_space((unsigned char)input[after]);
}

#endif
