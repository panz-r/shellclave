#define _POSIX_C_SOURCE 200809L
#include "shell_transform.h"
#include "alloc.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *VAR_PLACEHOLDER = "VAR_VALUE";
static const char *GLOB_PLACEHOLDER = "FILE_PATTERN";
static const char *SUBSHELL_PLACEHOLDER = "TEMP_FILE";

static bool is_shell_syntax_token(shell_token_type_t type) {
  return type == SHELL_TOKEN_PIPE || type == SHELL_TOKEN_PIPE_BOTH ||
         type == SHELL_TOKEN_PIPE_NEGATE || type == SHELL_TOKEN_REDIRECT_IN ||
         type == SHELL_TOKEN_REDIRECT_OUT || type == SHELL_TOKEN_REDIRECT_ERR ||
         type == SHELL_TOKEN_REDIRECT_APPEND ||
         type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         type == SHELL_TOKEN_REDIRECT_BOTH ||
         type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         type == SHELL_TOKEN_SEMICOLON || type == SHELL_TOKEN_AND ||
         type == SHELL_TOKEN_BACKGROUND || type == SHELL_TOKEN_OR ||
         type == SHELL_TOKEN_GROUP_START || type == SHELL_TOKEN_GROUP_END ||
         type == SHELL_TOKEN_SUBSHELL_START ||
         type == SHELL_TOKEN_SUBSHELL_END || type == SHELL_TOKEN_HEREDOC ||
         type == SHELL_TOKEN_HERESTRING || type == SHELL_TOKEN_PROCESS_SUB;
}

/* A variable may be adjacent to literal bytes within one shell word. Preserve
 * those bytes in the diagnostic display: `--limit=${count}` is one argv item,
 * not two items and not merely a bare generic variable. */
static shell_transform_status_t
transform_replace_word_variables(const shell_token_t *token, char **out,
                                 bool *replaced) {
  if (!token || !token->start || !out || !replaced)
    return SHELL_TRANSFORM_EINPUT;
  *out = NULL;
  *replaced = false;

  const char *text = token->start;
  size_t length = token->length;
  size_t output_length = 0;
  size_t literal_start = 0;
  shell_source_variable_scan_t scan = {0};
  size_t variable_start = 0, variable_after = 0;
  while (shell_source_next_variable_expansion(
      text, length, &scan, &variable_start, &variable_after)) {
    size_t literal_length = variable_start - literal_start;
    if (literal_length > SIZE_MAX - output_length ||
        strlen(VAR_PLACEHOLDER) > SIZE_MAX - output_length - literal_length)
      return SHELL_TRANSFORM_EOVERFLOW;
    output_length += literal_length + strlen(VAR_PLACEHOLDER);
    literal_start = variable_after;
    *replaced = true;
  }
  if (!*replaced)
    return SHELL_TRANSFORM_OK;

  /* Reserve the terminating NUL in the same final bound check. Equality
   * would otherwise let the following `+ 1` wrap. */
  if (length - literal_start >= SIZE_MAX - output_length)
    return SHELL_TRANSFORM_EOVERFLOW;
  output_length += length - literal_start;

  char *replacement = malloc(output_length + 1);
  if (!replacement)
    return SHELL_TRANSFORM_ENOMEM;
  size_t written = 0;
  literal_start = 0;
  scan = (shell_source_variable_scan_t){0};
  while (shell_source_next_variable_expansion(
      text, length, &scan, &variable_start, &variable_after)) {
    size_t literal_length = variable_start - literal_start;
    memcpy(replacement + written, text + literal_start, literal_length);
    written += literal_length;
    size_t placeholder_length = strlen(VAR_PLACEHOLDER);
    memcpy(replacement + written, VAR_PLACEHOLDER, placeholder_length);
    written += placeholder_length;
    literal_start = variable_after;
  }
  memcpy(replacement + written, text + literal_start, length - literal_start);
  written += length - literal_start;
  replacement[written] = '\0';
  *out = replacement;
  return SHELL_TRANSFORM_OK;
}

/* A quoted variable token normally stands for exactly one expansion, such as
 * `"$name"`. Keep its compact display placeholder in that case. Once the
 * shell word also contains literal bytes, it must follow the word-fragment
 * path so the display preserves its one-word structure. */
static bool token_is_bare_variable_expansion(const shell_token_t *token) {
  if (!token || !token->start)
    return false;
  shell_source_variable_scan_t scan = {0};
  size_t variable_start = 0;
  size_t variable_after = 0;
  if (!shell_source_next_variable_expansion(token->start, token->length, &scan,
                                            &variable_start, &variable_after))
    return false;
  size_t ignored_start = 0;
  size_t ignored_after = 0;
  if (shell_source_next_variable_expansion(token->start, token->length, &scan,
                                           &ignored_start, &ignored_after))
    return false;
  if (variable_start == 0 && variable_after == token->length)
    return true;
  return token->length >= 2 && token->start[0] == '"' &&
         token->start[token->length - 1] == '"' && variable_start == 1 &&
         variable_after == token->length - 1;
}

void shell_transformed_command_free(shell_transformed_command_t *command) {
  if (!command)
    return;
  free((void *)command->original_command);
  free((void *)command->display_text);
  if (command->tokens) {
    for (size_t i = 0; i < command->token_count; i++) {
      free((void *)command->tokens[i].original);
      if (command->tokens[i].transformed != command->tokens[i].original)
        free((void *)command->tokens[i].transformed);
    }
    free(command->tokens);
  }
  free(command);
}

static shell_transform_status_t
measure_transformed_command(const shell_transformed_command_t *command,
                            size_t *total_output) {
  size_t total = 0;
  const char *command_strings[] = {command->original_command,
                                   command->display_text};
  for (size_t i = 0; i < 2; i++) {
    size_t length = strlen(command_strings[i]);
    if (length > SIZE_MAX - total)
      return SHELL_TRANSFORM_EOVERFLOW;
    total += length;
  }
  for (size_t i = 0; i < command->token_count; i++) {
    const char *token_strings[] = {command->tokens[i].original,
                                   command->tokens[i].transformed};
    for (size_t j = 0; j < 2; j++) {
      size_t length = strlen(token_strings[j]);
      if (length > SIZE_MAX - total)
        return SHELL_TRANSFORM_EOVERFLOW;
      total += length;
    }
  }
  *total_output = total;
  return SHELL_TRANSFORM_OK;
}

static shell_transformed_token_t
create_transformed_token(const char *original, const char *transformed,
                         shell_transform_type_t type, bool is_shell_construct) {
  shell_transformed_token_t token;
  token.original = original;
  token.transformed = transformed;
  token.type = type;
  token.is_shell_construct = is_shell_construct;
  return token;
}

static void free_transformed_tokens(shell_transformed_token_t *tokens,
                                    size_t count) {
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].original);
    if (tokens[i].transformed != tokens[i].original)
      free((void *)tokens[i].transformed);
  }
  free(tokens);
}

static bool transform_tokens_share_word(const shell_token_t *left,
                                        const shell_token_t *right) {
  return left && right && left->position <= SIZE_MAX - left->length &&
         !is_shell_syntax_token(left->type) &&
         !is_shell_syntax_token(right->type) &&
         shell_tokenizer_token_continues_word(right,
                                              left->position + left->length);
}

/* Remove source-only escaped physical line endings from diagnostic fragments
 * without changing literal newlines inside ordinary single quotes. */
static size_t transform_fragment_display_write(const char *text,
                                               char *destination) {
  size_t length = strlen(text);
  char quote = '\0';
  size_t written = 0;
  for (size_t i = 0; i < length; i++) {
    char c = text[i];
    if (c == '\\' && quote != '\'' && i + 1 < length &&
        (text[i + 1] == '\n' || text[i + 1] == '\r')) {
      bool crlf = text[i + 1] == '\r' && i + 2 < length && text[i + 2] == '\n';
      i += crlf ? 2 : 1;
      continue;
    }
    if (destination)
      destination[written] = c;
    written++;
    if (c == '\\' && quote != '\'' && i + 1 < length) {
      if (destination)
        destination[written] = text[i + 1];
      written++;
      i++;
      continue;
    }
    if (quote == '\0') {
      if (c == '\'' || c == '"')
        quote = c;
    } else if (c == quote) {
      quote = '\0';
    }
  }
  return written;
}

static char *build_transformed_command(const shell_command_t *command,
                                       shell_transformed_token_t *tokens,
                                       size_t token_count,
                                       shell_transform_status_t *status) {
  if (!command || !tokens || !status)
    return NULL;
  size_t total_length = 0;
  for (size_t i = 0; i < token_count; i++) {
    size_t part_length =
        transform_fragment_display_write(tokens[i].transformed, NULL);
    bool separator = i > 0 && !transform_tokens_share_word(
                                  &command->tokens[i - 1], &command->tokens[i]);
    if (part_length > SIZE_MAX - total_length ||
        (separator && total_length == SIZE_MAX)) {
      *status = SHELL_TRANSFORM_EOVERFLOW;
      return NULL;
    }
    total_length += part_length;
    if (separator) {
      if (total_length == SIZE_MAX) {
        *status = SHELL_TRANSFORM_EOVERFLOW;
        return NULL;
      }
      total_length++;
    }
  }
  if (total_length == SIZE_MAX) {
    *status = SHELL_TRANSFORM_EOVERFLOW;
    return NULL;
  }

  char *buffer = malloc(total_length + 1);
  if (!buffer) {
    *status = SHELL_TRANSFORM_ENOMEM;
    return NULL;
  }

  char *pos = buffer;
  for (size_t i = 0; i < token_count; i++) {
    if (i > 0 && !transform_tokens_share_word(&command->tokens[i - 1],
                                              &command->tokens[i]))
      *pos++ = ' ';
    size_t length =
        transform_fragment_display_write(tokens[i].transformed, pos);
    pos += length;
  }
  *pos = '\0';
  return buffer;
}

shell_transform_status_t
shell_transform_command(const shell_command_t *cmd,
                        const shell_transform_limits_t *limits,
                        shell_transformed_command_t **transformed_cmd) {
  if (!transformed_cmd)
    return SHELL_TRANSFORM_EINPUT;
  *transformed_cmd = NULL;
  if (!cmd)
    return SHELL_TRANSFORM_EINPUT;

  shell_transformed_command_t *tcmd =
      malloc(sizeof(shell_transformed_command_t));
  if (!tcmd)
    return SHELL_TRANSFORM_ENOMEM;

  tcmd->original_command = NULL;
  tcmd->display_text = NULL;
  tcmd->tokens = NULL;
  tcmd->token_count = 0;
  tcmd->has_transformations = false;
  tcmd->has_shell_syntax = false;

  // Validate tokenized input exists before constructing transformed output.
  if (cmd->token_count == 0 || cmd->tokens == NULL) {
    free(tcmd);
    return SHELL_TRANSFORM_EINPUT;
  }

  const shell_token_t *first_token = &cmd->tokens[0];
  if (!first_token->start || cmd->end_pos < cmd->start_pos ||
      first_token->position < cmd->start_pos ||
      first_token->position > cmd->end_pos ||
      first_token->length > cmd->end_pos - first_token->position) {
    free(tcmd);
    return SHELL_TRANSFORM_EINPUT;
  }
  size_t prefix_length = first_token->position - cmd->start_pos;
  size_t orig_length = cmd->end_pos - cmd->start_pos;
  const char *orig_start = first_token->start - prefix_length;
  tcmd->original_command = strndup(orig_start, orig_length);
  if (!tcmd->original_command) {
    free(tcmd);
    return SHELL_TRANSFORM_ENOMEM;
  }
  if (limits && orig_length > limits->max_string_bytes) {
    free((void *)tcmd->original_command);
    free(tcmd);
    return SHELL_TRANSFORM_EOUTPUT_LIMIT;
  }

  if (cmd->token_count > SIZE_MAX / sizeof(shell_transformed_token_t)) {
    free((void *)tcmd->original_command);
    free(tcmd);
    return SHELL_TRANSFORM_EOVERFLOW;
  }
  shell_transformed_token_t *tokens =
      malloc(cmd->token_count * sizeof(shell_transformed_token_t));
  if (!tokens) {
    free((void *)tcmd->original_command);
    free(tcmd);
    return SHELL_TRANSFORM_ENOMEM;
  }

  for (size_t i = 0; i < cmd->token_count; i++) {
    const shell_token_t *tok = &cmd->tokens[i];
    if (!tok->start || tok->position < cmd->start_pos ||
        tok->position > cmd->end_pos ||
        tok->length > cmd->end_pos - tok->position) {
      free_transformed_tokens(tokens, i);
      free((void *)tcmd->original_command);
      free(tcmd);
      return SHELL_TRANSFORM_EINPUT;
    }
    shell_transform_type_t type = SHELL_TRANSFORM_NONE;
    const char *replacement = NULL;
    char *word_variable_replacement = NULL;
    switch (tok->type) {
    case SHELL_TOKEN_VARIABLE:
    case SHELL_TOKEN_SPECIAL_VAR:
      type = SHELL_TRANSFORM_VARIABLE;
      replacement = VAR_PLACEHOLDER;
      break;
    case SHELL_TOKEN_VARIABLE_QUOTED:
      if (token_is_bare_variable_expansion(tok)) {
        type = SHELL_TRANSFORM_VARIABLE;
        replacement = VAR_PLACEHOLDER;
      }
      break;
    case SHELL_TOKEN_GLOB:
    case SHELL_TOKEN_EXTGLOB:
      type = SHELL_TRANSFORM_GLOB;
      replacement = GLOB_PLACEHOLDER;
      break;
    case SHELL_TOKEN_SUBSHELL:
    case SHELL_TOKEN_PROCESS_SUB:
      type = SHELL_TRANSFORM_SUBSHELL;
      replacement = SUBSHELL_PLACEHOLDER;
      break;
    case SHELL_TOKEN_ARITHMETIC:
      type = SHELL_TRANSFORM_VARIABLE;
      replacement = VAR_PLACEHOLDER;
      break;
    default:
      break;
    }

    if (!replacement &&
        (tok->type == SHELL_TOKEN_COMMAND ||
         tok->type == SHELL_TOKEN_ARGUMENT ||
         tok->type == SHELL_TOKEN_VARIABLE_QUOTED) &&
        shell_tokenizer_token_has_variable(tok)) {
      bool replaced = false;
      shell_transform_status_t replace_status =
          transform_replace_word_variables(tok, &word_variable_replacement,
                                           &replaced);
      if (replace_status != SHELL_TRANSFORM_OK) {
        free_transformed_tokens(tokens, i);
        free((void *)tcmd->original_command);
        free(tcmd);
        return replace_status;
      }
      if (replaced) {
        type = SHELL_TRANSFORM_VARIABLE;
        replacement = word_variable_replacement;
      }
    }

    char *original = strndup(tok->start, tok->length);
    char *transformed = word_variable_replacement
                            ? word_variable_replacement
                            : (replacement ? strdup(replacement) : original);
    if (!original || !transformed) {
      free(original);
      if (transformed != original)
        free(transformed);
      free_transformed_tokens(tokens, i);
      free((void *)tcmd->original_command);
      free(tcmd);
      return SHELL_TRANSFORM_ENOMEM;
    }
    bool is_shell_construct =
        replacement || is_shell_syntax_token(tok->type) ||
        shell_source_word_has_executable_substitution(tok->start, tok->length);
    tokens[i] = create_transformed_token(original, transformed, type,
                                         is_shell_construct);
    if (replacement) {
      tcmd->has_transformations = true;
    }
    if (is_shell_construct)
      tcmd->has_shell_syntax = true;
  }

  tcmd->tokens = tokens;
  tcmd->token_count = cmd->token_count;
  shell_transform_status_t build_status = SHELL_TRANSFORM_OK;
  tcmd->display_text =
      build_transformed_command(cmd, tokens, tcmd->token_count, &build_status);

  if (!tcmd->display_text) {
    free_transformed_tokens(tokens, tcmd->token_count);
    free((void *)tcmd->original_command);
    free(tcmd);
    return build_status;
  }

  size_t transformed_length = strlen(tcmd->display_text);
  if (limits && transformed_length > limits->max_string_bytes)
    goto output_limit;
  for (size_t i = 0; i < tcmd->token_count; i++) {
    size_t original_length = strlen(tcmd->tokens[i].original);
    size_t token_length = strlen(tcmd->tokens[i].transformed);
    if (limits && (original_length > limits->max_string_bytes ||
                   token_length > limits->max_string_bytes))
      goto output_limit;
  }
  size_t total_output = 0;
  if (measure_transformed_command(tcmd, &total_output) != SHELL_TRANSFORM_OK)
    goto overflow;
  if (limits && total_output > limits->max_total_bytes)
    goto output_limit;

  *transformed_cmd = tcmd;
  return SHELL_TRANSFORM_OK;

output_limit:
  shell_transformed_command_free(tcmd);
  return SHELL_TRANSFORM_EOUTPUT_LIMIT;
overflow:
  shell_transformed_command_free(tcmd);
  return SHELL_TRANSFORM_EOVERFLOW;
}

shell_transform_status_t
shell_transform_command_line(const char *command_line, size_t command_length,
                             const shell_transform_limits_t *limits,
                             shell_transformed_command_t ***transformed_cmds,
                             size_t *transformed_count) {
  if (!transformed_cmds || !transformed_count)
    return SHELL_TRANSFORM_EINPUT;
  *transformed_cmds = NULL;
  *transformed_count = 0;
  if (!command_line)
    return SHELL_TRANSFORM_EINPUT;
  if (shell_tokenizer_has_unsupported_semantics(command_line, command_length))
    return SHELL_TRANSFORM_EPARSE;

  shell_command_t *cmds = NULL;
  size_t cmd_count = 0;

  switch (shell_tokenize_commands(command_line, command_length, &cmds,
                                  &cmd_count)) {
  case SHELL_TOKENIZE_OK:
    break;
  case SHELL_TOKENIZE_ENOMEM:
    return SHELL_TRANSFORM_ENOMEM;
  case SHELL_TOKENIZE_EOVERFLOW:
    return SHELL_TRANSFORM_EOVERFLOW;
  case SHELL_TOKENIZE_EINPUT:
    return SHELL_TRANSFORM_EINPUT;
  case SHELL_TOKENIZE_EPARSE:
  default:
    return SHELL_TRANSFORM_EPARSE;
  }

  if (cmd_count == 0) {
    return SHELL_TRANSFORM_OK;
  }

  if (cmd_count > SIZE_MAX / sizeof(shell_transformed_command_t *)) {
    shell_commands_free(cmds, cmd_count);
    return SHELL_TRANSFORM_EOVERFLOW;
  }
  shell_transformed_command_t **tcmds =
      malloc(cmd_count * sizeof(shell_transformed_command_t *));
  if (!tcmds) {
    shell_commands_free(cmds, cmd_count);
    return SHELL_TRANSFORM_ENOMEM;
  }

  size_t success_count = 0;
  size_t total_output = 0;
  for (size_t i = 0; i < cmd_count; i++) {
    shell_transform_status_t status =
        shell_transform_command(&cmds[i], limits, &tcmds[i]);
    if (status == SHELL_TRANSFORM_OK) {
      size_t command_output = 0;
      status = measure_transformed_command(tcmds[i], &command_output);
      if (status == SHELL_TRANSFORM_OK) {
        if (command_output > SIZE_MAX - total_output) {
          status = SHELL_TRANSFORM_EOVERFLOW;
        } else {
          total_output += command_output;
          if (limits && total_output > limits->max_total_bytes)
            status = SHELL_TRANSFORM_EOUTPUT_LIMIT;
        }
      }
      if (status == SHELL_TRANSFORM_OK) {
        success_count++;
        continue;
      }
      shell_transformed_command_free(tcmds[i]);
    }
    for (size_t j = 0; j < success_count; j++)
      shell_transformed_command_free(tcmds[j]);
    free(tcmds);
    shell_commands_free(cmds, cmd_count);
    return status;
  }

  *transformed_cmds = tcmds;
  *transformed_count = success_count;
  shell_commands_free(cmds, cmd_count);
  return SHELL_TRANSFORM_OK;
}

void shell_transformed_command_list_free(shell_transformed_command_t **commands,
                                         size_t count) {
  if (!commands)
    return;
  for (size_t i = 0; i < count; i++)
    shell_transformed_command_free(commands[i]);
  free(commands);
}

const char *shell_transformed_command_get_display_text(
    const shell_transformed_command_t *cmd) {
  return cmd ? cmd->display_text : NULL;
}

bool shell_transformed_command_has_transformations(
    const shell_transformed_command_t *cmd) {
  return cmd ? cmd->has_transformations : false;
}
