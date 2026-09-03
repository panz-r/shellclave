#define _POSIX_C_SOURCE 200809L
#include "shell_transform.h"
#include "alloc.h"
#include "shell_tokenizer_full.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *VAR_PLACEHOLDER = "VAR_VALUE";
static const char *GLOB_PLACEHOLDER = "FILE_PATTERN";
static const char *SUBSHELL_PLACEHOLDER = "TEMP_FILE";

static bool is_shell_syntax_token(shell_token_type_t type) {
  return type == SHELL_TOKEN_PIPE || type == SHELL_TOKEN_REDIRECT_IN ||
         type == SHELL_TOKEN_REDIRECT_OUT || type == SHELL_TOKEN_REDIRECT_ERR ||
         type == SHELL_TOKEN_REDIRECT_APPEND ||
         type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         type == SHELL_TOKEN_SEMICOLON || type == SHELL_TOKEN_AND ||
         type == SHELL_TOKEN_BACKGROUND || type == SHELL_TOKEN_OR ||
         type == SHELL_TOKEN_GROUP_START || type == SHELL_TOKEN_GROUP_END ||
         type == SHELL_TOKEN_SUBSHELL_START ||
         type == SHELL_TOKEN_SUBSHELL_END || type == SHELL_TOKEN_HEREDOC ||
         type == SHELL_TOKEN_HERESTRING || type == SHELL_TOKEN_PROCESS_SUB;
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

static char *build_transformed_command(shell_transformed_token_t *tokens,
                                       size_t token_count,
                                       shell_transform_status_t *status) {
  size_t total_length = 0;
  for (size_t i = 0; i < token_count; i++) {
    size_t part_length = strlen(tokens[i].transformed);
    if (part_length > SIZE_MAX - total_length ||
        (i > 0 && total_length == SIZE_MAX)) {
      *status = SHELL_TRANSFORM_EOVERFLOW;
      return NULL;
    }
    total_length += part_length;
    if (i > 0) {
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
    if (i > 0)
      *pos++ = ' ';
    size_t length = strlen(tokens[i].transformed);
    memcpy(pos, tokens[i].transformed, length);
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
    switch (tok->type) {
    case SHELL_TOKEN_VARIABLE:
    case SHELL_TOKEN_VARIABLE_QUOTED:
    case SHELL_TOKEN_SPECIAL_VAR:
      type = SHELL_TRANSFORM_VARIABLE;
      replacement = VAR_PLACEHOLDER;
      break;
    case SHELL_TOKEN_GLOB:
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

    char *original = strndup(tok->start, tok->length);
    char *transformed = replacement ? strdup(replacement) : original;
    if (!original || !transformed) {
      free(original);
      if (transformed != original)
        free(transformed);
      free_transformed_tokens(tokens, i);
      free((void *)tcmd->original_command);
      free(tcmd);
      return SHELL_TRANSFORM_ENOMEM;
    }
    tokens[i] =
        create_transformed_token(original, transformed, type, replacement);
    if (replacement) {
      tcmd->has_transformations = true;
    }
    if (replacement || is_shell_syntax_token(tok->type))
      tcmd->has_shell_syntax = true;
  }

  tcmd->tokens = tokens;
  tcmd->token_count = cmd->token_count;
  shell_transform_status_t build_status = SHELL_TRANSFORM_OK;
  tcmd->display_text =
      build_transformed_command(tokens, tcmd->token_count, &build_status);

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
