#define _POSIX_C_SOURCE 200809L
#include "shell_transform.h"
#include "shell_tokenizer_full.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *VAR_PLACEHOLDER = "VAR_VALUE";
static const char *GLOB_PLACEHOLDER = "FILE_PATTERN";
static const char *SUBSHELL_PLACEHOLDER = "TEMP_FILE";

static bool is_shell_syntax_token(token_type_t type) {
  return type == TOKEN_PIPE || type == TOKEN_REDIRECT_IN ||
         type == TOKEN_REDIRECT_OUT || type == TOKEN_REDIRECT_ERR ||
         type == TOKEN_REDIRECT_APPEND || type == TOKEN_SEMICOLON ||
         type == TOKEN_AND || type == TOKEN_OR ||
         type == TOKEN_SUBSHELL_START || type == TOKEN_SUBSHELL_END ||
         type == TOKEN_HEREDOC || type == TOKEN_HERESTRING ||
         type == TOKEN_PROCESS_SUB;
}

void shell_free_transformed_command(transformed_command_t *command) {
  if (!command)
    return;
  free((void *)command->original_command);
  free((void *)command->transformed_command);
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

static transformed_token_t create_transformed_token(const char *original,
                                                    const char *transformed,
                                                    transform_type_t type,
                                                    bool is_shell_construct) {
  transformed_token_t token;
  token.original = original;
  token.transformed = transformed;
  token.type = type;
  token.is_shell_construct = is_shell_construct;
  return token;
}

static void free_transformed_tokens(transformed_token_t *tokens, size_t count) {
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].original);
    if (tokens[i].transformed != tokens[i].original)
      free((void *)tokens[i].transformed);
  }
  free(tokens);
}

static char *build_transformed_command(transformed_token_t *tokens,
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
shell_transform_command(shell_command_t *cmd,
                        const shell_transform_limits_t *limits,
                        transformed_command_t **transformed_cmd) {
  if (!transformed_cmd)
    return SHELL_TRANSFORM_EINPUT;
  *transformed_cmd = NULL;
  if (!cmd)
    return SHELL_TRANSFORM_EINPUT;

  transformed_command_t *tcmd = malloc(sizeof(transformed_command_t));
  if (!tcmd)
    return SHELL_TRANSFORM_ENOMEM;

  tcmd->original_command = NULL;
  tcmd->transformed_command = NULL;
  tcmd->tokens = NULL;
  tcmd->token_count = 0;
  tcmd->has_transformations = false;
  tcmd->has_shell_syntax = false;

  // Validate tokenized input exists before constructing transformed output.
  if (cmd->token_count == 0 || cmd->tokens == NULL) {
    free(tcmd);
    return SHELL_TRANSFORM_EINPUT;
  }

  shell_token_t *first_token = &cmd->tokens[0];
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

  if (cmd->token_count > SIZE_MAX / sizeof(transformed_token_t)) {
    free((void *)tcmd->original_command);
    free(tcmd);
    return SHELL_TRANSFORM_EOVERFLOW;
  }
  transformed_token_t *tokens =
      malloc(cmd->token_count * sizeof(transformed_token_t));
  if (!tokens) {
    free((void *)tcmd->original_command);
    free(tcmd);
    return SHELL_TRANSFORM_ENOMEM;
  }

  for (size_t i = 0; i < cmd->token_count; i++) {
    shell_token_t *tok = &cmd->tokens[i];
    if (!tok->start || tok->position < cmd->start_pos ||
        tok->position > cmd->end_pos ||
        tok->length > cmd->end_pos - tok->position) {
      free_transformed_tokens(tokens, i);
      free((void *)tcmd->original_command);
      free(tcmd);
      return SHELL_TRANSFORM_EINPUT;
    }
    transform_type_t type = TRANSFORM_NONE;
    const char *replacement = NULL;
    switch (tok->type) {
    case TOKEN_VARIABLE:
    case TOKEN_VARIABLE_QUOTED:
    case TOKEN_SPECIAL_VAR:
      type = TRANSFORM_VARIABLE;
      replacement = VAR_PLACEHOLDER;
      break;
    case TOKEN_GLOB:
      type = TRANSFORM_GLOB;
      replacement = GLOB_PLACEHOLDER;
      break;
    case TOKEN_SUBSHELL:
    case TOKEN_PROCESS_SUB:
      type = TRANSFORM_SUBSHELL;
      replacement = SUBSHELL_PLACEHOLDER;
      break;
    case TOKEN_ARITHMETIC:
      type = TRANSFORM_VARIABLE;
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
  tcmd->transformed_command =
      build_transformed_command(tokens, tcmd->token_count, &build_status);

  if (!tcmd->transformed_command) {
    free_transformed_tokens(tokens, tcmd->token_count);
    free((void *)tcmd->original_command);
    free(tcmd);
    return build_status;
  }

  size_t total_output = orig_length;
  size_t transformed_length = strlen(tcmd->transformed_command);
  if (transformed_length > SIZE_MAX - total_output)
    goto overflow;
  total_output += transformed_length;
  if (limits && transformed_length > limits->max_string_bytes)
    goto output_limit;
  for (size_t i = 0; i < tcmd->token_count; i++) {
    size_t original_length = strlen(tcmd->tokens[i].original);
    size_t token_length = strlen(tcmd->tokens[i].transformed);
    if (limits && (original_length > limits->max_string_bytes ||
                   token_length > limits->max_string_bytes))
      goto output_limit;
    if (original_length > SIZE_MAX - total_output)
      goto overflow;
    total_output += original_length;
    if (token_length > SIZE_MAX - total_output)
      goto overflow;
    total_output += token_length;
  }
  if (limits && total_output > limits->max_total_bytes)
    goto output_limit;

  *transformed_cmd = tcmd;
  return SHELL_TRANSFORM_OK;

output_limit:
  shell_free_transformed_command(tcmd);
  return SHELL_TRANSFORM_EOUTPUT_LIMIT;
overflow:
  shell_free_transformed_command(tcmd);
  return SHELL_TRANSFORM_EOVERFLOW;
}

shell_transform_status_t shell_transform_command_line(
    const char *command_line, const shell_transform_limits_t *limits,
    transformed_command_t ***transformed_cmds, size_t *transformed_count) {
  if (!transformed_cmds || !transformed_count)
    return SHELL_TRANSFORM_EINPUT;
  *transformed_cmds = NULL;
  *transformed_count = 0;
  if (!command_line)
    return SHELL_TRANSFORM_EINPUT;

  shell_command_t *cmds = NULL;
  size_t cmd_count = 0;

  if (!shell_tokenize_commands(command_line, &cmds, &cmd_count))
    return SHELL_TRANSFORM_EPARSE;

  if (cmd_count == 0) {
    return SHELL_TRANSFORM_OK;
  }

  if (cmd_count > SIZE_MAX / sizeof(transformed_command_t *)) {
    shell_free_commands(cmds, cmd_count);
    return SHELL_TRANSFORM_EOVERFLOW;
  }
  transformed_command_t **tcmds =
      malloc(cmd_count * sizeof(transformed_command_t *));
  if (!tcmds) {
    shell_free_commands(cmds, cmd_count);
    return SHELL_TRANSFORM_ENOMEM;
  }

  size_t success_count = 0;
  for (size_t i = 0; i < cmd_count; i++) {
    shell_transform_status_t status =
        shell_transform_command(&cmds[i], limits, &tcmds[i]);
    if (status == SHELL_TRANSFORM_OK) {
      success_count++;
    } else {
      // On failure, free successfully transformed commands
      for (size_t j = 0; j < success_count; j++)
        shell_free_transformed_command(tcmds[j]);
      free(tcmds);
      shell_free_commands(cmds, cmd_count);
      return status;
    }
  }

  *transformed_cmds = tcmds;
  *transformed_count = success_count;
  shell_free_commands(cmds, cmd_count);
  return SHELL_TRANSFORM_OK;
}

void shell_free_transformed_commands(transformed_command_t **commands,
                                     size_t count) {
  if (!commands)
    return;
  for (size_t i = 0; i < count; i++)
    shell_free_transformed_command(commands[i]);
}

const char *shell_get_dfa_input(transformed_command_t *cmd) {
  return cmd ? cmd->transformed_command : NULL;
}

bool shell_has_transformations(transformed_command_t *cmd) {
  return cmd ? cmd->has_transformations : false;
}
