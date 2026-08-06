#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Helper: Check if token is shell operator
static bool is_shell_operator_token(shell_token_t *token) {
  return token->type == TOKEN_PIPE || token->type == TOKEN_REDIRECT_IN ||
         token->type == TOKEN_REDIRECT_OUT ||
         token->type == TOKEN_REDIRECT_ERR ||
         token->type == TOKEN_REDIRECT_APPEND ||
         token->type == TOKEN_SEMICOLON || token->type == TOKEN_AND ||
         token->type == TOKEN_OR || token->type == TOKEN_SUBSHELL_START ||
         token->type == TOKEN_SUBSHELL_END || token->type == TOKEN_HEREDOC ||
         token->type == TOKEN_HERESTRING;
}

static bool is_redirection_token(const shell_token_t *token) {
  return token->type == TOKEN_REDIRECT_IN ||
         token->type == TOKEN_REDIRECT_OUT ||
         token->type == TOKEN_REDIRECT_ERR ||
         token->type == TOKEN_REDIRECT_APPEND || token->type == TOKEN_HEREDOC ||
         token->type == TOKEN_HERESTRING;
}

static bool redirection_consumes_next_token(const shell_token_t *token) {
  if (token->type == TOKEN_HERESTRING)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

// Helper: Build clean command string from tokens
static char *build_clean_command(shell_token_t *tokens, size_t count);

// Forward declarations
static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            const char *original_line,
                                            shell_command_info_t *info);

static bool own_token_text(shell_command_t *basic_cmd,
                           const char *original_line,
                           shell_command_info_t *info);

static void clear_command_info(shell_command_info_t *info) {
  free((void *)info->original_command);
  free((void *)info->clean_command);
  free(info->shell_tokens);
  free(info->command_tokens);
  memset(info, 0, sizeof(*info));
}

// Helper: Build clean command string from tokens
static char *build_clean_command(shell_token_t *tokens, size_t count) {
  if (count == 0) {
    return strdup("");
  }

  // Calculate total length needed
  size_t total_length = 0;
  for (size_t i = 0; i < count; i++) {
    if (tokens[i].length > SIZE_MAX - total_length)
      return NULL;
    total_length += tokens[i].length;
    if (i > 0) {
      if (total_length == SIZE_MAX)
        return NULL;
      total_length++; // Space between arguments
    }
  }
  if (total_length == SIZE_MAX)
    return NULL;

  // Allocate buffer
  char *buffer = malloc(total_length + 1);
  if (!buffer)
    return NULL;

  // Build command string
  char *pos = buffer;
  for (size_t i = 0; i < count; i++) {
    if (i > 0) {
      *pos++ = ' ';
    }
    memcpy(pos, tokens[i].start, tokens[i].length);
    pos += tokens[i].length;
  }
  *pos = '\0';

  return buffer;
}

// Process single command with shell/command separation
static bool process_single_command(shell_command_t *basic_cmd,
                                   const char *original_line,
                                   shell_command_info_t *info) {
  if (!basic_cmd || !info)
    return false;

  // Initialize info
  memset(info, 0, sizeof(shell_command_info_t));

  // Store original command
  size_t orig_length = basic_cmd->end_pos - basic_cmd->start_pos;
  info->original_command =
      strndup(original_line + basic_cmd->start_pos, orig_length);
  if (!info->original_command)
    return false;

  bool success =
      process_single_command_internal(basic_cmd, original_line, info);
  if (success)
    success = own_token_text(basic_cmd, original_line, info);
  if (!success)
    clear_command_info(info);
  return success;
}

// Process single command (not a pipeline)
static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            const char *original_line,
                                            shell_command_info_t *info) {
  (void)original_line; // Unused

  // Separate shell tokens from command tokens
  shell_token_t *shell_tokens = NULL;
  shell_token_t *command_tokens = NULL;
  size_t shell_count = 0;
  size_t command_count = 0;
  bool consume_redirection_operand = false;

  // Allocate temporary arrays
  if (basic_cmd->token_count > SIZE_MAX / sizeof(shell_token_t))
    return false;
  shell_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
  command_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
  if (!shell_tokens || !command_tokens) {
    free(shell_tokens);
    free(command_tokens);
    return false;
  }

  // Classify tokens
  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    shell_token_t *token = &basic_cmd->tokens[i];

    if (is_shell_operator_token(token)) {
      // Shell operator
      shell_tokens[shell_count++] = *token;

      // Track shell features
      switch (token->type) {
      case TOKEN_PIPE:
        info->has_pipe_output = true;
        break;
      case TOKEN_REDIRECT_IN:
      case TOKEN_REDIRECT_OUT:
      case TOKEN_REDIRECT_APPEND:
      case TOKEN_HEREDOC:
      case TOKEN_HERESTRING:
        info->has_redirections = true;
        break;
      case TOKEN_REDIRECT_ERR:
        info->has_redirections = true;
        info->has_error_redirection = true;
        break;
      default:
        break;
      }
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
    } else if (consume_redirection_operand) {
      consume_redirection_operand = false;
    } else {
      // Command token
      command_tokens[command_count++] = *token;
    }
  }

  // Build clean command string
  info->clean_command = build_clean_command(command_tokens, command_count);
  if (!info->clean_command) {
    free(shell_tokens);
    free(command_tokens);
    return false;
  }

  // Copy tokens to info structure
  if (shell_count > 0) {
    if (shell_count > SIZE_MAX / sizeof(shell_token_t)) {
      clear_command_info(info);
      free(shell_tokens);
      free(command_tokens);
      return false;
    }
    info->shell_tokens = malloc(shell_count * sizeof(shell_token_t));
    if (!info->shell_tokens) {
      free((void *)info->clean_command);
      info->clean_command = NULL;
      free(shell_tokens);
      free(command_tokens);
      return false;
    }
    memcpy(info->shell_tokens, shell_tokens,
           shell_count * sizeof(shell_token_t));
    info->shell_token_count = shell_count;
  }

  if (command_count > 0) {
    if (command_count > SIZE_MAX / sizeof(shell_token_t)) {
      clear_command_info(info);
      free(shell_tokens);
      free(command_tokens);
      return false;
    }
    info->command_tokens = malloc(command_count * sizeof(shell_token_t));
    if (!info->command_tokens) {
      free((void *)info->clean_command);
      info->clean_command = NULL;
      free(info->shell_tokens);
      info->shell_tokens = NULL;
      info->shell_token_count = 0;
      free(shell_tokens);
      free(command_tokens);
      return false;
    }
    memcpy(info->command_tokens, command_tokens,
           command_count * sizeof(shell_token_t));
    info->command_token_count = command_count;
  }

  free(shell_tokens);
  free(command_tokens);
  return true;
}

static bool rebase_tokens(shell_token_t *tokens, size_t count,
                          const char *original_line, size_t command_start,
                          const char *owned_command, size_t command_length) {
  for (size_t i = 0; i < count; i++) {
    if (tokens[i].position < command_start)
      return false;
    size_t offset = tokens[i].position - command_start;
    if (offset > command_length || tokens[i].length > command_length - offset)
      return false;
    if (tokens[i].start != original_line + tokens[i].position)
      return false;
    tokens[i].start = owned_command + offset;
    tokens[i].position = offset;
  }
  return true;
}

static bool own_token_text(shell_command_t *basic_cmd,
                           const char *original_line,
                           shell_command_info_t *info) {
  size_t command_length = basic_cmd->end_pos - basic_cmd->start_pos;
  return rebase_tokens(info->shell_tokens, info->shell_token_count,
                       original_line, basic_cmd->start_pos,
                       info->original_command, command_length) &&
         rebase_tokens(info->command_tokens, info->command_token_count,
                       original_line, basic_cmd->start_pos,
                       info->original_command, command_length);
}

// Main processing function
shell_process_status_t shell_process_command(
    const char *command_line, const shell_process_limits_t *limits,
    shell_command_info_t **command_infos, size_t *command_count) {
  if (!command_infos || !command_count)
    return SHELL_PROCESS_EINPUT;
  *command_infos = NULL;
  *command_count = 0;
  if (!command_line)
    return SHELL_PROCESS_EINPUT;

  // First, tokenize normally
  shell_command_t *basic_commands;
  size_t basic_count;

  if (!shell_tokenize_commands(command_line, &basic_commands, &basic_count)) {
    return SHELL_PROCESS_EPARSE;
  }

  if (basic_count == 0) {
    return SHELL_PROCESS_OK;
  }

  // Allocate command info array
  if (basic_count > SIZE_MAX / sizeof(shell_command_info_t)) {
    shell_free_commands(basic_commands, basic_count);
    return SHELL_PROCESS_EOVERFLOW;
  }
  shell_command_info_t *infos =
      malloc(basic_count * sizeof(shell_command_info_t));
  if (!infos) {
    shell_free_commands(basic_commands, basic_count);
    *command_count = 0;
    return SHELL_PROCESS_ENOMEM;
  }

  // Process each command
  for (size_t i = 0; i < basic_count; i++) {
    if (!process_single_command(&basic_commands[i], command_line, &infos[i])) {
      shell_free_command_infos(infos, i);
      shell_free_commands(basic_commands, basic_count);
      return SHELL_PROCESS_ENOMEM;
    }
    if (i > 0 && infos[i - 1].has_pipe_output)
      infos[i].has_pipe_input = true;
  }

  if (limits) {
    size_t total_output = 0;
    for (size_t i = 0; i < basic_count; i++) {
      size_t original_length = strlen(infos[i].original_command);
      size_t clean_length = strlen(infos[i].clean_command);
      if (original_length > limits->max_string_bytes ||
          clean_length > limits->max_string_bytes) {
        shell_free_command_infos(infos, basic_count);
        shell_free_commands(basic_commands, basic_count);
        return SHELL_PROCESS_EOUTPUT_LIMIT;
      }
      if (original_length > SIZE_MAX - total_output ||
          clean_length > SIZE_MAX - total_output - original_length) {
        shell_free_command_infos(infos, basic_count);
        shell_free_commands(basic_commands, basic_count);
        return SHELL_PROCESS_EOVERFLOW;
      }
      total_output += original_length + clean_length;
    }
    if (total_output > limits->max_total_bytes) {
      shell_free_command_infos(infos, basic_count);
      shell_free_commands(basic_commands, basic_count);
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
  }

  shell_free_commands(basic_commands, basic_count);
  *command_infos = infos;
  *command_count = basic_count;
  return SHELL_PROCESS_OK;
}

// Free command info structures
void shell_free_command_infos(shell_command_info_t *infos, size_t count) {
  if (!infos)
    return;

  for (size_t i = 0; i < count; i++) {
    clear_command_info(&infos[i]);
  }
  free(infos);
}

// Get clean command for DFA validation
const char *shell_get_clean_command(shell_command_info_t *info) {
  return info ? info->clean_command : NULL;
}

// Check if command has dangerous shell features
bool shell_has_dangerous_features(shell_command_info_t *info) {
  if (!info)
    return false;

  if (info->shell_token_count != 0 || info->has_pipe_input ||
      info->has_pipe_output || info->has_redirections ||
      info->has_error_redirection)
    return true;

  /* Command and process substitutions are retained in the clean command so
   * the DFA can validate the surrounding argument. They still execute shell
   * code and therefore require shell-aware handling by the caller. */
  for (size_t i = 0; i < info->command_token_count; i++) {
    token_type_t type = info->command_tokens[i].type;
    if (type == TOKEN_SUBSHELL || type == TOKEN_PROCESS_SUB)
      return true;
  }
  return false;
}

// Process command line and extract DFA inputs
shell_process_status_t
shell_extract_dfa_inputs(const char *command_line,
                         const shell_process_limits_t *limits,
                         const char ***dfa_inputs, size_t *dfa_input_count,
                         bool *has_shell_features) {
  if (!dfa_inputs || !dfa_input_count || !has_shell_features)
    return SHELL_PROCESS_EINPUT;
  *dfa_inputs = NULL;
  *dfa_input_count = 0;
  *has_shell_features = false;
  if (!command_line)
    return SHELL_PROCESS_EINPUT;

  shell_command_info_t *infos;
  size_t count;

  shell_process_status_t process_status =
      shell_process_command(command_line, limits, &infos, &count);
  if (process_status != SHELL_PROCESS_OK) {
    return process_status;
  }

  if (count == 0) {
    return SHELL_PROCESS_OK;
  }

  // Allocate array for DFA inputs
  if (count > SIZE_MAX / sizeof(const char *)) {
    shell_free_command_infos(infos, count);
    return SHELL_PROCESS_EOVERFLOW;
  }
  const char **inputs = malloc(count * sizeof(const char *));
  if (!inputs) {
    shell_free_command_infos(infos, count);
    return SHELL_PROCESS_ENOMEM;
  }

  // Extract clean commands and check for shell features
  bool shell_features = false;
  for (size_t i = 0; i < count; i++) {
    inputs[i] = shell_get_clean_command(&infos[i]);
    if (shell_has_dangerous_features(&infos[i])) {
      shell_features = true;
    }
  }

  *dfa_inputs = inputs;
  *dfa_input_count = count;
  *has_shell_features = shell_features;

  // Note: We're transferring ownership of the clean_command strings to the
  // caller The caller gets pointers to the strings in infos[i].clean_command
  // After this function returns, the caller must free these strings
  // We must NOT call shell_free_command_infos because it would free
  // clean_command Instead, we manually free only the parts we still own

  // Free original_command and shell/command tokens but NOT clean_command
  for (size_t i = 0; i < count; i++) {
    free((void *)infos[i].original_command);
    free(infos[i].shell_tokens);
    free(infos[i].command_tokens);
    // Do NOT free infos[i].clean_command - caller owns it now
  }
  free(infos);

  return SHELL_PROCESS_OK;
}
