#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "alloc.h"
#include "shell_netstring.h"
#include "shell_processor_internal.h"
#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_shell_operator_token(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_PIPE ||
         token->type == SHELL_TOKEN_REDIRECT_IN ||
         token->type == SHELL_TOKEN_REDIRECT_OUT ||
         token->type == SHELL_TOKEN_REDIRECT_ERR ||
         token->type == SHELL_TOKEN_REDIRECT_APPEND ||
         token->type == SHELL_TOKEN_SEMICOLON ||
         token->type == SHELL_TOKEN_AND ||
         token->type == SHELL_TOKEN_BACKGROUND ||
         token->type == SHELL_TOKEN_OR ||
         token->type == SHELL_TOKEN_GROUP_START ||
         token->type == SHELL_TOKEN_GROUP_END ||
         token->type == SHELL_TOKEN_SUBSHELL_START ||
         token->type == SHELL_TOKEN_SUBSHELL_END ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

static bool is_redirection_token(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_REDIRECT_IN ||
         token->type == SHELL_TOKEN_REDIRECT_OUT ||
         token->type == SHELL_TOKEN_REDIRECT_ERR ||
         token->type == SHELL_TOKEN_REDIRECT_APPEND ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

static bool redirection_consumes_next_token(const shell_token_t *token) {
  if (token->type == SHELL_TOKEN_HERESTRING)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count) {
  if (!commands || !count || !command_line)
    return SHELL_PROCESS_EINPUT;
  *commands = NULL;
  *count = 0;
  switch (
      shell_tokenize_commands(command_line, command_length, commands, count)) {
  case SHELL_TOKENIZE_OK:
    break;
  case SHELL_TOKENIZE_ENOMEM:
    return SHELL_PROCESS_ENOMEM;
  case SHELL_TOKENIZE_EOVERFLOW:
    return SHELL_PROCESS_EOVERFLOW;
  case SHELL_TOKENIZE_EINPUT:
    return SHELL_PROCESS_EINPUT;
  case SHELL_TOKENIZE_EPARSE:
  default:
    return SHELL_PROCESS_EPARSE;
  }
  size_t total = 0;
  for (size_t i = 0; i < *count; i++) {
    size_t length = (*commands)[i].end_pos - (*commands)[i].start_pos;
    if (limits && length > limits->max_string_bytes)
      goto output_limit;
    if (length > SIZE_MAX - total)
      goto overflow;
    total += length;
  }
  if (limits && total > limits->max_total_bytes)
    goto output_limit;
  return SHELL_PROCESS_OK;

output_limit:
  shell_commands_free(*commands, *count);
  *commands = NULL;
  *count = 0;
  return SHELL_PROCESS_EOUTPUT_LIMIT;
overflow:
  shell_commands_free(*commands, *count);
  *commands = NULL;
  *count = 0;
  return SHELL_PROCESS_EOVERFLOW;
}

size_t shell_processed_command_word_count(const shell_command_t *command) {
  if (!command)
    return 0;
  size_t count = 0;
  bool consume_redirection_operand = false;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (is_shell_operator_token(token)) {
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
    } else if (consume_redirection_operand) {
      consume_redirection_operand = false;
    } else {
      count++;
    }
  }
  return count;
}

const shell_token_t *
shell_processed_command_word_at(const shell_command_t *command,
                                size_t word_index) {
  if (!command)
    return NULL;
  size_t found = 0;
  bool consume_redirection_operand = false;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (is_shell_operator_token(token)) {
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
    } else if (consume_redirection_operand) {
      consume_redirection_operand = false;
    } else if (found++ == word_index) {
      return token;
    }
  }
  return NULL;
}

bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input) {
  if (!command)
    return false;
  if (has_pipe_input)
    return true;
  for (size_t i = 0; i < command->token_count; i++) {
    if (is_shell_operator_token(&command->tokens[i]))
      return true;
  }
  size_t word_count = shell_processed_command_word_count(command);
  for (size_t i = 0; i < word_count; i++) {
    shell_token_type_t type = shell_processed_command_word_at(command, i)->type;
    if (type == SHELL_TOKEN_SUBSHELL || type == SHELL_TOKEN_PROCESS_SUB)
      return true;
  }
  return false;
}

bool shell_processed_command_has_pipe_output(const shell_command_t *command) {
  if (!command)
    return false;
  for (size_t i = 0; i < command->token_count; i++) {
    if (command->tokens[i].type == SHELL_TOKEN_PIPE)
      return true;
  }
  return false;
}

shell_process_status_t shell_measure_decoded_word(const char *text,
                                                  size_t length,
                                                  size_t *decoded_length) {
  if (decoded_length)
    *decoded_length = 0;
  if (!text || !decoded_length)
    return SHELL_PROCESS_EINPUT;
  size_t out = 0;
  char quote = 0;
  for (size_t i = 0; i < length; i++) {
    char c = text[i];
    if (quote == 0 && (c == '\'' || c == '"')) {
      quote = c;
      continue;
    }
    if (quote != 0 && c == quote) {
      quote = 0;
      continue;
    }
    if (c == '\\' && quote != '\'' && i + 1 < length) {
      char next = text[i + 1];
      if (quote == 0 || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n') {
        if (next != '\n') {
          if (out == SIZE_MAX)
            return SHELL_PROCESS_EOVERFLOW;
          out++;
        }
        i++;
        continue;
      }
    }
    if (out == SIZE_MAX)
      return SHELL_PROCESS_EOVERFLOW;
    out++;
  }
  *decoded_length = out;
  return SHELL_PROCESS_OK;
}

static char *decode_shell_word_unchecked(const char *text, size_t length,
                                         char *decoded) {
  char *out = decoded;
  char quote = 0;
  for (size_t i = 0; i < length; i++) {
    char c = text[i];
    if (quote == 0 && (c == '\'' || c == '"')) {
      quote = c;
      continue;
    }
    if (quote != 0 && c == quote) {
      quote = 0;
      continue;
    }
    if (c == '\\' && quote != '\'' && i + 1 < length) {
      char next = text[i + 1];
      if (quote == 0 || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n') {
        if (next != '\n')
          *out++ = next;
        i++;
        continue;
      }
    }
    *out++ = c;
  }
  return out;
}

shell_process_status_t shell_write_decoded_word(const char *text, size_t length,
                                                char *destination,
                                                size_t destination_size,
                                                size_t *written) {
  if (written)
    *written = 0;
  if (!text || !destination || !written)
    return SHELL_PROCESS_EINPUT;
  size_t decoded_length = 0;
  shell_process_status_t status =
      shell_measure_decoded_word(text, length, &decoded_length);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (destination_size < decoded_length)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  char *end = decode_shell_word_unchecked(text, length, destination);
  *written = (size_t)(end - destination);
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_decode_word(const char *text, size_t length,
                                         char **decoded,
                                         size_t *decoded_length) {
  if (decoded)
    *decoded = NULL;
  if (decoded_length)
    *decoded_length = 0;
  if (!text || !decoded || !decoded_length)
    return SHELL_PROCESS_EINPUT;
  shell_process_status_t status =
      shell_measure_decoded_word(text, length, decoded_length);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (*decoded_length == SIZE_MAX) {
    *decoded_length = 0;
    return SHELL_PROCESS_EOVERFLOW;
  }
  *decoded = malloc(*decoded_length + 1);
  if (!*decoded) {
    *decoded_length = 0;
    return SHELL_PROCESS_ENOMEM;
  }
  size_t written = 0;
  status = shell_write_decoded_word(text, length, *decoded, *decoded_length,
                                    &written);
  if (status != SHELL_PROCESS_OK) {
    free(*decoded);
    *decoded = NULL;
    *decoded_length = 0;
    return status;
  }
  (*decoded)[written] = '\0';
  return SHELL_PROCESS_OK;
}

static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            shell_command_info_t *info);

static bool own_token_text(shell_command_t *basic_cmd,
                           const char *original_line,
                           shell_command_info_t *info, size_t command_length);

static void clear_command_info(shell_command_info_t *info) {
  free((void *)info->original_command);
  free(info->shell_tokens);
  free(info->command_tokens);
  memset(info, 0, sizeof(*info));
}

static bool process_single_command(shell_command_t *basic_cmd,
                                   const char *original_line,
                                   shell_command_info_t *info) {
  if (!basic_cmd || !info)
    return false;

  memset(info, 0, sizeof(shell_command_info_t));

  /* The full tokenizer can associate a compound operator's final byte with
   * the preceding command even when that byte lies just beyond end_pos. Own
   * every byte referenced by its tokens so rebasing remains failure-atomic. */
  size_t command_end = basic_cmd->end_pos;
  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    const shell_token_t *token = &basic_cmd->tokens[i];
    if (token->position < basic_cmd->start_pos ||
        token->length > SIZE_MAX - token->position)
      return false;
    size_t token_end = token->position + token->length;
    if (token_end > command_end)
      command_end = token_end;
  }
  if (command_end < basic_cmd->start_pos)
    return false;
  size_t orig_length = command_end - basic_cmd->start_pos;
  info->original_command =
      strndup(original_line + basic_cmd->start_pos, orig_length);
  if (!info->original_command)
    return false;

  bool success = process_single_command_internal(basic_cmd, info);
  if (success)
    success = own_token_text(basic_cmd, original_line, info, orig_length);
  if (!success)
    clear_command_info(info);
  return success;
}

static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            shell_command_info_t *info) {
  size_t shell_count = 0;
  size_t command_count = 0;
  bool consume_redirection_operand = false;
  bool has_pipe_output = false;
  bool has_redirections = false;
  bool has_error_redirection = false;

  /* Count output categories before allocating. The returned metadata needs
   * exact owned arrays, so allocating full-size staging arrays only to copy
   * them again is unnecessary. */
  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    const shell_token_t *token = &basic_cmd->tokens[i];

    if (is_shell_operator_token(token)) {
      shell_count++;

      switch (token->type) {
      case SHELL_TOKEN_PIPE:
        has_pipe_output = true;
        break;
      case SHELL_TOKEN_REDIRECT_IN:
      case SHELL_TOKEN_REDIRECT_OUT:
      case SHELL_TOKEN_REDIRECT_APPEND:
      case SHELL_TOKEN_HEREDOC:
      case SHELL_TOKEN_HERESTRING:
        has_redirections = true;
        break;
      case SHELL_TOKEN_REDIRECT_ERR:
        has_redirections = true;
        has_error_redirection = true;
        break;
      default:
        break;
      }
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
    } else if (consume_redirection_operand) {
      consume_redirection_operand = false;
    } else {
      command_count++;
    }
  }

  shell_token_t *shell_tokens = NULL;
  shell_token_t *command_tokens = NULL;
  if (shell_count > 0) {
    if (shell_count > SIZE_MAX / sizeof(shell_token_t)) {
      return false;
    }
    shell_tokens = malloc(shell_count * sizeof(shell_token_t));
    if (!shell_tokens)
      return false;
  }

  if (command_count > 0) {
    if (command_count > SIZE_MAX / sizeof(shell_token_t)) {
      free(shell_tokens);
      return false;
    }
    command_tokens = malloc(command_count * sizeof(shell_token_t));
    if (!command_tokens) {
      free(shell_tokens);
      return false;
    }
  }

  size_t shell_index = 0;
  size_t command_index = 0;
  consume_redirection_operand = false;
  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    const shell_token_t *token = &basic_cmd->tokens[i];
    if (is_shell_operator_token(token)) {
      shell_tokens[shell_index++] = *token;
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
    } else if (consume_redirection_operand) {
      consume_redirection_operand = false;
    } else {
      command_tokens[command_index++] = *token;
    }
  }

  info->shell_tokens = shell_tokens;
  info->shell_token_count = shell_count;
  info->command_tokens = command_tokens;
  info->command_token_count = command_count;
  info->has_pipe_output = has_pipe_output;
  info->has_redirections = has_redirections;
  info->has_error_redirection = has_error_redirection;
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
                           shell_command_info_t *info, size_t command_length) {
  return rebase_tokens(info->shell_tokens, info->shell_token_count,
                       original_line, basic_cmd->start_pos,
                       info->original_command, command_length) &&
         rebase_tokens(info->command_tokens, info->command_token_count,
                       original_line, basic_cmd->start_pos,
                       info->original_command, command_length);
}

shell_process_status_t
shell_process_command(const char *command_line, size_t command_length,
                      const shell_process_limits_t *limits,
                      shell_command_info_t **command_infos,
                      size_t *command_count) {
  if (!command_infos || !command_count)
    return SHELL_PROCESS_EINPUT;
  *command_infos = NULL;
  *command_count = 0;
  if (!command_line)
    return SHELL_PROCESS_EINPUT;

  shell_command_t *basic_commands;
  size_t basic_count;

  shell_process_status_t parsed = shell_processed_commands_parse(
      command_line, command_length, limits, &basic_commands, &basic_count);
  if (parsed != SHELL_PROCESS_OK)
    return parsed;

  if (basic_count == 0) {
    return SHELL_PROCESS_OK;
  }

  if (basic_count > SIZE_MAX / sizeof(shell_command_info_t)) {
    shell_commands_free(basic_commands, basic_count);
    return SHELL_PROCESS_EOVERFLOW;
  }
  shell_command_info_t *infos =
      malloc(basic_count * sizeof(shell_command_info_t));
  if (!infos) {
    shell_commands_free(basic_commands, basic_count);
    *command_count = 0;
    return SHELL_PROCESS_ENOMEM;
  }

  for (size_t i = 0; i < basic_count; i++) {
    if (!process_single_command(&basic_commands[i], command_line, &infos[i])) {
      shell_command_infos_free(infos, i);
      shell_commands_free(basic_commands, basic_count);
      return SHELL_PROCESS_ENOMEM;
    }
    if (i > 0 && infos[i - 1].has_pipe_output)
      infos[i].has_pipe_input = true;
  }

  if (limits) {
    size_t total_output = 0;
    for (size_t i = 0; i < basic_count; i++) {
      size_t original_length = strlen(infos[i].original_command);
      if (original_length > limits->max_string_bytes) {
        shell_command_infos_free(infos, basic_count);
        shell_commands_free(basic_commands, basic_count);
        return SHELL_PROCESS_EOUTPUT_LIMIT;
      }
      if (original_length > SIZE_MAX - total_output) {
        shell_command_infos_free(infos, basic_count);
        shell_commands_free(basic_commands, basic_count);
        return SHELL_PROCESS_EOVERFLOW;
      }
      total_output += original_length;
    }
    if (total_output > limits->max_total_bytes) {
      shell_command_infos_free(infos, basic_count);
      shell_commands_free(basic_commands, basic_count);
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
  }

  shell_commands_free(basic_commands, basic_count);
  *command_infos = infos;
  *command_count = basic_count;
  return SHELL_PROCESS_OK;
}

void shell_command_infos_free(shell_command_info_t *infos, size_t count) {
  if (!infos)
    return;

  for (size_t i = 0; i < count; i++) {
    clear_command_info(&infos[i]);
  }
  free(infos);
}

static bool preserves_word_text(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_SUBSHELL ||
         token->type == SHELL_TOKEN_PROCESS_SUB ||
         token->type == SHELL_TOKEN_ARITHMETIC;
}

static shell_process_status_t rendered_word_length(const shell_token_t *token,
                                                   size_t *length) {
  if (preserves_word_text(token)) {
    *length = token->length;
    return SHELL_PROCESS_OK;
  }
  return shell_measure_decoded_word(token->start, token->length, length);
}

static char *render_word_into(const shell_token_t *token, char *destination) {
  if (preserves_word_text(token)) {
    memcpy(destination, token->start, token->length);
    return destination + token->length;
  }
  return decode_shell_word_unchecked(token->start, token->length, destination);
}

shell_process_status_t shell_measure_netargv(const shell_command_info_t *info,
                                             size_t *total) {
  if (total)
    *total = 0;
  if (!info || !total)
    return SHELL_PROCESS_EINPUT;
  *total = 0;
  for (size_t i = 0; i < info->command_token_count; i++) {
    size_t length = 0;
    shell_process_status_t status =
        rendered_word_length(&info->command_tokens[i], &length);
    if (status != SHELL_PROCESS_OK)
      return status;
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        *total > SIZE_MAX - record_length)
      return SHELL_PROCESS_EOVERFLOW;
    *total += record_length;
  }
  return SHELL_PROCESS_OK;
}

static char *write_netargv_unchecked(const shell_command_info_t *info,
                                     char *position) {
  for (size_t i = 0; i < info->command_token_count; i++) {
    const shell_token_t *token = &info->command_tokens[i];
    size_t length = 0;
    (void)rendered_word_length(token, &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    position = render_word_into(token, position);
    *position++ = ',';
  }
  return position;
}

shell_process_status_t shell_write_netargv(const shell_command_info_t *info,
                                           char *destination,
                                           size_t destination_size,
                                           size_t *written) {
  if (written)
    *written = 0;
  if (!info || !destination || !written)
    return SHELL_PROCESS_EINPUT;
  size_t total = 0;
  shell_process_status_t status = shell_measure_netargv(info, &total);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (total == SIZE_MAX || destination_size <= total)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  char *end = write_netargv_unchecked(info, destination);
  *end = '\0';
  *written = total;
  return SHELL_PROCESS_OK;
}

static shell_process_status_t
measure_basic_netargv(const shell_command_t *command, size_t *total) {
  *total = 0;
  size_t count = shell_processed_command_word_count(command);
  for (size_t i = 0; i < count; i++) {
    const shell_token_t *token = shell_processed_command_word_at(command, i);
    size_t length = 0;
    shell_process_status_t status = rendered_word_length(token, &length);
    if (status != SHELL_PROCESS_OK)
      return status;
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        *total > SIZE_MAX - record_length)
      return SHELL_PROCESS_EOVERFLOW;
    *total += record_length;
  }
  return SHELL_PROCESS_OK;
}

static char *write_basic_netargv(const shell_command_t *command,
                                 char *position) {
  size_t count = shell_processed_command_word_count(command);
  for (size_t i = 0; i < count; i++) {
    const shell_token_t *token = shell_processed_command_word_at(command, i);
    size_t length = 0;
    (void)rendered_word_length(token, &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    position = render_word_into(token, position);
    *position++ = ',';
  }
  return position;
}

shell_process_status_t
shell_render_netargv(const shell_command_info_t *info,
                     const shell_process_limits_t *limits, char **netargv) {
  if (netargv)
    *netargv = NULL;
  if (!info || !netargv)
    return SHELL_PROCESS_EINPUT;
  size_t total = 0;
  shell_process_status_t status = shell_measure_netargv(info, &total);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (limits &&
      (total > limits->max_string_bytes || total > limits->max_total_bytes))
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  if (total == SIZE_MAX)
    return SHELL_PROCESS_EOVERFLOW;
  char *encoded = malloc(total + 1);
  if (!encoded)
    return SHELL_PROCESS_ENOMEM;

  size_t written = 0;
  status = shell_write_netargv(info, encoded, total + 1, &written);
  if (status != SHELL_PROCESS_OK) {
    free(encoded);
    return status;
  }
  *netargv = encoded;
  return SHELL_PROCESS_OK;
}

// Check for shell features that require explicit downstream handling.
bool shell_command_info_has_dangerous_features(
    const shell_command_info_t *info) {
  if (!info)
    return false;

  if (info->shell_token_count != 0 || info->has_pipe_input ||
      info->has_pipe_output || info->has_redirections ||
      info->has_error_redirection)
    return true;

  /* Substitutions remain explicit netargv values. They can execute shell code,
   * so callers must handle them explicitly. */
  for (size_t i = 0; i < info->command_token_count; i++) {
    shell_token_type_t type = info->command_tokens[i].type;
    if (type == SHELL_TOKEN_SUBSHELL || type == SHELL_TOKEN_PROCESS_SUB)
      return true;
  }
  return false;
}

shell_process_status_t
shell_build_netargv_sequence(const char *command_line, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netargv_sequence, size_t *subcommand_count,
                             bool *has_shell_features) {
  if (netargv_sequence)
    *netargv_sequence = NULL;
  if (subcommand_count)
    *subcommand_count = 0;
  if (has_shell_features)
    *has_shell_features = false;
  if (!command_line || !netargv_sequence || !subcommand_count ||
      !has_shell_features)
    return SHELL_PROCESS_EINPUT;

  shell_command_t *commands = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_processed_commands_parse(
      command_line, command_length, limits, &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    if (shell_processed_command_has_dangerous_features(
            &commands[i],
            i > 0 && shell_processed_command_has_pipe_output(&commands[i - 1])))
      *has_shell_features = true;
    size_t length = 0;
    status = measure_basic_netargv(&commands[i], &length);
    if (status != SHELL_PROCESS_OK)
      goto fail_sequence;
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        total > SIZE_MAX - record_length) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail_sequence;
    }
    total += record_length;
  }
  if (limits &&
      (total > limits->max_string_bytes || total > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail_sequence;
  }
  char *encoded = malloc(total + 1);
  if (!encoded) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_sequence;
  }
  char *position = encoded;
  for (size_t i = 0; i < count; i++) {
    size_t length = 0;
    (void)measure_basic_netargv(&commands[i], &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    position = write_basic_netargv(&commands[i], position);
    *position++ = ',';
  }
  *position = '\0';
  shell_commands_free(commands, count);
  *netargv_sequence = encoded;
  *subcommand_count = count;
  return SHELL_PROCESS_OK;

fail_sequence:
  shell_commands_free(commands, count);
  *has_shell_features = false;
  return status;
}

shell_process_status_t
shell_build_command_netseq(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           char **command_netseq, size_t *subcommand_count) {
  if (command_netseq)
    *command_netseq = NULL;
  if (subcommand_count)
    *subcommand_count = 0;
  if (!command_line || !command_netseq || !subcommand_count)
    return SHELL_PROCESS_EINPUT;
  shell_command_t *commands = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_processed_commands_parse(
      command_line, command_length, limits, &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    if (shell_processed_command_word_count(&commands[i]) == 0) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_commands;
    }
    const shell_token_t *token =
        shell_processed_command_word_at(&commands[i], 0);
    size_t length = 0;
    status = shell_measure_decoded_word(token->start, token->length, &length);
    if (status != SHELL_PROCESS_OK)
      goto fail_commands;
    if (length == 0) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_commands;
    }
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        total > SIZE_MAX - record_length) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail_commands;
    }
    total += record_length;
  }
  if (limits &&
      (total > limits->max_string_bytes || total > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail_commands;
  }
  char *encoded = malloc(total + 1);
  if (!encoded) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_commands;
  }
  char *position = encoded;
  for (size_t i = 0; i < count; i++) {
    const shell_token_t *token =
        shell_processed_command_word_at(&commands[i], 0);
    size_t length = 0;
    (void)shell_measure_decoded_word(token->start, token->length, &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    position =
        decode_shell_word_unchecked(token->start, token->length, position);
    *position++ = ',';
  }
  *position = '\0';
  shell_commands_free(commands, count);
  *command_netseq = encoded;
  *subcommand_count = count;
  return SHELL_PROCESS_OK;

fail_commands:
  shell_commands_free(commands, count);
  return status;
}
