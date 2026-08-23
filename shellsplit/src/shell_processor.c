#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "alloc.h"
#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_shell_operator_token(shell_token_t *token) {
  return token->type == TOKEN_PIPE || token->type == TOKEN_REDIRECT_IN ||
         token->type == TOKEN_REDIRECT_OUT ||
         token->type == TOKEN_REDIRECT_ERR ||
         token->type == TOKEN_REDIRECT_APPEND ||
         token->type == TOKEN_SEMICOLON || token->type == TOKEN_AND ||
         token->type == TOKEN_BACKGROUND || token->type == TOKEN_OR ||
         token->type == TOKEN_GROUP_START || token->type == TOKEN_GROUP_END ||
         token->type == TOKEN_SUBSHELL_START ||
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

static char *build_clean_command(shell_token_t *tokens, size_t count);

static char *decode_shell_word(const char *text, size_t length,
                               size_t *decoded_length) {
  char *decoded = malloc(length + 1);
  if (!decoded)
    return NULL;
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
        if (next != '\n')
          decoded[out++] = next;
        i++;
        continue;
      }
    }
    decoded[out++] = c;
  }
  decoded[out] = '\0';
  *decoded_length = out;
  return decoded;
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
  *decoded = decode_shell_word(text, length, decoded_length);
  return *decoded ? SHELL_PROCESS_OK : SHELL_PROCESS_ENOMEM;
}

static bool processed_word_needs_quotes(const char *word, size_t length) {
  if (length == 0)
    return true;
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)word[i];
    if (isspace(c) || strchr("|&;<>'\"\\", c))
      return true;
  }
  return false;
}

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

static char *build_clean_command(shell_token_t *tokens, size_t count) {
  if (count == 0) {
    return strdup("");
  }

  char **words = calloc(count, sizeof(*words));
  size_t *lengths = calloc(count, sizeof(*lengths));
  bool *preserve_raw = calloc(count, sizeof(*preserve_raw));
  if (!words || !lengths || !preserve_raw) {
    free(words);
    free(lengths);
    free(preserve_raw);
    return NULL;
  }

  size_t total_length = 0;
  for (size_t i = 0; i < count; i++) {
    preserve_raw[i] = tokens[i].type == TOKEN_SUBSHELL ||
                      tokens[i].type == TOKEN_PROCESS_SUB ||
                      tokens[i].type == TOKEN_ARITHMETIC;
    words[i] =
        preserve_raw[i]
            ? strndup(tokens[i].start, tokens[i].length)
            : decode_shell_word(tokens[i].start, tokens[i].length, &lengths[i]);
    if (!words[i])
      goto fail;
    if (preserve_raw[i])
      lengths[i] = tokens[i].length;
    size_t encoded_length = lengths[i];
    if (!preserve_raw[i] && processed_word_needs_quotes(words[i], lengths[i])) {
      if (encoded_length > SIZE_MAX - 2)
        goto fail;
      encoded_length += 2;
      for (size_t j = 0; j < lengths[i]; j++)
        if (words[i][j] == '"' || words[i][j] == '\\') {
          if (encoded_length == SIZE_MAX)
            goto fail;
          encoded_length++;
        }
    }
    if (encoded_length > SIZE_MAX - total_length)
      goto fail;
    total_length += encoded_length;
    if (i > 0) {
      if (total_length == SIZE_MAX)
        goto fail;
      total_length++;
    }
  }
  if (total_length == SIZE_MAX)
    goto fail;

  char *buffer = malloc(total_length + 1);
  if (!buffer)
    goto fail;

  char *pos = buffer;
  for (size_t i = 0; i < count; i++) {
    if (i > 0)
      *pos++ = ' ';
    bool quote =
        !preserve_raw[i] && processed_word_needs_quotes(words[i], lengths[i]);
    if (quote)
      *pos++ = '"';
    for (size_t j = 0; j < lengths[i]; j++) {
      if (quote && (words[i][j] == '"' || words[i][j] == '\\'))
        *pos++ = '\\';
      *pos++ = words[i][j];
    }
    if (quote)
      *pos++ = '"';
    free(words[i]);
  }
  *pos = '\0';
  free(words);
  free(lengths);
  free(preserve_raw);

  return buffer;

fail:
  for (size_t i = 0; i < count; i++)
    free(words[i]);
  free(words);
  free(lengths);
  free(preserve_raw);
  return NULL;
}

static bool process_single_command(shell_command_t *basic_cmd,
                                   const char *original_line,
                                   shell_command_info_t *info) {
  if (!basic_cmd || !info)
    return false;

  memset(info, 0, sizeof(shell_command_info_t));

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

static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            const char *original_line,
                                            shell_command_info_t *info) {
  (void)original_line;

  shell_token_t *shell_tokens = NULL;
  shell_token_t *command_tokens = NULL;
  size_t shell_count = 0;
  size_t command_count = 0;
  bool consume_redirection_operand = false;

  if (basic_cmd->token_count > SIZE_MAX / sizeof(shell_token_t))
    return false;
  shell_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
  command_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
  if (!shell_tokens || !command_tokens) {
    free(shell_tokens);
    free(command_tokens);
    return false;
  }

  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    shell_token_t *token = &basic_cmd->tokens[i];

    if (is_shell_operator_token(token)) {
      shell_tokens[shell_count++] = *token;

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
      command_tokens[command_count++] = *token;
    }
  }

  info->clean_command = build_clean_command(command_tokens, command_count);
  if (!info->clean_command) {
    free(shell_tokens);
    free(command_tokens);
    return false;
  }

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

shell_process_status_t shell_process_command(
    const char *command_line, const shell_process_limits_t *limits,
    shell_command_info_t **command_infos, size_t *command_count) {
  if (!command_infos || !command_count)
    return SHELL_PROCESS_EINPUT;
  *command_infos = NULL;
  *command_count = 0;
  if (!command_line)
    return SHELL_PROCESS_EINPUT;

  shell_command_t *basic_commands;
  size_t basic_count;

  errno = 0;
  if (!shell_tokenize_commands(command_line, &basic_commands, &basic_count))
    return errno == ENOMEM ? SHELL_PROCESS_ENOMEM : SHELL_PROCESS_EPARSE;

  if (basic_count == 0) {
    return SHELL_PROCESS_OK;
  }

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

void shell_free_command_infos(shell_command_info_t *infos, size_t count) {
  if (!infos)
    return;

  for (size_t i = 0; i < count; i++) {
    clear_command_info(&infos[i]);
  }
  free(infos);
}

const char *shell_get_clean_command(shell_command_info_t *info) {
  return info ? info->clean_command : NULL;
}

static size_t decimal_digits(size_t value) {
  size_t digits = 1;
  while (value >= 10) {
    value /= 10;
    digits++;
  }
  return digits;
}

shell_process_status_t
shell_render_netargv(const shell_command_info_t *info,
                     const shell_process_limits_t *limits, char **netargv) {
  if (netargv)
    *netargv = NULL;
  if (!info || !netargv)
    return SHELL_PROCESS_EINPUT;
  size_t count = info->command_token_count;
  char **words = count ? calloc(count, sizeof(*words)) : NULL;
  size_t *lengths = count ? calloc(count, sizeof(*lengths)) : NULL;
  if (count && (!words || !lengths)) {
    free(words);
    free(lengths);
    return SHELL_PROCESS_ENOMEM;
  }
  size_t total = 0;
  shell_process_status_t status = SHELL_PROCESS_OK;
  size_t built = 0;
  for (; built < count; built++) {
    const shell_token_t *token = &info->command_tokens[built];
    bool preserve = token->type == TOKEN_SUBSHELL ||
                    token->type == TOKEN_PROCESS_SUB ||
                    token->type == TOKEN_ARITHMETIC;
    words[built] = preserve ? strndup(token->start, token->length)
                            : decode_shell_word(token->start, token->length,
                                                &lengths[built]);
    if (!words[built]) {
      status = SHELL_PROCESS_ENOMEM;
      goto fail_render;
    }
    if (preserve)
      lengths[built] = token->length;
    size_t framing = decimal_digits(lengths[built]) + 2;
    if (lengths[built] > SIZE_MAX - framing ||
        total > SIZE_MAX - lengths[built] - framing) {
      status = SHELL_PROCESS_EOVERFLOW;
      built++;
      goto fail_render;
    }
    total += lengths[built] + framing;
  }
  if (limits &&
      (total > limits->max_string_bytes || total > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail_render;
  }
  char *encoded = malloc(total + 1);
  if (!encoded) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_render;
  }
  char *position = encoded;
  for (size_t i = 0; i < count; i++) {
    int written =
        snprintf(position, decimal_digits(lengths[i]) + 2, "%zu:", lengths[i]);
    position += (size_t)written;
    memcpy(position, words[i], lengths[i]);
    position += lengths[i];
    *position++ = ',';
  }
  *position = '\0';
  for (size_t i = 0; i < count; i++)
    free(words[i]);
  free(words);
  free(lengths);
  *netargv = encoded;
  return SHELL_PROCESS_OK;

fail_render:
  for (size_t i = 0; i < built; i++)
    free(words[i]);
  free(words);
  free(lengths);
  return status;
}

// Check for shell features that require explicit downstream handling.
bool shell_has_dangerous_features(shell_command_info_t *info) {
  if (!info)
    return false;

  if (info->shell_token_count != 0 || info->has_pipe_input ||
      info->has_pipe_output || info->has_redirections ||
      info->has_error_redirection)
    return true;

  /* Command and process substitutions are kept in clean text so downstream
   * validators still see the surrounding context. They can execute shell
   * code, so callers must handle them explicitly.
   */
  for (size_t i = 0; i < info->command_token_count; i++) {
    token_type_t type = info->command_tokens[i].type;
    if (type == TOKEN_SUBSHELL || type == TOKEN_PROCESS_SUB)
      return true;
  }
  return false;
}

// Parse command line and return clean per-command inputs for downstream
// processing, while reporting whether shell features are present for
// caller-side handling.
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

  if (count > SIZE_MAX / sizeof(const char *)) {
    shell_free_command_infos(infos, count);
    return SHELL_PROCESS_EOVERFLOW;
  }
  const char **inputs = malloc(count * sizeof(const char *));
  if (!inputs) {
    shell_free_command_infos(infos, count);
    return SHELL_PROCESS_ENOMEM;
  }

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

  for (size_t i = 0; i < count; i++) {
    free((void *)infos[i].original_command);
    free(infos[i].shell_tokens);
    free(infos[i].command_tokens);
  }
  free(infos);

  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_extract_netargv_inputs(const char *command_line,
                             const shell_process_limits_t *limits,
                             const char ***netargv_inputs, size_t *input_count,
                             bool *has_shell_features) {
  if (!netargv_inputs || !input_count || !has_shell_features)
    return SHELL_PROCESS_EINPUT;
  *netargv_inputs = NULL;
  *input_count = 0;
  *has_shell_features = false;
  if (!command_line)
    return SHELL_PROCESS_EINPUT;
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shell_process_status_t status =
      shell_process_command(command_line, limits, &infos, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  const char **inputs = count ? calloc(count, sizeof(*inputs)) : NULL;
  if (count && !inputs) {
    shell_free_command_infos(infos, count);
    return SHELL_PROCESS_ENOMEM;
  }
  size_t aggregate = 0;
  size_t built = 0;
  for (; built < count; built++) {
    if (shell_has_dangerous_features(&infos[built]))
      *has_shell_features = true;
    status =
        shell_render_netargv(&infos[built], limits, (char **)&inputs[built]);
    if (status != SHELL_PROCESS_OK)
      goto fail_inputs;
    size_t length = strlen(inputs[built]);
    if (aggregate > SIZE_MAX - length) {
      status = SHELL_PROCESS_EOVERFLOW;
      built++;
      goto fail_inputs;
    }
    aggregate += length;
    if (limits && aggregate > limits->max_total_bytes) {
      status = SHELL_PROCESS_EOUTPUT_LIMIT;
      built++;
      goto fail_inputs;
    }
  }
  shell_free_command_infos(infos, count);
  *netargv_inputs = inputs;
  *input_count = count;
  return SHELL_PROCESS_OK;

fail_inputs:
  for (size_t i = 0; i < built; i++)
    free((void *)inputs[i]);
  free(inputs);
  shell_free_command_infos(infos, count);
  *has_shell_features = false;
  return status;
}
