#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "alloc.h"
#include "shell_netstring.h"
#include "shell_processor_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
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
         token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
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
         token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

static bool redirection_consumes_next_token(const shell_token_t *token) {
  /* `>|` has no trailing '<' or '>' byte, but it still requires a pathname.
   * Keep this semantic exception explicit rather than treating the final
   * spelling byte as the complete redirect grammar. */
  if (token->type == SHELL_TOKEN_HERESTRING ||
      token->type == SHELL_TOKEN_REDIRECT_CLOBBER)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

/* Lexical token classes deliberately retain standalone substitution forms,
 * but a complete shell word may join one to literal prefix/suffix bytes. Scan
 * the borrowed word when deciding whether downstream handling is required so
 * `prefix$(cmd)suffix` cannot lose its execution marker. Process
 * substitutions are literal inside double quotes; command substitutions and
 * backticks remain active there. */
static bool word_has_executable_substitution(const shell_token_t *token) {
  if (!token)
    return false;
  bool in_single_quote = false;
  bool in_double_quote = false;
  for (size_t i = 0; i < token->length; i++) {
    char c = token->start[i];
    if (c == '\\' && !in_single_quote && i + 1 < token->length) {
      i++;
      continue;
    }
    if (c == '\'' && !in_double_quote) {
      in_single_quote = !in_single_quote;
      continue;
    }
    if (c == '"' && !in_single_quote) {
      in_double_quote = !in_double_quote;
      continue;
    }
    if (in_single_quote)
      continue;
    if (c == '`')
      return true;
    if (c == '$' && i + 1 < token->length && token->start[i + 1] == '(' &&
        !(i + 2 < token->length && token->start[i + 2] == '('))
      return true;
    if (!in_double_quote && (c == '<' || c == '>') && i + 1 < token->length &&
        token->start[i + 1] == '(')
      return true;
  }
  return false;
}

static bool
command_ends_with_group_redirection(const shell_command_t *command) {
  if (!command || !command->ends_group)
    return false;
  for (size_t i = 0; i < command->token_count; i++) {
    /* end_pos is the closing delimiter position. A redirect before it is
     * internal to the group; only one after it binds to the compound group. */
    if (is_redirection_token(&command->tokens[i]) &&
        command->tokens[i].position >= command->end_pos)
      return true;
  }
  return false;
}

static shell_process_status_t validate_group_io_limit(const char *command_line,
                                                      size_t command_length,
                                                      size_t max_group_io_ops);

static bool source_bytes_are_supported(const char *command_line,
                                       size_t command_length) {
  for (size_t i = 0; i < command_length; i++) {
    unsigned char byte = (unsigned char)command_line[i];
    if ((byte < 0x20 && !isspace(byte)) || byte == 0x7f || byte >= 0x80)
      return false;
  }
  return true;
}

shell_process_status_t
shell_process_validate_supported_source(const char *command_line,
                                        size_t command_length,
                                        shell_parse_result_t *parsed) {
  if (!command_line)
    return SHELL_PROCESS_EINPUT;
  /* Keep error classification consistent with the lexical processor: bytes
   * outside Shellsplit's source-text domain are invalid input, not a valid
   * source string with malformed shell grammar. */
  if (!source_bytes_are_supported(command_line, command_length))
    return SHELL_PROCESS_EINPUT;

  /* Unsupported control compounds are a semantic rejection, not a capacity
   * result.  Detect them before the bounded fast parser can stop at an earlier
   * command limit and otherwise hide a later `while`, `select`, or similar
   * construct from canonical callers. */
  if (command_length <= UINT32_MAX &&
      shell_tokenizer_has_unsupported_control(command_line, command_length))
    return SHELL_PROCESS_EPARSE;

  shell_parse_result_t local = {0};
  shell_parse_result_t *target = parsed ? parsed : &local;
  shell_limits_t strict_limits = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  shell_error_t error =
      shell_parse_fast(command_line, command_length, &strict_limits, target);
  if (error == SHELL_OK)
    return SHELL_PROCESS_OK;
  if (error == SHELL_EINPUT)
    return SHELL_PROCESS_EINPUT;
  return error == SHELL_ETRUNC ? SHELL_PROCESS_EOUTPUT_LIMIT
                               : SHELL_PROCESS_EPARSE;
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
  if (shell_tokenizer_has_unsupported_control(command_line, command_length)) {
    shell_commands_free(*commands, *count);
    *commands = NULL;
    *count = 0;
    return SHELL_PROCESS_EPARSE;
  }
  if (limits && limits->max_group_io_ops != 0) {
    shell_process_status_t status = validate_group_io_limit(
        command_line, command_length, limits->max_group_io_ops);
    if (status != SHELL_PROCESS_OK) {
      shell_commands_free(*commands, *count);
      *commands = NULL;
      *count = 0;
      return status;
    }
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
  size_t redirection_operand_end = 0;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (is_shell_operator_token(token)) {
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
      redirection_operand_end = 0;
    } else if (consume_redirection_operand) {
      if (redirection_operand_end == 0 ||
          token->position == redirection_operand_end) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      count++;
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
  size_t redirection_operand_end = 0;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (is_shell_operator_token(token)) {
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
      redirection_operand_end = 0;
    } else if (consume_redirection_operand) {
      if (redirection_operand_end == 0 ||
          token->position == redirection_operand_end) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      if (found++ == word_index)
        return token;
    } else if (found++ == word_index) {
      return token;
    }
  }
  return NULL;
}

bool shell_processed_command_is_group_structure(const shell_command_t *commands,
                                                size_t count, size_t index) {
  if (!commands || index >= count)
    return false;

  /* The full tokenizer may reserve an empty trailing slot at a compound-group
   * boundary. It has no source tokens and is structural, unlike a written
   * redirect-only command, which remains an invalid executable record. */
  if (commands[index].token_count == 0)
    return true;

  return index > 0 &&
         shell_processed_command_word_count(&commands[index]) == 0 &&
         command_ends_with_group_redirection(&commands[index - 1]);
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
    if (word_has_executable_substitution(
            shell_processed_command_word_at(command, i)))
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

static shell_process_status_t
render_processed_word(const char *text, size_t length, char *destination,
                      size_t destination_size, size_t *written) {
  if (written)
    *written = 0;
  if (!text || !written || (destination == NULL && destination_size != 0))
    return SHELL_PROCESS_EINPUT;

  size_t out = 0;
  char quote = '\0';
  for (size_t i = 0; i < length;) {
    char c = text[i];
    if (quote == '\0' && (c == '\'' || c == '"')) {
      quote = c;
      i++;
      continue;
    }
    if (quote != '\0' && c == quote) {
      quote = '\0';
      i++;
      continue;
    }

    size_t dynamic_after = i;
    bool dynamic = false;
    if (quote != '\'' && c == '$' && i + 1 < length && text[i + 1] == '(') {
      if (i + 2 < length && text[i + 2] == '(') {
        dynamic = shell_source_skip_arithmetic_expansion(text, length, i,
                                                         &dynamic_after);
      } else {
        dynamic = shell_source_find_balanced_parentheses(text, length, i + 1,
                                                         &dynamic_after);
      }
    } else if (quote == '\0' && (c == '<' || c == '>') && i + 1 < length &&
               text[i + 1] == '(') {
      dynamic = shell_source_find_balanced_parentheses(text, length, i + 1,
                                                       &dynamic_after);
    } else if (quote != '\'' && c == '`') {
      dynamic_after = shell_source_skip_quoted_text(text, length, i, '`');
      dynamic = dynamic_after > i + 1 && dynamic_after <= length &&
                text[dynamic_after - 1] == '`';
    }
    if (dynamic) {
      size_t dynamic_length = dynamic_after - i;
      if (out > SIZE_MAX - dynamic_length)
        return SHELL_PROCESS_EOVERFLOW;
      if (destination) {
        if (out > destination_size || dynamic_length > destination_size - out)
          return SHELL_PROCESS_EOUTPUT_LIMIT;
        memcpy(destination + out, text + i, dynamic_length);
      }
      out += dynamic_length;
      i = dynamic_after;
      continue;
    }
    if (c == '\\' && quote != '\'' && i + 1 < length) {
      char next = text[i + 1];
      if (quote == '\0' || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n') {
        if (next != '\n') {
          if (out == SIZE_MAX)
            return SHELL_PROCESS_EOVERFLOW;
          if (destination) {
            if (out == destination_size)
              return SHELL_PROCESS_EOUTPUT_LIMIT;
            destination[out] = next;
          }
          out++;
        }
        i += 2;
        continue;
      }
    }
    if (out == SIZE_MAX)
      return SHELL_PROCESS_EOVERFLOW;
    if (destination) {
      if (out == destination_size)
        return SHELL_PROCESS_EOUTPUT_LIMIT;
      destination[out] = c;
    }
    out++;
    i++;
  }
  *written = out;
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_measure_processed_word(const char *text,
                                                    size_t length,
                                                    size_t *processed_length) {
  return render_processed_word(text, length, NULL, 0, processed_length);
}

shell_process_status_t
shell_write_processed_word(const char *text, size_t length, char *destination,
                           size_t destination_size, size_t *written) {
  if (written)
    *written = 0;
  if (!destination)
    return SHELL_PROCESS_EINPUT;
  return render_processed_word(text, length, destination, destination_size,
                               written);
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
  size_t redirection_operand_end = 0;
  bool have_command_word = false;
  size_t command_word_end = 0;
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
      case SHELL_TOKEN_REDIRECT_READ_WRITE:
      case SHELL_TOKEN_REDIRECT_CLOBBER:
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
      redirection_operand_end = 0;
    } else if (consume_redirection_operand) {
      if (redirection_operand_end == 0 ||
          token->position == redirection_operand_end) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      if (!have_command_word || token->position != command_word_end)
        command_count++;
      have_command_word = true;
      command_word_end = token->position + token->length;
    } else {
      if (!have_command_word || token->position != command_word_end)
        command_count++;
      have_command_word = true;
      command_word_end = token->position + token->length;
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
  redirection_operand_end = 0;
  for (size_t i = 0; i < basic_cmd->token_count; i++) {
    const shell_token_t *token = &basic_cmd->tokens[i];
    if (is_shell_operator_token(token)) {
      shell_tokens[shell_index++] = *token;
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
      redirection_operand_end = 0;
    } else if (consume_redirection_operand) {
      if (redirection_operand_end == 0 ||
          token->position == redirection_operand_end) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      if (command_index > 0) {
        shell_token_t *previous = &command_tokens[command_index - 1];
        size_t previous_end = previous->position + previous->length;
        if (previous_end == token->position) {
          previous->length += token->length;
          previous->is_quoted = previous->is_quoted || token->is_quoted;
          previous->is_escaped = previous->is_escaped || token->is_escaped;
          continue;
        }
      }
      command_tokens[command_index++] = *token;
    } else {
      if (command_index > 0) {
        shell_token_t *previous = &command_tokens[command_index - 1];
        size_t previous_end = previous->position + previous->length;
        if (previous_end == token->position) {
          previous->length += token->length;
          previous->is_quoted = previous->is_quoted || token->is_quoted;
          previous->is_escaped = previous->is_escaped || token->is_escaped;
          continue;
        }
      }
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

  size_t info_count = 0;
  for (size_t i = 0; i < basic_count; i++) {
    /* The operand of a redirect attached to a completed group is parser
     * structure, not an independently executable command. */
    if (shell_processed_command_is_group_structure(basic_commands, basic_count,
                                                   i))
      continue;
    if (!process_single_command(&basic_commands[i], command_line,
                                &infos[info_count])) {
      shell_command_infos_free(infos, info_count);
      shell_commands_free(basic_commands, basic_count);
      return SHELL_PROCESS_ENOMEM;
    }
    if (info_count > 0 && infos[info_count - 1].has_pipe_output)
      infos[info_count].has_pipe_input = true;
    info_count++;
  }

  if (limits) {
    size_t total_output = 0;
    for (size_t i = 0; i < info_count; i++) {
      size_t original_length = strlen(infos[i].original_command);
      if (original_length > limits->max_string_bytes) {
        shell_command_infos_free(infos, info_count);
        shell_commands_free(basic_commands, basic_count);
        return SHELL_PROCESS_EOUTPUT_LIMIT;
      }
      if (original_length > SIZE_MAX - total_output) {
        shell_command_infos_free(infos, info_count);
        shell_commands_free(basic_commands, basic_count);
        return SHELL_PROCESS_EOVERFLOW;
      }
      total_output += original_length;
    }
    if (total_output > limits->max_total_bytes) {
      shell_command_infos_free(infos, info_count);
      shell_commands_free(basic_commands, basic_count);
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
  }

  shell_commands_free(basic_commands, basic_count);
  *command_infos = infos;
  *command_count = info_count;
  return SHELL_PROCESS_OK;
}

void shell_processed_commands_free(shell_processed_commands_t *result) {
  if (!result)
    return;
  shell_command_infos_free(result->commands, result->command_count);
  free(result->groups);
  free(result->group_io_ops);
  memset(result, 0, sizeof(*result));
}

static bool range_is_structural(const shell_range_t *range) {
  return range->type == SHELL_TYPE_HEREDOC ||
         range->type == SHELL_TYPE_HERESTRING;
}

static bool fast_range_is_heredoc_body(const char *input, uint32_t length,
                                       const shell_parse_result_t *parsed,
                                       uint32_t range_index) {
  uint32_t range_start = parsed->cmds[range_index].start;
  uint32_t prior_body_after = 0;
  for (uint32_t marker_index = 0; marker_index < parsed->count;
       marker_index++) {
    if (parsed->cmds[marker_index].type != SHELL_TYPE_HEREDOC) {
      continue;
    }
    uint32_t marker_start = parsed->cmds[marker_index].start;
    if (marker_start < prior_body_after)
      continue;
    uint32_t header_end =
        (uint32_t)shell_source_line_end(input, length, marker_start);
    if (header_end == length)
      return false;
    size_t after = length;
    bool complete = false;
    if (!shell_source_skip_heredoc_sequence(input, length, marker_start, &after,
                                            &complete))
      return false;
    uint32_t body_start = header_end + 1;
    if (!complete)
      return range_start >= body_start;
    if (range_start >= body_start && range_start < after)
      return true;
    prior_body_after = (uint32_t)after;
  }
  return false;
}

static bool range_is_executable(const char *input, uint32_t length,
                                const shell_parse_result_t *parsed,
                                uint32_t range_index) {
  const shell_range_t *range = &parsed->cmds[range_index];
  uint32_t position = range->start;
  while (position < range->start + range->len &&
         isdigit((unsigned char)input[position]))
    position++;
  bool redirect_only = position < range->start + range->len &&
                       (input[position] == '<' || input[position] == '>');
  if (redirect_only) {
    for (uint32_t i = 0; i < parsed->group_count; i++) {
      const shell_group_t *group = &parsed->groups[i];
      if (group->end > range->start)
        continue;
      bool adjacent = true;
      for (uint32_t p = group->end; p < range->start; p++) {
        if (!isspace((unsigned char)input[p])) {
          adjacent = false;
          break;
        }
      }
      if (adjacent)
        return false;
    }
  }
  return !range_is_structural(&parsed->cmds[range_index]) &&
         !fast_range_is_heredoc_body(input, length, parsed, range_index);
}

static bool group_contains_command(const shell_group_t *group,
                                   uint32_t command_index) {
  return group && command_index >= group->first_command &&
         command_index < (uint32_t)group->first_command + group->command_count;
}

static bool command_is_group_boundary(const shell_parse_result_t *parsed,
                                      uint32_t command_index, bool first) {
  for (uint32_t i = 0; i < parsed->group_count; i++) {
    const shell_group_t *group = &parsed->groups[i];
    if (!group_contains_command(group, command_index))
      continue;
    uint32_t boundary =
        first ? group->first_command
              : (uint32_t)group->first_command + group->command_count - 1;
    if (command_index == boundary)
      return true;
  }
  return false;
}

static uint32_t skip_inline_space(const char *input, uint32_t position,
                                  uint32_t length) {
  while (position < length &&
         (input[position] == ' ' || input[position] == '\t'))
    position++;
  return position;
}

static shell_process_status_t
append_group_io_op(shell_processed_commands_t *result,
                   const shell_group_io_op_t *op, size_t max_group_io_ops) {
  if (max_group_io_ops && result->group_io_op_count >= max_group_io_ops)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  if (result->group_io_op_count == SIZE_MAX / sizeof(*result->group_io_ops))
    return SHELL_PROCESS_EOVERFLOW;
  size_t count = result->group_io_op_count + 1;
  shell_group_io_op_t *ops =
      realloc(result->group_io_ops, count * sizeof(*result->group_io_ops));
  if (!ops)
    return SHELL_PROCESS_ENOMEM;
  result->group_io_ops = ops;
  result->group_io_ops[result->group_io_op_count++] = *op;
  return SHELL_PROCESS_OK;
}

static bool parse_group_fd(const char *input, uint32_t start, uint32_t end,
                           uint32_t *fd, uint32_t *after) {
  size_t position = 0;
  uint32_t descriptor = 0;
  shell_source_io_number_t io_number =
      shell_source_parse_io_number(input, start, end, &position, &descriptor);
  if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return false;
  *fd = io_number == SHELL_SOURCE_IO_NUMBER_VALID ? descriptor : UINT32_MAX;
  *after = (uint32_t)position;
  return true;
}

static bool range_has_validated_token(const shell_parse_result_t *parsed,
                                      uint32_t range_index,
                                      const shell_command_t *commands,
                                      size_t command_count) {
  const shell_range_t *range = &parsed->cmds[range_index];
  uint64_t range_start = range->start;
  uint64_t range_end = range_start + range->len;
  for (size_t i = 0; i < command_count; i++) {
    for (size_t j = 0; j < commands[i].token_count; j++) {
      const shell_token_t *token = &commands[i].tokens[j];
      uint64_t token_start = token->position;
      uint64_t token_end = token_start + token->length;
      if (range_start < token_end && token_start < range_end)
        return true;
    }
  }
  return false;
}

/* Scan a redirect list without accepting executable words. Adjacent
 * redirections are legal, and every returned operation retains its own source
 * span rather than collapsing the list into flags. */
static shell_process_status_t
scan_group_redirects(const char *input, uint32_t start, uint32_t end,
                     uint16_t group_index, shell_processed_commands_t *result,
                     size_t max_group_io_ops, bool *found) {
  uint32_t position = skip_inline_space(input, start, end);
  *found = false;
  while (position < end) {
    uint32_t source_start = position;
    uint32_t fd = UINT32_MAX;
    if (!parse_group_fd(input, position, end, &fd, &position))
      return SHELL_PROCESS_EPARSE;
    if (position >= end || (input[position] != '<' && input[position] != '>'))
      return *found ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE;
    char direction = input[position++];
    bool append = direction == '>' && position < end && input[position] == '>';
    if (append)
      position++;
    bool clobber =
        direction == '>' && !append && position < end && input[position] == '|';
    if (clobber)
      position++;
    bool read_write =
        direction == '<' && position < end && input[position] == '>';
    if (read_write)
      position++;
    bool heredoc = direction == '<' && position < end && input[position] == '<';
    if (heredoc)
      position++;
    bool herestring = heredoc && position < end && input[position] == '<';
    if (herestring)
      position++;
    if (heredoc && !herestring && position < end && input[position] == '-')
      position++;
    uint32_t operand_start = skip_inline_space(input, position, end);
    uint32_t operand_end = operand_start;
    if (!heredoc && operand_start < end && input[operand_start] == '&') {
      operand_end++;
      if (operand_end < end && input[operand_end] == '-')
        operand_end++;
      else
        while (operand_end < end && isdigit((unsigned char)input[operand_end]))
          operand_end++;
    } else {
      operand_end =
          (uint32_t)shell_source_skip_redirect_word(input, operand_start, end);
    }
    if (operand_start == operand_end)
      return SHELL_PROCESS_EPARSE;

    shell_group_io_op_t op = {
        .group_index = group_index,
        .source_start = source_start,
        .source_end = operand_end,
        .operand_start = operand_start,
        .operand_end = operand_end,
        .fd = fd == UINT32_MAX ? (direction == '<' ? 0 : 1) : fd,
        .target_fd = UINT32_MAX,
        .kind = read_write
                    ? SHELL_GROUP_IO_READ_WRITE_FILE
                    : (direction == '<' ? SHELL_GROUP_IO_READ_FILE
                                        : (append ? SHELL_GROUP_IO_APPEND_FILE
                                                  : SHELL_GROUP_IO_WRITE_FILE)),
    };
    if (heredoc)
      op.kind = herestring ? SHELL_GROUP_IO_HERESTRING : SHELL_GROUP_IO_HEREDOC;
    if (!heredoc && operand_end - operand_start >= 2 &&
        (input[operand_start] == '<' || input[operand_start] == '>') &&
        input[operand_start + 1] == '(') {
      bool operand_input = input[operand_start] == '<';
      if (read_write)
        op.kind = operand_input ? SHELL_GROUP_IO_PROCESS_SUB_RW_IN
                                : SHELL_GROUP_IO_PROCESS_SUB_RW_OUT;
      else if ((direction == '<') == operand_input)
        op.kind = operand_input ? SHELL_GROUP_IO_PROCESS_SUB_IN
                                : SHELL_GROUP_IO_PROCESS_SUB_OUT;
      else
        op.kind = SHELL_GROUP_IO_PROCESS_SUB_UNROUTED;
    }
    if (!heredoc && operand_end - operand_start >= 2 &&
        input[operand_start] == '&') {
      if (input[operand_start + 1] == '-' && operand_end == operand_start + 2)
        op.kind = SHELL_GROUP_IO_CLOSE_FD;
      else {
        uint32_t target_after = 0;
        uint32_t target_fd = UINT32_MAX;
        if (!parse_group_fd(input, operand_start + 1, operand_end, &target_fd,
                            &target_after) ||
            target_fd == UINT32_MAX || target_after != operand_end)
          return SHELL_PROCESS_EPARSE;
        op.kind = SHELL_GROUP_IO_DUP_FD;
        op.target_fd = target_fd;
      }
    }
    shell_process_status_t status =
        append_group_io_op(result, &op, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
    *found = true;
    position = skip_inline_space(input, operand_end, end);
  }
  return SHELL_PROCESS_OK;
}

static int compare_group_io_ops(const void *left, const void *right) {
  const shell_group_io_op_t *a = left;
  const shell_group_io_op_t *b = right;
  if (a->source_start != b->source_start)
    return a->source_start < b->source_start ? -1 : 1;
  if (a->source_end != b->source_end)
    return a->source_end < b->source_end ? -1 : 1;
  return 0;
}

static shell_process_status_t
append_group_relation(shell_processed_commands_t *result, uint16_t group_index,
                      shell_group_io_kind_t kind, uint32_t source_start,
                      uint32_t source_end, size_t max_group_io_ops) {
  const shell_group_io_op_t op = {
      .group_index = group_index,
      .source_start = source_start,
      .source_end = source_end,
      .operand_start = source_end,
      .operand_end = source_end,
      .fd = UINT32_MAX,
      .target_fd = UINT32_MAX,
      .kind = kind,
  };
  return append_group_io_op(result, &op, max_group_io_ops);
}

static shell_process_status_t scan_group_io(const char *input, uint32_t length,
                                            const shell_group_t *group,
                                            uint16_t group_index,
                                            shell_processed_commands_t *result,
                                            size_t max_group_io_ops) {
  uint32_t before = group->start;
  while (before > 0 && isspace((unsigned char)input[before - 1]))
    before--;
  if (before > 0 && input[before - 1] == '|' &&
      (before < 2 || input[before - 2] != '|')) {
    shell_process_status_t status =
        append_group_relation(result, group_index, SHELL_GROUP_IO_PIPE_INPUT,
                              before - 1, before, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
  }

  uint32_t after = skip_inline_space(input, group->end, length);
  bool found = false;
  shell_process_status_t status = scan_group_redirects(
      input, after, length, group_index, result, max_group_io_ops, &found);
  if (status != SHELL_PROCESS_OK && (found || status != SHELL_PROCESS_EPARSE))
    return status;
  if (status != SHELL_PROCESS_OK)
    after = skip_inline_space(input, group->end, length);
  else if (found) {
    size_t last = result->group_io_op_count - 1;
    after = result->group_io_ops[last].source_end;
    after = skip_inline_space(input, after, length);
  }
  if (after < length && input[after] == '|' &&
      (after + 1 == length || input[after + 1] != '|')) {
    status =
        append_group_relation(result, group_index, SHELL_GROUP_IO_PIPE_OUTPUT,
                              after, after + 1, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
  }
  if (after < length && input[after] == '&' &&
      (after + 1 == length || input[after + 1] != '&'))
    return append_group_relation(result, group_index, SHELL_GROUP_IO_BACKGROUND,
                                 after, after + 1, max_group_io_ops);
  return SHELL_PROCESS_OK;
}

/* The netsequence APIs do not return group metadata, but their shared limits
 * contract still bounds the structural I/O discovered in one source command.
 * Validate that rare non-zero limit here, while the ordinary unbounded path
 * retains the single full-tokenizer pass used by the sequence builders. */
static shell_process_status_t validate_group_io_limit(const char *command_line,
                                                      size_t command_length,
                                                      size_t max_group_io_ops) {
  if (command_length > UINT32_MAX)
    return SHELL_PROCESS_EINPUT;
  shell_parse_result_t parsed = {0};
  shell_error_t error =
      shell_parse_fast(command_line, command_length, NULL, &parsed);
  if (error != SHELL_OK)
    return error == SHELL_ETRUNC ? SHELL_PROCESS_EOUTPUT_LIMIT
                                 : SHELL_PROCESS_EPARSE;
  shell_processed_commands_t result = {0};
  for (uint32_t i = 0; i < parsed.group_count; i++) {
    shell_process_status_t status =
        scan_group_io(command_line, (uint32_t)command_length, &parsed.groups[i],
                      (uint16_t)i, &result, max_group_io_ops);
    if (status != SHELL_PROCESS_OK) {
      shell_processed_commands_free(&result);
      return status;
    }
  }
  shell_processed_commands_free(&result);
  return SHELL_PROCESS_OK;
}

static shell_process_status_t
process_fast_range(const char *command_line, const shell_parse_result_t *parsed,
                   uint32_t range_index, shell_command_info_t *info,
                   bool *produced) {
  *produced = false;
  const shell_range_t *range = &parsed->cmds[range_index];
  shell_command_info_t *one = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_process_command(
      command_line + range->start, range->len, NULL, &one, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (count != 1) {
    shell_command_infos_free(one, count);
    return SHELL_PROCESS_EPARSE;
  }
  if (one[0].command_token_count == 0) {
    shell_command_infos_free(one, count);
    return SHELL_PROCESS_OK;
  }
  *info = one[0];
  free(one);
  info->has_pipe_input = range->type == SHELL_TYPE_PIPELINE &&
                         !command_is_group_boundary(parsed, range_index, true);
  info->has_pipe_output =
      (range->features & SHELL_FEAT_PIPELINE) != 0 &&
      !command_is_group_boundary(parsed, range_index, false);
  *produced = true;
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_process_commands(const char *command_line, size_t command_length,
                       const shell_process_limits_t *limits,
                       shell_processed_commands_t *result) {
  if (!result)
    return SHELL_PROCESS_EINPUT;
  memset(result, 0, sizeof(*result));
  /* Keep the full tokenizer as the lexical syntax authority for this
   * higher-level API. The strict fast pass supplies the complete semantic
   * simple-command ranges needed for group ownership and I/O. */
  shell_parse_result_t parsed = {0};
  shell_process_status_t validation = shell_process_validate_supported_source(
      command_line, command_length, &parsed);
  if (validation != SHELL_PROCESS_OK)
    return validation;
  shell_command_t *validated = NULL;
  size_t validated_count = 0;
  validation = shell_processed_commands_parse(
      command_line, command_length, limits, &validated, &validated_count);
  if (validation != SHELL_PROCESS_OK)
    return validation;

  if (parsed.count > 0) {
    result->commands = calloc(parsed.count, sizeof(*result->commands));
    if (!result->commands) {
      shell_commands_free(validated, validated_count);
      return SHELL_PROCESS_ENOMEM;
    }
  }
  /* A processed result drops structural ranges (heredoc markers, here
   * strings, and document bodies).  Preserve the original fast-range index
   * only while constructing the owned command list, then remap groups below
   * so their intervals are always safe to index into result->commands. */
  uint16_t command_index[SHELL_MAX_SUBCOMMANDS];
  for (uint32_t i = 0; i < parsed.count; i++)
    command_index[i] = UINT16_MAX;
  for (uint32_t i = 0; i < parsed.count; i++) {
    if (!range_is_executable(command_line, (uint32_t)command_length, &parsed,
                             i) ||
        !range_has_validated_token(&parsed, i, validated, validated_count))
      continue;
    bool produced = false;
    shell_process_status_t status =
        process_fast_range(command_line, &parsed, i,
                           &result->commands[result->command_count], &produced);
    if (status != SHELL_PROCESS_OK) {
      shell_processed_commands_free(result);
      shell_commands_free(validated, validated_count);
      return status;
    }
    if (produced) {
      command_index[i] = (uint16_t)result->command_count;
      result->command_count++;
    }
  }
  if (parsed.group_count > 0) {
    result->groups = malloc(parsed.group_count * sizeof(*result->groups));
    if (!result->groups) {
      shell_processed_commands_free(result);
      shell_commands_free(validated, validated_count);
      return SHELL_PROCESS_ENOMEM;
    }
    result->group_count = parsed.group_count;
    for (uint32_t i = 0; i < parsed.group_count; i++) {
      const shell_group_t *source = &parsed.groups[i];
      shell_group_t *group = &result->groups[i];
      *group = *source;
      uint32_t first = source->first_command;
      uint32_t last = first + source->command_count;
      uint16_t insertion = (uint16_t)result->command_count;
      uint16_t count = 0;
      for (uint32_t range = 0; range < parsed.count; range++) {
        if (range < first && command_index[range] != UINT16_MAX)
          insertion = (uint16_t)(command_index[range] + 1);
        if (range >= first && range < last &&
            command_index[range] != UINT16_MAX) {
          if (count == 0)
            insertion = command_index[range];
          count++;
        }
      }
      group->first_command = insertion;
      group->command_count = count;
      shell_process_status_t status = scan_group_io(
          command_line, (uint32_t)command_length, source, (uint16_t)i, result,
          limits ? limits->max_group_io_ops : 0);
      if (status != SHELL_PROCESS_OK) {
        shell_processed_commands_free(result);
        shell_commands_free(validated, validated_count);
        return status;
      }
    }
    if (result->group_io_op_count > 1)
      qsort(result->group_io_ops, result->group_io_op_count,
            sizeof(*result->group_io_ops), compare_group_io_ops);
  }

  size_t total_output = 0;
  for (size_t i = 0; i < result->command_count; i++) {
    size_t length = strlen(result->commands[i].original_command);
    if (limits && length > limits->max_string_bytes) {
      shell_processed_commands_free(result);
      shell_commands_free(validated, validated_count);
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
    if (length > SIZE_MAX - total_output) {
      shell_processed_commands_free(result);
      shell_commands_free(validated, validated_count);
      return SHELL_PROCESS_EOVERFLOW;
    }
    total_output += length;
  }
  if (limits && total_output > limits->max_total_bytes) {
    shell_processed_commands_free(result);
    shell_commands_free(validated, validated_count);
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  shell_commands_free(validated, validated_count);
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

static shell_process_status_t rendered_word_length(const shell_token_t *token,
                                                   size_t *length) {
  return shell_measure_processed_word(token->start, token->length, length);
}

static char *render_word_into(const shell_token_t *token, char *destination) {
  size_t written = 0;
  if (shell_write_processed_word(token->start, token->length, destination,
                                 SIZE_MAX, &written) != SHELL_PROCESS_OK)
    return NULL;
  return destination + written;
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

/* The full iterator exposes lexical expansion fragments for callers that
 * need them. Canonical argv instead has one record per source shell word, so
 * merge adjacent non-operator fragments into a small borrowed synthetic
 * token while rendering the direct netargv-sequence APIs. */
static bool basic_command_word_at(const shell_command_t *command, size_t wanted,
                                  shell_token_t *word) {
  if (!command || !word)
    return false;
  bool consume_redirection_operand = false;
  size_t redirection_operand_end = 0;
  size_t found = 0;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (is_shell_operator_token(token)) {
      consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
      redirection_operand_end = 0;
      continue;
    }
    if (consume_redirection_operand) {
      if (redirection_operand_end == 0 ||
          token->position == redirection_operand_end) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
    }

    shell_token_t merged = *token;
    size_t j = i + 1;
    while (j < command->token_count) {
      const shell_token_t *next = &command->tokens[j];
      if (is_shell_operator_token(next))
        break;
      if (merged.position > SIZE_MAX - merged.length ||
          merged.position + merged.length != next->position)
        break;
      merged.length += next->length;
      merged.is_quoted = merged.is_quoted || next->is_quoted;
      merged.is_escaped = merged.is_escaped || next->is_escaped;
      j++;
    }
    if (found++ == wanted) {
      *word = merged;
      return true;
    }
    i = j - 1;
  }
  return false;
}

static size_t basic_command_word_count(const shell_command_t *command) {
  size_t count = 0;
  shell_token_t word;
  while (basic_command_word_at(command, count, &word))
    count++;
  return count;
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
  size_t count = basic_command_word_count(command);
  for (size_t i = 0; i < count; i++) {
    shell_token_t word;
    if (!basic_command_word_at(command, i, &word))
      return SHELL_PROCESS_EPARSE;
    size_t length = 0;
    shell_process_status_t status = rendered_word_length(&word, &length);
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
  size_t count = basic_command_word_count(command);
  for (size_t i = 0; i < count; i++) {
    shell_token_t word;
    if (!basic_command_word_at(command, i, &word))
      return NULL;
    size_t length = 0;
    (void)rendered_word_length(&word, &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    position = render_word_into(&word, position);
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
    if (word_has_executable_substitution(&info->command_tokens[i]))
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

  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, NULL);
  if (status != SHELL_PROCESS_OK)
    return status;

  shell_command_t *commands = NULL;
  size_t count = 0;
  status = shell_processed_commands_parse(command_line, command_length, limits,
                                          &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t total = 0;
  size_t rendered_count = 0;
  for (size_t i = 0; i < count; i++) {
    /* A redirect following a compound group belongs to that group. The full
     * tokenizer retains its operand as a structural stage so redirection
     * metadata is not lost; canonical argv must not render it as a command. */
    if (shell_processed_command_is_group_structure(commands, count, i))
      continue;
    if (shell_processed_command_word_count(&commands[i]) == 0) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_sequence;
    }
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
    rendered_count++;
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
    if (shell_processed_command_is_group_structure(commands, count, i))
      continue;
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
  *subcommand_count = rendered_count;
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
  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, NULL);
  if (status != SHELL_PROCESS_OK)
    return status;
  shell_command_t *commands = NULL;
  size_t count = 0;
  status = shell_processed_commands_parse(command_line, command_length, limits,
                                          &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  size_t total = 0;
  size_t rendered_count = 0;
  for (size_t i = 0; i < count; i++) {
    if (shell_processed_command_is_group_structure(commands, count, i))
      continue;
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
    rendered_count++;
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
    if (shell_processed_command_is_group_structure(commands, count, i))
      continue;
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
  *subcommand_count = rendered_count;
  return SHELL_PROCESS_OK;

fail_commands:
  shell_commands_free(commands, count);
  return status;
}
