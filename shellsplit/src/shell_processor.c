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
         token->type == SHELL_TOKEN_PIPE_BOTH ||
         token->type == SHELL_TOKEN_PIPE_NEGATE ||
         token->type == SHELL_TOKEN_REDIRECT_IN ||
         token->type == SHELL_TOKEN_REDIRECT_OUT ||
         token->type == SHELL_TOKEN_REDIRECT_ERR ||
         token->type == SHELL_TOKEN_REDIRECT_APPEND ||
         token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
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
         token->type == SHELL_TOKEN_REDIRECT_BOTH ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

shell_process_status_t
shell_process_cstring_allocation_size(size_t content_length,
                                      size_t *allocation_size) {
  if (allocation_size)
    *allocation_size = 0;
  if (!allocation_size)
    return SHELL_PROCESS_EINPUT;
  if (content_length == SIZE_MAX)
    return SHELL_PROCESS_EOVERFLOW;
  *allocation_size = content_length + 1;
  return SHELL_PROCESS_OK;
}

static bool redirection_consumes_next_token(const shell_token_t *token) {
  /* `>|` has no trailing '<' or '>' byte, but it still requires a pathname.
   * Keep this semantic exception explicit rather than treating the final
   * spelling byte as the complete redirect grammar. */
  if (token->type == SHELL_TOKEN_HERESTRING ||
      token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
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
      shell_tokenizer_has_unsupported_semantics(command_line, command_length))
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
  if (shell_tokenizer_has_unsupported_semantics(command_line, command_length)) {
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

void shell_processed_word_iterator_init(
    shell_processed_word_iterator_t *iterator, const shell_command_t *command) {
  if (!iterator)
    return;
  *iterator = (shell_processed_word_iterator_t){.command = command};
}

bool shell_processed_word_iterator_next(
    shell_processed_word_iterator_t *iterator, shell_token_t *word) {
  if (!iterator || !word || !iterator->command)
    return false;
  const shell_command_t *command = iterator->command;
  while (iterator->token_index < command->token_count) {
    const shell_token_t *token = &command->tokens[iterator->token_index++];
    if (is_shell_operator_token(token)) {
      iterator->consume_redirection_operand =
          is_redirection_token(token) && redirection_consumes_next_token(token);
      iterator->redirection_operand_end = 0;
      continue;
    }
    if (iterator->consume_redirection_operand) {
      if (iterator->redirection_operand_end == 0 ||
          shell_tokenizer_token_continues_word(
              token, iterator->redirection_operand_end)) {
        if (token->position > SIZE_MAX - token->length) {
          /* The iterator cannot report malformed internal token spans. Treat
           * this operand as complete without wrapping its logical endpoint. */
          iterator->redirection_operand_end = SIZE_MAX;
          continue;
        }
        iterator->redirection_operand_end = token->position + token->length;
        continue;
      }
      iterator->consume_redirection_operand = false;
    }

    shell_token_t merged = *token;
    while (iterator->token_index < command->token_count) {
      const shell_token_t *next = &command->tokens[iterator->token_index];
      if (is_shell_operator_token(next) ||
          merged.position > SIZE_MAX - merged.length ||
          next->position > SIZE_MAX - next->length ||
          !shell_tokenizer_token_continues_word(next, merged.position +
                                                          merged.length))
        break;
      merged.length = next->position + next->length - merged.position;
      merged.is_quoted = merged.is_quoted || next->is_quoted;
      merged.is_escaped = merged.is_escaped || next->is_escaped;
      iterator->token_index++;
    }
    *word = merged;
    return true;
  }
  return false;
}

size_t shell_processed_command_word_count(const shell_command_t *command) {
  shell_processed_word_iterator_t iterator;
  shell_processed_word_iterator_init(&iterator, command);
  shell_token_t word;
  size_t count = 0;
  while (shell_processed_word_iterator_next(&iterator, &word))
    count++;
  return count;
}

bool shell_processed_command_is_group_structure(const shell_command_t *commands,
                                                size_t count, size_t index,
                                                const char *source,
                                                size_t source_length) {
  if (!commands || index >= count)
    return false;

  /* The full tokenizer may reserve an empty trailing slot at a compound-group
   * boundary. It has no source tokens and is structural, unlike a written
   * redirect-only command, which remains an argv-less execution stage for
   * anomaly-sequence builders. */
  if (commands[index].token_count == 0)
    return true;

  if (!source || index == 0)
    return false;
  const shell_command_t *previous_record = &commands[index - 1];
  if (previous_record->token_count != 0) {
    const shell_token_t *last_token =
        &previous_record->tokens[previous_record->token_count - 1];
    if (last_token->position > source_length ||
        last_token->length > source_length - last_token->position)
      return false;
    size_t start = last_token->position + last_token->length;
    size_t end = commands[index].tokens[0].position;
    if (start > source_length || end > source_length)
      return false;
    if (end > start &&
        shell_source_skip_inline_continuations(source, end, start) != end)
      return false;
  }

  /* A separator terminates the preceding group's redirect list. Its next
   * argv-less command is executable structure, not an attached operand. */
  if (index > 0 && commands[index - 1].token_count != 0) {
    const shell_command_t *previous = &commands[index - 1];
    shell_token_type_t last = previous->tokens[previous->token_count - 1].type;
    if (last == SHELL_TOKEN_SEMICOLON || last == SHELL_TOKEN_PIPE ||
        last == SHELL_TOKEN_PIPE_BOTH || last == SHELL_TOKEN_AND ||
        last == SHELL_TOKEN_OR || last == SHELL_TOKEN_BACKGROUND)
      return false;
  }

  return index > 0 &&
         shell_processed_command_word_count(&commands[index]) == 0 &&
         command_ends_with_group_redirection(&commands[index - 1]);
}

/* --- EXECUTION-STAGE COLLECTION ---------------------------------------- */

/* Anomaly sequences model every supported simple command that the shell will
 * execute while evaluating one source command.  The flat tokenizer exposes
 * only the immediate list, so recursively walk executable substitutions and
 * append the enclosing command last.  That produces a stable analysis order
 * (children before parent, siblings in source order) without claiming a
 * runtime schedule for pipeline members. */
typedef struct {
  shell_anomaly_stages_t *stages;
  const shell_process_limits_t *limits;
  uint32_t depth;
  shell_process_status_t status;
} shell_anomaly_stage_collect_t;

static shell_process_status_t
anomaly_collect_source(const char *source, size_t source_length,
                       shell_anomaly_stage_collect_t *collect);

void shell_anomaly_stages_free(shell_anomaly_stages_t *stages) {
  if (!stages)
    return;
  shell_commands_free(stages->commands, stages->count);
  *stages = (shell_anomaly_stages_t){0};
}

static bool anomaly_append_stage(shell_anomaly_stage_collect_t *collect,
                                 shell_command_t *command) {
  if (!collect || !collect->stages || !command)
    return false;
  if (collect->stages->count >= SHELL_MAX_SUBCOMMANDS) {
    collect->status = SHELL_PROCESS_EOUTPUT_LIMIT;
    return false;
  }
  if (collect->stages->count == SIZE_MAX / sizeof(*collect->stages->commands)) {
    collect->status = SHELL_PROCESS_EOVERFLOW;
    return false;
  }
  shell_command_t *grown = realloc(
      collect->stages->commands, (collect->stages->count + 1) * sizeof(*grown));
  if (!grown) {
    collect->status = SHELL_PROCESS_ENOMEM;
    return false;
  }
  collect->stages->commands = grown;
  grown[collect->stages->count++] = *command;
  *command = (shell_command_t){0};
  return true;
}

static bool anomaly_substitution_content(const char *source,
                                         size_t source_length, size_t start,
                                         size_t after,
                                         shell_source_substitution_kind_t kind,
                                         const char **content,
                                         size_t *content_length) {
  if (!source || !content || !content_length || start >= after ||
      after > source_length)
    return false;
  size_t prefix = kind == SHELL_SOURCE_SUBST_BACKTICK ? 1 : 2;
  size_t suffix = kind == SHELL_SOURCE_SUBST_BACKTICK ? 1 : 1;
  if (after - start < prefix + suffix)
    return false;
  *content = source + start + prefix;
  *content_length = after - start - prefix - suffix;
  return true;
}

static bool
anomaly_collect_substitutions(const char *source, size_t source_length,
                              bool allow_process_substitution,
                              shell_anomaly_stage_collect_t *collect) {
  if (!source || !collect)
    return false;
  shell_source_substitution_scan_t scan = {0};
  size_t start = 0;
  size_t after = 0;
  shell_source_substitution_kind_t kind;
  while (shell_source_next_executable_substitution(source, source_length, &scan,
                                                   &start, &after, &kind)) {
    if (!allow_process_substitution &&
        (kind == SHELL_SOURCE_SUBST_PROCESS_INPUT ||
         kind == SHELL_SOURCE_SUBST_PROCESS_OUTPUT))
      continue;
    const char *content = NULL;
    size_t content_length = 0;
    if (!anomaly_substitution_content(source, source_length, start, after, kind,
                                      &content, &content_length)) {
      collect->status = SHELL_PROCESS_EPARSE;
      return false;
    }
    if (collect->depth >= SHELL_MAX_SUBCOMMANDS) {
      collect->status = SHELL_PROCESS_EOUTPUT_LIMIT;
      return false;
    }
    collect->depth++;
    shell_process_status_t status =
        anomaly_collect_source(content, content_length, collect);
    collect->depth--;
    if (status != SHELL_PROCESS_OK) {
      collect->status = status;
      return false;
    }
  }
  return true;
}

/* Unlike an ordinary shell word, quote bytes in an unquoted heredoc body are
 * data. Only its expansion grammar can execute nested source. */
static bool
anomaly_collect_heredoc_substitutions(const char *source, size_t source_length,
                                      shell_anomaly_stage_collect_t *collect) {
  if (!source || !collect)
    return false;
  for (size_t position = 0; position < source_length; position++) {
    char c = source[position];
    if (c == '\\' && position + 1 < source_length) {
      char next = source[position + 1];
      if (next == '$' || next == '`' || next == '\\' || next == '\n' ||
          next == '\r') {
        position++;
        continue;
      }
    }
    size_t after = 0;
    const char *content = NULL;
    size_t content_length = 0;
    if (c == '`') {
      after =
          shell_source_skip_quoted_text(source, source_length, position, '`');
      if (after <= position + 1 || after > source_length ||
          source[after - 1] != '`') {
        collect->status = SHELL_PROCESS_EPARSE;
        return false;
      }
      content = source + position + 1;
      content_length = after - position - 2;
    } else if (c == '$' && position + 1 < source_length &&
               source[position + 1] == '{') {
      if (!shell_source_skip_parameter_expansion(source, source_length,
                                                 position, &after) ||
          after <= position + 3 || after > source_length ||
          source[after - 1] != '}') {
        collect->status = SHELL_PROCESS_EPARSE;
        return false;
      }
      if (!anomaly_collect_heredoc_substitutions(source + position + 2,
                                                 after - position - 3, collect))
        return false;
      position = after - 1;
      continue;
    } else if (c == '$' && position + 1 < source_length &&
               source[position + 1] == '(') {
      if (position + 2 < source_length && source[position + 2] == '(') {
        if (!shell_source_skip_arithmetic_expansion(source, source_length,
                                                    position, &after) ||
            after <= position + 5 || after > source_length) {
          collect->status = SHELL_PROCESS_EPARSE;
          return false;
        }
        if (!anomaly_collect_substitutions(
                source + position + 3, after - position - 5, false, collect))
          return false;
        position = after - 1;
        continue;
      }
      if (!shell_source_find_balanced_parentheses(source, source_length,
                                                  position + 1, &after) ||
          !anomaly_substitution_content(source, source_length, position, after,
                                        SHELL_SOURCE_SUBST_COMMAND, &content,
                                        &content_length)) {
        collect->status = SHELL_PROCESS_EPARSE;
        return false;
      }
    } else {
      continue;
    }
    if (collect->depth >= SHELL_MAX_SUBCOMMANDS) {
      collect->status = SHELL_PROCESS_EOUTPUT_LIMIT;
      return false;
    }
    collect->depth++;
    shell_process_status_t status =
        anomaly_collect_source(content, content_length, collect);
    collect->depth--;
    if (status != SHELL_PROCESS_OK) {
      collect->status = status;
      return false;
    }
    position = after - 1;
  }
  return true;
}

static bool anomaly_collect_heredoc_body(const char *input, size_t body_start,
                                         size_t body_length,
                                         bool delimiter_quoted, void *context) {
  shell_anomaly_stage_collect_t *collect = context;
  if (!collect || !input)
    return false;
  if (delimiter_quoted)
    return true;
  return anomaly_collect_heredoc_substitutions(input + body_start, body_length,
                                               collect);
}

static bool anomaly_heredoc_operator_position(const shell_token_t *token,
                                              size_t *operator_position) {
  if (!token || !operator_position || token->type != SHELL_TOKEN_HEREDOC)
    return false;
  for (size_t i = 0; i + 1 < token->length; i++) {
    if (token->start[i] == '<' && token->start[i + 1] == '<') {
      *operator_position = token->position + i;
      return true;
    }
  }
  return false;
}

static bool
anomaly_collect_command_substitutions(const char *source, size_t source_length,
                                      const shell_command_t *command,
                                      shell_anomaly_stage_collect_t *collect) {
  if (!source || !command || !collect)
    return false;
  size_t heredoc_after = 0;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
    if (token->position > source_length ||
        token->length > source_length - token->position) {
      collect->status = SHELL_PROCESS_EPARSE;
      return false;
    }
    if (token->type == SHELL_TOKEN_HEREDOC) {
      if (token->position < heredoc_after)
        continue;
      size_t operator_position = 0;
      size_t after = 0;
      bool complete = false;
      if (!anomaly_heredoc_operator_position(token, &operator_position) ||
          !shell_source_visit_heredoc_sequence(
              source, source_length, operator_position,
              anomaly_collect_heredoc_body, collect, &after, &complete) ||
          !complete) {
        collect->status = SHELL_PROCESS_EPARSE;
        return false;
      }
      heredoc_after = after;
      continue;
    }
    if (token->type == SHELL_TOKEN_ARITHMETIC && token->length >= 5 &&
        token->start[0] == '$' && token->start[1] == '(' &&
        token->start[2] == '(' && token->start[token->length - 2] == ')' &&
        token->start[token->length - 1] == ')') {
      if (!anomaly_collect_substitutions(token->start + 3, token->length - 5,
                                         false, collect))
        return false;
      continue;
    }
    if (!anomaly_collect_substitutions(token->start, token->length, true,
                                       collect))
      return false;
  }
  return true;
}

static shell_process_status_t
anomaly_collect_source(const char *source, size_t source_length,
                       shell_anomaly_stage_collect_t *collect) {
  if (!source || !collect || !collect->stages)
    return SHELL_PROCESS_EINPUT;
  shell_command_t *commands = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_processed_commands_parse(
      source, source_length, collect->limits, &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  for (size_t i = 0; i < count; i++) {
    if (!anomaly_collect_command_substitutions(source, source_length,
                                               &commands[i], collect)) {
      status = collect->status == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE
                                                   : collect->status;
      goto done;
    }
    if (shell_processed_command_is_group_structure(commands, count, i, source,
                                                   source_length))
      continue;
    if (!anomaly_append_stage(collect, &commands[i])) {
      status = collect->status == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE
                                                   : collect->status;
      goto done;
    }
  }
  status = SHELL_PROCESS_OK;

done:
  shell_commands_free(commands, count);
  return status;
}

shell_process_status_t
shell_anomaly_stages_parse(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           shell_anomaly_stages_t *stages) {
  if (!stages)
    return SHELL_PROCESS_EINPUT;
  *stages = (shell_anomaly_stages_t){0};
  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, NULL);
  if (status != SHELL_PROCESS_OK)
    return status;
  shell_anomaly_stage_collect_t collect = {
      .stages = stages,
      .limits = limits,
      .status = SHELL_PROCESS_OK,
  };
  status = anomaly_collect_source(command_line, command_length, &collect);
  if (status != SHELL_PROCESS_OK) {
    shell_anomaly_stages_free(stages);
    return status;
  }
  return SHELL_PROCESS_OK;
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
  shell_processed_word_iterator_t iterator;
  shell_processed_word_iterator_init(&iterator, command);
  shell_token_t word;
  while (shell_processed_word_iterator_next(&iterator, &word)) {
    if (shell_source_word_has_executable_substitution(word.start, word.length))
      return true;
  }
  return false;
}

bool shell_processed_command_has_pipe_output(const shell_command_t *command) {
  if (!command)
    return false;
  for (size_t i = 0; i < command->token_count; i++) {
    if (command->tokens[i].type == SHELL_TOKEN_PIPE ||
        command->tokens[i].type == SHELL_TOKEN_PIPE_BOTH)
      return true;
  }
  return false;
}

typedef struct {
  char *destination;
  size_t destination_size;
  size_t output_length;
  shell_decoded_word_visitor_t visitor;
  void *visitor_context;
  bool stopped;
  shell_process_status_t error;
} decoded_word_sink_t;

static shell_process_status_t decoded_word_emit(decoded_word_sink_t *sink,
                                                unsigned char value) {
  if (sink->stopped)
    return SHELL_PROCESS_OK;
  if (sink->output_length == SIZE_MAX)
    return SHELL_PROCESS_EOVERFLOW;
  if (sink->destination) {
    if (sink->output_length >= sink->destination_size)
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    sink->destination[sink->output_length] = (char)value;
  }
  size_t offset = sink->output_length++;
  if (sink->visitor && !sink->visitor(value, offset, sink->visitor_context))
    sink->stopped = true;
  return SHELL_PROCESS_OK;
}

static bool ansi_decode_emit(unsigned char byte, void *context) {
  decoded_word_sink_t *sink = context;
  sink->error = decoded_word_emit(sink, byte);
  return sink->error == SHELL_PROCESS_OK;
}

/* Decode one complete Bash $'...' fragment through the source-level decoder.
 * Canonical argv keeps decoded NUL bytes; heredoc matching uses the same
 * decoder with its distinct C-string delimiter rule. */
static shell_process_status_t ansi_decode_quote(const char *text, size_t length,
                                                size_t *position,
                                                decoded_word_sink_t *sink) {
  if (!sink)
    return SHELL_PROCESS_EPARSE;
  sink->error = SHELL_PROCESS_OK;
  if (shell_source_decode_ansi_c_quote(text, length, position, ansi_decode_emit,
                                       sink))
    return SHELL_PROCESS_OK;
  return sink->error == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE : sink->error;
}

static shell_process_status_t decode_shell_word(const char *text, size_t length,
                                                decoded_word_sink_t *sink) {
  char quote = 0;
  for (size_t i = 0; i < length; i++) {
    char c = text[i];
    if (quote == 0 && c == '$' && i + 1 < length && text[i + 1] == '\'') {
      size_t position = i;
      shell_process_status_t status =
          ansi_decode_quote(text, length, &position, sink);
      if (sink->stopped)
        return SHELL_PROCESS_OK;
      if (status != SHELL_PROCESS_OK)
        return status;
      i = position - 1;
      continue;
    }
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
          next == '\\' || next == '\n' || next == '\r') {
        if (next != '\n' && next != '\r') {
          shell_process_status_t status = decoded_word_emit(sink, next);
          if (status != SHELL_PROCESS_OK)
            return status;
          if (sink->stopped)
            return SHELL_PROCESS_OK;
        }
        i++;
        if (next == '\r' && i + 1 < length && text[i + 1] == '\n')
          i++;
        continue;
      }
    }
    shell_process_status_t status = decoded_word_emit(sink, (unsigned char)c);
    if (status != SHELL_PROCESS_OK)
      return status;
    if (sink->stopped)
      return SHELL_PROCESS_OK;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_visit_decoded_word(const char *text, size_t length,
                         shell_decoded_word_visitor_t visitor, void *context,
                         size_t *decoded_length) {
  if (decoded_length)
    *decoded_length = 0;
  if (!text || !decoded_length)
    return SHELL_PROCESS_EINPUT;
  decoded_word_sink_t sink = {
      .visitor = visitor,
      .visitor_context = context,
  };
  shell_process_status_t status = decode_shell_word(text, length, &sink);
  *decoded_length = sink.output_length;
  return status;
}

shell_process_status_t shell_measure_decoded_word(const char *text,
                                                  size_t length,
                                                  size_t *decoded_length) {
  return shell_visit_decoded_word(text, length, NULL, NULL, decoded_length);
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
  decoded_word_sink_t sink = {
      .destination = destination,
      .destination_size = destination_size,
  };
  status = decode_shell_word(text, length, &sink);
  if (status != SHELL_PROCESS_OK)
    return status;
  *written = sink.output_length;
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
    if (quote == '\0' && c == '$' && i + 1 < length && text[i + 1] == '\'') {
      decoded_word_sink_t sink = {
          .destination = destination,
          .destination_size = destination_size,
          .output_length = out,
      };
      shell_process_status_t status =
          ansi_decode_quote(text, length, &i, &sink);
      if (status != SHELL_PROCESS_OK)
        return status;
      out = sink.output_length;
      continue;
    }
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
          next == '\\' || next == '\n' || next == '\r') {
        if (next != '\n' && next != '\r') {
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
        if (next == '\r' && i < length && text[i] == '\n')
          i++;
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
  shell_pipe_mode_t pipe_output_mode = SHELL_PIPE_MODE_NONE;
  uint32_t pipeline_negation_count = basic_cmd->pipeline_negation_count;
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
        pipe_output_mode = SHELL_PIPE_MODE_STDOUT;
        break;
      case SHELL_TOKEN_PIPE_BOTH:
        pipe_output_mode = SHELL_PIPE_MODE_STDOUT_AND_STDERR;
        break;
      case SHELL_TOKEN_PIPE_NEGATE:
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
      case SHELL_TOKEN_REDIRECT_BOTH:
      case SHELL_TOKEN_REDIRECT_BOTH_APPEND:
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
      if (redirection_operand_end == 0 || shell_tokenizer_token_continues_word(
                                              token, redirection_operand_end)) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      if (!have_command_word ||
          !shell_tokenizer_token_continues_word(token, command_word_end))
        command_count++;
      have_command_word = true;
      command_word_end = token->position + token->length;
    } else {
      if (!have_command_word ||
          !shell_tokenizer_token_continues_word(token, command_word_end))
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
      if (redirection_operand_end == 0 || shell_tokenizer_token_continues_word(
                                              token, redirection_operand_end)) {
        redirection_operand_end = token->position + token->length;
        continue;
      }
      consume_redirection_operand = false;
      if (command_index > 0) {
        shell_token_t *previous = &command_tokens[command_index - 1];
        size_t previous_end = previous->position + previous->length;
        if (shell_tokenizer_token_continues_word(token, previous_end)) {
          previous->length =
              token->position + token->length - previous->position;
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
        if (shell_tokenizer_token_continues_word(token, previous_end)) {
          previous->length =
              token->position + token->length - previous->position;
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
  info->pipe_output_mode = pipe_output_mode;
  info->has_pipe_output = pipe_output_mode != SHELL_PIPE_MODE_NONE;
  info->pipeline_negation_count = pipeline_negation_count;
  info->pipeline_negated = (pipeline_negation_count & UINT32_C(1)) != 0;
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
    if (shell_processed_command_is_group_structure(
            basic_commands, basic_count, i, command_line, command_length))
      continue;
    if (!process_single_command(&basic_commands[i], command_line,
                                &infos[info_count])) {
      shell_command_infos_free(infos, info_count);
      shell_commands_free(basic_commands, basic_count);
      return SHELL_PROCESS_ENOMEM;
    }
    if (info_count > 0 && infos[info_count - 1].has_pipe_output) {
      infos[info_count].has_pipe_input = true;
      /* `!` modifies the complete pipeline. Propagate the exact count, not
       * merely a boolean, so an even number does not look inverted. */
      infos[info_count].pipeline_negation_count =
          infos[info_count - 1].pipeline_negation_count;
      infos[info_count].pipeline_negated =
          (infos[info_count].pipeline_negation_count & UINT32_C(1)) != 0;
    }
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
    uint32_t group_redirect_start =
        (uint32_t)shell_source_named_fd_start_before(input, length,
                                                     range->start);
    for (uint32_t i = 0; i < parsed->group_count; i++) {
      const shell_group_t *group = &parsed->groups[i];
      if (group->end > group_redirect_start)
        continue;
      if (shell_source_skip_inline_continuations(
              input, group_redirect_start, group->end) == group_redirect_start)
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
  if (shell_source_parse_named_fd_redirect(input, start, end, &position)) {
    *fd = SHELL_PROCESS_FD_NAMED;
    *after = (uint32_t)position;
    return true;
  }
  uint32_t descriptor = 0;
  shell_source_io_number_t io_number =
      shell_source_parse_io_number(input, start, end, &position, &descriptor);
  if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return false;
  *fd = io_number == SHELL_SOURCE_IO_NUMBER_VALID ? descriptor
                                                  : SHELL_PROCESS_FD_NONE;
  *after = (uint32_t)position;
  return true;
}

/* Scan a redirect list without accepting executable words. Adjacent
 * redirections are legal, and every returned operation retains its own source
 * span rather than collapsing the list into flags. */
static shell_process_status_t
scan_group_redirects(const char *input, uint32_t start, uint32_t end,
                     uint16_t group_index, shell_processed_commands_t *result,
                     size_t max_group_io_ops, bool *found) {
  uint32_t position =
      (uint32_t)shell_source_skip_inline_continuations(input, end, start);
  *found = false;
  while (position < end) {
    uint32_t source_start = position;
    size_t redirect_end = shell_source_skip_redirect(input, source_start, end);
    if (redirect_end == source_start)
      return *found ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE;
    /* Once the shared scanner has recognized a redirect, a later semantic
     * rejection must not be mistaken by scan_group_io() for ordinary text
     * following the group. */
    *found = true;

    uint32_t fd = SHELL_PROCESS_FD_NONE;
    if (!parse_group_fd(input, position, end, &fd, &position))
      return SHELL_PROCESS_EPARSE;
    bool combined = position + 1 < end && input[position] == '&' &&
                    input[position + 1] == '>';
    if (combined) {
      /* Bash supplies no descriptor-prefixed form of `&>` or `&>>`: a
       * preceding numeric or named token is an ordinary shell word.  The
       * shared scanner rejects such a group tail before this point; retain
       * this check so a future scanner change cannot emit a false fd-2 route.
       */
      if (fd != SHELL_PROCESS_FD_NONE)
        return SHELL_PROCESS_EPARSE;
      position++;
    }
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
    uint32_t operand_start =
        (uint32_t)shell_source_skip_inline_continuations(input, end, position);
    uint32_t operand_end = (uint32_t)redirect_end;
    if (operand_start >= operand_end || operand_end > end)
      return SHELL_PROCESS_EPARSE;
    if (!heredoc && fd == SHELL_PROCESS_FD_NAMED && input[operand_start] == '&')
      return SHELL_PROCESS_EPARSE;

    shell_group_io_op_t op = {
        .group_index = group_index,
        .source_start = source_start,
        .source_end = operand_end,
        .operand_start = operand_start,
        .operand_end = operand_end,
        .fd = fd == SHELL_PROCESS_FD_NONE ? (direction == '<' ? 0 : 1) : fd,
        .target_fd = SHELL_PROCESS_FD_NONE,
        .kind = read_write
                    ? SHELL_GROUP_IO_READ_WRITE_FILE
                    : (direction == '<' ? SHELL_GROUP_IO_READ_FILE
                                        : (append ? SHELL_GROUP_IO_APPEND_FILE
                                                  : SHELL_GROUP_IO_WRITE_FILE)),
    };
    if (heredoc)
      op.kind = herestring ? SHELL_GROUP_IO_HERESTRING : SHELL_GROUP_IO_HEREDOC;
    if (!heredoc && shell_source_word_is_process_substitution(
                        input + operand_start, operand_end - operand_start)) {
      if (fd == SHELL_PROCESS_FD_NAMED)
        return SHELL_PROCESS_EPARSE;
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
        uint32_t target_fd = SHELL_PROCESS_FD_NONE;
        if (!parse_group_fd(input, operand_start + 1, operand_end, &target_fd,
                            &target_after) ||
            target_fd == SHELL_PROCESS_FD_NONE ||
            target_fd == SHELL_PROCESS_FD_NAMED || target_after != operand_end)
          return SHELL_PROCESS_EPARSE;
        op.kind = SHELL_GROUP_IO_DUP_FD;
        op.target_fd = target_fd;
      }
    }
    shell_process_status_t status =
        append_group_io_op(result, &op, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
    if (combined) {
      op.fd = 2;
      status = append_group_io_op(result, &op, max_group_io_ops);
      if (status != SHELL_PROCESS_OK)
        return status;
    }
    position = (uint32_t)shell_source_skip_inline_continuations(input, end,
                                                                operand_end);
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
  /* A shared pipeline spelling belongs to both neighbouring groups. Its
   * source has no byte-level ordering between the output and input records,
   * but consumers must be able to apply the relation deterministically. */
  unsigned a_relation_order = (a->kind == SHELL_GROUP_IO_PIPE_OUTPUT ||
                               a->kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR)
                                  ? 0
                              : a->kind == SHELL_GROUP_IO_PIPE_INPUT ? 1
                                                                     : 2;
  unsigned b_relation_order = (b->kind == SHELL_GROUP_IO_PIPE_OUTPUT ||
                               b->kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR)
                                  ? 0
                              : b->kind == SHELL_GROUP_IO_PIPE_INPUT ? 1
                                                                     : 2;
  if (a_relation_order != b_relation_order)
    return a_relation_order < b_relation_order ? -1 : 1;
  /* Combined redirects intentionally share one spelling. Preserve Bash's
   * stdout-then-stderr descriptor order rather than depending on qsort's
   * unspecified order for equal elements. */
  if (a->fd != b->fd)
    return a->fd < b->fd ? -1 : 1;
  if (a->target_fd != b->target_fd)
    return a->target_fd < b->target_fd ? -1 : 1;
  if (a->kind != b->kind)
    return a->kind < b->kind ? -1 : 1;
  if (a->group_index != b->group_index)
    return a->group_index < b->group_index ? -1 : 1;
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
      .fd = SHELL_PROCESS_FD_NONE,
      .target_fd = SHELL_PROCESS_FD_NONE,
      .kind = kind,
  };
  return append_group_io_op(result, &op, max_group_io_ops);
}

static shell_process_status_t scan_group_io(const char *input, uint32_t length,
                                            const shell_group_t *group,
                                            uint16_t group_index,
                                            shell_processed_commands_t *result,
                                            size_t max_group_io_ops) {
  uint32_t before = (uint32_t)shell_source_skip_list_trivia_backward(
      input, length, group->start);
  uint32_t pipe_start = before;
  if (before >= 2 && input[before - 2] == '|' && input[before - 1] == '&') {
    pipe_start = before - 2;
  } else if (before > 0 && input[before - 1] == '|' &&
             (before < 2 || input[before - 2] != '|')) {
    pipe_start = before - 1;
  }
  if (pipe_start != before) {
    shell_process_status_t status =
        append_group_relation(result, group_index, SHELL_GROUP_IO_PIPE_INPUT,
                              pipe_start, before, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
  }

  uint32_t after = (uint32_t)shell_source_skip_inline_continuations(
      input, length, group->end);
  bool found = false;
  shell_process_status_t status = scan_group_redirects(
      input, after, length, group_index, result, max_group_io_ops, &found);
  if (status != SHELL_PROCESS_OK && (found || status != SHELL_PROCESS_EPARSE))
    return status;
  if (status != SHELL_PROCESS_OK)
    after = (uint32_t)shell_source_skip_inline_continuations(input, length,
                                                             group->end);
  else if (found) {
    size_t last = result->group_io_op_count - 1;
    after = result->group_io_ops[last].source_end;
    after =
        (uint32_t)shell_source_skip_inline_continuations(input, length, after);
  }
  if (after < length && input[after] == '|' &&
      (after + 1 == length || input[after + 1] != '|')) {
    bool pipe_stderr = after + 1 < length && input[after + 1] == '&';
    status = append_group_relation(
        result, group_index,
        pipe_stderr ? SHELL_GROUP_IO_PIPE_OUTPUT_STDERR
                    : SHELL_GROUP_IO_PIPE_OUTPUT,
        after, after + (pipe_stderr ? 2u : 1u), max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
    after += pipe_stderr ? 2 : 1;
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

/* Fast ranges stop immediately before a following list connector. If that
 * boundary follows a redirect operand through `\\` + a physical line ending,
 * retain the continuation bytes while reparsing the range: the full tokenizer
 * must see the LF/CRLF to avoid treating the dangling backslash as a command
 * word. Horizontal space alone remains outside the range. */
static size_t
range_length_with_trailing_continuation(const char *command_line,
                                        size_t command_length,
                                        const shell_range_t *range) {
  size_t range_end = (size_t)range->start + range->len;
  if (range_end > command_length)
    return 0;
  /* The fast parser conventionally includes the backslash in its range but
   * leaves the physical line-ending token for the connector scanner. */
  if (range_end < command_length && range_end > range->start &&
      command_line[range_end - 1] == '\\' &&
      (command_line[range_end] == '\n' || command_line[range_end] == '\r')) {
    size_t after = shell_source_skip_inline_continuations(
        command_line, command_length, range_end - 1);
    return after - range->start;
  }
  if (range_end < command_length && range_end >= (size_t)range->start + 2 &&
      command_line[range_end - 2] == '\\' &&
      command_line[range_end - 1] == '\r' && command_line[range_end] == '\n') {
    size_t after = shell_source_skip_inline_continuations(
        command_line, command_length, range_end - 2);
    return after - range->start;
  }
  size_t position = range_end;
  while (position < command_length &&
         (command_line[position] == ' ' || command_line[position] == '\t'))
    position++;
  if (position >= command_length || command_line[position] != '\\' ||
      position + 1 >= command_length ||
      (command_line[position + 1] != '\n' &&
       command_line[position + 1] != '\r'))
    return range->len;
  size_t after = shell_source_skip_inline_continuations(
      command_line, command_length, range_end);
  return after - range->start;
}

static shell_process_status_t
process_fast_range(const char *command_line, size_t command_length,
                   const shell_parse_result_t *parsed, uint32_t range_index,
                   shell_command_info_t *info, bool *produced) {
  *produced = false;
  const shell_range_t *range = &parsed->cmds[range_index];
  size_t range_length = range_length_with_trailing_continuation(
      command_line, command_length, range);
  if (range_length == 0)
    return SHELL_PROCESS_EPARSE;
  shell_command_info_t *one = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_process_command(
      command_line + range->start, range_length, NULL, &one, &count);
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
  /* The strict fast parser removes leading `!` modifiers from ordinary ranges
   * and carries their exact count in range metadata. Preserve compatibility
   * with old caller-supplied fast results that have only the modifier bit. */
  info->pipeline_negation_count = range->pipeline_negation_count;
  if (info->pipeline_negation_count == 0 &&
      (range->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0)
    info->pipeline_negation_count = 1;
  info->pipeline_negated = (info->pipeline_negation_count & UINT32_C(1)) != 0;
  info->has_pipe_input = range->type == SHELL_TYPE_PIPELINE &&
                         !command_is_group_boundary(parsed, range_index, true);
  /* SHELL_FEAT_PIPELINE identifies every member of a pipeline, including its
   * final stage. Output exists only when the following range is connected by
   * a pipeline operator; using the feature here falsely gave terminal stages
   * a stdout pipe output. */
  info->has_pipe_output =
      range_index + 1 < parsed->count &&
      parsed->cmds[range_index + 1].pipe_input_mode != SHELL_PIPE_MODE_NONE &&
      !command_is_group_boundary(parsed, range_index, false);
  if (info->has_pipe_output) {
    info->pipe_output_mode =
        (shell_pipe_mode_t)parsed->cmds[range_index + 1].pipe_input_mode;
  }
  *produced = true;
  return SHELL_PROCESS_OK;
}

/* The structured result intentionally omits argv-less redirect-only stages.
 * Retain command storage only once a real argv record has been produced, so a
 * successful redirect-only source has the same compact empty-array ownership
 * contract as every other zero-count result. */
static shell_process_status_t
append_processed_command(shell_processed_commands_t *result, size_t *capacity,
                         size_t maximum, shell_command_info_t *info) {
  if (result->command_count == *capacity) {
    size_t next_capacity = *capacity == 0 ? 1 : *capacity;
    if (next_capacity < maximum)
      next_capacity = next_capacity > maximum / 2 ? maximum : next_capacity * 2;
    shell_command_info_t *commands =
        realloc(result->commands, next_capacity * sizeof(*result->commands));
    if (!commands)
      return SHELL_PROCESS_ENOMEM;
    result->commands = commands;
    *capacity = next_capacity;
  }
  result->commands[result->command_count++] = *info;
  *info = (shell_command_info_t){0};
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_process_commands(const char *command_line, size_t command_length,
                       const shell_process_limits_t *limits,
                       shell_processed_commands_t *result) {
  if (!result)
    return SHELL_PROCESS_EINPUT;
  memset(result, 0, sizeof(*result));
  /* The validator combines full lexical list grammar with the strict fast
   * semantic ranges needed for group ownership and I/O. */
  shell_parse_result_t parsed = {0};
  shell_process_status_t validation = shell_process_validate_supported_source(
      command_line, command_length, &parsed);
  if (validation != SHELL_PROCESS_OK)
    return validation;
  /* This structured result describes executable simple-command records. A
   * syntactically valid comment-only source has no such record and therefore
   * is not a successful structured-processing result. Keep this distinct
   * from shell_process_validate_supported_source(), whose narrower contract
   * is grammar validation rather than result production. */
  if (parsed.count == 0)
    return SHELL_PROCESS_EPARSE;
  /* A processed result drops structural ranges (heredoc markers, here
   * strings, and document bodies).  Preserve the original fast-range index
   * only while constructing the owned command list, then remap groups below
   * so their intervals are always safe to index into result->commands. */
  uint16_t command_index[SHELL_MAX_SUBCOMMANDS];
  size_t command_capacity = 0;
  for (uint32_t i = 0; i < parsed.count; i++)
    command_index[i] = UINT16_MAX;
  for (uint32_t i = 0; i < parsed.count; i++) {
    if (!range_is_executable(command_line, (uint32_t)command_length, &parsed,
                             i))
      continue;
    bool produced = false;
    shell_command_info_t info = {0};
    shell_process_status_t status = process_fast_range(
        command_line, command_length, &parsed, i, &info, &produced);
    if (status != SHELL_PROCESS_OK) {
      clear_command_info(&info);
      shell_processed_commands_free(result);
      return status;
    }
    if (produced) {
      command_index[i] = (uint16_t)result->command_count;
      status = append_processed_command(result, &command_capacity, parsed.count,
                                        &info);
      if (status != SHELL_PROCESS_OK) {
        clear_command_info(&info);
        shell_processed_commands_free(result);
        return status;
      }
    }
  }
  if (parsed.group_count > 0) {
    result->groups = malloc(parsed.group_count * sizeof(*result->groups));
    if (!result->groups) {
      shell_processed_commands_free(result);
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
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
    if (length > SIZE_MAX - total_output) {
      shell_processed_commands_free(result);
      return SHELL_PROCESS_EOVERFLOW;
    }
    total_output += length;
  }
  if (limits && total_output > limits->max_total_bytes) {
    shell_processed_commands_free(result);
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
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
  shell_processed_word_iterator_t iterator;
  shell_processed_word_iterator_init(&iterator, command);
  shell_token_t word;
  while (shell_processed_word_iterator_next(&iterator, &word)) {
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
  shell_processed_word_iterator_t iterator;
  shell_processed_word_iterator_init(&iterator, command);
  shell_token_t word;
  while (shell_processed_word_iterator_next(&iterator, &word)) {
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
  shell_netstring_buffer_t encoded = {0};
  shell_process_status_t status =
      shell_render_netargv_buffer(info, limits, &encoded);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (memchr(encoded.data, '\0', encoded.length)) {
    shell_netstring_buffer_free(&encoded);
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  char *legacy = realloc(encoded.data, encoded.length + 1);
  if (!legacy) {
    shell_netstring_buffer_free(&encoded);
    return SHELL_PROCESS_ENOMEM;
  }
  legacy[encoded.length] = '\0';
  *netargv = legacy;
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_render_netargv_buffer(const shell_command_info_t *info,
                            const shell_process_limits_t *limits,
                            shell_netstring_buffer_t *buffer) {
  if (!info || !shell_netstring_buffer_is_empty(buffer))
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

  /* Keep a valid zero-length base pointer: write_netargv_unchecked() verifies
   * its final position even for an argv with no records. */
  unsigned char *data = malloc(total == 0 ? 1 : total);
  if (!data)
    return SHELL_PROCESS_ENOMEM;
  char *position = write_netargv_unchecked(info, (char *)data);
  if (position != (char *)data + total) {
    free(data);
    return SHELL_PROCESS_EPARSE;
  }
  buffer->data = data;
  buffer->length = total;
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
    const shell_token_t *word = &info->command_tokens[i];
    if (shell_source_word_has_executable_substitution(word->start,
                                                      word->length))
      return true;
  }
  return false;
}

static shell_process_status_t shell_build_netargv_sequence_impl(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, char **netargv_sequence,
    size_t *netargv_length, size_t *subcommand_count,
    bool *has_shell_features) {
  if (netargv_sequence)
    *netargv_sequence = NULL;
  if (netargv_length)
    *netargv_length = 0;
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
    if (shell_processed_command_is_group_structure(
            commands, count, i, command_line, command_length))
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
  size_t allocation_size = 0;
  status = shell_process_cstring_allocation_size(total, &allocation_size);
  if (status != SHELL_PROCESS_OK)
    goto fail_sequence;
  char *encoded = malloc(allocation_size);
  if (!encoded) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_sequence;
  }
  char *position = encoded;
  for (size_t i = 0; i < count; i++) {
    if (shell_processed_command_is_group_structure(
            commands, count, i, command_line, command_length))
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
  if (netargv_length)
    *netargv_length = total;
  *subcommand_count = rendered_count;
  return SHELL_PROCESS_OK;

fail_sequence:
  shell_commands_free(commands, count);
  *has_shell_features = false;
  return status;
}

shell_process_status_t
shell_build_netargv_sequence(const char *command_line, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netargv_sequence, size_t *subcommand_count,
                             bool *has_shell_features) {
  size_t length = 0;
  shell_process_status_t status = shell_build_netargv_sequence_impl(
      command_line, command_length, limits, netargv_sequence, &length,
      subcommand_count, has_shell_features);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (memchr(*netargv_sequence, '\0', length)) {
    free(*netargv_sequence);
    *netargv_sequence = NULL;
    *subcommand_count = 0;
    *has_shell_features = false;
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_build_netargv_sequence_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count, bool *has_shell_features) {
  if (!shell_netstring_buffer_is_empty(sequence) || !subcommand_count ||
      !has_shell_features)
    return SHELL_PROCESS_EINPUT;
  char *encoded = NULL;
  size_t length = 0;
  shell_process_status_t status = shell_build_netargv_sequence_impl(
      command_line, command_length, limits, &encoded, &length, subcommand_count,
      has_shell_features);
  if (status != SHELL_PROCESS_OK)
    return status;
  sequence->data = (unsigned char *)encoded;
  sequence->length = length;
  return SHELL_PROCESS_OK;
}

static shell_process_status_t shell_build_command_netseq_impl(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, char **command_netseq,
    size_t *command_length_out, size_t *subcommand_count) {
  if (command_netseq)
    *command_netseq = NULL;
  if (command_length_out)
    *command_length_out = 0;
  if (subcommand_count)
    *subcommand_count = 0;
  if (!command_line || !command_netseq || !subcommand_count)
    return SHELL_PROCESS_EINPUT;
  shell_anomaly_stages_t stages = {0};
  shell_process_status_t status =
      shell_anomaly_stages_parse(command_line, command_length, limits, &stages);
  if (status != SHELL_PROCESS_OK)
    return status;
  size_t total = 0;
  size_t rendered_count = 0;
  for (size_t i = 0; i < stages.count; i++) {
    if (shell_processed_command_word_count(&stages.commands[i]) == 0) {
      /* An argv-less redirect-only simple command is a real execution stage.
       * The anomaly sequence represents its missing argv[0] as a canonical
       * empty record. This sequence is not a policy netargv transport. */
      size_t record_length = 0;
      if (shell_netstring_encoded_length(0, &record_length) !=
              SHELL_NETSTRING_OK ||
          total > SIZE_MAX - record_length) {
        status = SHELL_PROCESS_EOVERFLOW;
        goto fail_commands;
      }
      total += record_length;
      rendered_count++;
      continue;
    }
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[i]);
    shell_token_t token;
    if (!shell_processed_word_iterator_next(&iterator, &token)) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_commands;
    }
    size_t length = 0;
    status = shell_measure_decoded_word(token.start, token.length, &length);
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
  size_t allocation_size = 0;
  status = shell_process_cstring_allocation_size(total, &allocation_size);
  if (status != SHELL_PROCESS_OK)
    goto fail_commands;
  char *encoded = malloc(allocation_size);
  if (!encoded) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_commands;
  }
  char *position = encoded;
  for (size_t i = 0; i < stages.count; i++) {
    if (shell_processed_command_word_count(&stages.commands[i]) == 0) {
      size_t prefix_length = 0;
      (void)shell_netstring_write_prefix(position, SIZE_MAX, 0, &prefix_length);
      position += prefix_length;
      *position++ = ',';
      continue;
    }
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[i]);
    shell_token_t token;
    if (!shell_processed_word_iterator_next(&iterator, &token)) {
      free(encoded);
      status = SHELL_PROCESS_EPARSE;
      goto fail_commands;
    }
    size_t length = 0;
    (void)shell_measure_decoded_word(token.start, token.length, &length);
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, length,
                                       &prefix_length);
    position += prefix_length;
    decoded_word_sink_t sink = {
        .destination = position,
        .destination_size = length,
    };
    status = decode_shell_word(token.start, token.length, &sink);
    if (status != SHELL_PROCESS_OK || sink.output_length != length) {
      free(encoded);
      status = status == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE : status;
      goto fail_commands;
    }
    position += sink.output_length;
    *position++ = ',';
  }
  *position = '\0';
  shell_anomaly_stages_free(&stages);
  *command_netseq = encoded;
  if (command_length_out)
    *command_length_out = total;
  *subcommand_count = rendered_count;
  return SHELL_PROCESS_OK;

fail_commands:
  shell_anomaly_stages_free(&stages);
  return status;
}

shell_process_status_t
shell_build_command_netseq(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           char **command_netseq, size_t *subcommand_count) {
  size_t length = 0;
  shell_process_status_t status = shell_build_command_netseq_impl(
      command_line, command_length, limits, command_netseq, &length,
      subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (memchr(*command_netseq, '\0', length)) {
    free(*command_netseq);
    *command_netseq = NULL;
    *subcommand_count = 0;
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_build_command_netseq_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count) {
  if (!shell_netstring_buffer_is_empty(sequence) || !subcommand_count)
    return SHELL_PROCESS_EINPUT;
  char *encoded = NULL;
  size_t length = 0;
  shell_process_status_t status =
      shell_build_command_netseq_impl(command_line, command_length, limits,
                                      &encoded, &length, subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  sequence->data = (unsigned char *)encoded;
  sequence->length = length;
  return SHELL_PROCESS_OK;
}
