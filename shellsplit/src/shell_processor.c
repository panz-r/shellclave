#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "alloc.h"
#include "shell_netstring.h"
#include "shell_pipeline_internal.h"
#include "shell_processor_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#define PROCESS_METADATA_WORK(kind) shellsplit_test_metadata_charge(kind)
#else
#define PROCESS_METADATA_WORK(kind) ((void)0)
#endif

static bool is_shell_operator_token(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_PIPE ||
         token->type == SHELL_TOKEN_PIPE_BOTH ||
         token->type == SHELL_TOKEN_PIPE_NEGATE ||
         token->type == SHELL_TOKEN_PIPE_TIME ||
         token->type == SHELL_TOKEN_PIPE_TIME_OPTION ||
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
  *allocation_size = 0;

  if (content_length == SIZE_MAX)
    return SHELL_PROCESS_EOVERFLOW;
  *allocation_size = content_length + 1;
  return SHELL_PROCESS_OK;
}

typedef struct {
  uint32_t value;
  size_t length;
  bool all_digits;
  bool exact_dash;
  bool overflow;
  bool has_nul;
} static_fd_target_t;

/* Required context is the live accumulator passed to the decoder visitor. */
static SHELL_NONNULL(3) bool static_fd_target_byte(unsigned char byte,
                                                   size_t offset,
                                                   void *context) {
  static_fd_target_t *target = context;
  if (byte == '\0') {
    target->has_nul = true;
    return false;
  }

  target->length++;
  if (offset != 0 || byte != '-')
    target->exact_dash = false;
  if (byte < '0' || byte > '9') {
    target->all_digits = false;
    return true;
  }
  if (target->all_digits && !target->overflow) {
    uint32_t digit = (uint32_t)(byte - '0');
    if (target->value > ((uint32_t)INT_MAX - digit) / 10u)
      target->overflow = true;
    else
      target->value = target->value * 10u + digit;
  }
  return true;
}

shell_process_fd_target_t
shell_process_classify_static_fd_target(const char *text, size_t length,
                                        uint32_t *fd) {
  *fd = SHELL_PROCESS_FD_NONE;
  if (length == 0)
    return SHELL_PROCESS_FD_TARGET_INVALID;

  /* Bash decides `>&word` after quote decoding.  Stream the complete word:
   * zero-padded descriptor spellings need not have a bounded source length,
   * while an all-digit spelling that exceeds INT_MAX is a bad descriptor, not
   * Bash's legacy combined-output pathname form. */
  static_fd_target_t target = {
      .all_digits = true,
      .exact_dash = true,
  };
  size_t decoded_length = 0;
  if (shell_visit_decoded_word(text, length, static_fd_target_byte, &target,
                               &decoded_length) != SHELL_PROCESS_OK ||
      target.has_nul || target.length == 0 || target.length != decoded_length)
    return SHELL_PROCESS_FD_TARGET_INVALID;
  if (target.exact_dash)
    return SHELL_PROCESS_FD_TARGET_CLOSE;
  if (!target.all_digits)
    return SHELL_PROCESS_FD_TARGET_PATH;
  if (target.overflow)
    return SHELL_PROCESS_FD_TARGET_INVALID;
  *fd = target.value;
  return SHELL_PROCESS_FD_TARGET_FD;
}

typedef struct {
  bool path_forcing;
  bool invalid;
} legacy_output_literal_scan_t;

static SHELL_NONNULL(1) void legacy_output_note_literal(
    legacy_output_literal_scan_t *scan, unsigned char byte) {
  if (byte == '\0') {
    scan->invalid = true;
    return;
  }
  if (byte != '-' && (byte < '0' || byte > '9'))
    scan->path_forcing = true;
}

static SHELL_NONNULL(2) bool legacy_output_note_ansi_literal(unsigned char byte,
                                                             void *context) {
  legacy_output_note_literal(context, byte);
  return true;
}

/* The caller is positioned at a backtick in a valid source span. This helper
 * checks whether the external spelling has a complete matching delimiter. */
static SHELL_NONNULL(1, 3) bool legacy_output_skip_backtick(const char *text,
                                                            size_t length,
                                                            size_t *position) {
  size_t after = shell_source_skip_quoted_text(text, length, *position, '`');
  if (after <= *position + 1 || after > length || text[after - 1] != '`')
    return false;
  *position = after;
  return true;
}

/* Bash resolves `>&word` after expansion and quote removal.  A literal byte
 * other than a digit or `-` anywhere in that word survives every later
 * expansion, so the result cannot be an FD number or close marker.  Scan
 * source fragments rather than the first raw byte: empty quotes, escaped line
 * continuations, and quoted or escaped literals may precede the proof. */
/* Required, nonempty source word from the redirect-classification boundary. */
static SHELL_NONNULL(1) bool legacy_output_has_path_forcing_literal(
    const char *text, size_t length) {

  legacy_output_literal_scan_t scan = {0};
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool logical_word_start = true;
  size_t bracket_examined = 0;
  for (size_t position = 0; position < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    char current = text[position];
    if (in_single_quote) {
      if (current == '\'') {
        in_single_quote = false;
        position++;
      } else {
        legacy_output_note_literal(&scan, (unsigned char)current);
        position++;
      }
      continue;
    }

    if (in_double_quote) {
      if (current == '"') {
        in_double_quote = false;
        position++;
        continue;
      }
      if (current == '\\') {
        if (position + 1 >= length)
          return false;
        char next = text[position + 1];
        if (next == '$' || next == '`' || next == '"' || next == '\\' ||
            next == '\n' || next == '\r') {
          if (next != '\n' && next != '\r')
            legacy_output_note_literal(&scan, (unsigned char)next);
          position += 2;
          if (next == '\r' && position < length && text[position] == '\n')
            position++;
          continue;
        }
        /* A backslash before an ordinary double-quoted byte is literal. */
        legacy_output_note_literal(&scan, (unsigned char)'\\');
        position++;
        continue;
      }
      if (current == '`') {
        if (!legacy_output_skip_backtick(text, length, &position))
          return false;
        continue;
      }
      if (current == '$') {
        size_t after = 0;
        if (shell_source_dollar_arithmetic_open(text, length, position, NULL)) {
          if (!shell_source_skip_arithmetic_expansion(text, length, position,
                                                      &after))
            return false;
          position = after;
          logical_word_start = false;
          continue;
        }
        size_t open = 0;
        if (shell_source_dollar_parentheses_open(text, length, position,
                                                 &open)) {
          if (!shell_source_find_balanced_parentheses(text, length, open,
                                                      &after))
            return false;
          position = after;
          logical_word_start = false;
          continue;
        }
        if (shell_source_skip_variable_expansion(text, length, position,
                                                 &after)) {
          position = after;
          logical_word_start = false;
          continue;
        }
        /* `$'...'` is not ANSI-C quoting inside double quotes. */
        legacy_output_note_literal(&scan, (unsigned char)'$');
        position++;
        logical_word_start = false;
        continue;
      }
      legacy_output_note_literal(&scan, (unsigned char)current);
      position++;
      logical_word_start = false;
      continue;
    }

    if (current == '\\') {
      size_t continued =
          shell_source_skip_escaped_line_endings(text, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      if (position + 1 >= length)
        return false;
      legacy_output_note_literal(&scan, (unsigned char)text[position + 1]);
      position += 2;
      logical_word_start = false;
      continue;
    }
    if (current == '\'') {
      in_single_quote = true;
      position++;
      logical_word_start = false;
      continue;
    }
    if (current == '"') {
      in_double_quote = true;
      position++;
      logical_word_start = false;
      continue;
    }
    if (current == '$' &&
        shell_source_logical_next_is(text, length, position, '\'', NULL)) {
      if (!shell_source_decode_ansi_c_quote(
              text, length, &position, legacy_output_note_ansi_literal, &scan))
        return false;
      logical_word_start = false;
      continue;
    }
    if (current == '`') {
      if (!legacy_output_skip_backtick(text, length, &position))
        return false;
      logical_word_start = false;
      continue;
    }
    if (current == '$') {
      size_t after = 0;
      if (shell_source_dollar_arithmetic_open(text, length, position, NULL)) {
        if (!shell_source_skip_arithmetic_expansion(text, length, position,
                                                    &after))
          return false;
        position = after;
        logical_word_start = false;
        continue;
      }
      size_t open = 0;
      if (shell_source_dollar_parentheses_open(text, length, position, &open)) {
        if (!shell_source_find_balanced_parentheses(text, length, open, &after))
          return false;
        position = after;
        logical_word_start = false;
        continue;
      }
      if (shell_source_skip_variable_expansion(text, length, position,
                                               &after)) {
        position = after;
        logical_word_start = false;
        continue;
      }
      legacy_output_note_literal(&scan, (unsigned char)'$');
      position++;
      logical_word_start = false;
      continue;
    }
    size_t open = 0;
    if ((current == '<' || current == '>') &&
        shell_source_process_substitution_open(text, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(text, length, open, &after))
        return false;
      position = after;
      logical_word_start = false;
      continue;
    }
    if (current == '~' && logical_word_start) {
      /* Tilde and its optional user name form one expansion prefix. A slash
       * after it is still a stable pathname byte and will be observed below. */
      position++;
      while (position < length && text[position] != '/')
        position++;
      logical_word_start = false;
      continue;
    }
    size_t extglob_after = 0;
    if (shell_source_skip_extglob(text, length, position, &extglob_after)) {
      position = extglob_after;
      logical_word_start = false;
      continue;
    }
    if (current == '*' || current == '?') {
      position++;
      logical_word_start = false;
      continue;
    }
    if (current == '[' && position >= bracket_examined) {
      shell_source_glob_probe_t probe =
          shell_source_probe_glob_bracket(text, length, position);
      bracket_examined = probe.after;
      if (probe.complete) {
        position = probe.after;
        logical_word_start = false;
        continue;
      }
    }
    if (current == '{') {
      shell_source_brace_fragment_t fragment =
          shell_source_scan_brace_fragment(text, length, position);
      if (!fragment.valid || fragment.has_nul)
        return false;
      /* A literal outer brace survives even when an inner pair expands.
       * An unmatched opener is also literal, not a reason to retry its suffix.
       */
      if (!fragment.complete || !fragment.own_expands)
        legacy_output_note_literal(&scan, (unsigned char)'{');
      position = fragment.after;
      logical_word_start = false;
      continue;
    }
    legacy_output_note_literal(&scan, (unsigned char)current);
    position++;
    logical_word_start = false;
  }
  return !scan.invalid && !in_single_quote && !in_double_quote &&
         scan.path_forcing;
}

shell_process_legacy_redirect_target_t
shell_process_classify_legacy_output_target(const char *text, size_t length) {
  if (length == 0)
    return SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED;
  /* Process substitution itself has pathname semantics.  The direction only
   * determines whether that pathname is usable as an I/O stream, not whether
   * the legacy `>&word` spelling denotes combined output. */
  if (shell_source_word_is_process_substitution(text, length))
    return SHELL_PROCESS_LEGACY_REDIRECT_PATH;

  size_t name_start = 0;
  size_t name_end = 0;
  if (shell_source_parse_named_fd_parameter(text, 0, length, &name_start,
                                            &name_end))
    return SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION;

  if (!shell_source_argument_has_dynamic_syntax(text, length)) {
    uint32_t ignored = SHELL_PROCESS_FD_NONE;
    switch (shell_process_classify_static_fd_target(text, length, &ignored)) {
    case SHELL_PROCESS_FD_TARGET_PATH:
      return SHELL_PROCESS_LEGACY_REDIRECT_PATH;
    case SHELL_PROCESS_FD_TARGET_FD:
    case SHELL_PROCESS_FD_TARGET_CLOSE:
      return SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION;
    case SHELL_PROCESS_FD_TARGET_INVALID:
    default:
      /* An empty, NUL-bearing, or out-of-range target cannot be either a
       * concrete pathname or a descriptor operation. Do not let a later
       * consumer reinterpret an execution-time redirect failure as a valid
       * combined-output route. */
      return SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED;
    }
  }

  /* A literal non-descriptor fragment makes every expanded result a pathname,
   * regardless of whether the remaining dynamic syntax is a parameter,
   * arithmetic expression, substitution, glob, or brace expansion. */
  if (legacy_output_has_path_forcing_literal(text, length))
    return SHELL_PROCESS_LEGACY_REDIRECT_PATH;
  return SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED;
}

static bool token_is_legacy_output_redirect(const shell_token_t *token) {
  if (!token || token->type != SHELL_TOKEN_REDIRECT_ERR)
    return false;
  size_t after = 0;
  uint32_t descriptor = 0;
  shell_source_io_number_t number = shell_source_parse_io_number(
      token->start, 0, token->length, &after, &descriptor);
  if (number == SHELL_SOURCE_IO_NUMBER_OVERFLOW || after + 2 != token->length ||
      token->start[after] != '>' || token->start[after + 1] != '&')
    return false;
  return number == SHELL_SOURCE_IO_NUMBER_NONE ||
         (number == SHELL_SOURCE_IO_NUMBER_VALID && descriptor == 1);
}

/* The full tokenizer preserves `>&word` as descriptor syntax. Decide its
 * legacy pathname interpretation before any canonical API can treat an
 * ambiguous command substitution as an ordinary redirect operand. */
static bool validate_legacy_output_redirects(const shell_command_t *commands,
                                             size_t count) {
  if (!commands)
    return count == 0;
  for (size_t i = 0; i < count; i++) {
    const shell_command_t *command = &commands[i];
    for (size_t token_index = 0; token_index < command->token_count;
         token_index++) {
      if (!token_is_legacy_output_redirect(&command->tokens[token_index]))
        continue;
      size_t operand_index = token_index + 1;
      if (operand_index == command->token_count ||
          is_shell_operator_token(&command->tokens[operand_index]))
        return false;
      const shell_token_t *first = &command->tokens[operand_index];
      if (first->position > SIZE_MAX - first->length)
        return false;
      size_t operand_end = first->position + first->length;
      while (++operand_index < command->token_count) {
        const shell_token_t *next = &command->tokens[operand_index];
        if (is_shell_operator_token(next) ||
            next->position > SIZE_MAX - next->length ||
            !shell_tokenizer_token_continues_word(next, operand_end))
          break;
        operand_end = next->position + next->length;
      }
      if (shell_process_classify_legacy_output_target(
              first->start, operand_end - first->position) ==
          SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED)
        return false;
    }
  }
  return true;
}

static bool redirection_consumes_next_token(const shell_token_t *token) {
  return token &&
         shell_source_redirection_consumes_word(token->start, token->length);
}

static SHELL_NONNULL(1) bool tokenized_commands_have_complete_group(
    const shell_command_t *commands, size_t count) {
  for (size_t i = 0; i < count; i++)
    if (commands[i].ends_group)
      return true;
  return false;
}

static SHELL_NONNULL(1, 3) shell_process_status_t
    consume_group_io_budget(const char *command_line, size_t command_length,
                            size_t *remaining, bool prevalidated);

static SHELL_NONNULL(1) shell_process_status_t
    validate_supported_source(const char *command_line, size_t command_length,
                              shell_parse_result_t *parsed) {
  /* Preserve the processor API's input/grammar distinction at its validation
   * boundary. The fast parser deliberately reports every unsupported source
   * byte as a parse failure. */
  if (!shell_source_bytes_valid(command_line, command_length))
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
shell_process_validate_supported_source(const char *command_line,
                                        size_t command_length,
                                        shell_parse_result_t *parsed) {
  shell_source_operation_begin(command_line, command_length);
  shell_process_status_t status =
      validate_supported_source(command_line, command_length, parsed);
  shell_source_operation_end();
  return status;
}

/* prevalidated selects construction from an immutable supported list already
 * checked by this operation's root boundary; false retains the diagnostic
 * semantic adapter. group_io_remaining is an optional operation-wide budget:
 * NULL means unbounded, while a pointed-to zero means exhausted. Borrowed
 * source spans are not output strings; byte limits belong to their renderer. */
static SHELL_NONNULL(1, 4, 5) shell_process_status_t
    shell_processed_commands_parse_impl(const char *command_line,
                                        size_t command_length,
                                        size_t *group_io_remaining,
                                        shell_command_t **commands,
                                        size_t *count, bool allow_initial_time,
                                        bool prevalidated) {
  *commands = NULL;
  *count = 0;

  shell_tokenize_status_t tokenized =
      prevalidated
          ? shell_tokenize_prevalidated_commands(command_line, command_length,
                                                 allow_initial_time, commands,
                                                 count)
          : shell_tokenize_supported_commands(command_line, command_length,
                                              allow_initial_time, false,
                                              commands, count);
  switch (tokenized) {
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
  if (!validate_legacy_output_redirects(*commands, *count)) {
    shell_commands_free(*commands, *count);
    *commands = NULL;
    *count = 0;
    return SHELL_PROCESS_EPARSE;
  }
  if (*count != 0 && group_io_remaining &&
      tokenized_commands_have_complete_group(*commands, *count)) {
    shell_process_status_t status = consume_group_io_budget(
        command_line, command_length, group_io_remaining, prevalidated);
    if (status != SHELL_PROCESS_OK) {
      shell_commands_free(*commands, *count);
      *commands = NULL;
      *count = 0;
      return status;
    }
  }
  return SHELL_PROCESS_OK;
}

void shell_processed_word_iterator_init(
    shell_processed_word_iterator_t *iterator, const shell_command_t *command) {
  *iterator = (shell_processed_word_iterator_t){.command = command};
}

bool shell_processed_word_iterator_next(
    shell_processed_word_iterator_t *iterator, shell_token_t *word) {
  if (!iterator->command)
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
        iterator->redirection_operand_end = token->position + token->length;
        continue;
      }
      iterator->consume_redirection_operand = false;
    }

    shell_token_t merged = *token;
    while (iterator->token_index < command->token_count) {
      const shell_token_t *next = &command->tokens[iterator->token_index];
      if (is_shell_operator_token(next) ||
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

/* A bare Bash timing operation is shell structure without executable argv.
 * Keep it distinct from a redirect-only command: the latter performs real I/O
 * and must remain unpolicyable, while the former can be omitted from policy
 * netargv without losing an execution decision. */
static SHELL_NONNULL(1) bool shell_processed_command_is_empty_timing(
    const shell_command_t *command) {
  if (command->pipeline_time_mode == SHELL_PIPE_TIME_NONE ||
      shell_processed_command_word_count(command) != 0)
    return false;
  for (size_t i = 0; i < command->token_count; i++) {
    switch (command->tokens[i].type) {
    case SHELL_TOKEN_PIPE_TIME:
    case SHELL_TOKEN_PIPE_TIME_OPTION:
    case SHELL_TOKEN_PIPE_NEGATE:
    case SHELL_TOKEN_SEMICOLON:
    case SHELL_TOKEN_BACKGROUND:
      break;
    default:
      return false;
    }
  }
  return true;
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
  size_t group_io_remaining;
  uint32_t depth;
  shell_process_status_t status;
} shell_anomaly_stage_collect_t;

/* source is a supported executable body borrowed from the validated root.
 * collect and its stages remain live throughout this recursive traversal. */
static SHELL_NONNULL(1, 3) shell_process_status_t
    anomaly_collect_source(const char *source, size_t source_length,
                           shell_anomaly_stage_collect_t *collect);

void shell_anomaly_stages_free(shell_anomaly_stages_t *stages) {
  if (!stages)
    return;
  shell_commands_free(stages->commands, stages->count);
  *stages = (shell_anomaly_stages_t){0};
}

static SHELL_NONNULL(1, 2) bool anomaly_append_stage(
    shell_anomaly_stage_collect_t *collect, shell_command_t *command) {
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

/* The expansion iterator supplies a complete delimited substitution in this
 * validated span. Extract its borrowed body; no source correspondence or
 * delimiter validation is repeated here. Backticks have a one-byte opener;
 * other kinds may contain physical continuations before the opening `(`. */
static SHELL_NONNULL(1, 6, 7) void anomaly_substitution_content(
    const char *source, size_t source_length, size_t start, size_t after,
    shell_source_substitution_kind_t kind, const char **content,
    size_t *content_length) {
  size_t body_start =
      kind == SHELL_SOURCE_SUBST_BACKTICK
          ? start + 1
          : shell_source_logical_following(source, source_length, start) + 1;
  *content = source + body_start;
  *content_length = after - body_start - 1;
}

static SHELL_NONNULL(1, 5) bool anomaly_collect_expansions(
    const char *source, size_t source_length, bool allow_process_substitution,
    bool heredoc, shell_anomaly_stage_collect_t *collect) {
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
  size_t start = 0;
  size_t after = 0;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t scan_status;
  while ((scan_status = shell_source_next_executable_substitution(
              source, source_length, &scan, &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    if (!allow_process_substitution &&
        (kind == SHELL_SOURCE_SUBST_PROCESS_INPUT ||
         kind == SHELL_SOURCE_SUBST_PROCESS_OUTPUT))
      continue;
    const char *content = NULL;
    size_t content_length = 0;
    anomaly_substitution_content(source, source_length, start, after, kind,
                                 &content, &content_length);
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
  if (scan_status == SHELL_SOURCE_SCAN_MALFORMED) {
    collect->status = SHELL_PROCESS_EPARSE;
    return false;
  }
  return true;
}

static SHELL_NONNULL(1, 4) bool anomaly_collect_substitutions(
    const char *source, size_t source_length, bool allow_process_substitution,
    shell_anomaly_stage_collect_t *collect) {
  return anomaly_collect_expansions(source, source_length,
                                    allow_process_substitution, false, collect);
}

/* Heredoc roots are data, while parameter patterns establish word quoting. */
static SHELL_NONNULL(1, 3) bool anomaly_collect_heredoc_substitutions(
    const char *source, size_t source_length,
    shell_anomaly_stage_collect_t *collect) {
  return anomaly_collect_expansions(source, source_length, true, true, collect);
}

static SHELL_NONNULL(1, 5) bool anomaly_collect_heredoc_body(
    const char *input, size_t body_start, size_t body_length,
    bool delimiter_quoted, void *context) {
  shell_anomaly_stage_collect_t *collect = context;
  if (delimiter_quoted)
    return true;
  return anomaly_collect_heredoc_substitutions(input + body_start, body_length,
                                               collect);
}

/* token is a heredoc from the current body's borrowed lexical records. */
static SHELL_NONNULL(1, 2) bool anomaly_heredoc_operator_position(
    const shell_token_t *token, size_t *operator_position) {
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

/* command's tokens borrow this immutable source; collect owns live stages. */
static SHELL_NONNULL(1, 3, 4) bool anomaly_collect_command_substitutions(
    const char *source, size_t source_length, const shell_command_t *command,
    shell_anomaly_stage_collect_t *collect) {
  size_t heredoc_after = 0;
  for (size_t i = 0; i < command->token_count; i++) {
    const shell_token_t *token = &command->tokens[i];
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
        /* A visitor can fail because nested collection exhausted resources.
         * Preserve that operational result instead of relabelling it as bad
         * heredoc syntax. No callback failure leaves a successful result. */
        if (collect->status == SHELL_PROCESS_OK)
          collect->status = SHELL_PROCESS_EPARSE;
        return false;
      }
      heredoc_after = after;
      continue;
    }
    if (token->type == SHELL_TOKEN_ARITHMETIC) {
      size_t content_start = 0;
      size_t content_length = 0;
      size_t after = 0;
      if (!shell_source_arithmetic_content(token->start, token->length, 0,
                                           &content_start, &content_length,
                                           &after) ||
          after != token->length ||
          !anomaly_collect_substitutions(token->start + content_start,
                                         content_length, false, collect))
        return false;
      continue;
    }
    if (!anomaly_collect_substitutions(token->start, token->length, true,
                                       collect))
      return false;
  }
  return true;
}

static SHELL_NONNULL(1, 3) shell_process_status_t
    anomaly_collect_source(const char *source, size_t source_length,
                           shell_anomaly_stage_collect_t *collect) {
  PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_ANOMALY_BODIES);
  shell_source_scope_t previous =
      shell_source_scope_begin(source, source_length);
  shell_command_t *commands = NULL;
  size_t count = 0;
  shell_process_status_t status = shell_processed_commands_parse_impl(
      source, source_length,
      collect->limits && collect->limits->max_group_io_ops != 0
          ? &collect->group_io_remaining
          : NULL,
      &commands, &count, true, true);
  if (status != SHELL_PROCESS_OK)
    goto done;
  for (size_t i = 0; i < count; i++) {
    if (!anomaly_collect_command_substitutions(source, source_length,
                                               &commands[i], collect)) {
      status = collect->status == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE
                                                   : collect->status;
      goto done;
    }
    if (!anomaly_append_stage(collect, &commands[i])) {
      status = collect->status == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE
                                                   : collect->status;
      goto done;
    }
  }
  status = SHELL_PROCESS_OK;

done:
  shell_commands_free(commands, count);
  shell_source_scope_end(previous);
  return status;
}

static SHELL_NONNULL(1, 4) shell_process_status_t
    anomaly_stages_parse(const char *command_line, size_t command_length,
                         const shell_process_limits_t *limits,
                         shell_anomaly_stages_t *stages) {
  *stages = (shell_anomaly_stages_t){0};
  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, NULL);
  if (status != SHELL_PROCESS_OK)
    return status;
  shell_anomaly_stage_collect_t collect = {
      .stages = stages,
      .limits = limits,
      .group_io_remaining = limits ? limits->max_group_io_ops : 0,
      .status = SHELL_PROCESS_OK,
  };
  status = anomaly_collect_source(command_line, command_length, &collect);
  if (status != SHELL_PROCESS_OK) {
    shell_anomaly_stages_free(stages);
    return status;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_anomaly_stages_parse(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           shell_anomaly_stages_t *stages) {
  shell_source_operation_begin(command_line, command_length);
  shell_process_status_t status =
      anomaly_stages_parse(command_line, command_length, limits, stages);
  shell_source_operation_end();
  return status;
}

shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count) {
  size_t remaining = limits ? limits->max_group_io_ops : 0;
  return shell_processed_commands_parse_impl(command_line, command_length,
                                             remaining != 0 ? &remaining : NULL,
                                             commands, count, true, false);
}

bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input) {
  if (!command)
    return false;
  /* Compound prefix tokens are intentionally omitted from flattened records;
   * their retained metadata is authoritative even without a list separator. */
  if (has_pipe_input || command->pipeline_time_mode != SHELL_PIPE_TIME_NONE ||
      command->pipeline_negation_count != 0)
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
  sink->error = SHELL_PROCESS_OK;
  bool locale_dependent = false;
  if (shell_source_decode_ansi_c_quote_impl(
          text, length, position, ansi_decode_emit, sink, &locale_dependent) &&
      !locale_dependent)
    return SHELL_PROCESS_OK;
  return sink->error == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE : sink->error;
}

static shell_process_status_t decode_shell_word(const char *text, size_t length,
                                                decoded_word_sink_t *sink) {
  char quote = 0;
  for (size_t i = 0; i < length; i++) {
    char c = text[i];
    if (quote == 0 && c == '$' &&
        shell_source_logical_next_is(text, length, i, '\'', NULL)) {
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
  *decoded_length = 0;

  decoded_word_sink_t sink = {
      .visitor = visitor,
      .visitor_context = context,
  };
  shell_process_status_t status = decode_shell_word(text, length, &sink);
  *decoded_length = sink.output_length;
  return status;
}

bool shell_visit_static_word(const char *text, size_t length,
                             shell_decoded_word_visitor_t visitor,
                             void *context, size_t *decoded_length) {
  *decoded_length = 0;
  if (shell_source_word_has_dynamic_syntax(text, length))
    return false;
  return shell_visit_decoded_word(text, length, visitor, context,
                                  decoded_length) == SHELL_PROCESS_OK;
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
  *written = 0;

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
  *written = 0;
  if ((destination == NULL) && (destination_size != 0))
    return SHELL_PROCESS_EINPUT;

  size_t out = 0;
  char quote = '\0';
  for (size_t i = 0; i < length;) {
    char c = text[i];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(text, length, i, '\'', NULL)) {
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
    if (quote != '\'' && c == '$' &&
        shell_source_dollar_parentheses_open(text, length, i, NULL)) {
      if (shell_source_dollar_arithmetic_open(text, length, i, NULL)) {
        dynamic = shell_source_skip_arithmetic_expansion(text, length, i,
                                                         &dynamic_after);
      } else {
        size_t open = 0;
        dynamic =
            shell_source_dollar_parentheses_open(text, length, i, &open) &&
            shell_source_find_balanced_parentheses(text, length, open,
                                                   &dynamic_after);
      }
    } else if (quote == '\0' && (c == '<' || c == '>')) {
      size_t open = 0;
      dynamic =
          shell_source_process_substitution_open(text, length, i, &open) &&
          shell_source_find_balanced_parentheses(text, length, open,
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
  *written = 0;

  return render_processed_word(text, length, destination, destination_size,
                               written);
}

shell_process_status_t shell_decode_word(const char *text, size_t length,
                                         char **decoded,
                                         size_t *decoded_length) {
  *decoded = NULL;
  *decoded_length = 0;

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
  /* The private destination is sized from the preceding measure. Decode
   * directly rather than invoking the public preflight-and-write API again. */
  decoded_word_sink_t sink = {
      .destination = *decoded,
      .destination_size = *decoded_length,
  };
  status = decode_shell_word(text, length, &sink);
  if (status != SHELL_PROCESS_OK) {
    free(*decoded);
    *decoded = NULL;
    *decoded_length = 0;
    return status;
  }
  (*decoded)[sink.output_length] = '\0';
  return SHELL_PROCESS_OK;
}

static bool process_single_command_internal(shell_command_t *basic_cmd,
                                            shell_command_info_t *info);

static SHELL_NONNULL(1, 2) void own_token_text(const shell_command_t *basic_cmd,
                                               shell_command_info_t *info);

static void clear_command_info(shell_command_info_t *info) {
  free((void *)info->original_command);
  free(info->shell_tokens);
  free(info->command_tokens);
  memset(info, 0, sizeof(*info));
}

/* Parser-produced tokens refer to original_line and lie in the command's
 * [start_pos, end_pos) span. info is fresh required output storage. */
static SHELL_NONNULL(1, 2, 3) bool process_single_command(
    shell_command_t *basic_cmd, const char *original_line,
    shell_command_info_t *info) {
  memset(info, 0, sizeof(shell_command_info_t));

  size_t orig_length = basic_cmd->end_pos - basic_cmd->start_pos;
  info->original_command =
      strndup(original_line + basic_cmd->start_pos, orig_length);
  if (!info->original_command)
    return false;

  bool success = process_single_command_internal(basic_cmd, info);
  if (success)
    own_token_text(basic_cmd, info);
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
  shell_pipeline_time_mode_t pipeline_time_mode = basic_cmd->pipeline_time_mode;
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
      case SHELL_TOKEN_PIPE_TIME:
      case SHELL_TOKEN_PIPE_TIME_OPTION:
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
      /* A redirection operator separates its operand from every earlier
       * command word.  Once its operand ends, the next word necessarily
       * starts a new command token; only the ordinary path below may merge
       * adjacent word fragments. */
      consume_redirection_operand = false;
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
      /* The preceding count/allocation pass used these same immutable tokens.
       * The analyzer cannot correlate the two loops; no runtime recheck is
       * appropriate for their established exact capacities. */
#ifdef __clang_analyzer__
      __attribute__((suppress))
#endif
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
      /* The count pass includes this first word after a redirect operand. */
#ifdef __clang_analyzer__
      __attribute__((suppress))
#endif
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
      /* The count pass includes every non-continuing ordinary word. */
#ifdef __clang_analyzer__
      __attribute__((suppress))
#endif
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
  info->pipeline_time_mode = pipeline_time_mode;
  info->has_redirections = has_redirections;
  info->has_error_redirection = has_error_redirection;
  return true;
}

/* Tokens were constructed from the original source, at or after command_start.
 * owned_command covers every token endpoint measured before allocation.
 * tokens may be NULL only for an empty array; owned_command is required. */
static SHELL_NONNULL(4) void rebase_tokens(shell_token_t *tokens, size_t count,
                                           size_t command_start,
                                           const char *owned_command) {
  for (size_t i = 0; i < count; i++) {
    size_t offset = tokens[i].position - command_start;
    tokens[i].start = owned_command + offset;
    tokens[i].position = offset;
  }
}

static SHELL_NONNULL(1, 2) void own_token_text(const shell_command_t *basic_cmd,
                                               shell_command_info_t *info) {
  rebase_tokens(info->shell_tokens, info->shell_token_count,
                basic_cmd->start_pos, info->original_command);
  rebase_tokens(info->command_tokens, info->command_token_count,
                basic_cmd->start_pos, info->original_command);
}

/* Byte limits describe the flat records returned to the caller.  Structural
 * group syntax is intentionally absent from this array, so it must not affect
 * the accounting here. */
static shell_process_status_t
validate_flat_command_limits(const shell_process_limits_t *limits,
                             const shell_command_info_t *infos,
                             size_t info_count) {
  size_t total_output = 0;
  for (size_t i = 0; i < info_count; i++) {
    size_t length = strlen(infos[i].original_command);
    if (limits && length > limits->max_string_bytes)
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    if (length > SIZE_MAX - total_output)
      return SHELL_PROCESS_EOVERFLOW;
    total_output += length;
  }
  if (limits && total_output > limits->max_total_bytes)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  return SHELL_PROCESS_OK;
}

/* Retain the lexical command array for the caller's selected processing path.
 * Flat byte limits apply after structural syntax has been removed; complete
 * group limits are enforced by the strict structured path. */
static shell_process_status_t
shell_process_command_tokenize(const char *command_line, size_t command_length,
                               shell_command_t **basic_commands,
                               size_t *basic_count, bool allow_initial_time) {
  return shell_processed_commands_parse_impl(command_line, command_length, NULL,
                                             basic_commands, basic_count,
                                             allow_initial_time, false);
}

/* Consume the tokenized command array. Ownership transfers to this helper on
 * every path, so a caller may select structured processing without repeating
 * the lexical pass for an ordinary source. Records satisfy the full tokenizer
 * contract; basic_commands may be NULL only when basic_count is zero. */
static SHELL_NONNULL(1, 5, 6) shell_process_status_t
    shell_process_command_lexical_from_tokens(
        const char *command_line, const shell_process_limits_t *limits,
        shell_command_t *basic_commands, size_t basic_count,
        shell_command_info_t **command_infos, size_t *command_count) {
  *command_infos = NULL;
  *command_count = 0;

  if (basic_count == 0) {
    shell_commands_free(basic_commands, basic_count);
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
    if (i > 0 && infos[i - 1].has_pipe_output) {
      infos[i].has_pipe_input = true;
    }
  }

  shell_process_status_t status =
      validate_flat_command_limits(limits, infos, basic_count);
  if (status != SHELL_PROCESS_OK) {
    shell_command_infos_free(infos, basic_count);
    shell_commands_free(basic_commands, basic_count);
    return status;
  }

  shell_commands_free(basic_commands, basic_count);
  *command_infos = infos;
  *command_count = basic_count;
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

/* Strict parsing already excludes heredoc bodies from executable ranges.
 * Consume that producer guarantee without rescanning the immutable source. */
static SHELL_NONNULL(1, 2) bool range_is_executable(
    const shell_parse_result_t *parsed, const shell_execution_map_t *execution,
    uint32_t range_index) {
  if (execution->pipeline.trailing_group[range_index] != UINT16_MAX)
    return false;
  return !range_is_structural(&parsed->cmds[range_index]) ||
         shell_execution_document(&parsed->cmds[range_index]);
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
                           uint32_t *fd, uint32_t *after, uint32_t *name_start,
                           uint32_t *name_end) {
  if (name_start)
    *name_start = 0;
  if (name_end)
    *name_end = 0;
  size_t position = 0;
  if (shell_source_parse_named_fd_redirect_at_word_start(input, start, end,
                                                         &position)) {
    size_t name_position = 0;
    if (!shell_source_parse_named_fd_at_word_start(input, start, position,
                                                   &name_position) ||
        name_position < start + 3 || name_position > position ||
        input[name_position - 1] != '}')
      return false;
    *fd = SHELL_PROCESS_FD_NAMED;
    *after = (uint32_t)position;
    if (name_start)
      *name_start = start;
    if (name_end)
      *name_end = (uint32_t)name_position;
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

/* A descriptor value stored by Bash's `{name}` allocator is referenced by an
 * ordinary parameter expansion in a duplication redirect.  Keep this helper
 * deliberately narrow: only a complete `$name` or `${name}` word, optionally
 * wrapped in one pair of double quotes, has a statically meaningful identity.
 * General parameter evaluation belongs to a later value-analysis layer. */
static bool parse_group_fd_parameter(const char *input, uint32_t start,
                                     uint32_t end, uint32_t *name_start,
                                     uint32_t *name_end) {
  size_t parsed_start = 0;
  size_t parsed_end = 0;
  if (!shell_source_parse_named_fd_parameter(input, start, end, &parsed_start,
                                             &parsed_end) ||
      parsed_start > UINT32_MAX || parsed_end > UINT32_MAX)
    return false;
  *name_start = (uint32_t)parsed_start;
  *name_end = (uint32_t)parsed_end;
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
    uint32_t fd_name_start = 0;
    uint32_t fd_name_end = 0;
    size_t combined_after = source_start;
    bool combined_append = shell_source_match_logical_punctuation(
        input, end, source_start, "&>>", &combined_after);
    bool combined =
        combined_append || shell_source_match_logical_punctuation(
                               input, end, source_start, "&>", &combined_after);
    if (combined) {
      /* Bash supplies no descriptor-prefixed form of `&>` or `&>>`: a
       * preceding numeric or named token is an ordinary shell word.  The
       * shared scanner rejects such a group tail before this point; retain
       * this check so a future scanner change cannot emit a false fd-2 route.
       */
      position = (uint32_t)combined_after;
    } else if (!parse_group_fd(input, position, end, &fd, &position,
                               &fd_name_start, &fd_name_end)) {
      return SHELL_PROCESS_EPARSE;
    }
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    if (!combined &&
        (position >= end || (input[position] != '<' && input[position] != '>')))
      return *found ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE;
    char direction = combined ? '>' : input[position++];
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    bool append = combined_append || (!combined && direction == '>' &&
                                      position < end && input[position] == '>');
    if (!combined && append)
      position++;
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    bool clobber =
        direction == '>' && !append && position < end && input[position] == '|';
    if (clobber)
      position++;
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    bool read_write =
        direction == '<' && position < end && input[position] == '>';
    if (read_write)
      position++;
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    bool heredoc = direction == '<' && position < end && input[position] == '<';
    if (heredoc)
      position++;
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    bool herestring = heredoc && position < end && input[position] == '<';
    if (herestring)
      position++;
    position =
        (uint32_t)shell_source_skip_escaped_line_endings(input, end, position);
    if (heredoc && !herestring && position < end && input[position] == '-')
      position++;
    uint32_t operand_start =
        (uint32_t)shell_source_skip_inline_continuations(input, end, position);
    uint32_t operand_end = (uint32_t)redirect_end;
    if (operand_start >= operand_end || operand_end > end)
      return SHELL_PROCESS_EPARSE;
    uint32_t legacy_operand_start =
        (uint32_t)shell_source_skip_inline_continuations(input, end,
                                                         operand_start + 1);
    bool legacy_combined =
        !combined && direction == '>' && !append && !read_write &&
        (fd == SHELL_PROCESS_FD_NONE || fd == 1) &&
        operand_start < operand_end && input[operand_start] == '&' &&
        legacy_operand_start < operand_end &&
        shell_process_classify_legacy_output_target(
            input + legacy_operand_start, operand_end - legacy_operand_start) ==
            SHELL_PROCESS_LEGACY_REDIRECT_PATH;
    if (legacy_combined) {
      operand_start = legacy_operand_start;
      combined = true;
    }
    if (!heredoc && (append || read_write) && input[operand_start] == '&')
      return SHELL_PROCESS_EPARSE;

    shell_group_io_op_t op = {
        .group_index = group_index,
        .source_start = source_start,
        .source_end = operand_end,
        .operand_start = operand_start,
        .operand_end = operand_end,
        .fd = fd == SHELL_PROCESS_FD_NONE ? (direction == '<' ? 0 : 1) : fd,
        .target_fd = SHELL_PROCESS_FD_NONE,
        .fd_name_start = fd_name_start,
        .fd_name_end = fd_name_end,
        .target_name_start = 0,
        .target_name_end = 0,
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
    if (!legacy_combined && !heredoc && !append && !read_write &&
        operand_end - operand_start >= 2 && input[operand_start] == '&') {
      /* The duplication operand is one shell word after `&`. Horizontal
       * whitespace and escaped physical line endings are lexical trivia here,
       * just as they are after every other redirect operator. Keep
       * operand_start unchanged so callers retain the complete source span. */
      uint32_t target_start = (uint32_t)shell_source_skip_inline_continuations(
          input, operand_end, (size_t)operand_start + 1);
      if (target_start >= operand_end)
        return SHELL_PROCESS_EPARSE;
      bool close_target =
          input[target_start] == '-' && target_start + 1 == operand_end;
      if (!close_target) {
        uint32_t target_after = 0;
        uint32_t target_fd = SHELL_PROCESS_FD_NONE;
        if (!parse_group_fd(input, target_start, operand_end, &target_fd,
                            &target_after, NULL, NULL) ||
            target_fd == SHELL_PROCESS_FD_NAMED ||
            target_after != operand_end) {
          uint32_t target_name_start = 0;
          uint32_t target_name_end = 0;
          if (parse_group_fd_parameter(input, target_start, operand_end,
                                       &target_name_start, &target_name_end)) {
            op.target_name_start = target_name_start;
            op.target_name_end = target_name_end;
          } else {
            shell_process_fd_target_t target =
                shell_process_classify_static_fd_target(
                    input + target_start, operand_end - target_start,
                    &target_fd);
            if (target == SHELL_PROCESS_FD_TARGET_CLOSE)
              close_target = true;
            else if (target == SHELL_PROCESS_FD_TARGET_FD)
              op.target_fd = target_fd;
            else
              return SHELL_PROCESS_EPARSE;
          }
        } else if (target_fd == SHELL_PROCESS_FD_NONE) {
          return SHELL_PROCESS_EPARSE;
        } else {
          op.target_fd = target_fd;
        }
      }
      op.kind = close_target ? SHELL_GROUP_IO_CLOSE_FD : SHELL_GROUP_IO_DUP_FD;
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
   * unspecified order for equal elements. Pipeline pairs differ in relation
   * order; combined redirects differ in fd. No parser-produced pair can still
   * differ in target, kind, or group after those keys compare equal. */
  if (a->fd != b->fd)
    return a->fd < b->fd ? -1 : 1;
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

static shell_process_status_t
scan_group_io(const char *input, uint32_t length, const shell_group_t *group,
              const shell_pipeline_index_t *pipeline, uint16_t group_index,
              shell_processed_commands_t *result, size_t max_group_io_ops) {
  if (pipeline->group_connector[group_index] == SHELL_TYPE_PIPELINE) {
    shell_process_status_t status = append_group_relation(
        result, group_index, SHELL_GROUP_IO_PIPE_INPUT,
        pipeline->group_connector_start[group_index],
        pipeline->group_connector_end[group_index], max_group_io_ops);
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
  size_t pipe_after = after;
  bool pipe_stderr = shell_source_match_logical_punctuation(
      input, length, after, "|&", &pipe_after);
  bool logical_or =
      shell_source_match_logical_punctuation(input, length, after, "||", NULL);
  if (after < length && input[after] == '|' && !logical_or) {
    if (!pipe_stderr)
      pipe_after = after + 1;
    status =
        append_group_relation(result, group_index,
                              pipe_stderr ? SHELL_GROUP_IO_PIPE_OUTPUT_STDERR
                                          : SHELL_GROUP_IO_PIPE_OUTPUT,
                              after, (uint32_t)pipe_after, max_group_io_ops);
    if (status != SHELL_PROCESS_OK)
      return status;
    after = (uint32_t)pipe_after;
  }
  bool logical_and =
      shell_source_match_logical_punctuation(input, length, after, "&&", NULL);
  if (after < length && input[after] == '&' && !logical_and)
    return append_group_relation(result, group_index, SHELL_GROUP_IO_BACKGROUND,
                                 after, after + 1, max_group_io_ops);
  return SHELL_PROCESS_OK;
}

/* Charge only the immediate body's group metadata, never descendant
 * substitution bodies: the collector visits those separately. A non-NULL
 * budget may already be exhausted. Construction still uses a nonzero cap in
 * that case because scan_group_io interprets zero as unbounded. */
static SHELL_NONNULL(1, 3) shell_process_status_t
    consume_group_io_budget(const char *command_line, size_t command_length,
                            size_t *remaining, bool prevalidated) {
  if (command_length > UINT32_MAX)
    return SHELL_PROCESS_EINPUT;
  shell_parse_result_t parsed = {0};
  shell_error_t error =
      prevalidated
          ? shell_parse_prevalidated(command_line, command_length, NULL,
                                     &parsed)
          : shell_parse_fast(command_line, command_length, NULL, &parsed);
  if (error != SHELL_OK)
    return error == SHELL_ETRUNC ? SHELL_PROCESS_EOUTPUT_LIMIT
                                 : SHELL_PROCESS_EPARSE;
  shell_processed_commands_t result = {0};
  shell_pipeline_index_t pipeline;
  shell_pipeline_index_build(command_line, command_length, &parsed, &pipeline);
  for (uint32_t i = 0; i < parsed.group_count; i++) {
    shell_process_status_t status = scan_group_io(
        command_line, (uint32_t)command_length, &parsed.groups[i], &pipeline,
        (uint16_t)i, &result, *remaining != 0 ? *remaining : 1);
    if (status != SHELL_PROCESS_OK) {
      shell_processed_commands_free(&result);
      return status;
    }
  }
  size_t count = result.group_io_op_count;
  shell_processed_commands_free(&result);
  if (count > *remaining)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  *remaining -= count;
  return SHELL_PROCESS_OK;
}

/* The range names one indexed stage in the unchanged successful strict parse
 * of a supported root. info is an empty destination; produced is required
 * writable storage. Construct that stage without revalidating it as a root:
 * after a pipe, an executable `time` must not become a reserved modifier. */
static SHELL_NONNULL(1, 3, 5, 7, 8) shell_process_status_t
    process_fast_range(const char *command_line, size_t command_length,
                       const shell_parse_result_t *parsed, uint32_t range_index,
                       const shell_execution_map_t *execution,
                       bool retain_empty, shell_command_info_t *info,
                       bool *produced) {
  *produced = false;
  shell_range_t stage_range =
      shell_execution_range(parsed, execution, range_index);
  const shell_range_t *range = &stage_range;
  shell_command_info_t *one = NULL;
  size_t count = 0;
  PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_GROUP_BOUNDARIES);
  bool opens_group =
      execution->pipeline.opening_group[range_index] != UINT16_MAX;
  bool allow_initial_time =
      range_index == 0 || range->type != SHELL_TYPE_PIPELINE || opens_group;
  PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_RANGE_BUILDS);
  shell_command_t *basic_commands = NULL;
  size_t basic_count = 0;
  const char *stage_source = command_line + range->start;
  shell_process_status_t status = shell_processed_commands_parse_impl(
      stage_source, range->len, NULL, &basic_commands, &basic_count,
      allow_initial_time, true);
  if (status != SHELL_PROCESS_OK)
    return status;
  status = shell_process_command_lexical_from_tokens(
      stage_source, NULL, basic_commands, basic_count, &one, &count);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (count != 1) {
    shell_command_infos_free(one, count);
    return SHELL_PROCESS_EPARSE;
  }
  if (one[0].command_token_count == 0 && !retain_empty) {
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
  info->pipeline_time_mode =
      (shell_pipeline_time_mode_t)range->pipeline_time_mode;
  info->has_pipe_input = range->type == SHELL_TYPE_PIPELINE && !opens_group;
  /* SHELL_FEAT_PIPELINE identifies every member of a pipeline, including its
   * final stage. Output exists only when the following range is connected by
   * a pipeline operator; using the feature here falsely gave terminal stages
   * a stdout pipe output. */
  uint32_t cursor = range_index + 1, end = range->start + range->len;
  shell_pipeline_stage_t next;
  info->has_pipe_output = shell_pipeline_next(
      command_line, command_length, parsed, &execution->pipeline,
      shell_pipeline_range_limit(parsed, &execution->pipeline, range_index),
      &cursor, &end, &next);
  if (info->has_pipe_output) {
    info->pipe_output_mode =
        (shell_pipe_mode_t)parsed->cmds[next.range].pipe_input_mode;
  }
  *produced = true;
  return SHELL_PROCESS_OK;
}

/* Allocate only for retained records: the structured result omits argv-less
 * stages, while the legacy flat adapter retains them in this same pass. */
static SHELL_NONNULL(1, 2, 4) shell_process_status_t
    append_processed_command(shell_processed_commands_t *result,
                             size_t *capacity, size_t maximum,
                             shell_command_info_t *info) {
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

/* Consume an unchanged successful strict parse already accepted by the
 * supported-source boundary for these immutable bytes. The caller initializes
 * result; lexical construction supplies word tokens without revalidation.
 * retain_empty selects flat adapter records without rebuilding nonempty ones.
 * Group indexes and byte limits always refer to the selected retained array. */
static SHELL_NONNULL(1, 4, 6) shell_process_status_t
    shell_process_commands_from_parse(const char *command_line,
                                      size_t command_length,
                                      const shell_process_limits_t *limits,
                                      const shell_parse_result_t *parsed,
                                      bool retain_empty,
                                      shell_processed_commands_t *result) {
  /* This structured result describes executable simple-command records. A
   * syntactically valid comment-only source has no such record and therefore
   * is not a successful structured-processing result. Keep this distinct
   * from shell_process_validate_supported_source(), whose narrower contract
   * is grammar validation rather than result production. */
  if (parsed->count == 0)
    return SHELL_PROCESS_EPARSE;
  /* Project every source-range boundary into the retained command array.
   * Prefix counts also preserve the insertion position of empty groups;
   * group remapping never rescans ranges or reconstructs source membership. */
  uint16_t retained_prefix[SHELL_MAX_SUBCOMMANDS + 1];
  shell_execution_map_t execution;
  shell_execution_map_build(command_line, command_length, parsed, &execution);
  size_t command_capacity = 0;
  for (uint32_t i = 0; i < parsed->count; i++) {
    PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_GROUP_REMAP);
    retained_prefix[i] = (uint16_t)result->command_count;
    if (execution.owner[i] != i || !execution.stage[i] ||
        !range_is_executable(parsed, &execution, i))
      continue;
    bool produced = false;
    shell_command_info_t info = {0};
    shell_process_status_t status =
        process_fast_range(command_line, command_length, parsed, i, &execution,
                           retain_empty, &info, &produced);
    if (status != SHELL_PROCESS_OK) {
      clear_command_info(&info);
      shell_processed_commands_free(result);
      return status;
    }
    if (produced) {
      status = append_processed_command(result, &command_capacity,
                                        parsed->count, &info);
      if (status != SHELL_PROCESS_OK) {
        clear_command_info(&info);
        shell_processed_commands_free(result);
        return status;
      }
    }
  }
  retained_prefix[parsed->count] = (uint16_t)result->command_count;
  if (parsed->group_count > 0) {
    result->groups = malloc(parsed->group_count * sizeof(*result->groups));
    if (!result->groups) {
      shell_processed_commands_free(result);
      return SHELL_PROCESS_ENOMEM;
    }
    result->group_count = parsed->group_count;
    for (uint32_t i = 0; i < parsed->group_count; i++) {
      PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_GROUP_REMAP);
      const shell_group_t *source = &parsed->groups[i];
      shell_group_t *group = &result->groups[i];
      *group = *source;
      uint32_t first = source->first_command;
      uint32_t last = first + source->command_count;
      group->first_command = retained_prefix[first];
      group->command_count = retained_prefix[last] - retained_prefix[first];
      shell_process_status_t status = scan_group_io(
          command_line, (uint32_t)command_length, source, &execution.pipeline,
          (uint16_t)i, result, limits ? limits->max_group_io_ops : 0);
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

static SHELL_NONNULL(1, 4) shell_process_status_t
    process_commands(const char *command_line, size_t command_length,
                     const shell_process_limits_t *limits,
                     shell_processed_commands_t *result) {
  memset(result, 0, sizeof(*result));
  shell_parse_result_t parsed = {0};
  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, &parsed);
  if (status != SHELL_PROCESS_OK)
    return status;
  return shell_process_commands_from_parse(command_line, command_length, limits,
                                           &parsed, false, result);
}

shell_process_status_t
shell_process_commands(const char *command_line, size_t command_length,
                       const shell_process_limits_t *limits,
                       shell_processed_commands_t *result) {
  shell_source_operation_begin(command_line, command_length);
  shell_process_status_t status =
      process_commands(command_line, command_length, limits, result);
  shell_source_operation_end();
  return status;
}

/* The flat result has no group-I/O side channel. Preserve its long-standing
 * redirection feature flags on the final enclosed command without putting a
 * group-owned redirect operand back into that command's source or argv. */
static SHELL_NONNULL(1) void flat_apply_group_redirect_flags(
    shell_processed_commands_t *processed) {
  /* Preserve the final argv-bearing member's legacy flags even when the flat
   * array also contains independent argv-less stages. Index that member in a
   * single prefix pass, rather than searching each group's interval. */
  uint16_t last_argv[SHELL_MAX_SUBCOMMANDS + 1];
  last_argv[0] = UINT16_MAX;
  for (size_t i = 0; i < processed->command_count; i++)
    last_argv[i + 1] = processed->commands[i].command_token_count != 0
                           ? (uint16_t)i
                           : last_argv[i];
  for (size_t i = 0; i < processed->group_io_op_count; i++) {
    const shell_group_io_op_t *op = &processed->group_io_ops[i];
    if (op->kind == SHELL_GROUP_IO_PIPE_INPUT ||
        op->kind == SHELL_GROUP_IO_PIPE_OUTPUT ||
        op->kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR ||
        op->kind == SHELL_GROUP_IO_BACKGROUND)
      continue;
    const shell_group_t *group = &processed->groups[op->group_index];
    uint16_t last = last_argv[group->first_command + group->command_count];
    if (last == UINT16_MAX || last < group->first_command)
      continue;
    shell_command_info_t *info = &processed->commands[last];
    info->has_redirections = true;
    info->has_error_redirection = info->has_error_redirection || op->fd == 2;
  }
}

static SHELL_NONNULL(1, 4, 5) shell_process_status_t
    process_command(const char *command_line, size_t command_length,
                    const shell_process_limits_t *limits,
                    shell_command_info_t **command_infos,
                    size_t *command_count) {
  *command_infos = NULL;
  *command_count = 0;

  /* Tokenize once before choosing the processing path. A complete group is a
   * single shell execution endpoint, while the old lexical result retains its
   * trailing redirect words in the final body record. Only that shape needs a
   * strict parse; ordinary and deliberately incomplete diagnostic input finish
   * directly from the lexical array. */
  shell_command_t *basic_commands = NULL;
  size_t basic_count = 0;
  shell_process_status_t lexical = shell_process_command_tokenize(
      command_line, command_length, &basic_commands, &basic_count, true);
  if (lexical != SHELL_PROCESS_OK)
    return lexical;
  if (basic_count == 0 ||
      !tokenized_commands_have_complete_group(basic_commands, basic_count))
    return shell_process_command_lexical_from_tokens(
        command_line, limits, basic_commands, basic_count, command_infos,
        command_count);

  shell_parse_result_t parsed = {0};
  PROCESS_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_STRICT_PARSE);
  if (shell_process_validate_supported_source(command_line, command_length,
                                              &parsed) == SHELL_PROCESS_OK &&
      parsed.group_count != 0) {
    shell_commands_free(basic_commands, basic_count);
    shell_processed_commands_t processed = {0};
    shell_process_status_t status = shell_process_commands_from_parse(
        command_line, command_length, limits, &parsed, true, &processed);
    if (status != SHELL_PROCESS_OK)
      return status;
    flat_apply_group_redirect_flags(&processed);
    *command_infos = processed.commands;
    *command_count = processed.command_count;
    processed.commands = NULL;
    processed.command_count = 0;
    shell_processed_commands_free(&processed);
    return SHELL_PROCESS_OK;
  }

  return shell_process_command_lexical_from_tokens(
      command_line, limits, basic_commands, basic_count, command_infos,
      command_count);
}

shell_process_status_t
shell_process_command(const char *command_line, size_t command_length,
                      const shell_process_limits_t *limits,
                      shell_command_info_t **command_infos,
                      size_t *command_count) {
  shell_source_operation_begin(command_line, command_length);
  shell_process_status_t status = process_command(
      command_line, command_length, limits, command_infos, command_count);
  shell_source_operation_end();
  return status;
}

void shell_command_infos_free(shell_command_info_t *infos, size_t count) {
  if (!infos)
    return;

  for (size_t i = 0; i < count; i++) {
    clear_command_info(&infos[i]);
  }
  free(infos);
}

/* The immutable token has passed measurement; destination has that measured
 * capacity. Writing cannot fail or require allocation under these guarantees.
 */
static SHELL_NONNULL(1, 2) char *render_word_into(const shell_token_t *token,
                                                  char *destination) {
  size_t written = 0;
  (void)shell_write_processed_word(token->start, token->length, destination,
                                   SIZE_MAX, &written);
  return destination + written;
}

shell_process_status_t shell_measure_netargv(const shell_command_info_t *info,
                                             size_t *total) {
  *total = 0;
  for (size_t i = 0; i < info->command_token_count; i++) {
    const shell_token_t *token = &info->command_tokens[i];
    size_t length = 0;
    shell_process_status_t status =
        shell_measure_processed_word(token->start, token->length, &length);
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

static SHELL_NONNULL(1, 2) char *write_netargv_unchecked(
    const shell_command_info_t *info, char *position) {
  for (size_t i = 0; i < info->command_token_count; i++) {
    const shell_token_t *token = &info->command_tokens[i];
    size_t length = 0;
    (void)shell_measure_processed_word(token->start, token->length, &length);
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
  *written = 0;

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
    shell_process_status_t status =
        shell_measure_processed_word(word.start, word.length, &length);
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

static SHELL_NONNULL(1, 2) char *write_basic_netargv(
    const shell_command_t *command, char *position) {
  shell_processed_word_iterator_t iterator;
  shell_processed_word_iterator_init(&iterator, command);
  shell_token_t word;
  while (shell_processed_word_iterator_next(&iterator, &word)) {
    size_t length = 0;
    (void)shell_measure_processed_word(word.start, word.length, &length);
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
shell_render_netargv_buffer(const shell_command_info_t *info,
                            const shell_process_limits_t *limits,
                            shell_netstring_buffer_t *buffer) {
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
  if (info->pipeline_time_mode != SHELL_PIPE_TIME_NONE ||
      info->pipeline_negation_count != 0 || info->shell_token_count != 0 ||
      info->has_pipe_input || info->has_pipe_output || info->has_redirections ||
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

static SHELL_NONNULL(1, 4, 6, 7) shell_process_status_t
    shell_build_netargv_sequence_body(const char *command_line,
                                      size_t command_length,
                                      const shell_process_limits_t *limits,
                                      char **netargv_sequence,
                                      size_t *netargv_length,
                                      size_t *subcommand_count,
                                      bool *has_shell_features) {
  *netargv_sequence = NULL;
  if (netargv_length)
    *netargv_length = 0;
  *subcommand_count = 0;
  *has_shell_features = false;

  shell_process_status_t status = shell_process_validate_supported_source(
      command_line, command_length, NULL);
  if (status != SHELL_PROCESS_OK)
    return status;

  shell_command_t *commands = NULL;
  size_t count = 0;
  size_t remaining = limits ? limits->max_group_io_ops : 0;
  status = shell_processed_commands_parse_impl(
      command_line, command_length, remaining != 0 ? &remaining : NULL,
      &commands, &count, true, true);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t total = 0;
  size_t rendered_count = 0;
  for (size_t i = 0; i < count; i++) {
    if (shell_processed_command_word_count(&commands[i]) == 0) {
      if (shell_processed_command_is_empty_timing(&commands[i])) {
        *has_shell_features = true;
        continue;
      }
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
    if (shell_processed_command_is_empty_timing(&commands[i]))
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

static SHELL_NONNULL(1, 4, 6, 7) shell_process_status_t
    shell_build_netargv_sequence_impl(const char *command_line,
                                      size_t command_length,
                                      const shell_process_limits_t *limits,
                                      char **netargv_sequence,
                                      size_t *netargv_length,
                                      size_t *subcommand_count,
                                      bool *has_shell_features) {
  shell_source_operation_begin(command_line, command_length);
  shell_process_status_t status = shell_build_netargv_sequence_body(
      command_line, command_length, limits, netargv_sequence, netargv_length,
      subcommand_count, has_shell_features);
  shell_source_operation_end();
  return status;
}

shell_process_status_t shell_build_netargv_sequence_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count, bool *has_shell_features) {
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
  *command_netseq = NULL;
  if (command_length_out)
    *command_length_out = 0;
  *subcommand_count = 0;

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

shell_process_status_t shell_build_command_netseq_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count) {
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
