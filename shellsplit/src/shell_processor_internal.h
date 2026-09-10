#ifndef SHELL_PROCESSOR_INTERNAL_H
#define SHELL_PROCESSOR_INTERNAL_H

#include "shell_processor.h"

/* Private borrowed-token view used by single-buffer netsequence producers.
 * The commands and token text remain owned by the full tokenizer. */
shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count);

/* Ordered owned view of every supported simple-command stage that executes
 * while evaluating one source command. Nested command and process
 * substitutions precede their enclosing command; siblings retain source
 * order. This deterministic analysis order is intentionally not a runtime
 * scheduling claim for pipeline members. */
typedef struct {
  shell_command_t *commands;
  size_t count;
} shell_anomaly_stages_t;

shell_process_status_t
shell_anomaly_stages_parse(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           shell_anomaly_stages_t *stages);
void shell_anomaly_stages_free(shell_anomaly_stages_t *stages);

/* Validate that complete source is representable by Shellsplit's semantic
 * command model. `parsed` is optional; when supplied it receives the strict
 * fast-parser result used for validation. The lexical-only flat API remains
 * intentionally tolerant and does not call this helper. */
shell_process_status_t
shell_process_validate_supported_source(const char *command_line,
                                        size_t command_length,
                                        shell_parse_result_t *parsed);

/* Return the storage needed for a NUL-terminated legacy adapter result.
 * Canonical buffers themselves are length-delimited, but their C-string
 * wrappers must reject SIZE_MAX rather than letting a trailing `+ 1` wrap. */
shell_process_status_t
shell_process_cstring_allocation_size(size_t content_length,
                                      size_t *allocation_size);

/* Borrowed tokenizer records: token pointers and positions must refer to the
 * same source buffer, including gaps occupied by escaped line continuations.
 * Each returned token is a synthetic span for one complete source word. Its
 * type comes from the first lexical fragment and its quoted/escaped flags are
 * the union of every fragment in the word. */
typedef struct {
  const shell_command_t *command;
  size_t token_index;
  bool consume_redirection_operand;
  size_t redirection_operand_end;
} shell_processed_word_iterator_t;

void shell_processed_word_iterator_init(
    shell_processed_word_iterator_t *iterator, const shell_command_t *command);
bool shell_processed_word_iterator_next(
    shell_processed_word_iterator_t *iterator, shell_token_t *word);
size_t shell_processed_command_word_count(const shell_command_t *command);
bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input);
bool shell_processed_command_has_pipe_output(const shell_command_t *command);
/* Source positions refer to this complete input. A physical list boundary
 * hidden by heredoc tokenization still terminates a group's redirect list. */
bool shell_processed_command_is_group_structure(const shell_command_t *commands,
                                                size_t count, size_t index,
                                                const char *source,
                                                size_t source_length);

#endif
