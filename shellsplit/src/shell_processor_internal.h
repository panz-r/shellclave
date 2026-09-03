#ifndef SHELL_PROCESSOR_INTERNAL_H
#define SHELL_PROCESSOR_INTERNAL_H

#include "shell_processor.h"

/* Private borrowed-token view used by single-buffer netsequence producers.
 * The commands and token text remain owned by the full tokenizer. */
shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count);

/* Validate that complete source is representable by Shellsplit's semantic
 * command model. `parsed` is optional; when supplied it receives the strict
 * fast-parser result used for validation. The lexical-only flat API remains
 * intentionally tolerant and does not call this helper. */
shell_process_status_t
shell_process_validate_supported_source(const char *command_line,
                                        size_t command_length,
                                        shell_parse_result_t *parsed);

size_t shell_processed_command_word_count(const shell_command_t *command);
const shell_token_t *
shell_processed_command_word_at(const shell_command_t *command,
                                size_t word_index);
bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input);
bool shell_processed_command_has_pipe_output(const shell_command_t *command);
bool shell_processed_command_is_group_structure(const shell_command_t *commands,
                                                size_t count, size_t index);

#endif
