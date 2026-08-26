#ifndef SHELL_PROCESSOR_INTERNAL_H
#define SHELL_PROCESSOR_INTERNAL_H

#include "shell_processor.h"

/* Private borrowed-token view used by single-buffer netsequence producers.
 * The commands and token text remain owned by the full tokenizer. */
shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count);

size_t shell_processed_command_word_count(const shell_command_t *command);
const shell_token_t *
shell_processed_command_word_at(const shell_command_t *command,
                                size_t word_index);
bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input);
bool shell_processed_command_has_pipe_output(const shell_command_t *command);

#endif
