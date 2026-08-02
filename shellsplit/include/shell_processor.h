#ifndef SHELL_PROCESSOR_H
#define SHELL_PROCESSOR_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extracts command-stage text and shell syntax metadata for DFA consumers.
 */

/**
 * Shell command structure with separated concerns
 */
typedef struct {
  const char *original_command; // Owned full command-stage text
  const char *clean_command;    // Owned command without shell syntax (for DFA)
  // Token text points into original_command, and positions are relative to it.
  shell_token_t *shell_tokens;   // Shell operators and redirections
  size_t shell_token_count;      // Number of shell tokens
  shell_token_t *command_tokens; // Command arguments only
  size_t command_token_count;    // Number of command arguments
  bool has_pipe_input;           // Has pipe input (|)
  bool has_pipe_output;          // Has pipe output (|)
  bool has_redirections;         // Has any redirections
  bool has_error_redirection;    // Has error redirection (2>)
} shell_command_info_t;

/**
 * Process shell command with proper separation
 *
 * Extracts clean commands and separates shell logic. On success, returned
 * command metadata owns all text it refers to and remains valid independently
 * of command_line. On failure, writable outputs are set to NULL and zero.
 */
bool shell_process_command(const char *command_line,
                           shell_command_info_t **command_infos,
                           size_t *command_count);

/**
 * Free command info structures
 */
void shell_free_command_infos(shell_command_info_t *infos, size_t count);

/**
 * Get clean command for DFA validation
 *
 * Returns command string without shell syntax
 */
const char *shell_get_clean_command(shell_command_info_t *info);

/**
 * Check if a command uses shell operators, redirections, or execution-bearing
 * substitutions that require shell-aware handling.
 */
bool shell_has_dangerous_features(shell_command_info_t *info);

/**
 * Process command line and extract DFA inputs. The caller owns each returned
 * string and the containing array. On failure, writable outputs are set to
 * NULL, zero, and false.
 */
bool shell_extract_dfa_inputs(
    const char *command_line,
    const char ***dfa_inputs, // Array of clean commands
    size_t *dfa_input_count,  // Number of commands
    bool *has_shell_features  // True if shell features present
);

#ifdef __cplusplus
}
#endif

#endif // SHELL_PROCESSOR_H
