#ifndef SHELL_PROCESSOR_H
#define SHELL_PROCESSOR_H

#include "shell_tokenizer.h"
#include <stdbool.h>
#include <stddef.h>

/**
 * Shell Command Processor - Proper separation of shell logic and command validation
 *
 * Architecture:
 * Shell Layer (this module) → Command Extraction → DFA Validation
 *     ↓
 * Handles: pipes, redirections, command separators, shell syntax
 *     ↓
 * Extracts: clean commands for DFA validation
 *     ↓
 * DFA validates: pure command semantics
 */

/**
 * Shell command structure with separated concerns
 */
typedef struct {
    const char* original_command;  // Full original command text
    const char* clean_command;     // Command without shell syntax (for DFA)
    shell_token_t* shell_tokens;   // Shell operators and redirections
    size_t shell_token_count;      // Number of shell tokens
    shell_token_t* command_tokens; // Command arguments only
    size_t command_token_count;   // Number of command arguments
    bool has_pipe_input;          // Has pipe input (|)
    bool has_pipe_output;         // Has pipe output (|)
    bool has_redirections;        // Has any redirections
    bool has_error_redirection;   // Has error redirection (2>)
} shell_command_info_t;

/**
 * Process shell command with proper separation
 *
 * Extracts clean commands and separates shell logic
 */
bool shell_process_command(
    const char* command_line,
    shell_command_info_t** command_infos,
    size_t* command_count
);

/**
 * Free command info structures
 */
void shell_free_command_infos(
    shell_command_info_t* infos,
    size_t count
);

/**
 * Get clean command for DFA validation
 *
 * Returns command string without shell syntax
 */
const char* shell_get_clean_command(
    shell_command_info_t* info
);

/**
 * Check if command has dangerous shell features
 */
bool shell_has_dangerous_features(
    shell_command_info_t* info
);

/**
 * Process command line and extract DFA inputs
 */
bool shell_extract_dfa_inputs(
    const char* command_line,
    const char*** dfa_inputs,      // Array of clean commands
    size_t* dfa_input_count,     // Number of commands
    bool* has_shell_features     // True if shell features present
);

#endif // SHELL_PROCESSOR_H