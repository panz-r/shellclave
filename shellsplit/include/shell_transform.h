#ifndef SHELL_TRANSFORM_H
#define SHELL_TRANSFORM_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>

/**
 * Shell Command Transformer - Converts shell constructs to semantic equivalents
 *
 * Philosophy: "Transform shell syntax into what it semantically means"
 *
 * Instead of making DFA understand shell syntax, transform:
 * - Variables → placeholder values
 * - Globbing → explicit file patterns
 * - Subshells → temporary file operations
 * - Pipes → temporary file chains
 *
 * This allows DFA to focus on command semantics, not shell syntax
 */

/**
 * Transformation types
 */
typedef enum {
    TRANSFORM_NONE,           // No transformation needed
    TRANSFORM_VARIABLE,       // Variable → placeholder
    TRANSFORM_GLOB,           // Glob → explicit pattern
    TRANSFORM_SUBSHELL,       // Subshell → temp file operation
    TRANSFORM_PIPE,           // Pipe → temp file chain
    TRANSFORM_REDIRECTION     // Redirection → explicit file
} transform_type_t;

/**
 * Transformed token
 */
typedef struct {
    const char* original;      // Original token text
    const char* transformed;   // Transformed text for DFA
    transform_type_t type;      // Type of transformation
    bool is_shell_construct;   // True if this was shell syntax
} transformed_token_t;

/**
 * Transformed command
 */
typedef struct {
    const char* original_command;      // Original command
    const char* transformed_command;   // Command for DFA validation
    transformed_token_t* tokens;       // Transformed tokens
    size_t token_count;               // Number of tokens
    bool has_transformations;         // Has any transformations
    bool has_shell_syntax;            // Has shell syntax
} transformed_command_t;

/**
 * Transform shell command to semantic equivalent
 *
 * Converts shell constructs to what they semantically represent
 */
bool shell_transform_command(
    shell_command_t* cmd,
    transformed_command_t** transformed_cmd
);

/**
 * Transform entire command line
 */
bool shell_transform_command_line(
    const char* command_line,
    transformed_command_t*** transformed_cmds,
    size_t* transformed_count
);

/**
 * Free transformed commands
 */
void shell_free_transformed_commands(
    transformed_command_t** commands,
    size_t count
);

/**
 * Get DFA input from transformed command
 */
const char* shell_get_dfa_input(
    transformed_command_t* cmd
);

/**
 * Check if command has shell transformations
 */
bool shell_has_transformations(
    transformed_command_t* cmd
);

#endif // SHELL_TRANSFORM_H