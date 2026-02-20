#ifndef SHELL_TOKENIZER_EXT_H
#define SHELL_TOKENIZER_EXT_H

#include "shell_tokenizer.h"

/**
 * Extended Shell Tokenizer - Adds shell scripting syntax support
 *
 * Supports:
 * - Variables: $VAR, ${VAR}, $1, $#, $?, $$
 * - Globbing: *, ?, [abc]
 * - Subshells: $(command), `command`
 *
 * Note: All token types are now unified in shell_tokenizer.h (token_type_t).
 * This header provides extended tokenizer functionality using the unified enum.
 */

/**
 * Extended command structure
 */
typedef struct {
    token_type_t type;  // Extended token type
    const char* start;           // Pointer to start of token
    size_t length;               // Length of token
    size_t position;             // Position in original string
    bool is_quoted;              // True if token is quoted
    bool is_escaped;             // True if token contains escapes
} extended_shell_token_t;

/**
 * Extended command structure
 */
typedef struct {
    extended_shell_token_t* tokens;
    size_t token_count;
    size_t start_pos;
    size_t end_pos;
    bool has_variables;          // Contains variables
    bool has_globs;              // Contains glob patterns
    bool has_subshells;          // Contains subshells
    bool has_arithmetic;         // Contains arithmetic expansion
} extended_shell_command_t;

/**
 * Extended tokenizer state
 */
typedef struct {
    const char* input;
    size_t position;
    size_t length;
    bool in_quotes;
    bool in_subshell;
    char quote_char;
    int paren_depth;
    int brace_depth;             // For ${VAR} tracking
    bool in_arithmetic;         // For $((expr)) tracking
} extended_shell_tokenizer_state_t;

/**
 * Initialize extended tokenizer
 */
void extended_shell_tokenizer_init(
    extended_shell_tokenizer_state_t* state,
    const char* input
);

/**
 * Get next extended token
 */
bool extended_shell_tokenizer_next(
    extended_shell_tokenizer_state_t* state,
    extended_shell_token_t* token
);

/**
 * Tokenize with extended syntax support
 */
bool extended_shell_tokenize_commands(
    const char* input,
    extended_shell_command_t** commands,
    size_t* command_count
);

/**
 * Free extended commands
 */
void extended_shell_free_commands(
    extended_shell_command_t* commands,
    size_t command_count
);

/**
 * Get human-readable extended token type name
 */
const char* extended_shell_token_type_name(
    token_type_t type
);

/**
 * Check if command has shell scripting features
 */
bool extended_shell_has_features(
    extended_shell_command_t* command
);

#endif // SHELL_TOKENIZER_EXT_H