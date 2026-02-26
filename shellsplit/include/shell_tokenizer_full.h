#ifndef SHELL_TOKENIZER_FULL_H
#define SHELL_TOKENIZER_FULL_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Shell Command Tokenizer
 *
 * Tokenizes shell command lines into individual commands, handling:
 * - Pipes (|)
 * - Redirections (>, <, >>, 2>, etc.)
 * - Command separators (&&, ||, ;)
 * - Quoting and escaping
 * - Subshells and command substitution
 * - Variables: $VAR, ${VAR}, $1, $#, $?, $$
 * - Globbing: *, ?, [abc]
 * - Arithmetic expansion: $((expr))
 */

/**
 * Token types - unified enum for all token types
 */
typedef enum {
    // Basic types
    TOKEN_COMMAND,      // Command name or path
    TOKEN_ARGUMENT,     // Command argument
    TOKEN_PIPE,         // Pipe operator
    TOKEN_REDIRECT_IN,  // Input redirection
    TOKEN_REDIRECT_OUT, // Output redirection
    TOKEN_REDIRECT_ERR, // Error redirection
    TOKEN_REDIRECT_APPEND, // Append redirection
    TOKEN_SEMICOLON,    // Command separator
    TOKEN_AND,          // Logical AND
    TOKEN_OR,           // Logical OR
    TOKEN_SUBSHELL_START, // Subshell start
    TOKEN_SUBSHELL_END,   // Subshell end
    TOKEN_END,           // End of tokens

    // Extended types
    TOKEN_VARIABLE,        // $VAR, ${VAR}
    TOKEN_VARIABLE_QUOTED, // "$VAR", '$VAR'
    TOKEN_SPECIAL_VAR,     // $1, $#, $?, $$
    TOKEN_GLOB,            // *.txt, file?
    TOKEN_SUBSHELL,        // $(command), `command`
    TOKEN_ARITHMETIC,      // $((expr))
    TOKEN_PROCESS_SUB,     // <(command), >(command)
    TOKEN_HEREDOC,         // << delimiter
    TOKEN_HERESTRING       // <<< here-string
} token_type_t;

/**
 * Token structure
 */
typedef struct {
    token_type_t type;      // Token type
    const char* start;     // Pointer to start of token in original string
    size_t length;         // Length of token
    size_t position;       // Position in original string
    bool is_quoted;        // True if token is quoted
    bool is_escaped;       // True if token contains escapes
} shell_token_t;

/**
 * Command structure (group of tokens representing one command)
 */
typedef struct {
    shell_token_t* tokens;  // Array of tokens
    size_t token_count;    // Number of tokens
    size_t start_pos;      // Start position in original string
    size_t end_pos;        // End position in original string
    bool has_variables;     // Contains variables ($VAR, ${VAR}, etc.)
    bool has_globs;        // Contains glob patterns (*, ?, [abc])
    bool has_subshells;    // Contains subshells ($(cmd), `cmd`)
    bool has_arithmetic;   // Contains arithmetic expansion ($((expr))
} shell_command_t;

/**
 * Tokenizer state
 */
typedef struct {
    const char* input;       // Input string
    size_t position;         // Current position
    size_t length;           // Total length
    bool in_quotes;          // Currently in quotes
    bool in_subshell;        // Currently in subshell
    char quote_char;         // Current quote character
    int paren_depth;        // Parentheses depth
    int brace_depth;        // Brace depth for ${VAR}
    bool in_arithmetic;      // Currently in arithmetic expansion
    int arith_depth;        // Arithmetic expansion nesting depth ($((...))
} shell_tokenizer_state_t;

/**
 * Initialize tokenizer
 */
void shell_tokenizer_init(shell_tokenizer_state_t* state, const char* input);

/**
 * Get next token
 */
bool shell_tokenizer_next(shell_tokenizer_state_t* state, shell_token_t* token);

/**
 * Tokenize entire command line into commands
 */
bool shell_tokenize_commands(const char* input, shell_command_t** commands, size_t* command_count);

/**
 * Free tokenized commands
 */
void shell_free_commands(shell_command_t* commands, size_t command_count);

/**
 * Get human-readable token type name
 */
const char* shell_token_type_name(token_type_t type);

/**
 * Check if command has shell scripting features
 */
bool shell_has_features(shell_command_t* command);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TOKENIZER_FULL_H
