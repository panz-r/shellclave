#ifndef SHELL_TOKENIZER_FULL_H
#define SHELL_TOKENIZER_FULL_H

#include <stdbool.h>
#include <stddef.h>

#include "shell_tokenizer.h"

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
 * - Comments, background separators (&), and parenthesized groups
 * - Quoting and escaping
 * - Subshells and command substitution
 * - Variables: $VAR, ${VAR}, $1, $#, $?, $$, $!, $@, $*, $-
 * - Globbing: *, ?, [abc]
 * - Arithmetic expansion: $((expr))
 */

/**
 * Token types - unified enum for all token types
 */
typedef enum {
  // Basic types
  SHELL_TOKEN_COMMAND,         // Command name or path
  SHELL_TOKEN_ARGUMENT,        // Command argument
  SHELL_TOKEN_PIPE,            // Pipe operator
  SHELL_TOKEN_REDIRECT_IN,     // Input redirection
  SHELL_TOKEN_REDIRECT_OUT,    // Output redirection
  SHELL_TOKEN_REDIRECT_ERR,    // Error redirection
  SHELL_TOKEN_REDIRECT_APPEND, // Append redirection
  SHELL_TOKEN_SEMICOLON,       // Command separator
  SHELL_TOKEN_AND,             // Logical AND
  SHELL_TOKEN_BACKGROUND,      // Background command separator (&)
  SHELL_TOKEN_OR,              // Logical OR
  SHELL_TOKEN_SUBSHELL_START,  // Subshell start
  SHELL_TOKEN_SUBSHELL_END,    // Subshell end
  SHELL_TOKEN_GROUP_START,     // Command-group start
  SHELL_TOKEN_GROUP_END,       // Command-group end
  SHELL_TOKEN_END,             // End of tokens

  // Extended types
  SHELL_TOKEN_VARIABLE,        // $VAR, ${VAR}
  SHELL_TOKEN_VARIABLE_QUOTED, // Double-quoted shell word containing an
                               // expansion
  SHELL_TOKEN_SPECIAL_VAR,     // $1, $#, $?, $$, $!, $@, $*, $-
  SHELL_TOKEN_GLOB,            // *.txt, file?
  SHELL_TOKEN_SUBSHELL,        // $(command), `command`
  SHELL_TOKEN_ARITHMETIC,      // $((expr))
  SHELL_TOKEN_PROCESS_SUB,     // <(command), >(command)
  SHELL_TOKEN_HEREDOC,         // << delimiter
  SHELL_TOKEN_HERESTRING,      // <<< here-string

  /* Kept at the end so existing token values remain stable. */
  SHELL_TOKEN_REDIRECT_READ_WRITE,  // <> input/output redirection
  SHELL_TOKEN_REDIRECT_CLOBBER,     // >| forced output redirection
  SHELL_TOKEN_PIPE_NEGATE,          // POSIX ! pipeline modifier
  SHELL_TOKEN_REDIRECT_BOTH,        // Bash &> word
  SHELL_TOKEN_REDIRECT_BOTH_APPEND, // Bash &>> word
  SHELL_TOKEN_ANSI_C_QUOTED,        // Bash $'...'
  SHELL_TOKEN_EXTGLOB,          // Bash ?(...), *(...), +(...), @(...), !(...)
  SHELL_TOKEN_ARRAY_ASSIGNMENT, // Bash indexed/associative assignment
  SHELL_TOKEN_CASE_TERMINATE,   // ;;
  SHELL_TOKEN_CASE_FALLTHROUGH, // ;&
  SHELL_TOKEN_CASE_TEST_NEXT,   // ;;&
  SHELL_TOKEN_TYPE_COUNT
} shell_token_type_t;

/**
 * Token structure
 */
typedef struct {
  shell_token_type_t type; // Token type
  const char *start;       // Pointer to start of token in original string
  size_t length;           // Length of token
  size_t position;         // Position in original string
  bool is_quoted;          // True if token is quoted
  bool is_escaped;         // True if token contains escapes
  size_t group_depth;      // Enclosing command-group nesting depth
  uint8_t group_kinds;     // shell_group_kind_t bitset of enclosing groups
} shell_token_t;

/**
 * Command structure (group of tokens representing one command)
 */
typedef struct {
  shell_token_t *tokens; // Array of tokens
  size_t token_count;    // Number of tokens
  size_t start_pos;      // Start position in original string
  size_t end_pos;        // End position in original string
  size_t group_depth;    // Enclosing command-group nesting depth
  uint8_t group_kinds;   // shell_group_kind_t bitset of enclosing groups
  bool has_variables;    // Contains variables ($VAR, ${VAR}, etc.)
  bool has_globs;        // Contains glob patterns (*, ?, [abc])
  bool has_subshells;    // Contains subshells ($(cmd), `cmd`)
  bool has_arithmetic;   // Contains arithmetic expansion ($((expr))
  bool has_loops;        // Contains loops (while, for, until)
  bool has_conditionals; // Contains conditionals (if/then/elif/else/fi)
  bool has_case;         // Contains case statements
  bool has_groups;       // Contains command groups
  bool ends_group;     // Last command content closes a group (redirections may
                       // follow)
  bool has_background; // Contains background execution
  bool pipeline_negated; // This command belongs to a `! pipeline`
} shell_command_t;

/* Fixed-capacity heredoc declaration retained until the declaration line has
 * ended and the corresponding data body can be skipped. */
typedef struct {
  size_t delimiter_position;
  size_t delimiter_length;
  bool strip_tabs;
} shell_pending_heredoc_t;

/**
 * Tokenizer state
 */
typedef struct {
  const char *input;     // Input string
  size_t position;       // Current position
  size_t length;         // Total length
  bool in_quotes;        // Currently in quotes
  bool in_subshell;      // Currently in subshell
  char quote_char;       // Current quote character
  int paren_depth;       // Parentheses depth
  int brace_depth;       // Brace depth for ${VAR}
  int brace_group_depth; // POSIX brace-group nesting depth
  uint8_t group_kinds;   // shell_group_kind_t bitset of enclosing groups
  bool in_arithmetic;    // Currently in arithmetic expansion
  int arith_depth;       // Arithmetic expansion nesting depth ($((...))

  shell_pending_heredoc_t pending_heredocs[SHELL_MAX_SUBCOMMANDS];
  size_t pending_heredoc_count;
  bool heredoc_error;

  // Track keywords for feature detection
  int if_depth;   // Track if/then/fi nesting
  int loop_depth; // Track while/for/until nesting
  int case_depth; // Track case/esac nesting
} shell_tokenizer_state_t;

/**
 * Initialize a tokenizer over exactly `input_length` source bytes. NULL input
 * is valid only with zero length. Returns false for invalid input or state.
 */
bool shell_tokenizer_init(shell_tokenizer_state_t *state, const char *input,
                          size_t input_length);

/**
 * Get the next lexical token. A heredoc declaration is one
 * SHELL_TOKEN_HEREDOC token spanning `<<` and its delimiter; its body and
 * terminator are opaque data and are skipped after the declaration line.
 * Returns false without advancing state when token is NULL. When token is
 * writable but state is NULL or exhausted, token is cleared and set to
 * SHELL_TOKEN_END.
 */
bool shell_tokenizer_next(shell_tokenizer_state_t *state, shell_token_t *token);

typedef enum {
  SHELL_TOKENIZE_OK = 0,
  SHELL_TOKENIZE_EINPUT,
  SHELL_TOKENIZE_EPARSE,
  SHELL_TOKENIZE_ENOMEM,
  SHELL_TOKENIZE_EOVERFLOW,
} shell_tokenize_status_t;

/**
 * Tokenize exactly `input_length` shell-source bytes into commands. Embedded
 * NUL is rejected. The caller frees the result
 * with shell_commands_free(); token text points into input, which must remain
 * valid until the result is freed. On failure, writable outputs are NULL and 0.
 */
shell_tokenize_status_t shell_tokenize_commands(const char *input,
                                                size_t input_length,
                                                shell_command_t **commands,
                                                size_t *command_count);

/**
 * Free tokenized commands
 */
void shell_commands_free(shell_command_t *commands, size_t command_count);

/**
 * Get human-readable token type name
 */
const char *shell_token_type_name(shell_token_type_t type);

/**
 * Check if command has shell scripting features
 */
bool shell_command_has_shell_features(const shell_command_t *command);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TOKENIZER_FULL_H
