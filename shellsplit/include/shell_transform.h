#ifndef SHELL_TRANSFORM_H
#define SHELL_TRANSFORM_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts tokenized shell constructs into strings for DFA consumers.
 */

/**
 * Transformation types
 */
typedef enum {
  TRANSFORM_NONE,       // No transformation needed
  TRANSFORM_VARIABLE,   // Variable → placeholder
  TRANSFORM_GLOB,       // Glob → explicit pattern
  TRANSFORM_SUBSHELL,   // Subshell → temp file operation
  TRANSFORM_PIPE,       // Pipe → temp file chain
  TRANSFORM_REDIRECTION // Redirection → explicit file
} transform_type_t;

/**
 * Transformed token
 */
typedef struct {
  const char *original;    // Owned, NUL-terminated original token text
  const char *transformed; // Owned/aliased NUL-terminated DFA token text
  transform_type_t type;   // Type of transformation
  bool is_shell_construct; // True if this was shell syntax
} transformed_token_t;

/**
 * Transformed command
 */
typedef struct {
  const char *original_command;    // Original command
  const char *transformed_command; // Command for DFA validation
  transformed_token_t *tokens;     // Transformed tokens
  size_t token_count;              // Number of tokens
  bool has_transformations;        // Has any transformations
  bool has_shell_syntax;           // Has shell syntax
} transformed_command_t;

/**
 * Transform shell command to semantic equivalent
 *
 * Converts shell constructs to what they semantically represent
 * On failure, *transformed_cmd is set to NULL when the output pointer is valid.
 */
bool shell_transform_command(shell_command_t *cmd,
                             transformed_command_t **transformed_cmd);

/**
 * Transform entire command line
 *
 * On failure, writable outputs are reset to NULL and zero.
 */
bool shell_transform_command_line(const char *command_line,
                                  transformed_command_t ***transformed_cmds,
                                  size_t *transformed_count);

/**
 * Free one transformed command.
 */
void shell_free_transformed_command(transformed_command_t *command);

/**
 * Free all commands contained in a transformed command pointer array.
 * The caller retains ownership of the outer array and must free it separately.
 */
void shell_free_transformed_commands(transformed_command_t **commands,
                                     size_t count);

/**
 * Get DFA input from transformed command
 */
const char *shell_get_dfa_input(transformed_command_t *cmd);

/**
 * Check if command has shell transformations
 */
bool shell_has_transformations(transformed_command_t *cmd);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TRANSFORM_H
