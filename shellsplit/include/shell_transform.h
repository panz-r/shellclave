#ifndef SHELL_TRANSFORM_H
#define SHELL_TRANSFORM_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts tokenized shell constructs into transformed strings for downstream
 * use.
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
  const char *original; // Owned, NUL-terminated original token text
  const char
      *transformed;      // Owned/aliased NUL-terminated transformed token text
  transform_type_t type; // Type of transformation
  bool is_shell_construct; // True if this was shell syntax
} transformed_token_t;

/**
 * Transformed command
 */
typedef struct {
  const char *original_command;    // Original command
  const char *transformed_command; // Command text after token-level transforms
  transformed_token_t *tokens;     // Transformed tokens
  size_t token_count;              // Number of tokens
  bool has_transformations;        // Has any transformations
  bool has_shell_syntax;           // Has shell syntax
} transformed_command_t;

typedef enum {
  SHELL_TRANSFORM_OK = 0,
  SHELL_TRANSFORM_EINPUT,
  SHELL_TRANSFORM_EPARSE,
  SHELL_TRANSFORM_ENOMEM,
  SHELL_TRANSFORM_EOVERFLOW,
  SHELL_TRANSFORM_EOUTPUT_LIMIT
} shell_transform_status_t;

/* Limits apply to each returned string and to the aggregate output of one
 * call.  A NULL limits pointer means unbounded output.  Sizes exclude the
 * terminating NUL. */
typedef struct {
  size_t max_string_bytes;
  size_t max_total_bytes;
} shell_transform_limits_t;

/**
 * Transform shell command to semantic equivalent
 *
 * Converts shell constructs to what they semantically represent
 * On failure, *transformed_cmd is set to NULL when the output pointer is valid.
 */
shell_transform_status_t
shell_transform_command(shell_command_t *cmd,
                        const shell_transform_limits_t *limits,
                        transformed_command_t **transformed_cmd);

/**
 * Transform entire command line
 *
 * On failure, writable outputs are reset to NULL and zero.
 */
shell_transform_status_t shell_transform_command_line(
    const char *command_line, const shell_transform_limits_t *limits,
    transformed_command_t ***transformed_cmds, size_t *transformed_count);

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
 * Get transformed command text for downstream processing.
 */
const char *shell_get_dfa_input(transformed_command_t *cmd);

/**
 * Return true when the transformed command has any shell-derived
 * normalizations.
 */
bool shell_has_transformations(transformed_command_t *cmd);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TRANSFORM_H
