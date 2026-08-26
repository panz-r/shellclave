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
  SHELL_TRANSFORM_NONE,       // No transformation needed
  SHELL_TRANSFORM_VARIABLE,   // Variable → placeholder
  SHELL_TRANSFORM_GLOB,       // Glob → explicit pattern
  SHELL_TRANSFORM_SUBSHELL,   // Subshell → temp file operation
  SHELL_TRANSFORM_PIPE,       // Pipe → temp file chain
  SHELL_TRANSFORM_REDIRECTION // Redirection → explicit file
} shell_transform_type_t;

/**
 * Transformed token
 */
typedef struct {
  const char *original; // Owned, NUL-terminated original token text
  const char
      *transformed; // Owned/aliased NUL-terminated transformed token text
  shell_transform_type_t type; // Type of transformation
  bool is_shell_construct;     // True if this was shell syntax
} shell_transformed_token_t;

/**
 * Transformed command
 */
typedef struct {
  const char *original_command; // Original command
  const char *display_text;     // Lossy diagnostic text after token transforms
  shell_transformed_token_t *tokens; // Transformed tokens
  size_t token_count;                // Number of tokens
  bool has_transformations;          // Has any transformations
  bool has_shell_syntax;             // Has shell syntax
} shell_transformed_command_t;

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
shell_transform_command(const shell_command_t *cmd,
                        const shell_transform_limits_t *limits,
                        shell_transformed_command_t **transformed_cmd);

/**
 * Transform exactly `command_length` shell-source bytes.
 *
 * On failure, writable outputs are reset to NULL and zero.
 */
shell_transform_status_t
shell_transform_command_line(const char *command_line, size_t command_length,
                             const shell_transform_limits_t *limits,
                             shell_transformed_command_t ***transformed_cmds,
                             size_t *transformed_count);

/**
 * Free one transformed command.
 */
void shell_transformed_command_free(shell_transformed_command_t *command);

/** Free the complete list returned by shell_transform_command_line(), including
 * every command and the outer pointer array. Safe to call with NULL. */
void shell_transformed_command_list_free(shell_transformed_command_t **commands,
                                         size_t count);

/**
 * Get lossy diagnostic text after token-level transforms. This is not shell
 * source or canonical netargv; programmatic consumers must use Shellsplit's
 * canonical sequence builders instead.
 */
const char *shell_transformed_command_get_display_text(
    const shell_transformed_command_t *cmd);

/**
 * Return true when the transformed command has any shell-derived
 * normalizations.
 */
bool shell_transformed_command_has_transformations(
    const shell_transformed_command_t *cmd);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TRANSFORM_H
