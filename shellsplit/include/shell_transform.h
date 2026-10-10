#ifndef SHELL_TRANSFORM_H
#define SHELL_TRANSFORM_H

#include "shell_contract.h"

#include "shell_tokenizer_full.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Produces diagnostic strings from tokenized shell constructs. Placeholders
 * describe expansions; they are not executable or semantically equivalent shell
 * source. Use canonical sequence builders for programmatic command transport.
 */

/**
 * Transformation types
 */
typedef enum {
  SHELL_TRANSFORM_NONE,     // Diagnostic spelling is retained
  SHELL_TRANSFORM_VARIABLE, // Variable/arithmetic diagnostic placeholder
  SHELL_TRANSFORM_GLOB,     // Glob diagnostic placeholder
  SHELL_TRANSFORM_SUBSHELL, // Command/process-substitution placeholder
  /* Reserved legacy values. Operators are marked with is_shell_construct but
   * are not rewritten and therefore never receive these transform types. */
  SHELL_TRANSFORM_PIPE,
  SHELL_TRANSFORM_REDIRECTION
} shell_transform_type_t;

/**
 * Transformed token
 */
typedef struct {
  const char *original; // Owned, NUL-terminated original token text
  const char
      *transformed; // Owned/aliased NUL-terminated transformed token text
  shell_transform_type_t type; // Type of transformation
  bool is_shell_construct;     // True if this token has shell semantics
} shell_transformed_token_t;

/**
 * Transformed command
 */
typedef struct {
  const char *original_command;      // Owned original command text
  const char *display_text;          // Owned lossy diagnostic text
  shell_transformed_token_t *tokens; // Transformed tokens
  size_t token_count;                // Number of tokens
  bool has_transformations;          // Has token-level placeholder replacements
  /* Has semantic shell syntax, including enclosing groups, pipeline prefixes,
   * and executable substitutions embedded in a word. This need not imply that
   * diagnostic display text changed. */
  bool has_shell_syntax;
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
 * Transform one nonempty tokenized command into diagnostic text.
 *
 * Caller preconditions: cmd has token_count > 0 and valid tokens, as returned
 * by shell_tokenize_commands() or an equivalent producer. All token spans refer
 * to the same contiguous, immutable, NUL-free source; their positions, lengths,
 * types, and command start_pos/end_pos describe that source consistently. The
 * command span includes any structural prefix before the first token. Keep the
 * command, token array, and source alive and unchanged throughout this call.
 * These relationships are not revalidated here. This diagnostic operation does
 * not validate complete shell syntax; use shell_transform_command_line() when
 * that validation is required.
 *
 * transformed_cmd is distinct writable pointer storage owning no live result.
 * The returned command owns its strings and does not borrow the input source.
 * NULL limits means unbounded output; otherwise limits must remain unchanged.
 * On failure, *transformed_cmd is set to NULL.
 */
shell_transform_status_t shell_transform_command(
    const shell_command_t *cmd, const shell_transform_limits_t *limits,
    shell_transformed_command_t **transformed_cmd) SHELL_NONNULL(1, 3);

/**
 * Transform exactly `command_length` shell-source bytes.
 * Complete syntax is required, including expansion and heredoc termination;
 * unlike lexical diagnostic iteration, unfinished source is not transformed.
 *
 * Shellsplit only transforms modeled simple-command lists, pipelines, and
 * brace/subshell groups. Control compounds (including function declarations,
 * `select`, and `coproc`), shell-semantic array forms, and unmodeled Bash
 * `[[ … ]]`, `(( … ))`, `$"…"`, and `;&` / `;;&` forms return
 * SHELL_TRANSFORM_EPARSE.
 *
 * On failure, writable outputs are reset to NULL and zero.
 */
shell_transform_status_t
shell_transform_command_line(const char *command_line, size_t command_length,
                             const shell_transform_limits_t *limits,
                             shell_transformed_command_t ***transformed_cmds,
                             size_t *transformed_count) SHELL_NONNULL(1, 4, 5);

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
    const shell_transformed_command_t *cmd) SHELL_NONNULL(1);

/**
 * Return true when at least one token received a diagnostic placeholder
 * replacement. Joining tokens or removing physical line continuations alone
 * does not set this flag; it is not a source/display equality test.
 */
bool shell_transformed_command_has_transformations(
    const shell_transformed_command_t *cmd) SHELL_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif // SHELL_TRANSFORM_H
