#ifndef SHELL_INTEROP_H
#define SHELL_INTEROP_H

#include "shell_tokenizer.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Handle-based parsing API for foreign-function interfaces. Each handle owns
 * its input buffer and last result; destroy it after its final accessor call.
 */

#define SHELL_INTEROP_BUFFER_SIZE 4096

typedef struct shell_interop_handle shell_interop_handle_t;

/* Create/destroy an interop parsing handle. Creation allocates parser state;
 * destroy releases it once parsing and result access are complete.
 */
shell_interop_handle_t *shell_interop_new(void);
void shell_interop_free(shell_interop_handle_t *handle);

/* Parse a shell command into the handle's bounded internal storage.
 *
 * Features are OR'd flags from shell_tokenizer.h:
 *   SHELL_FEAT_VARS       = 0x01  // $VAR, ${VAR}, $1
 *   SHELL_FEAT_GLOBS      = 0x02  // *, ?, [abc]
 *   SHELL_FEAT_SUBSHELL   = 0x04  // $(...), `...`
 *   SHELL_FEAT_ARITH      = 0x08  // $((...))
 *   SHELL_FEAT_HEREDOC    = 0x10  // << delimiter
 *   SHELL_FEAT_HERESTRING = 0x20  // <<< here-string
 *   SHELL_FEAT_PROCESS_SUB   = 0x040 // <(cmd), >(cmd)
 *   SHELL_FEAT_LOOPS         = 0x080 // for, while, until
 *   SHELL_FEAT_CONDITIONALS  = 0x100 // if/then/else/fi
 *   SHELL_FEAT_CASE          = 0x200 // case/esac
 *   SHELL_FEAT_SUBSHELL_FILE = 0x400 // $(<file)
 *   SHELL_FEAT_PIPELINE       = 0x800 // literal | pipeline construct
 *   SHELL_FEAT_GROUP          = 0x1000 // brace or parenthesized command group
 *
 * Command types (upper bits of type) describe the operator or structural
 * marker associated with one subcommand. The outer separator takes precedence
 * when a subcommand also contains a nested substitution; inspect features for
 * the nested syntax:
 *   SHELL_TYPE_SIMPLE     = 0x0000 // First or standalone command
 *   SHELL_TYPE_PIPELINE   = 0x0100 // Preceded by literal |
 *   SHELL_TYPE_AND        = 0x0200 // Preceded by &&
 *   SHELL_TYPE_OR         = 0x0400 // Preceded by ||
 *   SHELL_TYPE_SEMICOLON  = 0x0800 // Preceded by ;
 *   SHELL_TYPE_HEREDOC    = 0x1000 // Starts with <<
 *   SHELL_TYPE_HERESTRING = 0x2000 // Starts with <<<
 *   SHELL_TYPE_SUBSTITUTION = 0x4000 // Command/process substitution operator
 *   SHELL_TYPE_BACKGROUND = 0x8000 // Background command separator (&)
 *
 * `cmd` points to exactly `cmd_len` bytes and need not be null-terminated.
 * Embedded NUL bytes are rejected because they are not valid shell input.
 * On success, `subcommand_count` receives the number of parsed subcommands.
 * Every call clears the previous result before validating input.
 */
shell_error_t shell_interop_parse(shell_interop_handle_t *handle,
                                  const char *cmd, size_t cmd_len,
                                  size_t *subcommand_count);

/* Return the number of subcommands from the most recent successful parse. */
size_t shell_interop_subcommand_count(const shell_interop_handle_t *handle);

/* Copy range metadata for one subcommand. The range remains valid until the
 * next parse on handle or shell_interop_free(handle). */
bool shell_interop_subcommand_range(const shell_interop_handle_t *handle,
                                    size_t index, shell_range_t *range);

/* Return a borrowed, non-NUL-terminated subcommand view. It remains valid
 * until the next parse on handle or shell_interop_free(handle). */
bool shell_interop_subcommand_view(const shell_interop_handle_t *handle,
                                   size_t index, const char **data,
                                   size_t *length);

/* Return a heap-allocated NUL-terminated copy of one subcommand. The caller
 * releases a successful result with free(). */
char *shell_interop_subcommand_dup(const shell_interop_handle_t *handle,
                                   size_t index);

/* Format recognized feature flags into caller-owned storage. `written` gets
 * the byte count excluding NUL. The output is cleared on failure. */
shell_error_t shell_interop_format_features(uint32_t features, char *output,
                                            size_t output_size,
                                            size_t *written);

/* Return the static display name for a command separator type. */
const char *shell_interop_command_type_name(shell_cmd_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_INTEROP_H */
