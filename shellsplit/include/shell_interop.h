#ifndef SHELL_INTEROP_H
#define SHELL_INTEROP_H

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
shell_interop_handle_t *shell_interop_create(void);
void shell_interop_destroy(shell_interop_handle_t *handle);

/* Parse a shell command and return subcommand count (0 on error, -1 if cmd too
 * long)
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
 *   SHELL_FEAT_GROUP          = 0x1000 // parenthesized command group
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
 */
int shell_interop_parse(shell_interop_handle_t *handle, const char *cmd,
                        int cmd_len);

/* Return the number of subcommands from the most recent successful parse. */
int shell_interop_subcommand_count(shell_interop_handle_t *handle);

/* Return the command-subtype for subcommand index i (SHELL_TYPE_* flags), or 0
 * on invalid input. */
int shell_interop_subcommand_type(shell_interop_handle_t *handle, int i);

/* Return the feature bitmask describing shell features in subcommand index i,
 * or 0 on invalid input. */
int shell_interop_subcommand_features(shell_interop_handle_t *handle, int i);

/* Return byte offset where subcommand i starts in the original command string.
 */
int shell_interop_subcommand_start(shell_interop_handle_t *handle, int i);

/* Return the byte length of subcommand i in the original command string. */
int shell_interop_subcommand_len(shell_interop_handle_t *handle, int i);

/* Return heap-allocated copy of subcommand i text.
   Caller must free the result with shell_interop_free_str(). */
char *shell_interop_subcommand_str(shell_interop_handle_t *handle, int i);

/* Free a string returned by shell_interop_*_str functions */
void shell_interop_free_str(char *s);

/* Get string representation of features (caller must free via
 * shell_interop_free_str) */
char *shell_interop_features_str(int features);

/* Get string representation of command type (caller must free via
 * shell_interop_free_str) */
char *shell_interop_type_str(int type);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_INTEROP_H */
