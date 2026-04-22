#ifndef SHELL_INTEROP_H
#define SHELL_INTEROP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Go Interop - Handle-based API for thread-safe parsing
 * ============================================================ */

#define SHELL_INTEROP_BUFFER_SIZE 4096

typedef struct shell_interop_handle shell_interop_handle_t;

/* Create/destroy handle */
shell_interop_handle_t* shell_interop_create(void);
void shell_interop_destroy(shell_interop_handle_t* handle);

/* Parse a shell command and return subcommand count (0 on error, -1 if cmd too long)
 *
 * Features are OR'd flags from shell_tokenizer.h:
 *   SHELL_FEAT_VARS       = 0x01  // $VAR, ${VAR}, $1
 *   SHELL_FEAT_GLOBS      = 0x02  // *, ?, [abc]
 *   SHELL_FEAT_SUBSHELL   = 0x04  // $(...), `...`
 *   SHELL_FEAT_ARITH      = 0x08  // $((...))
 *   SHELL_FEAT_HEREDOC    = 0x10  // << delimiter
 *   SHELL_FEAT_HERESTRING = 0x20  // <<< here-string
 *   SHELL_FEAT_PROCESS_SUB = 0x40 // <(cmd), >(cmd)
 *
 * Command types (lower 8 bits of type):
 *   SHELL_TYPE_SIMPLE    = 0x00  // Single command
 *   SHELL_TYPE_PIPELINE = 0x100 // Followed by |
 *   SHELL_TYPE_AND      = 0x200 // Followed by &&
 *   SHELL_TYPE_OR       = 0x400 // Followed by ||
 *   SHELL_TYPE_SEMICOLON= 0x800 // Followed by ;
 */
int shell_interop_parse(shell_interop_handle_t* handle, const char* cmd, int cmd_len);

/* Get the number of subcommands from last parse */
int shell_interop_subcommand_count(shell_interop_handle_t* handle);

/* Get type of subcommand i (0-indexed) */
int shell_interop_subcommand_type(shell_interop_handle_t* handle, int i);

/* Get features of subcommand i */
int shell_interop_subcommand_features(shell_interop_handle_t* handle, int i);

/* Get start position of subcommand i in original string */
int shell_interop_subcommand_start(shell_interop_handle_t* handle, int i);

/* Get length of subcommand i */
int shell_interop_subcommand_len(shell_interop_handle_t* handle, int i);

/* Get the subcommand string (caller must free via shell_interop_free_str) */
char* shell_interop_subcommand_str(shell_interop_handle_t* handle, int i);

/* Free a string returned by shell_interop_*_str functions */
void shell_interop_free_str(char* s);

/* Get string representation of features (caller must free via shell_interop_free_str) */
char* shell_interop_features_str(int features);

/* Get string representation of command type (caller must free via shell_interop_free_str) */
char* shell_interop_type_str(int type);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_INTEROP_H */