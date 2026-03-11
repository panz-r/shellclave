#ifndef SHELL_INTEROP_H
#define SHELL_INTEROP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Go Interop - Simple wrapper functions for calling from Go
 * ============================================================ */

/* Parse a shell command and return subcommand info
 * Returns number of subcommands found (0 on error)
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
int shell_interop_parse(const char* cmd, int cmd_len);

/* Get the number of subcommands from last parse */
int shell_interop_subcommand_count(void);

/* Get type of subcommand i (0-indexed) */
int shell_interop_subcommand_type(int i);

/* Get features of subcommand i */
int shell_interop_subcommand_features(int i);

/* Get start position of subcommand i in original string */
int shell_interop_subcommand_start(int i);

/* Get length of subcommand i */
int shell_interop_subcommand_len(int i);

/* Get the subcommand string (caller must free) */
char* shell_interop_subcommand_str(int i);

/* Free a string returned by shell_interop_subcommand_str */
void shell_interop_free_str(char* s);

/* Get string representation of features (caller must free) */
char* shell_interop_features_str(int features);

/* Get string representation of command type (caller must free) */
char* shell_interop_type_str(int type);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_INTEROP_H */
