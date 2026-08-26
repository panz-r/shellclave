#ifndef SHELL_ABSTRACT_H
#define SHELL_ABSTRACT_H

#include "shell_processor.h"
#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Builds abstract command strings and extracted elements for downstream use.
 */

/* --- PHASE 1: EXTENDED TOKEN CLASSIFICATION --- */

/**
 * Abstract token kind used by downstream validation logic.
 */
typedef enum {
  SHELL_ABSTRACT_EV,   // Environment variable: $FOO → $EV_1
  SHELL_ABSTRACT_PV,   // Positional: $1 → $PV_1
  SHELL_ABSTRACT_SV,   // Special: $? → $SV_1
  SHELL_ABSTRACT_AP,   // Absolute path: /etc → $AP_1
  SHELL_ABSTRACT_RP,   // Relative path: ./foo → $RP_1
  SHELL_ABSTRACT_HP,   // Home path: ~/file → $HP_1
  SHELL_ABSTRACT_GB,   // Glob: *.txt → $GB_1
  SHELL_ABSTRACT_CS,   // Command subst: $(cmd) → $CS_1
  SHELL_ABSTRACT_AR,   // Arithmetic: $((x+1)) → $AR_1
  SHELL_ABSTRACT_STR,  // String: "foo" → $STR_1
  SHELL_ABSTRACT_REDIR // Redirect target: > file → $RD_1
} shell_abstract_type_t;

/**
 * Path category for validation rules
 */
typedef enum {
  SHELL_PATH_ROOT,     // /
  SHELL_PATH_ETC,      // /etc/
  SHELL_PATH_VAR,      // /var/
  SHELL_PATH_USR,      // /usr/
  SHELL_PATH_HOME,     // /home/*, /root
  SHELL_PATH_TMP,      // /tmp/
  SHELL_PATH_PROC,     // /proc/
  SHELL_PATH_SYS,      // /sys/
  SHELL_PATH_DEV,      // /dev/
  SHELL_PATH_OPT,      // /opt/
  SHELL_PATH_SRV,      // /srv/
  SHELL_PATH_RUN,      // /run/
  SHELL_PATH_SYSROOT,  // /sysroot/
  SHELL_PATH_BOOT,     // /boot/
  SHELL_PATH_MNT,      // /mnt/
  SHELL_PATH_MEDIA,    // /media/
  SHELL_PATH_SNAPSHOT, // /.snapshots/
  SHELL_PATH_OTHER     // anything else
} shell_path_category_t;

/**
 * Single abstracted element
 */
typedef struct {
  shell_abstract_type_t type;
  const char *original; // Original text from input
  char *abstraction;    // "$AP_1" (owned)
  size_t start;
  size_t end;

  // Classification details (owned copies)
  union {
    struct {
      char *name;     // For variables: "PATH", "1", etc.
      bool is_braced; // ${VAR} vs $VAR
      bool is_quoted;
    } var;

    struct {
      char *path; // "/etc", "./foo"
      bool is_absolute;
      bool ends_with_slash;
    } path;

    struct {
      char *pattern; // "*.txt"
      bool has_slash;
    } glob;

    struct {
      char *content; // Command substitution content
    } cmd_subst;
  } data;

  // Runtime-expandable data (set during validation phase)
  char *expanded;
} shell_abstract_element_t;

/**
 * Full abstracted command
 */
typedef struct {
  const char *original; // Owned copy of the input command
  char *display_text;   // Lossy diagnostic abstraction (owned)

  shell_abstract_element_t **elements; // Array of pointers (owned)
  size_t element_count;

  // Metadata flags
  bool has_variables;
  bool has_pos_vars;
  bool has_special_vars;
  bool has_globs;
  bool has_cmd_subst;
  bool has_abs_paths;
  bool has_rel_paths;
  bool has_home_paths;
  bool has_paths; // Any path type
  bool has_redirects;
  bool has_strings;
  bool has_arithmetic;
} shell_abstract_command_t;

/* --- PHASE 2: ABSTRACTION FUNCTIONS --- */

/**
 * Classify a raw token string (no tokenization needed)
 * Uses tokenizer types for basic classification
 */
shell_token_type_t shell_classify_raw_token(const char *text, size_t len);

/**
 * Create an abstracted command from original shell text.
 *
 * Input is a raw shell span: it need not be NUL-terminated, but cannot contain
 * NUL bytes. On success, `out` owns a command released with
 * shell_abstract_command_free(). On failure, `out` is NULL and the status
 * identifies invalid input, shell syntax, allocation failure, or overflow.
 */
typedef enum {
  SHELL_ABSTRACT_OK = 0,
  SHELL_ABSTRACT_EINPUT,
  SHELL_ABSTRACT_EPARSE,
  SHELL_ABSTRACT_ENOMEM,
  SHELL_ABSTRACT_EOVERFLOW,
} shell_abstract_status_t;

shell_abstract_status_t
shell_abstract_command_parse(const char *command, size_t command_length,
                             shell_abstract_command_t **out);

/**
 * Get the lossy diagnostic abstraction. This is not shell source or
 * canonical netargv; programmatic consumers must use Shellsplit's canonical
 * sequence builders instead.
 */
const char *
shell_abstract_command_get_display_text(const shell_abstract_command_t *cmd);

/**
 * Get all extracted elements for validation
 */
const shell_abstract_element_t *const *
shell_abstract_command_get_elements(const shell_abstract_command_t *cmd,
                                    size_t *count);

/** Get the mutable elements for explicit expansion or editing. */
shell_abstract_element_t *const *
shell_abstract_command_get_mutable_elements(shell_abstract_command_t *cmd,
                                            size_t *count);

/**
 * Get original command
 */
const char *
shell_abstract_command_get_source(const shell_abstract_command_t *cmd);

/**
 * Check if command has specific feature
 */
bool shell_abstract_command_has_variables(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_pos_vars(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_special_vars(
    const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_globs(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_paths(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_abs_paths(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_rel_paths(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_home_paths(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_cmd_subst(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_redirects(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_arithmetic(const shell_abstract_command_t *cmd);
bool shell_abstract_command_has_strings(const shell_abstract_command_t *cmd);

/**
 * Get element by abstraction string (e.g., "$AP_1")
 */
shell_abstract_element_t *
shell_abstract_command_find_element(shell_abstract_command_t *cmd,
                                    const char *abstraction);

/**
 * Get element by index
 */
shell_abstract_element_t *
shell_abstract_command_get_element(shell_abstract_command_t *cmd, size_t index);

/* --- PHASE 3: RUNTIME EXPANSION (OPTIONAL) --- */

/**
 * Runtime context for expansion
 */
typedef struct {
  const char *const *env; // Environment variables (NULL-terminated)
  const char *cwd;        // Current working directory
  bool resolve_symlinks;
} shell_runtime_context_t;

/**
 * Expand a single element using runtime context
 * Returns expanded string (caller must free) or NULL on failure
 */
char *shell_abstract_element_expand(shell_abstract_element_t *elem,
                                    const shell_runtime_context_t *ctx);

/**
 * Expand all elements in an abstracted command
 */
bool shell_abstract_command_expand(shell_abstract_command_t *cmd,
                                   const shell_runtime_context_t *ctx);

/* --- UTILITY FUNCTIONS --- */

/**
 * Get path category from resolved path
 */
shell_path_category_t shell_path_category_from_path(const char *resolved_path);

/**
 * Get human-readable name for abstract type
 */
const char *shell_abstract_type_name(shell_abstract_type_t type);

/**
 * Get human-readable name for path category
 */
const char *shell_path_category_name(shell_path_category_t cat);

/* --- CLEANUP --- */

/**
 * Free abstracted command and all elements
 */
void shell_abstract_command_free(shell_abstract_command_t *cmd);

#ifdef __cplusplus
}
#endif

#endif // SHELL_ABSTRACT_H
