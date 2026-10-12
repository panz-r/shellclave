#ifndef SHELL_ABSTRACT_H
#define SHELL_ABSTRACT_H

#include "shell_contract.h"

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
      /* Static parameter name, such as "PATH", "1", or "?". This is NULL
       * when the expansion selects a dynamic set of names (for example
       * `${!prefix*}`); `original` always retains the complete spelling. */
      char *name;
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
      /* Owned, non-NULL string for CS, AR and STR elements, including an
       * empty string for an empty payload. Excludes the source delimiters;
       * physical continuations within the payload are preserved. */
      char *content;
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
  /* Owned lossy diagnostic abstraction, not shell source or canonical argv.
   * Programmatic consumers use Shellsplit's canonical sequence builders. */
  char *display_text;

  shell_abstract_element_t **elements; // Array of pointers (owned)
  size_t element_count;

  /* Semantic feature flags include active expansions inside enclosing glob,
   * string, parameter and arithmetic elements; display spans never overlap.
   * Executable substitution bodies are separate inspections, not traversed
   * for variable/arithmetic flags here. Redirect targets retain their own
   * classification and are not counted as argument variables/arithmetic. */
  bool has_variables;
  bool has_pos_vars;
  bool has_special_vars;
  bool has_globs;
  /* Includes direct and parameter-expansion-nested command/process
   * substitutions. A nested substitution remains inside its enclosing
   * element so diagnostic display elements never overlap. */
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
 * Path-shaped words return ARGUMENT for downstream path abstraction. Otherwise
 * active glob syntax takes precedence over option spelling; quoted and escaped
 * glob punctuation is literal.
 */
shell_token_type_t shell_classify_raw_token(const char *text, size_t len)
    SHELL_NONNULL(1);

/**
 * Create an abstracted command from one complete supported shell command.
 *
 * Input is a raw shell span: it need not be NUL-terminated, but cannot contain
 * NUL bytes. Incomplete or malformed compound syntax is rejected rather than
 * abstracted through the tokenizer's tolerant diagnostic mode. On success,
 * `out` owns a command released with
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

/* Shellsplit abstracts modeled simple-command lists, pipelines, and
 * brace/subshell groups. Control compounds (including function declarations,
 * `select`, and `coproc`), shell-semantic array forms, and unmodeled Bash
 * `[[ … ]]`, `(( … ))`, `$"…"`, and `;&` / `;;&` forms return
 * SHELL_ABSTRACT_EPARSE. */
shell_abstract_status_t
shell_abstract_command_parse(const char *command, size_t command_length,
                             shell_abstract_command_t **out)
    SHELL_NONNULL(1, 3);

/**
 * Get all extracted elements for validation
 */
const shell_abstract_element_t *const *
shell_abstract_command_get_elements(const shell_abstract_command_t *cmd,
                                    size_t *count) SHELL_NONNULL(1, 2);

/** Get the mutable elements for explicit expansion or editing. */
shell_abstract_element_t *const *
shell_abstract_command_get_mutable_elements(shell_abstract_command_t *cmd,
                                            size_t *count) SHELL_NONNULL(1, 2);

/**
 * Get element by abstraction string (e.g., "$AP_1")
 */
shell_abstract_element_t *shell_abstract_command_find_element(
    shell_abstract_command_t *cmd, const char *abstraction) SHELL_NONNULL(1, 2);

/**
 * Get element by index
 */
shell_abstract_element_t *
shell_abstract_command_get_element(shell_abstract_command_t *cmd, size_t index)
    SHELL_NONNULL(1);

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
                                    const shell_runtime_context_t *ctx)
    SHELL_NONNULL(1, 2);

/**
 * Expand all elements in an abstracted command
 */
bool shell_abstract_command_expand(shell_abstract_command_t *cmd,
                                   const shell_runtime_context_t *ctx)
    SHELL_NONNULL(1, 2);

/* --- UTILITY FUNCTIONS --- */

/**
 * Get path category from resolved path
 */
shell_path_category_t shell_path_category_from_path(const char *resolved_path)
    SHELL_NONNULL(1);

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
