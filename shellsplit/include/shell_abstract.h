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
  SHELL_ABSTRACT_EV,    // Environment variable: $FOO → $EV_1
  SHELL_ABSTRACT_PV,    // Positional: $1 → $PV_1
  SHELL_ABSTRACT_SV,    // Special: $? → $SV_1
  SHELL_ABSTRACT_AP,    // Absolute path: /etc → $AP_1
  SHELL_ABSTRACT_RP,    // Relative path: ./foo → $RP_1
  SHELL_ABSTRACT_HP,    // Home path: ~/file → $HP_1
  SHELL_ABSTRACT_GB,    // Glob: *.txt → $GB_1
  SHELL_ABSTRACT_CS,    // Command subst: $(cmd) → $CS_1
  SHELL_ABSTRACT_AR,    // Arithmetic expansion or command → $AR_1
  SHELL_ABSTRACT_STR,   // String: "foo" → $STR_1
  SHELL_ABSTRACT_REDIR, // Redirect target: > file → $RD_1
  SHELL_ABSTRACT_CT,    // Conditional string command -> $CT_1
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
      /* Decoded static word value, such as "/etc" or "./foo": quotes and
       * escapes are removed, while `original` retains the exact spelling.
       * is_absolute and ends_with_slash describe this value. */
      char *path;
      bool is_absolute;
      bool ends_with_slash;
    } path;

    struct {
      char *pattern; // "*.txt"
      bool has_slash;
    } glob;

    struct {
      /* Owned, non-NULL string for CS, AR, CT and STR elements, including an
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
   * element so diagnostic display elements never overlap. Comparisons and
   * shifts in arithmetic commands preserve their arithmetic context. */
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
 * Blank source returns SHELL_ABSTRACT_BLANK with `out` NULL.
 */
typedef enum {
  SHELL_ABSTRACT_OK = 0,
  SHELL_ABSTRACT_EINPUT,
  SHELL_ABSTRACT_EPARSE,
  SHELL_ABSTRACT_ENOMEM,
  SHELL_ABSTRACT_EOVERFLOW,
  /* The source is valid but blank: whitespace, comments and escaped line
   * endings only. There is no command to abstract, which is not a parse
   * error. `out` is NULL. */
  SHELL_ABSTRACT_BLANK,
} shell_abstract_status_t;

/* Shellsplit abstracts modeled simple-command lists, pipelines, and
 * brace/subshell groups. Control compounds (including function declarations,
 * `select`, and `coproc`), shell-semantic array forms, and wider Bash
 * `[[ … ]]` predicates, dynamic/mutating arithmetic commands, `$"…"`, and `;&`
 * / `;;&` forms return SHELL_ABSTRACT_EPARSE. */
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
 * Supplies the value of one positional or special parameter. `type` is
 * SHELL_ABSTRACT_PV or SHELL_ABSTRACT_SV and `name` is the parameter name
 * without `$` or braces (`1`, `10`, `?`). Return true after storing the value
 * in `*value` and its byte count in `*value_length`; the bytes may be empty
 * (length zero, `*value` then unused), must not contain NUL, and need only
 * stay valid until the callback's caller returns, since expansion copies
 * them. A nonzero count requires `*value` to point to that many readable
 * bytes; expansion does not validate a result that breaks this. Return false
 * when the parameter has no known value. `context` is the context's
 * `parameters_context`. The callback must not modify the element.
 */
typedef bool (*shell_parameter_resolver_t)(shell_abstract_type_t type,
                                           const char *name, void *context,
                                           const char **value,
                                           size_t *value_length);

/**
 * Runtime context for expansion.
 *
 * Positional and special parameters are shell state, never environment
 * entries: Bash does not read `$1` or `$?` from the environment, so `env` is
 * consulted only for named variables. Callers who know such values supply
 * them through `parameters`.
 */
typedef struct {
  const char *const *env; // Environment variables (NULL-terminated)
  const char *cwd;        // Current working directory
  bool resolve_symlinks;
  /* Optional. When NULL every positional and special parameter is unresolved.
   * Not applied to named variables, which resolve only from env. */
  shell_parameter_resolver_t parameters;
  void *parameters_context; // Passed to parameters; may be NULL
} shell_runtime_context_t;

/**
 * Expand a single element using runtime context.
 *
 * Only variable (EV, PV, SV) and path (AP, RP, HP) elements have a runtime
 * value; every other kind returns NULL. A variable resolves only for a plain
 * reference, `$name` or `${name}`: a parameter operator (`${name:-word}`,
 * `${name:+word}`, `${#name}`, `${!name}`, substrings, pattern edits) or a
 * subscript changes the result in ways a lookup cannot model, so it returns
 * NULL rather than the unmodified value. A named variable (EV) resolves from
 * the context's environment only. A positional or special parameter (PV, SV)
 * resolves only through the context's `parameters` callback and is never read
 * from the environment, even from an entry named `1` or `?`. Path elements hold
 * the decoded word value, so escapes and quotes in the source are already
 * removed. A home path resolves only for `~` and `~/…`, from HOME in the
 * context. A
 * `~name` form names another user's home directory, which the context cannot
 * supply, so it returns NULL rather than the unexpanded text.
 *
 * Returns the expanded string (caller must free), or NULL when the element
 * cannot be resolved by this context or allocation fails.
 */
char *shell_abstract_element_expand(shell_abstract_element_t *elem,
                                    const shell_runtime_context_t *ctx)
    SHELL_NONNULL(1, 2);

/**
 * Expand every element that supports runtime expansion, storing each result
 * in the element's `expanded` field. Results from an earlier call are
 * replaced; an element that does not resolve ends with `expanded` NULL.
 *
 * Returns true when every expandable element (variable and path elements)
 * resolved. Elements of other kinds (globs, strings, substitutions,
 * arithmetic, redirects, conditionals) are never expandable: they keep a NULL
 * `expanded` and do not affect the result, so a command with none returns
 * true. Returns false when any expandable element did not resolve, for
 * example an unset variable, a positional or special parameter without a
 * callback, a parameter operator, a missing HOME, a `~name` home path or an
 * allocation failure. All elements are still processed, so
 * resolved elements keep their values after a false result. */
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
