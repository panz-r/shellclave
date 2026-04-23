/*
 * shellgate.h - Shell command policy gate
 *
 * Evaluates shell commands against a policy trie.
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 *
 * Usage:
 *   1. Create a gate with one or more policies
 *   2. Allocate an output buffer
 *   3. Call sg_eval() with a raw command string and the buffer
 *   4. Read the verdict, suggestions, and per-subcommand results
 *   5. Reuse the buffer for the next evaluation
 *   6. Destroy the gate when done
 *
 * Zero-copy: result pointers reference into the caller's output buffer.
 * Bounded:   output buffer size is the only limit on result data.
 * No allocations in the evaluation path.
 *
 * Thread safety: none. Caller synchronizes.
 */

#ifndef SHELLGATE_H
#define SHELLGATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define SG_MAX_SUBCMD_RESULTS 64

/* Feature flags that cause immediate rejection by default.
 * These are the same bits as SHELL_FEAT_* in shell_tokenizer.h. */
#define SG_REJECT_MASK_DEFAULT  ( \
    (1u << 2) |   /* SUBSHELL     */ \
    (1u << 3) |   /* ARITH        */ \
    (1u << 4) |   /* HEREDOC      */ \
    (1u << 5) |   /* HERESTRING   */ \
    (1u << 6) |   /* PROCESS_SUB  */ \
    (1u << 7) |   /* LOOPS        */ \
    (1u << 8) |   /* CONDITIONALS */ \
    (1u << 9) )   /* CASE         */

/* Ensure SG_REJECT_MASK_DEFAULT bits match SHELL_FEAT_* in shell_tokenizer.h */
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 2)) != 0, "SUBSHELL bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 3)) != 0, "ARITH bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 4)) != 0, "HEREDOC bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 5)) != 0, "HERESTRING bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 6)) != 0, "PROCESS_SUB bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 7)) != 0, "LOOPS bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 8)) != 0, "CONDITIONALS bit mismatch");
_Static_assert((SG_REJECT_MASK_DEFAULT & (1u << 9)) != 0, "CASE bit mismatch");

/* Suggested minimum output buffer size (8 KB fits most commands). */
#define SG_BUF_MIN 8192

/* ============================================================
 * VIOLATION FLAGS (category-encoded)
 * ============================================================
 *
 * Upper 16 bits encode the security domain:
 *   SG_VIOL_CAT_FILESYSTEM  - attacks on filesystem integrity
 *   SG_VIOL_CAT_PRIVILEGE   - privilege escalation vectors
 *   SG_VIOL_CAT_EXFIL       - data exfiltration patterns
 *
 * Caller decides what action to take based on these flags.
 * The violation carries severity only, no enforcement action.
 */

#define SG_VIOL_CAT_FILESYSTEM  (1u << 16)
#define SG_VIOL_CAT_PRIVILEGE   (1u << 17)
#define SG_VIOL_CAT_EXFIL       (1u << 18)
#define SG_VIOL_CAT_NETWORK     (1u << 19)

/* Filesystem Integrity */
#define SG_VIOL_WRITE_SENSITIVE   (SG_VIOL_CAT_FILESYSTEM | (1u << 0))
#define SG_VIOL_REMOVE_SYSTEM     (SG_VIOL_CAT_FILESYSTEM | (1u << 1))
#define SG_VIOL_PERM_SYSTEM       (SG_VIOL_CAT_FILESYSTEM | (1u << 2))
#define SG_VIOL_GIT_DESTRUCTIVE   (SG_VIOL_CAT_FILESYSTEM | (1u << 3))

/* Privilege Escalation */
#define SG_VIOL_ENV_PRIVILEGED    (SG_VIOL_CAT_PRIVILEGE  | (1u << 0))
#define SG_VIOL_SHELL_ESCALATION  (SG_VIOL_CAT_PRIVILEGE  | (1u << 1))
#define SG_VIOL_SUDO_REDIRECT     (SG_VIOL_CAT_PRIVILEGE  | (1u << 2))
#define SG_VIOL_PERSISTENCE       (SG_VIOL_CAT_PRIVILEGE  | (1u << 3))

/* Data Exfiltration */
#define SG_VIOL_WRITE_THEN_READ   (SG_VIOL_CAT_EXFIL | (1u << 0))
#define SG_VIOL_SUBST_SENSITIVE   (SG_VIOL_CAT_EXFIL | (1u << 1))
#define SG_VIOL_REDIRECT_FANOUT   (SG_VIOL_CAT_EXFIL | (1u << 2))
#define SG_VIOL_READ_SECRETS      (SG_VIOL_CAT_EXFIL | (1u << 3))
#define SG_VIOL_SHELL_OBFUSCATION (SG_VIOL_CAT_EXFIL | (1u << 4))

/* Network */
#define SG_VIOL_NET_DOWNLOAD_EXEC (SG_VIOL_CAT_NETWORK | (1u << 0))
#define SG_VIOL_NET_UPLOAD        (SG_VIOL_CAT_NETWORK | (1u << 1))
#define SG_VIOL_NET_LISTENER      (SG_VIOL_CAT_NETWORK | (1u << 2))

#define SG_MAX_VIOLATIONS 16

/* ============================================================
 * TYPES
 * ============================================================ */

typedef enum {
    SG_OK            =  0,
    SG_ERR_INVALID   = -1,
    SG_ERR_MEMORY    = -2,
    SG_ERR_PARSE     = -3,
    SG_ERR_TRUNC     = -4,
} sg_error_t;

typedef enum {
    SG_VERDICT_ALLOW        = 0,
    SG_VERDICT_DENY         = 1,
    SG_VERDICT_REJECT       = 2,
    SG_VERDICT_UNDETERMINED = 3,
} sg_verdict_t;

typedef enum {
    SG_STOP_FIRST_FAIL = 0,
    SG_STOP_FIRST_PASS = 1,
    SG_EVAL_ALL        = 2,
} sg_stop_mode_t;

/* Per-subcommand result: lightweight, pointers into output buffer. */
typedef struct {
    bool matches;
    sg_verdict_t verdict;
    const char *command;
    const char *reject_reason;

    uint32_t write_count;
    uint32_t read_count;
    uint32_t env_count;
    uint32_t violation_flags;
} sg_subcmd_result_t;

/* Single detected violation.  Strings point into output buffer. */
typedef struct {
    uint32_t type;
    uint32_t severity;
    uint32_t cmd_node_index;
    const char *description;
    const char *detail;
} sg_violation_t;

/* Top-level evaluation result: metadata + pointer array into buffer. */
typedef struct {
    sg_verdict_t verdict;
    const char *deny_reason;

    sg_subcmd_result_t subcmds[SG_MAX_SUBCMD_RESULTS];
    uint32_t subcmd_count;

    const char *suggestions[2];
    uint32_t suggestion_count;

    const char *deny_suggestions[2];
    uint32_t deny_suggestion_count;

    uint32_t attention_index;
    bool truncated;

    sg_violation_t violations[SG_MAX_VIOLATIONS];
    uint32_t       violation_count;
    uint32_t       violation_flags;
    bool           has_violations;
} sg_result_t;

typedef struct sg_gate sg_gate_t;

/* ============================================================
 * VIOLATION CONFIGURATION
 * ============================================================ */

#define SG_VIOL_MAX_PATHS   32
#define SG_VIOL_MAX_NAMES   16

typedef struct {
    /* Filesystem Integrity */
    const char *sensitive_write_paths[SG_VIOL_MAX_PATHS];
    uint32_t    sensitive_write_path_count;
    const char *sensitive_dirs[SG_VIOL_MAX_PATHS];
    uint32_t    sensitive_dir_count;

    /* Privilege Escalation */
    const char *sensitive_env_names[SG_VIOL_MAX_NAMES];
    uint32_t    sensitive_env_name_count;
    const char *sensitive_cmd_names[SG_VIOL_MAX_NAMES];
    uint32_t    sensitive_cmd_name_count;

    /* Data Exfiltration */
    const char *sensitive_read_paths[SG_VIOL_MAX_PATHS];
    uint32_t    sensitive_read_path_count;
    uint32_t    redirect_fanout_threshold;

    /* Network */
    const char *download_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    download_cmd_count;

    /* Shell spawn commands */
    const char *shell_spawn_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    shell_spawn_cmd_count;

    /* Permission modification commands */
    const char *perm_mod_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    perm_mod_cmd_count;

    /* Secret file paths (credential/key files) */
    const char *sensitive_secret_paths[SG_VIOL_MAX_PATHS];
    uint32_t    sensitive_secret_path_count;
    const char *file_reading_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    file_reading_cmd_count;

    /* Upload commands */
    const char *upload_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    upload_cmd_count;

    /* Listener commands */
    const char *listener_cmds[SG_VIOL_MAX_NAMES];
    uint32_t    listener_cmd_count;

    /* Shell profile paths */
    const char *shell_profile_paths[SG_VIOL_MAX_PATHS];
    uint32_t    shell_profile_path_count;
} sg_violation_config_t;

void sg_violation_config_default(sg_violation_config_t *cfg);

/* ============================================================
 * EXPANSION CALLBACKS
 * ============================================================ */

/*
 * Variable expansion callback.  Write the expanded value of `name`
 * into `buf` (at most `buf_size` bytes including NUL).
 * Return the number of bytes written (excluding NUL), or 0 if
 * the variable cannot be expanded.
 */
typedef size_t (*sg_expand_var_fn)(const char *name,
                                    char *buf, size_t buf_size,
                                    void *user_ctx);

/*
 * Glob expansion callback.  Write a space-separated list of
 * matches for `pattern` into `buf`.  Return bytes written
 * (excluding NUL), or 0 if no matches.
 */
typedef size_t (*sg_expand_glob_fn)(const char *pattern,
                                     char *buf, size_t buf_size,
                                     void *user_ctx);

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

sg_gate_t *sg_gate_new(void);
void sg_gate_free(sg_gate_t *gate);

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd);
sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask);
sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode);
sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled);

sg_error_t sg_gate_set_expand_var(sg_gate_t *gate,
                                   sg_expand_var_fn fn, void *user_ctx);
sg_error_t sg_gate_set_expand_glob(sg_gate_t *gate,
                                     sg_expand_glob_fn fn, void *user_ctx);

sg_error_t sg_gate_set_violation_config(sg_gate_t *gate,
                                          const sg_violation_config_t *config);

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path);
sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path);
sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_rule_count(const sg_gate_t *gate);
sg_error_t sg_gate_add_deny_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_deny_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_deny_rule_count(const sg_gate_t *gate);

/* ============================================================
 * EVALUATION
 * ============================================================ */

/*
 * Evaluate a raw command string against the loaded policy.
 *
 * `cmd` / `cmd_len` : raw command string to evaluate.  `cmd` must be
 *   null-terminated.  `cmd_len` is the length of the command string
 *   (excluding the null terminator, i.e. strlen(cmd)).
 *
 * `buf` / `buf_size` : caller-owned output buffer.  All string data
 *   (command texts, reject reasons, suggestions) is packed into this
 *   buffer.  Result pointers reference into it.  `buf` must remain
 *   valid while reading `sg_result_t` string fields.
 *
 * `out` : result metadata.  On return, subcmds[].command etc. point
 *   into `buf`.
 *
 * Returns SG_OK on success, SG_ERR_TRUNC if the buffer was too small
 *   (partial results are still valid), or SG_ERR_INVALID for bad args.
 */
sg_error_t sg_eval(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                   char *buf, size_t buf_size,
                   sg_result_t *out);

/* ============================================================
 * RESULT HELPERS
 * ============================================================ */

const char *sg_verdict_name(sg_verdict_t v);

#ifdef __cplusplus
}
#endif

#endif /* SHELLGATE_H */
