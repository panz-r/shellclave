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

/* Suggested minimum output buffer size (8 KB fits most commands). */
#define SG_BUF_MIN 8192

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
    SG_VERDICT_ALLOW  = 0,
    SG_VERDICT_DENY   = 1,
    SG_VERDICT_REJECT = 2,
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
} sg_subcmd_result_t;

/* Top-level evaluation result: metadata + pointer array into buffer. */
typedef struct {
    sg_verdict_t verdict;
    const char *deny_reason;

    sg_subcmd_result_t subcmds[SG_MAX_SUBCMD_RESULTS];
    uint32_t subcmd_count;

    const char *suggestions[2];
    uint32_t suggestion_count;

    uint32_t attention_index;
    bool truncated;
} sg_result_t;

typedef struct sg_gate sg_gate_t;

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

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path);
sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path);
sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_rule_count(const sg_gate_t *gate);

/* ============================================================
 * EVALUATION
 * ============================================================ */

/*
 * Evaluate a raw command string against the loaded policy.
 *
 * `buf` / `buf_size` : caller-owned output buffer.  All string data
 *   (command texts, reject reasons, suggestions) is packed into this
 *   buffer.  Result pointers reference into it.
 * `out` : result metadata.  On return, subcmds[].command etc. point
 *   into `buf`.
 *
 * Returns SG_OK on success, SG_ERR_TRUNC if the buffer was too small
 *   (partial results are still valid), or SG_ERR_INVALID for bad args.
 */
sg_error_t sg_eval(sg_gate_t *gate, const char *cmd,
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
