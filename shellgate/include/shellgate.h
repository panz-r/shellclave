/*
 * shellgate.h - Shell command policy gate
 *
 * Evaluates shell commands against a policy trie.
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 *
 * Usage:
 *   1. Create a gate with one or more policies
 *   2. Call sg_eval() with a raw command string
 *   3. Read the verdict and optional suggestions
 *   4. Destroy the gate when done
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

#define SG_MAX_POLICIES       8
#define SG_MAX_SUBCMD_RESULTS 64
#define SG_MAX_CMD_LEN        4096

/* Feature flags that cause immediate rejection by default */
#define SG_REJECT_MASK_DEFAULT  ( \
    (1u << 2) |   /* SUBSHELL   */ \
    (1u << 3) |   /* ARITH      */ \
    (1u << 4) |   /* HEREDOC    */ \
    (1u << 5) |   /* HERESTRING */ \
    (1u << 6) |   /* PROCESS_SUB*/ \
    (1u << 7) |   /* LOOPS      */ \
    (1u << 8) |   /* CONDITIONALS*/\
    (1u << 9) )   /* CASE       */

/* ============================================================
 * TYPES
 * ============================================================ */

typedef enum {
    SG_OK            =  0,
    SG_ERR_INVALID   = -1,
    SG_ERR_MEMORY    = -2,
    SG_ERR_PARSE     = -3,
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

typedef struct {
    bool matches;
    char   command[SG_MAX_CMD_LEN];
    char   reject_reason[128];
    sg_verdict_t verdict;
} sg_subcmd_result_t;

typedef struct {
    sg_verdict_t verdict;
    const char *deny_reason;

    sg_subcmd_result_t subcmds[SG_MAX_SUBCMD_RESULTS];
    uint32_t subcmd_count;

    char suggestion_a[1024];
    char suggestion_b[1024];
    uint32_t suggestion_count;

    uint32_t attention_index;
} sg_result_t;

typedef struct sg_gate sg_gate_t;

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

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path);
sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_rule_count(const sg_gate_t *gate);

/* ============================================================
 * EVALUATION
 * ============================================================ */

sg_error_t sg_eval(sg_gate_t *gate, const char *cmd, sg_result_t *out);

/* ============================================================
 * RESULT HELPERS
 * ============================================================ */

const char *sg_verdict_name(sg_verdict_t v);

#ifdef __cplusplus
}
#endif

#endif /* SHELLGATE_H */
