/*
 * shellgate.h - Shell command policy gate
 *
 * Evaluates shell commands with Shellsplit parsing and Shelltype policies.
 * Result strings reference the caller-provided output buffer; result arrays
 * have fixed capacities. Gates are not synchronized.
 */

#ifndef SHELLGATE_H
#define SHELLGATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* shelltype provides st_expand_suggestion_t, st_token_variant_t, st_node_t,
 * etc. */
#include "shelltype.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- CONSTANTS --- */

#define SG_MAX_SUBCMD_RESULTS 64

/* Feature flags that cause immediate rejection by default.
 * These are the same bits as SHELL_FEAT_* in shell_tokenizer.h. */
#define SG_REJECT_MASK_DEFAULT                                                 \
  ((1u << 3) | /* ARITH        */                                              \
   (1u << 4) | /* HEREDOC      */                                              \
   (1u << 5) | /* HERESTRING   */                                              \
   (1u << 7) | /* LOOPS        */                                              \
   (1u << 8) | /* CONDITIONALS */                                              \
   (1u << 9))  /* CASE         */

/* Ensure SG_REJECT_MASK_DEFAULT bits match SHELL_FEAT_* in shell_tokenizer.h */
#ifdef __cplusplus
#define SG_STATIC_ASSERT static_assert
#else
#define SG_STATIC_ASSERT _Static_assert
#endif
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 3)) != 0,
                 "ARITH bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 4)) != 0,
                 "HEREDOC bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 5)) != 0,
                 "HERESTRING bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 7)) != 0,
                 "LOOPS bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 8)) != 0,
                 "CONDITIONALS bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & (1u << 9)) != 0,
                 "CASE bit mismatch");
#undef SG_STATIC_ASSERT

/* Suggested output-buffer capacity. */
#define SG_BUF_MIN 8192

/* --- VIOLATION FLAGS --- */

#define SG_VIOL_CAT_FILESYSTEM (1u << 16)
#define SG_VIOL_CAT_PRIVILEGE (1u << 17)
#define SG_VIOL_CAT_EXFIL (1u << 18)
#define SG_VIOL_CAT_NETWORK (1u << 19)

/* Filesystem Integrity */
#define SG_VIOL_WRITE_SENSITIVE (1u << 0)
#define SG_VIOL_REMOVE_SYSTEM (1u << 1)
#define SG_VIOL_PERM_SYSTEM (1u << 2)
#define SG_VIOL_GIT_DESTRUCTIVE (1u << 3)

/* Privilege Escalation */
#define SG_VIOL_ENV_PRIVILEGED (1u << 4)
#define SG_VIOL_SHELL_ESCALATION (1u << 5)
#define SG_VIOL_SUDO_REDIRECT (1u << 6)
#define SG_VIOL_PERSISTENCE (1u << 7)

/* Data Exfiltration */
#define SG_VIOL_WRITE_THEN_READ (1u << 8)
#define SG_VIOL_SUBST_SENSITIVE (1u << 9)
#define SG_VIOL_REDIRECT_FANOUT (1u << 10)
#define SG_VIOL_READ_SECRETS (1u << 11)
#define SG_VIOL_SHELL_OBFUSCATION (1u << 12)

/* Network */
#define SG_VIOL_NET_DOWNLOAD_EXEC (1u << 13)
#define SG_VIOL_NET_UPLOAD (1u << 14)
#define SG_VIOL_NET_LISTENER (1u << 15)

#define SG_MAX_VIOLATIONS 16

/* Severity levels for violations (0-100). */
#define SG_SEVERITY_INFO 30
#define SG_SEVERITY_LOW 50
#define SG_SEVERITY_MEDIUM 70
#define SG_SEVERITY_HIGH 85
#define SG_SEVERITY_CRITICAL 95

/* --- TYPES --- */

typedef enum {
  SG_OK = 0,
  SG_ERR_INVALID = -1,
  SG_ERR_MEMORY = -2,
  SG_ERR_PARSE = -3,
  SG_ERR_TRUNC = -4,
  SG_ERR_IO = -5,
} sg_error_t;

typedef enum {
  SG_VERDICT_ALLOW = 0,
  SG_VERDICT_DENY = 1,
  SG_VERDICT_REJECT = 2,
  SG_VERDICT_UNDETERMINED = 3,
  SG_VERDICT_ALLOW_CONDITIONAL = 4,
} sg_verdict_t;

typedef enum {
  SG_STOP_FIRST_FAIL = 0,
  SG_STOP_FIRST_PASS =
      1, /* stops after first subcommand matching any policy (allow or deny) */
  SG_STOP_FIRST_ALLOW = 2, /* stops after first ALLOW verdict */
  SG_STOP_FIRST_DENY = 3,  /* stops after first DENY verdict */
  SG_EVAL_ALL = 4,
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
  bool requires_substitution_evaluation;
  int32_t substitution_parent_index;
  int32_t group_parent_index; /* Reserved for a future explicit group node. */
  uint16_t group_depth;       /* Parenthesized group nesting depth. */
  bool backgrounded;          /* Command runs in the background via '&'. */
  uint32_t violation_category_flags;
  uint32_t violation_type_flags;
  /* Deprecated alias retained for source compatibility. */
  uint32_t violation_flags;
} sg_subcmd_result_t;

/* Single detected violation.  Strings point into output buffer. */
typedef struct {
  uint32_t type;
  uint32_t category_flags;
  uint32_t severity;
  uint32_t cmd_node_index;
  const char *description;
  const char *detail;
} sg_violation_t;

/* Top-level evaluation result: metadata + pointer array into buffer.
 *
 * Violation fields (violations[], violation_count, violation_category_flags,
 * violation_type_flags,
 * violation_dropped_count, has_violations) are always populated from
 * the dependency graph scan, regardless of the overall verdict.
 * They reflect what the graph observed, not what the policy decided.
 */
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
  bool subcmd_truncated;
  bool violation_truncated;
  /* True when the configured stop mode deliberately left parsed
   * subcommands unevaluated. The verdict then describes only the evaluated
   * prefix; this is distinct from capacity or output truncation. */
  bool short_circuited;

  sg_violation_t violations[SG_MAX_VIOLATIONS];
  uint32_t violation_count;
  uint32_t violation_category_flags;
  uint32_t violation_type_flags;
  bool requires_substitution_evaluation;
  /* Deprecated alias retained for source compatibility. */
  uint32_t violation_flags;
  uint32_t violation_dropped_count;
  bool has_violations;

  /* Anomaly detection */
  /*
   * anomaly_score: bits per command (higher = more anomalous).
   *                 0.0 for sequences < 3 commands.
   *                 INFINITY if model cannot score (e.g., empty model).
   *
   * anomaly_detected: true if anomaly_score is finite and above threshold.
   *                    Always false for sequences with < 3 commands.
   *
   * anomaly_score_raw:  score from the raw command name model (bits/cmd).
   * anomaly_score_type: score from the type sequence model (bits/cmd).
   *                      0.0 if the type model is disabled, or if either the
   *                      command sequence or the type sequence has < 3 entries.
   *                      The two sequences come from different parsers, so
   *                      either can be the shorter one.
   */
  bool anomaly_detected;
  double anomaly_score;
  double anomaly_score_raw;
  double anomaly_score_type;
} sg_result_t;

typedef struct sg_gate sg_gate_t;

/* --- VIOLATION CONFIGURATION --- */

#define SG_VIOL_MAX_PATHS 32
#define SG_VIOL_MAX_NAMES 16

/**
 * Violation detection configuration.
 *
 * Path and name arrays are scanned linearly (arrays are small, <=32 elements).
 * Order does not matter for correctness.
 *
 * Violation fields in sg_result_t (violations[], violation_count,
 * violation_category_flags, violation_type_flags, violation_dropped_count,
 * has_violations) are
 * always populated from the dependency graph scan, regardless of
 * the overall verdict.  They reflect what the graph observed,
 * not what the policy decided.
 */
typedef struct {
  /* Filesystem Integrity */
  const char *sensitive_write_paths[SG_VIOL_MAX_PATHS];
  uint32_t sensitive_write_path_count;
  const char *sensitive_dirs[SG_VIOL_MAX_PATHS];
  uint32_t sensitive_dir_count;

  /* Privilege Escalation */
  const char *sensitive_env_names[SG_VIOL_MAX_NAMES];
  uint32_t sensitive_env_name_count;
  const char *sensitive_cmd_names[SG_VIOL_MAX_NAMES];
  uint32_t sensitive_cmd_name_count;

  /* Data Exfiltration */
  const char *sensitive_read_paths[SG_VIOL_MAX_PATHS];
  uint32_t sensitive_read_path_count;
  uint32_t redirect_fanout_threshold;

  /* Network */
  const char *download_cmds[SG_VIOL_MAX_NAMES];
  uint32_t download_cmd_count;

  /* Shell spawn commands */
  const char *shell_spawn_cmds[SG_VIOL_MAX_NAMES];
  uint32_t shell_spawn_cmd_count;

  /* Permission modification commands */
  const char *perm_mod_cmds[SG_VIOL_MAX_NAMES];
  uint32_t perm_mod_cmd_count;

  /* Secret file paths (credential/key files) */
  const char *sensitive_secret_paths[SG_VIOL_MAX_PATHS];
  uint32_t sensitive_secret_path_count;
  const char *file_reading_cmds[SG_VIOL_MAX_NAMES];
  uint32_t file_reading_cmd_count;

  /* Upload commands */
  const char *upload_cmds[SG_VIOL_MAX_NAMES];
  uint32_t upload_cmd_count;

  /* Listener commands */
  const char *listener_cmds[SG_VIOL_MAX_NAMES];
  uint32_t listener_cmd_count;

  /* Shell profile paths */
  const char *shell_profile_paths[SG_VIOL_MAX_PATHS];
  uint32_t shell_profile_path_count;
} sg_violation_config_t;

void sg_violation_config_default(sg_violation_config_t *cfg);

/* --- EXPANSION CALLBACKS --- */

/*
 * Variable expansion callback.  Write the expanded value of `name`
 * into `buf` (at most `buf_size` bytes including NUL).
 * Return the number of bytes written (excluding NUL), or 0 if
 * the variable cannot be expanded. Returning a value >= `buf_size`
 * is invalid and causes the evaluation to fail closed.
 */
typedef size_t (*sg_expand_var_fn)(const char *name, char *buf, size_t buf_size,
                                   void *user_ctx);

/*
 * Glob expansion callback.  Write a space-separated list of
 * matches for `pattern` into `buf`. Return bytes written
 * (excluding NUL), or 0 if no matches. Patterns longer than 255 bytes
 * are not passed to the callback; the evaluation reports SG_ERR_TRUNC.
 * Returning a value >= `buf_size` is invalid and causes the evaluation
 * to fail closed.
 */
typedef size_t (*sg_expand_glob_fn)(const char *pattern, char *buf,
                                    size_t buf_size, void *user_ctx);

/* --- LIFECYCLE --- */

sg_gate_t *sg_gate_new(void);
void sg_gate_free(sg_gate_t *gate);

/* --- ANOMALY DETECTION CONFIGURATION --- */

/*
 * Enable statistical anomaly detection on the gate.
 *
 * Creates an empty anomaly model. Scores are stored in sg_result_t by sg_eval.
 * Returns SG_ERR_INVALID for invalid parameters or SG_ERR_MEMORY on failure.
 */
sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate, double threshold,
                                  double alpha, double unk_prior);

/* Disable anomaly detection.  Frees the model. */
void sg_gate_disable_anomaly(sg_gate_t *gate);

/*
 * Set update mode for anomaly learning.
 *
 * If `update_only_on_allow` is true, the model is only updated when
 * the overall verdict is SG_VERDICT_ALLOW (not on deny/reject).
 * Default: false (model is updated on every sg_eval call regardless
 * of verdict, as long as anomaly_detected is false).
 */
sg_error_t sg_gate_set_anomaly_update_mode(sg_gate_t *gate,
                                           bool update_only_on_allow);

/*
 * Set whether to skip learning from anomalous commands.
 * If `skip_on_anomaly` is true, the model is NOT updated when
 * `anomaly_detected` is true (score exceeds threshold), even if
 * the verdict is ALLOW.  This prevents poisoning the model with
 * suspicious commands.
 * Default: true (skip anomalous commands).
 */
sg_error_t sg_gate_set_anomaly_update_on_non_anomaly(sg_gate_t *gate,
                                                     bool skip_on_anomaly);

/*
 * Set weights for hybrid anomaly scoring.
 *
 * The combined score is:
 *   combined = weight_raw * score_raw + weight_type * score_type
 *
 * Weights must be finite, non-negative, and sum to 1.0.
 * Default: weight_raw=0.5, weight_type=0.5.
 *
 * To disable the type model, set weight_type=0.0 and weight_raw=1.0.
 * To use only the type model, set weight_raw=0.0 and weight_type=1.0.
 */
sg_error_t sg_gate_set_anomaly_weights(sg_gate_t *gate, double weight_raw,
                                       double weight_type);

/* Combination mode for raw and type anomaly scores.
 *
 * SG_ANOMALY_COMBINE_WEIGHTED (default):
 *   combined = w_raw * score_raw + w_type * score_type
 *   Scores in bits/command; threshold is compared directly.
 *
 * SG_ANOMALY_COMBINE_BAYESIAN:
 *   Each model's score is converted to a log-odds ratio using an empirical
 *   CDF built from observed normal scores, then combined by summation in
 *   log-odds space. Higher combined values are more anomalous. Falls back to
 *   WEIGHTED until enough normal scores have been observed
 *   (anomaly_window_size samples, or 128 if adaptive is off).
 */
typedef enum {
  SG_ANOMALY_COMBINE_WEIGHTED = 0,
  SG_ANOMALY_COMBINE_BAYESIAN = 1
} sg_anomaly_combine_mode_t;

/* Set the score combination method.  Default: WEIGHTED.
 * Returns SG_ERR_INVALID if gate is NULL. */
sg_error_t sg_gate_set_anomaly_combine_mode(sg_gate_t *gate,
                                            sg_anomaly_combine_mode_t mode);

/*
 * Enable or disable adaptive threshold mode.
 *
 * When adaptive=true:
 *   - A rolling window of `window_size` scores from non-anomalous commands
 *     is maintained.
 *   - The threshold is computed as mean + k * stddev of the window.
 *   - Until the window is full, the fixed threshold (from
 * sg_gate_enable_anomaly) is used as fallback.
 *
 * When adaptive=false:
 *   - Reverts to the fixed threshold.
 *   - Frees the window buffer.
 *
 * Returns SG_ERR_INVALID if gate is NULL, or if adaptive=true and
 * window_size==0. Returns SG_ERR_MEMORY if buffer allocation fails.
 */
sg_error_t sg_gate_set_anomaly_adaptive(sg_gate_t *gate, bool adaptive,
                                        size_t window_size);

/*
 * Set the k multiplier for the adaptive threshold (default 3.0).
 * Threshold = mean + k * stddev.
 *
 * Only meaningful when adaptive threshold is enabled.
 * Returns SG_ERR_INVALID if gate is NULL, k is not finite, or k < 0.
 */
sg_error_t sg_gate_set_anomaly_k_factor(sg_gate_t *gate, double k);

/*
 * Set the type sequence cache size (default 0 = disabled).
 *
 * When cache_size > 0, an LRU cache stores type sequences for recently
 * evaluated commands, avoiding recomputation of shell_build_type_sequence
 * on repeated commands. The cache evicts the least-recently-used entry
 * when full.
 *
 * Call before or after sg_gate_enable_anomaly. Setting cache_size=0
 * frees the cache.
 *
 * Returns SG_ERR_INVALID if gate is NULL or cache_size > 8192.
 * Returns SG_ERR_MEMORY if allocation fails.
 */
sg_error_t sg_gate_set_anomaly_cache_size(sg_gate_t *gate, size_t cache_size);

/*
 * Atomically save the raw and type anomaly models as one versioned bundle.
 * The bundle is intentionally not compatible with standalone sg_anomaly v3
 * files or the former `{path}_type` sidecar convention.
 */
sg_error_t sg_gate_save_anomaly_model(const sg_gate_t *gate, const char *path);

/*
 * Transactionally load both anomaly models from a gate bundle. Existing
 * models are preserved on every failure. Returns SG_ERR_PARSE for malformed
 * or incompatible bundles, SG_ERR_MEMORY for allocation failure, and
 * SG_ERR_IO for filesystem failure.
 */
sg_error_t sg_gate_load_anomaly_model(sg_gate_t *gate, const char *path);

/*
 * Returns true if the anomaly model has had an allocation failure.
 */
bool sg_gate_anomaly_had_error(const sg_gate_t *gate);

/*
 * Returns the number of unique commands in the anomaly model.
 */
size_t sg_gate_anomaly_vocab_size(const sg_gate_t *gate);

/* --- CONFIGURATION --- */

/*
 * Strict mode (enabled by default):
 * The fast parser rejects ambiguous input as a parse error, including:
 *   - Control characters (0x01-0x1F, 0x7F)
 *   - High bytes (0x80-0xFF)
 *   - Unclosed quotes (in strict mode only)
 *   - Unclosed braces in ${VAR} expressions
 *
 * This is always enabled for security hardening.  Permissive mode
 * (strict_mode=false) is not exposed publicly.
 * `sg_gate_set_cwd()` returns SG_ERR_TRUNC and preserves the previous value
 * when `cwd` does not fit the gate's fixed storage.
 */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd);
sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask);
sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode);
sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled);

sg_error_t sg_gate_set_expand_var(sg_gate_t *gate, sg_expand_var_fn fn,
                                  void *user_ctx);
sg_error_t sg_gate_set_expand_glob(sg_gate_t *gate, sg_expand_glob_fn fn,
                                   void *user_ctx);

/*
 * Stores a shallow copy of `config`. All strings referenced by its arrays
 * must remain valid and unchanged until the gate is destroyed or another
 * violation configuration is installed.
 */
sg_error_t sg_gate_set_violation_config(sg_gate_t *gate,
                                        const sg_violation_config_t *config);

/* --- POLICY MANAGEMENT --- */

/* Loads and atomically appends rules to the existing allow policy. Malformed
 * policy data returns SG_ERR_PARSE; allocation and I/O failures preserve the
 * current policy and return SG_ERR_MEMORY and SG_ERR_IO respectively. */
sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path);
/* Policy persistence reports allocation and I/O failures distinctly. */
sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path);
/* Invalid patterns and policy capacity limits return SG_ERR_INVALID;
 * allocation failures return SG_ERR_MEMORY without changing the policy. */
sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_rule_count(const sg_gate_t *gate);
sg_error_t sg_gate_add_deny_rule(sg_gate_t *gate, const char *pattern);
sg_error_t sg_gate_remove_deny_rule(sg_gate_t *gate, const char *pattern);
uint32_t sg_gate_deny_rule_count(const sg_gate_t *gate);

/* --- EVALUATION --- */

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
 * A result with `SG_VERDICT_ALLOW_CONDITIONAL` contains a substitution
 * dependency. This API does not assume Bash or any specific executor; the
 * caller decides whether its execution mode can honor that dependency.
 *
 * Returns SG_OK on success, SG_ERR_PARSE for malformed input, SG_ERR_TRUNC if
 * the output buffer or bounded
 *   subcommand result array was too small (partial results are still valid),
 *   or SG_ERR_INVALID for bad args.  Inspect `truncated`, `subcmd_truncated`,
 *   and `violation_truncated` to identify the truncated result category.
 *   Any truncated result leaves the verdict SG_VERDICT_UNDETERMINED rather
 *   than authorizing incomplete output or an evaluated prefix.
 *
 * Early-stop modes preserve their prefix verdict. When parsed subcommands
 * remain unevaluated, `short_circuited` is true; callers authorizing the whole
 * input must require it to be false.
 */
sg_error_t sg_eval(sg_gate_t *gate, const char *cmd, size_t cmd_len, char *buf,
                   size_t buf_size, sg_result_t *out);

/*
 * Estimate minimum output buffer size needed for a command of `cmd_len` bytes.
 * Returns an estimate for command text and fixed result metadata; expansion
 * callbacks and violation details can require additional buffer space.
 */
size_t sg_eval_size_hint(size_t cmd_len);

/* --- SUGGESTION TOKEN VARIANTS (for TUI edit mode) --- */

/**
 * Given a suggestion pattern and a token position, return the observed
 * type variants at that position from the policy trie.
 *
 * Walks gate->pctx trie using the pattern. At edit_pos, reads
 * child->observed_types and returns types from most-specific to most-general:
 * [current_type, ..., *].
 *
 * @param gate         The gate (policy from gate->policy)
 * @param pattern      Suggestion pattern string (e.g., "timeout #num ls")
 * @param edit_pos     Token position to get variants for (0-indexed)
 * @param out_variants Output array (caller allocates, ST_MAX_TOKEN_VARIANTS)
 * @param max_variants Capacity of out_variants
 * @return Number of variants written (0 if position not found or invalid)
 */
size_t sg_gate_suggestion_token_variants_at(sg_gate_t *gate,
                                            const char *pattern,
                                            size_t edit_pos,
                                            st_token_variant_t *out_variants,
                                            size_t max_variants);

/* --- RESULT HELPERS --- */

const char *sg_verdict_name(sg_verdict_t v);
uint32_t sg_result_violation_dropped(const sg_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* SHELLGATE_H */
