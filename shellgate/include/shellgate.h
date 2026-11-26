/*
 * shellgate.h - Shell command policy gate
 *
 * Evaluates shell commands with Shellsplit parsing and Shelltype policies.
 * Result strings reference the caller-provided output buffer; result arrays
 * have fixed capacities. Gates are not synchronized.
 */

#ifndef SHELLGATE_H
#define SHELLGATE_H

#include "shell_contract.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* shelltype provides suggestion and token-variant result types. */
#include "sg_anomaly.h"
#include "shell_expand.h"
#include "shell_tokenizer.h"
#include "shelltype.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- CONSTANTS --- */

#define SG_MAX_SUBCOMMAND_RESULTS 64

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
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_ARITH) != 0,
                 "ARITH bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_HEREDOC) != 0,
                 "HEREDOC bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_HERESTRING) != 0,
                 "HERESTRING bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_LOOPS) != 0,
                 "LOOPS bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_CONDITIONALS) != 0,
                 "CONDITIONALS bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_CASE) != 0,
                 "CASE bit mismatch");
SG_STATIC_ASSERT((SG_REJECT_MASK_DEFAULT & SHELL_FEAT_IF) == 0,
                 "IF is modeled and allowed by default");
SG_STATIC_ASSERT(SG_REJECT_MASK_DEFAULT ==
                     (SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC |
                      SHELL_FEAT_HERESTRING | SHELL_FEAT_LOOPS |
                      SHELL_FEAT_CONDITIONALS | SHELL_FEAT_CASE),
                 "the default mask holds exactly these features");
#undef SG_STATIC_ASSERT

/* Baseline capacity for diagnostic-only buffers. A successful evaluation also
 * needs the bounded depgraph workspace in the same caller buffer; use
 * sg_gate_evaluate_size_hint() to size ordinary evaluation buffers. */
#define SG_DIAGNOSTIC_BUF_MIN 8192

/* --- TYPES --- */

typedef enum {
  SG_OK = 0,
  /* The source is valid but blank: whitespace, comments and escaped line
   * endings only, so it has no command to evaluate. This is not an error. */
  SG_BLANK = 1,
  SG_ERR_INVALID = -1,
  SG_ERR_MEMORY = -2,
  SG_ERR_PARSE = -3,
  SG_ERR_TRUNC = -4,
  SG_ERR_IO = -5,
  SG_ERR_EXPAND = -6,
  /* Shellsplit has no dependency model capturing every requirement for a
   * safe run of the source (SHELL_DEP_EUNMODELED), although its syntax may be
   * valid: it must not be executed. The verdict is SG_VERDICT_REJECT. */
  SG_ERR_UNMODELED = -7,
} sg_error_t;

/* Outcomes. A policy is installed with one of the policy outcomes:
 *   ALLOW, AUDIT, DISCOURAGE, REVIEW, NEEDS_REASON, DENY, DENY_ESCALATE.
 * The gate itself also produces REJECT (the source cannot be evaluated),
 * UNDETERMINED (no policy matched, or evaluation could not complete). The
 * intended meanings, which the application carries out:
 *   AUDIT           permitted; the application records the command.
 *   DISCOURAGE      a weak allow: advise the agent not to run it. It is not a
 *                   denial, and the agent may proceed if it persists.
 *   REVIEW          a reviewer decides.
 *   NEEDS_REASON    denied until the reason to run it has been explained and
 *                   audited.
 *   DENY            denied.
 *   DENY_ESCALATE   harder than DENY: stop the agent and escalate to its
 *                   parent agent or the user.
 * The library gives an outcome no behavior beyond its place in the order
 * below.
 *
 * A gate gives each subcommand one result per output (see OUTPUTS AND
 * OVERRIDES); a gate that declares none has one output, the most restrictive
 * outcome among the policies the subcommand matched. A subcommand's scalar
 * verdict is the most restrictive of its outputs, and a command's output is
 * its most restrictive subcommand's, with the scalar again the most restrictive
 * output. From most to least restrictive:
 *   REJECT, DENY_ESCALATE, DENY, NEEDS_REASON, REVIEW, UNDETERMINED,
 *   DISCOURAGE, AUDIT, ALLOW.
 * ALLOW, AUDIT and DISCOURAGE are the permitting outcomes: none of them is a
 * denial, and a command whose subcommands all permit is itself permitted.
 * The policies that matched stay visible through
 * sg_subcommand_result_t.matched_policies, and the diagnostic of a discouraged
 * subcommand through its reject_reason.
 *
 * A verdict is what the policies decided. What must hold for the input to run
 * as analyzed is separate: the `requirements` of a result, which Shellsplit
 * states and the gate passes on unchanged. A verdict never absorbs them. */
typedef enum {
  SG_VERDICT_ALLOW = 0,
  SG_VERDICT_DENY = 1,
  SG_VERDICT_REJECT = 2,
  SG_VERDICT_UNDETERMINED = 3,
  SG_VERDICT_REVIEW = 4,
  SG_VERDICT_AUDIT = 5,
  SG_VERDICT_NEEDS_REASON = 6,
  SG_VERDICT_DISCOURAGE = 7,
  SG_VERDICT_DENY_ESCALATE = 8,
} sg_verdict_t;

/* How evaluation stops early. The modes act on each subcommand's scalar
 * verdict (or on whether it matched any policy). */
typedef enum {
  SG_STOP_FIRST_FAIL = 0,
  SG_STOP_FIRST_PASS = 1, /* stops after first subcommand matching any policy */
  SG_STOP_FIRST_ALLOW = 2, /* stops after first ALLOW verdict */
  SG_STOP_FIRST_DENY = 3,  /* stops after first DENY verdict */
  /* Stops after the first subcommand whose verdict equals the outcome chosen
   * with sg_gate_set_stop_outcome() (default ALLOW). */
  SG_STOP_FIRST_OUTCOME = 4,
  SG_EVAL_ALL = 5,
} sg_stop_mode_t;

/* One output of the gate: a verdict, and the policy whose outcome produced it.
 * A gate has as many outputs as the caller declared (see sg_gate_add_output),
 * so its verdict can be one value or several dimensions. */
#define SG_MAX_OUTPUTS 8
typedef struct {
  sg_verdict_t verdict;
  /* Index of the policy that decided it (see sg_gate_policy_at), or UINT32_MAX
   * when no policy applied or the verdict is gate-produced (REJECT, a floor).
   */
  uint32_t policy;
  /* The deciding policy's user pointer (st_policy_user_data) as it was when the
   * call evaluated, so the application's own record is at hand without the gate
   * or the index; NULL when there is no deciding policy or none was set. It is
   * never interpreted by the library. */
  void *user_data;
} sg_output_t;

/* Per-subcommand result: lightweight, pointers into output buffer. */
typedef struct {
  /* True when at least one installed policy matched this subcommand. */
  bool matches;
  /* The most restrictive of `outputs`: a one-value summary. */
  sg_verdict_t verdict;
  /* The user pointer (see sg_output_t.user_data) of the policy that decided
   * `verdict`, when exactly one output is the most restrictive. If several
   * outputs tie, no single policy decided it: NULL. A gate with one output
   * always has one. The scalar is only a summary; the chain behind it is in
   * `outputs`. */
  void *deciding_user_data;
  /* One result per gate output, in the order they were declared; one for a
   * gate that declared none. See OUTPUTS AND OVERRIDES. */
  sg_output_t outputs[SG_MAX_OUTPUTS];
  uint32_t output_count;
  /* Bit i is set when the policy at index i (see sg_gate_policy_at) matched,
   * so `matches` is `matched_policies != 0`. Every installed policy is
   * evaluated: an earlier match never hides a later one, and overrides do not
   * remove a match from this mask. Indexes are stable until
   * sg_gate_remove_policy. A policy that matches nothing is not an error;
   * the only failure is an allocation inside a policy, which leaves every
   * output UNDETERMINED and is reported by the call. */
  uint32_t matched_policies;
  /* Readable diagnostic display only. It is lossy and must never be parsed. */
  const char *display_command;
  /* Canonical argv used for policy evaluation and all programmatic handling.
   * This is authoritative. Both pointers refer into the caller buffer. */
  const char *netargv;
  size_t netargv_length;
  /* SG_EXPANSION_UNRESOLVED_* bits for this command and inherited group I/O:
   * policy may still match processed source, not fully expanded runtime values.
   * Protected semantic operands also count, independently of rendering.
   * Resolving a containing word does not resolve nested file-substitution
   * operands. Reached pathname expansions count even if the open then fails.
   */
  uint32_t unresolved_expansion_flags;
  const char *reject_reason;

  /* Direct I/O plus I/O owned by an enclosing compound group. write_count also
   * includes output-file setup that the shell performs before a later redirect
   * replaces that descriptor. These are effective evaluation context counts,
   * not claims of direct command byte-flow edges. Inherited boundary FD routes
   * are not explicit redirect effects and do not contribute to these counts. */
  uint32_t write_count;
  uint32_t read_count;
  uint32_t env_count;
  /* What Shellsplit states must hold for this command to run as analyzed,
   * passed on unchanged: the union of the edge flags
   * SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD (a route delivers runtime-generated
   * word content directly to this command or to an enclosing compound group
   * that it may inherit; the content must be inspected in its receiving role)
   * and SHELL_DEP_EDGE_FLAG_REQUIRED, which a subcommand does not carry: see
   * sg_result_t.requirements. A dynamic FILE-name route alone selects I/O
   * topology and sets nothing. Empty when nothing is outstanding. */
  uint32_t requirements;
  /* True when any represented dynamic substitution route reaches this command
   * or an enclosing compound group. This includes FILE names supplied by
   * substitution routes, ordinary process-substitution I/O, and setup-only
   * input redirects such as `exec {fd}< <(producer)` or `< <(producer)`.
   * Output setup is source-only
   * and marks its downstream substitution consumer instead. Setup is topology
   * only: it does not by itself state a requirement or claim code execution or
   * risk. */
  bool has_dynamic_substitution_io;
  /* Structural relationships, group membership, background execution, and
   * pipeline timing belong to Shellsplit's dependency graph, not this policy
   * result. Applications needing topology use Shellsplit directly. */
} sg_subcommand_result_t;

/* Outcome of the deferred anomaly-model update for one completed evaluation.
 * SG_OK describes evaluation and policy handling; inspect this field when a
 * caller needs to know whether the evaluated sample actually entered the
 * anomaly model. Resource failures intentionally remain non-fatal to normal
 * gate evaluation, but are observable here. */
typedef enum {
  SG_ANOMALY_UPDATE_NOT_ATTEMPTED = 0,
  SG_ANOMALY_UPDATE_APPLIED,
  SG_ANOMALY_UPDATE_SKIPPED_DETECTED,
  SG_ANOMALY_UPDATE_SKIPPED_VERDICT,
  SG_ANOMALY_UPDATE_REJECTED_LIMIT,
  SG_ANOMALY_UPDATE_FAILED_MEMORY,
  SG_ANOMALY_UPDATE_FAILED_FORMAT,
} sg_anomaly_update_t;

/* Top-level evaluation result: metadata + pointer array into buffer.
 */
typedef struct {
  /* The most restrictive of `outputs`: a one-value summary. */
  sg_verdict_t verdict;
  /* The user pointer (see sg_output_t.user_data) of the policy that decided
   * `verdict`, when exactly one output is the most restrictive. If several
   * outputs tie, no single policy decided it: NULL. A gate with one output
   * always has one. The scalar is only a summary; the chain behind it is in
   * `outputs`. */
  void *deciding_user_data;
  /* One result per gate output, in the order they were declared (one for a
   * gate that declared none). Each is the most restrictive of that output over
   * the subcommands. */
  sg_output_t outputs[SG_MAX_OUTPUTS];
  uint32_t output_count;
  const char *deny_reason;

  sg_subcommand_result_t subcommands[SG_MAX_SUBCOMMAND_RESULTS];
  uint32_t subcommand_count;

  const char *suggestions[2];
  uint32_t suggestion_count;

  const char *deny_suggestions[2];
  uint32_t deny_suggestion_count;

  uint32_t attention_index;
  bool truncated;
  bool subcommand_truncated;
  /* True when the configured stop mode deliberately left parsed
   * subcommands unevaluated. The verdict then describes only the evaluated
   * prefix; this is distinct from capacity or output truncation. */
  bool short_circuited;

  /* What Shellsplit states must hold for the input to run as analyzed, passed
   * on unchanged from the dependency graph and not recomputed here: the union
   * over all its edges of SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD (runtime-
   * generated word content, to be inspected in its receiving role) and
   * SHELL_DEP_EDGE_FLAG_REQUIRED (a redirection open that must succeed, which
   * the application checks or provides before running). It covers edges whose
   * endpoints were not retained in the bounded result prefix. The routes and
   * edges behind each flag are in Shellsplit's graph; applications read them
   * there. Empty when nothing is outstanding. A verdict holds only while these
   * are satisfied: the gate never folds them into it. */
  uint32_t requirements;
  /* True when any represented dynamic substitution I/O path exists, including
   * FILE names supplied by substitution routes and process-substitution
   * descriptor setup/routes whose endpoint was not retained in the bounded
   * result prefix. A FILE name that is only an unresolved parameter sets
   * `unresolved_expansion_flags`, not this flag. This is not a risk
   * classification. */
  bool has_dynamic_substitution_io;
  /* Aggregate unresolved argv/path/conditional/arithmetic information over the
   * retained constructed graph, including group-owned I/O and commands omitted
   * by policy early-stop or output truncation, including nested pathname
   * expansions whose final I/O edge disappeared after a failed open.
   * Independent of rendering. A truncated graph covers only retained metadata;
   * failures before graph construction completes do not provide complete
   * expansion information. */
  uint32_t unresolved_expansion_flags;

  /* Anomaly detection */
  /*
   * anomaly_score: bits per anomaly stage (higher = more anomalous).
   *                 Stages include supported nested command, backtick,
   *                 process, and heredoc-body substitutions in Shellsplit's
   *                 deterministic child-before-parent analysis order.
   * Unresolved conditional arithmetic can be scored as a lexical stage
   *                 sequence; it blocks policy allowance and model/history
   *                 updates until resolved.
   *                 This is distinct from subcommand_count, which
   *                 describes policy-evaluable graph commands. A redirect-only
   *                 simple command is one anomaly stage even though it has no
   *                 policy-evaluable argv; a structural empty Bash `time`
   *                 pipeline is also one anomaly stage, without implying I/O.
   *                 0.0 for sequences with fewer than
   *                 three stages.
   *                 INFINITY if model cannot score (e.g., empty model).
   *
   * anomaly_detected: true if anomaly_score is finite and above threshold.
   *                    Always false for sequences with < 3 stages.
   *
   * anomaly_score_raw:  score from the raw command-name model (bits/stage).
   * anomaly_score_type: score from the type-sequence model (bits/stage).
   *                      0.0 if the type model is disabled, or if either the
   *                      raw or type sequence has < 3 aligned entries.
   */
  bool anomaly_detected;
  double anomaly_score;
  double anomaly_score_raw;
  double anomaly_score_type;
  /* See sg_anomaly_update_t. Defaults to NOT_ATTEMPTED when anomaly learning
   * is disabled, no canonical stages exist, or evaluation did not complete. */
  sg_anomaly_update_t anomaly_update;
} sg_result_t;

typedef struct sg_gate sg_gate_t;

enum {
  SG_EXPANSION_UNRESOLVED_ARGV = 1u << 0,
  SG_EXPANSION_UNRESOLVED_PATH = 1u << 1,
  /* An expanded conditional string remains unresolved, independently of argv.
   */
  SG_EXPANSION_UNRESOLVED_CONDITION = 1u << 2,
  /* Numeric conditional contents may introduce unmodeled arithmetic effects.
   * This blocks ALLOW until a pure dependency-resolved value is supplied. */
  SG_EXPANSION_UNRESOLVED_ARITHMETIC = 1u << 3,
};

/* --- LIFECYCLE --- */

sg_gate_t *sg_gate_new(void);
void sg_gate_free(sg_gate_t *gate);

/* Create a gate with supplied allow/deny policies instead of empty policies.
 * Owned inputs are distinct, exclusively caller-owned objects. Ownership
 * transfers only on success; on allocation failure the caller still owns both.
 * Borrowed inputs remain owned by the application (or another gate), which
 * must keep them alive until all borrowing gates detach and readers finish.
 * Installed policies are logically immutable: do not mutate, load, compact,
 * clear or free them. Evaluation can warm caches and update statistics.
 * Policies need not share a context; each policy retains its own context. */
sg_gate_t *sg_gate_new_with_policies_owned(st_policy_t *allow,
                                           st_policy_t *deny)
    SHELL_NONNULL(1, 2);
sg_gate_t *sg_gate_new_with_policies_borrowed(const st_policy_t *allow,
                                              const st_policy_t *deny)
    SHELL_NONNULL(1, 2);

/* Replace one policy without allocating or copying its rules. Owned setters
 * transfer exclusive ownership of a caller-owned replacement to this gate;
 * the replacement must not have another owner. Existing borrowed views do
 * not prevent ownership transfer, provided their lifetime remains valid.
 * Borrowed setters retain only a logical read-only view of a policy owned by
 * the application or another gate. That owner must keep the policy alive
 * until all borrowers detach and all readers and borrowed views finish.
 * The retired policy is freed only if this gate owned it. Neither kind of
 * replacement may alias an owned policy destroyed by this operation. Before
 * destroying the retired policy, detach every gate borrowing it and finish
 * its readers and borrowed views.
 * Serialize replacement/destruction against evaluation of this gate. Build
 * replacements with Shelltype before installation, never through these views.
 * These caller lifetime/ownership requirements are not checked at runtime. */
void sg_gate_set_allow_policy_owned(sg_gate_t *gate, st_policy_t *policy)
    SHELL_NONNULL(1, 2);
void sg_gate_set_deny_policy_owned(sg_gate_t *gate, st_policy_t *policy)
    SHELL_NONNULL(1, 2);
void sg_gate_set_allow_policy_borrowed(sg_gate_t *gate,
                                       const st_policy_t *policy)
    SHELL_NONNULL(1, 2);
void sg_gate_set_deny_policy_borrowed(sg_gate_t *gate,
                                      const st_policy_t *policy)
    SHELL_NONNULL(1, 2);

/* Borrow the installed logical read-only policy. Never mutate or free it.
 * Its gate association expires at replacement or gate destruction; an owned
 * retired policy is destroyed then. Shared policy statistics are aggregate,
 * not per gate. Use Shelltype directly for evaluation, inspection and save. */
const st_policy_t *sg_gate_allow_policy_borrowed(const sg_gate_t *gate)
    SHELL_NONNULL(1);
const st_policy_t *sg_gate_deny_policy_borrowed(const sg_gate_t *gate)
    SHELL_NONNULL(1);

/* --- POLICY LIST --- */

/* A gate holds an ordered list of policies, each installed with an outcome.
 * Index 0 is the allow policy and index 1 the deny policy: they always exist,
 * carry outcomes ALLOW and DENY, and are the ones replaced by the setters
 * above. Policies added below follow from index 2 in installation order.
 * Every policy is evaluated against every subcommand. Suggestions come from
 * indexes 0 and 1 only. A policy may be installed in several gates by
 * borrowing it, and the same policy may appear more than once.
 *
 * Ownership and lifetime follow the rules above: an owned policy is
 * exclusively the gate's and is freed with it or on removal; a borrowed one
 * must outlive every gate and reader that uses it and is never mutated while
 * installed. Neither is checked at runtime.
 *
 * outcome must be one of ALLOW, AUDIT, DISCOURAGE, REVIEW, NEEDS_REASON,
 * DENY, DENY_ESCALATE; any other value is SG_ERR_INVALID. A gate holds at
 * most SG_MAX_POLICIES; adding beyond that is SG_ERR_INVALID. On any error the
 * gate is unchanged and the caller still owns an owned policy. */
#define SG_MAX_POLICIES 16

sg_error_t sg_gate_add_policy_owned(sg_gate_t *gate, st_policy_t *policy,
                                    sg_verdict_t outcome) SHELL_NONNULL(1, 2);
sg_error_t sg_gate_add_policy_borrowed(sg_gate_t *gate,
                                       const st_policy_t *policy,
                                       sg_verdict_t outcome)
    SHELL_NONNULL(1, 2);

/* Remove the policy at index, which must satisfy 2 <= index < count: the allow
 * and deny policies are replaced, not removed. Later policies move down one
 * index, so matched_policies bits of earlier results no longer name them.
 * An owned policy is freed. Serialize against evaluation of this gate. */
void sg_gate_remove_policy(sg_gate_t *gate, uint32_t index) SHELL_NONNULL(1);

uint32_t sg_gate_policy_count(const sg_gate_t *gate) SHELL_NONNULL(1);

/* The installed policy at index, which must be < sg_gate_policy_count(). Never
 * mutate or free it. `outcome` is optional and receives the installed outcome.
 * The policy's user pointer (st_policy_user_data) is the application's link
 * from a matched index to its own data. */
const st_policy_t *sg_gate_policy_at(const sg_gate_t *gate, uint32_t index,
                                     sg_verdict_t *outcome) SHELL_NONNULL(1);

/* --- OUTPUTS AND OVERRIDES ---
 *
 * The caller chooses what a gate answers. Each declared output is one result
 * per subcommand, so a gate can give one verdict or a vector of them, one per
 * dimension.
 *
 * A relation "a overrides b" is its own object: a stands in front of b. It
 * connects two installed policies and is added with one call; the same two
 * policies may be related again by another relation. An output is rooted at a
 * policy and names the relations that make up its chain, so the same policies
 * can appear in many outputs with different continuations, and a relation can
 * be shared by several outputs.
 *
 * An output is its root's outcome when the root matched. When the root did not
 * match, it cannot override anything, and the output is what the policies it
 * stands in front of deliver: the output's relations from that policy are
 * tried in the order they were created, depth first, and the first policy that
 * matched decides. A chain a->b->c therefore reads as "first matching of a, b,
 * c". When nothing along the relations matched, the output is UNDETERMINED.
 * Each policy is visited once per output, so a cycle is harmless: with
 * relations a->b and b->a, an output rooted at a is a overriding b and one
 * rooted at b is b overriding a, two results.
 *
 * Relations matter only to the outputs that name them. A gate that declares no
 * outputs has one output, the most restrictive of all matches.
 * `result.verdict` and `subcommand.verdict` project the vector down to a scalar
 * as the most restrictive output; callers that use several dimensions read
 * `outputs`.
 *
 * The library cannot check that an overrider is really more specific than
 * what it overrides: one that is too broad lets its outcome replace a stricter
 * one.
 *
 * Policy and relation indexes are positions in their lists. Removing a policy
 * removes the relations that name it, drops the outputs rooted at it, and
 * renumbers the rest. */
#define SG_MAX_RELATIONS 64

/* Add the relation "the policy at `overrider` overrides the policy at
 * `overridden`" and store its id in `relation`. Returns SG_ERR_INVALID,
 * changing nothing, if either is not an installed policy, they are the same, or
 * SG_MAX_RELATIONS relations exist. */
sg_error_t sg_gate_add_override(sg_gate_t *gate, uint32_t overrider,
                                uint32_t overridden, uint32_t *relation)
    SHELL_NONNULL(1, 4);

/* The relation with id `relation`, which must be below
 * sg_gate_relation_count(). */
uint32_t sg_gate_relation_count(const sg_gate_t *gate) SHELL_NONNULL(1);
void sg_gate_relation_at(const sg_gate_t *gate, uint32_t relation,
                         uint32_t *overrider, uint32_t *overridden)
    SHELL_NONNULL(1, 3, 4);

/* Declare an output rooted at the policy at `root`, after the ones already
 * declared, that follows the `relation_count` relations whose ids are listed in
 * `relations`; `relations` may be NULL when the count is 0. The same root may
 * appear in several outputs. At most SG_MAX_OUTPUTS. Returns SG_ERR_INVALID,
 * changing nothing, for a root that is not installed, an id that is not a
 * relation, or when the outputs are full. */
sg_error_t sg_gate_add_output(sg_gate_t *gate, uint32_t root,
                              const uint32_t *relations,
                              uint32_t relation_count) SHELL_NONNULL(1);

/* The number of declared outputs, 0 for the implicit single output. */
uint32_t sg_gate_output_count(const sg_gate_t *gate) SHELL_NONNULL(1);

/* Remove every declared output, or every relation (which empties the relation
 * lists of the outputs). */
void sg_gate_clear_outputs(sg_gate_t *gate) SHELL_NONNULL(1);
void sg_gate_clear_overrides(sg_gate_t *gate) SHELL_NONNULL(1);

/* --- ANOMALY DETECTION CONFIGURATION --- */

/*
 * Enable statistical anomaly detection on the gate.
 *
 * Creates paired empty anomaly models using `config`. A NULL config selects
 * sg_anomaly_config_default(). Scores are stored in sg_result_t by
 * sg_gate_evaluate. Successful replacement clears calibration observations;
 * the configured adaptive window and k-factor are retained. The fixed
 * threshold is used during adaptive warm-up, in the current score units
 * (bits/stage for weighted scoring, log-odds for ready Bayesian scoring).
 * Returns SG_ERR_INVALID for an invalid threshold or
 * explicit config, and SG_ERR_MEMORY on allocation failure.
 */
sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate, double threshold,
                                  const sg_anomaly_config_t *config)
    SHELL_NONNULL(1);

/* Disable anomaly detection.  Frees the model. */
void sg_gate_disable_anomaly(sg_gate_t *gate) SHELL_NONNULL(1);

/*
 * Set update mode for anomaly learning.
 *
 * If `update_only_on_allow` is true, the model is only updated when
 * the overall verdict is SG_VERDICT_ALLOW and the result states no
 * `requirements`: a command with something still to inspect or provide is not
 * yet approved (not on deny/reject, nor on a pending requirement).
 * Default: false (model is updated on every sg_gate_evaluate call
 * regardless of verdict, as long as anomaly_detected is false).
 */
sg_error_t sg_gate_set_anomaly_update_mode(sg_gate_t *gate,
                                           bool update_only_on_allow)
    SHELL_NONNULL(1);

/*
 * Set whether to skip learning from anomalous stages.
 * If `skip` is true, the model is NOT updated when
 * `anomaly_detected` is true (score exceeds threshold), even if
 * the verdict is ALLOW.  This prevents poisoning the model with
 * suspicious stages.
 * Default: true (skip anomalous stages).
 */
sg_error_t sg_gate_set_anomaly_skip_on_detected(sg_gate_t *gate, bool skip)
    SHELL_NONNULL(1);

/*
 * Set weights for hybrid anomaly scoring.
 *
 * In weighted mode, including Bayesian warm-up, the combined score is:
 *   combined = weight_raw * score_raw + weight_type * score_type
 *
 * Weights must be finite, non-negative, and sum to 1.0.
 * Default: weight_raw=0.5, weight_type=0.5.
 *
 * To disable the type model, set weight_type=0.0 and weight_raw=1.0.
 * To use only the type model, set weight_raw=0.0 and weight_type=1.0.
 * Ready Bayesian scoring always combines both component log-odds and does
 * not use these weights. Changing weights resets adaptive observations only
 * when weighted scoring is currently effective; identical weights are a
 * no-op. Component distributions and model learning are preserved.
 */
sg_error_t sg_gate_set_anomaly_weights(sg_gate_t *gate, double weight_raw,
                                       double weight_type) SHELL_NONNULL(1);

/* Combination mode for raw and type anomaly scores.
 *
 * SG_ANOMALY_COMBINE_WEIGHTED (default):
 *   combined = w_raw * score_raw + w_type * score_type
 *   Scores in bits/stage; threshold is compared directly.
 *
 * SG_ANOMALY_COMBINE_BAYESIAN:
 *   Each model's score is converted to a log-odds ratio using an empirical
 *   CDF built from observed normal scores, then combined by summation in
 *   log-odds space. Higher combined values are more anomalous. Falls back to
 *   WEIGHTED until enough normal scores have been observed
 *   (the current adaptive window size, or 128 if adaptive is off).
 *   Readiness follows current settings, independent of setter order. The
 *   transition to ready Bayesian scoring clears the weighted adaptive window;
 *   log-odds calibration starts on the next successfully evaluated sample.
 */
typedef enum {
  SG_ANOMALY_COMBINE_WEIGHTED = 0,
  SG_ANOMALY_COMBINE_BAYESIAN = 1
} sg_anomaly_combine_mode_t;

/* Read-only result from scoring paired canonical anomaly sequences. */
typedef struct {
  double combined_score;
  double raw_score;
  double type_score;
  bool detected;
  size_t stage_count;
} sg_anomaly_sequence_score_t;

/* Set the score combination method. Default: WEIGHTED. Switching between
 * effective weighted and ready Bayesian scoring clears adaptive observations
 * and restarts fixed-threshold warm-up. Existing component distributions are
 * retained. Selecting the same effective regime does not reset calibration.
 * Allocation failure preserves the previous mode and all observations.
 * The gate pointer is required. */
sg_error_t sg_gate_set_anomaly_combine_mode(sg_gate_t *gate,
                                            sg_anomaly_combine_mode_t mode)
    SHELL_NONNULL(1);

/* Score matching outer netstring sequences using the gate's configured raw
 * and type models. This does not update either model, adaptive thresholds,
 * Bayesian histograms, or caches. Both sequences must be canonical and have
 * the same number of execution-stage records. */
sg_error_t sg_gate_score_anomaly_netseq(
    const sg_gate_t *gate, const char *raw_netseq, size_t raw_length,
    const char *type_netseq, size_t type_length,
    sg_anomaly_sequence_score_t *out) SHELL_NONNULL(1, 2, 4, 6);

/*
 * Enable or disable adaptive threshold mode.
 *
 * When adaptive=true:
 *   - A rolling window of `window_size` scores from non-anomalous stages
 *     is maintained.
 *   - The threshold is computed as mean + k * stddev of the window.
 *   - Until the window is full, the fixed threshold (from
 * sg_gate_enable_anomaly) is used as fallback.
 *   - Every successful enable/resize starts a fresh window. Bayesian
 *     component distributions are retained, and their readiness immediately
 *     uses the new window size.
 *
 * When adaptive=false:
 *   - Reverts to the fixed threshold.
 *   - Frees the window buffer.
 *   - Bayesian warm-up requires 128 normal observations, regardless of the
 *     previous adaptive window size.
 *
 * Returns SG_ERR_INVALID if adaptive=true and
 * window_size==0. Returns SG_ERR_MEMORY if buffer allocation fails, preserving
 * the previous window, readiness and observations.
 */
sg_error_t sg_gate_set_anomaly_adaptive(sg_gate_t *gate, bool adaptive,
                                        size_t window_size) SHELL_NONNULL(1);

/*
 * Set the k multiplier for the adaptive threshold (default 3.0).
 * Threshold = mean + k * stddev.
 *
 * Only meaningful when adaptive threshold is enabled.
 * Returns SG_ERR_INVALID if k is not finite or k < 0.
 */
sg_error_t sg_gate_set_anomaly_k_factor(sg_gate_t *gate, double k)
    SHELL_NONNULL(1);

/*
 * Set the type sequence cache size (default 0 = disabled).
 *
 * When cache_size > 0, an LRU cache stores type sequences for recently
 * evaluated command sources, avoiding recomputation by the paired anomaly
 * builder on repeated sources. The cache evicts the least-recently-used entry
 * when full.
 *
 * Call before or after sg_gate_enable_anomaly. Setting cache_size=0
 * frees the cache.
 *
 * Returns SG_ERR_INVALID if cache_size > 8192.
 * Returns SG_ERR_MEMORY if allocation fails.
 */
sg_error_t sg_gate_set_anomaly_cache_size(sg_gate_t *gate, size_t cache_size)
    SHELL_NONNULL(1);

/*
 * Atomically save the raw and type anomaly models as one versioned bundle.
 * The v2 bundle is intentionally not compatible with standalone sg_anomaly
 * files or the former `{path}_type` sidecar convention.
 * Existing regular files retain their mode; symlinks are replaced rather than
 * followed, and other file types are rejected. Failures before replacement
 * preserve the destination. A parent-directory synchronization failure can
 * report an error after the complete bundle is installed.
 * Filesystem-valid basenames need no extra room for a temporary suffix.
 * The complete save pathname, including NUL, must fit PATH_MAX; longer
 * spellings return SG_ERR_IO with errno ENAMETOOLONG before creating a file.
 * Permission and special mode bits are applied after serialization, subject
 * to OS permission rules; ownership is not copied. Temporary files remain
 * private until then.
 * Concurrent saves to the same path require external synchronization.
 */
sg_error_t sg_gate_save_anomaly_model(const sg_gate_t *gate, const char *path)
    SHELL_NONNULL(1, 2);

/*
 * Transactionally load both anomaly models from a gate bundle. Existing
 * models, calibration, and type-sequence cache are preserved on every failure.
 * The payload is read once into staging streams; its framing and checksum are
 * verified before either model is parsed or published. The checksum covers
 * exactly the staged bytes, not a separate read of a potentially changing file.
 * In-place changes may be rejected or leave an already-staged valid snapshot;
 * loading does not synchronize concurrent writers.
 * Successful loading clears adaptive observations, Bayesian component
 * distributions, and type-sequence cache entries; reusable storage and all
 * configured options are retained. Fixed-threshold warm-up
 * resumes for the loaded models. Returns SG_ERR_PARSE for malformed
 * or incompatible bundles, SG_ERR_MEMORY for allocation failure, and
 * SG_ERR_IO for filesystem failure.
 */
sg_error_t sg_gate_load_anomaly_model(sg_gate_t *gate, const char *path)
    SHELL_NONNULL(1, 2);

/*
 * Returns true if an anomaly model has had an allocation failure. This is a
 * sticky diagnostic; a failed, rolled-back update does not disable future
 * learning. Inspect sg_result_t.anomaly_update for the current evaluation.
 */
bool sg_gate_anomaly_had_error(const sg_gate_t *gate) SHELL_NONNULL(1);

/* Borrow the component models for direct read-only anomaly API operations.
 * NULL means disabled. Never mutate or free these models. Successful enable,
 * load, disable or gate destruction invalidates the handles; failed replacement
 * preserves them. Evaluation may learn in place. Serialize access against gate
 * evaluation, model replacement and destruction. */
const sg_anomaly_model_t *
sg_gate_anomaly_raw_model_borrowed(const sg_gate_t *gate) SHELL_NONNULL(1);
const sg_anomaly_model_t *
sg_gate_anomaly_type_model_borrowed(const sg_gate_t *gate) SHELL_NONNULL(1);

/* --- CONFIGURATION --- */

/*
 * Strict mode (enabled by default): the parser rejects malformed syntax,
 * including unclosed quotes and parameter expansions, and prohibited source
 * bytes. Comments, ordinary word literals and heredoc data admit high bytes
 * under scoped rules; executable children establish independent word contexts.
 * Arithmetic and selectors retain restricted code bytes. The executor fixes
 * LC_ALL to C/POSIX or UTF-8 as specified in the startup contract.
 * Literal NUL, DEL, and prohibited control bytes remain invalid.
 *
 * This is always enabled for security hardening.  Permissive mode
 * (strict_mode=false) is not exposed publicly.
 * `sg_gate_set_cwd()` returns SG_ERR_TRUNC and preserves the previous value
 * when `cwd` does not fit the gate's fixed storage.
 */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd)
    SHELL_NONNULL(1, 2);
sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask)
    SHELL_NONNULL(1);
sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode)
    SHELL_NONNULL(1);
/* The outcome SG_STOP_FIRST_OUTCOME stops on; a policy outcome as above, else
 * SG_ERR_INVALID and no change. */
sg_error_t sg_gate_set_stop_outcome(sg_gate_t *gate, sg_verdict_t outcome)
    SHELL_NONNULL(1);
sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled)
    SHELL_NONNULL(1);

/* Uses Shellsplit's public resolution contract. NULL fn disables resolution;
 * user_ctx is optional application state. Returned payloads must stay immutable
 * until sg_gate_evaluate() returns; its private graph does not escape that
 * call. Results are reused for graph construction and policy evaluation, with
 * at most one query per eligible word. Resolution never discharges SUBST
 * inspection. */
sg_error_t sg_gate_set_expand_word_netargv(sg_gate_t *gate,
                                           shell_expand_word_netargv_fn fn,
                                           void *user_ctx) SHELL_NONNULL(1);

/* --- EVALUATION --- */

/*
 * Evaluate a raw command string against the loaded policy.
 *
 * `cmd` / `cmd_len` : raw command bytes to evaluate. They need not be
 *   null-terminated, but embedded NUL bytes are rejected.
 *
 * `buf` / `buf_size` : caller-owned evaluation buffer. Evaluations that reach
 *   dependency-graph construction reserve a private aligned tail as bounded
 *   workspace, and their result strings (command texts, reject reasons, and
 *   suggestions) are packed into the remaining prefix. Parse errors,
 *   unsupported-feature rejections, and workspace-unavailable diagnostics
 *   occur before that reservation and may use the complete buffer. No result
 *   pointer refers to private workspace when it is reserved. Resolved paths
 *   may extend private scratch/identity storage into the prefix before result
 *   rendering; a larger buffer supplies both that storage and result space.
 *   `buf` must remain valid while reading `sg_result_t` string fields. Use
 *   sg_gate_evaluate_size_hint() for ordinary successful evaluations. `cmd`,
 *   `buf`, and `out` must occupy non-overlapping storage: command bytes are
 *   borrowed during rendering, `buf` is writable result/workspace storage,
 *   and `out` is writable metadata. This non-overlap requirement is a caller
 *   precondition and is not checked at runtime.
 *
 * Evaluation models the documented Bash subset and clean noninteractive
 * startup state in shell_depgraph.h and the Shellsplit README; it is not an
 * executor-neutral shell interpretation. Execution must honor that contract,
 * including privileged Bash startup with POSIXLY_CORRECT absent,
 * BASH_COMPAT/BASH_XTRACEFD cleared, all three variables then made readonly,
 * LC_ALL fixed to C/POSIX or UTF-8 and made readonly, and no
 * imported/shadowing functions, startup aliases or traps.
 * The library does not execute commands or choose the application's executor.
 * A result with a nonzero `requirements` carries what Shellsplit says must
 * hold: the caller must satisfy each, such as the dynamic-content inspection
 * of a substitution, before execution under that same model. An allowing
 * verdict is not authorization of runtime-generated content or of an open that
 * has yet to succeed.
 *
 * A syntactically valid redirect-only command, such as `>output`, has no argv
 * and therefore cannot be evaluated by the argv policy model. It returns
 * `SG_OK` with `SG_VERDICT_UNDETERMINED` and a diagnostic `deny_reason`; it
 * never inherits authorization from an adjacent command.
 *
 * Valid blank source (whitespace, comments, escaped line endings; zero-length
 * input is SG_ERR_INVALID) has no command to evaluate. It returns SG_BLANK with
 * no subcommands and the vacuous verdict SG_VERDICT_ALLOW, so a caller that
 * reads only the verdict is unaffected, while one that authorizes execution on
 * SG_OK sees the distinct status.
 *
 * Returns SG_OK on success, SG_ERR_PARSE for malformed input, SG_ERR_EXPAND
 * when an expansion callback fails or returns malformed canonical data,
 * SG_ERR_MEMORY if the evaluation buffer cannot also hold the bounded
 * depgraph workspace or resolved-path analysis storage, SG_ERR_TRUNC if the
 * output buffer or bounded subcommand result array was too small (partial
 * results are still valid), or syntax analysis exhausted its capacity. Syntax
 * exhaustion sets `subcommand_truncated` with an UNDETERMINED verdict. It
 * supplies no subcommand results when it stopped before any range was
 * qualified, and otherwise the retained prefix, whose rows are partial and
 * UNDETERMINED. Returns SG_ERR_UNMODELED, with verdict
 * SG_VERDICT_REJECT, when the source parses but the dependency model cannot
 * capture every requirement for running it safely, and
 * SG_ERR_INVALID for invalid source or buffer sizes.
 * The error code reports the primary failure: `truncated` independently
 * reports incomplete result or diagnostic rendering, so it can also be true
 * with SG_ERR_EXPAND when its failure diagnostic cannot fit, or SG_ERR_MEMORY
 * when even the workspace-unavailable diagnostic cannot fit. SG_ERR_TRUNC
 * always sets `truncated`. Inspect `truncated`,
 * and `subcommand_truncated` to identify the truncated result category. Any
 * truncated result leaves the verdict SG_VERDICT_UNDETERMINED rather than
 * authorizing incomplete output or an evaluated prefix. It also leaves
 * anomaly-model learning and adaptive/CDF calibration unchanged, so a caller
 * may grow its buffer and retry the same evaluation without counting that
 * source record twice.
 *
 * After argument validation initializes `out`, any fatal operational failure
 * also leaves its verdict SG_VERDICT_UNDETERMINED; this includes workspace,
 * expansion, canonical-sequence, and anomaly-model failures. A malformed or
 * unsupported source command intentionally remains SG_VERDICT_REJECT. Some
 * internal canonical failures share SG_ERR_PARSE with source parse failures,
 * so callers must use the result verdict rather than treating that status
 * alone as an authorization decision.
 *
 * Early-stop modes preserve their prefix verdict. When parsed subcommands
 * remain unevaluated, `short_circuited` is true; callers authorizing the whole
 * input must require it to be false.
 */
sg_error_t sg_gate_evaluate(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                            char *buf, size_t buf_size, sg_result_t *out)
    SHELL_NONNULL(1, 2, 4, 6);

/*
 * Return a recommended initial evaluation-buffer size for a command of
 * `cmd_len` bytes. The estimate includes both command/result storage and the
 * aligned bounded workspace: persistent expansion metadata plus depgraph,
 * retained source storage for ENV-read names, source-sized path decoding and
 * identity comparison scratch, and source scratch for anomaly analysis.
 * Retained names stay valid while subsequent analysis reuses graph storage.
 * Expansion callbacks can require additional workspace for resolved path bytes
 * as well as result-prefix space.
 */
size_t sg_gate_evaluate_size_hint(size_t cmd_len);

/* --- RESULT HELPERS --- */

const char *sg_verdict_name(sg_verdict_t v);

#ifdef __cplusplus
}
#endif

#endif /* SHELLGATE_H */
