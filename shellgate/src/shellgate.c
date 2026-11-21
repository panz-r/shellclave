/*
 * shellgate.c - Shell command policy gate
 *
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 */

#include "shellgate.h"
#include "sg_anomaly.h"
#include "sg_anomaly_internal.h"
#include "sg_io.h"
#include "shell_depgraph.h"
#include "shell_depgraph_internal.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_processor_internal.h"
#include "shell_sequence.h"
#include "shell_source.h"
#include "shell_source_runtime_internal.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full_internal.h"
#include "shell_word_internal.h"
#include "shelltype.h"
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XXH_STATIC_LINKING_ONLY
#include "sg_alloc.h"
#include <xxhash.h>

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#define SG_EDGE_WORK()                                                         \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_EDGES)
#define SG_EXPANSION_WORK()                                                    \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS)
#else
#define SG_EDGE_WORK() ((void)0)
#define SG_EXPANSION_WORK() ((void)0)
#endif

#define CDF_NUM_BUCKETS 128
#define CDF_MAX_SCORE 50.0
#define CDF_DEFAULT_MIN_SAMPLES 128

/* --- OUTPUT BUFFER WRITER --- */

typedef struct {
  char *base;
  size_t size;
  size_t used;
  bool overflow;
} buf_writer_t;

static void bw_init(buf_writer_t *w, char *buf, size_t buf_size) {
  w->base = buf;
  w->size = buf_size;
  w->used = 0;
  w->overflow = false;
}

/* Result strings and temporary depgraph route resolution share caller-owned
 * storage, not a lifetime: resolver scratch expires when evaluation returns,
 * while returned strings remain valid until the caller invalidates the buffer.
 * Partition that buffer instead of allocating a second hidden workspace.
 * The diagnostic writer occupies the prefix; an aligned resolver workspace
 * occupies the tail and is never exposed through sg_result_t. */
static SHELL_NONNULL(2) bool sg_eval_workspace_size(size_t command_length,
                                                    size_t *required);

static SHELL_NONNULL(1, 4, 5, 6) bool sg_partition_eval_buffer(
    char *buffer, size_t buffer_size, size_t command_length,
    size_t *output_size, void **workspace, size_t *workspace_size) {
  size_t required = 0;
  if (!sg_eval_workspace_size(command_length, &required))
    return false;
  size_t alignment = shell_dep_workspace_alignment();
  if (required > buffer_size)
    return false;
  /* The caller supplies buffer_size valid bytes. Keep placement arithmetic
   * within that object; only capacity for padding and a nonempty result
   * prefix needs checking here. */
  size_t prefix = buffer_size - required;
  size_t padding = (uintptr_t)(void *)(buffer + prefix) % alignment;
  if (padding >= prefix)
    return false;
  prefix -= padding;
  *output_size = prefix;
  *workspace = buffer + prefix;
  *workspace_size = buffer_size - prefix;
  return true;
}

static void bw_mark_overflow(buf_writer_t *w) {
  w->overflow = true;
  if (w->size != 0) {
    w->base[w->size - 1] = '\0';
    w->used = w->size;
  }
}

static const char *bw_copy(buf_writer_t *w, const char *src, size_t src_len) {
  if (w->used >= w->size) {
    w->overflow = true;
    return NULL;
  }
  size_t avail = w->size - w->used;
  size_t copy = src_len < avail ? src_len : avail - 1;
  /* The last byte can hold only the terminator. An empty string fits exactly;
   * a nonempty one would be cut to nothing, which the caller must not see. */
  if (src_len != 0 && copy == 0) {
    w->overflow = true;
    return NULL;
  }
  char *dst = w->base + w->used;
  memcpy(dst, src, copy);
  dst[copy] = '\0';
  const char *result = dst;
  w->used += copy + 1;
  if (src_len > copy)
    w->overflow = true;
  return result;
}

/* Render up to two suggestions into slots, starting after those already held.
 * Returns SG_ERR_TRUNC when the result buffer is exhausted, SG_ERR_MEMORY when
 * rendering cannot allocate, and SG_ERR_PARSE for a pattern that is not
 * canonical. A suggestion too long to render is simply unavailable, like one
 * the policy could not offer: it ends the list without an error. */
static sg_error_t bw_add_policy_suggestions(buf_writer_t *w,
                                            const st_expand_suggestion_t *found,
                                            size_t available,
                                            const char **slots,
                                            uint32_t *count) {
  while (*count < 2 && *count < available) {
    st_netpattern_view_t pattern = {
        .data = found[*count].pattern,
        .length = found[*count].pattern_length,
    };
    char *cpl = NULL;
    st_error_t rendered = st_netpattern_to_cpl_view(pattern, &cpl);
    if (rendered == ST_ERR_LIMIT)
      return SG_OK;
    if (rendered != ST_OK)
      return rendered == ST_ERR_MEMORY ? SG_ERR_MEMORY : SG_ERR_PARSE;
    slots[*count] = bw_copy(w, cpl, strlen(cpl));
    free(cpl);
    if (!slots[*count])
      return SG_ERR_TRUNC;
    ++*count;
  }
  return SG_OK;
}

static const char *bw_printf(buf_writer_t *w, const char *fmt, ...) {
  if (w->used >= w->size) {
    w->overflow = true;
    return NULL;
  }
  va_list ap;
  va_start(ap, fmt);
  size_t avail = w->size - w->used;
  int n = vsnprintf(w->base + w->used, avail, fmt, ap);
  va_end(ap);
  if (n < 0) {
    w->overflow = true;
    return NULL;
  }
  const char *result = w->base + w->used;
  if ((size_t)n >= avail) {
    w->used = w->size;
    w->overflow = true;
    if (w->size > 0)
      w->base[w->size - 1] = '\0';
  } else {
    w->used += (size_t)n + 1;
  }
  return result;
}

/* --- TYPE SEQUENCE LRU CACHE --- */

typedef struct {
  char *key;   /* command string (owned) */
  char *value; /* type sequence string (owned) */
  size_t key_len;
  size_t value_len;
  size_t value_count;
} lru_entry_t;

typedef struct {
  lru_entry_t *entries;
  size_t capacity; /* max entries */
  size_t count;    /* current entries */
} type_cache_t;

static void type_cache_clear(type_cache_t *c) {
  if (!c->entries)
    return;
  for (size_t i = 0; i < c->count; i++) {
    free(c->entries[i].key);
    free(c->entries[i].value);
  }
  c->count = 0;
}

static void type_cache_free(type_cache_t *c) {
  type_cache_clear(c);
  free(c->entries);
  c->entries = NULL;
  c->capacity = 0;
}

static void cdf_free(sg_gate_t *gate);
static bool cdf_ready(const sg_gate_t *gate) SHELL_NONNULL(1);
static const char *type_cache_lookup(type_cache_t *c, const char *key,
                                     size_t key_len, size_t *value_count,
                                     size_t *value_len) {
  if (!c->entries || c->count == 0)
    return NULL;
  for (size_t i = 0; i < c->count; i++) {
    if (c->entries[i].key_len == key_len &&
        memcmp(c->entries[i].key, key, key_len) == 0) {
      if (i < c->count - 1) {
        lru_entry_t tmp = c->entries[i];
        memmove(&c->entries[i], &c->entries[i + 1],
                (c->count - i - 1) * sizeof(lru_entry_t));
        c->entries[c->count - 1] = tmp;
      }
      *value_count = c->entries[c->count - 1].value_count;
      *value_len = c->entries[c->count - 1].value_len;
      return c->entries[c->count - 1].value;
    }
  }
  return NULL;
}

/* Insert or update. Evicts LRU (front) if full.
 * Takes ownership of value on success; caller must NOT free it.
 * Returns true on success, false on allocation failure. */
static bool type_cache_insert(type_cache_t *c, const char *key, size_t key_len,
                              char *value, size_t value_count,
                              size_t value_len) {
  if (c->capacity == 0)
    return false;

  char *key_copy = malloc(key_len + 1);
  if (!key_copy)
    return false;
  memcpy(key_copy, key, key_len);
  key_copy[key_len] = '\0';

  if (c->count >= c->capacity) {
    free(c->entries[0].key);
    free(c->entries[0].value);
    memmove(&c->entries[0], &c->entries[1],
            (c->count - 1) * sizeof(lru_entry_t));
    c->count--;
  }

  c->entries[c->count].key = key_copy;
  c->entries[c->count].key_len = key_len;
  c->entries[c->count].value = value;
  c->entries[c->count].value_count = value_count;
  c->entries[c->count].value_len = value_len;
  c->count++;
  return true;
}

/* --- GATE STATE --- */

typedef struct {
  const st_policy_t *policy;
  sg_verdict_t outcome;
  bool owned;
} sg_policy_entry_t;

/* One relation: "overrider" stands in front of "overridden". */
typedef struct {
  uint8_t overrider, overridden;
} sg_relation_t;

/* Matches are kept as a bit per policy in a uint32_t, relations as a bit per
 * relation in a uint64_t, and policy indexes in a uint8_t. */
_Static_assert(SG_MAX_POLICIES <= 32, "policy bits must fit a uint32_t");
_Static_assert(SG_MAX_RELATIONS <= 64, "relation bits must fit a uint64_t");
_Static_assert(SG_MAX_POLICIES <= UINT8_MAX, "policy index must fit a uint8_t");

/* Index 0 is the allow policy and index 1 the deny policy; both exist from
 * construction, so policy_count >= 2. */
enum { SG_ALLOW_SLOT = 0, SG_DENY_SLOT = 1, SG_SLOT_COUNT = 2 };

struct sg_gate {
  sg_policy_entry_t policies[SG_MAX_POLICIES];
  uint32_t policy_count;
  sg_verdict_t stop_outcome;

  /* Relations, in creation order; the id of a relation is its position.
   * "overrider" stands in front of "overridden". Two relations may connect the
   * same policies. */
  sg_relation_t relations[SG_MAX_RELATIONS];
  uint32_t relation_count;
  /* Declared outputs, in declaration order: the root policy of each, and the
   * set of relations it follows (bit i is relation i). */
  uint8_t output_roots[SG_MAX_OUTPUTS];
  uint64_t output_relations[SG_MAX_OUTPUTS];
  uint32_t output_count;

  char cwd[512];
  uint32_t reject_mask;
  sg_stop_mode_t stop_mode;
  bool suggestions;
  bool strict_mode;

  shell_expand_word_netargv_fn expand_word_netargv_fn;
  void *expand_word_netargv_ctx;

  /* Anomaly detection */
  sg_anomaly_model_t *anomaly_model; /* raw command name model */
  sg_anomaly_model_t
      *anomaly_model_type; /* type sequence model (NULL if disabled) */
  bool anomaly_enabled;
  double anomaly_threshold;
  bool anomaly_update_only_on_allow;
  bool anomaly_skip_on_detected; /* don't learn from anomalous commands */
  double anomaly_weight_raw;     /* weight for raw score (default 0.5) */
  double anomaly_weight_type;    /* weight for type score (default 0.5) */
  sg_anomaly_combine_mode_t
      anomaly_combine_mode; /* WEIGHTED or BAYESIAN (default WEIGHTED) */

  /* Bayesian CDF histograms */
  size_t cdf_raw_count;  /* observed normal samples (raw) */
  size_t cdf_type_count; /* observed normal samples (type) */
  size_t *cdf_raw_hist;  /* histogram buckets for raw scores */
  size_t *cdf_type_hist; /* histogram buckets for type scores */

  /* Adaptive threshold */
  bool anomaly_adaptive;          /* use adaptive threshold (default false) */
  size_t anomaly_window_size;     /* configured rolling window capacity */
  double anomaly_k_factor;        /* stddev multiplier (default 3.0) */
  double *anomaly_score_buf;      /* circular buffer of normal scores */
  size_t anomaly_score_count;     /* entries currently in buffer */
  size_t anomaly_score_idx;       /* next write position (circular) */
  bool anomaly_adaptive_armed;    /* window is full, threshold is computed */
  double anomaly_fixed_threshold; /* saved fixed threshold for fallback */

  /* Type sequence LRU cache */
  type_cache_t anomaly_type_cache; /* LRU cache for type sequences */
};

/* Calibration belongs to one model generation and one effective score
 * regime. A reset reuses storage; stale observations need not be scrubbed
 * because the rolling count starts over and only initialized entries are read.
 * Required gate storage is initialized and exclusively owned by the caller. */
static SHELL_NONNULL(1) void adaptive_reset(sg_gate_t *gate) {
  gate->anomaly_score_count = 0;
  gate->anomaly_score_idx = 0;
  gate->anomaly_adaptive_armed = false;
  gate->anomaly_threshold = gate->anomaly_fixed_threshold;
}

static SHELL_NONNULL(1) void cdf_reset(sg_gate_t *gate) {
  /* Histograms are either an allocated pair or absent together. */
  if (gate->cdf_raw_hist) {
    memset(gate->cdf_raw_hist, 0, CDF_NUM_BUCKETS * sizeof(size_t));
    memset(gate->cdf_type_hist, 0, CDF_NUM_BUCKETS * sizeof(size_t));
  }
  gate->cdf_raw_count = 0;
  gate->cdf_type_count = 0;
}

static SHELL_NONNULL(1) bool anomaly_uses_bayesian(const sg_gate_t *gate) {
  return gate->anomaly_combine_mode == SG_ANOMALY_COMBINE_BAYESIAN &&
         cdf_ready(gate);
}

/* --- LIFECYCLE --- */

sg_gate_t *sg_gate_new_with_policies_borrowed(const st_policy_t *allow,
                                              const st_policy_t *deny) {
  sg_gate_t *g = calloc(1, sizeof(*g));
  if (!g)
    return NULL;

  g->policies[SG_ALLOW_SLOT] =
      (sg_policy_entry_t){.policy = allow, .outcome = SG_VERDICT_ALLOW};
  g->policies[SG_DENY_SLOT] =
      (sg_policy_entry_t){.policy = deny, .outcome = SG_VERDICT_DENY};
  g->policy_count = 2;
  g->stop_outcome = SG_VERDICT_ALLOW;

  g->cwd[0] = '.'; /* calloc left the terminator in place */
  g->reject_mask = SG_REJECT_MASK_DEFAULT;
  g->stop_mode = SG_EVAL_ALL;
  g->suggestions = true;
  g->strict_mode = true;

  /* Anomaly detection defaults */
  g->anomaly_update_only_on_allow = false;
  g->anomaly_skip_on_detected = true;
  g->anomaly_weight_raw = 0.5;
  g->anomaly_weight_type = 0.5;
  g->anomaly_k_factor = 3.0;

  return g;
}

sg_gate_t *sg_gate_new_with_policies_owned(st_policy_t *allow,
                                           st_policy_t *deny) {
  sg_gate_t *gate = sg_gate_new_with_policies_borrowed(allow, deny);
  if (gate) {
    gate->policies[SG_ALLOW_SLOT].owned = true;
    gate->policies[SG_DENY_SLOT].owned = true;
  }
  return gate;
}

sg_gate_t *sg_gate_new(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  if (!context)
    return NULL;
  st_policy_t *allow = st_policy_new(context);
  st_policy_t *deny = allow ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  if (!deny) {
    st_policy_free(allow);
    return NULL;
  }
  sg_gate_t *gate = sg_gate_new_with_policies_owned(allow, deny);
  if (!gate) {
    st_policy_free(allow);
    st_policy_free(deny);
  }
  return gate;
}

void sg_gate_free(sg_gate_t *gate) {
  if (!gate)
    return;
  if (gate->anomaly_model)
    sg_anomaly_model_free(gate->anomaly_model);
  if (gate->anomaly_model_type)
    sg_anomaly_model_free(gate->anomaly_model_type);
  free(gate->anomaly_score_buf);
  type_cache_free(&gate->anomaly_type_cache);
  cdf_free(gate);
  for (uint32_t i = 0; i < gate->policy_count; i++)
    if (gate->policies[i].owned)
      st_policy_free((st_policy_t *)gate->policies[i].policy);
  free(gate);
}

/* --- CONFIGURATION --- */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd) {
  size_t length = strlen(cwd);
  if (length >= sizeof(gate->cwd))
    return SG_ERR_TRUNC;
  memcpy(gate->cwd, cwd, length + 1);
  return SG_OK;
}

sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask) {
  gate->reject_mask = mask;
  return SG_OK;
}

static bool sg_outcome_is_policy_outcome(sg_verdict_t outcome);

/* Position in the documented order, larger being more restrictive. `verdict`
 * is one of the sg_verdict_t values. */
static int sg_verdict_rank(sg_verdict_t verdict) {
  static const int ranks[] = {
      [SG_VERDICT_ALLOW] = 0,      [SG_VERDICT_AUDIT] = 1,
      [SG_VERDICT_DISCOURAGE] = 2, [SG_VERDICT_UNDETERMINED] = 3,
      [SG_VERDICT_REVIEW] = 4,     [SG_VERDICT_NEEDS_REASON] = 5,
      [SG_VERDICT_DENY] = 6,       [SG_VERDICT_DENY_ESCALATE] = 7,
      [SG_VERDICT_REJECT] = 8,
  };
  return ranks[verdict];
}

/* The user pointer behind the scalar verdict of `outputs`, `count` of them,
 * whose most restrictive is `verdict`. It is given only when exactly one output
 * is that restrictive: with a tie no single policy decided it, so NULL. */
static void *sg_scalar_user_data(const sg_output_t *outputs, uint32_t count,
                                 sg_verdict_t verdict) {
  const sg_output_t *only = NULL;
  uint32_t ties = 0;
  for (uint32_t k = 0; k < count; k++)
    if (outputs[k].verdict == verdict) {
      only = &outputs[k];
      ties++;
    }
  return ties == 1 ? only->user_data : NULL;
}

/* Output k of the whole command: the most restrictive over its subcommands.
 * `floor_undetermined` lifts anything weaker to UNDETERMINED, for an argv-less
 * redirect or unresolved arithmetic, which must not read as plainly allowed
 * yet must not mask a stricter result either. */
static sg_output_t sg_aggregate_output(const sg_result_t *out, uint32_t k,
                                       bool floor_undetermined) {
  sg_output_t worst = {.verdict = SG_VERDICT_ALLOW, .policy = UINT32_MAX};
  for (uint32_t i = 0; i < out->subcommand_count; i++) {
    sg_output_t each = out->subcommands[i].outputs[k];
    if (i == 0 ||
        sg_verdict_rank(each.verdict) > sg_verdict_rank(worst.verdict))
      worst = each;
  }
  if (floor_undetermined &&
      sg_verdict_rank(worst.verdict) < sg_verdict_rank(SG_VERDICT_UNDETERMINED))
    worst =
        (sg_output_t){.verdict = SG_VERDICT_UNDETERMINED, .policy = UINT32_MAX};
  return worst;
}

/* Verdicts that stop a command from proceeding as it is, and so carry the
 * command's deny_reason. A permitting outcome, however weak, is not one. */
static bool sg_verdict_needs_attention(sg_verdict_t verdict) {
  return sg_verdict_rank(verdict) > sg_verdict_rank(SG_VERDICT_UNDETERMINED);
}

/* The diagnostic recorded for a subcommand a policy outcome applies to. */
static const char *sg_outcome_reason(sg_verdict_t outcome) {
  switch (outcome) {
  case SG_VERDICT_DENY:
    return "deny policy match";
  case SG_VERDICT_DENY_ESCALATE:
    return "deny-escalate policy match";
  case SG_VERDICT_NEEDS_REASON:
    return "needs-reason policy match";
  case SG_VERDICT_REVIEW:
    return "review policy match";
  case SG_VERDICT_DISCOURAGE:
    return "discourage policy match";
  default:
    return NULL;
  }
}

/* The most restrictive result found so far; on a tie the earlier one stays. */
typedef struct {
  bool found;
  sg_verdict_t verdict;
  uint32_t policy;
} sg_pick_t;

static void sg_pick(sg_pick_t *pick, sg_verdict_t verdict, uint32_t policy) {
  if (!pick->found || sg_verdict_rank(verdict) > sg_verdict_rank(pick->verdict))
    *pick = (sg_pick_t){.found = true, .verdict = verdict, .policy = policy};
}

/* What `policy` delivers: its own outcome if it matched. Otherwise it cannot
 * override what it stands in front of, so it delivers what the first of those
 * policies delivers, taking the output's relations in creation order and going
 * depth first. Each policy is visited once, which ends any cycle. Returns
 * whether a matched policy was found. */
static bool sg_resolve_policy(const sg_gate_t *gate, uint64_t relations,
                              uint32_t policy, uint32_t matched,
                              uint32_t *visited, sg_pick_t *pick) {
  uint32_t bit = UINT32_C(1) << policy;
  if (*visited & bit)
    return false;
  *visited |= bit;
  if (matched & bit) {
    *pick = (sg_pick_t){.found = true,
                        .verdict = gate->policies[policy].outcome,
                        .policy = policy};
    return true;
  }
  for (uint32_t r = 0; r < gate->relation_count; r++)
    if ((relations & (UINT64_C(1) << r)) &&
        gate->relations[r].overrider == policy &&
        sg_resolve_policy(gate, relations, gate->relations[r].overridden,
                          matched, visited, pick))
      return true;
  return false;
}

/* The number of results a gate gives: its declared outputs, or one. */
static uint32_t sg_output_total(const sg_gate_t *gate) {
  return gate->output_count ? gate->output_count : 1;
}

/* Output k from the policies that matched. With no declared outputs the one
 * output is the most restrictive match. Nothing matched along the way is
 * UNDETERMINED. */
static sg_output_t sg_resolve_output(const sg_gate_t *gate, uint32_t k,
                                     uint32_t matched) {
  sg_pick_t pick = {0};
  if (gate->output_count == 0) {
    for (uint32_t pi = 0; pi < gate->policy_count; pi++)
      if (matched & (UINT32_C(1) << pi))
        sg_pick(&pick, gate->policies[pi].outcome, pi);
  } else {
    uint32_t visited = 0;
    (void)sg_resolve_policy(gate, gate->output_relations[k],
                            gate->output_roots[k], matched, &visited, &pick);
  }
  if (pick.found)
    return (sg_output_t){
        .verdict = pick.verdict,
        .policy = pick.policy,
        .user_data = st_policy_user_data(gate->policies[pick.policy].policy)};
  return (sg_output_t){.verdict = SG_VERDICT_UNDETERMINED,
                       .policy = UINT32_MAX};
}

sg_error_t sg_gate_set_stop_outcome(sg_gate_t *gate, sg_verdict_t outcome) {
  if (!sg_outcome_is_policy_outcome(outcome))
    return SG_ERR_INVALID;
  gate->stop_outcome = outcome;
  return SG_OK;
}

sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode) {
  if ((mode < SG_STOP_FIRST_FAIL) || (mode > SG_EVAL_ALL))
    return SG_ERR_INVALID;
  gate->stop_mode = mode;
  return SG_OK;
}

sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled) {
  gate->suggestions = enabled;
  return SG_OK;
}

sg_error_t sg_gate_set_expand_word_netargv(sg_gate_t *gate,
                                           shell_expand_word_netargv_fn fn,
                                           void *user_ctx) {
  gate->expand_word_netargv_fn = fn;
  gate->expand_word_netargv_ctx = user_ctx;
  return SG_OK;
}

/* --- ANOMALY DETECTION CONFIGURATION --- */

sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate, double threshold,
                                  const sg_anomaly_config_t *config) {
  if (!isfinite(threshold))
    return SG_ERR_INVALID;
  if (config && (!isfinite(config->alpha) || config->alpha <= 0.0))
    return SG_ERR_INVALID;
  sg_anomaly_model_t *new_raw = sg_anomaly_model_new_with_config(config);
  if (!new_raw)
    return SG_ERR_MEMORY;
  sg_anomaly_model_t *new_type = sg_anomaly_model_new_with_config(config);
  if (!new_type) {
    sg_anomaly_model_free(new_raw);
    return SG_ERR_MEMORY;
  }

  double *new_score_buf = NULL;
  size_t adaptive_window = gate->anomaly_window_size;
  if (gate->anomaly_adaptive && !gate->anomaly_score_buf) {
    new_score_buf = calloc(adaptive_window, sizeof(double));
    if (!new_score_buf) {
      sg_anomaly_model_free(new_raw);
      sg_anomaly_model_free(new_type);
      return SG_ERR_MEMORY;
    }
  }

  sg_anomaly_model_free(gate->anomaly_model);
  sg_anomaly_model_free(gate->anomaly_model_type);
  gate->anomaly_model = new_raw;
  gate->anomaly_model_type = new_type;
  if (new_score_buf) {
    gate->anomaly_score_buf = new_score_buf;
  }
  gate->anomaly_enabled = true;
  gate->anomaly_update_only_on_allow = false;
  gate->anomaly_skip_on_detected = true;
  gate->anomaly_weight_raw = 0.5;
  gate->anomaly_weight_type = 0.5;
  gate->anomaly_combine_mode = SG_ANOMALY_COMBINE_WEIGHTED;
  gate->anomaly_fixed_threshold = threshold;
  /* Reset observations while preserving adaptive configuration. */
  adaptive_reset(gate);
  cdf_free(gate);
  return SG_OK;
}

void sg_gate_disable_anomaly(sg_gate_t *gate) {
  if (gate->anomaly_model) {
    sg_anomaly_model_free(gate->anomaly_model);
    gate->anomaly_model = NULL;
  }
  if (gate->anomaly_model_type) {
    sg_anomaly_model_free(gate->anomaly_model_type);
    gate->anomaly_model_type = NULL;
  }
  gate->anomaly_enabled = false;
  free(gate->anomaly_score_buf);
  gate->anomaly_score_buf = NULL;
  adaptive_reset(gate);
  type_cache_clear(&gate->anomaly_type_cache);
  cdf_free(gate);
}

sg_error_t sg_gate_set_anomaly_update_mode(sg_gate_t *gate,
                                           bool update_only_on_allow) {
  gate->anomaly_update_only_on_allow = update_only_on_allow;
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_skip_on_detected(sg_gate_t *gate, bool skip) {
  gate->anomaly_skip_on_detected = skip;
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_weights(sg_gate_t *gate, double weight_raw,
                                       double weight_type) {
  if (!isfinite(weight_raw) || !isfinite(weight_type) || weight_raw < 0.0 ||
      weight_type < 0.0)
    return SG_ERR_INVALID;
  /* Weights must sum to approximately 1.0 */
  double sum = weight_raw + weight_type;
  if (sum < 0.99 || sum > 1.01)
    return SG_ERR_INVALID;
  bool changed = gate->anomaly_weight_raw != weight_raw ||
                 gate->anomaly_weight_type != weight_type;
  gate->anomaly_weight_raw = weight_raw;
  gate->anomaly_weight_type = weight_type;
  if (changed && !anomaly_uses_bayesian(gate))
    adaptive_reset(gate);
  return SG_OK;
}

/* --- ADAPTIVE THRESHOLD --- */

/* The configured, armed rolling window is full. All retained scores are
 * finite and were measured in the current effective score regime. */
static SHELL_NONNULL(1) void adaptive_recompute_threshold(sg_gate_t *gate) {
  /* Compute mean */
  double sum = 0.0;
  size_t n = gate->anomaly_window_size;
  for (size_t i = 0; i < n; i++)
    sum += gate->anomaly_score_buf[i];
  double mean = sum / (double)n;

  /* Compute stddev */
  double var_sum = 0.0;
  for (size_t i = 0; i < n; i++) {
    double diff = gate->anomaly_score_buf[i] - mean;
    var_sum += diff * diff;
  }
  double stddev = sqrt(var_sum / (double)n);

  gate->anomaly_threshold = mean + gate->anomaly_k_factor * stddev;
}

/* Adaptive mode supplies an allocated, positive-sized window. The caller
 * passes one finite, non-anomalous score after a successful evaluation. */
static SHELL_NONNULL(1) void adaptive_record_score(sg_gate_t *gate,
                                                   double score) {
  gate->anomaly_score_buf[gate->anomaly_score_idx] = score;
  gate->anomaly_score_idx =
      (gate->anomaly_score_idx + 1) % gate->anomaly_window_size;
  if (gate->anomaly_score_count < gate->anomaly_window_size)
    gate->anomaly_score_count++;

  /* Arm adaptive threshold once window is full */
  if (!gate->anomaly_adaptive_armed &&
      gate->anomaly_score_count >= gate->anomaly_window_size) {
    gate->anomaly_adaptive_armed = true;
  }

  /* Recompute threshold */
  if (gate->anomaly_adaptive_armed) {
    adaptive_recompute_threshold(gate);
  }
}

sg_error_t sg_gate_set_anomaly_adaptive(sg_gate_t *gate, bool adaptive,
                                        size_t window_size) {
  if (adaptive && window_size == 0)
    return SG_ERR_INVALID;

  if (!adaptive) {
    gate->anomaly_adaptive = false;
    free(gate->anomaly_score_buf);
    gate->anomaly_score_buf = NULL;
    adaptive_reset(gate);
    return SG_OK;
  }

  /* Allocate a new rolling anomaly score buffer sized for window_size. */
  double *new_buf = calloc(window_size, sizeof(double));
  if (!new_buf)
    return SG_ERR_MEMORY;

  /* Free old buffer */
  free(gate->anomaly_score_buf);
  gate->anomaly_score_buf = new_buf;
  gate->anomaly_window_size = window_size;
  gate->anomaly_adaptive = true;
  adaptive_reset(gate);
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_k_factor(sg_gate_t *gate, double k) {
  if (!isfinite(k) || k < 0.0)
    return SG_ERR_INVALID;
  gate->anomaly_k_factor = k;
  /* Recompute threshold if already armed */
  if (gate->anomaly_adaptive_armed)
    adaptive_recompute_threshold(gate);
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_cache_size(sg_gate_t *gate, size_t cache_size) {
  if (cache_size > 8192)
    return SG_ERR_INVALID;

  if (cache_size == 0) {
    type_cache_free(&gate->anomaly_type_cache);
    return SG_OK;
  }

  lru_entry_t *new_entries = calloc(cache_size, sizeof(lru_entry_t));
  if (!new_entries)
    return SG_ERR_MEMORY;

  /* Install only after allocation succeeds so failure preserves the existing
   * cache and its observable hit behavior. */
  type_cache_free(&gate->anomaly_type_cache);
  gate->anomaly_type_cache.entries = new_entries;
  gate->anomaly_type_cache.capacity = cache_size;
  gate->anomaly_type_cache.count = 0;
  return SG_OK;
}

/* --- BAYESIAN CDF HELPERS --- */

/* Histogram bucket of a finite, non-negative score. Scores at or above
 * CDF_MAX_SCORE saturate into the last bucket; the saturation happens before
 * the conversion, which is undefined for a value size_t cannot represent. */
static size_t cdf_bucket(double score) {
  if (score >= CDF_MAX_SCORE)
    return CDF_NUM_BUCKETS - 1;
  return (size_t)(score / CDF_MAX_SCORE * CDF_NUM_BUCKETS);
}

static void cdf_record(size_t *hist, size_t *total, double score) {
  if (!hist)
    return;
  if (!isfinite(score) || score < 0.0)
    return;
  size_t bucket = cdf_bucket(score);
  hist[bucket]++;
  (*total)++;
}

static double cdf_log_odds(const size_t *hist, size_t total, double score) {
  if (!hist || total == 0)
    return 0.0;
  if (!isfinite(score) || score < 0.0)
    return 0.0;

  size_t bucket = cdf_bucket(score);

  /* Use a smoothed mid-rank empirical CDF. Counting half of the current
   * bucket prevents a common tied normal score from landing at F(x)=1. */
  size_t below = 0;
  for (size_t i = 0; i < bucket; i++)
    below += hist[i];
  double rank = (double)below + 0.5 * (double)hist[bucket];
  double f = (rank + 0.5) / ((double)total + 1.0);

  /* Larger component scores are more anomalous, so their upper percentile
   * must produce larger (positive) log-odds. */
  return log(f / (1.0 - f));
}

static void cdf_free(sg_gate_t *gate) {
  free(gate->cdf_raw_hist);
  free(gate->cdf_type_hist);
  gate->cdf_raw_hist = NULL;
  gate->cdf_type_hist = NULL;
  cdf_reset(gate);
}

static bool cdf_ready(const sg_gate_t *gate) {
  size_t min_samples = gate->anomaly_adaptive ? gate->anomaly_window_size
                                              : CDF_DEFAULT_MIN_SAMPLES;
  return gate->cdf_raw_count >= min_samples &&
         gate->cdf_type_count >= min_samples;
}

static void combine_anomaly_scores(const sg_gate_t *gate, double raw_score,
                                   double type_score, double *combined) {
  if (anomaly_uses_bayesian(gate)) {
    *combined =
        cdf_log_odds(gate->cdf_raw_hist, gate->cdf_raw_count, raw_score) +
        cdf_log_odds(gate->cdf_type_hist, gate->cdf_type_count, type_score);
    return;
  }
  *combined = 0.0;
  if (gate->anomaly_weight_raw > 0.0) {
    if (!isfinite(raw_score)) {
      *combined = INFINITY;
      return;
    }
    *combined += raw_score * gate->anomaly_weight_raw;
  }
  if (gate->anomaly_weight_type > 0.0) {
    if (!isfinite(type_score)) {
      *combined = INFINITY;
      return;
    }
    *combined += type_score * gate->anomaly_weight_type;
  }
}

sg_error_t sg_gate_score_anomaly_netseq(const sg_gate_t *gate,
                                        const char *raw_netseq,
                                        size_t raw_length,
                                        const char *type_netseq,
                                        size_t type_length,
                                        sg_anomaly_sequence_score_t *out) {
  *out = (sg_anomaly_sequence_score_t){INFINITY, INFINITY, INFINITY, false, 0};

  if (!gate->anomaly_enabled || !gate->anomaly_model ||
      !gate->anomaly_model_type)
    return SG_ERR_INVALID;
  size_t raw_count = 0, type_count = 0;
  double raw_score = INFINITY, type_score = INFINITY;
  sg_anomaly_status_t raw_status = sg_anomaly_score_netseq_count(
      gate->anomaly_model, raw_netseq, raw_length, &raw_score, &raw_count);
  sg_anomaly_status_t type_status =
      sg_anomaly_score_netseq_count(gate->anomaly_model_type, type_netseq,
                                    type_length, &type_score, &type_count);
  if (raw_status == SG_ANOMALY_ERR_MEMORY ||
      type_status == SG_ANOMALY_ERR_MEMORY)
    return SG_ERR_MEMORY;
  if (raw_status != SG_ANOMALY_OK || type_status != SG_ANOMALY_OK ||
      raw_count != type_count)
    return SG_ERR_PARSE;
  out->raw_score = raw_score;
  out->type_score = type_score;
  out->stage_count = raw_count;
  if (raw_count < 3) {
    out->combined_score = 0.0;
    out->raw_score = 0.0;
    out->type_score = 0.0;
    return SG_OK;
  }
  combine_anomaly_scores(gate, out->raw_score, out->type_score,
                         &out->combined_score);
  double threshold = gate->anomaly_threshold;
  if (gate->anomaly_adaptive && !gate->anomaly_adaptive_armed)
    threshold = gate->anomaly_fixed_threshold;
  out->detected =
      isfinite(out->combined_score) && out->combined_score > threshold;
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_combine_mode(sg_gate_t *gate,
                                            sg_anomaly_combine_mode_t mode) {
  if (mode != SG_ANOMALY_COMBINE_WEIGHTED &&
      mode != SG_ANOMALY_COMBINE_BAYESIAN)
    return SG_ERR_INVALID;

  if (mode == SG_ANOMALY_COMBINE_BAYESIAN && !gate->cdf_raw_hist) {
    size_t *raw = calloc(CDF_NUM_BUCKETS, sizeof(size_t));
    if (!raw)
      return SG_ERR_MEMORY;
    size_t *type = calloc(CDF_NUM_BUCKETS, sizeof(size_t));
    if (!type) {
      free(raw);
      return SG_ERR_MEMORY;
    }
    gate->cdf_raw_hist = raw;
    gate->cdf_type_hist = type;
  }

  bool was_bayesian = anomaly_uses_bayesian(gate);
  gate->anomaly_combine_mode = mode;
  if (was_bayesian != anomaly_uses_bayesian(gate))
    adaptive_reset(gate);
  return SG_OK;
}

#define SG_BUNDLE_HEADER_SIZE 32U
static const unsigned char sg_bundle_magic[8] = {'S', 'G', 'A', 'B',
                                                 'N', 'D', 'L', '2'};

static void store_u64_le(unsigned char *dst, uint64_t value) {
  for (unsigned i = 0; i < 8; i++)
    dst[i] = (unsigned char)(value >> (i * 8));
}

static uint64_t load_u64_le(const unsigned char *src) {
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; i++)
    value |= (uint64_t)src[i] << (i * 8);
  return value;
}

static sg_error_t errno_to_gate_error(int error_number) {
  return error_number == ENOMEM ? SG_ERR_MEMORY : SG_ERR_IO;
}

static sg_error_t process_status_to_gate_error(shell_process_status_t status) {
  if (status == SHELL_PROCESS_ENOMEM)
    return SG_ERR_MEMORY;
  if (status == SHELL_PROCESS_EOUTPUT_LIMIT)
    return SG_ERR_TRUNC;
  return SG_ERR_PARSE;
}

static SHELL_NONNULL(1, 2) sg_error_t
    stream_size(FILE *stream, uint64_t *size) {
  if (sg_io_seek(stream, 0, SEEK_END) != 0)
    return errno_to_gate_error(errno);
  long end = sg_io_tell(stream);
  if (end < 0)
    return errno_to_gate_error(errno);
  *size = (uint64_t)end;
  return sg_io_seek(stream, 0, SEEK_SET) == 0 ? SG_OK
                                              : errno_to_gate_error(errno);
}

/* Required readable/writable streams and initialized hash state. The source
 * supplies count bytes or produces a typed truncation/I/O result. */
static SHELL_NONNULL(1, 2, 4) sg_error_t
    copy_stream(FILE *from, FILE *to, uint64_t count, XXH3_state_t *hash) {
  unsigned char buffer[16384];
  while (count > 0) {
    size_t chunk = count < sizeof(buffer) ? (size_t)count : sizeof(buffer);
    sg_io_read_result_t read = sg_io_read(from, buffer, chunk);
    if (read != SG_IO_READ_OK)
      return read == SG_IO_READ_EOF ? SG_ERR_PARSE : errno_to_gate_error(errno);
    if (sg_io_write(to, buffer, chunk) != 0)
      return errno_to_gate_error(errno);
    if (XXH3_64bits_update(hash, buffer, chunk) == XXH_ERROR)
      return SG_ERR_IO;
    count -= chunk;
  }
  return SG_OK;
}

static sg_error_t anomaly_stream_error(sg_anomaly_status_t status) {
  switch (status) {
  case SG_ANOMALY_OK:
    return SG_OK;
  case SG_ANOMALY_ERR_MEMORY:
    return SG_ERR_MEMORY;
  case SG_ANOMALY_ERR_FORMAT:
  case SG_ANOMALY_ERR_LIMIT:
    return SG_ERR_PARSE;
  default:
    return SG_ERR_IO;
  }
}

sg_error_t sg_gate_save_anomaly_model(const sg_gate_t *gate, const char *path) {
  if ((!gate->anomaly_enabled) || (!gate->anomaly_model) ||
      (!gate->anomaly_model_type))
    return SG_ERR_INVALID;

  FILE *raw = sg_io_tmpfile();
  if (!raw)
    return errno_to_gate_error(errno);
  FILE *type = sg_io_tmpfile();
  if (!type) {
    int error_number = errno;
    fclose(raw);
    return errno_to_gate_error(error_number);
  }
  uint64_t raw_size = 0, type_size = 0;
  sg_error_t result =
      anomaly_stream_error(sg_anomaly_write_stream(gate->anomaly_model, raw));
  if (result == SG_OK)
    result = anomaly_stream_error(
        sg_anomaly_write_stream(gate->anomaly_model_type, type));
  if (result == SG_OK)
    result = stream_size(raw, &raw_size);
  if (result == SG_OK)
    result = stream_size(type, &type_size);
  if (result == SG_OK && raw_size > UINT64_MAX - type_size)
    result = SG_ERR_TRUNC;
  if (result != SG_OK) {
    fclose(raw);
    fclose(type);
    return result;
  }

  sg_atomic_output_t output;
  sg_atomic_output_result_t begin = sg_atomic_output_begin(path, &output);
  if (begin != SG_ATOMIC_OUTPUT_OK) {
    fclose(raw);
    fclose(type);
    return begin == SG_ATOMIC_OUTPUT_MEMORY ? SG_ERR_MEMORY : SG_ERR_IO;
  }

  XXH3_state_t *hash = XXH3_createState();
  if (!hash) {
    sg_atomic_output_discard(&output);
    fclose(raw);
    fclose(type);
    return SG_ERR_MEMORY;
  }
  XXH3_64bits_reset(hash);
  unsigned char header[SG_BUNDLE_HEADER_SIZE] = {0};
  memcpy(header, sg_bundle_magic, sizeof(sg_bundle_magic));
  store_u64_le(header + 8, raw_size);
  store_u64_le(header + 16, type_size);
  result = sg_io_write(output.stream, header, sizeof(header)) == 0
               ? SG_OK
               : errno_to_gate_error(errno);
  if (result == SG_OK)
    result = copy_stream(raw, output.stream, raw_size, hash);
  if (result == SG_OK)
    result = copy_stream(type, output.stream, type_size, hash);
  if (result == SG_OK) {
    store_u64_le(header + 24, XXH3_64bits_digest(hash));
    if (sg_io_seek(output.stream, 0, SEEK_SET) != 0 ||
        sg_io_write(output.stream, header, sizeof(header)) != 0)
      result = errno_to_gate_error(errno);
  }
  XXH3_freeState(hash);
  int saved_errno = errno;
  if (sg_io_close(raw) != 0 && result == SG_OK) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  if (sg_io_close(type) != 0 && result == SG_OK) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  errno = saved_errno;
  if (result != SG_OK || sg_atomic_output_commit(&output) != 0) {
    if (result == SG_OK)
      saved_errno = errno;
    sg_atomic_output_discard(&output);
    errno = saved_errno;
    return result != SG_OK ? result : SG_ERR_IO;
  }
  return SG_OK;
}

sg_error_t sg_gate_load_anomaly_model(sg_gate_t *gate, const char *path) {
  if ((!gate->anomaly_enabled) || (!gate->anomaly_model) ||
      (!gate->anomaly_model_type))
    return SG_ERR_INVALID;

  FILE *bundle = fopen(path, "rb");
  if (!bundle) {
    int error_number = errno;
    return errno_to_gate_error(error_number);
  }
  unsigned char header[SG_BUNDLE_HEADER_SIZE];
  sg_io_read_result_t header_result =
      sg_io_read(bundle, header, sizeof(header));
  if (header_result != SG_IO_READ_OK) {
    sg_error_t result = header_result == SG_IO_READ_EOF
                            ? SG_ERR_PARSE
                            : errno_to_gate_error(errno);
    fclose(bundle);
    return result;
  }
  uint64_t raw_size = load_u64_le(header + 8);
  uint64_t type_size = load_u64_le(header + 16);
  uint64_t expected_hash = load_u64_le(header + 24);
  uint64_t file_size = 0;
  if (memcmp(header, sg_bundle_magic, sizeof(sg_bundle_magic)) != 0 ||
      raw_size == 0 || type_size == 0 || raw_size > UINT64_MAX - type_size ||
      raw_size + type_size > UINT64_MAX - SG_BUNDLE_HEADER_SIZE) {
    fclose(bundle);
    return SG_ERR_PARSE;
  }
  sg_error_t result = stream_size(bundle, &file_size);
  if (result != SG_OK) {
    fclose(bundle);
    return result;
  }
  if (file_size != SG_BUNDLE_HEADER_SIZE + raw_size + type_size) {
    fclose(bundle);
    return SG_ERR_PARSE;
  }
  if (sg_io_seek(bundle, SG_BUNDLE_HEADER_SIZE, SEEK_SET) != 0) {
    result = errno_to_gate_error(errno);
    fclose(bundle);
    return result;
  }

  FILE *raw = sg_io_tmpfile();
  if (!raw) {
    int error_number = errno;
    fclose(bundle);
    return errno_to_gate_error(error_number);
  }
  FILE *type = sg_io_tmpfile();
  if (!type) {
    int error_number = errno;
    fclose(raw);
    fclose(bundle);
    return errno_to_gate_error(error_number);
  }
  XXH3_state_t *hash = XXH3_createState();
  if (!hash) {
    fclose(raw);
    fclose(type);
    fclose(bundle);
    return SG_ERR_MEMORY;
  }
  XXH3_64bits_reset(hash);
  /* Hash exactly the bytes staged for the inner readers. A separate checksum
   * pass followed by a payload rewind could load different, unverified bytes
   * if the source file is modified in place. */
  result = copy_stream(bundle, raw, raw_size, hash);
  if (result == SG_OK)
    result = copy_stream(bundle, type, type_size, hash);
  if (result == SG_OK && XXH3_64bits_digest(hash) != expected_hash)
    result = SG_ERR_PARSE;
  if (result == SG_OK) {
    /* Also reject growth after the initial file-size check. */
    unsigned char trailing;
    sg_io_read_result_t end = sg_io_read(bundle, &trailing, 1);
    if (end != SG_IO_READ_EOF)
      result = end == SG_IO_READ_OK ? SG_ERR_PARSE : errno_to_gate_error(errno);
  }
  int saved_errno = errno;
  XXH3_freeState(hash);
  if (result == SG_OK && (sg_io_seek(raw, 0, SEEK_SET) != 0 ||
                          sg_io_seek(type, 0, SEEK_SET) != 0)) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  if (sg_io_close(bundle) != 0 && result == SG_OK) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  if (result != SG_OK) {
    fclose(raw);
    fclose(type);
    errno = saved_errno;
    return result;
  }

  sg_anomaly_model_t *loaded_raw = NULL;
  sg_anomaly_model_t *loaded_type = NULL;
  result = anomaly_stream_error(sg_anomaly_model_read_new(raw, &loaded_raw));
  if (result == SG_OK)
    result =
        anomaly_stream_error(sg_anomaly_model_read_new(type, &loaded_type));
  saved_errno = errno;
  if (sg_io_close(raw) != 0 && result == SG_OK) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  if (sg_io_close(type) != 0 && result == SG_OK) {
    result = errno_to_gate_error(errno);
    saved_errno = errno;
  }
  if (result != SG_OK) {
    sg_anomaly_model_free(loaded_raw);
    sg_anomaly_model_free(loaded_type);
    errno = saved_errno;
    return result;
  }

  sg_anomaly_model_free(gate->anomaly_model);
  sg_anomaly_model_free(gate->anomaly_model_type);
  gate->anomaly_model = loaded_raw;
  gate->anomaly_model_type = loaded_type;
  adaptive_reset(gate);
  cdf_reset(gate);
  type_cache_clear(&gate->anomaly_type_cache);
  errno = saved_errno;
  return SG_OK;
}

bool sg_gate_anomaly_had_error(const sg_gate_t *gate) {
  if (!gate->anomaly_model)
    return false;
  return sg_anomaly_model_had_error(gate->anomaly_model) ||
         sg_anomaly_model_had_error(gate->anomaly_model_type);
}

const sg_anomaly_model_t *
sg_gate_anomaly_raw_model_borrowed(const sg_gate_t *gate) {
  return gate->anomaly_model;
}

const sg_anomaly_model_t *
sg_gate_anomaly_type_model_borrowed(const sg_gate_t *gate) {
  return gate->anomaly_model_type;
}

/* Policies are stable installed objects; these operations change ownership,
 * not policy contents. Required pointers and lifetime relationships are caller
 * preconditions, including detaching borrowers before owned retirement. */
/* Replace the policy in one slot. The retired policy is freed only if the gate
 * owned it. */
static void sg_gate_replace_slot(sg_gate_t *gate, uint32_t slot,
                                 const st_policy_t *policy, bool owned) {
  if (gate->policies[slot].owned)
    st_policy_free((st_policy_t *)gate->policies[slot].policy);
  gate->policies[slot].policy = policy;
  gate->policies[slot].owned = owned;
}

void sg_gate_set_allow_policy_owned(sg_gate_t *gate, st_policy_t *policy) {
  sg_gate_replace_slot(gate, SG_ALLOW_SLOT, policy, true);
}

void sg_gate_set_deny_policy_owned(sg_gate_t *gate, st_policy_t *policy) {
  sg_gate_replace_slot(gate, SG_DENY_SLOT, policy, true);
}

void sg_gate_set_allow_policy_borrowed(sg_gate_t *gate,
                                       const st_policy_t *policy) {
  sg_gate_replace_slot(gate, SG_ALLOW_SLOT, policy, false);
}

void sg_gate_set_deny_policy_borrowed(sg_gate_t *gate,
                                      const st_policy_t *policy) {
  sg_gate_replace_slot(gate, SG_DENY_SLOT, policy, false);
}

const st_policy_t *sg_gate_allow_policy_borrowed(const sg_gate_t *gate) {
  return gate->policies[SG_ALLOW_SLOT].policy;
}

const st_policy_t *sg_gate_deny_policy_borrowed(const sg_gate_t *gate) {
  return gate->policies[SG_DENY_SLOT].policy;
}

/* The outcomes a policy may be installed with. */
static bool sg_outcome_is_policy_outcome(sg_verdict_t outcome) {
  switch (outcome) {
  case SG_VERDICT_ALLOW:
  case SG_VERDICT_AUDIT:
  case SG_VERDICT_DISCOURAGE:
  case SG_VERDICT_REVIEW:
  case SG_VERDICT_NEEDS_REASON:
  case SG_VERDICT_DENY:
  case SG_VERDICT_DENY_ESCALATE:
    return true;
  case SG_VERDICT_REJECT:
  case SG_VERDICT_UNDETERMINED:
    break;
  }
  return false;
}

static sg_error_t sg_gate_add_policy(sg_gate_t *gate, const st_policy_t *policy,
                                     sg_verdict_t outcome, bool owned) {
  if (!sg_outcome_is_policy_outcome(outcome) ||
      gate->policy_count == SG_MAX_POLICIES)
    return SG_ERR_INVALID;
  gate->policies[gate->policy_count++] =
      (sg_policy_entry_t){.policy = policy, .outcome = outcome, .owned = owned};
  return SG_OK;
}

sg_error_t sg_gate_add_policy_owned(sg_gate_t *gate, st_policy_t *policy,
                                    sg_verdict_t outcome) {
  return sg_gate_add_policy(gate, policy, outcome, true);
}

sg_error_t sg_gate_add_policy_borrowed(sg_gate_t *gate,
                                       const st_policy_t *policy,
                                       sg_verdict_t outcome) {
  return sg_gate_add_policy(gate, policy, outcome, false);
}

sg_error_t sg_gate_add_override(sg_gate_t *gate, uint32_t overrider,
                                uint32_t overridden, uint32_t *relation) {
  if (overrider >= gate->policy_count || overridden >= gate->policy_count ||
      overrider == overridden || gate->relation_count == SG_MAX_RELATIONS)
    return SG_ERR_INVALID;
  *relation = gate->relation_count;
  gate->relations[gate->relation_count++] = (sg_relation_t){
      .overrider = (uint8_t)overrider, .overridden = (uint8_t)overridden};
  return SG_OK;
}

uint32_t sg_gate_relation_count(const sg_gate_t *gate) {
  return gate->relation_count;
}

void sg_gate_relation_at(const sg_gate_t *gate, uint32_t relation,
                         uint32_t *overrider, uint32_t *overridden) {
  *overrider = gate->relations[relation].overrider;
  *overridden = gate->relations[relation].overridden;
}

sg_error_t sg_gate_add_output(sg_gate_t *gate, uint32_t root,
                              const uint32_t *relations,
                              uint32_t relation_count) {
  if (root >= gate->policy_count || gate->output_count == SG_MAX_OUTPUTS)
    return SG_ERR_INVALID;
  uint64_t mask = 0;
  for (uint32_t i = 0; i < relation_count; i++) {
    if (relations[i] >= gate->relation_count)
      return SG_ERR_INVALID;
    mask |= UINT64_C(1) << relations[i];
  }
  gate->output_roots[gate->output_count] = (uint8_t)root;
  gate->output_relations[gate->output_count++] = mask;
  return SG_OK;
}

uint32_t sg_gate_output_count(const sg_gate_t *gate) {
  return gate->output_count;
}

void sg_gate_clear_outputs(sg_gate_t *gate) { gate->output_count = 0; }

void sg_gate_clear_overrides(sg_gate_t *gate) {
  gate->relation_count = 0;
  memset(gate->output_relations, 0, sizeof(gate->output_relations));
}

void sg_gate_remove_policy(sg_gate_t *gate, uint32_t index) {
  if (gate->policies[index].owned)
    st_policy_free((st_policy_t *)gate->policies[index].policy);
  memmove(&gate->policies[index], &gate->policies[index + 1],
          (gate->policy_count - index - 1) * sizeof(gate->policies[0]));
  gate->policy_count--;

  /* Drop the relations that name the removed policy and the outputs rooted at
   * it, and renumber what follows. A relation keeps its place among the rest,
   * so the order in which an output tries them is unchanged. */
  uint32_t relation_map[SG_MAX_RELATIONS];
  uint32_t kept = 0;
  for (uint32_t r = 0; r < gate->relation_count; r++) {
    sg_relation_t relation = gate->relations[r];
    if (relation.overrider == index || relation.overridden == index) {
      relation_map[r] = UINT32_MAX;
      continue;
    }
    relation.overrider -= relation.overrider > index;
    relation.overridden -= relation.overridden > index;
    relation_map[r] = kept;
    gate->relations[kept++] = relation;
  }
  uint32_t old_relation_count = gate->relation_count;
  gate->relation_count = kept;
  kept = 0;
  for (uint32_t o = 0; o < gate->output_count; o++) {
    if (gate->output_roots[o] == index)
      continue;
    uint64_t mask = 0;
    for (uint32_t r = 0; r < old_relation_count; r++)
      if ((gate->output_relations[o] & (UINT64_C(1) << r)) &&
          relation_map[r] != UINT32_MAX)
        mask |= UINT64_C(1) << relation_map[r];
    gate->output_roots[kept] =
        (uint8_t)(gate->output_roots[o] - (gate->output_roots[o] > index));
    gate->output_relations[kept++] = mask;
  }
  gate->output_count = kept;
}

uint32_t sg_gate_policy_count(const sg_gate_t *gate) {
  return gate->policy_count;
}

const st_policy_t *sg_gate_policy_at(const sg_gate_t *gate, uint32_t index,
                                     sg_verdict_t *outcome) {
  if (outcome)
    *outcome = gate->policies[index].outcome;
  return gate->policies[index].policy;
}

/* --- INTERNAL: TOKEN EXPANSION HELPERS --- */

/* --- INTERNAL: BUILD COMMAND STRING WITH OPTIONAL EXPANSION --- */

/* The first pass validated this immutable expansion and reserved exactly its
 * measured display length plus a terminator. No additional preflight scan. */
/* encoded is prevalidated canonical netargv, or NULL for length zero.
 * display has the validated display_length + 1 writable bytes. */
static SHELL_NONNULL(3) void write_expansion_display(const char *encoded,
                                                     size_t length,
                                                     char *display) {
  shell_netstring_iter_t iter;
  (void)shell_netstring_iter_init(&iter, encoded, length);
  size_t used = 0, count = 0;
  shell_netstring_view_t view;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    if (count)
      display[used++] = ' ';
    for (size_t i = 0; i < view.payload_length; i++) {
      unsigned char byte = view.payload[i];
      if (byte >= 0x20 && byte <= 0x7e && byte != '\\') {
        display[used++] = (char)byte;
      } else {
        static const char hex[] = "0123456789abcdef";
        display[used++] = '\\';
        display[used++] = 'x';
        display[used++] = hex[byte >> 4];
        display[used++] = hex[byte & 0x0f];
      }
    }
    count++;
  }
  display[used] = '\0';
}

typedef struct {
  const char *text;
  const char *expansion_netargv;
  size_t text_length;
  size_t expansion_length;
  size_t payload_length;
  size_t display_length;
  bool expanded;
} command_word_t;

/* Parser-owned source words and validated callback records have different
 * semantics. Select their representation once, without decoding payload data
 * as source or constructing another argv. Both views borrow evaluation-lived
 * storage. token is a valid index in this command's retained token array. */
typedef struct {
  const char *source;
  size_t length;
  const shell_dep_word_value_t *value;
} sg_command_word_view_t;

static SHELL_NONNULL(1, 2) sg_command_word_view_t
    sg_command_word_view(const shell_dep_cmd_t *cmd,
                         const shell_expand_cache_t *cache, uint32_t token) {
  return (sg_command_word_view_t){
      cmd->tokens[token], cmd->token_lens[token],
      shell_expand_lookup(cache, cmd->tokens[token])};
}

/* graph/cache are unchanged constructed/prevalidated views. flags references
 * SHELL_DEP_MAX_NODES writable entries, distinct from both inputs. Collect
 * uncertainty before output rendering or early policy stops can omit commands.
 * Only retained graph metadata is examined; cached word lookups are O(1). */
static SHELL_NONNULL(1, 2, 3) uint32_t
    sg_expansion_flags_prepare(const shell_dep_graph_t *graph,
                               const shell_expand_cache_t *cache,
                               uint32_t *flags) {
  memset(flags, 0, SHELL_DEP_MAX_NODES * sizeof(*flags));
  uint32_t aggregate = 0;
  for (uint32_t ni = 0; ni < graph->node_count; ni++) {
    SG_EXPANSION_WORK();
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (cache->unresolved_paths[ni]) {
      flags[ni] |= SG_EXPANSION_UNRESOLVED_PATH;
      aggregate |= SG_EXPANSION_UNRESOLVED_PATH;
    }
    if (node->type != SHELL_NODE_CMD)
      continue;
    if (node->cmd.kind == SHELL_COMMAND_CONDITIONAL &&
        node->cmd.conditional_unresolved)
      flags[ni] |= SG_EXPANSION_UNRESOLVED_CONDITION;
    if (node->cmd.conditional_arithmetic_unresolved ||
        (graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC))
      flags[ni] |= SG_EXPANSION_UNRESOLVED_ARITHMETIC;
    for (uint32_t token = 0; token < node->cmd.token_count; token++) {
      SG_EXPANSION_WORK();
      const shell_dep_word_value_t *value =
          sg_command_word_view(&node->cmd, cache, token).value;
      if (value && value->dynamic && !value->resolved)
        flags[ni] |= SG_EXPANSION_UNRESOLVED_ARGV;
    }
    aggregate |= flags[ni];
  }
  for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
    SG_EXPANSION_WORK();
    const shell_dep_edge_t *edge = &graph->edges[ei];
    uint32_t document, owner;
    if (graph->nodes[edge->from].type == SHELL_NODE_DOC &&
        graph->nodes[edge->from].doc.kind == SHELL_DOC_FILE) {
      document = edge->from;
      owner = edge->to;
    } else if (graph->nodes[edge->to].type == SHELL_NODE_DOC &&
               graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE) {
      document = edge->to;
      owner = edge->from;
    } else {
      continue;
    }
    if (graph->nodes[owner].type != SHELL_NODE_CMD &&
        graph->nodes[owner].type != SHELL_NODE_GROUP)
      continue;
    const shell_dep_doc_t *doc = &graph->nodes[document].doc;
    bool unresolved = (doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0 &&
                      (doc->flags & (SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
                                     SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) == 0;
    bool owns_path =
        edge->type == SHELL_EDGE_ARG || edge->type == SHELL_EDGE_FILE_TEST ||
        edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_WRITE ||
        edge->type == SHELL_EDGE_APPEND || edge->type == SHELL_EDGE_FD_OPEN ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == document);
    if (unresolved && owns_path) {
      flags[owner] |= SG_EXPANSION_UNRESOLVED_PATH;
      aggregate |= SG_EXPANSION_UNRESOLVED_PATH;
    }
  }
  return aggregate;
}

/* cmd/cache are unchanged parsed/prevalidated views. bw is initialized over
 * the writable result prefix; all outputs are distinct writable storage. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) const
    char *build_cmd_string(const shell_dep_cmd_t *cmd, buf_writer_t *bw,
                           const shell_expand_cache_t *cache,
                           const char **netargv, size_t *netargv_length,
                           sg_error_t *build_error) {
  command_word_t words[SHELL_DEP_MAX_TOKENS];
  size_t display_total = 0;
  size_t net_total = 0;

  *build_error = SG_OK;
  *netargv = NULL;
  *netargv_length = 0;
  if (cmd->token_count > SHELL_DEP_MAX_TOKENS) {
    *build_error = SG_ERR_PARSE;
    return NULL;
  }

  for (uint32_t i = 0; i < cmd->token_count; i++) {
    command_word_t *word = &words[i];
    memset(word, 0, sizeof(*word));
    sg_command_word_view_t selected = sg_command_word_view(cmd, cache, i);
    word->text = selected.source;
    word->text_length = selected.length;

    const shell_dep_word_value_t *value = selected.value;
    word->expanded = value && value->resolved;
    if (word->expanded) {
      word->expansion_netargv = value->netargv;
      word->expansion_length = value->length;
      word->display_length = value->display_length;
    } else if (shell_measure_processed_word(word->text, word->text_length,
                                            &word->payload_length) !=
               SHELL_PROCESS_OK) {
      bw_mark_overflow(bw);
      return NULL;
    } else {
      word->display_length = word->text_length;
    }
    size_t record_length = word->expanded ? word->expansion_length : 0;
    if (!word->expanded &&
        shell_netstring_encoded_length(word->payload_length, &record_length) !=
            SHELL_NETSTRING_OK) {
      bw_mark_overflow(bw);
      return NULL;
    }
    size_t separator_length = i != 0;
    if (word->display_length > SIZE_MAX - separator_length ||
        display_total > SIZE_MAX - separator_length - word->display_length ||
        net_total > SIZE_MAX - record_length) {
      bw_mark_overflow(bw);
      return NULL;
    }
    display_total += separator_length + word->display_length;
    net_total += record_length;
  }

  if (bw->used > bw->size || display_total == SIZE_MAX ||
      net_total == SIZE_MAX || display_total + 1 > SIZE_MAX - net_total - 1 ||
      display_total + 1 + net_total + 1 > bw->size - bw->used) {
    bw_mark_overflow(bw);
    return NULL;
  }

  char *display = bw->base + bw->used;
  char *encoded = display + display_total + 1;
  size_t display_used = 0;
  size_t encoded_used = 0;
  for (uint32_t i = 0; i < cmd->token_count; i++) {
    const command_word_t *word = &words[i];
    if (i)
      display[display_used++] = ' ';
    if (word->expanded) {
      write_expansion_display(word->expansion_netargv, word->expansion_length,
                              display + display_used);
      display_used += word->display_length;
      if (word->expansion_length) {
        memcpy(encoded + encoded_used, word->expansion_netargv,
               word->expansion_length);
        encoded_used += word->expansion_length;
      }
      continue;
    }
    memcpy(display + display_used, word->text, word->text_length);
    display_used += word->text_length;
    size_t prefix_length = 0;
    if (shell_netstring_write_prefix(
            encoded + encoded_used, net_total - encoded_used,
            word->payload_length, &prefix_length) != SHELL_NETSTRING_OK) {
      bw_mark_overflow(bw);
      return NULL;
    }
    size_t written = 0;
    if (shell_write_processed_word(word->text, word->text_length,
                                   encoded + encoded_used + prefix_length,
                                   word->payload_length,
                                   &written) != SHELL_PROCESS_OK ||
        written != word->payload_length) {
      bw_mark_overflow(bw);
      return NULL;
    }
    encoded_used += prefix_length + written;
    encoded[encoded_used++] = ',';
  }
  display[display_used] = '\0';
  encoded[encoded_used] = '\0';
  bw->used += display_total + 1 + net_total + 1;
  *netargv = encoded;
  *netargv_length = net_total;
  return display;
}

/* --- INTERNAL: CHECK FEATURES FROM FAST PARSER AGAINST REJECT MASK --- */

static const char *check_features(const shell_parse_result_t *fast,
                                  uint32_t reject_mask, uint32_t *bad_idx) {
  static const struct {
    uint32_t bit;
    const char *name;
  } feats[] = {
      {SHELL_FEAT_SUBSHELL, "command substitution"},
      {SHELL_FEAT_ARITH, "arithmetic"},
      {SHELL_FEAT_HEREDOC, "heredoc"},
      {SHELL_FEAT_HERESTRING, "herestring"},
      {SHELL_FEAT_PROCESS_SUB, "process substitution"},
      {SHELL_FEAT_LOOPS, "loop"},
      {SHELL_FEAT_CONDITIONALS, "conditional"},
      {SHELL_FEAT_IF, "if statement"},
      {SHELL_FEAT_CASE, "case statement"},
      {SHELL_FEAT_VARS, "variable expansion"},
      {SHELL_FEAT_GLOBS, "glob pattern"},
      {SHELL_FEAT_SUBSHELL_FILE, "file command substitution"},
      {SHELL_FEAT_PIPELINE, "pipeline"},
      {SHELL_FEAT_GROUP, "command group"},
      {SHELL_FEAT_BACKGROUND, "background execution"},
      {SHELL_FEAT_EXTGLOB, "extended glob"},
      {SHELL_FEAT_ANSI_C_QUOTE, "ANSI-C quote"},
      {SHELL_FEAT_ARRAY, "array syntax"},
      {SHELL_FEAT_NAMED_FD, "named descriptor redirect"},
      {SHELL_FEAT_COMBINED_REDIRECT, "combined redirect"},
  };

  for (uint32_t si = 0; si < fast->count; si++) {
    uint32_t fbits = fast->cmds[si].features;
    for (int k = 0; k < (int)(sizeof(feats) / sizeof(feats[0])); k++) {
      if ((fbits & feats[k].bit) && (reject_mask & feats[k].bit)) {
        if (bad_idx)
          *bad_idx = si;
        return feats[k].name;
      }
    }
  }
  return NULL;
}

/* Valid constructed graph, immutable throughout evaluation. These indexes
 * reuse fixed graph storage while its separate source arena remains live. */
typedef struct {
  uint32_t out_head[SHELL_DEP_MAX_NODES], in_head[SHELL_DEP_MAX_NODES];
  uint32_t out_next[SHELL_DEP_MAX_EDGES], in_next[SHELL_DEP_MAX_EDGES];
  uint32_t group_writes[SHELL_DEP_MAX_NODES], group_reads[SHELL_DEP_MAX_NODES];
  uint32_t group_expansions[SHELL_DEP_MAX_NODES];
  uint8_t group_substitution[SHELL_DEP_MAX_NODES];
} sg_graph_index_t;

typedef struct {
  size_t graph, source, reusable, total;
} sg_eval_workspace_layout_t;

/* The fixed graph state ends at reusable; source analysis follows it and may
 * retain ENV names. After construction the reusable prefix holds the graph
 * index and anomaly source scratch. Both lifetimes therefore fit without
 * inspecting or relocating borrowed graph names. */
static SHELL_NONNULL(2) bool sg_eval_workspace_plan(
    size_t command_length, sg_eval_workspace_layout_t *layout) {
  if (!shell_dep_workspace_size(NULL, &layout->graph) ||
      !shell_source_workspace_size(command_length, &layout->source))
    return false;
  size_t overhead = sizeof(sg_graph_index_t);
  if (layout->source > SIZE_MAX - overhead)
    return false;
  layout->reusable = overhead + layout->source;
  if (layout->graph > layout->reusable)
    layout->reusable = layout->graph;
  size_t alignment = shell_dep_workspace_alignment();
  size_t padding = (alignment - layout->reusable % alignment) % alignment;
  if (padding > SIZE_MAX - layout->reusable)
    return false;
  layout->reusable += padding;
  if (layout->source > SIZE_MAX - layout->reusable)
    return false;
  layout->total = layout->reusable + layout->source;
  return true;
}

static SHELL_NONNULL(2) bool sg_eval_workspace_size(size_t command_length,
                                                    size_t *required) {
  sg_eval_workspace_layout_t layout;
  if (!sg_eval_workspace_plan(command_length, &layout))
    return false;
  size_t cache_size;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_expand_cache_size(command_length, &cache_size) ||
      cache_size > SIZE_MAX - alignment ||
      layout.total > SIZE_MAX - cache_size - alignment)
    return false;
  *required = layout.total + cache_size + alignment;
  return true;
}

#ifdef SHELLGATE_TEST_ALLOCATOR
/* Expose the histogram bucket mapping for a finite, non-negative score. */
size_t sg_test_cdf_bucket(double score) { return cdf_bucket(score); }

/* Drive the diagnostic writer directly: copy src into buf (size bytes, used
 * already consumed) and report the writer's state afterward. */
const char *sg_test_writer_copy(char *buf, size_t size, size_t used,
                                const char *src, size_t src_len,
                                size_t *used_after, bool *overflow) {
  buf_writer_t writer;
  bw_init(&writer, buf, size);
  writer.used = used;
  const char *result = bw_copy(&writer, src, src_len);
  *used_after = writer.used;
  *overflow = writer.overflow;
  return result;
}

bool sg_test_eval_workspace_layout(size_t length, sg_test_eval_layout_t *out) {
  sg_eval_workspace_layout_t layout;
  if (!sg_eval_workspace_plan(length, &layout))
    return false;
  *out = (sg_test_eval_layout_t){layout.graph, layout.source, layout.reusable,
                                 layout.total, sizeof(sg_graph_index_t)};
  return true;
}
#endif

static SHELL_NONNULL(1, 2) void sg_graph_index_build(
    const shell_dep_graph_t *graph, sg_graph_index_t *index) {
  memset(index, 0, sizeof(*index));
  for (uint32_t node = 0; node < graph->node_count; node++)
    index->out_head[node] = index->in_head[node] = UINT32_MAX;
  for (uint32_t ei = graph->edge_count; ei-- > 0;) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *edge = &graph->edges[ei];
    index->out_next[ei] = index->out_head[edge->from];
    index->out_head[edge->from] = ei;
    index->in_next[ei] = index->in_head[edge->to];
    index->in_head[edge->to] = ei;
  }
}

typedef struct {
  uint32_t group_parent[SHELL_DEP_MAX_NODES];
  bool timing_edge[SHELL_DEP_MAX_NODES];
  bool neutral_compatible[SHELL_DEP_MAX_NODES];
  bool unsafe_group_ancestor[SHELL_DEP_MAX_NODES];
} sg_policy_graph_summary_t;

/* Summarize the graph once before policy counting. Group-owned redirects can
 * be authorized through any contained real simple command, while a group
 * containing only structural empty-time endpoints has no argv policy subject
 * and must fail closed. The two queue passes propagate subjects upward and
 * unsafe redirect-only ancestry downward without repeated edge traversals. */
static SHELL_NONNULL(1, 2) void sg_policy_graph_summarize(
    const shell_dep_graph_t *graph, sg_policy_graph_summary_t *summary) {
  bool observable_io[SHELL_DEP_MAX_NODES] = {false};
  bool group_has_subject[SHELL_DEP_MAX_NODES] = {false};
  uint32_t group_children[SHELL_DEP_MAX_NODES] = {0};
  uint32_t first_group_child[SHELL_DEP_MAX_NODES];
  uint32_t next_group_sibling[SHELL_DEP_MAX_NODES];
  for (uint32_t node = 0; node < graph->node_count; node++) {
    summary->group_parent[node] = UINT32_MAX;
    summary->neutral_compatible[node] = true;
    first_group_child[node] = UINT32_MAX;
    next_group_sibling[node] = UINT32_MAX;
  }

  for (uint32_t edge_index = 0; edge_index < graph->edge_count; edge_index++) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *edge = &graph->edges[edge_index];
    bool observable =
        graph->nodes[edge->from].type != SHELL_NODE_FD &&
        graph->nodes[edge->to].type != SHELL_NODE_FD &&
        !(graph->nodes[edge->from].type == SHELL_NODE_DOC &&
          (graph->nodes[edge->from].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) &&
        (edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_WRITE ||
         edge->type == SHELL_EDGE_APPEND || edge->type == SHELL_EDGE_FD_OPEN ||
         edge->type == SHELL_EDGE_FD_CLOSE);
    if (observable) {
      observable_io[edge->from] = true;
      observable_io[edge->to] = true;
    }
    if (edge->type == SHELL_EDGE_GROUP) {
      summary->group_parent[edge->to] = edge->from;
      if (graph->nodes[edge->to].type == SHELL_NODE_CMD &&
          graph->nodes[edge->to].cmd.token_count > 0)
        group_has_subject[edge->from] = true;
      if (graph->nodes[edge->to].type == SHELL_NODE_GROUP) {
        group_children[edge->from]++;
        next_group_sibling[edge->to] = first_group_child[edge->from];
        first_group_child[edge->from] = edge->to;
      }
    }

    uint32_t endpoints[2] = {edge->from, edge->to};
    for (uint32_t endpoint_index = 0; endpoint_index < 2; endpoint_index++) {
      uint32_t endpoint = endpoints[endpoint_index];
      if (graph->nodes[endpoint].type != SHELL_NODE_CMD ||
          graph->nodes[endpoint].cmd.token_count != 0)
        continue;
      bool allowed =
          (!observable &&
           (edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_WRITE ||
            edge->type == SHELL_EDGE_APPEND)) ||
          (edge->type == SHELL_EDGE_TIME && edge->to == endpoint) ||
          (edge->type == SHELL_EDGE_GROUP && edge->to == endpoint &&
           graph->nodes[edge->from].type == SHELL_NODE_GROUP) ||
          edge->type == SHELL_EDGE_SEQ || edge->type == SHELL_EDGE_AND ||
          edge->type == SHELL_EDGE_OR || edge->type == SHELL_EDGE_BACKGROUND ||
          (graph->nodes[endpoint].cmd.kind == SHELL_COMMAND_CONDITIONAL &&
           (edge->type == SHELL_EDGE_FILE_TEST ||
            edge->type == SHELL_EDGE_FILE_COMPARE) &&
           edge->from == endpoint) ||
          (graph->nodes[endpoint].cmd.kind == SHELL_COMMAND_CONDITIONAL &&
           edge->type == SHELL_EDGE_ENV &&
           edge->flags == SHELL_DEP_EDGE_FLAG_ENV_READ &&
           edge->to == endpoint) ||
          (graph->nodes[endpoint].cmd.kind == SHELL_COMMAND_CONDITIONAL &&
           edge->type == SHELL_EDGE_SUBST && edge->to == endpoint);
      if (!allowed)
        summary->neutral_compatible[endpoint] = false;
    }
    if (edge->type == SHELL_EDGE_TIME && edge->to < graph->node_count)
      summary->timing_edge[edge->to] = true;
  }

  uint32_t queue[SHELL_DEP_MAX_NODES];
  uint32_t head = 0, tail = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_GROUP &&
        group_children[node] == 0)
      queue[tail++] = node;
  while (head < tail) {
    uint32_t group = queue[head++];
    uint32_t parent = summary->group_parent[group];
    if (parent == UINT32_MAX)
      continue;
    group_has_subject[parent] =
        group_has_subject[parent] || group_has_subject[group];
    if (--group_children[parent] == 0)
      queue[tail++] = parent;
  }

  head = tail = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_GROUP &&
        summary->group_parent[node] == UINT32_MAX)
      queue[tail++] = node;
  while (head < tail) {
    uint32_t group = queue[head++];
    uint32_t parent = summary->group_parent[group];
    summary->unsafe_group_ancestor[group] =
        (observable_io[group] && !group_has_subject[group]) ||
        (parent != UINT32_MAX && summary->unsafe_group_ancestor[parent]);
    for (uint32_t child = first_group_child[group]; child != UINT32_MAX;
         child = next_group_sibling[child])
      queue[tail++] = child;
  }
}

/* Pure expression commands and empty timing have execution endpoints without
 * argv. Expression-owned redirects require separate coverage. Enclosing
 * groups likewise cannot hide I/O without a contained argv policy subject. */
static SHELL_NONNULL(1, 2) bool sg_argvless_command_is_policy_neutral(
    const shell_dep_graph_t *graph, const sg_policy_graph_summary_t *summary,
    uint32_t command_index) {
  uint32_t group = summary->group_parent[command_index];
  const shell_dep_cmd_t *command = &graph->nodes[command_index].cmd;
  if (command->kind == SHELL_COMMAND_ARITHMETIC ||
      command->kind == SHELL_COMMAND_CONDITIONAL)
    return !command->has_redirections &&
           summary->neutral_compatible[command_index] &&
           (group == UINT32_MAX || !summary->unsafe_group_ancestor[group]);
  if (command->pipeline_time_mode == SHELL_PIPE_TIME_NONE)
    return false;
  return summary->timing_edge[command_index] &&
         summary->neutral_compatible[command_index] &&
         (group == UINT32_MAX || !summary->unsafe_group_ancestor[group]);
}

/* Group I/O stays attached to real GROUP nodes. Propagate result context once
 * down the containment tree; each command then reads its cached ancestry. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) void sg_group_context_prepare(
    const shell_dep_graph_t *graph, sg_graph_index_t *index,
    const sg_policy_graph_summary_t *summary, const uint32_t *writes,
    const uint32_t *reads, const uint32_t *expansions) {
  uint32_t queue[SHELL_DEP_MAX_NODES];
  uint32_t head = 0, tail = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_GROUP &&
        summary->group_parent[node] == UINT32_MAX)
      queue[tail++] = node;
  while (head < tail) {
    uint32_t parent = queue[head++];
    for (uint32_t ei = index->out_head[parent]; ei != UINT32_MAX;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[ei];
      if (edge->type != SHELL_EDGE_GROUP)
        continue;
      uint32_t child = edge->to;
      index->group_writes[child] = index->group_writes[parent] + writes[parent];
      index->group_reads[child] = index->group_reads[parent] + reads[parent];
      index->group_expansions[child] =
          index->group_expansions[parent] | expansions[parent];
      if (graph->nodes[child].type == SHELL_NODE_GROUP)
        queue[tail++] = child;
    }
  }
}

/* FD_OPEN preserves a redirect's setup-time side effect after its descriptor
 * route has been replaced. It is an output-file effect only when it retains a
 * concrete command/group -> FILE relation; descriptor duplication and input
 * setup deliberately remain topology-only. */
static SHELL_NONNULL(1, 2) bool sg_edge_is_file_output_open(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge) {
  const shell_dep_node_t *from = &graph->nodes[edge->from];
  const shell_dep_node_t *to = &graph->nodes[edge->to];
  return edge->type == SHELL_EDGE_FD_OPEN &&
         (from->type == SHELL_NODE_CMD || from->type == SHELL_NODE_GROUP) &&
         to->type == SHELL_NODE_DOC && to->doc.kind == SHELL_DOC_FILE &&
         edge->source_fd != SHELL_DEP_FD_NONE &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) == 0;
}

static SHELL_NONNULL(1, 2) bool sg_edge_is_output_effect(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge) {
  return (edge->type == SHELL_EDGE_WRITE &&
          graph->nodes[edge->to].type != SHELL_NODE_FD) ||
         edge->type == SHELL_EDGE_APPEND ||
         sg_edge_is_file_output_open(graph, edge);
}

/* Resolve the execution endpoint that owns a FILE redirect setup. Unlike
 * sg_edge_is_file_output_open(), this deliberately accepts both directions:
 * a dynamic pathname can select an input descriptor just as it can select an
 * output descriptor. FD_OPEN_DUP has no document endpoint and must not be
 * mistaken for a pathname-owning redirect. */
static SHELL_NONNULL(1, 2, 4) bool sg_file_setup_consumer(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge,
    uint32_t document, uint32_t *consumer) {
  *consumer = UINT32_MAX;
  if (edge->type == SHELL_EDGE_FD_OPEN &&
      (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0)
    return false;
  if ((edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_FD_OPEN) &&
      edge->from == document)
    *consumer = edge->to;
  else if ((edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND ||
            edge->type == SHELL_EDGE_FD_OPEN) &&
           edge->to == document)
    *consumer = edge->from;
  else
    return false;
  shell_dep_node_type_t type = graph->nodes[*consumer].type;
  return type == SHELL_NODE_CMD || type == SHELL_NODE_GROUP;
}

/* A SUBST edge terminates at the execution endpoint in the ordinary case.
 * Expandable heredocs and here-strings are document indirections: dynamic
 * bytes first enter the DOC, then its READ edge supplies the command or group
 * that owns the descriptor. A dynamic FILE name similarly reaches the owner
 * through its FILE I/O edge or retained FD_OPEN setup, but remains topology
 * only rather than a shell-word inspection dependency. Resolving its pathname
 * clears name uncertainty, not this substitution route or its ownership. */
static uint32_t
sg_substitution_consumers(const shell_dep_graph_t *graph,
                          const sg_graph_index_t *index, uint32_t target,
                          uint32_t edge_flags,
                          uint32_t consumers[SHELL_DEP_MAX_NODES]) {
  const shell_dep_node_t *node = &graph->nodes[target];
  if (node->type == SHELL_NODE_CMD || node->type == SHELL_NODE_GROUP) {
    consumers[0] = target;
    return 1;
  }
  if (node->type != SHELL_NODE_DOC)
    return 0;

  uint32_t count = 0;
  bool seen[SHELL_DEP_MAX_NODES] = {false};
  for (unsigned incoming = 0; incoming < 2; incoming++) {
    for (uint32_t edge_index = incoming ? index->in_head[target]
                                        : index->out_head[target];
         edge_index != UINT32_MAX;
         edge_index = incoming ? index->in_next[edge_index]
                               : index->out_next[edge_index]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[edge_index];
      uint32_t consumer = UINT32_MAX;
      if ((node->doc.kind == SHELL_DOC_HEREDOC ||
           node->doc.kind == SHELL_DOC_HERESTRING) &&
          edge->type == SHELL_EDGE_READ && edge->from == target)
        consumer = edge->to;
      else if (node->doc.kind == SHELL_DOC_FILE &&
               (edge_flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0)
        (void)sg_file_setup_consumer(graph, edge, target, &consumer);
      if (consumer >= graph->node_count)
        continue;
      shell_dep_node_type_t type = graph->nodes[consumer].type;
      if (type != SHELL_NODE_CMD && type != SHELL_NODE_GROUP)
        continue;
      if (!seen[consumer]) {
        seen[consumer] = true;
        consumers[count++] = consumer;
      }
    }
  }
  return count;
}

/* Most dynamic substitution topology is a SUBST edge. A setup-only process
 * substitution is intentionally retained as FD_OPEN until a later exact
 * `$name` use materializes byte flow: `exec {name}< <(producer)` and
 * `exec {name}> >(consumer)` set up descriptors but do not themselves move
 * bytes. The nested command may also have redirected its inherited stream,
 * leaving the setup attached to a retained endpoint instead of an executable
 * producer. It is nevertheless dynamic topology and must be visible in whole
 * results. Keep this structural distinction in one predicate so whole-result
 * and retained-subcommand passes cannot drift apart. */
static SHELL_NONNULL(1, 2) bool sg_edge_is_dynamic_substitution_route(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge) {
  if (edge->type == SHELL_EDGE_SUBST)
    return true;
  if (edge->type != SHELL_EDGE_FD_OPEN ||
      (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0)
    return false;
  shell_dep_node_type_t from = graph->nodes[edge->from].type;
  shell_dep_node_type_t to = graph->nodes[edge->to].type;
  bool from_execution = from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP;
  bool to_execution = to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP;
  if (edge->target_fd != SHELL_DEP_FD_NONE)
    return (from_execution || from == SHELL_NODE_ENDPOINT) && to_execution;
  return edge->source_fd != SHELL_DEP_FD_NONE && from_execution &&
         to == SHELL_NODE_ENDPOINT;
}

static SHELL_NONNULL(1, 2, 3, 4) uint32_t
    sg_dynamic_substitution_route_consumers(
        const shell_dep_graph_t *graph, const sg_graph_index_t *index,
        const shell_dep_edge_t *edge, uint32_t consumers[SHELL_DEP_MAX_NODES]) {
  if (!sg_edge_is_dynamic_substitution_route(graph, edge))
    return 0;
  if (edge->type == SHELL_EDGE_FD_OPEN &&
      edge->target_fd != SHELL_DEP_FD_NONE) {
    consumers[0] = edge->to;
    return 1;
  }
  return sg_substitution_consumers(graph, index, edge->to, edge->flags,
                                   consumers);
}

/* Effective evaluation context counts, per execution endpoint: file output
 * effects, reads from anything but a descriptor or implicit document, and
 * environment assignments. The arrays are zeroed and cover graph->node_count.
 * Group-owned I/O reaches contained commands through
 * sg_group_context_prepare(). */
static SHELL_NONNULL(1, 2, 3, 4) void sg_edge_context_counts(
    const shell_dep_graph_t *graph, uint32_t *writes, uint32_t *reads,
    uint32_t *envs) {
  for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *e = &graph->edges[ei];
    const shell_dep_node_t *from_node = &graph->nodes[e->from];
    const shell_dep_node_t *to_node = &graph->nodes[e->to];
    if (from_node->type == SHELL_NODE_CMD ||
        from_node->type == SHELL_NODE_GROUP) {
      if (sg_edge_is_output_effect(graph, e))
        writes[e->from]++;
    }
    if (to_node->type == SHELL_NODE_CMD || to_node->type == SHELL_NODE_GROUP) {
      if (e->type == SHELL_EDGE_READ && from_node->type != SHELL_NODE_FD &&
          !(from_node->type == SHELL_NODE_DOC &&
            (from_node->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)))
        reads[e->to]++;
      if (e->type == SHELL_EDGE_ENV &&
          !(e->flags & SHELL_DEP_EDGE_FLAG_ENV_READ))
        envs[e->to]++;
    }
  }
}

/* --- EVALUATION --- */

/* A group-level dynamic stream is inherited by every simple command it
 * contains unless the caller later resolves more detailed program semantics.
 * Keep the public result safe without inventing a direct producer-to-command
 * edge: a GROUP remains the authoritative graph consumer. */
static void sg_mark_group_substitution_consumers(
    const shell_dep_graph_t *graph, sg_graph_index_t *index,
    const sg_policy_graph_summary_t *summary, const uint32_t *node_result_index,
    sg_result_t *out) {
  /* A substitution graph can have source text inside this group's span while
   * remaining an independent graph fragment. Only GROUP edges express the
   * structural descendants that inherit a group descriptor. */
  uint32_t pending[SHELL_DEP_MAX_NODES];
  uint32_t head = 0, tail = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_GROUP &&
        summary->group_parent[node] == UINT32_MAX)
      pending[tail++] = node;
  while (head < tail) {
    uint32_t current = pending[head++];
    for (uint32_t edge_index = index->out_head[current];
         edge_index != UINT32_MAX; edge_index = index->out_next[edge_index]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[edge_index];
      if (edge->type != SHELL_EDGE_GROUP)
        continue;
      uint32_t node = edge->to;
      index->group_substitution[node] |= index->group_substitution[current];
      if (graph->nodes[node].type == SHELL_NODE_GROUP) {
        pending[tail++] = node;
      }
      if (graph->nodes[node].type != SHELL_NODE_CMD ||
          node_result_index[node] == UINT32_MAX ||
          index->group_substitution[node] == 0)
        continue;
      sg_subcommand_result_t *result =
          &out->subcommands[node_result_index[node]];
      result->has_dynamic_substitution_io = true;
      if (index->group_substitution[node] & 2)
        result->requirements |= SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD;
    }
  }
}

/* Rejections before per-command evaluation expose one synthetic policy result.
 */
static void sg_init_rejected_subcommand(sg_result_t *out,
                                        const char *reject_reason) {
  out->subcommand_count = 1;
  out->subcommands[0] = (sg_subcommand_result_t){
      .verdict = SG_VERDICT_REJECT,
      .reject_reason = reject_reason,
  };
}

/* Once evaluation has initialized a result, an operational failure must never
 * leave its optimistic initial verdict observable to the caller. Source
 * syntax and unsupported-feature paths explicitly reject before reaching this
 * helper; this helper is only for failures while constructing or evaluating
 * an otherwise accepted representation. A failure after the outputs were
 * aggregated drops them, so sg_complete_outputs makes every output
 * UNDETERMINED as well. */
static SHELL_NONNULL(1) sg_error_t
    sg_fail_undetermined(sg_result_t *out, sg_error_t error) {
  out->verdict = SG_VERDICT_UNDETERMINED;
  out->output_count = 0;
  out->deciding_user_data = NULL;
  return error;
}

static sg_error_t sg_gate_evaluate_body(sg_gate_t *gate, const char *cmd,
                                        size_t cmd_len, char *buf,
                                        size_t buf_size, sg_result_t *out);

/* Paths that end before the policies are resolved report only a scalar
 * verdict. Give them the vector shape: each output is that verdict. */
static void sg_complete_outputs(const sg_gate_t *gate, sg_result_t *out) {
  uint32_t total = sg_output_total(gate);
  for (uint32_t i = 0; i < out->subcommand_count; i++) {
    sg_subcommand_result_t *sr = &out->subcommands[i];
    if (sr->output_count != 0)
      continue;
    sr->output_count = total;
    for (uint32_t k = 0; k < total; k++)
      sr->outputs[k] =
          (sg_output_t){.verdict = sr->verdict, .policy = UINT32_MAX};
  }
  if (out->output_count != 0)
    return;
  out->output_count = total;
  for (uint32_t k = 0; k < total; k++)
    out->outputs[k] =
        (sg_output_t){.verdict = out->verdict, .policy = UINT32_MAX};
}

sg_error_t sg_gate_evaluate(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                            char *buf, size_t buf_size, sg_result_t *out) {
  sg_error_t status =
      sg_gate_evaluate_body(gate, cmd, cmd_len, buf, buf_size, out);
  /* SG_ERR_INVALID can return before the result is initialized. */
  if (status != SG_ERR_INVALID)
    sg_complete_outputs(gate, out);
  return status;
}

static sg_error_t sg_gate_evaluate_body(sg_gate_t *gate, const char *cmd,
                                        size_t cmd_len, char *buf,
                                        size_t buf_size, sg_result_t *out) {
  if (buf_size == 0)
    return SG_ERR_INVALID;
  if (cmd_len == 0 || memchr(cmd, '\0', cmd_len) != NULL)
    return SG_ERR_INVALID;
  memset(out, 0, sizeof(*out));
  /* A result no exit has decided is not an authorization. */
  out->verdict = SG_VERDICT_UNDETERMINED;

  buf_writer_t bw;
  bw_init(&bw, buf, buf_size);

  /* Step 1: Fast parse to check features */
  shell_parse_result_t fast;
  shell_limits_t lim = {.max_subcommands = 64,
                        .strict_mode = gate->strict_mode,
                        .workspace = buf,
                        .workspace_size = buf_size};
  shell_error_t ferr = shell_parse_fast(cmd, cmd_len, &lim, &fast);
  bool parse_truncated = ferr == SHELL_ETRUNC;
  /* Syntax capacity can stop validation before any ranges are qualified.
   * There is no complete analysis to inspect, score or classify by policy. */
  if (parse_truncated && fast.count == 0) {
    out->truncated = out->subcommand_truncated = true;
    out->verdict = SG_VERDICT_UNDETERMINED;
    return SG_ERR_TRUNC;
  }
  /* A successful zero-range parse already establishes semantic trivia.
   * Do not override a parse error with a second, broader C-whitespace scan. */
  if (ferr == SHELL_OK && fast.count == 0) {
    out->verdict = SG_VERDICT_ALLOW;
    return SG_BLANK;
  }
  if (ferr == SHELL_EPARSE && fast.count == 0) {
    out->verdict = SG_VERDICT_REJECT;
    out->deny_reason = bw_copy(&bw, "parse error", 11);
    sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return SG_ERR_PARSE;
  }
  if (ferr == SHELL_EPARSE) {
    out->verdict = SG_VERDICT_REJECT;
    out->deny_reason = bw_copy(&bw, "parse error", 11);
    sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return SG_ERR_PARSE;
  }

  /* Step 2: Feature rejection */
  uint32_t bad_idx = 0;
  const char *feat = check_features(&fast, gate->reject_mask, &bad_idx);
  if (feat) {
    out->verdict = SG_VERDICT_REJECT;
    out->deny_reason = bw_printf(&bw, "%s not allowed", feat);
    sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return SG_OK;
  }

  /* Step 3: Consume the unchanged fast parse of this exact source span. The
   * internal graph entry point borrows cmd for its offset-based token views;
   * it trusts parser-produced metadata and does not repeat the fast parse. */
  size_t output_size = 0;
  void *eval_workspace = NULL;
  size_t eval_workspace_size = 0;
  if (!sg_partition_eval_buffer(buf, buf_size, cmd_len, &output_size,
                                &eval_workspace, &eval_workspace_size)) {
    out->verdict = SG_VERDICT_UNDETERMINED;
    out->deny_reason = bw_copy(&bw, "depgraph workspace unavailable", 30);
    if (bw.overflow)
      out->truncated = true;
    return SG_ERR_MEMORY;
  }
  bw_init(&bw, buf, output_size);
  shell_expand_cache_t expansion_cache;
  void *dep_workspace;
  size_t dep_workspace_size;
  if (!shell_expand_cache_init(
          gate->expand_word_netargv_fn, gate->expand_word_netargv_ctx, cmd,
          cmd_len, true, eval_workspace, eval_workspace_size, &expansion_cache,
          &dep_workspace, &dep_workspace_size)) {
    out->verdict = SG_VERDICT_UNDETERMINED;
    out->deny_reason = bw_copy(&bw, "expansion workspace unavailable", 31);
    if (bw.overflow)
      out->truncated = true;
    return SG_ERR_MEMORY;
  }
  shell_dep_word_resolver_t resolver = {
      .expand = shell_expand_resolve,
      .context = &expansion_cache,
  };
  shell_dep_limits_t dep_limits = SHELL_DEP_LIMITS_DEFAULT;
  /* Partitioning already established this source length's sizing bound.
   * Shift fixed graph state to end immediately before the retained arena. */
  sg_eval_workspace_layout_t workspace_layout;
  (void)sg_eval_workspace_plan(cmd_len, &workspace_layout);
  dep_limits.workspace = (char *)dep_workspace + workspace_layout.reusable -
                         workspace_layout.graph;
  dep_limits.workspace_size = workspace_layout.graph + workspace_layout.source;
  shell_dep_graph_t graph;
  memset(&graph, 0, sizeof(graph));
  shell_dep_error_t derr = shell_dep_graph_parse_with_fast_resolver(
      cmd, cmd_len, gate->cwd, &dep_limits, &fast, &graph, &resolver,
      expansion_cache.unresolved_paths);
  bool depgraph_truncated = derr == SHELL_DEP_ETRUNC;
  if (expansion_cache.error != SHELL_DEP_OK) {
    sg_error_t expansion_error = expansion_cache.error == SHELL_DEP_ETRUNC
                                     ? SG_ERR_TRUNC
                                     : SG_ERR_EXPAND;
    out->verdict = SG_VERDICT_UNDETERMINED;
    out->truncated = expansion_cache.error == SHELL_DEP_ETRUNC;
    out->deny_reason = bw_copy(&bw, "word expansion failed", 21);
    if (bw.overflow)
      out->truncated = true;
    return expansion_error;
  }
  if (derr != SHELL_DEP_OK && !depgraph_truncated) {
    out->verdict = derr == SHELL_DEP_EWORKSPACE ? SG_VERDICT_UNDETERMINED
                                                : SG_VERDICT_REJECT;
    bool parse_error = derr == SHELL_DEP_EPARSE || derr == SHELL_DEP_EINPUT;
    bool unmodeled = derr == SHELL_DEP_EUNMODELED;
    out->deny_reason =
        bw_copy(&bw,
                derr == SHELL_DEP_EWORKSPACE ? "depgraph workspace unavailable"
                : parse_error                ? "parse error"
                : unmodeled                  ? "no safe dependency model"
                                             : "depgraph error",
                derr == SHELL_DEP_EWORKSPACE ? 30
                : parse_error                ? 11
                : unmodeled                  ? 24
                                             : 14);
    if (derr != SHELL_DEP_EWORKSPACE)
      sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return derr == SHELL_DEP_EWORKSPACE ? SG_ERR_MEMORY
           : unmodeled                  ? SG_ERR_UNMODELED
                                        : SG_ERR_PARSE;
  }

  /* This is graph-level information, not a property of whichever command
   * results fit in the caller's display buffer. Preserve it before any later
   * diagnostic rendering can return SG_ERR_TRUNC. The requirements are the
   * graph's own, passed on as its edge flags state them. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++) {
    const shell_dep_edge_t *edge = &graph.edges[ei];
    out->requirements |= edge->flags & SHELL_DEP_EDGE_FLAG_REQUIRED;
    if (sg_edge_is_dynamic_substitution_route(&graph, edge)) {
      out->has_dynamic_substitution_io = true;
      out->requirements |= edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD;
    }
  }

  dep_workspace_size = workspace_layout.reusable;
  /* Graph state is retired; its source arena and expansion cache remain live.
   * Only the separately sized prefix is reused by subsequent analysis. */
  sg_graph_index_t *graph_index = dep_workspace;
  sg_graph_index_build(&graph, graph_index);

  /* Step 3.5: Per-command effective I/O and environment counts */
  uint32_t cmd_write_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_read_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_env_count[SHELL_DEP_MAX_NODES];
  uint32_t node_expansion_flags[SHELL_DEP_MAX_NODES];
  memset(cmd_write_count, 0, sizeof(cmd_write_count));
  memset(cmd_read_count, 0, sizeof(cmd_read_count));
  memset(cmd_env_count, 0, sizeof(cmd_env_count));
  out->unresolved_expansion_flags = sg_expansion_flags_prepare(
      &graph, &expansion_cache, node_expansion_flags);
  sg_edge_context_counts(&graph, cmd_write_count, cmd_read_count,
                         cmd_env_count);

  /* Policy evaluation is graph-based. Anomaly sequences are built separately:
   * they include nested executable substitutions in deterministic analysis
   * order, whereas graph CMD nodes preserve dependency topology. */
  sg_policy_graph_summary_t policy_graph = {0};
  sg_policy_graph_summarize(&graph, &policy_graph);
  sg_group_context_prepare(&graph, graph_index, &policy_graph, cmd_write_count,
                           cmd_read_count, node_expansion_flags);
  size_t cmd_count = 0;
  bool has_unpolicyable_io_only_command = false;
  for (uint32_t ni = 0; ni < graph.node_count; ni++) {
    const shell_dep_node_t *node = &graph.nodes[ni];
    if (node->type != SHELL_NODE_CMD)
      continue;
    if (node->cmd.token_count > 0) {
      cmd_count++;
    } else if (!sg_argvless_command_is_policy_neutral(&graph, &policy_graph,
                                                      ni)) {
      /* A redirect-only simple command is valid shell syntax and remains in
       * the graph so its I/O effects are visible. It has no argv, though, so
       * the canonical argv policy model cannot authorize it. Shellsplit's
       * anomaly sequence carries an explicit empty argv[0] stage for it. */
      has_unpolicyable_io_only_command = true;
    }
  }

  /* Build one nested canonical type signature per execution stage. */
  const char *type_seq = NULL;
  char *owned_type_seq = NULL;
  char *owned_cmd_seq = NULL;
  size_t type_count = 0;
  size_t anomaly_count = 0;
  size_t cmd_seq_length = 0;
  size_t type_seq_length = 0;

  /* Only a complete retained lexical sequence is scored. Unresolved
   * arithmetic remains a separate semantic blocker and prevents learning
   * and history updates below. A bounded
   * prefix still gets policy diagnostics below, but must not be scored or
   * cached as a complete anomaly sequence. */
  bool anomaly_ready = !parse_truncated && !depgraph_truncated &&
                       gate->anomaly_enabled && gate->anomaly_model;
  if (anomaly_ready && gate->anomaly_model_type) {
    const char *cached = type_cache_lookup(
        &gate->anomaly_type_cache, cmd, cmd_len, &type_count, &type_seq_length);
    if (cached) {
      type_seq = cached;
    }
  }

  /* Anomaly detection: score the complete execution-stage sequence with the
   * hybrid model. Build first, rather than inferring a count from the graph:
   * command and process substitutions are execution stages but are not
   * top-level graph list members. */
  if (anomaly_ready) {
    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t typed = {0};
    /* The graph accepted this exact immutable source, including read options
     * whose supported roles depend on captured descriptor values. Collect
     * lexical analysis stages without repeating a context-free support check.
     * The stage order is not the dependency graph's node order. */
    shell_anomaly_stages_t stages = {0};
    /* Path preparation is finished. Scratch after the index now supplies
     * source analysis; the retained graph arena and expansion cache stay live.
     */
    shell_limits_t stage_limits = SHELL_LIMITS_DEFAULT;
    stage_limits.workspace = (char *)dep_workspace + sizeof(*graph_index);
    stage_limits.workspace_size = dep_workspace_size - sizeof(*graph_index);
    /* Keep lexical facts and source scratch alive through both collection
     * and rendering; nested words are still inspected by the renderers. */
    shell_source_operation_begin(cmd, cmd_len);
    shell_source_workspace_scope_t previous_source =
        shell_source_workspace_begin(cmd, cmd_len, stage_limits.workspace,
                                     stage_limits.workspace_size);
    shell_process_status_t command_status =
        shell_anomaly_stages_collect_prevalidated(cmd, cmd_len, NULL,
                                                  &stage_limits, &stages);
    if (command_status == SHELL_PROCESS_OK) {
      command_status =
          type_seq ? shell_build_command_netseq_from_stages(&stages, NULL, &raw,
                                                            &anomaly_count)
                   : shell_build_anomaly_netseqs_from_stages(
                         &stages, NULL, &raw, &typed, &anomaly_count);
    }
    shell_anomaly_stages_free(&stages);
    shell_source_workspace_end(previous_source);
    shell_source_operation_end();
    if (!type_seq) {
      type_count = anomaly_count;
      if (command_status == SHELL_PROCESS_OK) {
        type_seq = (const char *)typed.data;
        type_seq_length = typed.length;
        if (type_cache_insert(&gate->anomaly_type_cache, cmd, cmd_len,
                              (char *)typed.data, type_count,
                              type_seq_length)) {
          typed = (shell_netstring_buffer_t){0};
        } else {
          owned_type_seq = (char *)typed.data;
          typed = (shell_netstring_buffer_t){0};
          type_seq = owned_type_seq;
        }
      }
    }
    if (command_status != SHELL_PROCESS_OK || !raw.data) {
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&typed);
      free(owned_type_seq);
      out->verdict = SG_VERDICT_UNDETERMINED;
      if (command_status == SHELL_PROCESS_EOUTPUT_LIMIT)
        out->truncated = true;
      return command_status == SHELL_PROCESS_OK
                 ? SG_ERR_MEMORY
                 : process_status_to_gate_error(command_status);
    }
    owned_cmd_seq = (char *)raw.data;
    cmd_seq_length = raw.length;
    raw = (shell_netstring_buffer_t){0};
    if (!type_seq) {
      free(owned_cmd_seq);
      free(owned_type_seq);
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_MEMORY;
    }
    if (anomaly_count != 0) {
      sg_anomaly_sequence_score_t scores = {0};
      sg_error_t score_status =
          sg_gate_score_anomaly_netseq(gate, owned_cmd_seq, cmd_seq_length,
                                       type_seq, type_seq_length, &scores);
      if (score_status == SG_ERR_MEMORY) {
        free(owned_cmd_seq);
        free(owned_type_seq);
        return sg_fail_undetermined(out, SG_ERR_MEMORY);
      }
      if (score_status != SG_OK || type_count != anomaly_count ||
          scores.stage_count != anomaly_count) {
        free(owned_cmd_seq);
        free(owned_type_seq);
        return sg_fail_undetermined(out, SG_ERR_PARSE);
      }
      out->anomaly_score = scores.combined_score;
      out->anomaly_score_raw = scores.raw_score;
      out->anomaly_score_type = scores.type_score;
      out->anomaly_detected = scores.detected;
    } else {
      out->anomaly_score = 0.0;
      out->anomaly_detected = false;
    }
  }

  /* Step 4: Walk CMD nodes, evaluate each against policy */
  /* The depgraph may retain only the same bounded command prefix as the fast
   * parser. Preserve the fast parser's truncation signal so a complete-looking
   * 64-entry result can never be mistaken for evaluation of the whole input. */
  bool subcommand_truncated = parse_truncated || depgraph_truncated;
  bool stopped_early = false;
  sg_error_t evaluation_error = SG_OK;
  uint32_t node_result_index[SHELL_DEP_MAX_NODES];
  for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
    node_result_index[i] = UINT32_MAX;
  for (uint32_t ni = 0; ni < graph.node_count; ni++) {
    const shell_dep_node_t *node = &graph.nodes[ni];
    if (node->type != SHELL_NODE_CMD)
      continue;
    if (node->cmd.token_count == 0)
      continue;

    if (out->subcommand_count >= SG_MAX_SUBCOMMAND_RESULTS) {
      subcommand_truncated = true;
      break;
    }

    sg_subcommand_result_t *sr = &out->subcommands[out->subcommand_count++];
    /* The row is reached before its policies run, and a failure in between
     * returns with it as is: it must not read as the zero value, ALLOW. */
    sr->verdict = SG_VERDICT_UNDETERMINED;
    node_result_index[ni] = out->subcommand_count - 1;
    sr->unresolved_expansion_flags =
        node_expansion_flags[ni] | graph_index->group_expansions[ni];

    const char *policy_netargv = NULL;
    sg_error_t build_error = SG_OK;
    sr->display_command =
        build_cmd_string(&node->cmd, &bw, &expansion_cache, &policy_netargv,
                         &sr->netargv_length, &build_error);
    /* Rendering can return a partial command entry; uncertainty was already
     * collected for the retained graph independently of output capacity. */
    if (build_error != SG_OK) {
      out->verdict = SG_VERDICT_UNDETERMINED;
      free(owned_cmd_seq);
      free(owned_type_seq);
      return build_error;
    }
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      free(owned_cmd_seq);
      free(owned_type_seq);
      return SG_ERR_TRUNC;
    }
    sr->netargv = policy_netargv;
    st_netargv_view_t policy_netargv_view = {
        .data = policy_netargv,
        .length = sr->netargv_length,
    };

    sr->write_count = cmd_write_count[ni];
    sr->read_count = cmd_read_count[ni];
    sr->env_count = cmd_env_count[ni];
    sr->write_count += graph_index->group_writes[ni];
    sr->read_count += graph_index->group_reads[ni];

    /* Evaluate every installed policy, so no match hides another, and record
     * which matched. The allow and deny slots build suggestions when the
     * caller wants them; the match-only path avoids constructing any. */
    st_eval_result_t slot_eval[SG_SLOT_COUNT] = {{0}, {0}};
    uint32_t matched_mask = 0;
    bool policy_failed = false, failed_memory = false, deny_slot_failed = false;
    for (uint32_t pi = 0; pi < gate->policy_count; pi++) {
      const sg_policy_entry_t *entry = &gate->policies[pi];
      st_eval_result_t *eval =
          pi < SG_SLOT_COUNT && gate->suggestions ? &slot_eval[pi] : NULL;
      bool matches = false;
      st_error_t err =
          eval ? st_policy_eval_view(entry->policy, policy_netargv_view, eval)
               : st_policy_match_view(entry->policy, policy_netargv_view,
                                      &matches);
      if (eval) {
        matches = eval->matches;
        /* A suggestion can exceed its bounded display buffer without making
         * policy matching invalid. Allocation failure is different: preserve
         * the fail-closed contract for work Shellgate requested. */
        if (err == ST_OK && eval->suggestion_error == ST_ERR_MEMORY)
          err = eval->suggestion_error;
      }
      if (err != ST_OK) {
        policy_failed = true;
        failed_memory = failed_memory || err == ST_ERR_MEMORY;
        deny_slot_failed = deny_slot_failed || pi == SG_DENY_SLOT;
        continue;
      }
      if (matches)
        matched_mask |= UINT32_C(1) << pi;
    }
    /* Resolve each output from the matches; the subcommand's verdict is the
     * most restrictive of them. Policies are deterministic and a shape that
     * matches nothing is UNDETERMINED, not an error; the only failure is an
     * allocation inside a policy, which leaves every output UNDETERMINED and
     * is reported. */
    sr->output_count = sg_output_total(gate);
    sg_verdict_t best = SG_VERDICT_ALLOW;
    for (uint32_t k = 0; k < sr->output_count; k++) {
      sr->outputs[k] = policy_failed
                           ? (sg_output_t){.verdict = SG_VERDICT_UNDETERMINED,
                                           .policy = UINT32_MAX}
                           : sg_resolve_output(gate, k, matched_mask);
      if (k == 0 ||
          sg_verdict_rank(sr->outputs[k].verdict) > sg_verdict_rank(best))
        best = sr->outputs[k].verdict;
    }
    sr->deciding_user_data =
        sg_scalar_user_data(sr->outputs, sr->output_count, best);
    bool matched_any = matched_mask != 0;
    sr->matched_policies = matched_mask;
    sr->matches = matched_any;
    sr->verdict = best;
    if (policy_failed) {
      evaluation_error = failed_memory ? SG_ERR_MEMORY : SG_ERR_PARSE;
      sr->reject_reason =
          deny_slot_failed ? bw_copy(&bw, "deny policy evaluation failed", 29)
                           : bw_copy(&bw, "policy evaluation failed", 24);
    } else if (best != SG_VERDICT_UNDETERMINED) {
      const char *reason = sg_outcome_reason(best);
      sr->reject_reason = reason ? bw_copy(&bw, reason, strlen(reason)) : NULL;
    } else {
      if (gate->suggestions && !matched_any) {
        sg_error_t added =
            bw_add_policy_suggestions(&bw, slot_eval[SG_ALLOW_SLOT].suggestions,
                                      slot_eval[SG_ALLOW_SLOT].suggestion_count,
                                      out->suggestions, &out->suggestion_count);
        if (added == SG_ERR_TRUNC) {
          out->truncated = true;
          out->verdict = SG_VERDICT_UNDETERMINED;
          free(owned_cmd_seq);
          free(owned_type_seq);
          return SG_ERR_TRUNC;
        }
        if (added != SG_OK && evaluation_error == SG_OK)
          evaluation_error = added;
      }
    }
    if (gate->suggestions && !policy_failed &&
        !(matched_mask & (UINT32_C(1) << SG_DENY_SLOT)) &&
        out->deny_suggestion_count == 0) {
      /* Deny suggestions come from the deny policy when it did not match. */
      sg_error_t added = bw_add_policy_suggestions(
          &bw, slot_eval[SG_DENY_SLOT].suggestions,
          slot_eval[SG_DENY_SLOT].suggestion_count, out->deny_suggestions,
          &out->deny_suggestion_count);
      if (added == SG_ERR_TRUNC) {
        out->truncated = true;
        out->verdict = SG_VERDICT_UNDETERMINED;
        free(owned_cmd_seq);
        free(owned_type_seq);
        return SG_ERR_TRUNC;
      }
      if (added != SG_OK && evaluation_error == SG_OK)
        evaluation_error = added;
    }
    if (sg_verdict_needs_attention(sr->verdict)) {
      if (out->deny_reason == NULL) {
        out->deny_reason =
            sr->reject_reason ? sr->reject_reason : sr->display_command;
        out->attention_index = out->subcommand_count - 1;
      }
    }

    if (!sr->matches && gate->stop_mode == SG_STOP_FIRST_FAIL) {
      stopped_early = true;
      break;
    }
    if (sr->matches && gate->stop_mode == SG_STOP_FIRST_PASS) {
      stopped_early = true;
      break;
    }
    if (sr->verdict == SG_VERDICT_ALLOW &&
        gate->stop_mode == SG_STOP_FIRST_ALLOW) {
      stopped_early = true;
      break;
    }
    if (sr->verdict == SG_VERDICT_DENY &&
        gate->stop_mode == SG_STOP_FIRST_DENY) {
      stopped_early = true;
      break;
    }
    if (sr->verdict == gate->stop_outcome &&
        gate->stop_mode == SG_STOP_FIRST_OUTCOME) {
      stopped_early = true;
      break;
    }
  }

  out->short_circuited = stopped_early && out->subcommand_count < cmd_count;

  /* Dynamic substitution routes carry topology into an execution endpoint,
   * directly or through an expandable heredoc document. A named-FD input
   * process substitution remains a setup-only FD_OPEN route until a later
   * exact descriptor use. Resolve owners after all command nodes have been
   * visited. A group-owned stream is marked on every contained simple command
   * because any can consume its inherited descriptor. Only a flagged
   * shell-word edge states a requirement on the commands it reaches. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++) {
    const shell_dep_edge_t *edge = &graph.edges[ei];
    if (!sg_edge_is_dynamic_substitution_route(&graph, edge))
      continue;
    bool shell_word = (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0;
    uint32_t consumer_nodes[SHELL_DEP_MAX_NODES];
    uint32_t consumer_count = sg_dynamic_substitution_route_consumers(
        &graph, graph_index, edge, consumer_nodes);
    for (uint32_t consumer_index = 0; consumer_index < consumer_count;
         consumer_index++) {
      uint32_t consumer_node = consumer_nodes[consumer_index];
      if (graph.nodes[consumer_node].type == SHELL_NODE_GROUP) {
        graph_index->group_substitution[consumer_node] |= shell_word ? 3 : 1;
        continue;
      }
      uint32_t result_index = node_result_index[consumer_node];
      if (result_index == UINT32_MAX)
        continue;
      out->subcommands[result_index].has_dynamic_substitution_io = true;
      if (shell_word)
        out->subcommands[result_index].requirements |=
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD;
    }
  }

  sg_mark_group_substitution_consumers(&graph, graph_index, &policy_graph,
                                       node_result_index, out);

  out->truncated = bw.overflow || subcommand_truncated;
  out->subcommand_truncated = subcommand_truncated;
  if (subcommand_truncated) {
    /* The retained prefix cannot authorize a command composition whose tail
     * was not evaluated. Partial subcommand details remain available. */
    out->verdict = SG_VERDICT_UNDETERMINED;
    free(owned_cmd_seq);
    free(owned_type_seq);
    return SG_ERR_TRUNC;
  }
  /* Policy evaluation failures remain errors even when another part of the
   * composition is an argv-less redirect-only operation.  Undetermined is a
   * useful verdict for the latter, but it must not hide an allocation or
   * canonical-policy failure encountered while evaluating a real command. */
  if (evaluation_error != SG_OK) {
    out->verdict = SG_VERDICT_UNDETERMINED;
    free(owned_cmd_seq);
    free(owned_type_seq);
    return evaluation_error;
  }
  if (out->subcommand_count == 0 && !has_unpolicyable_io_only_command) {
    /* Truncation that leaves no subcommands means nothing was evaluated at all.
     * Reporting ALLOW/SG_OK would fail open on input the gate never inspected,
     * so surface it as undetermined and propagate the truncation error. */
    free(owned_cmd_seq);
    free(owned_type_seq);
    if (out->truncated) {
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    out->verdict =
        (out->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC)
            ? SG_VERDICT_UNDETERMINED
            : SG_VERDICT_ALLOW;
    return SG_OK;
  }

  /* Each output is its most restrictive subcommand; the verdict is the most
   * restrictive output. An argv-less redirect and unresolved arithmetic are
   * UNDETERMINED: they must not mask a stricter result in the same list. */
  bool floor_undetermined =
      has_unpolicyable_io_only_command ||
      (out->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC);
  out->output_count = sg_output_total(gate);
  for (uint32_t k = 0; k < out->output_count; k++) {
    out->outputs[k] = sg_aggregate_output(out, k, floor_undetermined);
    if (k == 0 || sg_verdict_rank(out->outputs[k].verdict) >
                      sg_verdict_rank(out->verdict))
      out->verdict = out->outputs[k].verdict;
  }
  out->deciding_user_data =
      sg_scalar_user_data(out->outputs, out->output_count, out->verdict);
  if (has_unpolicyable_io_only_command &&
      out->verdict == SG_VERDICT_UNDETERMINED && !out->deny_reason)
    out->deny_reason = bw_copy(
        &bw, "redirect-only shell operation is not argv-policy-evaluable", 58);

  /* Rendering is part of evaluation success. A caller that receives a
   * truncated result will normally retry with a larger buffer, so no learning
   * or calibration state may change until every diagnostic has fit. */
  if (bw.overflow) {
    out->truncated = true;
    free(owned_cmd_seq);
    free(owned_type_seq);
    return sg_fail_undetermined(out, SG_ERR_TRUNC);
  }

  /* Deferred anomaly model update — after a complete verdict is known. */
  if (gate->anomaly_enabled && gate->anomaly_model && anomaly_count > 0 &&
      !(out->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC)) {
    bool should_update = false;
    if (!gate->anomaly_update_only_on_allow) {
      /* Always update, but skip if anomalous and flag is set */
      should_update = !out->anomaly_detected || !gate->anomaly_skip_on_detected;
      if (!should_update)
        out->anomaly_update = SG_ANOMALY_UPDATE_SKIPPED_DETECTED;
    } else if (out->verdict == SG_VERDICT_ALLOW && out->requirements == 0) {
      /* Only update on an ALLOW with nothing outstanding to inspect */
      should_update = !out->anomaly_detected || !gate->anomaly_skip_on_detected;
      if (!should_update)
        out->anomaly_update = SG_ANOMALY_UPDATE_SKIPPED_DETECTED;
    } else {
      out->anomaly_update = SG_ANOMALY_UPDATE_SKIPPED_VERDICT;
    }

    /* A resource-failed transaction must not enter adaptive/CDF calibration.
     * Policy-configured learning skips retain their established independent
     * score-history behavior. */
    bool record_history = true;
    if (should_update) {
      sg_anomaly_status_t update_status = sg_anomaly_models_update_netseq_pair(
          gate->anomaly_model, owned_cmd_seq, cmd_seq_length,
          gate->anomaly_model_type && type_count > 0 ? gate->anomaly_model_type
                                                     : NULL,
          type_seq, type_seq_length);
      if (update_status != SG_ANOMALY_OK &&
          update_status != SG_ANOMALY_ERR_MEMORY &&
          update_status != SG_ANOMALY_ERR_LIMIT) {
        out->anomaly_update = SG_ANOMALY_UPDATE_FAILED_FORMAT;
        free(owned_cmd_seq);
        free(owned_type_seq);
        return sg_fail_undetermined(out, SG_ERR_PARSE);
      }
      /* Learning resource failures are non-fatal by contract, but the sample
       * did not enter either model. Do not let a retry distort adaptive or CDF
       * calibration with a score whose learning transaction was rolled back. */
      record_history = update_status == SG_ANOMALY_OK;
      if (update_status == SG_ANOMALY_OK)
        out->anomaly_update = SG_ANOMALY_UPDATE_APPLIED;
      else if (update_status == SG_ANOMALY_ERR_LIMIT)
        out->anomaly_update = SG_ANOMALY_UPDATE_REJECTED_LIMIT;
      else
        out->anomaly_update = SG_ANOMALY_UPDATE_FAILED_MEMORY;
    }

    if (record_history && !out->anomaly_detected && anomaly_count >= 3) {
      bool was_bayesian = anomaly_uses_bayesian(gate);
      if (gate->anomaly_combine_mode == SG_ANOMALY_COMBINE_BAYESIAN) {
        cdf_record(gate->cdf_raw_hist, &gate->cdf_raw_count,
                   out->anomaly_score_raw);
        cdf_record(gate->cdf_type_hist, &gate->cdf_type_count,
                   out->anomaly_score_type);
      }
      /* The last weighted warm-up score cannot enter a log-odds window.
       * Commit the CDF transition only after the evaluation/learning
       * transaction succeeds, retaining its component distributions. */
      if (was_bayesian != anomaly_uses_bayesian(gate))
        adaptive_reset(gate);
      else if (gate->anomaly_adaptive && isfinite(out->anomaly_score))
        adaptive_record_score(gate, out->anomaly_score);
    }
  }

  /* Free evaluation-owned anomaly sequence buffers. */
  free(owned_cmd_seq);
  free(owned_type_seq);

  return SG_OK;
}

/* --- HELPERS --- */

size_t sg_gate_evaluate_size_hint(size_t cmd_len) {
  size_t workspace_size = 0;
  if (!sg_eval_workspace_size(cmd_len, &workspace_size))
    return SIZE_MAX;
  size_t alignment = shell_dep_workspace_alignment();
  if (alignment == 0 || cmd_len > (SIZE_MAX - 512) / 4)
    return SIZE_MAX;
  size_t output_size = cmd_len * 4 + 512;
  if (workspace_size > SIZE_MAX - output_size)
    return SIZE_MAX;
  size_t total = output_size + workspace_size;
  if (alignment - 1 > SIZE_MAX - total)
    return SIZE_MAX;
  return total + alignment - 1;
}

const char *sg_verdict_name(sg_verdict_t v) {
  switch (v) {
  case SG_VERDICT_ALLOW:
    return "ALLOW";
  case SG_VERDICT_DENY:
    return "DENY";
  case SG_VERDICT_REJECT:
    return "REJECT";
  case SG_VERDICT_UNDETERMINED:
    return "UNDETERMINED";
  case SG_VERDICT_REVIEW:
    return "REVIEW";
  case SG_VERDICT_AUDIT:
    return "AUDIT";
  case SG_VERDICT_NEEDS_REASON:
    return "NEEDS_REASON";
  case SG_VERDICT_DISCOURAGE:
    return "DISCOURAGE";
  case SG_VERDICT_DENY_ESCALATE:
    return "DENY_ESCALATE";
  }
  return "UNKNOWN";
}
