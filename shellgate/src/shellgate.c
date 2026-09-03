/*
 * shellgate.c - Shell command policy gate
 *
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 */

#include "shellgate.h"
#include "sg_anomaly.h"
#include "sg_anomaly_internal.h"
#include "sg_io.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_depgraph_internal.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shelltype.h"
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XXH_STATIC_LINKING_ONLY
#include "sg_alloc.h"
#include <xxhash.h>

#define CDF_NUM_BUCKETS 128
#define CDF_MAX_SCORE 50.0
#define CDF_DEFAULT_MIN_SAMPLES 128

/* --- PORTABLE strlcpy --- */

static size_t sg_strlcpy(char *dst, const char *src, size_t size) {
  size_t slen = strlen(src);
  if (size > 0) {
    size_t copy = slen < size - 1 ? slen : size - 1;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
  }
  return slen;
}

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
  if (copy == 0 && avail <= 1) {
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

static const char *bw_copy_policy_cpl(buf_writer_t *w, const char *netpattern) {
  char *cpl = NULL;
  if (st_netpattern_to_cpl(netpattern, &cpl) != ST_OK)
    return NULL;
  const char *copy = bw_copy(w, cpl, strlen(cpl));
  free(cpl);
  return copy;
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
static const char *type_cache_lookup(type_cache_t *c, const char *key,
                                     size_t key_len, size_t *value_count) {
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
      return c->entries[c->count - 1].value;
    }
  }
  return NULL;
}

/* Insert or update. Evicts LRU (front) if full.
 * Takes ownership of value on success; caller must NOT free it.
 * Returns true on success, false on allocation failure. */
static bool type_cache_insert(type_cache_t *c, const char *key, size_t key_len,
                              char *value, size_t value_count) {
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
  c->count++;
  return true;
}

/* --- GATE STATE --- */

struct sg_gate {
  st_policy_ctx_t *pctx;
  st_policy_t *policy;
  st_policy_t *deny_policy;

  char cwd[512];
  uint32_t reject_mask;
  sg_stop_mode_t stop_mode;
  bool suggestions;
  bool strict_mode;

  sg_expand_netargv_fn expand_var_netargv_fn;
  void *expand_var_netargv_ctx;
  sg_expand_netargv_fn expand_glob_netargv_fn;
  void *expand_glob_netargv_ctx;

  bool viol_enabled;
  sg_violation_config_t viol_config;

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
  size_t cdf_bucket_count; /* minimum samples before Bayesian is ready */
  size_t cdf_raw_count;    /* observed normal samples (raw) */
  size_t cdf_type_count;   /* observed normal samples (type) */
  size_t *cdf_raw_hist;    /* histogram buckets for raw scores */
  size_t *cdf_type_hist;   /* histogram buckets for type scores */

  /* Adaptive threshold */
  bool anomaly_adaptive;          /* use adaptive threshold (default false) */
  size_t anomaly_window_size;     /* rolling window capacity (default 1000) */
  double anomaly_k_factor;        /* stddev multiplier (default 3.0) */
  double *anomaly_score_buf;      /* circular buffer of normal scores */
  size_t anomaly_score_count;     /* entries currently in buffer */
  size_t anomaly_score_idx;       /* next write position (circular) */
  bool anomaly_adaptive_armed;    /* window is full, threshold is computed */
  double anomaly_fixed_threshold; /* saved fixed threshold for fallback */

  /* Type sequence LRU cache */
  type_cache_t anomaly_type_cache; /* LRU cache for type sequences */
};

/* --- LIFECYCLE --- */

sg_gate_t *sg_gate_new(void) {
  sg_gate_t *g = calloc(1, sizeof(*g));
  if (!g)
    return NULL;

  g->pctx = st_policy_ctx_new();
  if (!g->pctx) {
    free(g);
    return NULL;
  }

  g->policy = st_policy_new(g->pctx);
  if (!g->policy) {
    st_policy_ctx_release(g->pctx);
    free(g);
    return NULL;
  }

  g->deny_policy = st_policy_new(g->pctx);
  if (!g->deny_policy) {
    st_policy_free(g->policy);
    st_policy_ctx_release(g->pctx);
    free(g);
    return NULL;
  }

  sg_strlcpy(g->cwd, ".", sizeof(g->cwd));
  g->reject_mask = SG_REJECT_MASK_DEFAULT;
  g->stop_mode = SG_EVAL_ALL;
  g->suggestions = true;
  g->strict_mode = true;

  /* Anomaly detection defaults */
  g->anomaly_update_only_on_allow = false;
  g->anomaly_skip_on_detected = true;
  g->anomaly_weight_raw = 0.5;
  g->anomaly_weight_type = 0.5;

  return g;
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
  if (gate->policy)
    st_policy_free(gate->policy);
  if (gate->deny_policy)
    st_policy_free(gate->deny_policy);
  if (gate->pctx)
    st_policy_ctx_release(gate->pctx);
  free(gate);
}

/* --- CONFIGURATION --- */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd) {
  if (!gate || !cwd)
    return SG_ERR_INVALID;
  if (strlen(cwd) >= sizeof(gate->cwd))
    return SG_ERR_TRUNC;
  sg_strlcpy(gate->cwd, cwd, sizeof(gate->cwd));
  return SG_OK;
}

sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->reject_mask = mask;
  return SG_OK;
}

sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode) {
  if (!gate || mode < SG_STOP_FIRST_FAIL || mode > SG_EVAL_ALL)
    return SG_ERR_INVALID;
  gate->stop_mode = mode;
  return SG_OK;
}

sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->suggestions = enabled;
  return SG_OK;
}

sg_error_t sg_gate_set_expand_var_netargv(sg_gate_t *gate,
                                          sg_expand_netargv_fn fn,
                                          void *user_ctx) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->expand_var_netargv_fn = fn;
  gate->expand_var_netargv_ctx = user_ctx;
  return SG_OK;
}

sg_error_t sg_gate_set_expand_glob_netargv(sg_gate_t *gate,
                                           sg_expand_netargv_fn fn,
                                           void *user_ctx) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->expand_glob_netargv_fn = fn;
  gate->expand_glob_netargv_ctx = user_ctx;
  return SG_OK;
}

static bool config_array_valid(const char *const *values, uint32_t count,
                               uint32_t capacity) {
  if (count > capacity)
    return false;
  for (uint32_t i = 0; i < count; i++)
    if (!values[i])
      return false;
  return true;
}

sg_error_t
sg_gate_set_violation_config_borrowed(sg_gate_t *gate,
                                      const sg_violation_config_t *config) {
  if (!gate || !config)
    return SG_ERR_INVALID;
  if (!config_array_valid(config->sensitive_write_paths,
                          config->sensitive_write_path_count,
                          SG_VIOL_MAX_PATHS) ||
      !config_array_valid(config->sensitive_dirs, config->sensitive_dir_count,
                          SG_VIOL_MAX_PATHS) ||
      !config_array_valid(config->sensitive_env_names,
                          config->sensitive_env_name_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->sensitive_cmd_names,
                          config->sensitive_cmd_name_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->sensitive_read_paths,
                          config->sensitive_read_path_count,
                          SG_VIOL_MAX_PATHS) ||
      !config_array_valid(config->download_cmds, config->download_cmd_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->shell_spawn_cmds,
                          config->shell_spawn_cmd_count, SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->perm_mod_cmds, config->perm_mod_cmd_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->sensitive_secret_paths,
                          config->sensitive_secret_path_count,
                          SG_VIOL_MAX_PATHS) ||
      !config_array_valid(config->file_reading_cmds,
                          config->file_reading_cmd_count, SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->upload_cmds, config->upload_cmd_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->listener_cmds, config->listener_cmd_count,
                          SG_VIOL_MAX_NAMES) ||
      !config_array_valid(config->shell_profile_paths,
                          config->shell_profile_path_count, SG_VIOL_MAX_PATHS))
    return SG_ERR_INVALID;
  gate->viol_enabled = true;
  gate->viol_config = *config;
  return SG_OK;
}

/* --- ANOMALY DETECTION CONFIGURATION --- */

sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate, double threshold,
                                  const sg_anomaly_config_t *config) {
  if (!gate || !isfinite(threshold))
    return SG_ERR_INVALID;
  if (config && (!isfinite(config->alpha) || config->alpha <= 0.0 ||
                 !isfinite(config->unknown_log_prior)))
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
    if (adaptive_window == 0)
      adaptive_window = 1000;
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
    gate->anomaly_window_size = adaptive_window;
  }
  gate->anomaly_enabled = true;
  gate->anomaly_threshold = threshold;
  gate->anomaly_update_only_on_allow = false;
  gate->anomaly_skip_on_detected = true;
  gate->anomaly_weight_raw = 0.5;
  gate->anomaly_weight_type = 0.5;
  gate->anomaly_combine_mode = SG_ANOMALY_COMBINE_WEIGHTED;
  gate->anomaly_fixed_threshold = threshold;
  /* Reset observations while preserving adaptive configuration. */
  gate->anomaly_score_count = 0;
  gate->anomaly_score_idx = 0;
  gate->anomaly_adaptive_armed = false;
  cdf_free(gate);
  return SG_OK;
}

void sg_gate_disable_anomaly(sg_gate_t *gate) {
  if (!gate)
    return;
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
  gate->anomaly_score_count = 0;
  gate->anomaly_score_idx = 0;
  gate->anomaly_adaptive_armed = false;
  type_cache_clear(&gate->anomaly_type_cache);
  cdf_free(gate);
}

sg_error_t sg_gate_set_anomaly_update_mode(sg_gate_t *gate,
                                           bool update_only_on_allow) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->anomaly_update_only_on_allow = update_only_on_allow;
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_skip_on_detected(sg_gate_t *gate, bool skip) {
  if (!gate)
    return SG_ERR_INVALID;
  gate->anomaly_skip_on_detected = skip;
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_weights(sg_gate_t *gate, double weight_raw,
                                       double weight_type) {
  if (!gate)
    return SG_ERR_INVALID;
  if (!isfinite(weight_raw) || !isfinite(weight_type) || weight_raw < 0.0 ||
      weight_type < 0.0)
    return SG_ERR_INVALID;
  /* Weights must sum to approximately 1.0 */
  double sum = weight_raw + weight_type;
  if (sum < 0.99 || sum > 1.01)
    return SG_ERR_INVALID;
  gate->anomaly_weight_raw = weight_raw;
  gate->anomaly_weight_type = weight_type;
  return SG_OK;
}

/* --- ADAPTIVE THRESHOLD --- */

static void adaptive_recompute_threshold(sg_gate_t *gate) {
  if (!gate->anomaly_score_buf || gate->anomaly_score_count == 0)
    return;

  /* Compute mean */
  double sum = 0.0;
  size_t n = gate->anomaly_score_count < gate->anomaly_window_size
                 ? gate->anomaly_score_count
                 : gate->anomaly_window_size;
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

static void adaptive_record_score(sg_gate_t *gate, double score) {
  if (!gate->anomaly_score_buf)
    return;
  if (!isfinite(score))
    return;

  gate->anomaly_score_buf[gate->anomaly_score_idx] = score;
  gate->anomaly_score_idx =
      (gate->anomaly_score_idx + 1) % gate->anomaly_window_size;
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
  if (!gate)
    return SG_ERR_INVALID;
  if (adaptive && window_size == 0)
    return SG_ERR_INVALID;

  if (!adaptive) {
    gate->anomaly_adaptive = false;
    gate->anomaly_adaptive_armed = false;
    gate->anomaly_threshold = gate->anomaly_fixed_threshold;
    free(gate->anomaly_score_buf);
    gate->anomaly_score_buf = NULL;
    gate->anomaly_score_count = 0;
    gate->anomaly_score_idx = 0;
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
  gate->anomaly_score_count = 0;
  gate->anomaly_score_idx = 0;
  gate->anomaly_adaptive = true;
  gate->anomaly_adaptive_armed = false;
  /* Threshold stays as fixed until window fills */
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_k_factor(sg_gate_t *gate, double k) {
  if (!gate)
    return SG_ERR_INVALID;
  if (!isfinite(k) || k < 0.0)
    return SG_ERR_INVALID;
  gate->anomaly_k_factor = k;
  /* Recompute threshold if already armed */
  if (gate->anomaly_adaptive_armed)
    adaptive_recompute_threshold(gate);
  return SG_OK;
}

sg_error_t sg_gate_set_anomaly_cache_size(sg_gate_t *gate, size_t cache_size) {
  if (!gate)
    return SG_ERR_INVALID;
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

static void cdf_record(size_t *hist, size_t *total, double score) {
  if (!hist)
    return;
  if (!isfinite(score) || score < 0.0)
    return;
  size_t bucket = (size_t)(score / CDF_MAX_SCORE * CDF_NUM_BUCKETS);
  if (bucket >= CDF_NUM_BUCKETS)
    bucket = CDF_NUM_BUCKETS - 1;
  hist[bucket]++;
  (*total)++;
}

static double cdf_log_odds(const size_t *hist, size_t total, double score) {
  if (!hist || total == 0)
    return 0.0;
  if (!isfinite(score) || score < 0.0)
    return 0.0;

  size_t bucket = (size_t)(score / CDF_MAX_SCORE * CDF_NUM_BUCKETS);
  if (bucket >= CDF_NUM_BUCKETS)
    bucket = CDF_NUM_BUCKETS - 1;

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
  gate->cdf_raw_count = 0;
  gate->cdf_type_count = 0;
}

static bool cdf_ready(const sg_gate_t *gate) {
  size_t min_samples = gate->cdf_bucket_count;
  return gate->cdf_raw_count >= min_samples &&
         gate->cdf_type_count >= min_samples;
}

static void combine_anomaly_scores(const sg_gate_t *gate, double raw_score,
                                   double type_score, double *combined) {
  if (gate->anomaly_combine_mode == SG_ANOMALY_COMBINE_BAYESIAN &&
      cdf_ready(gate)) {
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
  if (out)
    *out =
        (sg_anomaly_sequence_score_t){INFINITY, INFINITY, INFINITY, false, 0};
  if (!gate || !raw_netseq || !type_netseq || !out)
    return SG_ERR_INVALID;
  if (!gate->anomaly_enabled || !gate->anomaly_model ||
      !gate->anomaly_model_type)
    return SG_ERR_INVALID;
  size_t raw_count = 0, type_count = 0;
  if (sg_anomaly_netseq_count(raw_netseq, raw_length, false, &raw_count) !=
          SG_ANOMALY_OK ||
      sg_anomaly_netseq_count(type_netseq, type_length, false, &type_count) !=
          SG_ANOMALY_OK ||
      raw_count != type_count)
    return SG_ERR_PARSE;
  sg_anomaly_status_t raw_status = sg_anomaly_model_score_netseq(
      gate->anomaly_model, raw_netseq, raw_length, &out->raw_score);
  sg_anomaly_status_t type_status = sg_anomaly_model_score_netseq(
      gate->anomaly_model_type, type_netseq, type_length, &out->type_score);
  if (raw_status == SG_ANOMALY_ERR_MEMORY ||
      type_status == SG_ANOMALY_ERR_MEMORY)
    return SG_ERR_MEMORY;
  if (raw_status != SG_ANOMALY_OK || type_status != SG_ANOMALY_OK)
    return SG_ERR_PARSE;
  out->command_count = raw_count;
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
  if (!gate)
    return SG_ERR_INVALID;
  if (mode != SG_ANOMALY_COMBINE_WEIGHTED &&
      mode != SG_ANOMALY_COMBINE_BAYESIAN)
    return SG_ERR_INVALID;

  if (mode == SG_ANOMALY_COMBINE_BAYESIAN && !gate->cdf_raw_hist) {
    gate->cdf_raw_hist = calloc(CDF_NUM_BUCKETS, sizeof(size_t));
    gate->cdf_type_hist = calloc(CDF_NUM_BUCKETS, sizeof(size_t));
    if (!gate->cdf_raw_hist || !gate->cdf_type_hist) {
      cdf_free(gate);
      return SG_ERR_MEMORY;
    }
    gate->cdf_bucket_count = gate->anomaly_window_size > 0
                                 ? gate->anomaly_window_size
                                 : CDF_DEFAULT_MIN_SAMPLES;
  }

  gate->anomaly_combine_mode = mode;
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

static sg_error_t errno_to_gate_error(void) {
  return errno == ENOMEM ? SG_ERR_MEMORY : SG_ERR_IO;
}

static sg_error_t process_status_to_gate_error(shell_process_status_t status) {
  if (status == SHELL_PROCESS_ENOMEM)
    return SG_ERR_MEMORY;
  if (status == SHELL_PROCESS_EOUTPUT_LIMIT)
    return SG_ERR_TRUNC;
  return SG_ERR_PARSE;
}

static int stream_size(FILE *stream, uint64_t *size) {
  if (fseek(stream, 0, SEEK_END) != 0)
    return -1;
  long end = ftell(stream);
  if (end < 0)
    return -1;
  *size = (uint64_t)end;
  return fseek(stream, 0, SEEK_SET);
}

static int copy_stream(FILE *from, FILE *to, uint64_t count,
                       XXH3_state_t *hash) {
  unsigned char buffer[16384];
  while (count > 0) {
    size_t chunk = count < sizeof(buffer) ? (size_t)count : sizeof(buffer);
    if (fread(buffer, 1, chunk, from) != chunk ||
        (to && fwrite(buffer, 1, chunk, to) != chunk) ||
        (hash && XXH3_64bits_update(hash, buffer, chunk) == XXH_ERROR))
      return -1;
    count -= chunk;
  }
  return 0;
}

sg_error_t sg_gate_save_anomaly_model(const sg_gate_t *gate, const char *path) {
  if (!gate || !path || !gate->anomaly_enabled || !gate->anomaly_model ||
      !gate->anomaly_model_type)
    return SG_ERR_INVALID;

  FILE *raw = tmpfile();
  FILE *type = tmpfile();
  if (!raw || !type) {
    if (raw)
      fclose(raw);
    if (type)
      fclose(type);
    return errno_to_gate_error();
  }
  errno = 0;
  uint64_t raw_size = 0, type_size = 0;
  if (sg_anomaly_write_stream(gate->anomaly_model, raw) != 0 ||
      sg_anomaly_write_stream(gate->anomaly_model_type, type) != 0 ||
      stream_size(raw, &raw_size) != 0 || stream_size(type, &type_size) != 0 ||
      raw_size > UINT64_MAX - type_size) {
    sg_error_t error = errno_to_gate_error();
    fclose(raw);
    fclose(type);
    return error;
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
  int failed =
      fwrite(header, 1, sizeof(header), output.stream) != sizeof(header) ||
      copy_stream(raw, output.stream, raw_size, hash) != 0 ||
      copy_stream(type, output.stream, type_size, hash) != 0;
  if (!failed) {
    store_u64_le(header + 24, XXH3_64bits_digest(hash));
    failed = fseek(output.stream, 0, SEEK_SET) != 0 ||
             fwrite(header, 1, sizeof(header), output.stream) != sizeof(header);
  }
  XXH3_freeState(hash);
  fclose(raw);
  fclose(type);
  if (failed || sg_atomic_output_commit(&output) != 0) {
    if (output.temporary_path)
      sg_atomic_output_discard(&output);
    return SG_ERR_IO;
  }
  return SG_OK;
}

sg_error_t sg_gate_load_anomaly_model(sg_gate_t *gate, const char *path) {
  if (!gate || !path || !gate->anomaly_enabled || !gate->anomaly_model ||
      !gate->anomaly_model_type)
    return SG_ERR_INVALID;

  FILE *bundle = fopen(path, "rb");
  if (!bundle)
    return errno_to_gate_error();
  unsigned char header[SG_BUNDLE_HEADER_SIZE];
  if (fread(header, 1, sizeof(header), bundle) != sizeof(header)) {
    bool io_error = ferror(bundle) != 0;
    fclose(bundle);
    return io_error ? SG_ERR_IO : SG_ERR_PARSE;
  }
  uint64_t raw_size = load_u64_le(header + 8);
  uint64_t type_size = load_u64_le(header + 16);
  uint64_t expected_hash = load_u64_le(header + 24);
  uint64_t file_size = 0;
  if (memcmp(header, sg_bundle_magic, sizeof(sg_bundle_magic)) != 0 ||
      raw_size == 0 || type_size == 0 || raw_size > UINT64_MAX - type_size ||
      raw_size + type_size > UINT64_MAX - SG_BUNDLE_HEADER_SIZE ||
      stream_size(bundle, &file_size) != 0) {
    fclose(bundle);
    return SG_ERR_PARSE;
  }
  if (file_size != SG_BUNDLE_HEADER_SIZE + raw_size + type_size ||
      fseek(bundle, SG_BUNDLE_HEADER_SIZE, SEEK_SET) != 0) {
    fclose(bundle);
    return SG_ERR_PARSE;
  }

  XXH3_state_t *hash = XXH3_createState();
  if (!hash) {
    fclose(bundle);
    return SG_ERR_MEMORY;
  }
  XXH3_64bits_reset(hash);
  int hash_failed = copy_stream(bundle, NULL, raw_size + type_size, hash) != 0;
  uint64_t actual_hash = XXH3_64bits_digest(hash);
  XXH3_freeState(hash);
  if (hash_failed || actual_hash != expected_hash ||
      fseek(bundle, SG_BUNDLE_HEADER_SIZE, SEEK_SET) != 0) {
    fclose(bundle);
    return hash_failed ? SG_ERR_IO : SG_ERR_PARSE;
  }

  FILE *raw = tmpfile();
  FILE *type = tmpfile();
  if (!raw || !type) {
    if (raw)
      fclose(raw);
    if (type)
      fclose(type);
    fclose(bundle);
    return errno_to_gate_error();
  }
  int copy_failed = copy_stream(bundle, raw, raw_size, NULL) != 0 ||
                    copy_stream(bundle, type, type_size, NULL) != 0 ||
                    fseek(raw, 0, SEEK_SET) != 0 ||
                    fseek(type, 0, SEEK_SET) != 0;
  fclose(bundle);
  if (copy_failed) {
    fclose(raw);
    fclose(type);
    return SG_ERR_IO;
  }

  sg_anomaly_model_t *loaded_raw = sg_anomaly_model_new();
  sg_anomaly_model_t *loaded_type = sg_anomaly_model_new();
  if (!loaded_raw || !loaded_type) {
    sg_anomaly_model_free(loaded_raw);
    sg_anomaly_model_free(loaded_type);
    fclose(raw);
    fclose(type);
    return SG_ERR_MEMORY;
  }
  errno = 0;
  int raw_result = sg_anomaly_read_stream(loaded_raw, raw);
  int raw_errno = errno;
  errno = 0;
  int type_result = sg_anomaly_read_stream(loaded_type, type);
  int type_errno = errno;
  fclose(raw);
  fclose(type);
  if (raw_result != 0 || type_result != 0) {
    sg_anomaly_model_free(loaded_raw);
    sg_anomaly_model_free(loaded_type);
    if (raw_errno == ENOMEM || type_errno == ENOMEM)
      return SG_ERR_MEMORY;
    return SG_ERR_PARSE;
  }

  sg_anomaly_model_free(gate->anomaly_model);
  sg_anomaly_model_free(gate->anomaly_model_type);
  gate->anomaly_model = loaded_raw;
  gate->anomaly_model_type = loaded_type;
  type_cache_clear(&gate->anomaly_type_cache);
  return SG_OK;
}

bool sg_gate_anomaly_had_error(const sg_gate_t *gate) {
  if (!gate || !gate->anomaly_model)
    return false;
  return sg_anomaly_model_had_error(gate->anomaly_model) ||
         sg_anomaly_model_had_error(gate->anomaly_model_type);
}

size_t sg_gate_anomaly_vocab_size(const sg_gate_t *gate) {
  if (!gate || !gate->anomaly_model)
    return 0;
  return sg_anomaly_model_vocab_size(gate->anomaly_model);
}

/* --- SUGGESTION TOKEN VARIANTS --- */

/*
 * Given a suggestion pattern string and a token position, return type variants
 * for editing. Chain: literal → most_specific (via st_token_classify) → ...
 *        ... → suggested_wildcard (from suggestion) → ... → #any
 *
 * Variants walk from more specific to more general.
 * st_type_join gives the widening direction toward ST_TYPE_ANY.
 */
size_t sg_cpl_token_variants_at(const char *pattern, size_t edit_pos,
                                st_token_variant_t *out_variants,
                                size_t max_variants) {
  if (!pattern || !out_variants || max_variants == 0)
    return 0;
  if (pattern[0] == '\0')
    return 0;

  char *netpattern = NULL;
  st_token_array_t decoded = {0};
  if (st_netpattern_from_cpl(pattern, &netpattern) != ST_OK ||
      st_netpattern_decode(netpattern, &decoded) != ST_OK) {
    free(netpattern);
    return 0;
  }
  free(netpattern);
  size_t out =
      st_token_variants_at(&decoded, edit_pos, out_variants, max_variants);
  st_token_array_free(&decoded);
  return out;
}

/* --- POLICY MANAGEMENT --- */

static sg_error_t policy_mutation_error(st_error_t error) {
  switch (error) {
  case ST_OK:
    return SG_OK;
  case ST_ERR_MEMORY:
    return SG_ERR_MEMORY;
  case ST_ERR_IO:
    return SG_ERR_IO;
  case ST_ERR_INVALID:
  case ST_ERR_FAILED:
  case ST_ERR_FORMAT:
  case ST_ERR_LIMIT:
    return SG_ERR_INVALID;
  }
  return SG_ERR_INVALID;
}

static sg_error_t gate_add_netpattern(st_policy_t *policy,
                                      const char *netpattern) {
  if (!netpattern)
    return SG_ERR_INVALID;
  return policy_mutation_error(st_policy_add_netpattern(policy, netpattern));
}

static sg_error_t gate_remove_netpattern(st_policy_t *policy,
                                         const char *netpattern) {
  if (!netpattern)
    return SG_ERR_INVALID;
  return policy_mutation_error(st_policy_remove_netpattern(policy, netpattern));
}

static sg_error_t gate_batch_add_netpatterns(st_policy_t *policy,
                                             const char *const *netpatterns,
                                             size_t count) {
  if (!netpatterns || count == 0)
    return SG_ERR_INVALID;
  return policy_mutation_error(
      st_policy_batch_add_netpatterns(policy, netpatterns, count));
}

static sg_error_t policy_load_error(st_error_t error) {
  switch (error) {
  case ST_OK:
    return SG_OK;
  case ST_ERR_MEMORY:
    return SG_ERR_MEMORY;
  case ST_ERR_IO:
    return SG_ERR_IO;
  case ST_ERR_INVALID:
  case ST_ERR_FAILED:
  case ST_ERR_FORMAT:
  case ST_ERR_LIMIT:
    return SG_ERR_PARSE;
  }
  return SG_ERR_PARSE;
}

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path) {
  if (!gate || !path)
    return SG_ERR_INVALID;
  return policy_load_error(
      st_policy_load(gate->policy, path, /*clear_first=*/false));
}

sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path) {
  if (!gate || !path)
    return SG_ERR_INVALID;
  return policy_mutation_error(st_policy_save(gate->policy, path));
}

sg_error_t sg_gate_add_allow_netpattern(sg_gate_t *gate,
                                        const char *netpattern) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_add_netpattern(gate->policy, netpattern);
}

sg_error_t sg_gate_remove_allow_netpattern(sg_gate_t *gate,
                                           const char *netpattern) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_remove_netpattern(gate->policy, netpattern);
}

sg_error_t sg_gate_batch_add_allow_netpatterns(sg_gate_t *gate,
                                               const char *const *netpatterns,
                                               size_t count) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_batch_add_netpatterns(gate->policy, netpatterns, count);
}

sg_error_t sg_gate_add_allow_cpl(sg_gate_t *gate, const char *pattern) {
  if (!gate || !pattern)
    return SG_ERR_INVALID;
  char *netpattern = NULL;
  st_error_t error = st_netpattern_from_cpl(pattern, &netpattern);
  sg_error_t result = error == ST_OK
                          ? sg_gate_add_allow_netpattern(gate, netpattern)
                          : policy_mutation_error(error);
  free(netpattern);
  return result;
}

sg_error_t sg_gate_remove_allow_cpl(sg_gate_t *gate, const char *pattern) {
  if (!gate || !pattern)
    return SG_ERR_INVALID;
  char *netpattern = NULL;
  st_error_t error = st_netpattern_from_cpl(pattern, &netpattern);
  sg_error_t result = error == ST_OK
                          ? sg_gate_remove_allow_netpattern(gate, netpattern)
                          : policy_mutation_error(error);
  free(netpattern);
  return result;
}

size_t sg_gate_allow_rule_count(const sg_gate_t *gate) {
  if (!gate)
    return 0;
  return st_policy_rule_count(gate->policy);
}

sg_error_t sg_gate_add_deny_netpattern(sg_gate_t *gate,
                                       const char *netpattern) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_add_netpattern(gate->deny_policy, netpattern);
}

sg_error_t sg_gate_remove_deny_netpattern(sg_gate_t *gate,
                                          const char *netpattern) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_remove_netpattern(gate->deny_policy, netpattern);
}

sg_error_t sg_gate_batch_add_deny_netpatterns(sg_gate_t *gate,
                                              const char *const *netpatterns,
                                              size_t count) {
  if (!gate)
    return SG_ERR_INVALID;
  return gate_batch_add_netpatterns(gate->deny_policy, netpatterns, count);
}

sg_error_t sg_gate_add_deny_cpl(sg_gate_t *gate, const char *pattern) {
  if (!gate || !pattern)
    return SG_ERR_INVALID;
  char *netpattern = NULL;
  st_error_t error = st_netpattern_from_cpl(pattern, &netpattern);
  sg_error_t result = error == ST_OK
                          ? sg_gate_add_deny_netpattern(gate, netpattern)
                          : policy_mutation_error(error);
  free(netpattern);
  return result;
}

sg_error_t sg_gate_remove_deny_cpl(sg_gate_t *gate, const char *pattern) {
  if (!gate || !pattern)
    return SG_ERR_INVALID;
  char *netpattern = NULL;
  st_error_t error = st_netpattern_from_cpl(pattern, &netpattern);
  sg_error_t result = error == ST_OK
                          ? sg_gate_remove_deny_netpattern(gate, netpattern)
                          : policy_mutation_error(error);
  free(netpattern);
  return result;
}

size_t sg_gate_deny_rule_count(const sg_gate_t *gate) {
  if (!gate)
    return 0;
  return st_policy_rule_count(gate->deny_policy);
}

/* --- INTERNAL: TOKEN EXPANSION HELPERS --- */

static bool extract_var_name(const char *tok, size_t len, const char **name,
                             size_t *name_length) {
  if (len < 2 || tok[0] != '$')
    return false;

  size_t start = 1;
  size_t end = len;

  if (len > 3 && tok[1] == '{' && tok[len - 1] == '}') {
    start = 2;
    end = len - 1;
  }

  size_t nlen = end - start;
  if (nlen == 0)
    return false;

  for (size_t i = start; i < end; i++) {
    char c = tok[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_'))
      return false;
  }

  *name = tok + start;
  *name_length = nlen;
  return true;
}

static bool has_glob_chars(const char *tok, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (tok[i] == '*' || tok[i] == '?' || tok[i] == '[')
      return true;
  }
  return false;
}

/* --- INTERNAL: BUILD COMMAND STRING WITH OPTIONAL EXPANSION --- */

static bool measure_expansion_display(const char *encoded, size_t length,
                                      size_t *display_length) {
  if (!display_length)
    return false;
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, encoded, length) != SHELL_NETSTRING_OK)
    return false;
  size_t used = 0, count = 0;
  shell_netstring_view_t view;
  shell_netstring_status_t status;
  while ((status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    size_t separator = count != 0 ? 1 : 0;
    if (used > SIZE_MAX - separator ||
        view.payload_length > SIZE_MAX - used - separator)
      return false;
    if (memchr(view.payload, '\0', view.payload_length) != NULL)
      return false;
    used += (count != 0) + view.payload_length;
    count++;
  }
  if (status != SHELL_NETSTRING_DONE)
    return false;
  *display_length = used;
  return true;
}

static bool write_expansion_display(const char *encoded, size_t length,
                                    char *display, size_t display_size,
                                    size_t *written) {
  if (written)
    *written = 0;
  if (!display || !written)
    return false;
  size_t measured = 0;
  if (!measure_expansion_display(encoded, length, &measured) ||
      measured >= display_size)
    return false;
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, encoded, length) != SHELL_NETSTRING_OK)
    return false;
  size_t used = 0, count = 0;
  shell_netstring_view_t view;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    if (count)
      display[used++] = ' ';
    memcpy(display + used, view.payload, view.payload_length);
    used += view.payload_length;
    count++;
  }
  display[used] = '\0';
  *written = used;
  return true;
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

static bool valid_expansion_netargv(const char *netargv, size_t length) {
  return (netargv != NULL || length == 0) &&
         (length == 0 || (memchr(netargv, '\0', length) == NULL &&
                          shell_netstring_validate(netargv, length, NULL) ==
                              SHELL_NETSTRING_OK));
}

static const char *build_cmd_string(const shell_dep_cmd_t *cmd,
                                    buf_writer_t *bw, const sg_gate_t *gate,
                                    const char **netargv,
                                    size_t *netargv_length,
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
    word->text = cmd->tokens[i];
    word->text_length = cmd->token_lens[i];

    if (gate->expand_var_netargv_fn) {
      const char *var_name = NULL;
      size_t var_name_length = 0;
      if (extract_var_name(word->text, word->text_length, &var_name,
                           &var_name_length)) {
        sg_expand_status_t status = gate->expand_var_netargv_fn(
            var_name, var_name_length, &word->expansion_netargv,
            &word->expansion_length, gate->expand_var_netargv_ctx);
        if (status != SG_EXPAND_UNRESOLVED && status != SG_EXPAND_RESOLVED) {
          *build_error = SG_ERR_EXPAND;
          return NULL;
        }
        word->expanded = status == SG_EXPAND_RESOLVED;
      }
    }
    if (!word->expanded && gate->expand_glob_netargv_fn &&
        has_glob_chars(word->text, word->text_length)) {
      sg_expand_status_t status = gate->expand_glob_netargv_fn(
          word->text, word->text_length, &word->expansion_netargv,
          &word->expansion_length, gate->expand_glob_netargv_ctx);
      if (status != SG_EXPAND_UNRESOLVED && status != SG_EXPAND_RESOLVED) {
        *build_error = SG_ERR_EXPAND;
        return NULL;
      }
      word->expanded = status == SG_EXPAND_RESOLVED;
    }

    if (word->expanded) {
      if (!valid_expansion_netargv(word->expansion_netargv,
                                   word->expansion_length) ||
          !measure_expansion_display(
              word->expansion_netargv ? word->expansion_netargv : "",
              word->expansion_length, &word->display_length)) {
        *build_error = SG_ERR_EXPAND;
        return NULL;
      }
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
    if (display_total > SIZE_MAX - word->display_length - (i != 0) ||
        net_total > SIZE_MAX - record_length) {
      bw_mark_overflow(bw);
      return NULL;
    }
    display_total += (i != 0) + word->display_length;
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
      size_t written = 0;
      if (!write_expansion_display(
              word->expansion_netargv ? word->expansion_netargv : "",
              word->expansion_length, display + display_used,
              word->display_length + 1, &written) ||
          written != word->display_length) {
        *build_error = SG_ERR_EXPAND;
        return NULL;
      }
      display_used += written;
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
      {SHELL_FEAT_ARITH, "arithmetic expansion"},
      {SHELL_FEAT_HEREDOC, "heredoc"},
      {SHELL_FEAT_HERESTRING, "herestring"},
      {SHELL_FEAT_PROCESS_SUB, "process substitution"},
      {SHELL_FEAT_LOOPS, "loop"},
      {SHELL_FEAT_CONDITIONALS, "conditional"},
      {SHELL_FEAT_CASE, "case statement"},
      {SHELL_FEAT_VARS, "variable expansion"},
      {SHELL_FEAT_GLOBS, "glob expansion"},
      {SHELL_FEAT_SUBSHELL_FILE, "file command substitution"},
      {SHELL_FEAT_PIPELINE, "pipeline"},
      {SHELL_FEAT_GROUP, "command group"},
      {SHELL_FEAT_BACKGROUND, "background execution"},
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

/* --- VIOLATION DEFAULT CONFIG --- */

void sg_violation_config_default(sg_violation_config_t *cfg) {
  /* Arrays are kept in a stable human-readable order. Lookup is linear because
   * public configuration permits any order and caps each array at 32 entries.
   */
  static const char *def_write_paths[] = {
      "/bin/",  "/boot/", "/etc/", "/lib/",     "/proc/",
      "/root/", "/sbin/", "/sys/", "/usr/lib/", "/var/lib/",
  };
  static const char *def_dirs[] = {
      "/bin",  "/boot", "/etc", "/lib",     "/opt", "/proc",    "/root",
      "/sbin", "/sys",  "/usr", "/usr/lib", "/var", "/var/lib",
  };
  static const char *def_env[] = {
      "BASH_ENV",        "ENV",        "IFS",  "LD_DEBUG",
      "LD_LIBRARY_PATH", "LD_PRELOAD", "PATH",
  };
  static const char *def_cmds[] = {
      "crontab", "passwd", "scp", "ssh", "su", "sudo",
  };
  static const char *def_reads[] = {
      "/etc/ca-certificates", "/etc/gshadow", "/etc/shadow", "/etc/ssh/",
      "/root/.ssh/",
  };
  memset(cfg, 0, sizeof(*cfg));

  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_write_paths) / sizeof(def_write_paths[0])) &&
       i < SG_VIOL_MAX_PATHS;
       i++)
    cfg->sensitive_write_paths[cfg->sensitive_write_path_count++] =
        def_write_paths[i];

  for (uint32_t i = 0; i < (uint32_t)(sizeof(def_dirs) / sizeof(def_dirs[0])) &&
                       i < SG_VIOL_MAX_PATHS;
       i++)
    cfg->sensitive_dirs[cfg->sensitive_dir_count++] = def_dirs[i];

  for (uint32_t i = 0; i < (uint32_t)(sizeof(def_env) / sizeof(def_env[0])) &&
                       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->sensitive_env_names[cfg->sensitive_env_name_count++] = def_env[i];

  for (uint32_t i = 0; i < (uint32_t)(sizeof(def_cmds) / sizeof(def_cmds[0])) &&
                       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->sensitive_cmd_names[cfg->sensitive_cmd_name_count++] = def_cmds[i];

  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_reads) / sizeof(def_reads[0])) &&
       i < SG_VIOL_MAX_PATHS;
       i++)
    cfg->sensitive_read_paths[cfg->sensitive_read_path_count++] = def_reads[i];

  cfg->redirect_fanout_threshold = 3;

  static const char *def_downloads[] = {"curl", "wget"};
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_downloads) / sizeof(def_downloads[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->download_cmds[cfg->download_cmd_count++] = def_downloads[i];

  static const char *def_spawns[] = {"sh",     "bash", "env", "perl",
                                     "python", "ruby", "node"};
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_spawns) / sizeof(def_spawns[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->shell_spawn_cmds[cfg->shell_spawn_cmd_count++] = def_spawns[i];

  static const char *def_perms[] = {"chmod", "chown", "chgrp"};
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_perms) / sizeof(def_perms[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->perm_mod_cmds[cfg->perm_mod_cmd_count++] = def_perms[i];

  static const char *def_secrets[] = {
      "/.ssh/",    ".env",          "/.aws/",
      "/.kube/",   "/.npmrc",       "/.netrc",
      "/.pgpass",  "/.gitconfig",   "/.git-credentials",
      "/.docker/", "/.vault-token", "/.gnupg/",
  };
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_secrets) / sizeof(def_secrets[0])) &&
       i < SG_VIOL_MAX_PATHS;
       i++)
    cfg->sensitive_secret_paths[cfg->sensitive_secret_path_count++] =
        def_secrets[i];

  static const char *def_readcmds[] = {
      "cat",    "head", "tail", "less",    "more",
      "base64", "xxd",  "od",   "strings", "hexdump",
  };
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_readcmds) / sizeof(def_readcmds[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->file_reading_cmds[cfg->file_reading_cmd_count++] = def_readcmds[i];

  static const char *def_uploads[] = {"curl", "wget", "scp", "rsync"};
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_uploads) / sizeof(def_uploads[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->upload_cmds[cfg->upload_cmd_count++] = def_uploads[i];

  static const char *def_listeners[] = {
      "nc", "ncat", "netcat", "socat", "ngrok", "cloudflared",
  };
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_listeners) / sizeof(def_listeners[0])) &&
       i < SG_VIOL_MAX_NAMES;
       i++)
    cfg->listener_cmds[cfg->listener_cmd_count++] = def_listeners[i];

  static const char *def_profiles[] = {
      "/.bashrc",
      "/.profile",
      "/.zshrc",
      "/.bash_profile",
      "/.ssh/authorized_keys",
      "/.ssh/config",
  };
  for (uint32_t i = 0;
       i < (uint32_t)(sizeof(def_profiles) / sizeof(def_profiles[0])) &&
       i < SG_VIOL_MAX_PATHS;
       i++)
    cfg->shell_profile_paths[cfg->shell_profile_path_count++] = def_profiles[i];
}

/* --- VIOLATION SCANNING HELPERS --- */

/* Exact-match search on a small configured string array. Configuration arrays
 * are public and capped at SG_VIOL_MAX_NAMES, so lookup must not depend on a
 * caller preserving an undocumented sort order. */
static bool sg_name_found(const char *needle, uint32_t needle_len,
                          const char *const *names, uint32_t count,
                          uint32_t *out_idx) {
  for (uint32_t i = 0; i < count; i++) {
    const char *candidate = names[i];
    size_t cand_len = strlen(candidate);
    if (needle_len == cand_len && memcmp(needle, candidate, cand_len) == 0) {
      *out_idx = i;
      return true;
    }
  }
  return false;
}

/* Graph document paths retain their original source spelling for diagnostics.
 * Traverse an isolated shell word without materializing its decoded form so
 * every literal path rule applies the same quote and backslash semantics. A
 * false callback result stops traversal after a decisive match or mismatch. */
typedef bool (*sg_decoded_word_visitor_t)(char byte, size_t decoded_pos,
                                          void *context);

static void sg_visit_decoded_word(const char *word, uint32_t word_len,
                                  sg_decoded_word_visitor_t visitor,
                                  void *context) {
  char quote = '\0';
  size_t decoded_pos = 0;
  for (uint32_t pos = 0; pos < word_len; pos++) {
    char byte = word[pos];
    bool emit = true;
    if (quote == '\0' && (byte == '\'' || byte == '"')) {
      quote = byte;
      emit = false;
    } else if (quote != '\0' && byte == quote) {
      quote = '\0';
      emit = false;
    } else if (byte == '\\' && quote != '\'' && pos + 1 < word_len) {
      char next = word[pos + 1];
      if (quote == '\0' || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n') {
        pos++;
        byte = next;
        emit = next != '\n';
      }
    }
    if (!emit)
      continue;
    if (!visitor(byte, decoded_pos, context))
      return;
    decoded_pos++;
  }
}

typedef struct {
  const char *prefix;
  size_t prefix_len;
  size_t decoded_len;
  char first_after_prefix;
  bool matches;
} sg_decoded_prefix_match_t;

static bool sg_decoded_prefix_visit(char byte, size_t decoded_pos,
                                    void *context) {
  sg_decoded_prefix_match_t *match = context;
  if (decoded_pos < match->prefix_len && byte != match->prefix[decoded_pos]) {
    match->matches = false;
    return false;
  }
  if (decoded_pos == match->prefix_len)
    match->first_after_prefix = byte;
  match->decoded_len = decoded_pos + 1;
  return true;
}

static bool sg_decoded_path_found(const char *word, uint32_t word_len,
                                  const char *const *sorted_paths,
                                  uint32_t count, uint32_t *out_idx) {
  for (uint32_t i = 0; i < count; i++) {
    const char *prefix = sorted_paths[i];
    size_t prefix_len = strlen(prefix);
    if (prefix_len == 0)
      continue;

    sg_decoded_prefix_match_t match = {
        .prefix = prefix,
        .prefix_len = prefix_len,
        .matches = true,
    };
    sg_visit_decoded_word(word, word_len, sg_decoded_prefix_visit, &match);
    bool exact = match.decoded_len == prefix_len;
    bool child =
        match.decoded_len > prefix_len &&
        (prefix[prefix_len - 1] == '/' || match.first_after_prefix == '/');
    if (match.matches && (exact || child)) {
      *out_idx = i;
      return true;
    }
  }
  return false;
}

typedef struct {
  const char *needle;
  size_t needle_len;
  size_t matched_len;
  bool found;
} sg_decoded_contains_match_t;

/* Return the longest proper prefix of needle[0, matched_len) that is also a
 * suffix. Configuration values are small path fragments, so recomputing this
 * fallback avoids allocating a KMP table for every graph document. */
static size_t sg_decoded_match_fallback(const char *needle,
                                        size_t matched_len) {
  for (size_t candidate = matched_len - 1; candidate > 0; candidate--) {
    if (memcmp(needle, needle + matched_len - candidate, candidate) == 0)
      return candidate;
  }
  return 0;
}

static bool sg_decoded_contains_visit(char byte, size_t decoded_pos,
                                      void *context) {
  (void)decoded_pos;
  sg_decoded_contains_match_t *match = context;
  while (match->matched_len > 0 && byte != match->needle[match->matched_len])
    match->matched_len =
        sg_decoded_match_fallback(match->needle, match->matched_len);
  if (byte == match->needle[match->matched_len])
    match->matched_len++;
  if (match->matched_len == match->needle_len) {
    match->found = true;
    return false;
  }
  return true;
}

static bool sg_decoded_path_contains(const char *word, uint32_t word_len,
                                     const char *needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0)
    return false;
  sg_decoded_contains_match_t match = {
      .needle = needle,
      .needle_len = needle_len,
  };
  sg_visit_decoded_word(word, word_len, sg_decoded_contains_visit, &match);
  return match.found;
}

static bool tok_equals(const char *tok, uint32_t tok_len, const char *str) {
  size_t slen = strlen(str);
  return tok_len == slen && memcmp(tok, str, slen) == 0;
}

static bool tok_is_option(const char *tok, uint32_t tok_len,
                          const char *option) {
  size_t option_len = strlen(option);
  return tok_equals(tok, tok_len, option) ||
         (tok_len > option_len && tok[option_len] == '=' &&
          memcmp(tok, option, option_len) == 0);
}

static bool tok_basename_in(const char *tok, uint32_t tok_len,
                            const char *const *names, uint32_t name_count) {
  uint32_t basename = 0;
  for (uint32_t i = 0; i < tok_len; i++)
    if (tok[i] == '/')
      basename = i + 1;
  uint32_t basename_len = tok_len - basename;
  uint32_t ignored;
  return sg_name_found(tok + basename, basename_len, names, name_count,
                       &ignored);
}

static bool sudo_spawns_shell(const shell_dep_node_t *node,
                              const sg_violation_config_t *cfg) {
  uint32_t command = 1;
  while (command < node->cmd.token_count) {
    const char *tok = node->cmd.tokens[command];
    uint32_t len = node->cmd.token_lens[command];
    if (tok_equals(tok, len, "--")) {
      command++;
      break;
    }
    if (len == 0 || tok[0] != '-')
      break;

    static const char *value_options[] = {
        "-C",      "-D",      "-g",           "-h",
        "-p",      "-R",      "-T",           "-u",
        "-U",      "--chdir", "--close-from", "--command-timeout",
        "--group", "--host",  "--other-user", "--prompt",
        "--role",  "--type",  "--user",
    };
    bool consumes_next = false;
    for (size_t i = 0; i < sizeof(value_options) / sizeof(value_options[0]);
         i++) {
      size_t option_len = strlen(value_options[i]);
      if (len == option_len && memcmp(tok, value_options[i], option_len) == 0) {
        consumes_next = true;
        break;
      }
    }
    command += consumes_next && command + 1 < node->cmd.token_count ? 2 : 1;
  }

  return command < node->cmd.token_count &&
         tok_basename_in(node->cmd.tokens[command],
                         node->cmd.token_lens[command], cfg->shell_spawn_cmds,
                         cfg->shell_spawn_cmd_count);
}

static bool su_spawns_shell(const shell_dep_node_t *node,
                            const sg_violation_config_t *cfg) {
  for (uint32_t i = 1; i < node->cmd.token_count; i++) {
    const char *tok = node->cmd.tokens[i];
    uint32_t len = node->cmd.token_lens[i];
    if (tok_equals(tok, len, "-c") || tok_equals(tok, len, "--command") ||
        (len > 10 && memcmp(tok, "--command=", 10) == 0))
      return true;

    const char *shell = NULL;
    uint32_t shell_len = 0;
    if (tok_equals(tok, len, "-s") || tok_equals(tok, len, "--shell")) {
      if (i + 1 < node->cmd.token_count) {
        shell = node->cmd.tokens[++i];
        shell_len = node->cmd.token_lens[i];
      }
    } else if (len > 8 && memcmp(tok, "--shell=", 8) == 0) {
      shell = tok + 8;
      shell_len = len - 8;
    } else if (len > 2 && tok[0] == '-' && tok[1] == 's') {
      shell = tok + 2;
      shell_len = len - 2;
    }
    if (shell && tok_basename_in(shell, shell_len, cfg->shell_spawn_cmds,
                                 cfg->shell_spawn_cmd_count))
      return true;
  }
  return false;
}

static uint32_t sg_violation_categories(uint32_t types);

static void emit_violation(sg_violation_t *viol, uint32_t *count, uint32_t max,
                           uint32_t *dropped, uint32_t type, uint32_t severity,
                           uint32_t cmd_idx, const char *desc,
                           const char *detail) {
  if (*count >= max) {
    if (dropped)
      (*dropped)++;
    return;
  }
  if (!desc) {
    if (dropped)
      (*dropped)++;
    return;
  }
  sg_violation_t *v = &viol[(*count)++];
  v->type = type;
  v->category_flags = sg_violation_categories(type);
  v->severity = severity;
  v->command_node_index = cmd_idx;
  v->description = desc;
  v->detail = detail;
}

static bool has_control_flow_path(const shell_dep_graph_t *g, uint32_t from,
                                  uint32_t to) {
  if (from == to)
    return true;
  if (g->node_count > SHELL_DEP_MAX_NODES)
    return false;
  bool visited[SHELL_DEP_MAX_NODES] = {false};
  uint32_t stack[SHELL_DEP_MAX_NODES];

  size_t sp = 0;
  stack[sp++] = from;
  visited[from] = true;

  while (sp > 0) {
    uint32_t cur = stack[--sp];
    if (cur == to)
      return true;
    for (uint32_t i = 0; i < g->edge_count; i++) {
      const shell_dep_edge_t *e = &g->edges[i];
      if (e->from != cur)
        continue;
      if (e->type != SHELL_EDGE_SEQ && e->type != SHELL_EDGE_AND &&
          e->type != SHELL_EDGE_OR && e->type != SHELL_EDGE_PIPE &&
          e->type != SHELL_EDGE_BACKGROUND && e->type != SHELL_EDGE_GROUP)
        continue;
      if (!visited[e->to]) {
        visited[e->to] = true;
        stack[sp++] = e->to;
      }
    }
  }
  return false;
}

/* Group-owned I/O is real context for every contained command, but it remains
 * attached to the GROUP node in the dependency graph. Derive that context at
 * evaluation time instead of inventing command-to-document edges. */
static void sg_group_context(const shell_dep_graph_t *graph,
                             uint32_t command_index, const uint32_t *node_viols,
                             const uint32_t *node_write_count,
                             const uint32_t *node_read_count,
                             uint32_t *violations, uint32_t *write_count,
                             uint32_t *read_count) {
  bool visited[SHELL_DEP_MAX_NODES] = {false};
  uint32_t stack[SHELL_DEP_MAX_NODES];
  size_t stack_count = 0;
  stack[stack_count++] = command_index;
  while (stack_count > 0) {
    uint32_t child = stack[--stack_count];
    for (uint32_t i = 0; i < graph->edge_count; i++) {
      const shell_dep_edge_t *edge = &graph->edges[i];
      if (edge->type != SHELL_EDGE_GROUP || edge->to != child ||
          graph->nodes[edge->from].type != SHELL_NODE_GROUP ||
          visited[edge->from])
        continue;
      visited[edge->from] = true;
      *violations |= node_viols[edge->from];
      *write_count += node_write_count[edge->from];
      *read_count += node_read_count[edge->from];
      if (stack_count < SHELL_DEP_MAX_NODES)
        stack[stack_count++] = edge->from;
    }
  }
}

/* SUBST may start at a CMD/GROUP directly or at an ENDPOINT collector. Follow
 * only data-flow predecessors that feed that dynamic stream so the sensitive
 * substitution signal survives pipelines, nested substitutions, grouping, and
 * multi-producer collection without inventing command-to-command edges. */
static bool sg_substitution_source_sensitive(const shell_dep_graph_t *graph,
                                             uint32_t source,
                                             const sg_violation_config_t *cfg,
                                             uint32_t *document_index) {
  bool visited[SHELL_DEP_MAX_NODES] = {false};
  uint32_t stack[SHELL_DEP_MAX_NODES];
  size_t stack_count = 0;
  if (source >= graph->node_count)
    return false;
  stack[stack_count++] = source;
  while (stack_count > 0) {
    uint32_t current = stack[--stack_count];
    if (visited[current])
      continue;
    visited[current] = true;
    const shell_dep_node_t *current_node = &graph->nodes[current];
    if (current_node->type == SHELL_NODE_DOC &&
        current_node->doc.kind == SHELL_DOC_FILE) {
      uint32_t ignored;
      if (sg_decoded_path_found(current_node->doc.path,
                                current_node->doc.path_len,
                                cfg->sensitive_read_paths,
                                cfg->sensitive_read_path_count, &ignored)) {
        *document_index = current;
        return true;
      }
    }
    for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
      const shell_dep_edge_t *edge = &graph->edges[ei];
      uint32_t candidate = UINT32_MAX;
      if (edge->type == SHELL_EDGE_READ && edge->to == current)
        candidate = edge->from;
      else if (edge->type == SHELL_EDGE_ARG && edge->from == current)
        candidate = edge->to;
      else if ((edge->type == SHELL_EDGE_PIPE ||
                edge->type == SHELL_EDGE_SUBST) &&
               edge->to == current)
        candidate = edge->from;
      else if (current_node->type == SHELL_NODE_ENDPOINT &&
               edge->type == SHELL_EDGE_WRITE && edge->to == current)
        candidate = edge->from;
      else if (current_node->type == SHELL_NODE_GROUP &&
               edge->type == SHELL_EDGE_GROUP && edge->from == current)
        candidate = edge->to;
      if (candidate == UINT32_MAX)
        continue;
      if (candidate < graph->node_count && !visited[candidate] &&
          stack_count < SHELL_DEP_MAX_NODES)
        stack[stack_count++] = candidate;
    }
  }
  return false;
}

/* A SUBST edge terminates at the execution endpoint in the ordinary case.
 * Expandable heredocs and here-strings are document indirections: dynamic
 * bytes first enter the DOC, then its READ edge supplies the command or group
 * that owns the descriptor. A dynamic FILE name similarly reaches the owner
 * through its FILE I/O edge, but remains topology only rather than a
 * shell-word inspection dependency. */
static uint32_t
sg_substitution_consumers(const shell_dep_graph_t *graph, uint32_t target,
                          uint32_t edge_flags,
                          uint32_t consumers[SHELL_DEP_MAX_NODES]) {
  if (target >= graph->node_count)
    return 0;
  const shell_dep_node_t *node = &graph->nodes[target];
  if (node->type == SHELL_NODE_CMD || node->type == SHELL_NODE_GROUP) {
    consumers[0] = target;
    return 1;
  }
  if (node->type != SHELL_NODE_DOC)
    return 0;

  uint32_t count = 0;
  for (uint32_t edge_index = 0; edge_index < graph->edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph->edges[edge_index];
    uint32_t consumer = UINT32_MAX;
    if ((node->doc.kind == SHELL_DOC_HEREDOC ||
         node->doc.kind == SHELL_DOC_HERESTRING) &&
        edge->type == SHELL_EDGE_READ && edge->from == target)
      consumer = edge->to;
    else if (node->doc.kind == SHELL_DOC_FILE &&
             (node->doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0 &&
             (edge_flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0 &&
             ((edge->type == SHELL_EDGE_READ && edge->from == target) ||
              ((edge->type == SHELL_EDGE_WRITE ||
                edge->type == SHELL_EDGE_APPEND) &&
               edge->to == target)))
      consumer = edge->type == SHELL_EDGE_READ ? edge->to : edge->from;
    if (consumer >= graph->node_count)
      continue;
    shell_dep_node_type_t type = graph->nodes[consumer].type;
    if (type != SHELL_NODE_CMD && type != SHELL_NODE_GROUP)
      continue;
    bool duplicate = false;
    for (uint32_t previous = 0; previous < count; previous++)
      duplicate = duplicate || consumers[previous] == consumer;
    if (!duplicate && count < SHELL_DEP_MAX_NODES)
      consumers[count++] = consumer;
  }
  return count;
}

/* --- VIOLATION SCANNING ENGINE --- */

static void
sg_violation_scan(const shell_dep_graph_t *graph,
                  const sg_violation_config_t *cfg, buf_writer_t *bw,
                  sg_violation_t *violations, uint32_t max_violations,
                  uint32_t *violation_count, uint32_t *violation_type_flags,
                  uint32_t *violation_dropped, uint32_t *node_viols,
                  uint32_t *cmd_write_count, uint32_t *cmd_read_count,
                  uint32_t *cmd_env_count) {
  *violation_count = 0;
  *violation_type_flags = 0;
  *violation_dropped = 0;

  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    const shell_dep_edge_t *e = &graph->edges[ei];
    const shell_dep_node_t *from_node = &graph->nodes[e->from];
    const shell_dep_node_t *to_node = &graph->nodes[e->to];

    /* --- Per-node edge counters --- */
    if (from_node->type == SHELL_NODE_CMD ||
        from_node->type == SHELL_NODE_GROUP) {
      if (e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND)
        cmd_write_count[e->from]++;
    }
    if (to_node->type == SHELL_NODE_CMD || to_node->type == SHELL_NODE_GROUP) {
      if (e->type == SHELL_EDGE_READ)
        cmd_read_count[e->to]++;
      if (e->type == SHELL_EDGE_ENV)
        cmd_env_count[e->to]++;
    }

    /* --- SG_VIOL_WRITE_SENSITIVE --- */
    if ((e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND) &&
        to_node->type == SHELL_NODE_DOC &&
        to_node->doc.kind == SHELL_DOC_FILE) {
      uint32_t idx;
      if (sg_decoded_path_found(to_node->doc.path, to_node->doc.path_len,
                                cfg->sensitive_write_paths,
                                cfg->sensitive_write_path_count, &idx)) {
        const char *desc = bw_printf(bw, "writes to sensitive path");
        const char *det = bw_copy(bw, to_node->doc.path, to_node->doc.path_len);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_WRITE_SENSITIVE,
                       SG_SEVERITY_HIGH, e->from, desc, det);
        node_viols[e->from] |= SG_VIOL_WRITE_SENSITIVE;
        *violation_type_flags |= SG_VIOL_WRITE_SENSITIVE;
      }
    }

    /* --- SG_VIOL_ENV_PRIVILEGED --- */
    if (e->type == SHELL_EDGE_ENV && from_node->type == SHELL_NODE_DOC &&
        from_node->doc.kind == SHELL_DOC_ENVVAR &&
        to_node->type == SHELL_NODE_CMD && to_node->cmd.token_count > 0) {

      uint32_t idx;
      if (sg_name_found(from_node->doc.name, from_node->doc.name_len,
                        cfg->sensitive_env_names, cfg->sensitive_env_name_count,
                        &idx)) {
        const char *cmd0 = to_node->cmd.tokens[0];
        uint32_t cmd0_len = to_node->cmd.token_lens[0];
        if (sg_name_found(cmd0, cmd0_len, cfg->sensitive_cmd_names,
                          cfg->sensitive_cmd_name_count, &idx)) {
          const char *desc =
              bw_printf(bw, "sensitive env before privileged cmd");
          const char *det =
              bw_printf(bw, "%.*s before %.*s", (int)from_node->doc.name_len,
                        from_node->doc.name, (int)cmd0_len, cmd0);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_ENV_PRIVILEGED,
                         SG_SEVERITY_CRITICAL, e->to, desc, det);
          node_viols[e->to] |= SG_VIOL_ENV_PRIVILEGED;
          *violation_type_flags |= SG_VIOL_ENV_PRIVILEGED;
        }
      }
    }

    /* --- SG_VIOL_SUBST_SENSITIVE --- */
    if (e->type == SHELL_EDGE_SUBST) {
      uint32_t doc_idx;
      if (sg_substitution_source_sensitive(graph, e->from, cfg, &doc_idx)) {
        const shell_dep_node_t *doc = &graph->nodes[doc_idx];
        *violation_type_flags |= SG_VIOL_SUBST_SENSITIVE;
        uint32_t consumers[SHELL_DEP_MAX_NODES];
        uint32_t consumer_count =
            sg_substitution_consumers(graph, e->to, e->flags, consumers);
        for (uint32_t consumer_index = 0;
             consumer_index < consumer_count && !bw->overflow;
             consumer_index++) {
          const char *desc = bw_printf(bw, "subshell reads sensitive file");
          const char *det = bw_copy(bw, doc->doc.path, doc->doc.path_len);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_SUBST_SENSITIVE,
                         SG_SEVERITY_HIGH, consumers[consumer_index], desc,
                         det);
          node_viols[consumers[consumer_index]] |= SG_VIOL_SUBST_SENSITIVE;
        }
      }
    }
  }

  /* --- SG_VIOL_REMOVE_SYSTEM --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0)
      continue;
    const char *cmd0 = node->cmd.tokens[0];
    uint32_t cmd0_len = node->cmd.token_lens[0];
    if (!tok_equals(cmd0, cmd0_len, "rm") &&
        !tok_equals(cmd0, cmd0_len, "rmdir"))
      continue;
    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->from != ni || e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      uint32_t idx;
      if (sg_decoded_path_found(doc->doc.path, doc->doc.path_len,
                                cfg->sensitive_dirs, cfg->sensitive_dir_count,
                                &idx)) {
        const char *desc = bw_printf(bw, "removal of system directory");
        const char *det = bw_copy(bw, doc->doc.path, doc->doc.path_len);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_REMOVE_SYSTEM, 95, ni, desc,
                       det);
        node_viols[ni] |= SG_VIOL_REMOVE_SYSTEM;
        *violation_type_flags |= SG_VIOL_REMOVE_SYSTEM;
        break;
      }
    }
  }

  /* --- SG_VIOL_WRITE_THEN_READ --- */
  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    const shell_dep_edge_t *e1 = &graph->edges[ei];
    if (e1->type != SHELL_EDGE_WRITE && e1->type != SHELL_EDGE_APPEND)
      continue;
    const shell_dep_node_t *f1 = &graph->nodes[e1->to];
    if (f1->type != SHELL_NODE_DOC || f1->doc.kind != SHELL_DOC_FILE)
      continue;

    for (uint32_t ej = 0; ej < graph->edge_count && !bw->overflow; ej++) {
      const shell_dep_edge_t *e2 = &graph->edges[ej];
      uint32_t read_cmd;
      const shell_dep_node_t *f2;
      if (e2->type == SHELL_EDGE_READ) {
        read_cmd = e2->to;
        f2 = &graph->nodes[e2->from];
      } else if (e2->type == SHELL_EDGE_ARG) {
        read_cmd = e2->from;
        f2 = &graph->nodes[e2->to];
      } else {
        continue;
      }
      if (f2->type != SHELL_NODE_DOC || f2->doc.kind != SHELL_DOC_FILE)
        continue;
      if (f1->doc.path_len != f2->doc.path_len)
        continue;
      if (memcmp(f1->doc.path, f2->doc.path, f1->doc.path_len) != 0)
        continue;

      if (has_control_flow_path(graph, e1->from, read_cmd)) {
        const char *desc = bw_printf(bw, "write then read of same file");
        const char *det = bw_copy(bw, f1->doc.path, f1->doc.path_len);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_WRITE_THEN_READ,
                       SG_SEVERITY_MEDIUM, read_cmd, desc, det);
        node_viols[read_cmd] |= SG_VIOL_WRITE_THEN_READ;
        *violation_type_flags |= SG_VIOL_WRITE_THEN_READ;
        break;
      }
    }
  }

  /* --- SG_VIOL_REDIRECT_FANOUT --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    if (graph->nodes[ni].type != SHELL_NODE_CMD &&
        graph->nodes[ni].type != SHELL_NODE_GROUP)
      continue;
    if (cmd_write_count[ni] > cfg->redirect_fanout_threshold) {
      const char *desc = bw_printf(
          bw, "excessive redirect fan-out (%u targets)", cmd_write_count[ni]);
      emit_violation(violations, violation_count, max_violations,
                     violation_dropped, SG_VIOL_REDIRECT_FANOUT,
                     SG_SEVERITY_LOW, ni, desc, NULL);
      node_viols[ni] |= SG_VIOL_REDIRECT_FANOUT;
      *violation_type_flags |= SG_VIOL_REDIRECT_FANOUT;
    }
  }

  /* --- SG_VIOL_NET_DOWNLOAD_EXEC --- */
  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    const shell_dep_edge_t *e = &graph->edges[ei];
    if (e->type != SHELL_EDGE_PIPE)
      continue;
    const shell_dep_node_t *src = &graph->nodes[e->from];
    const shell_dep_node_t *dst = &graph->nodes[e->to];
    if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD)
      continue;
    if (src->cmd.token_count == 0 || dst->cmd.token_count == 0)
      continue;

    uint32_t idx;
    if (!sg_name_found(src->cmd.tokens[0], src->cmd.token_lens[0],
                       cfg->download_cmds, cfg->download_cmd_count, &idx))
      continue;
    if (!sg_name_found(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                       cfg->shell_spawn_cmds, cfg->shell_spawn_cmd_count, &idx))
      continue;

    const char *desc = bw_printf(bw, "download piped into shell executor");
    const char *det = bw_printf(bw, "%.*s | %.*s", (int)src->cmd.token_lens[0],
                                src->cmd.tokens[0], (int)dst->cmd.token_lens[0],
                                dst->cmd.tokens[0]);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_NET_DOWNLOAD_EXEC,
                   SG_SEVERITY_CRITICAL, e->to, desc, det);
    node_viols[e->to] |= SG_VIOL_NET_DOWNLOAD_EXEC;
    *violation_type_flags |= SG_VIOL_NET_DOWNLOAD_EXEC;
  }

  /* --- SG_VIOL_PERM_SYSTEM --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0)
      continue;

    uint32_t idx;
    if (!sg_name_found(node->cmd.tokens[0], node->cmd.token_lens[0],
                       cfg->perm_mod_cmds, cfg->perm_mod_cmd_count, &idx))
      continue;

    bool has_recursive = false;
    for (uint32_t t = 1; t < node->cmd.token_count; t++) {
      if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-R")) {
        has_recursive = true;
        break;
      }
    }
    if (!has_recursive)
      continue;

    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->from != ni || e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      if (sg_decoded_path_found(doc->doc.path, doc->doc.path_len,
                                cfg->sensitive_dirs, cfg->sensitive_dir_count,
                                &idx)) {
        const char *desc =
            bw_printf(bw, "recursive permission change on system dir");
        const char *det = bw_copy(bw, doc->doc.path, doc->doc.path_len);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_PERM_SYSTEM, SG_SEVERITY_HIGH,
                       ni, desc, det);
        node_viols[ni] |= SG_VIOL_PERM_SYSTEM;
        *violation_type_flags |= SG_VIOL_PERM_SYSTEM;
        break;
      }
    }
  }

  /* --- SG_VIOL_SHELL_ESCALATION --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2)
      continue;

    const char *cmd0 = node->cmd.tokens[0];
    uint32_t cmd0_len = node->cmd.token_lens[0];
    if (!tok_equals(cmd0, cmd0_len, "sudo") &&
        !tok_equals(cmd0, cmd0_len, "su"))
      continue;

    bool spawns_shell = tok_equals(cmd0, cmd0_len, "sudo")
                            ? sudo_spawns_shell(node, cfg)
                            : su_spawns_shell(node, cfg);
    if (!spawns_shell)
      continue;

    const char *desc = bw_printf(bw, "privileged shell spawn");
    const char *det = bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_SHELL_ESCALATION,
                   SG_SEVERITY_CRITICAL, ni, desc, det);
    node_viols[ni] |= SG_VIOL_SHELL_ESCALATION;
    *violation_type_flags |= SG_VIOL_SHELL_ESCALATION;
  }

  /* --- SG_VIOL_SUDO_REDIRECT --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0)
      continue;

    const char *cmd0 = node->cmd.tokens[0];
    uint32_t cmd0_len = node->cmd.token_lens[0];
    if (!tok_equals(cmd0, cmd0_len, "sudo") &&
        !tok_equals(cmd0, cmd0_len, "su"))
      continue;

    bool has_redirect = false;
    const char *target_path = NULL;
    uint32_t target_path_len = 0;
    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->from != ni)
        continue;
      if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND)
        continue;
      has_redirect = true;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type == SHELL_NODE_DOC && doc->doc.kind == SHELL_DOC_FILE) {
        target_path = doc->doc.path;
        target_path_len = doc->doc.path_len;
      }
      break;
    }
    if (!has_redirect)
      continue;

    const char *desc = bw_printf(bw, "sudo with redirect");
    const char *det = target_path ? bw_copy(bw, target_path, target_path_len)
                                  : bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_SUDO_REDIRECT, SG_SEVERITY_HIGH,
                   ni, desc, det);
    node_viols[ni] |= SG_VIOL_SUDO_REDIRECT;
    *violation_type_flags |= SG_VIOL_SUDO_REDIRECT;
  }

  /* --- SG_VIOL_READ_SECRETS --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0)
      continue;

    bool is_reader = false;
    for (uint32_t c = 0; c < cfg->file_reading_cmd_count; c++) {
      if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                     cfg->file_reading_cmds[c])) {
        is_reader = true;
        break;
      }
    }
    if (!is_reader)
      continue;

    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->from != ni || e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      for (uint32_t p = 0; p < cfg->sensitive_secret_path_count; p++) {
        if (sg_decoded_path_contains(doc->doc.path, doc->doc.path_len,
                                     cfg->sensitive_secret_paths[p])) {
          const char *desc = bw_printf(bw, "reading secret file");
          const char *det = bw_copy(bw, doc->doc.path, doc->doc.path_len);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_READ_SECRETS,
                         SG_SEVERITY_MEDIUM, ni, desc, det);
          node_viols[ni] |= SG_VIOL_READ_SECRETS;
          *violation_type_flags |= SG_VIOL_READ_SECRETS;
          break;
        }
      }
    }
  }

  /* --- SG_VIOL_NET_UPLOAD --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2)
      continue;

    const char *cmd0 = node->cmd.tokens[0];
    uint32_t cmd0_len = node->cmd.token_lens[0];

    bool is_upload = false;
    for (uint32_t c = 0; c < cfg->upload_cmd_count; c++) {
      if (tok_equals(cmd0, cmd0_len, cfg->upload_cmds[c])) {
        is_upload = true;
        break;
      }
    }
    if (!is_upload)
      continue;

    bool has_upload_flag = false;
    bool is_scp_upload = false;
    bool is_rsync_upload = false;

    if (tok_equals(cmd0, cmd0_len, "curl")) {
      for (uint32_t t = 1; t < node->cmd.token_count; t++) {
        const char *tok = node->cmd.tokens[t];
        uint32_t tlen = node->cmd.token_lens[t];
        if (tok_is_option(tok, tlen, "--data") ||
            tok_is_option(tok, tlen, "--data-binary") ||
            tok_is_option(tok, tlen, "--data-raw") ||
            tok_is_option(tok, tlen, "--data-urlencode") ||
            tok_is_option(tok, tlen, "--form") ||
            tok_is_option(tok, tlen, "--upload-file") ||
            tok_equals(tok, tlen, "-d") || tok_equals(tok, tlen, "-F") ||
            tok_equals(tok, tlen, "-T")) {
          has_upload_flag = true;
          break;
        }
        if (tlen >= 3 && tok[0] == '-' &&
            (tok[1] == 'd' || tok[1] == 'F' || tok[1] == 'T')) {
          has_upload_flag = true;
          break;
        }
      }
    } else if (tok_equals(cmd0, cmd0_len, "wget")) {
      for (uint32_t t = 1; t < node->cmd.token_count; t++) {
        if (tok_is_option(node->cmd.tokens[t], node->cmd.token_lens[t],
                          "--post-file") ||
            tok_is_option(node->cmd.tokens[t], node->cmd.token_lens[t],
                          "--post-data")) {
          has_upload_flag = true;
          break;
        }
      }
    } else if (tok_equals(cmd0, cmd0_len, "scp")) {
      const char *last = node->cmd.tokens[node->cmd.token_count - 1];
      uint32_t last_len = node->cmd.token_lens[node->cmd.token_count - 1];
      for (uint32_t c = 0; c < last_len; c++) {
        if (last[c] == ':') {
          is_scp_upload = true;
          break;
        }
      }
    } else if (tok_equals(cmd0, cmd0_len, "rsync")) {
      const char *last = node->cmd.tokens[node->cmd.token_count - 1];
      uint32_t last_len = node->cmd.token_lens[node->cmd.token_count - 1];
      for (uint32_t c = 0; c < last_len; c++) {
        if (last[c] == ':') {
          is_rsync_upload = true;
          break;
        }
      }
    }

    if (!has_upload_flag && !is_scp_upload && !is_rsync_upload)
      continue;

    const char *desc = bw_printf(bw, "network file upload");
    const char *det = bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_NET_UPLOAD, SG_SEVERITY_HIGH, ni,
                   desc, det);
    node_viols[ni] |= SG_VIOL_NET_UPLOAD;
    *violation_type_flags |= SG_VIOL_NET_UPLOAD;
  }

  /* --- SG_VIOL_NET_LISTENER --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2)
      continue;

    bool is_listener_cmd = false;
    for (uint32_t c = 0; c < cfg->listener_cmd_count; c++) {
      if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                     cfg->listener_cmds[c])) {
        is_listener_cmd = true;
        break;
      }
    }
    if (!is_listener_cmd)
      continue;

    bool has_listen = false;
    if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "nc") ||
        tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "ncat") ||
        tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "netcat")) {
      for (uint32_t t = 1; t < node->cmd.token_count; t++) {
        if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-l") ||
            tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
                       "--listen")) {
          has_listen = true;
          break;
        }
      }
    } else if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                          "socat")) {
      for (uint32_t t = 1; t < node->cmd.token_count; t++) {
        for (uint32_t c = 0; c < node->cmd.token_lens[t]; c++) {
          if (node->cmd.tokens[t][c] == 'L' || node->cmd.tokens[t][c] == 'l') {
            uint32_t remaining = node->cmd.token_lens[t] - c;
            if (remaining >= 6 &&
                (memcmp(node->cmd.tokens[t] + c, "LISTEN", 6) == 0 ||
                 memcmp(node->cmd.tokens[t] + c, "listen", 6) == 0)) {
              has_listen = true;
              break;
            }
          }
        }
        if (has_listen)
          break;
      }
    } else {
      has_listen = true;
    }

    if (!has_listen)
      continue;

    const char *desc = bw_printf(bw, "starting network listener");
    const char *det = bw_printf(bw, "%.*s", (int)node->cmd.token_lens[0],
                                node->cmd.tokens[0]);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_NET_LISTENER, SG_SEVERITY_HIGH,
                   ni, desc, det);
    node_viols[ni] |= SG_VIOL_NET_LISTENER;
    *violation_type_flags |= SG_VIOL_NET_LISTENER;
  }

  /* --- SG_VIOL_SHELL_OBFUSCATION --- */
  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    const shell_dep_edge_t *e = &graph->edges[ei];
    if (e->type != SHELL_EDGE_PIPE)
      continue;
    const shell_dep_node_t *src = &graph->nodes[e->from];
    const shell_dep_node_t *dst = &graph->nodes[e->to];
    if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD)
      continue;
    if (src->cmd.token_count == 0 || dst->cmd.token_count == 0)
      continue;

    bool is_decoder = false;
    if (tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "base64")) {
      for (uint32_t t = 1; t < src->cmd.token_count; t++) {
        if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
            tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t],
                       "--decode")) {
          is_decoder = true;
          break;
        }
      }
    }
    if (!is_decoder &&
        tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "openssl")) {
      bool has_enc = false, has_d = false;
      for (uint32_t t = 1; t < src->cmd.token_count; t++) {
        if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "enc"))
          has_enc = true;
        if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
            tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "--decode"))
          has_d = true;
      }
      if (has_enc && has_d)
        is_decoder = true;
    }
    if (!is_decoder)
      continue;

    bool is_spawn = false;
    for (uint32_t c = 0; c < cfg->shell_spawn_cmd_count; c++) {
      if (tok_equals(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                     cfg->shell_spawn_cmds[c])) {
        is_spawn = true;
        break;
      }
    }
    if (!is_spawn)
      continue;

    const char *desc = bw_printf(bw, "decoded payload piped to shell");
    const char *det = bw_printf(bw, "%.*s | %.*s", (int)src->cmd.token_lens[0],
                                src->cmd.tokens[0], (int)dst->cmd.token_lens[0],
                                dst->cmd.tokens[0]);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_SHELL_OBFUSCATION,
                   SG_SEVERITY_CRITICAL, e->to, desc, det);
    node_viols[e->to] |= SG_VIOL_SHELL_OBFUSCATION;
    *violation_type_flags |= SG_VIOL_SHELL_OBFUSCATION;
  }

  /* --- SG_VIOL_GIT_DESTRUCTIVE --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2)
      continue;
    if (!tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "git"))
      continue;

    const char *subcmd = node->cmd.tokens[1];
    uint32_t subcmd_len = node->cmd.token_lens[1];

    bool destructive = false;
    if (tok_equals(subcmd, subcmd_len, "push")) {
      for (uint32_t t = 2; t < node->cmd.token_count; t++) {
        if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
                       "--force") ||
            tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-f")) {
          destructive = true;
          break;
        }
      }
    } else if (tok_equals(subcmd, subcmd_len, "clean")) {
      for (uint32_t t = 2; t < node->cmd.token_count; t++) {
        if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-x") ||
            tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-fdx") ||
            tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-fx")) {
          destructive = true;
          break;
        }
      }
    } else if (tok_equals(subcmd, subcmd_len, "filter-branch")) {
      destructive = true;
    }

    if (!destructive)
      continue;

    const char *desc = bw_printf(bw, "destructive git operation");
    const char *det = bw_printf(bw, "git %.*s", (int)subcmd_len, subcmd);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_GIT_DESTRUCTIVE,
                   SG_SEVERITY_MEDIUM, ni, desc, det);
    node_viols[ni] |= SG_VIOL_GIT_DESTRUCTIVE;
    *violation_type_flags |= SG_VIOL_GIT_DESTRUCTIVE;
  }

  /* --- SG_VIOL_PERSISTENCE --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0)
      continue;

    const char *cmd0 = node->cmd.tokens[0];
    uint32_t cmd0_len = node->cmd.token_lens[0];

    if (tok_equals(cmd0, cmd0_len, "crontab")) {
      bool is_list = false;
      for (uint32_t t = 1; t < node->cmd.token_count; t++) {
        if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-l")) {
          is_list = true;
          break;
        }
      }
      if (!is_list) {
        const char *desc = bw_printf(bw, "crontab modification");
        const char *det = bw_printf(bw, "crontab");
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_PERSISTENCE,
                       SG_SEVERITY_MEDIUM, ni, desc, det);
        node_viols[ni] |= SG_VIOL_PERSISTENCE;
        *violation_type_flags |= SG_VIOL_PERSISTENCE;
      }
      continue;
    }

    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->from != ni)
        continue;
      if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      for (uint32_t p = 0; p < cfg->shell_profile_path_count; p++) {
        if (sg_decoded_path_contains(doc->doc.path, doc->doc.path_len,
                                     cfg->shell_profile_paths[p])) {
          const char *desc =
              bw_printf(bw, "writing to shell profile/ssh config");
          const char *det = bw_copy(bw, doc->doc.path, doc->doc.path_len);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_PERSISTENCE,
                         SG_SEVERITY_HIGH, ni, desc, det);
          node_viols[ni] |= SG_VIOL_PERSISTENCE;
          *violation_type_flags |= SG_VIOL_PERSISTENCE;
          break;
        }
      }
    }
  }
}

static uint32_t sg_violation_categories(uint32_t types) {
  uint32_t categories = 0;
  if (types & (SG_VIOL_WRITE_SENSITIVE | SG_VIOL_REMOVE_SYSTEM |
               SG_VIOL_PERM_SYSTEM | SG_VIOL_GIT_DESTRUCTIVE))
    categories |= SG_VIOL_CAT_FILESYSTEM;
  if (types & (SG_VIOL_ENV_PRIVILEGED | SG_VIOL_SHELL_ESCALATION |
               SG_VIOL_SUDO_REDIRECT | SG_VIOL_PERSISTENCE))
    categories |= SG_VIOL_CAT_PRIVILEGE;
  if (types & (SG_VIOL_WRITE_THEN_READ | SG_VIOL_SUBST_SENSITIVE |
               SG_VIOL_REDIRECT_FANOUT | SG_VIOL_READ_SECRETS |
               SG_VIOL_SHELL_OBFUSCATION))
    categories |= SG_VIOL_CAT_EXFIL;
  if (types &
      (SG_VIOL_NET_DOWNLOAD_EXEC | SG_VIOL_NET_UPLOAD | SG_VIOL_NET_LISTENER))
    categories |= SG_VIOL_CAT_NETWORK;
  return categories;
}

/* --- EVALUATION --- */

/* A group-level dynamic stream is inherited by every simple command it
 * contains unless the caller later resolves more detailed program semantics.
 * Keep the public result safe without inventing a direct producer-to-command
 * edge: a GROUP remains the authoritative graph consumer. */
static void sg_mark_group_substitution_consumers(
    const shell_dep_graph_t *graph, const uint32_t *node_result_index,
    uint32_t group_node, bool shell_word, sg_result_t *out) {
  if (group_node >= graph->node_count ||
      graph->nodes[group_node].type != SHELL_NODE_GROUP)
    return;

  /* A substitution graph can have source text inside this group's span while
   * remaining an independent graph fragment. Only GROUP edges express the
   * structural descendants that inherit a group descriptor. */
  bool visited[SHELL_DEP_MAX_NODES] = {false};
  uint32_t pending[SHELL_DEP_MAX_NODES];
  uint32_t pending_count = 0;
  visited[group_node] = true;
  pending[pending_count++] = group_node;
  while (pending_count > 0) {
    uint32_t current = pending[--pending_count];
    for (uint32_t edge_index = 0; edge_index < graph->edge_count;
         edge_index++) {
      const shell_dep_edge_t *edge = &graph->edges[edge_index];
      if (edge->type != SHELL_EDGE_GROUP || edge->from != current ||
          edge->to >= graph->node_count)
        continue;
      uint32_t node = edge->to;
      if (graph->nodes[node].type == SHELL_NODE_GROUP && !visited[node]) {
        visited[node] = true;
        pending[pending_count++] = node;
      }
      if (graph->nodes[node].type != SHELL_NODE_CMD ||
          node_result_index[node] == UINT32_MAX)
        continue;
      sg_subcommand_result_t *result =
          &out->subcommands[node_result_index[node]];
      result->has_dynamic_substitution_io = true;
      if (shell_word) {
        result->requires_substitution_evaluation = true;
      }
      if (shell_word && result->verdict == SG_VERDICT_ALLOW)
        result->verdict = SG_VERDICT_ALLOW_CONDITIONAL;
    }
  }
}

/* Rejections before per-command evaluation still expose one synthetic result.
 * Preserve the documented sentinel metadata instead of leaving zeroed indices
 * that could be mistaken for a relationship to result zero. */
static void sg_init_rejected_subcommand(sg_result_t *out,
                                        const char *reject_reason) {
  out->subcommand_count = 1;
  out->subcommands[0] = (sg_subcommand_result_t){
      .verdict = SG_VERDICT_REJECT,
      .reject_reason = reject_reason,
      .substitution_consumer_index = -1,
      .group_parent_index = -1,
  };
}

sg_error_t sg_gate_evaluate(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                            char *buf, size_t buf_size, sg_result_t *out) {
  if (!gate || !cmd || !buf || !out)
    return SG_ERR_INVALID;
  if (buf_size == 0)
    return SG_ERR_INVALID;
  if (cmd_len == 0 || memchr(cmd, '\0', cmd_len) != NULL)
    return SG_ERR_INVALID;

  memset(out, 0, sizeof(*out));
  out->verdict = SG_VERDICT_ALLOW;

  buf_writer_t bw;
  bw_init(&bw, buf, buf_size);

  /* Step 1: Fast parse to check features */
  shell_parse_result_t fast;
  shell_limits_t lim = {.max_subcommands = 64,
                        .strict_mode = gate->strict_mode};
  shell_error_t ferr = shell_parse_fast(cmd, cmd_len, &lim, &fast);
  bool parse_truncated = ferr == SHELL_ETRUNC;
  bool whitespace_only = true;
  for (size_t i = 0; i < cmd_len; i++) {
    if (!isspace((unsigned char)cmd[i])) {
      whitespace_only = false;
      break;
    }
  }
  if (whitespace_only) {
    out->verdict = SG_VERDICT_ALLOW;
    return SG_OK;
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

  /* Step 3: Build depgraph */
  shell_dep_graph_t graph;
  memset(&graph, 0, sizeof(graph));
  shell_dep_error_t derr = shell_dep_graph_parse_with_fast(
      cmd, cmd_len, gate->cwd, NULL, &fast, &graph);
  bool depgraph_truncated = derr == SHELL_DEP_ETRUNC;
  if (derr != SHELL_DEP_OK && !depgraph_truncated) {
    out->verdict = SG_VERDICT_REJECT;
    out->deny_reason = bw_copy(&bw, "depgraph error", 14);
    sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return SG_ERR_PARSE;
  }

  /* This is graph-level information, not a property of whichever command
   * results fit in the caller's display buffer. Preserve it before any later
   * diagnostic rendering can return SG_ERR_TRUNC. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++)
    if (graph.edges[ei].type == SHELL_EDGE_SUBST) {
      out->has_dynamic_substitution_io = true;
      if (graph.edges[ei].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD)
        out->requires_substitution_evaluation = true;
    }

  /* Step 3.5: Violation scan on the depgraph */
  uint32_t node_viols[SHELL_DEP_MAX_NODES];
  uint32_t cmd_write_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_read_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_env_count[SHELL_DEP_MAX_NODES];
  memset(node_viols, 0, sizeof(node_viols));
  memset(cmd_write_count, 0, sizeof(cmd_write_count));
  memset(cmd_read_count, 0, sizeof(cmd_read_count));
  memset(cmd_env_count, 0, sizeof(cmd_env_count));

  if (gate->viol_enabled) {
    sg_violation_scan(&graph, &gate->viol_config, &bw, out->violations,
                      SG_MAX_VIOLATIONS, &out->violation_count,
                      &out->violation_type_flags, &out->violation_dropped_count,
                      node_viols, cmd_write_count, cmd_read_count,
                      cmd_env_count);
    out->violation_category_flags =
        sg_violation_categories(out->violation_type_flags);
    out->has_violations = (out->violation_count > 0);
    out->violation_truncated = (out->violation_dropped_count > 0);
    if (bw.overflow) {
      out->truncated = true;
      out->violation_truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      out->deny_reason = bw_copy(&bw, "output buffer overflow", 22);
      return SG_ERR_TRUNC;
    }
  }

  /* Extract command sequence from graph (used for anomaly detection and
   * learning) */
  size_t cmd_count = 0;
  for (uint32_t ni = 0; ni < graph.node_count; ni++) {
    const shell_dep_node_t *node = &graph.nodes[ni];
    if (node->type == SHELL_NODE_CMD && node->cmd.token_count > 0) {
      cmd_count++;
    }
  }

  /* Build one nested canonical type signature per isolated command. */
  const char *type_seq = NULL;
  char *owned_type_seq = NULL;
  char *owned_cmd_seq = NULL;
  size_t type_count = 0;
  size_t anomaly_count = 0;
  size_t cmd_seq_length = 0;

  if (gate->anomaly_enabled && gate->anomaly_model_type && cmd_count > 0) {
    const char *cached =
        type_cache_lookup(&gate->anomaly_type_cache, cmd, cmd_len, &type_count);
    if (cached) {
      type_seq = cached;
    }
  }

  /* Anomaly detection: score the command sequence with hybrid model */
  if (gate->anomaly_enabled && gate->anomaly_model && cmd_count > 0) {
    shell_process_status_t command_status;
    if (type_seq) {
      command_status = shell_build_command_netseq(
          cmd, cmd_len, NULL, &owned_cmd_seq, &anomaly_count);
    } else {
      command_status = shell_build_anomaly_netseqs(
          cmd, cmd_len, NULL, &owned_cmd_seq, &owned_type_seq, &anomaly_count);
      type_count = anomaly_count;
      if (command_status == SHELL_PROCESS_OK) {
        if (type_cache_insert(&gate->anomaly_type_cache, cmd, cmd_len,
                              owned_type_seq, type_count)) {
          type_seq = owned_type_seq;
          owned_type_seq = NULL;
        } else {
          type_seq = owned_type_seq;
        }
      }
    }
    if (command_status != SHELL_PROCESS_OK || !owned_cmd_seq) {
      free(owned_cmd_seq);
      free(owned_type_seq);
      out->verdict = SG_VERDICT_UNDETERMINED;
      if (command_status == SHELL_PROCESS_EOUTPUT_LIMIT)
        out->truncated = true;
      return command_status == SHELL_PROCESS_OK
                 ? SG_ERR_MEMORY
                 : process_status_to_gate_error(command_status);
    }
    if (!type_seq) {
      free(owned_cmd_seq);
      free(owned_type_seq);
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_MEMORY;
    }
    cmd_seq_length = strlen(owned_cmd_seq);
    sg_anomaly_sequence_score_t scores = {0};
    sg_error_t score_status =
        sg_gate_score_anomaly_netseq(gate, owned_cmd_seq, cmd_seq_length,
                                     type_seq, strlen(type_seq), &scores);
    if (score_status == SG_ERR_MEMORY) {
      free(owned_cmd_seq);
      free(owned_type_seq);
      return SG_ERR_MEMORY;
    }
    if (score_status != SG_OK || type_count != anomaly_count ||
        scores.command_count != anomaly_count) {
      free(owned_cmd_seq);
      free(owned_type_seq);
      return SG_ERR_PARSE;
    }
    out->anomaly_score = scores.combined_score;
    out->anomaly_score_raw = scores.raw_score;
    out->anomaly_score_type = scores.type_score;
    out->anomaly_detected = scores.detected;
  } else if (gate->anomaly_enabled && gate->anomaly_model) {
    out->anomaly_score = 0.0;
    out->anomaly_detected = false;
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
    node_result_index[ni] = out->subcommand_count - 1;
    sr->substitution_consumer_index = -1;
    sr->group_parent_index = -1;
    sr->group_depth = node->cmd.group_depth;
    sr->group_kinds = node->cmd.group_kinds;
    sr->backgrounded = node->cmd.backgrounded;

    const char *policy_netargv = NULL;
    sg_error_t build_error = SG_OK;
    sr->display_command =
        build_cmd_string(&node->cmd, &bw, gate, &policy_netargv,
                         &sr->netargv_length, &build_error);
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
    sr->violation_type_flags = node_viols[ni];
    sg_group_context(&graph, ni, node_viols, cmd_write_count, cmd_read_count,
                     &sr->violation_type_flags, &sr->write_count,
                     &sr->read_count);
    sr->violation_category_flags =
        sg_violation_categories(sr->violation_type_flags);

    /* Check deny policy first. The match-only path avoids constructing
     * suggestions when the caller has disabled their display. */
    st_eval_result_t deny_eval = {0};
    bool deny_matches = false;
    st_error_t deny_err =
        gate->suggestions
            ? st_policy_eval_view(gate->deny_policy, policy_netargv_view,
                                  &deny_eval)
            : st_policy_match_view(gate->deny_policy, policy_netargv_view,
                                   &deny_matches);
    if (gate->suggestions) {
      deny_matches = deny_eval.matches;
      /* A suggestion can exceed its bounded display buffer without making
       * policy matching invalid. Allocation failure is different: preserve
       * the fail-closed contract for work Shellgate requested. */
      if (deny_err == ST_OK && deny_eval.suggestion_error == ST_ERR_MEMORY)
        deny_err = deny_eval.suggestion_error;
    }
    if (deny_err != ST_OK) {
      sr->matches = false;
      sr->verdict = SG_VERDICT_UNDETERMINED;
      sr->reject_reason = bw_copy(&bw, "deny policy evaluation failed", 29);
      evaluation_error =
          deny_err == ST_ERR_MEMORY ? SG_ERR_MEMORY : SG_ERR_PARSE;
    } else if (deny_matches) {
      sr->matches = true;
      sr->verdict = SG_VERDICT_DENY;
      sr->reject_reason = bw_copy(&bw, "deny policy match", 17);
    } else {
      /* Check allow policy with the same optional suggestion work. */
      st_eval_result_t eval = {0};
      bool allow_matches = false;
      st_error_t eval_err =
          gate->suggestions
              ? st_policy_eval_view(gate->policy, policy_netargv_view, &eval)
              : st_policy_match_view(gate->policy, policy_netargv_view,
                                     &allow_matches);
      if (gate->suggestions) {
        allow_matches = eval.matches;
        if (eval_err == ST_OK && eval.suggestion_error == ST_ERR_MEMORY)
          eval_err = eval.suggestion_error;
      }
      if (eval_err != ST_OK) {
        sr->matches = false;
        sr->verdict = SG_VERDICT_UNDETERMINED;
        evaluation_error =
            eval_err == ST_ERR_MEMORY ? SG_ERR_MEMORY : SG_ERR_PARSE;
      } else if (allow_matches) {
        sr->matches = true;
        sr->verdict = SG_VERDICT_ALLOW;
      } else {
        sr->matches = false;
        sr->verdict = SG_VERDICT_UNDETERMINED;

        if (gate->suggestions) {
          if (eval.suggestion_count > 0 && out->suggestion_count == 0) {
            out->suggestions[0] =
                bw_copy_policy_cpl(&bw, eval.suggestions[0].pattern);
            if (out->suggestions[0])
              out->suggestion_count++;
            else if (bw.overflow) {
              out->truncated = true;
              out->verdict = SG_VERDICT_UNDETERMINED;
              free(owned_cmd_seq);
              free(owned_type_seq);
              return SG_ERR_TRUNC;
            }
          }
          if (eval.suggestion_count > 1 && out->suggestion_count == 1) {
            out->suggestions[1] =
                bw_copy_policy_cpl(&bw, eval.suggestions[1].pattern);
            if (out->suggestions[1])
              out->suggestion_count++;
            else if (bw.overflow) {
              out->truncated = true;
              out->verdict = SG_VERDICT_UNDETERMINED;
              free(owned_cmd_seq);
              free(owned_type_seq);
              return SG_ERR_TRUNC;
            }
          }
        }
      }

      if (gate->suggestions) {
        /* Generate deny suggestions from deny policy */
        if (deny_err == ST_OK && out->deny_suggestion_count == 0) {
          if (deny_eval.suggestion_count > 0) {
            out->deny_suggestions[0] =
                bw_copy_policy_cpl(&bw, deny_eval.suggestions[0].pattern);
            if (out->deny_suggestions[0])
              out->deny_suggestion_count++;
            else if (bw.overflow) {
              out->truncated = true;
              out->verdict = SG_VERDICT_UNDETERMINED;
              free(owned_cmd_seq);
              free(owned_type_seq);
              return SG_ERR_TRUNC;
            }
          }
          if (deny_eval.suggestion_count > 1 &&
              out->deny_suggestion_count == 1) {
            out->deny_suggestions[1] =
                bw_copy_policy_cpl(&bw, deny_eval.suggestions[1].pattern);
            if (out->deny_suggestions[1])
              out->deny_suggestion_count++;
            else if (bw.overflow) {
              out->truncated = true;
              out->verdict = SG_VERDICT_UNDETERMINED;
              free(owned_cmd_seq);
              free(owned_type_seq);
              return SG_ERR_TRUNC;
            }
          }
        }
      }
    }
    if (sr->verdict == SG_VERDICT_REJECT || sr->verdict == SG_VERDICT_DENY) {
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
  }

  out->short_circuited = stopped_early && out->subcommand_count < cmd_count;

  /* SUBST edges carry dynamic topology into an execution endpoint, directly
   * or through an expandable heredoc document. Resolve that endpoint after
   * all command nodes have been visited. A group-owned stream is marked on
   * every contained simple command because any of them can consume its
   * inherited descriptor. Only a flagged shell-word edge requests another
   * Shellgate inspection or changes an ALLOW verdict to conditional. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++) {
    const shell_dep_edge_t *edge = &graph.edges[ei];
    if (edge->type != SHELL_EDGE_SUBST || edge->from >= graph.node_count ||
        edge->to >= graph.node_count)
      continue;
    bool shell_word = (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0;
    out->has_dynamic_substitution_io = true;
    if (shell_word)
      out->requires_substitution_evaluation = true;
    uint32_t consumer_nodes[SHELL_DEP_MAX_NODES];
    uint32_t consumer_count = sg_substitution_consumers(
        &graph, edge->to, edge->flags, consumer_nodes);
    uint32_t consumer = UINT32_MAX;
    for (uint32_t consumer_index = 0; consumer_index < consumer_count;
         consumer_index++) {
      uint32_t consumer_node = consumer_nodes[consumer_index];
      if (graph.nodes[consumer_node].type == SHELL_NODE_GROUP) {
        sg_mark_group_substitution_consumers(&graph, node_result_index,
                                             consumer_node, shell_word, out);
        continue;
      }
      uint32_t result_index = node_result_index[consumer_node];
      if (result_index == UINT32_MAX)
        continue;
      out->subcommands[result_index].has_dynamic_substitution_io = true;
      if (shell_word)
        out->subcommands[result_index].requires_substitution_evaluation = true;
      if (shell_word &&
          out->subcommands[result_index].verdict == SG_VERDICT_ALLOW)
        out->subcommands[result_index].verdict = SG_VERDICT_ALLOW_CONDITIONAL;
      if (consumer_count == 1)
        consumer = result_index;
    }
    if (consumer == UINT32_MAX ||
        (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0)
      continue;

    uint32_t producer = node_result_index[edge->from];
    if (producer != UINT32_MAX)
      out->subcommands[producer].substitution_consumer_index =
          (int32_t)consumer;
  }

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
  if (out->subcommand_count == 0) {
    /* Truncation that leaves no subcommands means nothing was evaluated at all.
     * Reporting ALLOW/SG_OK would fail open on input the gate never inspected,
     * so surface it as undetermined and propagate the truncation error. */
    free(owned_cmd_seq);
    free(owned_type_seq);
    if (out->truncated) {
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    out->verdict = SG_VERDICT_ALLOW;
    return SG_OK;
  }

  bool all_allow = true;
  bool any_conditional = false;
  bool any_reject = false;
  bool any_deny = false;
  for (uint32_t i = 0; i < out->subcommand_count; i++) {
    if (out->subcommands[i].verdict != SG_VERDICT_ALLOW &&
        out->subcommands[i].verdict != SG_VERDICT_ALLOW_CONDITIONAL)
      all_allow = false;
    if (out->subcommands[i].verdict == SG_VERDICT_ALLOW_CONDITIONAL)
      any_conditional = true;
    if (out->subcommands[i].verdict == SG_VERDICT_REJECT)
      any_reject = true;
    if (out->subcommands[i].verdict == SG_VERDICT_DENY)
      any_deny = true;
  }

  if (any_reject)
    out->verdict = SG_VERDICT_REJECT;
  else if (any_deny)
    out->verdict = SG_VERDICT_DENY;
  else if (all_allow)
    out->verdict = (out->requires_substitution_evaluation || any_conditional)
                       ? SG_VERDICT_ALLOW_CONDITIONAL
                       : SG_VERDICT_ALLOW;
  else
    out->verdict = SG_VERDICT_UNDETERMINED;

  if (evaluation_error != SG_OK) {
    out->verdict = SG_VERDICT_UNDETERMINED;
    free(owned_cmd_seq);
    free(owned_type_seq);
    return evaluation_error;
  }

  /* Deferred anomaly model update — after verdict is known */
  if (gate->anomaly_enabled && gate->anomaly_model && cmd_count > 0) {
    bool should_update = false;
    if (!gate->anomaly_update_only_on_allow) {
      /* Always update, but skip if anomalous and flag is set */
      should_update = !out->anomaly_detected || !gate->anomaly_skip_on_detected;
    } else if (out->verdict == SG_VERDICT_ALLOW) {
      /* Only update on ALLOW verdict */
      should_update = !out->anomaly_detected || !gate->anomaly_skip_on_detected;
    }

    /* Record normal scores for adaptive threshold (before update, using current
     * model) */
    if (gate->anomaly_adaptive && !out->anomaly_detected &&
        isfinite(out->anomaly_score) && anomaly_count >= 3)
      adaptive_record_score(gate, out->anomaly_score);

    /* Record per-model CDF for Bayesian combination */
    if (gate->anomaly_combine_mode == SG_ANOMALY_COMBINE_BAYESIAN &&
        !out->anomaly_detected && anomaly_count >= 3) {
      cdf_record(gate->cdf_raw_hist, &gate->cdf_raw_count,
                 out->anomaly_score_raw);
      cdf_record(gate->cdf_type_hist, &gate->cdf_type_count,
                 out->anomaly_score_type);
    }

    if (should_update) {
      sg_anomaly_status_t raw_status = sg_anomaly_model_update_netseq(
          gate->anomaly_model, owned_cmd_seq, cmd_seq_length);
      /* Also update type sequence model */
      sg_anomaly_status_t type_status = SG_ANOMALY_OK;
      if (gate->anomaly_model_type && type_count > 0)
        type_status = sg_anomaly_model_update_netseq(
            gate->anomaly_model_type, type_seq, strlen(type_seq));
      if ((raw_status != SG_ANOMALY_OK && raw_status != SG_ANOMALY_ERR_MEMORY &&
           raw_status != SG_ANOMALY_ERR_LIMIT) ||
          (type_status != SG_ANOMALY_OK &&
           type_status != SG_ANOMALY_ERR_MEMORY &&
           type_status != SG_ANOMALY_ERR_LIMIT)) {
        free(owned_cmd_seq);
        free(owned_type_seq);
        return SG_ERR_PARSE;
      }
    }
  }

  /* Free evaluation-owned anomaly sequence buffers. */
  free(owned_cmd_seq);
  free(owned_type_seq);

  if (bw.overflow) {
    /* A diagnostic write may truncate without aborting the current command
     * walk. The retained policy verdict is not safe to report when the caller
     * cannot inspect the complete result. */
    out->truncated = true;
    out->verdict = SG_VERDICT_UNDETERMINED;
    return SG_ERR_TRUNC;
  }

  return SG_OK;
}

/* --- HELPERS --- */

size_t sg_gate_evaluate_size_hint(size_t cmd_len) {
  if (cmd_len > (SIZE_MAX - 512) / 4)
    return SIZE_MAX;
  return cmd_len * 4 + 512;
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
  case SG_VERDICT_ALLOW_CONDITIONAL:
    return "ALLOW_CONDITIONAL";
  }
  return "UNKNOWN";
}

uint32_t sg_result_violation_dropped(const sg_result_t *result) {
  return result ? result->violation_dropped_count : 0;
}
