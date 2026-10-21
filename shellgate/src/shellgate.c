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

#ifdef SHELLGATE_TEST_ALLOCATOR
#include "test_sg_failures.h"
#define SG_PATH_WORK() sg_test_path_work_charge()
#define SG_PATH_DECODED() sg_test_path_decoded_charge()
#define SG_PATH_IDENTITY(bytes) sg_test_path_identity_charge(bytes)
#else
#define SG_PATH_WORK() ((void)0)
#define SG_PATH_DECODED() ((void)0)
#define SG_PATH_IDENTITY(bytes) ((void)0)
#endif

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#define SG_EDGE_WORK()                                                         \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_EDGES)
#define SG_ARGUMENT_WORK()                                                     \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_ARGUMENTS)
#define SG_VIOLATION_INDEX_WORK()                                              \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX)
#define SG_EXPANSION_WORK()                                                    \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS)
#else
#define SG_EDGE_WORK() ((void)0)
#define SG_ARGUMENT_WORK() ((void)0)
#define SG_VIOLATION_INDEX_WORK() ((void)0)
#define SG_EXPANSION_WORK() ((void)0)
#endif

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

/* Append diagnostic bytes without a terminator; the enclosing formatter
 * terminates once. Overflow preserves the writer's fail-closed contract. */
static SHELL_NONNULL(1) void bw_detail_byte(buf_writer_t *w, char byte) {
  if (w->used >= w->size || w->size - w->used <= 1) {
    bw_mark_overflow(w);
    return;
  }
  w->base[w->used++] = byte;
}

static SHELL_NONNULL(1, 2) void bw_detail_escaped(buf_writer_t *w,
                                                  const char *bytes,
                                                  size_t length) {
  static const char hex[] = "0123456789ABCDEF";
  for (size_t i = 0; i < length && !w->overflow; i++) {
    unsigned char byte = (unsigned char)bytes[i];
    if (byte < 0x20 || byte >= 0x7f) {
      bw_detail_byte(w, '\\');
      bw_detail_byte(w, 'x');
      bw_detail_byte(w, hex[byte >> 4]);
      bw_detail_byte(w, hex[byte & 15]);
    } else {
      if (byte == '\\' || byte == '"')
        bw_detail_byte(w, '\\');
      bw_detail_byte(w, (char)byte);
    }
  }
}

/* FILE documents have boundary-validated source and optional resolved spans.
 * Copy both into result storage; neither callback nor graph lifetime leaks
 * into a returned diagnostic. Source-only details retain their old format. */
static SHELL_NONNULL(1, 2) const
    char *bw_file_detail(buf_writer_t *w, const shell_dep_doc_t *doc) {
  if (!(doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH))
    return bw_copy(w, doc->path, doc->path_len);
  if (w->used >= w->size) {
    w->overflow = true;
    return NULL;
  }
  const char *result = w->base + w->used;
  const char prefix[] = "resolved \"";
  const char middle[] = "\" (source \"";
  for (size_t i = 0; i < sizeof(prefix) - 1; i++)
    bw_detail_byte(w, prefix[i]);
  bw_detail_escaped(w, doc->value, doc->value_len);
  for (size_t i = 0; i < sizeof(middle) - 1; i++)
    bw_detail_byte(w, middle[i]);
  bw_detail_escaped(w, doc->path, doc->path_len);
  bw_detail_byte(w, '"');
  bw_detail_byte(w, ')');
  if (!w->overflow)
    w->base[w->used++] = '\0';
  return result;
}

static const char *bw_copy_policy_cpl(buf_writer_t *w,
                                      st_netpattern_view_t netpattern) {
  char *cpl = NULL;
  if (st_netpattern_to_cpl_view(netpattern, &cpl) != ST_OK)
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
  const char *text; /* Borrows the immutable configuration string. */
  size_t length;
  const size_t *transitions;
  uint16_t alphabet_size;
  /* Biased classes; bytes absent from the NUL-free pattern transition to 0. */
  uint8_t alphabet[UINT8_MAX + 1];
} sg_path_fragment_t;

static bool sg_path_byte_equals(unsigned char a, unsigned char b) {
  SG_PATH_WORK();
  return a == b;
}

/* Compile a byte-class DFA before configuration publication.
 * Only bytes present in the pattern need columns (at most 255); all others
 * immediately return to state 0. Each eval transition is constant-time even
 * when many suffixes branch from one cached, partially matched CWD state.
 * transitions holds length * alphabet_size entries. The shadow state is the
 * longest proper border, so compilation needs no retained fallback table.
 */
static SHELL_NONNULL(1, 2) void sg_path_fragment_compile(
    sg_path_fragment_t *fragment, size_t *transitions) {
  size_t columns = fragment->alphabet_size;
  fragment->transitions = transitions;
  for (size_t column = 0; column < columns; column++) {
    SG_PATH_WORK();
    transitions[column] = 0;
  }
  SG_PATH_WORK();
  transitions[fragment->alphabet[(unsigned char)fragment->text[0]] - 1] = 1;
  size_t shadow = 0;
  for (size_t i = 1; i < fragment->length; i++) {
    size_t *row = transitions + i * columns;
    for (size_t column = 0; column < columns; column++) {
      SG_PATH_WORK();
      row[column] = transitions[shadow * columns + column];
    }
    unsigned byte_class = fragment->alphabet[(unsigned char)fragment->text[i]];
    SG_PATH_WORK();
    row[byte_class - 1] = i + 1;
    shadow = transitions[shadow * columns + byte_class - 1];
  }
}

/* Empty fragments match nothing. text is an explicit span, including any
 * embedded NUL decoded from ANSI-C quoting. For a nonempty fragment, state is
 * an unmatched prefix (< length); the caller stops advancing after a match.
 * No border is recomputed. */
static SHELL_NONNULL(1, 2, 4) bool sg_path_fragment_advance(
    const sg_path_fragment_t *fragment, const char *text, size_t length,
    size_t *state) {
  if (fragment->length == 0)
    return false;
  size_t matched = *state;
  for (size_t i = 0; i < length; i++) {
    SG_PATH_WORK();
    unsigned byte_class = fragment->alphabet[(unsigned char)text[i]];
    matched = byte_class
                  ? fragment->transitions[matched * fragment->alphabet_size +
                                          byte_class - 1]
                  : 0;
    if (matched == fragment->length) {
      *state = matched;
      return true;
    }
  }
  *state = matched;
  return false;
}

struct sg_gate {
  const st_policy_t *policy;
  const st_policy_t *deny_policy;
  bool owns_policy;
  bool owns_deny_policy;

  char cwd[512];
  uint32_t reject_mask;
  sg_stop_mode_t stop_mode;
  bool suggestions;
  bool strict_mode;

  shell_expand_word_netargv_fn expand_word_netargv_fn;
  void *expand_word_netargv_ctx;

  bool viol_enabled;
  sg_violation_config_t viol_config;
  sg_path_fragment_t secret_fragments[SG_VIOL_MAX_PATHS];
  sg_path_fragment_t profile_fragments[SG_VIOL_MAX_PATHS];
  size_t path_prefix_lengths[3][SG_VIOL_MAX_PATHS];
  size_t *path_fragment_tables;

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

  g->policy = allow;
  g->deny_policy = deny;

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
  g->anomaly_k_factor = 3.0;

  return g;
}

sg_gate_t *sg_gate_new_with_policies_owned(st_policy_t *allow,
                                           st_policy_t *deny) {
  sg_gate_t *gate = sg_gate_new_with_policies_borrowed(allow, deny);
  if (gate) {
    gate->owns_policy = true;
    gate->owns_deny_policy = true;
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
  free(gate->path_fragment_tables);
  type_cache_free(&gate->anomaly_type_cache);
  cdf_free(gate);
  if (gate->owns_policy)
    st_policy_free((st_policy_t *)gate->policy);
  if (gate->owns_deny_policy)
    st_policy_free((st_policy_t *)gate->deny_policy);
  free(gate);
}

/* --- CONFIGURATION --- */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd) {
  if (strlen(cwd) >= sizeof(gate->cwd))
    return SG_ERR_TRUNC;
  sg_strlcpy(gate->cwd, cwd, sizeof(gate->cwd));
  return SG_OK;
}

sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask) {
  gate->reject_mask = mask;
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

  sg_path_fragment_t fragments[2][SG_VIOL_MAX_PATHS] = {0};
  const char *const *lists[2] = {config->sensitive_secret_paths,
                                 config->shell_profile_paths};
  const uint32_t counts[2] = {config->sensitive_secret_path_count,
                              config->shell_profile_path_count};
  size_t total = 0;
  for (unsigned list = 0; list < 2; list++) {
    for (uint32_t i = 0; i < counts[list]; i++) {
      size_t length = strlen(lists[list][i]);
      sg_path_fragment_t *fragment = &fragments[list][i];
      fragment->text = lists[list][i];
      fragment->length = length;
      for (size_t j = 0; j < length; j++) {
        unsigned char byte = (unsigned char)fragment->text[j];
        if (fragment->alphabet[byte] == 0)
          fragment->alphabet[byte] = (uint8_t)++fragment->alphabet_size;
      }
      size_t columns = fragment->alphabet_size;
      if (columns && length > (SIZE_MAX / sizeof(size_t) - total) / columns)
        return SG_ERR_MEMORY;
      total += length * columns;
    }
  }
  size_t *tables = NULL;
  if (total != 0) {
    tables = malloc(total * sizeof(*tables));
    if (!tables)
      return SG_ERR_MEMORY;
    size_t offset = 0;
    for (unsigned list = 0; list < 2; list++) {
      for (uint32_t i = 0; i < counts[list]; i++) {
        if (fragments[list][i].length != 0) {
          sg_path_fragment_compile(&fragments[list][i], tables + offset);
          offset +=
              fragments[list][i].length * fragments[list][i].alphabet_size;
        }
      }
    }
  }
  /* Only these tables are owned; string lifetime remains the borrowed API's
   * caller contract. No old state changes until preparation has succeeded. */
  free(gate->path_fragment_tables);
  gate->path_fragment_tables = tables;
  memcpy(gate->secret_fragments, fragments[0], sizeof(fragments[0]));
  memcpy(gate->profile_fragments, fragments[1], sizeof(fragments[1]));
  gate->viol_enabled = true;
  gate->viol_config = *config;
  const char *const *prefixes[] = {config->sensitive_write_paths,
                                   config->sensitive_dirs,
                                   config->sensitive_read_paths};
  uint32_t prefix_counts[] = {config->sensitive_write_path_count,
                              config->sensitive_dir_count,
                              config->sensitive_read_path_count};
  memset(gate->path_prefix_lengths, 0, sizeof(gate->path_prefix_lengths));
  for (unsigned list = 0; list < 3; list++)
    for (uint32_t i = 0; i < prefix_counts[list]; i++)
      gate->path_prefix_lengths[list][i] = strlen(prefixes[list][i]);
  return SG_OK;
}

/* --- ANOMALY DETECTION CONFIGURATION --- */

sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate, double threshold,
                                  const sg_anomaly_config_t *config) {
  if (!isfinite(threshold))
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
void sg_gate_set_allow_policy_owned(sg_gate_t *gate, st_policy_t *policy) {
  if (gate->owns_policy)
    st_policy_free((st_policy_t *)gate->policy);
  gate->policy = policy;
  gate->owns_policy = true;
}

void sg_gate_set_deny_policy_owned(sg_gate_t *gate, st_policy_t *policy) {
  if (gate->owns_deny_policy)
    st_policy_free((st_policy_t *)gate->deny_policy);
  gate->deny_policy = policy;
  gate->owns_deny_policy = true;
}

void sg_gate_set_allow_policy_borrowed(sg_gate_t *gate,
                                       const st_policy_t *policy) {
  if (gate->owns_policy)
    st_policy_free((st_policy_t *)gate->policy);
  gate->policy = policy;
  gate->owns_policy = false;
}

void sg_gate_set_deny_policy_borrowed(sg_gate_t *gate,
                                      const st_policy_t *policy) {
  if (gate->owns_deny_policy)
    st_policy_free((st_policy_t *)gate->deny_policy);
  gate->deny_policy = policy;
  gate->owns_deny_policy = false;
}

const st_policy_t *sg_gate_allow_policy_borrowed(const sg_gate_t *gate) {
  return gate->policy;
}

const st_policy_t *sg_gate_deny_policy_borrowed(const sg_gate_t *gate) {
  return gate->deny_policy;
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
        edge->type == SHELL_EDGE_ARG || edge->type == SHELL_EDGE_READ ||
        edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND ||
        edge->type == SHELL_EDGE_FD_OPEN ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == document);
    if (unresolved && owns_path) {
      flags[owner] |= SG_EXPANSION_UNRESOLVED_PATH;
      aggregate |= SG_EXPANSION_UNRESOLVED_PATH;
    }
  }
  return aggregate;
}

typedef struct {
  const char *data;
  size_t length;
  bool decoded;
  bool dynamic;
} sg_argument_t;

typedef struct {
  const shell_dep_cmd_t *command;
  const shell_expand_cache_t *cache;
  uint32_t next_token;
  shell_netstring_iter_t records;
  bool expanding;
} sg_argument_iter_t;

/* first is a source-token position, including token_count for an empty tail.
 * Resolved framing was checked at the callback boundary. Empty expansions
 * contribute no arguments; empty records still contribute one argument. */
static SHELL_NONNULL(1, 2, 3) void sg_argument_iter_init(
    sg_argument_iter_t *iter, const shell_dep_cmd_t *cmd,
    const shell_expand_cache_t *cache, uint32_t first) {
  *iter =
      (sg_argument_iter_t){.command = cmd, .cache = cache, .next_token = first};
}

static SHELL_NONNULL(1, 2) bool sg_argument_iter_next(sg_argument_iter_t *iter,
                                                      sg_argument_t *argument) {
  for (;;) {
    if (iter->expanding) {
      shell_netstring_view_t record;
      if (shell_netstring_iter_next(&iter->records, &record) ==
          SHELL_NETSTRING_OK) {
        *argument = (sg_argument_t){(const char *)record.payload,
                                    record.payload_length, true, false};
        SG_ARGUMENT_WORK();
        return true;
      }
      iter->expanding = false;
    }
    if (iter->next_token == iter->command->token_count)
      return false;
    sg_command_word_view_t word =
        sg_command_word_view(iter->command, iter->cache, iter->next_token++);
    if (word.value && word.value->resolved) {
      (void)shell_netstring_iter_init(&iter->records, word.value->netargv,
                                      word.value->length);
      iter->expanding = true;
      continue;
    }
    *argument = (sg_argument_t){word.source, word.length, false,
                                word.value && word.value->dynamic};
    SG_ARGUMENT_WORK();
    return true;
  }
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
typedef struct {
  const char *expected;
  size_t expected_len;
  bool matches;
} sg_static_match_t;

static bool sg_static_match_byte(unsigned char byte, size_t position,
                                 void *context) {
  sg_static_match_t *match = context;
  if (position >= match->expected_len ||
      byte != (unsigned char)match->expected[position])
    match->matches = false;
  return true;
}

static bool sg_static_word_equals(const char *word, uint32_t word_len,
                                  const char *expected, size_t expected_len) {
  sg_static_match_t match = {expected, expected_len, true};
  size_t decoded_len = 0;
  return shell_visit_static_word(word, word_len, sg_static_match_byte, &match,
                                 &decoded_len) &&
         match.matches && decoded_len == expected_len;
}

static bool sg_command_name_equals(const char *word, uint32_t word_len,
                                   const char *name);

static bool sg_name_found(const char *needle, uint32_t needle_len,
                          const char *const *names, uint32_t count,
                          uint32_t *out_idx) {
  for (uint32_t i = 0; i < count; i++) {
    const char *candidate = names[i];
    if (sg_command_name_equals(needle, needle_len, candidate)) {
      *out_idx = i;
      return true;
    }
  }
  return false;
}

static bool sg_env_name_found(const shell_dep_doc_t *doc,
                              const char *const *names, uint32_t count,
                              uint32_t *out_idx) {
  for (uint32_t i = 0; i < count; i++) {
    size_t length = strlen(names[i]);
    if (shell_dep_doc_env_name_equals(doc, names[i], length)) {
      *out_idx = i;
      return true;
    }
  }
  return false;
}

/* FILE documents retain diagnostic source spelling, but absolute configured
 * paths describe execution identities. Use recorded CWD and static quote
 * removal once for this lookup, in the eval workspace no longer used by the
 * graph builder. Relative prefix entries retain source-spelling semantics.
 * If identity is unavailable, the original decoded-spelling heuristic still
 * applies; it never supplies an invented CWD for an unresolved path. */
typedef struct {
  const char *decoded;
  size_t decoded_length;
  const char *identity;
  size_t length;
  bool known;
  bool absolute;
} sg_file_path_t;

typedef struct {
  char *decoded;
  bool has_nul;
} sg_path_decode_t;

static SHELL_NONNULL(3) bool sg_path_decode_byte(unsigned char byte,
                                                 size_t position,
                                                 void *context) {
  sg_path_decode_t *decode = context;
  SG_PATH_DECODED();
  decode->decoded[position] = (char)byte;
  decode->has_nul |= byte == 0;
  return true;
}

/* Decode and normalize only the operand, never its shared CWD. Returned views
 * borrow scratch until its next use. Decoding/normalization cannot expand an
 * isolated word beyond its source length (plus the terminating NUL). The
 * workspace boundary reserves capacity for both source and resolved operands;
 * capacity covers value_len + 1 for a resolved operand or 2 * (path_len + 1)
 * for source decoding/normalization. Lack of storage never changes whether an
 * identity is known. */
static SHELL_NONNULL(1, 2) sg_file_path_t
    sg_file_path_prepare(const shell_dep_doc_t *doc, char *scratch,
                         size_t capacity) {
  if (doc->flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
    return (sg_file_path_t){.decoded = doc->path,
                            .decoded_length = doc->path_len,
                            .identity = doc->path,
                            .length = doc->path_len,
                            .absolute = true,
                            .known = true};
  if (doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) {
    sg_file_path_t path = {.decoded = doc->value,
                           .decoded_length = doc->value_len,
                           .identity = scratch};
    path.absolute = doc->value[0] == '/';
    path.known = path.absolute || doc->cwd_known;
    if (path.known) {
      SG_PATH_IDENTITY(path.decoded_length);
      memcpy(scratch, path.decoded, path.decoded_length);
      path.length = shell_dep_file_path_normalize(scratch, path.decoded_length);
    }
    return path;
  }
  size_t decoded_capacity = capacity / 2;
  char *identity = scratch + decoded_capacity;
  sg_file_path_t path = {.decoded = scratch, .identity = identity};
  sg_path_decode_t decode = {.decoded = scratch};
  /* The graph has already classified this redirect operand in its shell
   * context. Decode once for spelling heuristics; unresolved dynamic paths
   * must never acquire a concrete identity from generic word classification. */
  bool is_static = !(doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME);
  bool decoded = shell_visit_decoded_word(
                     doc->path, doc->path_len, sg_path_decode_byte, &decode,
                     &path.decoded_length) == SHELL_PROCESS_OK;
  is_static = is_static && decoded;
  path.absolute = is_static && path.decoded_length != 0 && scratch[0] == '/';
  path.known = is_static && path.decoded_length != 0 && !decode.has_nul &&
               (path.absolute || doc->cwd_known);
  if (path.known) {
    SG_PATH_IDENTITY(path.decoded_length);
    memcpy(identity, scratch, path.decoded_length);
    path.length = shell_dep_file_path_normalize(identity, path.decoded_length);
  }
  return path;
}

static bool tok_equals(const char *tok, uint32_t tok_len, const char *str) {
  return sg_static_word_equals(tok, tok_len, str, strlen(str));
}

typedef struct {
  const char *prefix;
  size_t prefix_len;
  unsigned char next_byte;
  bool matches;
} sg_static_prefix_t;

static bool sg_static_prefix_byte(unsigned char byte, size_t position,
                                  void *context) {
  sg_static_prefix_t *match = context;
  if (position < match->prefix_len &&
      byte != (unsigned char)match->prefix[position])
    match->matches = false;
  if (position == match->prefix_len)
    match->next_byte = byte;
  return true;
}

static bool sg_static_word_prefix(const char *word, uint32_t word_len,
                                  const char *prefix, size_t prefix_len,
                                  bool require_more) {
  sg_static_prefix_t match = {prefix, prefix_len, 0, true};
  size_t decoded_len = 0;
  return shell_visit_static_word(word, word_len, sg_static_prefix_byte, &match,
                                 &decoded_len) &&
         match.matches && decoded_len >= prefix_len + (require_more ? 1u : 0u);
}

/* A literal option prefix retains its meaning even when its value expands at
 * runtime. Syntactic decoding leaves expansion markers visible, so they
 * cannot supply bytes of the option prefix. */
static bool sg_decoded_word_prefix(const char *word, uint32_t word_len,
                                   const char *prefix, size_t prefix_len,
                                   bool require_more) {
  sg_static_prefix_t match = {prefix, prefix_len, 0, true};
  size_t decoded_len = 0;
  return shell_visit_decoded_word(word, word_len, sg_static_prefix_byte, &match,
                                  &decoded_len) == SHELL_PROCESS_OK &&
         match.matches && decoded_len >= prefix_len + (require_more ? 1u : 0u);
}

static bool sg_word_option_value(const char *word, uint32_t word_len,
                                 const char *option) {
  size_t option_len = strlen(option);
  sg_static_prefix_t match = {option, option_len, 0, true};
  size_t decoded_len = 0;
  return shell_visit_decoded_word(word, word_len, sg_static_prefix_byte, &match,
                                  &decoded_len) == SHELL_PROCESS_OK &&
         match.matches && decoded_len > option_len && match.next_byte == '=';
}

static bool tok_is_option(const char *tok, uint32_t tok_len,
                          const char *option) {
  return tok_equals(tok, tok_len, option) ||
         sg_word_option_value(tok, tok_len, option);
}

typedef struct {
  size_t last_slash;
} sg_static_basename_t;

static bool sg_static_basename_byte(unsigned char byte, size_t position,
                                    void *context) {
  sg_static_basename_t *name = context;
  if (byte == '/')
    name->last_slash = position + 1;
  return true;
}

typedef struct {
  size_t start;
  const char *candidate;
  size_t candidate_len;
  bool matches;
} sg_static_suffix_t;

static bool sg_static_suffix_byte(unsigned char byte, size_t position,
                                  void *context) {
  sg_static_suffix_t *suffix = context;
  if (position >= suffix->start &&
      (position - suffix->start >= suffix->candidate_len ||
       byte != (unsigned char)suffix->candidate[position - suffix->start]))
    suffix->matches = false;
  return true;
}

/* Match the executable after an option prefix without materializing a decoded
 * word. A configured path is exact; a bare name may match a static pathname's
 * basename. Use the same rule for direct commands and sudo/su operands. */
static bool sg_command_name_equals_after(const char *word, uint32_t word_len,
                                         size_t skip, const char *name) {
  size_t candidate_len = strlen(name);
  if (candidate_len == 0)
    return false;
  if (skip == 0 && sg_static_word_equals(word, word_len, name, candidate_len))
    return true;
  bool configured_path = strchr(name, '/') != NULL;
  if (skip == 0 && configured_path)
    return false;
  sg_static_basename_t basename = {skip};
  size_t decoded_len = 0;
  if (!shell_visit_static_word(word, word_len, sg_static_basename_byte,
                               &basename, &decoded_len) ||
      decoded_len <= skip)
    return false;
  size_t start = skip;
  if (!configured_path && basename.last_slash > skip)
    start = basename.last_slash;
  if (decoded_len - start != candidate_len)
    return false;
  sg_static_suffix_t suffix = {start, name, candidate_len, true};
  size_t ignored = 0;
  return shell_visit_static_word(word, word_len, sg_static_suffix_byte, &suffix,
                                 &ignored) &&
         suffix.matches;
}

static bool sg_command_name_in_after(const char *word, uint32_t word_len,
                                     size_t skip, const char *const *names,
                                     uint32_t name_count) {
  for (uint32_t i = 0; i < name_count; i++) {
    if (sg_command_name_equals_after(word, word_len, skip, names[i]))
      return true;
  }
  return false;
}

/* A configured path names that exact executable. A configured bare name also
 * recognizes a static path with the same basename; command lookup can yield
 * the same utility either through PATH or through an explicit pathname. This
 * remains a name-based violation heuristic, not filesystem resolution. */
static bool sg_command_name_equals(const char *word, uint32_t word_len,
                                   const char *name) {
  return sg_command_name_equals_after(word, word_len, 0, name);
}

typedef struct {
  bool starts_dash;
} sg_static_first_t;

static bool sg_static_first_byte(unsigned char byte, size_t position,
                                 void *context) {
  sg_static_first_t *first = context;
  if (position == 0)
    first->starts_dash = byte == '-';
  return true;
}

static bool sg_word_starts_dash(const char *word, uint32_t word_len) {
  sg_static_first_t first = {false};
  size_t decoded_len = 0;
  return shell_visit_decoded_word(word, word_len, sg_static_first_byte, &first,
                                  &decoded_len) == SHELL_PROCESS_OK &&
         decoded_len > 0 && first.starts_dash;
}

/* Shellsplit has already resolved static command/builtin wrapper syntax while
 * building the graph. Use that one interpretation for violation names too;
 * policy evaluation continues to receive the original unmodified argv.
 * `builtin external-name` does not execute the external utility. */
static SHELL_NONNULL(1, 2, 3, 4) bool sg_effective_command_word(
    const shell_dep_node_t *node, const char **word, uint32_t *length,
    uint32_t *index) {
  if (node->type != SHELL_NODE_CMD || !node->cmd.effective_command_known ||
      node->cmd.effective_command_wrapper == SHELL_DEP_COMMAND_BUILTIN)
    return false;
  *index = node->cmd.effective_command_token;
  *word = node->cmd.tokens[*index];
  *length = node->cmd.token_lens[*index];
  return true;
}

/* Argument records are already decoded data; fallback views retain the
 * existing source-aware heuristics, including literal option prefixes whose
 * values remain dynamic. Never pass a decoded view to source-word visitors. */
static SHELL_NONNULL(2) bool sg_argument_equals(sg_argument_t argument,
                                                const char *text) {
  size_t length = strlen(text);
  return argument.decoded
             ? argument.length == length &&
                   memcmp(argument.data, text, length) == 0
             : tok_equals(argument.data, (uint32_t)argument.length, text);
}

static SHELL_NONNULL(2) bool sg_argument_prefix(sg_argument_t argument,
                                                const char *prefix,
                                                size_t length, bool more,
                                                bool static_only) {
  if (argument.decoded)
    return argument.length >= length + (size_t)more &&
           memcmp(argument.data, prefix, length) == 0;
  return static_only
             ? sg_static_word_prefix(argument.data, (uint32_t)argument.length,
                                     prefix, length, more)
             : sg_decoded_word_prefix(argument.data, (uint32_t)argument.length,
                                      prefix, length, more);
}

static SHELL_NONNULL(2) bool sg_argument_option(sg_argument_t argument,
                                                const char *option) {
  if (!argument.decoded)
    return tok_is_option(argument.data, (uint32_t)argument.length, option);
  size_t length = strlen(option);
  return sg_argument_equals(argument, option) ||
         (argument.length > length && argument.data[length] == '=' &&
          memcmp(argument.data, option, length) == 0);
}

static bool sg_argument_starts_dash(sg_argument_t argument) {
  return argument.decoded
             ? argument.length != 0 && argument.data[0] == '-'
             : sg_word_starts_dash(argument.data, (uint32_t)argument.length);
}

static SHELL_NONNULL(3) bool sg_argument_name_in_after(sg_argument_t argument,
                                                       size_t skip,
                                                       const char *const *names,
                                                       uint32_t count) {
  if (!argument.decoded)
    return sg_command_name_in_after(argument.data, (uint32_t)argument.length,
                                    skip, names, count);
  if (argument.length <= skip)
    return false;
  size_t basename = skip;
  for (size_t i = skip; i < argument.length; i++)
    if (argument.data[i] == '/')
      basename = i + 1;
  for (uint32_t i = 0; i < count; i++) {
    size_t start = strchr(names[i], '/') ? skip : basename;
    size_t length = strlen(names[i]);
    if (argument.length - start == length &&
        memcmp(argument.data + start, names[i], length) == 0)
      return true;
  }
  return false;
}

typedef struct {
  unsigned char window[6];
  size_t used;
  bool colon, listener;
} sg_argument_substrings_t;

static SHELL_NONNULL(3) bool sg_argument_substring_byte(unsigned char byte,
                                                        size_t position,
                                                        void *context) {
  (void)position;
  sg_argument_substrings_t *facts = context;
  facts->colon |= byte == ':';
  if (facts->used == sizeof(facts->window)) {
    memmove(facts->window, facts->window + 1, sizeof(facts->window) - 1);
    facts->used--;
  }
  facts->window[facts->used++] = byte;
  if (facts->used == sizeof(facts->window))
    facts->listener |= memcmp(facts->window, "LISTEN", 6) == 0 ||
                       memcmp(facts->window, "listen", 6) == 0;
  return true;
}

/* Static source was classified at the expansion boundary. Decode it once for
 * all substring facts; resolved payloads are already bytes, including NULs.
 * Only genuinely unresolved source retains the source-spelling heuristic. */
static sg_argument_substrings_t sg_argument_substrings(sg_argument_t argument) {
  sg_argument_substrings_t facts = {0};
  if (!argument.decoded && !argument.dynamic) {
    size_t length;
    (void)shell_visit_decoded_word(argument.data, argument.length,
                                   sg_argument_substring_byte, &facts, &length);
  } else
    for (size_t i = 0; i < argument.length; i++)
      (void)sg_argument_substring_byte((unsigned char)argument.data[i], i,
                                       &facts);
  return facts;
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

#define SG_NODE_WORDS ((SHELL_DEP_MAX_NODES + 63) / 64)

enum {
  SG_FILE_PATH_SENSITIVE_WRITE = 1u << 0,
  SG_FILE_PATH_SENSITIVE_DIR = 1u << 1,
  SG_FILE_PATH_SENSITIVE_READ = 1u << 2,
  SG_FILE_PATH_PROFILE = 1u << 3,
  SG_FILE_PATH_SECRET = 1u << 4,
  /* Two roots distinguish identities anchored at an absolute initial CWD
   * from identities whose initial CWD is itself relative. Inserting one new
   * identity creates at most one split and one leaf. */
  SG_FILE_IDENTITY_ROOTS = 2,
  SG_FILE_IDENTITY_TRIE_NODES =
      SG_FILE_IDENTITY_ROOTS + 5 * SHELL_DEP_MAX_NODES,
};

_Static_assert(SG_FILE_IDENTITY_TRIE_NODES <= UINT16_MAX,
               "file identity trie indexes must fit their stored type");

/* State at an exact trie position. End-of-input prefix acceptance is separate:
 * /tmp must not make /tmp-more match. DFA states span CWD/operand boundaries.
 */
typedef struct {
  size_t length;
  uint32_t flags, prefixes[3];
  size_t fragments[2][SG_VIOL_MAX_PATHS];
} sg_file_match_t;

static SHELL_NONNULL(1, 3) const
    char *const *sg_path_prefix_list(const sg_gate_t *gate, unsigned list,
                                     uint32_t *count) {
  const sg_violation_config_t *config = &gate->viol_config;
  if (list == 0) {
    *count = config->sensitive_write_path_count;
    return config->sensitive_write_paths;
  }
  if (list == 1) {
    *count = config->sensitive_dir_count;
    return config->sensitive_dirs;
  }
  *count = config->sensitive_read_path_count;
  return config->sensitive_read_paths;
}

/* Modes 1/2 select absolute/relative configuration prefixes. Absolute fragments
 * use normalized absolute identities when known, never a relative-rooted
 * identity or its raw spelling. Unknown decoded paths retain all heuristics. */
static SHELL_NONNULL(1, 4) void sg_file_match_init(const sg_gate_t *gate,
                                                   unsigned prefix_modes,
                                                   bool absolute_fragments,
                                                   sg_file_match_t *match) {
  memset(match, 0, sizeof(*match));
  for (unsigned list = 0; list < 3; list++) {
    uint32_t count;
    const char *const *prefixes = sg_path_prefix_list(gate, list, &count);
    for (uint32_t i = 0; i < count; i++)
      if (gate->path_prefix_lengths[list][i] != 0 &&
          (prefix_modes & (prefixes[i][0] == '/' ? 1u : 2u)))
        match->prefixes[list] |= UINT32_C(1) << i;
  }
  const sg_path_fragment_t *fragments[] = {gate->profile_fragments,
                                           gate->secret_fragments};
  const uint32_t counts[] = {gate->viol_config.shell_profile_path_count,
                             gate->viol_config.sensitive_secret_path_count};
  for (unsigned list = 0; list < 2; list++)
    for (uint32_t i = 0; i < counts[list]; i++)
      if (!absolute_fragments && fragments[list][i].text[0] == '/')
        match->fragments[list][i] = SIZE_MAX;
}

static SHELL_NONNULL(1, 2,
                     4) void sg_file_match_extend(const sg_gate_t *gate,
                                                  const char *text,
                                                  size_t length,
                                                  sg_file_match_t *match) {
  for (unsigned list = 0; list < 3; list++) {
    uint32_t count;
    const char *const *prefixes = sg_path_prefix_list(gate, list, &count);
    uint32_t flag = UINT32_C(1) << list;
    if (match->flags & flag)
      continue;
    for (uint32_t i = 0; i < count; i++) {
      uint32_t bit = UINT32_C(1) << i;
      if (!(match->prefixes[list] & bit))
        continue;
      size_t prefix_length = gate->path_prefix_lengths[list][i];
      for (size_t j = 0; j < length; j++) {
        size_t position = match->length + j;
        if (position == prefix_length) {
          if (sg_path_byte_equals((unsigned char)text[j], '/'))
            match->flags |= flag;
          else
            match->prefixes[list] &= ~bit;
          break;
        }
        if (!sg_path_byte_equals((unsigned char)text[j],
                                 (unsigned char)prefixes[i][position])) {
          match->prefixes[list] &= ~bit;
          break;
        }
        if (position + 1 == prefix_length && prefixes[i][position] == '/') {
          match->flags |= flag;
          break;
        }
      }
      if (match->flags & flag)
        break;
    }
  }
  const sg_path_fragment_t *fragments[] = {gate->profile_fragments,
                                           gate->secret_fragments};
  const uint32_t counts[] = {gate->viol_config.shell_profile_path_count,
                             gate->viol_config.sensitive_secret_path_count};
  const uint32_t flags[] = {SG_FILE_PATH_PROFILE, SG_FILE_PATH_SECRET};
  for (unsigned list = 0; list < 2; list++) {
    if (match->flags & flags[list])
      continue;
    for (uint32_t i = 0; i < counts[list]; i++)
      if (match->fragments[list][i] != SIZE_MAX &&
          sg_path_fragment_advance(&fragments[list][i], text, length,
                                   &match->fragments[list][i])) {
        match->flags |= flags[list];
        break;
      }
  }
  match->length += length;
}

static SHELL_NONNULL(1, 2) uint32_t
    sg_file_match_flags(const sg_gate_t *gate, const sg_file_match_t *match) {
  uint32_t flags = match->flags;
  for (unsigned list = 0; list < 3; list++) {
    uint32_t candidates = match->prefixes[list];
    while (candidates) {
      unsigned i = (unsigned)__builtin_ctz(candidates);
      candidates &= candidates - 1;
      if (gate->path_prefix_lengths[list][i] == match->length) {
        flags |= UINT32_C(1) << list;
        break;
      }
    }
  }
  return flags;
}

typedef struct {
  size_t offset, length;
  uint32_t group_plus_one;
  sg_file_match_t match;
} sg_file_identity_node_t;

/* Valid constructed graph, immutable throughout evaluation. These indexes
 * live in the resolver workspace after parsing has released its scratch. */
typedef struct {
  uint32_t out_head[SHELL_DEP_MAX_NODES], in_head[SHELL_DEP_MAX_NODES];
  uint32_t out_next[SHELL_DEP_MAX_EDGES], in_next[SHELL_DEP_MAX_EDGES];
  uint32_t group_violations[SHELL_DEP_MAX_NODES];
  uint32_t group_writes[SHELL_DEP_MAX_NODES], group_reads[SHELL_DEP_MAX_NODES];
  uint32_t group_expansions[SHELL_DEP_MAX_NODES];
  uint8_t group_substitution[SHELL_DEP_MAX_NODES];
  /* Only the suffix is initialized when violation analysis is enabled. */
  uint32_t sensitive_head[SHELL_DEP_MAX_NODES];
  uint32_t sensitive_next[SHELL_DEP_MAX_EDGES];
  uint32_t sensitive_target[SHELL_DEP_MAX_EDGES];
  uint32_t sensitive_doc[SHELL_DEP_MAX_NODES];
  uint32_t file_group_count;
  uint32_t file_identity_group[SHELL_DEP_MAX_NODES];
  uint32_t file_path_flags[SHELL_DEP_MAX_NODES];
  /* Argument-dependent rule facts are computed once per command, including
   * decoder facts reused across all effective pipeline routes. */
  uint32_t argument_facts[SHELL_DEP_MAX_NODES];
  uint8_t git_operation[SHELL_DEP_MAX_NODES];
  uint64_t group_read_targets[SHELL_DEP_MAX_NODES][SG_NODE_WORDS];
  sg_file_identity_node_t file_identity_nodes[SG_FILE_IDENTITY_TRIE_NODES];
  uint16_t file_identity_children[SG_FILE_IDENTITY_TRIE_NODES][UINT8_MAX + 1];
  uint16_t file_identity_node_count;
  size_t file_identity_pool_used;
  /* Biased stable trie positions, indexed by installed CWD pool offset. */
  uint16_t cwd_identity[2][SHELL_DEP_CWD_BUF_SIZE];
  uint16_t cwd_directory[2][SHELL_DEP_CWD_BUF_SIZE];
  uint32_t pipe_producer_head[SHELL_DEP_MAX_NODES][SHELL_DEP_MAX_NODES];
  uint32_t pipe_consumer_head[SHELL_DEP_MAX_NODES][SHELL_DEP_MAX_NODES];
  uint32_t pipe_producer_next[SHELL_DEP_MAX_NODES];
  uint32_t pipe_consumer_next[SHELL_DEP_MAX_NODES];
  uint64_t control_reachable[SHELL_DEP_MAX_NODES][SG_NODE_WORDS];
} sg_graph_index_t;

/* Reuse the resolver workspace for one decoded FILE view and a persistent,
 * prefix-compressed canonical-identity pool. The pool shares CWD and path
 * prefixes across documents, so the source/CWD bound reserves all material
 * without multiplying it by the node count. */
static SHELL_NONNULL(2) bool sg_eval_workspace_size(size_t command_length,
                                                    size_t *required) {
  if (!shell_dep_workspace_size(NULL, required))
    return false;
  size_t delimiter_size;
  if (!shell_source_workspace_size(command_length, &delimiter_size) ||
      delimiter_size > SIZE_MAX - *required)
    return false;
  *required += delimiter_size; /* Delimiter preparation in the graph tail. */
  size_t overhead = sizeof(sg_graph_index_t);
  size_t cwd_space = SHELL_DEP_CWD_BUF_SIZE + 1u;
  if (command_length > (SIZE_MAX - overhead) / 4 - cwd_space)
    return false;
  size_t path_space = overhead + 4 * (command_length + cwd_space);
  if (path_space > *required)
    *required = path_space;
  size_t cache_size;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_expand_cache_size(command_length, &cache_size) ||
      *required > SIZE_MAX - cache_size - alignment)
    return false;
  *required += cache_size + alignment;
  return true;
}

/* This boundary sizes path storage from graph metadata, not callback source
 * spellings. Resolver storage is retired; cache storage remains live. bw has
 * an unused result prefix. Extend private storage into that prefix only when
 * the retired region cannot hold both contiguous spans, before any result
 * strings are emitted. source_length already passed sg_eval_workspace_size's
 * arithmetic boundary; outputs are distinct writable storage. All subsequent
 * path helpers rely on these capacities.
 */
static SHELL_NONNULL(1, 3, 5, 6, 7, 8, 9) bool sg_path_workspace_prepare(
    const shell_dep_graph_t *graph, size_t source_length, char *retired,
    size_t retired_size, buf_writer_t *bw, char **scratch,
    size_t *scratch_capacity, char **pool, size_t *pool_capacity) {
  size_t source_capacity = 2 * (source_length + SHELL_DEP_CWD_BUF_SIZE + 1u);
  size_t scratch_size = source_capacity;
  size_t pool_size = source_capacity;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    SG_VIOLATION_INDEX_WORK();
    const shell_dep_node_t *item = &graph->nodes[node];
    if (item->type != SHELL_NODE_DOC || item->doc.kind != SHELL_DOC_FILE ||
        !(item->doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) ||
        (item->doc.flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED))
      continue;
    const shell_dep_doc_t *doc = &item->doc;
    if (doc->value[0] != '/' && !doc->cwd_known)
      continue;
    size_t length = doc->value_len;
    if (length == SIZE_MAX || length > SIZE_MAX - pool_size)
      return false;
    if (length + 1 > scratch_size)
      scratch_size = length + 1;
    pool_size += length;
  }
  if (scratch_size <= retired_size &&
      pool_size <= retired_size - scratch_size) {
    *scratch = retired;
    *scratch_capacity = scratch_size;
    *pool = retired + scratch_size;
    *pool_capacity = retired_size - scratch_size;
    return true;
  }

  /* Put the larger span in retired storage when it fits, otherwise the
   * smaller span. Neither needs alignment: both contain only path bytes. */
  bool scratch_retired =
      scratch_size <= retired_size &&
      (scratch_size >= pool_size || pool_size > retired_size);
  bool pool_retired = !scratch_retired && pool_size <= retired_size;
  size_t extra = scratch_retired ? 0 : scratch_size;
  if (!pool_retired) {
    if (pool_size > SIZE_MAX - extra)
      return false;
    extra += pool_size;
  }
  if (extra >= bw->size)
    return false;
  bw->size -= extra;
  char *extension = bw->base + bw->size;
  *scratch = scratch_retired ? retired : extension;
  *scratch_capacity = scratch_size;
  *pool = pool_retired      ? retired
          : scratch_retired ? extension
                            : extension + scratch_size;
  *pool_capacity = pool_retired ? retired_size : pool_size;
  return true;
}

static SHELL_NONNULL(1, 2) void sg_graph_index_build(
    const shell_dep_graph_t *graph, sg_graph_index_t *index) {
  memset(index, 0, offsetof(sg_graph_index_t, sensitive_head));
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

/* Extend an exact identity/CWD cursor in a compressed byte trie. Edge labels
 * borrow the persistent pool; splitting reuses existing bytes and copies only
 * the divergent suffix. Direct byte transitions keep lookup linear in supplied
 * operand/CWD bytes, without revisiting a cached directory prefix. */
static SHELL_NONNULL(1, 2, 4, 6, 8) bool sg_file_identity_intern(
    sg_graph_index_t *index, const sg_gate_t *gate, uint16_t parent,
    const char *text, size_t length, char *pool, size_t pool_capacity,
    uint16_t *terminal) {
  size_t position = 0;
  while (position < length) {
    unsigned char first = (unsigned char)text[position];
    uint16_t child = index->file_identity_children[parent][first];
    if (child == 0) {
      size_t suffix_length = length - position;
      if (suffix_length > pool_capacity - index->file_identity_pool_used)
        return false;
      uint16_t leaf = index->file_identity_node_count++;
      size_t offset = index->file_identity_pool_used;
      SG_PATH_IDENTITY(suffix_length);
      memcpy(pool + offset, text + position, suffix_length);
      index->file_identity_pool_used += suffix_length;
      index->file_identity_nodes[leaf] = (sg_file_identity_node_t){
          .offset = offset,
          .length = suffix_length,
          .match = index->file_identity_nodes[parent].match,
      };
      sg_file_match_extend(gate, text + position, suffix_length,
                           &index->file_identity_nodes[leaf].match);
      index->file_identity_children[parent][first] = leaf;
      *terminal = leaf;
      return true;
    }

    sg_file_identity_node_t *edge = &index->file_identity_nodes[child];
    size_t available = length - position;
    size_t shared = edge->length < available ? edge->length : available;
    size_t common = 0;
    while (common < shared) {
      SG_PATH_IDENTITY(1);
      if (pool[edge->offset + common] != text[position + common])
        break;
      common++;
    }
    if (common == edge->length) {
      position += common;
      parent = child;
      continue;
    }

    bool input_ends = common == available;
    size_t suffix_length = input_ends ? 0 : available - common;
    /* First-byte transitions guarantee a nonempty common prefix. At most two
     * nodes per FILE, two per distinct CWD, and one separator node per CWD fit
     * the fixed bound. Splitting changes only the incoming edge of an existing
     * node, not its exact identity or cached predicate/CWD position. */
    if (suffix_length > pool_capacity - index->file_identity_pool_used)
      return false;
    uint16_t middle = index->file_identity_node_count++;
    index->file_identity_nodes[middle] = (sg_file_identity_node_t){
        .offset = edge->offset,
        .length = common,
        .match = index->file_identity_nodes[parent].match,
    };
    sg_file_match_extend(gate, pool + edge->offset, common,
                         &index->file_identity_nodes[middle].match);
    index->file_identity_children[parent][first] = middle;
    edge->offset += common;
    edge->length -= common;
    index->file_identity_children[middle][(unsigned char)pool[edge->offset]] =
        child;
    if (input_ends) {
      *terminal = middle;
    } else {
      uint16_t leaf = index->file_identity_node_count++;
      size_t offset = index->file_identity_pool_used;
      SG_PATH_IDENTITY(suffix_length);
      memcpy(pool + offset, text + position + common, suffix_length);
      index->file_identity_pool_used += suffix_length;
      index->file_identity_nodes[leaf] = (sg_file_identity_node_t){
          .offset = offset,
          .length = suffix_length,
          .match = index->file_identity_nodes[middle].match,
      };
      sg_file_match_extend(gate, text + position + common, suffix_length,
                           &index->file_identity_nodes[leaf].match);
      index->file_identity_children[middle][(unsigned char)pool[offset]] = leaf;
      *terminal = leaf;
    }
    return true;
  }
  *terminal = parent;
  return true;
}

/* The installed CWD pool offset is a trusted O(1) cache key. Prepare each
 * distinct directory once, without allocating or storing repeated full paths.
 * scratch has space for the bounded CWD plus its NUL. Identity/directory nodes
 * remain stable even if later absolute operands split trie edge labels. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool sg_file_cwd_prepare(
    sg_graph_index_t *index, const sg_gate_t *gate,
    const shell_dep_graph_t *graph, const shell_dep_doc_t *doc, char *scratch,
    char *pool, size_t pool_capacity) {
  unsigned root = doc->cwd_absolute ? 1u : 0u;
  if (index->cwd_identity[root][doc->cwd_offset] != 0)
    return true;
  const char *cwd = graph->cwd_buf.data + doc->cwd_offset;
  size_t length = 0;
  while (cwd[length] != '\0') {
    SG_PATH_IDENTITY(1);
    length++;
  }
  SG_PATH_IDENTITY(length);
  memcpy(scratch, cwd, length);
  /* Identity joining inserts '/' even for an empty retained CWD prefix (also
   * possible on a capacity-truncated graph). Preserve that lexical separator
   * without changing the separate absolute/relative provenance root. */
  if (length == 0) {
    scratch[0] = '/';
    length = 1;
  } else
    length = shell_dep_file_path_normalize(scratch, length);
  uint16_t identity, directory;
  if (!sg_file_identity_intern(index, gate, (uint16_t)root, scratch, length,
                               pool, pool_capacity, &identity))
    return false;
  if (length == 1 && scratch[0] == '.')
    directory = (uint16_t)root;
  else if (scratch[length - 1] == '/')
    directory = identity;
  else if (!sg_file_identity_intern(index, gate, identity, "/", 1, pool,
                                    pool_capacity, &directory))
    return false;
  index->cwd_identity[root][doc->cwd_offset] = identity + 1;
  index->cwd_directory[root][doc->cwd_offset] = directory + 1;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4, 5) bool sg_graph_violation_index_build(
    const shell_dep_graph_t *graph, sg_graph_index_t *index,
    const sg_gate_t *gate, char *path_scratch, char *identity_pool,
    size_t scratch_capacity, size_t pool_capacity) {
  size_t offset = offsetof(sg_graph_index_t, sensitive_head);
  memset((char *)index + offset, 0, sizeof(*index) - offset);
  index->file_identity_node_count = SG_FILE_IDENTITY_ROOTS;
  sg_file_match_init(gate, 0, false, &index->file_identity_nodes[0].match);
  sg_file_match_init(gate, 1, true, &index->file_identity_nodes[1].match);
  for (uint32_t node = 0; node < graph->node_count; node++) {
    SG_VIOLATION_INDEX_WORK();
    index->sensitive_head[node] = index->sensitive_doc[node] = UINT32_MAX;
    index->file_identity_group[node] = UINT32_MAX;
    index->pipe_producer_next[node] = 0;
    index->pipe_consumer_next[node] = 0;
    const shell_dep_node_t *item = &graph->nodes[node];
    if (item->type == SHELL_NODE_DOC && item->doc.kind == SHELL_DOC_FILE) {
      if (item->doc.flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)
        continue;
      if (item->doc.cwd_known &&
          !sg_file_cwd_prepare(index, gate, graph, &item->doc, path_scratch,
                               identity_pool, pool_capacity))
        return false;
      sg_file_path_t path =
          sg_file_path_prepare(&item->doc, path_scratch, scratch_capacity);
      uint32_t flags = 0;
      if (path.known) {
        uint16_t parent = 1, terminal;
        size_t length = path.length;
        if (!path.absolute) {
          unsigned root = item->doc.cwd_absolute ? 1u : 0u;
          if (length == 1 && path.identity[0] == '.') {
            parent = index->cwd_identity[root][item->doc.cwd_offset] - 1;
            length = 0;
          } else
            parent = index->cwd_directory[root][item->doc.cwd_offset] - 1;
        }
        if (!sg_file_identity_intern(index, gate, parent, path.identity, length,
                                     identity_pool, pool_capacity, &terminal))
          return false;
        sg_file_identity_node_t *identity =
            &index->file_identity_nodes[terminal];
        if (identity->group_plus_one == 0)
          identity->group_plus_one = ++index->file_group_count;
        index->file_identity_group[node] = identity->group_plus_one - 1;
        flags = sg_file_match_flags(gate, &identity->match);
      }
      sg_file_match_t decoded;
      sg_file_match_init(gate, path.known ? 2u : 3u, !path.known, &decoded);
      sg_file_match_extend(gate, path.decoded, path.decoded_length, &decoded);
      index->file_path_flags[node] =
          flags | sg_file_match_flags(gate, &decoded);
      if (index->file_path_flags[node] & SG_FILE_PATH_SENSITIVE_READ)
        index->sensitive_doc[node] = node;
    }
  }
  memset(index->pipe_producer_head, 0, sizeof(index->pipe_producer_head));
  memset(index->pipe_consumer_head, 0, sizeof(index->pipe_consumer_head));
  for (uint32_t ei = graph->edge_count; ei-- > 0;) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *edge = &graph->edges[ei];
    uint32_t document = UINT32_MAX;
    if (edge->type == SHELL_EDGE_READ &&
        graph->nodes[edge->from].type == SHELL_NODE_DOC)
      document = edge->from;
    else if (edge->type == SHELL_EDGE_ARG &&
             graph->nodes[edge->to].type == SHELL_NODE_DOC)
      document = edge->to;
    if (document != UINT32_MAX &&
        index->file_identity_group[document] != UINT32_MAX) {
      uint32_t target = edge->type == SHELL_EDGE_READ ? edge->to : edge->from;
      uint32_t group = index->file_identity_group[document];
      index->group_read_targets[group][target / 64] |= UINT64_C(1)
                                                       << (target % 64);
    }
    uint32_t source = UINT32_MAX, target = UINT32_MAX;
    if (edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_PIPE ||
        edge->type == SHELL_EDGE_SUBST ||
        (edge->type == SHELL_EDGE_WRITE &&
         graph->nodes[edge->to].type == SHELL_NODE_ENDPOINT)) {
      source = edge->from;
      target = edge->to;
    } else if (edge->type == SHELL_EDGE_ARG ||
               (edge->type == SHELL_EDGE_GROUP &&
                graph->nodes[edge->from].type == SHELL_NODE_GROUP)) {
      source = edge->to;
      target = edge->from;
    }
    if (source != UINT32_MAX) {
      index->sensitive_next[ei] = index->sensitive_head[source];
      index->sensitive_head[source] = ei;
      index->sensitive_target[ei] = target;
    }
  }
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type != SHELL_NODE_CMD)
      continue;
    const shell_dep_cmd_t *command = &graph->nodes[node].cmd;
    if (command->pipe_stdout_source < graph->node_count &&
        command->pipe_stdout_target < graph->node_count) {
      uint32_t *head = &index->pipe_producer_head[command->pipe_stdout_source]
                                                 [command->pipe_stdout_target];
      index->pipe_producer_next[node] = *head;
      *head = node + 1;
    }
    if (command->pipe_stdin_source < graph->node_count &&
        command->pipe_stdin_target < graph->node_count) {
      uint32_t *head = &index->pipe_consumer_head[command->pipe_stdin_source]
                                                 [command->pipe_stdin_target];
      index->pipe_consumer_next[node] = *head;
      *head = node + 1;
    }
  }
  return true;
}

static bool sg_control_flow_edge(shell_dep_edge_type_t type) {
  return type == SHELL_EDGE_SEQ || type == SHELL_EDGE_AND ||
         type == SHELL_EDGE_OR || type == SHELL_EDGE_PIPE ||
         type == SHELL_EDGE_BACKGROUND || type == SHELL_EDGE_GROUP;
}

/* Build reachability once. The Shellsplit graph contract guarantees that
 * control and containment edges form a DAG. A reverse topological pass can
 * therefore propagate target bitsets without searching the control graph for
 * each write/read candidate; callers never supply constructed graphs here. */
static SHELL_NONNULL(1, 2) void sg_control_reachability_prepare(
    const shell_dep_graph_t *graph, sg_graph_index_t *index) {
  uint32_t indegree[SHELL_DEP_MAX_NODES] = {0};
  uint32_t queue[SHELL_DEP_MAX_NODES];
  uint32_t order[SHELL_DEP_MAX_NODES];
  uint32_t head = 0, tail = 0, order_count = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    index->control_reachable[node][node / 64] |= UINT64_C(1) << (node % 64);
  for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *edge = &graph->edges[ei];
    if (!sg_control_flow_edge(edge->type))
      continue;
    indegree[edge->to]++;
    index->control_reachable[edge->from][edge->to / 64] |= UINT64_C(1)
                                                           << (edge->to % 64);
  }
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (indegree[node] == 0)
      queue[tail++] = node;
  while (head < tail) {
    uint32_t node = queue[head++];
    order[order_count++] = node;
    for (uint32_t ei = index->out_head[node]; ei != UINT32_MAX;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[ei];
      if (sg_control_flow_edge(edge->type) && --indegree[edge->to] == 0)
        queue[tail++] = edge->to;
    }
  }

  for (uint32_t position = order_count; position-- > 0;) {
    uint32_t node = order[position];
    uint64_t *reachable = index->control_reachable[node];
    for (uint32_t ei = index->out_head[node]; ei != UINT32_MAX;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[ei];
      if (!sg_control_flow_edge(edge->type))
        continue;
      const uint64_t *child = index->control_reachable[edge->to];
      for (uint32_t word = 0; word < SG_NODE_WORDS; word++)
        reachable[word] |= child[word];
    }
  }
  /* Outer successors run after a compound completes. Inherit only paths
   * outside that compound: containment must not invent backward flow between
   * siblings. Both passes visit containment edges once. */
  uint64_t descendants[SHELL_DEP_MAX_NODES][SG_NODE_WORDS] = {{0}};
  for (uint32_t position = order_count; position-- > 0;) {
    uint32_t node = order[position];
    descendants[node][node / 64] |= UINT64_C(1) << (node % 64);
    for (uint32_t ei = index->out_head[node]; ei != UINT32_MAX;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[ei];
      if (edge->type != SHELL_EDGE_GROUP ||
          graph->nodes[node].type != SHELL_NODE_GROUP)
        continue;
      for (uint32_t word = 0; word < SG_NODE_WORDS; word++)
        descendants[node][word] |= descendants[edge->to][word];
    }
  }
  for (uint32_t position = 0; position < order_count; position++) {
    uint32_t node = order[position];
    if (graph->nodes[node].type != SHELL_NODE_GROUP)
      continue;
    for (uint32_t ei = index->out_head[node]; ei != UINT32_MAX;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *edge = &graph->edges[ei];
      if (edge->type != SHELL_EDGE_GROUP)
        continue;
      for (uint32_t word = 0; word < SG_NODE_WORDS; word++)
        index->control_reachable[edge->to][word] |=
            index->control_reachable[node][word] & ~descendants[node][word];
    }
  }
}

typedef struct {
  uint32_t group_parent[SHELL_DEP_MAX_NODES];
  bool timing_edge[SHELL_DEP_MAX_NODES];
  bool timing_compatible[SHELL_DEP_MAX_NODES];
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
    summary->timing_compatible[node] = true;
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
          edge->type == SHELL_EDGE_OR || edge->type == SHELL_EDGE_BACKGROUND;
      if (!allowed)
        summary->timing_compatible[endpoint] = false;
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

/* An empty Bash `time` pipeline has a zero-token CMD only so the structural
 * TIME edge has an execution endpoint. It is policy-neutral only when neither
 * that endpoint nor an enclosing command group performs I/O without a real
 * contained argv policy subject. List and containment edges otherwise merely
 * place the structural endpoint in the surrounding command. */
static SHELL_NONNULL(1, 2) bool sg_argvless_command_is_empty_timing(
    const shell_dep_graph_t *graph, const sg_policy_graph_summary_t *summary,
    uint32_t command_index) {
  if (graph->nodes[command_index].cmd.pipeline_time_mode ==
      SHELL_PIPE_TIME_NONE)
    return false;
  uint32_t group = summary->group_parent[command_index];
  return summary->timing_edge[command_index] &&
         summary->timing_compatible[command_index] &&
         (group == UINT32_MAX || !summary->unsafe_group_ancestor[group]);
}

/* Each sensitive FILE is classified once; propagate one diagnostic witness
 * through the typed data-flow index. A node is enqueued once, so aliases and
 * cycles cannot multiply work, even when several SUBST queries share it. */
static SHELL_NONNULL(1, 2) void sg_sensitive_sources_prepare(
    const shell_dep_graph_t *graph, sg_graph_index_t *index) {
  uint32_t queue[SHELL_DEP_MAX_NODES];
  uint32_t head = 0, tail = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (index->sensitive_doc[node] == node)
      queue[tail++] = node;
  while (head < tail) {
    uint32_t source = queue[head++];
    for (uint32_t ei = index->sensitive_head[source]; ei != UINT32_MAX;
         ei = index->sensitive_next[ei]) {
      SG_EDGE_WORK();
      uint32_t target = index->sensitive_target[ei];
      if (index->sensitive_doc[target] == UINT32_MAX) {
        index->sensitive_doc[target] = index->sensitive_doc[source];
        queue[tail++] = target;
      }
    }
  }
}

/* Group I/O stays attached to real GROUP nodes. Propagate result context once
 * down the containment tree; each command then reads its cached ancestry. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6, 7) void sg_group_context_prepare(
    const shell_dep_graph_t *graph, sg_graph_index_t *index,
    const sg_policy_graph_summary_t *summary, const uint32_t *violations,
    const uint32_t *writes, const uint32_t *reads, const uint32_t *expansions) {
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
      index->group_violations[child] =
          index->group_violations[parent] | violations[parent];
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
static SHELL_NONNULL(1, 2) bool sg_edge_is_file_output_effect(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge) {
  const shell_dep_node_t *from = &graph->nodes[edge->from];
  const shell_dep_node_t *to = &graph->nodes[edge->to];
  if ((from->type != SHELL_NODE_CMD && from->type != SHELL_NODE_GROUP) ||
      to->type != SHELL_NODE_DOC || to->doc.kind != SHELL_DOC_FILE)
    return false;
  if (edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND)
    return true;
  return edge->type == SHELL_EDGE_FD_OPEN &&
         edge->source_fd != SHELL_DEP_FD_NONE &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) == 0;
}

static SHELL_NONNULL(1, 2) bool sg_edge_is_output_effect(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge) {
  return (edge->type == SHELL_EDGE_WRITE &&
          graph->nodes[edge->to].type != SHELL_NODE_FD) ||
         edge->type == SHELL_EDGE_APPEND ||
         sg_edge_is_file_output_effect(graph, edge);
}

/* Resolve the execution endpoint that owns a FILE redirect setup. Unlike
 * sg_edge_is_file_output_effect(), this deliberately accepts both directions:
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

/* --- VIOLATION SCANNING ENGINE --- */

typedef struct {
  bool valid;
  bool decodes;
} sg_base64_short_options_t;

static bool sg_base64_short_option_byte(unsigned char byte, size_t position,
                                        void *context) {
  sg_base64_short_options_t *options = context;
  if (position == 0)
    options->valid = byte == '-';
  else if (byte == 'd' || byte == 'D')
    options->decodes = true;
  else if (byte != 'i')
    options->valid = false;
  return true;
}

static bool sg_base64_short_options_decode(sg_argument_t argument) {
  sg_base64_short_options_t options = {0};
  size_t decoded_length = 0;
  bool known = true;
  if (argument.decoded) {
    for (size_t i = 0; i < argument.length; i++)
      (void)sg_base64_short_option_byte((unsigned char)argument.data[i], i,
                                        &options);
    decoded_length = argument.length;
  } else {
    known = shell_visit_static_word(argument.data, argument.length,
                                    sg_base64_short_option_byte, &options,
                                    &decoded_length);
  }
  return known && decoded_length > 1 && options.valid && options.decodes;
}

/* One forward traversal of each effective argv prepares all option-dependent
 * rule facts. These are heuristics, not shell dispatch metadata. Source-only
 * words retain their established interpretation; resolved records are data.
 * Facts remain reusable when a command supplies several graph pipe routes. */
static SHELL_NONNULL(1, 2, 3, 4) void sg_argument_facts_prepare(
    const shell_dep_graph_t *graph, sg_graph_index_t *index,
    const sg_violation_config_t *cfg, const shell_expand_cache_t *cache) {
  for (uint32_t ni = 0; ni < graph->node_count; ni++) {
    index->argument_facts[ni] = 0;
    index->git_operation[ni] = 0;
    const shell_dep_node_t *node = &graph->nodes[ni];
    const char *command;
    uint32_t length, command_index;
    if (!sg_effective_command_word(node, &command, &length, &command_index))
      continue;
    bool base64 = sg_command_name_equals(command, length, "base64");
    bool openssl = sg_command_name_equals(command, length, "openssl");
    bool sudo = sg_command_name_equals(command, length, "sudo");
    bool su = sg_command_name_equals(command, length, "su");
    bool curl = sg_command_name_equals(command, length, "curl");
    bool wget = sg_command_name_equals(command, length, "wget");
    bool remote_copy = sg_command_name_equals(command, length, "scp") ||
                       sg_command_name_equals(command, length, "rsync");
    bool netcat = sg_command_name_equals(command, length, "nc") ||
                  sg_command_name_equals(command, length, "ncat") ||
                  sg_command_name_equals(command, length, "netcat");
    bool socat = sg_command_name_equals(command, length, "socat");
    bool git = sg_command_name_equals(command, length, "git");
    bool crontab = sg_command_name_equals(command, length, "crontab");
    bool upload = sg_command_name_in_after(command, length, 0, cfg->upload_cmds,
                                           cfg->upload_cmd_count);
    bool listener = sg_command_name_in_after(
        command, length, 0, cfg->listener_cmds, cfg->listener_cmd_count);
    bool decoder_end = false, has_enc = false, has_decode = false;
    bool last_remote = false, cron_list = false, has_arguments = false;
    bool su_shell_next = false;
    enum {
      SUDO_OPTIONS,
      SUDO_VALUE,
      SUDO_COMMAND,
      SUDO_DONE
    } sudo_phase = SUDO_OPTIONS;
    sg_argument_iter_t iter;
    sg_argument_iter_init(&iter, &node->cmd, cache, command_index + 1);
    sg_argument_t argument;
    while (sg_argument_iter_next(&iter, &argument)) {
      bool first = !has_arguments;
      has_arguments = true;
      uint32_t *facts = &index->argument_facts[ni];
      if (sg_argument_equals(argument, "-R"))
        *facts |= SG_VIOL_PERM_SYSTEM;
      if ((base64 || openssl) && !decoder_end) {
        if (sg_argument_equals(argument, "--"))
          decoder_end = true;
        else if (base64 && (sg_argument_equals(argument, "--decode") ||
                            sg_base64_short_options_decode(argument)))
          *facts |= SG_VIOL_SHELL_OBFUSCATION;
        else if (openssl) {
          has_enc = has_enc || sg_argument_equals(argument, "enc");
          has_decode = has_decode || sg_argument_equals(argument, "-d") ||
                       sg_argument_equals(argument, "--decode");
        }
      }
      if (sudo) {
        if (sudo_phase == SUDO_VALUE)
          sudo_phase = SUDO_OPTIONS;
        else if (sudo_phase == SUDO_COMMAND ||
                 (sudo_phase == SUDO_OPTIONS &&
                  !sg_argument_starts_dash(argument))) {
          if (sg_argument_name_in_after(argument, 0, cfg->shell_spawn_cmds,
                                        cfg->shell_spawn_cmd_count))
            *facts |= SG_VIOL_SHELL_ESCALATION;
          sudo_phase = SUDO_DONE;
        } else if (sudo_phase == SUDO_OPTIONS) {
          if (sg_argument_equals(argument, "--"))
            sudo_phase = SUDO_COMMAND;
          else {
            static const char *value_options[] = {
                "-C",      "-D",      "-g",           "-h",
                "-p",      "-R",      "-T",           "-u",
                "-U",      "--chdir", "--close-from", "--command-timeout",
                "--group", "--host",  "--other-user", "--prompt",
                "--role",  "--type",  "--user"};
            for (size_t i = 0;
                 i < sizeof(value_options) / sizeof(value_options[0]); i++)
              if (sg_argument_equals(argument, value_options[i])) {
                sudo_phase = SUDO_VALUE;
                break;
              }
          }
        }
      }
      if (su) {
        if (su_shell_next) {
          if (sg_argument_name_in_after(argument, 0, cfg->shell_spawn_cmds,
                                        cfg->shell_spawn_cmd_count))
            *facts |= SG_VIOL_SHELL_ESCALATION;
          su_shell_next = false;
        } else if (sg_argument_equals(argument, "-c") ||
                   sg_argument_equals(argument, "--command") ||
                   sg_argument_prefix(argument, "--command=", 10, true, false))
          *facts |= SG_VIOL_SHELL_ESCALATION;
        else if (sg_argument_equals(argument, "-s") ||
                 sg_argument_equals(argument, "--shell"))
          su_shell_next = true;
        else if (sg_argument_prefix(argument, "--shell=", 8, true, true)) {
          if (sg_argument_name_in_after(argument, 8, cfg->shell_spawn_cmds,
                                        cfg->shell_spawn_cmd_count))
            *facts |= SG_VIOL_SHELL_ESCALATION;
        } else if (sg_argument_prefix(argument, "-s", 2, true, true) &&
                   sg_argument_name_in_after(argument, 2, cfg->shell_spawn_cmds,
                                             cfg->shell_spawn_cmd_count))
          *facts |= SG_VIOL_SHELL_ESCALATION;
      }
      if (upload && curl &&
          (sg_argument_option(argument, "--data") ||
           sg_argument_option(argument, "--data-binary") ||
           sg_argument_option(argument, "--data-raw") ||
           sg_argument_option(argument, "--data-urlencode") ||
           sg_argument_option(argument, "--form") ||
           sg_argument_option(argument, "--upload-file") ||
           sg_argument_equals(argument, "-d") ||
           sg_argument_equals(argument, "-F") ||
           sg_argument_equals(argument, "-T") ||
           sg_argument_prefix(argument, "-d", 2, true, false) ||
           sg_argument_prefix(argument, "-F", 2, true, false) ||
           sg_argument_prefix(argument, "-T", 2, true, false)))
        *facts |= SG_VIOL_NET_UPLOAD;
      if (upload && wget &&
          (sg_argument_option(argument, "--post-file") ||
           sg_argument_option(argument, "--post-data")))
        *facts |= SG_VIOL_NET_UPLOAD;
      sg_argument_substrings_t substrings = {0};
      if ((upload && remote_copy) || (listener && socat))
        substrings = sg_argument_substrings(argument);
      if (upload && remote_copy)
        last_remote = substrings.colon;
      if (listener && ((netcat && (sg_argument_equals(argument, "-l") ||
                                   sg_argument_equals(argument, "--listen"))) ||
                       (socat && substrings.listener) || (!netcat && !socat)))
        *facts |= SG_VIOL_NET_LISTENER;
      if (git) {
        if (first) {
          if (sg_argument_equals(argument, "push"))
            index->git_operation[ni] = 1;
          else if (sg_argument_equals(argument, "clean"))
            index->git_operation[ni] = 2;
          else if (sg_argument_equals(argument, "filter-branch")) {
            index->git_operation[ni] = 3;
            *facts |= SG_VIOL_GIT_DESTRUCTIVE;
          }
        } else if ((index->git_operation[ni] == 1 &&
                    (sg_argument_equals(argument, "--force") ||
                     sg_argument_equals(argument, "-f"))) ||
                   (index->git_operation[ni] == 2 &&
                    (sg_argument_equals(argument, "-x") ||
                     sg_argument_equals(argument, "-fdx") ||
                     sg_argument_equals(argument, "-fx"))))
          *facts |= SG_VIOL_GIT_DESTRUCTIVE;
      }
      if (crontab && sg_argument_equals(argument, "-l"))
        cron_list = true;
    }
    if (openssl && has_enc && has_decode)
      index->argument_facts[ni] |= SG_VIOL_SHELL_OBFUSCATION;
    if (last_remote)
      index->argument_facts[ni] |= SG_VIOL_NET_UPLOAD;
    if (crontab && !cron_list)
      index->argument_facts[ni] |= SG_VIOL_PERSISTENCE;
  }
}

/* All arrays cover the graph's bounded node/violation counts. graph and
 * expansions retain their validated immutable evaluation metadata. */
static SHELL_NONNULL(
    1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13,
    14) void sg_violation_scan(const shell_dep_graph_t *graph,
                               sg_graph_index_t *index, const sg_gate_t *gate,
                               buf_writer_t *bw, sg_violation_t *violations,
                               uint32_t max_violations,
                               uint32_t *violation_count,
                               uint32_t *violation_type_flags,
                               uint32_t *violation_dropped,
                               uint32_t *node_viols, uint32_t *cmd_write_count,
                               uint32_t *cmd_read_count,
                               uint32_t *cmd_env_count,
                               const shell_expand_cache_t *expansions) {
  const sg_violation_config_t *cfg = &gate->viol_config;
  *violation_count = 0;
  *violation_type_flags = 0;
  *violation_dropped = 0;
  sg_sensitive_sources_prepare(graph, index);
  sg_control_reachability_prepare(graph, index);
  sg_argument_facts_prepare(graph, index, cfg, expansions);

  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *e = &graph->edges[ei];
    const shell_dep_node_t *from_node = &graph->nodes[e->from];
    const shell_dep_node_t *to_node = &graph->nodes[e->to];

    /* --- Per-node edge counters --- */
    if (from_node->type == SHELL_NODE_CMD ||
        from_node->type == SHELL_NODE_GROUP) {
      if (sg_edge_is_output_effect(graph, e))
        cmd_write_count[e->from]++;
    }
    if (to_node->type == SHELL_NODE_CMD || to_node->type == SHELL_NODE_GROUP) {
      if (e->type == SHELL_EDGE_READ && from_node->type != SHELL_NODE_FD &&
          !(from_node->type == SHELL_NODE_DOC &&
            (from_node->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)))
        cmd_read_count[e->to]++;
      if (e->type == SHELL_EDGE_ENV)
        cmd_env_count[e->to]++;
    }

    /* --- SG_VIOL_WRITE_SENSITIVE --- */
    if (sg_edge_is_file_output_effect(graph, e)) {
      uint32_t path_flags = index->file_path_flags[e->to];
      if (path_flags & SG_FILE_PATH_SENSITIVE_WRITE) {
        const char *desc = bw_printf(bw, "writes to sensitive path");
        const char *det = bw_file_detail(bw, &to_node->doc);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_WRITE_SENSITIVE,
                       SG_SEVERITY_HIGH, e->from, desc, det);
        node_viols[e->from] |= SG_VIOL_WRITE_SENSITIVE;
        *violation_type_flags |= SG_VIOL_WRITE_SENSITIVE;
      }
      /* Profile writes are an effect of redirect setup, regardless of whether
       * the command name is known, is a builtin, or is absent altogether. */
      if (path_flags & SG_FILE_PATH_PROFILE) {
        const char *desc = bw_printf(bw, "writing to shell profile/ssh config");
        const char *det = bw_file_detail(bw, &to_node->doc);
        emit_violation(violations, violation_count, max_violations,
                       violation_dropped, SG_VIOL_PERSISTENCE, SG_SEVERITY_HIGH,
                       e->from, desc, det);
        node_viols[e->from] |= SG_VIOL_PERSISTENCE;
        *violation_type_flags |= SG_VIOL_PERSISTENCE;
      }
    }

    /* --- SG_VIOL_ENV_PRIVILEGED --- */
    if (e->type == SHELL_EDGE_ENV && from_node->type == SHELL_NODE_DOC &&
        from_node->doc.kind == SHELL_DOC_ENVVAR &&
        to_node->type == SHELL_NODE_CMD && to_node->cmd.token_count > 0) {

      uint32_t idx;
      if (sg_env_name_found(&from_node->doc, cfg->sensitive_env_names,
                            cfg->sensitive_env_name_count, &idx)) {
        uint32_t env_idx = idx;
        const char *cmd0 = NULL;
        uint32_t cmd0_len = 0, command_index = 0;
        if (sg_effective_command_word(to_node, &cmd0, &cmd0_len,
                                      &command_index) &&
            sg_name_found(cmd0, cmd0_len, cfg->sensitive_cmd_names,
                          cfg->sensitive_cmd_name_count, &idx)) {
          const char *desc =
              bw_printf(bw, "sensitive env before privileged cmd");
          const char *det =
              bw_printf(bw, "%s before %.*s", cfg->sensitive_env_names[env_idx],
                        (int)cmd0_len, cmd0);
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
      uint32_t doc_idx = index->sensitive_doc[e->from];
      if (doc_idx != UINT32_MAX) {
        const shell_dep_node_t *doc = &graph->nodes[doc_idx];
        *violation_type_flags |= SG_VIOL_SUBST_SENSITIVE;
        uint32_t consumers[SHELL_DEP_MAX_NODES];
        uint32_t consumer_count =
            sg_substitution_consumers(graph, index, e->to, e->flags, consumers);
        for (uint32_t consumer_index = 0;
             consumer_index < consumer_count && !bw->overflow;
             consumer_index++) {
          const char *desc = bw_printf(bw, "subshell reads sensitive file");
          const char *det = bw_file_detail(bw, &doc->doc);
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
    const char *cmd0 = NULL;
    uint32_t cmd0_len = 0, command_index = 0;
    if (!sg_effective_command_word(node, &cmd0, &cmd0_len, &command_index))
      continue;
    if (!sg_command_name_equals(cmd0, cmd0_len, "rm") &&
        !sg_command_name_equals(cmd0, cmd0_len, "rmdir"))
      continue;
    for (uint32_t ei = index->out_head[ni]; ei != UINT32_MAX && !bw->overflow;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      if (index->file_path_flags[e->to] & SG_FILE_PATH_SENSITIVE_DIR) {
        const char *desc = bw_printf(bw, "removal of system directory");
        const char *det = bw_file_detail(bw, &doc->doc);
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
    SG_EDGE_WORK();
    const shell_dep_edge_t *e1 = &graph->edges[ei];
    if (!sg_edge_is_file_output_effect(graph, e1))
      continue;
    const shell_dep_node_t *f1 = &graph->nodes[e1->to];
    if (f1->type != SHELL_NODE_DOC || f1->doc.kind != SHELL_DOC_FILE)
      continue;
    uint32_t write_doc = e1->to;
    uint32_t group = index->file_identity_group[write_doc];
    if (group == UINT32_MAX)
      continue;
    const uint64_t *reachable = index->control_reachable[e1->from];
    const uint64_t *read_targets = index->group_read_targets[group];
    uint32_t read_cmd = UINT32_MAX;
    for (uint32_t word = 0; word < SG_NODE_WORDS; word++) {
      SG_EDGE_WORK();
      uint64_t candidates = reachable[word] & read_targets[word];
      if (candidates == 0)
        continue;
      uint32_t bit = 0;
      while ((candidates & UINT64_C(1)) == 0) {
        candidates >>= 1;
        bit++;
      }
      read_cmd = word * 64 + bit;
      break;
    }
    if (read_cmd == UINT32_MAX)
      continue;

    const char *desc = bw_printf(bw, "write then read of matching path");
    const char *det = bw_file_detail(bw, &f1->doc);
    emit_violation(violations, violation_count, max_violations,
                   violation_dropped, SG_VIOL_WRITE_THEN_READ,
                   SG_SEVERITY_MEDIUM, read_cmd, desc, det);
    node_viols[read_cmd] |= SG_VIOL_WRITE_THEN_READ;
    *violation_type_flags |= SG_VIOL_WRITE_THEN_READ;
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

  /* Effective pipe routes include commands inside groups and exclude streams
   * replaced by redirects. Both data-to-executor rules must use them. */
  for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
    SG_EDGE_WORK();
    const shell_dep_edge_t *e = &graph->edges[ei];
    if (e->type != SHELL_EDGE_PIPE)
      continue;
    for (uint32_t encoded = index->pipe_producer_head[e->from][e->to];
         encoded != 0; encoded = index->pipe_producer_next[encoded - 1]) {
      uint32_t producer = encoded - 1;
      const shell_dep_node_t *src = &graph->nodes[producer];
      const char *source_word = NULL;
      uint32_t source_length = 0, source_index = 0;
      if (!sg_effective_command_word(src, &source_word, &source_length,
                                     &source_index) ||
          src->cmd.pipe_stdout_source != e->from ||
          src->cmd.pipe_stdout_target != e->to)
        continue;
      uint32_t idx;
      bool is_download =
          sg_name_found(source_word, source_length, cfg->download_cmds,
                        cfg->download_cmd_count, &idx);
      bool is_decoder =
          (index->argument_facts[producer] & SG_VIOL_SHELL_OBFUSCATION) != 0;
      if (!is_download && !is_decoder)
        continue;
      for (uint32_t encoded = index->pipe_consumer_head[e->from][e->to];
           encoded != 0; encoded = index->pipe_consumer_next[encoded - 1]) {
        uint32_t consumer = encoded - 1;
        const shell_dep_node_t *dst = &graph->nodes[consumer];
        const char *target_word = NULL;
        uint32_t target_length = 0, target_index = 0;
        if (!sg_effective_command_word(dst, &target_word, &target_length,
                                       &target_index) ||
            dst->cmd.pipe_stdin_source != e->from ||
            dst->cmd.pipe_stdin_target != e->to ||
            !sg_name_found(target_word, target_length, cfg->shell_spawn_cmds,
                           cfg->shell_spawn_cmd_count, &idx))
          continue;
        if (is_download &&
            (node_viols[consumer] & SG_VIOL_NET_DOWNLOAD_EXEC) == 0) {
          const char *desc =
              bw_printf(bw, "download piped into shell executor");
          const char *det =
              bw_printf(bw, "%.*s | %.*s", (int)source_length, source_word,
                        (int)target_length, target_word);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_NET_DOWNLOAD_EXEC,
                         SG_SEVERITY_CRITICAL, consumer, desc, det);
          node_viols[consumer] |= SG_VIOL_NET_DOWNLOAD_EXEC;
          *violation_type_flags |= SG_VIOL_NET_DOWNLOAD_EXEC;
        }
        if (is_decoder &&
            (node_viols[consumer] & SG_VIOL_SHELL_OBFUSCATION) == 0 &&
            !bw->overflow) {
          const char *desc = bw_printf(bw, "decoded payload piped to shell");
          const char *det =
              bw_printf(bw, "%.*s | %.*s", (int)source_length, source_word,
                        (int)target_length, target_word);
          emit_violation(violations, violation_count, max_violations,
                         violation_dropped, SG_VIOL_SHELL_OBFUSCATION,
                         SG_SEVERITY_CRITICAL, consumer, desc, det);
          node_viols[consumer] |= SG_VIOL_SHELL_OBFUSCATION;
          *violation_type_flags |= SG_VIOL_SHELL_OBFUSCATION;
        }
      }
    }
  }

  /* --- SG_VIOL_PERM_SYSTEM --- */
  for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
    const shell_dep_node_t *node = &graph->nodes[ni];
    const char *cmd0 = NULL;
    uint32_t cmd0_len = 0, command_index = 0;
    if (!sg_effective_command_word(node, &cmd0, &cmd0_len, &command_index))
      continue;

    uint32_t idx;
    if (!sg_name_found(cmd0, cmd0_len, cfg->perm_mod_cmds,
                       cfg->perm_mod_cmd_count, &idx))
      continue;

    if ((index->argument_facts[ni] & SG_VIOL_PERM_SYSTEM) == 0)
      continue;

    for (uint32_t ei = index->out_head[ni]; ei != UINT32_MAX && !bw->overflow;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      if (index->file_path_flags[e->to] & SG_FILE_PATH_SENSITIVE_DIR) {
        const char *desc =
            bw_printf(bw, "recursive permission change on system dir");
        const char *det = bw_file_detail(bw, &doc->doc);
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
    const char *cmd0 = NULL;
    uint32_t cmd0_len = 0, command_index = 0;
    if (!sg_effective_command_word(node, &cmd0, &cmd0_len, &command_index) ||
        node->cmd.token_count <= command_index + 1)
      continue;

    if (!sg_command_name_equals(cmd0, cmd0_len, "sudo") &&
        !sg_command_name_equals(cmd0, cmd0_len, "su"))
      continue;

    if ((index->argument_facts[ni] & SG_VIOL_SHELL_ESCALATION) == 0)
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
    const char *cmd0 = NULL;
    uint32_t cmd0_len = 0, command_index = 0;
    if (!sg_effective_command_word(node, &cmd0, &cmd0_len, &command_index))
      continue;

    if (!sg_command_name_equals(cmd0, cmd0_len, "sudo") &&
        !sg_command_name_equals(cmd0, cmd0_len, "su"))
      continue;

    bool has_redirect = false;
    const shell_dep_doc_t *target_file = NULL;
    for (uint32_t ei = index->out_head[ni]; ei != UINT32_MAX && !bw->overflow;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (!sg_edge_is_output_effect(graph, e))
        continue;
      has_redirect = true;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type == SHELL_NODE_DOC && doc->doc.kind == SHELL_DOC_FILE) {
        target_file = &doc->doc;
      }
      break;
    }
    if (!has_redirect)
      continue;

    const char *desc = bw_printf(bw, "sudo with redirect");
    const char *det = target_file ? bw_file_detail(bw, target_file)
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
    const char *cmd0 = NULL;
    uint32_t cmd0_len = 0, command_index = 0;
    if (!sg_effective_command_word(node, &cmd0, &cmd0_len, &command_index))
      continue;

    bool is_reader = false;
    for (uint32_t c = 0; c < cfg->file_reading_cmd_count; c++) {
      if (sg_command_name_equals(cmd0, cmd0_len, cfg->file_reading_cmds[c])) {
        is_reader = true;
        break;
      }
    }
    if (!is_reader)
      continue;

    for (uint32_t ei = index->out_head[ni]; ei != UINT32_MAX && !bw->overflow;
         ei = index->out_next[ei]) {
      SG_EDGE_WORK();
      const shell_dep_edge_t *e = &graph->edges[ei];
      if (e->type != SHELL_EDGE_ARG)
        continue;
      const shell_dep_node_t *doc = &graph->nodes[e->to];
      if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE)
        continue;
      if (!(index->file_path_flags[e->to] & SG_FILE_PATH_SECRET))
        continue;
      const char *desc = bw_printf(bw, "reading secret file");
      const char *det = bw_file_detail(bw, &doc->doc);
      emit_violation(violations, violation_count, max_violations,
                     violation_dropped, SG_VIOL_READ_SECRETS,
                     SG_SEVERITY_MEDIUM, ni, desc, det);
      node_viols[ni] |= SG_VIOL_READ_SECRETS;
      *violation_type_flags |= SG_VIOL_READ_SECRETS;
    }
  }

  /* Argument-dependent rules consume the facts from the single argv pass. */
  static const struct {
    uint32_t type, severity;
    const char *description;
  } argument_rules[] = {
      {SG_VIOL_NET_UPLOAD, SG_SEVERITY_HIGH, "network file upload"},
      {SG_VIOL_NET_LISTENER, SG_SEVERITY_HIGH, "starting network listener"},
      {SG_VIOL_GIT_DESTRUCTIVE, SG_SEVERITY_MEDIUM,
       "destructive git operation"},
      {SG_VIOL_PERSISTENCE, SG_SEVERITY_MEDIUM, "crontab modification"},
  };
  static const char *git_operations[] = {"", "push", "clean", "filter-branch"};
  for (size_t rule = 0;
       rule < sizeof(argument_rules) / sizeof(argument_rules[0]); rule++) {
    uint32_t type = argument_rules[rule].type;
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
      if ((index->argument_facts[ni] & type) == 0)
        continue;
      const shell_dep_cmd_t *command = &graph->nodes[ni].cmd;
      uint32_t token = command->effective_command_token;
      const char *desc = bw_copy(bw, argument_rules[rule].description,
                                 strlen(argument_rules[rule].description));
      const char *detail;
      if (type == SG_VIOL_GIT_DESTRUCTIVE)
        detail =
            bw_printf(bw, "git %s", git_operations[index->git_operation[ni]]);
      else if (type == SG_VIOL_PERSISTENCE)
        detail = bw_copy(bw, "crontab", 7);
      else
        detail = bw_printf(bw, "%.*s", (int)command->token_lens[token],
                           command->tokens[token]);
      emit_violation(violations, violation_count, max_violations,
                     violation_dropped, type, argument_rules[rule].severity, ni,
                     desc, detail);
      node_viols[ni] |= type;
      *violation_type_flags |= type;
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
      bool shell_word = (index->group_substitution[node] & 2) != 0;
      if (shell_word) {
        result->requires_substitution_evaluation = true;
      }
      if (shell_word && result->verdict == SG_VERDICT_ALLOW)
        result->verdict = SG_VERDICT_ALLOW_CONDITIONAL;
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
 * an otherwise accepted representation. */
static SHELL_NONNULL(1) sg_error_t
    sg_fail_undetermined(sg_result_t *out, sg_error_t error) {
  out->verdict = SG_VERDICT_UNDETERMINED;
  return error;
}

sg_error_t sg_gate_evaluate(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                            char *buf, size_t buf_size, sg_result_t *out) {
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
                        .strict_mode = gate->strict_mode,
                        .workspace = buf,
                        .workspace_size = buf_size};
  shell_error_t ferr = shell_parse_fast(cmd, cmd_len, &lim, &fast);
  bool parse_truncated = ferr == SHELL_ETRUNC;
  /* A successful zero-range parse already establishes semantic trivia.
   * Do not override a parse error with a second, broader C-whitespace scan. */
  if (ferr == SHELL_OK && fast.count == 0) {
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
  dep_limits.workspace = dep_workspace;
  dep_limits.workspace_size = dep_workspace_size;
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
    out->deny_reason =
        bw_copy(&bw,
                derr == SHELL_DEP_EWORKSPACE ? "depgraph workspace unavailable"
                : parse_error                ? "parse error"
                                             : "depgraph error",
                derr == SHELL_DEP_EWORKSPACE ? 30
                : parse_error                ? 11
                                             : 14);
    if (derr != SHELL_DEP_EWORKSPACE)
      sg_init_rejected_subcommand(out, out->deny_reason);
    if (bw.overflow) {
      out->truncated = true;
      out->verdict = SG_VERDICT_UNDETERMINED;
      return SG_ERR_TRUNC;
    }
    return derr == SHELL_DEP_EWORKSPACE ? SG_ERR_MEMORY : SG_ERR_PARSE;
  }

  /* This is graph-level information, not a property of whichever command
   * results fit in the caller's display buffer. Preserve it before any later
   * diagnostic rendering can return SG_ERR_TRUNC. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++)
    if (sg_edge_is_dynamic_substitution_route(&graph, &graph.edges[ei])) {
      out->has_dynamic_substitution_io = true;
      if (graph.edges[ei].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD)
        out->requires_substitution_evaluation = true;
    }

  /* The bounded resolver workspace is no longer live. Reuse its aligned
   * prefix for graph indexes and its remainder for path decoding scratch. */
  sg_graph_index_t *graph_index = dep_workspace;
  sg_graph_index_build(&graph, graph_index);

  /* Step 3.5: Violation scan on the depgraph */
  uint32_t node_viols[SHELL_DEP_MAX_NODES];
  uint32_t cmd_write_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_read_count[SHELL_DEP_MAX_NODES];
  uint32_t cmd_env_count[SHELL_DEP_MAX_NODES];
  uint32_t node_expansion_flags[SHELL_DEP_MAX_NODES];
  memset(node_viols, 0, sizeof(node_viols));
  memset(cmd_write_count, 0, sizeof(cmd_write_count));
  memset(cmd_read_count, 0, sizeof(cmd_read_count));
  memset(cmd_env_count, 0, sizeof(cmd_env_count));
  out->unresolved_expansion_flags = sg_expansion_flags_prepare(
      &graph, &expansion_cache, node_expansion_flags);

  if (gate->viol_enabled) {
    char *path_scratch, *identity_pool;
    size_t scratch_capacity, pool_capacity;
    if (!sg_path_workspace_prepare(
            &graph, cmd_len, (char *)dep_workspace + sizeof(*graph_index),
            dep_workspace_size - sizeof(*graph_index), &bw, &path_scratch,
            &scratch_capacity, &identity_pool, &pool_capacity) ||
        !sg_graph_violation_index_build(&graph, graph_index, gate, path_scratch,
                                        identity_pool, scratch_capacity,
                                        pool_capacity)) {
      out->verdict = SG_VERDICT_UNDETERMINED;
      out->deny_reason = bw_copy(&bw, "path index workspace unavailable", 32);
      if (bw.overflow)
        out->truncated = true;
      return SG_ERR_MEMORY;
    }
    sg_violation_scan(&graph, graph_index, gate, &bw, out->violations,
                      SG_MAX_VIOLATIONS, &out->violation_count,
                      &out->violation_type_flags, &out->violation_dropped_count,
                      node_viols, cmd_write_count, cmd_read_count,
                      cmd_env_count, &expansion_cache);
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

  /* Policy evaluation is graph-based. Anomaly sequences are built separately:
   * they include nested executable substitutions in deterministic analysis
   * order, whereas graph CMD nodes preserve dependency topology. */
  sg_policy_graph_summary_t policy_graph = {0};
  sg_policy_graph_summarize(&graph, &policy_graph);
  sg_group_context_prepare(&graph, graph_index, &policy_graph, node_viols,
                           cmd_write_count, cmd_read_count,
                           node_expansion_flags);
  size_t cmd_count = 0;
  bool has_unpolicyable_io_only_command = false;
  for (uint32_t ni = 0; ni < graph.node_count; ni++) {
    const shell_dep_node_t *node = &graph.nodes[ni];
    if (node->type != SHELL_NODE_CMD)
      continue;
    if (node->cmd.token_count > 0) {
      cmd_count++;
    } else if (!sg_argvless_command_is_empty_timing(&graph, &policy_graph,
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

  /* Only a complete graph establishes contextual semantic support. A bounded
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
    /* Graph/path preparation is finished. Its temporary tail now supplies
     * delimiter scratch; the graph index and expansion cache stay live. */
    shell_limits_t stage_limits = SHELL_LIMITS_DEFAULT;
    stage_limits.workspace = (char *)dep_workspace + sizeof(*graph_index);
    stage_limits.workspace_size = dep_workspace_size - sizeof(*graph_index);
    /* Keep lexical facts and delimiter scratch alive through both collection
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
    sr->violation_type_flags = node_viols[ni];
    sr->violation_type_flags |= graph_index->group_violations[ni];
    sr->write_count += graph_index->group_writes[ni];
    sr->read_count += graph_index->group_reads[ni];
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
            out->suggestions[0] = bw_copy_policy_cpl(
                &bw, (st_netpattern_view_t){
                         .data = eval.suggestions[0].pattern,
                         .length = eval.suggestions[0].pattern_length});
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
            out->suggestions[1] = bw_copy_policy_cpl(
                &bw, (st_netpattern_view_t){
                         .data = eval.suggestions[1].pattern,
                         .length = eval.suggestions[1].pattern_length});
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
            out->deny_suggestions[0] = bw_copy_policy_cpl(
                &bw, (st_netpattern_view_t){
                         .data = deny_eval.suggestions[0].pattern,
                         .length = deny_eval.suggestions[0].pattern_length});
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
            out->deny_suggestions[1] = bw_copy_policy_cpl(
                &bw, (st_netpattern_view_t){
                         .data = deny_eval.suggestions[1].pattern,
                         .length = deny_eval.suggestions[1].pattern_length});
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

  /* Dynamic substitution routes carry topology into an execution endpoint,
   * directly or through an expandable heredoc document. A named-FD input
   * process substitution remains a setup-only FD_OPEN route until a later
   * exact descriptor use. Resolve owners after all command nodes have been
   * visited. A group-owned stream is marked on every contained simple command
   * because any can consume its inherited descriptor. Only a flagged
   * shell-word edge requests another Shellgate inspection or changes an ALLOW
   * verdict to conditional. */
  for (uint32_t ei = 0; ei < graph.edge_count; ei++) {
    const shell_dep_edge_t *edge = &graph.edges[ei];
    if (!sg_edge_is_dynamic_substitution_route(&graph, edge))
      continue;
    bool shell_word = (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0;
    out->has_dynamic_substitution_io = true;
    if (shell_word)
      out->requires_substitution_evaluation = true;
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
        out->subcommands[result_index].requires_substitution_evaluation = true;
      if (shell_word &&
          out->subcommands[result_index].verdict == SG_VERDICT_ALLOW)
        out->subcommands[result_index].verdict = SG_VERDICT_ALLOW_CONDITIONAL;
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
  else if (has_unpolicyable_io_only_command) {
    /* An argv-less redirect is not policy-evaluable, but it must not mask a
     * definite DENY or REJECT from another simple command in the same list. */
    out->verdict = SG_VERDICT_UNDETERMINED;
    if (!out->deny_reason)
      out->deny_reason = bw_copy(
          &bw, "redirect-only shell operation is not argv-policy-evaluable",
          58);
  } else if (all_allow)
    out->verdict = (out->requires_substitution_evaluation || any_conditional)
                       ? SG_VERDICT_ALLOW_CONDITIONAL
                       : SG_VERDICT_ALLOW;
  else
    out->verdict = SG_VERDICT_UNDETERMINED;

  /* Rendering is part of evaluation success. A caller that receives a
   * truncated result will normally retry with a larger buffer, so no learning
   * or calibration state may change until every diagnostic has fit. */
  if (bw.overflow) {
    out->truncated = true;
    out->verdict = SG_VERDICT_UNDETERMINED;
    free(owned_cmd_seq);
    free(owned_type_seq);
    return SG_ERR_TRUNC;
  }

  /* Deferred anomaly model update — after a complete verdict is known. */
  if (gate->anomaly_enabled && gate->anomaly_model && anomaly_count > 0) {
    bool should_update = false;
    if (!gate->anomaly_update_only_on_allow) {
      /* Always update, but skip if anomalous and flag is set */
      should_update = !out->anomaly_detected || !gate->anomaly_skip_on_detected;
      if (!should_update)
        out->anomaly_update = SG_ANOMALY_UPDATE_SKIPPED_DETECTED;
    } else if (out->verdict == SG_VERDICT_ALLOW) {
      /* Only update on ALLOW verdict */
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
  case SG_VERDICT_ALLOW_CONDITIONAL:
    return "ALLOW_CONDITIONAL";
  }
  return "UNKNOWN";
}
