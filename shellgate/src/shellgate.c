/*
 * shellgate.c - Shell command policy gate
 *
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 */

#include "shellgate.h"
#include "sg_anomaly.h"
#include "shell_tokenizer.h"
#include "shell_depgraph.h"
#include "shell_abstract.h"
#include "shelltype.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

/* ============================================================
 * PORTABLE strlcpy
 * ============================================================ */

static size_t sg_strlcpy(char *dst, const char *src, size_t size)
{
    size_t slen = strlen(src);
    if (size > 0) {
        size_t copy = slen < size - 1 ? slen : size - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return slen;
}

/* ============================================================
 * OUTPUT BUFFER WRITER
 * ============================================================ */

typedef struct {
    char    *base;
    size_t   size;
    size_t   used;
    bool     overflow;
} buf_writer_t;

static void bw_init(buf_writer_t *w, char *buf, size_t buf_size)
{
    w->base     = buf;
    w->size     = buf_size;
    w->used     = 0;
    w->overflow = false;
}

static const char *bw_copy(buf_writer_t *w, const char *src, size_t src_len)
{
    if (w->used >= w->size) {
        w->overflow = true;
        return NULL;
    }
    size_t avail = w->size - w->used;
    size_t copy  = src_len < avail ? src_len : avail - 1;
    if (copy == 0 && avail <= 1) {
        w->overflow = true;
        return NULL;
    }
    char *dst = w->base + w->used;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
    const char *result = dst;
    w->used += copy + 1;
    if (src_len > copy) w->overflow = true;
    return result;
}

static const char *bw_printf(buf_writer_t *w, const char *fmt, ...)
{
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
        if (w->size > 0) w->base[w->size - 1] = '\0';
    } else {
        w->used += (size_t)n + 1;
    }
    return result;
}

/* ============================================================
 * TYPE SEQUENCE LRU CACHE
 *
 * Simple array-based LRU: MRU at end, LRU at front.
 * On insert, move to end. On eviction, remove front.
 * Linear scan for lookup (O(n), n ≤ 8192, acceptable).
 * ============================================================ */

typedef struct {
    char  *key;     /* command string (owned) */
    char  *value;   /* type sequence string (owned) */
    size_t key_len;
} lru_entry_t;

typedef struct {
    lru_entry_t *entries;
    size_t       capacity;   /* max entries */
    size_t       count;      /* current entries */
} type_cache_t;

static void type_cache_clear(type_cache_t *c)
{
    if (!c->entries) return;
    for (size_t i = 0; i < c->count; i++) {
        free(c->entries[i].key);
        free(c->entries[i].value);
    }
    c->count = 0;
}

static void type_cache_free(type_cache_t *c)
{
    type_cache_clear(c);
    free(c->entries);
    c->entries  = NULL;
    c->capacity = 0;
}

/* Lookup by key. Returns pointer to cached value string, or NULL.
 * On hit, moves entry to MRU position (end of array). */
static char *type_cache_lookup(type_cache_t *c, const char *key, size_t key_len)
{
    if (!c->entries || c->count == 0) return NULL;
    for (size_t i = 0; i < c->count; i++) {
        if (c->entries[i].key_len == key_len &&
            memcmp(c->entries[i].key, key, key_len) == 0) {
            /* Hit: move to end (MRU) by swapping with last element */
            if (i < c->count - 1) {
                lru_entry_t tmp = c->entries[i];
                c->entries[i] = c->entries[c->count - 1];
                c->entries[c->count - 1] = tmp;
            }
            return c->entries[c->count - 1].value;
        }
    }
    return NULL;
}

/* Insert or update. Evicts LRU (front) if full.
 * Takes ownership of value on success; caller must NOT free it.
 * Returns true on success, false on allocation failure. */
static bool type_cache_insert(type_cache_t *c, const char *key, size_t key_len,
                               char *value)
{
    if (c->capacity == 0) return false;

    /* Check if key already exists (update) */
    for (size_t i = 0; i < c->count; i++) {
        if (c->entries[i].key_len == key_len &&
            memcmp(c->entries[i].key, key, key_len) == 0) {
            free(c->entries[i].value);
            c->entries[i].value = value;
            /* Move to end (MRU) */
            if (i < c->count - 1) {
                lru_entry_t tmp = c->entries[i];
                c->entries[i] = c->entries[c->count - 1];
                c->entries[c->count - 1] = tmp;
            }
            return true;
        }
    }

    /* Evict LRU (index 0) if full */
    if (c->count >= c->capacity) {
        free(c->entries[0].key);
        free(c->entries[0].value);
        /* Shift remaining entries left */
        memmove(&c->entries[0], &c->entries[1], (c->count - 1) * sizeof(lru_entry_t));
        c->count--;
    }

    /* Insert at end */
    char *key_copy = malloc(key_len + 1);
    if (!key_copy) return false;
    memcpy(key_copy, key, key_len);
    key_copy[key_len] = '\0';

    c->entries[c->count].key     = key_copy;
    c->entries[c->count].key_len = key_len;
    c->entries[c->count].value   = value;
    c->count++;
    return true;
}

/* ============================================================
 * GATE STATE
 * ============================================================ */

struct sg_gate {
    st_policy_ctx_t *pctx;
    st_policy_t     *policy;
    st_policy_t     *deny_policy;

    char     cwd[512];
    uint32_t reject_mask;
    sg_stop_mode_t stop_mode;
    bool     suggestions;
    bool     strict_mode;

    sg_expand_var_fn  expand_var_fn;
    void             *expand_var_ctx;
    sg_expand_glob_fn expand_glob_fn;
    void             *expand_glob_ctx;

    bool                  viol_enabled;
    sg_violation_config_t viol_config;

    /* Anomaly detection */
    sg_anomaly_model_t *anomaly_model;       /* raw command name model */
    sg_anomaly_model_t *anomaly_model_type;  /* type sequence model (NULL if disabled) */
    bool                anomaly_enabled;
    double              anomaly_threshold;
    bool                anomaly_update_only_on_allow;
    bool                anomaly_update_on_non_anomaly;  /* don't learn from anomalous commands */
    double              anomaly_weight_raw;             /* weight for raw score (default 0.5) */
    double              anomaly_weight_type;            /* weight for type score (default 0.5) */

    /* Adaptive threshold */
    bool                anomaly_adaptive;       /* use adaptive threshold (default false) */
    size_t              anomaly_window_size;    /* rolling window capacity (default 1000) */
    double              anomaly_k_factor;       /* stddev multiplier (default 3.0) */
    double             *anomaly_score_buf;      /* circular buffer of normal scores */
    size_t              anomaly_score_count;    /* entries currently in buffer */
    size_t              anomaly_score_idx;      /* next write position (circular) */
    bool                anomaly_adaptive_armed; /* window is full, threshold is computed */
    double              anomaly_fixed_threshold;/* saved fixed threshold for fallback */

    /* Type sequence LRU cache */
    type_cache_t        anomaly_type_cache;   /* LRU cache for type sequences */
};

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

sg_gate_t *sg_gate_new(void)
{
    sg_gate_t *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->pctx = st_policy_ctx_new();
    if (!g->pctx) { free(g); return NULL; }

    g->policy = st_policy_new(g->pctx);
    if (!g->policy) { st_policy_ctx_free(g->pctx); free(g); return NULL; }

    g->deny_policy = st_policy_new(g->pctx);
    if (!g->deny_policy) { st_policy_free(g->policy); st_policy_ctx_free(g->pctx); free(g); return NULL; }

    sg_strlcpy(g->cwd, ".", sizeof(g->cwd));
    g->reject_mask = SG_REJECT_MASK_DEFAULT;
    g->stop_mode = SG_STOP_FIRST_FAIL;
    g->suggestions = true;
    g->strict_mode = true;

    /* Anomaly detection defaults */
    g->anomaly_update_only_on_allow = false;
    g->anomaly_update_on_non_anomaly = true;
    g->anomaly_weight_raw = 0.5;
    g->anomaly_weight_type = 0.5;

    return g;
}

void sg_gate_free(sg_gate_t *gate)
{
    if (!gate) return;
    if (gate->anomaly_model) sg_anomaly_model_free(gate->anomaly_model);
    if (gate->anomaly_model_type) sg_anomaly_model_free(gate->anomaly_model_type);
    free(gate->anomaly_score_buf);
    type_cache_free(&gate->anomaly_type_cache);
    if (gate->policy)       st_policy_free(gate->policy);
    if (gate->deny_policy)  st_policy_free(gate->deny_policy);
    if (gate->pctx)         st_policy_ctx_free(gate->pctx);
    free(gate);
}

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd)
{
    if (!gate || !cwd) return SG_ERR_INVALID;
    sg_strlcpy(gate->cwd, cwd, sizeof(gate->cwd));
    return SG_OK;
}

sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask)
{
    if (!gate) return SG_ERR_INVALID;
    gate->reject_mask = mask;
    return SG_OK;
}

sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode)
{
    if (!gate) return SG_ERR_INVALID;
    gate->stop_mode = mode;
    return SG_OK;
}

sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled)
{
    if (!gate) return SG_ERR_INVALID;
    gate->suggestions = enabled;
    return SG_OK;
}

sg_error_t sg_gate_set_expand_var(sg_gate_t *gate,
                                   sg_expand_var_fn fn, void *user_ctx)
{
    if (!gate) return SG_ERR_INVALID;
    gate->expand_var_fn  = fn;
    gate->expand_var_ctx = user_ctx;
    return SG_OK;
}

sg_error_t sg_gate_set_expand_glob(sg_gate_t *gate,
                                    sg_expand_glob_fn fn, void *user_ctx)
{
    if (!gate) return SG_ERR_INVALID;
    gate->expand_glob_fn  = fn;
    gate->expand_glob_ctx = user_ctx;
    return SG_OK;
}

sg_error_t sg_gate_set_violation_config(sg_gate_t *gate,
                                          const sg_violation_config_t *config)
{
    if (!gate || !config) return SG_ERR_INVALID;
    gate->viol_enabled = true;
    gate->viol_config = *config;
    return SG_OK;
}

/* ============================================================
 * ANOMALY DETECTION CONFIGURATION
 * ============================================================ */

sg_error_t sg_gate_enable_anomaly(sg_gate_t *gate,
                                    double threshold,
                                    double alpha,
                                    double unk_prior)
{
    if (!gate) return SG_ERR_INVALID;
    if (gate->anomaly_model)
        sg_anomaly_model_free(gate->anomaly_model);
    if (gate->anomaly_model_type)
        sg_anomaly_model_free(gate->anomaly_model_type);
    gate->anomaly_model = sg_anomaly_model_new_ex(alpha, unk_prior);
    if (!gate->anomaly_model) return SG_ERR_MEMORY;
    gate->anomaly_model_type = sg_anomaly_model_new_ex(alpha, unk_prior);
    if (!gate->anomaly_model_type) {
        sg_anomaly_model_free(gate->anomaly_model);
        gate->anomaly_model = NULL;
        return SG_ERR_MEMORY;
    }
    gate->anomaly_enabled = true;
    gate->anomaly_threshold = threshold;
    gate->anomaly_update_only_on_allow = false;
    gate->anomaly_update_on_non_anomaly = true;
    gate->anomaly_weight_raw = 0.5;
    gate->anomaly_weight_type = 0.5;
    gate->anomaly_fixed_threshold = threshold;
    /* Reset adaptive state (preserve adaptive flag and k_factor across re-enable) */
    gate->anomaly_score_count = 0;
    gate->anomaly_score_idx = 0;
    gate->anomaly_adaptive_armed = false;
    if (gate->anomaly_adaptive && !gate->anomaly_score_buf) {
        gate->anomaly_window_size = 1000;
        gate->anomaly_k_factor = 3.0;
        gate->anomaly_score_buf = calloc(1000, sizeof(double));
        if (!gate->anomaly_score_buf) return SG_ERR_MEMORY;
    }
    return SG_OK;
}

void sg_gate_disable_anomaly(sg_gate_t *gate)
{
    if (!gate) return;
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
}

sg_error_t sg_gate_set_anomaly_update_mode(sg_gate_t *gate,
                                             bool update_only_on_allow)
{
    if (!gate) return SG_ERR_INVALID;
    gate->anomaly_update_only_on_allow = update_only_on_allow;
    return SG_OK;
}

sg_error_t sg_gate_set_anomaly_update_on_non_anomaly(sg_gate_t *gate,
                                                      bool skip_on_anomaly)
{
    if (!gate) return SG_ERR_INVALID;
    gate->anomaly_update_on_non_anomaly = skip_on_anomaly;
    return SG_OK;
}

sg_error_t sg_gate_set_anomaly_weights(sg_gate_t *gate,
                                         double weight_raw,
                                         double weight_type)
{
    if (!gate) return SG_ERR_INVALID;
    if (weight_raw < 0.0 || weight_type < 0.0) return SG_ERR_INVALID;
    /* Weights must sum to approximately 1.0 */
    double sum = weight_raw + weight_type;
    if (sum < 0.99 || sum > 1.01) return SG_ERR_INVALID;
    gate->anomaly_weight_raw = weight_raw;
    gate->anomaly_weight_type = weight_type;
    return SG_OK;
}

/* ============================================================
 * ADAPTIVE THRESHOLD
 *
 * Maintains a circular buffer of scores from non-anomalous commands.
 * Threshold is computed as mean + k * stddev of the window.
 * Falls back to the fixed threshold until the window is full.
 * ============================================================ */

static void adaptive_recompute_threshold(sg_gate_t *gate)
{
    if (!gate->anomaly_score_buf || gate->anomaly_score_count == 0) return;

    /* Compute mean */
    double sum = 0.0;
    size_t n = gate->anomaly_score_count < gate->anomaly_window_size
               ? gate->anomaly_score_count : gate->anomaly_window_size;
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

static void adaptive_record_score(sg_gate_t *gate, double score)
{
    if (!gate->anomaly_score_buf) return;
    if (!isfinite(score)) return;

    gate->anomaly_score_buf[gate->anomaly_score_idx] = score;
    gate->anomaly_score_idx = (gate->anomaly_score_idx + 1) % gate->anomaly_window_size;
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

sg_error_t sg_gate_set_anomaly_adaptive(sg_gate_t *gate,
                                         bool adaptive, size_t window_size)
{
    if (!gate) return SG_ERR_INVALID;
    if (adaptive && window_size == 0) return SG_ERR_INVALID;

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

    /* Allocate new buffer */
    double *new_buf = calloc(window_size, sizeof(double));
    if (!new_buf) return SG_ERR_MEMORY;

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

sg_error_t sg_gate_set_anomaly_k_factor(sg_gate_t *gate, double k)
{
    if (!gate) return SG_ERR_INVALID;
    if (k < 0.0) return SG_ERR_INVALID;
    gate->anomaly_k_factor = k;
    /* Recompute threshold if already armed */
    if (gate->anomaly_adaptive_armed)
        adaptive_recompute_threshold(gate);
    return SG_OK;
}

sg_error_t sg_gate_set_anomaly_cache_size(sg_gate_t *gate, size_t cache_size)
{
    if (!gate) return SG_ERR_INVALID;
    if (cache_size > 8192) return SG_ERR_INVALID;

    if (cache_size == 0) {
        type_cache_free(&gate->anomaly_type_cache);
        return SG_OK;
    }

    /* Allocate new entries array */
    lru_entry_t *new_entries = calloc(cache_size, sizeof(lru_entry_t));
    if (!new_entries) return SG_ERR_MEMORY;

    /* Free old cache */
    type_cache_free(&gate->anomaly_type_cache);

    gate->anomaly_type_cache.entries  = new_entries;
    gate->anomaly_type_cache.capacity = cache_size;
    gate->anomaly_type_cache.count    = 0;
    return SG_OK;
}

sg_error_t sg_gate_save_anomaly_model(const sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    if (!gate->anomaly_enabled || !gate->anomaly_model) return SG_ERR_INVALID;
    if (sg_anomaly_save(gate->anomaly_model, path) != 0) return SG_ERR_IO;
    /* Save type model to {path}_type */
    if (gate->anomaly_model_type) {
        size_t plen = strlen(path);
        char *type_path = malloc(plen + 6);  /* "_type" + NUL */
        if (!type_path) return SG_ERR_MEMORY;
        memcpy(type_path, path, plen);
        memcpy(type_path + plen, "_type", 5);
        type_path[plen + 5] = '\0';
        int rc = sg_anomaly_save(gate->anomaly_model_type, type_path);
        free(type_path);
        if (rc != 0) return SG_ERR_IO;
    }
    return SG_OK;
}

sg_error_t sg_gate_load_anomaly_model(sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    if (!gate->anomaly_enabled || !gate->anomaly_model) return SG_ERR_INVALID;
    if (sg_anomaly_load(gate->anomaly_model, path) != 0) return SG_ERR_IO;
    /* Load type model from {path}_type if it exists */
    if (gate->anomaly_model_type) {
        size_t plen = strlen(path);
        char *type_path = malloc(plen + 6);
        if (!type_path) return SG_ERR_MEMORY;
        memcpy(type_path, path, plen);
        memcpy(type_path + plen, "_type", 5);
        type_path[plen + 5] = '\0';
        /* Graceful: if type file doesn't exist, that's OK */
        FILE *f = fopen(type_path, "rb");
        if (f) {
            fclose(f);
            if (sg_anomaly_load(gate->anomaly_model_type, type_path) != 0) {
                free(type_path);
                return SG_ERR_IO;
            }
        }
        free(type_path);
    }
    return SG_OK;
}

bool sg_gate_anomaly_had_error(const sg_gate_t *gate)
{
    if (!gate || !gate->anomaly_model) return false;
    return sg_anomaly_model_had_error(gate->anomaly_model);
}

size_t sg_gate_anomaly_vocab_size(const sg_gate_t *gate)
{
    if (!gate || !gate->anomaly_model) return 0;
    return sg_anomaly_vocab_size(gate->anomaly_model);
}

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    st_error_t err = st_policy_load(gate->policy, path, /*clear_first=*/false);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    st_error_t err = st_policy_save(gate->policy, path);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_add(gate->policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_remove(gate->policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

uint32_t sg_gate_rule_count(const sg_gate_t *gate)
{
    if (!gate) return 0;
    return (uint32_t)st_policy_count(gate->policy);
}

sg_error_t sg_gate_add_deny_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_add(gate->deny_policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_remove_deny_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_remove(gate->deny_policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

uint32_t sg_gate_deny_rule_count(const sg_gate_t *gate)
{
    if (!gate) return 0;
    return (uint32_t)st_policy_count(gate->deny_policy);
}

/* ============================================================
 * INTERNAL: TOKEN EXPANSION HELPERS
 * ============================================================ */

static bool extract_var_name(const char *tok, size_t len,
                              char *name_out, size_t name_max)
{
    if (len < 2 || tok[0] != '$') return false;

    size_t start = 1;
    size_t end   = len;

    if (len > 3 && tok[1] == '{' && tok[len - 1] == '}') {
        start = 2;
        end   = len - 1;
    }

    size_t nlen = end - start;
    if (nlen == 0 || nlen >= name_max) return false;

    for (size_t i = start; i < end; i++) {
        char c = tok[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
    }

    memcpy(name_out, tok + start, nlen);
    name_out[nlen] = '\0';
    return true;
}

static bool has_glob_chars(const char *tok, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (tok[i] == '*' || tok[i] == '?' || tok[i] == '[') return true;
    }
    return false;
}

/* ============================================================
 * INTERNAL: BUILD COMMAND STRING WITH OPTIONAL EXPANSION
 * ============================================================ */

/* Expansion buffer size. Callbacks must respect this limit;
 * truncation affects policy matching. Increase if commands can
 * expand to values longer than 4096 bytes. */
#define SG_EXPAND_BUF 4096

static const char *build_cmd_string(const shell_dep_cmd_t *cmd,
                                     buf_writer_t *bw,
                                     const sg_gate_t *gate)
{
    /*
     * Reconstructs the command by joining tokens with spaces.
     * Tokens are copied as-is — no additional quoting is applied.
     * This is intentional: the original shell input already contains
     * any necessary quoting, and adding quotes around tokens that
     * contain spaces or special characters would change the meaning
     * of the reconstructed command.  The goal is a readable display
     * string, not a round-trippable shell command.
     *
     * NOTE: Variable expansion (e.g. $FOO -> "a b c") or glob expansion
     * that produces strings containing spaces will change the token
     * count of the reconstructed command.  Policy matching is performed
     * on this flattened string, so such expansions can cause false
     * negatives or incorrect suggestions.  Callers should be aware of
     * this limitation when using expansion callbacks.
     */
    if (bw->used >= bw->size) { bw->overflow = true; return NULL; }

    size_t start = bw->used;
    size_t avail = bw->size - start;
    size_t pos   = 0;

    char exp_buf[SG_EXPAND_BUF];

    for (uint32_t i = 0; i < cmd->token_count; i++) {
        if (i > 0 && pos < avail) bw->base[start + pos++] = ' ';

        const char *text = cmd->tokens[i];
        size_t text_len  = cmd->token_lens[i];
        bool expanded    = false;

        /* Try variable expansion */
        if (gate->expand_var_fn) {
            char var_name[128];
            if (extract_var_name(text, text_len, var_name, sizeof(var_name))) {
                size_t elen = gate->expand_var_fn(var_name, exp_buf, sizeof(exp_buf),
                                                   gate->expand_var_ctx);
                if (elen > 0) {
                    text = exp_buf;
                    text_len = elen;
                    expanded = true;
                }
            }
        }

        /* Try glob expansion (only if variable expansion didn't fire) */
        if (!expanded && gate->expand_glob_fn) {
            if (has_glob_chars(text, text_len)) {
                char pattern[256];
                size_t plen = text_len < sizeof(pattern) - 1
                              ? text_len : sizeof(pattern) - 1;
                memcpy(pattern, text, plen);
                pattern[plen] = '\0';

                size_t elen = gate->expand_glob_fn(pattern, exp_buf, sizeof(exp_buf),
                                                    gate->expand_glob_ctx);
                if (elen > 0) {
                    text = exp_buf;
                    text_len = elen;
                }
            }
        }

        if (pos + text_len >= avail) {
            size_t writable = avail > pos + 1 ? avail - pos - 1 : 0;
            if (writable > 0) memcpy(bw->base + start + pos, text, writable);
            pos = avail > 0 ? avail - 1 : 0;
            bw->overflow = true;
            break;
        }
        memcpy(bw->base + start + pos, text, text_len);
        pos += text_len;
    }
    bw->base[start + pos] = '\0';
    bw->used = start + pos + 1;
    return bw->base + start;
}

/* ============================================================
 * INTERNAL: CHECK FEATURES FROM FAST PARSER AGAINST REJECT MASK
 * ============================================================ */

static const char *check_features(const shell_parse_result_t *fast,
                                   uint32_t reject_mask,
                                   uint32_t *bad_idx)
{
    static const struct { uint32_t bit; const char *name; } feats[] = {
        { SHELL_FEAT_SUBSHELL,     "command substitution" },
        { SHELL_FEAT_ARITH,        "arithmetic expansion" },
        { SHELL_FEAT_HEREDOC,      "heredoc" },
        { SHELL_FEAT_HERESTRING,   "herestring" },
        { SHELL_FEAT_PROCESS_SUB,  "process substitution" },
        { SHELL_FEAT_LOOPS,        "loop" },
        { SHELL_FEAT_CONDITIONALS, "conditional" },
        { SHELL_FEAT_CASE,         "case statement" },
    };

    for (uint32_t si = 0; si < fast->count; si++) {
        uint16_t fbits = fast->cmds[si].features;
        for (int k = 0; k < (int)(sizeof(feats)/sizeof(feats[0])); k++) {
            if ((fbits & feats[k].bit) && (reject_mask & feats[k].bit)) {
                if (bad_idx) *bad_idx = si;
                return feats[k].name;
            }
        }
    }
    return NULL;
}

/* ============================================================
 * VIOLATION DEFAULT CONFIG
 * ============================================================ */

void sg_violation_config_default(sg_violation_config_t *cfg)
{
    /* NOTE: All arrays must be kept in sorted order (lexicographic, C string
     * comparison) for efficient binary search.  Path arrays additionally require
     * shorter prefixes before longer paths that have them as a prefix.
     * The arrays below are already sorted accordingly. */
    static const char *def_write_paths[] = {
        "/bin/", "/boot/", "/etc/", "/lib/", "/proc/",
        "/root/", "/sbin/", "/sys/", "/usr/lib/", "/var/lib/",
    };
    static const char *def_dirs[] = {
        "/bin", "/boot", "/etc", "/lib", "/opt",
        "/proc", "/root", "/sbin", "/sys", "/usr",
        "/usr/lib", "/var", "/var/lib",
    };
    static const char *def_env[] = {
        "BASH_ENV", "ENV", "IFS", "LD_DEBUG",
        "LD_LIBRARY_PATH", "LD_PRELOAD", "PATH",
    };
    static const char *def_cmds[] = {
        "crontab", "passwd", "scp", "ssh", "su", "sudo",
    };
    static const char *def_reads[] = {
        "/etc/ca-certificates", "/etc/gshadow", "/etc/shadow",
        "/etc/ssh/", "/root/.ssh/",
    };
    memset(cfg, 0, sizeof(*cfg));

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_write_paths)/sizeof(def_write_paths[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_write_paths[cfg->sensitive_write_path_count++] = def_write_paths[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_dirs)/sizeof(def_dirs[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_dirs[cfg->sensitive_dir_count++] = def_dirs[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_env)/sizeof(def_env[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->sensitive_env_names[cfg->sensitive_env_name_count++] = def_env[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_cmds)/sizeof(def_cmds[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->sensitive_cmd_names[cfg->sensitive_cmd_name_count++] = def_cmds[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_reads)/sizeof(def_reads[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_read_paths[cfg->sensitive_read_path_count++] = def_reads[i];

    cfg->redirect_fanout_threshold = 3;

    static const char *def_downloads[] = { "curl", "wget" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_downloads)/sizeof(def_downloads[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->download_cmds[cfg->download_cmd_count++] = def_downloads[i];

    static const char *def_spawns[] = { "sh", "bash", "env", "perl", "python", "ruby", "node" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_spawns)/sizeof(def_spawns[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->shell_spawn_cmds[cfg->shell_spawn_cmd_count++] = def_spawns[i];

    static const char *def_perms[] = { "chmod", "chown", "chgrp" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_perms)/sizeof(def_perms[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->perm_mod_cmds[cfg->perm_mod_cmd_count++] = def_perms[i];

    static const char *def_secrets[] = {
        "/.ssh/", ".env", "/.aws/", "/.kube/",
        "/.npmrc", "/.netrc", "/.pgpass",
        "/.gitconfig", "/.git-credentials",
        "/.docker/", "/.vault-token", "/.gnupg/",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_secrets)/sizeof(def_secrets[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_secret_paths[cfg->sensitive_secret_path_count++] = def_secrets[i];

    static const char *def_readcmds[] = {
        "cat", "head", "tail", "less", "more",
        "base64", "xxd", "od", "strings", "hexdump",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_readcmds)/sizeof(def_readcmds[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->file_reading_cmds[cfg->file_reading_cmd_count++] = def_readcmds[i];

    static const char *def_uploads[] = { "curl", "wget", "scp", "rsync" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_uploads)/sizeof(def_uploads[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->upload_cmds[cfg->upload_cmd_count++] = def_uploads[i];

    static const char *def_listeners[] = {
        "nc", "ncat", "netcat", "socat",
        "ngrok", "cloudflared",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_listeners)/sizeof(def_listeners[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->listener_cmds[cfg->listener_cmd_count++] = def_listeners[i];

    static const char *def_profiles[] = {
        "/.bashrc", "/.profile", "/.zshrc",
        "/.bash_profile", "/.ssh/authorized_keys", "/.ssh/config",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_profiles)/sizeof(def_profiles[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->shell_profile_paths[cfg->shell_profile_path_count++] = def_profiles[i];
}

/* ============================================================
 * VIOLATION SCANNING HELPERS
 * ============================================================ */

/* Exact-match binary search on sorted null-terminated string array.
 * Requires array sorted in C string order (lexicographic).
 * Returns true and sets *out_idx if found. */
static bool sg_name_found(const char *needle, uint32_t needle_len,
                         const char *const *sorted_names, uint32_t count,
                         uint32_t *out_idx)
{
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const char *candidate = sorted_names[mid];
        size_t cand_len = strlen(candidate);
        int cmp = (needle_len < cand_len) ? -1 :
                  (needle_len > cand_len) ?  1 :
                  memcmp(needle, candidate, cand_len);
        if (cmp == 0) {
            *out_idx = mid;
            return true;
        }
        if (cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return false;
}

/* Prefix-match linear search on sorted path array.
 * For small arrays (max 32 entries), linear search is faster than binary search
 * due to better cache locality. The array is kept sorted (shorter paths first).
 * Returns true and sets *out_idx if a matching prefix is found. */
static bool sg_path_found(const char *path, uint32_t path_len,
                          const char *const *sorted_paths, uint32_t count,
                          uint32_t *out_idx)
{
    for (uint32_t i = 0; i < count; i++) {
        const char *prefix = sorted_paths[i];
        size_t plen = strlen(prefix);
        if (path_len >= plen && memcmp(path, prefix, plen) == 0) {
            *out_idx = i;
            return true;
        }
    }
    return false;
}

static bool path_contains(const char *path, uint32_t path_len,
                         const char *needle)
{
    size_t nlen = strlen(needle);
    if (path_len < nlen) return false;
    for (uint32_t i = 0; i <= path_len - nlen; i++) {
        if (memcmp(path + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

static bool tok_equals(const char *tok, uint32_t tok_len, const char *str)
{
    size_t slen = strlen(str);
    return tok_len == slen && memcmp(tok, str, slen) == 0;
}

static void emit_violation(sg_violation_t *viol, uint32_t *count,
                            uint32_t max, uint32_t *dropped,
                            uint32_t type, uint32_t severity,
                            uint32_t cmd_idx, const char *desc, const char *detail)
{
    if (*count >= max) { if (dropped) (*dropped)++; return; }
    if (!desc || !detail) { if (dropped) (*dropped)++; return; }
    sg_violation_t *v = &viol[(*count)++];
    v->type           = type;
    v->severity       = severity;
    v->cmd_node_index = cmd_idx;
    v->description    = desc;
    v->detail         = detail;
}

static bool has_control_flow_path(const shell_dep_graph_t *g,
                                    uint32_t from, uint32_t to)
{
    bool visited[SHELL_DEP_MAX_NODES];
    memset(visited, 0, sizeof(visited));
    uint32_t stack[SHELL_DEP_MAX_NODES];
    uint32_t sp = 0;
    stack[sp++] = from;
    visited[from] = true;

    while (sp > 0) {
        uint32_t cur = stack[--sp];
        if (cur == to) return true;
        for (uint32_t i = 0; i < g->edge_count; i++) {
            const shell_dep_edge_t *e = &g->edges[i];
            if (e->from != cur) continue;
            if (e->type != SHELL_EDGE_SEQ && e->type != SHELL_EDGE_AND &&
                e->type != SHELL_EDGE_OR  && e->type != SHELL_EDGE_PIPE)
                continue;
            if (!visited[e->to]) {
                visited[e->to] = true;
                stack[sp++] = e->to;
            }
        }
    }
    return false;
}

/* ============================================================
 * VIOLATION SCANNING ENGINE
 * ============================================================ */

static void sg_violation_scan(const shell_dep_graph_t *graph,
                               const sg_violation_config_t *cfg,
                               buf_writer_t *bw,
                               sg_violation_t *violations, uint32_t max_violations,
                               uint32_t *violation_count, uint32_t *violation_flags,
                               uint32_t *violation_dropped,
                               uint32_t *node_viols,
                               uint32_t *cmd_write_count, uint32_t *cmd_read_count,
                               uint32_t *cmd_env_count)
{
    *violation_count = 0;
    *violation_flags = 0;
    *violation_dropped = 0;

    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        const shell_dep_node_t *from_node = &graph->nodes[e->from];
        const shell_dep_node_t *to_node   = &graph->nodes[e->to];

        /* --- Per-node edge counters --- */
        if (from_node->type == SHELL_NODE_CMD) {
            if (e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND)
                cmd_write_count[e->from]++;
        }
        if (to_node->type == SHELL_NODE_CMD) {
            if (e->type == SHELL_EDGE_READ)
                cmd_read_count[e->to]++;
            if (e->type == SHELL_EDGE_ENV)
                cmd_env_count[e->to]++;
        }

        /* --- SG_VIOL_WRITE_SENSITIVE --- */
        if ((e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND)
            && to_node->type == SHELL_NODE_DOC && to_node->doc.kind == SHELL_DOC_FILE) {
            uint32_t idx;
            if (sg_path_found(to_node->doc.path, to_node->doc.path_len,
                              cfg->sensitive_write_paths, cfg->sensitive_write_path_count,
                              &idx)) {
                const char *desc = bw_printf(bw, "writes to sensitive path");
                const char *det  = bw_copy(bw, to_node->doc.path, to_node->doc.path_len);
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_WRITE_SENSITIVE, SG_SEVERITY_HIGH, e->from, desc, det);
                node_viols[e->from] |= SG_VIOL_WRITE_SENSITIVE;
                *violation_flags |= SG_VIOL_WRITE_SENSITIVE;
            }
        }

        /* --- SG_VIOL_ENV_PRIVILEGED --- */
        if (e->type == SHELL_EDGE_ENV
            && from_node->type == SHELL_NODE_DOC && from_node->doc.kind == SHELL_DOC_ENVVAR
            && to_node->type == SHELL_NODE_CMD && to_node->cmd.token_count > 0) {

            uint32_t idx;
            if (sg_name_found(from_node->doc.name, from_node->doc.name_len,
                              cfg->sensitive_env_names, cfg->sensitive_env_name_count,
                              &idx)) {
                const char *cmd0 = to_node->cmd.tokens[0];
                uint32_t cmd0_len = to_node->cmd.token_lens[0];
                if (sg_name_found(cmd0, cmd0_len,
                                   cfg->sensitive_cmd_names, cfg->sensitive_cmd_name_count,
                                   &idx)) {
                    const char *desc = bw_printf(bw, "sensitive env before privileged cmd");
                    const char *det  = bw_printf(bw, "%.*s before %.*s",
                                                  (int)from_node->doc.name_len, from_node->doc.name,
                                                  (int)cmd0_len, cmd0);
                    emit_violation(violations, violation_count, max_violations, violation_dropped,
                                   SG_VIOL_ENV_PRIVILEGED, SG_SEVERITY_CRITICAL, e->to, desc, det);
                    node_viols[e->to] |= SG_VIOL_ENV_PRIVILEGED;
                    *violation_flags |= SG_VIOL_ENV_PRIVILEGED;
                }
            }
        }

        /* --- SG_VIOL_SUBST_SENSITIVE --- */
        if (e->type == SHELL_EDGE_SUBST) {
            uint32_t sub_cmd = e->from;
            for (uint32_t ej = 0; ej < graph->edge_count && !bw->overflow; ej++) {
                const shell_dep_edge_t *re = &graph->edges[ej];
                if (re->to != sub_cmd) continue;
                if (re->type != SHELL_EDGE_READ && re->type != SHELL_EDGE_ARG) continue;
                const shell_dep_node_t *doc = &graph->nodes[re->from];
                if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
                uint32_t idx;
                if (sg_path_found(doc->doc.path, doc->doc.path_len,
                                  cfg->sensitive_read_paths, cfg->sensitive_read_path_count,
                                  &idx)) {
                    const char *desc = bw_printf(bw, "subshell reads sensitive file");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations, violation_dropped,
                                   SG_VIOL_SUBST_SENSITIVE, SG_SEVERITY_HIGH, e->to, desc, det);
                    node_viols[e->to] |= SG_VIOL_SUBST_SENSITIVE;
                    *violation_flags |= SG_VIOL_SUBST_SENSITIVE;
                    break;
                }
            }
        }
    }

    /* --- SG_VIOL_REMOVE_SYSTEM --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;
        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "rm") && !tok_equals(cmd0, cmd0_len, "rmdir"))
            continue;
        for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            uint32_t idx;
            if (sg_path_found(doc->doc.path, doc->doc.path_len,
                              cfg->sensitive_dirs, cfg->sensitive_dir_count,
                              &idx)) {
                const char *desc = bw_printf(bw, "removal of system directory");
                const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_REMOVE_SYSTEM, 95, ni, desc, det);
                node_viols[ni] |= SG_VIOL_REMOVE_SYSTEM;
                *violation_flags |= SG_VIOL_REMOVE_SYSTEM;
                break;
            }
        }
    }

    /* --- SG_VIOL_WRITE_THEN_READ --- */
    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
        const shell_dep_edge_t *e1 = &graph->edges[ei];
        if (e1->type != SHELL_EDGE_WRITE && e1->type != SHELL_EDGE_APPEND) continue;
        const shell_dep_node_t *f1 = &graph->nodes[e1->to];
        if (f1->type != SHELL_NODE_DOC || f1->doc.kind != SHELL_DOC_FILE) continue;

        for (uint32_t ej = 0; ej < graph->edge_count && !bw->overflow; ej++) {
            const shell_dep_edge_t *e2 = &graph->edges[ej];
            if (e2->type != SHELL_EDGE_READ) continue;
            const shell_dep_node_t *f2 = &graph->nodes[e2->from];
            if (f2->type != SHELL_NODE_DOC || f2->doc.kind != SHELL_DOC_FILE) continue;
            if (f1->doc.path_len != f2->doc.path_len) continue;
            if (memcmp(f1->doc.path, f2->doc.path, f1->doc.path_len) != 0) continue;

            if (has_control_flow_path(graph, e1->from, e2->to)) {
                const char *desc = bw_printf(bw, "write then read of same file");
                const char *det  = bw_copy(bw, f1->doc.path, f1->doc.path_len);
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_WRITE_THEN_READ, SG_SEVERITY_MEDIUM, e2->to, desc, det);
                node_viols[e2->to] |= SG_VIOL_WRITE_THEN_READ;
                *violation_flags |= SG_VIOL_WRITE_THEN_READ;
                break;
            }
        }
    }

    /* --- SG_VIOL_REDIRECT_FANOUT --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        if (graph->nodes[ni].type != SHELL_NODE_CMD) continue;
        if (cmd_write_count[ni] > cfg->redirect_fanout_threshold) {
            const char *desc = bw_printf(bw, "excessive redirect fan-out (%u targets)",
                                          cmd_write_count[ni]);
            emit_violation(violations, violation_count, max_violations, violation_dropped,
                           SG_VIOL_REDIRECT_FANOUT, SG_SEVERITY_LOW, ni, desc, NULL);
            node_viols[ni] |= SG_VIOL_REDIRECT_FANOUT;
            *violation_flags |= SG_VIOL_REDIRECT_FANOUT;
        }
    }

    /* --- SG_VIOL_NET_DOWNLOAD_EXEC --- */
    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        if (e->type != SHELL_EDGE_PIPE) continue;
        const shell_dep_node_t *src = &graph->nodes[e->from];
        const shell_dep_node_t *dst = &graph->nodes[e->to];
        if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD) continue;
        if (src->cmd.token_count == 0 || dst->cmd.token_count == 0) continue;

        uint32_t idx;
        if (!sg_name_found(src->cmd.tokens[0], src->cmd.token_lens[0],
                            cfg->download_cmds, cfg->download_cmd_count, &idx))
            continue;
        if (!sg_name_found(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                            cfg->shell_spawn_cmds, cfg->shell_spawn_cmd_count, &idx))
            continue;

        const char *desc = bw_printf(bw, "download piped into shell executor");
        const char *det  = bw_printf(bw, "%.*s | %.*s",
                                      (int)src->cmd.token_lens[0], src->cmd.tokens[0],
                                      (int)dst->cmd.token_lens[0], dst->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_NET_DOWNLOAD_EXEC, SG_SEVERITY_CRITICAL, e->to, desc, det);
        node_viols[e->to] |= SG_VIOL_NET_DOWNLOAD_EXEC;
        *violation_flags |= SG_VIOL_NET_DOWNLOAD_EXEC;
    }

    /* --- SG_VIOL_PERM_SYSTEM --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

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
        if (!has_recursive) continue;

        for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            if (sg_path_found(doc->doc.path, doc->doc.path_len,
                              cfg->sensitive_dirs, cfg->sensitive_dir_count,
                              &idx)) {
                const char *desc = bw_printf(bw, "recursive permission change on system dir");
                const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_PERM_SYSTEM, SG_SEVERITY_HIGH, ni, desc, det);
                node_viols[ni] |= SG_VIOL_PERM_SYSTEM;
                *violation_flags |= SG_VIOL_PERM_SYSTEM;
                break;
            }
        }
    }

    /* --- SG_VIOL_SHELL_ESCALATION --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "sudo") && !tok_equals(cmd0, cmd0_len, "su"))
            continue;

        uint32_t idx;
        if (tok_equals(cmd0, cmd0_len, "sudo") || tok_equals(cmd0, cmd0_len, "su")) {
            if (sg_name_found(node->cmd.tokens[1], node->cmd.token_lens[1],
                               cfg->shell_spawn_cmds, cfg->shell_spawn_cmd_count, &idx)) {
                const char *desc = bw_printf(bw, "privileged shell spawn");
                const char *det  = bw_printf(bw, "%.*s %.*s",
                                              (int)cmd0_len, cmd0,
                                              (int)node->cmd.token_lens[1], node->cmd.tokens[1]);
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_SHELL_ESCALATION, SG_SEVERITY_CRITICAL, ni, desc, det);
                node_viols[ni] |= SG_VIOL_SHELL_ESCALATION;
                *violation_flags |= SG_VIOL_SHELL_ESCALATION;
            }
        }
    }

    /* --- SG_VIOL_SUDO_REDIRECT --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "sudo") && !tok_equals(cmd0, cmd0_len, "su"))
            continue;

        bool has_redirect = false;
        const char *target_path = NULL;
        uint32_t target_path_len = 0;
        for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni) continue;
            if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND) continue;
            has_redirect = true;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type == SHELL_NODE_DOC && doc->doc.kind == SHELL_DOC_FILE) {
                target_path = doc->doc.path;
                target_path_len = doc->doc.path_len;
            }
            break;
        }
        if (!has_redirect) continue;

        const char *desc = bw_printf(bw, "sudo with redirect");
        const char *det  = target_path
            ? bw_copy(bw, target_path, target_path_len)
            : bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_SUDO_REDIRECT, SG_SEVERITY_HIGH, ni, desc, det);
        node_viols[ni] |= SG_VIOL_SUDO_REDIRECT;
        *violation_flags |= SG_VIOL_SUDO_REDIRECT;
    }

    /* --- SG_VIOL_READ_SECRETS --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        bool is_reader = false;
        for (uint32_t c = 0; c < cfg->file_reading_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                           cfg->file_reading_cmds[c])) {
                is_reader = true;
                break;
            }
        }
        if (!is_reader) continue;

        for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t p = 0; p < cfg->sensitive_secret_path_count; p++) {
                if (path_contains(doc->doc.path, doc->doc.path_len,
                                  cfg->sensitive_secret_paths[p])) {
                    const char *desc = bw_printf(bw, "reading secret file");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations, violation_dropped,
                                   SG_VIOL_READ_SECRETS, SG_SEVERITY_MEDIUM, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_READ_SECRETS;
                    *violation_flags |= SG_VIOL_READ_SECRETS;
                    break;
                }
            }
        }
    }

    /* --- SG_VIOL_NET_UPLOAD --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];

        bool is_upload = false;
        for (uint32_t c = 0; c < cfg->upload_cmd_count; c++) {
            if (tok_equals(cmd0, cmd0_len, cfg->upload_cmds[c])) {
                is_upload = true;
                break;
            }
        }
        if (!is_upload) continue;

        bool has_upload_flag = false;
        bool is_scp_upload = false;
        bool is_rsync_upload = false;

        if (tok_equals(cmd0, cmd0_len, "curl")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                const char *tok = node->cmd.tokens[t];
                uint32_t tlen = node->cmd.token_lens[t];
                if (tok_equals(tok, tlen, "-d") ||
                    tok_equals(tok, tlen, "--data") ||
                    tok_equals(tok, tlen, "--data-binary") ||
                    tok_equals(tok, tlen, "--data-raw") ||
                    tok_equals(tok, tlen, "--data-urlencode") ||
                    tok_equals(tok, tlen, "-F") ||
                    tok_equals(tok, tlen, "--form") ||
                    tok_equals(tok, tlen, "-T") ||
                    tok_equals(tok, tlen, "--upload-file")) {
                    has_upload_flag = true;
                    break;
                }
                if ((tlen >= 3 && tok[0] == '-' && tok[1] == 'd' && tok[2] == '@') ||
                    (tlen >= 3 && tok[0] == '-' && tok[1] == 'F' && tok[2] == '=') ||
                    (tlen >= 3 && tok[0] == '-' && tok[1] == 'T' && tok[2] != '\0')) {
                    has_upload_flag = true;
                    break;
                }
            }
        } else if (tok_equals(cmd0, cmd0_len, "wget")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
                               "--post-file") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
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

        if (!has_upload_flag && !is_scp_upload && !is_rsync_upload) continue;

        const char *desc = bw_printf(bw, "network file upload");
        const char *det  = bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_NET_UPLOAD, SG_SEVERITY_HIGH, ni, desc, det);
        node_viols[ni] |= SG_VIOL_NET_UPLOAD;
        *violation_flags |= SG_VIOL_NET_UPLOAD;
    }

    /* --- SG_VIOL_NET_LISTENER --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        bool is_listener_cmd = false;
        for (uint32_t c = 0; c < cfg->listener_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                           cfg->listener_cmds[c])) {
                is_listener_cmd = true;
                break;
            }
        }
        if (!is_listener_cmd) continue;

        bool has_listen = false;
        if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "nc") ||
            tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "ncat") ||
            tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "netcat")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-l") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "--listen")) {
                    has_listen = true;
                    break;
                }
            }
        } else if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "socat")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                for (uint32_t c = 0; c < node->cmd.token_lens[t]; c++) {
                    if (node->cmd.tokens[t][c] == 'L' ||
                        node->cmd.tokens[t][c] == 'l') {
                        uint32_t remaining = node->cmd.token_lens[t] - c;
                        if (remaining >= 6 &&
                            (memcmp(node->cmd.tokens[t] + c, "LISTEN", 6) == 0 ||
                             memcmp(node->cmd.tokens[t] + c, "listen", 6) == 0)) {
                            has_listen = true;
                            break;
                        }
                    }
                }
                if (has_listen) break;
            }
        } else {
            has_listen = true;
        }

        if (!has_listen) continue;

        const char *desc = bw_printf(bw, "starting network listener");
        const char *det  = bw_printf(bw, "%.*s", (int)node->cmd.token_lens[0],
                                      node->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_NET_LISTENER, SG_SEVERITY_HIGH, ni, desc, det);
        node_viols[ni] |= SG_VIOL_NET_LISTENER;
        *violation_flags |= SG_VIOL_NET_LISTENER;
    }

    /* --- SG_VIOL_SHELL_OBFUSCATION --- */
    for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        if (e->type != SHELL_EDGE_PIPE) continue;
        const shell_dep_node_t *src = &graph->nodes[e->from];
        const shell_dep_node_t *dst = &graph->nodes[e->to];
        if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD) continue;
        if (src->cmd.token_count == 0 || dst->cmd.token_count == 0) continue;

        bool is_decoder = false;
        if (tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "base64")) {
            for (uint32_t t = 1; t < src->cmd.token_count; t++) {
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
                    tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "--decode")) {
                    is_decoder = true;
                    break;
                }
            }
        }
        if (!is_decoder && tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "openssl")) {
            bool has_enc = false, has_d = false;
            for (uint32_t t = 1; t < src->cmd.token_count; t++) {
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "enc"))
                    has_enc = true;
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
                    tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "--decode"))
                    has_d = true;
            }
            if (has_enc && has_d) is_decoder = true;
        }
        if (!is_decoder) continue;

        bool is_spawn = false;
        for (uint32_t c = 0; c < cfg->shell_spawn_cmd_count; c++) {
            if (tok_equals(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                           cfg->shell_spawn_cmds[c])) {
                is_spawn = true;
                break;
            }
        }
        if (!is_spawn) continue;

        const char *desc = bw_printf(bw, "decoded payload piped to shell");
        const char *det  = bw_printf(bw, "%.*s | %.*s",
                                      (int)src->cmd.token_lens[0], src->cmd.tokens[0],
                                      (int)dst->cmd.token_lens[0], dst->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_SHELL_OBFUSCATION, SG_SEVERITY_CRITICAL, e->to, desc, det);
        node_viols[e->to] |= SG_VIOL_SHELL_OBFUSCATION;
        *violation_flags |= SG_VIOL_SHELL_OBFUSCATION;
    }

    /* --- SG_VIOL_GIT_DESTRUCTIVE --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;
        if (!tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "git"))
            continue;

        const char *subcmd = node->cmd.tokens[1];
        uint32_t subcmd_len = node->cmd.token_lens[1];

        bool destructive = false;
        if (tok_equals(subcmd, subcmd_len, "push")) {
            for (uint32_t t = 2; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "--force") ||
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

        if (!destructive) continue;

        const char *desc = bw_printf(bw, "destructive git operation");
        const char *det  = bw_printf(bw, "git %.*s", (int)subcmd_len, subcmd);
        emit_violation(violations, violation_count, max_violations, violation_dropped,
                       SG_VIOL_GIT_DESTRUCTIVE, SG_SEVERITY_MEDIUM, ni, desc, det);
        node_viols[ni] |= SG_VIOL_GIT_DESTRUCTIVE;
        *violation_flags |= SG_VIOL_GIT_DESTRUCTIVE;
    }

    /* --- SG_VIOL_PERSISTENCE --- */
    for (uint32_t ni = 0; ni < graph->node_count && !bw->overflow; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

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
                const char *det  = bw_printf(bw, "crontab");
                emit_violation(violations, violation_count, max_violations, violation_dropped,
                               SG_VIOL_PERSISTENCE, SG_SEVERITY_MEDIUM, ni, desc, det);
                node_viols[ni] |= SG_VIOL_PERSISTENCE;
                *violation_flags |= SG_VIOL_PERSISTENCE;
            }
            continue;
        }

        for (uint32_t ei = 0; ei < graph->edge_count && !bw->overflow; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni) continue;
            if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t p = 0; p < cfg->shell_profile_path_count; p++) {
                if (path_contains(doc->doc.path, doc->doc.path_len,
                                  cfg->shell_profile_paths[p])) {
                    const char *desc = bw_printf(bw, "writing to shell profile/ssh config");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations, violation_dropped,
                                   SG_VIOL_PERSISTENCE, SG_SEVERITY_HIGH, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_PERSISTENCE;
                    *violation_flags |= SG_VIOL_PERSISTENCE;
                    break;
                }
            }
        }
    }
}

/* ============================================================
 * EVALUATION
 * ============================================================ */

sg_error_t sg_eval(sg_gate_t *gate, const char *cmd, size_t cmd_len,
                   char *buf, size_t buf_size,
                   sg_result_t *out)
{
    if (!gate || !cmd || !buf || !out) return SG_ERR_INVALID;
    if (buf_size == 0) return SG_ERR_INVALID;
    if (cmd_len == 0) return SG_ERR_INVALID;

    memset(out, 0, sizeof(*out));
    out->verdict = SG_VERDICT_ALLOW;

    buf_writer_t bw;
    bw_init(&bw, buf, buf_size);

    /* Step 1: Fast parse to check features */
    shell_parse_result_t fast;
    shell_limits_t lim = { .max_subcommands = 64, .max_depth = 8, .strict_mode = gate->strict_mode };
    shell_error_t ferr = shell_parse_fast(cmd, cmd_len, &lim, &fast);
    if (ferr == SHELL_EPARSE && fast.count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return SG_OK;
    }
    if (ferr == SHELL_EPARSE) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_copy(&bw, "parse error", 11);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 2: Feature rejection */
    uint32_t bad_idx = 0;
    const char *feat = check_features(&fast, gate->reject_mask, &bad_idx);
    if (feat) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_printf(&bw, "%s not allowed", feat);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 3: Build depgraph */
    shell_dep_graph_t graph;
    memset(&graph, 0, sizeof(graph));
    shell_dep_error_t derr = shell_parse_depgraph(cmd, cmd_len, gate->cwd, NULL, 0, &graph);
    if (derr != SHELL_DEP_OK) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_copy(&bw, "depgraph error", 14);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
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
        sg_violation_scan(&graph, &gate->viol_config, &bw,
                          out->violations, SG_MAX_VIOLATIONS,
                          &out->violation_count, &out->violation_flags,
                          &out->violation_dropped_count,
                          node_viols, cmd_write_count, cmd_read_count, cmd_env_count);
        out->has_violations = (out->violation_count > 0);
        if (bw.overflow) {
            out->truncated = true;
            out->violation_truncated = (out->violation_count >= SG_MAX_VIOLATIONS);
            out->verdict = SG_VERDICT_UNDETERMINED;
            out->deny_reason = bw_copy(&bw, "output buffer overflow", 22);
            return SG_ERR_TRUNC;
        }
    }

    /* Extract command sequence from graph (used for anomaly detection and learning) */
    const char *cmd_seq[SHELL_DEP_MAX_NODES];
    size_t cmd_count = 0;
    for (uint32_t ni = 0; ni < graph.node_count; ni++) {
        const shell_dep_node_t *node = &graph.nodes[ni];
        if (node->type == SHELL_NODE_CMD && node->cmd.token_count > 0)
            cmd_seq[cmd_count++] = node->cmd.tokens[0];
    }

    /* Build type sequence tokens for hybrid anomaly detection.
     * Uses shell_build_type_sequence on the full command. An LRU cache
     * avoids recomputation for repeated commands. The cache stores immutable
     * copies; strtok_r tokenization operates on a mutable working copy. */
    char *type_seq_buf = NULL;
    const char *type_seq[SHELL_DEP_MAX_NODES];
    size_t type_count = 0;

    if (gate->anomaly_enabled && gate->anomaly_model_type && cmd_count > 0) {
        const char *cached = type_cache_lookup(&gate->anomaly_type_cache,
                                                cmd, cmd_len);
        if (cached) {
            type_seq_buf = strdup(cached);
        } else {
            char *raw = shell_build_type_sequence(cmd);
            if (raw) {
                /* Store immutable copy in cache before strtok_r mutates */
                if (gate->anomaly_type_cache.capacity > 0) {
                    char *for_cache = strdup(raw);
                    if (for_cache) {
                        if (!type_cache_insert(&gate->anomaly_type_cache,
                                                cmd, cmd_len, for_cache))
                            free(for_cache);
                    }
                }
                type_seq_buf = raw;
            }
        }
        if (type_seq_buf) {
            char *saveptr = NULL;
            char *tok = strtok_r(type_seq_buf, " ", &saveptr);
            while (tok && type_count < SHELL_DEP_MAX_NODES) {
                type_seq[type_count++] = tok;
                tok = strtok_r(NULL, " ", &saveptr);
            }
        }
    }

    /* Anomaly detection: score the command sequence with hybrid model */
    if (gate->anomaly_enabled && gate->anomaly_model && cmd_count > 0) {
        double score_raw = sg_anomaly_score(gate->anomaly_model, cmd_seq, cmd_count);
        double score_type = (gate->anomaly_model_type && type_count > 0)
                            ? sg_anomaly_score(gate->anomaly_model_type, type_seq, type_count)
                            : 0.0;

        out->anomaly_score_raw = score_raw;
        out->anomaly_score_type = score_type;

        if (cmd_count < 3) {
            out->anomaly_score = 0.0;
            out->anomaly_score_raw = 0.0;
            out->anomaly_score_type = 0.0;
            out->anomaly_detected = false;
        } else {
            /* Product of probabilities in log-space = weighted sum of bits */
            out->anomaly_score = score_raw * gate->anomaly_weight_raw
                               + score_type * gate->anomaly_weight_type;
            /* Choose effective threshold: adaptive if armed, else fixed */
            double eff_threshold = gate->anomaly_threshold;
            if (gate->anomaly_adaptive && !gate->anomaly_adaptive_armed)
                eff_threshold = gate->anomaly_fixed_threshold;
            out->anomaly_detected = (out->anomaly_score > eff_threshold);
        }
    } else if (gate->anomaly_enabled && gate->anomaly_model) {
        out->anomaly_score = 0.0;
        out->anomaly_detected = false;
    }

    /* Step 4: Walk CMD nodes, evaluate each against policy */
    bool subcmd_truncated = false;
    for (uint32_t ni = 0; ni < graph.node_count; ni++) {
        const shell_dep_node_t *node = &graph.nodes[ni];
        if (node->type != SHELL_NODE_CMD) continue;
        if (node->cmd.token_count == 0) continue;

        if (out->subcmd_count >= SG_MAX_SUBCMD_RESULTS) {
            subcmd_truncated = true;
            break;
        }

        sg_subcmd_result_t *sr = &out->subcmds[out->subcmd_count++];

        sr->command = build_cmd_string(&node->cmd, &bw, gate);
        if (bw.overflow) {
            out->truncated = true;
            return SG_ERR_TRUNC;
        }

        sr->write_count    = cmd_write_count[ni];
        sr->read_count     = cmd_read_count[ni];
        sr->env_count      = cmd_env_count[ni];
        sr->violation_flags = node_viols[ni];

        const char *cmd_str = sr->command ? sr->command : "";

        /* Check deny policy first */
        st_eval_result_t deny_eval;
        st_error_t deny_err = st_policy_eval(gate->deny_policy, cmd_str, &deny_eval);
        if (deny_err == ST_OK && deny_eval.matches) {
            sr->matches = true;
            sr->verdict = SG_VERDICT_DENY;
            sr->reject_reason = bw_copy(&bw, "deny policy match", 17);
        } else {
            /* Check allow policy */
            st_eval_result_t eval;
            st_error_t eval_err = st_policy_eval(gate->policy, cmd_str, &eval);
            if (eval_err != ST_OK) {
                sr->matches = false;
                sr->verdict = SG_VERDICT_UNDETERMINED;
            } else if (eval.matches) {
                sr->matches = true;
                sr->verdict = SG_VERDICT_ALLOW;
            } else {
                sr->matches = false;
                sr->verdict = SG_VERDICT_UNDETERMINED;

                if (gate->suggestions) {
                    if (eval.suggestion_count > 0 && out->suggestion_count == 0) {
                        out->suggestions[0] = bw_copy(&bw,
                            eval.suggestions[0].pattern,
                            strlen(eval.suggestions[0].pattern));
                        if (out->suggestions[0]) out->suggestion_count++;
                        else if (bw.overflow) { out->truncated = true; return SG_ERR_TRUNC; }
                    }
                    if (eval.suggestion_count > 1 && out->suggestion_count == 1) {
                        out->suggestions[1] = bw_copy(&bw,
                            eval.suggestions[1].pattern,
                            strlen(eval.suggestions[1].pattern));
                        if (out->suggestions[1]) out->suggestion_count++;
                        else if (bw.overflow) { out->truncated = true; return SG_ERR_TRUNC; }
                    }
                }
            }

            if (gate->suggestions) {
                /* Generate deny suggestions from deny policy */
                if (deny_err == ST_OK && out->deny_suggestion_count == 0) {
                    if (deny_eval.suggestion_count > 0) {
                        out->deny_suggestions[0] = bw_copy(&bw,
                            deny_eval.suggestions[0].pattern,
                            strlen(deny_eval.suggestions[0].pattern));
                        if (out->deny_suggestions[0]) out->deny_suggestion_count++;
                        else if (bw.overflow) { out->truncated = true; return SG_ERR_TRUNC; }
                    }
                    if (deny_eval.suggestion_count > 1 && out->deny_suggestion_count == 1) {
                        out->deny_suggestions[1] = bw_copy(&bw,
                            deny_eval.suggestions[1].pattern,
                            strlen(deny_eval.suggestions[1].pattern));
                        if (out->deny_suggestions[1]) out->deny_suggestion_count++;
                        else if (bw.overflow) { out->truncated = true; return SG_ERR_TRUNC; }
                    }
                }
            }
        }

    if (sr->verdict == SG_VERDICT_REJECT || sr->verdict == SG_VERDICT_DENY) {
            if (out->deny_reason == NULL) {
                out->deny_reason = sr->reject_reason ? sr->reject_reason : sr->command;
                out->attention_index = out->subcmd_count - 1;
            }
        }

        if (!sr->matches && gate->stop_mode == SG_STOP_FIRST_FAIL) break;
        if (sr->matches && gate->stop_mode == SG_STOP_FIRST_PASS) break;
        if (sr->verdict == SG_VERDICT_ALLOW && gate->stop_mode == SG_STOP_FIRST_ALLOW) break;
        if (sr->verdict == SG_VERDICT_DENY && gate->stop_mode == SG_STOP_FIRST_DENY) break;
    }

    out->truncated = bw.overflow || subcmd_truncated;
    out->subcmd_truncated = subcmd_truncated;
    if (out->subcmd_count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return bw.overflow ? SG_ERR_TRUNC : SG_OK;
    }

    bool all_allow = true;
    bool any_reject = false;
    bool any_deny = false;
    for (uint32_t i = 0; i < out->subcmd_count; i++) {
        if (out->subcmds[i].verdict != SG_VERDICT_ALLOW) all_allow = false;
        if (out->subcmds[i].verdict == SG_VERDICT_REJECT) any_reject = true;
        if (out->subcmds[i].verdict == SG_VERDICT_DENY) any_deny = true;
    }

    if (any_reject)
        out->verdict = SG_VERDICT_REJECT;
    else if (any_deny)
        out->verdict = SG_VERDICT_DENY;
    else if (all_allow)
        out->verdict = SG_VERDICT_ALLOW;
    else
        out->verdict = SG_VERDICT_UNDETERMINED;

    /* Deferred anomaly model update — after verdict is known */
    if (gate->anomaly_enabled && gate->anomaly_model && cmd_count > 0) {
        bool should_update = false;
        if (!gate->anomaly_update_only_on_allow) {
            /* Always update, but skip if anomalous and flag is set */
            should_update = !out->anomaly_detected || !gate->anomaly_update_on_non_anomaly;
        } else if (out->verdict == SG_VERDICT_ALLOW) {
            /* Only update on ALLOW verdict */
            should_update = !out->anomaly_detected || !gate->anomaly_update_on_non_anomaly;
        }

        /* Record normal scores for adaptive threshold (before update, using current model) */
        if (gate->anomaly_adaptive && !out->anomaly_detected && isfinite(out->anomaly_score) && cmd_count >= 3)
            adaptive_record_score(gate, out->anomaly_score);

        if (should_update) {
            sg_anomaly_update(gate->anomaly_model, cmd_seq, cmd_count);
            /* Also update type sequence model */
            if (gate->anomaly_model_type && type_count > 0)
                sg_anomaly_update(gate->anomaly_model_type, type_seq, type_count);
        }
    }

    /* Free type sequence buffer */
    free(type_seq_buf);

    return (bw.overflow || subcmd_truncated) ? SG_ERR_TRUNC : SG_OK;
}

/* ============================================================
 * HELPERS
 * ============================================================ */

size_t sg_eval_size_hint(size_t cmd_len)
{
    return cmd_len * 4 + 512;
}

const char *sg_verdict_name(sg_verdict_t v)
{
    switch (v) {
        case SG_VERDICT_ALLOW:        return "ALLOW";
        case SG_VERDICT_DENY:         return "DENY";
        case SG_VERDICT_REJECT:       return "REJECT";
        case SG_VERDICT_UNDETERMINED: return "UNDETERMINED";
    }
    return "UNKNOWN";
}

uint32_t sg_result_violation_dropped(const sg_result_t *result)
{
    return result ? result->violation_dropped_count : 0;
}
