/*
 * sg_anomaly.c - Statistical Anomaly Detection
 *
 * 4-gram language model with Kneser-Ney absolute discounting and
 * backoff to trigram/bigram/unigram.  All strings are owned by the model.
 * Context totals are maintained incrementally for O(1) probability lookups.
 *
 * Kneser-Ney discounting:
 *   For observed n-grams:  P_KN(w|ctx) = max(0, c - D) / c_ctx + D * |unique_cont| / c_ctx * P_KN_lower(w|ctx')
 *   For unobserved:        Back off to lower-order model
 *   D = absolute discount (default 0.5)
 *
 * Serialisation uses a binary format with length-prefixed keys:
 *   Header (text):  # anomaly-model-v3\n
 *                   # alpha unk_prior D total_uni total_bi total_tri total_quad vocab_size unk_count\n
 *   Entry (binary): uint8_t type; uint32_t key_len; uint8_t key[key_len]; uint64_t count; uint8_t nl;
 *   type values: 1='U', 2='B', 3='T', 4='Q'
 */

#include "sg_anomaly.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>

/* ============================================================
 * HASH MAP WITH LENGTH-PREFIXED KEYS
 *
 * Open-addressing with power-of-2 capacity and linear probing.
 * Keys are stored as owned length-prefixed blobs (not null-terminated strings).
 * hash_inc returns false if allocation failed or table is full.
 * ============================================================ */

#define HASH_LOAD 0.75

typedef struct {
    char   *key_data;   /* owned length-prefixed key (key_len bytes, no extra NUL) */
    size_t  key_len;     /* length of key_data */
    size_t  count;      /* observation count */
} hash_entry_t;

typedef struct {
    hash_entry_t *entries;
    size_t       capacity;  /* power of 2 */
    size_t       len;      /* occupied entries */
    size_t       total;    /* sum of all counts (for backoff) */
} hash_t;

/* MurmurHash3 64-bit finalizer */
static uint64_t fmix64(uint64_t h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* Hash a length-prefixed key */
static uint64_t hash_key_bytes(const char *key, size_t key_len, size_t cap)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < key_len; i++) {
        h ^= (uint8_t)key[i];
        h *= 0x100000001b3ULL;
    }
    return fmix64(h) & (cap - 1);
}

/* Compare two length-prefixed keys (no null-terminator needed) */
static bool hash_key_eq(const char *a, size_t a_len, const char *b, size_t b_len)
{
    if (a_len != b_len) return false;
    return memcmp(a, b, a_len) == 0;
}

static size_t hash_get(const hash_t *h, const char *key, size_t key_len)
{
    if (h->capacity == 0) return 0;
    size_t pos = hash_key_bytes(key, key_len, h->capacity);
    for (size_t probe = 0; probe < h->capacity; probe++) {
        size_t idx = (pos + probe) & (h->capacity - 1);
        hash_entry_t *e = &h->entries[idx];
        if (e->key_data == NULL) return 0;
        if (hash_key_eq(e->key_data, e->key_len, key, key_len)) return e->count;
    }
    return 0;
}

static bool hash_grow(hash_t *h)
{
    size_t new_cap = h->capacity == 0 ? 16 : h->capacity * 2;
    hash_entry_t *new_entries = calloc(new_cap, sizeof(new_entries[0]));
    if (!new_entries) return false;

    for (size_t i = 0; i < h->capacity; i++) {
        hash_entry_t *e = &h->entries[i];
        if (e->key_data == NULL) continue;
        size_t pos = hash_key_bytes(e->key_data, e->key_len, new_cap);
        for (size_t probe = 0; probe < new_cap; probe++) {
            size_t idx = (pos + probe) & (new_cap - 1);
            if (new_entries[idx].key_data == NULL) {
                new_entries[idx].key_data = malloc(e->key_len);
                if (!new_entries[idx].key_data) {
                    /* Partial growth - free what we allocated and fail */
                    for (size_t j = 0; j < new_cap; j++) free(new_entries[j].key_data);
                    free(new_entries);
                    return false;
                }
                memcpy(new_entries[idx].key_data, e->key_data, e->key_len);
                new_entries[idx].key_len = e->key_len;
                new_entries[idx].count = e->count;
                break;
            }
        }
    }
    for (size_t i = 0; i < h->capacity; i++) free(h->entries[i].key_data);
    free(h->entries);
    h->entries = new_entries;
    h->capacity = new_cap;
    return true;
}

static void hash_free(hash_t *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->capacity; i++) {
        free(h->entries[i].key_data);
    }
    free(h->entries);
    h->entries = NULL;
    h->capacity = 0;
    h->len = 0;
    h->total = 0;
}

static void hash_init(hash_t *h)
{
    h->entries = NULL;
    h->capacity = 0;
    h->len = 0;
    h->total = 0;
}

/*
 * Returns false if:
 *   - allocation failed (OOM), or
 *   - table is full (no empty slot found after probing all capacity entries)
 * On false return, the caller should set model->oom.
 */
static bool hash_inc(hash_t *h, const char *key, size_t key_len, size_t inc)
{
    if (h->capacity == 0) {
        if (!hash_grow(h)) return false;
    }

    if (h->len + 1 > (size_t)((double)h->capacity * HASH_LOAD)) {
        if (!hash_grow(h)) { /* continue on failure */ }
    }

    size_t pos = hash_key_bytes(key, key_len, h->capacity);
    for (size_t probe = 0; probe < h->capacity; probe++) {
        size_t idx = (pos + probe) & (h->capacity - 1);
        hash_entry_t *e = &h->entries[idx];
        if (e->key_data == NULL) {
            e->key_data = malloc(key_len);
            if (!e->key_data) return false;
            memcpy(e->key_data, key, key_len);
            e->key_len = key_len;
            e->count = inc;
            h->len++;
            h->total += inc;
            return true;
        }
        if (hash_key_eq(e->key_data, e->key_len, key, key_len)) {
            e->count += inc;
            h->total += inc;
            return true;
        }
    }
    /* Table full — no empty slot found */
    return false;
}

/* ============================================================
 * KEY BUILDING HELPERS
 *
 * Bigram key:  "prev\0curr"  (key_len = plen + 1 + clen + 1)
 * Trigram key: "p2\0p1\0curr" (key_len = p2len + 1 + p1len + 1 + clen + 1)
 * Context suffix for bigram: "prev\0"  (all bigrams starting with prev)
 * Context suffix for trigram: "p2\0p1\0" (all trigrams starting with p2,p1)
 *
 * All functions return the key length (0 on truncation or empty input).
 * ============================================================ */

static size_t build_bigram_key(char *buf, size_t buf_size,
                               const char *prev, const char *curr)
{
    size_t plen = strlen(prev);
    size_t clen = strlen(curr);
    if (plen == 0 || clen == 0) return 0;
    if (plen + 1 + clen + 1 > buf_size) return 0;
    memcpy(buf, prev, plen);
    buf[plen] = '\0';
    memcpy(buf + plen + 1, curr, clen);
    buf[plen + 1 + clen] = '\0';
    return plen + 1 + clen + 1;
}

static size_t build_trigram_key(char *buf, size_t buf_size,
                                 const char *p2, const char *p1, const char *curr)
{
    size_t p2len = strlen(p2);
    size_t p1len = strlen(p1);
    size_t clen = strlen(curr);
    if (p2len == 0 || p1len == 0 || clen == 0) return 0;
    if (p2len + 1 + p1len + 1 + clen + 1 > buf_size) return 0;
    char *dst = buf;
    memcpy(dst, p2, p2len);
    dst[p2len] = '\0';
    dst += p2len + 1;
    memcpy(dst, p1, p1len);
    dst[p1len] = '\0';
    dst += p1len + 1;
    memcpy(dst, curr, clen);
    dst[clen] = '\0';
    return p2len + 1 + p1len + 1 + clen + 1;
}

static size_t build_bigram_ctx(char *buf, size_t buf_size, const char *prev)
{
    size_t plen = strlen(prev);
    if (plen == 0) return 0;
    if (plen + 2 > buf_size) return 0;
    memcpy(buf, prev, plen);
    buf[plen] = '\0';
    buf[plen + 1] = '\0';
    return plen + 2;
}

static size_t build_trigram_ctx(char *buf, size_t buf_size,
                                const char *p2, const char *p1)
{
    size_t p2len = strlen(p2);
    size_t p1len = strlen(p1);
    if (p2len == 0 || p1len == 0) return 0;
    if (p2len + 1 + p1len + 2 > buf_size) return 0;
    char *dst = buf;
    memcpy(dst, p2, p2len);
    dst[p2len] = '\0';
    dst += p2len + 1;
    memcpy(dst, p1, p1len);
    dst[p1len] = '\0';
    return p2len + 1 + p1len + 2;
}

static size_t extract_bigram_ctx_len(const char *key, size_t max_len)
{
    size_t i = 0;
    while (i < max_len && key[i] != '\0') i++;
    i++; /* skip NUL */
    return i + 1; /* include trailing NUL in context */
}

static size_t extract_trigram_ctx_len(const char *key, size_t max_len)
{
    size_t i = 0;
    while (i < max_len && key[i] != '\0') i++;
    i++; /* skip first NUL */
    while (i < max_len && key[i] != '\0') i++;
    i++; /* skip second NUL */
    return i + 1; /* include trailing NUL in context */
}

static size_t build_4gram_key(char *buf, size_t buf_size,
                               const char *p3, const char *p2,
                               const char *p1, const char *curr)
{
    size_t p3len = strlen(p3);
    size_t p2len = strlen(p2);
    size_t p1len = strlen(p1);
    size_t clen = strlen(curr);
    if (p3len == 0 || p2len == 0 || p1len == 0 || clen == 0) return 0;
    if (p3len + 1 + p2len + 1 + p1len + 1 + clen + 1 > buf_size) return 0;
    char *dst = buf;
    memcpy(dst, p3, p3len); dst[p3len] = '\0'; dst += p3len + 1;
    memcpy(dst, p2, p2len); dst[p2len] = '\0'; dst += p2len + 1;
    memcpy(dst, p1, p1len); dst[p1len] = '\0'; dst += p1len + 1;
    memcpy(dst, curr, clen); dst[clen] = '\0';
    return p3len + 1 + p2len + 1 + p1len + 1 + clen + 1;
}

static size_t build_4gram_ctx(char *buf, size_t buf_size,
                               const char *p3, const char *p2, const char *p1)
{
    size_t p3len = strlen(p3);
    size_t p2len = strlen(p2);
    size_t p1len = strlen(p1);
    if (p3len == 0 || p2len == 0 || p1len == 0) return 0;
    if (p3len + 1 + p2len + 1 + p1len + 2 > buf_size) return 0;
    char *dst = buf;
    memcpy(dst, p3, p3len); dst[p3len] = '\0'; dst += p3len + 1;
    memcpy(dst, p2, p2len); dst[p2len] = '\0'; dst += p2len + 1;
    memcpy(dst, p1, p1len); dst[p1len] = '\0';
    return p3len + 1 + p2len + 1 + p1len + 2;
}

static size_t extract_4gram_ctx_len(const char *key, size_t max_len)
{
    size_t i = 0;
    /* skip 3 NUL-terminated strings */
    for (int n = 0; n < 3; n++) {
        while (i < max_len && key[i] != '\0') i++;
        i++; /* skip NUL */
    }
    return i + 1; /* include trailing NUL in context */
}

/* ============================================================
 * MODEL
 * ============================================================ */

struct sg_anomaly_model {
    hash_t   uni;         /* unigram counts */
    hash_t   bi;          /* bigram counts: key = "prev\0curr" */
    hash_t   tri;         /* trigram counts: key = "p2\0p1\0curr" */
    hash_t   quad;        /* 4-gram counts: key = "p3\0p2\0p1\0curr" */
    hash_t   bi_ctx;      /* bigram context totals: key = "prev\0", value = sum */
    hash_t   tri_ctx;     /* trigram context totals: key = "p2\0p1\0", value = sum */
    hash_t   quad_ctx;    /* 4-gram context totals: key = "p3\0p2\0p1\0", value = sum */
    size_t   total_uni;
    size_t   total_bi;
    size_t   total_tri;
    size_t   total_quad;
    double   alpha;       /* Dirichlet smoothing (used when KN data insufficient) */
    double   unk_prior;   /* fallback log-prob for unseen commands */
    double   kn_discount; /* Kneser-Ney absolute discount (default 0.5) */
    size_t   vocab_size;  /* number of unique unigrams */
    bool     oom;         /* true if any allocation failed */
    size_t   unk_count;   /* count of unseen commands for probability estimation */
};

sg_anomaly_model_t *sg_anomaly_model_new(void)
{
    return sg_anomaly_model_new_ex(0.1, -10.0);
}

sg_anomaly_model_t *sg_anomaly_model_new_ex(double alpha, double unk_prior)
{
    sg_anomaly_model_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->alpha = alpha;
    m->unk_prior = unk_prior;
    m->kn_discount = 0.5;
    m->vocab_size = 0;
    m->oom = false;
    hash_init(&m->uni);
    hash_init(&m->bi);
    hash_init(&m->tri);
    hash_init(&m->quad);
    hash_init(&m->bi_ctx);
    hash_init(&m->tri_ctx);
    hash_init(&m->quad_ctx);
    return m;
}

void sg_anomaly_model_free(sg_anomaly_model_t *model)
{
    if (!model) return;
    hash_free(&model->uni);
    hash_free(&model->bi);
    hash_free(&model->tri);
    hash_free(&model->quad);
    hash_free(&model->bi_ctx);
    hash_free(&model->tri_ctx);
    hash_free(&model->quad_ctx);
    free(model);
}

bool sg_anomaly_model_had_error(const sg_anomaly_model_t *model)
{
    return model ? model->oom : false;
}

void sg_anomaly_model_clear_error(sg_anomaly_model_t *model)
{
    if (model) model->oom = false;
}

/* ============================================================
 * PROBABILITY CALCULATION — Kneser-Ney with 4-gram backoff
 *
 * Compute log P(curr | p3, p2, p1) in bits using KN discounting.
 * Backoff chain: 4-gram → trigram → bigram → unigram → UNK.
 *
 * KN formula (for each n-gram level):
 *   P_KN(w | ctx) = max(0, c(ctx,w) - D) / c(ctx)
 *                   + D * |{w': c(ctx,w')>0}| / c(ctx) * P_KN_lower(w)
 *
 * The lower-order continuation probability uses the number of
 * distinct contexts in which w has appeared (not raw count).
 * For simplicity, we use raw counts as a proxy for continuation
 * counts in the first iteration.
 * ============================================================ */

/* Compute log probability of unknown command in bits */
static double unk_logprob(const sg_anomaly_model_t *m)
{
    /* P_unk = (unk_count + alpha) / (total_uni + unk_count + alpha * (V + 1)) */
    double V_plus_1 = (double)m->vocab_size + 1.0;
    double numer = (double)m->unk_count + m->alpha;
    double denom = (double)m->total_uni + m->unk_count + m->alpha * V_plus_1;
    if (denom <= 0) return m->unk_prior;  /* fallback if no data */
    return log(numer / denom) / M_LN2;   /* in bits */
}

/* Count number of unique n-gram continuations from a context hash.
 * This scans the hash table for entries whose key starts with ctx.
 * Used for KN discount weight computation.
 * For large tables this is O(n); acceptable for anomaly model sizes. */
static size_t count_unique_continuations(const hash_t *h,
                                          const char *ctx, size_t ctx_len)
{
    size_t count = 0;
    for (size_t i = 0; i < h->capacity; i++) {
        if (h->entries[i].key_data == NULL) continue;
        if (h->entries[i].key_len < ctx_len) continue;
        if (memcmp(h->entries[i].key_data, ctx, ctx_len) == 0)
            count++;
    }
    return count;
}

/*
 * KN probability at a given n-gram level.
 *
 * key, key_len:    the full n-gram key (e.g., "p2\0p1\0curr")
 * ctx, ctx_len:    the context suffix (e.g., "p2\0p1\0")
 * n_count:         count of this specific n-gram
 * ctx_total:       sum of all counts sharing this context
 * n_table:         the hash table to count unique continuations from
 * Returns log probability in bits.
 */
static double kn_level_logprob(const sg_anomaly_model_t *m,
                                size_t n_count, size_t ctx_total,
                                const hash_t *n_table,
                                const char *ctx, size_t ctx_len,
                                double lower_logprob)
{
    double D = m->kn_discount;

    if (ctx_total == 0) return lower_logprob;

    /* Number of unique continuations from this context */
    size_t unique_cont = count_unique_continuations(n_table, ctx, ctx_len);

    /* Discounted probability mass for observed n-gram */
    double disc_count = (double)n_count - D;
    if (disc_count < 0) disc_count = 0;

    /* Interpolation weight (probability mass for lower-order) */
    double lambda = D * (double)unique_cont / (double)ctx_total;

    /* Combined probability */
    double p_observed = disc_count / (double)ctx_total;
    double p_lower = lambda * exp(lower_logprob * M_LN2);  /* convert bits→prob */

    double p_total = p_observed + p_lower;
    if (p_total <= 0) return unk_logprob(m);
    return log(p_total) / M_LN2;
}

static double kn_logprob(const sg_anomaly_model_t *m,
                          const char *p3, const char *p2,
                          const char *p1, const char *curr)
{
    char key[2048];
    char ctx[1024];
    size_t key_len, ctx_len;

    /* === Level 1: Unigram (base) === */
    size_t uni_count = hash_get(&m->uni, curr, strlen(curr) + 1);
    double unigram_lp;
    if (uni_count > 0) {
        double denom = (double)m->total_uni + m->alpha * (double)m->vocab_size;
        double numer = (double)uni_count + m->alpha;
        unigram_lp = log(numer / denom) / M_LN2;
    } else {
        unigram_lp = unk_logprob(m);
    }

    /* === Level 2: Bigram === */
    key_len = build_bigram_key(key, sizeof(key), p1, curr);
    size_t bi_count = key_len > 0 ? hash_get(&m->bi, key, key_len) : 0;
    double bigram_lp;
    if (bi_count > 0) {
        ctx_len = build_bigram_ctx(ctx, sizeof(ctx), p1);
        size_t bi_ctx_total = ctx_len > 0 ? hash_get(&m->bi_ctx, ctx, ctx_len) : 0;
        if (bi_ctx_total == 0) bi_ctx_total = bi_count;
        bigram_lp = kn_level_logprob(m, bi_count, bi_ctx_total,
                                      &m->bi, ctx, ctx_len, unigram_lp);
    } else {
        bigram_lp = unigram_lp;
    }

    /* === Level 3: Trigram === */
    key_len = build_trigram_key(key, sizeof(key), p2, p1, curr);
    size_t tri_count = key_len > 0 ? hash_get(&m->tri, key, key_len) : 0;
    double trigram_lp;
    if (tri_count > 0) {
        ctx_len = build_trigram_ctx(ctx, sizeof(ctx), p2, p1);
        size_t tri_ctx_total = ctx_len > 0 ? hash_get(&m->tri_ctx, ctx, ctx_len) : 0;
        if (tri_ctx_total == 0) tri_ctx_total = tri_count;
        trigram_lp = kn_level_logprob(m, tri_count, tri_ctx_total,
                                       &m->tri, ctx, ctx_len, bigram_lp);
    } else {
        trigram_lp = bigram_lp;
    }

    /* === Level 4: 4-gram === */
    key_len = build_4gram_key(key, sizeof(key), p3, p2, p1, curr);
    size_t quad_count = key_len > 0 ? hash_get(&m->quad, key, key_len) : 0;
    if (quad_count > 0) {
        ctx_len = build_4gram_ctx(ctx, sizeof(ctx), p3, p2, p1);
        size_t quad_ctx_total = ctx_len > 0 ? hash_get(&m->quad_ctx, ctx, ctx_len) : 0;
        if (quad_ctx_total == 0) quad_ctx_total = quad_count;
        return kn_level_logprob(m, quad_count, quad_ctx_total,
                                 &m->quad, ctx, ctx_len, trigram_lp);
    }

    return trigram_lp;
}

/* ============================================================
 * SCORING
 *
 * Uses 4-gram KN backoff for sequences of len >= 4,
 * trigram KN backoff for len == 3.
 * Returns INFINITY for len < 3 (need at least one trigram).
 * ============================================================ */

double sg_anomaly_score(const sg_anomaly_model_t *model,
                         const char **seq, size_t len)
{
    if (!model || !seq) return INFINITY;
    if (len < 3) return INFINITY;
    if (model->total_uni == 0) return INFINITY;

    double total_bits = 0.0;
    size_t scored = 0;

    if (len >= 4) {
        /* Score using 4-gram context from i=3 onward */
        for (size_t i = 3; i < len; i++) {
            double lp = kn_logprob(model, seq[i-3], seq[i-2], seq[i-1], seq[i]);
            total_bits -= lp;
            scored++;
        }
    } else {
        /* len == 3: score one trigram using empty p3 */
        double lp = kn_logprob(model, "", seq[0], seq[1], seq[2]);
        total_bits -= lp;
        scored = 1;
    }

    return scored > 0 ? total_bits / (double)scored : INFINITY;
}

/* ============================================================
 * UPDATE (LEARNING)
 * ============================================================
 *
 * Note: sg_anomaly_score() returns INFINITY for sequences with
 * len < 3 (cannot form any trigrams). However, this update
 * function still adds unigrams and bigrams for shorter sequences.
 * This is intentional — the model learns from partial sequences.
 * ============================================================ */

void sg_anomaly_update(sg_anomaly_model_t *model,
                        const char **seq, size_t len)
{
    if (!model || !seq || len == 0) return;

    /* Update unigrams */
    for (size_t i = 0; i < len; i++) {
        size_t cmd_len = strlen(seq[i]) + 1;
        /* Check if command is already known */
        size_t existing = hash_get(&model->uni, seq[i], cmd_len);
        if (existing > 0) {
            /* Known command - increment normally */
            if (!hash_inc(&model->uni, seq[i], cmd_len, 1))
                model->oom = true;
        } else {
            /* New command - increment UNK count */
            model->unk_count++;
            /* Also add to vocabulary (promote after first sighting) */
            if (!hash_inc(&model->uni, seq[i], cmd_len, 1))
                model->oom = true;
        }
    }

    /* Update bigrams and their context totals */
    for (size_t i = 1; i < len; i++) {
        char key[512];
        size_t key_len = build_bigram_key(key, sizeof(key), seq[i-1], seq[i]);
        if (key_len > 0) {
            if (!hash_inc(&model->bi, key, key_len, 1))
                model->oom = true;
            char ctx[256];
            size_t ctx_len = build_bigram_ctx(ctx, sizeof(ctx), seq[i-1]);
            if (ctx_len > 0) {
                if (!hash_inc(&model->bi_ctx, ctx, ctx_len, 1))
                    model->oom = true;
            }
        }
    }

    /* Update trigrams and their context totals */
    for (size_t i = 2; i < len; i++) {
        char key[1024];
        size_t key_len = build_trigram_key(key, sizeof(key), seq[i-2], seq[i-1], seq[i]);
        if (key_len > 0) {
            if (!hash_inc(&model->tri, key, key_len, 1))
                model->oom = true;
            char ctx[512];
            size_t ctx_len = build_trigram_ctx(ctx, sizeof(ctx), seq[i-2], seq[i-1]);
            if (ctx_len > 0) {
                if (!hash_inc(&model->tri_ctx, ctx, ctx_len, 1))
                    model->oom = true;
            }
        }
    }

    /* Update 4-grams and their context totals */
    for (size_t i = 3; i < len; i++) {
        char key[2048];
        size_t key_len = build_4gram_key(key, sizeof(key),
                                          seq[i-3], seq[i-2], seq[i-1], seq[i]);
        if (key_len > 0) {
            if (!hash_inc(&model->quad, key, key_len, 1))
                model->oom = true;
            char ctx[1024];
            size_t ctx_len = build_4gram_ctx(ctx, sizeof(ctx),
                                              seq[i-3], seq[i-2], seq[i-1]);
            if (ctx_len > 0) {
                if (!hash_inc(&model->quad_ctx, ctx, ctx_len, 1))
                    model->oom = true;
            }
        }
    }

    model->total_uni  = model->uni.total;
    model->total_bi  = model->bi.total;
    model->total_tri = model->tri.total;
    model->total_quad = model->quad.total;
    model->vocab_size = model->uni.len;
}

/* ============================================================
 * SERIALISATION — Binary Format v3
 *
 * Header (text, for easy inspection):
 *   # anomaly-model-v3\n
 *   # alpha unk_prior total_uni total_bi total_tri vocab_size\n
 *
 * Entry (binary):
 *   uint8_t  type;       // 1='U', 2='B', 3='T'
 *   uint32_t key_len;     // bytes of key (including embedded NULs)
 *   uint8_t  key[key_len];
 *   uint64_t count;
 *   uint8_t  nl;          // '\n'
 *
 * bi_ctx and tri_ctx totals are NOT serialised — rebuilt from bi/tri on load.
 * ============================================================ */

#define BINARY_TYPE_UNI   1
#define BINARY_TYPE_BI    2
#define BINARY_TYPE_TRI   3
#define BINARY_TYPE_QUAD  4

int sg_anomaly_save(const sg_anomaly_model_t *model, const char *path)
{
    if (!model || !path) { errno = EINVAL; return -1; }

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    fprintf(f, "# anomaly-model-v3\n");
    fprintf(f, "# %.17g %.17g %.17g %zu %zu %zu %zu %zu %zu\n",
            model->alpha, model->unk_prior, model->kn_discount,
            model->total_uni, model->total_bi, model->total_tri,
            model->total_quad, model->vocab_size, model->unk_count);

    /* Write unigrams */
    for (size_t i = 0; i < model->uni.capacity; i++) {
        if (model->uni.entries[i].key_data == NULL) continue;
        uint8_t type = BINARY_TYPE_UNI;
        uint32_t key_len = (uint32_t)model->uni.entries[i].key_len;
        uint64_t count = (uint64_t)model->uni.entries[i].count;
        uint8_t nl = '\n';
        if (fwrite(&type, 1, 1, f) != 1 ||
            fwrite(&key_len, 4, 1, f) != 1 ||
            fwrite(model->uni.entries[i].key_data, 1, key_len, f) != key_len ||
            fwrite(&count, 8, 1, f) != 1 ||
            fwrite(&nl, 1, 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }

    /* Write bigrams */
    for (size_t i = 0; i < model->bi.capacity; i++) {
        if (model->bi.entries[i].key_data == NULL) continue;
        uint8_t type = BINARY_TYPE_BI;
        uint32_t key_len = (uint32_t)model->bi.entries[i].key_len;
        uint64_t count = (uint64_t)model->bi.entries[i].count;
        uint8_t nl = '\n';
        if (fwrite(&type, 1, 1, f) != 1 ||
            fwrite(&key_len, 4, 1, f) != 1 ||
            fwrite(model->bi.entries[i].key_data, 1, key_len, f) != key_len ||
            fwrite(&count, 8, 1, f) != 1 ||
            fwrite(&nl, 1, 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }

    /* Write trigrams */
    for (size_t i = 0; i < model->tri.capacity; i++) {
        if (model->tri.entries[i].key_data == NULL) continue;
        uint8_t type = BINARY_TYPE_TRI;
        uint32_t key_len = (uint32_t)model->tri.entries[i].key_len;
        uint64_t count = (uint64_t)model->tri.entries[i].count;
        uint8_t nl = '\n';
        if (fwrite(&type, 1, 1, f) != 1 ||
            fwrite(&key_len, 4, 1, f) != 1 ||
            fwrite(model->tri.entries[i].key_data, 1, key_len, f) != key_len ||
            fwrite(&count, 8, 1, f) != 1 ||
            fwrite(&nl, 1, 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }

    /* Write 4-grams */
    for (size_t i = 0; i < model->quad.capacity; i++) {
        if (model->quad.entries[i].key_data == NULL) continue;
        uint8_t type = BINARY_TYPE_QUAD;
        uint32_t key_len = (uint32_t)model->quad.entries[i].key_len;
        uint64_t count = (uint64_t)model->quad.entries[i].count;
        uint8_t nl = '\n';
        if (fwrite(&type, 1, 1, f) != 1 ||
            fwrite(&key_len, 4, 1, f) != 1 ||
            fwrite(model->quad.entries[i].key_data, 1, key_len, f) != key_len ||
            fwrite(&count, 8, 1, f) != 1 ||
            fwrite(&nl, 1, 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

int sg_anomaly_load(sg_anomaly_model_t *model, const char *path)
{
    if (!model || !path) { errno = EINVAL; return -1; }

    hash_free(&model->uni);
    hash_free(&model->bi);
    hash_free(&model->tri);
    hash_free(&model->quad);
    hash_free(&model->bi_ctx);
    hash_free(&model->tri_ctx);
    hash_free(&model->quad_ctx);
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = 0;
    model->unk_count = 0;
    model->oom = false;
    hash_init(&model->uni);
    hash_init(&model->bi);
    hash_init(&model->tri);
    hash_init(&model->quad);
    hash_init(&model->bi_ctx);
    hash_init(&model->tri_ctx);
    hash_init(&model->quad_ctx);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read text header lines by checking for # prefix */
    char line[256];
    while (1) {
        int ch = fgetc(f);
        if (ch == EOF) break;
        if (ch != '#') { ungetc(ch, f); break; }
        ungetc(ch, f);
        if (!fgets(line, sizeof(line), f)) break;
        if (strncmp(line, "# anomaly-model-v3", 17) != 0) {
            double alpha = 0, unk_prior = 0, kn_discount = 0;
            size_t tu = 0, tb = 0, tt = 0, tq = 0, vocab = 0, unk = 0;
            int n = sscanf(line + 1, " %lf %lf %lf %zu %zu %zu %zu %zu %zu",
                           &alpha, &unk_prior, &kn_discount,
                           &tu, &tb, &tt, &tq, &vocab, &unk);
            if (n >= 2) { model->alpha = alpha; model->unk_prior = unk_prior; }
            if (n >= 3 && kn_discount > 0) model->kn_discount = kn_discount;
            if (n >= 7) {
                model->total_uni = tu; model->total_bi = tb;
                model->total_tri = tt; model->total_quad = tq;
                model->vocab_size = vocab;
            }
            if (n >= 9) {
                model->unk_count = unk;
            }
        }
    }

    /* Read binary entries */
    while (1) {
        uint8_t type;
        if (fread(&type, 1, 1, f) != 1) break;

        uint32_t key_len;
        if (fread(&key_len, 4, 1, f) != 1) break;
        if (key_len > 4096) { fclose(f); errno = EPROTO; return -1; }

        char keybuf[4096];
        if (fread(keybuf, 1, key_len, f) != key_len) break;

        uint64_t count;
        if (fread(&count, 8, 1, f) != 1) break;

        uint8_t nl;
        if (fread(&nl, 1, 1, f) != 1) break;

        if (type == BINARY_TYPE_UNI) {
            if (!hash_inc(&model->uni, keybuf, key_len, (size_t)count)) model->oom = true;
        } else if (type == BINARY_TYPE_BI) {
            if (!hash_inc(&model->bi, keybuf, key_len, (size_t)count)) model->oom = true;
            /* Rebuild bigram context total */
            size_t ctx_len = extract_bigram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!hash_inc(&model->bi_ctx, keybuf, ctx_len, (size_t)count)) model->oom = true;
            }
        } else if (type == BINARY_TYPE_TRI) {
            if (!hash_inc(&model->tri, keybuf, key_len, (size_t)count)) model->oom = true;
            /* Rebuild trigram context total */
            size_t ctx_len = extract_trigram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!hash_inc(&model->tri_ctx, keybuf, ctx_len, (size_t)count)) model->oom = true;
            }
        } else if (type == BINARY_TYPE_QUAD) {
            if (!hash_inc(&model->quad, keybuf, key_len, (size_t)count)) model->oom = true;
            /* Rebuild 4-gram context total */
            size_t ctx_len = extract_4gram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!hash_inc(&model->quad_ctx, keybuf, ctx_len, (size_t)count)) model->oom = true;
            }
        }
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * ACCESSORS
 * ============================================================ */

size_t sg_anomaly_vocab_size(const sg_anomaly_model_t *model)
{
    return model ? model->uni.len : 0;
}

size_t sg_anomaly_total_uni(const sg_anomaly_model_t *model)
{
    return model ? model->total_uni : 0;
}

size_t sg_anomaly_total_bi(const sg_anomaly_model_t *model)
{
    return model ? model->total_bi : 0;
}

size_t sg_anomaly_total_tri(const sg_anomaly_model_t *model)
{
    return model ? model->total_tri : 0;
}

size_t sg_anomaly_total_quad(const sg_anomaly_model_t *model)
{
    return model ? model->total_quad : 0;
}

size_t sg_anomaly_uni_count(const sg_anomaly_model_t *model, const char *cmd)
{
    if (!model || !cmd) return 0;
    size_t cmd_len = strlen(cmd) + 1;
    return hash_get(&model->uni, cmd, cmd_len);
}

size_t sg_anomaly_unk_count(const sg_anomaly_model_t *model)
{
    return model ? model->unk_count : 0;
}

double sg_anomaly_kn_discount(const sg_anomaly_model_t *model)
{
    return model ? model->kn_discount : 0.0;
}

size_t sg_anomaly_bi_count(const sg_anomaly_model_t *model,
                             const char *prev, const char *curr)
{
    if (!model || !prev || !curr) return 0;
    char key[1024];
    size_t key_len = build_bigram_key(key, sizeof(key), prev, curr);
    return key_len > 0 ? hash_get(&model->bi, key, key_len) : 0;
}

size_t sg_anomaly_tri_count(const sg_anomaly_model_t *model,
                              const char *p2, const char *p1, const char *curr)
{
    if (!model || !p2 || !p1 || !curr) return 0;
    char key[1024];
    size_t key_len = build_trigram_key(key, sizeof(key), p2, p1, curr);
    return key_len > 0 ? hash_get(&model->tri, key, key_len) : 0;
}

size_t sg_anomaly_quad_count(const sg_anomaly_model_t *model,
                               const char *p3, const char *p2,
                               const char *p1, const char *curr)
{
    if (!model || !p3 || !p2 || !p1 || !curr) return 0;
    char key[2048];
    size_t key_len = build_4gram_key(key, sizeof(key), p3, p2, p1, curr);
    return key_len > 0 ? hash_get(&model->quad, key, key_len) : 0;
}

size_t sg_anomaly_total_contexts(const sg_anomaly_model_t *model)
{
    if (!model) return 0;
    return model->bi_ctx.len + model->tri_ctx.len + model->quad_ctx.len;
}

bool sg_anomaly_has_observed(const sg_anomaly_model_t *model,
                               const char **seq, size_t len)
{
    if (!model || !seq || len == 0) return false;
    /* Check unigrams first */
    for (size_t i = 0; i < len; i++) {
        if (seq[i] && hash_get(&model->uni, seq[i], strlen(seq[i]) + 1) > 0)
            return true;
    }
    return false;
}

void sg_anomaly_reset(sg_anomaly_model_t *model)
{
    if (!model) return;
    hash_free(&model->uni);
    hash_free(&model->bi);
    hash_free(&model->tri);
    hash_free(&model->quad);
    hash_free(&model->bi_ctx);
    hash_free(&model->tri_ctx);
    hash_free(&model->quad_ctx);
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = 0;
    model->unk_count = 0;
    model->oom = false;
    hash_init(&model->uni);
    hash_init(&model->bi);
    hash_init(&model->tri);
    hash_init(&model->quad);
    hash_init(&model->bi_ctx);
    hash_init(&model->tri_ctx);
    hash_init(&model->quad_ctx);
}

/* Apply decay to a hash table: multiply all counts by scale factor.
 * Entries with count < 0.5 are removed (effectively zero).
 * Returns number of entries removed. */
static size_t hash_decay(hash_t *h, double scale)
{
    if (!h || scale <= 0.0 || scale >= 1.0) return 0;

    size_t removed = 0;
    for (size_t i = 0; i < h->capacity; i++) {
        if (h->entries[i].key_data == NULL) continue;

        h->entries[i].count = (size_t)((double)h->entries[i].count * scale);
        if (h->entries[i].count < 1) {
            /* Remove this entry */
            free(h->entries[i].key_data);
            h->entries[i].key_data = NULL;
            h->entries[i].key_len = 0;
            h->entries[i].count = 0;
            h->len--;
            removed++;
        }
    }
    return removed;
}

void sg_anomaly_model_decay(sg_anomaly_model_t *model, double scale)
{
    if (!model || scale <= 0.0 || scale >= 1.0) return;

    hash_decay(&model->uni, scale);
    hash_decay(&model->bi, scale);
    hash_decay(&model->tri, scale);
    hash_decay(&model->quad, scale);
    hash_decay(&model->bi_ctx, scale);
    hash_decay(&model->tri_ctx, scale);
    hash_decay(&model->quad_ctx, scale);

    /* Recalculate totals (approximate after decay) */
    model->total_uni = model->uni.total;
    model->total_bi = model->bi.total;
    model->total_tri = model->tri.total;
    model->total_quad = model->quad.total;
    model->vocab_size = model->uni.len;
}

/* Remove entries with count less than min_count from a hash table.
 * Returns number of entries removed. */
static size_t hash_prune(hash_t *h, size_t min_count)
{
    if (!h || min_count == 0) return 0;

    size_t removed = 0;
    for (size_t i = 0; i < h->capacity; i++) {
        if (h->entries[i].key_data == NULL) continue;
        if (h->entries[i].count < min_count) {
            free(h->entries[i].key_data);
            h->entries[i].key_data = NULL;
            h->entries[i].key_len = 0;
            h->entries[i].count = 0;
            h->len--;
            removed++;
        }
    }
    return removed;
}

size_t sg_anomaly_model_prune(sg_anomaly_model_t *model, size_t min_count)
{
    if (!model || min_count == 0) return 0;

    size_t removed = 0;
    removed += hash_prune(&model->uni, min_count);
    removed += hash_prune(&model->bi, min_count);
    removed += hash_prune(&model->tri, min_count);
    removed += hash_prune(&model->quad, min_count);
    removed += hash_prune(&model->bi_ctx, min_count);
    removed += hash_prune(&model->tri_ctx, min_count);
    removed += hash_prune(&model->quad_ctx, min_count);

    /* Recalculate totals */
    model->total_uni = model->uni.total;
    model->total_bi = model->bi.total;
    model->total_tri = model->tri.total;
    model->total_quad = model->quad.total;
    model->vocab_size = model->uni.len;

    return removed;
}

/* Compact a hash table by rehashing to a smaller capacity if load factor is low.
 * Returns true if compaction happened, false otherwise. */
static bool hash_compact(hash_t *h)
{
    if (!h || h->capacity <= 16) return false;

    double load = (double)h->len / (double)h->capacity;
    if (load >= 0.25) return false;

    /* Calculate new capacity: smallest power of 2 >= len * 2 (for 0.5 load target) */
    size_t new_cap = 16;
    while (new_cap < h->len * 2 && new_cap < h->capacity / 2) {
        new_cap *= 2;
    }
    if (new_cap >= h->capacity) return false;

    hash_entry_t *new_entries = calloc(new_cap, sizeof(new_entries[0]));
    if (!new_entries) return false;

    /* Rehash all entries */
    for (size_t i = 0; i < h->capacity; i++) {
        if (h->entries[i].key_data == NULL) continue;

        size_t pos = hash_key_bytes(h->entries[i].key_data,
                                    h->entries[i].key_len, new_cap);
        for (size_t probe = 0; probe < new_cap; probe++) {
            size_t idx = (pos + probe) & (new_cap - 1);
            if (new_entries[idx].key_data == NULL) {
                new_entries[idx].key_data = h->entries[i].key_data;
                new_entries[idx].key_len = h->entries[i].key_len;
                new_entries[idx].count = h->entries[i].count;
                break;
            }
        }
    }

    free(h->entries);
    h->entries = new_entries;
    h->capacity = new_cap;
    return true;
}

bool sg_anomaly_model_compact(sg_anomaly_model_t *model)
{
    if (!model) return false;

    bool did_compact = false;
    did_compact |= hash_compact(&model->uni);
    did_compact |= hash_compact(&model->bi);
    did_compact |= hash_compact(&model->tri);
    did_compact |= hash_compact(&model->quad);
    did_compact |= hash_compact(&model->bi_ctx);
    did_compact |= hash_compact(&model->tri_ctx);
    did_compact |= hash_compact(&model->quad_ctx);

    return did_compact;
}
