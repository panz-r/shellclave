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
#include <draugr/ht.h>
#define XXH_STATIC_LINKING_ONLY
#include <xxhash.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>

/* ============================================================
 * COUNT TABLE HELPERS (wrapping draugr ht_table_t)
 *
 * Maps byte[] key -> int64_t count using Robin-Hood probing with
 * graveyard tombstones. Hash via xxhash3.
 * ============================================================ */

static uint64_t anomaly_hash_fn(const void *key, size_t key_len, void *user_ctx) {
    (void)user_ctx;
    return XXH3_64bits(key, key_len);
}

static ht_table_t *count_table_create(void) {
    return ht_create(NULL, anomaly_hash_fn, NULL, NULL);
}

static bool count_inc(ht_table_t *t, const char *key, size_t key_len,
                       int64_t inc, size_t *total) {
    if (!t) return false;
    uint64_t hash = anomaly_hash_fn(key, key_len, NULL);
    bool ok;
    ht_inc_with_hash(t, hash, key, key_len, inc, &ok);
    if (!ok) return false;
    *total += (size_t)inc;
    return true;
}

static size_t count_get(const ht_table_t *t, const char *key, size_t key_len) {
    size_t val_len = 0;
    const void *found = ht_find(t, key, key_len, &val_len);
    if (found && val_len == sizeof(int64_t))
        return (size_t)(*(const int64_t *)found);
    return 0;
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
    ht_table_t *uni;         /* unigram counts */
    ht_table_t *bi;          /* bigram counts: key = "prev\0curr" */
    ht_table_t *tri;         /* trigram counts: key = "p2\0p1\0curr" */
    ht_table_t *quad;        /* 4-gram counts: key = "p3\0p2\0p1\0curr" */
    ht_table_t *bi_ctx;      /* bigram context totals: key = "prev\0", value = sum */
    ht_table_t *tri_ctx;     /* trigram context totals: key = "p2\0p1\0", value = sum */
    ht_table_t *quad_ctx;    /* 4-gram context totals: key = "p3\0p2\0p1\0", value = sum */
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
    m->uni     = count_table_create();
    m->bi      = count_table_create();
    m->tri     = count_table_create();
    m->quad    = count_table_create();
    m->bi_ctx  = count_table_create();
    m->tri_ctx = count_table_create();
    m->quad_ctx = count_table_create();
    if (!m->uni || !m->bi || !m->tri || !m->quad ||
        !m->bi_ctx || !m->tri_ctx || !m->quad_ctx) {
        ht_destroy(m->uni);     ht_destroy(m->bi);
        ht_destroy(m->tri);     ht_destroy(m->quad);
        ht_destroy(m->bi_ctx);  ht_destroy(m->tri_ctx);
        ht_destroy(m->quad_ctx);
        free(m);
        return NULL;
    }
    return m;
}

void sg_anomaly_model_free(sg_anomaly_model_t *model)
{
    if (!model) return;
    ht_destroy(model->uni);
    ht_destroy(model->bi);
    ht_destroy(model->tri);
    ht_destroy(model->quad);
    ht_destroy(model->bi_ctx);
    ht_destroy(model->tri_ctx);
    ht_destroy(model->quad_ctx);
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
 * PROBABILITY CALCULATION - Kneser-Ney with 4-gram backoff
 *
 * Compute log P(curr | p3, p2, p1) in bits using KN discounting.
 * Backoff chain: 4-gram -> trigram -> bigram -> unigram -> UNK.
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
static size_t count_unique_continuations(const ht_table_t *t,
                                          const char *ctx, size_t ctx_len)
{
    size_t count = 0;
    ht_iter_t iter = ht_iter_begin(t);
    const void *key;
    size_t key_len;
    const void *val;
    size_t val_len;
    while (ht_iter_next((ht_table_t *)t, &iter, &key, &key_len, &val, &val_len)) {
        if (key_len < ctx_len) continue;
        if (memcmp(key, ctx, ctx_len) == 0)
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
                                const ht_table_t *n_table,
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
    double p_lower = lambda * exp(lower_logprob * M_LN2);  /* convert bits->prob */

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
    size_t uni_count = count_get(m->uni, curr, strlen(curr) + 1);
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
    size_t bi_count = key_len > 0 ? count_get(m->bi, key, key_len) : 0;
    double bigram_lp;
    if (bi_count > 0) {
        ctx_len = build_bigram_ctx(ctx, sizeof(ctx), p1);
        size_t bi_ctx_total = ctx_len > 0 ? count_get(m->bi_ctx, ctx, ctx_len) : 0;
        if (bi_ctx_total == 0) bi_ctx_total = bi_count;
        bigram_lp = kn_level_logprob(m, bi_count, bi_ctx_total,
                                      m->bi, ctx, ctx_len, unigram_lp);
    } else {
        bigram_lp = unigram_lp;
    }

    /* === Level 3: Trigram === */
    key_len = build_trigram_key(key, sizeof(key), p2, p1, curr);
    size_t tri_count = key_len > 0 ? count_get(m->tri, key, key_len) : 0;
    double trigram_lp;
    if (tri_count > 0) {
        ctx_len = build_trigram_ctx(ctx, sizeof(ctx), p2, p1);
        size_t tri_ctx_total = ctx_len > 0 ? count_get(m->tri_ctx, ctx, ctx_len) : 0;
        if (tri_ctx_total == 0) tri_ctx_total = tri_count;
        trigram_lp = kn_level_logprob(m, tri_count, tri_ctx_total,
                                       m->tri, ctx, ctx_len, bigram_lp);
    } else {
        trigram_lp = bigram_lp;
    }

    /* === Level 4: 4-gram === */
    key_len = build_4gram_key(key, sizeof(key), p3, p2, p1, curr);
    size_t quad_count = key_len > 0 ? count_get(m->quad, key, key_len) : 0;
    if (quad_count > 0) {
        ctx_len = build_4gram_ctx(ctx, sizeof(ctx), p3, p2, p1);
        size_t quad_ctx_total = ctx_len > 0 ? count_get(m->quad_ctx, ctx, ctx_len) : 0;
        if (quad_ctx_total == 0) quad_ctx_total = quad_count;
        return kn_level_logprob(m, quad_count, quad_ctx_total,
                                 m->quad, ctx, ctx_len, trigram_lp);
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
 * This is intentional -- the model learns from partial sequences.
 * ============================================================ */

void sg_anomaly_update(sg_anomaly_model_t *model,
                        const char **seq, size_t len)
{
    if (!model || !seq || len == 0) return;

    /* Dummy total for context tables (we don't track their totals separately) */
    size_t _ctx_total = 0;
    (void)_ctx_total;

    /* Update unigrams */
    for (size_t i = 0; i < len; i++) {
        size_t cmd_len = strlen(seq[i]) + 1;
        /* Check if command is already known */
        size_t existing = count_get(model->uni, seq[i], cmd_len);
        if (existing > 0) {
            /* Known command - increment normally */
            if (!count_inc(model->uni, seq[i], cmd_len, 1, &model->total_uni))
                model->oom = true;
        } else {
            /* New command - increment UNK count */
            model->unk_count++;
            /* Also add to vocabulary (promote after first sighting) */
            if (!count_inc(model->uni, seq[i], cmd_len, 1, &model->total_uni))
                model->oom = true;
        }
    }

    /* Update bigrams and their context totals */
    for (size_t i = 1; i < len; i++) {
        char key[512];
        size_t key_len = build_bigram_key(key, sizeof(key), seq[i-1], seq[i]);
        if (key_len > 0) {
            if (!count_inc(model->bi, key, key_len, 1, &model->total_bi))
                model->oom = true;
            char ctx[256];
            size_t ctx_len = build_bigram_ctx(ctx, sizeof(ctx), seq[i-1]);
            if (ctx_len > 0) {
                if (!count_inc(model->bi_ctx, ctx, ctx_len, 1, &_ctx_total))
                    model->oom = true;
            }
        }
    }

    /* Update trigrams and their context totals */
    for (size_t i = 2; i < len; i++) {
        char key[1024];
        size_t key_len = build_trigram_key(key, sizeof(key), seq[i-2], seq[i-1], seq[i]);
        if (key_len > 0) {
            if (!count_inc(model->tri, key, key_len, 1, &model->total_tri))
                model->oom = true;
            char ctx[512];
            size_t ctx_len = build_trigram_ctx(ctx, sizeof(ctx), seq[i-2], seq[i-1]);
            if (ctx_len > 0) {
                if (!count_inc(model->tri_ctx, ctx, ctx_len, 1, &_ctx_total))
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
            if (!count_inc(model->quad, key, key_len, 1, &model->total_quad))
                model->oom = true;
            char ctx[1024];
            size_t ctx_len = build_4gram_ctx(ctx, sizeof(ctx),
                                              seq[i-3], seq[i-2], seq[i-1]);
            if (ctx_len > 0) {
                if (!count_inc(model->quad_ctx, ctx, ctx_len, 1, &_ctx_total))
                    model->oom = true;
            }
        }
    }

    model->vocab_size = ht_size(model->uni);
}

/* ============================================================
 * SERIALISATION - Binary Format v3
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
 * bi_ctx and tri_ctx totals are NOT serialised -- rebuilt from bi/tri on load.
 * ============================================================ */

#define BINARY_TYPE_UNI   1
#define BINARY_TYPE_BI    2
#define BINARY_TYPE_TRI   3
#define BINARY_TYPE_QUAD  4

static int save_table(FILE *f, ht_table_t *t, uint8_t type)
{
    ht_iter_t iter = ht_iter_begin(t);
    const void *key;
    size_t key_len;
    const void *val;
    size_t val_len;
    uint8_t nl = '\n';
    while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
        if (val_len != sizeof(int64_t)) continue;
        int64_t count_i64 = *(const int64_t *)val;
        uint32_t kl = (uint32_t)key_len;
        uint64_t count_u64 = (uint64_t)count_i64;
        if (fwrite(&type, 1, 1, f) != 1 ||
            fwrite(&kl, 4, 1, f) != 1 ||
            fwrite(key, 1, kl, f) != kl ||
            fwrite(&count_u64, 8, 1, f) != 1 ||
            fwrite(&nl, 1, 1, f) != 1)
            return -1;
    }
    return 0;
}

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

    if (save_table(f, model->uni, BINARY_TYPE_UNI) < 0 ||
        save_table(f, model->bi, BINARY_TYPE_BI) < 0 ||
        save_table(f, model->tri, BINARY_TYPE_TRI) < 0 ||
        save_table(f, model->quad, BINARY_TYPE_QUAD) < 0) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int sg_anomaly_load(sg_anomaly_model_t *model, const char *path)
{
    if (!model || !path) { errno = EINVAL; return -1; }

    ht_destroy(model->uni);
    ht_destroy(model->bi);
    ht_destroy(model->tri);
    ht_destroy(model->quad);
    ht_destroy(model->bi_ctx);
    ht_destroy(model->tri_ctx);
    ht_destroy(model->quad_ctx);
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = 0;
    model->unk_count = 0;
    model->oom = false;
    model->uni     = count_table_create();
    model->bi      = count_table_create();
    model->tri     = count_table_create();
    model->quad    = count_table_create();
    model->bi_ctx  = count_table_create();
    model->tri_ctx = count_table_create();
    model->quad_ctx = count_table_create();

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
                /* Totals are rebuilt from binary entries by count_inc;
                 * just keep vocab_size from header. */
                (void)tu; (void)tb; (void)tt; (void)tq;
                model->vocab_size = vocab;
            }
            if (n >= 9) {
                model->unk_count = unk;
            }
        }
    }

    /* Dummy total for context table increments during load */
    size_t _ctx_total = 0;
    (void)_ctx_total;

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
            if (!count_inc(model->uni, keybuf, key_len, (int64_t)count, &model->total_uni))
                model->oom = true;
        } else if (type == BINARY_TYPE_BI) {
            if (!count_inc(model->bi, keybuf, key_len, (int64_t)count, &model->total_bi))
                model->oom = true;
            /* Rebuild bigram context total */
            size_t ctx_len = extract_bigram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!count_inc(model->bi_ctx, keybuf, ctx_len, (int64_t)count, &_ctx_total))
                    model->oom = true;
            }
        } else if (type == BINARY_TYPE_TRI) {
            if (!count_inc(model->tri, keybuf, key_len, (int64_t)count, &model->total_tri))
                model->oom = true;
            /* Rebuild trigram context total */
            size_t ctx_len = extract_trigram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!count_inc(model->tri_ctx, keybuf, ctx_len, (int64_t)count, &_ctx_total))
                    model->oom = true;
            }
        } else if (type == BINARY_TYPE_QUAD) {
            if (!count_inc(model->quad, keybuf, key_len, (int64_t)count, &model->total_quad))
                model->oom = true;
            /* Rebuild 4-gram context total */
            size_t ctx_len = extract_4gram_ctx_len(keybuf, key_len);
            if (ctx_len > 0) {
                if (!count_inc(model->quad_ctx, keybuf, ctx_len, (int64_t)count, &_ctx_total))
                    model->oom = true;
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
    return model ? ht_size(model->uni) : 0;
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
    return count_get(model->uni, cmd, cmd_len);
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
    return key_len > 0 ? count_get(model->bi, key, key_len) : 0;
}

size_t sg_anomaly_tri_count(const sg_anomaly_model_t *model,
                              const char *p2, const char *p1, const char *curr)
{
    if (!model || !p2 || !p1 || !curr) return 0;
    char key[1024];
    size_t key_len = build_trigram_key(key, sizeof(key), p2, p1, curr);
    return key_len > 0 ? count_get(model->tri, key, key_len) : 0;
}

size_t sg_anomaly_quad_count(const sg_anomaly_model_t *model,
                               const char *p3, const char *p2,
                               const char *p1, const char *curr)
{
    if (!model || !p3 || !p2 || !p1 || !curr) return 0;
    char key[2048];
    size_t key_len = build_4gram_key(key, sizeof(key), p3, p2, p1, curr);
    return key_len > 0 ? count_get(model->quad, key, key_len) : 0;
}

size_t sg_anomaly_total_contexts(const sg_anomaly_model_t *model)
{
    if (!model) return 0;
    return ht_size(model->bi_ctx) + ht_size(model->tri_ctx) + ht_size(model->quad_ctx);
}

bool sg_anomaly_has_observed(const sg_anomaly_model_t *model,
                               const char **seq, size_t len)
{
    if (!model || !seq || len == 0) return false;
    /* Check unigrams first */
    for (size_t i = 0; i < len; i++) {
        if (seq[i] && count_get(model->uni, seq[i], strlen(seq[i]) + 1) > 0)
            return true;
    }
    return false;
}

void sg_anomaly_reset(sg_anomaly_model_t *model)
{
    if (!model) return;
    ht_destroy(model->uni);
    ht_destroy(model->bi);
    ht_destroy(model->tri);
    ht_destroy(model->quad);
    ht_destroy(model->bi_ctx);
    ht_destroy(model->tri_ctx);
    ht_destroy(model->quad_ctx);
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = 0;
    model->unk_count = 0;
    model->oom = false;
    model->uni     = count_table_create();
    model->bi      = count_table_create();
    model->tri     = count_table_create();
    model->quad    = count_table_create();
    model->bi_ctx  = count_table_create();
    model->tri_ctx = count_table_create();
    model->quad_ctx = count_table_create();
}

/* Apply decay to a hash table: multiply all counts by scale factor.
 * Entries with count < 0.5 are removed (effectively zero).
 * Uses two-pass: collect keys to remove, then remove them. */
static size_t table_decay(ht_table_t *t, double scale)
{
    if (!t || scale <= 0.0 || scale >= 1.0) return 0;

    size_t remove_cap = 64;
    size_t remove_len = 0;
    struct { const void *key; size_t key_len; } *remove_list =
        malloc(remove_cap * sizeof(*remove_list));
    if (!remove_list) return 0;

    ht_iter_t iter = ht_iter_begin(t);
    const void *key; size_t key_len; const void *val; size_t val_len;
    while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
        if (val_len != sizeof(int64_t)) continue;
        int64_t old_count = *(const int64_t *)val;
        int64_t new_count = (int64_t)((double)old_count * scale);
        if (new_count < 1) {
            if (remove_len >= remove_cap) {
                remove_cap *= 2;
                void *tmp = realloc(remove_list, remove_cap * sizeof(*remove_list));
                if (!tmp) break;
                remove_list = tmp;
            }
            remove_list[remove_len].key = key;
            remove_list[remove_len].key_len = key_len;
            remove_len++;
        } else {
            uint64_t hash = anomaly_hash_fn(key, key_len, NULL);
            ht_upsert_with_hash(t, hash, key, key_len, &new_count, sizeof(new_count));
        }
    }
    for (size_t i = 0; i < remove_len; i++)
        ht_remove(t, remove_list[i].key, remove_list[i].key_len);
    free(remove_list);
    return remove_len;
}

void sg_anomaly_model_decay(sg_anomaly_model_t *model, double scale)
{
    if (!model || scale <= 0.0 || scale >= 1.0) return;

    table_decay(model->uni, scale);
    table_decay(model->bi, scale);
    table_decay(model->tri, scale);
    table_decay(model->quad, scale);
    table_decay(model->bi_ctx, scale);
    table_decay(model->tri_ctx, scale);
    table_decay(model->quad_ctx, scale);

    /* Recalculate totals (approximate after decay) */
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = ht_size(model->uni);

    /* Re-sum totals from tables */
    {
        ht_iter_t iter;
        const void *k; size_t kl; const void *v; size_t vl;
        iter = ht_iter_begin(model->uni);
        while (ht_iter_next(model->uni, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_uni += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->bi);
        while (ht_iter_next(model->bi, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_bi += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->tri);
        while (ht_iter_next(model->tri, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_tri += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->quad);
        while (ht_iter_next(model->quad, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_quad += (size_t)(*(const int64_t *)v);
        }
    }
}

/* Remove entries with count less than min_count from a hash table.
 * Returns number of entries removed.
 * Uses two-pass: collect keys to remove, then remove them. */
static size_t table_prune(ht_table_t *t, size_t min_count)
{
    if (!t || min_count == 0) return 0;

    size_t remove_cap = 64;
    size_t remove_len = 0;
    struct { const void *key; size_t key_len; } *remove_list =
        malloc(remove_cap * sizeof(*remove_list));
    if (!remove_list) return 0;

    ht_iter_t iter = ht_iter_begin(t);
    const void *key; size_t key_len; const void *val; size_t val_len;
    while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
        if (val_len != sizeof(int64_t)) continue;
        int64_t count = *(const int64_t *)val;
        if ((size_t)count < min_count) {
            if (remove_len >= remove_cap) {
                remove_cap *= 2;
                void *tmp = realloc(remove_list, remove_cap * sizeof(*remove_list));
                if (!tmp) break;
                remove_list = tmp;
            }
            remove_list[remove_len].key = key;
            remove_list[remove_len].key_len = key_len;
            remove_len++;
        }
    }
    for (size_t i = 0; i < remove_len; i++)
        ht_remove(t, remove_list[i].key, remove_list[i].key_len);
    free(remove_list);
    return remove_len;
}

size_t sg_anomaly_model_prune(sg_anomaly_model_t *model, size_t min_count)
{
    if (!model || min_count == 0) return 0;

    size_t removed = 0;
    removed += table_prune(model->uni, min_count);
    removed += table_prune(model->bi, min_count);
    removed += table_prune(model->tri, min_count);
    removed += table_prune(model->quad, min_count);
    removed += table_prune(model->bi_ctx, min_count);
    removed += table_prune(model->tri_ctx, min_count);
    removed += table_prune(model->quad_ctx, min_count);

    /* Recalculate totals */
    model->total_uni = 0;
    model->total_bi = 0;
    model->total_tri = 0;
    model->total_quad = 0;
    model->vocab_size = ht_size(model->uni);

    /* Re-sum totals from tables */
    {
        ht_iter_t iter;
        const void *k; size_t kl; const void *v; size_t vl;
        iter = ht_iter_begin(model->uni);
        while (ht_iter_next(model->uni, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_uni += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->bi);
        while (ht_iter_next(model->bi, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_bi += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->tri);
        while (ht_iter_next(model->tri, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_tri += (size_t)(*(const int64_t *)v);
        }
        iter = ht_iter_begin(model->quad);
        while (ht_iter_next(model->quad, &iter, &k, &kl, &v, &vl)) {
            if (vl == sizeof(int64_t))
                model->total_quad += (size_t)(*(const int64_t *)v);
        }
    }

    return removed;
}

bool sg_anomaly_model_compact(sg_anomaly_model_t *model)
{
    if (!model) return false;

    bool did_compact = false;
    ht_compact(model->uni);
    ht_compact(model->bi);
    ht_compact(model->tri);
    ht_compact(model->quad);
    ht_compact(model->bi_ctx);
    ht_compact(model->tri_ctx);
    ht_compact(model->quad_ctx);
    /* ht_compact returns void, assume compaction happened if tables exist */
    did_compact = (model->uni != NULL);

    return did_compact;
}
