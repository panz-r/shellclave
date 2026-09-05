/*
 * sg_anomaly.c - Statistical Anomaly Detection
 *
 * 4-gram language model with Kneser-Ney absolute discounting and
 * backoff to trigram/bigram/unigram.  All strings are owned by the model.
 * Context totals are maintained incrementally for O(1) probability lookups.
 *
 * Kneser-Ney discounting:
 *   Observed n-grams:
 *     P_KN(w|ctx) = max(0, c - D) / c_ctx
 *                  + D * |unique_cont| / c_ctx * P_KN_lower(w|ctx')
 *   Unobserved n-grams: back off to lower-order model.
 *   D = absolute discount (default 0.5)
 *
 * Serialisation uses a binary format with length-prefixed keys:
 *   Header (text):  # anomaly-model-v6\n
 *                   # alpha unk_prior D total_uni total_bi total_tri total_quad
 * vocab_size unk_count\n Entry (binary): uint8_t type; uint32_t key_len;
 * uint8_t key[key_len]; uint64_t count; uint8_t nl; type values: 1='U', 2='B',
 * 3='T', 4='Q'
 */

#include "sg_anomaly.h"
#include "sg_anomaly_internal.h"
#include "shell_netstring.h"
#include <draugr/ht.h>
#define XXH_STATIC_LINKING_ONLY
#include "sg_alloc.h"
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xxhash.h>

#ifdef SHELLGATE_TEST_ANOMALY_OPS
#include "test_sg_failures.h"
#define SG_ANOMALY_OP_FAILED() sg_test_anomaly_op_should_fail()
#else
#define SG_ANOMALY_OP_FAILED() false
#endif

/* A key is a concatenation of up to four canonical netstrings. A maximum
 * payload needs four decimal digits, a colon, and a trailing comma. */
#define SG_ANOMALY_MAX_KEY_LENGTH (4U * (SG_ANOMALY_MAX_COMMAND_LENGTH + 6U))

static sg_anomaly_status_t anomaly_status_from_errno(int error) {
  switch (error) {
  case EINVAL:
    return SG_ANOMALY_ERR_INVALID;
  case ENOMEM:
    return SG_ANOMALY_ERR_MEMORY;
  case EPROTO:
    return SG_ANOMALY_ERR_FORMAT;
  case EOVERFLOW:
    return SG_ANOMALY_ERR_LIMIT;
  default:
    return SG_ANOMALY_ERR_IO;
  }
}

static sg_anomaly_status_t anomaly_failure_status(void) {
  if (errno == 0)
    errno = EIO;
  return anomaly_status_from_errno(errno);
}

/* --- COUNT TABLE HELPERS --- */

static uint64_t anomaly_hash_fn(const void *key, size_t key_len,
                                void *user_ctx) {
  (void)user_ctx;
  return XXH3_64bits(key, key_len);
}

static ht_table_t *count_table_create(void) {
  if (SG_ANOMALY_OP_FAILED())
    return NULL;
  return ht_create(NULL, anomaly_hash_fn, NULL, NULL);
}

static bool count_inc(ht_table_t *t, const char *key, size_t key_len,
                      int64_t inc, size_t *total) {
  if (!t)
    return false;
  if (SG_ANOMALY_OP_FAILED())
    return false;
  uint64_t hash = anomaly_hash_fn(key, key_len, NULL);
  bool ok;
  ht_inc_with_hash(t, hash, key, key_len, inc, &ok);
  if (!ok)
    return false;
  *total += (size_t)inc;
  return true;
}

static int64_t count_value(const void *value) {
  int64_t count;
  memcpy(&count, value, sizeof(count));
  return count;
}

static size_t count_get(const ht_table_t *t, const char *key, size_t key_len) {
  size_t val_len = 0;
  const void *found = ht_find(t, key, key_len, &val_len);
  if (found && val_len == sizeof(int64_t))
    return (size_t)count_value(found);
  return 0;
}

/* --- KEY BUILDING HELPERS --- */

typedef sg_anomaly_item_view_t anomaly_bytes_t;

/* Internal keys use the same unambiguous netstring representation as the
 * public input.  This is required for payloads containing NUL bytes. */
static size_t build_key(char *buf, size_t buf_size,
                        const anomaly_bytes_t *items, size_t item_count) {
  size_t used = 0;
  if (!buf || !items || item_count == 0)
    return 0;
  for (size_t i = 0; i < item_count; i++) {
    if (!items[i].data || items[i].length == 0 || used >= buf_size)
      return 0;
    size_t record_length = 0;
    if (shell_netstring_encoded_length(items[i].length, &record_length) !=
            SHELL_NETSTRING_OK ||
        record_length > buf_size - used)
      return 0;
    size_t written = 0;
    if (shell_netstring_write(buf + used, buf_size - used, items[i].data,
                              items[i].length, &written) != SHELL_NETSTRING_OK)
      return 0;
    used += written;
  }
  return used;
}

static size_t serialized_key_prefix_length(const char *key, size_t length,
                                           size_t components) {
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, key, length) != SHELL_NETSTRING_OK)
    return 0;
  shell_netstring_view_t view;
  for (size_t i = 0; i < components; i++) {
    if (shell_netstring_iter_next(&iter, &view) != SHELL_NETSTRING_OK)
      return 0;
  }
  return iter.offset;
}

/* --- MODEL --- */

struct sg_anomaly_model {
  ht_table_t *uni;    /* unigram counts: one canonical netstring key */
  ht_table_t *bi;     /* bigram counts: two concatenated netstring keys */
  ht_table_t *tri;    /* trigram counts: three concatenated netstring keys */
  ht_table_t *quad;   /* 4-gram counts: four concatenated netstring keys */
  ht_table_t *bi_ctx; /* bigram context totals */
  ht_table_t *tri_ctx;
  ht_table_t *quad_ctx;
  size_t total_uni;
  size_t total_bi;
  size_t total_tri;
  size_t total_quad;
  double alpha;       /* Dirichlet smoothing (used when KN data insufficient) */
  double unk_prior;   /* fallback log-prob for unseen commands */
  double kn_discount; /* Kneser-Ney absolute discount (default 0.5) */
  size_t vocab_size;  /* number of unique unigrams */
  bool oom;           /* true if any allocation failed */
  size_t unk_count;   /* count of unseen commands for probability estimation */
};

void sg_anomaly_config_default(sg_anomaly_config_t *config) {
  if (!config)
    return;
  config->alpha = 0.1;
  config->unknown_log_prior = -10.0;
}

static sg_anomaly_model_t *anomaly_model_new(double alpha, double unk_prior) {
  sg_anomaly_model_t *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
  m->alpha = alpha;
  m->unk_prior = unk_prior;
  m->kn_discount = 0.5;
  m->vocab_size = 0;
  m->oom = false;
  m->uni = count_table_create();
  m->bi = count_table_create();
  m->tri = count_table_create();
  m->quad = count_table_create();
  m->bi_ctx = count_table_create();
  m->tri_ctx = count_table_create();
  m->quad_ctx = count_table_create();
  if (!m->uni || !m->bi || !m->tri || !m->quad || !m->bi_ctx || !m->tri_ctx ||
      !m->quad_ctx) {
    ht_destroy(m->uni);
    ht_destroy(m->bi);
    ht_destroy(m->tri);
    ht_destroy(m->quad);
    ht_destroy(m->bi_ctx);
    ht_destroy(m->tri_ctx);
    ht_destroy(m->quad_ctx);
    free(m);
    return NULL;
  }
  return m;
}

sg_anomaly_model_t *
sg_anomaly_model_new_with_config(const sg_anomaly_config_t *config) {
  sg_anomaly_config_t defaults;
  if (!config) {
    sg_anomaly_config_default(&defaults);
    config = &defaults;
  }
  if (!isfinite(config->alpha) || config->alpha <= 0.0 ||
      !isfinite(config->unknown_log_prior))
    return NULL;
  return anomaly_model_new(config->alpha, config->unknown_log_prior);
}

sg_anomaly_model_t *sg_anomaly_model_new(void) {
  return sg_anomaly_model_new_with_config(NULL);
}

void sg_anomaly_model_free(sg_anomaly_model_t *model) {
  if (!model)
    return;
  ht_destroy(model->uni);
  ht_destroy(model->bi);
  ht_destroy(model->tri);
  ht_destroy(model->quad);
  ht_destroy(model->bi_ctx);
  ht_destroy(model->tri_ctx);
  ht_destroy(model->quad_ctx);
  free(model);
}

bool sg_anomaly_model_had_error(const sg_anomaly_model_t *model) {
  return model ? model->oom : false;
}

void sg_anomaly_model_clear_error(sg_anomaly_model_t *model) {
  if (model)
    model->oom = false;
}

/* --- PROBABILITY CALCULATION --- */

/* Compute log probability of unknown command in bits */
static double unk_logprob(const sg_anomaly_model_t *m) {
  /* P_unk = (unk_count + alpha) / (total_uni + unk_count + alpha * (V + 1)) */
  double V_plus_1 = (double)m->vocab_size + 1.0;
  double numer = (double)m->unk_count + m->alpha;
  double denom = (double)m->total_uni + m->unk_count + m->alpha * V_plus_1;
  if (denom <= 0)
    return m->unk_prior;             /* fallback if no data */
  return log(numer / denom) / M_LN2; /* in bits */
}

/* Count number of unique n-gram continuations from a context hash.
 * This scans the hash table for entries whose key starts with ctx.
 * Used for KN discount weight computation.
 * For large tables this is O(n); acceptable for anomaly model sizes. */
static size_t count_unique_continuations(const ht_table_t *t, const char *ctx,
                                         size_t ctx_len) {
  size_t count = 0;
  ht_iter_t iter = ht_iter_begin(t);
  const void *key;
  size_t key_len;
  const void *val;
  size_t val_len;
  while (ht_iter_next((ht_table_t *)t, &iter, &key, &key_len, &val, &val_len)) {
    if (key_len < ctx_len)
      continue;
    if (memcmp(key, ctx, ctx_len) == 0)
      count++;
  }
  return count;
}

/*
 * KN probability at a given n-gram level.
 *
 * key, key_len:    the full n-gram key (concatenated canonical netstrings)
 * ctx, ctx_len:    its canonical netstring context prefix
 * n_count:         count of this specific n-gram
 * ctx_total:       sum of all counts sharing this context
 * n_table:         the hash table to count unique continuations from
 * Returns log probability in bits.
 */
static double kn_level_logprob(const sg_anomaly_model_t *m, size_t n_count,
                               size_t ctx_total, const ht_table_t *n_table,
                               const char *ctx, size_t ctx_len,
                               double lower_logprob) {
  double D = m->kn_discount;

  if (ctx_total == 0)
    return lower_logprob;

  /* Number of unique continuations from this context */
  size_t unique_cont = count_unique_continuations(n_table, ctx, ctx_len);

  /* Discounted probability mass for observed n-gram */
  double disc_count = (double)n_count - D;
  if (disc_count < 0)
    disc_count = 0;

  /* Interpolation weight (probability mass for lower-order) */
  double lambda = D * (double)unique_cont / (double)ctx_total;

  /* Combined probability */
  double p_observed = disc_count / (double)ctx_total;
  double p_lower = lambda * exp(lower_logprob * M_LN2); /* convert bits->prob */

  double p_total = p_observed + p_lower;
  if (p_total <= 0)
    return unk_logprob(m);
  return log(p_total) / M_LN2;
}

static double kn_logprob(const sg_anomaly_model_t *m, const anomaly_bytes_t *p3,
                         const anomaly_bytes_t *p2, const anomaly_bytes_t *p1,
                         const anomaly_bytes_t *curr) {
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  char ctx[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len, ctx_len;

  /* --- Level 1: Unigram (base) --- */
  key_len = build_key(key, sizeof(key), curr, 1);
  size_t uni_count = key_len > 0 ? count_get(m->uni, key, key_len) : 0;
  double unigram_lp;
  if (uni_count > 0) {
    double denom = (double)m->total_uni + m->alpha * (double)m->vocab_size;
    double numer = (double)uni_count + m->alpha;
    unigram_lp = log(numer / denom) / M_LN2;
  } else {
    unigram_lp = unk_logprob(m);
  }

  /* --- Level 2: Bigram --- */
  const anomaly_bytes_t bigram[] = {*p1, *curr};
  key_len = build_key(key, sizeof(key), bigram, 2);
  size_t bi_count = key_len > 0 ? count_get(m->bi, key, key_len) : 0;
  double bigram_lp;
  if (bi_count > 0) {
    ctx_len = build_key(ctx, sizeof(ctx), p1, 1);
    size_t bi_ctx_total = ctx_len > 0 ? count_get(m->bi_ctx, ctx, ctx_len) : 0;
    if (bi_ctx_total == 0)
      bi_ctx_total = bi_count;
    bigram_lp = kn_level_logprob(m, bi_count, bi_ctx_total, m->bi, ctx, ctx_len,
                                 unigram_lp);
  } else {
    bigram_lp = unigram_lp;
  }

  /* --- Level 3: Trigram --- */
  const anomaly_bytes_t trigram[] = {*p2, *p1, *curr};
  key_len = build_key(key, sizeof(key), trigram, 3);
  size_t tri_count = key_len > 0 ? count_get(m->tri, key, key_len) : 0;
  double trigram_lp;
  if (tri_count > 0) {
    ctx_len = build_key(ctx, sizeof(ctx), trigram, 2);
    size_t tri_ctx_total =
        ctx_len > 0 ? count_get(m->tri_ctx, ctx, ctx_len) : 0;
    if (tri_ctx_total == 0)
      tri_ctx_total = tri_count;
    trigram_lp = kn_level_logprob(m, tri_count, tri_ctx_total, m->tri, ctx,
                                  ctx_len, bigram_lp);
  } else {
    trigram_lp = bigram_lp;
  }

  /* --- Level 4: 4-gram --- */
  if (!p3)
    return trigram_lp;
  const anomaly_bytes_t quadgram[] = {*p3, *p2, *p1, *curr};
  key_len = build_key(key, sizeof(key), quadgram, 4);
  size_t quad_count = key_len > 0 ? count_get(m->quad, key, key_len) : 0;
  if (quad_count > 0) {
    ctx_len = build_key(ctx, sizeof(ctx), quadgram, 3);
    size_t quad_ctx_total =
        ctx_len > 0 ? count_get(m->quad_ctx, ctx, ctx_len) : 0;
    if (quad_ctx_total == 0)
      quad_ctx_total = quad_count;
    return kn_level_logprob(m, quad_count, quad_ctx_total, m->quad, ctx,
                            ctx_len, trigram_lp);
  }

  return trigram_lp;
}

/* --- SCORING --- */

static bool command_is_scorable(anomaly_bytes_t command) {
  return command.data && command.length != 0;
}

/* The length cap bounds the memory a single key can consume, so it constrains
 * what may be learned, not what may be scored. Scoring an over-long name is
 * safe: its n-gram keys never fit the key buffer, so it backs off to the
 * unknown-command probability and reads as highly anomalous. Rejecting it here
 * instead would return INFINITY and suppress detection entirely. */
static bool command_is_valid(anomaly_bytes_t command) {
  return command_is_scorable(command) &&
         command.length <= SG_ANOMALY_MAX_COMMAND_LENGTH;
}

static sg_anomaly_status_t netstring_status(shell_netstring_status_t status) {
  if (status == SHELL_NETSTRING_OK || status == SHELL_NETSTRING_DONE)
    return SG_ANOMALY_OK;
  return status == SHELL_NETSTRING_EOVERFLOW ? SG_ANOMALY_ERR_LIMIT
                                             : SG_ANOMALY_ERR_FORMAT;
}

static sg_anomaly_status_t validate_netseq(const char *netseq, size_t length,
                                           bool enforce_item_limit,
                                           size_t *count) {
  *count = 0;
  if (!netseq && length != 0)
    return SG_ANOMALY_ERR_FORMAT;
  shell_netstring_iter_t iter;
  shell_netstring_status_t net_status =
      shell_netstring_iter_init(&iter, netseq, length);
  if (net_status != SHELL_NETSTRING_OK)
    return netstring_status(net_status);
  shell_netstring_view_t view;
  while ((net_status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    if (view.payload_length == 0)
      return SG_ANOMALY_ERR_FORMAT;
    if (enforce_item_limit &&
        view.payload_length > SG_ANOMALY_MAX_COMMAND_LENGTH)
      return SG_ANOMALY_ERR_LIMIT;
    (*count)++;
  }
  return net_status == SHELL_NETSTRING_DONE ? SG_ANOMALY_OK
                                            : netstring_status(net_status);
}

sg_anomaly_status_t sg_anomaly_netseq_count(const char *netseq, size_t length,
                                            bool enforce_item_limit,
                                            size_t *count) {
  if (!count || !netseq)
    return SG_ANOMALY_ERR_INVALID;
  return validate_netseq(netseq, length, enforce_item_limit, count);
}

sg_anomaly_status_t
sg_anomaly_model_score_netseq(const sg_anomaly_model_t *model,
                              const char *netseq, size_t netseq_length,
                              double *score) {
  if (score)
    *score = INFINITY;
  if (!model || !netseq || !score)
    return SG_ANOMALY_ERR_INVALID;
  size_t count = 0;
  sg_anomaly_status_t status =
      validate_netseq(netseq, netseq_length, false, &count);
  if (status != SG_ANOMALY_OK)
    return status;
  if (count < 3 || model->total_uni == 0)
    return SG_ANOMALY_OK;
  anomaly_bytes_t window[4];
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, netseq, netseq_length) !=
      SHELL_NETSTRING_OK)
    return SG_ANOMALY_ERR_FORMAT;
  double total_bits = 0.0;
  size_t seen = 0, scored = 0;
  shell_netstring_view_t view;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    size_t slot = seen % 4;
    window[slot] = (anomaly_bytes_t){.data = (const char *)view.payload,
                                     .length = view.payload_length};
    seen++;
    if (seen >= 4) {
      total_bits -=
          kn_logprob(model, &window[(seen - 4) % 4], &window[(seen - 3) % 4],
                     &window[(seen - 2) % 4], &window[(seen - 1) % 4]);
      scored++;
    }
  }
  if (seen == 3) {
    total_bits -= kn_logprob(model, NULL, &window[0], &window[1], &window[2]);
    scored = 1;
  }
  *score = total_bits / (double)scored;
  return SG_ANOMALY_OK;
}

sg_anomaly_status_t sg_anomaly_model_update_netseq(sg_anomaly_model_t *model,
                                                   const char *netseq,
                                                   size_t netseq_length) {
  if (!model || !netseq)
    return SG_ANOMALY_ERR_INVALID;
  size_t count = 0;
  sg_anomaly_status_t status =
      validate_netseq(netseq, netseq_length, true, &count);
  if (status != SG_ANOMALY_OK)
    return status;
  anomaly_bytes_t window[4];
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, netseq, netseq_length) !=
      SHELL_NETSTRING_OK)
    return SG_ANOMALY_ERR_FORMAT;
  shell_netstring_view_t view;
  size_t seen = 0, ctx_total = 0;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    size_t slot = seen % 4;
    window[slot] = (anomaly_bytes_t){.data = (const char *)view.payload,
                                     .length = view.payload_length};
    const anomaly_bytes_t *curr = &window[slot];
    char key[SG_ANOMALY_MAX_KEY_LENGTH], ctx[SG_ANOMALY_MAX_KEY_LENGTH];
    size_t key_len = build_key(key, sizeof(key), curr, 1);
    if (key_len == 0)
      return SG_ANOMALY_ERR_LIMIT;
    if (count_get(model->uni, key, key_len) == 0)
      model->unk_count++;
    if (!count_inc(model->uni, key, key_len, 1, &model->total_uni))
      model->oom = true;
    seen++;
    if (seen >= 2) {
      const anomaly_bytes_t pair[] = {window[(seen - 2) % 4], *curr};
      key_len = build_key(key, sizeof(key), pair, 2);
      size_t ctx_len = build_key(ctx, sizeof(ctx), pair, 1);
      if (key_len == 0 || ctx_len == 0 ||
          !count_inc(model->bi, key, key_len, 1, &model->total_bi) ||
          !count_inc(model->bi_ctx, ctx, ctx_len, 1, &ctx_total))
        model->oom = true;
    }
    if (seen >= 3) {
      const anomaly_bytes_t triple[] = {window[(seen - 3) % 4],
                                        window[(seen - 2) % 4], *curr};
      key_len = build_key(key, sizeof(key), triple, 3);
      size_t ctx_len = build_key(ctx, sizeof(ctx), triple, 2);
      if (key_len == 0 || ctx_len == 0 ||
          !count_inc(model->tri, key, key_len, 1, &model->total_tri) ||
          !count_inc(model->tri_ctx, ctx, ctx_len, 1, &ctx_total))
        model->oom = true;
    }
    if (seen >= 4) {
      const anomaly_bytes_t quad[] = {window[(seen - 4) % 4],
                                      window[(seen - 3) % 4],
                                      window[(seen - 2) % 4], *curr};
      key_len = build_key(key, sizeof(key), quad, 4);
      size_t ctx_len = build_key(ctx, sizeof(ctx), quad, 3);
      if (key_len == 0 || ctx_len == 0 ||
          !count_inc(model->quad, key, key_len, 1, &model->total_quad) ||
          !count_inc(model->quad_ctx, ctx, ctx_len, 1, &ctx_total))
        model->oom = true;
    }
  }
  model->vocab_size = ht_size(model->uni);
  return model->oom ? SG_ANOMALY_ERR_MEMORY : SG_ANOMALY_OK;
}

/* --- SERIALISATION --- */

#define BINARY_TYPE_UNI 1
#define BINARY_TYPE_BI 2
#define BINARY_TYPE_TRI 3
#define BINARY_TYPE_QUAD 4

static int save_table(FILE *f, ht_table_t *t, uint8_t type) {
  ht_iter_t iter = ht_iter_begin(t);
  const void *key;
  size_t key_len;
  const void *val;
  size_t val_len;
  uint8_t nl = '\n';
  while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
    if (val_len != sizeof(int64_t))
      continue;
    int64_t count_i64 = count_value(val);
    uint32_t kl = (uint32_t)key_len;
    uint64_t count_u64 = (uint64_t)count_i64;
    if (fwrite(&type, 1, 1, f) != 1 || fwrite(&kl, 4, 1, f) != 1 ||
        fwrite(key, 1, kl, f) != kl || fwrite(&count_u64, 8, 1, f) != 1 ||
        fwrite(&nl, 1, 1, f) != 1)
      return -1;
  }
  return 0;
}

int sg_anomaly_write_stream(const sg_anomaly_model_t *model, FILE *f) {
  if (!model || !f) {
    errno = EINVAL;
    return -1;
  }
  if (fprintf(f, "# anomaly-model-v6\n") < 0 ||
      fprintf(f, "# %.17g %.17g %.17g %zu %zu %zu %zu %zu %zu\n", model->alpha,
              model->unk_prior, model->kn_discount, model->total_uni,
              model->total_bi, model->total_tri, model->total_quad,
              model->vocab_size, model->unk_count) < 0 ||
      save_table(f, model->uni, BINARY_TYPE_UNI) < 0 ||
      save_table(f, model->bi, BINARY_TYPE_BI) < 0 ||
      save_table(f, model->tri, BINARY_TYPE_TRI) < 0 ||
      save_table(f, model->quad, BINARY_TYPE_QUAD) < 0 || fflush(f) != 0)
    return -1;
  return 0;
}

sg_anomaly_status_t sg_anomaly_model_save(const sg_anomaly_model_t *model,
                                          const char *path) {
  if (!model || !path) {
    errno = EINVAL;
    return SG_ANOMALY_ERR_INVALID;
  }

  FILE *f = fopen(path, "wb");
  if (!f)
    return anomaly_failure_status();

  errno = 0;
  int result = sg_anomaly_write_stream(model, f);
  int saved_errno = errno;

  if (fclose(f) != 0) {
    result = -1;
    saved_errno = errno;
  }
  if (result == 0)
    return SG_ANOMALY_OK;
  errno = saved_errno;
  return anomaly_failure_status();
}

static bool serialized_key_valid(const char *key, size_t length,
                                 size_t components) {
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, key, length) != SHELL_NETSTRING_OK)
    return false;
  shell_netstring_view_t view;
  for (size_t i = 0; i < components; i++) {
    if (shell_netstring_iter_next(&iter, &view) != SHELL_NETSTRING_OK ||
        view.payload_length == 0 ||
        view.payload_length > SG_ANOMALY_MAX_COMMAND_LENGTH)
      return false;
  }
  return shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_DONE;
}

static bool serialized_line_end(const char *text) {
  return text[0] == '\0' || (text[0] == '\n' && text[1] == '\0') ||
         (text[0] == '\r' && text[1] == '\n' && text[2] == '\0');
}

static int load_anomaly_stream(sg_anomaly_model_t *model, FILE *f) {
  char line[256];
  if (!fgets(line, sizeof(line), f) ||
      (strcmp(line, "# anomaly-model-v6\n") != 0 &&
       strcmp(line, "# anomaly-model-v6\r\n") != 0)) {
    if (ferror(f))
      return -1;
    errno = EPROTO;
    return -1;
  }
  if (!fgets(line, sizeof(line), f)) {
    if (ferror(f))
      return -1;
    errno = EPROTO;
    return -1;
  }

  double alpha = 0.0, unk_prior = 0.0, kn_discount = 0.0;
  size_t expected_uni = 0, expected_bi = 0, expected_tri = 0;
  size_t expected_quad = 0, expected_vocab = 0, unk_count = 0;
  int consumed = 0;
  int fields = sscanf(line, "# %lf %lf %lf %zu %zu %zu %zu %zu %zu%n", &alpha,
                      &unk_prior, &kn_discount, &expected_uni, &expected_bi,
                      &expected_tri, &expected_quad, &expected_vocab,
                      &unk_count, &consumed);
  if (fields != 9 || !serialized_line_end(line + consumed) ||
      !isfinite(alpha) || !isfinite(unk_prior) || !isfinite(kn_discount) ||
      alpha <= 0.0 || kn_discount <= 0.0) {
    errno = EPROTO;
    return -1;
  }
  model->alpha = alpha;
  model->unk_prior = unk_prior;
  model->kn_discount = kn_discount;
  model->unk_count = unk_count;

  size_t context_total = 0;
  for (;;) {
    uint8_t type = 0;
    if (fread(&type, 1, 1, f) != 1) {
      if (feof(f))
        break;
      return -1;
    }

    uint32_t key_len = 0;
    uint64_t count = 0;
    uint8_t newline = 0;
    char key[SG_ANOMALY_MAX_KEY_LENGTH];
    if (fread(&key_len, sizeof(key_len), 1, f) != 1 || key_len == 0 ||
        key_len > sizeof(key) || fread(key, 1, key_len, f) != key_len ||
        fread(&count, sizeof(count), 1, f) != 1 || count == 0 ||
        count > INT64_MAX || count > SIZE_MAX ||
        fread(&newline, 1, 1, f) != 1 || newline != '\n' || type < 1 ||
        type > 4 || !serialized_key_valid(key, key_len, type)) {
      if (ferror(f))
        return -1;
      errno = EPROTO;
      return -1;
    }

    ht_table_t *table = NULL;
    size_t *total = NULL;
    ht_table_t *context_table = NULL;
    size_t context_length = 0;
    if (type == BINARY_TYPE_UNI) {
      table = model->uni;
      total = &model->total_uni;
    } else if (type == BINARY_TYPE_BI) {
      table = model->bi;
      total = &model->total_bi;
      context_table = model->bi_ctx;
      context_length = serialized_key_prefix_length(key, key_len, 1);
    } else if (type == BINARY_TYPE_TRI) {
      table = model->tri;
      total = &model->total_tri;
      context_table = model->tri_ctx;
      context_length = serialized_key_prefix_length(key, key_len, 2);
    } else {
      table = model->quad;
      total = &model->total_quad;
      context_table = model->quad_ctx;
      context_length = serialized_key_prefix_length(key, key_len, 3);
    }

    if ((context_table && context_length == 0) ||
        *total > SIZE_MAX - (size_t)count ||
        (context_table && context_total > SIZE_MAX - (size_t)count)) {
      errno = EOVERFLOW;
      return -1;
    }
    if (!count_inc(table, key, key_len, (int64_t)count, total) ||
        (context_table && !count_inc(context_table, key, context_length,
                                     (int64_t)count, &context_total))) {
      errno = ENOMEM;
      return -1;
    }
  }

  model->vocab_size = ht_size(model->uni);
  if (model->total_uni != expected_uni || model->total_bi != expected_bi ||
      model->total_tri != expected_tri || model->total_quad != expected_quad ||
      model->vocab_size != expected_vocab) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

int sg_anomaly_read_stream(sg_anomaly_model_t *model, FILE *f) {
  if (!model || !f) {
    errno = EINVAL;
    return -1;
  }
  sg_anomaly_model_t *loaded =
      anomaly_model_new(model->alpha, model->unk_prior);
  if (!loaded) {
    errno = ENOMEM;
    return -1;
  }

  int result = load_anomaly_stream(loaded, f);
  int saved_errno = errno;
  if (result == 0) {
    sg_anomaly_model_t previous = *model;
    *model = *loaded;
    *loaded = previous;
  }
  sg_anomaly_model_free(loaded);
  errno = saved_errno;
  return result;
}

sg_anomaly_status_t sg_anomaly_model_load(sg_anomaly_model_t *model,
                                          const char *path) {
  if (!model || !path) {
    errno = EINVAL;
    return SG_ANOMALY_ERR_INVALID;
  }

  FILE *f = fopen(path, "rb");
  if (!f)
    return anomaly_failure_status();
  errno = 0;
  int result = sg_anomaly_read_stream(model, f);
  int saved_errno = errno;
  if (fclose(f) != 0 && result == 0) {
    result = -1;
    saved_errno = errno;
  }
  if (result == 0)
    return SG_ANOMALY_OK;
  errno = saved_errno;
  return anomaly_failure_status();
}

/* --- ACCESSORS --- */

size_t sg_anomaly_model_vocab_size(const sg_anomaly_model_t *model) {
  return model ? ht_size(model->uni) : 0;
}

size_t sg_anomaly_model_total_unigrams(const sg_anomaly_model_t *model) {
  return model ? model->total_uni : 0;
}

size_t sg_anomaly_model_total_bigrams(const sg_anomaly_model_t *model) {
  return model ? model->total_bi : 0;
}

size_t sg_anomaly_model_total_trigrams(const sg_anomaly_model_t *model) {
  return model ? model->total_tri : 0;
}

size_t sg_anomaly_model_total_fourgrams(const sg_anomaly_model_t *model) {
  return model ? model->total_quad : 0;
}

size_t sg_anomaly_model_unigram_count_view(const sg_anomaly_model_t *model,
                                           sg_anomaly_item_view_t cmd) {
  anomaly_bytes_t command = cmd;
  if (!model || !command_is_valid(command))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), &command, 1);
  return key_len > 0 ? count_get(model->uni, key, key_len) : 0;
}

size_t sg_anomaly_model_unigram_count(const sg_anomaly_model_t *model,
                                      const char *cmd) {
  return sg_anomaly_model_unigram_count_view(
      model,
      (sg_anomaly_item_view_t){.data = cmd, .length = cmd ? strlen(cmd) : 0});
}

size_t sg_anomaly_model_unknown_count(const sg_anomaly_model_t *model) {
  return model ? model->unk_count : 0;
}

double sg_anomaly_model_kneser_ney_discount(const sg_anomaly_model_t *model) {
  return model ? model->kn_discount : 0.0;
}

size_t sg_anomaly_model_bigram_count_view(const sg_anomaly_model_t *model,
                                          sg_anomaly_item_view_t prev,
                                          sg_anomaly_item_view_t curr) {
  const anomaly_bytes_t pair[] = {
      prev,
      curr,
  };
  if (!model || !command_is_valid(pair[0]) || !command_is_valid(pair[1]))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), pair, 2);
  return key_len > 0 ? count_get(model->bi, key, key_len) : 0;
}

size_t sg_anomaly_model_bigram_count(const sg_anomaly_model_t *model,
                                     const char *prev, const char *curr) {
  return sg_anomaly_model_bigram_count_view(
      model,
      (sg_anomaly_item_view_t){.data = prev, .length = prev ? strlen(prev) : 0},
      (sg_anomaly_item_view_t){.data = curr,
                               .length = curr ? strlen(curr) : 0});
}

size_t sg_anomaly_model_trigram_count_view(const sg_anomaly_model_t *model,
                                           sg_anomaly_item_view_t p2,
                                           sg_anomaly_item_view_t p1,
                                           sg_anomaly_item_view_t curr) {
  const anomaly_bytes_t triple[] = {
      p2,
      p1,
      curr,
  };
  if (!model || !command_is_valid(triple[0]) || !command_is_valid(triple[1]) ||
      !command_is_valid(triple[2]))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), triple, 3);
  return key_len > 0 ? count_get(model->tri, key, key_len) : 0;
}

size_t sg_anomaly_model_trigram_count(const sg_anomaly_model_t *model,
                                      const char *p2, const char *p1,
                                      const char *curr) {
  return sg_anomaly_model_trigram_count_view(
      model,
      (sg_anomaly_item_view_t){.data = p2, .length = p2 ? strlen(p2) : 0},
      (sg_anomaly_item_view_t){.data = p1, .length = p1 ? strlen(p1) : 0},
      (sg_anomaly_item_view_t){.data = curr,
                               .length = curr ? strlen(curr) : 0});
}

size_t sg_anomaly_model_fourgram_count_view(const sg_anomaly_model_t *model,
                                            sg_anomaly_item_view_t p3,
                                            sg_anomaly_item_view_t p2,
                                            sg_anomaly_item_view_t p1,
                                            sg_anomaly_item_view_t curr) {
  const anomaly_bytes_t quad[] = {
      p3,
      p2,
      p1,
      curr,
  };
  if (!model || !command_is_valid(quad[0]) || !command_is_valid(quad[1]) ||
      !command_is_valid(quad[2]) || !command_is_valid(quad[3]))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), quad, 4);
  return key_len > 0 ? count_get(model->quad, key, key_len) : 0;
}

size_t sg_anomaly_model_fourgram_count(const sg_anomaly_model_t *model,
                                       const char *p3, const char *p2,
                                       const char *p1, const char *curr) {
  return sg_anomaly_model_fourgram_count_view(
      model,
      (sg_anomaly_item_view_t){.data = p3, .length = p3 ? strlen(p3) : 0},
      (sg_anomaly_item_view_t){.data = p2, .length = p2 ? strlen(p2) : 0},
      (sg_anomaly_item_view_t){.data = p1, .length = p1 ? strlen(p1) : 0},
      (sg_anomaly_item_view_t){.data = curr,
                               .length = curr ? strlen(curr) : 0});
}

size_t sg_anomaly_model_total_contexts(const sg_anomaly_model_t *model) {
  if (!model)
    return 0;
  return ht_size(model->bi_ctx) + ht_size(model->tri_ctx) +
         ht_size(model->quad_ctx);
}

sg_anomaly_status_t
sg_anomaly_model_has_observed_netseq(const sg_anomaly_model_t *model,
                                     const char *netseq, size_t netseq_length,
                                     bool *observed) {
  if (observed)
    *observed = false;
  if (!model || !netseq || !observed)
    return SG_ANOMALY_ERR_INVALID;
  size_t count = 0;
  sg_anomaly_status_t status =
      validate_netseq(netseq, netseq_length, false, &count);
  if (status != SG_ANOMALY_OK)
    return status;
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, netseq, netseq_length) !=
      SHELL_NETSTRING_OK)
    return SG_ANOMALY_ERR_FORMAT;
  shell_netstring_view_t view;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    anomaly_bytes_t command = {.data = (const char *)view.payload,
                               .length = view.payload_length};
    if (!command_is_valid(command))
      continue;
    char key[SG_ANOMALY_MAX_KEY_LENGTH];
    size_t key_len = build_key(key, sizeof(key), &command, 1);
    if (key_len > 0 && count_get(model->uni, key, key_len) > 0) {
      *observed = true;
      break;
    }
  }
  return SG_ANOMALY_OK;
}

typedef struct {
  ht_table_t *uni;
  ht_table_t *bi;
  ht_table_t *tri;
  ht_table_t *quad;
  ht_table_t *bi_ctx;
  ht_table_t *tri_ctx;
  ht_table_t *quad_ctx;
} anomaly_tables_t;

static anomaly_tables_t anomaly_tables_from_model(sg_anomaly_model_t *model) {
  return (anomaly_tables_t){model->uni,     model->bi,     model->tri,
                            model->quad,    model->bi_ctx, model->tri_ctx,
                            model->quad_ctx};
}

static void anomaly_tables_destroy(anomaly_tables_t *tables) {
  ht_destroy(tables->uni);
  ht_destroy(tables->bi);
  ht_destroy(tables->tri);
  ht_destroy(tables->quad);
  ht_destroy(tables->bi_ctx);
  ht_destroy(tables->tri_ctx);
  ht_destroy(tables->quad_ctx);
  memset(tables, 0, sizeof(*tables));
}

static ht_table_t *count_table_clone(const ht_table_t *source) {
  ht_table_t *copy = count_table_create();
  if (!copy)
    return NULL;

  ht_iter_t iter = ht_iter_begin((ht_table_t *)source);
  const void *key;
  size_t key_len;
  const void *value;
  size_t value_len;
  while (ht_iter_next((ht_table_t *)source, &iter, &key, &key_len, &value,
                      &value_len)) {
    if (SG_ANOMALY_OP_FAILED() ||
        ht_upsert_with_hash(copy, anomaly_hash_fn(key, key_len, NULL), key,
                            key_len, value, value_len) == HT_INSERT_FAILED) {
      ht_destroy(copy);
      return NULL;
    }
  }
  return copy;
}

static bool anomaly_tables_clone(const anomaly_tables_t *source,
                                 anomaly_tables_t *copy) {
  memset(copy, 0, sizeof(*copy));
  const ht_table_t *sources[] = {
      source->uni,    source->bi,      source->tri,     source->quad,
      source->bi_ctx, source->tri_ctx, source->quad_ctx};
  ht_table_t **destinations[] = {&copy->uni,     &copy->bi,     &copy->tri,
                                 &copy->quad,    &copy->bi_ctx, &copy->tri_ctx,
                                 &copy->quad_ctx};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    *destinations[i] = count_table_clone(sources[i]);
    if (!*destinations[i]) {
      anomaly_tables_destroy(copy);
      return false;
    }
  }
  return true;
}

static void anomaly_replace_model(sg_anomaly_model_t *model,
                                  sg_anomaly_model_t *staged) {
  sg_anomaly_model_t previous = *model;
  *model = *staged;
  *staged = previous;
  sg_anomaly_model_free(staged);
}

static void anomaly_recalculate_totals(sg_anomaly_model_t *model) {
  model->total_uni = 0;
  model->total_bi = 0;
  model->total_tri = 0;
  model->total_quad = 0;
  model->vocab_size = ht_size(model->uni);

  ht_table_t *tables[] = {model->uni, model->bi, model->tri, model->quad};
  size_t *totals[] = {&model->total_uni, &model->total_bi, &model->total_tri,
                      &model->total_quad};
  for (size_t table_index = 0; table_index < 4; table_index++) {
    ht_iter_t iter = ht_iter_begin(tables[table_index]);
    const void *key;
    size_t key_len;
    const void *value;
    size_t value_len;
    while (ht_iter_next(tables[table_index], &iter, &key, &key_len, &value,
                        &value_len)) {
      (void)key;
      (void)key_len;
      if (value_len == sizeof(int64_t))
        *totals[table_index] += (size_t)count_value(value);
    }
  }
}

sg_anomaly_status_t sg_anomaly_model_reset(sg_anomaly_model_t *model) {
  if (!model)
    return SG_ANOMALY_ERR_INVALID;

  sg_anomaly_model_t *staged =
      anomaly_model_new(model->alpha, model->unk_prior);
  if (!staged) {
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  staged->kn_discount = model->kn_discount;
  staged->oom = false;
  anomaly_replace_model(model, staged);
  return SG_ANOMALY_OK;
}

typedef struct {
  void *key;
  size_t key_len;
  int64_t count;
} count_change_t;

static void free_count_changes(count_change_t *changes, size_t count) {
  if (!changes)
    return;
  for (size_t i = 0; i < count; i++)
    free(changes[i].key);
  free(changes);
}

/* Apply decay to a hash table: multiply all counts by scale factor.
 * Entries with count < 1 are removed. Keys must be copied before mutation
 * because Draugr may relocate entry storage during upsert or removal. */
static bool table_decay(ht_table_t *t, double scale) {
  if (!t || scale <= 0.0 || scale >= 1.0)
    return true;

  size_t change_cap = ht_size(t);
  if (change_cap == 0)
    return true;
  size_t change_len = 0;
  count_change_t *changes = calloc(change_cap, sizeof(*changes));
  if (!changes)
    return false;

  ht_iter_t iter = ht_iter_begin(t);
  const void *key;
  size_t key_len;
  const void *val;
  size_t val_len;
  while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
    if (val_len != sizeof(int64_t))
      continue;
    changes[change_len].key = malloc(key_len);
    if (!changes[change_len].key) {
      free_count_changes(changes, change_len);
      return false;
    }
    memcpy(changes[change_len].key, key, key_len);
    changes[change_len].key_len = key_len;
    changes[change_len].count = (int64_t)((double)count_value(val) * scale);
    change_len++;
  }

  bool success = true;
  for (size_t i = 0; i < change_len; i++) {
    if (changes[i].count < 1) {
      if (SG_ANOMALY_OP_FAILED() ||
          ht_remove(t, changes[i].key, changes[i].key_len) == 0)
        success = false;
    } else {
      uint64_t hash = anomaly_hash_fn(changes[i].key, changes[i].key_len, NULL);
      if (SG_ANOMALY_OP_FAILED() ||
          ht_upsert_with_hash(t, hash, changes[i].key, changes[i].key_len,
                              &changes[i].count,
                              sizeof(changes[i].count)) == HT_INSERT_FAILED)
        success = false;
    }
  }
  free_count_changes(changes, change_len);
  return success;
}

sg_anomaly_status_t sg_anomaly_model_decay(sg_anomaly_model_t *model,
                                           double scale) {
  if (!model || !isfinite(scale) || scale <= 0.0 || scale > 1.0)
    return SG_ANOMALY_ERR_INVALID;
  if (scale == 1.0)
    return SG_ANOMALY_OK;

  sg_anomaly_model_t *staged = calloc(1, sizeof(*staged));
  if (!staged) {
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  *staged = *model;
  staged->uni = staged->bi = staged->tri = staged->quad = NULL;
  staged->bi_ctx = staged->tri_ctx = staged->quad_ctx = NULL;
  anomaly_tables_t source = anomaly_tables_from_model(model);
  anomaly_tables_t copy;
  if (!anomaly_tables_clone(&source, &copy)) {
    free(staged);
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  staged->uni = copy.uni;
  staged->bi = copy.bi;
  staged->tri = copy.tri;
  staged->quad = copy.quad;
  staged->bi_ctx = copy.bi_ctx;
  staged->tri_ctx = copy.tri_ctx;
  staged->quad_ctx = copy.quad_ctx;

  ht_table_t *tables[] = {staged->uni,     staged->bi,     staged->tri,
                          staged->quad,    staged->bi_ctx, staged->tri_ctx,
                          staged->quad_ctx};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    if (!table_decay(tables[i], scale)) {
      sg_anomaly_model_free(staged);
      model->oom = true;
      return SG_ANOMALY_ERR_MEMORY;
    }
  }
  staged->unk_count = (size_t)((double)staged->unk_count * scale);
  anomaly_recalculate_totals(staged);
  anomaly_replace_model(model, staged);
  return SG_ANOMALY_OK;
}

/* Remove entries with count less than min_count from a hash table.
 * Returns number of entries removed.
 * Uses two-pass: collect keys to remove, then remove them. */
static size_t table_prune(ht_table_t *t, size_t min_count, bool *success) {
  if (!t || min_count == 0)
    return 0;

  size_t remove_cap = ht_size(t);
  if (remove_cap == 0)
    return 0;
  size_t remove_len = 0;
  count_change_t *remove_list = calloc(remove_cap, sizeof(*remove_list));
  if (!remove_list) {
    *success = false;
    return 0;
  }

  ht_iter_t iter = ht_iter_begin(t);
  const void *key;
  size_t key_len;
  const void *val;
  size_t val_len;
  while (ht_iter_next(t, &iter, &key, &key_len, &val, &val_len)) {
    if (val_len != sizeof(int64_t))
      continue;
    int64_t count = count_value(val);
    if ((size_t)count < min_count) {
      remove_list[remove_len].key = malloc(key_len);
      if (!remove_list[remove_len].key) {
        free_count_changes(remove_list, remove_len);
        *success = false;
        return 0;
      }
      memcpy(remove_list[remove_len].key, key, key_len);
      remove_list[remove_len].key_len = key_len;
      remove_len++;
    }
  }
  for (size_t i = 0; i < remove_len; i++)
    if (SG_ANOMALY_OP_FAILED() ||
        ht_remove(t, remove_list[i].key, remove_list[i].key_len) == 0) {
      free_count_changes(remove_list, remove_len);
      *success = false;
      return 0;
    }
  free_count_changes(remove_list, remove_len);
  return remove_len;
}

sg_anomaly_status_t sg_anomaly_model_prune(sg_anomaly_model_t *model,
                                           size_t min_count, size_t *removed) {
  if (!model || !removed)
    return SG_ANOMALY_ERR_INVALID;
  if (min_count == 0) {
    *removed = 0;
    return SG_ANOMALY_OK;
  }

  sg_anomaly_model_t *staged = calloc(1, sizeof(*staged));
  if (!staged) {
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  *staged = *model;
  staged->uni = staged->bi = staged->tri = staged->quad = NULL;
  staged->bi_ctx = staged->tri_ctx = staged->quad_ctx = NULL;
  anomaly_tables_t source = anomaly_tables_from_model(model);
  anomaly_tables_t copy;
  if (!anomaly_tables_clone(&source, &copy)) {
    free(staged);
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  staged->uni = copy.uni;
  staged->bi = copy.bi;
  staged->tri = copy.tri;
  staged->quad = copy.quad;
  staged->bi_ctx = copy.bi_ctx;
  staged->tri_ctx = copy.tri_ctx;
  staged->quad_ctx = copy.quad_ctx;

  bool success = true;
  size_t count = 0;
  count += table_prune(staged->uni, min_count, &success);
  count += table_prune(staged->bi, min_count, &success);
  count += table_prune(staged->tri, min_count, &success);
  count += table_prune(staged->quad, min_count, &success);
  count += table_prune(staged->bi_ctx, min_count, &success);
  count += table_prune(staged->tri_ctx, min_count, &success);
  count += table_prune(staged->quad_ctx, min_count, &success);
  if (!success) {
    sg_anomaly_model_free(staged);
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  anomaly_recalculate_totals(staged);
  anomaly_replace_model(model, staged);
  *removed = count;
  return SG_ANOMALY_OK;
}

sg_anomaly_status_t sg_anomaly_model_compact(sg_anomaly_model_t *model) {
  if (!model)
    return SG_ANOMALY_ERR_INVALID;

  bool success = ht_compact(model->uni);
  success = ht_compact(model->bi) && success;
  success = ht_compact(model->tri) && success;
  success = ht_compact(model->quad) && success;
  success = ht_compact(model->bi_ctx) && success;
  success = ht_compact(model->tri_ctx) && success;
  success = ht_compact(model->quad_ctx) && success;
  return success ? SG_ANOMALY_OK : SG_ANOMALY_ERR_MEMORY;
}
