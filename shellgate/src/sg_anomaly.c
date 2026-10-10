/*
 * sg_anomaly.c - Statistical Anomaly Detection
 *
 * 4-gram language model with Kneser-Ney absolute discounting and
 * backoff to trigram/bigram/unigram.  All strings are owned by the model.
 * Context totals and distinct continuation counts are maintained together
 * for O(1) expected probability lookups.
 *
 * Kneser-Ney discounting:
 *   Observed n-grams:
 *     P_KN(w|ctx) = max(0, c - D) / c_ctx
 *                  + D * |unique_cont| / c_ctx * P_KN_lower(w|ctx')
 *   Unobserved n-grams: back off to lower-order model.
 *   D = absolute discount (default 0.5)
 *
 * Serialisation uses a binary format with length-prefixed keys:
 *   Header (text):  # anomaly-model-v7\n
 *                   # alpha unk_prior D total_uni total_bi total_tri total_quad
 * vocab_size unk_count\n Entry (binary): uint8_t type; uint32_t key_len;
 * uint8_t key[key_len]; uint64_t count; uint8_t nl; type values: 1='U', 2='B',
 * 3='T', 4='Q'
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "sg_anomaly.h"
#include "sg_anomaly_internal.h"
#include "shell_netstring.h"
#include <draugr/ht.h>
#define XXH_STATIC_LINKING_ONLY
#include "sg_alloc.h"
#include "sg_io.h"
#include <errno.h>
#include <float.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xxhash.h>

#ifdef SHELLGATE_TEST_ANOMALY_OPS
#include "test_sg_failures.h"
#define SG_ANOMALY_OP_FAILED() sg_test_anomaly_op_should_fail()
#define SG_ANOMALY_SCORE_FAILURE() sg_test_anomaly_score_take_failure()
#define SG_ANOMALY_UPDATE_FAILURE() sg_test_anomaly_update_take_failure()
#define SG_ANOMALY_TABLE_WORK() sg_test_anomaly_work_charge()
#else
#define SG_ANOMALY_OP_FAILED() false
#define SG_ANOMALY_SCORE_FAILURE() SG_ANOMALY_OK
#define SG_ANOMALY_UPDATE_FAILURE() SG_ANOMALY_OK
#define SG_ANOMALY_TABLE_WORK() ((void)0)
#endif

/* A key is a concatenation of up to four canonical netstrings. A maximum
 * payload needs four decimal digits, a colon, and a trailing comma. */
#define SG_ANOMALY_MAX_KEY_LENGTH (4U * (SG_ANOMALY_MAX_STAGE_LENGTH + 6U))

/* At an actual stream-operation failure errno describes I/O, not input
 * syntax. EINVAL/EPROTO from the filesystem must not become format errors. */
static sg_anomaly_status_t anomaly_io_failure_status(void) {
  if (errno == 0)
    errno = EIO;
  return errno == ENOMEM ? SG_ANOMALY_ERR_MEMORY : SG_ANOMALY_ERR_IO;
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

/* Internal iteration requires all outputs. Charge traversal as well as keyed
 * lookup work so a scoring regression cannot hide a full-table scan. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool count_table_next(
    ht_table_t *table, ht_iter_t *iter, const void **key, size_t *key_length,
    const void **value, size_t *value_length) {
  SG_ANOMALY_TABLE_WORK();
  return ht_iter_next(table, iter, key, key_length, value, value_length);
}

/* Persisted keys and positive increments have already passed framing/range
 * validation. Check accumulation, not caller storage: Draugr's increment
 * saturates, whereas every accepted model must retain exact counters. total
 * is the owning n-gram order's required aggregate counter. */
static SHELL_NONNULL(1, 2, 5) sg_anomaly_status_t
    count_add_loaded(ht_table_t *t, const char *key, size_t key_len,
                     int64_t inc, size_t *total) {
  uint64_t hash = anomaly_hash_fn(key, key_len, NULL);
  size_t value_length;
  const void *found = ht_find_with_hash(t, hash, key, key_len, &value_length);
  int64_t previous = 0;
  if (found)
    memcpy(&previous, found, sizeof(previous));
  if (previous > INT64_MAX - inc || *total > SIZE_MAX - (size_t)inc) {
    errno = EOVERFLOW;
    return SG_ANOMALY_ERR_LIMIT;
  }
  int64_t next = previous + inc;
  if (SG_ANOMALY_OP_FAILED() ||
      ht_upsert_with_hash(t, hash, key, key_len, &next, sizeof(next)) ==
          HT_INSERT_FAILED) {
    errno = ENOMEM;
    return SG_ANOMALY_ERR_MEMORY;
  }
  *total += (size_t)inc;
  return SG_ANOMALY_OK;
}

static int64_t count_value(const void *value) {
  int64_t count;
  memcpy(&count, value, sizeof(count));
  return count;
}

static size_t count_get(const ht_table_t *t, const char *key, size_t key_len) {
  SG_ANOMALY_TABLE_WORK();
  size_t val_len = 0;
  const void *found = ht_find(t, key, key_len, &val_len);
  if (found && val_len == sizeof(int64_t))
    return (size_t)count_value(found);
  return 0;
}

/* Derived context entries are private, fixed-size statistics. Every live
 * n-gram contributes its count to total and exactly one continuation. */
typedef struct {
  int64_t total;
  size_t continuations;
} anomaly_context_t;

static SHELL_NONNULL(1, 2) anomaly_context_t
    context_get(const ht_table_t *table, const char *key, size_t length) {
  SG_ANOMALY_TABLE_WORK();
  size_t value_length;
  const void *value = ht_find(table, key, length, &value_length);
  anomaly_context_t context = {0};
  if (value)
    memcpy(&context, value, sizeof(context));
  return context;
}

/* Rebuild from validated positive n-gram counters. The owning rebuild has
 * checked aggregate size_t bounds; continuations cannot exceed that total. */
static SHELL_NONNULL(1, 2) sg_anomaly_status_t
    context_add_loaded(ht_table_t *table, const char *key, size_t length,
                       int64_t count) {
  anomaly_context_t context = context_get(table, key, length);
  if (context.total > INT64_MAX - count) {
    errno = EOVERFLOW;
    return SG_ANOMALY_ERR_LIMIT;
  }
  context.total += count;
  context.continuations++;
  if (SG_ANOMALY_OP_FAILED() ||
      ht_upsert(table, key, length, &context, sizeof(context)) ==
          HT_INSERT_FAILED) {
    errno = ENOMEM;
    return SG_ANOMALY_ERR_MEMORY;
  }
  return SG_ANOMALY_OK;
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
    if (!items[i].data || used >= buf_size)
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
  ht_table_t *bi_ctx; /* context totals and distinct continuation counts */
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
  bool oom;           /* sticky record of an allocation failure, not poison */
  size_t unk_count;   /* count of unseen commands for probability estimation */
};

/* Context tables and aggregate totals are derived from the four authoritative
 * n-gram tables. Build replacements completely before publishing them so load
 * and maintenance operations cannot expose a partially rebuilt model. */
static SHELL_NONNULL(1) sg_anomaly_status_t
    anomaly_rebuild_derived(sg_anomaly_model_t *model) {
  ht_table_t *contexts[] = {count_table_create(), count_table_create(),
                            count_table_create()};
  if (!contexts[0] || !contexts[1] || !contexts[2]) {
    for (size_t i = 0; i < 3; i++)
      ht_destroy(contexts[i]);
    errno = ENOMEM;
    return SG_ANOMALY_ERR_MEMORY;
  }

  ht_table_t *ngrams[] = {model->uni, model->bi, model->tri, model->quad};
  size_t totals[] = {0, 0, 0, 0};
  sg_anomaly_status_t status = SG_ANOMALY_OK;
  for (size_t order = 0; order < 4 && status == SG_ANOMALY_OK; order++) {
    ht_iter_t iter = ht_iter_begin(ngrams[order]);
    const void *key;
    size_t key_len;
    const void *value;
    size_t value_len;
    while (count_table_next(ngrams[order], &iter, &key, &key_len, &value,
                            &value_len)) {
      int64_t count = count_value(value);
      if (totals[order] > SIZE_MAX - (size_t)count) {
        errno = EOVERFLOW;
        status = SG_ANOMALY_ERR_LIMIT;
        break;
      }
      totals[order] += (size_t)count;
      if (order != 0) {
        size_t prefix_length =
            serialized_key_prefix_length(key, key_len, order);
        status =
            context_add_loaded(contexts[order - 1], key, prefix_length, count);
        if (status != SG_ANOMALY_OK)
          break;
      }
    }
  }
  if (status != SG_ANOMALY_OK) {
    for (size_t i = 0; i < 3; i++)
      ht_destroy(contexts[i]);
    return status;
  }

  ht_destroy(model->bi_ctx);
  ht_destroy(model->tri_ctx);
  ht_destroy(model->quad_ctx);
  model->bi_ctx = contexts[0];
  model->tri_ctx = contexts[1];
  model->quad_ctx = contexts[2];
  model->total_uni = totals[0];
  model->total_bi = totals[1];
  model->total_tri = totals[2];
  model->total_quad = totals[3];
  model->vocab_size = ht_size(model->uni);
  return SG_ANOMALY_OK;
}

void sg_anomaly_config_default(sg_anomaly_config_t *config) {
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
  return model->oom;
}

void sg_anomaly_model_clear_error(sg_anomaly_model_t *model) {
  model->oom = false;
}

/* --- PROBABILITY CALCULATION --- */

/* Add positive terms in the log domain without overflowing an intermediate
 * product or sum. Negative infinity represents an absent zero term. */
static double log_add_positive(double left, double right) {
  if (left == -INFINITY)
    return right;
  if (right == -INFINITY)
    return left;
  double maximum = left > right ? left : right;
  double minimum = left > right ? right : left;
  return maximum + log1p(exp(minimum - maximum));
}

static double log_count(size_t count) {
  return count == 0 ? -INFINITY : log((double)count);
}

/* Compute log probability of unknown command in bits. */
static double unk_logprob(const sg_anomaly_model_t *m) {
  /* P_unk = (unk_count + alpha) / (total_uni + unk_count + alpha * (V + 1)) */
  double log_alpha = log(m->alpha);
  double numerator = log_add_positive(log_count(m->unk_count), log_alpha);
  double denominator =
      log_add_positive(log_count(m->total_uni), log_count(m->unk_count));
  denominator = log_add_positive(denominator,
                                 log_alpha + log((double)m->vocab_size + 1.0));
  if (!isfinite(denominator))
    return m->unk_prior;
  return (numerator - denominator) / M_LN2;
}

/*
 * KN probability at a given n-gram level.
 *
 * n_count: count of this observed n-gram.
 * context: statistics maintained for its canonical netstring prefix.
 * Every observed n-gram has a live context with a positive total.
 * Returns log probability in bits.
 */
static double kn_level_logprob(const sg_anomaly_model_t *m, size_t n_count,
                               anomaly_context_t context,
                               double lower_logprob) {
  double D = m->kn_discount;
  double ctx_total = (double)context.total;

  /* Discounted probability mass for observed n-gram */
  double disc_count = (double)n_count - D;
  if (disc_count < 0)
    disc_count = 0;

  /* Interpolation weight (probability mass for lower-order) */
  double lambda = D * (double)context.continuations / ctx_total;

  /* Combined probability */
  double p_observed = disc_count / ctx_total;
  double p_lower = lambda * exp(lower_logprob * M_LN2); /* convert bits->prob */

  double p_total = p_observed + p_lower;
  if (p_total <= 0)
    return unk_logprob(m);
  if (p_total > 1.0)
    p_total = 1.0;
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
    double log_alpha = log(m->alpha);
    double numerator = log_add_positive(log_count(uni_count), log_alpha);
    double denominator = log_add_positive(
        log_count(m->total_uni), log_alpha + log((double)m->vocab_size));
    unigram_lp = (numerator - denominator) / M_LN2;
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
    bigram_lp = kn_level_logprob(
        m, bi_count, context_get(m->bi_ctx, ctx, ctx_len), unigram_lp);
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
    trigram_lp = kn_level_logprob(
        m, tri_count, context_get(m->tri_ctx, ctx, ctx_len), bigram_lp);
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
    return kn_level_logprob(m, quad_count,
                            context_get(m->quad_ctx, ctx, ctx_len), trigram_lp);
  }

  return trigram_lp;
}

/* --- SCORING --- */

static bool command_is_scorable(anomaly_bytes_t command) {
  return command.data != NULL;
}

/* The length cap bounds the memory a single key can consume, so it constrains
 * what may be learned, not what may be scored. Scoring an over-long name is
 * safe: its n-gram keys never fit the key buffer, so it backs off to the
 * unknown-command probability and reads as highly anomalous. Rejecting it here
 * instead would return INFINITY and suppress detection entirely. */
static bool command_is_valid(anomaly_bytes_t command) {
  return command_is_scorable(command) &&
         command.length <= SG_ANOMALY_MAX_STAGE_LENGTH;
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
  shell_netstring_iter_t iter;
  shell_netstring_status_t net_status =
      shell_netstring_iter_init(&iter, netseq, length);
  if (net_status != SHELL_NETSTRING_OK)
    return netstring_status(net_status);
  shell_netstring_view_t view;
  while ((net_status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    if (enforce_item_limit && view.payload_length > SG_ANOMALY_MAX_STAGE_LENGTH)
      return SG_ANOMALY_ERR_LIMIT;
    (*count)++;
  }
  return net_status == SHELL_NETSTRING_DONE ? SG_ANOMALY_OK
                                            : netstring_status(net_status);
}

sg_anomaly_status_t sg_anomaly_netseq_count(const char *netseq, size_t length,
                                            bool enforce_item_limit,
                                            size_t *count) {
  return validate_netseq(netseq, length, enforce_item_limit, count);
}

/* Validate framing while scoring each record once. Publish neither count nor
 * score until the complete sequence is valid, including malformed tails on
 * short samples and untrained models. */
sg_anomaly_status_t
sg_anomaly_score_netseq_count(const sg_anomaly_model_t *model,
                              const char *netseq, size_t netseq_length,
                              double *score, size_t *count) {
  *score = INFINITY;
  *count = 0;
  shell_netstring_iter_t iter;
  /* netseq is required, so initialization cannot fail. The iterator still
   * validates every record's framing below. */
  (void)shell_netstring_iter_init(&iter, netseq, netseq_length);
  shell_netstring_status_t net_status;
  anomaly_bytes_t window[4];
  double total_bits = 0.0;
  size_t seen = 0, scored = 0;
  shell_netstring_view_t view;
  while ((net_status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    window[seen % 4] = (anomaly_bytes_t){.data = (const char *)view.payload,
                                         .length = view.payload_length};
    seen++;
    if (model->total_uni != 0 && seen >= 4) {
      total_bits -=
          kn_logprob(model, &window[(seen - 4) % 4], &window[(seen - 3) % 4],
                     &window[(seen - 2) % 4], &window[(seen - 1) % 4]);
      scored++;
    }
  }
  if (net_status != SHELL_NETSTRING_DONE)
    return netstring_status(net_status);
  sg_anomaly_status_t status = SG_ANOMALY_SCORE_FAILURE();
  if (status != SG_ANOMALY_OK)
    return status;
  *count = seen;
  if (seen < 3 || model->total_uni == 0)
    return SG_ANOMALY_OK;
  if (seen == 3) {
    total_bits -= kn_logprob(model, NULL, &window[0], &window[1], &window[2]);
    scored = 1;
  }
  *score = total_bits / (double)scored;
  return SG_ANOMALY_OK;
}

sg_anomaly_status_t
sg_anomaly_model_score_netseq(const sg_anomaly_model_t *model,
                              const char *netseq, size_t netseq_length,
                              double *score) {
  size_t count;
  return sg_anomaly_score_netseq_count(model, netseq, netseq_length, score,
                                       &count);
}

typedef enum {
  ANOMALY_TABLE_UNI,
  ANOMALY_TABLE_BI,
  ANOMALY_TABLE_TRI,
  ANOMALY_TABLE_QUAD,
  ANOMALY_TABLE_BI_CTX,
  ANOMALY_TABLE_TRI_CTX,
  ANOMALY_TABLE_QUAD_CTX,
} anomaly_table_kind_t;

typedef struct {
  anomaly_table_kind_t table;
  uint8_t order;
  size_t end;
  bool inserted;
  bool new_continuation;
  bool applied;
} anomaly_update_action_t;

typedef struct {
  sg_anomaly_model_t *model;
  anomaly_bytes_t *items;
  size_t item_count;
  size_t item_filled;
  anomaly_update_action_t *actions;
  size_t action_count;
  size_t applied_count;
  size_t unknown_added;
} anomaly_update_txn_t;

static ht_table_t *anomaly_table_for_kind(sg_anomaly_model_t *model,
                                          anomaly_table_kind_t table) {
  switch (table) {
  case ANOMALY_TABLE_UNI:
    return model->uni;
  case ANOMALY_TABLE_BI:
    return model->bi;
  case ANOMALY_TABLE_TRI:
    return model->tri;
  case ANOMALY_TABLE_QUAD:
    return model->quad;
  case ANOMALY_TABLE_BI_CTX:
    return model->bi_ctx;
  case ANOMALY_TABLE_TRI_CTX:
    return model->tri_ctx;
  case ANOMALY_TABLE_QUAD_CTX:
    return model->quad_ctx;
  }
  return NULL;
}

static size_t *anomaly_total_for_kind(sg_anomaly_model_t *model,
                                      anomaly_table_kind_t table) {
  switch (table) {
  case ANOMALY_TABLE_UNI:
    return &model->total_uni;
  case ANOMALY_TABLE_BI:
    return &model->total_bi;
  case ANOMALY_TABLE_TRI:
    return &model->total_tri;
  case ANOMALY_TABLE_QUAD:
    return &model->total_quad;
  case ANOMALY_TABLE_BI_CTX:
  case ANOMALY_TABLE_TRI_CTX:
  case ANOMALY_TABLE_QUAD_CTX:
    return NULL;
  }
  return NULL;
}

static void anomaly_update_txn_free(anomaly_update_txn_t *txn) {
  if (!txn)
    return;
  free(txn->items);
  free(txn->actions);
  *txn = (anomaly_update_txn_t){0};
}

/* Prepared journals reserve seven actions per item. The caller supplies an
 * order in [1,4], a complete item window and a free action slot. Each context
 * action immediately follows its n-gram action, recording whether that n-gram
 * added a distinct continuation when applied. */
static SHELL_NONNULL(1) void anomaly_update_txn_add(anomaly_update_txn_t *txn,
                                                    anomaly_table_kind_t table,
                                                    uint8_t order, size_t end) {
  txn->actions[txn->action_count++] = (anomaly_update_action_t){
      .table = table,
      .order = order,
      .end = end,
  };
}

/* Prepared actions contain 1..4 validated stage spans. Four maximum-sized
 * stages fit SG_ANOMALY_MAX_KEY_LENGTH, so this writes one complete key without
 * repeating the stage-length validation. */
static SHELL_NONNULL(1, 2, 3) size_t
    anomaly_update_txn_key(const anomaly_update_txn_t *txn,
                           const anomaly_update_action_t *action,
                           char key[SG_ANOMALY_MAX_KEY_LENGTH]) {
  return build_key(key, SG_ANOMALY_MAX_KEY_LENGTH,
                   &txn->items[action->end + 1 - action->order], action->order);
}

/* Build every mutation before touching a table. The journal stores source
 * views, not duplicated keys, so transaction memory is linear in record count
 * rather than in the maximum n-gram key size. */
static SHELL_NONNULL(1, 2, 4) sg_anomaly_status_t
    anomaly_update_txn_prepare(sg_anomaly_model_t *model, const char *netseq,
                               size_t netseq_length,
                               anomaly_update_txn_t *txn) {
  *txn = (anomaly_update_txn_t){.model = model};
  size_t count = 0;
  sg_anomaly_status_t status =
      validate_netseq(netseq, netseq_length, true, &count);
  if (status != SG_ANOMALY_OK)
    return status;
  if (count > SIZE_MAX / 7 || count > SIZE_MAX / sizeof(*txn->items) ||
      count * 7 > SIZE_MAX / sizeof(*txn->actions))
    return SG_ANOMALY_ERR_LIMIT;

  if (count != 0) {
    /* The model's backing hash tables are independently allocatable. Keep the
     * per-update journal outside Shellgate's cache-allocation fault seam so a
     * cache optimization failure cannot masquerade as a failed learn. */
    txn->items = realloc(NULL, count * sizeof(*txn->items));
    txn->actions = realloc(NULL, count * 7 * sizeof(*txn->actions));
    if (!txn->items || !txn->actions) {
      anomaly_update_txn_free(txn);
      return SG_ANOMALY_ERR_MEMORY;
    }
  }
  txn->item_count = count;

  shell_netstring_iter_t iter;
  /* The first pass validated framing and capacity. The input remains immutable
   * until this operation returns; no second consistency check is needed. */
  (void)shell_netstring_iter_init(&iter, netseq, netseq_length);
  shell_netstring_view_t view;
  while (shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK) {
    size_t index = txn->item_filled++;
    txn->items[index] = (anomaly_bytes_t){.data = (const char *)view.payload,
                                          .length = view.payload_length};
    anomaly_update_txn_add(txn, ANOMALY_TABLE_UNI, 1, index);
    if (index >= 1) {
      anomaly_update_txn_add(txn, ANOMALY_TABLE_BI, 2, index);
      anomaly_update_txn_add(txn, ANOMALY_TABLE_BI_CTX, 1, index - 1);
    }
    if (index >= 2) {
      anomaly_update_txn_add(txn, ANOMALY_TABLE_TRI, 3, index);
      anomaly_update_txn_add(txn, ANOMALY_TABLE_TRI_CTX, 2, index - 1);
    }
    if (index >= 3) {
      anomaly_update_txn_add(txn, ANOMALY_TABLE_QUAD, 4, index);
      anomaly_update_txn_add(txn, ANOMALY_TABLE_QUAD_CTX, 3, index - 1);
    }
  }
  return SG_ANOMALY_OK;
}

/* An empty optional-type journal has no model and nothing to undo. */
static SHELL_NONNULL(1) void anomaly_update_txn_rollback(
    anomaly_update_txn_t *txn) {
  if (!txn->model)
    return;
  while (txn->applied_count != 0) {
    anomaly_update_action_t *action = &txn->actions[--txn->applied_count];
    if (!action->applied)
      continue;
    char key[SG_ANOMALY_MAX_KEY_LENGTH];
    size_t key_length = anomaly_update_txn_key(txn, action, key);
    ht_table_t *table = anomaly_table_for_kind(txn->model, action->table);
    size_t *total = anomaly_total_for_kind(txn->model, action->table);
    /* Preparation established every key fits. Applied actions have live
     * entries; changing their fixed-size values cannot allocate in Draugr. */
    if (action->inserted) {
      (void)ht_remove(table, key, key_length);
    } else if (action->table >= ANOMALY_TABLE_BI_CTX) {
      anomaly_context_t context = context_get(table, key, key_length);
      context.total--;
      context.continuations -= action->new_continuation;
      (void)ht_upsert_with_hash(table, anomaly_hash_fn(key, key_length, NULL),
                                key, key_length, &context, sizeof(context));
    } else {
      bool ok = false;
      (void)ht_inc_with_hash(table, anomaly_hash_fn(key, key_length, NULL), key,
                             key_length, -1, &ok);
    }
    if (total)
      (*total)--;
    action->applied = false;
  }
  txn->model->unk_count -= txn->unknown_added;
  txn->unknown_added = 0;
}

/* Requires a successfully prepared journal with a model. */
static SHELL_NONNULL(1) sg_anomaly_status_t
    anomaly_update_txn_apply(anomaly_update_txn_t *txn) {
  /* `oom` records an earlier failure for diagnostics. Prepared updates are
   * failure-atomic, so a successfully rolled-back model remains usable. */
  sg_anomaly_status_t injected = SG_ANOMALY_UPDATE_FAILURE();
  if (injected != SG_ANOMALY_OK)
    return injected;
  for (size_t i = 0; i < txn->action_count; i++) {
    anomaly_update_action_t *action = &txn->actions[i];
    char key[SG_ANOMALY_MAX_KEY_LENGTH];
    size_t key_length = anomaly_update_txn_key(txn, action, key);
    ht_table_t *table = anomaly_table_for_kind(txn->model, action->table);
    size_t *total = anomaly_total_for_kind(txn->model, action->table);
    bool is_context = action->table >= ANOMALY_TABLE_BI_CTX;
    anomaly_context_t context = {0};
    if (is_context)
      context = context_get(table, key, key_length);
    size_t previous_count =
        is_context ? (size_t)context.total : count_get(table, key, key_length);
    if (previous_count >= INT64_MAX || (total && *total == SIZE_MAX) ||
        (action->table == ANOMALY_TABLE_UNI && previous_count == 0 &&
         txn->model->unk_count == SIZE_MAX))
      return SG_ANOMALY_ERR_LIMIT;
    action->inserted = previous_count == 0;
    if (SG_ANOMALY_OP_FAILED())
      return SG_ANOMALY_ERR_MEMORY;
    uint64_t hash = anomaly_hash_fn(key, key_length, NULL);
    if (is_context) {
      action->new_continuation = txn->actions[i - 1].inserted;
      context.total++;
      context.continuations += action->new_continuation;
      if (ht_upsert_with_hash(table, hash, key, key_length, &context,
                              sizeof(context)) == HT_INSERT_FAILED)
        return SG_ANOMALY_ERR_MEMORY;
    } else {
      bool ok = false;
      (void)ht_inc_with_hash(table, hash, key, key_length, 1, &ok);
      if (!ok)
        return SG_ANOMALY_ERR_MEMORY;
    }
    if (total)
      (*total)++;
    if (action->table == ANOMALY_TABLE_UNI && action->inserted) {
      txn->model->unk_count++;
      txn->unknown_added++;
    }
    action->applied = true;
    txn->applied_count++;
  }
  return SG_ANOMALY_OK;
}

/* An empty optional-type journal has no model and nothing to commit. */
static SHELL_NONNULL(1) void anomaly_update_txn_commit(
    anomaly_update_txn_t *txn) {
  if (!txn->model)
    return;
  txn->model->vocab_size = ht_size(txn->model->uni);
  anomaly_update_txn_free(txn);
}

sg_anomaly_status_t sg_anomaly_model_update_netseq(sg_anomaly_model_t *model,
                                                   const char *netseq,
                                                   size_t netseq_length) {
  anomaly_update_txn_t txn;
  sg_anomaly_status_t status =
      anomaly_update_txn_prepare(model, netseq, netseq_length, &txn);
  if (status != SG_ANOMALY_OK) {
    if (status == SG_ANOMALY_ERR_MEMORY)
      model->oom = true;
    return status;
  }
  status = anomaly_update_txn_apply(&txn);
  if (status != SG_ANOMALY_OK) {
    anomaly_update_txn_rollback(&txn);
    anomaly_update_txn_free(&txn);
    if (status == SG_ANOMALY_ERR_MEMORY)
      model->oom = true;
    return status;
  }
  anomaly_update_txn_commit(&txn);
  return SG_ANOMALY_OK;
}

sg_anomaly_status_t sg_anomaly_models_update_netseq_pair(
    sg_anomaly_model_t *raw, const char *raw_netseq, size_t raw_length,
    sg_anomaly_model_t *type, const char *type_netseq, size_t type_length) {
  anomaly_update_txn_t raw_txn;
  anomaly_update_txn_t type_txn;
  sg_anomaly_status_t status =
      anomaly_update_txn_prepare(raw, raw_netseq, raw_length, &raw_txn);
  if (status != SG_ANOMALY_OK) {
    if (status == SG_ANOMALY_ERR_MEMORY)
      raw->oom = true;
    return status;
  }
  bool have_type = type != NULL;
  if (have_type) {
    status =
        anomaly_update_txn_prepare(type, type_netseq, type_length, &type_txn);
    if (status != SG_ANOMALY_OK) {
      anomaly_update_txn_free(&raw_txn);
      if (status == SG_ANOMALY_ERR_MEMORY)
        type->oom = true;
      return status;
    }
  } else {
    type_txn = (anomaly_update_txn_t){0};
  }
  if (have_type && raw_txn.item_count != type_txn.item_count) {
    anomaly_update_txn_free(&type_txn);
    anomaly_update_txn_free(&raw_txn);
    return SG_ANOMALY_ERR_FORMAT;
  }
  status = anomaly_update_txn_apply(&raw_txn);
  bool type_attempted = status == SG_ANOMALY_OK && have_type;
  if (type_attempted)
    status = anomaly_update_txn_apply(&type_txn);
  if (status != SG_ANOMALY_OK) {
    anomaly_update_txn_rollback(&type_txn);
    anomaly_update_txn_rollback(&raw_txn);
    anomaly_update_txn_free(&type_txn);
    anomaly_update_txn_free(&raw_txn);
    if (status == SG_ANOMALY_ERR_MEMORY) {
      if (type_attempted)
        type->oom = true;
      else
        raw->oom = true;
    }
    return status;
  }
  anomaly_update_txn_commit(&type_txn);
  anomaly_update_txn_commit(&raw_txn);
  return SG_ANOMALY_OK;
}

/* --- SERIALISATION --- */

typedef struct {
  locale_t numeric;
  locale_t previous;
} anomaly_locale_t;

/* Persistence owns this operational locale scope, not the process locale.
 * end requires a successfully begun scope; neither helper validates storage. */
static SHELL_NONNULL(1) sg_anomaly_status_t
    anomaly_locale_begin(anomaly_locale_t *scope) {
#ifdef SHELLGATE_TEST_IO
  int injected = sg_test_locale_take_error();
  if (injected) {
    errno = injected;
    return anomaly_io_failure_status();
  }
#endif
  scope->numeric = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  if (!scope->numeric)
    return anomaly_io_failure_status();
  scope->previous = uselocale(scope->numeric);
  return SG_ANOMALY_OK;
}

static SHELL_NONNULL(1) void anomaly_locale_end(anomaly_locale_t *scope) {
  int saved_errno = errno;
  uselocale(scope->previous);
  freelocale(scope->numeric);
  errno = saved_errno;
}

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
  while (count_table_next(t, &iter, &key, &key_len, &val, &val_len)) {
    if (val_len != sizeof(int64_t))
      continue;
    int64_t count_i64 = count_value(val);
    uint32_t kl = (uint32_t)key_len;
    uint64_t count_u64 = (uint64_t)count_i64;
    if (sg_io_write(f, &type, 1) != 0 || sg_io_write(f, &kl, 4) != 0 ||
        sg_io_write(f, key, kl) != 0 || sg_io_write(f, &count_u64, 8) != 0 ||
        sg_io_write(f, &nl, 1) != 0)
      return -1;
  }
  return 0;
}

sg_anomaly_status_t sg_anomaly_write_stream(const sg_anomaly_model_t *model,
                                            FILE *f) {
  anomaly_locale_t locale;
  sg_anomaly_status_t status = anomaly_locale_begin(&locale);
  if (status != SG_ANOMALY_OK)
    return status;
  errno = 0;
  if (sg_io_printf(f, "# anomaly-model-v7\n") < 0 ||
      sg_io_printf(f, "# %.17g %.17g %.17g %zu %zu %zu %zu %zu %zu\n",
                   model->alpha, model->unk_prior, model->kn_discount,
                   model->total_uni, model->total_bi, model->total_tri,
                   model->total_quad, model->vocab_size,
                   model->unk_count) < 0 ||
      save_table(f, model->uni, BINARY_TYPE_UNI) < 0 ||
      save_table(f, model->bi, BINARY_TYPE_BI) < 0 ||
      save_table(f, model->tri, BINARY_TYPE_TRI) < 0 ||
      save_table(f, model->quad, BINARY_TYPE_QUAD) < 0 || sg_io_flush(f) != 0)
    status = anomaly_io_failure_status();
  anomaly_locale_end(&locale);
  return status;
}

sg_anomaly_status_t sg_anomaly_model_save(const sg_anomaly_model_t *model,
                                          const char *path) {
  sg_atomic_output_t output;
  sg_atomic_output_result_t begin = sg_atomic_output_begin(path, &output);
  if (begin != SG_ATOMIC_OUTPUT_OK)
    return anomaly_io_failure_status();

  sg_anomaly_status_t result = sg_anomaly_write_stream(model, output.stream);
  if (result != SG_ANOMALY_OK) {
    sg_atomic_output_discard(&output);
    return result;
  }
  return sg_atomic_output_commit(&output) == 0 ? SG_ANOMALY_OK
                                               : anomaly_io_failure_status();
}

static bool serialized_key_valid(const char *key, size_t length,
                                 size_t components, bool allow_empty_items) {
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, key, length) != SHELL_NETSTRING_OK)
    return false;
  shell_netstring_view_t view;
  for (size_t i = 0; i < components; i++) {
    if (shell_netstring_iter_next(&iter, &view) != SHELL_NETSTRING_OK ||
        (!allow_empty_items && view.payload_length == 0) ||
        view.payload_length > SG_ANOMALY_MAX_STAGE_LENGTH)
      return false;
  }
  return shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_DONE;
}

static bool serialized_line_end(const char *text) {
  return (text[0] == '\n' && text[1] == '\0') ||
         (text[0] == '\r' && text[1] == '\n' && text[2] == '\0');
}

static bool serialized_header_space(unsigned char byte) {
  return byte == ' ' || byte == '\t';
}

static SHELL_NONNULL(1) bool serialized_header_separator(const char **cursor) {
  if (!serialized_header_space((unsigned char)**cursor))
    return false;
  do {
    (*cursor)++;
  } while (serialized_header_space((unsigned char)**cursor));
  return true;
}

/* Parse the exact decimal spelling emitted by the writer. The surrounding
 * header parser owns field separation and line termination. */
static SHELL_NONNULL(1, 2) sg_anomaly_status_t
    serialized_header_double(const char **cursor, double *value) {
  const char *start = *cursor;
  const char *scan = start;
  if (*scan == '+' || *scan == '-')
    scan++;
  bool digits = false;
  while (*scan >= '0' && *scan <= '9') {
    digits = true;
    scan++;
  }
  if (*scan == '.') {
    scan++;
    while (*scan >= '0' && *scan <= '9') {
      digits = true;
      scan++;
    }
  }
  if (!digits) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  if (*scan == 'e' || *scan == 'E') {
    scan++;
    if (*scan == '+' || *scan == '-')
      scan++;
    const char *exponent = scan;
    while (*scan >= '0' && *scan <= '9')
      scan++;
    if (scan == exponent) {
      errno = EPROTO;
      return SG_ANOMALY_ERR_FORMAT;
    }
  }
  if (!serialized_header_space((unsigned char)*scan) &&
      !serialized_line_end(scan)) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }

  errno = 0;
  char *end;
  double parsed = strtod(start, &end);
  /* A correctly rounded subnormal can report ERANGE while still preserving
   * the exact finite value written by %.17g. Reject only complete underflow
   * to zero; overflow is rejected by the finite-value requirement. */
  if (end != scan || (errno == ERANGE && parsed == 0.0) || !isfinite(parsed)) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  *cursor = scan;
  *value = parsed;
  return SG_ANOMALY_OK;
}

static SHELL_NONNULL(1, 2) sg_anomaly_status_t
    serialized_header_size(const char **cursor, size_t *value) {
  const char *scan = *cursor;
  if (*scan < '0' || *scan > '9') {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  size_t parsed = 0;
  do {
    unsigned digit = (unsigned)(*scan - '0');
    if (parsed > (SIZE_MAX - digit) / 10) {
      errno = EOVERFLOW;
      return SG_ANOMALY_ERR_LIMIT;
    }
    parsed = parsed * 10 + digit;
    scan++;
  } while (*scan >= '0' && *scan <= '9');
  if (!serialized_header_space((unsigned char)*scan) &&
      !serialized_line_end(scan)) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  *cursor = scan;
  *value = parsed;
  return SG_ANOMALY_OK;
}

static SHELL_NONNULL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) sg_anomaly_status_t
    serialized_header_parse(const char *line, double *alpha, double *unk_prior,
                            double *kn_discount, size_t *expected_uni,
                            size_t *expected_bi, size_t *expected_tri,
                            size_t *expected_quad, size_t *expected_vocab,
                            size_t *unk_count) {
  const char *cursor = line;
  if (*cursor++ != '#' || !serialized_header_separator(&cursor)) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  double *doubles[] = {alpha, unk_prior, kn_discount};
  for (size_t i = 0; i < 3; i++) {
    sg_anomaly_status_t status = serialized_header_double(&cursor, doubles[i]);
    if (status != SG_ANOMALY_OK)
      return status;
    if (!serialized_header_separator(&cursor)) {
      errno = EPROTO;
      return SG_ANOMALY_ERR_FORMAT;
    }
  }
  size_t *counts[] = {expected_uni,  expected_bi,    expected_tri,
                      expected_quad, expected_vocab, unk_count};
  for (size_t i = 0; i < 6; i++) {
    sg_anomaly_status_t status = serialized_header_size(&cursor, counts[i]);
    if (status != SG_ANOMALY_OK)
      return status;
    if (i + 1 < 6 && !serialized_header_separator(&cursor)) {
      errno = EPROTO;
      return SG_ANOMALY_ERR_FORMAT;
    }
  }
  if (!serialized_line_end(cursor) || *alpha <= 0.0 || *kn_discount <= 0.0 ||
      *kn_discount > 1.0) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  return SG_ANOMALY_OK;
}

static SHELL_NONNULL(1, 2) sg_anomaly_status_t
    anomaly_read_field(FILE *stream, void *buffer, size_t length) {
  sg_io_read_result_t result = sg_io_read(stream, buffer, length);
  if (result == SG_IO_READ_OK)
    return SG_ANOMALY_OK;
  if (result == SG_IO_READ_EOF) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  return anomaly_io_failure_status();
}

/* Untrusted persisted text boundary: a complete bounded physical line with
 * no embedded NUL. Successful output is a NUL-terminated LF/CRLF line which
 * the field parsers may inspect without repeating storage/framing checks. */
static SHELL_NONNULL(1, 2) sg_anomaly_status_t
    anomaly_read_header_line(FILE *stream, char *line, size_t capacity) {
  size_t length;
  sg_io_read_result_t result = sg_io_read_line(stream, line, capacity, &length);
  if (result == SG_IO_READ_ERROR)
    return anomaly_io_failure_status();
  if (result == SG_IO_READ_EOF || line[length - 1] != '\n' ||
      memchr(line, '\0', length)) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  return SG_ANOMALY_OK;
}

static sg_anomaly_status_t load_anomaly_stream(sg_anomaly_model_t *model,
                                               FILE *f) {
  char line[256];
  sg_anomaly_status_t line_status =
      anomaly_read_header_line(f, line, sizeof(line));
  if (line_status != SG_ANOMALY_OK)
    return line_status;
  bool allow_empty_items = strcmp(line, "# anomaly-model-v7\n") == 0 ||
                           strcmp(line, "# anomaly-model-v7\r\n") == 0;
  bool legacy_v6 = strcmp(line, "# anomaly-model-v6\n") == 0 ||
                   strcmp(line, "# anomaly-model-v6\r\n") == 0;
  if (!allow_empty_items && !legacy_v6) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  line_status = anomaly_read_header_line(f, line, sizeof(line));
  if (line_status != SG_ANOMALY_OK)
    return line_status;

  double alpha = 0.0, unk_prior = 0.0, kn_discount = 0.0;
  size_t expected_uni = 0, expected_bi = 0, expected_tri = 0;
  size_t expected_quad = 0, expected_vocab = 0, unk_count = 0;
  sg_anomaly_status_t header_status = serialized_header_parse(
      line, &alpha, &unk_prior, &kn_discount, &expected_uni, &expected_bi,
      &expected_tri, &expected_quad, &expected_vocab, &unk_count);
  if (header_status != SG_ANOMALY_OK)
    return header_status;
  model->alpha = alpha;
  model->unk_prior = unk_prior;
  model->kn_discount = kn_discount;
  model->unk_count = unk_count;

  for (;;) {
    uint8_t type = 0;
    sg_io_read_result_t record = sg_io_read(f, &type, 1);
    if (record != SG_IO_READ_OK) {
      if (record == SG_IO_READ_EOF)
        break;
      return anomaly_io_failure_status();
    }

    uint32_t key_len = 0;
    uint64_t count = 0;
    uint8_t newline = 0;
    char key[SG_ANOMALY_MAX_KEY_LENGTH];
    sg_anomaly_status_t status =
        anomaly_read_field(f, &key_len, sizeof(key_len));
    if (status != SG_ANOMALY_OK)
      return status;
    if (key_len == 0 || key_len > sizeof(key)) {
      errno = EPROTO;
      return SG_ANOMALY_ERR_FORMAT;
    }
    status = anomaly_read_field(f, key, key_len);
    if (status == SG_ANOMALY_OK)
      status = anomaly_read_field(f, &count, sizeof(count));
    if (status == SG_ANOMALY_OK)
      status = anomaly_read_field(f, &newline, 1);
    if (status != SG_ANOMALY_OK)
      return status;
    if (count == 0 || count > INT64_MAX || count > SIZE_MAX ||
        newline != '\n' || type < 1 || type > 4 ||
        !serialized_key_valid(key, key_len, type, allow_empty_items)) {
      errno = EPROTO;
      return SG_ANOMALY_ERR_FORMAT;
    }

    ht_table_t *table = NULL;
    size_t *total = NULL;
    if (type == BINARY_TYPE_UNI) {
      table = model->uni;
      total = &model->total_uni;
    } else if (type == BINARY_TYPE_BI) {
      table = model->bi;
      total = &model->total_bi;
    } else if (type == BINARY_TYPE_TRI) {
      table = model->tri;
      total = &model->total_tri;
    } else {
      table = model->quad;
      total = &model->total_quad;
    }

    status = count_add_loaded(table, key, key_len, (int64_t)count, total);
    if (status != SG_ANOMALY_OK)
      return status;
  }

  model->vocab_size = ht_size(model->uni);
  if (model->total_uni != expected_uni || model->total_bi != expected_bi ||
      model->total_tri != expected_tri || model->total_quad != expected_quad ||
      model->vocab_size != expected_vocab) {
    errno = EPROTO;
    return SG_ANOMALY_ERR_FORMAT;
  }
  return anomaly_rebuild_derived(model);
}

sg_anomaly_status_t sg_anomaly_model_read_new(FILE *f,
                                              sg_anomaly_model_t **out) {
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  if (!loaded) {
    errno = ENOMEM;
    return SG_ANOMALY_ERR_MEMORY;
  }

  anomaly_locale_t locale;
  sg_anomaly_status_t status = anomaly_locale_begin(&locale);
  if (status == SG_ANOMALY_OK) {
    errno = 0;
    status = load_anomaly_stream(loaded, f);
    anomaly_locale_end(&locale);
  }
  int saved_errno = errno;
  if (status == SG_ANOMALY_OK)
    *out = loaded;
  else
    sg_anomaly_model_free(loaded);
  errno = saved_errno;
  return status;
}

sg_anomaly_status_t sg_anomaly_read_stream(sg_anomaly_model_t *model, FILE *f) {
  sg_anomaly_model_t *loaded = NULL;
  sg_anomaly_status_t status = sg_anomaly_model_read_new(f, &loaded);
  if (status == SG_ANOMALY_OK) {
    int saved_errno = errno;
    sg_anomaly_model_t previous = *model;
    *model = *loaded;
    *loaded = previous;
    sg_anomaly_model_free(loaded);
    errno = saved_errno;
  }
  return status;
}

sg_anomaly_status_t sg_anomaly_model_load(sg_anomaly_model_t *model,
                                          const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return anomaly_io_failure_status();
  sg_anomaly_model_t *loaded = NULL;
  sg_anomaly_status_t result = sg_anomaly_model_read_new(f, &loaded);
  int saved_errno = errno;
  if (sg_io_close(f) != 0 && result == SG_ANOMALY_OK) {
    result = anomaly_io_failure_status();
    saved_errno = errno;
  }
  if (result == SG_ANOMALY_OK) {
    sg_anomaly_model_t previous = *model;
    *model = *loaded;
    *loaded = previous;
  }
  sg_anomaly_model_free(loaded);
  errno = saved_errno;
  return result;
}

/* --- ACCESSORS --- */

size_t sg_anomaly_model_vocab_size(const sg_anomaly_model_t *model) {
  return ht_size(model->uni);
}

size_t sg_anomaly_model_total_unigrams(const sg_anomaly_model_t *model) {
  return model->total_uni;
}

size_t sg_anomaly_model_total_bigrams(const sg_anomaly_model_t *model) {
  return model->total_bi;
}

size_t sg_anomaly_model_total_trigrams(const sg_anomaly_model_t *model) {
  return model->total_tri;
}

size_t sg_anomaly_model_total_fourgrams(const sg_anomaly_model_t *model) {
  return model->total_quad;
}

size_t sg_anomaly_model_unigram_count_view(const sg_anomaly_model_t *model,
                                           sg_anomaly_item_view_t cmd) {
  anomaly_bytes_t command = cmd;
  if (!command_is_valid(command))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), &command, 1);
  return key_len > 0 ? count_get(model->uni, key, key_len) : 0;
}

size_t sg_anomaly_model_unigram_count(const sg_anomaly_model_t *model,
                                      const char *cmd) {
  return sg_anomaly_model_unigram_count_view(
      model, (sg_anomaly_item_view_t){.data = cmd, .length = strlen(cmd)});
}

size_t sg_anomaly_model_unknown_count(const sg_anomaly_model_t *model) {
  return model->unk_count;
}

double sg_anomaly_model_kneser_ney_discount(const sg_anomaly_model_t *model) {
  return model->kn_discount;
}

size_t sg_anomaly_model_bigram_count_view(const sg_anomaly_model_t *model,
                                          sg_anomaly_item_view_t prev,
                                          sg_anomaly_item_view_t curr) {
  const anomaly_bytes_t pair[] = {
      prev,
      curr,
  };
  if ((!command_is_valid(pair[0])) || (!command_is_valid(pair[1])))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), pair, 2);
  return key_len > 0 ? count_get(model->bi, key, key_len) : 0;
}

size_t sg_anomaly_model_bigram_count(const sg_anomaly_model_t *model,
                                     const char *prev, const char *curr) {
  return sg_anomaly_model_bigram_count_view(
      model, (sg_anomaly_item_view_t){.data = prev, .length = strlen(prev)},
      (sg_anomaly_item_view_t){.data = curr, .length = strlen(curr)});
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
  if ((!command_is_valid(triple[0])) || (!command_is_valid(triple[1])) ||
      (!command_is_valid(triple[2])))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), triple, 3);
  return key_len > 0 ? count_get(model->tri, key, key_len) : 0;
}

size_t sg_anomaly_model_trigram_count(const sg_anomaly_model_t *model,
                                      const char *p2, const char *p1,
                                      const char *curr) {
  return sg_anomaly_model_trigram_count_view(
      model, (sg_anomaly_item_view_t){.data = p2, .length = strlen(p2)},
      (sg_anomaly_item_view_t){.data = p1, .length = strlen(p1)},
      (sg_anomaly_item_view_t){.data = curr, .length = strlen(curr)});
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
  if ((!command_is_valid(quad[0])) || (!command_is_valid(quad[1])) ||
      (!command_is_valid(quad[2])) || (!command_is_valid(quad[3])))
    return 0;
  char key[SG_ANOMALY_MAX_KEY_LENGTH];
  size_t key_len = build_key(key, sizeof(key), quad, 4);
  return key_len > 0 ? count_get(model->quad, key, key_len) : 0;
}

size_t sg_anomaly_model_fourgram_count(const sg_anomaly_model_t *model,
                                       const char *p3, const char *p2,
                                       const char *p1, const char *curr) {
  return sg_anomaly_model_fourgram_count_view(
      model, (sg_anomaly_item_view_t){.data = p3, .length = strlen(p3)},
      (sg_anomaly_item_view_t){.data = p2, .length = strlen(p2)},
      (sg_anomaly_item_view_t){.data = p1, .length = strlen(p1)},
      (sg_anomaly_item_view_t){.data = curr, .length = strlen(curr)});
}

size_t sg_anomaly_model_total_contexts(const sg_anomaly_model_t *model) {
  return ht_size(model->bi_ctx) + ht_size(model->tri_ctx) +
         ht_size(model->quad_ctx);
}

sg_anomaly_status_t
sg_anomaly_model_has_observed_netseq(const sg_anomaly_model_t *model,
                                     const char *netseq, size_t netseq_length,
                                     bool *observed) {
  *observed = false;

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
  while (count_table_next((ht_table_t *)source, &iter, &key, &key_len, &value,
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
  const ht_table_t *sources[] = {source->uni, source->bi, source->tri,
                                 source->quad};
  ht_table_t **destinations[] = {&copy->uni, &copy->bi, &copy->tri,
                                 &copy->quad};
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

sg_anomaly_status_t sg_anomaly_model_reset(sg_anomaly_model_t *model) {
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

typedef struct {
  uint64_t significand;
  unsigned shift;
} anomaly_decay_scale_t;

/* Public decay has established finite 0 < scale < 1. Decompose once, rather
 * than rounding each integer counter to double before multiplication. */
static anomaly_decay_scale_t anomaly_decay_scale(double scale) {
  _Static_assert(FLT_RADIX == 2 && DBL_MANT_DIG <= 64,
                 "Decay requires a binary double significand fitting uint64_t");
  _Static_assert(sizeof(size_t) <= sizeof(uint64_t),
                 "Anomaly counters fit uint64_t");
  int exponent;
  double fraction = frexp(scale, &exponent);
  return (anomaly_decay_scale_t){
      .significand = (uint64_t)ldexp(fraction, DBL_MANT_DIG),
      .shift = (unsigned)(DBL_MANT_DIG - exponent),
  };
}

/* Exact floor(count * scale), including the full integer counter precision.
 * Four 32-bit products form the unsigned 128-bit product without extensions.
 * A subnormal scale can require more than 128 right-shift bits, yielding zero.
 * scale is the decomposition of a validated decay factor; shift is positive. */
static uint64_t anomaly_decay_count(uint64_t count,
                                    anomaly_decay_scale_t scale) {
  uint64_t count_low = (uint32_t)count;
  uint64_t count_high = count >> 32;
  uint64_t scale_low = (uint32_t)scale.significand;
  uint64_t scale_high = scale.significand >> 32;
  uint64_t low_product = count_low * scale_low;
  uint64_t middle = count_high * scale_low + (low_product >> 32);
  uint64_t high = middle >> 32;
  middle = count_low * scale_high + (uint32_t)middle;
  high += count_high * scale_high + (middle >> 32);
  uint64_t low = (middle << 32) | (uint32_t)low_product;

  if (scale.shift >= 128)
    return 0;
  if (scale.shift >= 64)
    return high >> (scale.shift - 64);
  return (high << (64 - scale.shift)) | (low >> scale.shift);
}

/* Apply decay to a hash table: multiply all counts by scale factor.
 * Entries with count < 1 are removed. Keys must be copied before mutation
 * because Draugr may relocate entry storage during upsert or removal. Table
 * entries are owned positive int64_t counters; scale is prevalidated. */
static SHELL_NONNULL(1) bool table_decay(ht_table_t *t,
                                         anomaly_decay_scale_t scale) {
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
  while (count_table_next(t, &iter, &key, &key_len, &val, &val_len)) {
    changes[change_len].key = malloc(key_len);
    if (!changes[change_len].key) {
      free_count_changes(changes, change_len);
      return false;
    }
    memcpy(changes[change_len].key, key, key_len);
    changes[change_len].key_len = key_len;
    changes[change_len].count =
        (int64_t)anomaly_decay_count((uint64_t)count_value(val), scale);
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
  if ((!isfinite(scale)) || (scale <= 0.0) || (scale > 1.0))
    return SG_ANOMALY_ERR_INVALID;
  if (scale == 1.0)
    return SG_ANOMALY_OK;
  anomaly_decay_scale_t decay = anomaly_decay_scale(scale);

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

  ht_table_t *tables[] = {staged->uni, staged->bi, staged->tri, staged->quad};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    if (!table_decay(tables[i], decay)) {
      sg_anomaly_model_free(staged);
      model->oom = true;
      return SG_ANOMALY_ERR_MEMORY;
    }
  }
  staged->unk_count = (size_t)anomaly_decay_count(staged->unk_count, decay);
  sg_anomaly_status_t status = anomaly_rebuild_derived(staged);
  if (status != SG_ANOMALY_OK) {
    sg_anomaly_model_free(staged);
    if (status == SG_ANOMALY_ERR_MEMORY)
      model->oom = true;
    return status;
  }
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
  while (count_table_next(t, &iter, &key, &key_len, &val, &val_len)) {
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

  bool success = true;
  size_t count = 0;
  count += table_prune(staged->uni, min_count, &success);
  count += table_prune(staged->bi, min_count, &success);
  count += table_prune(staged->tri, min_count, &success);
  count += table_prune(staged->quad, min_count, &success);
  if (!success) {
    sg_anomaly_model_free(staged);
    model->oom = true;
    return SG_ANOMALY_ERR_MEMORY;
  }
  sg_anomaly_status_t status = anomaly_rebuild_derived(staged);
  if (status != SG_ANOMALY_OK) {
    sg_anomaly_model_free(staged);
    if (status == SG_ANOMALY_ERR_MEMORY)
      model->oom = true;
    return status;
  }
  anomaly_replace_model(model, staged);
  *removed = count;
  return SG_ANOMALY_OK;
}

sg_anomaly_status_t sg_anomaly_model_compact(sg_anomaly_model_t *model) {
  ht_table_t *tables[] = {model->uni,     model->bi,     model->tri,
                          model->quad,    model->bi_ctx, model->tri_ctx,
                          model->quad_ctx};
  bool success = true;
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++)
    if (SG_ANOMALY_OP_FAILED() || !ht_compact(tables[i]))
      success = false;
  if (!success)
    model->oom = true;
  return success ? SG_ANOMALY_OK : SG_ANOMALY_ERR_MEMORY;
}
