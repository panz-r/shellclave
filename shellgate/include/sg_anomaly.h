/*
 * sg_anomaly.h - Statistical Anomaly Detection for shellgate
 *
 * Uses a 4-gram language model with backoff to score command sequences.
 * The model owns all its memory (strings are strdup'd).
 *
 * Scores are average negative log-probability in bits per command; higher
 * scores represent less probable sequences.
 */

#ifndef SG_ANOMALY_H
#define SG_ANOMALY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- TYPES --- */

/* Opaque anomaly model.  All memory is owned and freed on destroy. */
typedef struct sg_anomaly_model sg_anomaly_model_t;

/* Results returned by maintenance operations. */
typedef enum {
  SG_ANOMALY_OK = 0,
  SG_ANOMALY_ERR_INVALID = -1,
  SG_ANOMALY_ERR_MEMORY = -2,
  SG_ANOMALY_ERR_FORMAT = -3,
  SG_ANOMALY_ERR_LIMIT = -4,
  SG_ANOMALY_ERR_IO = -5,
} sg_anomaly_status_t;

/* Maximum decoded sequence-item length accepted while learning. Scoring
 * accepts longer items and treats them as unknown. Four maximum-length items
 * and their terminators fit exactly in the serialized n-gram key limit. */
#define SG_ANOMALY_MAX_COMMAND_LENGTH 1023

/* --- ERROR STATE --- */

/*
 * Returns true if the model encountered an allocation failure
 * (e.g., strdup returned NULL) during an update operation.
 * Call sg_anomaly_model_clear_error() to reset.
 */
bool sg_anomaly_model_had_error(const sg_anomaly_model_t *model);

/*
 * Clear the OOM error flag after the caller has handled it.
 */
void sg_anomaly_model_clear_error(sg_anomaly_model_t *model);

/* --- LIFECYCLE --- */

typedef struct {
  /* Dirichlet smoothing parameter; must be finite and positive. */
  double alpha;
  /* Fallback log-probability; must be finite. */
  double unknown_log_prior;
} sg_anomaly_config_t;

/* Initialize a configuration with the default hyperparameters. */
void sg_anomaly_config_default(sg_anomaly_config_t *config);

/* Create a new model with default hyperparameters.
 * Returns NULL on allocation failure. */
sg_anomaly_model_t *sg_anomaly_model_new(void);

/* Create a new model with `config`, or defaults when it is NULL. Invalid
 * explicit configuration and allocation failure both return NULL. */
sg_anomaly_model_t *
sg_anomaly_model_new_with_config(const sg_anomaly_config_t *config);

/* Free all memory associated with the model. */
void sg_anomaly_model_free(sg_anomaly_model_t *model);

/* --- SCORING --- */

/*
 * Score a command sequence.
 *
 * `netseq` is a canonical concatenation of non-empty netstring records. Each
 * record is one opaque sequence item, such as an executable name or a nested
 * per-command type signature.
 *
 * Returns the average negative log-probability per command (bits).
 * Higher = more anomalous.
 * On success, writes INFINITY when the sequence has fewer than three items or
 * the model is empty. Malformed and non-canonical framing returns
 * SG_ANOMALY_ERR_FORMAT.
 *
 * Names longer than SG_ANOMALY_MAX_COMMAND_LENGTH are scored, not rejected.
 * They can never have been learned, so they score as unknown commands and
 * read as highly anomalous.
 *
 * Does not modify the model.
 */
sg_anomaly_status_t
sg_anomaly_model_score_netseq(const sg_anomaly_model_t *model,
                              const char *netseq, size_t netseq_length,
                              double *score);

/* --- UPDATE (LEARNING) --- */

/*
 * Update the model with a command sequence.
 *
 * The model copies each decoded non-empty record. The caller retains ownership
 * of `netseq`. Malformed framing is rejected without changing the model.
 *
 * Updates every unigram and consecutive bigram, trigram, and 4-gram in the
 * sequence.
 *
 * Unigrams and bigrams are also updated when the record count is below 3
 * (e.g. a 2-token sequence contributes 1 bigram and 2 unigrams).
 */
sg_anomaly_status_t sg_anomaly_model_update_netseq(sg_anomaly_model_t *model,
                                                   const char *netseq,
                                                   size_t netseq_length);

/* --- SERIALISATION --- */

/*
 * Save the model to a versioned binary file.
 *
 * Returns SG_ANOMALY_OK on success. On failure, returns a specific status and
 * preserves errno for OS-level diagnostics.
 */
sg_anomaly_status_t sg_anomaly_model_save(const sg_anomaly_model_t *model,
                                          const char *path);

/*
 * Load a model from a file written by sg_anomaly_model_save().
 *
 * Returns SG_ANOMALY_OK on success. Malformed persisted data returns
 * SG_ANOMALY_ERR_FORMAT; the existing model remains unchanged on every
 * failure. errno remains available for OS-level diagnostics.
 * On error, the existing model is unchanged.
 */
sg_anomaly_status_t sg_anomaly_model_load(sg_anomaly_model_t *model,
                                          const char *path);

/* --- ACCESSORS --- */

/* Total number of unique commands observed (unigram vocabulary). */
size_t sg_anomaly_model_vocab_size(const sg_anomaly_model_t *model);

/* Total number of unigram observations. */
size_t sg_anomaly_model_total_unigrams(const sg_anomaly_model_t *model);

/* Total number of bigram observations. */
size_t sg_anomaly_model_total_bigrams(const sg_anomaly_model_t *model);

/* Total number of trigram observations. */
size_t sg_anomaly_model_total_trigrams(const sg_anomaly_model_t *model);

/* Total number of 4-gram observations. */
size_t sg_anomaly_model_total_fourgrams(const sg_anomaly_model_t *model);

/* Get unigram count for a command.  Returns 0 if never seen. */
size_t sg_anomaly_model_unigram_count(const sg_anomaly_model_t *model,
                                      const char *cmd);

/* Get count of unseen commands (for UNK probability estimation). */
size_t sg_anomaly_model_unknown_count(const sg_anomaly_model_t *model);

/* Get the Kneser-Ney absolute discount parameter (default 0.5). */
double sg_anomaly_model_kneser_ney_discount(const sg_anomaly_model_t *model);

/* Get bigram count for (prev, curr). Returns 0 if never seen. */
size_t sg_anomaly_model_bigram_count(const sg_anomaly_model_t *model,
                                     const char *prev, const char *curr);

/* Get trigram count for (p2, p1, curr). Returns 0 if never seen. */
size_t sg_anomaly_model_trigram_count(const sg_anomaly_model_t *model,
                                      const char *p2, const char *p1,
                                      const char *curr);

/* Get 4-gram count for (p3, p2, p1, curr). Returns 0 if never seen. */
size_t sg_anomaly_model_fourgram_count(const sg_anomaly_model_t *model,
                                       const char *p3, const char *p2,
                                       const char *p1, const char *curr);

/* Get total number of unique n-gram contexts across all levels. */
size_t sg_anomaly_model_total_contexts(const sg_anomaly_model_t *model);

/* Check whether any command in a canonical netsequence has been observed.
 * Empty sequences are valid and produce false. */
sg_anomaly_status_t
sg_anomaly_model_has_observed_netseq(const sg_anomaly_model_t *model,
                                     const char *netseq, size_t netseq_length,
                                     bool *observed);

/* Clear all counts and reset to a fresh model.
 * Hyperparameters are preserved. The operation is atomic: on failure the
 * existing counts remain unchanged. */
sg_anomaly_status_t sg_anomaly_model_reset(sg_anomaly_model_t *model);

/* Apply exponential decay to all counts.
 * Scale should be between 0.0 and 1.0 (e.g., 0.99 for 1% decay).
 * Entries with count < 1 after scaling are removed.
 * Use periodically to prevent unbounded memory growth in long-running
 * processes. */
/* Returns SG_ANOMALY_ERR_INVALID for a null model or scale outside (0, 1]. */
sg_anomaly_status_t sg_anomaly_model_decay(sg_anomaly_model_t *model,
                                           double scale);

/* Remove n-grams with count less than min_count.
 * On success, writes the total number of entries removed to `removed`.
 * The operation is atomic: on failure the model and `*removed` are unchanged.
 * Use to reduce model size and remove noise from rare patterns. */
sg_anomaly_status_t sg_anomaly_model_prune(sg_anomaly_model_t *model,
                                           size_t min_count, size_t *removed);

/* Rebuild all hash tables to compact their internal storage. Call after decay
 * or prune to recover memory. A memory failure can leave some tables compacted
 * but never changes learned counts or scores. */
sg_anomaly_status_t sg_anomaly_model_compact(sg_anomaly_model_t *model);

#ifdef __cplusplus
}
#endif

#endif /* SG_ANOMALY_H */
