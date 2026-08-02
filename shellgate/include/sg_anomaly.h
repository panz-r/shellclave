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

/* ============================================================
 * TYPES
 * ============================================================ */

/* Opaque anomaly model.  All memory is owned and freed on destroy. */
typedef struct sg_anomaly_model sg_anomaly_model_t;

/* Maximum command-name length accepted by update, scoring, and lookup APIs.
 * Four maximum-length commands and their terminators fit exactly in the
 * serialized n-gram key limit. */
#define SG_ANOMALY_MAX_COMMAND_LENGTH 1023

/* ============================================================
 * ERROR STATE
 * ============================================================ */

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

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

/* Create a new model with default hyperparameters.
 * Returns NULL on allocation failure. */
sg_anomaly_model_t *sg_anomaly_model_new(void);

/* Create a new model with explicit hyperparameters.
 *
 *   alpha      : smoothing parameter (0.01 - 1.0 recommended, try 0.1)
 *   unk_prior  : log-probability of unseen command (try -10.0 = very rare)
 *
 * Returns NULL on allocation failure. */
sg_anomaly_model_t *sg_anomaly_model_new_ex(double alpha, double unk_prior);

/* Free all memory associated with the model. */
void sg_anomaly_model_free(sg_anomaly_model_t *model);

/* ============================================================
 * SCORING
 * ============================================================ */

/*
 * Score a command sequence.
 *
 * `seq` is an array of `len` non-null, non-empty command names (e.g. tokens[0]
 * from depgraph).
 * The model does NOT copy these strings — it only reads them.
 *
 * Returns the average negative log-probability per command (bits).
 * Higher = more anomalous.
 * Returns INFINITY if len < 3, or if any entry is NULL or empty.
 *
 * Names longer than SG_ANOMALY_MAX_COMMAND_LENGTH are scored, not rejected.
 * They can never have been learned, so they score as unknown commands and
 * read as highly anomalous.
 *
 * Does not modify the model.
 */
double sg_anomaly_score(const sg_anomaly_model_t *model, const char **seq,
                        size_t len);

/* ============================================================
 * UPDATE (LEARNING)
 * ============================================================ */

/*
 * Update the model with a command sequence.
 *
 * The model copies each non-null, non-empty command name — the caller's array
 * can be freed after this call without affecting the stored model. An invalid
 * sequence is ignored without changing the model.
 *
 * Updates every unigram and consecutive bigram, trigram, and 4-gram in the
 * sequence.
 *
 * Unigrams and bigrams are also updated even when len < 3
 * (e.g. a 2-token sequence contributes 1 bigram and 2 unigrams).
 */
void sg_anomaly_update(sg_anomaly_model_t *model, const char **seq, size_t len);

/* ============================================================
 * SERIALISATION
 * ============================================================ */

/*
 * Save the model to a versioned binary file.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int sg_anomaly_save(const sg_anomaly_model_t *model, const char *path);

/*
 * Load a model from a file written by sg_anomaly_save().
 *
 * Returns 0 on success, -1 on error (errno set).
 * On error, the existing model is unchanged.
 */
int sg_anomaly_load(sg_anomaly_model_t *model, const char *path);

/* ============================================================
 * ACCESSORS
 * ============================================================ */

/* Total number of unique commands observed (unigram vocabulary). */
size_t sg_anomaly_vocab_size(const sg_anomaly_model_t *model);

/* Total number of unigram observations. */
size_t sg_anomaly_total_uni(const sg_anomaly_model_t *model);

/* Total number of bigram observations. */
size_t sg_anomaly_total_bi(const sg_anomaly_model_t *model);

/* Total number of trigram observations. */
size_t sg_anomaly_total_tri(const sg_anomaly_model_t *model);

/* Total number of 4-gram observations. */
size_t sg_anomaly_total_quad(const sg_anomaly_model_t *model);

/* Get unigram count for a command.  Returns 0 if never seen. */
size_t sg_anomaly_uni_count(const sg_anomaly_model_t *model, const char *cmd);

/* Get count of unseen commands (for UNK probability estimation). */
size_t sg_anomaly_unk_count(const sg_anomaly_model_t *model);

/* Get the Kneser-Ney absolute discount parameter (default 0.5). */
double sg_anomaly_kn_discount(const sg_anomaly_model_t *model);

/* Get bigram count for (prev, curr). Returns 0 if never seen. */
size_t sg_anomaly_bi_count(const sg_anomaly_model_t *model, const char *prev,
                           const char *curr);

/* Get trigram count for (p2, p1, curr). Returns 0 if never seen. */
size_t sg_anomaly_tri_count(const sg_anomaly_model_t *model, const char *p2,
                            const char *p1, const char *curr);

/* Get 4-gram count for (p3, p2, p1, curr). Returns 0 if never seen. */
size_t sg_anomaly_quad_count(const sg_anomaly_model_t *model, const char *p3,
                             const char *p2, const char *p1, const char *curr);

/* Get total number of unique n-gram contexts across all levels. */
size_t sg_anomaly_total_contexts(const sg_anomaly_model_t *model);

/* Check if any command in the sequence has been observed by the model. */
bool sg_anomaly_has_observed(const sg_anomaly_model_t *model, const char **seq,
                             size_t len);

/* Clear all counts and reset to a fresh model.
 * Hyperparameters (alpha, unk_prior) are preserved. */
void sg_anomaly_reset(sg_anomaly_model_t *model);

/* Apply exponential decay to all counts.
 * Scale should be between 0.0 and 1.0 (e.g., 0.99 for 1% decay).
 * Entries with count < 1 after scaling are removed.
 * Use periodically to prevent unbounded memory growth in long-running
 * processes. */
void sg_anomaly_model_decay(sg_anomaly_model_t *model, double scale);

/* Remove n-grams with count less than min_count.
 * Returns total number of entries removed from all hash tables.
 * Use to reduce model size and remove noise from rare patterns. */
size_t sg_anomaly_model_prune(sg_anomaly_model_t *model, size_t min_count);

/* Rebuild all hash tables to compact their internal storage.
 * Call after decay or prune to recover memory.
 * Returns true if every table was compacted successfully. */
bool sg_anomaly_model_compact(sg_anomaly_model_t *model);

#ifdef __cplusplus
}
#endif

#endif /* SG_ANOMALY_H */
