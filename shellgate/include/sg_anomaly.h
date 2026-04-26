/*
 * sg_anomaly.h - Statistical Anomaly Detection for shellgate
 *
 * Uses a trigram language model with backoff to score command sequences.
 * The model owns all its memory (strings are strdup'd).
 *
 * Scoring: average negative log-probability in bits per command.
 * A higher score indicates a less probable (more anomalous) sequence.
 * Typical thresholds: 2.0-5.0 bits/command depending on workload.
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
 * `seq` is an array of `len` command names (e.g. tokens[0] from depgraph).
 * The model does NOT copy these strings — it only reads them.
 *
 * Returns the average negative log-probability per command (bits).
 * Higher = more anomalous.
 * Returns INFINITY if len < 3 (need at least one trigram).
 *
 * Does not modify the model.
 */
double sg_anomaly_score(const sg_anomaly_model_t *model,
                         const char **seq, size_t len);

/* ============================================================
 * UPDATE (LEARNING)
 * ============================================================ */

/*
 * Update the model with a command sequence.
 *
 * The model copies each command name — the caller's array can be freed
 * after this call without affecting the stored model.
 *
 * For each consecutive triple (p2, p1, curr) in the sequence:
 *   - Increment unigram count for curr
 *   - Increment bigram count for (p1, curr)
 *   - Increment trigram count for (p2, p1, curr)
 *
 * Unigrams and bigrams are also updated even when len < 3
 * (e.g. a 2-token sequence contributes 1 bigram and 2 unigrams).
 */
void sg_anomaly_update(sg_anomaly_model_t *model,
                        const char **seq, size_t len);

/* ============================================================
 * SERIALISATION
 * ============================================================ */

/*
 * Save the model to a text file.
 *
 * Format (one entry per line, no trailing blank line):
 *   U|cmd|count
 *   B|prev\0curr|count
 *   T|p2\0p1\0curr|count
 *   # alpha unk_prior total_uni total_bi total_tri
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int sg_anomaly_save(const sg_anomaly_model_t *model, const char *path);

/*
 * Load a model from a text file.
 *
 * Frees any existing model data and rebuilds from the file.
 * The file must be in the format written by sg_anomaly_save().
 *
 * Returns 0 on success, -1 on error (errno set).
 * On error, the model is left in an undefined state — caller should
 * free it and create a new one.
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

/* Get unigram count for a command.  Returns 0 if never seen. */
size_t sg_anomaly_uni_count(const sg_anomaly_model_t *model, const char *cmd);

/* Get count of unseen commands (for UNK probability estimation). */
size_t sg_anomaly_unk_count(const sg_anomaly_model_t *model);

/* Clear all counts and reset to a fresh model.
 * Hyperparameters (alpha, unk_prior) are preserved. */
void sg_anomaly_reset(sg_anomaly_model_t *model);

/* Apply exponential decay to all counts.
 * Scale should be between 0.0 and 1.0 (e.g., 0.99 for 1% decay).
 * Entries with count < 1 after scaling are removed.
 * Use periodically to prevent unbounded memory growth in long-running processes. */
void sg_anomaly_model_decay(sg_anomaly_model_t *model, double scale);

/* Remove n-grams with count less than min_count.
 * Returns total number of entries removed from all hash tables.
 * Use to reduce model size and remove noise from rare patterns. */
size_t sg_anomaly_model_prune(sg_anomaly_model_t *model, size_t min_count);

/* Rehash tables to smaller capacity if load factor is below 0.25.
 * Call after decay or prune to recover memory.
 * Returns true if any table was compacted, false otherwise. */
bool sg_anomaly_model_compact(sg_anomaly_model_t *model);

#ifdef __cplusplus
}
#endif

#endif /* SG_ANOMALY_H */
