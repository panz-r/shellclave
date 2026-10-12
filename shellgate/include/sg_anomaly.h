/*
 * sg_anomaly.h - Statistical Anomaly Detection for shellgate
 *
 * Uses a 4-gram language model with backoff to score anomaly-stage sequences.
 * The model owns copied, length-delimited byte keys; keys may contain NUL.
 *
 * Scores are average negative log-probability in bits per stage; higher
 * scores represent less probable sequences.
 */

#ifndef SG_ANOMALY_H
#define SG_ANOMALY_H

#include "shell_contract.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- TYPES --- */

/* Opaque anomaly model.  All memory is owned and freed on destroy. */
typedef struct sg_anomaly_model sg_anomaly_model_t;

/* Borrowed opaque anomaly-stage bytes. A valid item has non-NULL data and may
 * include embedded NUL bytes. A zero-length item is reserved for Shellsplit's
 * argv-less stage sentinel (redirect-only commands and structural empty Bash
 * `time` stages); it is not an executable name or necessarily an I/O operation.
 */
typedef struct {
  const char *data;
  size_t length;
} sg_anomaly_item_view_t;

/* Results returned by model operations. */
typedef enum {
  SG_ANOMALY_OK = 0,
  SG_ANOMALY_ERR_INVALID = -1,
  SG_ANOMALY_ERR_MEMORY = -2,
  SG_ANOMALY_ERR_FORMAT = -3,
  SG_ANOMALY_ERR_LIMIT = -4,
  SG_ANOMALY_ERR_IO = -5,
} sg_anomaly_status_t;

/* Maximum decoded anomaly-stage-item length accepted while learning. Scoring
 * accepts longer items and treats them as unknown. Four maximum-length items
 * fit exactly in the internal concatenated-netstring key limit. */
#define SG_ANOMALY_MAX_STAGE_LENGTH 1023

/* --- ERROR STATE --- */

/*
 * Returns true if learning or maintenance encountered an allocation failure.
 * This is a sticky diagnostic, not an unusable-model state: operations may be
 * retried without clearing it, and successful updates, decay, prune, or
 * compaction do not clear it. Call sg_anomaly_model_clear_error() after
 * observing the diagnostic. A successful reset or load replaces the model
 * with a fresh diagnostic state. Serialization reports failures through its
 * returned status, without setting this learning/maintenance diagnostic.
 */
bool sg_anomaly_model_had_error(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/*
 * Clear the OOM error flag after the caller has handled it.
 */
void sg_anomaly_model_clear_error(sg_anomaly_model_t *model) SHELL_NONNULL(1);

/* --- LIFECYCLE --- */

typedef struct {
  /* Dirichlet smoothing parameter; must be finite and positive. */
  double alpha;
  /* Fallback log-probability; must be finite. */
  double unknown_log_prior;
} sg_anomaly_config_t;

/* Initialize a configuration with the default hyperparameters. */
void sg_anomaly_config_default(sg_anomaly_config_t *config) SHELL_NONNULL(1);

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
 * Score an anomaly-stage sequence.
 *
 * `netseq` is a canonical concatenation of netstring records. Each record is
 * one opaque byte sequence, such as an executable name or a nested per-stage
 * type signature. A zero-length record is reserved for Shellsplit's
 * argv-less stage sentinel, including empty Bash `time` stages. Payloads may
 * contain NUL bytes; callers must always provide the explicit sequence length.
 *
 * Returns the average negative log-probability per anomaly stage (bits).
 * Higher = more anomalous.
 * On success, writes INFINITY when the sequence has fewer than three items or
 * the model is empty. Malformed and non-canonical framing returns
 * SG_ANOMALY_ERR_FORMAT.
 *
 * Items longer than SG_ANOMALY_MAX_STAGE_LENGTH are scored, not rejected.
 * They can never have been learned, so they score as unknown stages and read
 * as highly anomalous.
 *
 * Does not modify the model. Uses a bounded number of expected O(1) table
 * lookups per stage; scoring does not traverse the learned model's tables.
 */
sg_anomaly_status_t
sg_anomaly_model_score_netseq(const sg_anomaly_model_t *model,
                              const char *netseq, size_t netseq_length,
                              double *score) SHELL_NONNULL(1, 2, 4);

/* --- UPDATE (LEARNING) --- */

/*
 * Update the model with an anomaly-stage sequence.
 *
 * The model copies each decoded byte record. The caller retains ownership of
 * `netseq`. A zero-length record is the argv-less stage
 * sentinel; payloads may otherwise contain NUL bytes. Malformed framing is
 * rejected without changing the model.
 *
 * Updates every unigram and consecutive bigram, trigram, and 4-gram in the
 * sequence.
 *
 * Unigrams and bigrams are also updated when the record count is below 3
 * (e.g. a 2-token sequence contributes 1 bigram and 2 unigrams).
 */
sg_anomaly_status_t sg_anomaly_model_update_netseq(sg_anomaly_model_t *model,
                                                   const char *netseq,
                                                   size_t netseq_length)
    SHELL_NONNULL(1, 2);

/* --- SERIALISATION --- */

/*
 * Save the model to a versioned binary file.
 * Text header numbers use the C numeric locale, independently of the
 * caller's locale; the caller's thread and process locales are unchanged.
 * Writes to an owned temporary file beside path, then atomically replaces it.
 * Before replacement, failures leave the previous destination unchanged. A
 * parent-directory synchronization failure can report an error after the
 * complete new file is installed. Existing regular files retain their mode;
 * symlinks are replaced rather than followed, and other file types are
 * rejected. Filesystem-valid basenames need no extra room for a temporary
 * suffix. Permission and special mode bits are applied after serialization,
 * subject to OS permission rules; ownership is not copied. Temporary files
 * remain private until then. Concurrent saves to the same path require external
 * synchronization.
 * The complete save pathname, including NUL, must fit PATH_MAX; longer
 * spellings return SG_ANOMALY_ERR_IO with errno ENAMETOOLONG before creating
 * a file.
 *
 * Returns SG_ANOMALY_OK on success. On failure, returns a specific status and
 * preserves errno for OS-level diagnostics.
 */
sg_anomaly_status_t sg_anomaly_model_save(const sg_anomaly_model_t *model,
                                          const char *path) SHELL_NONNULL(1, 2);

/*
 * Load a model from a file written by sg_anomaly_model_save().
 *
 * Returns SG_ANOMALY_OK after decoding and closing the file successfully.
 * Malformed persisted data returns SG_ANOMALY_ERR_FORMAT.
 * Text headers require complete LF/CRLF lines without embedded NUL; binary
 * keys retain arbitrary bytes, including NUL. Header numbers use C-locale
 * decimal spelling regardless of the caller's locale.
 * Accumulated n-gram and context counts must fit signed 64-bit counters, and
 * totals must fit size_t; overflow returns SG_ANOMALY_ERR_LIMIT with errno
 * set to EOVERFLOW.
 * The existing model remains unchanged on every failure, including close
 * failure. Status and errno describe the first failure, not cleanup failures.
 */
sg_anomaly_status_t sg_anomaly_model_load(sg_anomaly_model_t *model,
                                          const char *path) SHELL_NONNULL(1, 2);

/* --- ACCESSORS --- */

/* Total number of unique anomaly stages observed (unigram vocabulary). */
size_t sg_anomaly_model_vocab_size(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Total number of unigram observations. */
size_t sg_anomaly_model_total_unigrams(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Total number of bigram observations. */
size_t sg_anomaly_model_total_bigrams(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Total number of trigram observations. */
size_t sg_anomaly_model_total_trigrams(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Total number of 4-gram observations. */
size_t sg_anomaly_model_total_fourgrams(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Get unigram count for opaque anomaly-stage bytes. Returns 0 if never seen
 * or the view is invalid. */
size_t sg_anomaly_model_unigram_count_view(const sg_anomaly_model_t *model,
                                           sg_anomaly_item_view_t cmd)
    SHELL_NONNULL(1);

/* Get count of unseen anomaly stages (for UNK probability estimation). */
size_t sg_anomaly_model_unknown_count(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Get the Kneser-Ney absolute discount parameter (default 0.5). */
double sg_anomaly_model_kneser_ney_discount(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Get bigram count for opaque anomaly-stage bytes. Returns 0 if never seen or
 * any view is invalid. */
size_t sg_anomaly_model_bigram_count_view(const sg_anomaly_model_t *model,
                                          sg_anomaly_item_view_t prev,
                                          sg_anomaly_item_view_t curr)
    SHELL_NONNULL(1);

/* Get trigram count for opaque anomaly-stage bytes. Returns 0 if never seen
 * or any view is invalid. */
size_t sg_anomaly_model_trigram_count_view(const sg_anomaly_model_t *model,
                                           sg_anomaly_item_view_t p2,
                                           sg_anomaly_item_view_t p1,
                                           sg_anomaly_item_view_t curr)
    SHELL_NONNULL(1);

/* Get 4-gram count for opaque anomaly-stage bytes. Returns 0 if never seen
 * or any view is invalid. */
size_t sg_anomaly_model_fourgram_count_view(const sg_anomaly_model_t *model,
                                            sg_anomaly_item_view_t p3,
                                            sg_anomaly_item_view_t p2,
                                            sg_anomaly_item_view_t p1,
                                            sg_anomaly_item_view_t curr)
    SHELL_NONNULL(1);

/* Get total number of unique n-gram contexts across all levels. */
size_t sg_anomaly_model_total_contexts(const sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Check whether any anomaly stage in a canonical netsequence has been
 * observed. Empty sequences are valid and produce false. */
sg_anomaly_status_t
sg_anomaly_model_has_observed_netseq(const sg_anomaly_model_t *model,
                                     const char *netseq, size_t netseq_length,
                                     bool *observed) SHELL_NONNULL(1, 2, 4);

/* Clear all counts and reset to a fresh model.
 * Hyperparameters are preserved. The operation is atomic: on failure the
 * existing counts remain unchanged. Success clears the sticky diagnostic. */
sg_anomaly_status_t sg_anomaly_model_reset(sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

/* Apply exponential decay to all counts.
 * Scale should be between 0.0 and 1.0 (e.g., 0.99 for 1% decay).
 * Each integer count becomes floor(count * scale), evaluated using the exact
 * supplied binary floating-point scale without rounding the count to double.
 * Entries with count < 1 after scaling are removed.
 * Use periodically to prevent unbounded memory growth in long-running
 * processes. */
/* Returns SG_ANOMALY_ERR_INVALID for scale outside (0, 1]. */
sg_anomaly_status_t sg_anomaly_model_decay(sg_anomaly_model_t *model,
                                           double scale) SHELL_NONNULL(1);

/* Remove authoritative n-grams with count less than min_count. Derived context
 * totals are rebuilt and are not included in `removed`.
 * On success, writes the total number of n-gram entries removed to `removed`.
 * The operation is atomic: on failure the model and `*removed` are unchanged.
 * Use to reduce model size and remove noise from rare patterns. */
sg_anomaly_status_t sg_anomaly_model_prune(sg_anomaly_model_t *model,
                                           size_t min_count, size_t *removed)
    SHELL_NONNULL(1, 3);

/* Rebuild all hash tables to compact their internal storage. Call after decay
 * or prune to recover memory. A memory failure can leave some tables compacted
 * but never changes learned counts or scores, and sets the sticky diagnostic.
 * All tables are attempted; retrying is safe and success does not clear a
 * previously recorded diagnostic. */
sg_anomaly_status_t sg_anomaly_model_compact(sg_anomaly_model_t *model)
    SHELL_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* SG_ANOMALY_H */
