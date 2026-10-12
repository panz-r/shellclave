#ifndef SG_ANOMALY_INTERNAL_H
#define SG_ANOMALY_INTERNAL_H

#include "sg_anomaly.h"
#include <stdio.h>

/* Model, sequence, score and count are required. Score a complete canonical
 * sequence in one traversal. On failure publish INFINITY and a zero count. */
sg_anomaly_status_t
sg_anomaly_score_netseq_count(const sg_anomaly_model_t *model,
                              const char *netseq, size_t length, double *score,
                              size_t *count) SHELL_NONNULL(1, 2, 4, 5);

/* Internal stream form used to embed the v7 single-model format in
 * Shellgate's atomic v2 hybrid bundle. The caller owns the stream; read is
 * failure-atomic. Typed results distinguish format, limit, memory and I/O
 * failures without relying on errno surviving unrelated cleanup. */
sg_anomaly_status_t sg_anomaly_write_stream(const sg_anomaly_model_t *model,
                                            FILE *stream) SHELL_NONNULL(1, 2);
sg_anomaly_status_t sg_anomaly_read_stream(sg_anomaly_model_t *model,
                                           FILE *stream) SHELL_NONNULL(1, 2);

/* Decode into one new owned model. The caller owns and closes stream; out
 * points to an empty destination and stays NULL on failure. Publication may
 * be deferred until an owning file/bundle operation has also closed streams.
 * Required storage remains valid and distinct throughout the call. */
sg_anomaly_status_t sg_anomaly_model_read_new(FILE *stream,
                                              sg_anomaly_model_t **out)
    SHELL_NONNULL(1, 2);

/* Learn matching raw and type sequences as one transaction. Their outer stage
 * counts must agree. If either model cannot accept the sample, neither retains
 * any of its learned counts. `raw`
 * and `type` must be distinct when both are non-NULL; a NULL type model
 * selects the single-model form used by compatibility callers. */
sg_anomaly_status_t sg_anomaly_models_update_netseq_pair(
    sg_anomaly_model_t *raw, const char *raw_netseq, size_t raw_length,
    sg_anomaly_model_t *type, const char *type_netseq, size_t type_length)
    SHELL_NONNULL(1, 2);

#endif
