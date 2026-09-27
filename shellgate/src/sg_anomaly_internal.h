#ifndef SG_ANOMALY_INTERNAL_H
#define SG_ANOMALY_INTERNAL_H

#include "sg_anomaly.h"
#include <stdio.h>

/* Internal stream form used to embed the v7 single-model format in
 * Shellgate's atomic v2 hybrid bundle. The caller owns the stream. */
int sg_anomaly_write_stream(const sg_anomaly_model_t *model, FILE *stream);
int sg_anomaly_read_stream(sg_anomaly_model_t *model, FILE *stream);

/* Validate a canonical sequence and report its outer record count. */
sg_anomaly_status_t sg_anomaly_netseq_count(const char *netseq, size_t length,
                                            bool enforce_item_limit,
                                            size_t *count);

/* Learn matching raw and type sequences as one transaction. Their outer stage
 * counts must agree. If either model cannot accept the sample, neither retains
 * any of its learned counts. `raw`
 * and `type` must be distinct when both are non-NULL; a NULL type model
 * selects the single-model form used by compatibility callers. */
sg_anomaly_status_t sg_anomaly_models_update_netseq_pair(
    sg_anomaly_model_t *raw, const char *raw_netseq, size_t raw_length,
    sg_anomaly_model_t *type, const char *type_netseq, size_t type_length);

#endif
