#ifndef SG_ANOMALY_INTERNAL_H
#define SG_ANOMALY_INTERNAL_H

#include "sg_anomaly.h"
#include <stdio.h>

/* Internal stream form used to embed the v5 single-model format in
 * Shellgate's atomic v2 hybrid bundle. The caller owns the stream. */
int sg_anomaly_write_stream(const sg_anomaly_model_t *model, FILE *stream);
int sg_anomaly_read_stream(sg_anomaly_model_t *model, FILE *stream);

/* Validate a canonical sequence and report its outer record count. */
sg_anomaly_status_t sg_anomaly_netseq_count(const char *netseq, size_t length,
                                            bool enforce_item_limit,
                                            size_t *count);

#endif
