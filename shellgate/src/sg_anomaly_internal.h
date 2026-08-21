#ifndef SG_ANOMALY_INTERNAL_H
#define SG_ANOMALY_INTERNAL_H

#include "sg_anomaly.h"
#include <stdio.h>

/* Internal stream form used to embed the unchanged v3 single-model format in
 * Shellgate's atomic hybrid bundle. The caller owns the stream. */
int sg_anomaly_write_stream(const sg_anomaly_model_t *model, FILE *stream);
int sg_anomaly_read_stream(sg_anomaly_model_t *model, FILE *stream);

#endif
