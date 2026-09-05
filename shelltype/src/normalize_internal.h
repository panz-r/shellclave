#ifndef SHELLTYPE_NORMALIZE_INTERNAL_H
#define SHELLTYPE_NORMALIZE_INTERNAL_H

#include "shelltype.h"

/* Allocation-free classifier storage for policy read paths. The text buffers
 * provide stable token text while the public visitor serves borrowed views. */
typedef struct {
  st_token_t tokens[ST_MAX_CMD_TOKENS];
  char text[ST_MAX_CMD_TOKENS][ST_MAX_TOKEN_LEN];
  size_t count;
} st_token_scratch_t;

st_error_t st_netargv_classify_scratch_view(st_netargv_view_t netargv,
                                            st_token_scratch_t *scratch);

/* Classify one explicit byte span with the same rules used for canonical
 * netargv payloads.  This is internal because public C-string classification
 * remains available through st_token_classify(). */
st_token_type_t st_token_classify_bytes(const char *text, size_t length);

#endif
