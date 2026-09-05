#ifndef SHELLTYPE_POLICY_CTX_H
#define SHELLTYPE_POLICY_CTX_H

#include "shelltype.h"

st_error_t st_policy_ctx_swap_storage(st_policy_ctx_t *destination,
                                      st_policy_ctx_t *replacement);
const char *st_policy_ctx_intern(st_policy_ctx_t *ctx, const char *str);
const char *st_policy_ctx_intern_view(st_policy_ctx_t *ctx, const char *data,
                                      size_t length);
/* True when the caller reference and exactly one policy reference remain. */
bool st_policy_ctx_is_exclusive(const st_policy_ctx_t *ctx);

#endif
