#ifndef SHELLTYPE_POLICY_CTX_H
#define SHELLTYPE_POLICY_CTX_H

#include "shelltype.h"

/* Reset storage while the calling policy keeps its context reference. */
st_error_t st_policy_ctx_reset_for_policy(st_policy_ctx_t *ctx);

#endif
