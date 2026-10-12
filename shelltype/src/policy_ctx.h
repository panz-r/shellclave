#ifndef SHELLTYPE_POLICY_CTX_H
#define SHELLTYPE_POLICY_CTX_H

#include "shelltype.h"

/* Required live, distinct contexts. replacement is private staging storage;
 * the caller holds the destination policy's write lock. The operation checks
 * exclusive ownership under the context locks, since sharing may change while
 * compaction is staged. */
st_error_t st_policy_ctx_swap_storage(st_policy_ctx_t *destination,
                                      st_policy_ctx_t *replacement)
    SHELL_NONNULL(1, 2);
/* Required live context and length < SIZE_MAX readable bytes. Returned interned
 * storage is borrowed until the context is reset, compacted or released;
 * allocation failure returns NULL without invalidating existing strings.
 * data may be NULL only for length == 0. The caller provides a valid span;
 * embedded NUL bytes are preserved. This is not a
 * framing or pointer-validation boundary. */
const char *st_policy_ctx_intern_view(st_policy_ctx_t *ctx, const char *data,
                                      size_t length) SHELL_NONNULL(1);
/* Required live context. True when the caller reference and exactly one policy
 * reference remain; a snapshot, not a reservation of exclusive ownership. */
bool st_policy_ctx_is_exclusive(const st_policy_ctx_t *ctx) SHELL_NONNULL(1);

#endif
