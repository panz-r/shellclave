#ifndef SHELLTYPE_NORMALIZE_INTERNAL_H
#define SHELLTYPE_NORMALIZE_INTERNAL_H

#include "shelltype.h"

/* Allocation-free classifier storage for policy read paths. Text borrows
 * immutable netargv payloads for the call's lifetime, with explicit lengths.
 * Empty payloads use a static empty string for the legacy token length rule. */
typedef struct {
  st_token_t tokens[ST_MAX_CMD_TOKENS];
  size_t count;
} st_token_scratch_t;

st_error_t st_netargv_classify_scratch_view(st_netargv_view_t netargv,
                                            st_token_scratch_t *scratch)
    SHELL_NONNULL(2);

/* Classify one explicit byte span with the same rules used for canonical
 * netargv payloads.  This is internal because public C-string classification
 * remains available through st_token_classify(). The caller supplies immutable
 * readable storage of `length` bytes for the call. NULL is permitted only for
 * an empty span (length == 0); this leaf does not validate span storage. */
st_token_type_t st_token_classify_bytes(const char *text, size_t length);

/* Context is determined by the preceding concrete argv payload, not its type.
 * Empty spans may have NULL data. These helpers consume already-delimited
 * immutable payloads; they do not validate framing or copy their storage. */
typedef enum {
  ST_ARG_CONTEXT_NONE,
  ST_ARG_CONTEXT_LONG_OPTION,
  ST_ARG_CONTEXT_SIGNAL,
  ST_ARG_CONTEXT_REGEX,
  ST_ARG_CONTEXT_COUNT
} st_arg_context_t;
st_arg_context_t st_arg_context_after(const char *text, size_t length);
st_token_type_t st_token_classify_context(const char *text, size_t length,
                                          st_arg_context_t context);

/* Possible runtime types of a literal at pos in valid canonical pattern
 * tokens. pos is in bounds and tokens[pos] is a non-compound literal. A
 * literal predecessor determines the exact context; a generalized predecessor
 * leaves it unknown, so every context is considered. This is semantic coverage
 * analysis, not token validation. Only the immediate predecessor is read. */
uint64_t st_pattern_literal_types(const st_token_t *tokens, size_t pos)
    SHELL_NONNULL(1);

/* A compound edit changes its capture, never its outer literal token. */
static inline SHELL_NONNULL(1) st_token_type_t
    st_token_edit_type(const st_token_t *token) {
  return token->compound ? token->capture_type : token->type;
}

#endif
