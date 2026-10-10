#ifndef SHELLTYPE_PATTERN_INTERNAL_H
#define SHELLTYPE_PATTERN_INTERNAL_H

#include "shelltype.h"
#include <string.h>

/* Policy command words cannot be compounds or whole-token ANY. token is a
 * valid decoded canonical token; type is a valid current or proposed type.
 * Editing a compound argument uses its capture type. This checks positional
 * grammar; storage and token metadata are caller preconditions. */
static inline SHELL_NONNULL(1) bool st_pattern_token_type_allowed(
    const st_token_t *token, size_t pos, st_token_type_t type) {
  return pos != 0 || (!token->compound && type != ST_TYPE_ANY);
}

/* Runtime wildcard acceptance is not lattice ordering: unclassified literals
 * satisfy only ANY, while some classified unions accept concrete forms.
 * Both types must be valid enum values. */
extern const uint64_t st_runtime_match_mask[ST_TYPE_COUNT];
static inline bool st_runtime_type_matches(st_token_type_t concrete,
                                           st_token_type_t wildcard) {
  return (st_runtime_match_mask[concrete] & (UINT64_C(1) << wildcard)) != 0;
}

/* Test literal affixes and borrow the intervening capture, including an empty
 * capture. Every span is readable and required pointers are valid even when
 * its length is zero; output storage is distinct from input. On a mismatch,
 * outputs are unchanged. No terminators, copies or framing validation. */
static inline SHELL_NONNULL(1, 3, 5, 7, 8) bool st_pattern_capture_span(
    const char *text, size_t text_length, const char *prefix,
    size_t prefix_length, const char *suffix, size_t suffix_length,
    const char **capture, size_t *capture_length) {
  if (prefix_length > text_length ||
      suffix_length > text_length - prefix_length ||
      memcmp(text, prefix, prefix_length) != 0 ||
      memcmp(text + text_length - suffix_length, suffix, suffix_length) != 0)
    return false;
  *capture = text + prefix_length;
  *capture_length = text_length - prefix_length - suffix_length;
  return true;
}

/* Match a classified value against a valid canonical wildcard spelling.
 * Required byte spans need no terminator. The caller supplies the correct
 * standalone or argv-context classification; this helper checks runtime type
 * acceptance and closed parameter metadata, not token consistency. */
bool st_pattern_wildcard_matches(const char *text, size_t text_length,
                                 st_token_type_t type, const char *wildcard,
                                 size_t wildcard_length,
                                 st_token_type_t wildcard_type)
    SHELL_NONNULL(1, 4);

#endif
