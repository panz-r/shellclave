#ifndef SHELL_EXPAND_INTERNAL_H
#define SHELL_EXPAND_INTERNAL_H

#include "shell_depgraph.h"
#include "shell_expand.h"

/* Private whole-word resolution bridge. The owner/source are unchanged parser
 * spans. A resolved value was canonically validated by the application-facing
 * boundary; graph leaves consume these prechecked bytes without decoding them
 * as shell source. Prepared metadata stays immutable through construction;
 * payloads remain valid for the lifetime of the output graph. Request objects
 * and their borrowed CWD strings are callback-scoped; source spans retain the
 * source lifetime. NULL resolver disables resolution. Callback failure returns
 * NULL. */
typedef struct {
  const char *word;
  size_t word_length;
  const char *owner;
  size_t owner_length;
  const char *cwd;
  bool cwd_known, cwd_absolute;
  shell_expand_word_purpose_t purpose;
  bool eligible;
} shell_dep_expand_request_t;

typedef struct {
  const char *netargv;
  size_t length, count, display_length;
  const char *first;
  size_t first_length;
  bool resolved;
  bool dynamic;
} shell_dep_word_value_t;

typedef const shell_dep_word_value_t *(*shell_dep_expand_fn)(
    const shell_dep_expand_request_t *request, void *context)SHELL_NONNULL(1);

typedef struct {
  shell_dep_expand_fn expand;
  void *context;
} shell_dep_word_resolver_t;

typedef struct {
  shell_dep_word_value_t value;
} shell_expand_entry_t;

typedef struct {
  shell_expand_word_netargv_fn expand;
  void *context;
  bool measure_display;
  const char *source;
  size_t length, count, capacity;
  uint32_t *offsets;
  uint8_t *unresolved_paths;
  shell_expand_entry_t *entries;
  shell_dep_error_t error;
} shell_expand_cache_t;

bool shell_expand_cache_size(size_t length, size_t *size) SHELL_NONNULL(2);
/* source/length passed the source and arithmetic sizing boundaries. Workspace
 * is aligned and its readable/writable span has workspace_size bytes. This
 * partition checks remaining capacity; it does not repeat caller span or
 * source-correspondence checks. NULL expand disables application resolution.
 * context is optional. measure_display enables escaped diagnostic sizing in
 * the same framing pass, without imposing that byte scan on graph-only use. */
bool shell_expand_cache_init(shell_expand_word_netargv_fn expand, void *context,
                             const char *source, size_t length,
                             bool measure_display, void *workspace,
                             size_t workspace_size, shell_expand_cache_t *cache,
                             void **resolver_workspace,
                             size_t *resolver_workspace_size)
    SHELL_NONNULL(3, 6, 8, 9, 10);
/* Lookup/resolution require a successfully initialized cache and a word within
 * its unchanged source. entries and offsets reference its live workspace;
 * count <= capacity, and every nonzero offset handle is in [1, count] and
 * identifies an initialized entry. Zero is the sole cache-miss sentinel. */
const shell_dep_word_value_t *
shell_expand_lookup(const shell_expand_cache_t *cache, const char *word)
    SHELL_NONNULL(1, 2);
const shell_dep_word_value_t *
shell_expand_resolve(const shell_dep_expand_request_t *request, void *context)
    SHELL_NONNULL(1, 2);
#endif
