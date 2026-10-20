#include "shell_expand_internal.h"
#include "shell_netstring.h"
#include "shell_source_internal.h"
#include <stdint.h>
#include <string.h>

#define SHELL_EXPAND_CAPACITY                                                  \
  (SHELL_DEP_MAX_NODES * SHELL_DEP_MAX_TOKENS + SHELL_DEP_MAX_EDGES)

static size_t shell_expand_capacity(size_t length) {
  return length < SHELL_EXPAND_CAPACITY ? length + 1 : SHELL_EXPAND_CAPACITY;
}

bool shell_expand_cache_size(size_t length, size_t *size) {
  size_t capacity = shell_expand_capacity(length);
  size_t entries =
      capacity * sizeof(shell_expand_entry_t) + SHELL_DEP_MAX_NODES;
  size_t padding = _Alignof(shell_expand_entry_t) - 1;
  if (length > (SIZE_MAX - entries - padding) / sizeof(uint32_t) - 1)
    return false;
  *size = entries + (length + 1) * sizeof(uint32_t) + padding;
  return true;
}

/* The partitioned evaluation tail is aligned for Shellsplit's workspace.
 * Retain the expansion cache at its front and align the remaining resolver
 * workspace once; both regions live until evaluation returns. */
bool shell_expand_cache_init(shell_expand_word_netargv_fn expand, void *context,
                             const char *source, size_t length,
                             bool measure_display, void *workspace,
                             size_t workspace_size, shell_expand_cache_t *cache,
                             void **resolver_workspace,
                             size_t *resolver_workspace_size) {
  size_t capacity = shell_expand_capacity(length);
  size_t entry_bytes =
      capacity * sizeof(shell_expand_entry_t) + SHELL_DEP_MAX_NODES;
  size_t offset_bytes = (length + 1) * sizeof(uint32_t);
  uintptr_t base = (uintptr_t)workspace;
  uintptr_t cursor = base + entry_bytes + offset_bytes;
  size_t alignment = shell_dep_workspace_alignment();
  cursor = (cursor + alignment - 1) & ~(uintptr_t)(alignment - 1);
  if (cursor < base || cursor - base > workspace_size)
    return false;
  *cache = (shell_expand_cache_t){
      .expand = expand,
      .context = context,
      .measure_display = measure_display,
      .source = source,
      .length = length,
      .capacity = capacity,
      .offsets = (uint32_t *)((char *)workspace + entry_bytes),
      .unresolved_paths =
          (uint8_t *)workspace + capacity * sizeof(shell_expand_entry_t),
      .entries = workspace,
  };
  memset(cache->offsets, 0, offset_bytes);
  *resolver_workspace = (void *)cursor;
  *resolver_workspace_size = workspace_size - (size_t)(cursor - base);
  return true;
}

/* word is within cache's immutable source; its offset indexes the initialized
 * source-sized table. Entries remain immutable until evaluation returns. */
const shell_dep_word_value_t *
shell_expand_lookup(const shell_expand_cache_t *cache, const char *word) {
  uint32_t handle = cache->offsets[(size_t)(word - cache->source)];
  return handle ? &cache->entries[handle - 1].value : NULL;
}

/* Canonical framing and resource arithmetic are checked once here, at the
 * callback boundary. value has zero-initialized count/display/first metadata;
 * netargv is the callback's possibly empty byte span. Successful metadata is
 * consumed without revalidation. */
static SHELL_NONNULL(1) bool shell_expand_validate(
    shell_dep_word_value_t *value, bool path, bool measure_display) {
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, value->netargv, value->length) !=
      SHELL_NETSTRING_OK)
    return false;
  shell_netstring_view_t view;
  shell_netstring_status_t status;
  while ((status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    if (path && memchr(view.payload, 0, view.payload_length))
      return false;
    if (!value->count) {
      value->first = (const char *)view.payload;
      value->first_length = view.payload_length;
    }
    size_t width = measure_display && value->count != 0;
    for (size_t i = 0; measure_display && i < view.payload_length; i++) {
      unsigned char byte = view.payload[i];
      size_t n = byte >= 0x20 && byte <= 0x7e && byte != '\\' ? 1 : 4;
      if (width > SIZE_MAX - n)
        return false;
      width += n;
    }
    if (value->display_length > SIZE_MAX - width)
      return false;
    value->display_length += width;
    value->count++;
  }
  return status == SHELL_NETSTRING_DONE;
}

/* request supplies unchanged parser spans within context's original source.
 * context is the initialized evaluation cache; both are required storage. */
const shell_dep_word_value_t *
shell_expand_resolve(const shell_dep_expand_request_t *request, void *context) {
  shell_expand_cache_t *cache = context;
  size_t offset = (size_t)(request->word - cache->source);
  uint32_t handle = cache->offsets[offset];
  if (handle)
    return &cache->entries[handle - 1].value;
  if (cache->count == cache->capacity) {
    cache->error = SHELL_DEP_ETRUNC;
    return NULL;
  }
  shell_expand_entry_t *entry = &cache->entries[cache->count++];
  *entry = (shell_expand_entry_t){0};
  cache->offsets[offset] = (uint32_t)cache->count;
  /* Arguments and redirect operands share the argument-context expansion
   * rule; redirect purpose still controls resolver eligibility below. */
  entry->value.dynamic = shell_source_argument_has_dynamic_syntax(
      request->word, request->word_length);
  if (!entry->value.dynamic || !request->eligible || !cache->expand)
    return &entry->value;
  shell_expand_word_request_t query = {
      .source = cache->source,
      .source_length = cache->length,
      .word_offset = (size_t)(request->word - cache->source),
      .word_length = request->word_length,
      .owner_offset = (size_t)(request->owner - cache->source),
      .owner_length = request->owner_length,
      .purpose = request->purpose,
      .cwd = request->cwd_known ? request->cwd : NULL,
      .cwd_known = request->cwd_known,
      .cwd_absolute = request->cwd_absolute,
  };
  shell_source_operation_t previous = shell_source_operation_suspend();
  shell_expand_status_t status = cache->expand(
      &query, &entry->value.netargv, &entry->value.length, cache->context);
  shell_source_operation_restore(previous);
  if (status == SHELL_EXPAND_UNRESOLVED) {
    entry->value.netargv = NULL;
    entry->value.length = 0;
    return &entry->value;
  }
  if (status != SHELL_EXPAND_RESOLVED ||
      !shell_expand_validate(&entry->value,
                             request->purpose != SHELL_EXPAND_WORD_ARGUMENT,
                             cache->measure_display)) {
    cache->error = SHELL_DEP_EEXPAND;
    return NULL;
  }
  entry->value.resolved = true;
  return &entry->value;
}
