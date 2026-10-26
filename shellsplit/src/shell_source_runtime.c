#include "alloc.h"
#include "shell_heredoc_storage_internal.h"
#include "shell_source.h"
#include "shell_source_lexical_internal.h"
#include "shell_source_runtime_internal.h"
#include <stdlib.h>
#include <string.h>

/* Internal views share one immutable source operation. User callbacks suspend
 * its scalar state and keep its cache live in the owning workspace. */
#define SHELL_SOURCE_INDEX_PROBES (4u * SHELL_MAX_SUBCOMMANDS)
typedef shell_source_index_entry_t source_index_entry_t;
static _Thread_local shell_source_operation_t source_operation;
static _Thread_local shell_source_index_t default_index;
static _Thread_local unsigned default_generation;
static _Thread_local bool default_index_borrowed;

/* Shared source arena bound. Printer pieces, live nested delimiter values,
 * decoded subjects, conditional patterns and compiled builtin-test programs
 * use the front. Persistent subscript facts and iterator continuation records
 * use the tail. The value allowance covers pattern units, a literal run's
 * size_t prefix table, a decoded subject, and prepared test arguments/nodes
 * with alignment. Test programs borrow this arena through recursive analysis.
 * This bounds storage independently of syntax/depth/output capacities and
 * does not inspect source bytes. */
bool shell_source_workspace_size(size_t length, size_t *size) {
  const size_t factor = SHELL_HEREDOC_PIECE_FACTOR +
                        SHELL_SOURCE_VALUE_SCRATCH_FACTOR +
                        sizeof(shell_source_array_boundary_t) + 64;
  *size = 0;
  if (length > SIZE_MAX / factor)
    return false;
  *size = length * factor;
  return true;
}

void shell_source_operation_begin(const char *input, size_t length) {
  if (source_operation.depth++ != 0)
    return;
  source_operation.begin = (uintptr_t)input;
  source_operation.end = (uintptr_t)input + length;
  source_operation.scope = (shell_source_scope_t){
      source_operation.begin, source_operation.end, source_operation.begin};
  source_operation.bytes_prechecked = false;
  source_operation.index = NULL;
  source_operation.owns_default_index = !default_index_borrowed;
  if (source_operation.owns_default_index) {
    default_index_borrowed = true;
    source_operation.index = &default_index;
    if (++default_generation == 0) {
      memset(&default_index, 0, sizeof(default_index));
      default_generation = 1;
    }
    source_operation.generation = default_generation;
  }
  source_operation.workspace = NULL;
  source_operation.workspace_begin = source_operation.begin;
  source_operation.workspace_end = source_operation.end;
  source_operation.workspace_size = source_operation.scratch_used = 0;
  source_operation.scratch_exhausted = false;
  source_operation.owned_workspace = NULL;
  source_operation.arrays = (shell_source_array_index_t){0};
}

void shell_source_operation_prechecked(void) {
  source_operation.bytes_prechecked = true;
}

bool shell_source_operation_begin_owned(const char *input, size_t length) {
  shell_source_operation_begin(input, length);
  if (source_operation.depth != 1)
    return true;
  /* One conservative sizing scan, not another syntax pass. Source without
   * documents or many brackets needs no arena. Flat delimiters retain their
   * two-byte bound, plus the measured bracket-record storage; only grouped
   * delimiter spelling needs the source-sized printer bound. Quoted/data
   * bracket occurrences may overreserve records, not a whole printer arena. */
  bool document = false, grouped = false;
  size_t brackets = 0;
  for (size_t i = 0; i < length; i++) {
    SHELL_SOURCE_WORD_SCAN(1);
    brackets += input[i] == '[';
    document |= input[i] == '<' &&
                shell_source_logical_next_is(input, length, i, '<', NULL);
    grouped |= shell_source_heredoc_fragment_open(input, length, i) ||
               shell_source_process_substitution_open(input, length, i, NULL);
  }
  source_operation.arrays.count = brackets;
  bool array_storage = brackets > SHELL_SOURCE_INLINE_ARRAYS;
  if (!document && !array_storage)
    return true;
  size_t size = 0;
  bool printer = document && grouped;
  bool sized = true;
  if (printer)
    sized = shell_source_workspace_size(length, &size);
  else {
    if (document) {
      sized = length <= SIZE_MAX / 2;
      if (sized)
        size = 2 * length;
    }
    size_t padding = _Alignof(shell_source_array_boundary_t) - 1;
    if (brackets) {
      sized = sized && size <= SIZE_MAX - padding &&
              brackets <= (SIZE_MAX - size - padding) /
                              sizeof(shell_source_array_boundary_t);
      if (sized)
        size += brackets * sizeof(shell_source_array_boundary_t) + padding;
    }
  }
  if (!sized) {
    shell_source_operation_end();
    return false;
  }
  if (size <= sizeof(source_operation.scratch) && !array_storage)
    return true;
  source_operation.owned_workspace = malloc(size);
  if (!source_operation.owned_workspace) {
    shell_source_operation_end();
    return false;
  }
  source_operation.workspace = source_operation.owned_workspace;
  source_operation.workspace_size = size;
  return true;
}

void shell_source_operation_end(void) {
  if (--source_operation.depth == 0) {
    free(source_operation.owned_workspace);
    source_operation.owned_workspace = NULL;
    if (source_operation.owns_default_index)
      default_index_borrowed = false;
    source_operation.owns_default_index = false;
    source_operation.index = NULL;
    source_operation.workspace = NULL;
    source_operation.workspace_size = source_operation.scratch_used = 0;
  }
}

shell_source_operation_t shell_source_operation_suspend(void) {
  shell_source_operation_t previous = source_operation;
  source_operation = (shell_source_operation_t){0};
  return previous;
}

void shell_source_operation_restore(shell_source_operation_t previous) {
  source_operation = previous;
}

void shell_source_operation_index(shell_source_index_t *index) {
  if (source_operation.depth != 1)
    return; /* An internal subparse already shares its owner's backing. */
  if (source_operation.owns_default_index)
    default_index_borrowed = false;
  source_operation.owns_default_index = false;
  memset(index, 0, sizeof(*index));
  source_operation.index = index;
  source_operation.generation = 1;
}

shell_source_workspace_scope_t shell_source_workspace_begin(const char *source,
                                                            size_t length,
                                                            void *buffer,
                                                            size_t size) {
  uintptr_t begin = (uintptr_t)source;
  shell_source_workspace_scope_t previous = {
      source_operation.workspace,
      source_operation.workspace_size,
      source_operation.scratch_used,
      source_operation.scratch_exhausted,
      begin >= source_operation.workspace_begin &&
          begin <= source_operation.workspace_end &&
          length <= source_operation.workspace_end - begin,
      source_operation.workspace_begin,
      source_operation.workspace_end,
      source_operation.arrays,
      false,
      {{0}}};
  if (!previous.inherit) {
    source_operation.scratch_exhausted = false;
    source_operation.workspace = NULL;
    source_operation.workspace_size = source_operation.scratch_used = 0;
    source_operation.workspace_begin = begin;
    source_operation.workspace_end = begin + length;
    source_operation.arrays = (shell_source_array_index_t){0};
  }
  bool replace = buffer && size > sizeof(source_operation.scratch) &&
                 buffer != source_operation.workspace;
  previous.share_arrays = previous.inherit && !replace;
  if (!previous.share_arrays && previous.arrays.prepared &&
      !previous.arrays.entries)
    memcpy(previous.inline_arrays, source_operation.inline_arrays,
           sizeof(previous.inline_arrays));
  if (replace) {
    source_operation.workspace = buffer;
    source_operation.workspace_size = size;
    source_operation.scratch_used = 0;
    source_operation.arrays = (shell_source_array_index_t){0};
  }
  return previous;
}

void shell_source_workspace_end(shell_source_workspace_scope_t previous) {
  bool failed = source_operation.scratch_exhausted;
  size_t size = source_operation.workspace_size;
  shell_source_array_index_t arrays = source_operation.arrays;
  source_operation.workspace = previous.buffer;
  source_operation.workspace_size =
      previous.share_arrays ? size : previous.size;
  source_operation.scratch_used = previous.used;
  source_operation.workspace_begin = previous.begin;
  source_operation.workspace_end = previous.end;
  source_operation.arrays = previous.share_arrays ? arrays : previous.arrays;
  if (!previous.share_arrays && previous.arrays.prepared &&
      !previous.arrays.entries)
    memcpy(source_operation.inline_arrays, previous.inline_arrays,
           sizeof(previous.inline_arrays));
  source_operation.scratch_exhausted =
      previous.exhausted || (previous.inherit && failed);
}

size_t shell_source_scratch_mark(void) { return source_operation.scratch_used; }

void *shell_source_scratch_take(size_t size) {
  size_t capacity = source_operation.workspace
                        ? source_operation.workspace_size
                        : sizeof(source_operation.scratch);
  if (size > capacity - source_operation.scratch_used) {
    source_operation.scratch_exhausted = true;
    return NULL;
  }
  unsigned char *base = source_operation.workspace ? source_operation.workspace
                                                   : source_operation.scratch;
  void *result = base + source_operation.scratch_used;
  source_operation.scratch_used += size;
  return result;
}

void *shell_source_scratch_take_array(size_t count, size_t element_size,
                                      size_t alignment) {
  size_t padding = alignment - 1;
  if (count > SIZE_MAX / element_size ||
      count * element_size > SIZE_MAX - padding) {
    source_operation.scratch_exhausted = true;
    return NULL;
  }
  unsigned char *storage =
      shell_source_scratch_take(count * element_size + padding);
  if (!storage)
    return NULL;
  return storage + (-(uintptr_t)storage & (uintptr_t)padding);
}

void shell_source_scratch_release(size_t mark) {
  source_operation.scratch_used = mark;
}

bool shell_source_scratch_exhausted(void) {
  return source_operation.scratch_exhausted ||
         (source_operation.depth && !source_operation.index);
}

/* Reserve persistent facts from the arena's tail. Temporary source-scratch
 * marks release only its front; they cannot overwrite the index while
 * unwinding. Counting and filling are two linear storage-preparation passes,
 * not syntax validation. Ordinary bracket data is deliberately allowed to
 * overreserve. */
static void source_array_index_prepare(void) {
  shell_source_array_index_t *index = &source_operation.arrays;
  if (index->prepared)
    return;
  index->prepared = true;
  const char *source = (const char *)source_operation.workspace_begin;
  size_t length =
      source_operation.workspace_end - source_operation.workspace_begin;
  /* Allocating adapters already measured this immutable view. Zero can mean
   * unmeasured: a requested opening bracket proves the count is nonzero. */
  size_t count = index->count;
  if (!count) {
    for (size_t i = 0; i < length; ++i) {
      SHELL_SOURCE_WORD_SCAN(1);
      count += source[i] == '[';
    }
  }
  index->count = count;
  shell_source_array_boundary_t *entries = source_operation.inline_arrays;
  if (count > SHELL_SOURCE_INLINE_ARRAYS || source_operation.workspace) {
    size_t capacity = source_operation.workspace_size;
    size_t alignment = _Alignof(shell_source_array_boundary_t);
    if (!source_operation.workspace || count > SIZE_MAX / sizeof(*entries))
      goto exhausted;
    size_t bytes = count * sizeof(*entries);
    uintptr_t base = (uintptr_t)source_operation.workspace;
    if (bytes > capacity)
      goto exhausted;
    uintptr_t at = (base + capacity - bytes) & ~(uintptr_t)(alignment - 1);
    if (at < base || at - base < source_operation.scratch_used)
      goto exhausted;
    source_operation.workspace_size = at - base;
    index->entries = entries = (shell_source_array_boundary_t *)at;
  }
  size_t entry = 0;
  for (size_t i = 0; i < length; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (source[i] == '[')
      entries[entry++] =
          (shell_source_array_boundary_t){.key = (uintptr_t)(source + i)};
  }
  return;
exhausted:
  source_operation.scratch_exhausted = true;
}

shell_source_array_boundary_t *
shell_source_array_boundary(const char *opening) {
  source_array_index_prepare();
  if (source_operation.scratch_exhausted)
    return NULL;
  shell_source_array_index_t *index = &source_operation.arrays;
  shell_source_array_boundary_t *entries =
      index->entries ? index->entries : source_operation.inline_arrays;
  uintptr_t key = (uintptr_t)opening;
  size_t low = 0, high = index->count;
  while (low < high) {
    size_t mid = low + (high - low) / 2;
    if (entries[mid].key < key)
      low = mid + 1;
    else
      high = mid;
  }
  return &entries[low];
}

/* A public iterator can outlive one next() operation. Its supplied workspace
 * retains the same private facts between calls; no iterator/result grows to
 * own them. Small default iterations have at most eight bracket candidates,
 * so recreating their bounded inline index cannot cause quadratic work. */
typedef struct {
  shell_source_array_index_t arrays;
  size_t scratch_size;
} source_iterator_workspace_t;

static SHELL_NONNULL(1) void source_iterator_workspace_save(
    void *workspace, size_t workspace_size) {
  source_iterator_workspace_t saved = {source_operation.arrays,
                                       source_operation.workspace_size};
  if (!saved.arrays.entries)
    saved.arrays = (shell_source_array_index_t){0};
  memcpy((char *)workspace + workspace_size - sizeof(saved), &saved,
         sizeof(saved));
}

shell_source_scope_t shell_source_scope_begin(const char *input,
                                              size_t length) {
  shell_source_scope_t previous = source_operation.scope;
  source_operation.scope = (shell_source_scope_t){
      (uintptr_t)input, (uintptr_t)input + length, (uintptr_t)input};
  return previous;
}

void shell_source_scope_end(shell_source_scope_t previous) {
  source_operation.scope = previous;
}

void shell_source_scope_frontier(const char *input, size_t position) {
  /* A separate word-view iterator must not advance its enclosing body. This
   * selects the scratch owner; it does not validate a source/parse contract. */
  if (input && (uintptr_t)input == source_operation.scope.begin)
    source_operation.scope.frontier = (uintptr_t)input + position;
}

static SHELL_NONNULL(1) bool source_operation_contains(const char *input,
                                                       size_t length) {
  uintptr_t begin = (uintptr_t)input;
  return source_operation.depth != 0 && begin >= source_operation.begin &&
         begin <= source_operation.end &&
         length <= source_operation.end - begin;
}

static SHELL_NONNULL(1) source_index_entry_t *source_index_entry(
    const char *input, size_t length, size_t position, unsigned kind) {
  if (!source_operation.index || !source_operation_contains(input, length))
    return NULL;
  uintptr_t key = (uintptr_t)input + position;
  size_t slot = ((key >> 3) ^ key ^ (kind * 31u)) % SHELL_SOURCE_INDEX_CAPACITY;
  source_index_entry_t *available = NULL;
  for (size_t probe = 0; probe < SHELL_SOURCE_INDEX_PROBES; probe++) {
    source_index_entry_t *entry = &source_operation.index->entries[slot];
    if (entry->generation != source_operation.generation)
      return available ? available : entry;
    if (entry->key == key && entry->kind == kind)
      return entry;
    uintptr_t after = entry->value;
    /* Completed siblings and facts outside the current body must not crowd
     * out its boundaries. Enclosing boundaries stay live while a child owns
     * the scratch. Keep probing for an exact hit before reusing a slot,
     * preserving collision chains. */
    if (!available && (after < source_operation.scope.begin ||
                       entry->key > source_operation.scope.end ||
                       (entry->key >= source_operation.scope.begin &&
                        after <= source_operation.scope.frontier)))
      available = entry;
    slot = (slot + 1) % SHELL_SOURCE_INDEX_CAPACITY;
  }
  return available;
}

bool shell_source_index_get(const char *input, size_t length, size_t position,
                            unsigned kind, size_t *value, size_t *height) {
  source_index_entry_t *entry =
      source_index_entry(input, length, position, kind);
  if (!entry || entry->generation != source_operation.generation ||
      entry->key != (uintptr_t)input + position || entry->kind != kind)
    return false;
  *value = entry->value - (uintptr_t)input;
  *height = entry->height;
  return true;
}

void shell_source_index_put(const char *input, size_t length, size_t position,
                            unsigned kind, size_t value, size_t height) {
  source_index_entry_t *entry =
      source_index_entry(input, length, position, kind);
  if (!entry) {
    if (!source_operation.index || !source_operation_contains(input, length))
      return;
    uintptr_t key = (uintptr_t)input + position;
    size_t slot =
        ((key >> 3) ^ key ^ (kind * 31u)) % SHELL_SOURCE_INDEX_CAPACITY;
    entry = &source_operation.index->entries[slot];
    size_t smallest = entry->value - entry->key;
    for (size_t probe = 1; probe < SHELL_SOURCE_INDEX_PROBES; probe++) {
      source_index_entry_t *candidate =
          &source_operation.index
               ->entries[(slot + probe) % SHELL_SOURCE_INDEX_CAPACITY];
      size_t span = candidate->value - candidate->key;
      if (span < smallest) {
        entry = candidate;
        smallest = span;
      }
    }
    /* A short sibling must not evict an enclosing subtree boundary: losing
     * that boundary causes its complete suffix to be visited at every level.
     * Prefer the entries that avoid the largest source traversal. */
    size_t span = value - position;
    if (span < smallest)
      return;
  }
  *entry = (source_index_entry_t){.key = (uintptr_t)input + position,
                                  .value = (uintptr_t)input + value,
                                  .kind = kind,
                                  .height = height,
                                  .generation = source_operation.generation};
}

bool shell_source_operation_bytes_admitted(const char *source, size_t length) {
  return source_operation.bytes_prechecked &&
         source_operation_contains(source, length);
}

void shell_source_operation_note_admitted(const char *source, size_t length) {
  if (source_operation.depth != 0 &&
      (uintptr_t)source == source_operation.begin &&
      length == source_operation.end - source_operation.begin)
    source_operation.bytes_prechecked = true;
}

shell_source_iterator_scope_t
shell_source_iterator_begin(const char *source, size_t length, void **workspace,
                            size_t *workspace_size, bool initialize) {
  shell_source_operation_begin(source, length);
  bool independent = source_operation.depth == 1;
  if (initialize &&
      (!independent ||
       *workspace_size <= sizeof(source_operation.scratch) +
                              sizeof(source_iterator_workspace_t))) {
    *workspace = NULL;
    *workspace_size = 0;
  }
  shell_source_iterator_scope_t previous = {
      .workspace = shell_source_workspace_begin(source, length, *workspace,
                                                *workspace_size),
      .persistent = independent && *workspace};
  if (previous.persistent) {
    if (initialize)
      source_operation.workspace_size -= sizeof(source_iterator_workspace_t);
    else {
      source_iterator_workspace_t saved;
      memcpy(&saved, (char *)*workspace + *workspace_size - sizeof(saved),
             sizeof(saved));
      source_operation.workspace_size = saved.scratch_size;
      source_operation.arrays = saved.arrays;
    }
  }
  return previous;
}

void shell_source_iterator_end(shell_source_iterator_scope_t previous,
                               void *workspace, size_t workspace_size) {
  if (previous.persistent)
    source_iterator_workspace_save(workspace, workspace_size);
  shell_source_workspace_end(previous.workspace);
  shell_source_operation_end();
}
