#ifndef SHELL_SOURCE_RUNTIME_INTERNAL_H
#define SHELL_SOURCE_RUNTIME_INTERNAL_H

#include "shell_tokenizer.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Operation-local lexical index. Delimiter consumers reuse source boundaries
 * found during the forward nested walk instead of balancing each ancestor's
 * suffix again. Entries refer only to the immutable root span and expire at
 * the end of the outer operation; this is not caller-consistency validation.
 * No public result owns this index or grows to carry it. */
enum {
  SHELL_SOURCE_INDEX_PARENS = 1,
  SHELL_SOURCE_INDEX_PARAMETER,
  SHELL_SOURCE_INDEX_DOUBLE_QUOTE,
  SHELL_SOURCE_INDEX_ARITHMETIC = 5,
  SHELL_SOURCE_INDEX_HEREDOC_BODY,
  SHELL_SOURCE_INDEX_UNCLOSED_PARENS,
  SHELL_SOURCE_INDEX_BACKTICK,
  SHELL_SOURCE_INDEX_UNCLOSED_BACKTICK,
  SHELL_SOURCE_INDEX_LITERAL_FRAGMENT,
  SHELL_SOURCE_INDEX_ARITHMETIC_BODY,
  SHELL_SOURCE_INDEX_UNCLOSED_ARITHMETIC_BODY,
};
typedef struct {
  uintptr_t begin, end, frontier;
} shell_source_scope_t;
/* Private backing, owned by one operation. Graphs reserve it in their existing
 * workspace; allocation-free defaults lease the bounded TLS instance. */
#define SHELL_SOURCE_INDEX_CAPACITY 4096u
typedef struct {
  uintptr_t key;
  size_t value, height;
  unsigned kind, generation;
} shell_source_index_entry_t;
typedef struct {
  shell_source_index_entry_t entries[SHELL_SOURCE_INDEX_CAPACITY];
} shell_source_index_t;
/* Non-evicting subscript facts. Entries are ordered by source offset, so an
 * unsuccessful outer candidate cannot make nested candidates rescan it.
 * parent is temporary linkage for the iterative matching walk. */
typedef struct shell_source_array_boundary {
  uintptr_t key, after, failed_end;
  struct shell_source_array_boundary *parent;
} shell_source_array_boundary_t;
#define SHELL_SOURCE_INLINE_ARRAYS 8u
/* Temporary value storage per source byte within the aggregate arena bound. */
enum { SHELL_SOURCE_VALUE_SCRATCH_FACTOR = 64 };
typedef struct {
  shell_source_array_boundary_t *entries;
  size_t count;
  bool prepared;
} shell_source_array_index_t;
typedef struct {
  uintptr_t begin, end;
  shell_source_scope_t scope;
  unsigned depth, generation;
  bool bytes_prechecked, owns_default_index;
  shell_source_index_t *index;
  unsigned char scratch[256];
  void *workspace;
  uintptr_t workspace_begin, workspace_end;
  size_t workspace_size, scratch_used;
  bool scratch_exhausted;
  void *owned_workspace;
  shell_source_array_index_t arrays;
  shell_source_array_boundary_t inline_arrays[SHELL_SOURCE_INLINE_ARRAYS];
} shell_source_operation_t;
#ifdef __cplusplus
extern "C" {
#endif
void shell_source_operation_begin(const char *input, size_t length)
    SHELL_NONNULL(1);
/* The root graph adapter already has a successful strict parse or qualified
 * draft prefix for exactly this operation's immutable root. Transfer its
 * byte-admission guarantee without traversing the source. Error/truncated
 * results establish no such guarantee. Independent callbacks do not inherit
 * it; recursive implementation views share their root's proof. */
void shell_source_operation_prechecked(void);
void shell_source_operation_end(void);
/* Allocating adapters reserve one operation-owned arena, reused by internal
 * views and released by operation_end. False means allocation failure and
 * leaves no active operation. Allocation-free boundaries never call this. */
bool shell_source_operation_begin_owned(const char *input, size_t length)
    SHELL_NONNULL(1);
/* Internal consumers explicitly share this operation. Application callbacks
 * suspend it instead: their public calls are independent validation domains,
 * even when their input overlaps the enclosing source. No cache is copied. */
shell_source_operation_t shell_source_operation_suspend(void);
void shell_source_operation_restore(shell_source_operation_t previous);
/* Bind initialized operation-local backing before any source traversal. The
 * required index is writable, aligned, and lives through the operation. */
void shell_source_operation_index(shell_source_index_t *index) SHELL_NONNULL(1);
/* Borrow optional additional scratch for this operation. NULL/zero keeps the
 * bounded private default. Contained consumers inherit their owner's buffer;
 * application callbacks have independent operations regardless of overlap. */
typedef struct {
  void *buffer;
  size_t size, used;
  bool exhausted, inherit;
  uintptr_t begin, end;
  shell_source_array_index_t arrays;
  bool share_arrays;
  shell_source_array_boundary_t inline_arrays[SHELL_SOURCE_INLINE_ARRAYS];
} shell_source_workspace_scope_t;
shell_source_workspace_scope_t
shell_source_workspace_begin(const char *source, size_t length, void *buffer,
                             size_t size) SHELL_NONNULL(1);
void shell_source_workspace_end(shell_source_workspace_scope_t previous);
size_t shell_source_scratch_mark(void);
void *shell_source_scratch_take(size_t size);
/* Reserve an aligned array within an active source operation. element_size
 * must be positive and alignment a nonzero power of two. Zero count permits
 * an empty span. Multiplication, padding overflow and capacity exhaustion
 * return NULL, set sticky exhaustion and leave the scratch mark unchanged.
 * Workspace sizing supplies capacity bounds; reservations check arithmetic
 * independently, including when callers provide smaller buffers. */
void *shell_source_scratch_take_array(size_t count, size_t element_size,
                                      size_t alignment);
void shell_source_scratch_release(size_t mark);
bool shell_source_scratch_exhausted(void);
/* Enter one borrowed lexical body, restoring its enclosing body on exit.
 * Index capacity belongs to this active scope and its ancestors, not to facts
 * from arbitrary siblings inspected earlier in the operation. */
shell_source_scope_t shell_source_scope_begin(const char *input, size_t length)
    SHELL_NONNULL(1);
void shell_source_scope_end(shell_source_scope_t previous);
/* A lexical iterator consumes its current scope in source order. Matching a
 * delimiter does not advance this frontier: its children have not been
 * consumed yet. NULL denotes an inactive/empty diagnostic iterator. */
void shell_source_scope_frontier(const char *input, size_t position);
bool shell_source_index_get(const char *input, size_t length, size_t position,
                            unsigned kind, size_t *value, size_t *height)
    SHELL_NONNULL(1, 5, 6);
void shell_source_index_put(const char *input, size_t length, size_t position,
                            unsigned kind, size_t value, size_t height)
    SHELL_NONNULL(1);
/* opening identifies a known opening bracket in this workspace's immutable
 * source view. NULL reports unavailable bookkeeping scratch, not a syntax
 * error. Returned storage lasts through the operation and is not evicted. */
shell_source_array_boundary_t *shell_source_array_boundary(const char *opening)
    SHELL_NONNULL(1);
/* Admission reuse is an operation fact. Only an admitted exact root grants
 * reuse to contained immutable spans; unrelated or suspended operations do not.
 * note_admitted records successful byte admission without scanning source. */
bool shell_source_operation_bytes_admitted(const char *source, size_t length)
    SHELL_NONNULL(1);
void shell_source_operation_note_admitted(const char *source, size_t length)
    SHELL_NONNULL(1);

/* An iterator borrows its source and optional workspace. Initialization may
 * clear unusable workspace fields; advancement restores its saved facts.
 * A non-NULL buffer supplies workspace_size exclusively borrowed bytes and
 * stays live through the scope. Advancement requires its initialized facts.
 * The returned scope must be ended once, after the iterator's work, with the
 * same workspace fields. Required field pointers reference distinct storage. */
typedef struct {
  shell_source_workspace_scope_t workspace;
  bool persistent;
} shell_source_iterator_scope_t;
shell_source_iterator_scope_t
shell_source_iterator_begin(const char *source, size_t length, void **workspace,
                            size_t *workspace_size, bool initialize)
    SHELL_NONNULL(1, 3, 4);
void shell_source_iterator_end(shell_source_iterator_scope_t previous,
                               void *workspace, size_t workspace_size);
#ifdef __cplusplus
}
#endif

#endif
