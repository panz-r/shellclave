#ifndef SHELLGATE_TEST_EVAL_BUFFER_H
#define SHELLGATE_TEST_EVAL_BUFFER_H

#include "shell_depgraph.h"
#include "shellgate.h"
#include <stdint.h>

/* Test-only mirror of the size hint's result allowance and aligned private
 * tail placement. Derive the current complete workspace from Shellgate's
 * hint, not Shellsplit's smaller workspace. Keep this allowance in sync with
 * sg_gate_evaluate_size_hint; no production sizing or public API is added. */
static inline size_t sg_test_eval_workspace_size(size_t command_length) {
  size_t alignment = shell_dep_workspace_alignment();
  size_t hint = sg_gate_evaluate_size_hint(command_length);
  if (hint == SIZE_MAX || command_length > (SIZE_MAX - 512) / 4)
    return 0;
  size_t allowance = command_length * 4 + 512;
  if (hint < allowance + alignment - 1)
    return 0;
  return hint - allowance - (alignment - 1);
}

/* storage has workspace_size + prefix_size + alignment - 1 writable bytes,
 * where workspace_size is the measured evaluation workspace and alignment is
 * shell_dep_workspace_alignment(). Shift the buffer so its private tail starts
 * aligned immediately after exactly prefix_size public bytes. */
static inline SHELL_NONNULL(1) char *sg_test_eval_buffer_for_prefix(
    char *storage, size_t prefix_size) {
  size_t alignment = shell_dep_workspace_alignment();
  size_t remainder = ((uintptr_t)storage + prefix_size) % alignment;
  return storage + (remainder ? alignment - remainder : 0);
}

/* Source-sized private reservation before resolved-path extensions. buffer
 * is valid writable evaluation storage of buffer_size bytes. Returns
 * zero if it cannot contain a reserved private tail plus a public prefix.
 * The byte at the returned offset is private. An oversized resolved-path
 * fixture must subtract its additional private reservation from this offset;
 * preceding bytes are then the usable public prefix. */
static inline SHELL_NONNULL(1) size_t
    sg_test_eval_prefix_size(const char *buffer, size_t buffer_size,
                             size_t command_length) {
  size_t workspace = sg_test_eval_workspace_size(command_length);
  if (buffer_size == 0 || workspace == 0 || workspace > buffer_size)
    return 0;
  uintptr_t begin = (uintptr_t)buffer;
  if (buffer_size > UINTPTR_MAX - begin)
    return 0;
  uintptr_t start = begin + buffer_size - workspace;
  start -= start % shell_dep_workspace_alignment();
  return start <= begin ? 0 : (size_t)(start - begin);
}

#endif
