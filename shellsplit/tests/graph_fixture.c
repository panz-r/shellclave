#include "graph_fixture.h"
#include "shell_tokenizer.h"
#include <stdint.h>
#include <stdlib.h>

bool shellsplit_graph_fixture_init(shellsplit_graph_fixture_t *fixture,
                                   shellsplit_fixture_size_t mode,
                                   size_t source_length, unsigned graph_count,
                                   bool round_capacity, size_t extra_storage) {
  *fixture = (shellsplit_graph_fixture_t){.limits = SHELL_DEP_LIMITS_DEFAULT};
  size_t bytes, extra;
  if (!shell_dep_workspace_size(&fixture->limits, &bytes))
    return false;
  if (mode == SHELLSPLIT_FIXTURE_SOURCE) {
    if (!shell_source_workspace_size(source_length, &extra) ||
        extra > SIZE_MAX - bytes)
      return false;
    bytes += extra;
  } else if (mode == SHELLSPLIT_FIXTURE_RESOLVED) {
    if (!shell_dep_resolved_workspace_size(source_length, &fixture->limits,
                                           &extra))
      return false;
    if (extra > bytes)
      bytes = extra;
  }
  size_t alignment = shell_dep_workspace_alignment();
  if (bytes > SIZE_MAX - (alignment - 1))
    return false;
  size_t capacity = round_capacity
                        ? ((bytes + alignment - 1) / alignment) * alignment
                        : bytes;
  if (extra_storage > SIZE_MAX - capacity ||
      capacity + extra_storage > SIZE_MAX - (alignment - 1))
    return false;
  size_t allocated =
      ((capacity + extra_storage + alignment - 1) / alignment) * alignment;
  fixture->workspace = aligned_alloc(alignment, allocated);
  if (!fixture->workspace)
    return false;
  fixture->limits.workspace = fixture->workspace;
  fixture->limits.workspace_size = capacity;
  for (unsigned i = 0; i < graph_count; ++i) {
    fixture->graph[i] = malloc(sizeof(*fixture->graph[i]));
    if (!fixture->graph[i]) {
      shellsplit_graph_fixture_destroy(fixture);
      return false;
    }
  }
  return true;
}

void shellsplit_graph_fixture_destroy(shellsplit_graph_fixture_t *fixture) {
  free(fixture->graph[1]);
  free(fixture->graph[0]);
  free(fixture->workspace);
  *fixture = (shellsplit_graph_fixture_t){0};
}
