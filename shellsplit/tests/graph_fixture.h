#ifndef SHELLSPLIT_TEST_GRAPH_FIXTURE_H
#define SHELLSPLIT_TEST_GRAPH_FIXTURE_H

#include "shell_depgraph.h"

/* Owns workspace and graph storage. Initialize once, then borrow limits and
 * graphs until cleanup. Changing limits does not change owned storage. */
typedef struct {
  shell_dep_limits_t limits;
  void *workspace;
  shell_dep_graph_t *graph[2];
} shellsplit_graph_fixture_t;

typedef enum {
  SHELLSPLIT_FIXTURE_FIXED,
  SHELLSPLIT_FIXTURE_SOURCE,
  SHELLSPLIT_FIXTURE_RESOLVED
} shellsplit_fixture_size_t;

/* fixture points to empty writable storage and mode is a declared value;
 * graph_count is 0, 1 or 2. On failure no storage remains owned and destroy
 * is permitted. On success destroy must run before reinitializing fixture.
 * source_length sizes source scratch or resolved storage. round_capacity
 * exposes the rounded workspace capacity to the graph builder.
 * extra_storage reserves additional bytes beyond the requested capacity for
 * tests that deliberately offset the supplied workspace pointer. */
bool shellsplit_graph_fixture_init(shellsplit_graph_fixture_t *fixture,
                                   shellsplit_fixture_size_t mode,
                                   size_t source_length, unsigned graph_count,
                                   bool round_capacity, size_t extra_storage)
    SHELL_NONNULL(1);
void shellsplit_graph_fixture_destroy(shellsplit_graph_fixture_t *fixture)
    SHELL_NONNULL(1);
#endif
