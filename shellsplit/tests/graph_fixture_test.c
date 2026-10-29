#include "graph_fixture.h"
#include <stdint.h>
#include <stdio.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fixture: %s:%d: %s\n", __FILE__, __LINE__, #x);         \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  shellsplit_graph_fixture_t fixture;
  size_t alignment = shell_dep_workspace_alignment();
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 64,
                                      2, true, alignment));
  CHECK(fixture.graph[0] && fixture.graph[1] &&
        fixture.graph[0] != fixture.graph[1]);
  CHECK((uintptr_t)fixture.workspace % alignment == 0);
  CHECK(fixture.limits.workspace_size % alignment == 0);
  ((unsigned char *)
       fixture.workspace)[fixture.limits.workspace_size + alignment - 1] = 1;
  fixture.limits.workspace = NULL;
  fixture.limits.workspace_size = 0;
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 65,
                                      0, true, 1));
  ((unsigned char *)fixture.workspace)[fixture.limits.workspace_size] = 1;
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 0,
                                      false, 0));
  CHECK(!fixture.graph[0] && !fixture.graph[1]);
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(!shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE,
                                       SIZE_MAX, 1, false, 0));
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(!shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                       false, SIZE_MAX));
  shellsplit_graph_fixture_destroy(&fixture);
  return 0;
}
