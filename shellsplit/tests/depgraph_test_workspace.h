/* Shared caller-owned resolver storage for dependency-graph test surfaces.
 * Production callers must supply this explicitly through shell_dep_limits_t;
 * the test adapter keeps legacy test fixtures focused on their graph contract
 * while dedicated tests exercise absent and undersized workspaces directly. */
#ifndef SHELLSPLIT_DEPGRAPH_TEST_WORKSPACE_H
#define SHELLSPLIT_DEPGRAPH_TEST_WORKSPACE_H

#include "../src/shell_depgraph_internal.h"

#include <stddef.h>
#include <stdint.h>

/* Keep this fixture deliberately larger than the current measured maximum so
 * a route-workspace growth turns the dedicated size-contract test into the
 * place that needs adjustment, rather than silently restoring heap use. */
static _Alignas(
    max_align_t) unsigned char shellsplit_test_dep_workspace[3u * 1024u *
                                                             1024u];

static bool shellsplit_test_dep_limits(const shell_dep_limits_t *limits,
                                       shell_dep_limits_t *effective) {
  if (!effective)
    return false;
  *effective = limits ? *limits : SHELL_DEP_LIMITS_DEFAULT;
  if (effective->workspace)
    return true;
  size_t required = 0;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_dep_workspace_size(effective, &required) ||
      required > sizeof(shellsplit_test_dep_workspace) || alignment == 0 ||
      alignment > _Alignof(max_align_t) ||
      (uintptr_t)(void *)shellsplit_test_dep_workspace % alignment != 0)
    return false;
  effective->workspace = shellsplit_test_dep_workspace;
  effective->workspace_size = sizeof(shellsplit_test_dep_workspace);
  return true;
}

static inline shell_dep_error_t shellsplit_test_dep_graph_parse(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, shell_dep_graph_t *out) {
  shell_dep_limits_t effective;
  if (!shellsplit_test_dep_limits(limits, &effective))
    return SHELL_DEP_EWORKSPACE;
  return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, &effective, out);
}

static inline shell_dep_error_t shellsplit_test_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  shell_dep_limits_t effective;
  if (!shellsplit_test_dep_limits(limits, &effective))
    return SHELL_DEP_EWORKSPACE;
  return shell_dep_graph_parse_with_fast(cmd, cmd_len, initial_cwd, &effective,
                                         fast, out);
}

#define shell_dep_graph_parse shellsplit_test_dep_graph_parse
#define shell_dep_graph_parse_with_fast                                        \
  shellsplit_test_dep_graph_parse_with_fast

#endif
