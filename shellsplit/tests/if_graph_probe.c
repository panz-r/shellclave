/* Print the graph of the source in argv[1], run from the directory argv[2]
 * ("/" without it): a status line, then one line per
 * node (a command's first word, a file document's path) and per edge, with
 * "required" on an open the graph states as a requirement, and each command's
 * working directory when the graph knows it. The
 * differential test against pinned Bash (tests/test_bash_if_descriptors.py)
 * reads it. */
#include "shell_depgraph.h"
#include "shell_source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3)
    return 2;
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t size = 0, delimiters = 0, alignment = shell_dep_workspace_alignment();
  if (!shell_dep_workspace_size(&limits, &size) ||
      !shell_source_workspace_size(strlen(argv[1]), &delimiters) ||
      delimiters > SIZE_MAX - size)
    return 2;
  size += delimiters;
  void *workspace =
      aligned_alloc(alignment, (size + alignment - 1) / alignment * alignment);
  if (!workspace)
    return 2;
  limits.workspace = workspace;
  limits.workspace_size = size;
  static shell_dep_graph_t graph;
  shell_dep_error_t error = shell_dep_graph_parse(
      argv[1], strlen(argv[1]), argc == 3 ? argv[2] : "/", &limits, &graph);
  printf("rc=%d\n", (int)error);
  if (error == SHELL_DEP_OK) {
    for (uint32_t i = 0; i < graph.node_count; i++) {
      const shell_dep_node_t *node = &graph.nodes[i];
      if (node->type == SHELL_NODE_CMD && node->cmd.token_count) {
        printf("cmd %u %.*s\n", i, (int)node->cmd.token_lens[0],
               node->cmd.tokens[0]);
        if (node->cmd.cwd_known)
          printf("cwd %u %s\n", i, graph.cwd_buf.data + node->cmd.cwd_offset);
        else
          printf("cwd %u unknown\n", i);
      } else if (node->type == SHELL_NODE_DOC &&
                 node->doc.kind == SHELL_DOC_FILE)
        printf("file %u %.*s\n", i, (int)node->doc.path_len, node->doc.path);
    }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      printf("edge %u %u %s%s\n", graph.edges[i].from, graph.edges[i].to,
             shell_dep_edge_type_name(graph.edges[i].type),
             graph.edges[i].flags & SHELL_DEP_EDGE_FLAG_REQUIRED ? " required"
                                                                 : "");
  }
  free(workspace);
  return 0;
}
