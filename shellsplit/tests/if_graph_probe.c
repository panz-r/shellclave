/* Print the graph of a source: a status line, then one line per node (a
 * command's first word, a file document's path) and per edge, with "required"
 * on an open the graph states as a requirement, and each command's working
 * directory when the graph knows it. Run from the directory argv[2] ("/"
 * without it) on the source in argv[1].
 *
 * With argv[1] "--batch" the sources are NUL-terminated records on standard
 * input and each report ends with a line "--": one process serves a whole
 * differential run. The differential test against pinned Bash
 * (tests/test_bash_if_descriptors.py) reads it. */
#include "shell_depgraph.h"
#include "shell_source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Report the graph of the NUL-terminated source of length bytes; workspace
 * holds at least what workspace_for gives for that length. */
static void report(const char *source, size_t length, const char *cwd,
                   void *workspace, size_t workspace_size) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.workspace = workspace;
  limits.workspace_size = workspace_size;
  static shell_dep_graph_t graph;
  shell_dep_error_t error =
      shell_dep_graph_parse(source, length, cwd, &limits, &graph);
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
}

/* The workspace size a source of at most max_length bytes needs; nonzero
 * when it overflows. */
static int workspace_for(size_t max_length, size_t *size) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t delimiters = 0;
  if (!shell_dep_workspace_size(&limits, size) ||
      !shell_source_workspace_size(max_length, &delimiters) ||
      delimiters > SIZE_MAX - *size)
    return 1;
  *size += delimiters;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3)
    return 2;
  const char *cwd = argc == 3 ? argv[2] : "/";
  bool batch = !strcmp(argv[1], "--batch");
  char *input = NULL;
  size_t used = 0, capacity = 0;
  if (batch) {
    for (;;) {
      if (used + 1 >= capacity) {
        capacity = capacity ? capacity * 2 : 1 << 16;
        input = realloc(input, capacity);
        if (!input)
          return 2;
      }
      size_t got = fread(input + used, 1, capacity - used - 1, stdin);
      if (!got)
        break;
      used += got;
    }
    if (input)
      input[used] = 0; /* ends an unterminated last record */
  }
  size_t longest = 0;
  if (batch) {
    for (size_t at = 0; at < used;) {
      size_t length = strlen(input + at);
      if (length > longest)
        longest = length;
      at += length + 1;
    }
  } else
    longest = strlen(argv[1]);
  size_t size, alignment = shell_dep_workspace_alignment();
  if (workspace_for(longest, &size))
    return 2;
  void *workspace =
      aligned_alloc(alignment, (size + alignment - 1) / alignment * alignment);
  if (!workspace)
    return 2;
  if (!batch)
    report(argv[1], strlen(argv[1]), cwd, workspace, size);
  else
    for (size_t at = 0; at < used;) {
      size_t length = strlen(input + at);
      report(input + at, length, cwd, workspace, size);
      puts("--");
      at += length + 1;
    }
  free(workspace);
  free(input);
  return 0;
}
