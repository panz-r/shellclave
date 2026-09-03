#ifndef SHELLSPLIT_TEST_DEPGRAPH_INVARIANTS_H
#define SHELLSPLIT_TEST_DEPGRAPH_INVARIANTS_H

#include "shell_depgraph.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool shellsplit_test_span_in_input(const char *input, size_t length,
                                          const char *pointer, uint32_t span) {
  if (!pointer)
    return span == 0;
  uintptr_t begin = (uintptr_t)input;
  uintptr_t end = begin + length;
  uintptr_t value = (uintptr_t)pointer;
  return value >= begin && value <= end && span <= end - value;
}

static bool shellsplit_test_edge_types_match(const shell_dep_graph_t *graph,
                                             const shell_dep_edge_t *edge) {
  shell_dep_node_type_t from = graph->nodes[edge->from].type;
  shell_dep_node_type_t to = graph->nodes[edge->to].type;
  switch (edge->type) {
  case SHELL_EDGE_READ:
  case SHELL_EDGE_ENV:
    return from == SHELL_NODE_DOC &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP);
  case SHELL_EDGE_ARG:
    return (from == SHELL_NODE_DOC && to == SHELL_NODE_CMD) ||
           (from == SHELL_NODE_CMD && to == SHELL_NODE_DOC);
  case SHELL_EDGE_WRITE:
  case SHELL_EDGE_APPEND:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP) &&
           (to == SHELL_NODE_DOC || to == SHELL_NODE_ENDPOINT);
  case SHELL_EDGE_PIPE:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP) &&
           /* A terminal ENDPOINT preserves an upstream pipe write after a
            * later redirect replaces its reader.  The production graph
            * validator constrains that endpoint to the terminal form. */
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP ||
            to == SHELL_NODE_ENDPOINT);
  case SHELL_EDGE_SUBST:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP ||
            from == SHELL_NODE_ENDPOINT ||
            (from == SHELL_NODE_DOC &&
             graph->nodes[edge->from].doc.kind == SHELL_DOC_FILE)) &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP ||
            (to == SHELL_NODE_DOC &&
             (graph->nodes[edge->to].doc.kind == SHELL_DOC_HEREDOC ||
              graph->nodes[edge->to].doc.kind == SHELL_DOC_HERESTRING ||
              (graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE &&
               (graph->nodes[edge->to].doc.flags &
                SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0 &&
               (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) !=
                   0)))) &&
           (((from == SHELL_NODE_ENDPOINT || from == SHELL_NODE_DOC) &&
             edge->source_fd == SHELL_DEP_FD_NONE) ||
            ((from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP) &&
             edge->source_fd != SHELL_DEP_FD_NONE));
  case SHELL_EDGE_SEQ:
  case SHELL_EDGE_AND:
  case SHELL_EDGE_OR:
  case SHELL_EDGE_BACKGROUND:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP) &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP);
  case SHELL_EDGE_CWD:
    return from == SHELL_NODE_CMD && to == SHELL_NODE_CMD;
  case SHELL_EDGE_GROUP:
    return from == SHELL_NODE_GROUP &&
           (to == SHELL_NODE_GROUP || to == SHELL_NODE_CMD) &&
           edge->dir == SHELL_DIR_FORWARD &&
           edge->source_fd == SHELL_DEP_FD_NONE &&
           edge->target_fd == SHELL_DEP_FD_NONE &&
           (to != SHELL_NODE_GROUP ||
            graph->nodes[edge->to].group.parent == edge->from);
  }
  return false;
}

static bool
shellsplit_test_substitution_acyclic_visit(const shell_dep_graph_t *graph,
                                           uint32_t node,
                                           uint8_t color[SHELL_DEP_MAX_NODES]) {
  color[node] = 1;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != SHELL_EDGE_SUBST || edge->from != node)
      continue;
    if (color[edge->to] == 1)
      return false;
    if (color[edge->to] == 0 &&
        !shellsplit_test_substitution_acyclic_visit(graph, edge->to, color))
      return false;
  }
  color[node] = 2;
  return true;
}

static bool
shellsplit_test_substitution_ancestry_valid(const shell_dep_graph_t *graph) {
  uint8_t color[SHELL_DEP_MAX_NODES] = {0};
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (color[node] == 0 &&
        !shellsplit_test_substitution_acyclic_visit(graph, node, color))
      return false;
  }
  return true;
}

static bool shellsplit_test_depgraph_invariants(
    const char *input, size_t length, shell_dep_error_t error,
    const shell_dep_graph_t *graph, const shell_dep_limits_t *limits) {
  uint32_t max_nodes = limits->max_nodes < SHELL_DEP_MAX_NODES
                           ? limits->max_nodes
                           : SHELL_DEP_MAX_NODES;
  uint32_t max_edges = limits->max_edges < SHELL_DEP_MAX_EDGES
                           ? limits->max_edges
                           : SHELL_DEP_MAX_EDGES;
  uint32_t max_tokens = limits->max_tokens_per_cmd < SHELL_DEP_MAX_TOKENS
                            ? limits->max_tokens_per_cmd
                            : SHELL_DEP_MAX_TOKENS;
  uint32_t max_cwd =
      limits->cwd_buf_size == 0 ? SHELL_DEP_CWD_BUF_SIZE : limits->cwd_buf_size;
  if (max_cwd > SHELL_DEP_CWD_BUF_SIZE)
    max_cwd = SHELL_DEP_CWD_BUF_SIZE;

  if (error != SHELL_DEP_OK && error != SHELL_DEP_EINPUT &&
      error != SHELL_DEP_ETRUNC && error != SHELL_DEP_EPARSE)
    return false;
  if ((error == SHELL_DEP_OK && graph->status != SHELL_DEP_STATUS_OK) ||
      (error == SHELL_DEP_ETRUNC &&
       !(graph->status & SHELL_DEP_STATUS_TRUNCATED)) ||
      ((error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE) &&
       graph->status != SHELL_DEP_STATUS_ERROR) ||
      graph->node_count > max_nodes || graph->edge_count > max_edges ||
      graph->cwd_buf.len > max_cwd ||
      (graph->cwd_buf.len > 0 &&
       graph->cwd_buf.data[graph->cwd_buf.len - 1] != '\0'))
    return false;

  if (error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE)
    return graph->node_count == 0 && graph->edge_count == 0;
  if (!shell_dep_graph_validate(graph).valid)
    return false;

  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->from >= graph->node_count || edge->to >= graph->node_count ||
        edge->type > SHELL_EDGE_GROUP || edge->dir > SHELL_DIR_UNDIR ||
        (edge->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                         SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) != 0 ||
        ((edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ||
        (edge->type != SHELL_EDGE_SUBST &&
         edge->flags != SHELL_DEP_EDGE_FLAG_NONE) ||
        !shellsplit_test_edge_types_match(graph, edge))
      return false;
  }
  if (!shellsplit_test_substitution_ancestry_valid(graph))
    return false;

  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD) {
      if (node->cmd.token_count > max_tokens ||
          node->cmd.cwd_offset >= graph->cwd_buf.len ||
          !memchr(graph->cwd_buf.data + node->cmd.cwd_offset, '\0',
                  graph->cwd_buf.len - node->cmd.cwd_offset))
        return false;
      for (uint32_t j = 0; j < node->cmd.token_count; j++)
        if (!shellsplit_test_span_in_input(input, length, node->cmd.tokens[j],
                                           node->cmd.token_lens[j]))
          return false;
    } else if (node->type == SHELL_NODE_GROUP) {
      if (!shellsplit_test_span_in_input(input, length, node->group.start,
                                         node->group.length))
        return false;
    } else if (node->type != SHELL_NODE_ENDPOINT &&
               (node->type != SHELL_NODE_DOC ||
                node->doc.kind < SHELL_DOC_FILE ||
                node->doc.kind > SHELL_DOC_ENVVAR ||
                !shellsplit_test_span_in_input(input, length, node->doc.path,
                                               node->doc.path_len) ||
                !shellsplit_test_span_in_input(input, length, node->doc.name,
                                               node->doc.name_len) ||
                !shellsplit_test_span_in_input(input, length, node->doc.value,
                                               node->doc.value_len) ||
                (node->doc.flags & ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
                                     SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                                     SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
                                     SHELL_DEP_DOC_FLAG_TRANSIENT)) != 0)) {
      return false;
    }
  }
  return true;
}

#endif
