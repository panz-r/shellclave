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
    return from == SHELL_NODE_DOC && to == SHELL_NODE_CMD;
  case SHELL_EDGE_ARG:
    return (from == SHELL_NODE_DOC && to == SHELL_NODE_CMD) ||
           (from == SHELL_NODE_CMD && to == SHELL_NODE_DOC);
  case SHELL_EDGE_WRITE:
  case SHELL_EDGE_APPEND:
    return from == SHELL_NODE_CMD && to == SHELL_NODE_DOC;
  case SHELL_EDGE_PIPE:
  case SHELL_EDGE_SUBST:
  case SHELL_EDGE_SEQ:
  case SHELL_EDGE_AND:
  case SHELL_EDGE_OR:
  case SHELL_EDGE_CWD:
  case SHELL_EDGE_BACKGROUND:
  case SHELL_EDGE_GROUP:
    return from == SHELL_NODE_CMD && to == SHELL_NODE_CMD;
  }
  return false;
}

static bool
shellsplit_test_substitution_ancestry_valid(const shell_dep_graph_t *graph) {
  for (uint32_t start = 0; start < graph->node_count; start++) {
    if (graph->nodes[start].type != SHELL_NODE_CMD)
      continue;
    bool seen[SHELL_DEP_MAX_NODES] = {false};
    uint32_t current = start;
    while (true) {
      if (seen[current])
        return false;
      seen[current] = true;
      uint32_t parent = UINT32_MAX;
      for (uint32_t i = 0; i < graph->edge_count; i++) {
        const shell_dep_edge_t *edge = &graph->edges[i];
        if (edge->type != SHELL_EDGE_SUBST || edge->from != current)
          continue;
        if (parent != UINT32_MAX)
          return false;
        parent = edge->to;
      }
      if (parent == UINT32_MAX)
        break;
      current = parent;
    }
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
    } else if (node->type != SHELL_NODE_DOC ||
               node->doc.kind < SHELL_DOC_FILE ||
               node->doc.kind > SHELL_DOC_ENVVAR ||
               !shellsplit_test_span_in_input(input, length, node->doc.path,
                                              node->doc.path_len) ||
               !shellsplit_test_span_in_input(input, length, node->doc.name,
                                              node->doc.name_len) ||
               !shellsplit_test_span_in_input(input, length, node->doc.value,
                                              node->doc.value_len)) {
      return false;
    }
  }
  return true;
}

#endif
