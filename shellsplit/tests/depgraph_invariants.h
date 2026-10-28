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
    return (from == SHELL_NODE_DOC || from == SHELL_NODE_FD) &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP);
  case SHELL_EDGE_ENV:
    return from == SHELL_NODE_DOC &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP);
  case SHELL_EDGE_ARG:
    return (from == SHELL_NODE_DOC && to == SHELL_NODE_CMD) ||
           (from == SHELL_NODE_CMD && to == SHELL_NODE_DOC);
  case SHELL_EDGE_FILE_TEST:
    return from == SHELL_NODE_CMD && to == SHELL_NODE_DOC &&
           graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE;
  case SHELL_EDGE_FILE_COMPARE:
    return from == SHELL_NODE_CMD && to == SHELL_NODE_FILE_COMPARISON;
  case SHELL_EDGE_FILE_LEFT:
  case SHELL_EDGE_FILE_RIGHT:
    return from == SHELL_NODE_FILE_COMPARISON && to == SHELL_NODE_DOC &&
           graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE;
  case SHELL_EDGE_WRITE:
  case SHELL_EDGE_APPEND:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP ||
            from == SHELL_NODE_TIME) &&
           (to == SHELL_NODE_DOC || to == SHELL_NODE_ENDPOINT ||
            (to == SHELL_NODE_FD && edge->type == SHELL_EDGE_WRITE));
  case SHELL_EDGE_PIPE:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP ||
            from == SHELL_NODE_TIME) &&
           /* A terminal ENDPOINT preserves an upstream pipe write after a
            * later redirect replaces its reader.  The production graph
            * validator constrains that endpoint to the terminal form. */
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP ||
            to == SHELL_NODE_ENDPOINT);
  case SHELL_EDGE_SUBST:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP ||
            from == SHELL_NODE_ENDPOINT || from == SHELL_NODE_TIME ||
            (from == SHELL_NODE_DOC &&
             graph->nodes[edge->from].doc.kind == SHELL_DOC_FILE)) &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP ||
            (to == SHELL_NODE_DOC &&
             (graph->nodes[edge->to].doc.kind == SHELL_DOC_HEREDOC ||
              graph->nodes[edge->to].doc.kind == SHELL_DOC_HERESTRING ||
              (graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE &&
               (graph->nodes[edge->to].doc.flags &
                (SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                 SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
                 SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) != 0 &&
               (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) !=
                   0)))) &&
           (((from == SHELL_NODE_ENDPOINT || from == SHELL_NODE_DOC) &&
             edge->source_fd == SHELL_DEP_FD_NONE) ||
            ((from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP ||
              from == SHELL_NODE_TIME) &&
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
  case SHELL_EDGE_FD_OPEN:
    /* shell_dep_graph_validate() runs before this helper.  Keep FD_OPEN's
     * deliberately detailed setup grammar in that single production oracle
     * instead of maintaining a second, fuzz-only copy that can drift. */
    return true;
  case SHELL_EDGE_FD_CLOSE:
    return (from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP) && from == to &&
           edge->from == edge->to && edge->source_fd != SHELL_DEP_FD_NONE &&
           edge->target_fd == SHELL_DEP_FD_NONE &&
           edge->flags == SHELL_DEP_EDGE_FLAG_NONE &&
           edge->dir == SHELL_DIR_FORWARD;
  case SHELL_EDGE_TIME:
    return from == SHELL_NODE_TIME &&
           (to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP) &&
           edge->source_fd == SHELL_DEP_FD_NONE &&
           edge->target_fd == SHELL_DEP_FD_NONE &&
           edge->flags == SHELL_DEP_EDGE_FLAG_NONE &&
           edge->dir == SHELL_DIR_FORWARD;
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
      error != SHELL_DEP_ETRUNC && error != SHELL_DEP_EPARSE &&
      error != SHELL_DEP_EWORKSPACE && error != SHELL_DEP_EEXPAND)
    return false;
  if ((error == SHELL_DEP_OK && graph->status != SHELL_DEP_STATUS_OK) ||
      (error == SHELL_DEP_ETRUNC &&
       graph->status != SHELL_DEP_STATUS_TRUNCATED) ||
      ((error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE ||
        error == SHELL_DEP_EWORKSPACE || error == SHELL_DEP_EEXPAND) &&
       graph->status != SHELL_DEP_STATUS_ERROR) ||
      graph->node_count > max_nodes || graph->edge_count > max_edges ||
      graph->cwd_buf.len > max_cwd ||
      (graph->cwd_buf.len > 0 &&
       graph->cwd_buf.data[graph->cwd_buf.len - 1] != '\0'))
    return false;

  if (error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE ||
      error == SHELL_DEP_EWORKSPACE || error == SHELL_DEP_EEXPAND)
    return graph->node_count == 0 && graph->edge_count == 0;
  if (!shell_dep_graph_validate(graph).valid)
    return false;

  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->from >= graph->node_count || edge->to >= graph->node_count ||
        edge->type > SHELL_EDGE_FILE_RIGHT || edge->dir > SHELL_DIR_UNDIR ||
        (edge->type == SHELL_EDGE_FILE_TEST
             ? (edge->flags == 0 ||
                (edge->flags &
                 ~(SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP |
                   SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ)) != 0)
             : ((edge->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                                 SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME |
                                 SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND |
                                 SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP)) != 0 ||
                ((edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
                 (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ||
                ((edge->flags & (SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                                 SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) !=
                     0 &&
                 edge->type != SHELL_EDGE_SUBST) ||
                ((edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0 &&
                 edge->type != SHELL_EDGE_FD_OPEN) ||
                ((edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0 &&
                 edge->type != SHELL_EDGE_FD_OPEN))) ||
        !shellsplit_test_span_in_input(input, length, edge->source_fd_name,
                                       edge->source_fd_name_len) ||
        !shellsplit_test_span_in_input(input, length, edge->target_fd_name,
                                       edge->target_fd_name_len) ||
        !shellsplit_test_edge_types_match(graph, edge))
      return false;
  }
  if (!shellsplit_test_substitution_ancestry_valid(graph))
    return false;

  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD) {
      if (node->cmd.pipeline_negated !=
          ((node->cmd.pipeline_negation_count & 1u) != 0))
        return false;
      if (node->cmd.token_count > max_tokens ||
          node->cmd.cwd_offset >= graph->cwd_buf.len ||
          !memchr(graph->cwd_buf.data + node->cmd.cwd_offset, '\0',
                  graph->cwd_buf.len - node->cmd.cwd_offset))
        return false;
      if ((node->cmd.pipeline_time_mode == SHELL_PIPE_TIME_NONE) !=
              (node->cmd.pipeline_time_id == 0) &&
          !((graph->status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
            node->cmd.pipeline_time_mode != SHELL_PIPE_TIME_NONE &&
            node->cmd.pipeline_time_id == 0))
        return false;
      if (node->cmd.pipeline_time_id != 0) {
        uint32_t timer = node->cmd.pipeline_time_id - 1;
        if (timer >= graph->node_count ||
            graph->nodes[timer].type != SHELL_NODE_TIME ||
            graph->nodes[timer].time.mode != node->cmd.pipeline_time_mode)
          return false;
      }
      for (uint32_t j = 0; j < node->cmd.token_count; j++)
        if (!shellsplit_test_span_in_input(input, length, node->cmd.tokens[j],
                                           node->cmd.token_lens[j]))
          return false;
    } else if (node->type == SHELL_NODE_GROUP) {
      if (node->group.pipeline_negated !=
          ((node->group.pipeline_negation_count & 1u) != 0))
        return false;
      if (!shellsplit_test_span_in_input(input, length, node->group.start,
                                         node->group.length))
        return false;
      if ((node->group.pipeline_time_mode == SHELL_PIPE_TIME_NONE) !=
              (node->group.pipeline_time_id == 0) &&
          !((graph->status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
            node->group.pipeline_time_mode != SHELL_PIPE_TIME_NONE &&
            node->group.pipeline_time_id == 0))
        return false;
      if (node->group.pipeline_time_id != 0) {
        uint32_t timer = node->group.pipeline_time_id - 1;
        if (timer >= graph->node_count ||
            graph->nodes[timer].type != SHELL_NODE_TIME ||
            graph->nodes[timer].time.mode != node->group.pipeline_time_mode)
          return false;
      }
    } else if (node->type == SHELL_NODE_TIME) {
      uint32_t report_flows = 0;
      uint32_t external_flows = 0;
      uint32_t target = UINT32_MAX;
      uint32_t target_count = 0;
      uint32_t target_timer_count = 0;
      bool external_seen[SHELL_DEP_TIME_MAX_EXTERNAL_FDS] = {false};
      bool topology_valid = true;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        if (graph->edges[edge].from == i) {
          if (graph->edges[edge].type == SHELL_EDGE_TIME) {
            target = graph->edges[edge].to;
            target_count++;
          } else if ((graph->edges[edge].type == SHELL_EDGE_WRITE ||
                      graph->edges[edge].type == SHELL_EDGE_APPEND ||
                      graph->edges[edge].type == SHELL_EDGE_PIPE ||
                      graph->edges[edge].type == SHELL_EDGE_SUBST) &&
                     graph->edges[edge].source_fd == node->time.report_fd) {
            const shell_dep_node_t *destination =
                &graph->nodes[graph->edges[edge].to];
            if (destination->type != SHELL_NODE_FD)
              report_flows++;
            else {
              external_flows++;
              bool declared = false;
              for (uint32_t fd = 0; fd < node->time.report_external_fd_count;
                   fd++)
                if (node->time.report_external_fds[fd] ==
                    destination->fd.number) {
                  if (external_seen[fd])
                    return false;
                  external_seen[fd] = true;
                  declared = true;
                }
              topology_valid &= declared;
            }
          } else {
            topology_valid = false;
          }
        } else if (graph->edges[edge].to == i) {
          topology_valid = false;
        }
      bool target_valid = target < graph->node_count;
      shell_pipeline_time_mode_t target_mode = SHELL_PIPE_TIME_NONE;
      uint32_t target_time_id = 0;
      if (target_valid && graph->nodes[target].type == SHELL_NODE_CMD) {
        target_mode = graph->nodes[target].cmd.pipeline_time_mode;
        target_time_id = graph->nodes[target].cmd.pipeline_time_id;
      } else if (target_valid &&
                 graph->nodes[target].type == SHELL_NODE_GROUP) {
        target_mode = graph->nodes[target].group.pipeline_time_mode;
        target_time_id = graph->nodes[target].group.pipeline_time_id;
      } else {
        target_valid = false;
      }
      if (target_valid)
        for (uint32_t edge = 0; edge < graph->edge_count; edge++)
          if (graph->edges[edge].type == SHELL_EDGE_TIME &&
              graph->edges[edge].to == target &&
              graph->edges[edge].from < graph->node_count &&
              graph->nodes[graph->edges[edge].from].type == SHELL_NODE_TIME)
            target_timer_count++;
      if (node->time.report_external_fd_count > SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
        return false;
      if (external_flows != node->time.report_external_fd_count)
        return false;
      for (uint32_t fd = 0; fd < node->time.report_external_fd_count; fd++)
        if (!external_seen[fd])
          return false;
      bool has_external = node->time.report_external_fd_count != 0;
      bool has_graph = report_flows != 0;
      bool has_closed =
          (node->time.report_route_flags & SHELL_TIME_REPORT_ROUTE_CLOSED) != 0;
      bool has_unavailable = (node->time.report_route_flags &
                              SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) != 0;
      bool has_unknown = (node->time.report_route_flags &
                          SHELL_TIME_REPORT_ROUTE_UNKNOWN) != 0;
      uint32_t expected_flags =
          (has_external ? SHELL_TIME_REPORT_ROUTE_EXTERNAL : 0) |
          (has_graph ? SHELL_TIME_REPORT_ROUTE_GRAPH : 0) |
          (has_closed ? SHELL_TIME_REPORT_ROUTE_CLOSED : 0) |
          (has_unavailable ? SHELL_TIME_REPORT_ROUTE_UNAVAILABLE : 0) |
          (has_unknown ? SHELL_TIME_REPORT_ROUTE_UNKNOWN : 0);
      bool route_valid =
          node->time.report_route_flags == expected_flags &&
          (!has_unknown || (graph->status & SHELL_DEP_STATUS_TRUNCATED) != 0);
      for (uint32_t fd = 0; fd < node->time.report_external_fd_count; fd++) {
        route_valid = route_valid &&
                      node->time.report_external_fds[fd] <= SHELL_DEP_FD_MAX;
        for (uint32_t prior = 0; prior < fd; prior++)
          route_valid = route_valid && node->time.report_external_fds[prior] !=
                                           node->time.report_external_fds[fd];
      }
      if (node->time.report_route == SHELL_TIME_REPORT_EXTERNAL)
        route_valid =
            route_valid && report_flows == 0 &&
            node->time.report_target_fd <= SHELL_DEP_FD_MAX &&
            node->time.report_external_fd_count == 1 &&
            node->time.report_external_fds[0] == node->time.report_target_fd &&
            node->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_EXTERNAL;
      else if (node->time.report_route == SHELL_TIME_REPORT_GRAPH)
        route_valid =
            route_valid && report_flows == 1 &&
            node->time.report_target_fd == SHELL_DEP_FD_NONE &&
            node->time.report_external_fd_count == 0 &&
            node->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_GRAPH;
      else if (node->time.report_route == SHELL_TIME_REPORT_CLOSED)
        route_valid =
            route_valid && report_flows == 0 &&
            node->time.report_target_fd == SHELL_DEP_FD_NONE &&
            node->time.report_external_fd_count == 0 &&
            node->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_CLOSED;
      else if (node->time.report_route == SHELL_TIME_REPORT_UNAVAILABLE)
        route_valid = route_valid && report_flows == 0 &&
                      node->time.report_target_fd == SHELL_DEP_FD_NONE &&
                      node->time.report_external_fd_count == 0 &&
                      node->time.report_route_flags ==
                          SHELL_TIME_REPORT_ROUTE_UNAVAILABLE;
      else if (node->time.report_route == SHELL_TIME_REPORT_UNKNOWN)
        route_valid =
            route_valid && report_flows == 0 &&
            node->time.report_target_fd == SHELL_DEP_FD_NONE &&
            node->time.report_external_fd_count == 0 &&
            node->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_UNKNOWN &&
            (graph->status & SHELL_DEP_STATUS_TRUNCATED) != 0;
      else if (node->time.report_route == SHELL_TIME_REPORT_MULTIPLE)
        route_valid = route_valid &&
                      report_flows + node->time.report_external_fd_count +
                              (has_closed ? 1u : 0u) +
                              (has_unavailable ? 1u : 0u) +
                              (has_unknown ? 1u : 0u) >=
                          2 &&
                      node->time.report_target_fd == SHELL_DEP_FD_NONE;
      else
        route_valid = false;
      if (!shellsplit_test_span_in_input(input, length, node->time.start,
                                         node->time.length) ||
          node->time.mode < SHELL_PIPE_TIME_DEFAULT ||
          node->time.mode > SHELL_PIPE_TIME_POSIX ||
          node->time.report_fd != 2 || !route_valid || !topology_valid ||
          target_count != 1 || !target_valid ||
          target_mode != node->time.mode || target_timer_count != 1 ||
          target_time_id != i + 1)
        return false;
    } else if (node->type == SHELL_NODE_FILE_COMPARISON) {
      if (!node->file_comparison.predicates ||
          (node->file_comparison.predicates & ~7u) ||
          (node->file_comparison.empty_operands & ~3u))
        return false;
    } else if (node->type == SHELL_NODE_FD) {
      if (node->fd.number > SHELL_DEP_FD_MAX)
        return false;
    } else if (node->type != SHELL_NODE_ENDPOINT &&
               (node->type != SHELL_NODE_DOC ||
                node->doc.kind < SHELL_DOC_FILE ||
                node->doc.kind > SHELL_DOC_ENVVAR ||
                ((node->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
                     ? node->doc.kind != SHELL_DOC_FILE ||
                           node->doc.flags != SHELL_DEP_DOC_FLAG_IMPLICIT ||
                           node->doc.path_len != 9 || node->doc.path == NULL ||
                           memcmp(node->doc.path, "/dev/null", 9) != 0
                     : !shellsplit_test_span_in_input(input, length,
                                                      node->doc.path,
                                                      node->doc.path_len)) ||
                !shellsplit_test_span_in_input(input, length, node->doc.name,
                                               node->doc.name_len) ||
                ((node->doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)
                     ? node->doc.kind != SHELL_DOC_FILE ||
                           node->doc.value == NULL ||
                           node->doc.value_len == 0 ||
                           memchr(node->doc.value, 0, node->doc.value_len) !=
                               NULL
                     : !shellsplit_test_span_in_input(input, length,
                                                      node->doc.value,
                                                      node->doc.value_len)) ||
                (node->doc.flags & ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
                                     SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                                     SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
                                     SHELL_DEP_DOC_FLAG_TRANSIENT |
                                     SHELL_DEP_DOC_FLAG_ENVVAR_APPEND |
                                     SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
                                     SHELL_DEP_DOC_FLAG_EXPANSION_FAILED |
                                     SHELL_DEP_DOC_FLAG_IMPLICIT)) != 0)) {
      return false;
    }
  }
  return true;
}

#endif
