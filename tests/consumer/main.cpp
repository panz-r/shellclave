#include <shell_depgraph.h>
#include <shell_tokenizer.h>
#include <shellgate.h>
#include <shelltype.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

#ifdef SG_BUF_MIN
#error "SG_BUF_MIN must not be exposed by the current public API"
#endif
#ifndef SG_DIAGNOSTIC_BUF_MIN
#error "SG_DIAGNOSTIC_BUF_MIN must remain available for diagnostic buffers"
#endif

static shell_expand_status_t
resolve_input(const shell_expand_word_request_t *request, const char **netargv,
              std::size_t *length, void *context) {
  (void)context;
  if (request->purpose != SHELL_EXPAND_WORD_REDIRECT_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  *netargv = "10:/tmp/input,";
  *length = sizeof("10:/tmp/input,") - 1;
  return SHELL_EXPAND_RESOLVED;
}

static bool check_depgraph_workspace_api() {
  std::size_t workspace_size = 0;
  std::size_t alignment = shell_dep_workspace_alignment();
  if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
      !shell_dep_resolved_workspace_size(256, nullptr, &workspace_size) ||
      workspace_size == 0 ||
      workspace_size >
          std::numeric_limits<std::size_t>::max() - (alignment - 1))
    return false;

  auto *raw =
      static_cast<unsigned char *>(std::malloc(workspace_size + alignment - 1));
  if (!raw)
    return false;
  std::uintptr_t address = reinterpret_cast<std::uintptr_t>(raw);
  std::size_t padding =
      static_cast<std::size_t>((alignment - address % alignment) % alignment);
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.workspace = raw + padding;
  limits.workspace_size = workspace_size;
  shell_dep_graph_t graph{};
  bool ok = shell_dep_graph_parse("echo hello", std::strlen("echo hello"), ".",
                                  &limits, &graph) == SHELL_DEP_OK &&
            shell_dep_graph_validate(&graph).valid;
  if (ok) {
    constexpr char timed[] = "time -p echo hello | cat";
    ok = shell_dep_graph_parse(timed, sizeof(timed) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    std::uint32_t timers = 0;
    std::uint32_t timed_commands = 0;
    for (std::uint32_t i = 0; ok && i < graph.node_count; ++i) {
      if (graph.nodes[i].type == SHELL_NODE_TIME) {
        ++timers;
        ok = graph.nodes[i].time.mode == SHELL_PIPE_TIME_POSIX &&
             graph.nodes[i].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
             graph.nodes[i].time.report_target_fd == 2 &&
             graph.nodes[i].time.report_route_flags ==
                 SHELL_TIME_REPORT_ROUTE_EXTERNAL &&
             graph.nodes[i].time.report_external_fd_count == 1 &&
             graph.nodes[i].time.report_external_fds[0] == 2;
      } else if (graph.nodes[i].type == SHELL_NODE_CMD) {
        ok = graph.nodes[i].cmd.pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
             graph.nodes[i].cmd.pipeline_time_id != 0;
        ++timed_commands;
      }
    }
    ok = ok && timers == 1 && timed_commands == 2;
  }
  if (ok) {
    constexpr char resolved[] = "cat <\"$INPUT\"";
    ok = shell_dep_graph_parse_resolved(resolved, sizeof(resolved) - 1, ".",
                                        &limits, &graph, resolve_input, nullptr,
                                        nullptr) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
  }
  if (ok) {
    constexpr char redirected[] = "wc -l file.txt 2>&1";
    ok = shell_dep_graph_parse(redirected, sizeof(redirected) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK;
    bool stderr_to_stdout = false;
    for (std::uint32_t i = 0; ok && i < graph.edge_count; ++i) {
      const auto &edge = graph.edges[i];
      stderr_to_stdout |= edge.type == SHELL_EDGE_WRITE &&
                          edge.source_fd == 2 &&
                          graph.nodes[edge.to].type == SHELL_NODE_FD &&
                          graph.nodes[edge.to].fd.number == 1;
    }
    ok = ok && stderr_to_stdout && shell_dep_graph_validate(&graph).valid;
  }
  if (ok) {
    constexpr char directory[] = "cd /tmp; pwd";
    ok = shell_dep_graph_parse(directory, sizeof(directory) - 1, "/", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    unsigned commands = 0, cwd_edges = 0;
    for (std::uint32_t i = 0; ok && i < graph.node_count; i++)
      if (graph.nodes[i].type == SHELL_NODE_CMD) {
        const auto &command = graph.nodes[i].cmd;
        ok = command.cwd_known &&
             std::strcmp(graph.cwd_buf.data + command.cwd_offset,
                         commands == 0 ? "/" : "/tmp") == 0;
        ++commands;
      }
    for (std::uint32_t i = 0; i < graph.edge_count; i++)
      cwd_edges += graph.edges[i].type == SHELL_EDGE_CWD;
    ok = ok && commands == 2 && cwd_edges == 1;
  }
  if (ok) {
    constexpr char background[] = "wc -c &";
    ok = shell_dep_graph_parse(background, sizeof(background) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    unsigned implicit = 0;
    for (std::uint32_t i = 0; ok && i < graph.node_count; ++i)
      if (graph.nodes[i].type == SHELL_NODE_DOC &&
          (graph.nodes[i].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
        ++implicit;
        ok = graph.nodes[i].doc.path_len == 9 &&
             std::memcmp(graph.nodes[i].doc.path, "/dev/null", 9) == 0;
      }
    ok = ok && implicit == 1;
  }
  std::free(raw);
  return ok;
}

static bool check_validation_details_api() {
  st_netpattern_t pattern{};
  st_token_array_t details{};
  bool ok =
      st_netpattern_from_cpl_owned("tool pre{#n}post", &pattern) == ST_OK &&
      st_netpattern_validate_view({pattern.data, pattern.length}, &details) ==
          ST_OK &&
      details.count == 2 && details.tokens[1].compound &&
      details.tokens[1].capture_type == ST_TYPE_NUMBER &&
      details.tokens[1].prefix_length == 3 &&
      details.tokens[1].suffix_length == 4;
  st_token_array_free(&details);
  st_netpattern_free(&pattern);
  return ok;
}

int main() {
  constexpr char exact_token[] = {'4', '2', '\0', 'x'};
  if (st_token_classify(exact_token, 2) != ST_TYPE_NUMBER ||
      st_token_classify(exact_token, sizeof(exact_token)) != ST_TYPE_LITERAL ||
      st_token_classify(nullptr, 0) != ST_TYPE_LITERAL)
    return 20;
  shell_parse_result_t parsed{};
  if (shell_parse_fast("echo", 4, nullptr, &parsed) != SHELL_OK ||
      parsed.status != SHELL_STATUS_OK || parsed.count != 1)
    return 1;

  st_learner_config_t learner_config{1, 0.0, 0};
  st_learner_t *learner = st_learner_new(&learner_config);
  if (!learner)
    return 2;
  st_token_array_t typed{};
  st_netargv_view_t netargv{"4:echo,", 7};
  if (st_netargv_classify_view(netargv, &typed) != ST_OK || typed.count != 1) {
    st_token_array_free(&typed);
    st_learner_free(learner);
    return 3;
  }
  st_token_array_free(&typed);
  st_learner_free(learner);

  if (!check_depgraph_workspace_api())
    return 4;
  if (!check_validation_details_api())
    return 7;

  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return 5;
  sg_gate_free(gate);
  if (std::strcmp(shell_error_string(SHELL_OK), "OK") != 0 ||
      std::strcmp(shell_dep_error_string(SHELL_DEP_OK), "OK") != 0)
    return 6;
  return 0;
}
