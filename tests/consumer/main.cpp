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

static bool check_depgraph_workspace_api() {
  std::size_t workspace_size = 0;
  std::size_t alignment = shell_dep_workspace_alignment();
  if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
      !shell_dep_workspace_size(nullptr, &workspace_size) ||
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
  std::free(raw);
  return ok;
}

int main() {
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

  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return 5;
  sg_gate_free(gate);
  if (std::strcmp(shell_error_string(SHELL_OK), "OK") != 0 ||
      std::strcmp(shell_dep_error_string(SHELL_DEP_OK), "OK") != 0)
    return 6;
  return 0;
}
