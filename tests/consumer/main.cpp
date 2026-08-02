#include <shell_depgraph.h>
#include <shell_tokenizer.h>
#include <shellgate.h>
#include <shelltype.h>

#include <cstring>

int main() {
  shell_parse_result_t parsed{};
  if (shell_parse_fast("echo", 4, nullptr, &parsed) != SHELL_OK ||
      parsed.status != SHELL_STATUS_OK || parsed.count != 1)
    return 1;

  st_learner_t *learner = st_learner_new(1, 0.0);
  if (!learner)
    return 2;
  st_learner_free(learner);

  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return 3;
  sg_gate_free(gate);
  if (std::strcmp(shell_error_string(SHELL_OK), "OK") != 0 ||
      std::strcmp(shell_dep_error_string(SHELL_DEP_OK), "OK") != 0)
    return 4;
  return 0;
}
