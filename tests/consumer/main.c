#include <shell_tokenizer.h>
#include <shellgate.h>
#include <shelltype.h>

#include <string.h>

int main(void) {
  static const char command[] = "echo hello && printf done";
  shell_parse_result_t parsed = {0};
  shell_error_t error =
      shell_parse_fast(command, strlen(command), NULL, &parsed);
  if (error != SHELL_OK || parsed.status != SHELL_STATUS_OK ||
      parsed.count != 2 || parsed.cmds[0].start != 0 ||
      parsed.cmds[0].len != strlen("echo hello") ||
      parsed.cmds[1].type != SHELL_TYPE_AND ||
      parsed.cmds[1].start != strlen("echo hello && ") ||
      parsed.cmds[1].len != strlen("printf done"))
    return 1;

  st_learner_t *learner = st_learner_new(1, 0.01);
  if (!learner || st_feed(learner, "echo hello") != ST_OK) {
    st_learner_free(learner);
    return 2;
  }
  size_t suggestion_count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &suggestion_count);
  if (!suggestions || suggestion_count != 2 ||
      strcmp(suggestions[0].pattern, "echo") != 0 ||
      suggestions[0].count != 1 || suggestions[0].confidence != 1.0 ||
      strcmp(suggestions[1].pattern, "echo hello") != 0 ||
      suggestions[1].count != 1 || suggestions[1].confidence != 1.0) {
    st_free_suggestions(suggestions, suggestion_count);
    st_learner_free(learner);
    return 3;
  }
  st_free_suggestions(suggestions, suggestion_count);
  st_learner_free(learner);

  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_add_rule(gate, "echo hello") != SG_OK) {
    sg_gate_free(gate);
    return 4;
  }
  char buffer[SG_BUF_MIN];
  sg_result_t result;
  sg_error_t gate_error = sg_eval(gate, "echo hello", strlen("echo hello"),
                                  buffer, sizeof(buffer), &result);
  sg_gate_free(gate);
  return gate_error == SG_OK && result.verdict == SG_VERDICT_ALLOW ? 0 : 5;
}
