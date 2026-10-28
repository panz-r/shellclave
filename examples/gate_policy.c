#include <shellgate.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* gate-example:start */
/* Report policy and independent conditions; application authorization is
 * separate. On error, result storage need not contain initialized metadata. */
static SHELL_NONNULL(1, 2, 4) void report_analysis(FILE *output,
                                                   const char *source,
                                                   sg_error_t error,
                                                   const sg_result_t *result) {
  fprintf(output, "%s: ", source);
  if (error != SG_OK) {
    fprintf(output, "evaluation failed (%d)\n", error);
    return;
  }
  if (result->truncated || result->short_circuited)
    fputs("incomplete evaluation; reported ", output);
  fprintf(output, "argv policy %s", sg_verdict_name(result->verdict));
  if (result->requires_substitution_evaluation)
    fputs("; substitution inspection required", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV)
    fputs("; unresolved argv", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH)
    fputs("; unresolved pathname", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION)
    fputs("; unresolved condition", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC)
    fputs("; unresolved arithmetic", output);
  if (result->has_dynamic_substitution_io)
    fputs("; dynamic substitution I/O present", output);
  fputc('\n', output);
}
/* gate-example:end */

static SHELL_NONNULL(1, 2) bool add_rule(st_policy_t *policy, const char *cpl) {
  st_netpattern_t pattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error == ST_OK)
    error = st_policy_add_netpattern_view(
        policy, (st_netpattern_view_t){pattern.data, pattern.length});
  st_netpattern_free(&pattern);
  return error == ST_OK;
}

static sg_gate_t *example_gate(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *allow = context ? st_policy_new(context) : NULL;
  st_policy_t *deny = allow ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  sg_gate_t *gate = NULL;
  if (deny && add_rule(allow, "git status --short") &&
      add_rule(allow, "echo *") && add_rule(allow, "whoami") &&
      add_rule(deny, "git reset --hard")) {
    gate = sg_gate_new_with_policies_owned(allow, deny);
    if (gate) {
      /* Ownership transferred; installed rules stay fixed. */
      allow = deny = NULL;
    }
  }
  st_policy_free(allow);
  st_policy_free(deny);
  if (gate && sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK) {
    sg_gate_free(gate);
    gate = NULL;
  }
  return gate;
}

int main(void) {
  static const char *const commands[] = {"git status --short",
                                         "git reset --hard",
                                         "git log --oneline",
                                         "if true; then :; fi",
                                         "echo \"$(whoami)\"",
                                         "echo \"$VALUE\"",
                                         "echo ok >\"$OUT\"",
                                         "git status --short >report.txt",
                                         "echo \"$(whoami)\" >\"$OUT\"",
                                         "echo ok < <(whoami)"};
  sg_gate_t *gate = example_gate();
  if (!gate) {
    fputs("policy setup failed\n", stderr);
    return EXIT_FAILURE;
  }
  int status = EXIT_SUCCESS;
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
    size_t length = strlen(commands[i]);
    size_t size = sg_gate_evaluate_size_hint(length);
    char *buffer = size == SIZE_MAX ? NULL : malloc(size);
    if (!buffer) {
      fputs("evaluation buffer allocation failed\n", stderr);
      status = EXIT_FAILURE;
      break;
    }
    sg_result_t result = {.verdict = SG_VERDICT_UNDETERMINED};
    sg_error_t error =
        sg_gate_evaluate(gate, commands[i], length, buffer, size, &result);
    report_analysis(stdout, commands[i], error, &result);
    if (error != SG_OK) {
      fprintf(stderr, "evaluation error %d\n", error);
      if (error == SG_ERR_MEMORY || error == SG_ERR_TRUNC)
        fputs("check capacity limits before retrying with a larger buffer\n",
              stderr);
      status = EXIT_FAILURE;
    }
    /* Copy any needed result strings before releasing their backing buffer. */
    free(buffer);
  }
  sg_gate_free(gate);
  return status; /* Reports demo completion; commands are only analyzed. */
}
