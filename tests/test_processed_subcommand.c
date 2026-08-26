#include "shell_processor.h"
#include "shelltype.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_pipeline(const char *input, const char *expected_clean,
                          const char *const *expected_tokens,
                          size_t expected_count) {
  (void)expected_clean;
  shell_command_info_t *commands = NULL;
  size_t command_count = 0;
  char *netargv = NULL;
  if (shell_process_command(input, strlen(input), NULL, &commands,
                            &command_count) != SHELL_PROCESS_OK ||
      command_count != 1 ||
      shell_command_info_has_dangerous_features(&commands[0]))
    goto fail;
  if (shell_render_netargv(&commands[0], NULL, &netargv) != SHELL_PROCESS_OK)
    goto fail;

  st_token_array_t typed = {0};
  if (st_netargv_classify(netargv, &typed) != ST_OK ||
      typed.count != expected_count) {
    st_token_array_free(&typed);
    goto fail;
  }
  for (size_t i = 0; i < expected_count; i++) {
    if (strcmp(typed.tokens[i].text, expected_tokens[i]) != 0) {
      st_token_array_free(&typed);
      goto fail;
    }
  }
  st_token_array_free(&typed);
  shell_command_infos_free(commands, command_count);
  free(netargv);
  return 1;

fail:
  shell_command_infos_free(commands, command_count);
  free(netargv);
  return 0;
}

static int check_trusted_processed_input(void) {
  static const char netargv[] =
      "6:printf,9:two words,16:literal>operator,3:a\\b,";
  static const char *const expected[] = {"printf", "two words",
                                         "literal>operator", "a\\b"};
  st_token_array_t typed = {0};
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  if (!learner || st_netargv_classify(netargv, &typed) != ST_OK ||
      typed.count != sizeof(expected) / sizeof(expected[0]))
    goto fail;
  for (size_t i = 0; i < typed.count; i++)
    if (strcmp(typed.tokens[i].text, expected[i]) != 0)
      goto fail;
  if (st_learner_feed_netargv(learner, netargv) != ST_OK)
    goto fail;
  char *netpattern = NULL;
  if (!policy || st_netpattern_from_cpl("printf * * *", &netpattern) != ST_OK ||
      st_policy_add_netpattern(policy, netpattern) != ST_OK) {
    free(netpattern);
    goto fail;
  }
  free(netpattern);
  st_eval_result_t result = {0};
  if (st_policy_eval(policy, netargv, &result) != ST_OK || !result.matches)
    goto fail;
  const char **matches = NULL;
  size_t match_count = 0;
  if (st_policy_verify_all(policy, netargv, &matches, &match_count) != ST_OK ||
      match_count != 1) {
    st_policy_matches_free(matches);
    goto fail;
  }
  st_policy_matches_free(matches);
  st_token_array_free(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;

fail:
  st_token_array_free(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 0;
}

int main(void) {
  static const char *const assembled[] = {"echo", "foobar", "a b",
                                          "pre mid post"};
  static const char *const empty[] = {"printf", "", "", ">"};
  static const char *const escaped[] = {"printf", "a\"b", "c'd", "x\\y"};
  int passed =
      check_pipeline("echo foo\"bar\" a\\ b pre' mid 'post",
                     "echo foobar \"a b\" \"pre mid post\"", assembled, 4) &&
      check_pipeline("printf '' \"\" '>'", "printf \"\" \"\" \">\"", empty,
                     4) &&
      check_pipeline("printf 'a\"b' \"c'd\" 'x\\y'",
                     "printf \"a\\\"b\" \"c'd\" \"x\\\\y\"", escaped, 4) &&
      check_trusted_processed_input();
  printf("processed-subcommand integration: %s\n", passed ? "PASS" : "FAIL");
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
