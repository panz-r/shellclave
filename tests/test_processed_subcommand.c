#include "shell_processor.h"
#include "shelltype.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_pipeline(const char *input, const char *expected_clean,
                          const char *const *expected_tokens,
                          size_t expected_count) {
  const char **processed = NULL;
  size_t processed_count = 0;
  bool has_features = false;
  const char **netargv = NULL;
  size_t netargv_count = 0;
  bool netargv_features = false;
  if (shell_extract_dfa_inputs(input, NULL, &processed, &processed_count,
                               &has_features) != SHELL_PROCESS_OK ||
      processed_count != 1 || has_features ||
      strcmp(processed[0], expected_clean) != 0) {
    goto fail;
  }

  if (shell_extract_netargv_inputs(input, NULL, &netargv, &netargv_count,
                                   &netargv_features) != SHELL_PROCESS_OK ||
      netargv_count != 1 || netargv_features) {
    goto fail;
  }

  st_token_array_t typed = {0};
  if (st_classify(netargv[0], &typed) != ST_OK ||
      typed.count != expected_count) {
    st_free_token_array(&typed);
    goto fail;
  }
  for (size_t i = 0; i < expected_count; i++) {
    if (strcmp(typed.tokens[i].text, expected_tokens[i]) != 0) {
      st_free_token_array(&typed);
      goto fail;
    }
  }
  st_free_token_array(&typed);
  free((void *)processed[0]);
  free(processed);
  free((void *)netargv[0]);
  free(netargv);
  return 1;

fail:
  if (processed) {
    for (size_t i = 0; i < processed_count; i++)
      free((void *)processed[i]);
  }
  free(processed);
  if (netargv) {
    for (size_t i = 0; i < netargv_count; i++)
      free((void *)netargv[i]);
  }
  free(netargv);
  return 0;
}

static int check_trusted_processed_input(void) {
  static const char netargv[] =
      "6:printf,9:two words,16:literal>operator,3:a\\b,";
  static const char *const expected[] = {"printf", "two words",
                                         "literal>operator", "a\\b"};
  st_token_array_t typed = {0};
  st_learner_t *learner = st_learner_new(1, 0.0);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  if (!learner || st_classify(netargv, &typed) != ST_OK ||
      typed.count != sizeof(expected) / sizeof(expected[0]))
    goto fail;
  for (size_t i = 0; i < typed.count; i++)
    if (strcmp(typed.tokens[i].text, expected[i]) != 0)
      goto fail;
  if (st_feed(learner, netargv) != ST_OK)
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
    st_policy_free_matches(matches, match_count);
    goto fail;
  }
  st_policy_free_matches(matches, match_count);
  st_free_token_array(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;

fail:
  st_free_token_array(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
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
