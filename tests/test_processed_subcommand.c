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
  if (shell_extract_dfa_inputs(input, NULL, &processed, &processed_count,
                               &has_features) != SHELL_PROCESS_OK ||
      processed_count != 1 || has_features ||
      strcmp(processed[0], expected_clean) != 0) {
    goto fail;
  }

  st_token_array_t typed = {0};
  if (st_classify(processed[0], &typed) != ST_OK ||
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
  return 1;

fail:
  if (processed) {
    for (size_t i = 0; i < processed_count; i++)
      free((void *)processed[i]);
  }
  free(processed);
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
                     "printf \"a\\\"b\" \"c'd\" \"x\\\\y\"", escaped, 4);
  printf("processed-subcommand integration: %s\n", passed ? "PASS" : "FAIL");
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
