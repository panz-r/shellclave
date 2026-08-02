/* Verification and suggestion integration tests. */

#include "shelltype.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    assertion failed: %s at %s:%d\n", #condition, __FILE__,      \
             __LINE__);                                                        \
      return 0;                                                                \
    }                                                                          \
  } while (0)

#define TEST(function)                                                         \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      tests_passed++;                                                          \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      tests_failed++;                                                          \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_policy_t *new_policy(st_policy_ctx_t *context,
                               const char *const *patterns, size_t count) {
  st_policy_t *policy = st_policy_new(context);
  if (!policy)
    return NULL;
  for (size_t i = 0; i < count; i++)
    if (st_policy_add(policy, patterns[i]) != ST_OK) {
      st_policy_free(policy);
      return NULL;
    }
  return policy;
}

static int test_verify_all_matrix(void) {
  static const char *patterns[] = {"git commit -m *", "git commit -m fix",
                                   "git status", "typed #n #val",
                                   "typed #val #n"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  st_policy_t *policy =
      new_policy(context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(policy != NULL);

  static const struct {
    const char *command;
    const char *expected[2];
    size_t count;
  } cases[] = {
      {"git commit -m hello", {"git commit -m *", NULL}, 1},
      {"git commit -m fix", {"git commit -m *", NULL}, 1},
      {"git status", {"git status", NULL}, 1},
      {"typed 1 2", {"typed #n #val", "typed #val #n"}, 2},
      {"rm -rf /", {NULL, NULL}, 0},
  };

  /* The wildcard subsumes the exact commit rule; the crossing typed rules do
   * not subsume one another. */
  ASSERT(st_policy_count(policy) == 4);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char **matches = NULL;
    size_t count = 99;
    ASSERT(st_policy_verify_all(policy, cases[i].command, &matches, &count) ==
           ST_OK);
    ASSERT(count == cases[i].count);
    ASSERT((count == 0) == (matches == NULL));
    for (size_t j = 0; j < cases[i].count; j++) {
      bool found = false;
      for (size_t k = 0; k < count; k++)
        found = found || strcmp(matches[k], cases[i].expected[j]) == 0;
      ASSERT(found);
    }
    st_policy_free_matches(matches, count);
  }

  const char **matches = (const char **)1;
  size_t count = 99;
  ASSERT(st_policy_verify_all(policy, "", &matches, &count) == ST_OK);
  ASSERT(matches == NULL && count == 0);
  const struct {
    const st_policy_t *policy;
    const char *command;
    bool give_matches;
    bool give_count;
  } invalid[] = {{NULL, "git status", true, true},
                 {policy, NULL, true, true},
                 {policy, "git status", false, true},
                 {policy, "git status", true, false}};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    matches = (const char **)1;
    count = 99;
    ASSERT(st_policy_verify_all(invalid[i].policy, invalid[i].command,
                                invalid[i].give_matches ? &matches : NULL,
                                invalid[i].give_count ? &count : NULL) ==
           ST_ERR_INVALID);
    ASSERT(!invalid[i].give_matches || matches == NULL);
    ASSERT(!invalid[i].give_count || count == 0);
  }
  st_policy_free_matches(NULL, 99);

  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int suggestion_is(const st_expand_suggestion_t *suggestion,
                         const char *pattern, const char *based_on,
                         double confidence) {
  return strcmp(suggestion->pattern, pattern) == 0 &&
         ((suggestion->based_on == NULL && based_on == NULL) ||
          (suggestion->based_on != NULL && based_on != NULL &&
           strcmp(suggestion->based_on, based_on) == 0)) &&
         suggestion->confidence == confidence;
}

static int test_suggestion_round_trip_matrix(void) {
  static const char *patterns[] = {"git status", "ls -la *"};
  static const struct {
    const char *command;
    const char *suggestions[2];
    const char *based_on[2];
    double confidence;
  } cases[] = {
      {"git commit -m hello",
       {"git commit -m hello", "git commit #sopt hello"},
       {"git status", NULL},
       0.25},
      {"docker run -it ubuntu bash",
       {"docker run -it ubuntu bash", "docker run #sopt ubuntu bash"},
       {NULL, NULL},
       0.0},
      {"rm -rf /", {"rm -rf /", "rm #sopt /"}, {NULL, NULL}, 0.0},
      {"totally-unrelated-command",
       {"totally-unrelated-command", "#hyp"},
       {NULL, NULL},
       0.0},
  };

  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  st_policy_t *policy =
      new_policy(context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_eval_result_t result = {0};
    ASSERT(st_policy_eval(policy, cases[i].command, &result) == ST_OK);
    ASSERT(!result.matches && result.matching_pattern == NULL);
    ASSERT(result.suggestion_count == 2);
    for (size_t j = 0; j < result.suggestion_count; j++) {
      ASSERT(suggestion_is(&result.suggestions[j], cases[i].suggestions[j],
                           cases[i].based_on[j], cases[i].confidence));

      st_policy_t *accepted = new_policy(context, &cases[i].suggestions[j], 1);
      ASSERT(accepted != NULL);
      ASSERT(st_policy_add(accepted, cases[i].suggestions[j]) == ST_OK);
      st_eval_result_t accepted_result = {0};
      ASSERT(st_policy_eval(accepted, cases[i].command, &accepted_result) ==
             ST_OK);
      ASSERT(accepted_result.matches &&
             accepted_result.matching_pattern != NULL);
      st_policy_free(accepted);
    }
  }
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

int main(void) {
  printf("Running verification tests...\n\n");
  TEST(test_verify_all_matrix);
  TEST(test_suggestion_round_trip_matrix);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
