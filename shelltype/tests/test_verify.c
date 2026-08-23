/* Verification and suggestion integration tests. */

#include "shelltype.h"
#include "test_allocator.h"
#include "test_netargv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

static int pattern_is_cpl(const char *actual, const char *cpl) {
  if (!actual || !cpl)
    return actual == cpl;
  char *encoded = NULL;
  int equal = st_netpattern_from_cpl(cpl, &encoded) == ST_OK &&
              strcmp(actual, encoded) == 0;
  free(encoded);
  return equal;
}

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
    if (test_st_policy_add(policy, patterns[i]) != ST_OK) {
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
    ASSERT(test_st_policy_verify_all(policy, cases[i].command, &matches,
                                     &count) == ST_OK);
    ASSERT(count == cases[i].count);
    ASSERT((count == 0) == (matches == NULL));
    for (size_t j = 0; j < count; j++) {
      for (size_t k = j + 1; k < count; k++)
        ASSERT(strcmp(matches[j], matches[k]) != 0);
    }
    for (size_t j = 0; j < cases[i].count; j++) {
      bool found = false;
      for (size_t k = 0; k < count; k++)
        found = found || pattern_is_cpl(matches[k], cases[i].expected[j]);
      ASSERT(found);
    }
    st_policy_free_matches(matches, count);
  }

  const char **matches = (const char **)1;
  size_t count = 99;
  ASSERT(test_st_policy_verify_all(policy, "", &matches, &count) == ST_OK);
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
    ASSERT(test_st_policy_verify_all(invalid[i].policy, invalid[i].command,
                                     invalid[i].give_matches ? &matches : NULL,
                                     invalid[i].give_count ? &count : NULL) ==
           ST_ERR_INVALID);
    ASSERT(!invalid[i].give_matches || matches == NULL);
    ASSERT(!invalid[i].give_count || count == 0);
  }
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_verify_and_precedence_matrix(void) {
  static const char *orders[][2] = {{"x #n #val", "x #val #n"},
                                    {"x #val #n", "x #n #val"}};
  for (size_t order = 0; order < sizeof(orders) / sizeof(orders[0]); order++) {
    st_policy_ctx_t *context = st_policy_ctx_new();
    ASSERT(context != NULL);
    st_policy_t *policy = new_policy(context, orders[order], 2);
    ASSERT(policy != NULL);

    const char **matches = NULL;
    size_t count = 0;
    ASSERT(test_st_policy_verify_all(policy, "x 1 2", &matches, &count) ==
           ST_OK);
    ASSERT(count == 2);
    ASSERT(matches != NULL);
    ASSERT(pattern_is_cpl(matches[0], "x #n #val"));
    ASSERT(pattern_is_cpl(matches[1], "x #val #n"));
    st_policy_free_matches(matches, count);

    for (size_t phase = 0; phase < 2; phase++) {
      st_eval_result_t result = {0};
      ASSERT(test_st_policy_eval(policy, "x 1 2", &result) == ST_OK);
      ASSERT(result.matches && result.matching_pattern != NULL);
      ASSERT(pattern_is_cpl(result.matching_pattern, "x #n #val"));
      if (phase == 0)
        ASSERT(st_policy_compact(policy) == ST_OK);
    }

    st_policy_free(policy);
    st_policy_ctx_free(context);
  }
  return 1;
}

static int test_verify_all_allocation_failures_clear_outputs(void) {
  static const char *patterns[] = {"x #n #val", "x #val #n"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, patterns, 2);
  ASSERT(context != NULL && policy != NULL);
  st_test_alloc_reset();
  const char **probe_matches = NULL;
  size_t probe_count = 0;
  ASSERT(test_st_policy_verify_all(policy, "x 1 2", &probe_matches,
                                   &probe_count) == ST_OK);
  ASSERT(probe_matches != NULL && probe_count == 2);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_policy_free_matches(probe_matches, probe_count);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    const char **matches = (const char **)1;
    size_t count = 99;
    st_test_alloc_fail_at(fail_at);
    st_error_t err =
        test_st_policy_verify_all(policy, "x 1 2", &matches, &count);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(matches == NULL && count == 0);
    } else {
      ASSERT(err == ST_OK);
      ASSERT(matches != NULL && count == 2);
      st_policy_free_matches(matches, count);
    }
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_semver_informational_coexistence(void) {
  static const char *patterns[] = {"install #semver.patch",
                                   "install #semver.major", "install #semver.*",
                                   "install #semver.minor"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, patterns, 4);
  ASSERT(context && policy && st_policy_count(policy) == 4);

  const char **matches = NULL;
  size_t count = 0;
  ASSERT(test_st_policy_verify_all(policy, "install 1.2.3", &matches, &count) ==
         ST_OK);
  ASSERT(count == 4);
  for (size_t p = 0; p < 4; p++) {
    bool found = false;
    for (size_t m = 0; m < count; m++)
      found = found || pattern_is_cpl(matches[m], patterns[p]);
    ASSERT(found);
  }
  st_policy_free_matches(matches, count);

  st_eval_result_t result = {0};
  ASSERT(test_st_policy_eval(policy, "install 1.2.3", &result) == ST_OK);
  ASSERT(result.matches &&
         pattern_is_cpl(result.matching_pattern, "install #semver.*"));
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(test_st_policy_eval(policy, "install 2.0.0-alpha", &result) == ST_OK);
  ASSERT(result.matches &&
         pattern_is_cpl(result.matching_pattern, "install #semver.*"));

  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_verify_high_fanout_growth(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context && policy);
  char expected[ST_MAX_NETPATTERN_LEN] = {0};
  size_t pattern_count = 0;
  for (unsigned mask = 0; mask < (1u << 9); mask++) {
    if (__builtin_popcount(mask) != 4)
      continue;
    char pattern[ST_MAX_NETPATTERN_LEN] = "x";
    for (unsigned pos = 0; pos < 9; pos++)
      strcat(pattern, (mask & (1u << pos)) ? " #n" : " #val");
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
    if (expected[0] == '\0' || strcmp(pattern, expected) < 0)
      strcpy(expected, pattern);
    pattern_count++;
  }
  ASSERT(pattern_count == 126 && st_policy_count(policy) == 126);
  const char *command = "x 1 2 3 4 5 6 7 8 9";
  const char **matches = NULL;
  size_t count = 0;
  ASSERT(test_st_policy_verify_all(policy, command, &matches, &count) == ST_OK);
  ASSERT(count == 126);
  st_policy_free_matches(matches, count);
  st_eval_result_t result = {0};
  ASSERT(test_st_policy_eval(policy, command, &result) == ST_OK);
  ASSERT(result.matches && pattern_is_cpl(result.matching_pattern, expected));

  st_test_alloc_reset();
  ASSERT(test_st_policy_eval(policy, command, &result) == ST_OK);
  size_t eval_allocations = st_test_alloc_count();
  bool eval_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= eval_allocations; fail_at++) {
    memset(&result, 0xa5, sizeof(result));
    st_test_alloc_fail_at(fail_at);
    st_error_t error = test_st_policy_eval(policy, command, &result);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      eval_failure_observed = true;
      ASSERT(!result.matches && result.matching_pattern == NULL &&
             result.suggestion_count == 0 && result.error == ST_OK);
    } else {
      ASSERT(error == ST_OK && result.matches && result.matching_pattern &&
             pattern_is_cpl(result.matching_pattern, expected));
    }
  }
  ASSERT(eval_failure_observed);

  st_test_alloc_reset();
  ASSERT(test_st_policy_verify_all(policy, command, &matches, &count) == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_policy_free_matches(matches, count);
  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    matches = (const char **)1;
    count = 99;
    st_test_alloc_fail_at(fail_at);
    st_error_t error =
        test_st_policy_verify_all(policy, command, &matches, &count);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(matches == NULL && count == 0);
    } else {
      ASSERT(error == ST_OK && count == 126);
      st_policy_free_matches(matches, count);
    }
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int suggestion_is(const st_expand_suggestion_t *suggestion,
                         const char *pattern, const char *based_on,
                         double confidence) {
  int matches = pattern_is_cpl(suggestion->pattern, pattern) &&
                ((suggestion->based_on == NULL && based_on == NULL) ||
                 (suggestion->based_on != NULL && based_on != NULL &&
                  pattern_is_cpl(suggestion->based_on, based_on))) &&
                suggestion->confidence == confidence;
  if (!matches)
    printf("    suggestion actual={%s, %s, %.17g} expected={%s, %s, %.17g}\n",
           suggestion->pattern,
           suggestion->based_on ? suggestion->based_on : "(null)",
           suggestion->confidence, pattern, based_on ? based_on : "(null)",
           confidence);
  return matches;
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
    ASSERT(test_st_policy_eval(policy, cases[i].command, &result) == ST_OK);
    ASSERT(!result.matches && result.matching_pattern == NULL);
    ASSERT(result.suggestion_count == 2);
    for (size_t j = 0; j < result.suggestion_count; j++) {
      ASSERT(suggestion_is(&result.suggestions[j], cases[i].suggestions[j],
                           cases[i].based_on[j], cases[i].confidence));

      st_policy_t *accepted = new_policy(context, &cases[i].suggestions[j], 1);
      ASSERT(accepted != NULL);
      st_eval_result_t accepted_result = {0};
      ASSERT(test_st_policy_eval(accepted, cases[i].command,
                                 &accepted_result) == ST_OK);
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
  TEST(test_verify_and_precedence_matrix);
  TEST(test_verify_all_allocation_failures_clear_outputs);
  TEST(test_semver_informational_coexistence);
  TEST(test_verify_high_fanout_growth);
  TEST(test_suggestion_round_trip_matrix);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
