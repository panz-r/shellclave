/* End-to-end tests for suggestion ranking across mixed command workloads. */

#include "shelltype.h"
#include "test_netargv.h"
#include "trie_internal.h"
#include <math.h>
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

static int feed_all(st_learner_t *learner, const char *const *commands,
                    size_t count) {
  for (size_t i = 0; i < count; i++)
    if (test_st_feed(learner, commands[i]) != ST_OK)
      return 0;
  return learner->trie.total_commands == count;
}

typedef struct {
  const char *pattern;
  uint32_t count;
  double confidence;
} expected_suggestion_t;

static int suggestions_equal(const st_suggestion_t *actual, size_t actual_count,
                             const expected_suggestion_t *expected,
                             size_t expected_count) {
  if (actual_count != expected_count || (expected_count > 0 && !actual)) {
    fprintf(stderr, "suggestion count: actual=%zu expected=%zu\n", actual_count,
            expected_count);
    for (size_t i = 0; actual && i < actual_count; i++)
      fprintf(stderr, "  %s (%u, %.3f)\n", actual[i].pattern, actual[i].count,
              actual[i].confidence);
    return 0;
  }
  for (size_t i = 0; i < expected_count; i++) {
    char *expected_pattern = NULL;
    int same = actual[i].pattern &&
               st_netpattern_from_cpl(expected[i].pattern, &expected_pattern) ==
                   ST_OK &&
               strcmp(actual[i].pattern, expected_pattern) == 0;
    free(expected_pattern);
    if (!same || actual[i].count != expected[i].count ||
        fabs(actual[i].confidence - expected[i].confidence) > 0.000001)
      return 0;
  }
  return 1;
}

static int suggestions_replay_exactly(const st_suggestion_t *suggestions,
                                      size_t suggestion_count,
                                      const char *const *commands,
                                      size_t command_count) {
  for (size_t i = 0; i < suggestion_count; i++) {
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    if (!policy ||
        test_st_policy_add(policy, suggestions[i].pattern) != ST_OK) {
      st_policy_free(policy);
      st_policy_ctx_release(context);
      return 0;
    }
    uint32_t matches = 0;
    for (size_t command = 0; command < command_count; command++) {
      st_eval_result_t result = {0};
      if (test_st_policy_eval(policy, commands[command], &result) != ST_OK) {
        st_policy_free(policy);
        st_policy_ctx_release(context);
        return 0;
      }
      matches += result.matches;
    }
    st_policy_free(policy);
    st_policy_ctx_release(context);
    if (matches != suggestions[i].count)
      return 0;
  }
  return 1;
}

static int test_realistic_workload_matrix(void) {
  static const char *commands[] = {
      "git commit -m Initial-commit",
      "git commit -m Fix-bug",
      "git commit -m Add-feature",
      "git commit -m Update-docs",
      "git commit -m Refactor-code",
      "cat /var/log/syslog | grep ERROR",
      "cat /var/log/auth.log | grep FAILED",
      "cat /var/log/kern.log | grep WARN",
      "cat /var/log/dmesg | grep error",
      "docker run -it ubuntu bash",
      "docker run -it alpine sh",
      "docker run -it nginx bash",
      "docker run -it python python3",
  };
  static const expected_suggestion_t expected[] = {
      {"git commit #sopt #hyp", 5, 1.0},
      {"cat #p | grep *", 4, 1.0},
  };

  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 3,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  ASSERT(feed_all(learner, commands, sizeof(commands) / sizeof(commands[0])));
  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  ASSERT(suggestions_replay_exactly(suggestions, count, commands,
                                    sizeof(commands) / sizeof(commands[0])));
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_large_dataset_ranking(void) {
  static const struct {
    const char *format;
    int count;
  } families[] = {
      {"grep -r pattern-%d /home/user/project", 30},
      {"cat /tmp/output-%d.txt | wc -l", 25},
      {"find /var/log -name file-%d.log", 20},
      {"docker run -it image-%d bash", 15},
      {"systemctl restart service-%d", 10},
  };
  static const expected_suggestion_t expected[] = {
      {"grep #sopt #hyp #p", 30, 1.0},
      {"cat #p | wc #sopt", 25, 1.0},
      {"find #p #sopt *", 20, 1.0},
      {"docker run #sopt #hyp bash", 15, 1.0},
      {"systemctl restart #hyp", 10, 1.0},
  };
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 5,
                             .min_confidence = 0.01,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
       family++)
    for (int i = 0; i < families[family].count; i++) {
      char command[128];
      snprintf(command, sizeof(command), families[family].format, i);
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
  ASSERT(learner->trie.total_commands == 100);

  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  const char *commands[100];
  char command_storage[100][128];
  size_t command_count = 0;
  for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
       family++)
    for (int i = 0; i < families[family].count; i++) {
      snprintf(command_storage[command_count],
               sizeof(command_storage[command_count]), families[family].format,
               i);
      commands[command_count] = command_storage[command_count];
      command_count++;
    }
  ASSERT(
      suggestions_replay_exactly(suggestions, count, commands, command_count));
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

int main(void) {
  printf("Running shelltype integration tests...\n\n");
  TEST(test_realistic_workload_matrix);
  TEST(test_large_dataset_ranking);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
