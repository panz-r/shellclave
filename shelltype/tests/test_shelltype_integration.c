/* End-to-end tests for suggestion ranking across mixed command workloads. */

#include "shelltype.h"
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
    if (st_feed(learner, commands[i]) != ST_OK)
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
  if (actual_count != expected_count || (expected_count > 0 && !actual))
    return 0;
  for (size_t i = 0; i < expected_count; i++)
    if (!actual[i].pattern ||
        strcmp(actual[i].pattern, expected[i].pattern) != 0 ||
        actual[i].count != expected[i].count ||
        fabs(actual[i].confidence - expected[i].confidence) > 0.000001)
      return 0;
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
      {"git commit", 5, 1.0},
      {"git commit #sopt", 5, 1.0},
      {"git commit #sopt #hyp", 5, 1.0},
      {"cat #p", 4, 1.0},
      {"cat #p |", 4, 1.0},
      {"cat #p | grep", 4, 1.0},
      {"docker run", 4, 1.0},
      {"docker run #sopt", 4, 1.0},
      {"git", 5, 5.0 / 13.0},
      {"cat", 4, 4.0 / 13.0},
      {"docker", 4, 4.0 / 13.0},
  };

  st_learner_t *learner = st_learner_new(3, 0.0);
  ASSERT(learner != NULL);
  ASSERT(feed_all(learner, commands, sizeof(commands) / sizeof(commands[0])));
  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  st_free_suggestions(suggestions, count);
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
      {"grep #sopt", 30, 1.0},
      {"grep #sopt #hyp", 30, 1.0},
      {"grep #sopt #hyp #p", 30, 1.0},
      {"cat #p.txt", 25, 1.0},
      {"cat #p |", 25, 1.0},
      {"cat #p | wc", 25, 1.0},
      {"cat #p | wc #sopt", 25, 1.0},
      {"find #p", 20, 1.0},
      {"find #p #sopt", 20, 1.0},
      {"docker run", 15, 1.0},
      {"docker run #sopt", 15, 1.0},
      {"docker run #sopt #hyp", 15, 1.0},
      {"docker run #sopt #hyp bash", 15, 1.0},
      {"systemctl restart", 10, 1.0},
      {"systemctl restart #hyp", 10, 1.0},
      {"grep", 30, 0.30},
      {"cat", 25, 0.25},
      {"find", 20, 0.20},
      {"docker", 15, 0.15},
      {"systemctl", 10, 0.10},
  };
  st_learner_t *learner = st_learner_new(5, 0.01);
  ASSERT(learner != NULL);
  for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
       family++)
    for (int i = 0; i < families[family].count; i++) {
      char command[128];
      snprintf(command, sizeof(command), families[family].format, i);
      ASSERT(st_feed(learner, command) == ST_OK);
    }
  ASSERT(learner->trie.total_commands == 100);

  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  st_free_suggestions(suggestions, count);
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
