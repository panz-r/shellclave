/* Core unit tests for the command policy learner. */

#define _POSIX_C_SOURCE 200809L
#include "shelltype.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static int normalized_equals(const char *input, const char *expected) {
  char **tokens = NULL;
  size_t count = 0;
  if (st_normalize(input, &tokens, &count) != ST_OK)
    return 0;

  char actual[512] = {0};
  size_t used = 0;
  int valid = true;
  for (size_t i = 0; i < count; i++) {
    size_t length = strlen(tokens[i]);
    if (used + length + (i != 0) >= sizeof(actual)) {
      valid = false;
      break;
    }
    if (i != 0)
      actual[used++] = ' ';
    memcpy(actual + used, tokens[i], length);
    used += length;
  }
  actual[used] = '\0';
  valid = valid && strcmp(actual, expected) == 0;
  if (!valid)
    printf("    '%s': got '%s', expected '%s'\n", input, actual, expected);
  st_free_tokens(tokens, count);
  return valid;
}

static int test_normalization_matrix(void) {
  static const struct {
    const char *input;
    const char *expected;
  } cases[] = {
      {"ls -la", "ls #sopt"},
      {"cat /etc/passwd", "cat #p"},
      {"git commit --message \"hello world\"", "git commit #lopt #qs"},
      {"git commit -m msg", "git commit #sopt msg"},
      {"docker run -it ubuntu bash", "docker run #sopt ubuntu bash"},
      {"cat /var/log/syslog | grep ERROR", "cat #p | grep ERROR"},
      {"ls > /tmp/out.txt", "ls > #p"},
      {"head -n 42 file.txt", "head #sopt #n #f"},
      {"git show 0xdeadbeef", "git show #n"},
      {"ping 192.168.1.1", "ping #i"},
      {"export PATH=/usr/bin", "export PATH= #p"},
      {"gcc -o myprog main.c", "gcc #sopt myprog #f"},
      {"echo \"hello world\"", "echo #qs"},
      {"git show A1B2C3D4e5f6a7b8", "git show #h"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(normalized_equals(cases[i].input, cases[i].expected));
  return 1;
}

static st_node_t *find_child(st_node_t *parent, const char *token) {
  for (size_t i = 0; i < parent->num_children; i++)
    if (strcmp(parent->children[i]->token, token) == 0)
      return parent->children[i];
  return NULL;
}

static int test_learner_state_transitions(void) {
  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(learner && learner->trie.root);
  ASSERT(learner->trie.total_commands == 0);
  ASSERT(learner->trie.root->count == 0);

  static const char *commands[] = {"git commit -m one", "git commit -m two",
                                   "git commit -m three", "git status",
                                   "git status"};
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    ASSERT(st_feed(learner, commands[i]) == ST_OK);
    ASSERT(learner->trie.total_commands == i + 1);
    ASSERT(learner->trie.root->count == i + 1);
  }

  st_node_t *git = find_child(learner->trie.root, "git");
  ASSERT(git && git->count == 5);
  ASSERT(find_child(git, "commit") != NULL);
  ASSERT(find_child(git, "status") != NULL);
  ASSERT(st_feed(learner, "") == ST_ERR_INVALID);
  ASSERT(st_feed(learner, NULL) == ST_ERR_INVALID);
  ASSERT(st_feed(NULL, "git status") == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 5);

  st_token_array_t parsed = {0};
  ASSERT(st_normalize_typed("curl /tmp/data", &parsed) == ST_OK);
  ASSERT(st_feed_parsed(learner, "curl /tmp/data", &parsed) == ST_OK);
  st_free_token_array(&parsed);
  ASSERT(learner->trie.total_commands == 6);
  ASSERT(learner->trie.root->count == 6);
  ASSERT(find_child(learner->trie.root, "curl") != NULL);

  st_token_array_t empty = {0};
  ASSERT(st_feed_parsed(NULL, "curl /tmp/data", &empty) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(learner, NULL, &empty) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(learner, "", &empty) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(learner, "curl /tmp/data", NULL) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(learner, "curl /tmp/data", &empty) == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 6);
  st_learner_free(learner);
  st_learner_free(NULL);
  return 1;
}

typedef struct {
  const char *pattern;
  uint32_t count;
  double confidence;
} expected_suggestion_t;

static int suggestions_equal(const st_suggestion_t *actual, size_t actual_count,
                             const expected_suggestion_t *expected,
                             size_t expected_count) {
  if (!actual || actual_count != expected_count)
    return 0;
  for (size_t i = 0; i < expected_count; i++)
    if (!actual[i].pattern ||
        strcmp(actual[i].pattern, expected[i].pattern) != 0 ||
        actual[i].count != expected[i].count ||
        fabs(actual[i].confidence - expected[i].confidence) > 0.000001)
      return 0;
  return 1;
}

static int test_suggestion_matrix(void) {
  static const struct {
    const char *name;
    const char *format;
    size_t repetitions;
    expected_suggestion_t expected[5];
    size_t expected_count;
  } cases[] = {
      {"path family",
       "ls -l /tmp/file%zu",
       5,
       {{"ls", 5, 1.0}, {"ls #sopt", 5, 1.0}, {"ls #sopt #p", 5, 1.0}},
       3},
      {"pipeline family",
       "cat /var/log/file%zu.log | grep ERROR",
       4,
       {{"cat", 4, 1.0},
        {"cat #p.log", 4, 1.0},
        {"cat #p |", 4, 1.0},
        {"cat #p | grep", 4, 1.0},
        {"cat #p | grep ERROR", 4, 1.0}},
       5},
      {"extension family",
       "cat /etc/file%zu.cfg",
       5,
       {{"cat", 5, 1.0}, {"cat #p.cfg", 5, 1.0}},
       2},
      {"size suffix family",
       "allocate %zuMiB",
       5,
       {{"allocate", 5, 1.0}, {"allocate #size.MiB", 5, 1.0}},
       2},
  };

  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    st_learner_t *learner = st_learner_new(3, 0.0);
    ASSERT(learner != NULL);
    for (size_t i = 0; i < cases[c].repetitions; i++) {
      char command[128];
      snprintf(command, sizeof(command), cases[c].format, i);
      ASSERT(st_feed(learner, command) == ST_OK);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions_equal(suggestions, count, cases[c].expected,
                             cases[c].expected_count));
    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
  }
  return 1;
}

static int test_suggestion_thresholds_and_limit(void) {
  static const expected_suggestion_t expected_capped[] = {
      {"cat", 4, 1.0},
      {"cat #p.log", 4, 1.0},
      {"cat #p |", 4, 1.0},
  };
  st_learner_t *learner = st_learner_new(6, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 5; i++) {
    char command[64];
    snprintf(command, sizeof(command), "ls -l /tmp/file%zu", i);
    ASSERT(st_feed(learner, command) == ST_OK);
  }
  size_t count = 99;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(!suggestions && count == 0);
  st_learner_free(learner);

  learner = st_learner_new(3, 0.0);
  ASSERT(learner != NULL);
  learner->max_suggestions = 3;
  for (size_t i = 0; i < 4; i++) {
    char command[128];
    snprintf(command, sizeof(command), "cat /var/log/file%zu.log | grep ERROR",
             i);
    ASSERT(st_feed(learner, command) == ST_OK);
  }
  suggestions = st_suggest(learner, &count);
  ASSERT(
      suggestions_equal(suggestions, count, expected_capped,
                        sizeof(expected_capped) / sizeof(expected_capped[0])));
  st_free_suggestions(suggestions, count);
  learner->max_suggestions = 0;
  count = 17;
  ASSERT(st_suggest(learner, &count) == NULL && count == 0);
  st_learner_free(learner);
  return 1;
}

static int test_confidence_ranking(void) {
  static const expected_suggestion_t expected[] = {
      {"git", 10, 1.0},
      {"git commit #sopt", 8, 1.0},
      {"git commit", 8, 0.8},
  };
  st_learner_t *learner = st_learner_new(2, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 8; i++) {
    char command[64];
    snprintf(command, sizeof(command), "git commit -m msg%zu", i);
    ASSERT(st_feed(learner, command) == ST_OK);
  }
  ASSERT(st_feed(learner, "git status") == ST_OK);
  ASSERT(st_feed(learner, "git log") == ST_OK);

  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_blacklist_filters_exact_suggestion(void) {
  static const expected_suggestion_t expected[] = {
      {"ls", 5, 1.0},
      {"ls #sopt", 5, 1.0},
  };
  st_learner_t *learner = st_learner_new(3, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 5; i++) {
    char command[64];
    snprintf(command, sizeof(command), "ls -l /tmp/file%zu", i);
    ASSERT(st_feed(learner, command) == ST_OK);
  }
  ASSERT(st_blacklist_add(learner, "ls #sopt #p") == ST_OK);
  ASSERT(st_blacklist_add(learner, "ls #sopt #p") == ST_OK);
  ASSERT(st_blacklist_add(learner, "") == ST_ERR_INVALID);
  ASSERT(learner->blacklist_count == 1);
  ASSERT(st_is_blacklisted(learner, "ls #sopt #p"));
  ASSERT(!st_is_blacklisted(learner, "ls #sopt"));
  ASSERT(!st_is_blacklisted(learner, ""));

  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_serialization_roundtrip_and_validation(void) {
  char path[] = "/tmp/shelltype-learner-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  close(fd);

  st_learner_t *source = st_learner_new(3, 0.0);
  st_learner_t *loaded = st_learner_new(3, 0.0);
  ASSERT(source && loaded);
  ASSERT(st_feed(loaded, "obsolete command") == ST_OK);
  for (size_t i = 0; i < 4; i++) {
    char command[128];
    snprintf(command, sizeof(command), "cat /var/log/file%zu | grep ERROR", i);
    ASSERT(st_feed(source, command) == ST_OK);
  }
  ASSERT(st_save(source, path) == ST_OK);
  ASSERT(st_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(find_child(loaded->trie.root, "obsolete") == NULL);

  size_t source_count = 0, loaded_count = 0;
  st_suggestion_t *source_items = st_suggest(source, &source_count);
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(source_items && loaded_items && source_count == 5 &&
         loaded_count == source_count);
  for (size_t i = 0; i < source_count; i++) {
    ASSERT(strcmp(loaded_items[i].pattern, source_items[i].pattern) == 0);
    ASSERT(loaded_items[i].count == source_items[i].count);
    ASSERT(fabs(loaded_items[i].confidence - source_items[i].confidence) <
           0.000001);
  }

  static const char *malformed[] = {
      "not a record\n",
      "0\tgit\n",
      "12x\tgit\n",
      "4294967296\tgit\n",
      "1\t\n",
      "# total_commands=oops\n1\tgit\n",
      "# total_commands=1\n1\tgit\nbroken\n",
      "# total_commands=1\n2\tgit\n",
      "# total_commands=2\n1\tgit commit\n",
      "# total_commands=2\n1\tgit\n1\tgit\n",
  };
  size_t original_children = loaded->trie.root->num_children;
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    FILE *fixture = fopen(path, "w");
    ASSERT(fixture != NULL);
    ASSERT(fputs(malformed[i], fixture) >= 0);
    ASSERT(fclose(fixture) == 0);
    ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    ASSERT(loaded->trie.root->num_children == original_children);
    ASSERT(find_child(loaded->trie.root, "git") == NULL);
  }

  if (access("/dev/full", W_OK) == 0)
    ASSERT(st_save(source, "/dev/full") == ST_ERR_IO);

  st_free_suggestions(source_items, source_count);
  st_free_suggestions(loaded_items, loaded_count);
  st_learner_free(source);
  st_learner_free(loaded);
  unlink(path);
  return 1;
}

static int test_empty_and_null_apis(void) {
  st_learner_t *learner = st_learner_new(5, 0.05);
  ASSERT(learner != NULL);
  size_t count = 17;
  ASSERT(st_suggest(learner, &count) == NULL && count == 0);
  count = 17;
  ASSERT(st_suggest(NULL, &count) == NULL && count == 0);
  ASSERT(st_suggest(learner, NULL) == NULL);
  ASSERT(st_blacklist_add(NULL, "pattern") == ST_ERR_INVALID);
  ASSERT(st_blacklist_add(learner, NULL) == ST_ERR_INVALID);
  ASSERT(!st_is_blacklisted(NULL, "pattern"));
  ASSERT(!st_is_blacklisted(learner, NULL));
  ASSERT(st_save(NULL, "/tmp/unused") == ST_ERR_INVALID);
  ASSERT(st_save(learner, NULL) == ST_ERR_INVALID);
  ASSERT(st_load(NULL, "/tmp/unused") == ST_ERR_INVALID);
  ASSERT(st_load(learner, NULL) == ST_ERR_INVALID);
  st_free_suggestions(NULL, 0);
  st_learner_free(learner);
  return 1;
}

int main(void) {
  printf("Running shelltype unit tests...\n\n");
  TEST(test_normalization_matrix);
  TEST(test_learner_state_transitions);
  TEST(test_suggestion_matrix);
  TEST(test_suggestion_thresholds_and_limit);
  TEST(test_confidence_ranking);
  TEST(test_blacklist_filters_exact_suggestion);
  TEST(test_serialization_roundtrip_and_validation);
  TEST(test_empty_and_null_apis);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
