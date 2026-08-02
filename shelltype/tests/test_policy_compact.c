/* Integration tests for large policy compaction and NFA rendering. */

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

static int eval_matches(st_policy_t *policy, const char *command,
                        const char *expected_pattern) {
  st_eval_result_t result = {0};
  st_error_t error = st_policy_eval(policy, command, &result);
  int valid = error == ST_OK && result.matches == (expected_pattern != NULL);
  if (expected_pattern)
    valid = valid && result.matching_pattern &&
            strcmp(result.matching_pattern, expected_pattern) == 0;
  else
    valid = valid && result.matching_pattern == NULL;
  if (!valid)
    printf("    '%s': matches=%d pattern=%s expected=%s error=%d\n", command,
           result.matches,
           result.matching_pattern ? result.matching_pattern : "-",
           expected_pattern ? expected_pattern : "-", error);
  return valid;
}

static int verify_alternating_policy(st_policy_t *policy, int pattern_count) {
  for (int i = 0; i < pattern_count; i++) {
    char command[128];
    char expected[128];
    snprintf(command, sizeof(command), "cmd%d --option value /path/to/file%d",
             i, i);
    snprintf(expected, sizeof(expected), "cmd%d --option * /path/to/file%d", i,
             i);
    if (!eval_matches(policy, command, i % 2 ? expected : NULL))
      return 0;
  }
  return 1;
}

static int test_large_policy_compaction(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, NULL, 0);
  ASSERT(policy != NULL);
  ASSERT(st_policy_compact(policy) == ST_OK);
  const int pattern_count = 200;
  for (int i = 0; i < pattern_count; i++) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "cmd%d --option * /path/to/file%d", i,
             i);
    ASSERT(st_policy_add(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == (size_t)pattern_count);
  size_t populated_states = st_policy_state_count(policy);
  size_t populated_memory = st_policy_memory_usage(policy);
  ASSERT(populated_states > (size_t)pattern_count);
  ASSERT(populated_memory > 0);
  ASSERT(st_policy_working_set(policy) <= populated_memory);
  ASSERT(eval_matches(policy, "cmd42 --option value /path/to/file42",
                      "cmd42 --option * /path/to/file42"));
  ASSERT(eval_matches(policy, "cmd199 --option value /path/to/file199",
                      "cmd199 --option * /path/to/file199"));
  ASSERT(eval_matches(policy, "cmd200 --option value /path/to/file200", NULL));

  for (int i = 0; i < pattern_count; i += 2) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "cmd%d --option * /path/to/file%d", i,
             i);
    ASSERT(st_policy_remove(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == (size_t)pattern_count / 2);
  size_t stale_states = st_policy_state_count(policy);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_count(policy) == (size_t)pattern_count / 2);
  ASSERT(st_policy_state_count(policy) < stale_states);
  ASSERT(st_policy_memory_usage(policy) < populated_memory);
  ASSERT(verify_alternating_policy(policy, pattern_count));

  size_t compacted_states = st_policy_state_count(policy);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_state_count(policy) == compacted_states);
  ASSERT(verify_alternating_policy(policy, pattern_count));

  const char *new_pattern = "fresh #n";
  ASSERT(st_policy_add(policy, new_pattern) == ST_OK);
  ASSERT(eval_matches(policy, "fresh 17", new_pattern));
  ASSERT(st_policy_remove(policy, new_pattern) == ST_OK);
  ASSERT(eval_matches(policy, "fresh 17", NULL));
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_state_count(policy) == compacted_states);
  ASSERT(verify_alternating_policy(policy, pattern_count));
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file)
    return NULL;
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return NULL;
  }
  long length = ftell(file);
  if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  char *contents = malloc((size_t)length + 1);
  if (!contents) {
    fclose(file);
    return NULL;
  }
  size_t bytes = fread(contents, 1, (size_t)length, file);
  fclose(file);
  if (bytes != (size_t)length) {
    free(contents);
    return NULL;
  }
  contents[bytes] = '\0';
  return contents;
}

static size_t occurrence_count(const char *text, const char *needle) {
  size_t count = 0;
  size_t length = strlen(needle);
  for (const char *found = strstr(text, needle); found;
       found = strstr(found + length, needle))
    count++;
  return count;
}

static int rendered_nfa_matches(const char *rendered, const char *identifier,
                                unsigned category_mask,
                                unsigned pattern_id_base, bool include_tags) {
  char expected[96];
  snprintf(expected, sizeof(expected), "Identifier: %s\n", identifier);
  if (!strstr(rendered, "NFA_ALPHABET\n") || !strstr(rendered, expected) ||
      !strstr(rendered, "AlphabetSize: 261\n") ||
      !strstr(rendered, "Initial: 0\n") ||
      !strstr(rendered, "Symbol 256: 0-255 (special)") ||
      !strstr(rendered, "Symbol 256 ->") ||
      !strstr(rendered, "Symbol 259 ->") ||
      occurrence_count(rendered, "EosTarget: yes") != 3)
    return 0;

  snprintf(expected, sizeof(expected), "CategoryMask: 0x%02x", category_mask);
  if (occurrence_count(rendered, expected) != 3)
    return 0;
  for (unsigned i = 0; i < 3; i++) {
    snprintf(expected, sizeof(expected), "PatternId: %u\n",
             pattern_id_base + i);
    if (!strstr(rendered, expected))
      return 0;
  }

  static const char *tags[] = {"git commit", "git status", "cat *"};
  if (occurrence_count(rendered, "Tags: ") != (include_tags ? 3u : 0u))
    return 0;
  for (size_t i = 0; include_tags && i < sizeof(tags) / sizeof(tags[0]); i++) {
    snprintf(expected, sizeof(expected), "Tags: %s\n", tags[i]);
    if (!strstr(rendered, expected))
      return 0;
  }
  return 1;
}

static int test_nfa_rendering_contract(void) {
  static const char *patterns[] = {"git commit", "git status", "cat *"};
  const char *path = "test_compact_policy.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, patterns, 3);
  ASSERT(policy != NULL);
  st_nfa_render_opts_t options = {.category_mask = 0x05,
                                  .pattern_id_base = 7,
                                  .include_tags = true,
                                  .identifier = "compact-policy-test"};
  const struct {
    const st_nfa_render_opts_t *options;
    const char *identifier;
    unsigned category_mask;
    unsigned pattern_id_base;
    bool include_tags;
  } cases[] = {{&options, "compact-policy-test", 0x05, 7, true},
               {NULL, "rbox policy", 0x01, 1, false}};
  ASSERT(st_policy_render_nfa(NULL, path, &options) == ST_ERR_INVALID);
  ASSERT(st_policy_render_nfa(policy, NULL, &options) == ST_ERR_INVALID);
  ASSERT(st_policy_render_nfa(policy, ".", &options) == ST_ERR_IO);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(st_policy_render_nfa(policy, path, cases[i].options) == ST_OK);
    char *rendered = read_file(path);
    ASSERT(rendered != NULL);
    ASSERT(rendered_nfa_matches(
        rendered, cases[i].identifier, cases[i].category_mask,
        cases[i].pattern_id_base, cases[i].include_tags));
    free(rendered);
  }
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

int main(void) {
  printf("Running compact policy tests...\n\n");
  TEST(test_large_policy_compaction);
  TEST(test_nfa_rendering_contract);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
