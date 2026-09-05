/*
 * test_policy.c – Unit tests for the policy module.
 */

#define _POSIX_C_SOURCE 200809L

#include "policy_ctx.h"
#include "shelltype.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_netargv.h"
#include "trie_internal.h"
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static char policy_temp_paths[3][256];

static void cleanup_policy_temp_files(void) {
  for (size_t i = 0;
       i < sizeof(policy_temp_paths) / sizeof(policy_temp_paths[0]); i++) {
    if (policy_temp_paths[i][0] != '\0') {
      (void)unlink(policy_temp_paths[i]);
      policy_temp_paths[i][0] = '\0';
    }
  }
}

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %-40s ", #name);                                                 \
    if (name()) {                                                              \
      tests_passed++;                                                          \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      tests_failed++;                                                          \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__);  \
      return 0;                                                                \
    }                                                                          \
  } while (0)
#define ASSERT_STR_EQ(a, b)                                                    \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, \
             __LINE__);                                                        \
      return 0;                                                                \
    }                                                                          \
  } while (0)
#define ASSERT_OK(expression) ASSERT((expression) == ST_OK)

static int pattern_is_cpl(const char *actual, const char *expected_cpl) {
  if (!actual || !expected_cpl)
    return actual == expected_cpl;
  char *expected = NULL;
  int equal = st_netpattern_from_cpl(expected_cpl, &expected) == ST_OK &&
              strcmp(actual, expected) == 0;
  free(expected);
  return equal;
}

static int compare_netpattern_views(st_netpattern_view_t left,
                                    st_netpattern_view_t right) {
  size_t shared = left.length < right.length ? left.length : right.length;
  int compared = shared ? memcmp(left.data, right.data, shared) : 0;
  if (compared != 0)
    return compared;
  return left.length > right.length ? 1 : left.length < right.length ? -1 : 0;
}

static st_token_type_t test_pattern_token_type(const char *token) {
  if (!token)
    return ST_TYPE_LITERAL;
  for (int type = ST_TYPE_LITERAL; type < ST_TYPE_COUNT; type++)
    if (strcmp(token, st_type_symbol[type]) == 0)
      return (st_token_type_t)type;
  return ST_TYPE_LITERAL;
}

/* Legacy-shaped test adapters keep the existing lattice matrices readable
 * while exercising the canonical 0.3 APIs underneath. */
static size_t st_policy_suggest_token_variants(st_learner_t *learner,
                                               const char **tokens,
                                               size_t count, size_t edit_pos,
                                               st_token_variant_t *out) {
  st_token_t typed[ST_MAX_CMD_TOKENS];
  if (!tokens || count > ST_MAX_CMD_TOKENS)
    return st_learner_suggest_token_variants(learner, NULL, edit_pos, out);
  for (size_t i = 0; i < count; i++)
    typed[i] = (st_token_t){.text = (char *)tokens[i],
                            .type = test_pattern_token_type(tokens[i])};
  st_token_array_t pattern = {.tokens = typed, .count = count};
  return st_learner_suggest_token_variants(learner, &pattern, edit_pos, out);
}

static char *st_policy_apply_type_at(st_learner_t *learner, const char **tokens,
                                     size_t count, size_t edit_pos,
                                     st_token_type_t new_type) {
  (void)learner;
  if (!tokens || count == 0 || count > ST_MAX_CMD_TOKENS)
    return NULL;
  st_token_t typed[ST_MAX_CMD_TOKENS];
  for (size_t i = 0; i < count; i++) {
    if (!tokens[i])
      return NULL;
    typed[i] = (st_token_t){.text = (char *)tokens[i],
                            .type = test_pattern_token_type(tokens[i])};
  }
  char *pattern = NULL, *changed = NULL, *cpl = NULL;
  if (st_netpattern_encode(typed, count, &pattern) != ST_OK ||
      st_netpattern_apply_type_at(pattern, edit_pos, new_type, &changed) !=
          ST_OK ||
      st_netpattern_to_cpl(changed, &cpl) != ST_OK) {
    free(cpl);
    cpl = NULL;
  }
  free(changed);
  free(pattern);
  return cpl;
}

static int policy_matches(st_policy_t *policy, const char *command,
                          bool expected) {
  st_eval_result_t result = {0};
  return test_st_policy_eval(policy, command, &result) == ST_OK &&
         result.matches == expected;
}

static int policy_eval_is(st_policy_t *policy, const char *command,
                          const char *expected);

static int test_isolated_subcommand_match_boundaries(void) {
  static const struct {
    const char *pattern;
    const char *commands[5];
    bool expected[5];
    size_t command_count;
  } cases[] = {
      {"probe 42",
       {"probe 42", "probe 7", "probe x42", "probe 42 extra"},
       {true, false, false, false},
       4},
      {"probe #n",
       {"probe 42", "probe -7", "probe x42", "probe 42x", "probe 42 extra"},
       {true, true, false, false, false},
       5},
      {"probe *",
       {"probe value", "probe 42", "probe", "probe two words"},
       {true, true, false, false},
       4},
      {"allocate #size.MiB",
       {"allocate 1MiB", "allocate 2MiB", "allocate 1GiB", "allocate 1MiBx",
        "allocate 1MiB extra"},
       {true, true, false, false, false},
       5},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, cases[i].pattern) == ST_OK);
    for (size_t j = 0; j < cases[i].command_count; j++)
      ASSERT(
          policy_matches(policy, cases[i].commands[j], cases[i].expected[j]));
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }
  return 1;
}

static int read_policy_file(const char *path, char *buffer, size_t capacity,
                            size_t *length) {
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return 0;
  size_t used = fread(buffer, 1, capacity, fp);
  int read_error = ferror(fp);
  int close_result = fclose(fp);
  int valid = !read_error && close_result == 0 && used < capacity;
  if (!valid)
    return 0;
  if (length)
    *length = used;
  return 1;
}

static int no_policy_save_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return 0;
  int result = glob(pattern, 0, NULL, &matches);
  globfree(&matches);
  return result == GLOB_NOMATCH;
}

static void remove_policy_save_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return;
  if (glob(pattern, 0, NULL, &matches) == 0)
    for (size_t i = 0; i < matches.gl_pathc; i++)
      (void)unlink(matches.gl_pathv[i]);
  globfree(&matches);
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

static int test_policy_mutation_lifecycle(void) {
  static const struct {
    const char *pattern;
    st_error_t error;
    size_t count;
  } additions[] = {
      {"git", ST_OK, 1},
      {"git commit", ST_OK, 2},
      {"git commit -m *", ST_OK, 3},
      {"git commit -m *", ST_OK, 3},
      {"ls -l *", ST_OK, 4},
      {"cat * | grep *", ST_OK, 5},
      {"", ST_ERR_INVALID, 5},
      {NULL, ST_ERR_INVALID, 5},
  };
  static const struct {
    const char *pattern;
    st_error_t error;
    size_t count;
  } removals[] = {
      {"docker run *", ST_OK, 5}, {"", ST_ERR_INVALID, 5},
      {NULL, ST_ERR_INVALID, 5},  {"git commit", ST_OK, 4},
      {"git", ST_OK, 3},          {"git commit -m *", ST_OK, 2},
      {"ls -l *", ST_OK, 1},      {"cat * | grep *", ST_OK, 0},
  };

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  ASSERT(st_policy_new(NULL) == NULL);
  ASSERT(st_policy_rule_count(NULL) == 0);
  ASSERT(test_st_policy_add(NULL, "git") == ST_ERR_INVALID);
  ASSERT(test_st_policy_remove(NULL, "git") == ST_ERR_INVALID);

  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(additions) / sizeof(additions[0]); i++) {
    ASSERT(test_st_policy_add(policy, additions[i].pattern) ==
           additions[i].error);
    ASSERT(st_policy_rule_count(policy) == additions[i].count);
  }
  ASSERT(policy_matches(policy, "git", true));
  ASSERT(policy_matches(policy, "git commit", true));
  ASSERT(policy_matches(policy, "git commit -m message", true));
  ASSERT(policy_matches(policy, "ls -l /tmp", true));
  ASSERT(policy_matches(policy, "cat input | grep error", true));

  for (size_t i = 0; i < sizeof(removals) / sizeof(removals[0]); i++) {
    ASSERT(test_st_policy_remove(policy, removals[i].pattern) ==
           removals[i].error);
    ASSERT(st_policy_rule_count(policy) == removals[i].count);
    if (i == 3) {
      ASSERT(policy_matches(policy, "git", true));
      ASSERT(policy_matches(policy, "git commit", false));
      ASSERT(policy_matches(policy, "git commit -m message", true));
    } else if (i == 4) {
      ASSERT(policy_matches(policy, "git", false));
      ASSERT(policy_matches(policy, "git commit -m message", true));
    }
  }
  ASSERT(policy_matches(policy, "ls -l /tmp", false));
  ASSERT(policy_matches(policy, "cat input | grep error", false));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* --- SERIALIZATION --- */

static int test_policy_persistence_transitions(void) {
  static const char *patterns[] = {"git",
                                   "git commit -m *",
                                   "ls -l *",
                                   "cat * | grep *",
                                   "#uuid.v4 inspect",
                                   "\"#CRC16:\" 00000000"};
  static const char *probes[] = {"git",
                                 "git commit -m message",
                                 "ls -l /tmp",
                                 "cat input | grep error",
                                 "550e8400-e29b-41d4-a716-446655440000 inspect",
                                 "#CRC16: 00000000",
                                 "cmd0 arg0 value",
                                 "cmd49 arg49 value"};
  char path[] = "/tmp/shelltype-policy-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);
  ASSERT(close(fd) == 0);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *source = st_policy_new(ctx);
  st_policy_t *loaded = st_policy_new(ctx);
  st_policy_t *empty = st_policy_new(ctx);
  ASSERT(ctx && source && loaded && empty);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(source, patterns[i]) == ST_OK);
  char *framed_pattern = NULL;
  ASSERT(st_netpattern_from_cpl("printf \"\" \"line\\nfeed\"",
                                &framed_pattern) == ST_OK);
  ASSERT(test_st_policy_add(source, framed_pattern) == ST_OK);
  free(framed_pattern);
  for (int i = 0; i < 50; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "cmd%d arg%d *", i, i);
    ASSERT(test_st_policy_add(source, pattern) == ST_OK);
  }
  const size_t source_count = sizeof(patterns) / sizeof(patterns[0]) + 51;
  ASSERT(st_policy_rule_count(source) == source_count);
  ASSERT(st_policy_save(NULL, path) == ST_ERR_INVALID);
  ASSERT(st_policy_save(source, NULL) == ST_ERR_INVALID);
  ASSERT(st_policy_load(NULL, path, false) == ST_ERR_INVALID);
  ASSERT(st_policy_load(loaded, NULL, false) == ST_ERR_INVALID);
  ASSERT(st_policy_save(source, path) == ST_OK);

  st_test_alloc_reset();
  ASSERT(st_policy_clear(loaded) == ST_OK);
  ASSERT(test_st_policy_add(loaded, "preserve value") == ST_OK);
  st_test_alloc_reset();
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  size_t load_allocations = st_test_alloc_count();
  ASSERT(load_allocations > 0);
  st_eval_result_t framed_result = {0};
  ASSERT(test_st_policy_eval(loaded, "printf '' 'line\nfeed'",
                             &framed_result) == ST_OK);
  ASSERT(framed_result.matches);

  bool load_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= load_allocations; fail_at++) {
    ASSERT(st_policy_clear(loaded) == ST_OK);
    ASSERT(test_st_policy_add(loaded, "preserve value") == ST_OK);
    size_t before = st_policy_rule_count(loaded);
    st_test_alloc_fail_at(fail_at);
    st_error_t load_err = st_policy_load(loaded, path, true);
    st_test_alloc_reset();
    if (load_err == ST_ERR_MEMORY) {
      load_failure_observed = true;
      ASSERT(st_policy_rule_count(loaded) == before);
      ASSERT(st_policy_rule_count(loaded) == 1);
      ASSERT(policy_matches(loaded, "preserve value", true));
      ASSERT(!policy_matches(loaded, "git", true));
    } else {
      if (load_err != ST_OK)
        printf("    policy load fail_at=%zu returned %s\n", fail_at,
               st_error_string(load_err));
      ASSERT(load_err == ST_OK);
    }
  }
  ASSERT(load_failure_observed);
  ASSERT(st_policy_clear(loaded) == ST_OK);
  ASSERT(test_st_policy_add(loaded, "docker run *") == ST_OK);

  /* The declared count is part of the file contract, not advisory metadata. */
  FILE *rewrite = fopen(path, "r+");
  ASSERT(rewrite != NULL);
  ASSERT(fprintf(rewrite, "# CPL v1\n# patterns: %zu\n", source_count - 1) > 0);
  ASSERT(fclose(rewrite) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(loaded) == 1);
  ASSERT(policy_matches(loaded, "docker run image", true));
  ASSERT(st_policy_save(source, path) == ST_OK);

  rewrite = fopen(path, "a");
  ASSERT(rewrite != NULL);
  ASSERT(fputs("trailing data\n", rewrite) >= 0);
  ASSERT(fclose(rewrite) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(loaded) == 1);
  ASSERT(policy_matches(loaded, "docker run image", true));
  ASSERT(st_policy_save(source, path) == ST_OK);

  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count + 1);
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_matches(loaded, probes[i], true));
  ASSERT(policy_matches(loaded, "docker run image", true));

  /* Appending the same model is idempotent; replacing drops old entries. */
  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count + 1);
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count);
  ASSERT(policy_matches(loaded, "docker run image", false));

  FILE *bad = fopen(path, "w");
  ASSERT(bad != NULL);
  ASSERT(fprintf(bad, "# CPL v1\n# patterns: 1\nunknown *\n"
                      "# CRC32: deadbeef\n") > 0);
  ASSERT(fclose(bad) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(loaded) == source_count);
  ASSERT(policy_matches(loaded, "docker run image", false));
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_matches(loaded, probes[i], true));

  ASSERT(st_policy_save(empty, path) == ST_OK);
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == 0);
  ASSERT(unlink(path) == 0);
  ASSERT(st_policy_load(source, path, false) == ST_ERR_IO);

  st_policy_free(empty);
  st_policy_free(loaded);
  st_policy_free(source);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_policy_save_determinism_and_compaction(void) {
  char first_path[] = "/tmp/shelltype-policy-save-a-XXXXXX";
  char second_path[] = "/tmp/shelltype-policy-save-b-XXXXXX";
  int first_fd = mkstemp(first_path);
  int second_fd = mkstemp(second_path);
  ASSERT(first_fd >= 0 && second_fd >= 0);
  snprintf(policy_temp_paths[1], sizeof(policy_temp_paths[1]), "%s",
           first_path);
  snprintf(policy_temp_paths[2], sizeof(policy_temp_paths[2]), "%s",
           second_path);
  ASSERT(close(first_fd) == 0 && close(second_fd) == 0);

  static const char *patterns[] = {"echo \"a\\\"b\"", "copy #path", "run #n",
                                   "cat * | grep *"};
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(policy, patterns[i]) == ST_OK);
  ASSERT(st_policy_save(policy, first_path) == ST_OK);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_save(policy, second_path) == ST_OK);

  char first[8192], second[8192];
  size_t first_length = 0, second_length = 0;
  ASSERT(read_policy_file(first_path, first, sizeof(first), &first_length));
  ASSERT(read_policy_file(second_path, second, sizeof(second), &second_length));
  static const char v3_header[] = "# shelltype-policy v3\n";
  ASSERT(first_length >= sizeof(v3_header) - 1 &&
         memcmp(first, v3_header, sizeof(v3_header) - 1) == 0);
  ASSERT(first_length == second_length &&
         memcmp(first, second, first_length) == 0);
  /* The quoted pattern exercises serialization text/escaping; the remaining
   * entries are checked through the evaluator because their command spelling
   * is unambiguous. */
  for (size_t i = 1; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    st_eval_result_t result = {0};
    const char *command = i == 1
                              ? "copy /tmp/file"
                              : (i == 2 ? "run 42" : "cat input | grep error");
    st_error_t error = test_st_policy_eval(policy, command, &result);
    if (error != ST_OK || !result.matches)
      printf("    save case %zu command '%s' error=%d pattern=%s\n", i, command,
             error, result.matching_pattern ? result.matching_pattern : "-");
    ASSERT(error == ST_OK && result.matches);
  }
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(first_path) == 0 && unlink(second_path) == 0);
  policy_temp_paths[1][0] = '\0';
  policy_temp_paths[2][0] = '\0';
  return 1;
}

static int test_policy_load_read_failures_preserve_state(void) {
  char path[] = "/tmp/shelltype-policy-read-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);
  st_policy_ctx_t *source_context = st_policy_ctx_new();
  st_policy_t *source = source_context ? st_policy_new(source_context) : NULL;
  ASSERT(source != NULL);
  ASSERT(test_st_policy_add(source, "replacement #n") == ST_OK);
  ASSERT(test_st_policy_add(source, "replacement #uuid.v4") == ST_OK);
  ASSERT(st_policy_save(source, path) == ST_OK);

  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe = probe_context ? st_policy_new(probe_context) : NULL;
  ASSERT(probe != NULL);
  st_test_io_reset();
  ASSERT(st_policy_load(probe, path, true) == ST_OK);
  size_t read_count = st_test_read_count();
  st_test_io_reset();
  ASSERT(read_count > 0);
  st_policy_free(probe);
  st_policy_ctx_release(probe_context);

  for (size_t clear_first = 0; clear_first < 2; clear_first++) {
    for (size_t fail_at = 1; fail_at <= read_count; fail_at++) {
      st_policy_ctx_t *context = st_policy_ctx_new();
      st_policy_t *policy = context ? st_policy_new(context) : NULL;
      ASSERT(policy != NULL);
      ASSERT(test_st_policy_add(policy, "preserve value") == ST_OK);
      st_test_read_fail_at(fail_at);
      ASSERT(st_policy_load(policy, path, clear_first != 0) == ST_ERR_IO);
      st_test_io_reset();
      ASSERT(st_policy_rule_count(policy) == 1);
      ASSERT(policy_matches(policy, "preserve value", true));
      ASSERT(policy_matches(policy, "replacement 42", false));
      ASSERT(test_st_policy_add(policy, "after failure") == ST_OK);
      st_policy_free(policy);
      st_policy_ctx_release(context);
    }

    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, "preserve value") == ST_OK);
    st_test_io_fail_at(1);
    ASSERT(st_policy_load(policy, path, clear_first != 0) == ST_ERR_IO);
    st_test_io_reset();
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT(policy_matches(policy, "preserve value", true));
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }

  st_policy_free(source);
  st_policy_ctx_release(source_context);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_append_load_subsumption_failures_are_atomic(void) {
  char path[] = "/tmp/shelltype-policy-append-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);
  st_policy_ctx_t *source_context = st_policy_ctx_new();
  st_policy_t *source = source_context ? st_policy_new(source_context) : NULL;
  ASSERT(source != NULL);
  ASSERT(test_st_policy_add(source, "copy #path") == ST_OK);
  ASSERT(test_st_policy_add(source, "incoming #n") == ST_OK);
  ASSERT(st_policy_save(source, path) == ST_OK);

  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe = probe_context ? st_policy_new(probe_context) : NULL;
  ASSERT(probe != NULL);
  ASSERT(test_st_policy_add(probe, "copy /tmp/a") == ST_OK);
  ASSERT(test_st_policy_add(probe, "copy /tmp/b") == ST_OK);
  ASSERT(test_st_policy_add(probe, "keep command") == ST_OK);
  st_test_alloc_reset();
  ASSERT(st_policy_load(probe, path, false) == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_test_alloc_reset();
  ASSERT(allocations > 0);
  ASSERT(st_policy_rule_count(probe) == 3);
  ASSERT(policy_eval_is(probe, "copy /tmp/a", "copy #path"));
  st_policy_free(probe);
  st_policy_ctx_release(probe_context);

  bool observed_failure = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, "copy /tmp/a") == ST_OK);
    ASSERT(test_st_policy_add(policy, "copy /tmp/b") == ST_OK);
    ASSERT(test_st_policy_add(policy, "keep command") == ST_OK);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_policy_load(policy, path, false);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      observed_failure = true;
      ASSERT(st_policy_rule_count(policy) == 3);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_eval_is(policy, "copy /tmp/b", "copy /tmp/b"));
      ASSERT(policy_eval_is(policy, "incoming 7", NULL));
    } else {
      ASSERT(error == ST_OK);
      ASSERT(st_policy_rule_count(policy) == 3);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy #path"));
      ASSERT(policy_eval_is(policy, "incoming 7", "incoming #n"));
    }
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
  ASSERT(observed_failure);
  st_policy_free(source);
  st_policy_ctx_release(source_context);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_policy_save_io_failures_are_atomic(void) {
  char path[] = "/tmp/shelltype-policy-io-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  ASSERT_OK(test_st_policy_add(policy, "git status"));
  ASSERT_OK(test_st_policy_add(policy, "container #uuid.v4"));

  st_test_io_reset();
  ASSERT_OK(st_policy_save(policy, path));
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count >= 4);

  static const char sentinel[] = "preserve-existing-policy";
  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    FILE *fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    ASSERT(fwrite(sentinel, 1, sizeof(sentinel) - 1, fp) ==
           sizeof(sentinel) - 1);
    ASSERT(fclose(fp) == 0);

    st_test_io_fail_at(fail_at);
    st_error_t error = st_policy_save(policy, path);
    st_test_io_reset();
    ASSERT(error == ST_ERR_IO);

    char contents[4096];
    size_t length = 0;
    ASSERT(read_policy_file(path, contents, sizeof(contents), &length));
    bool old_file = length == sizeof(sentinel) - 1 &&
                    memcmp(contents, sentinel, length) == 0;
    if (!old_file) {
      st_policy_ctx_t *check_ctx = st_policy_ctx_new();
      st_policy_t *check = check_ctx ? st_policy_new(check_ctx) : NULL;
      ASSERT(check != NULL && st_policy_load(check, path, true) == ST_OK);
      ASSERT(policy_matches(check, "git status", true));
      st_policy_free(check);
      st_policy_ctx_release(check_ctx);
    }
    ASSERT(no_policy_save_temps(path));
    ASSERT(policy_matches(policy, "git status", true));
  }

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_policy_save_crash_boundaries(void) {
  char path[] = "/tmp/shelltype-policy-crash-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *old_policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_t *new_policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx && old_policy && new_policy);
  ASSERT_OK(test_st_policy_add(old_policy, "old 42"));
  ASSERT_OK(test_st_policy_add(new_policy, "new #n"));

  st_test_io_reset();
  ASSERT_OK(st_policy_save(new_policy, path));
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count > 0);
  st_test_io_reset();
  for (size_t crash_after = 1; crash_after <= operation_count; crash_after++) {
    ASSERT_OK(st_policy_save(old_policy, path));
    pid_t child = fork();
    ASSERT(child >= 0);
    if (child == 0) {
      st_test_io_crash_after(crash_after);
      (void)st_policy_save(new_policy, path);
      _exit(92);
    }
    int status = 0;
    ASSERT(waitpid(child, &status, 0) == child);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 91);
    st_test_io_reset();

    st_policy_ctx_t *loaded_ctx = st_policy_ctx_new();
    st_policy_t *loaded = loaded_ctx ? st_policy_new(loaded_ctx) : NULL;
    ASSERT(loaded && st_policy_load(loaded, path, true) == ST_OK);
    ASSERT(policy_matches(loaded, "old 42", true) ||
           policy_matches(loaded, "new 7", true));
    st_policy_free(loaded);
    st_policy_ctx_release(loaded_ctx);
    remove_policy_save_temps(path);
  }

  st_policy_free(old_policy);
  st_policy_free(new_policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_policy_save_recovery_ignores_stale_temps(void) {
  char path[] = "/tmp/shelltype-policy-recovery-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);

  char stale_path[sizeof(path) + 16];
  ASSERT(snprintf(stale_path, sizeof(stale_path), "%s.stale", path) > 0);
  FILE *stale = fopen(stale_path, "wb");
  ASSERT(stale != NULL);
  ASSERT(fputs("incomplete temporary policy", stale) >= 0);
  ASSERT(fclose(stale) == 0);
  snprintf(policy_temp_paths[1], sizeof(policy_temp_paths[1]), "%s",
           stale_path);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *old_policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_t *new_policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx && old_policy && new_policy);
  ASSERT_OK(test_st_policy_add(old_policy, "old 42"));
  ASSERT_OK(test_st_policy_add(new_policy, "new #n"));
  ASSERT_OK(st_policy_save(old_policy, path));

  st_test_io_reset();
  ASSERT_OK(st_policy_save(new_policy, path));
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count > 0);
  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    ASSERT_OK(st_policy_save(old_policy, path));
    st_test_io_fail_at(fail_at);
    st_error_t error = st_policy_save(new_policy, path);
    st_test_io_reset();
    ASSERT(error == ST_ERR_IO);
    ASSERT(access(stale_path, F_OK) == 0);

    st_policy_ctx_t *loaded_ctx = st_policy_ctx_new();
    st_policy_t *loaded = loaded_ctx ? st_policy_new(loaded_ctx) : NULL;
    ASSERT(loaded != NULL);
    ASSERT(st_policy_load(loaded, path, true) == ST_OK);
    ASSERT(policy_matches(loaded, "old 42", true) ||
           policy_matches(loaded, "new 7", true));
    st_policy_free(loaded);
    st_policy_ctx_release(loaded_ctx);
  }
  ASSERT_OK(st_policy_save(new_policy, path));
  st_policy_ctx_t *loaded_ctx = st_policy_ctx_new();
  st_policy_t *loaded = loaded_ctx ? st_policy_new(loaded_ctx) : NULL;
  ASSERT(loaded != NULL && st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(policy_matches(loaded, "new 7", true));
  ASSERT(access(stale_path, F_OK) == 0);
  st_policy_free(loaded);
  st_policy_ctx_release(loaded_ctx);
  st_policy_free(old_policy);
  st_policy_free(new_policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_policy_load_rejects_binary_and_overlong_lines(void) {
  char path[] = "/tmp/shelltype-policy-load-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  ASSERT_OK(test_st_policy_add(policy, "preserve value"));

  static const unsigned char binary[] =
      "# CPL v1\n# patterns: 1\ngit\0evil\n# CRC32: 00000000\n";
  FILE *fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fwrite(binary, 1, sizeof(binary) - 1, fp) == sizeof(binary) - 1);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_matches(policy, "preserve value", true));

  static const char *const malformed_v3[] = {"01:x,\n", "3:ab,\n"};
  for (size_t i = 0; i < sizeof(malformed_v3) / sizeof(malformed_v3[0]); i++) {
    fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    ASSERT(fputs("# shelltype-policy v3\n# patterns: 1\n", fp) >= 0);
    ASSERT(fputs(malformed_v3[i], fp) >= 0);
    ASSERT(fclose(fp) == 0);
    ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT(policy_matches(policy, "preserve value", true));
  }

  static const unsigned char nul_v3[] =
      "# shelltype-policy v3\n# patterns: 1\n3:a\0b,\n";
  fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fwrite(nul_v3, 1, sizeof(nul_v3) - 1, fp) == sizeof(nul_v3) - 1);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_matches(policy, "preserve value", true));

  fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fputs("# CPL v1\n# patterns: 1\n", fp) >= 0);
  for (size_t i = 0; i < 4096; i++)
    ASSERT(fputc('a', fp) != EOF);
  ASSERT(fputs("\n# CRC32: 00000000\n", fp) >= 0);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_matches(policy, "preserve value", true));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

/* Basic evaluation outcomes share one contract: non-matches and empty input
 * are successful evaluations, while the result pointer is optional. */
static int test_evaluation_contract_matrix(void) {
  static const char *cases[] = {"docker run ubuntu", ""};
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT_OK(test_st_policy_add(policy, "git commit -m *"));

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_eval_result_t result = {.matches = true,
                               .matching_pattern = (const char *)1,
                               .suggestion_count = 2,
                               .suggestion_error = ST_ERR_FAILED};
    st_error_t error = test_st_policy_eval(policy, cases[i], &result);
    ASSERT(error == ST_OK);
    ASSERT(!result.matches && result.matching_pattern == NULL);
  }
  bool matches = true;
  ASSERT(test_st_policy_match(policy, "docker run ubuntu", &matches) == ST_OK);
  ASSERT(!matches);
  ASSERT(test_st_policy_eval(policy, "docker run ubuntu", NULL) ==
         ST_ERR_INVALID);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_invalid_inputs_clear_results(void) {
  st_eval_result_t result = {.matches = true,
                             .matching_pattern = (const char *)1,
                             .suggestion_count = 2,
                             .suggestion_error = ST_ERR_FAILED};
  ASSERT(test_st_policy_eval(NULL, "git status", &result) == ST_ERR_INVALID);
  ASSERT(!result.matches && result.matching_pattern == NULL &&
         result.suggestion_count == 0 && result.suggestion_error == ST_OK);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL);
  result.matches = true;
  result.matching_pattern = (const char *)1;
  result.suggestion_count = 2;
  result.suggestion_error = ST_ERR_FAILED;
  ASSERT(test_st_policy_eval(policy, NULL, &result) == ST_ERR_INVALID);
  ASSERT(!result.matches && result.matching_pattern == NULL &&
         result.suggestion_count == 0 && result.suggestion_error == ST_OK);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* A first-position typed wildcard is valid even though bare `*` is not. The
 * prefilter must skip a literal only when that wildcard accepts its type. */
static int test_filter_wildcard_compatibility_matrix(void) {
  static const struct {
    const char *wildcard_pattern;
    const char *command;
    bool with_literal;
    bool filter_rejects;
    size_t suggestion_count;
    const char *suggestions[2];
    const char *based_on[2];
    double confidence;
  } cases[] = {
      {"#w run",
       "GET status",
       true,
       false,
       1,
       {"#method status", NULL},
       {"#w run", NULL},
       0.5},
      {"#n run",
       "https://example.com status",
       true,
       true,
       2,
       {"https://example.com status", "#u status"},
       {NULL, NULL},
       0.0},
      {"#n run",
       "42 status",
       true,
       false,
       1,
       {"#n status", NULL},
       {"#n run", NULL},
       0.5},
      {"#n run",
       "https://example.com run",
       false,
       false,
       2,
       {"https://example.com run", "#u run"},
       {NULL, NULL},
       0.0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    if (cases[i].with_literal)
      ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
    ASSERT(test_st_policy_add(policy, cases[i].wildcard_pattern) == ST_OK);

    st_policy_stats_t before = {0}, after = {0};
    st_policy_get_stats(policy, &before);
    bool matches = false;
    ASSERT(test_st_policy_match(policy, cases[i].command, &matches) == ST_OK);
    st_policy_get_stats(policy, &after);
    ASSERT(after.eval_count == before.eval_count + 1);
    if (after.filter_reject_count !=
            before.filter_reject_count + cases[i].filter_rejects ||
        after.trie_walk_count !=
            before.trie_walk_count + !cases[i].filter_rejects) {
      printf(
          "  filter case %zu: reject delta=%llu, walk delta=%llu\n", i,
          (unsigned long long)(after.filter_reject_count -
                               before.filter_reject_count),
          (unsigned long long)(after.trie_walk_count - before.trie_walk_count));
      return 0;
    }

    st_eval_result_t result = {0};
    ASSERT(test_st_policy_eval(policy, cases[i].command, &result) == ST_OK);
    ASSERT(!result.matches);
    ASSERT(result.suggestion_count == cases[i].suggestion_count);
    for (size_t j = 0; j < result.suggestion_count; j++)
      ASSERT(suggestion_is(&result.suggestions[j], cases[i].suggestions[j],
                           cases[i].based_on[j], cases[i].confidence));
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }

  return 1;
}

static int assert_prefilter_never_rejects_matches(st_policy_t *policy,
                                                  const char *const *commands,
                                                  size_t count) {
  for (size_t i = 0; i < count; i++) {
    st_policy_stats_t before = {0}, after = {0};
    st_policy_get_stats(policy, &before);
    bool matches = false;
    ASSERT_OK(test_st_policy_match(policy, commands[i], &matches));
    ASSERT(matches);
    st_policy_get_stats(policy, &after);
    ASSERT(after.filter_reject_count == before.filter_reject_count);
    ASSERT(after.trie_walk_count == before.trie_walk_count + 1);
    ASSERT(policy_matches(policy, commands[i], true));
  }
  return 1;
}

static int test_prefilter_match_invariant_across_lifecycle(void) {
  static const char *patterns[] = {"git status", "copy #size.MiB",
                                   "container #uuid.v4", "echo *"};
  static const char *commands[] = {
      "git status", "copy 12MiB",
      "container 550e8400-e29b-41d4-a716-446655440000", "echo anything"};
  char path[] = "/tmp/shelltype-prefilter-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  for (size_t i = 0; i < 4; i++)
    ASSERT_OK(test_st_policy_add(policy, patterns[i]));
  ASSERT(assert_prefilter_never_rejects_matches(policy, commands, 4));
  ASSERT_OK(st_policy_compact(policy));
  ASSERT(assert_prefilter_never_rejects_matches(policy, commands, 4));
  ASSERT_OK(st_policy_save(policy, path));
  ASSERT_OK(st_policy_load(policy, path, true));
  ASSERT(assert_prefilter_never_rejects_matches(policy, commands, 4));
  ASSERT_OK(test_st_policy_remove(policy, patterns[1]));
  ASSERT_OK(test_st_policy_add(policy, patterns[1]));
  ASSERT(assert_prefilter_never_rejects_matches(policy, commands, 4));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_suggestion_contracts(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT_OK(test_st_policy_add(policy, "docker run -d nginx"));
  ASSERT_OK(test_st_policy_add(policy, "docker run -it ubuntu"));
  ASSERT_OK(test_st_policy_add(policy, "docker run --rm alpine"));

  st_eval_result_t result = {0};
  ASSERT(test_st_policy_eval(policy, "docker exec -it container", &result) ==
         ST_OK);
  ASSERT(!result.matches);
  ASSERT(result.suggestion_count == 2);
  ASSERT(suggestion_is(&result.suggestions[0], "docker exec -it container",
                       "docker run --rm alpine", 0.25));
  ASSERT(suggestion_is(&result.suggestions[1], "docker exec #sopt container",
                       NULL, 0.25));

  static const struct {
    st_token_type_t type;
    const char *symbol;
    const char *wider_pattern;
  } variant_cases[] = {
      {ST_TYPE_SHA, "#sha", "docker #h"},
      {ST_TYPE_HEXHASH, "#h", "docker #val"},
      {ST_TYPE_NUMBER, "#n", "docker #val"},
      {ST_TYPE_IPV4, "#i", "docker #ipaddr"},
      {ST_TYPE_IPV6, "#ipv6", "docker #ipaddr"},
      {ST_TYPE_IPADDR, "#ipaddr", "docker #val"},
      {ST_TYPE_QUOTED, "#q", "docker #qs"},
      {ST_TYPE_QUOTED_SPACE, "#qs", "docker #val"},
      {ST_TYPE_FILENAME, "#f", "docker #r"},
      {ST_TYPE_REL_PATH, "#r", "docker #path"},
      {ST_TYPE_ABS_PATH, "#p", "docker #path"},
      {ST_TYPE_PATH, "#path", NULL},
      {ST_TYPE_URL, "#u", NULL},
      {ST_TYPE_VALUE, "#val", NULL},
      {ST_TYPE_SHORTOPT, "#sopt", "docker #opt"},
      {ST_TYPE_LONGOPT, "#lopt", "docker #opt"},
      {ST_TYPE_OPT, "#opt", "docker #val"},
      {ST_TYPE_PORT, "#port", "docker #n"},
      {ST_TYPE_PERM_OCTAL, "#perm", "docker #n"},
      {ST_TYPE_METHOD, "#method", "docker #w"},
      {ST_TYPE_UUID, "#uuid", "docker #val"},
      {ST_TYPE_EMAIL, "#email", "docker #val"},
      {ST_TYPE_HOSTNAME, "#host", "docker #val"},
      {ST_TYPE_SIZE, "#size", "docker #val"},
      {ST_TYPE_SEMVER, "#semver", "docker #val"},
      {ST_TYPE_TIMESTAMP, "#ts", "docker #val"},
      {ST_TYPE_ENV_VAR, "#env", "docker #val"},
      {ST_TYPE_HYPHENATED, "#hyp", "docker #w"},
      {ST_TYPE_BRANCH, "#branch", "docker #val"},
      {ST_TYPE_IMAGE, "#image", "docker #val"},
      {ST_TYPE_PKG, "#pkg", "docker #val"},
      {ST_TYPE_USER, "#user", "docker #val"},
      {ST_TYPE_FINGERPRINT, "#fp", "docker #val"},
      {ST_TYPE_MAC, "#mac", "docker #val"},
      {ST_TYPE_CRON, "#cron", "docker #val"},
      {ST_TYPE_DURATION, "#duration", "docker #val"},
      {ST_TYPE_REGEX, "#regex", "docker #val"},
      {ST_TYPE_GLOB, "#glob", "docker #val"},
      {ST_TYPE_RANGE, "#range", "docker #val"},
      {ST_TYPE_SIGNAL, "#signal", "docker #val"},
      {ST_TYPE_USER_GROUP, "#user_group", "docker #val"},
      {ST_TYPE_WORD, "#w", "docker #val"},
      {ST_TYPE_ANY, "*", NULL},
  };
  st_expand_suggestion_t variants[3] = {0};
  for (size_t i = 0; i < sizeof(variant_cases) / sizeof(variant_cases[0]);
       i++) {
    st_token_t tokens[2] = {{.text = "docker", .type = ST_TYPE_LITERAL},
                            {.text = (char *)variant_cases[i].symbol,
                             .type = variant_cases[i].type}};
    size_t count = st_policy_suggest_variants(policy, tokens, 2, variants);
    ASSERT(count == (variant_cases[i].wider_pattern ? 2 : 1));
    char exact[64];
    snprintf(exact, sizeof(exact), "docker \"%s\"", variant_cases[i].symbol);
    ASSERT(suggestion_is(&variants[0], exact, NULL, 1.0));
    if (variant_cases[i].wider_pattern)
      ASSERT(suggestion_is(&variants[1], variant_cases[i].wider_pattern, NULL,
                           1.0));
    if (variant_cases[i].wider_pattern) {
      st_token_array_t decoded = {0};
      ASSERT(st_netpattern_decode(variants[1].pattern, &decoded) == ST_OK);
      ASSERT(decoded.count == 2);
      st_token_type_t wider = decoded.tokens[1].type;
      ASSERT(wider != ST_TYPE_LITERAL && wider != ST_TYPE_ANY &&
             wider != variant_cases[i].type &&
             st_is_compatible(variant_cases[i].type, wider));
      st_token_array_free(&decoded);
      for (int candidate = ST_TYPE_HEXHASH; candidate < ST_TYPE_COUNT;
           candidate++) {
        st_token_type_t intermediate = (st_token_type_t)candidate;
        ASSERT(intermediate == variant_cases[i].type || intermediate == wider ||
               !st_is_compatible(variant_cases[i].type, intermediate) ||
               !st_is_compatible(intermediate, wider));
      }
    }
  }

  st_token_t tokens[2] = {{.text = "docker", .type = ST_TYPE_LITERAL},
                          {.text = "#n", .type = ST_TYPE_NUMBER}};
  ASSERT(st_policy_suggest_variants(NULL, tokens, 2, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, NULL, 2, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, tokens, 0, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, tokens, 2, NULL) == 0);

  st_token_t too_many[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many) / sizeof(too_many[0]); i++)
    too_many[i] = (st_token_t){.text = "x", .type = ST_TYPE_LITERAL};
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_variants(policy, too_many,
                                    sizeof(too_many) / sizeof(too_many[0]),
                                    variants) == 0);
  for (size_t i = 0; i < 3; i++)
    ASSERT(variants[i].pattern[0] == '\0' && variants[i].based_on == NULL &&
           variants[i].confidence == 0.0);

  char oversized[ST_MAX_NETPATTERN_LEN];
  memset(oversized, 'x', sizeof(oversized) - 1);
  oversized[sizeof(oversized) - 1] = '\0';
  st_token_t overlong[] = {
      {.text = oversized, .type = ST_TYPE_LITERAL},
      {.text = "#n", .type = ST_TYPE_NUMBER},
  };
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_variants(policy, overlong, 2, variants) == 0);
  for (size_t i = 0; i < 3; i++)
    ASSERT(variants[i].pattern[0] == '\0' && variants[i].based_on == NULL &&
           variants[i].confidence == 0.0);

  st_token_t invalid_tokens[] = {
      {.text = NULL, .type = ST_TYPE_LITERAL},
      {.text = "value", .type = ST_TYPE_COUNT},
      {.text = "value", .type = (st_token_type_t)-1},
  };
  for (size_t i = 0; i < sizeof(invalid_tokens) / sizeof(invalid_tokens[0]);
       i++) {
    memset(variants, 0xa5, sizeof(variants));
    ASSERT(st_policy_suggest_variants(policy, invalid_tokens + i, 1,
                                      variants) == 0);
    for (size_t j = 0; j < 3; j++)
      ASSERT(variants[j].pattern[0] == '\0' && variants[j].based_on == NULL &&
             variants[j].confidence == 0.0);
  }

  st_token_array_t quoted_space = {0};
  ASSERT(test_st_classify("echo \"two words\"", &quoted_space) == ST_OK);
  ASSERT(quoted_space.count == 2 &&
         quoted_space.tokens[1].type == ST_TYPE_QUOTED_SPACE);
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_variants(policy, quoted_space.tokens,
                                    quoted_space.count, variants) >= 1);
  st_token_array_t exact = {0};
  ASSERT(st_netpattern_decode(variants[0].pattern, &exact) == ST_OK);
  ASSERT(exact.count == 2 && strcmp(exact.tokens[1].text, "two words") == 0);
  st_token_array_free(&exact);
  st_token_array_free(&quoted_space);

  st_test_alloc_reset();
  ASSERT(st_policy_suggest_variants(policy, tokens, 2, variants) == 2);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    memset(variants, 0xa5, sizeof(variants));
    st_test_alloc_fail_at(fail_at);
    ASSERT(st_policy_suggest_variants(policy, tokens, 2, variants) == 0);
    st_test_alloc_reset();
    for (size_t i = 0; i < 3; i++)
      ASSERT(variants[i].pattern[0] == '\0' && variants[i].based_on == NULL &&
             variants[i].confidence == 0.0);
  }

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int suggestions_equal(const st_eval_result_t *left,
                             const st_eval_result_t *right) {
  if (left->matches != right->matches ||
      left->suggestion_count != right->suggestion_count) {
    printf("    suggestion result shape differs: %d/%zu != %d/%zu\n",
           left->matches, left->suggestion_count, right->matches,
           right->suggestion_count);
    return 0;
  }
  for (size_t i = 0; i < left->suggestion_count; i++) {
    const char *left_based = left->suggestions[i].based_on;
    const char *right_based = right->suggestions[i].based_on;
    if (strcmp(left->suggestions[i].pattern, right->suggestions[i].pattern) !=
            0 ||
        left->suggestions[i].confidence != right->suggestions[i].confidence ||
        ((left_based == NULL) != (right_based == NULL)) ||
        (left_based && strcmp(left_based, right_based) != 0)) {
      printf("    suggestion %zu differs: {%s, %s, %.17g} != "
             "{%s, %s, %.17g}\n",
             i, left->suggestions[i].pattern,
             left_based ? left_based : "(null)",
             left->suggestions[i].confidence, right->suggestions[i].pattern,
             right_based ? right_based : "(null)",
             right->suggestions[i].confidence);
      return 0;
    }
  }
  return 1;
}

static int test_branching_suggestions_are_lifecycle_independent(void) {
  static const char *patterns[] = {"run #size.MiB tail", "run #size.GiB other",
                                   "run #val final"};
  static const size_t orders[][3] = {{0, 1, 2}, {2, 1, 0}, {1, 0, 2}};
  const char *command = "run 2MiB missing";
  char path[] = "/tmp/shelltype-suggestion-order-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);

  st_policy_ctx_t *contexts[3] = {0};
  st_policy_t *policies[3] = {0};
  for (size_t order = 0; order < 3; order++) {
    contexts[order] = st_policy_ctx_new();
    policies[order] = st_policy_new(contexts[order]);
    ASSERT(contexts[order] && policies[order]);
    for (size_t i = 0; i < 3; i++)
      ASSERT(test_st_policy_add(policies[order], patterns[orders[order][i]]) ==
             ST_OK);
    st_eval_result_t actual = {0};
    ASSERT(test_st_policy_eval(policies[order], command, &actual) == ST_OK);
    ASSERT(!actual.matches && actual.suggestion_count > 0);
    if (order > 0) {
      st_eval_result_t reference = {0};
      ASSERT(test_st_policy_eval(policies[0], command, &reference) == ST_OK);
      ASSERT(suggestions_equal(&reference, &actual));
      ASSERT(st_policy_compact(policies[order]) == ST_OK);
      st_eval_result_t compacted = {0};
      ASSERT(test_st_policy_eval(policies[order], command, &compacted) ==
             ST_OK);
      ASSERT(test_st_policy_eval(policies[0], command, &reference) == ST_OK);
      ASSERT(suggestions_equal(&reference, &compacted));
    }
  }

  ASSERT(st_policy_save(policies[0], path) == ST_OK);
  st_policy_ctx_t *loaded_context = st_policy_ctx_new();
  st_policy_t *loaded = st_policy_new(loaded_context);
  ASSERT(loaded_context && loaded &&
         st_policy_load(loaded, path, true) == ST_OK);
  st_eval_result_t reference = {0};
  st_eval_result_t loaded_result = {0};
  ASSERT(test_st_policy_eval(policies[0], command, &reference) == ST_OK);
  ASSERT(test_st_policy_eval(loaded, command, &loaded_result) == ST_OK);
  ASSERT(suggestions_equal(&reference, &loaded_result));

  st_policy_free(loaded);
  st_policy_ctx_release(loaded_context);
  for (size_t i = 0; i < 3; i++) {
    st_policy_free(policies[i]);
    st_policy_ctx_release(contexts[i]);
  }
  ASSERT(unlink(path) == 0);
  policy_temp_paths[0][0] = '\0';
  return 1;
}

static int test_suggestion_render_allocation_failures(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  ASSERT(test_st_policy_add(policy, "docker run -d nginx") == ST_OK);
  ASSERT(test_st_policy_add(policy, "docker run -it ubuntu") == ST_OK);

  st_test_alloc_reset();
  st_eval_result_t probe = {0};
  ASSERT(test_st_policy_eval(policy, "docker exec -it container", &probe) ==
         ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);

  bool observed_render_failure = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_eval_result_t result = {.matches = true,
                               .matching_pattern = (const char *)1,
                               .suggestion_count = 2,
                               .suggestion_error = ST_ERR_FAILED};
    st_test_alloc_fail_at(fail_at);
    st_error_t error =
        test_st_policy_eval(policy, "docker exec -it container", &result);
    st_test_alloc_reset();
    ASSERT(error == ST_OK);
    ASSERT(!result.matches && result.matching_pattern == NULL);
    ASSERT(result.suggestion_count <= 2);
    if (result.suggestion_error == ST_ERR_MEMORY) {
      observed_render_failure = true;
      ASSERT(result.suggestion_count == 0);
    }
  }
  ASSERT(observed_render_failure);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_context_and_compaction_transitions(void) {
  st_policy_ctx_t *released = st_policy_ctx_new();
  ASSERT(released != NULL);
  st_policy_ctx_release(released);

  st_policy_ctx_t *shared = st_policy_ctx_new();
  ASSERT(shared != NULL);
  st_policy_t *shared_policy = st_policy_new(shared);
  ASSERT(shared_policy != NULL);
  st_policy_ctx_release(shared);
  ASSERT(test_st_policy_add(shared_policy, "survives caller release") == ST_OK);
  st_policy_free(shared_policy);

  st_policy_ctx_t *ctx = st_policy_ctx_new_with_arena(1);
  ASSERT(ctx != NULL);
  st_policy_ctx_t *defaulted = st_policy_ctx_new_with_arena(0);
  ASSERT(defaulted != NULL);
  ASSERT(st_policy_ctx_intern(defaulted, "zero-arena") != NULL);
  st_policy_ctx_release(defaulted);
  ASSERT(st_policy_ctx_reset(NULL) == ST_ERR_INVALID);
  ASSERT(st_policy_ctx_reset(NULL) == ST_ERR_INVALID);
  ASSERT(!st_policy_ctx_is_exclusive(NULL));
  ASSERT(st_policy_ctx_intern(NULL, "value") == NULL);
  ASSERT(st_policy_ctx_intern(ctx, NULL) == NULL);
  ASSERT(strcmp(st_policy_ctx_intern(ctx, ""), "") == 0);
  const char *first = st_policy_ctx_intern(ctx, "shared");
  ASSERT(first != NULL && st_policy_ctx_intern(ctx, "shared") == first);

  char before_growth[701];
  char forces_growth[2001];
  memset(before_growth, 'a', sizeof(before_growth) - 1);
  before_growth[sizeof(before_growth) - 1] = '\0';
  memset(forces_growth, 'b', sizeof(forces_growth) - 1);
  forces_growth[sizeof(forces_growth) - 1] = '\0';
  const char *stable = st_policy_ctx_intern(ctx, before_growth);
  ASSERT(stable != NULL);
  ASSERT(st_policy_ctx_intern(ctx, forces_growth) != NULL);
  ASSERT(strcmp(stable, before_growth) == 0);
  ASSERT(st_policy_ctx_intern(ctx, before_growth) == stable);

  st_policy_t *p1 = st_policy_new(ctx);
  ASSERT(p1 != NULL);
  ASSERT(st_policy_ctx_is_exclusive(ctx));
  ASSERT(test_st_policy_add(p1, "git status") == ST_OK);
  ASSERT(test_st_policy_add(p1, "git commit -m *") == ST_OK);
  ASSERT(test_st_policy_add(p1, "ls -la") == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_ERR_INVALID);
  ASSERT(st_policy_ctx_reset(ctx) == ST_ERR_INVALID);

  st_policy_t *p2 = st_policy_new(ctx);
  ASSERT(p2 != NULL);
  ASSERT(!st_policy_ctx_is_exclusive(ctx));
  ASSERT(test_st_policy_add(p2, "docker ps") == ST_OK);
  ASSERT(st_policy_compact(p1) == ST_ERR_INVALID);
  ASSERT(policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_matches(p2, "docker ps", true));

  st_policy_free(p2);
  ASSERT(st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_compact(p1) == ST_OK);
  ASSERT(st_policy_rule_count(p1) == 3);
  ASSERT(policy_matches(p1, "git status", true));
  ASSERT(policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_matches(p1, "ls -la", true));

  st_policy_free(p1);
  ASSERT(!st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  const char *second = st_policy_ctx_intern(ctx, "reused");
  ASSERT(second != NULL && strcmp(second, "reused") == 0);
  p1 = st_policy_new(ctx);
  ASSERT(p1 != NULL);
  ASSERT(test_st_policy_add(p1, "new policy") == ST_OK);
  ASSERT(policy_matches(p1, "new policy", true));
  st_policy_free(p1);
  st_policy_ctx_release(ctx);
  ASSERT(st_policy_ctx_new_with_arena(SIZE_MAX) == NULL);
  return 1;
}

static int test_context_allocation_failures_preserve_storage(void) {
  st_test_alloc_reset();
  st_policy_ctx_t *probe = st_policy_ctx_new();
  ASSERT(probe != NULL);
  for (size_t i = 0; i < 768; i++) {
    char value[32];
    snprintf(value, sizeof(value), "probe-%zu", i);
    ASSERT(st_policy_ctx_intern(probe, value) != NULL);
  }
  st_test_alloc_reset();
  char growth_value[2048];
  memset(growth_value, 'g', sizeof(growth_value) - 1);
  growth_value[sizeof(growth_value) - 1] = '\0';
  ASSERT(st_policy_ctx_intern(probe, growth_value) != NULL);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_policy_ctx_release(probe);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    ASSERT(ctx != NULL);
    const char *stable = st_policy_ctx_intern(ctx, "stable-value");
    ASSERT(stable != NULL);
    for (size_t i = 1; i < 768; i++) {
      char value[32];
      snprintf(value, sizeof(value), "intern-%zu", i);
      ASSERT(st_policy_ctx_intern(ctx, value) != NULL);
    }
    st_test_alloc_fail_at(fail_at);
    const char *grown = st_policy_ctx_intern(ctx, "triggers-pool-growth");
    st_test_alloc_reset();
    ASSERT(grown == NULL);
    ASSERT(strcmp(stable, "stable-value") == 0);
    ASSERT(st_policy_ctx_intern(ctx, "stable-value") == stable);
    ASSERT(st_policy_ctx_intern(ctx, "after-failure") != NULL);
    st_policy_ctx_release(ctx);
  }

  st_test_alloc_reset();
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  const char *stable = st_policy_ctx_intern(ctx, "reset-stable");
  ASSERT(stable != NULL);
  st_test_alloc_fail_at(1);
  ASSERT(st_policy_ctx_reset(ctx) == ST_ERR_MEMORY);
  st_test_alloc_reset();
  ASSERT(strcmp(stable, "reset-stable") == 0);
  ASSERT(st_policy_ctx_intern(ctx, "reset-stable") == stable);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_context_and_policy_construction_failures(void) {
  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new_with_arena(64);
  ASSERT(probe_context != NULL);
  size_t context_allocations = st_test_alloc_count();
  ASSERT(context_allocations > 0);
  st_policy_ctx_release(probe_context);

  bool context_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= context_allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_policy_ctx_t *context = st_policy_ctx_new_with_arena(64);
    st_test_alloc_reset();
    if (!context) {
      context_failure_observed = true;
      continue;
    }
    ASSERT(st_policy_ctx_intern(context, "usable") != NULL);
    st_policy_ctx_release(context);
  }
  ASSERT(context_failure_observed);

  st_test_alloc_reset();
  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  st_test_alloc_reset();
  st_policy_t *probe_policy = st_policy_new(context);
  ASSERT(probe_policy != NULL);
  size_t policy_allocations = st_test_alloc_count();
  ASSERT(policy_allocations > 0);
  st_policy_free(probe_policy);

  bool policy_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= policy_allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_policy_t *policy = st_policy_new(context);
    st_test_alloc_reset();
    if (!policy) {
      policy_failure_observed = true;
      ASSERT(st_policy_ctx_intern(context, "after construction failure") !=
             NULL);
      continue;
    }
    ASSERT(test_st_policy_add(policy, "constructed safely") == ST_OK);
    st_policy_free(policy);
  }
  ASSERT(policy_failure_observed);
  st_policy_ctx_release(context);
  return 1;
}

static int test_policy_contract_matrix(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  ASSERT(test_st_policy_remove(policy, "missing") == ST_OK);
  ASSERT(st_policy_memory_usage(NULL) == 0);
  ASSERT(st_policy_working_set(NULL) == 0);
  ASSERT(st_policy_state_count(NULL) == 0);
  st_policy_stats_t empty_stats = {.eval_count = 7, .pattern_count = 11};
  st_policy_get_stats(NULL, &empty_stats);
  ASSERT(empty_stats.eval_count == 0 && empty_stats.filter_reject_count == 0 &&
         empty_stats.trie_walk_count == 0 &&
         empty_stats.suggestion_count == 0 &&
         empty_stats.filter_rebuild_count == 0 &&
         empty_stats.filter_rebuild_us == 0 && empty_stats.pattern_count == 0 &&
         empty_stats.state_count == 0 && empty_stats.memory_bytes == 0);
  st_policy_get_stats(policy, NULL);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(st_policy_merge(policy, policy) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_pattern_validation_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t error;
    const char *probe;
  } cases[] = {{"", ST_ERR_INVALID, NULL},
               {NULL, ST_ERR_INVALID, NULL},
               {"* status", ST_ERR_INVALID, NULL},
               {"  * status", ST_ERR_INVALID, NULL},
               {"* *", ST_ERR_INVALID, NULL},
               {"git\tstatus", ST_ERR_INVALID, NULL},
               {"git\nstatus", ST_ERR_INVALID, NULL},
               {"git\rstatus", ST_ERR_INVALID, NULL},
               {"git \x01status", ST_ERR_INVALID, NULL},
               {"git \x7fstatus", ST_ERR_INVALID, NULL},
               {"git status", ST_OK, "git status"},
               {"git *", ST_OK, "git anything"},
               {"docker run -it * *", ST_OK, "docker run -it image shell"},
               {"git * status", ST_OK, "git branch status"},
               {"docker run #path #path", ST_OK, "docker run /etc /var"},
               {"#w run", ST_OK, "GET run"}};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(test_st_validate_pattern(cases[i].pattern, NULL) == cases[i].error);
    ASSERT(test_st_policy_add(policy, cases[i].pattern) == cases[i].error);
    ASSERT(st_policy_rule_count(policy) == (cases[i].error == ST_OK));
    if (cases[i].probe && !policy_matches(policy, cases[i].probe, true)) {
      printf("  validation case %zu did not match probe '%s'\n", i,
             cases[i].probe);
      return 0;
    }
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }

  /* The metadata-producing path must preserve exact token text and base type,
   * while validation failures clear the entire output structure. */
  st_pattern_info_t info;
  ASSERT(test_st_validate_pattern("cat #size.MiB", &info) == ST_OK);
  ASSERT(info.token_count == 2);
  ASSERT_STR_EQ(info.token_texts[0], "cat");
  ASSERT(info.token_types[0] == ST_TYPE_LITERAL);
  ASSERT_STR_EQ(info.token_texts[1], "#size.MiB");
  ASSERT(info.token_types[1] == ST_TYPE_SIZE);
  memset(&info, 0xa5, sizeof(info));
  ASSERT(test_st_validate_pattern("dd #size.XX", &info) == ST_ERR_INVALID);
  ASSERT(info.token_count == 0);
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS; i++)
    ASSERT(info.token_texts[i][0] == '\0' && info.token_types[i] == 0);

  char too_long[ST_MAX_NETPATTERN_LEN + 1];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  memset(&info, 0xa5, sizeof(info));
  ASSERT(test_st_validate_pattern(too_long, &info) == ST_ERR_INVALID);
  ASSERT(info.token_count == 0 && info.token_texts[0][0] == '\0');
  st_policy_ctx_t *limit_ctx = st_policy_ctx_new();
  st_policy_t *limit_policy = st_policy_new(limit_ctx);
  ASSERT(limit_ctx != NULL && limit_policy != NULL);
  ASSERT(test_st_policy_add(limit_policy, too_long) == ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(limit_policy) == 0);

  char too_long_token[ST_MAX_TOKEN_LEN + 3];
  too_long_token[0] = 'x';
  too_long_token[1] = ' ';
  memset(too_long_token + 2, 'y', ST_MAX_TOKEN_LEN);
  too_long_token[ST_MAX_TOKEN_LEN + 2] = '\0';
  ASSERT(test_st_validate_pattern(too_long_token, NULL) == ST_ERR_INVALID);
  ASSERT(test_st_policy_add(limit_policy, too_long_token) == ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(limit_policy) == 0);

  char too_many[(ST_MAX_CMD_TOKENS + 1) * 2 + 1];
  size_t used = 0;
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS + 1; i++) {
    too_many[used++] = 'x';
    too_many[used++] = ' ';
  }
  too_many[used - 1] = '\0';
  ASSERT(test_st_validate_pattern(too_many, NULL) == ST_ERR_INVALID);
  ASSERT(test_st_policy_add(limit_policy, too_many) == ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(limit_policy) == 0);

  ASSERT(test_st_policy_add(limit_policy, "preserved pattern") == ST_OK);
  const char *hostile_batch[] = {"new pattern", "bad\npattern"};
  ASSERT(test_st_policy_batch_add(limit_policy, hostile_batch, 2) ==
         ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(limit_policy) == 1);
  ASSERT(policy_matches(limit_policy, "preserved pattern", true));
  ASSERT(policy_matches(limit_policy, "new pattern", false));
  st_policy_free(limit_policy);
  st_policy_ctx_release(limit_ctx);

  return 1;
}

/* DOT export format and escaping contract. */
static int test_dot_export(void) {
  char path[] = "/tmp/shelltype-policy-dot-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(policy_temp_paths[1], sizeof(policy_temp_paths[1]), "%s", path);
  ASSERT(close(fd) == 0);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(test_st_policy_add(policy, "git commit -m *") == ST_OK);
  ASSERT(test_st_policy_add(policy, "echo \"a\\\"b\"") == ST_OK);
  st_token_t binary_tokens[] = {
      {.text = "echo", .type = ST_TYPE_LITERAL},
      {.text = "",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = "a",
       .prefix_length = 1,
       .capture = "#n",
       .capture_length = 2,
       .suffix = "\0z",
       .suffix_length = 2,
       .capture_type = ST_TYPE_NUMBER},
  };
  st_netpattern_t binary_pattern = {0};
  ASSERT(st_netpattern_encode_owned(binary_tokens, 2, &binary_pattern) ==
         ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = binary_pattern.data,
                                            .length = binary_pattern.length}) ==
         ST_OK);
  ASSERT(st_policy_dump_dot(NULL, path) == ST_ERR_INVALID);
  ASSERT(st_policy_dump_dot(policy, NULL) == ST_ERR_INVALID);
  ASSERT(st_policy_dump_dot(policy, path) == ST_OK);

  FILE *fp = fopen(path, "r");
  ASSERT(fp != NULL);
  char output[8192];
  size_t length = fread(output, 1, sizeof(output) - 1, fp);
  ASSERT(!ferror(fp) && length > 0);
  output[length] = '\0';
  ASSERT(fclose(fp) == 0);
  ASSERT(strncmp(output, "digraph policy_trie", 18) == 0);
  ASSERT(strstr(output, "git") != NULL);
  ASSERT(strstr(output, "status") != NULL);
  ASSERT(strstr(output, "commit") != NULL);
  ASSERT(strstr(output, "a\\\"b") != NULL);
  ASSERT(strstr(output, "a{#n}\\x00z") != NULL);
  ASSERT(unlink(path) == 0);

  st_netpattern_free(&binary_pattern);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Dry-run simulation reports redundancy without mutating the policy. */
static int test_dry_run_simulate(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(test_st_policy_add(policy, "git #w"));
  ASSERT_OK(test_st_policy_add(policy, "cat #size.MiB"));

  static const struct {
    const char *proposal;
    bool redundant;
    const char *conflict;
  } cases[] = {
      {"git status", false, NULL}, {"git #w", true, "git #w"},
      {"git *", false, NULL},      {"cat #size.MiB", true, "cat #size.MiB"},
      {"cat #size", false, NULL},  {"docker ps", false, NULL}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    bool redundant = !cases[i].redundant;
    const char *conflict = (const char *)1;
    char *proposal = NULL;
    ASSERT(st_netpattern_from_cpl(cases[i].proposal, &proposal) == ST_OK);
    ASSERT(st_policy_simulate_add_netpattern(policy, proposal, &redundant,
                                             &conflict) == ST_OK);
    free(proposal);
    ASSERT(redundant == cases[i].redundant);
    ASSERT((!conflict && !cases[i].conflict) ||
           (conflict && cases[i].conflict &&
            pattern_is_cpl(conflict, cases[i].conflict)));
  }

  bool redundant_without_conflict = false;
  char *proposal = NULL;
  ASSERT(st_netpattern_from_cpl("git status", &proposal) == ST_OK);
  ASSERT(st_policy_simulate_add_netpattern(
             policy, proposal, &redundant_without_conflict, NULL) == ST_OK);
  ASSERT(!redundant_without_conflict);

  bool redundant = true;
  const char *conflict = (const char *)1;
  ASSERT(st_policy_simulate_add_netpattern(policy, "", &redundant, &conflict) ==
         ST_ERR_FORMAT);
  ASSERT(!redundant && conflict == NULL);
  ASSERT(st_policy_simulate_add_netpattern(policy, proposal, NULL, &conflict) ==
         ST_ERR_INVALID);
  ASSERT(conflict == NULL);
  free(proposal);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* --- CONCURRENCY AND ATOMIC TESTS --- */

static int test_statistics_transitions(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(test_st_policy_add(policy, "ls -la") == ST_OK);
  ASSERT(test_st_policy_add(policy, "docker ps") == ST_OK);

  st_policy_stats_t stats = {0};
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 0);
  ASSERT(stats.pattern_count == 3);
  ASSERT(stats.state_count > 0);
  ASSERT(stats.memory_bytes >= stats.state_count);

  static const char *commands[] = {"git status", "ls -la", "docker ps"};
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    st_eval_result_t result = {0};
    ASSERT(test_st_policy_eval(policy, commands[i], &result) == ST_OK);
    ASSERT(result.matches);
  }

  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 3);
  ASSERT(stats.trie_walk_count == 3);
  ASSERT(stats.filter_reject_count == 0);
  ASSERT(stats.suggestion_count == 0);

  st_eval_result_t result = {0};
  ASSERT(test_st_policy_eval(policy, "unknown cmd", &result) == ST_OK);
  ASSERT(!result.matches);
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 4);
  ASSERT(stats.trie_walk_count == 4);
  ASSERT(stats.suggestion_count == result.suggestion_count);
  ASSERT(stats.suggestion_count > 0);

  bool matches = true;
  ASSERT(test_st_policy_match(policy, "unknown cmd", &matches) == ST_OK);
  ASSERT(!matches);
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 5);
  ASSERT(stats.trie_walk_count == 4);
  ASSERT(stats.filter_reject_count == 1);
  ASSERT(stats.suggestion_count == result.suggestion_count);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* The first evaluation after a mutation rebuilds the lazy prefilter once. */
static int test_filter_rebuild_lazy_trigger(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  /* Add patterns - triggers filter build */
  ASSERT_OK(test_st_policy_add(policy, "git status"));
  ASSERT_OK(test_st_policy_add(policy, "git commit -m *"));

  st_policy_stats_t stats1;
  st_policy_get_stats(policy, &stats1);

  /* Add more patterns - epoch changes, next eval triggers rebuild */
  ASSERT_OK(test_st_policy_add(policy, "ls -la"));
  ASSERT_OK(test_st_policy_add(policy, "docker run *"));

  /* First eval should trigger rebuild */
  st_eval_result_t result;
  ASSERT_OK(test_st_policy_eval(policy, "docker ps", &result));

  st_policy_stats_t stats2;
  st_policy_get_stats(policy, &stats2);

  /* The first evaluation after a mutation must actually rebuild. */
  ASSERT(stats2.filter_rebuild_count > stats1.filter_rebuild_count);

  /* Second eval should not trigger rebuild */
  ASSERT_OK(test_st_policy_eval(policy, "docker ps", &result));

  st_policy_stats_t stats3;
  st_policy_get_stats(policy, &stats3);

  ASSERT(stats3.filter_rebuild_count == stats2.filter_rebuild_count);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Clearing removes all patterns without preventing policy reuse. */
static int test_policy_clear(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(test_st_policy_add(policy, "git status"));
  ASSERT_OK(test_st_policy_add(policy, "git commit -m *"));
  ASSERT_OK(test_st_policy_add(policy, "ls -la"));
  ASSERT(st_policy_rule_count(policy) == 3);

  /* Clear must not need fresh storage to restore the empty root. */
  st_test_alloc_fail_at(1);
  st_error_t err = st_policy_clear(policy);
  st_test_alloc_reset();
  ASSERT(err == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 0);

  /* Policy should still work after clear */
  st_eval_result_t result;
  err = test_st_policy_eval(policy, "git status", &result);
  ASSERT(err == ST_OK);
  ASSERT(!result.matches); /* No patterns, no match */

  /* Should be able to add new patterns */
  err = test_st_policy_add(policy, "docker ps");
  ASSERT(err == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);

  err = test_st_policy_eval(policy, "docker ps", &result);
  ASSERT(err == ST_OK);
  ASSERT(result.matches);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_eval_is(st_policy_t *policy, const char *command,
                          const char *expected) {
  st_eval_result_t result;
  if (test_st_policy_eval(policy, command, &result) != ST_OK ||
      result.matches != (expected != NULL))
    return 0;
  return expected ? result.matching_pattern &&
                        pattern_is_cpl(result.matching_pattern, expected)
                  : result.matching_pattern == NULL;
}

static int test_literal_and_wildcard_semantics(void) {
  static const char *patterns[] = {
      "exact-number 42",
      "any-number #n",
      "exact-option --help",
      "any-option #opt",
      "exact-url https://example.test/a",
      "any-url #u",
      "git #opt",
      "docker run #val",
  };
  static const struct {
    const char *command;
    const char *expected;
  } cases[] = {
      {"exact-number 42", "exact-number 42"},
      {"exact-number 43", NULL},
      {"any-number 43", "any-number #n"},
      {"exact-option --help", "exact-option --help"},
      {"exact-option --verbose", NULL},
      {"any-option --verbose", "any-option #opt"},
      {"exact-url https://example.test/a", "exact-url https://example.test/a"},
      {"exact-url https://example.test/b", NULL},
      {"any-url https://example.test/b", "any-url #u"},
      {"git -v", "git #opt"},
      {"git -la", "git #opt"},
      {"git --help", "git #opt"},
      {"git status", NULL},
      {"docker run -d", "docker run #val"},
      {"docker run --rm", "docker run #val"}};
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(ctx && policy);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(policy, patterns[i]) == ST_OK);
  ASSERT(st_policy_rule_count(policy) ==
         sizeof(patterns) / sizeof(patterns[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(policy_eval_is(policy, cases[i].command, cases[i].expected));

  static const char *const quoted[] = {"echo \"#n\"", "printf \"\"",
                                       "say \"two words\""};
  for (size_t i = 0; i < sizeof(quoted) / sizeof(quoted[0]); i++) {
    char *netpattern = NULL;
    ASSERT(st_netpattern_from_cpl(quoted[i], &netpattern) == ST_OK);
    ASSERT(test_st_policy_add(policy, netpattern) == ST_OK);
    free(netpattern);
  }
  st_eval_result_t quoted_result = {0};
  ASSERT(test_st_policy_eval(policy, "echo #n", &quoted_result) == ST_OK &&
         quoted_result.matches);
  ASSERT(test_st_policy_eval(policy, "echo 42", &quoted_result) == ST_OK &&
         !quoted_result.matches);
  ASSERT(test_st_policy_eval(policy, "printf ''", &quoted_result) == ST_OK &&
         quoted_result.matches);
  ASSERT(test_st_policy_eval(policy, "say 'two words'", &quoted_result) ==
             ST_OK &&
         quoted_result.matches);
  ASSERT(st_policy_compact(policy) == ST_OK);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(policy_eval_is(policy, cases[i].command, cases[i].expected));
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Subsumption for parametrized types. */
static int test_param_subsumption_matrix(void) {
  static const struct {
    const char *specific;
    const char *generic;
    const char *probe;
  } cases[] = {
      {"allocate #size.MiB", "allocate #size", "allocate 12KiB"},
      {"container #uuid.v4", "container #uuid",
       "container 550e8400-e29b-41d4-a716-446655440000"},
  };

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT_OK(test_st_policy_add(policy, cases[i].specific));
    ASSERT_OK(test_st_policy_add(policy, cases[i].generic));
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT_OK(st_policy_compact(policy));
    ASSERT(st_policy_rule_count(policy) == 1);

    st_eval_result_t result = {0};
    ASSERT_OK(test_st_policy_eval(policy, cases[i].probe, &result));
    ASSERT(result.matches && result.matching_pattern != NULL);
    ASSERT(pattern_is_cpl(result.matching_pattern, cases[i].generic));
    ASSERT_OK(test_st_policy_remove(policy, cases[i].specific));
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT(policy_eval_is(policy, cases[i].probe, cases[i].generic));
    st_policy_free(policy);
  }
  st_pattern_info_t alias_info = {0};
  ASSERT(test_st_validate_pattern("container #uuid.5", &alias_info) == ST_OK);
  ASSERT_STR_EQ(alias_info.token_texts[1], "#uuid.v5");
  st_policy_t *alias_policy = st_policy_new(ctx);
  ASSERT(alias_policy != NULL);
  ASSERT_OK(test_st_policy_add(alias_policy, "container #uuid.5"));
  ASSERT(policy_eval_is(alias_policy,
                        "container 4be33a94-0c5b-5516-a922-d07dedd59172",
                        "container #uuid.v5"));
  st_policy_free(alias_policy);

  st_policy_t *sizes = st_policy_new(ctx);
  ASSERT(sizes != NULL);
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size.MiB}"));
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size.G}"));
  ASSERT_OK(st_policy_compact(sizes));
  ASSERT(st_policy_rule_count(sizes) == 2);
  ASSERT(policy_eval_is(sizes, "dd bs=10MiB", "dd bs={#size.MiB}"));
  ASSERT(policy_eval_is(sizes, "dd bs=2G", "dd bs={#size.G}"));
  ASSERT(policy_eval_is(sizes, "dd bs=10K", NULL));
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size}"));
  ASSERT(st_policy_rule_count(sizes) == 1);
  ASSERT(policy_eval_is(sizes, "dd bs=10K", "dd bs={#size}"));
  st_policy_free(sizes);

  st_policy_t *compound = st_policy_new(ctx);
  ASSERT(compound != NULL);
  ASSERT_OK(test_st_policy_add(compound, "tool --output={#path}"));
  ASSERT(policy_eval_is(compound, "tool --output=/tmp/result",
                        "tool --output={#path}"));
  ASSERT(policy_eval_is(compound, "tool '--output=/tmp/a b'",
                        "tool --output={#path}"));
  ASSERT(policy_eval_is(compound, "tool --output= /tmp/result", NULL));
  ASSERT(policy_eval_is(compound, "tool --output /tmp/result", NULL));
  ASSERT(policy_eval_is(compound, "tool '--output=#path'", NULL));
  st_policy_free(compound);

  st_policy_t *coexisting = st_policy_new(ctx);
  ASSERT(coexisting != NULL);
  ASSERT_OK(test_st_policy_add(coexisting, "container #uuid.v4"));
  ASSERT_OK(test_st_policy_add(coexisting, "container #uuid.v5"));
  ASSERT(st_policy_rule_count(coexisting) == 2);
  ASSERT(policy_eval_is(coexisting,
                        "container 550e8400-e29b-41d4-a716-446655440000",
                        "container #uuid.v4"));
  ASSERT(policy_eval_is(coexisting,
                        "container 4be33a94-0c5b-5516-a922-d07dedd59172",
                        "container #uuid.v5"));
  ASSERT(policy_eval_is(
      coexisting, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", NULL));
  st_policy_free(coexisting);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Matching behavior for all parametrized policy types. */

static int test_param_match_matrix(void) {
  static const struct {
    const char *pattern;
    const char *accepted[3];
    const char *rejected[2];
  } cases[] = {
      {"container #uuid.v4",
       {"container 550e8400-e29b-41d4-a716-446655440000", NULL},
       {"container 6fa459ea-ee8a-3ca4-894e-db77e160355e"}},
      {"container #uuid",
       {"container 550e8400-e29b-41d4-a716-446655440000",
        "container 6fa459ea-ee8a-3ca4-894e-db77e160355e"},
       {NULL}},
      {"install #semver.major", {"install 1.2.3", NULL}, {NULL}},
      {"log #ts.date", {"log 2025-04-24", NULL}, {"log 15:30:00"}},
      {"log #ts.time", {"log 15:30:00", NULL}, {"log 2025-04-24"}},
      {"log #ts.datetime",
       {"log 2025-04-24T15:30:00Z", NULL},
       {"log 2025-04-24"}},
      {"echo #hash", {"echo sha256", "echo md5"}, {NULL}},
      {"docker pull #image",
       {"docker pull ghcr.io/org/app:v1", "docker pull nginx:latest"},
       {NULL}},
      {"npm install #pkg",
       {"npm install @babel/core", NULL},
       {"npm install express"}},
      {"git checkout #branch",
       {"git checkout feature/login", "git checkout main"},
       {NULL}},
      {"echo #sha.40",
       {"echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", NULL},
       {"echo abcdef1"}},
      {"echo #sha.short", {"echo deadbee", NULL}, {"echo deadbeef"}},
      {"echo #sha.64",
       {"echo 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        NULL},
       {"echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}},
      {"ssh-keygen #fp.sha256",
       {"ssh-keygen SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE", NULL},
       {"ssh-keygen 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d"}},
      {"ssh-keygen #fp.md5",
       {"ssh-keygen 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d", NULL},
       {"ssh-keygen SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE"}},
      {"sleep #duration.s", {"sleep 30s", "sleep -1.5s", NULL}, {"sleep 2h"}},
      {"sleep #duration.ms", {"sleep 100ms", NULL}, {"sleep 100us"}},
      {"seq #range.step", {"seq 1-5", "seq 0-100"}, {NULL}},
      {"chmod #perm.bits", {"chmod 755", "chmod 0644"}, {NULL}},
  };
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, cases[i].pattern) == ST_OK);
    ASSERT(st_policy_rule_count(policy) == 1);
    for (size_t j = 0; j < 3 && cases[i].accepted[j]; j++) {
      st_eval_result_t result;
      ASSERT(test_st_policy_eval(policy, cases[i].accepted[j], &result) ==
             ST_OK);
      if (!result.matches) {
        printf("  Pattern '%s' rejected '%s'\n", cases[i].pattern,
               cases[i].accepted[j]);
        return 0;
      }
      ASSERT(pattern_is_cpl(result.matching_pattern, cases[i].pattern));
    }
    for (size_t j = 0; j < 2 && cases[i].rejected[j]; j++) {
      st_eval_result_t result;
      ASSERT(test_st_policy_eval(policy, cases[i].rejected[j], &result) ==
             ST_OK);
      if (result.matches) {
        printf("  Pattern '%s' unexpectedly accepted '%s'\n", cases[i].pattern,
               cases[i].rejected[j]);
        return 0;
      }
    }
    st_policy_free(policy);
  }

  st_policy_ctx_release(ctx);
  return 1;
}

/* Parameter validation. */

static int test_param_validation_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t expected;
  } cases[] = {
      {"cat #path.cfg", ST_ERR_INVALID},
      {"cat #p.log", ST_ERR_INVALID},
      {"cat #path.", ST_ERR_INVALID},
      {"cat #path.bad/name", ST_ERR_INVALID},
      {"dd #size.MiB", ST_OK},
      {"dd #size.xyz", ST_ERR_INVALID},
      {"container #uuid.v4", ST_OK},
      {"container #uuid.5", ST_OK},
      {"container #uuid.v3", ST_ERR_INVALID},
      {"install #semver.major", ST_OK},
      {"install #semver.minor", ST_OK},
      {"install #semver.patch", ST_OK},
      {"install #semver.*", ST_OK},
      {"install #semver.build", ST_ERR_INVALID},
      {"log #ts.date", ST_OK},
      {"log #ts.time", ST_OK},
      {"log #ts.datetime", ST_OK},
      {"log #ts.foo", ST_ERR_INVALID},
      {"git #branch.feature_name", ST_ERR_INVALID},
      {"git #branch.bad/name", ST_ERR_INVALID},
      {"echo #sha.short", ST_OK},
      {"echo #sha.40", ST_OK},
      {"echo #sha.64", ST_OK},
      {"echo #sha.128", ST_ERR_INVALID},
      {"pull #image.ghcr.io/org", ST_ERR_INVALID},
      {"pull #image.bad:name", ST_ERR_INVALID},
      {"install #pkg.@types/node", ST_ERR_INVALID},
      {"install #pkg.bad:name", ST_ERR_INVALID},
      {"login #user.www-data", ST_ERR_INVALID},
      {"login #user.bad.name", ST_ERR_INVALID},
      {"key #fp.md5", ST_OK},
      {"key #fp.sha256", ST_OK},
      {"key #fp.sha1", ST_ERR_INVALID},
      {"echo #hash.sha256", ST_ERR_INVALID},
      {"echo #hash.invalid", ST_ERR_INVALID},
      {"sleep #duration.s", ST_OK},
      {"sleep #duration.xx", ST_ERR_INVALID},
      {"kill #signal.TERM", ST_ERR_INVALID},
      {"kill #signal.SIGTERM", ST_ERR_INVALID},
      {"kill #signal.FOOBAR", ST_ERR_INVALID},
      {"seq #range.step", ST_OK},
      {"seq #range.invalid", ST_ERR_INVALID},
      {"chmod #perm.bits", ST_OK},
      {"chmod #perm.foo", ST_ERR_INVALID},
  };
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_pattern_info_t info;
    ASSERT(test_st_validate_pattern(cases[i].pattern, &info) ==
           cases[i].expected);

    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, cases[i].pattern) == cases[i].expected);
    ASSERT(st_policy_rule_count(policy) ==
           (cases[i].expected == ST_OK ? 1 : 0));
    st_policy_free(policy);
  }
  st_policy_ctx_release(ctx);
  return 1;
}

/* --- POLICY MERGE (st_policy_merge) --- */

static int add_patterns(st_policy_t *policy, const char *const *patterns,
                        size_t count) {
  for (size_t i = 0; i < count; i++)
    if (test_st_policy_add(policy, patterns[i]) != ST_OK)
      return 0;
  return 1;
}

static int test_merge_matrix(void) {
  static const struct {
    const char *destination[3];
    size_t destination_count;
    const char *source[3];
    size_t source_count;
    size_t merged_count;
    struct {
      const char *command;
      const char *expected;
    } probes[4];
    size_t probe_count;
  } cases[] = {
      {{"git status"}, 1, {NULL}, 0, 1, {{"git status", "git status"}}, 1},
      {{"git status", "git commit -m *"},
       2,
       {"git status", "git pull"},
       2,
       3,
       {{"git status", "git status"},
        {"git pull", "git pull"},
        {"git commit -m hello", "git commit -m *"}},
       3},
      {{"git status"},
       1,
       {"ls", "cat #path"},
       2,
       3,
       {{"git status", "git status"},
        {"ls", "ls"},
        {"cat /etc/hosts", "cat #path"},
        {"rm -rf /", NULL}},
       4},
      {{"git status", "git commit"},
       2,
       {"git *"},
       1,
       1,
       {{"git status", "git *"}, {"git commit", "git *"}},
       2},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *destination_context = st_policy_ctx_new();
    st_policy_ctx_t *source_context = st_policy_ctx_new();
    st_policy_t *destination = st_policy_new(destination_context);
    st_policy_t *source = st_policy_new(source_context);
    ASSERT(destination != NULL && source != NULL);
    ASSERT(add_patterns(destination, cases[i].destination,
                        cases[i].destination_count));
    ASSERT(add_patterns(source, cases[i].source, cases[i].source_count));
    size_t source_count = st_policy_rule_count(source);
    ASSERT(st_policy_merge(destination, source) == ST_OK);
    ASSERT(st_policy_rule_count(destination) == cases[i].merged_count);
    ASSERT(st_policy_rule_count(source) == source_count);
    ASSERT(st_policy_merge(source, destination) == ST_OK);
    ASSERT(st_policy_rule_count(source) == cases[i].merged_count);
    for (size_t j = 0; j < cases[i].probe_count; j++) {
      ASSERT(policy_eval_is(destination, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
      ASSERT(policy_eval_is(source, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
    }
    st_policy_free(destination);
    st_policy_free(source);
    st_policy_ctx_release(destination_context);
    st_policy_ctx_release(source_context);
  }
  return 1;
}

static int test_merge_allocation_failures_preserve_destination(void) {
  const char *destination_patterns[] = {"copy /tmp/a", "copy /tmp/b",
                                        "keep command"};
  const char *source_patterns[] = {"copy #path", "merge #n"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_dst_ctx = st_policy_ctx_new();
  st_policy_ctx_t *probe_src_ctx = st_policy_ctx_new();
  st_policy_t *probe_dst = st_policy_new(probe_dst_ctx);
  st_policy_t *probe_src = st_policy_new(probe_src_ctx);
  ASSERT(probe_dst_ctx && probe_src_ctx && probe_dst && probe_src);
  ASSERT(add_patterns(probe_dst, destination_patterns, 3));
  ASSERT(add_patterns(probe_src, source_patterns, 2));
  st_test_alloc_reset();
  ASSERT(st_policy_merge(probe_dst, probe_src) == ST_OK);
  size_t merge_allocations = st_test_alloc_count();
  ASSERT(merge_allocations > 0);
  st_policy_free(probe_dst);
  st_policy_free(probe_src);
  st_policy_ctx_release(probe_dst_ctx);
  st_policy_ctx_release(probe_src_ctx);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= merge_allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *dst_ctx = st_policy_ctx_new();
    st_policy_ctx_t *src_ctx = st_policy_ctx_new();
    st_policy_t *dst = st_policy_new(dst_ctx);
    st_policy_t *src = st_policy_new(src_ctx);
    ASSERT(dst_ctx && src_ctx && dst && src);
    ASSERT(add_patterns(dst, destination_patterns, 3));
    ASSERT(add_patterns(src, source_patterns, 2));
    st_test_alloc_fail_at(fail_at);
    st_error_t err = st_policy_merge(dst, src);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(st_policy_rule_count(dst) == 3);
      ASSERT(policy_matches(dst, "keep command", true));
      ASSERT(policy_eval_is(dst, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_eval_is(dst, "copy /tmp/b", "copy /tmp/b"));
      ASSERT(policy_matches(dst, "merge 7", false));
    } else {
      ASSERT(err == ST_OK);
      ASSERT(st_policy_rule_count(dst) == 3);
      ASSERT(policy_eval_is(dst, "copy /tmp/a", "copy #path"));
      ASSERT(policy_matches(dst, "merge 7", true));
    }
    st_policy_free(dst);
    st_policy_free(src);
    st_policy_ctx_release(dst_ctx);
    st_policy_ctx_release(src_ctx);
  }
  ASSERT(observed);
  return 1;
}

/* --- POLICY DIFF (st_policy_diff) --- */

static int string_set_is(const st_netpattern_t *actual, size_t actual_count,
                         const char *const *expected, size_t expected_count) {
  if (actual_count != expected_count)
    return 0;
  for (size_t i = 0; i < actual_count; i++)
    for (size_t j = i + 1; j < actual_count; j++)
      if (actual[i].length == actual[j].length &&
          memcmp(actual[i].data, actual[j].data, actual[i].length) == 0)
        return 0;
  for (size_t i = 0; i < expected_count; i++) {
    int found = 0;
    for (size_t j = 0; j < actual_count; j++)
      if (pattern_is_cpl(actual[j].data, expected[i])) {
        found = 1;
        break;
      }
    if (!found)
      return 0;
  }
  return 1;
}

static bool count_policy_match(st_netpattern_view_t pattern, void *user_ctx) {
  size_t *count = user_ctx;
  return pattern.data && count && (++*count, true);
}

static int test_netargv_view_policy_apis(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL);
  ASSERT(test_st_policy_add(policy, "echo hello") == ST_OK);

  static const char input[] = "4:echo,5:hello,not netargv";
  st_netargv_view_t view = {
      .data = input,
      .length = strlen("4:echo,5:hello,"),
  };
  st_eval_result_t eval = {0};
  bool matches = false;
  st_netpattern_view_t *all = NULL;
  size_t all_count = 0;
  size_t visited = 0;
  ASSERT(st_policy_eval_view(policy, view, &eval) == ST_OK && eval.matches);
  ASSERT(st_policy_match_view(policy, view, &matches) == ST_OK && matches);
  ASSERT(st_policy_verify_all_view(policy, view, &all, &all_count) == ST_OK);
  ASSERT(all_count == 1 && pattern_is_cpl(all[0].data, "echo hello"));
  st_policy_matches_free(all);
  ASSERT(st_policy_visit_matches_view(policy, view, count_policy_match,
                                      &visited, &visited) == ST_OK);
  ASSERT(visited == 1);
  visited = 0;
  st_test_alloc_fail_at(1);
  st_error_t visit_error = st_policy_visit_matches_view(
      policy, view, count_policy_match, &visited, &visited);
  st_test_alloc_reset();
  ASSERT(visit_error == ST_OK && visited == 1);

  st_netpattern_t binary_pattern = {0};
  ASSERT(st_netpattern_from_cpl_owned("echo \"\\x00x\"", &binary_pattern) ==
         ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = binary_pattern.data,
                                            .length = binary_pattern.length}) ==
         ST_OK);
  static const char binary_netargv[] = {'4', ':', 'e', 'c',  'h', 'o',
                                        ',', '2', ':', '\0', 'x', ','};
  view = (st_netargv_view_t){.data = binary_netargv,
                             .length = sizeof(binary_netargv)};
  ASSERT(st_policy_match_view(policy, view, &matches) == ST_OK && matches);
  ASSERT(st_policy_eval_view(policy, view, &eval) == ST_OK && eval.matches &&
         eval.matching_pattern != NULL &&
         eval.matching_pattern_length == binary_pattern.length);
  all = NULL;
  all_count = 0;
  ASSERT(st_policy_verify_all_view(policy, view, &all, &all_count) == ST_OK &&
         all_count == 1 && all[0].length == binary_pattern.length &&
         memcmp(all[0].data, binary_pattern.data, binary_pattern.length) == 0);
  st_policy_matches_free(all);
  st_policy_t *before_binary = st_policy_new(ctx);
  ASSERT(before_binary != NULL &&
         test_st_policy_add(before_binary, "echo hello") == ST_OK);
  st_policy_diff_t binary_diff = {0};
  ASSERT(st_policy_diff(before_binary, policy, &binary_diff) == ST_OK &&
         binary_diff.added_count == 1 && binary_diff.removed_count == 0 &&
         binary_diff.added[0].length == binary_pattern.length &&
         memcmp(binary_diff.added[0].data, binary_pattern.data,
                binary_pattern.length) == 0);
  st_policy_diff_free(&binary_diff);
  st_policy_free(before_binary);
  char binary_path[] = "/tmp/shelltype-policy-binary-XXXXXX";
  int binary_fd = mkstemp(binary_path);
  ASSERT(binary_fd >= 0);
  ASSERT(close(binary_fd) == 0);
  ASSERT(st_policy_save(policy, binary_path) == ST_OK);
  st_policy_ctx_t *loaded_ctx = st_policy_ctx_new();
  st_policy_t *loaded = loaded_ctx ? st_policy_new(loaded_ctx) : NULL;
  ASSERT(loaded != NULL && st_policy_load(loaded, binary_path, true) == ST_OK);
  ASSERT(st_policy_match_view(loaded, view, &matches) == ST_OK && matches);
  ASSERT(st_policy_compact(loaded) == ST_OK);
  ASSERT(st_policy_match_view(loaded, view, &matches) == ST_OK && matches);
  st_policy_free(loaded);
  st_policy_ctx_release(loaded_ctx);
  ASSERT(unlink(binary_path) == 0);
  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){.data = binary_pattern.data,
                                            .length = binary_pattern.length}) ==
         ST_OK);
  ASSERT(st_policy_match_view(policy, view, &matches) == ST_OK && !matches);
  st_netpattern_free(&binary_pattern);

  st_learner_t *learner = st_learner_new(NULL);
  ASSERT(learner != NULL);
  ASSERT(st_learner_feed_netargv_view(learner, view) == ST_OK);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_suggestion_byte_output_contract(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL && test_st_policy_add(policy, "echo stable") == ST_OK);

  /* A poisoned result must become a wholly initialized result, including the
   * legacy terminator after its explicit canonical suggestion length. */
  st_eval_result_t legacy_eval;
  memset(&legacy_eval, 0xa5, sizeof(legacy_eval));
  ASSERT(test_st_policy_eval(policy, "echo changed", &legacy_eval) == ST_OK &&
         !legacy_eval.matches && legacy_eval.suggestion_count != 0 &&
         legacy_eval.suggestions[0].pattern_length != 0 &&
         legacy_eval.suggestions[0]
                 .pattern[legacy_eval.suggestions[0].pattern_length] == '\0');
  st_token_array_t decoded = {0};
  ASSERT(st_netpattern_decode(legacy_eval.suggestions[0].pattern, &decoded) ==
             ST_OK &&
         decoded.count == 2 && strcmp(decoded.tokens[0].text, "echo") == 0 &&
         strcmp(decoded.tokens[1].text, "changed") == 0);
  st_token_array_free(&decoded);

  st_policy_t *binary_policy = st_policy_new(ctx);
  ASSERT(binary_policy != NULL);
  static const char known[] = {'\0', 'k', 'n', 'o', 'w', 'n'};
  st_token_t known_tokens[] = {
      {.text = "echo", .type = ST_TYPE_LITERAL},
      {.text = known, .text_length = sizeof(known), .type = ST_TYPE_LITERAL},
  };
  st_netpattern_t known_pattern = {0};
  ASSERT(st_netpattern_encode_owned(known_tokens, 2, &known_pattern) == ST_OK &&
         st_policy_add_netpattern_view(
             binary_policy,
             (st_netpattern_view_t){.data = known_pattern.data,
                                    .length = known_pattern.length}) == ST_OK);

  static const char binary_netargv[] = {'4', ':', 'e', 'c',  'h', 'o',
                                        ',', '6', ':', '\0', 'o', 't',
                                        'h', 'e', 'r', ','};
  st_eval_result_t binary_eval;
  memset(&binary_eval, 0xa5, sizeof(binary_eval));
  ASSERT(
      st_policy_eval_view(binary_policy,
                          (st_netargv_view_t){.data = binary_netargv,
                                              .length = sizeof(binary_netargv)},
                          &binary_eval) == ST_OK &&
      !binary_eval.matches && binary_eval.suggestion_count != 0 &&
      binary_eval.suggestions[0].based_on != NULL &&
      binary_eval.suggestions[0].based_on_length == known_pattern.length &&
      memcmp(binary_eval.suggestions[0].based_on, known_pattern.data,
             known_pattern.length) == 0 &&
      binary_eval.suggestions[0]
              .pattern[binary_eval.suggestions[0].pattern_length] == '\0');
  char *rendered = NULL;
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){
                 .data = binary_eval.suggestions[0].pattern,
                 .length = binary_eval.suggestions[0].pattern_length},
             &rendered) == ST_OK &&
         strcmp(rendered, "echo \"\\x00other\"") == 0);
  free(rendered);

  static const char direct_bytes[] = {'v', 'i', 'e', 'w'};
  st_token_t direct_tokens[] = {
      {.text = direct_bytes,
       .text_length = sizeof(direct_bytes),
       .type = ST_TYPE_LITERAL},
  };
  st_expand_suggestion_t variants[3];
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(
      st_policy_suggest_variants(binary_policy, direct_tokens, 1, variants) ==
          1 &&
      variants[0].pattern_length != 0 &&
      variants[0].pattern[variants[0].pattern_length] == '\0' &&
      st_netpattern_decode_view(
          (st_netpattern_view_t){.data = variants[0].pattern,
                                 .length = variants[0].pattern_length},
          &decoded) == ST_OK &&
      decoded.count == 1 &&
      decoded.tokens[0].text_length == sizeof(direct_bytes) &&
      memcmp(decoded.tokens[0].text, direct_bytes, sizeof(direct_bytes)) == 0);
  st_token_array_free(&decoded);

  st_netpattern_free(&known_pattern);
  st_policy_free(binary_policy);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Compound policy entries are keyed by their canonical component boundaries,
 * not only their flattened display text. All matching and removal paths must
 * retain arbitrary bytes in the literal affixes. */
static int test_compound_policy_binary_identity(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL);

  static const char binary_prefix[] = {'a', '\0', '{'};
  static const char binary_suffix[] = {'}', '\0', 'z'};
  st_token_t binary_tokens[] = {
      {.text = "cmd", .type = ST_TYPE_LITERAL},
      {.text = "",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = binary_prefix,
       .prefix_length = sizeof(binary_prefix),
       .capture = "#n",
       .capture_length = 2,
       .suffix = binary_suffix,
       .suffix_length = sizeof(binary_suffix),
       .capture_type = ST_TYPE_NUMBER},
  };
  st_netpattern_t binary_pattern = {0};
  ASSERT(st_netpattern_encode_owned(binary_tokens, 2, &binary_pattern) ==
         ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = binary_pattern.data,
                                            .length = binary_pattern.length}) ==
         ST_OK);

  static const char binary_command[] = {
      '3',  ':', 'c', 'm', 'd', ',',  '8', ':', 'a',
      '\0', '{', '4', '2', '}', '\0', 'z', ',',
  };
  static const char binary_mismatch[] = {
      '3',  ':', 'c', 'm', 'd', ',',  '8', ':', 'a',
      '\0', '{', 'x', '2', '}', '\0', 'z', ',',
  };
  bool matches = false;
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = binary_command,
                                 .length = sizeof(binary_command)},
             &matches) == ST_OK &&
         matches);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = binary_mismatch,
                                 .length = sizeof(binary_mismatch)},
             &matches) == ST_OK &&
         !matches);

  st_netpattern_view_t *all = NULL;
  size_t all_count = 0;
  ASSERT(st_policy_verify_all_view(
             policy,
             (st_netargv_view_t){.data = binary_command,
                                 .length = sizeof(binary_command)},
             &all, &all_count) == ST_OK &&
         all_count == 1 && all[0].length == binary_pattern.length &&
         memcmp(all[0].data, binary_pattern.data, binary_pattern.length) == 0);
  st_policy_matches_free(all);
  size_t visited = 0;
  ASSERT(st_policy_visit_matches_view(
             policy,
             (st_netargv_view_t){.data = binary_command,
                                 .length = sizeof(binary_command)},
             count_policy_match, &visited, &visited) == ST_OK &&
         visited == 1);

  st_token_t collision_a[] = {
      {.text = "cmd", .type = ST_TYPE_LITERAL},
      {.text = "a{#n}{#n}x",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = "a",
       .prefix_length = 1,
       .capture = "#n",
       .capture_length = 2,
       .suffix = "{#n}x",
       .suffix_length = 5,
       .capture_type = ST_TYPE_NUMBER},
  };
  st_token_t collision_b[] = {
      {.text = "cmd", .type = ST_TYPE_LITERAL},
      {.text = "a{#n}{#n}x",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = "a{#n}",
       .prefix_length = 5,
       .capture = "#n",
       .capture_length = 2,
       .suffix = "x",
       .suffix_length = 1,
       .capture_type = ST_TYPE_NUMBER},
  };
  st_netpattern_t pattern_a = {0};
  st_netpattern_t pattern_b = {0};
  ASSERT(st_netpattern_encode_owned(collision_a, 2, &pattern_a) == ST_OK);
  ASSERT(st_netpattern_encode_owned(collision_b, 2, &pattern_b) == ST_OK);
  st_token_array_t decoded_collision = {0};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = pattern_b.data,
                                    .length = pattern_b.length},
             &decoded_collision) == ST_OK);
  st_token_array_free(&decoded_collision);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = pattern_a.data,
                                            .length = pattern_a.length}) ==
         ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = pattern_b.data,
                                            .length = pattern_b.length}) ==
         ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);

  char *command_a = test_netargv("cmd a42{#n}x");
  char *command_b = test_netargv("cmd 'a{#n}42x'");
  ASSERT(command_a != NULL && command_b != NULL);
  st_eval_result_t eval = {0};
  ASSERT(st_policy_eval_view(policy,
                             (st_netargv_view_t){.data = command_a,
                                                 .length = strlen(command_a)},
                             &eval) == ST_OK &&
         eval.matches && eval.matching_pattern_length == pattern_a.length &&
         memcmp(eval.matching_pattern, pattern_a.data, pattern_a.length) == 0);
  ASSERT(st_policy_eval_view(policy,
                             (st_netargv_view_t){.data = command_b,
                                                 .length = strlen(command_b)},
                             &eval) == ST_OK &&
         eval.matches && eval.matching_pattern_length == pattern_b.length &&
         memcmp(eval.matching_pattern, pattern_b.data, pattern_b.length) == 0);

  st_token_t overlap_a[] = {
      {.text = "cmd", .type = ST_TYPE_LITERAL},
      {.text = "a{*}{*}x",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = "a",
       .prefix_length = 1,
       .capture = "*",
       .capture_length = 1,
       .suffix = "{*}x",
       .suffix_length = 4,
       .capture_type = ST_TYPE_ANY},
  };
  st_token_t overlap_b[] = {
      {.text = "cmd", .type = ST_TYPE_LITERAL},
      {.text = "a{*}{*}x",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = "a{*}",
       .prefix_length = 4,
       .capture = "*",
       .capture_length = 1,
       .suffix = "x",
       .suffix_length = 1,
       .capture_type = ST_TYPE_ANY},
  };
  st_netpattern_t overlap_pattern_a = {0};
  st_netpattern_t overlap_pattern_b = {0};
  ASSERT(st_netpattern_encode_owned(overlap_a, 2, &overlap_pattern_a) == ST_OK);
  ASSERT(st_netpattern_encode_owned(overlap_b, 2, &overlap_pattern_b) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = overlap_pattern_a.data,
                         .length = overlap_pattern_a.length}) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = overlap_pattern_b.data,
                         .length = overlap_pattern_b.length}) == ST_OK);
  char *overlap_command = test_netargv("cmd 'a{*}{*}x'");
  ASSERT(overlap_command != NULL);
  all = NULL;
  all_count = 0;
  ASSERT(st_policy_verify_all_view(
             policy,
             (st_netargv_view_t){.data = overlap_command,
                                 .length = strlen(overlap_command)},
             &all, &all_count) == ST_OK &&
         all_count == 2);
  st_policy_matches_free(all);
  visited = 0;
  ASSERT(st_policy_visit_matches_view(
             policy,
             (st_netargv_view_t){.data = overlap_command,
                                 .length = strlen(overlap_command)},
             count_policy_match, &visited, &visited) == ST_OK &&
         visited == 2);
  const st_netpattern_t *preferred =
      compare_netpattern_views(
          (st_netpattern_view_t){.data = overlap_pattern_a.data,
                                 .length = overlap_pattern_a.length},
          (st_netpattern_view_t){.data = overlap_pattern_b.data,
                                 .length = overlap_pattern_b.length}) < 0
          ? &overlap_pattern_a
          : &overlap_pattern_b;
  ASSERT(st_policy_eval_view(
             policy,
             (st_netargv_view_t){.data = overlap_command,
                                 .length = strlen(overlap_command)},
             &eval) == ST_OK &&
         eval.matches && eval.matching_pattern_length == preferred->length &&
         memcmp(eval.matching_pattern, preferred->data, preferred->length) ==
             0);
  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = overlap_pattern_a.data,
                         .length = overlap_pattern_a.length}) == ST_OK);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = overlap_command,
                                 .length = strlen(overlap_command)},
             &matches) == ST_OK &&
         matches);
  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = overlap_pattern_b.data,
                         .length = overlap_pattern_b.length}) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);
  free(overlap_command);
  st_netpattern_free(&overlap_pattern_b);
  st_netpattern_free(&overlap_pattern_a);

  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){.data = pattern_a.data,
                                            .length = pattern_a.length}) ==
         ST_OK);
  ASSERT(st_policy_rule_count(policy) == 2);
  ASSERT(st_policy_match_view(policy,
                              (st_netargv_view_t){.data = command_a,
                                                  .length = strlen(command_a)},
                              &matches) == ST_OK &&
         !matches);
  ASSERT(st_policy_match_view(policy,
                              (st_netargv_view_t){.data = command_b,
                                                  .length = strlen(command_b)},
                              &matches) == ST_OK &&
         matches);

  free(command_a);
  free(command_b);
  st_netpattern_free(&pattern_b);
  st_netpattern_free(&pattern_a);
  st_netpattern_free(&binary_pattern);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

typedef struct {
  st_policy_diff_kind_t kinds[4];
  const char *patterns[4];
  size_t count;
  size_t stop_after;
} diff_visit_expect_t;

static bool check_policy_diff(st_policy_diff_kind_t kind,
                              st_netpattern_view_t pattern, void *user_ctx) {
  diff_visit_expect_t *expect = user_ctx;
  if (!expect ||
      expect->count == sizeof(expect->kinds) / sizeof(expect->kinds[0]))
    return false;
  size_t index = expect->count++;
  if (kind != expect->kinds[index] || !pattern.data ||
      !pattern_is_cpl(pattern.data, expect->patterns[index]))
    return false;
  return expect->stop_after == 0 || expect->count < expect->stop_after;
}

static bool count_policy_diff_without_allocation(st_policy_diff_kind_t kind,
                                                 st_netpattern_view_t pattern,
                                                 void *user_ctx) {
  (void)kind;
  size_t *count = user_ctx;
  if (!pattern.data || !count)
    return false;
  (*count)++;
  return true;
}

static int test_policy_diff_visit_contract(void) {
  st_policy_ctx_t *left_ctx = st_policy_ctx_new();
  st_policy_ctx_t *right_ctx = st_policy_ctx_new();
  st_policy_t *left = left_ctx ? st_policy_new(left_ctx) : NULL;
  st_policy_t *right = right_ctx ? st_policy_new(right_ctx) : NULL;
  ASSERT(left != NULL && right != NULL);
  ASSERT(add_patterns(left, (const char *[]){"git status", "cat #path"}, 2));
  ASSERT(
      add_patterns(right, (const char *[]){"git status", "ls", "echo *"}, 3));

  diff_visit_expect_t expect = {
      .kinds = {ST_POLICY_DIFF_ADDED, ST_POLICY_DIFF_ADDED,
                ST_POLICY_DIFF_REMOVED},
      .patterns = {"ls", "echo *", "cat #path"},
  };
  size_t visited = 0;
  ASSERT(st_policy_visit_diff(left, right, check_policy_diff, &expect,
                              &visited) == ST_OK);
  ASSERT(visited == 3 && expect.count == 3);

  size_t allocation_free_count = 0;
  st_test_alloc_fail_at(1);
  st_error_t visit_error =
      st_policy_visit_diff(left, right, count_policy_diff_without_allocation,
                           &allocation_free_count, &visited);
  st_test_alloc_reset();
  ASSERT(visit_error == ST_OK && visited == 3 && allocation_free_count == 3);

  expect.count = 0;
  expect.stop_after = 1;
  ASSERT(st_policy_visit_diff(left, right, check_policy_diff, &expect,
                              &visited) == ST_OK);
  ASSERT(visited == 1 && expect.count == 1);
  ASSERT(st_policy_visit_diff(left, left, check_policy_diff, &expect,
                              &visited) == ST_OK &&
         visited == 0);

  st_policy_free(left);
  st_policy_free(right);
  st_policy_ctx_release(left_ctx);
  st_policy_ctx_release(right_ctx);
  return 1;
}

static int test_diff_matrix_and_symmetry(void) {
  static const struct {
    const char *left[4];
    size_t left_count;
    const char *right[4];
    size_t right_count;
    const char *added[4];
    size_t added_count;
    const char *removed[4];
    size_t removed_count;
  } cases[] = {
      {{"git status", "cat #path"},
       2,
       {"git status", "cat #path"},
       2,
       {NULL},
       0,
       {NULL},
       0},
      {{"git status", "cat #path"},
       2,
       {"git status", "ls"},
       2,
       {"ls"},
       1,
       {"cat #path"},
       1},
      {{"git status"}, 1, {NULL}, 0, {NULL}, 0, {"git status"}, 1},
      {{"git status", "cat #path", "head -n #n"},
       3,
       {"git status", "ls", "echo *"},
       3,
       {"ls", "echo *"},
       2,
       {"cat #path", "head -n #n"},
       2},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *left_context = st_policy_ctx_new();
    st_policy_ctx_t *right_context = st_policy_ctx_new();
    st_policy_t *left = st_policy_new(left_context);
    st_policy_t *right = st_policy_new(right_context);
    ASSERT(left != NULL && right != NULL);
    ASSERT(add_patterns(left, cases[i].left, cases[i].left_count));
    ASSERT(add_patterns(right, cases[i].right, cases[i].right_count));

    st_policy_diff_t forward = {0};
    ASSERT(st_policy_diff(left, right, &forward) == ST_OK);
    ASSERT(string_set_is(forward.added, forward.added_count, cases[i].added,
                         cases[i].added_count));
    ASSERT(string_set_is(forward.removed, forward.removed_count,
                         cases[i].removed, cases[i].removed_count));
    st_policy_diff_free(&forward);

    st_policy_diff_t reverse = {0};
    ASSERT(st_policy_diff(right, left, &reverse) == ST_OK);
    ASSERT(string_set_is(reverse.added, reverse.added_count, cases[i].removed,
                         cases[i].removed_count));
    ASSERT(string_set_is(reverse.removed, reverse.removed_count, cases[i].added,
                         cases[i].added_count));
    st_policy_diff_free(&reverse);

    if (i == 1) {
      st_policy_diff_t identity = {0};
      ASSERT(st_policy_diff(left, left, &identity) == ST_OK);
      ASSERT(identity.added_count == 0 && identity.removed_count == 0);
      st_policy_diff_free(&identity);

      st_policy_diff_t reused = {0};
      ASSERT(st_policy_diff(left, right, &reused) == ST_OK);
      st_netpattern_t *reused_added = reused.added;
      size_t reused_added_count = reused.added_count;
      st_netpattern_t *reused_removed = reused.removed;
      size_t reused_removed_count = reused.removed_count;
      ASSERT(st_policy_diff(right, left, &reused) == ST_ERR_INVALID);
      ASSERT(reused.added == reused_added &&
             reused.added_count == reused_added_count &&
             reused.removed == reused_removed &&
             reused.removed_count == reused_removed_count);
      st_policy_diff_free(&reused);
      ASSERT(st_policy_diff(right, left, &reused) == ST_OK);
      st_policy_diff_free(&reused);
    }
    st_policy_free(left);
    st_policy_free(right);
    st_policy_ctx_release(left_context);
    st_policy_ctx_release(right_context);
  }
  return 1;
}

static int test_diff_allocation_failures_clear_result(void) {
  const char *left_patterns[] = {"git status", "cat #path", "head -n #n"};
  const char *right_patterns[] = {"git status", "ls", "echo *"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_left_context = st_policy_ctx_new();
  st_policy_ctx_t *probe_right_context = st_policy_ctx_new();
  st_policy_t *probe_left = st_policy_new(probe_left_context);
  st_policy_t *probe_right = st_policy_new(probe_right_context);
  ASSERT(probe_left_context && probe_right_context && probe_left &&
         probe_right);
  ASSERT(add_patterns(probe_left, left_patterns, 3));
  ASSERT(add_patterns(probe_right, right_patterns, 3));
  st_test_alloc_reset();
  st_policy_diff_t probe_result = {0};
  ASSERT(st_policy_diff(probe_left, probe_right, &probe_result) == ST_OK);
  size_t diff_allocations = st_test_alloc_count();
  ASSERT(diff_allocations > 0);
  st_policy_diff_free(&probe_result);

  st_policy_diff_t reuse_after_free = {0};
  ASSERT(st_policy_diff(probe_left, probe_right, &reuse_after_free) == ST_OK);
  st_policy_diff_free(&reuse_after_free);
  st_test_alloc_fail_at(1);
  ASSERT(st_policy_diff(probe_left, probe_right, &reuse_after_free) ==
         ST_ERR_MEMORY);
  st_test_alloc_reset();
  ASSERT(reuse_after_free.added == NULL && reuse_after_free.added_count == 0 &&
         reuse_after_free.removed == NULL &&
         reuse_after_free.removed_count == 0);
  st_policy_free(probe_left);
  st_policy_free(probe_right);
  st_policy_ctx_release(probe_left_context);
  st_policy_ctx_release(probe_right_context);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= diff_allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *left_context = st_policy_ctx_new();
    st_policy_ctx_t *right_context = st_policy_ctx_new();
    ASSERT(left_context != NULL && right_context != NULL);
    st_policy_t *left = st_policy_new(left_context);
    st_policy_t *right = st_policy_new(right_context);
    ASSERT(left != NULL && right != NULL);
    ASSERT(add_patterns(left, left_patterns, 3));
    ASSERT(add_patterns(right, right_patterns, 3));

    st_policy_diff_t result = {0};
    st_test_alloc_fail_at(fail_at);
    st_error_t err = st_policy_diff(left, right, &result);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(result.added == NULL && result.added_count == 0);
      ASSERT(result.removed == NULL && result.removed_count == 0);
    } else {
      ASSERT(err == ST_OK);
      st_policy_diff_free(&result);
    }
    st_policy_free(left);
    st_policy_free(right);
    st_policy_ctx_release(left_context);
    st_policy_ctx_release(right_context);
  }
  ASSERT(observed);
  return 1;
}

/* --- INCREMENTAL SUBSUMPTION TESTS --- */

static int test_incremental_subsumption_matrix(void) {
  static const struct {
    const char *additions[4];
    size_t counts[4];
    size_t addition_count;
    struct {
      const char *command;
      const char *expected;
    } probes[3];
    size_t probe_count;
  } cases[] = {
      {{"git *", "git status"}, {1, 1}, 2, {{"git status", "git *"}}, 1},
      {{"git status", "git commit", "git *"},
       {1, 2, 1},
       3,
       {{"git status", "git *"}, {"git commit", "git *"}},
       2},
      {{"git status", "git commit -m *", "git *"},
       {1, 2, 2},
       3,
       {{"git status", "git *"}, {"git commit -m fix", "git commit -m *"}},
       2},
      {{"allocate #size.MiB", "allocate #size"},
       {1, 1},
       2,
       {{"allocate 1MiB", "allocate #size"},
        {"allocate 2GiB", "allocate #size"}},
       2},
      {{"git -v", "git #opt"},
       {1, 1},
       2,
       {{"git -v", "git #opt"}, {"git --help", "git #opt"}},
       2},
      {{"ping #i", "ping #ipv6", "ping #ipaddr"},
       {1, 2, 1},
       3,
       {{"ping 192.168.1.1", "ping #ipaddr"}, {"ping ::1", "ping #ipaddr"}},
       2},
      {{"cat #f", "cat #r", "cat #p", "cat #path"},
       {1, 1, 2, 1},
       4,
       {{"cat file.txt", "cat #path"},
        {"cat src/app.c", "cat #path"},
        {"cat /etc/hosts", "cat #path"}},
       3},
      {{"git", "git status", "git commit -m *", "git *"},
       {1, 2, 3, 3},
       4,
       {{"git", "git"},
        {"git status", "git *"},
        {"git commit -m fix", "git commit -m *"}},
       3},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    for (size_t j = 0; j < cases[i].addition_count; j++) {
      ASSERT(test_st_policy_add(policy, cases[i].additions[j]) == ST_OK);
      ASSERT(st_policy_rule_count(policy) == cases[i].counts[j]);
    }
    for (size_t j = 0; j < cases[i].probe_count; j++)
      ASSERT(policy_eval_is(policy, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }
  return 1;
}

/* Stress test: 100 literals subsumed by one wildcard */
static int test_incr_stress(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);

  for (int i = 0; i < 100; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "cmd arg%d", i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_rule_count(policy) == 100);

  /* Adding a wildcard subsumes all 100 literals */
  st_error_t err = test_st_policy_add(policy, "cmd *");
  ASSERT(err == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);

  /* All 100 variants still match */
  static const char *probes[] = {"cmd arg0", "cmd arg42", "cmd arg99"};
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_eval_is(policy, probes[i], "cmd *"));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_incremental_batch_remove_readd(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);

  const char *batch[] = {"git status", "git commit", "git pull", "git *"};
  ASSERT(test_st_policy_batch_add(policy, batch, 4) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "git status", "git *"));

  ASSERT(test_st_policy_remove(policy, "git *") == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 0);

  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "git status", "git status"));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_batch_add_is_atomic(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(test_st_policy_batch_add(NULL, (const char *[]){"invalid"}, 1) ==
         ST_ERR_INVALID);
  ASSERT(test_st_policy_batch_add(policy, NULL, 0) == ST_ERR_INVALID);
  ASSERT(test_st_policy_batch_add(policy, NULL, 1) == ST_ERR_INVALID);

  const char *invalid_middle[] = {"docker ps", NULL, "ls -la"};
  ASSERT(test_st_policy_batch_add(policy, invalid_middle, 3) == ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "git status", "git status"));
  ASSERT(policy_eval_is(policy, "docker ps", NULL));
  ASSERT(policy_eval_is(policy, "ls -la", NULL));

  const char *valid[] = {"docker ps", "git status", "cat #path"};
  ASSERT(test_st_policy_batch_add(policy, valid, 3) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);
  ASSERT(policy_eval_is(policy, "docker ps", "docker ps"));
  ASSERT(policy_eval_is(policy, "cat /tmp/input", "cat #path"));

  ASSERT(test_st_policy_batch_add(policy, valid, 0) == ST_ERR_INVALID);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int test_batch_add_allocation_failures_are_atomic(void) {
  const char *initial[] = {"copy /tmp/a", "copy /tmp/b", "keep command"};
  const char *batch[] = {"other #n", "copy #path", "tail exact"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe_policy =
      probe_context ? st_policy_new(probe_context) : NULL;
  ASSERT(probe_context != NULL && probe_policy != NULL);
  ASSERT(add_patterns(probe_policy, initial, 3));
  st_test_alloc_reset();
  ASSERT(test_st_policy_batch_add(probe_policy, batch, 3) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_policy_free(probe_policy);
  st_policy_ctx_release(probe_context);

  bool observed_failure = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *context = st_policy_ctx_new();
    ASSERT(context != NULL);
    st_policy_t *policy = st_policy_new(context);
    ASSERT(policy != NULL);
    ASSERT(add_patterns(policy, initial, 3));
    size_t before = st_policy_rule_count(policy);
    st_test_alloc_fail_at(fail_at);
    st_error_t err = test_st_policy_batch_add(policy, batch, 3);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed_failure = true;
      ASSERT(st_policy_rule_count(policy) == before);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_eval_is(policy, "copy /tmp/b", "copy /tmp/b"));
      ASSERT(policy_eval_is(policy, "other 7", NULL));
    } else {
      ASSERT(err == ST_OK);
      ASSERT(st_policy_rule_count(policy) == 4);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy #path"));
    }
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
  ASSERT(observed_failure);
  return 1;
}

static int test_add_allocation_failures_are_atomic(void) {
  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe_policy =
      probe_context ? st_policy_new(probe_context) : NULL;
  ASSERT(probe_context != NULL && probe_policy != NULL);
  ASSERT(test_st_policy_add(probe_policy, "copy /tmp/a") == ST_OK);
  ASSERT(test_st_policy_add(probe_policy, "copy /tmp/b") == ST_OK);
  st_test_alloc_reset();
  ASSERT(test_st_policy_add(probe_policy, "copy #path") == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_policy_free(probe_policy);
  st_policy_ctx_release(probe_context);

  bool observed_failure = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, "copy /tmp/a") == ST_OK);
    ASSERT(test_st_policy_add(policy, "copy /tmp/b") == ST_OK);

    st_test_alloc_fail_at(fail_at);
    st_error_t err = test_st_policy_add(policy, "copy #path");
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed_failure = true;
      ASSERT(st_policy_rule_count(policy) == 2);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_eval_is(policy, "copy /tmp/b", "copy /tmp/b"));
    } else {
      ASSERT(err == ST_OK);
      ASSERT(st_policy_rule_count(policy) == 1);
      ASSERT(policy_eval_is(policy, "copy /tmp/a", "copy #path"));
    }
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
  ASSERT(observed_failure);
  return 1;
}

static int variants_match(st_learner_t *learner, const char **tokens,
                          size_t token_count, size_t position,
                          const st_token_type_t *expected,
                          size_t expected_count) {
  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS];
  size_t count = st_policy_suggest_token_variants(learner, tokens, token_count,
                                                  position, variants);
  if (count != expected_count) {
    printf("    variant count: got %zu, expected %zu\n", count, expected_count);
    for (size_t i = 0; i < count; i++)
      printf("      [%zu] %d (%s)\n", i, variants[i].type,
             variants[i].type_symbol ? variants[i].type_symbol : "NULL");
    return 0;
  }
  for (size_t i = 0; i < count; i++) {
    if (variants[i].type != expected[i] || !variants[i].type_symbol ||
        strcmp(variants[i].type_symbol, st_type_symbol[expected[i]]) != 0 ||
        variants[i].sample_value != NULL ||
        variants[i].sample_value_length != 0) {
      printf("    variant %zu: got %d (%s), expected %d (%s)\n", i,
             variants[i].type,
             variants[i].type_symbol ? variants[i].type_symbol : "NULL",
             expected[i], st_type_symbol[expected[i]]);
      return 0;
    }
  }
  return 1;
}

static int variant_lists_equal(const st_token_variant_t *left,
                               size_t left_count,
                               const st_token_variant_t *right,
                               size_t right_count) {
  if (left_count != right_count)
    return 0;
  for (size_t i = 0; i < left_count; i++)
    if (left[i].type != right[i].type ||
        strcmp(left[i].type_symbol, right[i].type_symbol) != 0 ||
        left[i].sample_value != right[i].sample_value ||
        left[i].sample_value_length != right[i].sample_value_length)
      return 0;
  return 1;
}

static int test_token_variant_matrix(void) {
  static const st_token_type_t path[] = {ST_TYPE_ABS_PATH, ST_TYPE_PATH,
                                         ST_TYPE_ANY};
  static const st_token_type_t rel_path[] = {ST_TYPE_REL_PATH, ST_TYPE_PATH,
                                             ST_TYPE_ANY};
  static const st_token_type_t scalar[] = {ST_TYPE_SHA, ST_TYPE_VALUE,
                                           ST_TYPE_ANY};
  static const st_token_type_t word[] = {ST_TYPE_WORD, ST_TYPE_ANY};
  static const st_token_type_t literal[] = {ST_TYPE_VALUE, ST_TYPE_ANY};
  static const st_token_type_t any[] = {ST_TYPE_ANY};
  static const struct {
    const char *token;
    const st_token_type_t *expected;
    size_t expected_count;
  } fallback_cases[] = {
      {"#p", path, 3}, {"#r", rel_path, 3},     {"#sha", scalar, 3},
      {"#w", word, 2}, {"literal", literal, 2}, {"*", any, 1},
  };
  st_learner_t empty = {0};
  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS];

  for (size_t i = 0; i < sizeof(fallback_cases) / sizeof(fallback_cases[0]);
       i++) {
    const char *tokens[] = {"cmd", fallback_cases[i].token};
    ASSERT(variants_match(&empty, tokens, 2, 1, fallback_cases[i].expected,
                          fallback_cases[i].expected_count));
  }

  const char *command_tokens[] = {"literal"};
  size_t command_count =
      st_policy_suggest_token_variants(&empty, command_tokens, 1, 0, variants);
  ASSERT(command_count == 1);
  ASSERT(variants[0].type == ST_TYPE_VALUE);
  char *edited_command =
      st_policy_apply_type_at(&empty, command_tokens, 1, 0, variants[0].type);
  ASSERT(edited_command != NULL);
  ASSERT(test_st_validate_pattern(edited_command, NULL) == ST_OK);
  free(edited_command);

  const char *valid[] = {"cmd", "#w"};
  const char *with_null[] = {"cmd", NULL};
  const char *with_control[] = {"cmd", "bad\003token"};
  const char *with_separator[] = {"cmd", "two tokens"};
  ASSERT(st_policy_suggest_token_variants(NULL, valid, 2, 1, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, NULL, 2, 1, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, valid, 2, 2, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, valid, 2, 1, NULL) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, with_null, 2, 1, variants) ==
         0);
  ASSERT(st_policy_suggest_token_variants(&empty, with_control, 2, 1,
                                          variants) > 0);
  ASSERT(st_policy_suggest_token_variants(&empty, with_separator, 2, 1,
                                          variants) > 0);
  const char *too_many_tokens[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many_tokens) / sizeof(too_many_tokens[0]);
       i++)
    too_many_tokens[i] = "#w";
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_token_variants(&empty, too_many_tokens,
                                          sizeof(too_many_tokens) /
                                              sizeof(too_many_tokens[0]),
                                          1, variants) == 0);
  for (size_t i = 0; i < ST_MAX_TOKEN_VARIANTS; i++)
    ASSERT(variants[i].type == ST_TYPE_LITERAL &&
           variants[i].type_symbol == NULL &&
           variants[i].sample_value == NULL &&
           variants[i].sample_value_length == 0);

  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  ASSERT(test_st_feed(learner, "git commit -m /first/path") == ST_OK);
  ASSERT(test_st_feed(learner, "git commit -m /second/path") == ST_OK);
  ASSERT(test_st_feed(learner, "git commit -m ../relative/path") == ST_OK);
  ASSERT(test_st_feed(learner, "curl -X GET https://one.example") == ST_OK);
  ASSERT(test_st_feed(learner, "curl -X POST https://two.example") == ST_OK);
  ASSERT(test_st_feed(learner, "curl -X 42 https://number.example") == ST_OK);
  ASSERT(test_st_feed(learner, "branch 42 /number/path") == ST_OK);
  ASSERT(test_st_feed(learner, "branch https://example.test ../url/path") ==
         ST_OK);
  ASSERT(test_st_feed(learner, "branch 7 ../number/relative") == ST_OK);

  const char *learned_path[] = {"git", "commit", "#sopt", "#p"};
  const char *narrow_path[] = {"git", "commit", "#sopt", "*"};
  const char *method[] = {"curl", "#sopt", "#method", "#u"};
  const char *generic_prefix[] = {"branch", "*", "*"};
  static const st_token_type_t observed_paths[] = {
      ST_TYPE_ABS_PATH, ST_TYPE_REL_PATH, ST_TYPE_PATH, ST_TYPE_ANY};
  static const st_token_type_t narrowed[] = {ST_TYPE_REL_PATH, ST_TYPE_ABS_PATH,
                                             ST_TYPE_ANY};
  static const st_token_type_t method_types[] = {ST_TYPE_METHOD, ST_TYPE_NUMBER,
                                                 ST_TYPE_ANY};
  static const st_token_type_t url_types[] = {ST_TYPE_URL, ST_TYPE_ANY};
  static const st_token_type_t prefix_union[] = {ST_TYPE_REL_PATH,
                                                 ST_TYPE_ABS_PATH, ST_TYPE_ANY};
  ASSERT(variants_match(learner, learned_path, 4, 3, observed_paths, 4));
  ASSERT(variants_match(learner, narrow_path, 4, 3, narrowed, 3));
  ASSERT(variants_match(learner, method, 4, 2, method_types, 3));
  ASSERT(variants_match(learner, method, 4, 3, url_types, 2));
  ASSERT(variants_match(learner, generic_prefix, 3, 2, prefix_union, 3));

  static const char *saturation_commands[] = {
      "probe 42",          "probe 192.0.2.1",   "probe word",
      "probe /absolute",   "probe ../relative", "probe file.txt",
      "probe https://x.y", "probe --long",      "probe -s",
  };
  for (size_t i = 0;
       i < sizeof(saturation_commands) / sizeof(saturation_commands[0]); i++)
    ASSERT(test_st_feed(learner, saturation_commands[i]) == ST_OK);
  const char *saturated[] = {"probe", "#n"};
  size_t saturated_count =
      st_policy_suggest_token_variants(learner, saturated, 2, 1, variants);
  ASSERT(saturated_count == ST_MAX_TOKEN_VARIANTS);
  ASSERT(variants[0].type == ST_TYPE_NUMBER);
  ASSERT(variants[saturated_count - 1].type == ST_TYPE_ANY);
  for (size_t i = 0; i < saturated_count; i++)
    for (size_t j = i + 1; j < saturated_count; j++)
      ASSERT(variants[i].type != variants[j].type);

  static const size_t saturation_orders[][9] = {
      {8, 7, 6, 5, 4, 3, 2, 1, 0},
      {4, 0, 8, 2, 6, 1, 7, 3, 5},
  };
  for (size_t order = 0;
       order < sizeof(saturation_orders) / sizeof(saturation_orders[0]);
       order++) {
    st_learner_t *permuted = st_learner_new(
        &(st_learner_config_t){.min_support = 1,
                               .min_confidence = 0.0,
                               .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
    ASSERT(permuted != NULL);
    for (size_t i = 0;
         i < sizeof(saturation_commands) / sizeof(saturation_commands[0]); i++)
      ASSERT(test_st_feed(permuted,
                          saturation_commands[saturation_orders[order][i]]) ==
             ST_OK);
    st_token_variant_t reordered[ST_MAX_TOKEN_VARIANTS];
    size_t reordered_count =
        st_policy_suggest_token_variants(permuted, saturated, 2, 1, reordered);
    ASSERT(variant_lists_equal(variants, saturated_count, reordered,
                               reordered_count));
    st_learner_free(permuted);
  }

  size_t count =
      st_policy_suggest_token_variants(learner, learned_path, 4, 3, variants);
  ASSERT(count == 4);
  for (size_t i = 0; i < count; i++) {
    char *edited =
        st_policy_apply_type_at(learner, learned_path, 4, 3, variants[i].type);
    ASSERT(edited != NULL);
    st_pattern_info_t info;
    ASSERT(test_st_validate_pattern(edited, &info) == ST_OK);
    ASSERT(info.token_count == 4);
    free(edited);
  }

  st_learner_free(learner);
  return 1;
}

/* --- APPLY TYPE AT POSITION (st_policy_apply_type_at) --- */
/* All tests share setup: ctx + zeroed learner, then test different
 * positions/types. */

static int test_apply_type_matrix(void) {
  static const char *three[] = {"git", "#path", "#n"};
  static const char *four[] = {"git", "#p", "commit", "#n"};
  static const char *message[] = {"git", "commit", "-m", "#val"};
  static const char *single[] = {"#path"};
  static const char *symbol[] = {"cmd", "#placeholder"};
  static const struct {
    const char **tokens;
    size_t count;
    size_t position;
    st_token_type_t type;
    const char *expected;
  } cases[] = {
      {three, 3, 0, ST_TYPE_WORD, "#w #path #n"},
      {three, 3, 1, ST_TYPE_ABS_PATH, "git #p #n"},
      {message, 4, 3, ST_TYPE_ANY, "git commit -m *"},
      {four, 4, 1, ST_TYPE_REL_PATH, "git #r commit #n"},
      {four, 4, 0, ST_TYPE_WORD, "#w #p commit #n"},
      {four, 4, 3, ST_TYPE_VALUE, "git #p commit #val"},
      {single, 1, 0, ST_TYPE_ANY, "*"},
      {symbol, 2, 1, ST_TYPE_WORD, "cmd #w"},
      {symbol, 2, 1, ST_TYPE_VALUE, "cmd #val"},
      {symbol, 2, 1, ST_TYPE_ABS_PATH, "cmd #p"},
      {symbol, 2, 1, ST_TYPE_REL_PATH, "cmd #r"},
      {symbol, 2, 1, ST_TYPE_NUMBER, "cmd #n"},
      {symbol, 2, 1, ST_TYPE_IPV4, "cmd #i"},
      {symbol, 2, 1, ST_TYPE_URL, "cmd #u"},
      {symbol, 2, 1, ST_TYPE_ANY, "cmd *"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *actual =
        st_policy_apply_type_at(NULL, cases[i].tokens, cases[i].count,
                                cases[i].position, cases[i].type);
    ASSERT(actual != NULL);
    ASSERT_STR_EQ(actual, cases[i].expected);
    free(actual);
  }

  ASSERT_STR_EQ(three[0], "git");
  ASSERT_STR_EQ(three[1], "#path");
  ASSERT_STR_EQ(three[2], "#n");

  const char *with_null[] = {"git", NULL};
  ASSERT(st_policy_apply_type_at(NULL, NULL, 1, 0, ST_TYPE_WORD) == NULL);
  ASSERT(st_policy_apply_type_at(NULL, three, 0, 0, ST_TYPE_WORD) == NULL);
  ASSERT(st_policy_apply_type_at(NULL, three, 3, 3, ST_TYPE_WORD) == NULL);
  ASSERT(st_policy_apply_type_at(NULL, three, 3, 0, ST_TYPE_LITERAL) == NULL);
  ASSERT(st_policy_apply_type_at(NULL, three, 3, 0, ST_TYPE_COUNT) == NULL);
  ASSERT(st_policy_apply_type_at(NULL, with_null, 2, 0, ST_TYPE_WORD) == NULL);

  char oversized[ST_MAX_NETPATTERN_LEN];
  memset(oversized, 'x', sizeof(oversized));
  oversized[sizeof(oversized) - 1] = '\0';
  const char *too_long[] = {oversized, "tail"};
  ASSERT(st_policy_apply_type_at(NULL, too_long, 2, 1, ST_TYPE_WORD) == NULL);
  const char *too_long_token[] = {"head", oversized};
  ASSERT(st_policy_apply_type_at(NULL, too_long_token, 2, 0, ST_TYPE_WORD) ==
         NULL);
  const char *too_many_tokens[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many_tokens) / sizeof(too_many_tokens[0]);
       i++)
    too_many_tokens[i] = "value";
  ASSERT(st_policy_apply_type_at(NULL, too_many_tokens,
                                 sizeof(too_many_tokens) /
                                     sizeof(too_many_tokens[0]),
                                 0, ST_TYPE_WORD) == NULL);

  const char *chain[] = {"docker", "run", "nginx"};
  char *step1 = st_policy_apply_type_at(NULL, chain, 3, 2, ST_TYPE_IMAGE);
  ASSERT(step1 != NULL);
  ASSERT_STR_EQ(step1, "docker run #image");
  const char *step1_tokens[] = {"docker", "run", "#image"};
  char *step2 = st_policy_apply_type_at(NULL, step1_tokens, 3, 1, ST_TYPE_OPT);
  ASSERT(step2 != NULL);
  ASSERT_STR_EQ(step2, "docker #opt #image");
  free(step1);
  free(step2);

  return 1;
}

int main(void) {
  atexit(cleanup_policy_temp_files);
  printf("Running policy unit tests...\n\n");

  printf("Lifecycle and mutation:\n");
  TEST(test_policy_mutation_lifecycle);

  printf("\nSerialisation:\n");
  TEST(test_policy_persistence_transitions);
  TEST(test_policy_load_read_failures_preserve_state);
  TEST(test_append_load_subsumption_failures_are_atomic);
  TEST(test_policy_save_determinism_and_compaction);
  TEST(test_policy_save_io_failures_are_atomic);
  TEST(test_policy_save_crash_boundaries);
  TEST(test_policy_save_recovery_ignores_stale_temps);
  TEST(test_policy_load_rejects_binary_and_overlong_lines);

  printf("\nEvaluation and suggestions:\n");
  TEST(test_evaluation_contract_matrix);
  TEST(test_isolated_subcommand_match_boundaries);
  TEST(test_invalid_inputs_clear_results);
  TEST(test_filter_wildcard_compatibility_matrix);
  TEST(test_prefilter_match_invariant_across_lifecycle);
  TEST(test_suggestion_contracts);
  TEST(test_branching_suggestions_are_lifecycle_independent);
  TEST(test_suggestion_render_allocation_failures);
  TEST(test_suggestion_byte_output_contract);

  printf("\nContext and validation:\n");
  TEST(test_context_and_compaction_transitions);
  TEST(test_context_allocation_failures_preserve_storage);
  TEST(test_context_and_policy_construction_failures);
  TEST(test_policy_contract_matrix);
  TEST(test_pattern_validation_matrix);

  printf("\nDiagnostics and suggestions:\n");
  TEST(test_statistics_transitions);
  TEST(test_dot_export);
  TEST(test_dry_run_simulate);

  printf("\nPolicy maintenance:\n");
  TEST(test_filter_rebuild_lazy_trigger);
  TEST(test_policy_clear);

  printf("\nLiteral and wildcard semantics:\n");
  TEST(test_literal_and_wildcard_semantics);

  printf("\nParametrized wildcard matching and subsumption:\n");
  TEST(test_param_match_matrix);
  TEST(test_param_subsumption_matrix);

  printf("\nParameter validation:\n");
  TEST(test_param_validation_matrix);

  printf("\nPolicy merge (st_policy_merge):\n");
  TEST(test_merge_matrix);
  TEST(test_merge_allocation_failures_preserve_destination);

  printf("\nPolicy diff (st_policy_diff):\n");
  TEST(test_netargv_view_policy_apis);
  TEST(test_compound_policy_binary_identity);
  TEST(test_policy_diff_visit_contract);
  TEST(test_diff_matrix_and_symmetry);
  TEST(test_diff_allocation_failures_clear_result);

  printf("\nIncremental subsumption:\n");
  TEST(test_incremental_subsumption_matrix);
  TEST(test_incr_stress);
  TEST(test_incremental_batch_remove_readd);
  TEST(test_batch_add_is_atomic);
  TEST(test_batch_add_allocation_failures_are_atomic);
  TEST(test_add_allocation_failures_are_atomic);

  printf("\nToken variant suggestion (st_policy_suggest_token_variants):\n");
  TEST(test_token_variant_matrix);

  printf("\nApply type at position (st_policy_apply_type_at):\n");
  TEST(test_apply_type_matrix);

  printf("\n========================================\n");
  printf("Results: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
