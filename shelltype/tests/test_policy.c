/* Policy: construction and evaluation of rule sets, the compact form, the
 * model-based transition checks, capacity boundaries and the caller's user
 * pointer. */
#define _POSIX_C_SOURCE 200809L
#include "../../tests/atomic_file_fixture.h"
#include "metadata.h"
#include "policy_ctx.h"
#include "shelltype.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_netargv.h"
#include "trie_internal.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* --- policy (from test_policy.c) --- */
/*
 * test_policy.c – Unit tests for the policy module.
 */

static int policy_tests_run = 0;
static int policy_tests_passed = 0;
static int policy_tests_failed = 0;
static char policy_policy_temp_paths[3][256];
static char policy_policy_save_directory[256];

static void policy_cleanup_policy_temp_files(void) {
  for (size_t i = 0; i < sizeof(policy_policy_temp_paths) /
                             sizeof(policy_policy_temp_paths[0]);
       i++) {
    if (policy_policy_temp_paths[i][0] != '\0') {
      (void)unlink(policy_policy_temp_paths[i]);
      policy_policy_temp_paths[i][0] = '\0';
    }
  }
  if (policy_policy_save_directory[0]) {
    char path[272];
    snprintf(path, sizeof(path), "%s/policy", policy_policy_save_directory);
    (void)test_atomic_temp_files(path, true);
    (void)rmdir(policy_policy_save_directory);
    policy_policy_save_directory[0] = '\0';
  }
}

#define TEST(name)                                                             \
  do {                                                                         \
    policy_tests_run++;                                                        \
    printf("  %-40s ", #name);                                                 \
    if (name()) {                                                              \
      policy_tests_passed++;                                                   \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      policy_tests_failed++;                                                   \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__);  \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)
#define ASSERT_STR_EQ(a, b)                                                    \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, \
             __LINE__);                                                        \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)
#define ASSERT_OK(expression) ASSERT((expression) == ST_OK)

static int policy_compare_netpattern_views(st_netpattern_view_t left,
                                           st_netpattern_view_t right) {
  size_t shared = left.length < right.length ? left.length : right.length;
  int compared = shared ? memcmp(left.data, right.data, shared) : 0;
  if (compared != 0)
    return compared;
  return left.length > right.length ? 1 : left.length < right.length ? -1 : 0;
}

static st_token_type_t policy_test_pattern_token_type(const char *token) {
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
  if (count > ST_MAX_CMD_TOKENS) {
    memset(out, 0, ST_MAX_TOKEN_VARIANTS * sizeof(*out));
    return 0;
  }
  for (size_t i = 0; i < count; i++)
    typed[i] = (st_token_t){.text = (char *)tokens[i],
                            .type = policy_test_pattern_token_type(tokens[i])};
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
                            .type = policy_test_pattern_token_type(tokens[i])};
  }
  st_netpattern_t pattern = {0};
  st_netpattern_t changed = {0};
  char *cpl = NULL;
  if (st_netpattern_encode_owned(typed, count, &pattern) != ST_OK ||
      st_netpattern_apply_type_at_owned(
          (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
          edit_pos, new_type, &changed) != ST_OK ||
      st_netpattern_to_cpl_view(
          (st_netpattern_view_t){(const char *)changed.data, changed.length},
          &cpl) != ST_OK) {
    free(cpl);
    cpl = NULL;
  }
  st_netpattern_free(&changed);
  st_netpattern_free(&pattern);
  return cpl;
}

static int policy_policy_matches(st_policy_t *policy, const char *command,
                                 bool expected) {
  st_eval_result_t result = {0};
  return test_st_policy_eval(policy, command, &result) == ST_OK &&
         result.matches == expected;
}

static int policy_policy_eval_is(st_policy_t *policy, const char *command,
                                 const char *expected);

static int policy_suggestion_is(const st_expand_suggestion_t *suggestion,
                                const char *pattern, const char *based_on,
                                double confidence) {
  int matches =
      test_pattern_is_cpl((st_netpattern_view_t){suggestion->pattern,
                                                 suggestion->pattern_length},
                          pattern) &&
      ((suggestion->based_on == NULL && based_on == NULL) ||
       (suggestion->based_on != NULL && based_on != NULL &&
        test_pattern_is_cpl((st_netpattern_view_t){suggestion->based_on,
                                                   suggestion->based_on_length},
                            based_on))) &&
      suggestion->confidence == confidence;
  if (!matches)
    printf("    suggestion actual={%s, %s, %.17g} expected={%s, %s, %.17g}\n",
           suggestion->pattern,
           suggestion->based_on ? suggestion->based_on : "(null)",
           suggestion->confidence, pattern, based_on ? based_on : "(null)",
           confidence);
  return matches;
}

/* --- SERIALIZATION --- */

/* The bytes in use never exceed the bytes allocated: adding a pattern grows
 * child arrays, and removing it leaves their blocks and states in the arena
 * until compaction, so the working set counts entries, not their slots. */
static int policy_test_working_set_never_exceeds_memory(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(ctx && policy);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);
  ASSERT(test_st_policy_add(policy, "docker ps") == ST_OK);
  for (int i = 0; i < 2000; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "temporary%d value", i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
    ASSERT(st_policy_working_set(policy) <= st_policy_memory_usage(policy));
    ASSERT(test_st_policy_remove(policy, pattern) == ST_OK);
    ASSERT(st_policy_working_set(policy) <= st_policy_memory_usage(policy));
  }
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_test_policy_persistence_transitions(void) {
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
  snprintf(policy_policy_temp_paths[0], sizeof(policy_policy_temp_paths[0]),
           "%s", path);
  ASSERT(close(fd) == 0);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *source = st_policy_new(ctx);
  st_policy_t *loaded = st_policy_new(ctx);
  st_policy_t *empty = st_policy_new(ctx);
  ASSERT(ctx && source && loaded && empty);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(source, patterns[i]) == ST_OK);
  st_netpattern_t framed_pattern = {0};
  ASSERT(st_netpattern_from_cpl_owned("printf \"\" \"line\\nfeed\"",
                                      &framed_pattern) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             source, (st_netpattern_view_t){framed_pattern.data,
                                            framed_pattern.length}) == ST_OK);
  st_netpattern_free(&framed_pattern);
  for (int i = 0; i < 50; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "cmd%d arg%d *", i, i);
    ASSERT(test_st_policy_add(source, pattern) == ST_OK);
  }
  const size_t source_count = sizeof(patterns) / sizeof(patterns[0]) + 51;
  ASSERT(st_policy_rule_count(source) == source_count);

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
      ASSERT(policy_policy_matches(loaded, "preserve value", true));
      ASSERT(!policy_policy_matches(loaded, "git", true));
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
  ASSERT(policy_policy_matches(loaded, "docker run image", true));
  ASSERT(st_policy_save(source, path) == ST_OK);

  rewrite = fopen(path, "a");
  ASSERT(rewrite != NULL);
  ASSERT(fputs("trailing data\n", rewrite) >= 0);
  ASSERT(fclose(rewrite) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(loaded) == 1);
  ASSERT(policy_policy_matches(loaded, "docker run image", true));
  ASSERT(st_policy_save(source, path) == ST_OK);

  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count + 1);
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_policy_matches(loaded, probes[i], true));
  ASSERT(policy_policy_matches(loaded, "docker run image", true));

  /* Appending the same model is idempotent; replacing drops old entries. */
  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count + 1);
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(st_policy_rule_count(loaded) == source_count);
  ASSERT(policy_policy_matches(loaded, "docker run image", false));

  FILE *bad = fopen(path, "w");
  ASSERT(bad != NULL);
  ASSERT(fprintf(bad, "# CPL v1\n# patterns: 1\nunknown *\n"
                      "# CRC32: deadbeef\n") > 0);
  ASSERT(fclose(bad) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(loaded) == source_count);
  ASSERT(policy_policy_matches(loaded, "docker run image", false));
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_policy_matches(loaded, probes[i], true));

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

static int policy_test_policy_load_read_failures_preserve_state(void) {
  char path[] = "/tmp/shelltype-policy-read-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_policy_temp_paths[0], sizeof(policy_policy_temp_paths[0]),
           "%s", path);
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
      ASSERT(policy_policy_matches(policy, "preserve value", true));
      ASSERT(policy_policy_matches(policy, "replacement 42", false));
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
    ASSERT(policy_policy_matches(policy, "preserve value", true));
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }

  st_policy_free(source);
  st_policy_ctx_release(source_context);
  ASSERT(unlink(path) == 0);
  policy_policy_temp_paths[0][0] = '\0';
  return 1;
}

static int policy_test_append_load_subsumption_failures_are_atomic(void) {
  char path[] = "/tmp/shelltype-policy-append-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_policy_temp_paths[0], sizeof(policy_policy_temp_paths[0]),
           "%s", path);
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
  ASSERT(policy_policy_eval_is(probe, "copy /tmp/a", "copy #path"));
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
      ASSERT(policy_policy_eval_is(policy, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_policy_eval_is(policy, "copy /tmp/b", "copy /tmp/b"));
      ASSERT(policy_policy_eval_is(policy, "incoming 7", NULL));
    } else {
      ASSERT(error == ST_OK);
      ASSERT(st_policy_rule_count(policy) == 3);
      ASSERT(policy_policy_eval_is(policy, "copy /tmp/a", "copy #path"));
      ASSERT(policy_policy_eval_is(policy, "incoming 7", "incoming #n"));
    }
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
  ASSERT(observed_failure);
  st_policy_free(source);
  st_policy_ctx_release(source_context);
  ASSERT(unlink(path) == 0);
  policy_policy_temp_paths[0][0] = '\0';
  return 1;
}

static int policy_test_policy_load_rejects_binary_and_overlong_lines(void) {
  char path[] = "/tmp/shelltype-policy-load-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(policy_policy_temp_paths[0], sizeof(policy_policy_temp_paths[0]),
           "%s", path);

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
  ASSERT(policy_policy_matches(policy, "preserve value", true));

  static const char *const malformed_v3[] = {"01:x,\n", "3:ab,\n"};
  for (size_t i = 0; i < sizeof(malformed_v3) / sizeof(malformed_v3[0]); i++) {
    fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    ASSERT(fputs("# shelltype-policy v3\n# patterns: 1\n", fp) >= 0);
    ASSERT(fputs(malformed_v3[i], fp) >= 0);
    ASSERT(fclose(fp) == 0);
    ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT(policy_policy_matches(policy, "preserve value", true));
  }

  static const unsigned char nul_v3[] =
      "# shelltype-policy v3\n# patterns: 1\n3:a\0b,\n";
  fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fwrite(nul_v3, 1, sizeof(nul_v3) - 1, fp) == sizeof(nul_v3) - 1);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_policy_matches(policy, "preserve value", true));

  fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fputs("# CPL v1\n# patterns: 1\n", fp) >= 0);
  for (size_t i = 0; i < 4096; i++)
    ASSERT(fputc('a', fp) != EOF);
  ASSERT(fputs("\n# CRC32: 00000000\n", fp) >= 0);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_policy_load(policy, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_policy_matches(policy, "preserve value", true));

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  ASSERT(unlink(path) == 0);
  policy_policy_temp_paths[0][0] = '\0';
  return 1;
}

/* Basic evaluation outcomes share one contract: non-matches and empty input
 * are successful evaluations, while the result pointer is optional. */
static int policy_test_evaluation_contract_matrix(void) {
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

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_test_invalid_inputs_clear_results(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  const st_netargv_view_t inputs[] = {
      {.data = NULL, .length = 1},
      {.data = "01:x,", .length = 5},
      {.data = "2:x,", .length = 4},
  };
  for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
    st_eval_result_t result = {.matches = true,
                               .matching_pattern = (const char *)1,
                               .suggestion_count = 2,
                               .suggestion_error = ST_ERR_FAILED};
    ASSERT(st_policy_eval_view(policy, inputs[i], &result) != ST_OK);
    ASSERT(!result.matches && result.matching_pattern == NULL &&
           result.suggestion_count == 0 && result.suggestion_error == ST_OK);
  }
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_test_suggestion_contracts(void) {
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
  ASSERT(policy_suggestion_is(&result.suggestions[0],
                              "docker exec -it container",
                              "docker run --rm alpine", 0.25));
  ASSERT(policy_suggestion_is(&result.suggestions[1],
                              "docker exec #sopt container", NULL, 0.25));

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
    ASSERT(policy_suggestion_is(&variants[0], exact, NULL, 1.0));
    if (variant_cases[i].wider_pattern)
      ASSERT(policy_suggestion_is(&variants[1], variant_cases[i].wider_pattern,
                                  NULL, 1.0));
    if (variant_cases[i].wider_pattern) {
      st_token_array_t decoded = {0};
      ASSERT(st_netpattern_decode_view(
                 (st_netpattern_view_t){variants[1].pattern,
                                        variants[1].pattern_length},
                 &decoded) == ST_OK);
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

  ASSERT(st_policy_suggest_variants(policy, tokens, 0, variants) == 0);

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

  st_netpattern_t quoted_pattern = {0};
  st_token_array_t quoted_space = {0};
  ASSERT(st_netpattern_from_cpl_owned("echo \"two words\"", &quoted_pattern) ==
         ST_OK);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){(const char *)quoted_pattern.data,
                                    quoted_pattern.length},
             &quoted_space) == ST_OK);
  ASSERT(quoted_space.count == 2 &&
         quoted_space.tokens[1].type == ST_TYPE_LITERAL);
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_variants(policy, quoted_space.tokens,
                                    quoted_space.count, variants) == 1);
  st_token_array_t exact = {0};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){variants[0].pattern,
                                    variants[0].pattern_length},
             &exact) == ST_OK);
  ASSERT(exact.count == 2 && strcmp(exact.tokens[1].text, "two words") == 0);
  st_token_array_free(&exact);
  st_token_array_free(&quoted_space);
  st_netpattern_free(&quoted_pattern);

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

static int policy_test_context_and_compaction_transitions(void) {
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
  ASSERT(st_policy_ctx_intern_view(defaulted, "zero-arena",
                                   (sizeof("zero-arena") - 1)) != NULL);
  st_policy_ctx_release(defaulted);

  ASSERT(strcmp(st_policy_ctx_intern_view(ctx, NULL, 0), "") == 0);
  ASSERT(strcmp(st_policy_ctx_intern_view(ctx, "", (sizeof("") - 1)), "") == 0);
  const char *first =
      st_policy_ctx_intern_view(ctx, "shared", (sizeof("shared") - 1));
  ASSERT(first != NULL && st_policy_ctx_intern_view(
                              ctx, "shared", (sizeof("shared") - 1)) == first);

  char before_growth[701];
  char forces_growth[2001];
  memset(before_growth, 'a', sizeof(before_growth) - 1);
  before_growth[sizeof(before_growth) - 1] = '\0';
  memset(forces_growth, 'b', sizeof(forces_growth) - 1);
  forces_growth[sizeof(forces_growth) - 1] = '\0';
  const char *stable =
      st_policy_ctx_intern_view(ctx, before_growth, strlen(before_growth));
  ASSERT(stable != NULL);
  ASSERT(st_policy_ctx_intern_view(ctx, forces_growth, strlen(forces_growth)) !=
         NULL);
  ASSERT(strcmp(stable, before_growth) == 0);
  ASSERT(st_policy_ctx_intern_view(ctx, before_growth, strlen(before_growth)) ==
         stable);

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
  ASSERT(policy_policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_policy_matches(p2, "docker ps", true));

  st_policy_free(p2);
  ASSERT(st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_compact(p1) == ST_OK);
  ASSERT(st_policy_rule_count(p1) == 3);
  ASSERT(policy_policy_matches(p1, "git status", true));
  ASSERT(policy_policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_policy_matches(p1, "ls -la", true));

  st_policy_free(p1);
  ASSERT(!st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  const char *second =
      st_policy_ctx_intern_view(ctx, "reused", (sizeof("reused") - 1));
  ASSERT(second != NULL && strcmp(second, "reused") == 0);
  p1 = st_policy_new(ctx);
  ASSERT(p1 != NULL);
  ASSERT(test_st_policy_add(p1, "new policy") == ST_OK);
  ASSERT(policy_policy_matches(p1, "new policy", true));
  st_policy_free(p1);
  st_policy_ctx_release(ctx);
  ASSERT(st_policy_ctx_new_with_arena(SIZE_MAX) == NULL);
  return 1;
}

static int policy_test_context_allocation_failures_preserve_storage(void) {
  st_test_alloc_reset();
  st_policy_ctx_t *probe = st_policy_ctx_new();
  ASSERT(probe != NULL);
  for (size_t i = 0; i < 768; i++) {
    char value[32];
    snprintf(value, sizeof(value), "probe-%zu", i);
    ASSERT(st_policy_ctx_intern_view(probe, value, strlen(value)) != NULL);
  }
  st_test_alloc_reset();
  char growth_value[2048];
  memset(growth_value, 'g', sizeof(growth_value) - 1);
  growth_value[sizeof(growth_value) - 1] = '\0';
  ASSERT(st_policy_ctx_intern_view(probe, growth_value, strlen(growth_value)) !=
         NULL);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_policy_ctx_release(probe);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    ASSERT(ctx != NULL);
    const char *stable = st_policy_ctx_intern_view(
        ctx, "stable-value", (sizeof("stable-value") - 1));
    ASSERT(stable != NULL);
    for (size_t i = 1; i < 768; i++) {
      char value[32];
      snprintf(value, sizeof(value), "intern-%zu", i);
      ASSERT(st_policy_ctx_intern_view(ctx, value, strlen(value)) != NULL);
    }
    st_test_alloc_fail_at(fail_at);
    const char *grown = st_policy_ctx_intern_view(
        ctx, "triggers-pool-growth", (sizeof("triggers-pool-growth") - 1));
    st_test_alloc_reset();
    ASSERT(grown == NULL);
    ASSERT(strcmp(stable, "stable-value") == 0);
    ASSERT(st_policy_ctx_intern_view(ctx, "stable-value",
                                     (sizeof("stable-value") - 1)) == stable);
    ASSERT(st_policy_ctx_intern_view(ctx, "after-failure",
                                     (sizeof("after-failure") - 1)) != NULL);
    st_policy_ctx_release(ctx);
  }

  st_test_alloc_reset();
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  const char *stable = st_policy_ctx_intern_view(ctx, "reset-stable",
                                                 (sizeof("reset-stable") - 1));
  ASSERT(stable != NULL);
  st_test_alloc_fail_at(1);
  ASSERT(st_policy_ctx_reset(ctx) == ST_ERR_MEMORY);
  st_test_alloc_reset();
  ASSERT(strcmp(stable, "reset-stable") == 0);
  ASSERT(st_policy_ctx_intern_view(ctx, "reset-stable",
                                   (sizeof("reset-stable") - 1)) == stable);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_test_policy_contract_matrix(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(ctx != NULL && policy != NULL);
  ASSERT(test_st_policy_remove(policy, "missing") == ST_OK);

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

static int policy_test_pattern_validation_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t error;
    const char *probe;
  } cases[] = {{"", ST_ERR_INVALID, NULL},
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
    if (cases[i].probe &&
        !policy_policy_matches(policy, cases[i].probe, true)) {
      printf("  validation case %zu did not match probe '%s'\n", i,
             cases[i].probe);
      return 0;
    }
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }

  /* Validation transfers exact decoded tokens, and failures leave the
   * caller's empty output unchanged. */
  st_token_array_t info = {0};
  ASSERT(test_st_validate_pattern("cat #size.MiB", &info) == ST_OK);
  ASSERT(info.count == 2);
  ASSERT_STR_EQ(info.tokens[0].text, "cat");
  ASSERT(info.tokens[0].type == ST_TYPE_LITERAL);
  ASSERT_STR_EQ(info.tokens[1].text, "#size.MiB");
  ASSERT(info.tokens[1].type == ST_TYPE_SIZE);
  st_token_array_free(&info);
  ASSERT(test_st_validate_pattern("dd #size.XX", &info) == ST_ERR_INVALID);
  ASSERT(info.count == 0 && info.tokens == NULL);

  char too_long[ST_MAX_NETPATTERN_LEN + 1];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  ASSERT(test_st_validate_pattern(too_long, &info) == ST_ERR_INVALID);
  ASSERT(info.count == 0 && info.tokens == NULL);
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
  ASSERT(policy_policy_matches(limit_policy, "preserved pattern", true));
  ASSERT(policy_policy_matches(limit_policy, "new pattern", false));
  st_policy_free(limit_policy);
  st_policy_ctx_release(limit_ctx);

  return 1;
}

/* DOT export format and escaping contract. */
static int policy_test_dot_export(void) {
  char path[] = "/tmp/shelltype-policy-dot-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(policy_policy_temp_paths[1], sizeof(policy_policy_temp_paths[1]),
           "%s", path);
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
             policy,
             (st_netpattern_view_t){.data = (const char *)binary_pattern.data,
                                    .length = binary_pattern.length}) == ST_OK);

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
static int policy_test_dry_run_simulate(void) {
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
    st_netpattern_view_t conflict = {0};
    st_netpattern_t proposal = {0};
    ASSERT(st_netpattern_from_cpl_owned(cases[i].proposal, &proposal) == ST_OK);
    ASSERT(st_policy_simulate_add_netpattern_view(
               policy,
               (st_netpattern_view_t){(const char *)proposal.data,
                                      proposal.length},
               &redundant, &conflict) == ST_OK);
    st_netpattern_free(&proposal);
    ASSERT(redundant == cases[i].redundant);
    ASSERT((!conflict.data && !cases[i].conflict) ||
           (conflict.data && cases[i].conflict &&
            test_pattern_is_cpl(conflict, cases[i].conflict)));
  }

  bool redundant_without_conflict = false;
  st_netpattern_t proposal = {0};
  ASSERT(st_netpattern_from_cpl_owned("git status", &proposal) == ST_OK);
  ASSERT(
      st_policy_simulate_add_netpattern_view(
          policy,
          (st_netpattern_view_t){(const char *)proposal.data, proposal.length},
          &redundant_without_conflict, NULL) == ST_OK);
  ASSERT(!redundant_without_conflict);

  bool redundant = true;
  st_netpattern_view_t conflict = {0};
  ASSERT(st_policy_simulate_add_netpattern_view(
             policy, (st_netpattern_view_t){"", sizeof("") - 1}, &redundant,
             &conflict) == ST_ERR_FORMAT);
  ASSERT(!redundant && conflict.data == NULL && conflict.length == 0);

  ASSERT(conflict.data == NULL);
  st_netpattern_free(&proposal);

  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

/* --- CONCURRENCY AND ATOMIC TESTS --- */

static int policy_test_statistics_transitions(void) {
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

static int policy_policy_eval_is(st_policy_t *policy, const char *command,
                                 const char *expected) {
  st_eval_result_t result;
  if (test_st_policy_eval(policy, command, &result) != ST_OK ||
      result.matches != (expected != NULL))
    return 0;
  return expected
             ? result.matching_pattern &&
                   test_pattern_is_cpl(
                       (st_netpattern_view_t){result.matching_pattern,
                                              result.matching_pattern_length},
                       expected)
             : result.matching_pattern == NULL;
}

/* Subsumption for parametrized types. */
static int policy_test_param_subsumption_matrix(void) {
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
    ASSERT(test_pattern_is_cpl(
        (st_netpattern_view_t){result.matching_pattern,
                               result.matching_pattern_length},
        cases[i].generic));
    ASSERT_OK(test_st_policy_remove(policy, cases[i].specific));
    ASSERT(st_policy_rule_count(policy) == 1);
    ASSERT(policy_policy_eval_is(policy, cases[i].probe, cases[i].generic));
    st_policy_free(policy);
  }
  st_token_array_t alias_info = {0};
  ASSERT(test_st_validate_pattern("container #uuid.5", &alias_info) == ST_OK);
  ASSERT_STR_EQ(alias_info.tokens[1].text, "#uuid.v5");
  st_token_array_free(&alias_info);
  st_policy_t *alias_policy = st_policy_new(ctx);
  ASSERT(alias_policy != NULL);
  ASSERT_OK(test_st_policy_add(alias_policy, "container #uuid.5"));
  ASSERT(policy_policy_eval_is(alias_policy,
                               "container 4be33a94-0c5b-5516-a922-d07dedd59172",
                               "container #uuid.v5"));
  st_policy_free(alias_policy);

  st_policy_t *sizes = st_policy_new(ctx);
  ASSERT(sizes != NULL);
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size.MiB}"));
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size.G}"));
  ASSERT_OK(st_policy_compact(sizes));
  ASSERT(st_policy_rule_count(sizes) == 2);
  ASSERT(policy_policy_eval_is(sizes, "dd bs=10MiB", "dd bs={#size.MiB}"));
  ASSERT(policy_policy_eval_is(sizes, "dd bs=2G", "dd bs={#size.G}"));
  ASSERT(policy_policy_eval_is(sizes, "dd bs=10K", NULL));
  ASSERT_OK(test_st_policy_add(sizes, "dd bs={#size}"));
  ASSERT(st_policy_rule_count(sizes) == 1);
  ASSERT(policy_policy_eval_is(sizes, "dd bs=10K", "dd bs={#size}"));
  st_policy_free(sizes);

  st_policy_t *compound = st_policy_new(ctx);
  ASSERT(compound != NULL);
  ASSERT_OK(test_st_policy_add(compound, "tool --output={#path}"));
  ASSERT(policy_policy_eval_is(compound, "tool --output=/tmp/result",
                               "tool --output={#path}"));
  ASSERT(policy_policy_eval_is(compound, "tool '--output=/tmp/a b'",
                               "tool --output={#path}"));
  ASSERT(policy_policy_eval_is(compound, "tool --output= /tmp/result", NULL));
  ASSERT(policy_policy_eval_is(compound, "tool --output /tmp/result", NULL));
  ASSERT(policy_policy_eval_is(compound, "tool '--output=#path'", NULL));
  st_policy_free(compound);

  st_policy_t *coexisting = st_policy_new(ctx);
  ASSERT(coexisting != NULL);
  ASSERT_OK(test_st_policy_add(coexisting, "container #uuid.v4"));
  ASSERT_OK(test_st_policy_add(coexisting, "container #uuid.v5"));
  ASSERT(st_policy_rule_count(coexisting) == 2);
  ASSERT(policy_policy_eval_is(coexisting,
                               "container 550e8400-e29b-41d4-a716-446655440000",
                               "container #uuid.v4"));
  ASSERT(policy_policy_eval_is(coexisting,
                               "container 4be33a94-0c5b-5516-a922-d07dedd59172",
                               "container #uuid.v5"));
  ASSERT(policy_policy_eval_is(
      coexisting, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", NULL));
  st_policy_free(coexisting);
  st_policy_ctx_release(ctx);
  return 1;
}

/* Matching behavior for all parametrized policy types. */

/* Parameter validation. */

/* --- POLICY MERGE (st_policy_merge) --- */

static int policy_add_patterns(st_policy_t *policy, const char *const *patterns,
                               size_t count) {
  for (size_t i = 0; i < count; i++)
    if (test_st_policy_add(policy, patterns[i]) != ST_OK)
      return 0;
  return 1;
}

static int policy_test_merge_allocation_failures_preserve_destination(void) {
  const char *destination_patterns[] = {"copy /tmp/a", "copy /tmp/b",
                                        "keep command"};
  const char *source_patterns[] = {"copy #path", "merge #n"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_dst_ctx = st_policy_ctx_new();
  st_policy_ctx_t *probe_src_ctx = st_policy_ctx_new();
  st_policy_t *probe_dst = st_policy_new(probe_dst_ctx);
  st_policy_t *probe_src = st_policy_new(probe_src_ctx);
  ASSERT(probe_dst_ctx && probe_src_ctx && probe_dst && probe_src);
  ASSERT(policy_add_patterns(probe_dst, destination_patterns, 3));
  ASSERT(policy_add_patterns(probe_src, source_patterns, 2));
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
    ASSERT(policy_add_patterns(dst, destination_patterns, 3));
    ASSERT(policy_add_patterns(src, source_patterns, 2));
    st_test_alloc_fail_at(fail_at);
    st_error_t err = st_policy_merge(dst, src);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(st_policy_rule_count(dst) == 3);
      ASSERT(policy_policy_matches(dst, "keep command", true));
      ASSERT(policy_policy_eval_is(dst, "copy /tmp/a", "copy /tmp/a"));
      ASSERT(policy_policy_eval_is(dst, "copy /tmp/b", "copy /tmp/b"));
      ASSERT(policy_policy_matches(dst, "merge 7", false));
    } else {
      ASSERT(err == ST_OK);
      ASSERT(st_policy_rule_count(dst) == 3);
      ASSERT(policy_policy_eval_is(dst, "copy /tmp/a", "copy #path"));
      ASSERT(policy_policy_matches(dst, "merge 7", true));
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

static int policy_string_set_is(const st_netpattern_t *actual,
                                size_t actual_count,
                                const char *const *expected,
                                size_t expected_count) {
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
      if (test_pattern_is_cpl(
              (st_netpattern_view_t){actual[j].data, actual[j].length},
              expected[i])) {
        found = 1;
        break;
      }
    if (!found)
      return 0;
  }
  return 1;
}

static bool policy_count_policy_match(st_netpattern_view_t pattern,
                                      void *user_ctx) {
  size_t *count = user_ctx;
  return pattern.data && count && (++*count, true);
}

/* Compound policy entries are keyed by their canonical component boundaries,
 * not only their flattened display text. All matching and removal paths must
 * retain arbitrary bytes in the literal affixes. */
static int policy_test_compound_policy_binary_identity(void) {
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
             policy,
             (st_netpattern_view_t){.data = (const char *)binary_pattern.data,
                                    .length = binary_pattern.length}) == ST_OK);

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
             policy_count_policy_match, &visited, &visited) == ST_OK &&
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
             (st_netpattern_view_t){.data = (const char *)pattern_b.data,
                                    .length = pattern_b.length},
             &decoded_collision) == ST_OK);
  st_token_array_free(&decoded_collision);
  ASSERT(
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){.data = (const char *)pattern_a.data,
                                         .length = pattern_a.length}) == ST_OK);
  ASSERT(
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){.data = (const char *)pattern_b.data,
                                         .length = pattern_b.length}) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);

  shell_netstring_buffer_t command_a = test_netargv("cmd a42{#n}x");
  shell_netstring_buffer_t command_b = test_netargv("cmd 'a{#n}42x'");
  ASSERT(command_a.data != NULL && command_b.data != NULL);
  st_eval_result_t eval = {0};
  ASSERT(st_policy_eval_view(
             policy,
             (st_netargv_view_t){.data = (const char *)command_a.data,
                                 .length = command_a.length},
             &eval) == ST_OK &&
         eval.matches && eval.matching_pattern_length == pattern_a.length &&
         memcmp(eval.matching_pattern, pattern_a.data, pattern_a.length) == 0);
  ASSERT(st_policy_eval_view(
             policy,
             (st_netargv_view_t){.data = (const char *)command_b.data,
                                 .length = command_b.length},
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
                         .data = (const char *)overlap_pattern_a.data,
                         .length = overlap_pattern_a.length}) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = (const char *)overlap_pattern_b.data,
                         .length = overlap_pattern_b.length}) == ST_OK);
  shell_netstring_buffer_t overlap_command = test_netargv("cmd 'a{*}{*}x'");
  ASSERT(overlap_command.data != NULL);
  all = NULL;
  all_count = 0;
  ASSERT(st_policy_verify_all_view(
             policy,
             (st_netargv_view_t){.data = (const char *)overlap_command.data,
                                 .length = overlap_command.length},
             &all, &all_count) == ST_OK &&
         all_count == 2);
  st_policy_matches_free(all);
  visited = 0;
  ASSERT(st_policy_visit_matches_view(
             policy,
             (st_netargv_view_t){.data = (const char *)overlap_command.data,
                                 .length = overlap_command.length},
             policy_count_policy_match, &visited, &visited) == ST_OK &&
         visited == 2);
  const st_netpattern_t *preferred =
      policy_compare_netpattern_views(
          (st_netpattern_view_t){.data = (const char *)overlap_pattern_a.data,
                                 .length = overlap_pattern_a.length},
          (st_netpattern_view_t){.data = (const char *)overlap_pattern_b.data,
                                 .length = overlap_pattern_b.length}) < 0
          ? &overlap_pattern_a
          : &overlap_pattern_b;
  ASSERT(st_policy_eval_view(
             policy,
             (st_netargv_view_t){.data = (const char *)overlap_command.data,
                                 .length = overlap_command.length},
             &eval) == ST_OK &&
         eval.matches && eval.matching_pattern_length == preferred->length &&
         memcmp(eval.matching_pattern, preferred->data, preferred->length) ==
             0);
  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = (const char *)overlap_pattern_a.data,
                         .length = overlap_pattern_a.length}) == ST_OK);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = (const char *)overlap_command.data,
                                 .length = overlap_command.length},
             &matches) == ST_OK &&
         matches);
  ASSERT(st_policy_remove_netpattern_view(
             policy, (st_netpattern_view_t){
                         .data = (const char *)overlap_pattern_b.data,
                         .length = overlap_pattern_b.length}) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);
  shell_netstring_buffer_free(&overlap_command);
  st_netpattern_free(&overlap_pattern_b);
  st_netpattern_free(&overlap_pattern_a);

  ASSERT(
      st_policy_remove_netpattern_view(
          policy, (st_netpattern_view_t){.data = (const char *)pattern_a.data,
                                         .length = pattern_a.length}) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 2);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = (const char *)command_a.data,
                                 .length = command_a.length},
             &matches) == ST_OK &&
         !matches);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){.data = (const char *)command_b.data,
                                 .length = command_b.length},
             &matches) == ST_OK &&
         matches);

  shell_netstring_buffer_free(&command_a);
  shell_netstring_buffer_free(&command_b);
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
} policy_diff_visit_expect_t;

static int policy_test_diff_matrix_and_symmetry(void) {
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
    ASSERT(policy_add_patterns(left, cases[i].left, cases[i].left_count));
    ASSERT(policy_add_patterns(right, cases[i].right, cases[i].right_count));

    st_policy_diff_t forward = {0};
    ASSERT(st_policy_diff(left, right, &forward) == ST_OK);
    ASSERT(policy_string_set_is(forward.added, forward.added_count,
                                cases[i].added, cases[i].added_count));
    ASSERT(policy_string_set_is(forward.removed, forward.removed_count,
                                cases[i].removed, cases[i].removed_count));
    st_policy_diff_free(&forward);

    st_policy_diff_t reverse = {0};
    ASSERT(st_policy_diff(right, left, &reverse) == ST_OK);
    ASSERT(policy_string_set_is(reverse.added, reverse.added_count,
                                cases[i].removed, cases[i].removed_count));
    ASSERT(policy_string_set_is(reverse.removed, reverse.removed_count,
                                cases[i].added, cases[i].added_count));
    st_policy_diff_free(&reverse);

    if (i == 1) {
      st_policy_diff_t identity = {0};
      ASSERT(st_policy_diff(left, left, &identity) == ST_OK);
      ASSERT(identity.added_count == 0 && identity.removed_count == 0);
      st_policy_diff_free(&identity);

      st_policy_diff_t reused = {0};
      ASSERT(st_policy_diff(left, right, &reused) == ST_OK);
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

static int policy_test_diff_allocation_failures_clear_result(void) {
  const char *left_patterns[] = {"git status", "cat #path", "head -n #n"};
  const char *right_patterns[] = {"git status", "ls", "echo *"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_left_context = st_policy_ctx_new();
  st_policy_ctx_t *probe_right_context = st_policy_ctx_new();
  st_policy_t *probe_left = st_policy_new(probe_left_context);
  st_policy_t *probe_right = st_policy_new(probe_right_context);
  ASSERT(probe_left_context && probe_right_context && probe_left &&
         probe_right);
  ASSERT(policy_add_patterns(probe_left, left_patterns, 3));
  ASSERT(policy_add_patterns(probe_right, right_patterns, 3));
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
    ASSERT(policy_add_patterns(left, left_patterns, 3));
    ASSERT(policy_add_patterns(right, right_patterns, 3));

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

static int policy_test_batch_add_is_atomic(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  ASSERT(policy != NULL);
  ASSERT(test_st_policy_add(policy, "git status") == ST_OK);

  ASSERT(test_st_policy_batch_add(policy, NULL, 0) == ST_ERR_INVALID);
  ASSERT(test_st_policy_batch_add(policy, NULL, 1) == ST_ERR_INVALID);

  const char *invalid_middle[] = {"docker ps", "", "ls -la"};
  ASSERT(test_st_policy_batch_add(policy, invalid_middle, 3) == ST_ERR_INVALID);
  /* A NULL record is malformed batch data at the canonical batch boundary,
   * not a valid CPL string to pass through the conversion helper. */
  st_netpattern_t first = {0};
  st_netpattern_t last = {0};
  ASSERT(st_netpattern_from_cpl_owned("docker ps", &first) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("ls -la", &last) == ST_OK);
  const st_netpattern_view_t null_record[] = {
      {first.data, first.length}, {0}, {last.data, last.length}};
  st_error_t null_error =
      st_policy_batch_add_netpattern_views(policy, null_record, 3);
  st_netpattern_free(&first);
  st_netpattern_free(&last);
  ASSERT(null_error == ST_ERR_INVALID);
  ASSERT(st_policy_rule_count(policy) == 1);
  ASSERT(policy_policy_eval_is(policy, "git status", "git status"));
  ASSERT(policy_policy_eval_is(policy, "docker ps", NULL));
  ASSERT(policy_policy_eval_is(policy, "ls -la", NULL));

  const char *valid[] = {"docker ps", "git status", "cat #path"};
  ASSERT(test_st_policy_batch_add(policy, valid, 3) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 3);
  ASSERT(policy_policy_eval_is(policy, "docker ps", "docker ps"));
  ASSERT(policy_policy_eval_is(policy, "cat /tmp/input", "cat #path"));

  ASSERT(test_st_policy_batch_add(policy, valid, 0) == ST_ERR_INVALID);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;
}

static int policy_variants_match(st_learner_t *learner, const char **tokens,
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
        strcmp(variants[i].type_symbol, st_type_symbol[expected[i]]) != 0) {
      printf("    variant %zu: got %d (%s), expected %d (%s)\n", i,
             variants[i].type,
             variants[i].type_symbol ? variants[i].type_symbol : "NULL",
             expected[i], st_type_symbol[expected[i]]);
      return 0;
    }
  }
  return 1;
}

static int policy_test_variant_queries_are_allocation_free(void) {
  static const struct {
    const char *cpl;
    size_t position, count;
  } cases[] = {
      {"cmd #n", 1, 2},
      {"tool pre{#n}post", 1, 3},
      {"tool pre{#n}post #val", 2, 2},
      {"tool * #val", 2, 4},
      {"tool /tmp/a #val", 2, 2},
      {"tool #size.MiB #val", 2, 2},
      {"tool #duration.ms #val", 2, 2},
      {"tool #uuid.v4 #val", 2, 2},
      {"tool #semver.major #val", 2, 2},
      {"tool #semver.minor #val", 2, 2},
      {"tool #semver.patch #val", 2, 2},
      {"tool #semver.* #val", 2, 2},
      {"tool #ts.date #val", 2, 2},
      {"tool #ts.datetime #val", 2, 2},
      {"tool tag={#ts.datetime}post #val", 2, 2},
      {"tool #sha.short #val", 2, 2},
      {"tool #fp.md5 #val", 2, 2},
      {"tool #range.step #val", 2, 2},
      {"tool #perm.bits #val", 2, 2},
      {"tool \"pre\\x00\"{#n}\"\\x00post\" #val", 2, 2},
  };
  st_learner_t *learner = st_learner_new(NULL);
  ASSERT(learner != NULL);
  ASSERT(st_learner_feed_netargv_view(
             learner,
             (st_netargv_view_t){"4:tool,9:pre42post,6:/tmp/x,",
                                 sizeof("4:tool,9:pre42post,6:/tmp/x,") - 1}) ==
         ST_OK);
  ASSERT(st_learner_feed_netargv_view(
             learner,
             (st_netargv_view_t){"4:tool,10:preHUPpost,8:../rel/x,",
                                 sizeof("4:tool,10:preHUPpost,8:../rel/x,") -
                                     1}) == ST_OK);
  ASSERT(st_learner_feed_netargv_view(
             learner, (st_netargv_view_t){"4:tool,6:/tmp/a,2:42,",
                                          sizeof("4:tool,6:/tmp/a,2:42,") -
                                              1}) == ST_OK);
  ASSERT(st_learner_feed_netargv_view(
             learner, (st_netargv_view_t){"4:tool,5:10MiB,6:/tmp/x,",
                                          sizeof("4:tool,5:10MiB,6:/tmp/x,") -
                                              1}) == ST_OK);
  ASSERT(st_learner_feed_netargv_view(
             learner,
             (st_netargv_view_t){
                 "4:tool,28:tag=2026-10-05t12:34:56Zpost,2:42,",
                 sizeof("4:tool,28:tag=2026-10-05t12:34:56Zpost,2:42,") - 1}) ==
         ST_OK);
  static const char *const parameter_records[] = {
      "tool 10ms 42",
      "tool 550e8400-e29b-41d4-a716-446655440000 42",
      "tool 1.2.3 42",
      "tool 2.7.1-beta+build 42",
      "tool 2026-10-05 42",
      "tool 2026-10-05t12:34:56Z 42",
      "tool abcdef0 42",
      "tool ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89 42",
      "tool 1-9 42",
      "tool 0644 42",
  };
  for (size_t i = 0;
       i < sizeof(parameter_records) / sizeof(parameter_records[0]); i++)
    ASSERT(test_st_feed(learner, parameter_records[i]) == ST_OK);
  static const char binary[] = "4:tool,11:pre\0"
                               "42\0post,6:/tmp/x,";
  ASSERT(st_learner_feed_netargv_view(
             learner, (st_netargv_view_t){binary, sizeof(binary) - 1}) ==
         ST_OK);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_netpattern_t pattern = {0};
    st_token_array_t decoded = {0};
    ASSERT(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    ASSERT(
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK);
    st_token_variant_t ordinary[ST_MAX_TOKEN_VARIANTS] = {0};
    st_token_variant_t failed[ST_MAX_TOKEN_VARIANTS] = {0};
    st_test_alloc_reset();
    size_t count = st_learner_suggest_token_variants(
        learner, &decoded, cases[i].position, ordinary);
    size_t allocations = st_test_alloc_count();
    st_test_alloc_fail_at(1);
    size_t failed_count = st_learner_suggest_token_variants(
        learner, &decoded, cases[i].position, failed);
    size_t failed_allocations = st_test_alloc_count();
    st_test_alloc_reset();
    ASSERT(count == cases[i].count && allocations == 0 &&
           failed_allocations == 0 && failed_count == count);
    for (size_t j = 0; j < count; j++) {
      ASSERT(ordinary[j].type == failed[j].type);
      ASSERT(ordinary[j].type_symbol == failed[j].type_symbol);
    }
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
  }
  st_learner_free(learner);
  return 1;
}

static int policy_variant_lists_equal(const st_token_variant_t *left,
                                      size_t left_count,
                                      const st_token_variant_t *right,
                                      size_t right_count) {
  if (left_count != right_count)
    return 0;
  for (size_t i = 0; i < left_count; i++)
    if (left[i].type != right[i].type ||
        strcmp(left[i].type_symbol, right[i].type_symbol) != 0)
      return 0;
  return 1;
}

static int policy_test_token_variant_matrix(void) {
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
  st_learner_t *empty = st_learner_new(NULL);
  ASSERT(empty != NULL);
  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS];

  for (size_t i = 0; i < sizeof(fallback_cases) / sizeof(fallback_cases[0]);
       i++) {
    const char *tokens[] = {"cmd", fallback_cases[i].token};
    ASSERT(policy_variants_match(empty, tokens, 2, 1,
                                 fallback_cases[i].expected,
                                 fallback_cases[i].expected_count));
  }

  const char *command_tokens[] = {"literal"};
  size_t command_count =
      st_policy_suggest_token_variants(empty, command_tokens, 1, 0, variants);
  ASSERT(command_count == 1);
  ASSERT(variants[0].type == ST_TYPE_VALUE);
  char *edited_command =
      st_policy_apply_type_at(empty, command_tokens, 1, 0, variants[0].type);
  ASSERT(edited_command != NULL);
  ASSERT(test_st_validate_pattern(edited_command, NULL) == ST_OK);
  free(edited_command);

  const char *valid[] = {"cmd", "#w"};
  const char *with_control[] = {"cmd", "bad\003token"};
  const char *with_separator[] = {"cmd", "two tokens"};
  ASSERT(st_policy_suggest_token_variants(empty, valid, 2, 2, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(empty, with_control, 2, 1, variants) >
         0);
  ASSERT(st_policy_suggest_token_variants(empty, with_separator, 2, 1,
                                          variants) > 0);
  const char *too_many_tokens[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many_tokens) / sizeof(too_many_tokens[0]);
       i++)
    too_many_tokens[i] = "#w";
  memset(variants, 0xa5, sizeof(variants));
  ASSERT(st_policy_suggest_token_variants(empty, too_many_tokens,
                                          sizeof(too_many_tokens) /
                                              sizeof(too_many_tokens[0]),
                                          1, variants) == 0);
  for (size_t i = 0; i < ST_MAX_TOKEN_VARIANTS; i++)
    ASSERT(variants[i].type == ST_TYPE_LITERAL &&
           variants[i].type_symbol == NULL);

  st_learner_free(empty);
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
  ASSERT(policy_variants_match(learner, learned_path, 4, 3, observed_paths, 4));
  ASSERT(policy_variants_match(learner, narrow_path, 4, 3, narrowed, 3));
  ASSERT(policy_variants_match(learner, method, 4, 2, method_types, 3));
  ASSERT(policy_variants_match(learner, method, 4, 3, url_types, 2));
  ASSERT(policy_variants_match(learner, generic_prefix, 3, 2, prefix_union, 3));

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
    ASSERT(policy_variant_lists_equal(variants, saturated_count, reordered,
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
    st_token_array_t info = {0};
    ASSERT(test_st_validate_pattern(edited, &info) == ST_OK);
    ASSERT(info.count == 4);
    st_token_array_free(&info);
    free(edited);
  }

  st_learner_free(learner);
  return 1;
}

/* --- APPLY TYPE AT POSITION (st_policy_apply_type_at) --- */
/* All tests share setup: ctx + zeroed learner, then test different
 * positions/types. */

static int policy_test_apply_type_matrix(void) {
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
  ASSERT(st_policy_apply_type_at(NULL, single, 1, 0, ST_TYPE_ANY) == NULL);
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

static int run_policy(int argc, char **argv) {
  (void)argc;
  (void)argv;
  atexit(policy_cleanup_policy_temp_files);
  printf("Running policy unit tests...\n\n");

  printf("Lifecycle and mutation:\n");

  TEST(policy_test_working_set_never_exceeds_memory);
  printf("\nSerialisation:\n");
  TEST(policy_test_policy_persistence_transitions);
  TEST(policy_test_policy_load_read_failures_preserve_state);
  TEST(policy_test_append_load_subsumption_failures_are_atomic);
  TEST(policy_test_policy_load_rejects_binary_and_overlong_lines);

  printf("\nEvaluation and suggestions:\n");
  TEST(policy_test_evaluation_contract_matrix);
  TEST(policy_test_invalid_inputs_clear_results);
  TEST(policy_test_suggestion_contracts);

  printf("\nContext and validation:\n");
  TEST(policy_test_context_and_compaction_transitions);
  TEST(policy_test_context_allocation_failures_preserve_storage);
  TEST(policy_test_policy_contract_matrix);
  TEST(policy_test_pattern_validation_matrix);

  printf("\nDiagnostics and suggestions:\n");
  TEST(policy_test_statistics_transitions);
  TEST(policy_test_dot_export);
  TEST(policy_test_dry_run_simulate);

  printf("\nPolicy maintenance:\n");

  printf("\nLiteral and wildcard semantics:\n");

  printf("\nParametrized wildcard matching and subsumption:\n");
  TEST(policy_test_param_subsumption_matrix);

  printf("\nParameter validation:\n");

  printf("\nPolicy merge (st_policy_merge):\n");
  TEST(policy_test_merge_allocation_failures_preserve_destination);

  printf("\nPolicy diff (st_policy_diff):\n");
  TEST(policy_test_compound_policy_binary_identity);
  TEST(policy_test_diff_matrix_and_symmetry);
  TEST(policy_test_diff_allocation_failures_clear_result);

  printf("\nIncremental subsumption:\n");
  TEST(policy_test_batch_add_is_atomic);

  printf("\nToken variant suggestion (st_policy_suggest_token_variants):\n");
  TEST(policy_test_token_variant_matrix);
  TEST(policy_test_variant_queries_are_allocation_free);

  printf("\nApply type at position (st_policy_apply_type_at):\n");
  TEST(policy_test_apply_type_matrix);

  printf("\n========================================\n");
  printf("Results: %d/%d passed, %d failed\n", policy_tests_passed,
         policy_tests_run, policy_tests_failed);

  return policy_tests_failed > 0 ? 1 : 0;
}
#undef TEST
#undef ASSERT
#undef ASSERT_STR_EQ
#undef ASSERT_OK
#undef CHECK_BUCKET

/* --- compact (from test_policy_compact.c) --- */
/* Integration tests for large policy compaction and NFA rendering. */

static int compact_tests_run;
static int compact_tests_passed;
static int compact_tests_failed;
static char compact_nfa_save_directory[256];

static void compact_cleanup_nfa_save_directory(void) {
  if (compact_nfa_save_directory[0]) {
    (void)test_atomic_cleanup_directory(compact_nfa_save_directory);
    compact_nfa_save_directory[0] = '\0';
  }
}

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    assertion failed: %s at %s:%d\n", #condition, __FILE__,      \
             __LINE__);                                                        \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define TEST(function)                                                         \
  do {                                                                         \
    compact_tests_run++;                                                       \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      compact_tests_passed++;                                                  \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      compact_tests_failed++;                                                  \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_policy_t *compact_new_policy(st_policy_ctx_t *context,
                                       const char *const *patterns,
                                       size_t count) {
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

static int compact_eval_matches(st_policy_t *policy, const char *command,
                                const char *expected_pattern) {
  st_eval_result_t result = {0};
  st_error_t error = test_st_policy_eval(policy, command, &result);
  int valid = error == ST_OK && result.matches == (expected_pattern != NULL);
  if (expected_pattern)
    valid = valid && test_pattern_is_cpl(
                         (st_netpattern_view_t){result.matching_pattern,
                                                result.matching_pattern_length},
                         expected_pattern);
  else
    valid = valid && result.matching_pattern == NULL;
  if (!valid)
    printf("    '%s': matches=%d pattern=%s expected=%s error=%d\n", command,
           result.matches,
           result.matching_pattern ? result.matching_pattern : "-",
           expected_pattern ? expected_pattern : "-", error);
  return valid;
}

static int compact_test_compaction_allocation_failures_are_atomic(void) {
  static const char *patterns[] = {"git status", "copy #path", "probe #n"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe = compact_new_policy(probe_context, patterns, 3);
  ASSERT(probe_context != NULL && probe != NULL);
  st_test_alloc_reset();
  ASSERT(st_policy_compact(probe) == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_policy_free(probe);
  st_policy_ctx_release(probe_context);
  ASSERT(allocations > 0);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = compact_new_policy(context, patterns, 3);
    ASSERT(context != NULL && policy != NULL);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_policy_compact(policy);
    st_test_alloc_reset();
    ASSERT(error == ST_OK || error == ST_ERR_MEMORY);
    ASSERT(st_policy_rule_count(policy) == 3);
    ASSERT(compact_eval_matches(policy, "git status", "git status"));
    ASSERT(compact_eval_matches(policy, "copy /tmp/value", "copy #path"));
    ASSERT(compact_eval_matches(policy, "probe 17", "probe #n"));
    ASSERT(test_st_policy_add(policy, "after failure") == ST_OK);
    ASSERT(compact_eval_matches(policy, "after failure", "after failure"));
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
  return 1;
}

static char *compact_read_file(const char *path) {
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

static size_t compact_occurrence_count(const char *text, const char *needle) {
  size_t count = 0;
  size_t length = strlen(needle);
  for (const char *found = strstr(text, needle); found;
       found = strstr(found + length, needle))
    count++;
  return count;
}

typedef struct {
  int symbol;
  size_t target;
} compact_parsed_transition_t;

typedef struct {
  bool accepting;
  char tag[ST_MAX_NETPATTERN_LEN];
  compact_parsed_transition_t *transitions;
  size_t count;
} compact_parsed_nfa_state_t;

typedef struct {
  compact_parsed_nfa_state_t *states;
  size_t count;
  size_t initial;
} compact_parsed_nfa_t;

static void compact_parsed_nfa_free(compact_parsed_nfa_t *nfa) {
  for (size_t i = 0; i < nfa->count; i++)
    free(nfa->states[i].transitions);
  free(nfa->states);
  memset(nfa, 0, sizeof(*nfa));
}

static int compact_parsed_nfa_load(const char *path,
                                   compact_parsed_nfa_t *nfa) {
  FILE *file = fopen(path, "r");
  if (!file)
    return 0;
  char line[2048];
  size_t current = SIZE_MAX;
  while (fgets(line, sizeof(line), file)) {
    size_t value;
    if (sscanf(line, "States: %zu", &value) == 1) {
      if (nfa->states || value == 0 || value > SIZE_MAX / sizeof(*nfa->states))
        goto fail;
      compact_parsed_nfa_state_t *states =
          st_test_calloc(value, sizeof(*states));
      if (!states)
        goto fail;
      nfa->states = states;
      nfa->count = value;
    } else if (sscanf(line, "Initial: %zu", &value) == 1) {
      nfa->initial = value;
    } else if (sscanf(line, "State %zu:", &value) == 1) {
      if (value >= nfa->count)
        goto fail;
      current = value;
    } else if (current < nfa->count && strstr(line, "EosTarget: yes")) {
      nfa->states[current].accepting = true;
    } else if (current < nfa->count && strstr(line, "  Tags: ") == line) {
      char *tag = line + strlen("  Tags: ");
      tag[strcspn(tag, "\r\n")] = '\0';
      snprintf(nfa->states[current].tag, sizeof(nfa->states[current].tag), "%s",
               tag);
    } else if (current < nfa->count) {
      int symbol;
      size_t target;
      if (sscanf(line, "    Symbol %d -> %zu", &symbol, &target) == 2) {
        compact_parsed_nfa_state_t *state = &nfa->states[current];
        if (target >= nfa->count ||
            state->count >= SIZE_MAX / sizeof(*state->transitions))
          goto fail;
        compact_parsed_transition_t *grown =
            realloc(state->transitions,
                    (state->count + 1) * sizeof(*state->transitions));
        if (!grown) {
          goto fail;
        }
        state->transitions = grown;
        state->transitions[state->count++] =
            (compact_parsed_transition_t){symbol, target};
      }
    }
  }
  int valid = !ferror(file) && nfa->states && nfa->initial < nfa->count;
  if (fclose(file) != 0)
    valid = 0;
  if (!valid)
    compact_parsed_nfa_free(nfa);
  return valid;

fail:
  fclose(file);
  compact_parsed_nfa_free(nfa);
  return 0;
}

static void compact_epsilon_closure(const compact_parsed_nfa_t *nfa,
                                    bool *active) {
  bool changed;
  do {
    changed = false;
    for (size_t i = 0; i < nfa->count; i++) {
      if (!active[i])
        continue;
      for (size_t j = 0; j < nfa->states[i].count; j++) {
        compact_parsed_transition_t transition = nfa->states[i].transitions[j];
        if (transition.symbol == 257 && !active[transition.target]) {
          active[transition.target] = true;
          changed = true;
        }
      }
    }
  } while (changed);
}

static size_t compact_parsed_nfa_matches(const compact_parsed_nfa_t *nfa,
                                         const char *input,
                                         const char **matches,
                                         size_t capacity) {
  bool *active = calloc(nfa->count, sizeof(bool));
  bool *next = calloc(nfa->count, sizeof(bool));
  if (!active || !next) {
    free(active);
    free(next);
    return SIZE_MAX;
  }
  active[nfa->initial] = true;
  compact_epsilon_closure(nfa, active);
  for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
    memset(next, 0, nfa->count * sizeof(bool));
    for (size_t i = 0; i < nfa->count; i++) {
      if (!active[i])
        continue;
      for (size_t j = 0; j < nfa->states[i].count; j++) {
        compact_parsed_transition_t transition = nfa->states[i].transitions[j];
        bool accepts = transition.symbol == *p || (transition.symbol == 256) ||
                       (transition.symbol == 259 && *p == ' ') ||
                       (transition.symbol == 260 && *p == '\t');
        if (accepts)
          next[transition.target] = true;
      }
    }
    bool *swap = active;
    active = next;
    next = swap;
    compact_epsilon_closure(nfa, active);
  }
  size_t count = 0;
  for (size_t i = 0; i < nfa->count; i++)
    if (active[i] && nfa->states[i].accepting) {
      if (count < capacity)
        matches[count] = nfa->states[i].tag;
      count++;
    }
  free(active);
  free(next);
  return count;
}

typedef struct {
  const compact_parsed_nfa_t *nfa;
  const st_token_array_t *tokens;
  const char **matches;
  size_t match_count;
  size_t match_capacity;
  char buffer[ST_MAX_NETPATTERN_LEN];
} compact_typed_nfa_ctx_t;

static bool
compact_typed_metadata_matches(const st_token_t *token,
                               const st_metadata_entry_t *metadata) {
  const char *text = token->text;
  if (metadata->type == ST_TYPE_SIZE) {
    const st_metadata_entry_t *observed =
        token->type == ST_TYPE_SIZE
            ? st_metadata_lookup(ST_TYPE_SIZE, st_size_suffix(text))
            : NULL;
    return observed && observed->id == metadata->id;
  }
  if (metadata->type == ST_TYPE_UUID)
    return token->type == ST_TYPE_UUID && strlen(text) == 36 &&
           ((metadata->id == ST_META_UUID_V4 && text[14] == '4') ||
            (metadata->id == ST_META_UUID_V5 && text[14] == '5'));
  if (metadata->type == ST_TYPE_SEMVER)
    return token->type == ST_TYPE_SEMVER;
  if (metadata->type == ST_TYPE_TIMESTAMP) {
    if (token->type != ST_TYPE_TIMESTAMP)
      return false;
    size_t length = strlen(text);
    return (metadata->id == ST_META_TIMESTAMP_DATE && length == 10 &&
            text[4] == '-' && text[7] == '-') ||
           (metadata->id == ST_META_TIMESTAMP_TIME && length == 8 &&
            text[2] == ':' && text[5] == ':') ||
           (metadata->id == ST_META_TIMESTAMP_DATETIME && length >= 19 &&
            (text[10] == 'T' || text[10] == ' '));
  }
  if (metadata->type == ST_TYPE_SHA) {
    if (token->type != ST_TYPE_SHA && token->type != ST_TYPE_HEXHASH)
      return false;
    size_t length = strlen(text);
    for (size_t i = 0; i < length; i++)
      if (!isxdigit((unsigned char)text[i]))
        return false;
    return (metadata->id == ST_META_SHA_SHORT && length == 7) ||
           (metadata->id == ST_META_SHA_40 && length == 40) ||
           (metadata->id == ST_META_SHA_64 && length == 64);
  }
  if (metadata->type == ST_TYPE_FINGERPRINT)
    return token->type == ST_TYPE_FINGERPRINT &&
           ((metadata->id == ST_META_FINGERPRINT_SHA256 &&
             strncmp(text, "SHA256:", 7) == 0) ||
            (metadata->id == ST_META_FINGERPRINT_MD5 && strlen(text) == 47 &&
             text[2] == ':' && text[5] == ':'));
  if (metadata->type == ST_TYPE_DURATION) {
    if (token->type != ST_TYPE_DURATION)
      return false;
    const char *suffix = text;
    if (*suffix == '-')
      suffix++;
    while (*suffix && (isdigit((unsigned char)*suffix) || *suffix == '.'))
      suffix++;
    const st_metadata_entry_t *observed =
        st_metadata_lookup(ST_TYPE_DURATION, suffix);
    return observed && observed->id == metadata->id;
  }
  if (metadata->type == ST_TYPE_RANGE)
    return token->type == ST_TYPE_RANGE;
  if (metadata->type == ST_TYPE_PERM_OCTAL)
    return token->type == ST_TYPE_PERM_OCTAL;
  return false;
}

static void compact_typed_nfa_walk(compact_typed_nfa_ctx_t *ctx,
                                   size_t token_index, size_t used) {
  if (token_index == ctx->tokens->count) {
    const char *found[32] = {0};
    size_t count = compact_parsed_nfa_matches(ctx->nfa, ctx->buffer, found, 32);
    ASSERT(count <= sizeof(found) / sizeof(found[0]));
    for (size_t i = 0; i < count; i++) {
      ASSERT(found[i] != NULL);
      bool duplicate = false;
      for (size_t j = 0; j < ctx->match_count; j++)
        duplicate = duplicate || strcmp(ctx->matches[j], found[i]) == 0;
      if (!duplicate && ctx->match_count < ctx->match_capacity)
        ctx->matches[ctx->match_count++] = found[i];
    }
    return;
  }
  const st_token_t *token = &ctx->tokens->tokens[token_index];
  const char *forms[8] = {token->text};
  char metadata_forms[6][32];
  size_t form_count = 1;
  if (token->type != ST_TYPE_LITERAL &&
      strcmp(token->text, st_type_symbol[token->type]) != 0)
    forms[form_count++] = st_type_symbol[token->type];
  size_t metadata_form_count = 0;
  for (size_t i = 0;
       i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++) {
    const st_metadata_entry_t *metadata = &st_metadata_entries[i];
    if (!compact_typed_metadata_matches(token, metadata))
      continue;
    if (metadata_form_count >=
        sizeof(metadata_forms) / sizeof(metadata_forms[0]))
      return;
    snprintf(metadata_forms[metadata_form_count],
             sizeof(metadata_forms[metadata_form_count]), "%s.%s",
             st_type_symbol[metadata->type], metadata->name);
    forms[form_count++] = metadata_forms[metadata_form_count++];
  }
  for (size_t form = 0; form < form_count; form++) {
    size_t length = strlen(forms[form]);
    size_t next = used + (token_index != 0) + length;
    if (next >= sizeof(ctx->buffer))
      continue;
    if (token_index != 0)
      ctx->buffer[used++] = ' ';
    memcpy(ctx->buffer + used, forms[form], length + 1);
    compact_typed_nfa_walk(ctx, token_index + 1, next);
    used -= token_index != 0;
  }
}

static size_t compact_parsed_nfa_matches_typed(const compact_parsed_nfa_t *nfa,
                                               const char *command,
                                               const char **matches,
                                               size_t match_capacity) {
  st_token_array_t tokens = {0};
  if (test_st_classify(command, &tokens) != ST_OK)
    return 0;
  compact_typed_nfa_ctx_t ctx = {.nfa = nfa,
                                 .tokens = &tokens,
                                 .matches = matches,
                                 .match_capacity = match_capacity};
  compact_typed_nfa_walk(&ctx, 0, 0);
  st_token_array_free(&tokens);
  return ctx.match_count;
}

static int compact_rendered_nfa_matches(const char *rendered,
                                        const char *identifier,
                                        unsigned category_mask,
                                        unsigned pattern_id_base,
                                        bool include_tags) {
  char expected[96];
  snprintf(expected, sizeof(expected), "Identifier: %s\n", identifier);
  if (!strstr(rendered, "NFA_ALPHABET\n") || !strstr(rendered, expected) ||
      !strstr(rendered, "AlphabetSize: 261\n") ||
      !strstr(rendered, "Initial: 0\n") ||
      !strstr(rendered, "Symbol 256: 0-255 (special)") ||
      !strstr(rendered, "Symbol 259 ->") ||
      compact_occurrence_count(rendered, "EosTarget: yes") != 3)
    return 0;

  snprintf(expected, sizeof(expected), "CategoryMask: 0x%02x", category_mask);
  if (compact_occurrence_count(rendered, expected) != 3)
    return 0;
  for (unsigned i = 0; i < 3; i++) {
    snprintf(expected, sizeof(expected), "PatternId: %u\n",
             pattern_id_base + i);
    if (!strstr(rendered, expected))
      return 0;
  }

  static const char *tags[] = {"git commit", "git status", "cat *"};
  if (compact_occurrence_count(rendered, "Tags: ") != (include_tags ? 3u : 0u))
    return 0;
  for (size_t i = 0; include_tags && i < sizeof(tags) / sizeof(tags[0]); i++) {
    snprintf(expected, sizeof(expected), "Tags: %s\n", tags[i]);
    if (!strstr(rendered, expected))
      return 0;
  }
  return 1;
}

static int compact_test_nfa_rendering_contract(void) {
  static const char *patterns[] = {"git commit", "git status", "cat *"};
  const char *path = "test_compact_policy.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *empty = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && empty != NULL);
  ASSERT(st_policy_render_nfa(empty, path, NULL) == ST_OK);
  char *empty_rendered = compact_read_file(path);
  ASSERT(empty_rendered != NULL);
  ASSERT(strstr(empty_rendered, "NFA_ALPHABET") != NULL);
  ASSERT(strstr(empty_rendered, "States: 1") != NULL);
  free(empty_rendered);
  st_policy_free(empty);
  st_policy_t *policy = compact_new_policy(context, patterns, 3);
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

  st_nfa_render_opts_t hostile = options;
  hostile.identifier = "injected\nStates: 0";
  ASSERT(st_policy_render_nfa(policy, path, &hostile) == ST_ERR_INVALID);
  ASSERT(st_policy_render_nfa(policy, ".", &options) == ST_ERR_IO);
  st_nfa_render_opts_t overflowing = options;
  overflowing.pattern_id_base = UINT32_MAX - 1;
  ASSERT(st_policy_render_nfa(policy, path, &overflowing) == ST_ERR_LIMIT);
  if (access("/dev/full", W_OK) == 0)
    ASSERT(st_policy_render_nfa(policy, "/dev/full", &options) == ST_ERR_IO);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(st_policy_render_nfa(policy, path, cases[i].options) == ST_OK);
    char *rendered = compact_read_file(path);
    ASSERT(rendered != NULL);
    ASSERT(compact_rendered_nfa_matches(
        rendered, cases[i].identifier, cases[i].category_mask,
        cases[i].pattern_id_base, cases[i].include_tags));
    free(rendered);
  }
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int compact_test_nfa_binary_literal_rendering(void) {
  const char *path = "test_binary_policy.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  st_netpattern_t pattern = {0};
  st_netpattern_t empty_literal = {0};
  ASSERT(context != NULL && policy != NULL);
  ASSERT(st_netpattern_from_cpl_owned("echo \"a\\x00b\"", &pattern) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){.data = (const char *)pattern.data,
                                            .length = pattern.length}) ==
         ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("empty \"\"", &empty_literal) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy,
             (st_netpattern_view_t){.data = (const char *)empty_literal.data,
                                    .length = empty_literal.length}) == ST_OK);

  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "binary-policy"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  char *rendered = compact_read_file(path);
  ASSERT(rendered != NULL);
  ASSERT(strstr(rendered, "    Symbol 0 ->") != NULL);
  ASSERT(strstr(rendered, "    Symbol 257 ->") != NULL);
  ASSERT(strstr(rendered, "  Tags: echo \"a\\x00b\"\n") != NULL);
  free(rendered);

  options.include_tags = false;
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  rendered = compact_read_file(path);
  ASSERT(rendered != NULL);
  ASSERT(strstr(rendered, "    Symbol 0 ->") != NULL);
  ASSERT(strstr(rendered, "    Symbol 257 ->") != NULL);
  ASSERT(strstr(rendered, "  Tags: ") == NULL);
  free(rendered);
  ASSERT(remove(path) == 0);
  st_netpattern_free(&pattern);
  st_netpattern_free(&empty_literal);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int compact_test_nfa_lattice_transition_matrix(void) {
  const char *path = "/tmp/shelltype-nfa-lattice.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && policy != NULL);

  char patterns[ST_TYPE_COUNT][64];
  for (int policy_type = ST_TYPE_LITERAL + 1; policy_type < ST_TYPE_COUNT;
       policy_type++) {
    ASSERT(snprintf(patterns[policy_type], sizeof(patterns[policy_type]),
                    "type%02d %s", policy_type,
                    st_type_symbol[policy_type]) > 0);
    ASSERT(test_st_policy_add(policy, patterns[policy_type]) == ST_OK);
  }

  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "lattice-matrix"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  compact_parsed_nfa_t nfa = {0};
  ASSERT(compact_parsed_nfa_load(path, &nfa));

  for (int policy_type = ST_TYPE_LITERAL + 1; policy_type < ST_TYPE_COUNT;
       policy_type++) {
    for (int command_type = ST_TYPE_LITERAL + 1; command_type < ST_TYPE_ANY;
         command_type++) {
      char input[64];
      ASSERT(snprintf(input, sizeof(input), "type%02d %s", policy_type,
                      st_type_symbol[command_type]) > 0);
      const char *matches[2] = {0};
      size_t count = compact_parsed_nfa_matches(&nfa, input, matches, 2);
      bool expected = st_is_compatible((st_token_type_t)command_type,
                                       (st_token_type_t)policy_type);
      ASSERT(count == (expected ? 1u : 0u));
      if (expected)
        ASSERT(strcmp(matches[0], patterns[policy_type]) == 0);
    }

    char literal_input[64];
    ASSERT(snprintf(literal_input, sizeof(literal_input),
                    "type%02d literal-value", policy_type) > 0);
    const char *matches[2] = {0};
    size_t count = compact_parsed_nfa_matches(&nfa, literal_input, matches, 2);
    ASSERT(count == (policy_type == ST_TYPE_ANY ? 1u : 0u));
  }

  compact_parsed_nfa_free(&nfa);
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

typedef struct {
  const char *command;
  const char *expected[5];
} compact_metadata_match_case_t;

static int
compact_metadata_matches_expected(st_policy_t *policy, const char *path,
                                  const compact_metadata_match_case_t *cases,
                                  size_t case_count) {
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "metadata-cross-product"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  compact_parsed_nfa_t nfa = {0};
  ASSERT(compact_parsed_nfa_load(path, &nfa));
  for (size_t i = 0; i < case_count; i++) {
    size_t expected_count = 0;
    while (expected_count < 5 && cases[i].expected[expected_count])
      expected_count++;
    st_netpattern_view_t *policy_matches = NULL;
    size_t policy_count = 0;
    ASSERT(test_st_policy_verify_all(policy, cases[i].command, &policy_matches,
                                     &policy_count) == ST_OK);
    const char *nfa_matches[8] = {0};
    size_t nfa_count = compact_parsed_nfa_matches_typed(&nfa, cases[i].command,
                                                        nfa_matches, 8);
    ASSERT(policy_count == expected_count);
    ASSERT(nfa_count == expected_count);
    for (size_t expected = 0; expected < expected_count; expected++) {
      bool policy_found = false;
      bool nfa_found = false;
      for (size_t actual = 0; actual < policy_count; actual++)
        policy_found =
            policy_found || test_pattern_is_cpl(policy_matches[actual],
                                                cases[i].expected[expected]);
      for (size_t actual = 0; actual < nfa_count; actual++)
        nfa_found = nfa_found || strcmp(nfa_matches[actual],
                                        cases[i].expected[expected]) == 0;
      if (!policy_found || !nfa_found) {
        printf("    metadata case '%s' missing '%s' (policy=%d nfa=%d, "
               "counts=%zu/%zu)\n",
               cases[i].command, cases[i].expected[expected], policy_found,
               nfa_found, policy_count, nfa_count);
        st_policy_matches_free(policy_matches);
        compact_parsed_nfa_free(&nfa);
        return 0;
      }
    }
    st_policy_matches_free(policy_matches);
  }
  compact_parsed_nfa_free(&nfa);
  return 1;
}

/* Every closed metadata sibling occupies the same trie position.  Expected
 * match sets are hand-authored so neither the policy matcher nor the typed NFA
 * adapter acts as the oracle for the other. */
static int compact_test_nfa_same_prefix_metadata_cross_product(void) {
  static const char *patterns[] = {
      "size #size.K",          "size #size.M",          "size #size.G",
      "size #size.T",          "size #size.Ki",         "size #size.Mi",
      "size #size.Gi",         "size #size.Ti",         "size #size.KB",
      "size #size.MB",         "size #size.GB",         "size #size.TB",
      "size #size.B",          "size #size.bytes",      "size #size.KiB",
      "size #size.MiB",        "size #size.GiB",        "size #size.TiB",
      "uuid #uuid.v4",         "uuid #uuid.v5",         "semver #semver.major",
      "semver #semver.minor",  "semver #semver.patch",  "semver #semver.*",
      "time #ts.date",         "time #ts.time",         "time #ts.datetime",
      "sha #sha.short",        "sha #sha.40",           "sha #sha.64",
      "finger #fp.sha256",     "finger #fp.md5",        "duration #duration.ns",
      "duration #duration.us", "duration #duration.ms", "duration #duration.s",
      "duration #duration.m",  "duration #duration.h",  "duration #duration.d",
      "duration #duration.w",  "range #range.step",     "perm #perm.bits",
      "uuid-alias #uuid.4",    "size-alias #size.b",
  };
  static const compact_metadata_match_case_t cases[] = {
      {"size 2K", {"size #size.K", NULL}},
      {"size 2M", {"size #size.M", NULL}},
      {"size 2G", {"size #size.G", NULL}},
      {"size 2T", {"size #size.T", NULL}},
      {"size 2Ki", {"size #size.Ki", NULL}},
      {"size 2Mi", {"size #size.Mi", NULL}},
      {"size 2Gi", {"size #size.Gi", NULL}},
      {"size 2Ti", {"size #size.Ti", NULL}},
      {"size 2KB", {"size #size.KB", NULL}},
      {"size 2MB", {"size #size.MB", NULL}},
      {"size 2GB", {"size #size.GB", NULL}},
      {"size 2TB", {"size #size.TB", NULL}},
      {"size 2B", {"size #size.B", NULL}},
      {"size 2bytes", {"size #size.bytes", NULL}},
      {"size 2KiB", {"size #size.KiB", NULL}},
      {"size 2MiB", {"size #size.MiB", NULL}},
      {"size 2GiB", {"size #size.GiB", NULL}},
      {"size 2TiB", {"size #size.TiB", NULL}},
      {"size 2XB", {NULL}},
      {"uuid 550e8400-e29b-41d4-a716-446655440000", {"uuid #uuid.v4", NULL}},
      {"uuid 550e8400-e29b-51d4-a716-446655440000", {"uuid #uuid.v5", NULL}},
      {"uuid 550e8400-e29b-31d4-a716-446655440000", {NULL}},
      {"semver 1.2.3",
       {"semver #semver.major", "semver #semver.minor", "semver #semver.patch",
        "semver #semver.*", NULL}},
      {"time 2025-04-24", {"time #ts.date", NULL}},
      {"time 15:30:00", {"time #ts.time", NULL}},
      {"time 2025-04-24T15:30:00Z", {"time #ts.datetime", NULL}},
      {"sha deadbee", {"sha #sha.short", NULL}},
      {"sha deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", {"sha #sha.40", NULL}},
      {"sha 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
       {"sha #sha.64", NULL}},
      {"finger SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
       {"finger #fp.sha256", NULL}},
      {"finger 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d",
       {"finger #fp.md5", NULL}},
      {"duration 10ns", {"duration #duration.ns", NULL}},
      {"duration 10us", {"duration #duration.us", NULL}},
      {"duration 10ms", {"duration #duration.ms", NULL}},
      {"duration 10s", {"duration #duration.s", NULL}},
      {"duration 10m", {"duration #duration.m", NULL}},
      {"duration 10h", {"duration #duration.h", NULL}},
      {"duration 10d", {"duration #duration.d", NULL}},
      {"duration 10w", {"duration #duration.w", NULL}},
      {"duration 10y", {NULL}},
      {"range 1-5", {"range #range.step", NULL}},
      {"perm 0755", {"perm #perm.bits", NULL}},
      {"uuid-alias 550e8400-e29b-41d4-a716-446655440000",
       {"uuid-alias #uuid.v4", NULL}},
      {"size-alias 2B", {"size-alias #size.B", NULL}},
  };
  const char *nfa_path = "/tmp/shelltype-nfa-metadata-matrix.nfa";
  const char *policy_path = "/tmp/shelltype-nfa-metadata-matrix.policy";
  st_policy_ctx_t *source_context = st_policy_ctx_new();
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *source = source_context ? st_policy_new(source_context) : NULL;
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(source && policy);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(source, patterns[i]) == ST_OK);
  ASSERT(st_policy_merge(policy, source) == ST_OK);
  ASSERT(compact_metadata_matches_expected(policy, nfa_path, cases,
                                           sizeof(cases) / sizeof(cases[0])));

  char *rendered = compact_read_file(nfa_path);
  ASSERT(rendered != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]) - 2; i++)
    ASSERT(strstr(rendered, patterns[i]) != NULL);
  ASSERT(strstr(rendered, "uuid-alias #uuid.v4") != NULL);
  ASSERT(strstr(rendered, "size-alias #size.B") != NULL);
  ASSERT(strstr(rendered, "uuid-alias #uuid.4") == NULL);
  ASSERT(strstr(rendered, "size-alias #size.b") == NULL);
  ASSERT(strstr(rendered, "550e8400-e29b") == NULL);
  ASSERT(strstr(rendered, "uNiVztks") == NULL);
  free(rendered);

  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(compact_metadata_matches_expected(policy, nfa_path, cases,
                                           sizeof(cases) / sizeof(cases[0])));
  ASSERT(st_policy_save(policy, policy_path) == ST_OK);
  ASSERT(st_policy_clear(policy) == ST_OK);
  ASSERT(st_policy_load(policy, policy_path, true) == ST_OK);
  ASSERT(compact_metadata_matches_expected(policy, nfa_path, cases,
                                           sizeof(cases) / sizeof(cases[0])));

  ASSERT(remove(nfa_path) == 0 && remove(policy_path) == 0);
  st_policy_free(policy);
  st_policy_free(source);
  st_policy_ctx_release(context);
  st_policy_ctx_release(source_context);
  return 1;
}

static int compact_test_nfa_allocation_failures(void) {
  static const char *patterns[] = {"git commit", "git status", "cat *"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = compact_new_policy(context, patterns, 3);
  ASSERT(context != NULL && policy != NULL);
  char large_pattern[512] = "large ";
  memset(large_pattern + strlen(large_pattern), 'a', 200);
  large_pattern[206] = ' ';
  memset(large_pattern + 207, 'b', 200);
  large_pattern[407] = '\0';
  ASSERT(test_st_policy_add(policy, large_pattern) == ST_OK);
  st_test_alloc_reset();
  ASSERT(st_policy_render_nfa(policy, "/tmp/shelltype-nfa-fail", NULL) ==
         ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  (void)remove("/tmp/shelltype-nfa-fail");
  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_error_t err =
        st_policy_render_nfa(policy, "/tmp/shelltype-nfa-fail", NULL);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY)
      observed = true;
    else
      ASSERT(err == ST_OK || err == ST_ERR_IO);
    (void)remove("/tmp/shelltype-nfa-fail");
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int compact_test_dot_allocation_failures_are_clean(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && policy != NULL);
  for (size_t i = 0; i < 300; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "dot-failure-%zu", i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
  }

  const char *path = "/tmp/shelltype-dot-failure.dot";
  st_test_alloc_reset();
  ASSERT(st_policy_dump_dot(policy, path) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  (void)remove(path);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_policy_dump_dot(policy, path);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(
          compact_eval_matches(policy, "dot-failure-299", "dot-failure-299"));
    } else {
      ASSERT(error == ST_OK || error == ST_ERR_IO);
    }
    (void)remove(path);
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

typedef st_error_t (*atomic_writer_t)(void *object, const char *path);

static int run_compact(int argc, char **argv) {
  (void)argc;
  (void)argv;
  atexit(compact_cleanup_nfa_save_directory);
  printf("Running compact policy tests...\n\n");
  TEST(compact_test_compaction_allocation_failures_are_atomic);
  TEST(compact_test_nfa_rendering_contract);
  TEST(compact_test_nfa_binary_literal_rendering);
  TEST(compact_test_nfa_lattice_transition_matrix);
  TEST(compact_test_nfa_same_prefix_metadata_cross_product);
  TEST(compact_test_nfa_allocation_failures);
  TEST(compact_test_dot_allocation_failures_are_clean);
  printf("\nResults: %d/%d passed, %d failed\n", compact_tests_passed,
         compact_tests_run, compact_tests_failed);
  return compact_tests_failed > 0 ? 1 : 0;
}
#undef ASSERT
#undef TEST

/* --- model (from test_policy_model.c) --- */
static const char *const model_patterns[] = {
    "git status",
    "docker ps",
    "copy #duration.ms",
    "copy #duration.s",
    "copy #duration",
    "container #uuid.v4",
    "container #uuid.v5",
    "container #uuid",
    "run #size.MiB",
    "run #size.GiB",
    "run #size",
    "echo *",
    "net #i",
    "net #ipv6",
    "net #ipaddr",
    "option #sopt",
    "option #lopt",
    "option #opt",
    "scalar #n",
    "scalar #uuid",
    "scalar #val",
    "locate #p",
    "locate #r",
    "locate #path",
    "word #method",
    "word #hyp",
    "word #w",
};

static const char *const model_probes[] = {
    "git status",
    "docker ps",
    "copy 10ms",
    "copy 2s",
    "copy 3h",
    "container 550e8400-e29b-41d4-a716-446655440000",
    "container 550e8400-e29b-51d4-a716-446655440000",
    "run 12MiB",
    "run 2GiB",
    "run 4KB",
    "echo anything",
    "unknown command",
    "net 192.168.1.1",
    "net 2001:db8::1",
    "option -v",
    "option --verbose",
    "scalar 42",
    "scalar 550e8400-e29b-41d4-a716-446655440000",
    "locate /tmp/file",
    "locate src/main.c",
    "word GET",
    "word feature-flag",
};

static uint32_t model_random_next(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

#define PROBE_BIT(index) (UINT64_C(1) << (index))

/* A closed, hand-authored semantic domain for an independent matcher oracle.
 * The masks deliberately do not use normalization, the lattice tables, or
 * either production matcher.  The probe set contains every equivalence class
 * distinguished by these patterns, so set inclusion is also the subsumption
 * relation within this model. */
static const char *const model_cross_probes[] = {
    "mix /tmp/a 42",
    "mix /tmp/a 7",
    "mix /tmp/b 7",
    "mix /tmp/b 42",
    "mix ../relative 42",
    "mix file.txt 9",
    "mix /tmp/a 550e8400-e29b-41d4-a716-446655440000",
    "mix 550e8400-e29b-41d4-a716-446655440000 42",
    "mix 42 word",
    "mix word 42",
    "mix 7 other",
    "mix 42 7",
    "id 550e8400-e29b-41d4-a716-446655440000 1MiB",
    "id 550e8400-e29b-51d4-a716-446655440000 2MiB",
    "id 123e4567-e89b-42d3-a456-426614174000 3GiB",
    "id 123e4567-e89b-52d3-a456-426614174000 4GiB",
    "id 6ba7b810-9dad-41d1-80b4-00c04fd430c8 5KB",
    "id 550e8400-e29b-31d4-a716-446655440000 6MiB",
};

typedef struct {
  const char *pattern;
  uint64_t matches;
} model_reference_pattern_t;

static const model_reference_pattern_t model_cross_patterns[] = {
    {"mix /tmp/a 42", PROBE_BIT(0)},
    {"mix /tmp/a #n", PROBE_BIT(0) | PROBE_BIT(1)},
    {"mix #p 42", PROBE_BIT(0) | PROBE_BIT(3)},
    {"mix #p #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3)},
    {"mix #path #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) |
                         PROBE_BIT(4) | PROBE_BIT(5)},
    {"mix #p #val",
     PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) | PROBE_BIT(6)},
    {"mix #path #val", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) |
                           PROBE_BIT(3) | PROBE_BIT(4) | PROBE_BIT(5) |
                           PROBE_BIT(6)},
    {"mix * 42",
     PROBE_BIT(0) | PROBE_BIT(3) | PROBE_BIT(4) | PROBE_BIT(7) | PROBE_BIT(9)},
    {"mix 42 *", PROBE_BIT(8) | PROBE_BIT(11)},
    {"mix #n *", PROBE_BIT(8) | PROBE_BIT(10) | PROBE_BIT(11)},
    {"mix * #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) |
                     PROBE_BIT(4) | PROBE_BIT(5) | PROBE_BIT(7) | PROBE_BIT(9) |
                     PROBE_BIT(11)},
    {"id #uuid.v4 #size.MiB", PROBE_BIT(12)},
    {"id #uuid.v5 #size.MiB", PROBE_BIT(13)},
    {"id #uuid.v4 #size.GiB", PROBE_BIT(14)},
    {"id #uuid #size", PROBE_BIT(12) | PROBE_BIT(13) | PROBE_BIT(14) |
                           PROBE_BIT(15) | PROBE_BIT(16) | PROBE_BIT(17)},
    {"id #uuid.v4 #size", PROBE_BIT(12) | PROBE_BIT(14) | PROBE_BIT(16)},
    {"id #uuid #size.MiB", PROBE_BIT(12) | PROBE_BIT(13) | PROBE_BIT(17)},
};

static bool model_reference_subsumes(size_t wider, size_t narrower) {
  return (model_cross_patterns[narrower].matches &
          ~model_cross_patterns[wider].matches) == 0;
}

static void model_reference_add(bool *active, size_t index) {
  for (size_t i = 0;
       i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]); i++)
    if (active[i] && model_reference_subsumes(i, index))
      return;
  for (size_t i = 0;
       i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]); i++)
    if (active[i] && model_reference_subsumes(index, i))
      active[i] = false;
  active[index] = true;
}

static const char *model_reference_selected(const bool *active, size_t probe) {
  const char *selected = NULL;
  size_t selected_index = 0;
  for (size_t i = 0;
       i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]);
       i++) {
    if (!active[i] || !(model_cross_patterns[i].matches & PROBE_BIT(probe)))
      continue;
    if (!selected) {
      selected = model_cross_patterns[i].pattern;
      selected_index = i;
      continue;
    }
    bool selected_covers_candidate =
        model_reference_subsumes(selected_index, i);
    bool candidate_covers_selected =
        model_reference_subsumes(i, selected_index);
    if ((selected_covers_candidate != candidate_covers_selected &&
         selected_covers_candidate) ||
        (selected_covers_candidate == candidate_covers_selected &&
         strcmp(model_cross_patterns[i].pattern, selected) < 0)) {
      selected = model_cross_patterns[i].pattern;
      selected_index = i;
    }
  }
  return selected;
}

static int model_cross_policy_matches_model(st_policy_t *actual,
                                            const bool *active, uint32_t seed,
                                            size_t step) {
  size_t expected_policy_count = 0;
  for (size_t i = 0;
       i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]); i++)
    expected_policy_count += active[i] ? 1u : 0u;
  if (st_policy_rule_count(actual) != expected_policy_count)
    return 0;

  for (size_t probe = 0;
       probe < sizeof(model_cross_probes) / sizeof(model_cross_probes[0]);
       probe++) {
    size_t expected_match_count = 0;
    for (size_t i = 0;
         i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]);
         i++)
      expected_match_count +=
          active[i] && (model_cross_patterns[i].matches & PROBE_BIT(probe))
              ? 1u
              : 0u;
    const char *selected = model_reference_selected(active, probe);
    st_eval_result_t result = {0};
    if (test_st_policy_eval(actual, model_cross_probes[probe], &result) !=
            ST_OK ||
        result.matches != (selected != NULL) ||
        ((result.matching_pattern == NULL) != (selected == NULL)) ||
        (selected && !test_pattern_is_cpl(
                         (st_netpattern_view_t){result.matching_pattern,
                                                result.matching_pattern_length},
                         selected))) {
      fprintf(stderr, "cross seed %u step %zu probe %zu: eval differs\n", seed,
              step, probe);
      fprintf(stderr, "  actual=%s expected=%s\n",
              result.matching_pattern ? result.matching_pattern : "(none)",
              selected ? selected : "(none)");
      return 0;
    }

    st_netpattern_view_t *matches = NULL;
    size_t match_count = 0;
    if (test_st_policy_verify_all(actual, model_cross_probes[probe], &matches,
                                  &match_count) != ST_OK ||
        match_count != expected_match_count) {
      st_policy_matches_free(matches);
      return 0;
    }
    for (size_t i = 0;
         i < sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]);
         i++) {
      if (!active[i] || !(model_cross_patterns[i].matches & PROBE_BIT(probe)))
        continue;
      bool found = false;
      for (size_t j = 0; j < match_count; j++)
        found = found || test_pattern_is_cpl(matches[j],
                                             model_cross_patterns[i].pattern);
      if (!found) {
        st_policy_matches_free(matches);
        return 0;
      }
    }
    st_policy_matches_free(matches);
  }
  return 1;
}

static int model_run_cross_policy_model(const char *replace_path,
                                        const char *append_path) {
  for (uint32_t seed = 1; seed <= 8; seed++) {
    st_policy_ctx_t *actual_ctx = st_policy_ctx_new();
    st_policy_t *actual = actual_ctx ? st_policy_new(actual_ctx) : NULL;
    bool active[sizeof(model_cross_patterns) /
                sizeof(model_cross_patterns[0])] = {false};
    uint32_t state = seed * UINT32_C(17);
    if (!actual_ctx || !actual)
      return 0;

    for (size_t step = 0; step < 256; step++) {
      size_t index =
          model_random_next(&state) %
          (sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]));
      size_t second =
          model_random_next(&state) %
          (sizeof(model_cross_patterns) / sizeof(model_cross_patterns[0]));
      uint32_t operation = model_random_next(&state) % 9;
      if (operation <= 1) {
        if (test_st_policy_add(actual, model_cross_patterns[index].pattern) !=
            ST_OK)
          return 0;
        model_reference_add(active, index);
      } else if (operation == 2) {
        if (test_st_policy_remove(actual,
                                  model_cross_patterns[index].pattern) != ST_OK)
          return 0;
        active[index] = false;
      } else if (operation == 3) {
        const char *batch[] = {model_cross_patterns[index].pattern,
                               model_cross_patterns[second].pattern};
        if (test_st_policy_batch_add(actual, batch, 2) != ST_OK)
          return 0;
        model_reference_add(active, index);
        model_reference_add(active, second);
      } else if (operation == 4) {
        if (st_policy_compact(actual) != ST_OK)
          return 0;
      } else if (operation == 5) {
        if (st_policy_save(actual, replace_path) != ST_OK ||
            st_policy_load(actual, replace_path, true) != ST_OK)
          return 0;
      } else if (operation == 6 && (model_random_next(&state) & 7u) == 0) {
        if (st_policy_clear(actual) != ST_OK)
          return 0;
        memset(active, 0, sizeof(active));
      } else {
        st_policy_ctx_t *source_ctx = st_policy_ctx_new();
        st_policy_t *source = source_ctx ? st_policy_new(source_ctx) : NULL;
        if (!source ||
            test_st_policy_add(source, model_cross_patterns[index].pattern) !=
                ST_OK ||
            test_st_policy_add(source, model_cross_patterns[second].pattern) !=
                ST_OK)
          return 0;
        st_error_t err;
        if (operation == 7) {
          err = st_policy_merge(actual, source);
        } else {
          err = st_policy_save(source, append_path);
          if (err == ST_OK)
            err = st_policy_load(actual, append_path, false);
        }
        st_policy_free(source);
        st_policy_ctx_release(source_ctx);
        if (err != ST_OK)
          return 0;
        model_reference_add(active, index);
        model_reference_add(active, second);
      }

      if (!model_cross_policy_matches_model(actual, active, seed, step))
        return 0;
    }
    st_policy_free(actual);
    st_policy_ctx_release(actual_ctx);
  }
  return 1;
}

static int model_family(size_t index) {
  if (index >= 2 && index <= 4)
    return 1;
  if (index >= 5 && index <= 7)
    return 2;
  if (index >= 8 && index <= 10)
    return 3;
  if (index >= 12 && index <= 14)
    return 4;
  if (index >= 15 && index <= 17)
    return 5;
  if (index >= 18 && index <= 20)
    return 6;
  if (index >= 21 && index <= 23)
    return 7;
  if (index >= 24 && index <= 26)
    return 8;
  return 0;
}

static bool model_is_generic(size_t index) {
  return index == 4 || index == 7 || index == 10 || index == 14 ||
         index == 17 || index == 20 || index == 23 || index == 26;
}

static void model_model_add(bool *active, size_t index) {
  int group = model_family(index);
  if (group != 0 && !model_is_generic(index)) {
    for (size_t i = 0; i < sizeof(model_patterns) / sizeof(model_patterns[0]);
         i++)
      if (active[i] && model_family(i) == group && model_is_generic(i))
        return;
  }
  if (group != 0 && model_is_generic(index))
    for (size_t i = 0; i < sizeof(model_patterns) / sizeof(model_patterns[0]);
         i++)
      if (model_family(i) == group)
        active[i] = false;
  active[index] = true;
}

static const char *model_expected_pattern(const bool *active, size_t probe) {
  static const int specific[] = {0,  1,  2,  3,  -1, 5,  6,  8,  9,  -1, 11,
                                 -1, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25};
  static const int generic[] = {-1, -1, 4,  4,  4,  7,  7,  10, 10, 10, -1,
                                -1, 14, 14, 17, 17, 20, 20, 23, 23, 26, 26};
  if (specific[probe] >= 0 && active[specific[probe]])
    return model_patterns[specific[probe]];
  if (generic[probe] >= 0 && active[generic[probe]])
    return model_patterns[generic[probe]];
  return NULL;
}

static int model_policy_matches_model(st_policy_t *actual, const bool *active,
                                      uint32_t seed, size_t step) {
  size_t expected_count = 0;
  for (size_t i = 0; i < sizeof(model_patterns) / sizeof(model_patterns[0]);
       i++)
    expected_count += active[i] ? 1 : 0;
  if (st_policy_rule_count(actual) != expected_count) {
    fprintf(stderr, "seed %u step %zu: count differs (%zu != %zu)\n", seed,
            step, st_policy_rule_count(actual), expected_count);
    return 0;
  }
  for (size_t i = 0; i < sizeof(model_probes) / sizeof(model_probes[0]); i++) {
    const char *expected = model_expected_pattern(active, i);
    st_eval_result_t result = {0};
    if (test_st_policy_eval(actual, model_probes[i], &result) != ST_OK ||
        result.matches != (expected != NULL) ||
        ((result.matching_pattern == NULL) != (expected == NULL)) ||
        (expected && !test_pattern_is_cpl(
                         (st_netpattern_view_t){result.matching_pattern,
                                                result.matching_pattern_length},
                         expected))) {
      fprintf(stderr, "seed %u step %zu probe %zu: evaluation differs\n", seed,
              step, i);
      fprintf(stderr, "  actual=%s expected=%s\n",
              result.matching_pattern ? result.matching_pattern : "(none)",
              expected ? expected : "(none)");
      return 0;
    }
    st_netpattern_view_t *matches = NULL;
    size_t match_count = 0;
    if (test_st_policy_verify_all(actual, model_probes[i], &matches,
                                  &match_count) != ST_OK ||
        match_count != (expected ? 1u : 0u) ||
        (expected && !test_pattern_is_cpl(matches[0], expected))) {
      st_policy_matches_free(matches);
      return 0;
    }
    st_policy_matches_free(matches);
  }
  return 1;
}

static int run_model(int argc, char **argv) {
  (void)argc;
  (void)argv;
  char path[] = "/tmp/shelltype-model-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0 || close(fd) != 0)
    return 1;
  char append_path[] = "/tmp/shelltype-cross-model-XXXXXX";
  fd = mkstemp(append_path);
  if (fd < 0 || close(fd) != 0) {
    unlink(path);
    return 1;
  }

  for (uint32_t seed = 1; seed <= 8; seed++) {
    st_policy_ctx_t *actual_ctx = st_policy_ctx_new();
    st_policy_t *actual = actual_ctx ? st_policy_new(actual_ctx) : NULL;
    bool active[sizeof(model_patterns) / sizeof(model_patterns[0])] = {false};
    uint32_t state = seed;
    if (!actual_ctx || !actual)
      return 1;

    for (size_t step = 0; step < 256; step++) {
      size_t index = model_random_next(&state) %
                     (sizeof(model_patterns) / sizeof(model_patterns[0]));
      uint32_t operation = model_random_next(&state) % 7;
      switch (operation) {
      case 0:
      case 1:
        if (test_st_policy_add(actual, model_patterns[index]) != ST_OK)
          return 1;
        model_model_add(active, index);
        break;
      case 2:
        if (test_st_policy_remove(actual, model_patterns[index]) != ST_OK)
          return 1;
        active[index] = false;
        break;
      case 3: {
        size_t second = model_random_next(&state) %
                        (sizeof(model_patterns) / sizeof(model_patterns[0]));
        const char *batch[] = {model_patterns[index], model_patterns[second]};
        if (test_st_policy_batch_add(actual, batch, 2) != ST_OK)
          return 1;
        model_model_add(active, index);
        model_model_add(active, second);
        break;
      }
      case 4:
        if (st_policy_compact(actual) != ST_OK)
          return 1;
        break;
      case 5:
        if (st_policy_save(actual, path) != ST_OK ||
            st_policy_load(actual, path, true) != ST_OK)
          return 1;
        break;
      case 6:
        if ((model_random_next(&state) & 15u) == 0) {
          if (st_policy_clear(actual) != ST_OK)
            return 1;
          memset(active, 0, sizeof(active));
        }
        break;
      }

      if (!model_policy_matches_model(actual, active, seed, step))
        return 1;
    }
    st_policy_free(actual);
    st_policy_ctx_release(actual_ctx);
  }
  if (!model_run_cross_policy_model(path, append_path)) {
    unlink(path);
    unlink(append_path);
    return 1;
  }
  unlink(path);
  unlink(append_path);
  puts("policy models: 2 domains x 8 seeds x 256 transitions passed");
  return 0;
}
#undef PROBE_BIT

/* --- capacity (from test_policy_capacity.c) --- */
enum { capacity_GROUP_COUNT = 256, capacity_LEAVES_PER_GROUP = 256 };

static int capacity_make_pattern(char *buffer, size_t capacity, size_t group,
                                 size_t leaf) {
  int written = snprintf(buffer, capacity, "group%03zu leaf%03zu", group, leaf);
  return written >= 0 && (size_t)written < capacity;
}

static SHELL_NONNULL(1) void report_error(const char *operation,
                                          st_error_t error) {
  int error_number = errno;
  fprintf(stderr, "%s failed: %s (error=%d)", operation, st_error_string(error),
          error);
  if (error == ST_ERR_IO)
    fprintf(stderr, " errno=%d (%s)", error_number, strerror(error_number));
  fputc('\n', stderr);
}

static int matches(st_policy_t *policy, const char *command, bool expected) {
  st_eval_result_t result = {0};
  return test_st_policy_eval(policy, command, &result) == ST_OK &&
         result.matches == expected;
}

static int capacity_files_equal(const char *left_path, const char *right_path) {
  FILE *left = fopen(left_path, "rb");
  FILE *right = fopen(right_path, "rb");
  if (!left || !right) {
    if (left)
      fclose(left);
    if (right)
      fclose(right);
    return 0;
  }
  unsigned char left_buffer[8192], right_buffer[8192];
  int equal = 1;
  for (;;) {
    size_t left_count = fread(left_buffer, 1, sizeof(left_buffer), left);
    size_t right_count = fread(right_buffer, 1, sizeof(right_buffer), right);
    if (left_count != right_count ||
        memcmp(left_buffer, right_buffer, left_count) != 0) {
      equal = 0;
      break;
    }
    if (left_count < sizeof(left_buffer)) {
      equal = feof(left) && feof(right) && !ferror(left) && !ferror(right);
      break;
    }
  }
  int left_closed = fclose(left);
  int right_closed = fclose(right);
  if (left_closed != 0 || right_closed != 0)
    equal = 0;
  return equal;
}

static int capacity_nfa_ids_cover_capacity(const char *path, uint32_t base,
                                           const char *first,
                                           const char *middle,
                                           const char *last) {
  FILE *file = fopen(path, "r");
  if (!file)
    return 0;
  bool *seen = calloc(ST_MAX_POLICY_PATTERNS, sizeof(*seen));
  if (!seen) {
    fclose(file);
    return 0;
  }
  char line[ST_MAX_NETPATTERN_LEN + 128];
  size_t id_count = 0, tag_count = 0;
  bool saw_first = false, saw_middle = false, saw_last = false;
  uint32_t current_id = 0;
  while (fgets(line, sizeof(line), file)) {
    (void)sscanf(line, " PatternId: %u", &current_id);
    if (strstr(line, "EosTarget: yes")) {
      if (current_id < base || current_id - base >= ST_MAX_POLICY_PATTERNS ||
          seen[current_id - base]) {
        free(seen);
        fclose(file);
        return 0;
      }
      seen[current_id - base] = true;
      id_count++;
    }
    if (strstr(line, "Tags: ")) {
      tag_count++;
      saw_first = saw_first || strstr(line, first) != NULL;
      saw_middle = saw_middle || strstr(line, middle) != NULL;
      saw_last = saw_last || strstr(line, last) != NULL;
    }
  }
  int valid = fclose(file) == 0 && id_count == ST_MAX_POLICY_PATTERNS &&
              tag_count == ST_MAX_POLICY_PATTERNS && saw_first && saw_middle &&
              saw_last;
  for (size_t i = 0; i < ST_MAX_POLICY_PATTERNS; i++)
    valid = valid && seen[i];
  free(seen);
  return valid;
}

static int run_capacity(int argc, char **argv) {
  (void)argc;
  (void)argv;
  int status = 1;
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_ctx_t *loaded_context = NULL;
  st_policy_t *loaded = NULL;
  char directory[PATH_MAX], paths[3][PATH_MAX];
  char *first_save = paths[0], *second_save = paths[1], *nfa_path = paths[2];
  bool directory_created = false;
  char pattern[ST_MAX_NETPATTERN_LEN];
  if (!ctx || !policy) {
    fprintf(stderr, "policy allocation failed\n");
    goto cleanup;
  }

  /* The full-capacity NFA is much larger than the saved policies. Keep every
   * fixture in one private directory and honor the caller's storage choice. */
  const char *temporary_root = getenv("TMPDIR");
  if (!temporary_root || !temporary_root[0])
    temporary_root = "/tmp";
  int written = snprintf(directory, sizeof(directory),
                         "%s/shelltype-capacity-XXXXXX", temporary_root);
  if (written < 0 || (size_t)written >= sizeof(directory)) {
    fprintf(stderr, "capacity fixture directory path is too long\n");
    goto cleanup;
  }
  if (!mkdtemp(directory)) {
    perror("capacity fixture directory creation failed");
    goto cleanup;
  }
  directory_created = true;
  static const char *const filenames[] = {"first.policy", "second.policy",
                                          "policy.nfa"};
  for (size_t i = 0; i < sizeof(filenames) / sizeof(*filenames); ++i) {
    written =
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", directory, filenames[i]);
    if (written < 0 || (size_t)written >= sizeof(paths[i])) {
      fprintf(stderr, "capacity fixture file path is too long\n");
      goto cleanup;
    }
  }

  size_t added = 0;
  for (size_t group = 0; group < capacity_GROUP_COUNT; group++) {
    size_t leaves = group + 1 == capacity_GROUP_COUNT
                        ? capacity_LEAVES_PER_GROUP - 1
                        : capacity_LEAVES_PER_GROUP;
    for (size_t leaf = 0; leaf < leaves; leaf++) {
      if (!capacity_make_pattern(pattern, sizeof(pattern), group, leaf) ||
          test_st_policy_add(policy, pattern) != ST_OK) {
        fprintf(stderr, "initial add failed group=%zu leaf=%zu\n", group, leaf);
        goto cleanup;
      }
      added++;
    }
  }
  if (added != ST_MAX_POLICY_PATTERNS ||
      st_policy_rule_count(policy) != added) {
    fprintf(stderr, "initial count failed: %zu/%zu\n", added,
            st_policy_rule_count(policy));
    goto cleanup;
  }

  if (!capacity_make_pattern(pattern, sizeof(pattern), capacity_GROUP_COUNT - 1,
                             capacity_LEAVES_PER_GROUP - 1) ||
      test_st_policy_add(policy, pattern) != ST_ERR_LIMIT ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS) {
    fprintf(stderr, "capacity limit check failed\n");
    goto cleanup;
  }

  char first[ST_MAX_NETPATTERN_LEN], middle[ST_MAX_NETPATTERN_LEN];
  char last[ST_MAX_NETPATTERN_LEN], removed[ST_MAX_NETPATTERN_LEN];
  if (!capacity_make_pattern(first, sizeof(first), 0, 0) ||
      !capacity_make_pattern(middle, sizeof(middle), capacity_GROUP_COUNT / 2,
                             capacity_LEAVES_PER_GROUP / 2) ||
      !capacity_make_pattern(last, sizeof(last), capacity_GROUP_COUNT - 1,
                             capacity_LEAVES_PER_GROUP - 2) ||
      !capacity_make_pattern(removed, sizeof(removed), capacity_GROUP_COUNT / 2,
                             capacity_LEAVES_PER_GROUP / 2 + 1) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, last, true)) {
    fprintf(stderr, "initial match check failed\n");
    goto cleanup;
  }

  if (test_st_policy_remove(policy, removed) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
      !matches(policy, removed, false) ||
      test_st_policy_add(policy, pattern) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, pattern, true)) {
    fprintf(stderr, "remove/readd check failed\n");
    goto cleanup;
  }

  /* Reuse tombstoned registry slots across existing and new trie branches. */
  static const struct {
    size_t group;
    size_t leaf;
  } replacements[] = {
      {1, 100},
      {capacity_GROUP_COUNT / 2, 100},
      {capacity_GROUP_COUNT - 1, capacity_LEAVES_PER_GROUP - 2}};
  for (size_t i = 0; i < sizeof(replacements) / sizeof(replacements[0]); i++) {
    char old_pattern[ST_MAX_NETPATTERN_LEN];
    char replacement[ST_MAX_NETPATTERN_LEN];
    if (!capacity_make_pattern(old_pattern, sizeof(old_pattern),
                               replacements[i].group, replacements[i].leaf) ||
        !capacity_make_pattern(replacement, sizeof(replacement),
                               capacity_GROUP_COUNT, i) ||
        test_st_policy_remove(policy, old_pattern) != ST_OK ||
        st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
        test_st_policy_add(policy, replacement) != ST_OK ||
        st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
        !matches(policy, replacement, true)) {
      fprintf(stderr, "tombstone reuse failed at group %zu (count=%zu)\n",
              replacements[i].group, st_policy_rule_count(policy));
      goto cleanup;
    }
  }

  char replacement_last[ST_MAX_NETPATTERN_LEN];
  if (!capacity_make_pattern(replacement_last, sizeof(replacement_last),
                             capacity_GROUP_COUNT, 2) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true)) {
    fprintf(stderr, "replacement last check failed\n");
    goto cleanup;
  }

  /* Exercise the complete lifecycle while the 16-bit registry is full. */
  if (st_policy_compact(policy) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true)) {
    fprintf(stderr, "compact check failed\n");
    goto cleanup;
  }

  st_error_t error = st_policy_save(policy, first_save);
  if (error != ST_OK) {
    report_error("first save", error);
    goto cleanup;
  }

  loaded_context = st_policy_ctx_new();
  loaded = loaded_context ? st_policy_new(loaded_context) : NULL;
  if (!loaded) {
    fprintf(stderr, "loaded policy allocation failed\n");
    goto cleanup;
  }
  error = st_policy_load(loaded, first_save, true);
  if (error != ST_OK) {
    report_error("policy load", error);
    goto cleanup;
  }
  if (st_policy_rule_count(loaded) != ST_MAX_POLICY_PATTERNS ||
      !matches(loaded, first, true) || !matches(loaded, middle, true) ||
      !matches(loaded, replacement_last, true)) {
    fprintf(stderr, "loaded policy match check failed\n");
    goto cleanup;
  }
  error = st_policy_save(loaded, second_save);
  if (error != ST_OK) {
    report_error("second save", error);
    goto cleanup;
  }
  if (!capacity_files_equal(first_save, second_save)) {
    fprintf(stderr, "load/save equivalence failed\n");
    goto cleanup;
  }

  uint32_t highest_base = UINT32_MAX - (uint32_t)ST_MAX_POLICY_PATTERNS + 1u;
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = highest_base,
                                  .include_tags = true,
                                  .identifier = "capacity"};
  error = st_policy_render_nfa(loaded, nfa_path, &options);
  if (error != ST_OK) {
    report_error("nfa render", error);
    goto cleanup;
  }
  if (!capacity_nfa_ids_cover_capacity(nfa_path, highest_base, first, middle,
                                       replacement_last)) {
    fprintf(stderr, "nfa capacity check failed\n");
    goto cleanup;
  }
  options.pattern_id_base++;
  if (st_policy_render_nfa(loaded, nfa_path, &options) != ST_ERR_LIMIT) {
    fprintf(stderr, "nfa pattern id limit check failed\n");
    goto cleanup;
  }

  /* Capacity checks must account for the narrower rules removed by a broader
   * insertion. All 256 group000 rules are replaced by one rule. */
  st_error_t broad_result = test_st_policy_add(policy, "group000 *");
  if (broad_result != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      !matches(policy, "group000 any-value", true)) {
    fprintf(stderr, "broad insertion failed: error=%d count=%zu\n",
            broad_result, st_policy_rule_count(policy));
    goto cleanup;
  }
  if (test_st_policy_add(policy, "group000 still-covered") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      test_st_policy_remove(policy, "group000 *") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 256 ||
      test_st_policy_add(policy, "group000 restored") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      !matches(policy, "group000 restored", true)) {
    fprintf(stderr, "literal fast-path wildcard check failed\n");
    goto cleanup;
  }

  status = 0;
cleanup:
  st_policy_free(loaded);
  st_policy_ctx_release(loaded_context);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  if (directory_created && !test_atomic_cleanup_directory(directory)) {
    fprintf(stderr, "capacity fixture directory cleanup failed: %s\n",
            directory);
    status = 1;
  }
  if (status == 0)
    puts("policy capacity: boundary, tombstone reuse, and subsumption passed");
  return status;
}

/* --- user_data (from test_policy_user_data.c) --- */
/* The user pointer on a policy object is the caller's association: never
 * interpreted, freed or serialized, and untouched by every other operation. */

static int user_data_failed;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      user_data_failed = 1;                                                    \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static int user_data_test_association(void) {
  char directory[] = "/tmp/shelltype-user-data-XXXXXX";
  int made = mkdtemp(directory) != NULL;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *first = context ? st_policy_new(context) : NULL;
  st_policy_t *second = context ? st_policy_new(context) : NULL;
  st_policy_t *loaded = context ? st_policy_new(context) : NULL;
  int first_record = 1, second_record = 2, loaded_record = 3;
  char path[256];
  CHECK(made && context && first && second && loaded);

  /* A new policy has no association, and each object keeps its own. */
  CHECK(st_policy_user_data(first) == NULL);
  st_policy_set_user_data(first, &first_record);
  st_policy_set_user_data(second, &second_record);
  CHECK(st_policy_user_data(first) == &first_record);
  CHECK(st_policy_user_data(second) == &second_record);

  /* Rules, evaluation, save, load and clear all leave it alone. */
  CHECK(test_st_policy_add(first, "git status") == ST_OK);
  CHECK(st_policy_user_data(first) == &first_record);
  st_netargv_view_t input = {.data = "3:git,6:status,", .length = 15};
  bool matched = false;
  CHECK(st_policy_match_view(first, input, &matched) == ST_OK && matched);
  CHECK(st_policy_user_data(first) == &first_record);

  snprintf(path, sizeof(path), "%s/policy", directory);
  CHECK(st_policy_save(first, path) == ST_OK);
  st_policy_set_user_data(loaded, &loaded_record);
  CHECK(st_policy_load(loaded, path, true) == ST_OK);
  CHECK(st_policy_user_data(loaded) == &loaded_record);
  CHECK(st_policy_user_data(first) == &first_record);

  CHECK(st_policy_clear(first) == ST_OK);
  CHECK(st_policy_user_data(first) == &first_record);

  /* The caller can clear it, and a policy copied by loading carries none. */
  st_policy_set_user_data(first, NULL);
  CHECK(st_policy_user_data(first) == NULL);
  CHECK(st_policy_user_data(second) == &second_record);

cleanup:
  st_policy_free(first);
  st_policy_free(second);
  st_policy_free(loaded);
  st_policy_ctx_release(context);
  if (made)
    (void)test_atomic_cleanup_directory(directory);
  return user_data_failed;
}

static int run_user_data(int argc, char **argv) {
  (void)argc;
  (void)argv;
  if (user_data_test_association() != 0)
    return 1;
  puts("policy user data tests passed");
  return 0;
}
#undef CHECK

int main(int argc, char **argv) {
  int status = 0;
  status |= run_policy(argc, argv);
  status |= run_compact(argc, argv);
  status |= run_model(argc, argv);
  status |= run_capacity(argc, argv);
  status |= run_user_data(argc, argv);
  return status != 0;
}
