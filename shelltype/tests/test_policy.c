/*
 * test_policy.c – Unit tests for the policy module.
 */

#define _POSIX_C_SOURCE 200809L

#include "shelltype.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int policy_matches(st_policy_t *policy, const char *command,
                          bool expected) {
  st_eval_result_t result = {0};
  return st_policy_eval(policy, command, &result) == ST_OK &&
         result.matches == expected;
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
      {"docker run *", ST_OK, 5},    {"", ST_ERR_INVALID, 5},
      {NULL, ST_ERR_INVALID, 5},     {"git commit", ST_OK, 4},
      {"git commit -m *", ST_OK, 3}, {"git", ST_OK, 2},
      {"ls -l *", ST_OK, 1},         {"cat * | grep *", ST_OK, 0},
      {"cat * | grep *", ST_OK, 0},
  };

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  ASSERT(st_policy_new(NULL) == NULL);
  ASSERT(st_policy_count(NULL) == 0);
  ASSERT(st_policy_add(NULL, "git") == ST_ERR_INVALID);
  ASSERT(st_policy_remove(NULL, "git") == ST_ERR_INVALID);
  st_policy_free(NULL);

  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(additions) / sizeof(additions[0]); i++) {
    ASSERT(st_policy_add(policy, additions[i].pattern) == additions[i].error);
    ASSERT(st_policy_count(policy) == additions[i].count);
  }
  ASSERT(policy_matches(policy, "git", true));
  ASSERT(policy_matches(policy, "git commit", true));
  ASSERT(policy_matches(policy, "git commit -m message", true));
  ASSERT(policy_matches(policy, "ls -l /tmp", true));
  ASSERT(policy_matches(policy, "cat input | grep error", true));

  for (size_t i = 0; i < sizeof(removals) / sizeof(removals[0]); i++) {
    ASSERT(st_policy_remove(policy, removals[i].pattern) == removals[i].error);
    ASSERT(st_policy_count(policy) == removals[i].count);
    if (i == 3) {
      ASSERT(policy_matches(policy, "git", true));
      ASSERT(policy_matches(policy, "git commit", false));
      ASSERT(policy_matches(policy, "git commit -m message", true));
    }
  }
  ASSERT(policy_matches(policy, "git", false));
  ASSERT(policy_matches(policy, "ls -l /tmp", false));
  ASSERT(policy_matches(policy, "cat input | grep error", false));

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

static int test_policy_persistence_transitions(void) {
  static const char *patterns[] = {"git", "git commit -m *", "ls -l *",
                                   "cat * | grep *"};
  static const char *probes[] = {"git",
                                 "git commit -m message",
                                 "ls -l /tmp",
                                 "cat input | grep error",
                                 "cmd0 arg0 value",
                                 "cmd49 arg49 value"};
  char path[] = "/tmp/shelltype-policy-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  ASSERT(close(fd) == 0);
  snprintf(policy_temp_paths[0], sizeof(policy_temp_paths[0]), "%s", path);

  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *source = st_policy_new(ctx);
  st_policy_t *loaded = st_policy_new(ctx);
  st_policy_t *empty = st_policy_new(ctx);
  ASSERT(ctx && source && loaded && empty);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(st_policy_add(source, patterns[i]) == ST_OK);
  for (int i = 0; i < 50; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "cmd%d arg%d *", i, i);
    ASSERT(st_policy_add(source, pattern) == ST_OK);
  }
  const size_t source_count = sizeof(patterns) / sizeof(patterns[0]) + 50;
  ASSERT(st_policy_count(source) == source_count);
  ASSERT(st_policy_save(NULL, path) == ST_ERR_INVALID);
  ASSERT(st_policy_save(source, NULL) == ST_ERR_INVALID);
  ASSERT(st_policy_load(NULL, path, false) == ST_ERR_INVALID);
  ASSERT(st_policy_load(loaded, NULL, false) == ST_ERR_INVALID);
  ASSERT(st_policy_save(source, path) == ST_OK);

  ASSERT(st_policy_add(loaded, "docker run *") == ST_OK);
  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_count(loaded) == source_count + 1);
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_matches(loaded, probes[i], true));
  ASSERT(policy_matches(loaded, "docker run image", true));

  /* Appending the same model is idempotent; replacing drops old entries. */
  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_count(loaded) == source_count + 1);
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(st_policy_count(loaded) == source_count);
  ASSERT(policy_matches(loaded, "docker run image", false));

  FILE *bad = fopen(path, "w");
  ASSERT(bad != NULL);
  ASSERT(fprintf(bad, "# CPL v1\n# patterns: 1\nunknown *\n"
                      "# CRC32: deadbeef\n") > 0);
  ASSERT(fclose(bad) == 0);
  ASSERT(st_policy_load(loaded, path, true) == ST_ERR_FORMAT);
  ASSERT(st_policy_count(loaded) == source_count);
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_matches(loaded, probes[i], true));

  ASSERT(st_policy_save(empty, path) == ST_OK);
  ASSERT(st_policy_load(loaded, path, true) == ST_OK);
  ASSERT(st_policy_count(loaded) == 0);
  ASSERT(unlink(path) == 0);
  ASSERT(st_policy_load(source, path, false) == ST_ERR_IO);

  st_policy_free(empty);
  st_policy_free(loaded);
  st_policy_free(source);
  st_policy_ctx_free(ctx);
  return 1;
}

/* ============================================================
 * BUG FIX TESTS
 * ============================================================ */

/* Fix 1: st_policy_eval returns ST_OK for non-matching commands */
static int test_non_matching_returns_ok(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));

  st_eval_result_t result;
  st_error_t err = st_policy_eval(policy, "docker run ubuntu", &result);
  ASSERT(err == ST_OK);
  ASSERT(!result.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Fix 1: verify-only path (result==NULL) returns ST_OK for non-match */
static int test_verify_only_returns_ok(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));

  /* Completely unrelated command — should return ST_OK, not error */
  st_error_t err = st_policy_eval(policy, "docker run ubuntu", NULL);
  ASSERT(err == ST_OK);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Fix 5: empty command returns ST_OK with matches=false */
static int test_empty_command_returns_ok(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));

  st_eval_result_t result;
  st_error_t err = st_policy_eval(policy, "", &result);
  ASSERT(err == ST_OK);
  ASSERT(!result.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
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
      ASSERT(st_policy_add(policy, "git status") == ST_OK);
    ASSERT(st_policy_add(policy, cases[i].wildcard_pattern) == ST_OK);

    st_policy_stats_t before = {0}, after = {0};
    st_policy_get_stats(policy, &before);
    ASSERT(st_policy_eval(policy, cases[i].command, NULL) == ST_OK);
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
    ASSERT(st_policy_eval(policy, cases[i].command, &result) == ST_OK);
    ASSERT(!result.matches);
    ASSERT(result.suggestion_count == cases[i].suggestion_count);
    for (size_t j = 0; j < result.suggestion_count; j++)
      ASSERT(suggestion_is(&result.suggestions[j], cases[i].suggestions[j],
                           cases[i].based_on[j], cases[i].confidence));
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
  }
  return 1;
}

static int test_suggestion_contracts(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT_OK(st_policy_add(policy, "docker run -d nginx"));
  ASSERT_OK(st_policy_add(policy, "docker run -it ubuntu"));
  ASSERT_OK(st_policy_add(policy, "docker run --rm alpine"));

  st_eval_result_t result = {0};
  ASSERT(st_policy_eval(policy, "docker exec -it container", &result) == ST_OK);
  ASSERT(!result.matches);
  ASSERT(result.suggestion_count == 2);
  ASSERT(suggestion_is(&result.suggestions[0], "docker exec -it container",
                       NULL, 0.25));
  ASSERT(suggestion_is(&result.suggestions[1], "docker exec #sopt container",
                       NULL, 0.25));

  static const struct {
    st_token_type_t type;
    const char *symbol;
    const char *wider_pattern;
  } variant_cases[] = {
      {ST_TYPE_SHA, "#sha", "docker #h"},
      {ST_TYPE_IPV4, "#i", "docker #ipaddr"},
      {ST_TYPE_QUOTED, "#q", "docker #qs"},
      {ST_TYPE_FILENAME, "#f", "docker #r"},
      {ST_TYPE_ABS_PATH, "#p", "docker #path"},
      {ST_TYPE_SHORTOPT, "#sopt", "docker #opt"},
      {ST_TYPE_PORT, "#port", "docker #n"},
      {ST_TYPE_PERM_OCTAL, "#perm", "docker #n"},
      {ST_TYPE_METHOD, "#method", "docker #w"},
      {ST_TYPE_UUID, "#uuid", "docker #val"},
      {ST_TYPE_WORD, "#w", NULL},
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
    snprintf(exact, sizeof(exact), "docker %s", variant_cases[i].symbol);
    ASSERT(suggestion_is(&variants[0], exact, NULL, 1.0));
    if (variant_cases[i].wider_pattern)
      ASSERT(suggestion_is(&variants[1], variant_cases[i].wider_pattern, NULL,
                           1.0));
  }

  st_token_t tokens[2] = {{.text = "docker", .type = ST_TYPE_LITERAL},
                          {.text = "#n", .type = ST_TYPE_NUMBER}};
  ASSERT(st_policy_suggest_variants(NULL, tokens, 2, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, NULL, 2, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, tokens, 0, variants) == 0);
  ASSERT(st_policy_suggest_variants(policy, tokens, 2, NULL) == 0);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_context_and_compaction_transitions(void) {
  st_policy_ctx_retain(NULL);
  st_policy_ctx_release(NULL);
  st_policy_ctx_t *released = st_policy_ctx_new();
  ASSERT(released != NULL);
  st_policy_ctx_release(released);

  st_policy_ctx_t *ctx = st_policy_ctx_new_with_arena(1);
  ASSERT(ctx != NULL);
  ASSERT(st_policy_ctx_reset(NULL) == ST_ERR_INVALID);
  ASSERT(st_policy_ctx_compact(NULL) == ST_ERR_INVALID);
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
  ASSERT(st_policy_add(p1, "git status") == ST_OK);
  ASSERT(st_policy_add(p1, "git commit -m *") == ST_OK);
  ASSERT(st_policy_add(p1, "ls -la") == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_ERR_INVALID);
  ASSERT(st_policy_ctx_compact(ctx) == ST_ERR_INVALID);

  st_policy_t *p2 = st_policy_new(ctx);
  ASSERT(p2 != NULL);
  ASSERT(!st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_add(p2, "docker ps") == ST_OK);
  ASSERT(st_policy_compact(p1) == ST_ERR_INVALID);
  ASSERT(policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_matches(p2, "docker ps", true));

  st_policy_free(p2);
  ASSERT(st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_compact(p1) == ST_OK);
  ASSERT(st_policy_count(p1) == 3);
  ASSERT(policy_matches(p1, "git status", true));
  ASSERT(policy_matches(p1, "git commit -m fix", true));
  ASSERT(policy_matches(p1, "ls -la", true));

  st_policy_free(p1);
  ASSERT(!st_policy_ctx_is_exclusive(ctx));
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_reset(ctx) == ST_OK);
  ASSERT(st_policy_ctx_compact(ctx) == ST_OK);
  const char *second = st_policy_ctx_intern(ctx, "reused");
  ASSERT(second != NULL && strcmp(second, "reused") == 0);
  p1 = st_policy_new(ctx);
  ASSERT(p1 != NULL);
  ASSERT(st_policy_add(p1, "new policy") == ST_OK);
  ASSERT(policy_matches(p1, "new policy", true));
  st_policy_free(p1);
  st_policy_ctx_free(ctx);
  ASSERT(st_policy_ctx_new_with_arena(SIZE_MAX) == NULL);
  return 1;
}

static int test_pattern_validation_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t error;
    const char *probe;
  } cases[] = {{"* status", ST_ERR_INVALID, NULL},
               {"  * status", ST_ERR_INVALID, NULL},
               {"* *", ST_ERR_INVALID, NULL},
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
    ASSERT(st_policy_add(policy, cases[i].pattern) == cases[i].error);
    ASSERT(st_policy_count(policy) == (cases[i].error == ST_OK));
    if (cases[i].probe && !policy_matches(policy, cases[i].probe, true)) {
      printf("  validation case %zu did not match probe '%s'\n", i,
             cases[i].probe);
      return 0;
    }
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
  }
  return 1;
}

/* Test DOT export */
static int test_dot_export(void) {
  char path[] = "/tmp/shelltype-policy-dot-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  ASSERT(close(fd) == 0);
  snprintf(policy_temp_paths[1], sizeof(policy_temp_paths[1]), "%s", path);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT(st_policy_add(policy, "git status") == ST_OK);
  ASSERT(st_policy_add(policy, "git commit -m *") == ST_OK);
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
  ASSERT(unlink(path) == 0);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test dry-run simulation */
static int test_dry_run_simulate(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "git status"));

  bool would_match = false;
  const char *conflict = NULL;
  st_error_t err =
      st_policy_simulate_add(policy, "git status", &would_match, &conflict);
  ASSERT(err == ST_OK);
  ASSERT(would_match == true);
  ASSERT(conflict != NULL);

  err = st_policy_simulate_add(policy, "git commit", &would_match, &conflict);
  ASSERT(err == ST_OK);
  ASSERT(would_match == false);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* ============================================================
 * CONCURRENCY AND ATOMIC TESTS
 * ============================================================ */

static int test_statistics_transitions(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  ASSERT(st_policy_add(policy, "git status") == ST_OK);
  ASSERT(st_policy_add(policy, "ls -la") == ST_OK);
  ASSERT(st_policy_add(policy, "docker ps") == ST_OK);

  st_policy_stats_t stats = {0};
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 0);
  ASSERT(stats.pattern_count == 3);
  ASSERT(stats.state_count > 0);
  ASSERT(stats.memory_bytes >= stats.state_count);

  static const char *commands[] = {"git status", "ls -la", "docker ps"};
  for (int i = 0; i < 100; i++) {
    for (size_t j = 0; j < sizeof(commands) / sizeof(commands[0]); j++) {
      st_eval_result_t result = {0};
      ASSERT(st_policy_eval(policy, commands[j], &result) == ST_OK);
      ASSERT(result.matches);
    }
  }

  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 300);
  ASSERT(stats.trie_walk_count == 300);
  ASSERT(stats.filter_reject_count == 0);
  ASSERT(stats.suggestion_count == 0);

  st_eval_result_t result = {0};
  ASSERT(st_policy_eval(policy, "unknown cmd", &result) == ST_OK);
  ASSERT(!result.matches);
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 301);
  ASSERT(stats.trie_walk_count == 301);
  ASSERT(stats.suggestion_count == result.suggestion_count);
  ASSERT(stats.suggestion_count > 0);

  ASSERT(st_policy_eval(policy, "unknown cmd", NULL) == ST_OK);
  st_policy_get_stats(policy, &stats);
  ASSERT(stats.eval_count == 302);
  ASSERT(stats.trie_walk_count == 301);
  ASSERT(stats.filter_reject_count == 1);
  ASSERT(stats.suggestion_count == result.suggestion_count);
  st_policy_get_stats(NULL, &stats);
  st_policy_get_stats(policy, NULL);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test remove prefix keeps children */
static int test_remove_prefix_keeps_children(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "git"));
  ASSERT_OK(st_policy_add(policy, "git commit"));
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));
  ASSERT(st_policy_count(policy) == 3);

  /* Remove "git" prefix - "git commit" and "git commit -m *" should remain */
  st_error_t err = st_policy_remove(policy, "git");
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 2);

  /* Verify remaining patterns work */
  st_eval_result_t result;
  err = st_policy_eval(policy, "git status", &result);
  ASSERT(err == ST_OK);
  ASSERT(!result.matches); /* "git" was removed */

  err = st_policy_eval(policy, "git commit", &result);
  ASSERT(err == ST_OK);
  ASSERT(result.matches);

  err = st_policy_eval(policy, "git commit -m fix", &result);
  ASSERT(err == ST_OK);
  ASSERT(result.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test filter rebuild lazy trigger */
static int test_filter_rebuild_lazy_trigger(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  /* Add patterns - triggers filter build */
  ASSERT_OK(st_policy_add(policy, "git status"));
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));

  st_policy_stats_t stats1;
  st_policy_get_stats(policy, &stats1);

  /* Add more patterns - epoch changes, next eval triggers rebuild */
  ASSERT_OK(st_policy_add(policy, "ls -la"));
  ASSERT_OK(st_policy_add(policy, "docker run *"));

  /* First eval should trigger rebuild */
  st_eval_result_t result;
  ASSERT_OK(st_policy_eval(policy, "docker ps", &result));

  st_policy_stats_t stats2;
  st_policy_get_stats(policy, &stats2);

  /* The first evaluation after a mutation must actually rebuild. */
  ASSERT(stats2.filter_rebuild_count > stats1.filter_rebuild_count);

  /* Second eval should not trigger rebuild */
  ASSERT_OK(st_policy_eval(policy, "docker ps", &result));

  st_policy_stats_t stats3;
  st_policy_get_stats(policy, &stats3);

  ASSERT(stats3.filter_rebuild_count == stats2.filter_rebuild_count);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test st_policy_clear removes all patterns */
static int test_policy_clear(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "git status"));
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));
  ASSERT_OK(st_policy_add(policy, "ls -la"));
  ASSERT(st_policy_count(policy) == 3);

  /* Clear should remove all patterns */
  st_error_t err = st_policy_clear(policy);
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 0);

  /* Policy should still work after clear */
  st_eval_result_t result;
  err = st_policy_eval(policy, "git status", &result);
  ASSERT(err == ST_OK);
  ASSERT(!result.matches); /* No patterns, no match */

  /* Should be able to add new patterns */
  err = st_policy_add(policy, "docker ps");
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 1);

  err = st_policy_eval(policy, "docker ps", &result);
  ASSERT(err == ST_OK);
  ASSERT(result.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test that incremental subsumption removes patterns subsumed by more general
 * ones. With incremental subsumption, adding `git commit -m *` after the
 * literals immediately removes them — no compact needed. */
static int test_compact_removes_subsumed(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  /* Add literal patterns */
  ASSERT_OK(st_policy_add(policy, "git commit -m msg1"));
  ASSERT_OK(st_policy_add(policy, "git commit -m msg2"));
  ASSERT_OK(st_policy_add(policy, "git commit -m msg3"));
  ASSERT(st_policy_count(policy) == 3);

  /* Adding the wildcard immediately subsumes the 3 specific patterns */
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));
  ASSERT(st_policy_count(policy) == 1);

  /* Verify the remaining pattern matches */
  st_eval_result_t result;
  st_error_t err = st_policy_eval(policy, "git commit -m hello", &result);
  ASSERT(err == ST_OK);
  ASSERT(result.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* Test that compact keeps patterns with different lengths */
static int test_compact_keeps_different_lengths(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "git status"));
  ASSERT_OK(st_policy_add(policy, "git commit -m *"));

  ASSERT(st_policy_count(policy) == 2);

  st_error_t err = st_policy_compact(policy);
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 2); /* Both kept */

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int policy_eval_is(st_policy_t *policy, const char *command,
                          const char *expected) {
  st_eval_result_t result;
  if (st_policy_eval(policy, command, &result) != ST_OK ||
      result.matches != (expected != NULL))
    return 0;
  return expected ? result.matching_pattern &&
                        strcmp(result.matching_pattern, expected) == 0
                  : result.matching_pattern == NULL;
}

static int test_option_type_matrix(void) {
  static const char *patterns[] = {"git #opt", "docker run #val"};
  static const struct {
    const char *command;
    const char *expected;
  } cases[] = {{"git -v", "git #opt"},
               {"git -la", "git #opt"},
               {"git --help", "git #opt"},
               {"git status", NULL},
               {"docker run -d", "docker run #val"},
               {"docker run --rm", "docker run #val"}};
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(st_policy_add(policy, patterns[i]) == ST_OK);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(policy_eval_is(policy, cases[i].command, cases[i].expected));
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_param_path_lifecycle(void) {
  static const char *patterns[] = {"cat #path.cfg", "cat #path.log"};
  static const struct {
    const char *command;
    const char *expected;
  } specific_cases[] = {{"cat /etc/app.cfg", "cat #path.cfg"},
                        {"cat src/app.cfg", "cat #path.cfg"},
                        {"cat /var/sys.log", "cat #path.log"},
                        {"cat /etc/app.txt", NULL},
                        {"cat /etc/hosts", NULL}};
  const char *path = "test_param_policy.tmp";
  snprintf(policy_temp_paths[2], sizeof(policy_temp_paths[2]), "%s", path);
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_ctx_t *loaded_ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  st_policy_t *loaded = st_policy_new(loaded_ctx);
  ASSERT(policy != NULL && loaded != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    ASSERT(st_policy_add(policy, patterns[i]) == ST_OK);
    ASSERT(st_policy_add(policy, patterns[i]) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == 2);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_count(policy) == 2);
  for (size_t i = 0; i < sizeof(specific_cases) / sizeof(specific_cases[0]);
       i++)
    ASSERT(policy_eval_is(policy, specific_cases[i].command,
                          specific_cases[i].expected));

  ASSERT(st_policy_save(policy, path) == ST_OK);
  ASSERT(st_policy_load(loaded, path, false) == ST_OK);
  ASSERT(st_policy_count(loaded) == 2);
  for (size_t i = 0; i < sizeof(specific_cases) / sizeof(specific_cases[0]);
       i++)
    ASSERT(policy_eval_is(loaded, specific_cases[i].command,
                          specific_cases[i].expected));
  ASSERT(remove(path) == 0);

  ASSERT(st_policy_add(loaded, "cat #path") == ST_OK);
  ASSERT(st_policy_count(loaded) == 1);
  ASSERT(st_policy_compact(loaded) == ST_OK);
  static const char *generic_commands[] = {
      "cat /etc/app.cfg", "cat /var/sys.log", "cat /etc/app.txt"};
  for (size_t i = 0; i < sizeof(generic_commands) / sizeof(generic_commands[0]);
       i++)
    ASSERT(policy_eval_is(loaded, generic_commands[i], "cat #path"));
  st_policy_free(policy);
  st_policy_free(loaded);
  st_policy_ctx_free(ctx);
  st_policy_ctx_free(loaded_ctx);
  return 1;
}

static int test_param_duplicate_type_matrix(void) {
  static const struct {
    const char *pattern;
    const char *command;
  } cases[] = {
      {"cat #size.MiB", "cat 100MiB"},
      {"uuidgen #uuid.v4", "uuidgen 550e8400-e29b-41d4-a716-446655440000"},
      {"date #ts.date", "date 2024-01-15"},
  };
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(st_policy_add(policy, cases[i].pattern) == ST_OK);
    ASSERT(st_policy_add(policy, cases[i].pattern) == ST_OK);
    ASSERT(st_policy_count(policy) == i + 1);
    ASSERT(policy_eval_is(policy, cases[i].command, cases[i].pattern));
  }
  ASSERT(st_policy_add(policy, "cat #size.GiB") == ST_OK);
  ASSERT(st_policy_count(policy) == 4);
  ASSERT(st_policy_add(policy, "cat #n.cfg") == ST_ERR_INVALID);
  ASSERT(st_policy_count(policy) == 4);
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_param_size_lifecycle(void) {
  static const char *patterns[] = {"dd bs= #size.MiB", "dd bs= #size.G"};
  static const struct {
    const char *command;
    const char *expected;
  } cases[] = {{"dd bs=10MiB", "dd bs= #size.MiB"},
               {"dd bs=2G", "dd bs= #size.G"},
               {"dd bs=10K", NULL}};
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(st_policy_add(policy, patterns[i]) == ST_OK);
  ASSERT(st_policy_count(policy) == 2);
  ASSERT(st_policy_compact(policy) == ST_OK);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(policy_eval_is(policy, cases[i].command, cases[i].expected));
  ASSERT(st_policy_add(policy, "dd bs= #size") == ST_OK);
  ASSERT(st_policy_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "dd bs=10K", "dd bs= #size"));
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* ============================================================
 * PHASE 2: NEW PARAMETRIZED TYPES (#hash.algo, #image.registry,
 * #pkg.scope, #branch.prefix, #sha.length, #duration.unit,
 * #signal.name, #range.step, #perm.bits)
 * ============================================================ */

/* --- Subsumption for parametrized types --- */
static int test_param_subsume_specific_to_generic(void) {
  /* Specific parametrized patterns should be subsumed by generic ones */
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "kill #signal.TERM"));
  ASSERT(st_policy_count(policy) == 1);

  ASSERT_OK(st_policy_add(policy, "kill #signal"));
  ASSERT(st_policy_count(policy) == 1);

  st_eval_result_t r;
  ASSERT_OK(st_policy_eval(policy, "kill INT", &r));
  ASSERT(r.matches); /* INT matches generic #signal */

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_param_subsume_via_same_base(void) {
  /* Patterns with same base type but different params should NOT subsume each
   * other */
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "kill #signal.TERM"));
  ASSERT(st_policy_count(policy) == 1);

  ASSERT_OK(st_policy_add(policy, "kill #signal.INT"));
  ASSERT(st_policy_count(policy) == 2);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
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
      {"cat #path.cfg",
       {"cat /etc/app.cfg", "cat relative.cfg", NULL},
       {"cat /etc/app.txt", "cat /etc/.cfg"}},
      {"sha256sum #hash.sha256", {"sha256sum sha256", NULL}, {"sha256sum md5"}},
      {"echo #hash", {"echo sha256", "echo md5"}, {NULL}},
      {"docker pull #image.ghcr.io",
       {"docker pull ghcr.io/org/app:v1", NULL},
       {"docker pull docker.io/library/redis"}},
      {"docker pull #image",
       {"docker pull ghcr.io/org/app:v1", "docker pull nginx:latest"},
       {NULL}},
      {"npm install #pkg.@babel",
       {"npm install @babel/core", NULL},
       {"npm install @types/node"}},
      {"npm install #pkg",
       {"npm install @babel/core", NULL},
       {"npm install express"}},
      {"git checkout #branch.feature",
       {"git checkout feature/login", NULL},
       {"git checkout release/v1"}},
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
      {"login #user.system",
       {"login root", "login www-data", NULL},
       {"login deploy-user"}},
      {"login #user.root", {"login root", NULL}, {"login nobody"}},
      {"ssh-keygen #fp.sha256",
       {"ssh-keygen SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE", NULL},
       {"ssh-keygen 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d"}},
      {"ssh-keygen #fp.md5",
       {"ssh-keygen 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d", NULL},
       {"ssh-keygen SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE"}},
      {"sleep #duration.s", {"sleep 30s", "sleep -1.5s", NULL}, {"sleep 2h"}},
      {"sleep #duration.ms", {"sleep 100ms", NULL}, {"sleep 100us"}},
      {"kill #signal.TERM", {"kill TERM", "kill SIGTERM"}, {"kill INT"}},
      {"kill #signal.INT", {"kill INT", "kill SIGINT", NULL}, {"kill 9"}},
      {"seq #range.step", {"seq 1-5", "seq 0-100"}, {NULL}},
      {"chmod #perm.bits", {"chmod 755", "chmod 0644"}, {NULL}},
  };
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  ASSERT(ctx != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(st_policy_add(policy, cases[i].pattern) == ST_OK);
    ASSERT(st_policy_count(policy) == 1);
    for (size_t j = 0; j < 3 && cases[i].accepted[j]; j++) {
      st_eval_result_t result;
      ASSERT(st_policy_eval(policy, cases[i].accepted[j], &result) == ST_OK);
      if (!result.matches) {
        printf("  Pattern '%s' rejected '%s'\n", cases[i].pattern,
               cases[i].accepted[j]);
        return 0;
      }
      ASSERT_STR_EQ(result.matching_pattern, cases[i].pattern);
    }
    for (size_t j = 0; j < 2 && cases[i].rejected[j]; j++) {
      st_eval_result_t result;
      ASSERT(st_policy_eval(policy, cases[i].rejected[j], &result) == ST_OK);
      ASSERT(!result.matches);
    }
    st_policy_free(policy);
  }
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_param_uuid_coexist(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "container #uuid.v4"));
  ASSERT_OK(st_policy_add(policy, "container #uuid.v5"));
  ASSERT(st_policy_count(policy) == 2);

  st_eval_result_t r1;
  ASSERT_OK(st_policy_eval(
      policy, "container 550e8400-e29b-41d4-a716-446655440000", &r1));
  ASSERT(r1.matches);

  st_eval_result_t r2;
  ASSERT_OK(st_policy_eval(
      policy, "container 4be33a94-0c5b-5516-a922-d07dedd59172", &r2));
  ASSERT(r2.matches);

  /* v3 matches neither */
  st_eval_result_t r3;
  ASSERT_OK(st_policy_eval(
      policy, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", &r3));
  ASSERT(!r3.matches);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_param_uuid_compact(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);

  ASSERT_OK(st_policy_add(policy, "container #uuid.v4"));
  ASSERT_OK(st_policy_add(policy, "container #uuid"));

  st_error_t err = st_policy_compact(policy);
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 1);

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

/* --- Phase 2: Parameter validation --- */

static int test_param_validation_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t expected;
  } cases[] = {
      {"cat #path.cfg", ST_OK},
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
      {"git #branch.feature_name", ST_OK},
      {"git #branch.bad/name", ST_ERR_INVALID},
      {"echo #sha.short", ST_OK},
      {"echo #sha.40", ST_OK},
      {"echo #sha.64", ST_OK},
      {"echo #sha.128", ST_ERR_INVALID},
      {"pull #image.ghcr.io/org", ST_OK},
      {"pull #image.bad:name", ST_ERR_INVALID},
      {"install #pkg.@types/node", ST_OK},
      {"install #pkg.bad:name", ST_ERR_INVALID},
      {"login #user.www-data", ST_OK},
      {"login #user.bad.name", ST_ERR_INVALID},
      {"key #fp.md5", ST_OK},
      {"key #fp.sha256", ST_OK},
      {"key #fp.sha1", ST_ERR_INVALID},
      {"echo #hash.sha256", ST_OK},
      {"echo #hash.invalid", ST_ERR_INVALID},
      {"sleep #duration.s", ST_OK},
      {"sleep #duration.xx", ST_ERR_INVALID},
      {"kill #signal.TERM", ST_OK},
      {"kill #signal.SIGTERM", ST_OK},
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
    ASSERT(st_validate_pattern(cases[i].pattern, &info) == cases[i].expected);

    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(st_policy_add(policy, cases[i].pattern) == cases[i].expected);
    ASSERT(st_policy_count(policy) == (cases[i].expected == ST_OK ? 1 : 0));
    st_policy_free(policy);
  }
  st_policy_ctx_free(ctx);
  return 1;
}

/* ============================================================
 * PATTERN VALIDATION (st_validate_pattern)
 * ============================================================ */

static int test_validate_pattern_matrix(void) {
  static const struct {
    const char *pattern;
    st_error_t expected;
  } cases[] = {
      {"git status", ST_OK},     {"cat #path", ST_OK},
      {"cat #path.cfg", ST_OK},  {"dd #size.XX", ST_ERR_INVALID},
      {"", ST_ERR_INVALID},      {NULL, ST_ERR_INVALID},
      {"* foo", ST_ERR_INVALID},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(st_validate_pattern(cases[i].pattern, NULL) == cases[i].expected);

  /* The metadata-producing path must agree with validation and preserve the
   * exact token text and classified base type. */
  st_pattern_info_t info;
  st_error_t err = st_validate_pattern("cat #path.cfg", &info);
  ASSERT(err == ST_OK);
  ASSERT(info.token_count == 2);
  ASSERT_STR_EQ(info.token_texts[0], "cat");
  ASSERT(info.token_types[0] == ST_TYPE_LITERAL);
  ASSERT_STR_EQ(info.token_texts[1], "#path.cfg");
  ASSERT(info.token_types[1] == ST_TYPE_PATH);
  return 1;
}

/* ============================================================
 * POLICY MERGE (st_policy_merge)
 * ============================================================ */

static int add_patterns(st_policy_t *policy, const char *const *patterns,
                        size_t count) {
  for (size_t i = 0; i < count; i++)
    if (st_policy_add(policy, patterns[i]) != ST_OK)
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
    size_t source_count = st_policy_count(source);
    ASSERT(st_policy_merge(destination, source) == ST_OK);
    ASSERT(st_policy_count(destination) == cases[i].merged_count);
    ASSERT(st_policy_count(source) == source_count);
    ASSERT(st_policy_merge(source, destination) == ST_OK);
    ASSERT(st_policy_count(source) == cases[i].merged_count);
    for (size_t j = 0; j < cases[i].probe_count; j++) {
      ASSERT(policy_eval_is(destination, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
      ASSERT(policy_eval_is(source, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
    }
    st_policy_free(destination);
    st_policy_free(source);
    st_policy_ctx_free(destination_context);
    st_policy_ctx_free(source_context);
  }
  return 1;
}

/* ============================================================
 * POLICY DIFF (st_policy_diff)
 * ============================================================ */

static int string_set_is(char *const *actual, size_t actual_count,
                         const char *const *expected, size_t expected_count) {
  if (actual_count != expected_count)
    return 0;
  for (size_t i = 0; i < expected_count; i++) {
    int found = 0;
    for (size_t j = 0; j < actual_count; j++)
      if (strcmp(actual[j], expected[i]) == 0) {
        found = 1;
        break;
      }
    if (!found)
      return 0;
  }
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

    st_policy_diff_t forward;
    ASSERT(st_policy_diff(left, right, &forward) == ST_OK);
    ASSERT(string_set_is(forward.added, forward.added_count, cases[i].added,
                         cases[i].added_count));
    ASSERT(string_set_is(forward.removed, forward.removed_count,
                         cases[i].removed, cases[i].removed_count));
    st_free_diff_result(&forward);

    st_policy_diff_t reverse;
    ASSERT(st_policy_diff(right, left, &reverse) == ST_OK);
    ASSERT(string_set_is(reverse.added, reverse.added_count, cases[i].removed,
                         cases[i].removed_count));
    ASSERT(string_set_is(reverse.removed, reverse.removed_count, cases[i].added,
                         cases[i].added_count));
    st_free_diff_result(&reverse);

    st_policy_diff_t identity;
    ASSERT(st_policy_diff(left, left, &identity) == ST_OK);
    ASSERT(identity.added_count == 0 && identity.removed_count == 0);
    st_free_diff_result(&identity);
    st_policy_free(left);
    st_policy_free(right);
    st_policy_ctx_free(left_context);
    st_policy_ctx_free(right_context);
  }
  return 1;
}

/* ============================================================
 * INCREMENTAL SUBSUMPTION TESTS
 * ============================================================ */

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
      {{"cat #path.cfg", "cat #path"},
       {1, 1},
       2,
       {{"cat /etc/app.cfg", "cat #path"}, {"cat /etc/app.log", "cat #path"}},
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
      ASSERT(st_policy_add(policy, cases[i].additions[j]) == ST_OK);
      ASSERT(st_policy_count(policy) == cases[i].counts[j]);
    }
    for (size_t j = 0; j < cases[i].probe_count; j++)
      ASSERT(policy_eval_is(policy, cases[i].probes[j].command,
                            cases[i].probes[j].expected));
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
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
    ASSERT(st_policy_add(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == 100);

  /* Adding a wildcard subsumes all 100 literals */
  st_error_t err = st_policy_add(policy, "cmd *");
  ASSERT(err == ST_OK);
  ASSERT(st_policy_count(policy) == 1);

  /* All 100 variants still match */
  static const char *probes[] = {"cmd arg0", "cmd arg42", "cmd arg99"};
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    ASSERT(policy_eval_is(policy, probes[i], "cmd *"));

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return 1;
}

static int test_incremental_batch_remove_readd(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(ctx);
  ASSERT(policy != NULL);

  const char *batch[] = {"git status", "git commit", "git pull", "git *"};
  ASSERT(st_policy_batch_add(policy, batch, 4) == ST_OK);
  ASSERT(st_policy_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "git status", "git *"));

  ASSERT(st_policy_remove(policy, "git *") == ST_OK);
  ASSERT(st_policy_count(policy) == 0);

  ASSERT(st_policy_add(policy, "git status") == ST_OK);
  ASSERT(st_policy_count(policy) == 1);
  ASSERT(policy_eval_is(policy, "git status", "git status"));

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
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
        variants[i].sample_value != NULL) {
      printf("    variant %zu: got %d (%s), expected %d (%s)\n", i,
             variants[i].type,
             variants[i].type_symbol ? variants[i].type_symbol : "NULL",
             expected[i], st_type_symbol[expected[i]]);
      return 0;
    }
  }
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

  for (size_t i = 0; i < sizeof(fallback_cases) / sizeof(fallback_cases[0]);
       i++) {
    const char *tokens[] = {"cmd", fallback_cases[i].token};
    ASSERT(variants_match(&empty, tokens, 2, 1, fallback_cases[i].expected,
                          fallback_cases[i].expected_count));
  }

  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS];
  const char *valid[] = {"cmd", "#w"};
  const char *with_null[] = {"cmd", NULL};
  ASSERT(st_policy_suggest_token_variants(NULL, valid, 2, 1, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, NULL, 2, 1, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, valid, 2, 2, variants) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, valid, 2, 1, NULL) == 0);
  ASSERT(st_policy_suggest_token_variants(&empty, with_null, 2, 1, variants) ==
         0);

  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(learner != NULL);
  ASSERT(st_feed(learner, "git commit -m /first/path") == ST_OK);
  ASSERT(st_feed(learner, "git commit -m /second/path") == ST_OK);
  ASSERT(st_feed(learner, "git commit -m ../relative/path") == ST_OK);
  ASSERT(st_feed(learner, "curl -X GET https://one.example") == ST_OK);
  ASSERT(st_feed(learner, "curl -X POST https://two.example") == ST_OK);
  ASSERT(st_feed(learner, "curl -X 42 https://number.example") == ST_OK);
  ASSERT(st_feed(learner, "branch 42 /number/path") == ST_OK);
  ASSERT(st_feed(learner, "branch https://example.test ../url/path") == ST_OK);
  ASSERT(st_feed(learner, "branch 7 ../number/relative") == ST_OK);

  const char *learned_path[] = {"git", "commit", "#sopt", "#p"};
  const char *narrow_path[] = {"git", "commit", "#sopt", "*"};
  const char *method[] = {"curl", "#sopt", "#method", "#u"};
  const char *generic_prefix[] = {"branch", "*", "*"};
  static const st_token_type_t observed_paths[] = {
      ST_TYPE_ABS_PATH, ST_TYPE_REL_PATH, ST_TYPE_PATH, ST_TYPE_ANY};
  static const st_token_type_t narrowed[] = {ST_TYPE_ABS_PATH, ST_TYPE_REL_PATH,
                                             ST_TYPE_ANY};
  static const st_token_type_t method_types[] = {ST_TYPE_METHOD, ST_TYPE_NUMBER,
                                                 ST_TYPE_ANY};
  static const st_token_type_t url_types[] = {ST_TYPE_URL, ST_TYPE_ANY};
  static const st_token_type_t prefix_union[] = {ST_TYPE_ABS_PATH,
                                                 ST_TYPE_REL_PATH, ST_TYPE_ANY};
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
    ASSERT(st_feed(learner, saturation_commands[i]) == ST_OK);
  const char *saturated[] = {"probe", "#n"};
  size_t saturated_count =
      st_policy_suggest_token_variants(learner, saturated, 2, 1, variants);
  ASSERT(saturated_count == ST_MAX_TOKEN_VARIANTS);
  ASSERT(variants[0].type == ST_TYPE_NUMBER);
  ASSERT(variants[saturated_count - 1].type == ST_TYPE_ANY);
  for (size_t i = 0; i < saturated_count; i++)
    for (size_t j = i + 1; j < saturated_count; j++)
      ASSERT(variants[i].type != variants[j].type);

  size_t count =
      st_policy_suggest_token_variants(learner, learned_path, 4, 3, variants);
  ASSERT(count == 4);
  for (size_t i = 0; i < count; i++) {
    char *edited =
        st_policy_apply_type_at(learner, learned_path, 4, 3, variants[i].type);
    ASSERT(edited != NULL);
    st_pattern_info_t info;
    ASSERT(st_validate_pattern(edited, &info) == ST_OK);
    ASSERT(info.token_count == 4);
    free(edited);
  }

  st_learner_free(learner);
  return 1;
}

/* ============================================================
 * APPLY TYPE AT POSITION (st_policy_apply_type_at)
 * All tests share setup: ctx + zeroed learner, then test different
 * positions/types
 * ============================================================ */

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

  char oversized[ST_MAX_PATTERN_LEN];
  memset(oversized, 'x', sizeof(oversized));
  oversized[sizeof(oversized) - 1] = '\0';
  const char *too_long[] = {oversized, "tail"};
  ASSERT(st_policy_apply_type_at(NULL, too_long, 2, 1, ST_TYPE_WORD) == NULL);
  const char *too_long_token[] = {"head", oversized};
  ASSERT(st_policy_apply_type_at(NULL, too_long_token, 2, 0, ST_TYPE_WORD) ==
         NULL);

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

  printf("\nBug fixes:\n");
  TEST(test_non_matching_returns_ok);
  TEST(test_verify_only_returns_ok);
  TEST(test_empty_command_returns_ok);
  TEST(test_filter_wildcard_compatibility_matrix);
  TEST(test_suggestion_contracts);

  printf("\nContext and validation:\n");
  TEST(test_context_and_compaction_transitions);
  TEST(test_pattern_validation_matrix);

  printf("\nDiagnostics and suggestions:\n");
  TEST(test_statistics_transitions);
  TEST(test_dot_export);
  TEST(test_dry_run_simulate);

  printf("\nPolicy maintenance:\n");
  TEST(test_remove_prefix_keeps_children);
  TEST(test_filter_rebuild_lazy_trigger);
  TEST(test_policy_clear);
  TEST(test_compact_removes_subsumed);
  TEST(test_compact_keeps_different_lengths);

  printf("\nOptions (#opt):\n");
  TEST(test_option_type_matrix);

  printf("\nParametrized wildcard lifecycles:\n");
  TEST(test_param_path_lifecycle);
  TEST(test_param_duplicate_type_matrix);
  TEST(test_param_size_lifecycle);

  printf("\nNew parametrized wildcards (#hash, #image, #pkg, #branch, #sha, "
         "#duration, #signal, #range, #perm):\n");
  TEST(test_param_match_matrix);
  TEST(test_param_subsume_specific_to_generic);
  TEST(test_param_subsume_via_same_base);

  printf("\nParametrized uuid/semver/timestamp:\n");
  TEST(test_param_uuid_coexist);
  TEST(test_param_uuid_compact);

  printf("\nParameter validation:\n");
  TEST(test_param_validation_matrix);

  printf("\nPattern validation (st_validate_pattern):\n");
  TEST(test_validate_pattern_matrix);

  printf("\nPolicy merge (st_policy_merge):\n");
  TEST(test_merge_matrix);

  printf("\nPolicy diff (st_policy_diff):\n");
  TEST(test_diff_matrix_and_symmetry);

  printf("\nIncremental subsumption:\n");
  TEST(test_incremental_subsumption_matrix);
  TEST(test_incr_stress);
  TEST(test_incremental_batch_remove_readd);

  printf("\nToken variant suggestion (st_policy_suggest_token_variants):\n");
  TEST(test_token_variant_matrix);

  printf("\nApply type at position (st_policy_apply_type_at):\n");
  TEST(test_apply_type_matrix);

  printf("\n========================================\n");
  printf("Results: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
