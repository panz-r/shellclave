/*
 * test_policy_compact.c - Unit tests for the compact policy module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "shelltype.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-45s ", #name); \
    if (name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        tests_failed++; \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, __LINE__); return 0; } } while(0)

/* ============================================================
 * CONTEXT TESTS
 * ============================================================ */

static int test_ctx_create_free(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    ASSERT(ctx != NULL);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_ctx_intern(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    const char *a = st_policy_ctx_intern(ctx, "hello");
    const char *b = st_policy_ctx_intern(ctx, "hello");
    const char *c = st_policy_ctx_intern(ctx, "world");
    ASSERT(a == b);
    ASSERT(a != c);
    ASSERT(strcmp(a, "hello") == 0);
    ASSERT(strcmp(c, "world") == 0);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_ctx_shared_between_policies(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *p1 = st_policy_new(ctx);
    st_policy_t *p2 = st_policy_new(ctx);

    st_policy_add(p1, "git commit -m *");
    st_policy_add(p2, "git status");

    const char *a = st_policy_ctx_intern(ctx, "git");
    ASSERT(a != NULL);

    st_policy_free(p1);
    st_policy_free(p2);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * POLICY LIFECYCLE
 * ============================================================ */

static int test_policy_create_free(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(st_policy_count(policy) == 0);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_null_free(void)
{
    st_policy_free(NULL);
    return 1;
}

/* ============================================================
 * ADD PATTERNS
 * ============================================================ */

static int test_add_single(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "git commit");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_duplicate(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git commit");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_multiple(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la");
    ASSERT(st_policy_count(policy) == 3);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_empty(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_null(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, NULL);
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_wildcards(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat *");
    st_policy_add(policy, "ls -la *");
    st_policy_add(policy, "head -n #n");
    ASSERT(st_policy_count(policy) == 3);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_add_shared_prefix(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "git commit -a");
    st_policy_add(policy, "git status");
    ASSERT(st_policy_count(policy) == 3);

    size_t usage = st_policy_memory_usage(policy);
    ASSERT(usage > 0);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * REMOVE PATTERNS
 * ============================================================ */

static int test_remove(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git status");
    ASSERT(st_policy_count(policy) == 2);

    st_policy_remove(policy, "git commit");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_remove_nonexistent(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit");
    st_policy_remove(policy, "git status");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * VERIFICATION
 * ============================================================ */

static int test_verify_exact_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT(r.matching_pattern != NULL);
    ASSERT_STR_EQ(r.matching_pattern, "git commit -m *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_no_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git push origin main", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.matching_pattern == NULL);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_path(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cat /etc/passwd", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "cat *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_number(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "head -n *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "head -n 42", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "head -n *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_exact_length(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_pipeline(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat * | grep *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cat /var/log/syslog | grep ERROR", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "cat * | grep *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_multiple_patterns(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "docker run -it * *");
    st_policy_add(policy, "cat * | grep *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "git commit -m *");

    err = st_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "docker run -it * *");

    err = st_policy_eval(policy, "rm -rf /", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_flag_value(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "gcc -o myprog main.c");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "gcc -o myprog main.c", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "gcc -o myprog main.c");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * VERIFY ALL
 * ============================================================ */

static int test_verify_all_matches(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "git commit -m fix");

    const char **matches = NULL;
    size_t count = 0;
    st_error_t err = st_policy_verify_all(policy, "git commit -m hello", &matches, &count);
    ASSERT(err == ST_OK);
    ASSERT(count == 1);
    ASSERT_STR_EQ(matches[0], "git commit -m *");

    st_policy_free_matches(matches, count);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_all_no_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");

    const char **matches = NULL;
    size_t count = 0;
    st_error_t err = st_policy_verify_all(policy, "rm -rf /", &matches, &count);
    ASSERT(err == ST_OK);
    ASSERT(count == 0);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

static int test_save_load(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *p1 = st_policy_new(ctx);

    st_policy_add(p1, "git commit -m *");
    st_policy_add(p1, "ls -la *");
    st_policy_add(p1, "cat * | grep *");

    st_error_t err = st_policy_save(p1, "tests/test_compact_save.tmp");
    ASSERT(err == ST_OK);

    st_policy_t *p2 = st_policy_new(ctx);
    err = st_policy_load(p2, "tests/test_compact_save.tmp");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(p2) == 3);

    st_eval_result_t r;
    err = st_policy_eval(p2, "git commit -m fix", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "git commit -m *");

    st_policy_free(p1);
    st_policy_free(p2);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MEMORY USAGE
 * ============================================================ */

static int test_memory_usage(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    size_t empty = st_policy_memory_usage(policy);
    ASSERT(empty > 0);

    for (int i = 0; i < 100; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        st_policy_add(policy, cmd);
    }
    ASSERT(st_policy_count(policy) == 100);

    for (int i = 0; i < 50; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -la /path/to/dir%d", i);
        st_policy_add(policy, cmd);
    }
    ASSERT(st_policy_count(policy) == 101);

    size_t filled = st_policy_memory_usage(policy);
    ASSERT(filled > empty);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_state_count(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    ASSERT(st_policy_state_count(policy) == 1);

    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_state_count(policy) == 5);

    st_policy_add(policy, "git status");
    ASSERT(st_policy_state_count(policy) == 6);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * LARGE POLICY
 * ============================================================ */

static int test_large_policy(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    for (int i = 0; i < 1000; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "cmd%d --option * /path/to/file%d", i, i);
        st_policy_add(policy, cmd);
    }

    ASSERT(st_policy_count(policy) == 1000);

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cmd42 --option something /path/to/file42", &r);
    ASSERT(err == ST_OK);

    err = st_policy_eval(policy, "cmd999 --option test /path/to/file999", &r);
    ASSERT(err == ST_OK);

    err = st_policy_eval(policy, "cmd1000 --option x /path/to/file1000", &r);
    ASSERT(err == ST_OK);

    size_t alloc = st_policy_memory_usage(policy);
    size_t ws = st_policy_working_set(policy);
    printf("  (allocated: %zu bytes, working set: %zu bytes for 1000 patterns) ", alloc, ws);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PER-POSITION FILTER
 * ============================================================ */

static int test_filter_definite_no(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "ls -la *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "zzz commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.matching_pattern == NULL);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_filter_no_false_negatives(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat /etc/passwd");
    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cat /etc/passwd", &r);
    ASSERT(err == ST_OK);

    err = st_policy_eval(policy, "git status", &r);
    ASSERT(err == ST_OK);

    err = st_policy_eval(policy, "ls -la /tmp", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_filter_empty_policy(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "anything", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * NFA RENDERING
 * ============================================================ */

static int test_render_nfa_basic(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");

    st_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = true,
        .identifier = "test-policy",
    };

    st_error_t err = st_policy_render_nfa(policy, "tests/test_render.nfa", &opts);
    ASSERT(err == ST_OK);

    FILE *fp = fopen("tests/test_render.nfa", "r");
    ASSERT(fp != NULL);

    char line[256];
    ASSERT(fgets(line, sizeof(line), fp) != NULL);
    ASSERT(strstr(line, "NFA_ALPHABET") != NULL);
    ASSERT(fgets(line, sizeof(line), fp) != NULL);
    ASSERT(strstr(line, "Identifier: test-policy") != NULL);

    fclose(fp);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_render_nfa_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat *");

    st_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = false,
        .identifier = "wildcard-test",
    };

    st_error_t err = st_policy_render_nfa(policy, "tests/test_render_wc.nfa", &opts);
    ASSERT(err == ST_OK);

    FILE *fp = fopen("tests/test_render_wc.nfa", "r");
    ASSERT(fp != NULL);

    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    ASSERT(strstr(buf, "Symbol 256") != NULL);

    fclose(fp);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_render_nfa_multiple_patterns(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la");

    st_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = true,
        .identifier = "multi-test",
    };

    st_error_t err = st_policy_render_nfa(policy, "tests/test_render_multi.nfa", &opts);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running compact policy unit tests...\n\n");

    printf("Context:\n");
    TEST(test_ctx_create_free);
    TEST(test_ctx_intern);
    TEST(test_ctx_shared_between_policies);

    printf("\nLifecycle:\n");
    TEST(test_policy_create_free);
    TEST(test_policy_null_free);

    printf("\nAdd:\n");
    TEST(test_add_single);
    TEST(test_add_duplicate);
    TEST(test_add_multiple);
    TEST(test_add_empty);
    TEST(test_add_null);
    TEST(test_add_wildcards);
    TEST(test_add_shared_prefix);

    printf("\nRemove:\n");
    TEST(test_remove);
    TEST(test_remove_nonexistent);

    printf("\nVerify:\n");
    TEST(test_verify_exact_match);
    TEST(test_verify_no_match);
    TEST(test_verify_wildcard_path);
    TEST(test_verify_wildcard_number);
    TEST(test_verify_exact_length);
    TEST(test_verify_pipeline);
    TEST(test_verify_multiple_patterns);
    TEST(test_verify_flag_value);

    printf("\nVerify all:\n");
    TEST(test_verify_all_matches);
    TEST(test_verify_all_no_match);

    printf("\nSerialization:\n");
    TEST(test_save_load);

    printf("\nMemory:\n");
    TEST(test_memory_usage);
    TEST(test_state_count);

    printf("\nLarge policy:\n");
    TEST(test_large_policy);

    printf("\nNFA rendering:\n");
    TEST(test_render_nfa_basic);
    TEST(test_render_nfa_wildcard);
    TEST(test_render_nfa_multiple_patterns);

    printf("\nPer-position filter:\n");
    TEST(test_filter_definite_no);
    TEST(test_filter_no_false_negatives);
    TEST(test_filter_empty_policy);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
