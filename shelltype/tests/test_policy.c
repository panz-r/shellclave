/*
 * test_policy.c – Unit tests for the policy module.
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
    printf("  %-40s ", #name); \
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
 * LIFECYCLE
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

static int test_policy_free_null(void)
{
    st_policy_free(NULL);
    return 1;
}

/* ============================================================
 * ADD
 * ============================================================ */

static int test_policy_add_single(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_error_t err = st_policy_add(policy, "git commit -m *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_duplicate(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 1);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_multiple(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "ls -l *");
    st_policy_add(policy, "cat * | grep *");
    ASSERT(st_policy_count(policy) == 3);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_empty(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_error_t err = st_policy_add(policy, "");
    ASSERT(err == ST_ERR_INVALID);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_null(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_error_t err = st_policy_add(policy, NULL);
    ASSERT(err == ST_ERR_INVALID);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_prefix_patterns(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git");
    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 3);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * REMOVE
 * ============================================================ */

static int test_policy_remove(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "ls -l *");
    ASSERT(st_policy_count(policy) == 2);

    st_error_t err = st_policy_remove(policy, "git commit -m *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_nonexistent(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    st_error_t err = st_policy_remove(policy, "docker run *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_pruning(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_remove(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 0);
    ASSERT(policy != NULL);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_partial_prefix(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git");
    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 3);

    st_policy_remove(policy, "git commit");
    ASSERT(st_policy_count(policy) == 2);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

static int test_policy_save_load(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy1 = st_policy_new(ctx);
    st_policy_add(policy1, "git commit -m *");
    st_policy_add(policy1, "ls -l *");
    st_policy_add(policy1, "cat * | grep *");

    st_error_t err = st_policy_save(policy1, "tests/test_policy_save.tmp");
    ASSERT(err == ST_OK);

    st_policy_t *policy2 = st_policy_new(ctx);
    err = st_policy_load(policy2, "tests/test_policy_save.tmp", false);
    ASSERT(err == ST_OK);

    ASSERT(st_policy_count(policy2) == 3);

    st_policy_free(policy1);
    st_policy_free(policy2);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_load_empty(void)
{
    FILE *fp = fopen("tests/test_policy_empty.tmp", "w");
    ASSERT(fp != NULL);
    fprintf(fp, "# CPL v1\n");
    fprintf(fp, "# patterns: 0\n");
    fprintf(fp, "# CRC32: 00000000\n");
    fclose(fp);

    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_error_t err = st_policy_load(policy, "tests/test_policy_empty.tmp", false);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 0);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_roundtrip_many_patterns(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy1 = st_policy_new(ctx);
    for (int i = 0; i < 50; i++) {
        char pattern[128];
        snprintf(pattern, sizeof(pattern), "cmd%d arg%d *", i, i);
        st_policy_add(policy1, pattern);
    }
    ASSERT(st_policy_count(policy1) == 50);

    st_policy_save(policy1, "tests/test_policy_many.tmp");

    st_policy_t *policy2 = st_policy_new(ctx);
    st_policy_load(policy2, "tests/test_policy_many.tmp", false);
    ASSERT(st_policy_count(policy2) == 50);

    st_policy_free(policy1);
    st_policy_free(policy2);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running policy unit tests...\n\n");

    printf("Lifecycle:\n");
    TEST(test_policy_create_free);
    TEST(test_policy_free_null);

    printf("\nAdd:\n");
    TEST(test_policy_add_single);
    TEST(test_policy_add_duplicate);
    TEST(test_policy_add_multiple);
    TEST(test_policy_add_empty);
    TEST(test_policy_add_null);
    TEST(test_policy_add_prefix_patterns);

    printf("\nRemove:\n");
    TEST(test_policy_remove);
    TEST(test_policy_remove_nonexistent);
    TEST(test_policy_remove_pruning);
    TEST(test_policy_remove_partial_prefix);

    printf("\nSerialisation:\n");
    TEST(test_policy_save_load);
    TEST(test_policy_load_empty);
    TEST(test_policy_roundtrip_many_patterns);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
