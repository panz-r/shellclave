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
 * BUG FIX TESTS
 * ============================================================ */

/* Fix 1: st_policy_eval returns ST_OK for non-matching commands */
static int test_non_matching_returns_ok(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");

    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "docker run ubuntu", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 1: verify-only path (result==NULL) returns ST_OK for non-match */
static int test_verify_only_returns_ok(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");

    /* Completely unrelated command — should return ST_OK, not error */
    st_error_t err = st_policy_eval(policy, "docker run ubuntu", NULL);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 5: empty command returns ST_OK with matches=false */
static int test_empty_command_returns_ok(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");

    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 4: CRC mismatch does not modify policy */
static int test_crc_mismatch_no_partial_load(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 1);

    /* Create a file with bad CRC */
    FILE *fp = fopen("tests/test_crc_bad.tmp", "w");
    ASSERT(fp != NULL);
    fprintf(fp, "# CPL v1\n");
    fprintf(fp, "# patterns: 1\n");
    fprintf(fp, "ls -la *\n");
    fprintf(fp, "# CRC32: deadbeef\n");
    fclose(fp);

    st_error_t err = st_policy_load(policy, "tests/test_crc_bad.tmp", false);
    ASSERT(err == ST_ERR_FORMAT);
    /* Policy must still have original pattern intact */
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 2 (filter bug): Per-position filter correctly handles depth with both
 * literals and incompatible wildcards. Previously, if ANY wildcard existed at
 * a depth, the filter check was skipped for ALL literal tokens at that depth,
 * even when the wildcard was incompatible with the literal type.
 *
 * Scenario: depth 0 has literal "git" AND wildcard "*" (ANY). When evaluating
 * "unknown status", the filter should still reject "unknown" because the ANY
 * wildcard only matches ANY tokens, not LITERAL tokens. */
static int test_filter_with_literal_and_any_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Add patterns that create both literal and ANY wildcard at depth 0 */
    st_policy_add(policy, "git status");
    st_policy_add(policy, "* run");  /* ANY wildcard at depth 0 */

    /* "unknown status" should NOT match - filter should reject it */
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "unknown status", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);
    ASSERT(result.suggestion_count > 0);

    /* "git status" SHOULD match - it's a known pattern */
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 3.1: Wildcard generalization is capped at #w instead of jumping to *
 * to prevent over-broad suggestions. */
static int test_generalization_capped_at_word(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Add patterns that will cause generalization to jump to *
     * if the cap wasn't in place */
    st_policy_add(policy, "docker run -d nginx");
    st_policy_add(policy, "docker run -it ubuntu");
    st_policy_add(policy, "docker run --rm alpine");

    /* Evaluating "docker exec -it container" should suggest generalization
     * but NOT "* exec -it *" - it should be capped at #w */
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "docker exec -it container", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);
    ASSERT(result.suggestion_count > 0);

    /* Check that suggestions don't contain bare "*" for the divergent token */
    for (size_t i = 0; i < result.suggestion_count; i++) {
        /* The suggestion should use #w or more specific, not * */
        ASSERT(result.suggestions[i].pattern == NULL ||
               strstr(result.suggestions[i].pattern, " * ") == NULL);
    }

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Fix 6: st_policy_ctx_reset is idempotent */
static int test_ctx_reset_idempotent(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_ctx_intern(ctx, "test");

    st_policy_ctx_reset(ctx);
    /* Intern after reset should work */
    const char *s = st_policy_ctx_intern(ctx, "hello");
    ASSERT(s != NULL);
    ASSERT(strcmp(s, "hello") == 0);

    /* Double reset should not crash */
    st_policy_ctx_reset(ctx);
    st_policy_ctx_reset(ctx);

    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * NEW FEATURE TESTS (Recommendations 1, 4, 6, 7, 11)
 * ============================================================ */

/* Test reference counting: reset should fail when policy exists */
static int test_ctx_reset_with_active_policy(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    /* Reset should fail because policy is still active */
    st_error_t err = st_policy_ctx_reset(ctx);
    ASSERT(err == ST_ERR_INVALID);
    
    st_policy_free(policy);
    
    /* Reset should succeed now that policy is freed */
    err = st_policy_ctx_reset(ctx);
    ASSERT(err == ST_OK);
    
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test retain/release */
static int test_ctx_retain_release(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    
    /* Initial refcount should be 1 */
    st_policy_t *p1 = st_policy_new(ctx);
    ASSERT(p1 != NULL);
    
    /* Adding another policy should retain */
    st_policy_t *p2 = st_policy_new(ctx);
    ASSERT(p2 != NULL);
    
    st_policy_free(p1);
    /* Reset should still fail because p2 exists */
    st_error_t err = st_policy_ctx_reset(ctx);
    ASSERT(err == ST_ERR_INVALID);
    
    st_policy_free(p2);
    /* Now reset should succeed */
    err = st_policy_ctx_reset(ctx);
    ASSERT(err == ST_OK);
    
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test pattern validation: reject * at first position */
static int test_pattern_reject_star_first(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    /* Pattern starting with * should be rejected */
    st_error_t err = st_policy_add(policy, "* status");
    ASSERT(err == ST_ERR_INVALID);
    
    /* Valid pattern should work */
    err = st_policy_add(policy, "git status");
    ASSERT(err == ST_OK);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test pattern validation: reject adjacent * tokens */
static int test_pattern_reject_adjacent_star(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    /* Adjacent * tokens at the start should be rejected */
    st_error_t err = st_policy_add(policy, "* *");
    ASSERT(err == ST_ERR_INVALID);
    
    /* Valid patterns with * later in the pattern are OK */
    err = st_policy_add(policy, "git *");
    ASSERT(err == ST_OK);
    
    err = st_policy_add(policy, "docker run -it * *");
    ASSERT(err == ST_OK);
    
    err = st_policy_add(policy, "git * status");
    ASSERT(err == ST_OK);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test pattern validation: adjacent wildcards ARE allowed */
static int test_pattern_adjacent_wildcards_allowed(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    /* Adjacent wildcards should be ALLOWED (valid pattern) */
    st_error_t err = st_policy_add(policy, "docker run #path #path");
    ASSERT(err == ST_OK);
    
    /* Verify it works - /etc and /var are both paths */
    st_eval_result_t result;
    err = st_policy_eval(policy, "docker run /etc /var", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test statistics tracking */
static int test_stats_tracking(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    /* Check stats */
    st_policy_stats_t stats;
    st_policy_get_stats(policy, &stats);
    ASSERT(stats.eval_count > 0);
    ASSERT(stats.pattern_count == 2);
    ASSERT(stats.state_count > 0);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test DOT export */
static int test_dot_export(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    
    st_error_t err = st_policy_dump_dot(policy, "tests/test_output.dot");
    ASSERT(err == ST_OK);
    
    /* Check file was created */
    FILE *fp = fopen("tests/test_output.dot", "r");
    ASSERT(fp != NULL);
    char line[256];
    ASSERT(fgets(line, sizeof(line), fp) != NULL);
    ASSERT(strncmp(line, "digraph policy_trie", 18) == 0);
    fclose(fp);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test dry-run simulation */
static int test_dry_run_simulate(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git status");
    
    bool would_match = false;
    const char *conflict = NULL;
    st_error_t err = st_policy_simulate_add(policy, "git status", &would_match, &conflict);
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

/* Test miner suggestions capped at #w */
static int test_miner_capped_at_word(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "docker run #n");
    
    st_token_t tokens[2] = {
        { .text = "docker", .type = ST_TYPE_LITERAL },
        { .text = "#n", .type = ST_TYPE_NUMBER }
    };
    
    st_expand_suggestion_t suggestions[3];
    size_t count = st_policy_suggest_variants(policy, tokens, 2, suggestions);
    ASSERT(count >= 1);
    
    /* Check that none of the suggestions contain bare "*" */
    for (size_t i = 0; i < count; i++) {
        ASSERT(strstr(suggestions[i].pattern, " * ") == NULL);
    }
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * CONCURRENCY AND ATOMIC TESTS
 * ============================================================ */

/* Test that atomic stats are correctly incremented in single-threaded usage */
static int test_atomic_stats_single_thread(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la");
    st_policy_add(policy, "docker ps");
    
    /* Perform multiple evaluations */
    for (int i = 0; i < 100; i++) {
        st_eval_result_t result;
        st_policy_eval(policy, "git status", &result);
        st_policy_eval(policy, "ls -la", &result);
        st_policy_eval(policy, "docker ps", &result);
    }
    
    /* Verify stats are accurate (no races in single-threaded case) */
    st_policy_stats_t stats;
    st_policy_get_stats(policy, &stats);
    ASSERT(stats.eval_count == 300);  /* Exactly 300 evaluations */
    ASSERT(stats.trie_walk_count >= 200);  /* Most walked the trie */
    ASSERT(stats.suggestion_count == 0);  /* All matched, no suggestions */
    
    /* Non-matching eval should increment stats */
    st_eval_result_t result;
    st_policy_eval(policy, "unknown cmd", &result);
    ASSERT(!result.matches);
    
    st_policy_get_stats(policy, &stats);
    ASSERT(stats.eval_count == 301);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test that stats are atomic (verify atomic_load returns updated values) */
static int test_atomic_stats_accuracy(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git *");
    
    /* Do many evaluations and verify counts match exactly */
    for (int i = 0; i < 50; i++) {
        st_eval_result_t r1, r2, r3;
        st_policy_eval(policy, "git status", &r1);
        st_policy_eval(policy, "git commit", &r2);
        st_policy_eval(policy, "ls", &r3);
    }
    
    st_policy_stats_t stats;
    st_policy_get_stats(policy, &stats);
    
    /* Verify total eval count is exactly 150 */
    ASSERT(stats.eval_count == 150);
    
    /* Verify stats are being collected (all counters are accessible) */
    ASSERT(stats.trie_walk_count > 0);  /* Some evaluations walked the trie */
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test compact fails when context is shared */
static int test_compact_shared_context_fails(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *p1 = st_policy_new(ctx);
    st_policy_t *p2 = st_policy_new(ctx);  /* Shares context */
    
    st_policy_add(p1, "git status");
    st_policy_add(p2, "ls -la");
    
    /* Compact should fail because context is shared */
    st_error_t err = st_policy_compact(p1);
    ASSERT(err == ST_ERR_INVALID);
    
    /* Verify policies still work */
    st_eval_result_t result;
    err = st_policy_eval(p1, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(p2, "ls -la", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    st_policy_free(p1);
    st_policy_free(p2);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test compact succeeds with exclusive context */
static int test_compact_exclusive_context(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "ls -la");
    
    /* Compact should succeed */
    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    
    /* Verify policy still works */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(policy, "git commit -m fix", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test remove prefix keeps children */
static int test_remove_prefix_keeps_children(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    st_policy_add(policy, "git");
    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 3);
    
    /* Remove "git" prefix - "git commit" and "git commit -m *" should remain */
    st_error_t err = st_policy_remove(policy, "git");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 2);
    
    /* Verify remaining patterns work */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);  /* "git" was removed */
    
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
static int test_filter_rebuild_lazy_trigger(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    
    /* Add patterns - triggers filter build */
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    
    st_policy_stats_t stats1;
    st_policy_get_stats(policy, &stats1);
    
    /* Add more patterns - epoch changes, next eval triggers rebuild */
    st_policy_add(policy, "ls -la");
    st_policy_add(policy, "docker run *");
    
    /* First eval should trigger rebuild */
    st_eval_result_t result;
    st_policy_eval(policy, "docker ps", &result);
    
    st_policy_stats_t stats2;
    st_policy_get_stats(policy, &stats2);
    
    /* Filter rebuild count should have increased */
    ASSERT(stats2.filter_rebuild_count >= stats1.filter_rebuild_count);
    
    /* Second eval should not trigger rebuild */
    st_policy_eval(policy, "docker ps", &result);
    
    st_policy_stats_t stats3;
    st_policy_get_stats(policy, &stats3);
    
    ASSERT(stats3.filter_rebuild_count == stats2.filter_rebuild_count);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test st_policy_clear removes all patterns */
static int test_policy_clear(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "ls -la");
    ASSERT(st_policy_count(policy) == 3);

    /* Clear should remove all patterns */
    st_error_t err = st_policy_clear(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 0);

    /* Policy should still work after clear */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);  /* No patterns, no match */

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

/* Test st_policy_ctx_compact works with exclusive context */
static int test_ctx_compact(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Add some patterns to grow the arena */
    for (int i = 0; i < 10; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        st_policy_add(policy, cmd);
    }

    /* Compact should fail while policy exists (refcount > 1) */
    st_error_t err = st_policy_ctx_compact(ctx);
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);

    /* Now compact should succeed (refcount == 1) */
    err = st_policy_ctx_compact(ctx);
    ASSERT(err == ST_OK);

    /* Verify context is still usable */
    policy = st_policy_new(ctx);
    ASSERT(policy != NULL);
    err = st_policy_add(policy, "git status");
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test that incremental subsumption removes patterns subsumed by more general ones.
 * With incremental subsumption, adding `git commit -m *` after the literals
 * immediately removes them — no compact needed. */
static int test_compact_removes_subsumed(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Add literal patterns */
    st_policy_add(policy, "git commit -m msg1");
    st_policy_add(policy, "git commit -m msg2");
    st_policy_add(policy, "git commit -m msg3");
    ASSERT(st_policy_count(policy) == 3);

    /* Adding the wildcard immediately subsumes the 3 specific patterns */
    st_policy_add(policy, "git commit -m *");
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
static int test_compact_keeps_different_lengths(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");  /* Different length, not subsumed */

    ASSERT(st_policy_count(policy) == 2);

    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 2);  /* Both kept */

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test that policy with #opt matches command-line options */
static int test_policy_opt_matching(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git #opt");
    
    st_eval_result_t result;
    st_error_t err;
    
    /* Short options */
    err = st_policy_eval(policy, "git -v", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(policy, "git -h", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(policy, "git -la", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    /* Long options */
    err = st_policy_eval(policy, "git --help", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(policy, "git --version", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    /* Options with attached value (--option=value is split into --option and =value) */
    /* Note: "--output=file" becomes git --output = file, so #opt matches --output */
    /* For testing, use simple options without attached values */
    
    /* Non-option args should not match */
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Test that policy with #val also matches options (options are values) */
static int test_policy_opt_matches_value(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "docker run #val");
    
    st_eval_result_t result;
    st_error_t err;
    
    /* Options should match #val */
    err = st_policy_eval(policy, "docker run -d", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    err = st_policy_eval(policy, "docker run --rm", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PARAMETRIZED WILDCARDS (#path.cfg etc.)
 * ============================================================ */

static int test_param_add_path_ext(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    ASSERT(policy != NULL);

    st_error_t err = st_policy_add(policy, "cat #path.cfg");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_match_correct_ext(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");

    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "cat /etc/app.cfg", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    ASSERT_STR_EQ(result.matching_pattern, "cat #path.cfg");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_no_match_wrong_ext(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");

    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "cat /etc/app.log", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_unparametrized_subsumes(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path");

    /* #path should match any path including .cfg */
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "cat /etc/app.cfg", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_coexist_different_ext(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path.log");
    ASSERT(st_policy_count(policy) == 2);

    /* .cfg matches cfg pattern */
    st_eval_result_t r1;
    st_policy_eval(policy, "cat /etc/app.cfg", &r1);
    ASSERT(r1.matches);

    /* .log matches log pattern */
    st_eval_result_t r2;
    st_policy_eval(policy, "cat /var/sys.log", &r2);
    ASSERT(r2.matches);

    /* .txt matches neither */
    st_eval_result_t r3;
    st_policy_eval(policy, "cat /etc/app.txt", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* With incremental subsumption, adding `cat #path` after `cat #path.cfg`
 * subsumes the parametrized pattern. Only `cat #path` remains. */
static int test_param_coexist_with_unparametrized(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path");

    /* #path subsumes #path.cfg, so only one pattern remains */
    ASSERT(st_policy_count(policy) == 1);

    /* .cfg still matches via #path */
    st_eval_result_t r1;
    st_policy_eval(policy, "cat /etc/app.cfg", &r1);
    ASSERT(r1.matches);

    /* .log matches #path */
    st_eval_result_t r2;
    st_policy_eval(policy, "cat /etc/app.log", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_compact_subsumes(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* #path subsumes #path.cfg — incremental subsumption removes #path.cfg */
    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path");
    ASSERT(st_policy_count(policy) == 1);

    /* Compact just reclaims arena memory, no subsumption change */
    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Should still match .cfg */
    st_eval_result_t result;
    st_policy_eval(policy, "cat /etc/app.cfg", &result);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_compact_different_ext_keeps_both(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* #path.cfg and #path.log are incomparable */
    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path.log");
    ASSERT(st_policy_count(policy) == 2);

    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 2);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_serialization_roundtrip(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path.log");

    const char *path = "/tmp/test_param_serialization.tmp";
    st_error_t err = st_policy_save(policy, path);
    ASSERT(err == ST_OK);

    /* Load into a new policy */
    st_policy_t *policy2 = st_policy_new(ctx);
    err = st_policy_load(policy2, path, true);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy2) == 2);

    /* Verify matching still works */
    st_eval_result_t r1;
    st_policy_eval(policy2, "cat /etc/app.cfg", &r1);
    ASSERT(r1.matches);
    ASSERT_STR_EQ(r1.matching_pattern, "cat #path.cfg");

    st_eval_result_t r2;
    st_policy_eval(policy2, "cat /var/sys.log", &r2);
    ASSERT(r2.matches);
    ASSERT_STR_EQ(r2.matching_pattern, "cat #path.log");

    st_eval_result_t r3;
    st_policy_eval(policy2, "cat /etc/app.txt", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy2);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    remove(path);
    return 1;
}

static int test_param_no_extension_no_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");

    /* Path without extension should not match #path.cfg */
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "cat /etc/hosts", &result);
    ASSERT(err == ST_OK);
    ASSERT(!result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_relpath_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");

    /* Relative paths ending in .cfg should also match #path.cfg */
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "cat src/app.cfg", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_duplicate_add(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");
    st_policy_add(policy, "cat #path.cfg");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_duplicate_non_path(void)
{
    /* Non-path parametrized wildcards (size, uuid, timestamp, semver) should also
     * deduplicate correctly. Previously find_wildcard_child was used for insertion
     * lookup, which called param_matches() on the wildcard symbol (e.g., "#size.MiB"),
     * causing it to fail and insert duplicates. */
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #size.MiB");
    st_policy_add(policy, "cat #size.MiB");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_add(policy, "uuidgen #uuid.v4");
    st_policy_add(policy, "uuidgen #uuid.v4");
    ASSERT(st_policy_count(policy) == 2);

    st_policy_add(policy, "date #ts.date");
    st_policy_add(policy, "date #ts.date");
    ASSERT(st_policy_count(policy) == 3);

    /* Verify the patterns still match appropriate tokens */
    st_eval_result_t r;
    st_error_t err;

    err = st_policy_eval(policy, "cat 100MiB", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    err = st_policy_eval(policy, "uuidgen 550e8400-e29b-41d4-a716-446655440000", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    err = st_policy_eval(policy, "date 2024-01-15", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* Different parameters should NOT be deduplicated */
    st_policy_add(policy, "cat #size.GiB");
    ASSERT(st_policy_count(policy) == 4);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_non_path_type_rejected(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* #n.cfg: the prefix "#n" is a wildcard symbol but #n does not support
     * parameters. Since the user wrote a parametrized form of a non-param
     * type, this is rejected as invalid. */
    st_error_t err = st_policy_add(policy, "cat #n.cfg");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- Phase 1: Size parametrization --- */

static int test_param_size_add(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Pattern must match the normalized command form.
     * "bs=10MiB" normalizes to "bs=" + "#size" */
    st_error_t err = st_policy_add(policy, "dd bs= #size.MiB");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_size_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "dd bs= #size.MiB");

    st_eval_result_t r1;
    st_policy_eval(policy, "dd bs=10MiB", &r1);
    ASSERT(r1.matches);

    /* Wrong suffix */
    st_eval_result_t r3;
    st_policy_eval(policy, "dd bs=10G", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_size_coexist(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "dd bs= #size.MiB");
    st_policy_add(policy, "dd bs= #size.G");
    ASSERT(st_policy_count(policy) == 2);

    st_eval_result_t r1;
    st_policy_eval(policy, "dd bs=10MiB", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "dd bs=2G", &r2);
    ASSERT(r2.matches);

    st_eval_result_t r3;
    st_policy_eval(policy, "dd bs=10K", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_size_compact_keeps_both(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "dd bs= #size.MiB");
    st_policy_add(policy, "dd bs= #size.G");

    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 2);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_size_compact_subsumed(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "dd bs= #size.MiB");
    st_policy_add(policy, "dd bs= #size");

    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Generic #size should still match MiB tokens */
    st_eval_result_t r;
    st_policy_eval(policy, "dd bs=10MiB", &r);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PHASE 2: NEW PARAMETRIZED TYPES (#hash.algo, #image.registry,
 * #pkg.scope, #branch.prefix, #sha.length, #duration.unit,
 * #signal.name, #range.step, #perm.bits)
 * ============================================================ */

/* --- #hash.algo: hash algorithm name --- */
static int test_param_hash_algo_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "sha256sum #hash.sha256");
    ASSERT(err == ST_OK);

    /* sha256 algorithm matches (#hash.sha256 matches sha256 as algorithm name) */
    st_eval_result_t r1;
    st_policy_eval(policy, "sha256sum sha256", &r1);
    ASSERT(r1.matches);

    /* md5 algorithm does NOT match sha256 policy */
    st_eval_result_t r2;
    st_policy_eval(policy, "md5sum md5", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_hash_algo_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "echo #hash");
    ASSERT(err == ST_OK);

    /* Any hash algo matches generic #hash */
    st_eval_result_t r1;
    st_policy_eval(policy, "echo sha256", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "echo md5", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_hash_algo_invalid_param(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Invalid algo name → ST_ERR_INVALID */
    st_error_t err = st_policy_add(policy, "echo #hash.invalid");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #image.registry: image with registry prefix --- */
static int test_param_image_registry_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "docker pull #image.ghcr.io");
    ASSERT(err == ST_OK);

    /* ghcr.io registry matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "docker pull ghcr.io/org/app:v1", &r1);
    ASSERT(r1.matches);

    /* docker.io registry does NOT match ghcr.io */
    st_eval_result_t r2;
    st_policy_eval(policy, "docker pull docker.io/library/redis", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_image_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "docker pull #image");
    ASSERT(err == ST_OK);

    /* Any image matches generic #image */
    st_eval_result_t r1;
    st_policy_eval(policy, "docker pull ghcr.io/org/app:v1", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "docker pull nginx:latest", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #pkg.scope: scoped package --- */
static int test_param_pkg_scope_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "npm install #pkg.@babel");
    ASSERT(err == ST_OK);

    /* @babel scope matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "npm install @babel/core", &r1);
    ASSERT(r1.matches);

    /* @types scope does NOT match @babel */
    st_eval_result_t r2;
    st_policy_eval(policy, "npm install @types/node", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_pkg_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "npm install #pkg");
    ASSERT(err == ST_OK);

    /* Any package matches generic #pkg (only scoped @name packages classify as PKG) */
    st_eval_result_t r1;
    st_policy_eval(policy, "npm install @babel/core", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "npm install express", &r2);
    ASSERT(!r2.matches);  /* plain word is LITERAL, not compatible with PKG */

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #branch.prefix: branch with slash --- */
static int test_param_branch_prefix_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "git checkout #branch.feature");
    ASSERT(err == ST_OK);

    /* feature prefix matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "git checkout feature/login", &r1);
    ASSERT(r1.matches);

    /* release prefix does NOT match feature */
    st_eval_result_t r2;
    st_policy_eval(policy, "git checkout release/v1", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_branch_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "git checkout #branch");
    ASSERT(err == ST_OK);

    /* Any branch matches generic #branch */
    st_eval_result_t r1;
    st_policy_eval(policy, "git checkout feature/login", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "git checkout main", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #sha.length: SHA length variant --- */
static int test_param_sha_length_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "echo #sha.40");
    ASSERT(err == ST_OK);

    /* 40-char SHA matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", &r1);
    ASSERT(r1.matches);

    /* 7-char short does NOT match 40 */
    st_eval_result_t r2;
    st_policy_eval(policy, "echo abcdef1", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_sha_length_invalid(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Invalid length → ST_ERR_INVALID */
    st_error_t err = st_policy_add(policy, "echo #sha.128");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #duration.unit: duration with time unit --- */
static int test_param_duration_unit_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "sleep #duration.s");
    ASSERT(err == ST_OK);

    /* seconds duration matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "sleep 30s", &r1);
    ASSERT(r1.matches);

    /* hours duration does NOT match seconds */
    st_eval_result_t r2;
    st_policy_eval(policy, "sleep 2h", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_duration_unit_invalid(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Invalid unit → ST_ERR_INVALID */
    st_error_t err = st_policy_add(policy, "sleep #duration.xx");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #signal.name: signal name --- */
static int test_param_signal_name_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "kill #signal.TERM");
    ASSERT(err == ST_OK);

    /* TERM matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "kill TERM", &r1);
    ASSERT(r1.matches);

    /* SIGTERM also matches (SIG prefix stripped) */
    st_eval_result_t r2;
    st_policy_eval(policy, "kill SIGTERM", &r2);
    ASSERT(r2.matches);

    /* INT does NOT match TERM */
    st_eval_result_t r3;
    st_policy_eval(policy, "kill INT", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_signal_name_invalid(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Invalid signal name → ST_ERR_INVALID */
    st_error_t err = st_policy_add(policy, "kill #signal.FOOBAR");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #range.step: range marker (param ignored) --- */
static int test_param_range_step_marker(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "seq #range.step");
    ASSERT(err == ST_OK);

    /* Any range matches (param ignored) */
    st_eval_result_t r1;
    st_policy_eval(policy, "seq 1-5", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "seq 0-100", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- #perm.bits: permission marker (param ignored) --- */
static int test_param_perm_bits_marker(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_error_t err = st_policy_add(policy, "chmod #perm.bits");
    ASSERT(err == ST_OK);

    /* Any permission matches (param ignored) */
    st_eval_result_t r1;
    st_policy_eval(policy, "chmod 755", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "chmod 0644", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- Validation tests for new types --- */
static int test_param_validate_new_types(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();

    /* #hash.algo: valid algos accepted */
    st_pattern_info_t info;
    st_error_t err = st_validate_pattern("echo #hash.sha256", &info);
    ASSERT(err == ST_OK);

    /* #hash.algo: invalid algo rejected */
    err = st_validate_pattern("echo #hash.foo", &info);
    ASSERT(err == ST_ERR_INVALID);

    /* #duration.unit: valid units accepted */
    err = st_validate_pattern("sleep #duration.s", &info);
    ASSERT(err == ST_OK);

    /* #duration.unit: invalid unit rejected */
    err = st_validate_pattern("sleep #duration.xx", &info);
    ASSERT(err == ST_ERR_INVALID);

    /* #signal.name: valid signals accepted */
    err = st_validate_pattern("kill #signal.TERM", &info);
    ASSERT(err == ST_OK);

    /* #signal.name: invalid signal rejected */
    err = st_validate_pattern("kill #signal.FOOBAR", &info);
    ASSERT(err == ST_ERR_INVALID);

    /* #range.step: only "step" accepted */
    err = st_validate_pattern("seq #range.step", &info);
    ASSERT(err == ST_OK);
    err = st_validate_pattern("seq #range.invalid", &info);
    ASSERT(err == ST_ERR_INVALID);

    /* #perm.bits: only "bits" accepted */
    err = st_validate_pattern("chmod #perm.bits", &info);
    ASSERT(err == ST_OK);
    err = st_validate_pattern("chmod #perm.foo", &info);
    ASSERT(err == ST_ERR_INVALID);

    st_policy_ctx_free(ctx);
    return 1;
}

/* --- Subsumption for parametrized types --- */
static int test_param_subsume_specific_to_generic(void)
{
    /* Specific parametrized patterns should be subsumed by generic ones */
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "kill #signal.TERM");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_add(policy, "kill #signal");  /* should subsume #signal.TERM */
    ASSERT(st_policy_count(policy) == 1);

    st_eval_result_t r;
    st_policy_eval(policy, "kill INT", &r);
    ASSERT(r.matches);  /* INT matches generic #signal */

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_subsume_via_same_base(void)
{
    /* Patterns with same base type but different params should NOT subsume each other */
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "kill #signal.TERM");
    ASSERT(st_policy_count(policy) == 1);

    st_policy_add(policy, "kill #signal.INT");  /* different param, both stay */
    ASSERT(st_policy_count(policy) == 2);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- Phase 1b: UUID/SEMVER/TIMESTAMP parametrization --- */

static int test_param_uuid_v4(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "container #uuid.v4");

    /* v4 UUID matches */
    st_eval_result_t r1;
    st_policy_eval(policy, "container 550e8400-e29b-41d4-a716-446655440000", &r1);
    ASSERT(r1.matches);

    /* v3 UUID does NOT match */
    st_eval_result_t r2;
    st_policy_eval(policy, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_uuid_unparametrized(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "container #uuid");

    /* Any UUID matches unparametrized */
    st_eval_result_t r1;
    st_policy_eval(policy, "container 550e8400-e29b-41d4-a716-446655440000", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_uuid_coexist(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "container #uuid.v4");
    st_policy_add(policy, "container #uuid.v5");
    ASSERT(st_policy_count(policy) == 2);

    st_eval_result_t r1;
    st_policy_eval(policy, "container 550e8400-e29b-41d4-a716-446655440000", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "container 4be33a94-0c5b-5516-a922-d07dedd59172", &r2);
    ASSERT(r2.matches);

    /* v3 matches neither */
    st_eval_result_t r3;
    st_policy_eval(policy, "container 6fa459ea-ee8a-3ca4-894e-db77e160355e", &r3);
    ASSERT(!r3.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_uuid_compact(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "container #uuid.v4");
    st_policy_add(policy, "container #uuid");

    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_semver(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "install #semver.major");

    /* Any semver matches (parameter is informational) */
    st_eval_result_t r;
    st_policy_eval(policy, "install 1.2.3", &r);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_ts_date(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "log #ts.date");

    st_eval_result_t r1;
    st_policy_eval(policy, "log 2025-04-24", &r1);
    ASSERT(r1.matches);

    /* Time does not match date-only pattern */
    st_eval_result_t r2;
    st_policy_eval(policy, "log 15:30:00", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_ts_time(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "log #ts.time");

    st_eval_result_t r1;
    st_policy_eval(policy, "log 15:30:00", &r1);
    ASSERT(r1.matches);

    /* Date does not match time-only pattern */
    st_eval_result_t r2;
    st_policy_eval(policy, "log 2025-04-24", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_ts_datetime(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "log #ts.datetime");

    st_eval_result_t r1;
    st_policy_eval(policy, "log 2025-04-24T15:30:00Z", &r1);
    ASSERT(r1.matches);

    /* Date-only does not match datetime pattern */
    st_eval_result_t r2;
    st_policy_eval(policy, "log 2025-04-24", &r2);
    ASSERT(!r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* --- Phase 2: Parameter validation --- */

static int test_param_validate_bad_path(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Empty parameter after dot → rejected as invalid parametrized wildcard */
    st_error_t err = st_policy_add(policy, "cat #path.");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_validate_bad_size(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* "xyz" is not a known size suffix → rejected */
    st_error_t err = st_policy_add(policy, "dd bs= #size.xyz");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_validate_bad_uuid(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* v3 is not a valid UUID version param → rejected */
    st_error_t err = st_policy_add(policy, "container #uuid.v3");
    ASSERT(err == ST_ERR_INVALID);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_param_validate_bad_ts(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* "foo" is not a valid timestamp param → rejected */
    st_error_t err = st_policy_add(policy, "log #ts.foo");
    ASSERT(err == ST_ERR_INVALID);

    st_eval_result_t r;
    st_policy_eval(policy, "log 2025-04-24", &r);
    ASSERT(!r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PATTERN VALIDATION (st_validate_pattern)
 * ============================================================ */

static int test_validate_valid_literal(void)
{
    st_error_t err = st_validate_pattern("git status", NULL);
    ASSERT(err == ST_OK);
    return 1;
}

static int test_test_validate_valid_wildcard(void)
{
    st_error_t err = st_validate_pattern("cat #path", NULL);
    ASSERT(err == ST_OK);
    return 1;
}

static int test_validate_valid_parametrized(void)
{
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

static int test_validate_invalid_param(void)
{
    /* #size.XX is not a valid size suffix → rejected */
    st_error_t err = st_validate_pattern("dd #size.XX", NULL);
    ASSERT(err == ST_ERR_INVALID);
    return 1;
}

static int test_validate_empty(void)
{
    st_error_t err = st_validate_pattern("", NULL);
    ASSERT(err == ST_ERR_INVALID);

    err = st_validate_pattern(NULL, NULL);
    ASSERT(err == ST_ERR_INVALID);
    return 1;
}

static int test_validate_reject_star_first(void)
{
    st_error_t err = st_validate_pattern("* foo", NULL);
    ASSERT(err == ST_ERR_INVALID);
    return 1;
}

/* ============================================================
 * POLICY MERGE (st_policy_merge)
 * ============================================================ */

static int test_merge_empty_src(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *dst = st_policy_new(ctx1);
    st_policy_t *src = st_policy_new(ctx2);

    st_policy_add(dst, "git status");

    st_error_t err = st_policy_merge(dst, src);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(dst) == 1);

    st_policy_free(dst);
    st_policy_free(src);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

static int test_merge_overlapping(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *dst = st_policy_new(ctx1);
    st_policy_t *src = st_policy_new(ctx2);

    st_policy_add(dst, "git status");
    st_policy_add(dst, "git commit -m *");

    st_policy_add(src, "git status");
    st_policy_add(src, "git pull");

    st_error_t err = st_policy_merge(dst, src);
    ASSERT(err == ST_OK);
    /* git status is duplicate, git pull is new */
    ASSERT(st_policy_count(dst) == 3);

    /* Verify merged patterns match correctly */
    st_eval_result_t r;
    st_policy_eval(dst, "git status", &r);
    ASSERT(r.matches);
    st_policy_eval(dst, "git pull", &r);
    ASSERT(r.matches);
    st_policy_eval(dst, "git commit -m \"hello\"", &r);
    ASSERT(r.matches);

    st_policy_free(dst);
    st_policy_free(src);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

static int test_merge_disjoint(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *dst = st_policy_new(ctx1);
    st_policy_t *src = st_policy_new(ctx2);

    st_policy_add(dst, "git status");

    st_policy_add(src, "ls");
    st_policy_add(src, "cat #path");

    st_error_t err = st_policy_merge(dst, src);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(dst) == 3);

    st_eval_result_t r;
    st_policy_eval(dst, "git status", &r);
    ASSERT(r.matches);
    st_policy_eval(dst, "ls", &r);
    ASSERT(r.matches);
    st_policy_eval(dst, "cat /etc/hosts", &r);
    ASSERT(r.matches);

    st_policy_free(dst);
    st_policy_free(src);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

/* ============================================================
 * POLICY DIFF (st_policy_diff)
 * ============================================================ */

static int test_diff_identical(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *a = st_policy_new(ctx1);
    st_policy_t *b = st_policy_new(ctx2);

    st_policy_add(a, "git status");
    st_policy_add(a, "cat #path");
    st_policy_add(b, "git status");
    st_policy_add(b, "cat #path");

    st_policy_diff_t diff;
    st_error_t err = st_policy_diff(a, b, &diff);
    ASSERT(err == ST_OK);
    ASSERT(diff.added_count == 0);
    ASSERT(diff.removed_count == 0);

    st_free_diff_result(&diff);
    st_policy_free(a);
    st_policy_free(b);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

static int test_diff_added_and_removed(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *a = st_policy_new(ctx1);
    st_policy_t *b = st_policy_new(ctx2);

    st_policy_add(a, "git status");
    st_policy_add(a, "cat #path");

    st_policy_add(b, "git status");
    st_policy_add(b, "ls");

    st_policy_diff_t diff;
    st_error_t err = st_policy_diff(a, b, &diff);
    ASSERT(err == ST_OK);
    ASSERT(diff.added_count == 1);
    ASSERT_STR_EQ(diff.added[0], "ls");
    ASSERT(diff.removed_count == 1);
    ASSERT_STR_EQ(diff.removed[0], "cat #path");

    st_free_diff_result(&diff);
    st_policy_free(a);
    st_policy_free(b);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

static int test_diff_empty(void)
{
    st_policy_ctx_t *ctx1 = st_policy_ctx_new();
    st_policy_ctx_t *ctx2 = st_policy_ctx_new();
    st_policy_t *a = st_policy_new(ctx1);
    st_policy_t *b = st_policy_new(ctx2);

    st_policy_add(a, "git status");

    st_policy_diff_t diff;
    st_error_t err = st_policy_diff(a, b, &diff);
    ASSERT(err == ST_OK);
    ASSERT(diff.added_count == 0);
    ASSERT(diff.removed_count == 1);

    st_free_diff_result(&diff);
    st_policy_free(a);
    st_policy_free(b);
    st_policy_ctx_free(ctx1);
    st_policy_ctx_free(ctx2);
    return 1;
}

/* ============================================================
 * INCREMENTAL SUBSUMPTION TESTS
 * ============================================================ */

/* Adding a specific pattern after a general one: rejected (subsumed) */
static int test_incr_subsumed_by_existing(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git *");
    st_error_t err = st_policy_add(policy, "git status");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* The general pattern still matches */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    ASSERT_STR_EQ(result.matching_pattern, "git *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Adding a general pattern after specific ones: specifics are removed */
static int test_incr_subsumes_existing(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit");
    ASSERT(st_policy_count(policy) == 2);

    /* Adding the wildcard removes the two specifics */
    st_error_t err = st_policy_add(policy, "git *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Both commands still match via the wildcard */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    err = st_policy_eval(policy, "git commit", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Patterns of different lengths are never compared */
static int test_incr_keeps_different_lengths(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 2);

    /* `git *` only subsumes same-length (2-token) patterns */
    st_policy_add(policy, "git *");
    ASSERT(st_policy_count(policy) == 2);  /* `git commit -m *` kept */

    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, "git commit -m fix", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Parametrized wildcard subsumed by generic: #path.cfg subsumed by #path */
static int test_incr_parametrized(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #path.cfg");
    ASSERT(st_policy_count(policy) == 1);

    /* #path subsumes #path.cfg */
    st_error_t err = st_policy_add(policy, "cat #path");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Both .cfg and .log match via #path */
    st_eval_result_t r1;
    st_policy_eval(policy, "cat /etc/app.cfg", &r1);
    ASSERT(r1.matches);

    st_eval_result_t r2;
    st_policy_eval(policy, "cat /etc/app.log", &r2);
    ASSERT(r2.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* #opt wildcard subsumes a classified-literal option.
 * Note: two OPT-type tokens at the same trie node can't coexist
 * (trie design: one wildcard child per type per node). So we test
 * with a single literal option. */
static int test_incr_opt_wildcard(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git -v");
    ASSERT(st_policy_count(policy) == 1);

    /* git #opt subsumes git -v (#opt is an explicit wildcard, -v is classified literal) */
    st_error_t err = st_policy_add(policy, "git #opt");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_eval_result_t r;
    err = st_policy_eval(policy, "git -v", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* Also matches other options */
    err = st_policy_eval(policy, "git --help", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* #ipaddr subsumes both #ipv4 and #ipv6 */
static int test_incr_ipaddr_subsumes(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "ping #i");
    st_policy_add(policy, "ping #ipv6");
    ASSERT(st_policy_count(policy) == 2);

    /* #ipaddr subsumes both #i and #ipv6 */
    st_error_t err = st_policy_add(policy, "ping #ipaddr");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Both IPv4 and IPv6 commands match */
    st_eval_result_t r;
    err = st_policy_eval(policy, "ping 192.168.1.1", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    err = st_policy_eval(policy, "ping ::1", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Stress test: 100 literals subsumed by one wildcard */
static int test_incr_stress(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    for (int i = 0; i < 100; i++) {
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "cmd arg%d", i);
        st_policy_add(policy, pattern);
    }
    ASSERT(st_policy_count(policy) == 100);

    /* Adding a wildcard subsumes all 100 literals */
    st_error_t err = st_policy_add(policy, "cmd *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* All 100 variants still match */
    st_eval_result_t result;
    err = st_policy_eval(policy, "cmd arg42", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);
    ASSERT_STR_EQ(result.matching_pattern, "cmd *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Removal cleans up length bucket properly */
static int test_incr_remove_cleans_bucket(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit");
    st_policy_add(policy, "git *");
    ASSERT(st_policy_count(policy) == 1);

    /* Remove the remaining pattern */
    st_error_t err = st_policy_remove(policy, "git *");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 0);

    /* Adding a specific after removal should work */
    err = st_policy_add(policy, "git status");
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* batch_add also triggers incremental subsumption */
static int test_incr_batch_add(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    const char *batch[] = {
        "git status",
        "git commit",
        "git pull",
        "git *"
    };
    st_error_t err = st_policy_batch_add(policy, batch, 4);
    ASSERT(err == ST_OK);
    /* git * subsumes the other 3 */
    ASSERT(st_policy_count(policy) == 1);

    st_eval_result_t result;
    err = st_policy_eval(policy, "git status", &result);
    ASSERT(err == ST_OK);
    ASSERT(result.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* Wildcard subsumption along the type lattice.
 * #f (filename) ⊂ #r (relpath) ⊂ #path, and #p (abspath) ⊂ #path.
 * Adding #r after #f: #r subsumes #f (filename is compatible with relpath).
 * Adding #p after #r: #p and #r are incomparable (different branches).
 * Adding #path subsumes everything.
 */
static int test_incr_wildcard_same_length(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "cat #f");    /* filename */
    ASSERT(st_policy_count(policy) == 1);

    /* #r subsumes #f (filename ⊂ relpath) */
    st_policy_add(policy, "cat #r");
    ASSERT(st_policy_count(policy) == 1);

    /* #p is incomparable with #r, so both coexist */
    st_policy_add(policy, "cat #p");
    ASSERT(st_policy_count(policy) == 2);

    /* #path subsumes both #r and #p */
    st_policy_add(policy, "cat #path");
    ASSERT(st_policy_count(policy) == 1);

    st_eval_result_t r;
    st_policy_eval(policy, "cat /etc/hosts", &r);
    ASSERT(r.matches);

    st_policy_eval(policy, "cat src/app.c", &r);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* No cross-length subsumption: patterns with different token counts are independent */
static int test_incr_no_cross_length_subsumption(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git");
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git commit -m *");
    ASSERT(st_policy_count(policy) == 3);

    /* `git *` (2 tokens) should NOT subsume `git` (1 token) */
    st_policy_add(policy, "git *");
    ASSERT(st_policy_count(policy) == 3);  /* git and git commit -m * kept */

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    err = st_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

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

    printf("\nBug fixes:\n");
    TEST(test_non_matching_returns_ok);
    TEST(test_verify_only_returns_ok);
    TEST(test_empty_command_returns_ok);
    TEST(test_crc_mismatch_no_partial_load);
    TEST(test_filter_with_literal_and_any_wildcard);
    TEST(test_generalization_capped_at_word);
    TEST(test_ctx_reset_idempotent);

    printf("\nNew features:\n");
    TEST(test_ctx_reset_with_active_policy);
    TEST(test_ctx_retain_release);
    TEST(test_pattern_reject_star_first);
    TEST(test_pattern_reject_adjacent_star);
    TEST(test_pattern_adjacent_wildcards_allowed);
    TEST(test_stats_tracking);
    TEST(test_dot_export);
    TEST(test_dry_run_simulate);
    TEST(test_miner_capped_at_word);

    printf("\nConcurrency and atomic:\n");
    TEST(test_atomic_stats_single_thread);
    TEST(test_atomic_stats_accuracy);
    TEST(test_compact_shared_context_fails);
    TEST(test_compact_exclusive_context);
    TEST(test_remove_prefix_keeps_children);
    TEST(test_filter_rebuild_lazy_trigger);
    TEST(test_policy_clear);
    TEST(test_ctx_compact);
    TEST(test_compact_removes_subsumed);
    TEST(test_compact_keeps_different_lengths);

    printf("\nOptions (#opt):\n");
    TEST(test_policy_opt_matching);
    TEST(test_policy_opt_matches_value);

    printf("\nParametrized wildcards (#path.cfg):\n");
    TEST(test_param_add_path_ext);
    TEST(test_param_match_correct_ext);
    TEST(test_param_no_match_wrong_ext);
    TEST(test_param_unparametrized_subsumes);
    TEST(test_param_coexist_different_ext);
    TEST(test_param_coexist_with_unparametrized);
    TEST(test_param_compact_subsumes);
    TEST(test_param_compact_different_ext_keeps_both);
    TEST(test_param_serialization_roundtrip);
    TEST(test_param_no_extension_no_match);
    TEST(test_param_relpath_match);
    TEST(test_param_duplicate_add);
    TEST(test_param_duplicate_non_path);
    TEST(test_param_non_path_type_rejected);

    printf("\nParametrized size (#size.MiB):\n");
    TEST(test_param_size_add);
    TEST(test_param_size_match);
    TEST(test_param_size_coexist);
    TEST(test_param_size_compact_keeps_both);
    TEST(test_param_size_compact_subsumed);

    printf("\nNew parametrized wildcards (#hash, #image, #pkg, #branch, #sha, #duration, #signal, #range, #perm):\n");
    TEST(test_param_hash_algo_match);
    TEST(test_param_hash_algo_wildcard);
    TEST(test_param_hash_algo_invalid_param);
    TEST(test_param_image_registry_match);
    TEST(test_param_image_wildcard);
    TEST(test_param_pkg_scope_match);
    TEST(test_param_pkg_wildcard);
    TEST(test_param_branch_prefix_match);
    TEST(test_param_branch_wildcard);
    TEST(test_param_sha_length_match);
    TEST(test_param_sha_length_invalid);
    TEST(test_param_duration_unit_match);
    TEST(test_param_duration_unit_invalid);
    TEST(test_param_signal_name_match);
    TEST(test_param_signal_name_invalid);
    TEST(test_param_range_step_marker);
    TEST(test_param_perm_bits_marker);
    TEST(test_param_validate_new_types);
    TEST(test_param_subsume_specific_to_generic);
    TEST(test_param_subsume_via_same_base);

    printf("\nParametrized uuid/semver/timestamp:\n");
    TEST(test_param_uuid_v4);
    TEST(test_param_uuid_unparametrized);
    TEST(test_param_uuid_coexist);
    TEST(test_param_uuid_compact);
    TEST(test_param_semver);
    TEST(test_param_ts_date);
    TEST(test_param_ts_time);
    TEST(test_param_ts_datetime);

    printf("\nParameter validation:\n");
    TEST(test_param_validate_bad_path);
    TEST(test_param_validate_bad_size);
    TEST(test_param_validate_bad_uuid);
    TEST(test_param_validate_bad_ts);

    printf("\nPattern validation (st_validate_pattern):\n");
    TEST(test_validate_valid_literal);
    TEST(test_test_validate_valid_wildcard);
    TEST(test_validate_valid_parametrized);
    TEST(test_validate_invalid_param);
    TEST(test_validate_empty);
    TEST(test_validate_reject_star_first);

    printf("\nPolicy merge (st_policy_merge):\n");
    TEST(test_merge_empty_src);
    TEST(test_merge_overlapping);
    TEST(test_merge_disjoint);

    printf("\nPolicy diff (st_policy_diff):\n");
    TEST(test_diff_identical);
    TEST(test_diff_added_and_removed);
    TEST(test_diff_empty);

    printf("\nIncremental subsumption:\n");
    TEST(test_incr_subsumed_by_existing);
    TEST(test_incr_subsumes_existing);
    TEST(test_incr_keeps_different_lengths);
    TEST(test_incr_parametrized);
    TEST(test_incr_opt_wildcard);
    TEST(test_incr_ipaddr_subsumes);
    TEST(test_incr_stress);
    TEST(test_incr_remove_cleans_bucket);
    TEST(test_incr_batch_add);
    TEST(test_incr_wildcard_same_length);
    TEST(test_incr_no_cross_length_subsumption);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
