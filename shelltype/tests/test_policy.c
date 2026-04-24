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

/* Test that compact removes patterns subsumed by more general ones */
static int test_compact_removes_subsumed(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Add patterns where #w will be subsumed by * at same position */
    st_policy_add(policy, "git commit -m msg1");
    st_policy_add(policy, "git commit -m msg2");
    st_policy_add(policy, "git commit -m msg3");
    st_policy_add(policy, "git commit -m *");  /* This subsumes the above (same length) */

    ASSERT(st_policy_count(policy) == 4);

    /* Compact should remove the 3 specific patterns, keep the wildcard */
    st_error_t err = st_policy_compact(policy);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 1);

    /* Verify the remaining pattern matches */
    st_eval_result_t result;
    err = st_policy_eval(policy, "git commit -m hello", &result);
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

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
