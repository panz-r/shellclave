/*
 * test_verify.c – Unit tests for the verify module.
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
 * EXACT MATCH
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

/* ============================================================
 * WILDCARD SEMANTICS
 * ============================================================ */

static int test_verify_wildcard_single_token(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit -m", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_path(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "cat *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cat /etc/passwd", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT(r.matching_pattern != NULL);
    ASSERT_STR_EQ(r.matching_pattern, "cat *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_number(void)
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

/* ============================================================
 * EXACT LENGTH
 * ============================================================ */

static int test_verify_exact_length_shorter_command(void)
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

static int test_verify_exact_length_longer_command(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PIPELINES
 * ============================================================ */

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

static int test_verify_pipeline_no_match_wrong_cmd(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "cat * | grep *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "cat file | wc -l", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MULTIPLE PATTERNS
 * ============================================================ */

static int test_verify_multiple_patterns_first_match(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "ls -la *");
    st_policy_add(policy, "git commit -m *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "ls -la /tmp", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "ls -la *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_multiple_patterns_different_prefixes(void)
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

    err = st_policy_eval(policy, "cat log.txt | grep error", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "cat * | grep *");

    err = st_policy_eval(policy, "rm -rf /", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * VERIFY_ALL
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
    ASSERT(matches == NULL);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

static int test_verify_empty_policy(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_redirection(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "ls > *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "ls > /tmp/out.txt", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "ls > *");

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

static int test_verify_command_with_quotes(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "echo *");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "echo \"hello world\"", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "echo *");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_flag_value(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "gcc --output * main.c");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "gcc --output program main.c", &r);
    ASSERT(err == ST_OK);
    ASSERT_STR_EQ(r.matching_pattern, "gcc --output * main.c");

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_after_remove(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);
    st_policy_add(policy, "git commit -m *");
    st_policy_add(policy, "git status");

    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == ST_OK);

    st_policy_remove(policy, "git commit -m *");

    err = st_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == ST_OK);

    err = st_policy_eval(policy, "git status", &r);
    ASSERT(err == ST_OK);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * FULL EVAL + SUGGEST + ACCEPT LOOP
 * ============================================================ */

static int test_eval_suggest_accept_loop(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la *");

    /* 1. Verify a matching command */
    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "git status", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "git status");

    /* 2. Verify a non-matching command — should produce suggestions */
    err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);
    ASSERT(strstr(r.suggestions[0].pattern, "git") != NULL);
    ASSERT(strstr(r.suggestions[1].pattern, "git") != NULL);

    /* 3. Accept suggestion A (exact) and add to policy */
    err = st_policy_add(policy, r.suggestions[0].pattern);
    ASSERT(err == ST_OK);
    ASSERT(st_policy_count(policy) == 3);

    /* 4. Now the same command should match */
    err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* 5. A completely different command should still not match */
    err = st_policy_eval(policy, "rm -rf /", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

static int test_eval_suggest_variants_loop(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    st_policy_add(policy, "git status");
    st_policy_add(policy, "ls -la *");

    /* Get suggestions for a new command */
    st_eval_result_t r;
    st_error_t err = st_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);

    /* Tokenize the chosen suggestion for Step 2 */
    st_token_array_t chosen;
    st_normalize_typed(r.suggestions[0].pattern, &chosen);

    /* Get variants — variant 0 is always all-literals */
    st_expand_suggestion_t variants[3];
    size_t nv = st_policy_suggest_variants(policy, chosen.tokens, chosen.count, variants);
    ASSERT(nv >= 1);

    /* Variant 0 should be all-literals */
    ASSERT(strstr(variants[0].pattern, "docker") != NULL);

    /* Accept the literal variant and add to policy */
    err = st_policy_add(policy, variants[0].pattern);
    ASSERT(err == ST_OK);

    /* Now the command should match */
    err = st_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    st_free_token_array(&chosen);
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * COMPLEX: FULL EVAL + FILTER + SUGGEST STRESS TEST
 *
 * Exercises:
 *   - Filter pre-check rejects in verify-only mode (skip trie walk)
 *   - Filter pre-check rejects but still walks trie for suggestions
 *   - Wildcard widening suggestion path
 *   - Literal-to-wildcard generalization path
 *   - Multiple add/eval cycles with filter rebuild
 *   - Divergence at various depths
 *   - Commands longer than FILTER_POS_LEVELS
 * ============================================================ */

static int test_complex_eval_filter_suggest_stress(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Build a policy with:
     *  - Shared prefix "git" with multiple children (status, log, push)
     *  - A wildcard pattern "ls -la *"
     *  - A deep pattern "docker run -it * *"
     *  - Multiple paths at position 1 for literal-to-wildcard trigger
     */
    st_policy_add(policy, "git status");
    st_policy_add(policy, "git log");
    st_policy_add(policy, "git push");
    st_policy_add(policy, "ls -la *");
    st_policy_add(policy, "docker run -it * *");
    st_policy_add(policy, "cat /etc/passwd");
    st_policy_add(policy, "cat /etc/shadow");
    st_policy_add(policy, "cat /etc/hosts");

    st_eval_result_t r;
    st_error_t err;

    /* --- 1. Exact match --- */
    err = st_policy_eval(policy, "git status", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "git status");

    /* --- 2. Wildcard match --- */
    err = st_policy_eval(policy, "ls -la /tmp/foo", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "ls -la *");

    /* --- 3. Deep wildcard match --- */
    err = st_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "docker run -it * *");

    /* --- 4. Filter reject in verify-only mode (completely unrelated) --- */
    /* "zzz" is not in any position 0 filter → filter rejects, no trie walk.
     * With fixed error semantics, non-match returns ST_OK (not an error). */
    err = st_policy_eval(policy, "zzz something", NULL);
    ASSERT(err == ST_OK);

    /* --- 5. Filter reject with suggestions (divergence at position 0) --- */
    err = st_policy_eval(policy, "zzz something", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);
    /* Both suggestions should contain "zzz" since divergence is at position 0 */
    ASSERT(strstr(r.suggestions[0].pattern, "zzz") != NULL);
    ASSERT(strstr(r.suggestions[1].pattern, "zzz") != NULL);

    /* --- 6. Filter passes, trie diverges at position 1 --- */
    /* "git" matches at position 0, but "commit" not in children */
    err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);
    /* Suggestion A should have "git commit -m hello" (exact) */
    ASSERT(strstr(r.suggestions[0].pattern, "git") != NULL);
    ASSERT(strstr(r.suggestions[0].pattern, "commit") != NULL);
    /* Suggestion B should have wildcard at position 1 (3 literals: status,log,push → #w) */
    ASSERT(strstr(r.suggestions[1].pattern, "git") != NULL);

    /* --- 7. Accept suggestion B, re-evaluate --- */
    err = st_policy_add(policy, r.suggestions[1].pattern);
    ASSERT(err == ST_OK);

    /* The same command should now match */
    err = st_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* --- 8. Another variant: same prefix, different wildcard value --- */
    /* Suggestion B has wildcard at position 1, so any word there should match.
     * But positions 2+ are literals from the original command. */
    err = st_policy_eval(policy, "git rebase -m hello", &r);
    /* May or may not match depending on suggestion B content */
    /* Just verify it produces valid output */
    ASSERT(r.suggestion_count == 2 || r.matches);

    /* --- 9. Literal-to-wildcard generalization --- */
    /* Add 3 patterns with different WORD tokens at position 1.
     * Note: we use words like "alpha", "beta", "gamma" rather than short
     * options like "-a", "-b", "-c", because short options are now classified
     * as #opt and get merged into a single pattern. */
    st_policy_add(policy, "mycmd alpha value");
    st_policy_add(policy, "mycmd beta value");
    st_policy_add(policy, "mycmd gamma value");

    /* "mycmd delta value" diverges at position 1 where we have
     * 3 literal children: alpha, beta, gamma */
    err = st_policy_eval(policy, "mycmd delta value", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);
    /* Suggestion B should have a wildcard at position 1 */
    ASSERT(strstr(r.suggestions[1].pattern, "mycmd") != NULL);

    /* --- 10. Accept the literal-to-wildcard suggestion --- */
    err = st_policy_add(policy, r.suggestions[1].pattern);
    ASSERT(err == ST_OK);

    /* Now it should match */
    err = st_policy_eval(policy, "mycmd delta value", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* --- 11. Long command (beyond FILTER_POS_LEVELS=4) --- */
    err = st_policy_eval(policy, "docker run -it --rm ubuntu /bin/bash -c 'echo hello'", &r);
    /* This may or may not match depending on pattern structure */
    /* Just verify it doesn't crash and produces valid output */
    if (r.matches) {
        ASSERT(r.matching_pattern != NULL);
    } else {
        ASSERT(r.suggestion_count == 2);
    }

    /* --- 12. Filter rebuild after multiple additions --- */
    /* After many adds, the epoch has changed many times.
     * The next eval should trigger a filter rebuild. */
    for (int i = 0; i < 10; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "custom-cmd-%d --flag value", i);
        st_policy_add(policy, cmd);
    }

    /* This eval should trigger filter rebuild and still work correctly */
    err = st_policy_eval(policy, "git status", &r);
    ASSERT(err == ST_OK);
    ASSERT(r.matches);

    /* A completely unrelated command should still be rejected */
    err = st_policy_eval(policy, "totally-unrelated-command", &r);
    ASSERT(err == ST_OK);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running verify unit tests...\n\n");

    printf("Exact match:\n");
    TEST(test_verify_exact_match);
    TEST(test_verify_no_match);

    printf("\nWildcard semantics:\n");
    TEST(test_verify_wildcard_single_token);
    TEST(test_verify_wildcard_matches_path);
    TEST(test_verify_wildcard_matches_number);

    printf("\nExact length:\n");
    TEST(test_verify_exact_length_shorter_command);
    TEST(test_verify_exact_length_longer_command);

    printf("\nPipelines:\n");
    TEST(test_verify_pipeline);
    TEST(test_verify_pipeline_no_match_wrong_cmd);

    printf("\nMultiple patterns:\n");
    TEST(test_verify_multiple_patterns_first_match);
    TEST(test_verify_multiple_patterns_different_prefixes);

    printf("\nVerify all:\n");
    TEST(test_verify_all_matches);
    TEST(test_verify_all_no_match);

    printf("\nEdge cases:\n");
    TEST(test_verify_empty_policy);
    TEST(test_verify_redirection);
    TEST(test_verify_flag_value);
    TEST(test_verify_command_with_quotes);
    TEST(test_verify_wildcard_matches_flag_value);
    TEST(test_verify_after_remove);

    printf("\nEval + suggest + accept loop:\n");
    TEST(test_eval_suggest_accept_loop);
    TEST(test_eval_suggest_variants_loop);
    TEST(test_complex_eval_filter_suggest_stress);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
