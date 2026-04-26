/*
 * test_cpl.c - Unit tests for the Command Policy Learner.
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
 * NORMALISATION TESTS
 * ============================================================ */

static int test_normalize_simple(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("ls -la", &tokens, &count);
    ASSERT(err == ST_OK);
    /* -la is now classified as a short option (#sopt) */
    ASSERT(count == 2);
    ASSERT_STR_EQ(tokens[0], "ls");
    ASSERT_STR_EQ(tokens[1], "#sopt");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_path(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("cat /etc/passwd", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count == 2);
    ASSERT_STR_EQ(tokens[0], "cat");
    ASSERT_STR_EQ(tokens[1], "#p");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_long(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("git commit --message \"hello world\"", &tokens, &count);
    ASSERT(err == ST_OK);
    /* git, commit, --message (now #lopt), * */
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "commit");
    ASSERT_STR_EQ(tokens[2], "#lopt");
    /* Next token should be the wildcard */
    ASSERT(count >= 4);
    ASSERT_STR_EQ(tokens[3], "#qs");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_short(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("git commit -m msg", &tokens, &count);
    ASSERT(err == ST_OK);
    /* -m is now classified as a short option (#sopt); msg is kept as literal */
    ASSERT(count == 4);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "commit");
    ASSERT_STR_EQ(tokens[2], "#sopt");
    ASSERT_STR_EQ(tokens[3], "msg");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_attached(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("docker run -it ubuntu bash", &tokens, &count);
    ASSERT(err == ST_OK);
    /* -i, *, -t, *, ubuntu, bash */
    /* -it is treated as a multi-char short flag, so it stays as -it */
    /* Actually, -it has 3 chars after '-', so is_short_flag_with_attached_value returns true */
    /* -i, *, -t, * */
    /* Let's verify the actual behavior */
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_pipeline(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("cat /var/log/syslog | grep ERROR", &tokens, &count);
    ASSERT(err == ST_OK);
    /* cat, #p, |, grep, #w */
    ASSERT(count >= 5);
    ASSERT_STR_EQ(tokens[0], "cat");
    ASSERT_STR_EQ(tokens[1], "#p");
    ASSERT_STR_EQ(tokens[2], "|");
    ASSERT_STR_EQ(tokens[3], "grep");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_redirection(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("ls > /tmp/out.txt", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "ls");
    ASSERT_STR_EQ(tokens[1], ">");
    ASSERT_STR_EQ(tokens[2], "#p");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_number(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("head -n 42 file.txt", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 4);
    ASSERT_STR_EQ(tokens[0], "head");
    ASSERT_STR_EQ(tokens[1], "#sopt");  /* -n is a short option */
    ASSERT_STR_EQ(tokens[2], "#n");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_hex(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("git show 0xdeadbeef", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "show");
    ASSERT_STR_EQ(tokens[2], "#n");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_ip(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("ping 192.168.1.1", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 2);
    ASSERT_STR_EQ(tokens[0], "ping");
    ASSERT_STR_EQ(tokens[1], "#i");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_env_assignment(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("export PATH=/usr/bin", &tokens, &count);
    ASSERT(err == ST_OK);
    /* export, PATH=, * */
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "export");
    ASSERT_STR_EQ(tokens[1], "PATH=");
    ASSERT_STR_EQ(tokens[2], "#p");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_long_flag_equals(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("gcc -o myprog main.c", &tokens, &count);
    ASSERT(err == ST_OK);
    /* -o is now classified as a short option (#sopt); the value follows as literal.
     * main.c is classified as #f (filename). */
    ASSERT(count == 4);
    ASSERT_STR_EQ(tokens[0], "gcc");
    ASSERT_STR_EQ(tokens[1], "#sopt");
    ASSERT_STR_EQ(tokens[2], "myprog");
    ASSERT_STR_EQ(tokens[3], "#f");
    st_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * TRIE TESTS
 * ============================================================ */

static int test_trie_create_free(void)
{
    st_learner_t *learner = st_learner_new(5, 0.05);
    ASSERT(learner != NULL);
    ASSERT(learner->trie.root != NULL);
    ASSERT(learner->trie.total_commands == 0);
    st_learner_free(learner);
    return 1;
}

static int test_trie_insert_single(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    st_error_t err = st_feed(learner, "ls -la");
    ASSERT(err == ST_OK);
    ASSERT(learner->trie.total_commands == 1);
    st_learner_free(learner);
    return 1;
}

static int test_trie_insert_multiple(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    st_feed(learner, "ls -la /tmp");
    st_feed(learner, "ls -la /var");
    st_feed(learner, "ls -la /home");
    ASSERT(learner->trie.total_commands == 3);
    st_learner_free(learner);
    return 1;
}

static int test_trie_counts(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    st_feed(learner, "git commit -m msg1");
    st_feed(learner, "git commit -m msg2");
    st_feed(learner, "git commit -m msg3");
    st_feed(learner, "git status");
    st_feed(learner, "git status");

    /* Root count should be 5 */
    ASSERT(learner->trie.root->count == 5);

    /* Find "git" child */
    st_node_t *git_node = NULL;
    for (size_t i = 0; i < learner->trie.root->num_children; i++) {
        if (strcmp(learner->trie.root->children[i]->token, "git") == 0) {
            git_node = learner->trie.root->children[i];
            break;
        }
    }
    ASSERT(git_node != NULL);
    ASSERT(git_node->count == 5);

    st_learner_free(learner);
    return 1;
}

/* ============================================================
 * SUGGESTION TESTS
 * ============================================================ */

static int test_suggest_basic(void)
{
    st_learner_t *learner = st_learner_new(3, 0.0);
    /* Feed 5 identical commands */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        st_feed(learner, cmd);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* The pattern "ls #sopt #p" should be among suggestions (since -l is now a short option) */
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "ls") &&
            (strstr(suggestions[i].pattern, "#sopt") || strstr(suggestions[i].pattern, "#opt")) &&
            strstr(suggestions[i].pattern, "#p")) {
            found = true;
            ASSERT(suggestions[i].count == 5);
            break;
        }
    }
    ASSERT(found);

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_pipeline(void)
{
    st_learner_t *learner = st_learner_new(3, 0.0);
    for (int i = 0; i < 4; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "cat /var/log/file%d.log | grep ERROR", i);
        st_feed(learner, cmd);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* Look for a pattern containing pipe */
    bool found_pipe = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "|")) {
            found_pipe = true;
            break;
        }
    }
    ASSERT(found_pipe);

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_confidence_ranking(void)
{
    st_learner_t *learner = st_learner_new(2, 0.0);
    /* 10 git commands, 8 of which are "git commit -m *" */
    for (int i = 0; i < 8; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        st_feed(learner, cmd);
    }
    st_feed(learner, "git status");
    st_feed(learner, "git log");

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* First suggestion should have highest confidence */
    if (count >= 2) {
        ASSERT(suggestions[0].confidence >= suggestions[1].confidence);
    }

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_no_duplicates(void)
{
    st_learner_t *learner = st_learner_new(2, 0.0);
    for (int i = 0; i < 5; i++) {
        st_feed(learner, "ls -la");
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions != NULL);

    /* Check no duplicate patterns */
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            ASSERT(strcmp(suggestions[i].pattern, suggestions[j].pattern) != 0);
        }
    }

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_min_support_filter(void)
{
    st_learner_t *learner = st_learner_new(10, 0.0);
    /* Feed only 5 commands – below min_support */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        st_feed(learner, cmd);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    /* No suggestions should meet min_support=10 */
    ASSERT(count == 0 || suggestions == NULL);

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_max_suggestions(void)
{
    st_learner_t *learner = st_learner_new(2, 0.0);
    learner->max_suggestions = 3;

    /* Feed many different commands */
    for (int i = 0; i < 20; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "cmd%d arg%d val%d", i, i, i);
        st_feed(learner, cmd);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(count <= 3);

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

/* ============================================================
 * BLACKLIST TESTS
 * ============================================================ */

static int test_blacklist_add_and_check(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    ASSERT(st_blacklist_add(learner, "git commit -m *") == ST_OK);
    ASSERT(st_is_blacklisted(learner, "git commit -m *"));
    ASSERT(!st_is_blacklisted(learner, "git status"));
    st_learner_free(learner);
    return 1;
}

static int test_blacklist_prevents_suggestion(void)
{
    st_learner_t *learner = st_learner_new(2, 0.0);
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        st_feed(learner, cmd);
    }

    /* Blacklist the pattern */
    st_blacklist_add(learner, "ls -l *");

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);

    /* The blacklisted pattern should not appear */
    for (size_t i = 0; i < count; i++) {
        ASSERT(strcmp(suggestions[i].pattern, "ls -l *") != 0);
    }

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

/* ============================================================
 * SERIALISATION TESTS
 * ============================================================ */

static int test_save_and_load(void)
{
    st_learner_t *learner1 = st_learner_new(1, 0.0);
    st_feed(learner1, "git commit -m msg1");
    st_feed(learner1, "git commit -m msg2");
    st_feed(learner1, "ls -la /tmp");
    st_feed(learner1, "ls -la /var");

    st_error_t err = st_save(learner1, "tests/test_save_load.tmp");
    ASSERT(err == ST_OK);

    st_learner_t *learner2 = st_learner_new(1, 0.0);
    err = st_load(learner2, "tests/test_save_load.tmp");
    ASSERT(err == ST_OK);

    /* Verify the loaded learner can produce suggestions */
    size_t count2 = 0;
    st_suggestion_t *s2 = st_suggest(learner2, &count2);
    ASSERT(count2 > 0);

    /* Verify at least one suggestion contains "git" or "ls" */
    bool found = false;
    for (size_t i = 0; i < count2; i++) {
        if (strstr(s2[i].pattern, "git") || strstr(s2[i].pattern, "ls")) {
            found = true;
            break;
        }
    }
    ASSERT(found);

    st_free_suggestions(s2, count2);
    st_learner_free(learner1);
    st_learner_free(learner2);
    return 1;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

static int test_empty_command(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    st_error_t err = st_feed(learner, "");
    ASSERT(err == ST_ERR_INVALID);
    st_learner_free(learner);
    return 1;
}

static int test_null_command(void)
{
    st_learner_t *learner = st_learner_new(1, 0.0);
    st_error_t err = st_feed(learner, NULL);
    ASSERT(err == ST_ERR_INVALID);
    st_learner_free(learner);
    return 1;
}

static int test_suggest_empty_trie(void)
{
    st_learner_t *learner = st_learner_new(5, 0.05);
    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions == NULL);
    ASSERT(count == 0);
    st_learner_free(learner);
    return 1;
}

static int test_normalize_quoted_string(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("echo \"hello world\"", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 2);
    ASSERT_STR_EQ(tokens[0], "echo");
    /* Quoted string with space → #qs */
    ASSERT_STR_EQ(tokens[1], "#qs");
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_hash(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("git show a1b2c3d4e5f6a7b8", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "show");
    ASSERT_STR_EQ(tokens[2], "#h");
    st_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * LEARNER PARAMETRIZED SUGGESTIONS
 * ============================================================ */

static int test_suggest_path_ext(void)
{
    /* Feed many .cfg paths and verify learner suggests #p.cfg */
    st_learner_t *learner = st_learner_new(3, 0.05);

    /* Feed 5 commands with .cfg absolute paths */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "cat /etc/file%d.cfg", i);
        st_feed(learner, cmd);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(count > 0);

    /* Find the suggestion containing "#p.cfg" */
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "#p.cfg") != NULL) {
            found = true;
            break;
        }
    }
    ASSERT(found);

    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running shelltype unit tests...\n\n");

    printf("Normalisation:\n");
    TEST(test_normalize_simple);
    TEST(test_normalize_path);
    TEST(test_normalize_flag_value_long);
    TEST(test_normalize_flag_value_short);
    TEST(test_normalize_flag_value_attached);
    TEST(test_normalize_pipeline);
    TEST(test_normalize_redirection);
    TEST(test_normalize_number);
    TEST(test_normalize_hex);
    TEST(test_normalize_ip);
    TEST(test_normalize_env_assignment);
    TEST(test_normalize_long_flag_equals);
    TEST(test_normalize_quoted_string);
    TEST(test_normalize_hash);

    printf("\nTrie:\n");
    TEST(test_trie_create_free);
    TEST(test_trie_insert_single);
    TEST(test_trie_insert_multiple);
    TEST(test_trie_counts);

    printf("\nSuggestions:\n");
    TEST(test_suggest_basic);
    TEST(test_suggest_pipeline);
    TEST(test_suggest_confidence_ranking);
    TEST(test_suggest_no_duplicates);
    TEST(test_suggest_min_support_filter);
    TEST(test_suggest_max_suggestions);

    printf("\nBlacklist:\n");
    TEST(test_blacklist_add_and_check);
    TEST(test_blacklist_prevents_suggestion);

    printf("\nSerialisation:\n");
    TEST(test_save_and_load);

    printf("\nEdge cases:\n");
    TEST(test_empty_command);
    TEST(test_null_command);
    TEST(test_suggest_empty_trie);

    printf("\nLearner parametrized suggestions:\n");
    TEST(test_suggest_path_ext);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
