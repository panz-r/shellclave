#include "shellgate.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int pass_count = 0;
static int fail_count = 0;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("    FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while(0)

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %-40s ", #name); int _pf = fail_count; test_##name(); if (fail_count == _pf) { printf("PASS\n"); pass_count++; } } while(0)

static sg_gate_t *gate_with_rules(const char **rules, int count)
{
    sg_gate_t *g = sg_gate_new();
    for (int i = 0; i < count; i++)
        sg_gate_add_rule(g, rules[i]);
    return g;
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

TEST(gate_create_destroy)
{
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    sg_gate_free(g);
}

TEST(gate_null_safety)
{
    sg_gate_free(NULL);
    ASSERT(sg_gate_rule_count(NULL) == 0);
    ASSERT(sg_eval(NULL, "ls", NULL) == SG_ERR_INVALID);
}

/* ============================================================
 * SIMPLE ALLOW / DENY
 * ============================================================ */

TEST(allow_simple_command)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_error_t err = sg_eval(g, "ls", &r);
    ASSERT(err == SG_OK);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmd_count == 1);
    ASSERT(r.subcmds[0].matches);
    sg_gate_free(g);
}

TEST(deny_unknown_command)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_error_t err = sg_eval(g, "rm -rf /", &r);
    ASSERT(err == SG_OK);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

TEST(allow_with_args)
{
    const char *rules[] = { "ls * *" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "ls -la /home", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(deny_empty_policy)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    sg_eval(g, "ls", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

/* ============================================================
 * PIPES
 * ============================================================ */

TEST(allow_pipe_both_match)
{
    const char *rules[] = { "ls", "sort" };
    sg_gate_t *g = gate_with_rules(rules, 2);
    sg_result_t r;
    sg_eval(g, "ls | sort", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmd_count == 2);
    sg_gate_free(g);
}

TEST(deny_pipe_one_fails)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "ls | rm", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    ASSERT(r.subcmd_count >= 1);
    sg_gate_free(g);
}

/* ============================================================
 * OPERATORS
 * ============================================================ */

TEST(allow_semicolon_both_match)
{
    const char *rules[] = { "ls", "pwd" };
    sg_gate_t *g = gate_with_rules(rules, 2);
    sg_result_t r;
    sg_eval(g, "ls ; pwd", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(deny_and_first_fails)
{
    const char *rules[] = { "rm" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "rm -rf / && ls", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

TEST(deny_or_first_fails)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "rm || ls", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

/* ============================================================
 * WILDCARD PATTERNS
 * ============================================================ */

TEST(allow_wildcard_args)
{
    const char *rules[] = { "git * * *" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "git commit -m hello", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(allow_path_wildcard)
{
    const char *rules[] = { "cat #path" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "cat /etc/passwd", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

/* ============================================================
 * FEATURE REJECTION
 * ============================================================ */

TEST(reject_subshell)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "echo *");
    sg_result_t r;
    sg_eval(g, "echo $(whoami)", &r);
    ASSERT(r.verdict == SG_VERDICT_REJECT);
    ASSERT(r.subcmds[0].reject_reason[0] != '\0');
    sg_gate_free(g);
}

TEST(reject_heredoc)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat");
    sg_result_t r;
    sg_eval(g, "cat <<EOF\nhello\nEOF", &r);
    ASSERT(r.verdict == SG_VERDICT_REJECT);
    sg_gate_free(g);
}

/* ============================================================
 * SUGGESTIONS
 * ============================================================ */

TEST(suggestions_on_deny)
{
    const char *rules[] = { "git status" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_eval(g, "git commit", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

TEST(suggestions_disabled)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_gate_set_suggestions(g, false);
    sg_result_t r;
    sg_eval(g, "rm", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(eval_empty_command)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    sg_error_t err = sg_eval(g, "", &r);
    ASSERT(err == SG_ERR_INVALID);
    sg_gate_free(g);
}

TEST(eval_whitespace_command)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls");
    sg_result_t r;
    sg_eval(g, "   ", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(eval_parse_error)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    sg_eval(g, "echo \"unclosed", &r);
    ASSERT(r.verdict == SG_VERDICT_REJECT);
    sg_gate_free(g);
}

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

TEST(config_cwd)
{
    sg_gate_t *g = sg_gate_new();
    sg_error_t err = sg_gate_set_cwd(g, "/tmp");
    ASSERT(err == SG_OK);
    sg_gate_free(g);
}

TEST(config_stop_first_fail)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_gate_set_stop_mode(g, SG_STOP_FIRST_FAIL);
    sg_result_t r;
    sg_eval(g, "rm ; ls", &r);
    ASSERT(r.subcmd_count == 1);
    ASSERT(!r.subcmds[0].matches);
    sg_gate_free(g);
}

TEST(config_eval_all)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_gate_set_stop_mode(g, SG_EVAL_ALL);
    sg_result_t r;
    sg_eval(g, "rm ; ls", &r);
    ASSERT(r.subcmd_count == 2);
    ASSERT(!r.subcmds[0].matches);
    ASSERT(r.subcmds[1].matches);
    sg_gate_free(g);
}

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

TEST(add_remove_rule)
{
    sg_gate_t *g = sg_gate_new();
    ASSERT(sg_gate_rule_count(g) == 0);
    sg_gate_add_rule(g, "ls");
    ASSERT(sg_gate_rule_count(g) == 1);
    sg_gate_remove_rule(g, "ls");
    ASSERT(sg_gate_rule_count(g) == 0);
    sg_gate_free(g);
}

TEST(remove_nonexistent)
{
    sg_gate_t *g = sg_gate_new();
    sg_error_t err = sg_gate_remove_rule(g, "nope");
    ASSERT(err == SG_OK);
    sg_gate_free(g);
}

/* ============================================================
 * VERDICT HELPERS
 * ============================================================ */

TEST(verdict_names)
{
    ASSERT(strcmp(sg_verdict_name(SG_VERDICT_ALLOW), "ALLOW") == 0);
    ASSERT(strcmp(sg_verdict_name(SG_VERDICT_DENY), "DENY") == 0);
    ASSERT(strcmp(sg_verdict_name(SG_VERDICT_REJECT), "REJECT") == 0);
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("shellgate tests\n\n");

    printf("Lifecycle:\n");
    RUN(gate_create_destroy);
    RUN(gate_null_safety);

    printf("\nAllow/Deny:\n");
    RUN(allow_simple_command);
    RUN(deny_unknown_command);
    RUN(allow_with_args);
    RUN(deny_empty_policy);

    printf("\nPipes:\n");
    RUN(allow_pipe_both_match);
    RUN(deny_pipe_one_fails);

    printf("\nOperators:\n");
    RUN(allow_semicolon_both_match);
    RUN(deny_and_first_fails);
    RUN(deny_or_first_fails);

    printf("\nWildcard patterns:\n");
    RUN(allow_wildcard_args);
    RUN(allow_path_wildcard);

    printf("\nFeature rejection:\n");
    RUN(reject_subshell);
    RUN(reject_heredoc);

    printf("\nSuggestions:\n");
    RUN(suggestions_on_deny);
    RUN(suggestions_disabled);

    printf("\nEdge cases:\n");
    RUN(eval_empty_command);
    RUN(eval_whitespace_command);
    RUN(eval_parse_error);

    printf("\nConfiguration:\n");
    RUN(config_cwd);
    RUN(config_stop_first_fail);
    RUN(config_eval_all);

    printf("\nPolicy management:\n");
    RUN(add_remove_rule);
    RUN(remove_nonexistent);

    printf("\nHelpers:\n");
    RUN(verdict_names);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
