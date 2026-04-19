#include "shell_depgraph.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int pass_count = 0;
static int fail_count = 0;
static bool verbose = false;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("    FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("    FAIL: expected '%s', got '%s' at %s:%d\n", (b), (a), __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while(0)

#define ASSERT_STRN_EQ(s, slen, expected) do { \
    const char *_e = (expected); \
    uint32_t _elen = (uint32_t)strlen(_e); \
    if ((slen) != _elen || memcmp((s), _e, _elen) != 0) { \
        printf("    FAIL: expected '%s' (len %u), got '%.*s' (len %u) at %s:%d\n", \
               _e, _elen, (slen), (s), (slen), __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while(0)

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s ... ", #name); test_##name(); if (fail_count == prev) { printf("PASS\n"); } } while(0)

/* ============================================================
 * HELPERS
 * ============================================================ */

static uint32_t count_type(const shell_dep_graph_t *g, shell_dep_node_type_t type)
{
    uint32_t c = 0;
    for (uint32_t i = 0; i < g->node_count; i++)
        if (g->nodes[i].type == type) c++;
    return c;
}

static uint32_t count_edge_type(const shell_dep_graph_t *g, shell_dep_edge_type_t type)
{
    uint32_t c = 0;
    for (uint32_t i = 0; i < g->edge_count; i++)
        if (g->edges[i].type == type) c++;
    return c;
}

static uint32_t count_doc_kind(const shell_dep_graph_t *g, shell_dep_doc_kind_t kind)
{
    uint32_t c = 0;
    for (uint32_t i = 0; i < g->node_count; i++)
        if (g->nodes[i].type == SHELL_NODE_DOC && g->nodes[i].doc.kind == kind) c++;
    return c;
}

static int find_first_cmd(const shell_dep_graph_t *g)
{
    for (uint32_t i = 0; i < g->node_count; i++)
        if (g->nodes[i].type == SHELL_NODE_CMD) return (int)i;
    return -1;
}

static bool has_edge(const shell_dep_graph_t *g, uint32_t from, uint32_t to,
                      shell_dep_edge_type_t type)
{
    for (uint32_t i = 0; i < g->edge_count; i++)
        if (g->edges[i].from == from && g->edges[i].to == to && g->edges[i].type == type)
            return true;
    return false;
}

static shell_dep_error_t parse(const char *cmd, shell_dep_graph_t *g)
{
    return shell_parse_depgraph(cmd, strlen(cmd), ".", NULL, g);
}

static shell_dep_error_t parse_cwd(const char *cmd, const char *cwd, shell_dep_graph_t *g)
{
    return shell_parse_depgraph(cmd, strlen(cmd), cwd, NULL, g);
}

/* ============================================================
 * BASIC COMMANDS
 * ============================================================ */

TEST(simple_command)
{
    shell_dep_graph_t g;
    shell_dep_error_t err = parse("ls -la", &g);
    ASSERT(err == SHELL_DEP_OK);
    ASSERT(g.node_count == 1);
    ASSERT(g.nodes[0].type == SHELL_NODE_CMD);
    ASSERT(g.nodes[0].cmd.token_count == 2);
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[0], g.nodes[0].cmd.token_lens[0], "ls");
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[1], g.nodes[0].cmd.token_lens[1], "-la");
    ASSERT(g.edge_count == 0);
    pass_count++;
}

TEST(command_with_args)
{
     shell_dep_graph_t g;
    parse("gcc -Wall -Wextra -o myapp main.c", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(g.nodes[0].cmd.token_count == 6);
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[0], g.nodes[0].cmd.token_lens[0], "gcc");
    pass_count++;
}

TEST(quoted_args)
{
     shell_dep_graph_t g;
    parse("echo 'hello world' \"foo bar\"", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(g.nodes[0].cmd.token_count == 3);
    pass_count++;
}

TEST(single_word_command)
{
     shell_dep_graph_t g;
    parse("ls", &g);
    ASSERT(g.node_count == 1);
    ASSERT(g.nodes[0].type == SHELL_NODE_CMD);
    ASSERT(g.nodes[0].cmd.token_count == 1);
    pass_count++;
}

TEST(whitespace_only)
{
     shell_dep_graph_t g;
    memset(&g, 0, sizeof(g));
    shell_dep_error_t err = shell_parse_depgraph("   ", 3, ".", NULL, &g);
    ASSERT(err == SHELL_DEP_OK);
    ASSERT(g.node_count == 0);
    pass_count++;
}

TEST(token_zero_copy)
{
     const char *cmd = "echo hello";
    shell_dep_graph_t g;
    parse(cmd, &g);
    ASSERT(g.nodes[0].cmd.tokens[0] >= cmd);
    ASSERT(g.nodes[0].cmd.tokens[0] < cmd + strlen(cmd));
    pass_count++;
}

/* ============================================================
 * OPERATORS
 * ============================================================ */

TEST(pipe)
{
     shell_dep_graph_t g;
    parse("cat file.txt | grep x", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
    pass_count++;
}

TEST(pipe_direction)
{
     shell_dep_graph_t g;
    parse("cmd1 | cmd2", &g);
    int c0 = find_first_cmd(&g);
    ASSERT(c0 >= 0);
    uint32_t c1 = (uint32_t)(c0 + 1);
    ASSERT(g.nodes[c1].type == SHELL_NODE_CMD);
    ASSERT(has_edge(&g, (uint32_t)c0, c1, SHELL_EDGE_PIPE));
    pass_count++;
}

TEST(and)
{
     shell_dep_graph_t g;
    parse("cmd1 && cmd2", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == 1);
    pass_count++;
}

TEST(or)
{
     shell_dep_graph_t g;
    parse("cmd1 || cmd2", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_OR) == 1);
    pass_count++;
}

TEST(semicolon)
{
     shell_dep_graph_t g;
    parse("cmd1 ; cmd2", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SEQ) == 1);
    pass_count++;
}

TEST(mixed_operators)
{
     shell_dep_graph_t g;
    parse("cmd1 && cmd2 || cmd3", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
    ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_OR) == 1);
    pass_count++;
}

TEST(three_stage_pipe)
{
     shell_dep_graph_t g;
    parse("cat file | sort | uniq", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 2);
    pass_count++;
}

/* ============================================================
 * REDIRECTS
 * ============================================================ */

TEST(redirect_out)
{
     shell_dep_graph_t g;
    parse("echo hello > out.txt", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
    pass_count++;
}

TEST(redirect_in)
{
     shell_dep_graph_t g;
    parse("sort < input.txt", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_READ) == 1);
    pass_count++;
}

TEST(redirect_append)
{
     shell_dep_graph_t g;
    parse("echo hello >> out.txt", &g);
    ASSERT(count_edge_type(&g, SHELL_EDGE_APPEND) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    pass_count++;
}

TEST(redirect_stderr)
{
     shell_dep_graph_t g;
    parse("cmd 2> err.log", &g);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    pass_count++;
}

TEST(redirect_stderr_append)
{
     shell_dep_graph_t g;
    parse("cmd 2>> err.log", &g);
    ASSERT(count_edge_type(&g, SHELL_EDGE_APPEND) == 1);
    pass_count++;
}

TEST(multiple_redirects)
{
     shell_dep_graph_t g;
    parse("cmd > out.txt 2> err.log", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 2);
    pass_count++;
}

TEST(redirect_write_direction)
{
     shell_dep_graph_t g;
    parse("echo hello > out.txt", &g);
    int cmd_idx = find_first_cmd(&g);
    ASSERT(cmd_idx >= 0);
    for (uint32_t i = 0; i < g.edge_count; i++) {
        if (g.edges[i].type == SHELL_EDGE_WRITE) {
            ASSERT(g.edges[i].from == (uint32_t)cmd_idx);
            ASSERT(g.nodes[g.edges[i].to].type == SHELL_NODE_DOC);
            ASSERT(g.nodes[g.edges[i].to].doc.kind == SHELL_DOC_FILE);
        }
    }
    pass_count++;
}

TEST(redirect_file_path_len)
{
     shell_dep_graph_t g;
    parse("cmd > /tmp/output.txt", &g);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_FILE) {
            ASSERT_STRN_EQ(g.nodes[i].doc.path, g.nodes[i].doc.path_len, "/tmp/output.txt");
        }
    }
    pass_count++;
}

/* ============================================================
 * CWD TRACKING
 * ============================================================ */

TEST(cd_relative)
{
     shell_dep_graph_t g;
    parse_cwd("cd ../foo && ls", "/home/user", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(g.nodes[0].cmd.cwd != NULL);
    ASSERT(strstr(g.nodes[0].cmd.cwd, "foo") != NULL);
    pass_count++;
}

TEST(cd_absolute)
{
     shell_dep_graph_t g;
    parse_cwd("cd /tmp && ls", "/home/user", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT_STR_EQ(g.nodes[0].cmd.cwd, "/tmp");
    pass_count++;
}

TEST(cd_no_args)
{
     shell_dep_graph_t g;
    parse_cwd("cd && ls", "/home/user", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT_STR_EQ(g.nodes[0].cmd.cwd, "$HOME");
    pass_count++;
}

TEST(cd_dotdot_normalization)
{
     shell_dep_graph_t g;
    parse_cwd("cd .. && pwd", "/home/user/docs", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT_STR_EQ(g.nodes[0].cmd.cwd, "/home/user");
    pass_count++;
}

TEST(cd_default_cwd)
{
     shell_dep_graph_t g;
    parse("ls", &g);
    ASSERT(g.nodes[0].cmd.cwd != NULL);
    ASSERT(g.nodes[0].cmd.cwd[0] == '.');
    pass_count++;
}

/* ============================================================
 * ENVIRONMENT VARIABLES
 * ============================================================ */

TEST(single_env_var)
{
     shell_dep_graph_t g;
    parse("FOO=bar cmd", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_ENVVAR) {
            ASSERT_STRN_EQ(g.nodes[i].doc.name, g.nodes[i].doc.name_len, "FOO");
            ASSERT_STRN_EQ(g.nodes[i].doc.value, g.nodes[i].doc.value_len, "bar");
        }
    }
    ASSERT(count_edge_type(&g, SHELL_EDGE_ENV) == 1);
    pass_count++;
}

TEST(multiple_env_vars)
{
     shell_dep_graph_t g;
    parse("FOO=bar BAZ=qux cmd arg", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ENV) == 2);
    pass_count++;
}

TEST(env_var_empty_value)
{
     shell_dep_graph_t g;
    parse("FOO= cmd", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_ENVVAR) {
            ASSERT(g.nodes[i].doc.name_len == 3);
            ASSERT(g.nodes[i].doc.value_len == 0);
        }
    }
    pass_count++;
}

TEST(env_var_with_path_value)
{
     shell_dep_graph_t g;
    parse("PATH=/usr/bin ls", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_ENVVAR) {
            ASSERT_STRN_EQ(g.nodes[i].doc.name, g.nodes[i].doc.name_len, "PATH");
            ASSERT_STRN_EQ(g.nodes[i].doc.value, g.nodes[i].doc.value_len, "/usr/bin");
        }
    }
    pass_count++;
}

TEST(env_var_edge_direction)
{
     shell_dep_graph_t g;
    parse("FOO=bar cmd", &g);
    for (uint32_t i = 0; i < g.edge_count; i++) {
        if (g.edges[i].type == SHELL_EDGE_ENV) {
            ASSERT(g.nodes[g.edges[i].from].type == SHELL_NODE_DOC);
            ASSERT(g.nodes[g.edges[i].from].doc.kind == SHELL_DOC_ENVVAR);
            ASSERT(g.nodes[g.edges[i].to].type == SHELL_NODE_CMD);
        }
    }
    pass_count++;
}

TEST(export_cmd)
{
     shell_dep_graph_t g;
    parse("export FOO=bar", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 1);
    ASSERT(g.nodes[0].cmd.token_count >= 1);
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[0], g.nodes[0].cmd.token_lens[0], "export");
    ASSERT(count_edge_type(&g, SHELL_EDGE_ENV) == 1);
    pass_count++;
}

/* ============================================================
 * FILE ARGUMENTS
 * ============================================================ */

TEST(file_arg_with_slash)
{
     shell_dep_graph_t g;
    parse("cat /etc/passwd", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ARG) == 1);
    pass_count++;
}

TEST(file_arg_with_dot)
{
     shell_dep_graph_t g;
    parse("cat file.txt", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ARG) == 1);
    pass_count++;
}

TEST(non_file_arg_no_doc)
{
     shell_dep_graph_t g;
    parse("echo hello world", &g);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 0);
    pass_count++;
}

TEST(file_arg_undirected)
{
     shell_dep_graph_t g;
    parse("cat file.txt", &g);
    for (uint32_t i = 0; i < g.edge_count; i++) {
        if (g.edges[i].type == SHELL_EDGE_ARG) {
            ASSERT(g.edges[i].dir == SHELL_DIR_UNDIR);
        }
    }
    pass_count++;
}

TEST(file_arg_path_len)
{
     shell_dep_graph_t g;
    parse("cat /etc/passwd", &g);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_FILE &&
            g.nodes[i].doc.path != NULL) {
            ASSERT_STRN_EQ(g.nodes[i].doc.path, g.nodes[i].doc.path_len, "/etc/passwd");
        }
    }
    pass_count++;
}

/* ============================================================
 * SUBSHELLS
 * ============================================================ */

TEST(dollar_subshell)
{
     shell_dep_graph_t g;
    parse("echo $(whoami)", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) == 1);
    pass_count++;
}

TEST(backtick_subshell)
{
     shell_dep_graph_t g;
    parse("echo `whoami`", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) == 1);
    pass_count++;
}

TEST(subst_edge_direction)
{
     shell_dep_graph_t g;
    parse("echo $(whoami)", &g);
    for (uint32_t i = 0; i < g.edge_count; i++) {
        if (g.edges[i].type == SHELL_EDGE_SUBST) {
            ASSERT(g.nodes[g.edges[i].from].type == SHELL_NODE_CMD);
            ASSERT(g.nodes[g.edges[i].to].type == SHELL_NODE_CMD);
        }
    }
    pass_count++;
}

TEST(subshell_with_file)
{
     shell_dep_graph_t g;
    parse("echo $(cat /etc/hosts)", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) >= 1);
    pass_count++;
}

TEST(multiple_subshells)
{
     shell_dep_graph_t g;
    parse("echo $(date) $(whoami)", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) >= 3);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) == 2);
    pass_count++;
}

/* ============================================================
 * HEREDOCS
 * ============================================================ */

TEST(basic_heredoc)
{
     shell_dep_graph_t g;
    parse("cat <<EOF\nhello\nEOF", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_HEREDOC) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_READ) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_HEREDOC) {
            ASSERT_STRN_EQ(g.nodes[i].doc.value, g.nodes[i].doc.value_len, "hello");
            ASSERT_STRN_EQ(g.nodes[i].doc.name, g.nodes[i].doc.name_len, "EOF");
        }
    }
    pass_count++;
}

TEST(multiline_heredoc)
{
     shell_dep_graph_t g;
    parse("sort <<DELIM\nline1\nline2\nDELIM", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_HEREDOC) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_HEREDOC) {
            ASSERT(g.nodes[i].doc.value_len == 11);
            ASSERT(memcmp(g.nodes[i].doc.value, "line1\nline2", 11) == 0);
        }
    }
    pass_count++;
}

TEST(heredoc_with_pipe)
{
     shell_dep_graph_t g;
    parse("cat <<EOF | sort\nhello\nEOF", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_doc_kind(&g, SHELL_DOC_HEREDOC) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_READ) == 1);
    pass_count++;
}

TEST(heredoc_with_redirect)
{
     shell_dep_graph_t g;
    parse("cat <<EOF > out.txt\nhello\nEOF", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_HEREDOC) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
    pass_count++;
}

TEST(heredoc_read_edge_direction)
{
     shell_dep_graph_t g;
    parse("cat <<EOF\nhello\nEOF", &g);
    for (uint32_t i = 0; i < g.edge_count; i++) {
        if (g.edges[i].type == SHELL_EDGE_READ && g.nodes[g.edges[i].from].doc.kind == SHELL_DOC_HEREDOC) {
            ASSERT(g.nodes[g.edges[i].from].type == SHELL_NODE_DOC);
            ASSERT(g.nodes[g.edges[i].to].type == SHELL_NODE_CMD);
        }
    }
    pass_count++;
}

/* ============================================================
 * HERESTRINGS
 * ============================================================ */

TEST(basic_herestring)
{
     shell_dep_graph_t g;
    parse("cat <<< hello", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_HERESTRING) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_READ) == 1);
    for (uint32_t i = 0; i < g.node_count; i++) {
        if (g.nodes[i].type == SHELL_NODE_DOC && g.nodes[i].doc.kind == SHELL_DOC_HERESTRING) {
            ASSERT_STRN_EQ(g.nodes[i].doc.value, g.nodes[i].doc.value_len, "hello");
        }
    }
    pass_count++;
}

/* ============================================================
 * ERROR HANDLING
 * ============================================================ */

TEST(null_input)
{
     shell_dep_graph_t g;
    shell_dep_error_t err = shell_parse_depgraph(NULL, 0, ".", NULL, &g);
    ASSERT(err == SHELL_DEP_EINPUT);
    pass_count++;
}

TEST(null_output)
{
     shell_dep_error_t err = shell_parse_depgraph("ls", 2, ".", NULL, NULL);
    ASSERT(err == SHELL_DEP_EINPUT);
    pass_count++;
}

TEST(empty_input)
{
     shell_dep_graph_t g;
    shell_dep_error_t err = shell_parse_depgraph("", 0, ".", NULL, &g);
    ASSERT(err == SHELL_DEP_EINPUT);
    pass_count++;
}

TEST(parse_error)
{
     shell_dep_graph_t g;
    shell_dep_error_t err = shell_parse_depgraph("unclosed \"quote", 15, ".", NULL, &g);
    ASSERT(err == SHELL_DEP_EPARSE);
    pass_count++;
}

/* ============================================================
 * GRAPH INTEGRITY
 * ============================================================ */

TEST(validate_simple)
{
     shell_dep_graph_t g;
    parse("ls -la", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_pipe)
{
     shell_dep_graph_t g;
    parse("cmd1 | cmd2", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_redirect)
{
     shell_dep_graph_t g;
    parse("echo hello > out.txt", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_env_var)
{
     shell_dep_graph_t g;
    parse("FOO=bar cmd", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_subshell)
{
     shell_dep_graph_t g;
    parse("echo $(whoami)", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_heredoc)
{
     shell_dep_graph_t g;
    parse("cat <<EOF\nhello\nEOF", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

TEST(validate_complex)
{
     shell_dep_graph_t g;
    parse("cat /etc/passwd | grep root > /tmp/result.txt", &g);
    shell_dep_validate_result_t vr = shell_dep_validate(&g);
    ASSERT(vr.valid);
    pass_count++;
}

/* ============================================================
 * COMPLEX COMMANDS
 * ============================================================ */

TEST(complex_pipeline)
{
     shell_dep_graph_t g;
    parse("cat /etc/passwd | grep root > /tmp/result.txt", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) >= 2);
    pass_count++;
}

TEST(full_workflow)
{
     shell_dep_graph_t g;
    parse("FOO=bar cat file.txt | sort > out.txt", &g);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ENV) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
    pass_count++;
}

TEST(graph_dump_no_crash)
{
     shell_dep_graph_t g;
    parse("FOO=bar cat file.txt | sort > out.txt", &g);
    shell_dep_graph_dump(&g, stderr);
    pass_count++;
}

TEST(name_helpers)
{
     ASSERT(strcmp(shell_dep_edge_type_name(SHELL_EDGE_PIPE), "PIPE") == 0);
    ASSERT(strcmp(shell_dep_node_type_name(SHELL_NODE_CMD), "CMD") == 0);
    ASSERT(strcmp(shell_dep_doc_kind_name(SHELL_DOC_FILE), "FILE") == 0);
    ASSERT(strcmp(shell_dep_edge_type_name((shell_dep_edge_type_t)99), "UNKNOWN") == 0);
    pass_count++;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = true;

    printf("Running depgraph tests...\n\n");

    printf("Basic Commands:\n");
    int prev;
    prev = fail_count; RUN(simple_command);
    prev = fail_count; RUN(command_with_args);
    prev = fail_count; RUN(quoted_args);
    prev = fail_count; RUN(single_word_command);
    prev = fail_count; RUN(whitespace_only);
    prev = fail_count; RUN(token_zero_copy);

    printf("\nOperators:\n");
    prev = fail_count; RUN(pipe);
    prev = fail_count; RUN(pipe_direction);
    prev = fail_count; RUN(and);
    prev = fail_count; RUN(or);
    prev = fail_count; RUN(semicolon);
    prev = fail_count; RUN(mixed_operators);
    prev = fail_count; RUN(three_stage_pipe);

    printf("\nRedirects:\n");
    prev = fail_count; RUN(redirect_out);
    prev = fail_count; RUN(redirect_in);
    prev = fail_count; RUN(redirect_append);
    prev = fail_count; RUN(redirect_stderr);
    prev = fail_count; RUN(redirect_stderr_append);
    prev = fail_count; RUN(multiple_redirects);
    prev = fail_count; RUN(redirect_write_direction);
    prev = fail_count; RUN(redirect_file_path_len);

    printf("\nCWD Tracking:\n");
    prev = fail_count; RUN(cd_relative);
    prev = fail_count; RUN(cd_absolute);
    prev = fail_count; RUN(cd_no_args);
    prev = fail_count; RUN(cd_dotdot_normalization);
    prev = fail_count; RUN(cd_default_cwd);

    printf("\nEnvironment Variables:\n");
    prev = fail_count; RUN(single_env_var);
    prev = fail_count; RUN(multiple_env_vars);
    prev = fail_count; RUN(env_var_empty_value);
    prev = fail_count; RUN(env_var_with_path_value);
    prev = fail_count; RUN(env_var_edge_direction);
    prev = fail_count; RUN(export_cmd);

    printf("\nFile Arguments:\n");
    prev = fail_count; RUN(file_arg_with_slash);
    prev = fail_count; RUN(file_arg_with_dot);
    prev = fail_count; RUN(non_file_arg_no_doc);
    prev = fail_count; RUN(file_arg_undirected);
    prev = fail_count; RUN(file_arg_path_len);

    printf("\nSubshells:\n");
    prev = fail_count; RUN(dollar_subshell);
    prev = fail_count; RUN(backtick_subshell);
    prev = fail_count; RUN(subst_edge_direction);
    prev = fail_count; RUN(subshell_with_file);
    prev = fail_count; RUN(multiple_subshells);

    printf("\nHeredocs:\n");
    prev = fail_count; RUN(basic_heredoc);
    prev = fail_count; RUN(multiline_heredoc);
    prev = fail_count; RUN(heredoc_with_pipe);
    prev = fail_count; RUN(heredoc_with_redirect);
    prev = fail_count; RUN(heredoc_read_edge_direction);

    printf("\nHerestrings:\n");
    prev = fail_count; RUN(basic_herestring);

    printf("\nError Handling:\n");
    prev = fail_count; RUN(null_input);
    prev = fail_count; RUN(null_output);
    prev = fail_count; RUN(empty_input);
    prev = fail_count; RUN(parse_error);

    printf("\nGraph Integrity:\n");
    prev = fail_count; RUN(validate_simple);
    prev = fail_count; RUN(validate_pipe);
    prev = fail_count; RUN(validate_redirect);
    prev = fail_count; RUN(validate_env_var);
    prev = fail_count; RUN(validate_subshell);
    prev = fail_count; RUN(validate_heredoc);
    prev = fail_count; RUN(validate_complex);

    printf("\nComplex:\n");
    prev = fail_count; RUN(complex_pipeline);
    prev = fail_count; RUN(full_workflow);
    prev = fail_count; RUN(graph_dump_no_crash);
    prev = fail_count; RUN(name_helpers);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
