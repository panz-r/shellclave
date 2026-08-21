#include "depgraph_invariants.h"
#include "shell_depgraph.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass_count = 0;
static int fail_count = 0;
static bool verbose = false;

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("    FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__);            \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STR_EQ(a, b)                                                    \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("    FAIL: expected '%s', got '%s' at %s:%d\n", (b), (a),         \
             __FILE__, __LINE__);                                              \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STRN_EQ(s, slen, expected)                                      \
  do {                                                                         \
    const char *_e = (expected);                                               \
    uint32_t _elen = (uint32_t)strlen(_e);                                     \
    if ((slen) != _elen || memcmp((s), _e, _elen) != 0) {                      \
      printf(                                                                  \
          "    FAIL: expected '%s' (len %u), got '%.*s' (len %u) at %s:%d\n",  \
          _e, _elen, (slen), (s), (slen), __FILE__, __LINE__);                 \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %s ... ", #name);                                                \
    int _previous_fail_count = fail_count;                                     \
    test_##name();                                                             \
    if (fail_count == _previous_fail_count) {                                  \
      printf("PASS\n");                                                        \
    }                                                                          \
  } while (0)

/* --- HELPERS --- */

static uint32_t count_type(const shell_dep_graph_t *g,
                           shell_dep_node_type_t type) {
  uint32_t c = 0;
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == type)
      c++;
  return c;
}

static uint32_t count_edge_type(const shell_dep_graph_t *g,
                                shell_dep_edge_type_t type) {
  uint32_t c = 0;
  for (uint32_t i = 0; i < g->edge_count; i++)
    if (g->edges[i].type == type)
      c++;
  return c;
}

static uint32_t count_doc_kind(const shell_dep_graph_t *g,
                               shell_dep_doc_kind_t kind) {
  uint32_t c = 0;
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_DOC && g->nodes[i].doc.kind == kind)
      c++;
  return c;
}

static int find_first_cmd(const shell_dep_graph_t *g) {
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_CMD)
      return (int)i;
  return -1;
}

static int find_nth_cmd(const shell_dep_graph_t *g, uint32_t ordinal) {
  for (uint32_t i = 0; i < g->node_count; i++) {
    if (g->nodes[i].type != SHELL_NODE_CMD)
      continue;
    if (ordinal-- == 0)
      return (int)i;
  }
  return -1;
}

static shell_dep_error_t parse(const char *cmd, shell_dep_graph_t *g) {
  memset(g, 0, sizeof(*g));
  return shell_parse_depgraph(cmd, strlen(cmd), ".", NULL, 0, g);
}

static shell_dep_error_t parse_cwd(const char *cmd, const char *cwd,
                                   shell_dep_graph_t *g) {
  memset(g, 0, sizeof(*g));
  return shell_parse_depgraph(cmd, strlen(cmd), cwd, NULL, 0, g);
}

static const char *get_cwd_str(const shell_dep_graph_t *g,
                               uint32_t cwd_offset) {
  if (cwd_offset >= g->cwd_buf.len)
    return ".";
  return g->cwd_buf.data + cwd_offset;
}

/* --- BASIC COMMANDS --- */

TEST(basic_command_matrix) {
  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t token_count;
    uint32_t edge_count;
    const char *first_token;
    const char *last_token;
  } cases[] = {
      {"ls -la", 1, 2, 0, "ls", "-la"},
      {"gcc -Wall -Wextra -o myapp main.c", 1, 6, 1, "gcc", "main.c"},
      {"echo 'hello world' \"foo bar\"", 1, 3, 0, "echo", "\"foo bar\""},
      {"ls", 1, 1, 0, "ls", "ls"},
      {"   ", 0, 0, 0, NULL, NULL},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(g.edge_count == cases[i].edge_count);
    if (cases[i].command_count == 0)
      continue;
    ASSERT(g.nodes[0].type == SHELL_NODE_CMD);
    ASSERT(g.nodes[0].cmd.token_count == cases[i].token_count);
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[0], g.nodes[0].cmd.token_lens[0],
                   cases[i].first_token);
    uint32_t last = g.nodes[0].cmd.token_count - 1;
    ASSERT_STRN_EQ(g.nodes[0].cmd.tokens[last], g.nodes[0].cmd.token_lens[last],
                   cases[i].last_token);
  }
  pass_count++;
}

TEST(token_zero_copy) {
  const char *cmd = "echo hello";
  shell_dep_graph_t g;
  parse(cmd, &g);
  ASSERT(g.nodes[0].cmd.tokens[0] >= cmd);
  ASSERT(g.nodes[0].cmd.tokens[0] < cmd + strlen(cmd));
  pass_count++;
}

/* --- OPERATORS --- */

TEST(operator_matrix) {
  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t pipe_count;
    uint32_t and_count;
    uint32_t or_count;
    uint32_t sequence_count;
  } cases[] = {
      {"cat file.txt | grep x", 2, 1, 0, 0, 0},
      {"cmd1 && cmd2", 2, 0, 1, 0, 0},
      {"cmd1 || cmd2", 2, 0, 0, 1, 0},
      {"cmd1 ; cmd2", 2, 0, 0, 0, 1},
      {"cmd1 && cmd2 || cmd3", 3, 0, 1, 1, 0},
      {"cat file | sort | uniq", 3, 2, 0, 0, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == cases[i].pipe_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == cases[i].and_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_OR) == cases[i].or_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SEQ) == cases[i].sequence_count);
    for (uint32_t j = 0; j < g.edge_count; j++) {
      shell_dep_edge_type_t type = g.edges[j].type;
      if (type == SHELL_EDGE_PIPE || type == SHELL_EDGE_AND ||
          type == SHELL_EDGE_OR || type == SHELL_EDGE_SEQ) {
        ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_CMD);
        ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
      }
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

/* --- REDIRECTS --- */

TEST(redirect_matrix) {
  static const struct {
    const char *command;
    shell_dep_edge_type_t edge_type;
    uint32_t file_count;
    uint32_t edge_count;
    uint32_t command_tokens;
    const char *expected_path;
  } cases[] = {
      {"echo hello > out.txt", SHELL_EDGE_WRITE, 1, 1, 2, "out.txt"},
      {"sort < input.txt", SHELL_EDGE_READ, 1, 1, 1, "input.txt"},
      {"echo hello >> out.txt", SHELL_EDGE_APPEND, 1, 1, 2, "out.txt"},
      {"cmd 2> err.log", SHELL_EDGE_WRITE, 1, 1, 1, "err.log"},
      {"cmd 2>> err.log", SHELL_EDGE_APPEND, 1, 1, 1, "err.log"},
      {"cmd 12>> audit.log", SHELL_EDGE_APPEND, 1, 1, 1, "audit.log"},
      {"cmd 2>&1 3>&- <&0 4<&-", SHELL_EDGE_WRITE, 0, 0, 1, NULL},
      {"cmd > out.txt 2> err.log", SHELL_EDGE_WRITE, 2, 2, 1, NULL},
      {"cmd > /tmp/output.txt", SHELL_EDGE_WRITE, 1, 1, 1, "/tmp/output.txt"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    int command_index = find_first_cmd(&g);
    ASSERT(command_index >= 0);
    ASSERT(g.nodes[command_index].cmd.token_count == cases[i].command_tokens);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == cases[i].file_count);
    ASSERT(count_edge_type(&g, cases[i].edge_type) == cases[i].edge_count);

    bool found_path = cases[i].expected_path == NULL;
    for (uint32_t j = 0; j < g.node_count; j++) {
      if (g.nodes[j].type == SHELL_NODE_DOC &&
          g.nodes[j].doc.kind == SHELL_DOC_FILE && cases[i].expected_path &&
          g.nodes[j].doc.path_len == strlen(cases[i].expected_path) &&
          memcmp(g.nodes[j].doc.path, cases[i].expected_path,
                 g.nodes[j].doc.path_len) == 0)
        found_path = true;
    }
    ASSERT(found_path);

    for (uint32_t j = 0; j < g.edge_count; j++) {
      if (g.edges[j].type != cases[i].edge_type)
        continue;
      if (cases[i].edge_type == SHELL_EDGE_READ) {
        ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_DOC);
        ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
      } else {
        ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_CMD);
        ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_DOC);
      }
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

/* --- CWD TRACKING --- */

TEST(cwd_matrix) {
  static const struct {
    const char *command;
    const char *initial_cwd;
    const char *expected_cwd;
  } cases[] = {
      {"cd ../foo && ls", "/home/user", "/home/foo"},
      {"cd /tmp && ls", "/home/user", "/tmp"},
      {"cd && ls", "/home/user", "$HOME"},
      {"cd .. && pwd", "/home/user/docs", "/home/user"},
      {"cd ./foo && ls", "/home/user", "/home/user/foo"},
      {"cd foo//bar && ls", "/home/user", "/home/user/foo/bar"},
      {"cd ../../foo && ls", "/home/user", "/foo"},
      {"cd /tmp//nested/../final && ls", "/home/user", "/tmp/final"},
      {"ls", ".", "."},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse_cwd(cases[i].command, cases[i].initial_cwd, &g) ==
           SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    int command_index = find_first_cmd(&g);
    ASSERT(command_index >= 0);
    ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[command_index].cmd.cwd_offset),
                  cases[i].expected_cwd);
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

TEST(composition_metadata_matrix) {
  static const struct {
    const char *command;
    uint32_t commands;
    shell_dep_edge_type_t edge;
    bool first_background;
    uint16_t first_group_depth;
  } cases[] = {
      {"echo one & echo two", 2, SHELL_EDGE_BACKGROUND, true, 0},
      {"(echo one; echo two)", 2, SHELL_EDGE_GROUP, false, 1},
      {"(echo one; echo two); echo three", 3, SHELL_EDGE_SEQ, false, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].commands);
    if (count_edge_type(&g, cases[i].edge) < 1) {
      printf("    case %zu missing edge %s (nodes=%u edges=%u)\n", i,
             shell_dep_edge_type_name(cases[i].edge), g.node_count,
             g.edge_count);
      shell_dep_graph_dump(&g, stdout);
      fail_count++;
      return;
    }
    int first = find_first_cmd(&g);
    ASSERT(first >= 0);
    ASSERT(g.nodes[first].cmd.backgrounded == cases[i].first_background);
    ASSERT(g.nodes[first].cmd.group_depth == cases[i].first_group_depth);
    ASSERT(shell_dep_validate(&g).valid);
  }

  shell_dep_graph_t g;
  shell_dep_limits_t cwd_limits = SHELL_DEP_LIMITS_DEFAULT;
  cwd_limits.cd_as_cmd = true;
  memset(&g, 0, sizeof(g));
  ASSERT(shell_parse_depgraph("cd /tmp | pwd", strlen("cd /tmp | pwd"), ".",
                              &cwd_limits, 0, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                ".");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_parse_depgraph("cd /tmp & pwd", strlen("cd /tmp & pwd"), ".",
                              &cwd_limits, 0, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                ".");
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.backgrounded);
  ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_known);
  memset(&g, 0, sizeof(g));
  ASSERT(shell_parse_depgraph("cd /tmp; pwd", strlen("cd /tmp; pwd"), ".",
                              &cwd_limits, 0, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_parse_depgraph("(cd /tmp; pwd); pwd",
                              strlen("(cd /tmp; pwd); pwd"), ".", &cwd_limits,
                              0, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 2)].cmd.cwd_offset),
                ".");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_parse_depgraph("cd /tmp && pwd; pwd",
                              strlen("cd /tmp && pwd; pwd"), ".", &cwd_limits,
                              0, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(!g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_known);
  pass_count++;
}

TEST(comment_matrix) {
  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t file_count;
  } cases[] = {
      {"echo # | rm", 1, 0},
      {"echo # /etc/passwd\npwd", 2, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == cases[i].file_count);
    ASSERT(shell_dep_validate(&graph).valid);
  }
  pass_count++;
}

/* --- ENVIRONMENT VARIABLES --- */

TEST(environment_matrix) {
  static const struct {
    const char *command;
    uint32_t environment_count;
    const char *names[2];
    const char *values[2];
    const char *command_name;
  } cases[] = {
      {"FOO=bar cmd", 1, {"FOO", NULL}, {"bar", NULL}, NULL},
      {"FOO=bar BAZ=qux cmd arg", 2, {"FOO", "BAZ"}, {"bar", "qux"}, NULL},
      {"FOO= cmd", 1, {"FOO", NULL}, {"", NULL}, NULL},
      {"PATH=/usr/bin ls", 1, {"PATH", NULL}, {"/usr/bin", NULL}, NULL},
      {"export FOO=bar", 1, {"FOO", NULL}, {"bar", NULL}, "export"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_ENVVAR) == cases[i].environment_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ENV) == cases[i].environment_count);

    for (uint32_t expected = 0; expected < cases[i].environment_count;
         expected++) {
      bool found = false;
      for (uint32_t j = 0; j < g.node_count; j++) {
        if (g.nodes[j].type != SHELL_NODE_DOC ||
            g.nodes[j].doc.kind != SHELL_DOC_ENVVAR)
          continue;
        if (g.nodes[j].doc.name_len == strlen(cases[i].names[expected]) &&
            memcmp(g.nodes[j].doc.name, cases[i].names[expected],
                   g.nodes[j].doc.name_len) == 0 &&
            g.nodes[j].doc.value_len == strlen(cases[i].values[expected]) &&
            memcmp(g.nodes[j].doc.value, cases[i].values[expected],
                   g.nodes[j].doc.value_len) == 0)
          found = true;
      }
      ASSERT(found);
    }

    for (uint32_t j = 0; j < g.edge_count; j++) {
      if (g.edges[j].type != SHELL_EDGE_ENV)
        continue;
      ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_DOC);
      ASSERT(g.nodes[g.edges[j].from].doc.kind == SHELL_DOC_ENVVAR);
      ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
    }
    if (cases[i].command_name) {
      int command_index = find_first_cmd(&g);
      ASSERT(command_index >= 0);
      ASSERT_STRN_EQ(g.nodes[command_index].cmd.tokens[0],
                     g.nodes[command_index].cmd.token_lens[0],
                     cases[i].command_name);
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

/* --- FILE ARGUMENTS --- */

TEST(file_argument_matrix) {
  static const struct {
    const char *command;
    uint32_t file_count;
    uint32_t argument_edge_count;
    const char *expected_path;
  } cases[] = {
      {"cat /etc/passwd", 1, 1, "/etc/passwd"},
      {"cat file.txt", 1, 1, "file.txt"},
      {"echo hello world", 0, 0, NULL},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == cases[i].file_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_ARG) == cases[i].argument_edge_count);
    bool found_path = cases[i].expected_path == NULL;
    for (uint32_t j = 0; j < g.node_count; j++) {
      if (g.nodes[j].type == SHELL_NODE_DOC &&
          g.nodes[j].doc.kind == SHELL_DOC_FILE && cases[i].expected_path &&
          g.nodes[j].doc.path_len == strlen(cases[i].expected_path) &&
          memcmp(g.nodes[j].doc.path, cases[i].expected_path,
                 g.nodes[j].doc.path_len) == 0)
        found_path = true;
    }
    ASSERT(found_path);
    for (uint32_t j = 0; j < g.edge_count; j++) {
      if (g.edges[j].type == SHELL_EDGE_ARG)
        ASSERT(g.edges[j].dir == SHELL_DIR_UNDIR);
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

/* --- SUBSHELLS --- */

TEST(subshell_matrix) {
  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t substitution_count;
    uint32_t file_count;
  } cases[] = {
      {"echo $(whoami)", 2, 1, 0},
      {"echo `whoami`", 2, 1, 0},
      {"echo \"$(cat /etc/shadow)\"", 2, 1, 1},
      {"echo \\$(whoami)", 1, 0, 0},
      {"echo panz", 1, 0, 0},
      {"echo $(cat /etc/hosts)", 2, 1, 1},
      {"echo $(date) $(whoami)", 3, 2, 0},
      {"cat <(whoami)", 2, 1, 0},
      {"echo \"'$(id)", 2, 1, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) ==
           cases[i].substitution_count);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == cases[i].file_count);
    for (uint32_t j = 0; j < g.edge_count; j++) {
      if (g.edges[j].type != SHELL_EDGE_SUBST)
        continue;
      ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_CMD);
      ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

TEST(nested_composition_matrix) {
  static const struct {
    const char *name;
    const char *command;
    const char *commands[5];
    int32_t parents[5];
    uint32_t command_count;
    uint32_t pipe_count;
    uint32_t read_count;
  } cases[] = {
      {"nested command substitution",
       "echo $(printf x $(whoami))",
       {"echo", "printf", "whoami"},
       {-1, 0, 1},
       3,
       0,
       0},
      {"sibling command substitutions",
       "echo $(id) $(pwd)",
       {"echo", "id", "pwd"},
       {-1, 0, 0},
       3,
       0,
       0},
      {"adjacent command substitutions",
       "echo $(id)$(pwd)",
       {"echo", "id", "pwd"},
       {-1, 0, 0},
       3,
       0,
       0},
      {"embedded adjacent substitutions",
       "echo prefix$(id)suffix$(pwd)",
       {"echo", "id", "pwd"},
       {-1, 0, 0},
       3,
       0,
       0},
      {"mixed substitution forms",
       "echo $(id)`pwd`",
       {"echo", "id", "pwd"},
       {-1, 0, 0},
       3,
       0,
       0},
      {"substitution inside arithmetic",
       "echo $(( $(id) + 1 ))",
       {"echo", "id"},
       {-1, 0},
       2,
       0,
       0},
      {"escaped closing parenthesis",
       "echo $(printf \\))",
       {"echo", "printf"},
       {-1, 0},
       2,
       0,
       0},
      {"quoted closing parenthesis",
       "echo $(printf ')')",
       {"echo", "printf"},
       {-1, 0},
       2,
       0,
       0},
      {"escaped closing backtick",
       "echo `printf \\``",
       {"echo", "printf"},
       {-1, 0},
       2,
       0,
       0},
      {"adjacent substitutions in double quotes",
       "echo \"$(id)$(pwd)\"",
       {"echo", "id", "pwd"},
       {-1, 0, 0},
       3,
       0,
       0},
      {"odd escaped substitution delimiter",
       "echo \\$(id)",
       {"echo"},
       {-1},
       1,
       0,
       0},
      {"even escaped substitution delimiter",
       "echo \\\\$(id)",
       {"echo", "id"},
       {-1, 0},
       2,
       0,
       0},
      {"quoted process substitution",
       "cat <(printf '%s' '(x)') | sort",
       {"cat", "printf", "sort"},
       {-1, 0, -1},
       3,
       1,
       0},
      {"odd escaped process close",
       "cat <(printf \\))",
       {"cat", "printf"},
       {-1, 0},
       2,
       0,
       0},
      {"even escaped process close",
       "cat <(printf \\\\)",
       {"cat", "printf"},
       {-1, 0},
       2,
       0,
       0},
      {"nested process substitution",
       "cat <(sort <(cat /tmp/a))",
       {"cat", "sort", "cat"},
       {-1, 0, 1},
       3,
       0,
       0},
      {"pipeline inside substitution",
       "echo $(cat /tmp/a | sort)",
       {"echo", "cat", "sort"},
       {-1, 0, 0},
       3,
       1,
       0},
      {"redirect inside substitution",
       "echo $(sort < /tmp/a)",
       {"echo", "sort"},
       {-1, 0},
       2,
       0,
       1},
  };

  for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(cases[ci].command, &graph);
    ASSERT(error == SHELL_DEP_OK);
    bool valid = shellsplit_test_depgraph_invariants(
        cases[ci].command, strlen(cases[ci].command), error, &graph,
        &SHELL_DEP_LIMITS_DEFAULT);
    if (!valid) {
      printf("    invariant failure: %s\n", cases[ci].name);
      shell_dep_graph_dump(&graph, stdout);
    }
    ASSERT(valid);
    uint32_t actual_commands = count_type(&graph, SHELL_NODE_CMD);
    if (actual_commands != cases[ci].command_count) {
      printf("    %s: got %u commands, expected %u\n", cases[ci].name,
             actual_commands, cases[ci].command_count);
      shell_dep_graph_dump(&graph, stdout);
    }
    ASSERT(actual_commands == cases[ci].command_count);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == cases[ci].pipe_count);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == cases[ci].read_count);

    uint32_t command_nodes[5];
    uint32_t command_count = 0;
    for (uint32_t i = 0; i < graph.node_count; i++)
      if (graph.nodes[i].type == SHELL_NODE_CMD)
        command_nodes[command_count++] = i;
    ASSERT(command_count == cases[ci].command_count);

    for (uint32_t i = 0; i < command_count; i++) {
      const shell_dep_cmd_t *command = &graph.nodes[command_nodes[i]].cmd;
      ASSERT(command->token_count > 0);
      ASSERT_STRN_EQ(command->tokens[0], command->token_lens[0],
                     cases[ci].commands[i]);
      int32_t parent = -1;
      for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
        if (graph.edges[edge].type != SHELL_EDGE_SUBST ||
            graph.edges[edge].from != command_nodes[i])
          continue;
        ASSERT(parent == -1);
        for (uint32_t candidate = 0; candidate < command_count; candidate++)
          if (command_nodes[candidate] == graph.edges[edge].to)
            parent = (int32_t)candidate;
      }
      if (parent != cases[ci].parents[i])
        printf("    %s command %u: parent %d, expected %d\n", cases[ci].name, i,
               parent, cases[ci].parents[i]);
      ASSERT(parent == cases[ci].parents[i]);
    }
  }
  pass_count++;
}

/* --- HEREDOCS AND HERESTRINGS --- */

TEST(inline_document_matrix) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t document_kind;
    uint32_t command_count;
    uint32_t file_count;
    uint32_t pipe_count;
    uint32_t write_count;
    const char *delimiter;
    const char *value;
  } cases[] = {
      {"cat <<EOF\nhello\nEOF", SHELL_DOC_HEREDOC, 1, 0, 0, 0, "EOF", "hello"},
      {"sort <<DELIM\nline1\nline2\nDELIM", SHELL_DOC_HEREDOC, 1, 0, 0, 0,
       "DELIM", "line1\nline2"},
      {"cat <<EOF | sort\nhello\nEOF", SHELL_DOC_HEREDOC, 2, 0, 1, 0, "EOF",
       "hello"},
      {"cat <<EOF\n$(id)\nEOF", SHELL_DOC_HEREDOC, 1, 0, 0, 0, "EOF", "$(id)"},
      {"cat <<EOF\nbody\nEOF && pwd", SHELL_DOC_HEREDOC, 2, 0, 0, 0, "EOF",
       "body"},
      {"cat <<EOF > out.txt\nhello\nEOF", SHELL_DOC_HEREDOC, 1, 1, 0, 1, "EOF",
       "hello"},
      {"cat <<-'EOF'\n\tsecret\n\tEOF", SHELL_DOC_HEREDOC, 1, 0, 0, 0, "EOF",
       "secret"},
      {"cat <<< hello", SHELL_DOC_HERESTRING, 1, 0, 0, 0, NULL, "hello"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(count_doc_kind(&g, cases[i].document_kind) == 1);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == cases[i].file_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_READ) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == cases[i].pipe_count);
    ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == cases[i].write_count);

    bool found_document = false;
    for (uint32_t j = 0; j < g.node_count; j++) {
      if (g.nodes[j].type != SHELL_NODE_DOC ||
          g.nodes[j].doc.kind != cases[i].document_kind)
        continue;
      found_document = true;
      ASSERT_STRN_EQ(g.nodes[j].doc.value, g.nodes[j].doc.value_len,
                     cases[i].value);
      if (cases[i].delimiter)
        ASSERT_STRN_EQ(g.nodes[j].doc.name, g.nodes[j].doc.name_len,
                       cases[i].delimiter);
    }
    ASSERT(found_document);
    for (uint32_t j = 0; j < g.edge_count; j++) {
      if (g.edges[j].type != SHELL_EDGE_READ)
        continue;
      ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_DOC);
      ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
    }
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

/* --- ERROR HANDLING --- */

TEST(null_input) {
  shell_dep_graph_t g;
  memset(&g, 0xA5, sizeof(g));
  shell_dep_error_t err = shell_parse_depgraph(NULL, 0, ".", NULL, 0, &g);
  ASSERT(err == SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 && g.cwd_buf.len == 0);
  ASSERT(g.status == SHELL_DEP_STATUS_ERROR);
  pass_count++;
}

TEST(null_output) {
  shell_dep_error_t err = shell_parse_depgraph("ls", 2, ".", NULL, 0, NULL);
  ASSERT(err == SHELL_DEP_EINPUT);
  pass_count++;
}

TEST(empty_input) {
  shell_dep_graph_t g;
  memset(&g, 0xA5, sizeof(g));
  shell_dep_error_t err = shell_parse_depgraph("", 0, ".", NULL, 0, &g);
  ASSERT(err == SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 && g.cwd_buf.len == 0);
  ASSERT(g.status == SHELL_DEP_STATUS_ERROR);
  pass_count++;
}

TEST(adversarial_limits) {
  shell_dep_graph_t g;
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cwd_buf_size = 1;
  memset(&g, 0xA5, sizeof(g));
  ASSERT(shell_parse_depgraph("x", 1, ".", &limits, 0, &g) == SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 &&
         g.status == SHELL_DEP_STATUS_ERROR && g.cwd_buf.len == 0);
#if SIZE_MAX > UINT32_MAX
  memset(&g, 0xA5, sizeof(g));
  ASSERT(shell_parse_depgraph("x", (size_t)UINT32_MAX + 1, ".", NULL, 0, &g) ==
         SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 &&
         g.status == SHELL_DEP_STATUS_ERROR && g.cwd_buf.len == 0);
#endif
  pass_count++;
}

TEST(parse_error) {
  shell_dep_graph_t g;
  // Depgraph is permissive by design - unclosed quotes are allowed.
  // shell_parse_fast with strict_mode=true rejects them, but depgraph
  // uses default permissive limits. This test documents the permissive
  // behavior.
  shell_dep_error_t err =
      shell_parse_depgraph("unclosed \"quote", 15, ".", NULL, 0, &g);
  ASSERT(err == SHELL_DEP_OK); // permissive, not EPARSE
  const char invalid[] = "\x80";
  ASSERT(shell_parse_depgraph(invalid, sizeof(invalid) - 1, ".", NULL, 0, &g) ==
         SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(dialect_boundary_matrix) {
  static const char *cases[] = {
      "{ echo hi; }",
      "foo() { echo hi; }",
      "case value in x) echo x ;; esac",
      "for ((i=0; i<2; i++)); do echo $i; done",
      "cmd &>file",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(cases[i], &graph);
    ASSERT(error == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  }

  /* Reserved words are only structural at command position.  Keeping them
   * as ordinary arguments prevents the boundary guard from rejecting valid
   * literal data merely because it contains a keyword spelling. */
  static const char *literal_cases[] = {
      "echo function", "echo case", "echo esac", "echo for",
      "echo in",       "echo {",    "echo }"};
  for (size_t i = 0; i < sizeof(literal_cases) / sizeof(literal_cases[0]);
       i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(literal_cases[i], &graph);
    ASSERT(error == SHELL_DEP_OK);
    ASSERT(graph.status == SHELL_DEP_STATUS_OK);
    ASSERT(graph.node_count == 1);
  }
  pass_count++;
}

TEST(nested_parse_error_matrix) {
  static const char *cases[] = {
      "echo $(case value in x)",
      "cat <(for ((i=0; i<1; i++)); do echo x; done)",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(cases[i], &graph);
    ASSERT(error == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  }
  pass_count++;
}

TEST(limit_matrix) {
  static const struct {
    const char *command;
    shell_dep_limits_t limits;
    uint32_t depth;
    shell_dep_error_t error;
    uint32_t node_count;
    uint32_t edge_count;
    uint32_t command_tokens;
  } cases[] = {
      {"cmd1 ; cmd2", {1, 8, 8, 0, false}, 0, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo hi > out.txt", {8, 0, 8, 0, false}, 0, SHELL_DEP_ETRUNC, 1, 0, 2},
      {"echo hello", {8, 8, 1, 0, false}, 0, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"cd /tmp && ls", {8, 8, 8, 4, false}, 0, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo $(cat /etc/hosts)",
       {2, 8, 8, 0, false},
       0,
       SHELL_DEP_ETRUNC,
       1,
       0,
       2},
      {"c 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 "
       "24 25 26 27 28 29 30 31 32 33",
       {64, 64, SHELL_DEP_MAX_TOKENS, 0, false},
       0,
       SHELL_DEP_ETRUNC,
       1,
       0,
       SHELL_DEP_MAX_TOKENS},
      {"echo hello",
       {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, false},
       0,
       SHELL_DEP_OK,
       1,
       0,
       2},
      {"echo hello", {8, 8, 8, 0, false}, 17, SHELL_DEP_EPARSE, 0, 0, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    memset(&g, 0, sizeof(g));
    shell_dep_error_t error =
        shell_parse_depgraph(cases[i].command, strlen(cases[i].command), ".",
                             &cases[i].limits, cases[i].depth, &g);
    if (error != cases[i].error)
      printf("    limit case %zu: got %s, expected %s\n", i,
             shell_dep_error_string(error),
             shell_dep_error_string(cases[i].error));
    ASSERT(error == cases[i].error);
    ASSERT(g.node_count == cases[i].node_count);
    ASSERT(g.edge_count == cases[i].edge_count);
    if (error == SHELL_DEP_ETRUNC)
      ASSERT(g.status & SHELL_DEP_STATUS_TRUNCATED);
    if (error == SHELL_DEP_EPARSE)
      ASSERT(g.status == SHELL_DEP_STATUS_ERROR);
    if (cases[i].node_count > 0 && g.nodes[0].type == SHELL_NODE_CMD)
      ASSERT(g.nodes[0].cmd.token_count == cases[i].command_tokens);
    ASSERT(shell_dep_validate(&g).valid);
  }

  shell_dep_limits_t cd_limits = SHELL_DEP_LIMITS_DEFAULT;
  cd_limits.cd_as_cmd = true;
  shell_dep_graph_t g;
  ASSERT(shell_parse_depgraph("cd /tmp && pwd", 14, "/home/user", &cd_limits, 0,
                              &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT(count_edge_type(&g, SHELL_EDGE_CWD) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_ARG) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == 1);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[2].cmd.cwd_offset), "/tmp");
  ASSERT(shell_dep_validate(&g).valid);
  pass_count++;
}

TEST(nested_limit_cross_product) {
  static const char command[] =
      "echo $(cat /tmp/a | sort) && cat <(printf x) | wc";
  static const struct {
    uint32_t nodes;
    uint32_t edges;
    uint32_t tokens;
    uint32_t cwd;
    shell_dep_error_t expected;
  } bounds[] = {
      {1, 0, 1, 2, SHELL_DEP_ETRUNC},
      {2, 1, 2, 4, SHELL_DEP_ETRUNC},
      {4, 3, 4, 8, SHELL_DEP_ETRUNC},
      {8, 8, 8, 32, SHELL_DEP_OK},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE, SHELL_DEP_OK},
  };

  for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); i++) {
    shell_dep_limits_t limits = {bounds[i].nodes, bounds[i].edges,
                                 bounds[i].tokens, bounds[i].cwd, false};
    shell_dep_graph_t graph;
    shell_dep_error_t error =
        shell_parse_depgraph(command, strlen(command), ".", &limits, 0, &graph);
    if (error != bounds[i].expected)
      printf("    nested limit row %zu: got %s, expected %s\n", i,
             shell_dep_error_string(error),
             shell_dep_error_string(bounds[i].expected));
    ASSERT(error == bounds[i].expected);
    ASSERT(shellsplit_test_depgraph_invariants(command, strlen(command), error,
                                               &graph, &limits));
  }

  for (uint32_t depth = 15; depth <= 17; depth++) {
    static const char nested[] = "echo $(echo $(id))";
    shell_dep_graph_t graph;
    shell_dep_error_t error = shell_parse_depgraph(
        nested, strlen(nested), ".", &SHELL_DEP_LIMITS_DEFAULT, depth, &graph);
    ASSERT(error == SHELL_DEP_EPARSE);
    ASSERT(shellsplit_test_depgraph_invariants(
        nested, strlen(nested), error, &graph, &SHELL_DEP_LIMITS_DEFAULT));
  }
  pass_count++;
}

/* --- GRAPH INTEGRITY --- */

TEST(validation_matrix) {
  static const char *valid_commands[] = {
      "ls -la",
      "cmd1 | cmd2",
      "echo hello > out.txt",
      "FOO=bar cmd",
      "echo $(whoami)",
      "cat <<EOF\nhello\nEOF",
      "cat /etc/passwd | grep root > /tmp/result.txt",
  };

  for (size_t i = 0; i < sizeof(valid_commands) / sizeof(valid_commands[0]);
       i++) {
    shell_dep_graph_t g;
    ASSERT(parse(valid_commands[i], &g) == SHELL_DEP_OK);
    shell_dep_validate_result_t validation = shell_dep_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }

  shell_dep_graph_t g;
  ASSERT(parse("cmd1 | cmd2", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count > 0);
  g.edges[0].to = g.node_count;
  shell_dep_validate_result_t validation = shell_dep_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(validation.errors[0].edge_idx == 0);
  ASSERT(strstr(validation.errors[0].msg, "OOB") != NULL);

  ASSERT(parse("echo hello > out.txt", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count > 0);
  g.edges[0].type = SHELL_EDGE_READ;
  validation = shell_dep_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("ls", &g) == SHELL_DEP_OK);
  int command_index = find_first_cmd(&g);
  ASSERT(command_index >= 0);
  g.nodes[command_index].cmd.cwd_offset = (uint32_t)g.cwd_buf.len;
  validation = shell_dep_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "cwd_offset") != NULL);

  ASSERT(parse("cmd1 | cmd2", &g) == SHELL_DEP_OK);
  g.edges[0].type = (shell_dep_edge_type_t)UINT32_MAX;
  validation = shell_dep_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);
  pass_count++;
}

/* --- COMPLEX COMMANDS --- */

TEST(graph_dump_contract) {
  FILE *output = tmpfile();
  ASSERT(output != NULL);
  shell_dep_graph_t g;
  ASSERT(parse("FOO=bar cat file.txt | sort > out.txt", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("cat <<EOF\nhello\nEOF", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("cat <<< hello", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);

  ASSERT(fflush(output) == 0);
  ASSERT(fseek(output, 0, SEEK_SET) == 0);
  char text[4096];
  size_t length = fread(text, 1, sizeof(text) - 1, output);
  ASSERT(!ferror(output));
  text[length] = '\0';
  ASSERT(strstr(text, "Graph:") != NULL);
  ASSERT(strstr(text, "CMD cwd=\".\"") != NULL);
  ASSERT(strstr(text, "DOC ENVVAR name=\"FOO\" value=\"bar\"") != NULL);
  ASSERT(strstr(text, "DOC FILE path=\"file.txt\"") != NULL);
  ASSERT(strstr(text, "DOC HEREDOC delim=\"EOF\" content=\"hello\"") != NULL);
  ASSERT(strstr(text, "DOC HERESTRING content=\"hello\"") != NULL);
  ASSERT(strstr(text, "PIPE ->") != NULL);
  ASSERT(strstr(text, "ARG <>") != NULL);
  ASSERT(fclose(output) == 0);
  pass_count++;
}

TEST(name_helpers) {
  static const char *edge_names[] = {"READ", "WRITE", "APPEND", "PIPE",
                                     "ARG",  "ENV",   "SUBST",  "SEQ",
                                     "AND",  "OR",    "CWD",    "BACKGROUND",
                                     "GROUP"},
                    *node_names[] = {"CMD", "DOC", "GROUP"},
                    *doc_names[] = {"FILE", "HEREDOC", "HERESTRING", "ENVVAR"},
                    *error_names[] = {"OK", "Invalid input",
                                      "Truncated (limits exceeded)",
                                      "Parse error"};
  for (size_t i = 0; i < sizeof(edge_names) / sizeof(edge_names[0]); i++)
    ASSERT_STR_EQ(shell_dep_edge_type_name((shell_dep_edge_type_t)i),
                  edge_names[i]);
  for (size_t i = 0; i < sizeof(node_names) / sizeof(node_names[0]); i++)
    ASSERT_STR_EQ(shell_dep_node_type_name((shell_dep_node_type_t)i),
                  node_names[i]);
  for (size_t i = 0; i < sizeof(doc_names) / sizeof(doc_names[0]); i++)
    ASSERT_STR_EQ(shell_dep_doc_kind_name((shell_dep_doc_kind_t)i),
                  doc_names[i]);
  for (size_t i = 0; i < sizeof(error_names) / sizeof(error_names[0]); i++)
    ASSERT_STR_EQ(shell_dep_error_string((shell_dep_error_t) - (int)i),
                  error_names[i]);
  ASSERT_STR_EQ(shell_dep_edge_type_name((shell_dep_edge_type_t)-1), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_edge_type_name((shell_dep_edge_type_t)99), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_node_type_name((shell_dep_node_type_t)-1), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_node_type_name((shell_dep_node_type_t)99), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_doc_kind_name((shell_dep_doc_kind_t)-1), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_doc_kind_name((shell_dep_doc_kind_t)99), "UNKNOWN");
  ASSERT_STR_EQ(shell_dep_error_string((shell_dep_error_t)99), "Unknown error");
  pass_count++;
}

/* --- MAIN --- */

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "-v") == 0)
    verbose = true;

  printf("Running depgraph tests...\n\n");

  printf("Basic Commands:\n");
  RUN(basic_command_matrix);
  RUN(token_zero_copy);

  printf("\nOperators:\n");
  RUN(operator_matrix);

  printf("\nRedirects:\n");
  RUN(redirect_matrix);

  printf("\nCWD Tracking:\n");
  RUN(cwd_matrix);
  RUN(composition_metadata_matrix);
  RUN(comment_matrix);

  printf("\nEnvironment Variables:\n");
  RUN(environment_matrix);

  printf("\nFile Arguments:\n");
  RUN(file_argument_matrix);

  printf("\nSubshells:\n");
  RUN(subshell_matrix);
  RUN(nested_composition_matrix);

  printf("\nHeredocs and herestrings:\n");
  RUN(inline_document_matrix);

  printf("\nError Handling:\n");
  RUN(null_input);
  RUN(null_output);
  RUN(empty_input);
  RUN(adversarial_limits);
  RUN(parse_error);
  RUN(dialect_boundary_matrix);
  RUN(nested_parse_error_matrix);
  RUN(limit_matrix);
  RUN(nested_limit_cross_product);

  printf("\nGraph Integrity:\n");
  RUN(validation_matrix);

  printf("\nComplex:\n");
  RUN(graph_dump_contract);
  RUN(name_helpers);

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
