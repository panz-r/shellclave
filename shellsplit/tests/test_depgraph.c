#include "../src/shell_depgraph_internal.h"
#include "depgraph_invariants.h"
#include "shell_depgraph.h"
#include "shell_tokenizer.h"
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

static bool has_edge(const shell_dep_graph_t *g, shell_dep_edge_type_t type,
                     uint32_t from, uint32_t to) {
  for (uint32_t i = 0; i < g->edge_count; i++)
    if (g->edges[i].type == type && g->edges[i].from == from &&
        g->edges[i].to == to)
      return true;
  return false;
}

static bool has_edge_fds(const shell_dep_graph_t *g, shell_dep_edge_type_t type,
                         uint32_t from, uint32_t to, uint32_t source_fd,
                         uint32_t target_fd) {
  for (uint32_t i = 0; i < g->edge_count; i++)
    if (g->edges[i].type == type && g->edges[i].from == from &&
        g->edges[i].to == to && g->edges[i].source_fd == source_fd &&
        g->edges[i].target_fd == target_fd)
      return true;
  return false;
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

static int find_group(const shell_dep_graph_t *g, uint8_t kind,
                      uint32_t parent) {
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_GROUP &&
        g->nodes[i].group.kind == kind && g->nodes[i].group.parent == parent)
      return (int)i;
  return -1;
}

static int find_endpoint(const shell_dep_graph_t *g) {
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_ENDPOINT)
      return (int)i;
  return -1;
}

static int find_doc(const shell_dep_graph_t *g, shell_dep_doc_kind_t kind) {
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_DOC && g->nodes[i].doc.kind == kind)
      return (int)i;
  return -1;
}

static shell_dep_error_t parse(const char *cmd, shell_dep_graph_t *g) {
  memset(g, 0, sizeof(*g));
  return shell_dep_graph_parse(cmd, strlen(cmd), ".", NULL, g);
}

static shell_dep_error_t parse_cwd(const char *cmd, const char *cwd,
                                   shell_dep_graph_t *g) {
  memset(g, 0, sizeof(*g));
  return shell_dep_graph_parse(cmd, strlen(cmd), cwd, NULL, g);
}

static const char *get_cwd_str(const shell_dep_graph_t *g,
                               uint32_t cwd_offset) {
  if (cwd_offset >= g->cwd_buf.len)
    return ".";
  return g->cwd_buf.data + cwd_offset;
}

static bool doc_content_equals(const shell_dep_doc_t *doc,
                               const char *expected) {
  size_t length = 0;
  size_t written = 0;
  char output[256];
  size_t expected_length = strlen(expected);
  return shell_dep_doc_content_length(doc, &length) &&
         length == expected_length && length < sizeof(output) &&
         shell_dep_doc_write_content(doc, output, sizeof(output), &written) &&
         written == expected_length &&
         memcmp(output, expected, expected_length) == 0;
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

TEST(supplied_fast_parser_contract) {
  const char *command = "cd /tmp && printf 'two words' >out | sed s/x/y/";
  shell_parse_result_t fast = {0};
  ASSERT(shell_parse_fast(command, strlen(command), NULL, &fast) == SHELL_OK);

  shell_dep_graph_t regular;
  shell_dep_graph_t supplied;
  ASSERT(parse(command, &regular) == SHELL_DEP_OK);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_OK);
  ASSERT(supplied.node_count == regular.node_count);
  ASSERT(supplied.edge_count == regular.edge_count);
  ASSERT(supplied.status == regular.status);
  ASSERT(shell_dep_graph_validate(&supplied).valid);

  shell_limits_t short_limits = {.max_subcommands = 1, .strict_mode = false};
  ASSERT(shell_parse_fast(command, strlen(command), &short_limits, &fast) ==
         SHELL_ETRUNC);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_ETRUNC);
  ASSERT(supplied.status & SHELL_DEP_STATUS_TRUNCATED);

  shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                           .strict_mode = true};
  ASSERT(shell_parse_fast("echo 'unterminated", strlen("echo 'unterminated"),
                          &strict, &fast) == SHELL_EPARSE);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(
             "echo 'unterminated", strlen("echo 'unterminated"), ".", NULL,
             &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status & SHELL_DEP_STATUS_ERROR);

  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         NULL, &supplied) == SHELL_DEP_OK);
  ASSERT(supplied.node_count == regular.node_count &&
         supplied.edge_count == regular.edge_count);

  const char *grouped = "{ echo; }";
  ASSERT(shell_parse_fast(grouped, strlen(grouped), NULL, &fast) == SHELL_OK);
  ASSERT(fast.group_count == 1);
  fast.groups[0].end = 0;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(grouped, strlen(grouped), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_ETRUNC);
  ASSERT((supplied.status & SHELL_DEP_STATUS_TRUNCATED) != 0);
  ASSERT(supplied.node_count == 1 && supplied.nodes[0].type == SHELL_NODE_CMD);
  ASSERT(shell_dep_graph_validate(&supplied).valid);

  /* Structurally impossible supplied metadata must fail before any fixed-size
   * graph scratch arrays are indexed. */
  ASSERT(shell_parse_fast(command, strlen(command), NULL, &fast) == SHELL_OK);
  fast.count = SHELL_MAX_SUBCOMMANDS + 1;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast(command, strlen(command), NULL, &fast) == SHELL_OK);
  fast.cmds[0].start = UINT32_MAX;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast("{( echo; )}", strlen("{( echo; )}"), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[1].parent = 1;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("{( echo; )}", strlen("{( echo; )}"),
                                         ".", NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast(grouped, strlen(grouped), NULL, &fast) == SHELL_OK);
  fast.group_count = SHELL_MAX_GROUPS + 1;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(grouped, strlen(grouped), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  const char *two_groups = "{ echo one; } ; { echo two; }";
  ASSERT(shell_parse_fast(two_groups, strlen(two_groups), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[0].end = fast.cmds[0].start + fast.cmds[0].len - 1;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(two_groups, strlen(two_groups), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
    ASSERT(shell_dep_graph_validate(&g).valid);
  }

  shell_dep_graph_t g;
  shell_dep_limits_t cwd_limits = SHELL_DEP_LIMITS_DEFAULT;
  cwd_limits.cd_as_cmd = true;
  memset(&g, 0, sizeof(g));
  ASSERT(shell_dep_graph_parse("cd /tmp | pwd", strlen("cd /tmp | pwd"), ".",
                               &cwd_limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                ".");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_dep_graph_parse("cd /tmp & pwd", strlen("cd /tmp & pwd"), ".",
                               &cwd_limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                ".");
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.backgrounded);
  ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_known);
  memset(&g, 0, sizeof(g));
  ASSERT(shell_dep_graph_parse("cd /tmp; pwd", strlen("cd /tmp; pwd"), ".",
                               &cwd_limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_dep_graph_parse("(cd /tmp; pwd); pwd",
                               strlen("(cd /tmp; pwd); pwd"), ".", &cwd_limits,
                               &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 2)].cmd.cwd_offset),
                ".");
  memset(&g, 0, sizeof(g));
  ASSERT(shell_dep_graph_parse("cd /tmp && pwd; pwd",
                               strlen("cd /tmp && pwd; pwd"), ".", &cwd_limits,
                               &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(!g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_known);
  pass_count++;
}

TEST(posix_brace_group_pipeline) {
  const char *command =
      "cd /workspace && { sleep 2; printf 'q'; } | ./clock > /tmp/clock.out";
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cd_as_cmd = true;
  shell_dep_graph_t g = {0};
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits, &g) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 4);
  ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_GROUP) >= 2);
  ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) >= 2);
  int sleep = find_nth_cmd(&g, 1);
  int printf_cmd = find_nth_cmd(&g, 2);
  int clock_cmd = find_nth_cmd(&g, 3);
  int group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(sleep >= 0 && printf_cmd >= 0 && clock_cmd >= 0 && group >= 0);
  ASSERT(has_edge(&g, SHELL_EDGE_PIPE, (uint32_t)group, (uint32_t)clock_cmd));
  ASSERT(g.nodes[sleep].cmd.group_kinds == SHELL_GROUP_BRACE);
  ASSERT(g.nodes[printf_cmd].cmd.group_kinds == SHELL_GROUP_BRACE);
}

TEST(posix_brace_group_input_and_redirect) {
  const char *command =
      "./source | { read line; printf '%s\\n' \"$line\"; } > /tmp/out";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
  int group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  int source = find_nth_cmd(&g, 0);
  int read_cmd = find_nth_cmd(&g, 1);
  int printf_cmd = find_nth_cmd(&g, 2);
  ASSERT(read_cmd >= 0 && printf_cmd >= 0 && source >= 0 && group >= 0);
  ASSERT(has_edge(&g, SHELL_EDGE_PIPE, (uint32_t)source, (uint32_t)group));
  ASSERT(g.nodes[read_cmd].cmd.group_kinds == SHELL_GROUP_BRACE);
  ASSERT(g.nodes[printf_cmd].cmd.group_kinds == SHELL_GROUP_BRACE);
}

TEST(compound_group_input_redirect_overrides_pipe) {
  struct {
    const char *command;
    shell_dep_doc_kind_t kind;
  } cases[] = {
      {"./source | { cat; } < /tmp/input", SHELL_DOC_FILE},
      {"./source | { cat; } <<'EOF'\npayload\nEOF\n", SHELL_DOC_HEREDOC},
      {"./source | { cat; } <<< \"payload\"", SHELL_DOC_HERESTRING},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
    /* The explicit fd-0 source replaces the group's pipeline reader. The
     * source still writes to the real pipe, represented by a terminal
     * endpoint rather than a false source-to-group relation. */
    ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
    int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    ASSERT(group >= 0);
    bool document_to_group = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (edge->type != SHELL_EDGE_READ || edge->to != (uint32_t)group ||
          edge->target_fd != 0)
        continue;
      ASSERT(graph.nodes[edge->from].type == SHELL_NODE_DOC);
      document_to_group = graph.nodes[edge->from].doc.kind == cases[i].kind;
    }
    ASSERT(document_to_group);
    bool terminal_pipe = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      terminal_pipe =
          terminal_pipe || (edge->type == SHELL_EDGE_PIPE &&
                            graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT &&
                            graph.nodes[edge->to].endpoint.reserved != 0);
    }
    ASSERT(terminal_pipe);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(effective_descriptor_routing) {
  shell_dep_graph_t graph;

  ASSERT(parse("cat < /tmp/first < /tmp/second", &graph) == SHELL_DEP_OK);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  bool second_is_active = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_READ || item->target_fd != 0)
      continue;
    const shell_dep_doc_t *document = &graph.nodes[item->from].doc;
    second_is_active =
        document->path_len == strlen("/tmp/second") &&
        memcmp(document->path, "/tmp/second", document->path_len) == 0;
  }
  ASSERT(second_is_active && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat 3< /tmp/input 0<&3", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 2);
  bool input_fd_three = false;
  bool input_fd_zero = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_READ)
      continue;
    input_fd_three = input_fd_three || item->target_fd == 3;
    input_fd_zero = input_fd_zero || item->target_fd == 0;
  }
  ASSERT(input_fd_three && input_fd_zero &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat < /tmp/input 1<&0", &graph) == SHELL_DEP_OK);
  bool input_fd_one = false;
  input_fd_zero = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_READ)
      continue;
    input_fd_zero = input_fd_zero || item->target_fd == 0;
    input_fd_one = input_fd_one || item->target_fd == 1;
  }
  ASSERT(input_fd_zero && input_fd_one &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x > /tmp/out 0>&1", &graph) == SHELL_DEP_OK);
  bool output_fd_zero = false;
  bool output_fd_one = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_WRITE)
      continue;
    output_fd_zero = output_fd_zero || item->source_fd == 0;
    output_fd_one = output_fd_one || item->source_fd == 1;
  }
  ASSERT(output_fd_zero && output_fd_one &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x 0>&1 | cat 1<&0", &graph) == SHELL_DEP_OK);
  bool pipe_source_zero = false;
  bool pipe_source_one = false;
  bool pipe_target_zero = false;
  bool pipe_target_one = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_PIPE)
      continue;
    pipe_source_zero = pipe_source_zero || item->source_fd == 0;
    pipe_source_one = pipe_source_one || item->source_fd == 1;
    pipe_target_zero = pipe_target_zero || item->target_fd == 0;
    pipe_target_one = pipe_target_one || item->target_fd == 1;
  }
  ASSERT(pipe_source_zero && pipe_source_one && pipe_target_zero &&
         pipe_target_one && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat < /tmp/input 0<&-", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 0);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x > /tmp/out 2>&1", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 2);
  bool out_fd_one = false;
  bool out_fd_two = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_WRITE)
      continue;
    out_fd_one = out_fd_one || item->source_fd == 1;
    out_fd_two = out_fd_two || item->source_fd == 2;
  }
  ASSERT(out_fd_one && out_fd_two && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x 2>&1 > /tmp/out | cat", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  bool stderr_pipe = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    stderr_pipe = stderr_pipe || (item->type == SHELL_EDGE_PIPE &&
                                  item->source_fd == 2 && item->target_fd == 0);
  }
  ASSERT(stderr_pipe && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("./source | { cat; } 3<&0 < /tmp/input", &graph) ==
         SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0 && count_edge_type(&graph, SHELL_EDGE_READ) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  bool group_file_stdin = false;
  bool group_pipe_alias = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    group_file_stdin = group_file_stdin ||
                       (item->type == SHELL_EDGE_READ &&
                        item->to == (uint32_t)group && item->target_fd == 0);
    group_pipe_alias = group_pipe_alias ||
                       (item->type == SHELL_EDGE_PIPE &&
                        item->to == (uint32_t)group && item->target_fd == 3);
  }
  ASSERT(group_file_stdin && group_pipe_alias &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(sibling_brace_group_pipeline_endpoints) {
  const char *command =
      "{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
      "{ printf tail; }";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3);
  ASSERT(count_type(&graph, SHELL_NODE_GROUP) == 3);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_AND) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_APPEND) == 1);

  bool pipe_groups = false;
  bool and_groups = false;
  bool leading_write = false;
  bool trailing_append = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type == SHELL_EDGE_PIPE) {
      pipe_groups = graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                    graph.nodes[edge->to].type == SHELL_NODE_GROUP &&
                    edge->from != edge->to;
    } else if (edge->type == SHELL_EDGE_AND) {
      and_groups = graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                   graph.nodes[edge->to].type == SHELL_NODE_GROUP &&
                   edge->from != edge->to;
    } else if (edge->type == SHELL_EDGE_WRITE) {
      leading_write = graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                      edge->source_fd == 3;
    } else if (edge->type == SHELL_EDGE_APPEND) {
      trailing_append = graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                        edge->source_fd == 2;
    }
  }
  ASSERT(pipe_groups && and_groups && leading_write && trailing_append);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(nested_brace_group_pipeline_scope) {
  const char *command =
      "./source | { ( read first; printf first; ); printf last; } | ./sink";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 5);
  /* The outer group is the only endpoint for each external pipeline. */
  ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 2);
}

TEST(internal_brace_group_pipeline_stays_internal) {
  const char *command = "{ ./producer | ./consumer; ./after; }";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
}

TEST(brace_group_redirect_list_scope) {
  const char *command = "{ echo one; echo two; } > /tmp/out 2> /tmp/err";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 2);
  int group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0);
  for (uint32_t i = 0; i < g.edge_count; i++)
    if (g.edges[i].type == SHELL_EDGE_WRITE)
      ASSERT(g.edges[i].from == (uint32_t)group);
}

TEST(compound_group_io_endpoints) {
  const char *command = "./source | ( cat; cat; ) > /tmp/out";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(count_edge_type(&g, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_WRITE) == 1);
  int source = find_nth_cmd(&g, 0);
  int group = find_group(&g, SHELL_GROUP_SUBSHELL, UINT32_MAX);
  ASSERT(source >= 0 && group >= 0);
  ASSERT(has_edge(&g, SHELL_EDGE_PIPE, (uint32_t)source, (uint32_t)group));
  for (uint32_t i = 0; i < g.edge_count; i++) {
    if (g.edges[i].type == SHELL_EDGE_WRITE)
      ASSERT(g.edges[i].from == (uint32_t)group);
  }
  ASSERT(shell_dep_graph_validate(&g).valid);
  pass_count++;
}

TEST(compound_group_leading_redirect_endpoints) {
  const char *command = "{ echo one; } 3>/tmp/trace </tmp/in 2>>/tmp/brace.err";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 3);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_APPEND) == 1);
  bool read = false;
  bool trace = false;
  bool append = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type == SHELL_EDGE_READ)
      read = edge->to == (uint32_t)group && edge->target_fd == 0;
    if (edge->type == SHELL_EDGE_WRITE)
      trace = edge->from == (uint32_t)group && edge->source_fd == 3;
    if (edge->type == SHELL_EDGE_APPEND)
      append = edge->from == (uint32_t)group && edge->source_fd == 2;
  }
  ASSERT(read && trace && append);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(compound_group_read_write_redirect) {
  const char *command = "{ cat; } <> /tmp/read-write >| /tmp/forced";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0 && count_doc_kind(&graph, SHELL_DOC_FILE) == 2);
  bool read_write_read = false;
  bool read_write_write = false;
  bool forced_write = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    read_write_read = read_write_read ||
                      (edge->type == SHELL_EDGE_READ &&
                       edge->to == (uint32_t)group && edge->target_fd == 0);
    read_write_write = read_write_write ||
                       (edge->type == SHELL_EDGE_WRITE &&
                        edge->from == (uint32_t)group && edge->source_fd == 0);
    forced_write =
        forced_write || (edge->type == SHELL_EDGE_WRITE &&
                         edge->from == (uint32_t)group && edge->source_fd == 1);
  }
  ASSERT(read_write_read && read_write_write && forced_write);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(compound_group_descriptor_operations_preserve_known_routes) {
  const char *command =
      "{ echo one; } 3>/tmp/trace 0</tmp/in 2>>/tmp/brace.err 6>&1 4<&0 5>&-";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 3);
  /* 4<&0 preserves the file source on both live input descriptors. Unknown
   * inherited stdout copied to fd 6 remains intentionally unmaterialized. */
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_APPEND) == 1);
  bool read = false;
  bool copied_read = false;
  bool trace = false;
  bool append = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type == SHELL_EDGE_READ)
      read = read || (edge->to == (uint32_t)group && edge->target_fd == 0);
    if (edge->type == SHELL_EDGE_READ)
      copied_read =
          copied_read || (edge->to == (uint32_t)group && edge->target_fd == 4);
    if (edge->type == SHELL_EDGE_WRITE)
      trace = edge->from == (uint32_t)group && edge->source_fd == 3;
    if (edge->type == SHELL_EDGE_APPEND)
      append = edge->from == (uint32_t)group && edge->source_fd == 2;
  }
  ASSERT(read && copied_read && trace && append);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(compound_group_heredoc_descriptor_relations) {
  const char *command =
      "{ cat; cat; } 4<&0 5>&- <<-'EOF' 3>\"/tmp/trace file\" 6>&1\n"
      "\tpayload\n"
      "\tEOF\n";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2);
  /* Descriptor operations are not graph artifacts; only the heredoc and
   * quoted output path produce endpoint relations. */
  ASSERT(count_type(&graph, SHELL_NODE_DOC) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  bool heredoc_read = false;
  bool file_write = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    heredoc_read =
        heredoc_read || (edge->type == SHELL_EDGE_READ &&
                         edge->to == (uint32_t)group && edge->target_fd == 0);
    file_write =
        file_write || (edge->type == SHELL_EDGE_WRITE &&
                       edge->from == (uint32_t)group && edge->source_fd == 3);
  }
  ASSERT(heredoc_read && file_write);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(canonical_heredoc_delimiter_contract) {
  static const struct {
    const char *command;
    uint32_t documents;
    uint32_t literals;
    const char *first_delimiter;
  } cases[] = {
      {"{ cat; } << EOF\nbody\nEOF\n", 1, 0, "EOF"},
      {"{ cat; } <<\"E\\qF\"\nbody\nE\\qF\n", 1, 1, "E\\qF"},
      {"{ cat; } <<''\n\n", 1, 1, ""},
      {"{ cat; } << EOF <<-\"F\"\r\none\r\nEOF\r\n\ttwo\r\n\tF\r\n", 2, 1,
       "EOF"},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    ASSERT(group >= 0 && count_type(&graph, SHELL_NODE_CMD) == 1 &&
           count_doc_kind(&graph, SHELL_DOC_HEREDOC) == cases[i].documents);

    uint32_t documents = 0;
    uint32_t literals = 0;
    uint32_t reads = 0;
    const shell_dep_doc_t *first = NULL;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const shell_dep_node_t *current = &graph.nodes[node];
      if (current->type != SHELL_NODE_DOC ||
          current->doc.kind != SHELL_DOC_HEREDOC)
        continue;
      if (!first)
        first = &current->doc;
      documents++;
      literals +=
          (current->doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) != 0;
    }
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      if (graph.edges[edge].type == SHELL_EDGE_READ) {
        ASSERT(graph.edges[edge].to == (uint32_t)group);
        reads++;
      }
    ASSERT(documents == cases[i].documents && literals == cases[i].literals &&
           reads > 0 && first != NULL);
    ASSERT_STRN_EQ(first->name, first->name_len, cases[i].first_delimiter);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(compound_group_leading_descriptor_operations) {
  const char *command = "{ :; { echo one; } 7>/tmp/inner 6>&1; echo outer; } "
                        "3>/tmp/trace 4<&0 5>&-";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(outer >= 0);
  int inner = find_group(&graph, SHELL_GROUP_BRACE, (uint32_t)outer);
  ASSERT(inner >= 0);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3);
  /* Only real file redirects become document relations. The four descriptor
   * operations are group syntax, but neither files nor graph edges. */
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 0);
  bool outer_write = false;
  bool inner_write = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type != SHELL_EDGE_WRITE)
      continue;
    outer_write =
        outer_write || (edge->from == (uint32_t)outer && edge->source_fd == 3);
    inner_write =
        inner_write || (edge->from == (uint32_t)inner && edge->source_fd == 7);
  }
  ASSERT(outer_write && inner_write);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(nested_compound_group_redirect_ownership) {
  const char *command = "{ :; { echo inner; } 3>/tmp/inner 4<&0; echo outer; } "
                        "7>/tmp/outer 2>>/tmp/outer.err";
  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  int outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(outer >= 0);
  int inner = find_group(&graph, SHELL_GROUP_BRACE, (uint32_t)outer);
  ASSERT(inner >= 0);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 3);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_APPEND) == 1);
  bool outer_write = false;
  bool inner_write = false;
  bool outer_append = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type == SHELL_EDGE_WRITE && edge->from == (uint32_t)outer &&
        edge->source_fd == 7)
      outer_write = true;
    if (edge->type == SHELL_EDGE_WRITE && edge->from == (uint32_t)inner &&
        edge->source_fd == 3)
      inner_write = true;
    if (edge->type == SHELL_EDGE_APPEND && edge->from == (uint32_t)outer &&
        edge->source_fd == 2)
      outer_append = true;
  }
  ASSERT(outer_write && inner_write && outer_append);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_aggregate_control_scope) {
  static const struct {
    const char *command;
    shell_dep_edge_type_t edge_type;
    bool group_is_source;
  } cases[] = {
      {"{ ./first; ./second; } && ./after", SHELL_EDGE_AND, true},
      {"./before || { ./first; ./second; }", SHELL_EDGE_OR, false},
      {"{ ./first; ./second; } & ./after", SHELL_EDGE_BACKGROUND, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g = {0};
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    int group = -1;
    for (uint32_t n = 0; n < g.node_count; n++) {
      if (g.nodes[n].type == SHELL_NODE_GROUP &&
          g.nodes[n].group.kind == SHELL_GROUP_BRACE) {
        group = (int)n;
        break;
      }
    }
    ASSERT(group >= 0);
    bool aggregate_edge = false;
    for (uint32_t e = 0; e < g.edge_count; e++) {
      const shell_dep_edge_t *edge = &g.edges[e];
      if (edge->type == cases[i].edge_type &&
          (cases[i].group_is_source ? edge->from == (uint32_t)group
                                    : edge->to == (uint32_t)group)) {
        aggregate_edge = true;
        break;
      }
    }
    ASSERT(aggregate_edge);
  }
}

TEST(nested_brace_group_aggregate_control_scope) {
  const char *command =
      "{ { ./inner_one; ./inner_two; } && ./outer; } || ./after";
  shell_dep_graph_t g = {0};
  ASSERT(parse(command, &g) == SHELL_DEP_OK);
  int outer = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(outer >= 0);
  int inner = find_group(&g, SHELL_GROUP_BRACE, (uint32_t)outer);
  ASSERT(inner >= 0);
  bool inner_and = false;
  bool outer_or = false;
  for (uint32_t i = 0; i < g.edge_count; i++) {
    const shell_dep_edge_t *edge = &g.edges[i];
    inner_and |= edge->type == SHELL_EDGE_AND && edge->from == (uint32_t)inner;
    outer_or |= edge->type == SHELL_EDGE_OR && edge->from == (uint32_t)outer;
  }
  ASSERT(inner_and && outer_or);
  ASSERT(shell_dep_graph_validate(&g).valid);
  pass_count++;
}

TEST(brace_group_cwd_scope) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cd_as_cmd = true;
  shell_dep_graph_t g = {0};
  const char *brace = "{ cd /tmp; pwd; }; pwd";
  ASSERT(shell_dep_graph_parse(brace, strlen(brace), "/home/user", &limits,
                               &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  int after_brace = find_nth_cmd(&g, 2);
  ASSERT(after_brace >= 0);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[after_brace].cmd.cwd_offset), "/tmp");

  memset(&g, 0, sizeof(g));
  const char *subshell = "{ ( cd /tmp; pwd; ); pwd; }";
  ASSERT(shell_dep_graph_parse(subshell, strlen(subshell), "/home/user",
                               &limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  int after_subshell = find_nth_cmd(&g, 2);
  ASSERT(after_subshell >= 0);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[after_subshell].cmd.cwd_offset),
                "/home/user");

  /* An aggregate pipe executes the entire group in an isolated execution
   * context. The group's local `cd` applies to its following member but must
   * neither leak to the pipe peer nor to the subsequent list command. */
  memset(&g, 0, sizeof(g));
  const char *piped = "{ cd /tmp; echo x; } | cat; pwd";
  ASSERT(shell_dep_graph_parse(piped, strlen(piped), "/home/user", &limits,
                               &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 4);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 0)].cmd.cwd_offset),
                "/home/user");
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 2)].cmd.cwd_offset),
                "/home/user");
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 3)].cmd.cwd_offset),
                "/home/user");

  /* Background execution is also aggregate: every enclosed simple command
   * is marked backgrounded and its local CWD cannot affect the foreground. */
  memset(&g, 0, sizeof(g));
  const char *backgrounded = "{ cd /tmp; echo x; } & pwd";
  ASSERT(shell_dep_graph_parse(backgrounded, strlen(backgrounded), "/home/user",
                               &limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.backgrounded);
  ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.backgrounded);
  ASSERT(!g.nodes[find_nth_cmd(&g, 2)].cmd.backgrounded);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 2)].cmd.cwd_offset),
                "/home/user");

  memset(&g, 0, sizeof(g));
  const char *subshell_backgrounded = "( cd /tmp; echo x; ) & pwd";
  ASSERT(shell_dep_graph_parse(subshell_backgrounded,
                               strlen(subshell_backgrounded), "/home/user",
                               &limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 3);
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.backgrounded);
  ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.backgrounded);
  ASSERT(!g.nodes[find_nth_cmd(&g, 2)].cmd.backgrounded);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 2)].cmd.cwd_offset),
                "/home/user");
  ASSERT(shell_dep_graph_validate(&g).valid);
  pass_count++;
}

TEST(substitution_word_boundary_contract) {
  static const struct {
    const char *command;
    const char *word;
    uint32_t command_count;
    uint32_t subst_edges;
  } cases[] = {
      {"echo foo$(cat)bar", "foo$(cat)bar", 2, 1},
      {"echo <(cat)foo", "<(cat)foo", 2, 1},
      {"echo pre${value}post", "pre${value}post", 1, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == cases[i].command_count);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == cases[i].subst_edges);
    int outer = find_first_cmd(&graph);
    ASSERT(outer >= 0 && graph.nodes[outer].cmd.token_count == 2);
    ASSERT_STRN_EQ(graph.nodes[outer].cmd.tokens[1],
                   graph.nodes[outer].cmd.token_lens[1], cases[i].word);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  /* Process substitution syntax inside double quotes is literal. Command
   * substitution remains active there, so the quote context must be carried
   * into the graph scanner rather than globally disabling substitutions. */
  shell_dep_graph_t graph = {0};
  ASSERT(parse("echo \"<(cat)foo\"", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);
  int outer = find_first_cmd(&graph);
  ASSERT(outer >= 0 && graph.nodes[outer].cmd.token_count == 2);
  ASSERT_STRN_EQ(graph.nodes[outer].cmd.tokens[1],
                 graph.nodes[outer].cmd.token_lens[1], "\"<(cat)foo\"");

  memset(&graph, 0, sizeof(graph));
  ASSERT(parse("echo \"$(cat)\"", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_capacity_contract) {
  const char *command =
      "{ { echo one; echo two; } | cat; echo three; } > /tmp/group.out";
  shell_dep_graph_t baseline = {0};
  ASSERT(parse(command, &baseline) == SHELL_DEP_OK);
  ASSERT(count_type(&baseline, SHELL_NODE_GROUP) == 2);
  ASSERT(count_edge_type(&baseline, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_edge_type(&baseline, SHELL_EDGE_WRITE) == 1);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 2;
  shell_dep_graph_t limited = {0};
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &limited) == SHELL_DEP_ETRUNC);
  ASSERT(limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(limited.node_count <= limits.max_nodes);
  ASSERT(shell_dep_graph_validate(&limited).valid);

  limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_edges = 1;
  memset(&limited, 0, sizeof(limited));
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &limited) == SHELL_DEP_ETRUNC);
  ASSERT(limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(limited.edge_count <= limits.max_edges);
  ASSERT(shell_dep_graph_validate(&limited).valid);
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
    ASSERT(shell_dep_graph_validate(&graph).valid);
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
      {"echo $(<file)", 1, 1, 1},
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
      ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_CMD ||
             (g.nodes[g.edges[j].from].type == SHELL_NODE_DOC &&
              g.nodes[g.edges[j].from].doc.kind == SHELL_DOC_FILE));
      ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
      if (g.nodes[g.edges[j].from].type == SHELL_NODE_DOC)
        ASSERT(g.edges[j].source_fd == SHELL_DEP_FD_NONE &&
               g.edges[j].target_fd == SHELL_DEP_FD_NONE);
    }
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
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
       {-1, -1, 0},
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

TEST(dynamic_substitution_io_topology) {
  shell_dep_graph_t graph;
  ASSERT(parse("echo $(printf value)", &graph) == SHELL_DEP_OK);
  int outer = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  ASSERT(outer >= 0 && producer >= 0 && find_endpoint(&graph) < 0);
  bool direct = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    direct = direct || (edge->type == SHELL_EDGE_SUBST &&
                        edge->from == (uint32_t)producer &&
                        edge->to == (uint32_t)outer && edge->source_fd == 1);
  }
  ASSERT(direct && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(<\"/tmp/substitution input\")", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  ASSERT(outer >= 0 && count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_READ) == 0);
  bool file_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type != SHELL_EDGE_SUBST || edge->to != (uint32_t)outer ||
        edge->source_fd != SHELL_DEP_FD_NONE ||
        edge->target_fd != SHELL_DEP_FD_NONE ||
        graph.nodes[edge->from].type != SHELL_NODE_DOC)
      continue;
    ASSERT(graph.nodes[edge->from].doc.kind == SHELL_DOC_FILE);
    ASSERT_STRN_EQ(graph.nodes[edge->from].doc.path,
                   graph.nodes[edge->from].doc.path_len,
                   "\"/tmp/substitution input\"");
    file_substitution = true;
  }
  ASSERT(file_substitution && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $( { sleep 2; printf q; } | ./clock )", &graph) ==
         SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  ASSERT(outer >= 0 && count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         find_endpoint(&graph) < 0);
  bool grouped_pipe = false;
  bool group_to_outer = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    grouped_pipe =
        grouped_pipe || (edge->type == SHELL_EDGE_PIPE &&
                         graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                         graph.nodes[edge->to].type == SHELL_NODE_CMD);
    group_to_outer =
        group_to_outer || (edge->type == SHELL_EDGE_SUBST &&
                           graph.nodes[edge->from].type == SHELL_NODE_CMD &&
                           edge->to == (uint32_t)outer && edge->source_fd == 1);
  }
  ASSERT(grouped_pipe && group_to_outer &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(printf first; printf second)", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  int collector = find_endpoint(&graph);
  ASSERT(outer >= 0 && collector >= 0);
  uint32_t collector_writes = 0;
  bool collector_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type == SHELL_EDGE_WRITE && edge->to == (uint32_t)collector &&
        edge->source_fd == 1)
      collector_writes++;
    if (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)collector &&
        edge->to == (uint32_t)outer && edge->source_fd == SHELL_DEP_FD_NONE &&
        edge->target_fd == SHELL_DEP_FD_NONE)
      collector_substitution = true;
  }
  ASSERT(collector_writes == 2 && collector_substitution &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(printf hidden > /tmp/hidden)", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf value 2> >(cat)", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  int nested = find_nth_cmd(&graph, 1);
  collector = find_endpoint(&graph);
  ASSERT(outer >= 0 && nested >= 0 && collector >= 0);
  bool source_write = false;
  bool sink_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    source_write =
        source_write ||
        (edge->type == SHELL_EDGE_WRITE && edge->from == (uint32_t)outer &&
         edge->to == (uint32_t)collector && edge->source_fd == 2);
    sink_substitution =
        sink_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)collector &&
         edge->to == (uint32_t)nested);
  }
  ASSERT(source_write && sink_substitution &&
         shell_dep_graph_validate(&graph).valid);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 3;
  static const char multi_output[] = "echo $(printf first; printf second)";
  ASSERT(shell_dep_graph_parse(multi_output, strlen(multi_output), ".", &limits,
                               &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.node_count == 1 && graph.edge_count == 0 &&
         (graph.status & SHELL_DEP_STATUS_TRUNCATED));

  limits.max_nodes = 1;
  static const char file_substitution_input[] = "echo $(</tmp/input)";
  ASSERT(shell_dep_graph_parse(file_substitution_input,
                               strlen(file_substitution_input), ".", &limits,
                               &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.node_count == 1 && graph.edge_count == 0 &&
         (graph.status & SHELL_DEP_STATUS_TRUNCATED));
  pass_count++;
}

TEST(file_command_substitution_intersections) {
  shell_dep_graph_t graph;

  ASSERT(parse("echo $(</tmp/one)$(<\"/tmp/two words\")", &graph) ==
         SHELL_DEP_OK);
  int outer = find_nth_cmd(&graph, 0);
  ASSERT(outer >= 0 && count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_READ) == 0);
  bool saw_one = false;
  bool saw_two = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type != SHELL_EDGE_SUBST || edge->to != (uint32_t)outer)
      continue;
    ASSERT(edge->source_fd == SHELL_DEP_FD_NONE &&
           edge->target_fd == SHELL_DEP_FD_NONE);
    ASSERT(graph.nodes[edge->from].type == SHELL_NODE_DOC);
    ASSERT(graph.nodes[edge->from].doc.kind == SHELL_DOC_FILE);
    saw_one = saw_one ||
              (graph.nodes[edge->from].doc.path_len == strlen("/tmp/one") &&
               memcmp(graph.nodes[edge->from].doc.path, "/tmp/one",
                      strlen("/tmp/one")) == 0);
    saw_two =
        saw_two ||
        (graph.nodes[edge->from].doc.path_len == strlen("\"/tmp/two words\"") &&
         memcmp(graph.nodes[edge->from].doc.path, "\"/tmp/two words\"",
                strlen("\"/tmp/two words\"")) == 0);
  }
  ASSERT(saw_one && saw_two && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ echo $(</tmp/group-input); }", &graph) == SHELL_DEP_OK);
  int grouped = find_nth_cmd(&graph, 0);
  ASSERT(grouped >= 0 && count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         graph.nodes[grouped].cmd.group_depth == 1);
  bool group_file_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    group_file_substitution =
        group_file_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->to == (uint32_t)grouped &&
         edge->source_fd == SHELL_DEP_FD_NONE &&
         edge->target_fd == SHELL_DEP_FD_NONE &&
         graph.nodes[edge->from].type == SHELL_NODE_DOC &&
         graph.nodes[edge->from].doc.kind == SHELL_DOC_FILE);
  }
  ASSERT(group_file_substitution && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $( { printf $(</tmp/nested-input); } )", &graph) ==
         SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  int nested = find_nth_cmd(&graph, 1);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(outer >= 0 && nested >= 0 && group >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
  bool nested_file_substitution = false;
  bool group_output_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    nested_file_substitution =
        nested_file_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->to == (uint32_t)nested &&
         edge->source_fd == SHELL_DEP_FD_NONE &&
         edge->target_fd == SHELL_DEP_FD_NONE &&
         graph.nodes[edge->from].type == SHELL_NODE_DOC);
    group_output_substitution =
        group_output_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)group &&
         edge->to == (uint32_t)outer && edge->source_fd == 1);
  }
  ASSERT(nested_file_substitution && group_output_substitution &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(</tmp/direct)$(id)", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  int command_producer = find_nth_cmd(&graph, 1);
  ASSERT(outer >= 0 && command_producer >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
  bool direct_file = false;
  bool command_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    direct_file =
        direct_file ||
        (edge->type == SHELL_EDGE_SUBST &&
         graph.nodes[edge->from].type == SHELL_NODE_DOC &&
         edge->to == (uint32_t)outer && edge->source_fd == SHELL_DEP_FD_NONE &&
         edge->target_fd == SHELL_DEP_FD_NONE);
    command_substitution =
        command_substitution ||
        (edge->type == SHELL_EDGE_SUBST &&
         edge->from == (uint32_t)command_producer &&
         edge->to == (uint32_t)outer && edge->source_fd == 1);
  }
  ASSERT(direct_file && command_substitution &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(< /tmp/spaced)", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  ASSERT(outer >= 0 && count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_READ) == 0);
  bool spaced_file_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    spaced_file_substitution =
        spaced_file_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->to == (uint32_t)outer &&
         edge->source_fd == SHELL_DEP_FD_NONE &&
         edge->target_fd == SHELL_DEP_FD_NONE &&
         graph.nodes[edge->from].type == SHELL_NODE_DOC &&
         graph.nodes[edge->from].doc.path_len == strlen("/tmp/spaced") &&
         memcmp(graph.nodes[edge->from].doc.path, "/tmp/spaced",
                strlen("/tmp/spaced")) == 0);
  }
  ASSERT(spaced_file_substitution && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(</tmp/input printf)", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  nested = find_nth_cmd(&graph, 1);
  ASSERT(outer >= 0 && nested >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1);
  bool ordinary_read = false;
  bool ordinary_substitution = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    ordinary_read =
        ordinary_read || (edge->type == SHELL_EDGE_READ &&
                          graph.nodes[edge->from].type == SHELL_NODE_DOC &&
                          edge->to == (uint32_t)nested && edge->target_fd == 0);
    ordinary_substitution =
        ordinary_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)nested &&
         edge->to == (uint32_t)outer && edge->source_fd == 1);
    ASSERT(!(edge->type == SHELL_EDGE_SUBST &&
             graph.nodes[edge->from].type == SHELL_NODE_DOC));
  }
  ASSERT(ordinary_read && ordinary_substitution &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(</tmp/unterminated", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_edges = 1;
  static const char two_file_substitutions[] = "echo $(</tmp/one)$(</tmp/two)";
  ASSERT(shell_dep_graph_parse(two_file_substitutions,
                               strlen(two_file_substitutions), ".", &limits,
                               &graph) == SHELL_DEP_ETRUNC);
  ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) && graph.edge_count == 1 &&
         graph.node_count == 2 && shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(file_command_substitution_dynamic_operands) {
  shell_dep_graph_t graph;

  ASSERT(parse("echo $(< <(printf q))", &graph) == SHELL_DEP_OK);
  int outer = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  ASSERT(outer >= 0 && producer >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0);
  bool process_file_content = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    process_file_content =
        process_file_content ||
        (current->type == SHELL_EDGE_SUBST &&
         current->from == (uint32_t)producer &&
         current->to == (uint32_t)outer && current->source_fd == 1 &&
         current->target_fd == SHELL_DEP_FD_NONE &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(process_file_content && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(<$(printf /tmp/value))", &graph) == SHELL_DEP_OK);
  outer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(outer >= 0 && producer >= 0);
  int dynamic_file = -1;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    const shell_dep_node_t *current = &graph.nodes[node];
    if (current->type == SHELL_NODE_DOC &&
        current->doc.kind == SHELL_DOC_FILE &&
        current->doc.path_len == strlen("$(printf /tmp/value)") &&
        memcmp(current->doc.path, "$(printf /tmp/value)",
               current->doc.path_len) == 0)
      dynamic_file = (int)node;
  }
  ASSERT(dynamic_file >= 0 && (graph.nodes[dynamic_file].doc.flags &
                               SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0);
  bool dynamic_name = false;
  bool selected_file_content = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    dynamic_name =
        dynamic_name ||
        (current->type == SHELL_EDGE_SUBST &&
         current->from == (uint32_t)producer &&
         current->to == (uint32_t)dynamic_file && current->source_fd == 1 &&
         current->target_fd == SHELL_DEP_FD_NONE &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0 &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) == 0);
    selected_file_content =
        selected_file_content ||
        (current->type == SHELL_EDGE_SUBST &&
         current->from == (uint32_t)dynamic_file &&
         current->to == (uint32_t)outer &&
         current->source_fd == SHELL_DEP_FD_NONE &&
         current->target_fd == SHELL_DEP_FD_NONE &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(dynamic_name && selected_file_content &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(<prefix`printf /tmp/value`suffix)", &graph) ==
         SHELL_DEP_OK);
  bool saw_backtick_filename = false;
  bool saw_backtick_name_flow = false;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    const shell_dep_node_t *current = &graph.nodes[node];
    saw_backtick_filename =
        saw_backtick_filename ||
        (current->type == SHELL_NODE_DOC &&
         current->doc.kind == SHELL_DOC_FILE &&
         (current->doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0);
  }
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    saw_backtick_name_flow = saw_backtick_name_flow ||
                             (graph.edges[edge].type == SHELL_EDGE_SUBST &&
                              (graph.edges[edge].flags &
                               SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0);
  ASSERT(saw_backtick_filename && saw_backtick_name_flow &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo $(<$(printf /tmp/value)", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  pass_count++;
}

TEST(io_number_boundaries) {
  shell_dep_graph_t graph;
  ASSERT(parse("cat 2147483647</tmp/input", &graph) == SHELL_DEP_OK);
  int command = find_nth_cmd(&graph, 0);
  ASSERT(command >= 0);
  bool max_read = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    max_read = max_read || (graph.edges[edge].type == SHELL_EDGE_READ &&
                            graph.edges[edge].to == (uint32_t)command &&
                            graph.edges[edge].target_fd == SHELL_DEP_FD_MAX);
  ASSERT(max_read && graph.nodes[command].cmd.token_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat 2147483648</tmp/input", &graph) == SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 0);
  ASSERT(command >= 0 && graph.nodes[command].cmd.token_count == 2 &&
         graph.nodes[command].cmd.token_lens[1] == strlen("2147483648") &&
         memcmp(graph.nodes[command].cmd.tokens[1], "2147483648",
                strlen("2147483648")) == 0);
  bool default_read = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    default_read = default_read || (graph.edges[edge].type == SHELL_EDGE_READ &&
                                    graph.edges[edge].to == (uint32_t)command &&
                                    graph.edges[edge].target_fd == 0);
  ASSERT(default_read && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat 2147483647<<<value", &graph) == SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 0);
  bool max_herestring = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    max_herestring =
        max_herestring || (graph.edges[edge].type == SHELL_EDGE_READ &&
                           graph.edges[edge].to == (uint32_t)command &&
                           graph.edges[edge].target_fd == SHELL_DEP_FD_MAX);
  ASSERT(command >= 0 && max_herestring &&
         graph.nodes[command].cmd.token_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat 2147483648<<<value", &graph) == SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 0);
  bool default_herestring = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    default_herestring =
        default_herestring || (graph.edges[edge].type == SHELL_EDGE_READ &&
                               graph.edges[edge].to == (uint32_t)command &&
                               graph.edges[edge].target_fd == 0);
  ASSERT(command >= 0 && default_herestring &&
         graph.nodes[command].cmd.token_count == 2 &&
         shell_dep_graph_validate(&graph).valid);
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
    uint32_t substitution_count;
    const char *delimiter;
    const char *value;
  } cases[] = {
      {"cat <<EOF\nhello\nEOF", SHELL_DOC_HEREDOC, 1, 0, 0, 0, 0, "EOF",
       "hello"},
      {"sort <<DELIM\nline1\nline2\nDELIM", SHELL_DOC_HEREDOC, 1, 0, 0, 0, 0,
       "DELIM", "line1\nline2"},
      {"cat <<EOF | sort\nhello\nEOF", SHELL_DOC_HEREDOC, 2, 0, 1, 0, 0, "EOF",
       "hello"},
      {"cat <<EOF\n$(id)\nEOF", SHELL_DOC_HEREDOC, 2, 0, 0, 0, 1, "EOF",
       "$(id)"},
      {"cat <<EOF\nbody\nEOF\npwd", SHELL_DOC_HEREDOC, 2, 0, 0, 0, 0, "EOF",
       "body"},
      {"cat <<E'OF'\nbody\nEOF\npwd", SHELL_DOC_HEREDOC, 2, 0, 0, 0, 0, "E'OF'",
       "body"},
      {"cat <<EOF > out.txt\nhello\nEOF", SHELL_DOC_HEREDOC, 1, 1, 0, 1, 0,
       "EOF", "hello"},
      {"cat <<-'EOF'\n\tsecret\n\tEOF", SHELL_DOC_HEREDOC, 1, 0, 0, 0, 0, "EOF",
       "secret"},
      {"cat <<< hello", SHELL_DOC_HERESTRING, 1, 0, 0, 0, 0, NULL, "hello"},
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
    ASSERT(count_edge_type(&g, SHELL_EDGE_SUBST) ==
           cases[i].substitution_count);

    bool found_document = false;
    for (uint32_t j = 0; j < g.node_count; j++) {
      if (g.nodes[j].type != SHELL_NODE_DOC ||
          g.nodes[j].doc.kind != cases[i].document_kind)
        continue;
      found_document = true;
      ASSERT(doc_content_equals(&g.nodes[j].doc, cases[i].value));
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
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  pass_count++;
}

TEST(heredoc_content_writer_contract) {
  const char *command = "cat <<-EOF\r\n\tone\r\n\t\ttwo\r\n\tEOF\r\n";
  shell_dep_graph_t graph;
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  const shell_dep_doc_t *document = NULL;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if (graph.nodes[i].type == SHELL_NODE_DOC &&
        graph.nodes[i].doc.kind == SHELL_DOC_HEREDOC) {
      document = &graph.nodes[i].doc;
      break;
    }
  ASSERT(document != NULL);
  ASSERT(document->flags == SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS);
  ASSERT_STRN_EQ(document->value, document->value_len, "\tone\r\n\t\ttwo\r");

  size_t length = 0;
  size_t written = SIZE_MAX;
  char content[32];
  memset(content, 0xA5, sizeof(content));
  ASSERT(shell_dep_doc_content_length(document, &length));
  ASSERT(length == strlen("one\r\ntwo\r"));
  ASSERT(!shell_dep_doc_write_content(document, content, length - 1, &written));
  ASSERT(written == 0 && (unsigned char)content[0] == 0xA5);
  ASSERT(shell_dep_doc_write_content(document, content, length, &written));
  ASSERT(written == length);
  ASSERT_STRN_EQ(content, (uint32_t)written, "one\r\ntwo\r");
  ASSERT(shell_dep_graph_validate(&graph).valid);

  const char *bare_cr = "cat <<-EOF\n\tone\r\tstill-same-line\n\ttwo\nEOF\n";
  ASSERT(parse(bare_cr, &graph) == SHELL_DEP_OK);
  document = NULL;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if (graph.nodes[i].type == SHELL_NODE_DOC &&
        graph.nodes[i].doc.kind == SHELL_DOC_HEREDOC) {
      document = &graph.nodes[i].doc;
      break;
    }
  ASSERT(document != NULL &&
         doc_content_equals(document, "one\r\tstill-same-line\ntwo") &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(document_content_api_error_contract) {
  size_t length = SIZE_MAX;
  size_t written = SIZE_MAX;
  char output[32] = {0};
  shell_dep_doc_t empty = {0};
  shell_dep_doc_t malformed_value = {.value = NULL, .value_len = 1};
  shell_dep_doc_t malformed_flags = {
      .value = "value", .value_len = 5, .flags = UINT8_MAX};
  static const char physical[] = "\tone\n\t\ttwo\nthree";
  shell_dep_doc_t stripped = {
      .value = physical,
      .value_len = sizeof(physical) - 1,
      .flags = SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS,
  };

  ASSERT(!shell_dep_doc_content_length(NULL, &length) && length == 0);
  length = SIZE_MAX;
  ASSERT(!shell_dep_doc_content_length(&empty, NULL));
  ASSERT(!shell_dep_doc_content_length(&malformed_value, &length) &&
         length == 0);
  ASSERT(!shell_dep_doc_content_length(&malformed_flags, &length) &&
         length == 0);
  ASSERT(shell_dep_doc_content_length(&empty, &length) && length == 0);

  written = SIZE_MAX;
  ASSERT(!shell_dep_doc_write_content(NULL, output, sizeof(output), &written) &&
         written == 0);
  written = SIZE_MAX;
  ASSERT(!shell_dep_doc_write_content(&empty, output, sizeof(output), NULL));
  written = SIZE_MAX;
  ASSERT(shell_dep_doc_write_content(&empty, NULL, 0, &written) &&
         written == 0);
  written = SIZE_MAX;
  ASSERT(
      !shell_dep_doc_write_content(&stripped, NULL, sizeof(output), &written) &&
      written == 0);
  written = SIZE_MAX;
  ASSERT(!shell_dep_doc_write_content(&stripped, output, 12, &written) &&
         written == 0);
  ASSERT(shell_dep_doc_content_length(&stripped, &length) && length == 13);
  ASSERT(shell_dep_doc_write_content(&stripped, output, sizeof(output),
                                     &written) &&
         written == length);
  ASSERT_STRN_EQ(output, (uint32_t)written, "one\ntwo\nthree");
  pass_count++;
}

TEST(expandable_heredoc_substitution_matrix) {
  shell_dep_graph_t graph;

  ASSERT(parse("cat <<EOF\n$(id)\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  int document = -1;
  int producer = find_nth_cmd(&graph, 1);
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      document = (int)node;
  ASSERT(document >= 0 && producer >= 0);
  bool dynamic_document = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    dynamic_document =
        dynamic_document ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)producer &&
         item->to == (uint32_t)document && item->source_fd == 1 &&
         item->target_fd == SHELL_DEP_FD_NONE);
  }
  ASSERT(dynamic_document && shell_dep_graph_validate(&graph).valid);

  /* `<<-` is still expandable and accepts CRLF line endings.  The document
   * helpers own tab removal; substitution discovery must retain the physical
   * source bytes and remain independent of that presentation detail. */
  ASSERT(parse("cat <<-EOF\r\n\t$(id)\r\n\tEOF\r\n", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC) {
      document = (int)node;
      ASSERT(graph.nodes[node].doc.flags &
             SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS);
    }
  ASSERT(document >= 0 && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<'EOF'\n$(id)\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC) {
      document = (int)node;
      ASSERT(graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL);
    }
  ASSERT(document >= 0 && shell_dep_graph_validate(&graph).valid);

  static const char *const literal_delimiters[] = {"cat <<\\EOF\n$(id)\nEOF",
                                                   "cat <<E\"OF\"\n$(id)\nEOF"};
  for (size_t i = 0;
       i < sizeof(literal_delimiters) / sizeof(literal_delimiters[0]); i++) {
    ASSERT(parse(literal_delimiters[i], &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);
    bool literal = false;
    for (uint32_t node = 0; node < graph.node_count; node++)
      literal =
          literal ||
          (graph.nodes[node].type == SHELL_NODE_DOC &&
           graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC &&
           (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
    ASSERT(literal && shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("cat <<EOF </dev/null\n$(id)\nEOF", &graph) == SHELL_DEP_OK);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      document = (int)node;
  ASSERT(document >= 0 &&
         (graph.nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT));
  bool heredoc_read = false;
  bool heredoc_subst = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    heredoc_read =
        heredoc_read || (graph.edges[edge].type == SHELL_EDGE_READ &&
                         graph.edges[edge].from == (uint32_t)document);
    heredoc_subst =
        heredoc_subst || (graph.edges[edge].type == SHELL_EDGE_SUBST &&
                          graph.edges[edge].to == (uint32_t)document);
  }
  ASSERT(!heredoc_read && heredoc_subst &&
         shell_dep_graph_validate(&graph).valid);

  /* Quotes in an unquoted heredoc body are data, not syntax that disables
   * command substitution. Both POSIX substitution spellings remain live. */
  ASSERT(parse("cat <<EOF\n\"$(id)\" '$(pwd)' `date`\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 4 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 3 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n\\$(id)\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);

  ASSERT(parse("cat <<EOF\n\\$(id) \\`date\\`\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* Empty substitutions are syntactically valid and contribute no producer;
   * scanning must continue to a following live substitution. A
   * backslash-newline is likewise one escaped heredoc byte rather than an
   * expansion boundary. */
  ASSERT(parse("cat <<EOF\n$()$(id)\\\n$(pwd)\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n`id\nEOF", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Heredocs are read in lexical order even when a later input redirect
   * replaces fd 0. Preserve the transient first document's dynamic edge but
   * only the final document can reach the command as a READ edge. */
  ASSERT(parse("cat <<A <<-B\n$(id)\nA\n\t$(pwd)\n\tB\n", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  uint32_t transient_count = 0;
  uint32_t strip_tabs_count = 0;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_HEREDOC)
      continue;
    transient_count +=
        (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0;
    strip_tabs_count += (graph.nodes[node].doc.flags &
                         SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS) != 0;
  }
  ASSERT(transient_count == 1 && strip_tabs_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$(</tmp/heredoc-input)\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  bool file_to_document = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    file_to_document = file_to_document ||
                       (item->type == SHELL_EDGE_SUBST &&
                        graph.nodes[item->from].type == SHELL_NODE_DOC &&
                        graph.nodes[item->from].doc.kind == SHELL_DOC_FILE &&
                        graph.nodes[item->to].doc.kind == SHELL_DOC_HEREDOC &&
                        item->source_fd == SHELL_DEP_FD_NONE &&
                        item->target_fd == SHELL_DEP_FD_NONE);
  }
  ASSERT(file_to_document && shell_dep_graph_validate(&graph).valid);

  /* Multiple producers have no false direct relation.  Their stdout first
   * converges at an explicit endpoint, which is the sole document source. */
  ASSERT(parse("cat <<EOF\n$(printf one; printf two)\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  int endpoint = find_endpoint(&graph);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      document = (int)node;
  ASSERT(endpoint >= 0 && document >= 0 &&
         has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                  (uint32_t)document) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$( { sleep 2; printf q; } | ./clock )\nEOF",
               &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 4 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$(id\nEOF", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  pass_count++;
}

TEST(heredoc_substitution_cross_product_matrix) {
  shell_dep_graph_t graph;

  /* Keep the three distinct document sources separate: a direct FILE source,
   * one executable producer, and a collector for a multi-command list. */
  ASSERT(
      parse("cat <<EOF\n$(</tmp/mixed-file)$(id)$(printf one; printf two)\nEOF",
            &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 4 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 3);
  int document = -1;
  int collector = find_endpoint(&graph);
  uint32_t file_sources = 0;
  uint32_t command_sources = 0;
  uint32_t collector_sources = 0;
  uint32_t collector_writes = 0;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      document = (int)node;
  ASSERT(document >= 0 && collector >= 0);
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type == SHELL_EDGE_WRITE && item->to == (uint32_t)collector &&
        item->source_fd == 1)
      collector_writes++;
    if (item->type != SHELL_EDGE_SUBST || item->to != (uint32_t)document)
      continue;
    if (graph.nodes[item->from].type == SHELL_NODE_DOC) {
      ASSERT(graph.nodes[item->from].doc.kind == SHELL_DOC_FILE);
      ASSERT(item->source_fd == SHELL_DEP_FD_NONE &&
             item->target_fd == SHELL_DEP_FD_NONE);
      file_sources++;
    } else if (item->from == (uint32_t)collector) {
      ASSERT(item->source_fd == SHELL_DEP_FD_NONE &&
             item->target_fd == SHELL_DEP_FD_NONE);
      collector_sources++;
    } else {
      ASSERT(graph.nodes[item->from].type == SHELL_NODE_CMD &&
             item->source_fd == 1);
      command_sources++;
    }
  }
  ASSERT(file_sources == 1 && command_sources == 1 && collector_sources == 1 &&
         collector_writes == 2 && shell_dep_graph_validate(&graph).valid);

  /* Process-substitution bytes remain an ordinary dynamic input relation;
   * they do not require a fake collector when one producer is unambiguous. */
  ASSERT(parse("cat <<EOF\n$(cat < <(printf config))\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
  int root = find_nth_cmd(&graph, 0);
  int nested = find_nth_cmd(&graph, 1);
  int producer = find_nth_cmd(&graph, 2);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      document = (int)node;
  ASSERT(root >= 0 && nested >= 0 && producer >= 0 && document >= 0);
  bool process_input = false;
  bool document_output = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    process_input =
        process_input ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)producer &&
         item->to == (uint32_t)nested && item->source_fd == 1);
    document_output =
        document_output ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)nested &&
         item->to == (uint32_t)document && item->source_fd == 1);
  }
  ASSERT(process_input && document_output && root >= 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$(printf value 2> >(cat))\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
  bool stderr_collector = false;
  bool output_document = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    stderr_collector =
        stderr_collector ||
        (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
         graph.nodes[item->to].type == SHELL_NODE_ENDPOINT);
    output_document = output_document ||
                      (item->type == SHELL_EDGE_SUBST &&
                       graph.nodes[item->to].type == SHELL_NODE_DOC &&
                       graph.nodes[item->to].doc.kind == SHELL_DOC_HEREDOC);
  }
  ASSERT(stderr_collector && output_document &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$( { printf payload; } | ./clock < <(printf config) "
               ")\nEOF",
               &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 4 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 1 &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(group_heredoc_descriptor_substitution_routing) {
  static const struct {
    const char *command;
    bool consumed;
    uint32_t expected_dynamic_consumers;
  } cases[] = {
      {"{ cat <&4; } 3<<EOF 4<&3 3>&-\n$(id)\nEOF", true, 1},
      {"{ cat <&4; } 3<<EOF 3>&- 4<&3\n$(id)\nEOF", false, 0},
  };

  for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
    shell_dep_graph_t graph;
    ASSERT(parse(cases[ci].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
           count_type(&graph, SHELL_NODE_GROUP) == 1 &&
           count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 1 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
    int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    int document = -1;
    uint32_t dynamic_edges = 0;
    bool read_at_fd_four = false;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_DOC &&
          graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
        document = (int)node;
    ASSERT(group >= 0 && document >= 0);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *item = &graph.edges[edge];
      dynamic_edges +=
          item->type == SHELL_EDGE_SUBST && item->to == (uint32_t)document;
      read_at_fd_four =
          read_at_fd_four ||
          (item->type == SHELL_EDGE_READ && item->from == (uint32_t)document &&
           item->to == (uint32_t)group && item->target_fd == 4);
    }
    bool transient =
        graph.nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT;
    ASSERT(dynamic_edges == 1 && read_at_fd_four == cases[ci].consumed &&
           transient == !cases[ci].consumed &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(brace_group_substitution_boundary_matrix) {
  shell_dep_graph_t graph;

  /* A word substitution belongs to the command that consumes its bytes even
   * when that command is a member of a pipeline group.  The group retains the
   * pipeline relation; it must not replace the command as this substitution's
   * consumer. */
  ASSERT(parse("{ echo $(id); } | cat", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  int echo_command = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(echo_command >= 0 && producer >= 0 && group >= 0);
  bool direct_word_flow = false;
  bool group_pipe = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    direct_word_flow =
        direct_word_flow ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)producer &&
         item->to == (uint32_t)echo_command && item->source_fd == 1);
    group_pipe = group_pipe || (item->type == SHELL_EDGE_PIPE &&
                                item->from == (uint32_t)group);
  }
  ASSERT(direct_word_flow && group_pipe &&
         shell_dep_graph_validate(&graph).valid);

  /* The same ownership rule applies to a process-input producer. */
  ASSERT(parse("{ cat < <(printf config); } | sort", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  int consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0);
  bool process_input = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    process_input =
        process_input ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)producer &&
         item->to == (uint32_t)consumer && item->source_fd == 1);
  }
  ASSERT(process_input && shell_dep_graph_validate(&graph).valid);

  /* An output process substitution receives the redirect's actual descriptor
   * rather than being coerced to stdout. */
  ASSERT(parse("{ printf value 3> >(cat); }", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  bool fd_three_write = false;
  bool collector_input = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    fd_three_write = fd_three_write ||
                     (item->type == SHELL_EDGE_WRITE && item->source_fd == 3 &&
                      graph.nodes[item->to].type == SHELL_NODE_ENDPOINT);
    collector_input = collector_input ||
                      (item->type == SHELL_EDGE_SUBST &&
                       graph.nodes[item->from].type == SHELL_NODE_ENDPOINT &&
                       item->target_fd == 0);
  }
  ASSERT(fd_three_write && collector_input &&
         shell_dep_graph_validate(&graph).valid);

  /* Quoted delimiters preserve body bytes and suppress every form of command
   * substitution, including content that resembles a brace-group command. */
  ASSERT(parse("{ cat <<'EOF'\n$( { id; } )\nEOF\n}", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_type(&graph, SHELL_NODE_GROUP) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);
  bool literal_document = false;
  for (uint32_t node = 0; node < graph.node_count; node++)
    literal_document =
        literal_document ||
        (graph.nodes[node].type == SHELL_NODE_DOC &&
         graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC &&
         (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
  ASSERT(literal_document && shell_dep_graph_validate(&graph).valid);

  /* Near-miss brace syntax must fail rather than flattening the substitution
   * into a partial command list. */
  ASSERT(parse("{ echo $(id) }", &graph) == SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(brace_group_process_substitution_routing) {
  shell_dep_graph_t graph;

  /* A process input attached to a compound group supplies the group boundary,
   * rather than being projected onto the first member command. */
  ASSERT(parse("{ cat; } < <(printf config)", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int consumer = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && consumer >= 0 && producer >= 0);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)group, 1, 0) &&
         !has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                   (uint32_t)consumer) &&
         shell_dep_graph_validate(&graph).valid);

  /* Output process substitution retains the redirected descriptor explicitly:
   * the group writes to a collector, and the collector supplies nested stdin.
   */
  ASSERT(parse("{ printf value; } > >(cat)", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int endpoint = find_endpoint(&graph);
  consumer = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && endpoint >= 0 && consumer >= 0);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A process-substitution redirect after the group remains group-owned even
   * when its descriptor is also used in the enclosed list. */
  ASSERT(parse("{ printf value >&3; } 3> >(cat)", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  consumer = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && endpoint >= 0 && consumer >= 0);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Redirect operand scanning keeps separators inside the process-substitution
   * command opaque, so every nested stdin consumer remains group-owned. */
  ASSERT(parse("{ printf value >&3; } 3> >(printf one; cat)", &graph) ==
         SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  ASSERT(group >= 0 && endpoint >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A later process input replaces the pipe on fd 0. A descriptor duplicated
   * before that replacement still retains the pipe on fd 3. */
  ASSERT(parse("printf source | { cat; } 3<&0 < <(printf config)", &graph) ==
         SHELL_DEP_OK);
  int source = find_nth_cmd(&graph, 0);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  producer = find_nth_cmd(&graph, 2);
  ASSERT(source >= 0 && group >= 0 && producer >= 0);
  ASSERT(has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)group, 1, 3) &&
         !has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                       (uint32_t)group, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)group, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* The inner process input already owns the target group's fd 0. The outer
   * output-process redirect therefore has no shell-level stream endpoint: it
   * must not invent an outer WRITE through a collector that bypasses fd 0. */
  ASSERT(parse("printf outer > >({ cat; } < <(printf inner))", &graph) ==
         SHELL_DEP_OK);
  int writer = find_nth_cmd(&graph, 0);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  consumer = find_nth_cmd(&graph, 1);
  producer = find_nth_cmd(&graph, 2);
  ASSERT(
      writer >= 0 && group >= 0 && consumer >= 0 && producer >= 0 &&
      count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
      count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
      count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
      has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                   (uint32_t)group, 1, 0) &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)writer, (uint32_t)group) &&
      shell_dep_graph_validate(&graph).valid);

  /* Quote and escape handling must not close an output process substitution
   * early. A nested word substitution remains a separate dynamic flow into
   * the process-substitution consumer. */
  static const char *const quoted_cases[] = {
      "{ printf value; } 3> >(printf '%s' 'a)')",
      "{ printf value; } 3> >(printf '%s' \\))",
  };
  for (uint32_t i = 0; i < sizeof(quoted_cases) / sizeof(quoted_cases[0]);
       i++) {
    ASSERT(parse(quoted_cases[i], &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
           count_type(&graph, SHELL_NODE_GROUP) == 1 &&
           count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
           count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("{ printf value; } 3> >(printf '%s' \"$(id)\")", &graph) ==
         SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  consumer = find_nth_cmd(&graph, 1);
  producer = find_nth_cmd(&graph, 2);
  ASSERT(group >= 0 && endpoint >= 0 && consumer >= 0 && producer >= 0);
  /* The output-process descriptor belongs to the enclosing printf. The nested
   * `id` is a separate command-substitution producer, not another fd-0 sink
   * for the collector. */
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         !has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                       (uint32_t)producer, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)consumer, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(process_substitution_stream_topology) {
  shell_dep_graph_t graph;

  /* A process substitution used as an argument is not an fd-0 redirect. The
   * producer relation is dynamic, but its target descriptor stays unspecified
   * because the receiving program decides whether it opens that path. */
  ASSERT(parse("cat <(printf config)", &graph) == SHELL_DEP_OK);
  int consumer = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)consumer, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* `>(consumer)` as an argument similarly supplies a path, but the shell
   * cannot claim that the outer program writes any descriptor to it. Retain
   * the nested command without a fabricated dynamic I/O edge. */
  ASSERT(parse("printf >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* Only GROUP edges define structural membership. The nested brace group is
   * an independently parsed word substitution even though its source lies
   * inside the outer group's byte range. Its stdout is already consumed by
   * the enclosing echo and must not be added as a second outer producer. */
  ASSERT(parse("echo $({ echo $({ printf nested; }); })", &graph) ==
         SHELL_DEP_OK);
  int outer_consumer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  ASSERT(outer_consumer >= 0 && consumer >= 0 &&
         count_type(&graph, SHELL_NODE_GROUP) == 2 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         shell_dep_graph_validate(&graph).valid);
  bool outer_group_stream = false;
  bool nested_group_stream = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    if (current->type != SHELL_EDGE_SUBST || current->source_fd != 1 ||
        current->target_fd != SHELL_DEP_FD_NONE ||
        graph.nodes[current->from].type != SHELL_NODE_GROUP)
      continue;
    outer_group_stream =
        outer_group_stream || current->to == (uint32_t)outer_consumer;
    nested_group_stream =
        nested_group_stream || current->to == (uint32_t)consumer;
  }
  ASSERT(outer_group_stream && nested_group_stream);

  /* `< <(...)` redirects the receiving command's stdin from the nested
   * producer. The producer's bytes are dynamic input; whether `sh` treats
   * them as source is deliberately outside the shell grammar. */
  ASSERT(parse("sh < <(printf 'printf nested\\n')", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)consumer, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* `> >(...)` routes the writer's chosen descriptor through a collector to
   * the nested consumer's stdin. Keep the collector instead of fabricating a
   * direct command edge: it represents the distinct redirection endpoint. */
  ASSERT(parse("cat log > >(sh)", &graph) == SHELL_DEP_OK);
  int writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  int endpoint = find_endpoint(&graph);
  ASSERT(writer >= 0 && consumer >= 0 && endpoint >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Append-mode process substitutions use the same descriptor route as
   * output substitutions. `>>` must not leave an APPEND edge to a fake file
   * named `>(sh)`. */
  ASSERT(parse("cat log 2>> >(sh)", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(writer >= 0 && consumer >= 0 && endpoint >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_APPEND) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ printf payload; } 3>> >(cat)", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  consumer = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && endpoint >= 0 && consumer >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_APPEND) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A nested compound consumer remains an explicit group boundary. The
   * collector feeds that boundary; it must not fabricate an endpoint-to-sh
   * edge simply because `sh` is the group's only current member. */
  ASSERT(parse("printf payload > >({ sh; })", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(writer >= 0 && consumer >= 0 && endpoint >= 0 && group >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)group, SHELL_DEP_FD_NONE, 0) &&
         !has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                   (uint32_t)consumer) &&
         shell_dep_graph_validate(&graph).valid);

  /* Cross-direction process substitutions evaluate their nested command but
   * do not establish the redirected byte stream. Do not invert that relation
   * or manufacture a file named after the process-substitution spelling. */
  ASSERT(parse("cat < >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat > <(printf input)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* A redirect need not be separated from its process-substitution operand.
   * `><(` is a compact cross-direction spelling, not the `<>` read/write
   * operator, and therefore creates no fabricated stream. */
  ASSERT(parse("cat><(printf input)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* `<>` has distinct input and output semantics. With an input process
   * substitution it has a real dynamic input route; with an output process
   * substitution its write side feeds the nested consumer. Neither form
   * manufactures the unknown opposite direction. */
  ASSERT(parse("cat <> <(printf input)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)consumer, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <> >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 && endpoint >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)consumer,
                      (uint32_t)endpoint, 0, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)producer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* The graph preserves an explicitly selected descriptor even though the
   * outer command may or may not write it at runtime. */
  ASSERT(parse("cat 3<> >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 && endpoint >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)consumer,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)producer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Source-order routing can replace an output process substitution. The
   * nested command still exists, but an endpoint that receives no outer data
   * must not retain a stale SUBST edge or make the graph invalid. */
  ASSERT(parse("cat log > >(sh) > /tmp/final.out", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  bool final_file_write = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    final_file_write =
        final_file_write ||
        (current->type == SHELL_EDGE_WRITE &&
         current->from == (uint32_t)writer && current->source_fd == 1 &&
         graph.nodes[current->to].type == SHELL_NODE_DOC &&
         graph.nodes[current->to].doc.kind == SHELL_DOC_FILE);
  }
  ASSERT(writer >= 0 && consumer >= 0 && final_file_write &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log <> >(sh) 0> /tmp/final.out", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  final_file_write = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    final_file_write =
        final_file_write ||
        (current->type == SHELL_EDGE_WRITE &&
         current->from == (uint32_t)writer && current->source_fd == 0 &&
         graph.nodes[current->to].type == SHELL_NODE_DOC &&
         graph.nodes[current->to].doc.kind == SHELL_DOC_FILE);
  }
  ASSERT(writer >= 0 && consumer >= 0 && final_file_write &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log > >(sh) 1>&-", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  consumer = find_nth_cmd(&graph, 1);
  ASSERT(writer >= 0 && consumer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* The same source-order replacement applies to a group-owned descriptor. */
  ASSERT(parse("{ printf payload; } > >(sh) > /tmp/final.out", &graph) ==
         SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  consumer = find_nth_cmd(&graph, 1);
  final_file_write = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    final_file_write =
        final_file_write ||
        (current->type == SHELL_EDGE_WRITE &&
         current->from == (uint32_t)group && current->source_fd == 1 &&
         graph.nodes[current->to].type == SHELL_NODE_DOC &&
         graph.nodes[current->to].doc.kind == SHELL_DOC_FILE);
  }
  ASSERT(group >= 0 && consumer >= 0 && final_file_write &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(substitution_descriptor_provenance) {
  static const struct {
    const char *command;
    uint32_t substitution_edges;
  } output_cases[] = {
      {"echo $(printf x)", 1},
      {"echo $(printf x >&-)", 0},
      {"echo $(printf x 1>&2)", 0},
      {"echo $(printf x 1>&1)", 1},
      {"echo $(printf x 2>&1 1>&2)", 1},
      {"echo $({ printf x >&-; })", 0},
      {"echo $({ printf x 2>&1 1>&2; })", 1},
  };

  shell_dep_graph_t graph;
  for (uint32_t i = 0; i < sizeof(output_cases) / sizeof(output_cases[0]);
       i++) {
    ASSERT(parse(output_cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) ==
           output_cases[i].substitution_edges);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const struct {
    const char *command;
    uint32_t substitution_edges;
  } input_cases[] = {
      {"printf x > >(sh)", 1},           {"printf x > >(sh 0<&-)", 0},
      {"printf x > >(sh 0<&1)", 0},      {"printf x > >(sh 0<&0)", 1},
      {"printf x > >({ sh 0<&-; })", 0},
  };
  for (uint32_t i = 0; i < sizeof(input_cases) / sizeof(input_cases[0]); i++) {
    ASSERT(parse(input_cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) ==
           input_cases[i].substitution_edges);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(substitution_scanner_and_flag_contract) {
  shell_dep_graph_t graph = {0};

  ASSERT(parse("echo $(printf value)", &graph) == SHELL_DEP_OK);
  bool saw_shell_word = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    saw_shell_word =
        saw_shell_word ||
        (current->type == SHELL_EDGE_SUBST &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(saw_shell_word && shell_dep_graph_validate(&graph).valid);

  /* The shift operator remains arithmetic while the surrounding command
   * substitution still produces a shell-word inspection edge. */
  ASSERT(parse("echo $(printf '%s' $((1 << 2)))", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 0);
  saw_shell_word = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    saw_shell_word =
        saw_shell_word ||
        (graph.edges[edge].type == SHELL_EDGE_SUBST &&
         (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  ASSERT(saw_shell_word && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <(printf '%s' $((1 << 2)))", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 0);
  bool saw_process_route = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    saw_process_route = saw_process_route ||
                        (graph.edges[edge].type == SHELL_EDGE_SUBST &&
                         graph.edges[edge].flags == SHELL_DEP_EDGE_FLAG_NONE);
  ASSERT(saw_process_route && shell_dep_graph_validate(&graph).valid);

  /* A parenthesis in the deferred body is not the end of `<(...)`. The
   * resulting edge is dynamic descriptor I/O, not shell-word content. */
  static const char nested_heredoc[] = "cat <(cat <<EOF\n)\nEOF\n)";
  ASSERT(parse(nested_heredoc, &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  saw_process_route = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    saw_process_route =
        saw_process_route || (current->type == SHELL_EDGE_SUBST &&
                              current->flags == SHELL_DEP_EDGE_FLAG_NONE);
  }
  ASSERT(saw_process_route && shell_dep_graph_validate(&graph).valid);

  static const char nested_command_heredoc[] = "echo $(cat <<EOF\n)\nEOF\n)";
  ASSERT(parse(nested_command_heredoc, &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  saw_shell_word = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    saw_shell_word =
        saw_shell_word ||
        (current->type == SHELL_EDGE_SUBST &&
         (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(saw_shell_word && shell_dep_graph_validate(&graph).valid);

  /* Redirection-word scanning must retain embedded substitutions as one
   * operand rather than stopping at the space in the nested command. */
  ASSERT(parse("{ echo; } >prefix$(printf /tmp/out)suffix", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) >= 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);
  bool saw_dynamic_name = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    saw_dynamic_name =
        saw_dynamic_name ||
        (graph.edges[edge].type == SHELL_EDGE_SUBST &&
         graph.edges[edge].flags == SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME);
  ASSERT(saw_dynamic_name);

  ASSERT(parse("cat <(cat <<EOF\n)\n", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  pass_count++;
}

TEST(herestring_substitution_topology) {
  shell_dep_graph_t graph = {0};

  /* A here-string is a document consumer: command-substitution bytes enter
   * the document before its actual stdin route reaches the owning command. */
  ASSERT(parse("sh <<< $(cat /etc/shadow)", &graph) == SHELL_DEP_OK);
  int owner = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  int document = find_doc(&graph, SHELL_DOC_HERESTRING);
  ASSERT(owner >= 0 && producer >= 0 && document >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)owner, SHELL_DEP_FD_NONE, 0));
  bool shell_word_document = false;
  for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph.edges[edge_index];
    shell_word_document =
        shell_word_document ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)producer &&
         edge->to == (uint32_t)document &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
         edge->source_fd == 1 && edge->target_fd == SHELL_DEP_FD_NONE);
  }
  ASSERT(shell_word_document && shell_dep_graph_validate(&graph).valid);

  /* An io_number adjoining `<<<` belongs to the redirect, not a synthetic
   * executable command. */
  ASSERT(parse("sh 3<<< payload", &graph) == SHELL_DEP_OK);
  owner = find_nth_cmd(&graph, 0);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  ASSERT(owner >= 0 && document >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 1 &&
         doc_content_equals(&graph.nodes[document].doc, "payload") &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)owner, SHELL_DEP_FD_NONE, 3) &&
         shell_dep_graph_validate(&graph).valid);

  /* The direct file-command form is the same document flow, without
   * manufacturing an executable producer. */
  ASSERT(parse("sh <<< $(</etc/shadow)", &graph) == SHELL_DEP_OK);
  owner = find_nth_cmd(&graph, 0);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  int file = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(owner >= 0 && document >= 0 && file >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)file,
                      (uint32_t)document, SHELL_DEP_FD_NONE,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)owner, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A trailing brace-group redirect has the same document target, but its
   * actual I/O owner is the GROUP endpoint rather than a member command. */
  ASSERT(parse("{ cat; } <<< $(printf value)", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  producer = find_nth_cmd(&graph, 1);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  ASSERT(group >= 0 && producer >= 0 && document >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)group, SHELL_DEP_FD_NONE, 0));
  shell_word_document = false;
  for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph.edges[edge_index];
    shell_word_document =
        shell_word_document ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)producer &&
         edge->to == (uint32_t)document &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(shell_word_document && shell_dep_graph_validate(&graph).valid);

  /* A spaced process-substitution redirect must not hide a later group-tail
   * here-string. The process endpoint and shell-word document retain their
   * independent routes to the group's real I/O owner. */
  ASSERT(parse("{ sh; } > >(cat) <<< \"$(printf payload)\"", &graph) ==
         SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int process_consumer = find_nth_cmd(&graph, 1);
  producer = find_nth_cmd(&graph, 2);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  shell_word_document = false;
  for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph.edges[edge_index];
    shell_word_document =
        shell_word_document ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)producer &&
         edge->to == (uint32_t)document &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(group >= 0 && process_consumer >= 0 && producer >= 0 &&
         document >= 0 && count_type(&graph, SHELL_NODE_CMD) == 3 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)group, SHELL_DEP_FD_NONE, 0) &&
         shell_word_document && shell_dep_graph_validate(&graph).valid);

  /* A later redirect supersedes the here-string's fd 0 route, but the
   * expandable input document remains visible as setup-time shell syntax. */
  ASSERT(parse("sh <<< $(printf stale) </dev/null", &graph) == SHELL_DEP_OK);
  owner = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  bool transient_read = false;
  bool transient_substitution = false;
  for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph.edges[edge_index];
    transient_read = transient_read || (edge->type == SHELL_EDGE_READ &&
                                        edge->from == (uint32_t)document);
    transient_substitution =
        transient_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)producer &&
         edge->to == (uint32_t)document &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(owner >= 0 && producer >= 0 && document >= 0 &&
         (graph.nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) &&
         !transient_read && transient_substitution &&
         shellsplit_test_depgraph_invariants(
             "sh <<< $(printf stale) </dev/null",
             strlen("sh <<< $(printf stale) </dev/null"), SHELL_DEP_OK, &graph,
             &SHELL_DEP_LIMITS_DEFAULT));

  /* Group-tail recovery retains every here-string in source order. The final
   * fd-0 binding reaches the GROUP endpoint; the earlier one is transient. */
  ASSERT(parse("{ cat; } 3>&1 <<< stale 0<<< $(printf live)", &graph) ==
         SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  producer = find_nth_cmd(&graph, 1);
  int stale_document = -1;
  int effective_document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_HERESTRING)
      continue;
    if (doc_content_equals(&graph.nodes[node].doc, "stale"))
      stale_document = (int)node;
    if (doc_content_equals(&graph.nodes[node].doc, "$(printf live)"))
      effective_document = (int)node;
  }
  bool stale_read = false;
  bool effective_read = false;
  bool effective_substitution = false;
  for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
    const shell_dep_edge_t *edge = &graph.edges[edge_index];
    stale_read = stale_read || (edge->type == SHELL_EDGE_READ &&
                                edge->from == (uint32_t)stale_document);
    effective_read =
        effective_read || (edge->type == SHELL_EDGE_READ &&
                           edge->from == (uint32_t)effective_document &&
                           edge->to == (uint32_t)group && edge->target_fd == 0);
    effective_substitution =
        effective_substitution ||
        (edge->type == SHELL_EDGE_SUBST && edge->from == (uint32_t)producer &&
         edge->to == (uint32_t)effective_document &&
         (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
  }
  ASSERT(
      group >= 0 && producer >= 0 && stale_document >= 0 &&
      effective_document >= 0 &&
      (graph.nodes[stale_document].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) &&
      !(graph.nodes[effective_document].doc.flags &
        SHELL_DEP_DOC_FLAG_TRANSIENT) &&
      !stale_read && effective_read && effective_substitution &&
      count_doc_kind(&graph, SHELL_DOC_HERESTRING) == 2 &&
      count_edge_type(&graph, SHELL_EDGE_READ) == 1 &&
      shellsplit_test_depgraph_invariants(
          "{ cat; } 3>&1 <<< stale 0<<< $(printf live)",
          strlen("{ cat; } 3>&1 <<< stale 0<<< $(printf live)"), SHELL_DEP_OK,
          &graph, &SHELL_DEP_LIMITS_DEFAULT));

  /* Quoted source spelling remains literal here-string content. */
  ASSERT(parse("sh <<< '$(cat /etc/shadow)'", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_HERESTRING) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("sh <<< $(cat", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  pass_count++;
}

static bool make_nested_heredoc_substitution(char *command, size_t capacity,
                                             bool process_substitution) {
  int written = snprintf(command, capacity,
                         process_substitution ? "cat <(cat" : "echo $(cat");
  if (written < 0 || (size_t)written >= capacity)
    return false;
  size_t used = (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, " <<H%u", i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, "\n");
  if (written < 0 || (size_t)written >= capacity - used)
    return false;
  used += (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, "body%u\nH%u\n", i, i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, ")");
  return written >= 0 && (size_t)written < capacity - used;
}

TEST(substitution_comment_and_heredoc_capacity) {
  shell_dep_graph_t graph = {0};

  ASSERT(parse("echo $(printf value # )", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  ASSERT(parse("cat <(printf value # )", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("echo $(printf value # )\nprintf done)", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) >= 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) >= 1);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  for (int process_substitution = 0; process_substitution <= 1;
       process_substitution++) {
    char command[512];
    ASSERT(make_nested_heredoc_substitution(command, sizeof(command),
                                            process_substitution != 0));
    ASSERT(parse(command, &graph) == SHELL_DEP_ETRUNC);
    ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
           count_doc_kind(&graph, SHELL_DOC_HEREDOC) <=
               SHELL_DEP_MAX_HEREDOCS &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(brace_group_process_substitution_error_contract) {
  static const char *const invalid[] = {
      "{ sh; } < <(printf",
      "{ printf payload; } > >(sh",
      "{ sh; } < <(printf 'unterminated)",
      "cat >$(printf",
      "{ cat; } >$(printf",
      "export VALUE=$(printf",
      "VALUE=$(printf cat",
      "echo > (printf value)",
      "echo < (printf value)",
      "{ echo; } > (cat)",
      "echo >> (printf value)",
      "cat << (EOF",
  };
  for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(invalid[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0 && graph.cwd_buf.len == 0);
  }
  pass_count++;
}

TEST(brace_group_process_substitution_recursion_limit) {
  char command[512] = "sh";
  for (uint32_t depth = 0; depth < 16; depth++) {
    char nested[sizeof(command)];
    int written = snprintf(nested, sizeof(nested), "{ sh; } < <(%s)", command);
    ASSERT(written > 0 && (size_t)written < sizeof(nested));
    memcpy(command, nested, (size_t)written + 1);
  }

  shell_dep_graph_t graph = {0};
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  char over_limit[sizeof(command)];
  int written =
      snprintf(over_limit, sizeof(over_limit), "{ sh; } < <(%s)", command);
  ASSERT(written > 0 && (size_t)written < sizeof(over_limit));
  ASSERT(parse(over_limit, &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0 && graph.cwd_buf.len == 0);
  pass_count++;
}

TEST(process_substitution_word_limit_contract) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("cat >$(</tmp/dynamic-target)", &graph) == SHELL_DEP_OK);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 2;
  ASSERT(shell_dep_graph_parse("cat >$(printf one; printf two)",
                               strlen("cat >$(printf one; printf two)"), ".",
                               &limits, &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  ASSERT(shell_dep_graph_parse(
             "cat >$(printf one; printf two; printf three)",
             strlen("cat >$(printf one; printf two; printf three)"), ".",
             &limits, &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  limits.max_nodes = 1;
  ASSERT(shell_dep_graph_parse("printf >(sh)", strlen("printf >(sh)"), ".",
                               &limits, &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(heredoc_count_substitution_capacity) {
  static const char at_limit[] =
      "cat <<A <<B <<C <<D <<E <<F <<G <<H\n"
      "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
      "seven\nG\n$(id)\nH\n";
  static const char overflow[] =
      "cat <<A <<B <<C <<D <<E <<F <<G <<H <<I\n"
      "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
      "seven\nG\neight\nH\n$(id)\nI\n";
  static const char malformed_overflow[] =
      "cat <<A <<B <<C <<D <<E <<F <<G <<H <<I\n"
      "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
      "seven\nG\neight\nH\n$(id)\n";
  shell_dep_graph_t graph;
  ASSERT(parse(at_limit, &graph) == SHELL_DEP_OK);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_HEREDOC) == SHELL_DEP_MAX_HEREDOCS &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  uint32_t transient_count = 0;
  uint32_t live_reads = 0;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_HEREDOC)
      transient_count +=
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    live_reads +=
        graph.edges[edge].type == SHELL_EDGE_READ &&
        graph.nodes[graph.edges[edge].from].type == SHELL_NODE_DOC &&
        graph.nodes[graph.edges[edge].from].doc.kind == SHELL_DOC_HEREDOC;
  ASSERT(transient_count == SHELL_DEP_MAX_HEREDOCS - 1 && live_reads == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse(overflow, &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_HEREDOC) <= SHELL_DEP_MAX_HEREDOCS);
  ASSERT(shellsplit_test_depgraph_invariants(overflow, strlen(overflow),
                                             SHELL_DEP_ETRUNC, &graph,
                                             &SHELL_DEP_LIMITS_DEFAULT));

  ASSERT(parse(malformed_overflow, &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR);
  ASSERT(shellsplit_test_depgraph_invariants(
      malformed_overflow, strlen(malformed_overflow), SHELL_DEP_EPARSE, &graph,
      &SHELL_DEP_LIMITS_DEFAULT));
  pass_count++;
}

TEST(substitution_operand_matrix) {
  static const struct {
    const char *command;
    shell_dep_edge_type_t io_type;
    bool read_write;
  } cases[] = {
      {"cat >$(id)", SHELL_EDGE_WRITE, false},
      {"cat >\"$(id)\"", SHELL_EDGE_WRITE, false},
      {"cat <\"$(id)\"", SHELL_EDGE_READ, false},
      {"cat >>\"$(id)\"", SHELL_EDGE_APPEND, false},
      {"cat >|\"$(id)\"", SHELL_EDGE_WRITE, false},
      {"cat <>\"$(id)\"", SHELL_EDGE_READ, true},
  };
  shell_dep_graph_t graph;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int owner = find_nth_cmd(&graph, 0);
    int producer = find_nth_cmd(&graph, 1);
    int document = -1;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_DOC &&
          graph.nodes[node].doc.kind == SHELL_DOC_FILE &&
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0)
        document = (int)node;
    ASSERT(owner >= 0 && producer >= 0 && document >= 0 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);

    bool pathname_flow = false;
    bool shell_word_flow = false;
    bool expected_io = false;
    bool paired_io = !cases[i].read_write;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *current = &graph.edges[edge];
      pathname_flow =
          pathname_flow ||
          (current->type == SHELL_EDGE_SUBST &&
           current->from == (uint32_t)producer &&
           current->to == (uint32_t)document && current->source_fd == 1 &&
           current->target_fd == SHELL_DEP_FD_NONE &&
           current->flags == SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME);
      shell_word_flow =
          shell_word_flow ||
          (current->type == SHELL_EDGE_SUBST &&
           (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
      expected_io =
          expected_io ||
          (current->type == cases[i].io_type &&
           ((cases[i].io_type == SHELL_EDGE_READ &&
             current->from == (uint32_t)document &&
             current->to == (uint32_t)owner && current->target_fd == 0) ||
            (cases[i].io_type != SHELL_EDGE_READ &&
             current->from == (uint32_t)owner &&
             current->to == (uint32_t)document && current->source_fd == 1)));
      if (cases[i].read_write)
        paired_io = paired_io || (current->type == SHELL_EDGE_WRITE &&
                                  current->from == (uint32_t)owner &&
                                  current->to == (uint32_t)document &&
                                  current->source_fd == 0);
    }
    ASSERT(pathname_flow && !shell_word_flow && expected_io && paired_io &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* The pathname-selection relation remains even when a later close replaces
   * the descriptor, but no obsolete file WRITE edge claims fd 3 stays open. */
  ASSERT(parse("3>\"$(id)\" 3>&-", &graph) == SHELL_DEP_OK);
  bool dynamic_target = false;
  bool pathname_flow = false;
  int producer = find_nth_cmd(&graph, 1);
  int document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_FILE) {
      dynamic_target =
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0;
      if (dynamic_target)
        document = (int)node;
    }
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    pathname_flow =
        pathname_flow ||
        (graph.edges[edge].type == SHELL_EDGE_SUBST &&
         graph.edges[edge].from == (uint32_t)producer &&
         graph.edges[edge].to == (uint32_t)document &&
         graph.edges[edge].flags == SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME);
  ASSERT(dynamic_target && pathname_flow &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ cat; } >\"$(id)\"", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  producer = find_nth_cmd(&graph, 1);
  document = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_FILE &&
        (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0)
      document = (int)node;
  ASSERT(group >= 0 && producer >= 0 && document >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE));
  pathname_flow = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    pathname_flow =
        pathname_flow ||
        (graph.edges[edge].type == SHELL_EDGE_SUBST &&
         graph.edges[edge].from == (uint32_t)producer &&
         graph.edges[edge].to == (uint32_t)document &&
         graph.edges[edge].flags == SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME);
  ASSERT(pathname_flow && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("VALUE=\"$(id)\" printf '%s\\n' \"$VALUE\"", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_document_scope) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t kind;
    const char *name;
    const char *value;
  } cases[] = {
      {"{ cat; cat; } <<EOF\npayload\nEOF", SHELL_DOC_HEREDOC, "EOF",
       "payload"},
      {"{ cat; cat; } <<-'EOF'\n\tpayload\n\tEOF", SHELL_DOC_HEREDOC, "EOF",
       "payload"},
      {"{ cat; cat; } <<EOF\r\npayload\r\nEOF\r\n", SHELL_DOC_HEREDOC, "EOF",
       "payload\r"},
      {"{ cat; cat; } <<-\"EOF\"\r\n\tpayload\r\n\tEOF\r\n", SHELL_DOC_HEREDOC,
       "EOF", "payload\r"},
      {"{ cat; cat; } <<< \"two words\"", SHELL_DOC_HERESTRING, NULL,
       "\"two words\""},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_GROUP) == 1);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2);
    ASSERT(count_doc_kind(&graph, cases[i].kind) == 1);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);

    int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    bool group_reads = false;
    bool document_found = false;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      if (graph.nodes[n].type != SHELL_NODE_DOC ||
          graph.nodes[n].doc.kind != cases[i].kind)
        continue;
      document_found = true;
      ASSERT(doc_content_equals(&graph.nodes[n].doc, cases[i].value));
      if (cases[i].name)
        ASSERT_STRN_EQ(graph.nodes[n].doc.name, graph.nodes[n].doc.name_len,
                       cases[i].name);
      for (uint32_t e = 0; e < graph.edge_count; e++) {
        if (graph.edges[e].from != n || graph.edges[e].type != SHELL_EDGE_READ)
          continue;
        group_reads = group >= 0 && graph.edges[e].to == (uint32_t)group;
      }
    }
    ASSERT(document_found && group_reads);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(brace_group_local_document_scope) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t kind;
    const char *name;
    const char *value;
  } cases[] = {
      {"{ cat <<\"A B\"; printf after; }\nbody\nA B\n", SHELL_DOC_HEREDOC,
       "A B", "body"},
      {"{ cat <<<value; printf after; }", SHELL_DOC_HERESTRING, NULL, "value"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    ASSERT(group >= 0 && count_type(&graph, SHELL_NODE_CMD) == 2 &&
           count_doc_kind(&graph, cases[i].kind) == 1 &&
           count_edge_type(&graph, SHELL_EDGE_READ) == 1);

    bool document_found = false;
    bool command_read = false;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const shell_dep_node_t *current = &graph.nodes[node];
      if (current->type != SHELL_NODE_DOC || current->doc.kind != cases[i].kind)
        continue;
      document_found = true;
      ASSERT(doc_content_equals(&current->doc, cases[i].value));
      if (cases[i].name)
        ASSERT_STRN_EQ(current->doc.name, current->doc.name_len, cases[i].name);
      for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
        const shell_dep_edge_t *relation = &graph.edges[edge];
        if (relation->type != SHELL_EDGE_READ || relation->from != node)
          continue;
        command_read =
            graph.nodes[relation->to].type == SHELL_NODE_CMD &&
            has_edge(&graph, SHELL_EDGE_GROUP, (uint32_t)group, relation->to);
      }
    }
    ASSERT(document_found && command_read &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(brace_group_multiple_documents) {
  const char *command = "{ cat; cat; } <<A <<-'B'\n"
                        "one\n"
                        "A\n"
                        "\ttwo\n"
                        "\tB\n";
  shell_dep_graph_t graph;
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_GROUP) == 1);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 2);
  /* Both documents are parsed, but the second fd-0 redirect is the effective
   * stdin source. The first remains represented as document syntax only. */
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  bool found_a = false;
  bool found_b = false;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    const shell_dep_node_t *node = &graph.nodes[i];
    if (node->type != SHELL_NODE_DOC || node->doc.kind != SHELL_DOC_HEREDOC)
      continue;
    if (node->doc.name_len == 1 && node->doc.name[0] == 'A') {
      ASSERT(doc_content_equals(&node->doc, "one"));
      found_a = true;
    } else if (node->doc.name_len == 1 && node->doc.name[0] == 'B') {
      ASSERT(doc_content_equals(&node->doc, "two"));
      found_b = true;
    }
  }
  ASSERT(found_a && found_b);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_document_pipeline_composition) {
  const char *command =
      "{ cat; cat; } <<EOF | sort > /tmp/brace.out 2>>/tmp/brace.err\n"
      "payload\n"
      "EOF";
  shell_dep_graph_t graph;
  ASSERT(parse(command, &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_GROUP) == 1);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 1);
  ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 2);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_APPEND) == 1);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_document_capacity) {
  const char *command = "{ cat; cat; } <<EOF\npayload\nEOF";
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 4;
  limits.max_edges = 4;
  shell_dep_graph_t graph = {0};
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &graph) == SHELL_DEP_OK);
  ASSERT(!(graph.status & SHELL_DEP_STATUS_TRUNCATED));
  ASSERT(count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 1);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_READ) == 1);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  limits.max_edges = 2;
  memset(&graph, 0, sizeof(graph));
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &graph) == SHELL_DEP_ETRUNC);
  ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(graph.edge_count <= limits.max_edges);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(brace_group_document_limit_cross_product) {
  const char *command = "{ { { cat; cat; } ; } ; } <<A <<B\n"
                        "one\n"
                        "A\n"
                        "two\n"
                        "B\n";
  shell_dep_graph_t baseline;
  ASSERT(parse(command, &baseline) == SHELL_DEP_OK);
  ASSERT(count_type(&baseline, SHELL_NODE_GROUP) == 3);
  ASSERT(count_doc_kind(&baseline, SHELL_DOC_HEREDOC) == 2);
  ASSERT(count_edge_type(&baseline, SHELL_EDGE_READ) == 1);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 5;
  limits.max_edges = 5;
  shell_dep_graph_t limited = {0};
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &limited) == SHELL_DEP_ETRUNC);
  ASSERT(limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(limited.node_count <= limits.max_nodes);
  ASSERT(limited.edge_count <= limits.max_edges);
  ASSERT(shell_dep_graph_validate(&limited).valid);

  pass_count++;
}

TEST(heredoc_substitution_limit_cross_product) {
  static const char command[] = "cat <<EOF\n$(printf one; printf two)\nEOF";
  shell_dep_graph_t baseline;
  ASSERT(parse(command, &baseline) == SHELL_DEP_OK);
  ASSERT(count_type(&baseline, SHELL_NODE_CMD) == 3 &&
         count_type(&baseline, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&baseline, SHELL_DOC_HEREDOC) == 1);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 3;
  limits.max_edges = 3;
  shell_dep_graph_t limited = {0};
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &limited) == SHELL_DEP_ETRUNC);
  ASSERT(limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(limited.node_count <= limits.max_nodes);
  ASSERT(limited.edge_count <= limits.max_edges);
  ASSERT(shell_dep_graph_validate(&limited).valid);

  /* Constrain the nested graph itself, not merely the append into the parent.
   * The parent remains valid and reports a bounded partial graph. */
  limits.max_nodes = 2;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
  memset(&limited, 0, sizeof(limited));
  ASSERT(shell_dep_graph_parse(command, strlen(command), ".", &limits,
                               &limited) == SHELL_DEP_ETRUNC);
  ASSERT(limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(limited.node_count <= limits.max_nodes);
  ASSERT(shell_dep_graph_validate(&limited).valid);
  pass_count++;
}

/* --- ERROR HANDLING --- */

TEST(reused_output_contract) {
  static const struct {
    const char *command;
    shell_dep_edge_type_t edge_type;
    bool cd_as_cmd;
  } edge_cases[] = {
      {"FOO=bar env", SHELL_EDGE_ENV, false},
      {"cat < /tmp/input", SHELL_EDGE_READ, false},
      {"printf value /tmp/output", SHELL_EDGE_ARG, false},
      {"{ echo; }", SHELL_EDGE_GROUP, false},
      {"cd /tmp; pwd", SHELL_EDGE_CWD, true},
      {"echo one; echo two", SHELL_EDGE_SEQ, false},
  };
  shell_dep_graph_t graph;
  memset(&graph, 0xA5, sizeof(graph));

  for (size_t i = 0; i < sizeof(edge_cases) / sizeof(edge_cases[0]); i++) {
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    limits.cd_as_cmd = edge_cases[i].cd_as_cmd;
    ASSERT(shell_dep_graph_parse(edge_cases[i].command,
                                 strlen(edge_cases[i].command), ".", &limits,
                                 &graph) == SHELL_DEP_OK);
    ASSERT(graph.cwd_buf.len > 0);
    if (count_edge_type(&graph, edge_cases[i].edge_type) == 0) {
      printf("    reused graph case %zu missing edge %s\n", i,
             shell_dep_edge_type_name(edge_cases[i].edge_type));
      shell_dep_graph_dump(&graph, stdout);
      fail_count++;
      return;
    }
    ASSERT(shell_dep_graph_validate(&graph).valid);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      ASSERT(graph.edges[edge].flags == SHELL_DEP_EDGE_FLAG_NONE);
  }

  static const struct {
    const char *command;
    shell_dep_error_t error;
    uint32_t status;
  } early_cases[] = {
      {" \t\n", SHELL_DEP_OK, SHELL_DEP_STATUS_OK},
      {"echo \"unterminated", SHELL_DEP_EPARSE, SHELL_DEP_STATUS_ERROR},
      {"while true; do :; done", SHELL_DEP_EPARSE, SHELL_DEP_STATUS_ERROR},
  };
  for (size_t i = 0; i < sizeof(early_cases) / sizeof(early_cases[0]); i++) {
    ASSERT(shell_dep_graph_parse(early_cases[i].command,
                                 strlen(early_cases[i].command), ".", NULL,
                                 &graph) == early_cases[i].error);
    if (graph.node_count != 0 || graph.edge_count != 0 ||
        graph.cwd_buf.len != 0 || graph.status != early_cases[i].status) {
      printf("    reused graph early case %zu retained output\n", i);
      shell_dep_graph_dump(&graph, stdout);
      fail_count++;
      return;
    }
  }
  pass_count++;
}

TEST(null_input) {
  shell_dep_graph_t g;
  memset(&g, 0xA5, sizeof(g));
  shell_dep_error_t err = shell_dep_graph_parse(NULL, 0, ".", NULL, &g);
  ASSERT(err == SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 && g.cwd_buf.len == 0);
  ASSERT(g.status == SHELL_DEP_STATUS_ERROR);
  pass_count++;
}

TEST(null_output) {
  shell_dep_error_t err = shell_dep_graph_parse("ls", 2, ".", NULL, NULL);
  ASSERT(err == SHELL_DEP_EINPUT);
  pass_count++;
}

TEST(empty_input) {
  shell_dep_graph_t g;
  memset(&g, 0xA5, sizeof(g));
  shell_dep_error_t err = shell_dep_graph_parse("", 0, ".", NULL, &g);
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
  ASSERT(shell_dep_graph_parse("x", 1, ".", &limits, &g) == SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 &&
         g.status == SHELL_DEP_STATUS_ERROR && g.cwd_buf.len == 0);
#if SIZE_MAX > UINT32_MAX
  memset(&g, 0xA5, sizeof(g));
  ASSERT(shell_dep_graph_parse("x", (size_t)UINT32_MAX + 1, ".", NULL, &g) ==
         SHELL_DEP_EINPUT);
  ASSERT(g.node_count == 0 && g.edge_count == 0 &&
         g.status == SHELL_DEP_STATUS_ERROR && g.cwd_buf.len == 0);
#endif
  pass_count++;
}

TEST(parse_error) {
  static const char *const malformed[] = {
      "unclosed \"quote",
      "echo $(unterminated",
      "{ echo; ",
      "cat <<EOF\nbody\n",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(malformed[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
           graph.cwd_buf.len == 0);
  }
  shell_dep_graph_t g = {0};
  const char invalid[] = "\x80";
  ASSERT(shell_dep_graph_parse(invalid, sizeof(invalid) - 1, ".", NULL, &g) ==
         SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(dialect_boundary_matrix) {
  static const char *cases[] = {
      "foo() { echo hi; }",
      "function foo { echo hi; }",
      "case value in x) echo x ;; esac",
      "for ((i=0; i<2; i++)); do echo $i; done",
      "for value in one two; do echo $value; done",
      "if test -f file; then echo yes; else echo no; fi",
      "while read line; do echo $line; done",
      "until test -f file; do sleep 1; done",
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
      "echo if then elif else fi while until for do done case in esac function",
      "echo 'if' \"while\" \\for",
      "# if true; then\nprintf case",
      "command if then",
      "NAME=value printf until",
      "echo $(printf if while until for case)",
      "cat <(printf if while until for case)",
      "echo {",
      "echo }",
  };
  for (size_t i = 0; i < sizeof(literal_cases) / sizeof(literal_cases[0]);
       i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(literal_cases[i], &graph);
    ASSERT(error == SHELL_DEP_OK);
    ASSERT(graph.status == SHELL_DEP_STATUS_OK);
    ASSERT(graph.node_count > 0 && shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(nested_parse_error_matrix) {
  static const char *cases[] = {
      "{ if test -f file; then echo yes; fi; }",
      "( while read line; do echo $line; done )",
      "echo $(until test -f file; do sleep 1; done)",
      "cat <(for value in one; do echo $value; done)",
      "cat <<EOF\n$(case value in value) echo yes;; esac)\nEOF",
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
    shell_dep_error_t error;
    uint32_t node_count;
    uint32_t edge_count;
    uint32_t command_tokens;
  } cases[] = {
      {"cmd1 ; cmd2", {1, 8, 8, 0, false}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo hi > out.txt", {8, 0, 8, 0, false}, SHELL_DEP_ETRUNC, 1, 0, 2},
      {"echo hello", {8, 8, 1, 0, false}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"cd /tmp && ls", {8, 8, 8, 4, false}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo $(cat /etc/hosts)",
       {2, 8, 8, 0, false},
       SHELL_DEP_ETRUNC,
       1,
       0,
       2},
      {"c 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 "
       "24 25 26 27 28 29 30 31 32 33",
       {64, 64, SHELL_DEP_MAX_TOKENS, 0, false},
       SHELL_DEP_ETRUNC,
       1,
       0,
       SHELL_DEP_MAX_TOKENS},
      {"echo hello",
       {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, false},
       SHELL_DEP_OK,
       1,
       0,
       2},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    memset(&g, 0, sizeof(g));
    shell_dep_error_t error = shell_dep_graph_parse(
        cases[i].command, strlen(cases[i].command), ".", &cases[i].limits, &g);
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
    ASSERT(shell_dep_graph_validate(&g).valid);
  }

  shell_dep_limits_t cd_limits = SHELL_DEP_LIMITS_DEFAULT;
  cd_limits.cd_as_cmd = true;
  shell_dep_graph_t g;
  ASSERT(shell_dep_graph_parse("cd /tmp && pwd", 14, "/home/user", &cd_limits,
                               &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT(count_edge_type(&g, SHELL_EDGE_CWD) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_ARG) == 1);
  ASSERT(count_edge_type(&g, SHELL_EDGE_AND) == 1);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[2].cmd.cwd_offset), "/tmp");
  ASSERT(shell_dep_graph_validate(&g).valid);
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
        shell_dep_graph_parse(command, strlen(command), ".", &limits, &graph);
    if (error != bounds[i].expected)
      printf("    nested limit row %zu: got %s, expected %s\n", i,
             shell_dep_error_string(error),
             shell_dep_error_string(bounds[i].expected));
    ASSERT(error == bounds[i].expected);
    ASSERT(shellsplit_test_depgraph_invariants(command, strlen(command), error,
                                               &graph, &limits));
  }

  char nested[256] = "id";
  for (size_t depth = 0; depth <= 16; depth++) {
    char next[sizeof(nested)];
    int written = snprintf(next, sizeof(next), "echo $(%s)", nested);
    ASSERT(written > 0 && (size_t)written < sizeof(next));
    memcpy(nested, next, (size_t)written + 1);
  }
  shell_dep_graph_t graph;
  shell_dep_error_t error = shell_dep_graph_parse(
      nested, strlen(nested), ".", &SHELL_DEP_LIMITS_DEFAULT, &graph);
  ASSERT(error == SHELL_DEP_EPARSE);
  ASSERT(shellsplit_test_depgraph_invariants(
      nested, strlen(nested), error, &graph, &SHELL_DEP_LIMITS_DEFAULT));

  char heredoc_nested[512];
  int heredoc_length = snprintf(heredoc_nested, sizeof(heredoc_nested),
                                "cat <<EOF\n$(%s)\nEOF", nested);
  ASSERT(heredoc_length > 0 && (size_t)heredoc_length < sizeof(heredoc_nested));
  error = shell_dep_graph_parse(heredoc_nested, (size_t)heredoc_length, ".",
                                &SHELL_DEP_LIMITS_DEFAULT, &graph);
  ASSERT(error == SHELL_DEP_EPARSE);
  ASSERT(shellsplit_test_depgraph_invariants(
      heredoc_nested, (size_t)heredoc_length, error, &graph,
      &SHELL_DEP_LIMITS_DEFAULT));

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
      "echo $(<file)",
      "cat <<EOF\nhello\nEOF",
      "cat <<< ''",
      "FOO= cmd",
      "cat /etc/passwd | grep root > /tmp/result.txt",
  };

  for (size_t i = 0; i < sizeof(valid_commands) / sizeof(valid_commands[0]);
       i++) {
    shell_dep_graph_t g;
    ASSERT(parse(valid_commands[i], &g) == SHELL_DEP_OK);
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }

  shell_dep_graph_t g;
  ASSERT(parse("cmd1 | cmd2", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count > 0);
  g.edges[0].to = g.node_count;
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(validation.errors[0].edge_idx == 0);
  ASSERT(strstr(validation.errors[0].msg, "OOB") != NULL);

  ASSERT(parse("echo hello > out.txt", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count > 0);
  g.edges[0].type = SHELL_EDGE_READ;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("echo $(<file)", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count == 1);
  g.edges[0].source_fd = 0;
  g.edges[0].target_fd = SHELL_DEP_FD_NONE;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("echo $(id)", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count == 1);
  g.edges[0].flags = SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("echo $(id)", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count == 1);
  g.edges[0].target_fd = 0;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("cat <<EOF\n$(id)\nEOF", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count >= 2);
  uint32_t inline_substitution = UINT32_MAX;
  for (uint32_t edge = 0; edge < g.edge_count; edge++)
    if (g.edges[edge].type == SHELL_EDGE_SUBST &&
        (g.edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
        g.nodes[g.edges[edge].to].type == SHELL_NODE_DOC)
      inline_substitution = edge;
  ASSERT(inline_substitution != UINT32_MAX);
  g.edges[inline_substitution].flags = SHELL_DEP_EDGE_FLAG_NONE;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("cmd1 | cmd2", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count == 1);
  g.edges[0].source_fd = SHELL_DEP_FD_MAX + 1u;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "descriptor outside") != NULL);

  ASSERT(parse("cat < /tmp/input", &g) == SHELL_DEP_OK);
  ASSERT(g.edge_count == 1);
  g.edges[0].target_fd = SHELL_DEP_FD_MAX + 1u;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "descriptor outside") != NULL);

  ASSERT(parse("ls", &g) == SHELL_DEP_OK);
  int command_index = find_first_cmd(&g);
  ASSERT(command_index >= 0);
  g.nodes[command_index].cmd.cwd_offset = (uint32_t)g.cwd_buf.len;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "cwd_offset") != NULL);

  memset(&g, 0, sizeof(g));
  g.node_count = 1;
  g.nodes[0].type = SHELL_NODE_CMD;
  g.cwd_buf.data[0] = 'x';
  g.cwd_buf.len = 1;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "NUL-terminated") != NULL);

  ASSERT(parse("cmd1 | cmd2", &g) == SHELL_DEP_OK);
  g.edges[0].type = (shell_dep_edge_type_t)UINT32_MAX;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "invalid edge type") != NULL);
  pass_count++;
}

TEST(validation_rejects_malformed_endpoint_metadata) {
  shell_dep_graph_t graph = {0};
  graph.node_count = 1;
  graph.nodes[0].type = SHELL_NODE_ENDPOINT;
  graph.nodes[0].endpoint.reserved = UINT8_MAX;
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count >= 1);
  ASSERT(strstr(validation.errors[0].msg, "unknown endpoint") != NULL);

  memset(&graph, 0, sizeof(graph));
  graph.node_count = 2;
  graph.cwd_buf.data[0] = '.';
  graph.cwd_buf.data[1] = '\0';
  graph.cwd_buf.len = 2;
  graph.nodes[0].type = SHELL_NODE_CMD;
  graph.nodes[1].type = SHELL_NODE_CMD;
  graph.edges[0] = (shell_dep_edge_t){
      .from = 0,
      .to = 1,
      .type = SHELL_EDGE_SEQ,
      .dir = SHELL_DIR_FORWARD,
      .flags = SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
  graph.edge_count = 1;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "invalid flags") != NULL);

  graph.edges[0].flags = SHELL_DEP_EDGE_FLAG_NONE;
  graph.edges[0].type = (shell_dep_edge_type_t)UINT32_MAX;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "invalid edge type") != NULL);
  pass_count++;
}

TEST(validation_rejects_corrupt_counts_documents_and_endpoint_shapes) {
  shell_dep_graph_t graph = {0};
  shell_dep_graph_validation_t validation;

  graph.node_count = SHELL_DEP_MAX_NODES + 1u;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "node_count") != NULL);

  memset(&graph, 0, sizeof(graph));
  graph.edge_count = SHELL_DEP_MAX_EDGES + 1u;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "edge_count") != NULL);

  memset(&graph, 0, sizeof(graph));
  graph.cwd_buf.len = SHELL_DEP_CWD_BUF_SIZE + 1u;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "cwd_buf.len") != NULL);

  ASSERT(parse("cat < /tmp/input", &graph) == SHELL_DEP_OK);
  int document = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(document >= 0);
  graph.nodes[document].doc.kind = (shell_dep_doc_kind_t)UINT8_MAX;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "DOC node"));

  ASSERT(parse("cat < /tmp/input", &graph) == SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(document >= 0);
  graph.nodes[document].doc.flags = SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "DOC node"));

  ASSERT(parse("cat < /tmp/input", &graph) == SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(document >= 0);
  graph.nodes[document].doc.path = NULL;
  graph.nodes[document].doc.path_len = 1;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "DOC node"));

  ASSERT(parse("cat <<EOF\nbody\nEOF", &graph) == SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_HEREDOC);
  ASSERT(document >= 0);
  graph.nodes[document].doc.flags |= SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "DOC node"));

  ASSERT(parse("printf x > >(sh)", &graph) == SHELL_DEP_OK);
  int collector = find_endpoint(&graph);
  ASSERT(collector >= 0 && graph.nodes[collector].endpoint.reserved == 0);
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].to == (uint32_t)collector)
      graph.edges[edge].type = SHELL_EDGE_PIPE;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "ENDPOINT"));

  /* A redirected pipeline reader retains the producer through a terminal
   * endpoint. It accepts only incoming PIPE edges and no consumers. */
  ASSERT(parse("printf x | { cat; } < /tmp/input", &graph) == SHELL_DEP_OK);
  int terminal = -1;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if (graph.nodes[i].type == SHELL_NODE_ENDPOINT &&
        graph.nodes[i].endpoint.reserved != 0)
      terminal = (int)i;
  ASSERT(terminal >= 0 && shell_dep_graph_validate(&graph).valid);
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].to == (uint32_t)terminal)
      graph.edges[edge].type = SHELL_EDGE_WRITE;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "ENDPOINT"));

  ASSERT(parse("printf x | { cat; } < /tmp/input", &graph) == SHELL_DEP_OK);
  terminal = -1;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if (graph.nodes[i].type == SHELL_NODE_ENDPOINT &&
        graph.nodes[i].endpoint.reserved != 0)
      terminal = (int)i;
  ASSERT(terminal >= 0 && graph.edge_count < SHELL_DEP_MAX_EDGES);
  graph.edges[graph.edge_count++] = (shell_dep_edge_t){
      .from = (uint32_t)terminal,
      .to = 0,
      .type = SHELL_EDGE_SUBST,
      .dir = SHELL_DIR_FORWARD,
      .flags = SHELL_DEP_EDGE_FLAG_NONE,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && strstr(validation.errors[0].msg, "ENDPOINT"));
  pass_count++;
}

TEST(validation_rejects_malformed_group_metadata) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("{ { echo inner; }; }", &graph) == SHELL_DEP_OK);
  int outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int inner =
      outer >= 0 ? find_group(&graph, SHELL_GROUP_BRACE, (uint32_t)outer) : -1;
  ASSERT(outer >= 0 && inner >= 0);
  graph.nodes[inner].group.parent = (uint32_t)inner;
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count > 0);
  ASSERT(strstr(validation.errors[0].msg, "GROUP node") != NULL);

  static const uint8_t invalid_kinds[] = {
      0,
      SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL,
      UINT8_MAX,
  };
  for (uint32_t kind = 0;
       kind < sizeof(invalid_kinds) / sizeof(invalid_kinds[0]); kind++) {
    ASSERT(parse("{ echo inner; }", &graph) == SHELL_DEP_OK);
    outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    ASSERT(outer >= 0);
    graph.nodes[outer].group.kind = invalid_kinds[kind];
    validation = shell_dep_graph_validate(&graph);
    ASSERT(!validation.valid && validation.error_count == 1);
    ASSERT(strstr(validation.errors[0].msg, "invalid kind") != NULL);
  }

  ASSERT(parse("{ echo inner; }", &graph) == SHELL_DEP_OK);
  outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int command = find_first_cmd(&graph);
  ASSERT(outer >= 0 && command >= 0);
  uint32_t member_edge = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_GROUP &&
        graph.edges[edge].from == (uint32_t)outer &&
        graph.edges[edge].to == (uint32_t)command)
      member_edge = edge;
  ASSERT(member_edge != UINT32_MAX);
  graph.edges[member_edge].dir = SHELL_DIR_UNDIR;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "invalid direction") != NULL);

  ASSERT(parse("{ echo inner; }", &graph) == SHELL_DEP_OK);
  outer = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  command = find_first_cmd(&graph);
  ASSERT(outer >= 0 && command >= 0);
  member_edge = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_GROUP &&
        graph.edges[edge].from == (uint32_t)outer &&
        graph.edges[edge].to == (uint32_t)command)
      member_edge = edge;
  ASSERT(member_edge != UINT32_MAX);
  graph.edges[member_edge].source_fd = 1;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
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
  ASSERT(parse("echo $(id)", &g) == SHELL_DEP_OK);
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
  ASSERT(strstr(text, "PIPE[1:0]") != NULL);
  ASSERT(strstr(text, "ARG[4294967295:4294967295] <>") != NULL);
  ASSERT(strstr(text, "SUBST[1:4294967295]") != NULL);
  ASSERT(strstr(text, "flags=0x1") != NULL);
  ASSERT(fclose(output) == 0);
  pass_count++;
}

TEST(name_helpers) {
  static const char *edge_names[] = {"READ", "WRITE", "APPEND", "PIPE",
                                     "ARG",  "ENV",   "SUBST",  "SEQ",
                                     "AND",  "OR",    "CWD",    "BACKGROUND",
                                     "GROUP"},
                    *node_names[] = {"CMD", "DOC", "GROUP", "ENDPOINT"},
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
  RUN(supplied_fast_parser_contract);

  printf("\nOperators:\n");
  RUN(operator_matrix);

  printf("\nRedirects:\n");
  RUN(redirect_matrix);

  printf("\nCWD Tracking:\n");
  RUN(cwd_matrix);
  RUN(composition_metadata_matrix);
  RUN(posix_brace_group_pipeline);
  RUN(posix_brace_group_input_and_redirect);
  RUN(compound_group_input_redirect_overrides_pipe);
  RUN(effective_descriptor_routing);
  RUN(sibling_brace_group_pipeline_endpoints);
  RUN(nested_brace_group_pipeline_scope);
  RUN(internal_brace_group_pipeline_stays_internal);
  RUN(brace_group_redirect_list_scope);
  RUN(compound_group_io_endpoints);
  RUN(compound_group_leading_redirect_endpoints);
  RUN(compound_group_read_write_redirect);
  RUN(compound_group_descriptor_operations_preserve_known_routes);
  RUN(compound_group_heredoc_descriptor_relations);
  RUN(canonical_heredoc_delimiter_contract);
  RUN(compound_group_leading_descriptor_operations);
  RUN(nested_compound_group_redirect_ownership);
  RUN(brace_group_aggregate_control_scope);
  RUN(nested_brace_group_aggregate_control_scope);
  RUN(brace_group_cwd_scope);
  RUN(substitution_word_boundary_contract);
  RUN(brace_group_capacity_contract);
  RUN(comment_matrix);

  printf("\nEnvironment Variables:\n");
  RUN(environment_matrix);

  printf("\nFile Arguments:\n");
  RUN(file_argument_matrix);

  printf("\nSubshells:\n");
  RUN(subshell_matrix);
  RUN(nested_composition_matrix);
  RUN(dynamic_substitution_io_topology);
  RUN(file_command_substitution_intersections);
  RUN(file_command_substitution_dynamic_operands);
  RUN(io_number_boundaries);

  printf("\nHeredocs and herestrings:\n");
  RUN(inline_document_matrix);
  RUN(heredoc_content_writer_contract);
  RUN(document_content_api_error_contract);
  RUN(expandable_heredoc_substitution_matrix);
  RUN(heredoc_substitution_cross_product_matrix);
  RUN(group_heredoc_descriptor_substitution_routing);
  RUN(brace_group_substitution_boundary_matrix);
  RUN(brace_group_process_substitution_routing);
  RUN(process_substitution_stream_topology);
  RUN(substitution_descriptor_provenance);
  RUN(substitution_scanner_and_flag_contract);
  RUN(herestring_substitution_topology);
  RUN(substitution_comment_and_heredoc_capacity);
  RUN(brace_group_process_substitution_error_contract);
  RUN(brace_group_process_substitution_recursion_limit);
  RUN(process_substitution_word_limit_contract);
  RUN(heredoc_count_substitution_capacity);
  RUN(substitution_operand_matrix);
  RUN(brace_group_document_scope);
  RUN(brace_group_local_document_scope);
  RUN(brace_group_multiple_documents);
  RUN(brace_group_document_pipeline_composition);
  RUN(brace_group_document_capacity);
  RUN(brace_group_document_limit_cross_product);
  RUN(heredoc_substitution_limit_cross_product);

  printf("\nError Handling:\n");
  RUN(reused_output_contract);
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
  RUN(validation_rejects_malformed_endpoint_metadata);
  RUN(validation_rejects_corrupt_counts_documents_and_endpoint_shapes);
  RUN(validation_rejects_malformed_group_metadata);

  printf("\nComplex:\n");
  RUN(graph_dump_contract);
  RUN(name_helpers);

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
