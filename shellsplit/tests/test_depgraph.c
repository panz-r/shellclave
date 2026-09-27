#include "../src/shell_depgraph_internal.h"
#include "depgraph_invariants.h"
#include "depgraph_test_workspace.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_tokenizer.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The shared test adapter intentionally supplies workspace. Keep raw entry
 * points available for the public ownership/error contract itself. */
#undef shell_dep_graph_parse
#undef shell_dep_graph_parse_with_fast
static shell_dep_error_t raw_dep_graph_parse(const char *cmd, size_t cmd_len,
                                             const char *initial_cwd,
                                             const shell_dep_limits_t *limits,
                                             shell_dep_graph_t *out) {
  return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, limits, out);
}
static shell_dep_error_t raw_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  return shell_dep_graph_parse_with_fast(cmd, cmd_len, initial_cwd, limits,
                                         fast, out);
}
#define shell_dep_graph_parse shellsplit_test_dep_graph_parse
#define shell_dep_graph_parse_with_fast                                        \
  shellsplit_test_dep_graph_parse_with_fast

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

static bool has_only_public_edge_flags(const shell_dep_graph_t *g) {
  const uint8_t public_flags = SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                               SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME |
                               SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND |
                               SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP;
  for (uint32_t i = 0; i < g->edge_count; i++)
    if ((g->edges[i].flags & ~public_flags) != 0)
      return false;
  return true;
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

static int find_cmd_tokens(const shell_dep_graph_t *g, const char *first,
                           const char *second) {
  if (!first)
    return -1;
  size_t first_len = strlen(first);
  size_t second_len = second ? strlen(second) : 0;
  for (uint32_t i = 0; i < g->node_count; i++) {
    const shell_dep_node_t *node = &g->nodes[i];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0 ||
        node->cmd.token_lens[0] != first_len ||
        memcmp(node->cmd.tokens[0], first, first_len) != 0)
      continue;
    if (!second)
      return (int)i;
    if (node->cmd.token_count > 1 && node->cmd.token_lens[1] == second_len &&
        memcmp(node->cmd.tokens[1], second, second_len) == 0)
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

static int find_file_doc(const shell_dep_graph_t *g, const char *path) {
  if (!path)
    return -1;
  size_t length = strlen(path);
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_DOC &&
        g->nodes[i].doc.kind == SHELL_DOC_FILE &&
        g->nodes[i].doc.path_len == length &&
        memcmp(g->nodes[i].doc.path, path, length) == 0)
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

  /* `fast` is borrowed at entry. Deliberately overlap its trailing count with
   * the graph's first output field: the parser must snapshot metadata before
   * it initializes output storage. */
  typedef union {
    max_align_t alignment;
    unsigned char bytes[offsetof(shell_parse_result_t, count) +
                        sizeof(shell_dep_graph_t)];
  } fast_graph_overlap_t;
  fast_graph_overlap_t overlap = {0};
  shell_parse_result_t *overlapping_fast =
      (shell_parse_result_t *)(void *)overlap.bytes;
  shell_dep_graph_t *overlapping_graph =
      (shell_dep_graph_t *)(void *)(overlap.bytes +
                                    offsetof(shell_parse_result_t, count));
  ASSERT((uintptr_t)overlapping_graph % _Alignof(shell_dep_graph_t) == 0);
  ASSERT(shell_parse_fast(command, strlen(command), NULL, overlapping_fast) ==
         SHELL_OK);
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         overlapping_fast,
                                         overlapping_graph) == SHELL_DEP_OK);
  ASSERT(overlapping_graph->node_count == regular.node_count &&
         overlapping_graph->edge_count == regular.edge_count &&
         overlapping_graph->status == regular.status &&
         shell_dep_graph_validate(overlapping_graph).valid);

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

  ASSERT(shell_parse_fast("cat 3<<<value", strlen("cat 3<<<value"), NULL,
                          &fast) == SHELL_OK);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("cat 3<<<value",
                                         strlen("cat 3<<<value"), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&supplied).valid);

  ASSERT(shell_parse_fast("printf x", strlen("printf x"), NULL, &fast) ==
         SHELL_OK);
  fast.cmds[0].type = UINT16_MAX;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("printf x", strlen("printf x"), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast(command, strlen(command), NULL, &fast) == SHELL_OK);
  fast.cmds[0].start = UINT32_MAX;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  const char *and_source = "printf x && cat";
  ASSERT(shell_parse_fast(and_source, strlen(and_source), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.count == 2);
  fast.cmds[1].type = SHELL_TYPE_PIPELINE;
  fast.cmds[1].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(and_source, strlen(and_source), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  const char *or_source = "printf x || cat";
  ASSERT(shell_parse_fast(or_source, strlen(or_source), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.count == 2);
  fast.cmds[1].type = SHELL_TYPE_PIPELINE;
  fast.cmds[1].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(or_source, strlen(or_source), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  const char *pipe_both = "printf x |& cat";
  ASSERT(shell_parse_fast(pipe_both, strlen(pipe_both), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.count == 2);
  fast.cmds[1].pipe_input_mode = UINT8_MAX;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(pipe_both, strlen(pipe_both), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  /* Pipe mode is routing metadata, so supplied fast results must agree with
   * their source spelling.  Retain the old zero-initialized `|` contract but
   * never let it erase the distinct `|&` stderr route. */
  const char *normal_pipe = "printf x | cat";
  ASSERT(shell_parse_fast(normal_pipe, strlen(normal_pipe), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.count == 2 && fast.cmds[1].type == SHELL_TYPE_PIPELINE);
  fast.cmds[1].pipe_input_mode = SHELL_PIPE_MODE_NONE;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(normal_pipe, strlen(normal_pipe), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&supplied, SHELL_EDGE_PIPE) == 1 &&
         shell_dep_graph_validate(&supplied).valid);

  /* A compound pipeline stage starts at its opening delimiter, while its
   * first executable range starts inside the group. Supplied metadata must be
   * checked against the delimiter before that opening delimiter. */
  const char *grouped_pipe = "{ printf x; } | cat";
  ASSERT(shell_parse_fast(grouped_pipe, strlen(grouped_pipe), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.count == 2 && fast.group_count == 1 &&
         fast.cmds[1].type == SHELL_TYPE_PIPELINE);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(grouped_pipe, strlen(grouped_pipe),
                                         ".", NULL, &fast,
                                         &supplied) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&supplied, SHELL_EDGE_PIPE) == 1 &&
         shell_dep_graph_validate(&supplied).valid);

  ASSERT(shell_parse_fast(normal_pipe, strlen(normal_pipe), NULL, &fast) ==
         SHELL_OK);
  fast.cmds[1].pipe_input_mode = SHELL_PIPE_MODE_STDOUT_AND_STDERR;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(normal_pipe, strlen(normal_pipe), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast(pipe_both, strlen(pipe_both), NULL, &fast) ==
         SHELL_OK);
  fast.cmds[1].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(pipe_both, strlen(pipe_both), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  /* Recursive substitution analysis has a fixed semantic depth limit. It
   * must fail closed rather than returning a partially connected graph. */
  char deep_substitution[96] = "echo ";
  size_t deep_length = strlen(deep_substitution);
  for (size_t i = 0; i < 17; i++) {
    deep_substitution[deep_length++] = '$';
    deep_substitution[deep_length++] = '(';
  }
  deep_substitution[deep_length++] = ':';
  for (size_t i = 0; i < 17; i++)
    deep_substitution[deep_length++] = ')';
  deep_substitution[deep_length] = '\0';
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse(deep_substitution, deep_length, ".", NULL,
                               &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast("printf x", strlen("printf x"), NULL, &fast) ==
         SHELL_OK);
  fast.cmds[0].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("printf x", strlen("printf x"), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast(normal_pipe, strlen(normal_pipe), NULL, &fast) ==
         SHELL_OK);
  fast.cmds[0].type = SHELL_TYPE_PIPELINE;
  fast.cmds[0].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(normal_pipe, strlen(normal_pipe), ".",
                                         NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast("{( echo; )}", strlen("{( echo; )}"), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[0].end = 0;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("{( echo; )}", strlen("{( echo; )}"),
                                         ".", NULL, &fast,
                                         &supplied) == SHELL_DEP_ETRUNC);
  ASSERT((supplied.status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
         shell_dep_graph_validate(&supplied).valid);

  ASSERT(shell_parse_fast("{( echo; )}", strlen("{( echo; )}"), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[0].command_count = 0;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("{( echo; )}", strlen("{( echo; )}"),
                                         ".", NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  ASSERT(shell_parse_fast("{( echo; )}", strlen("{( echo; )}"), NULL, &fast) ==
         SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[1].parent = UINT16_MAX;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast("{( echo; )}", strlen("{( echo; )}"),
                                         ".", NULL, &fast,
                                         &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  const char *overlapping_groups = "{ echo one; } ; { echo two; }";
  ASSERT(shell_parse_fast(overlapping_groups, strlen(overlapping_groups), NULL,
                          &fast) == SHELL_OK);
  ASSERT(fast.group_count == 2);
  fast.groups[0].end = fast.groups[1].start + 1;
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(overlapping_groups,
                                         strlen(overlapping_groups), ".", NULL,
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

  /* The supplied-fast shortcut is an optimization, never authority to turn
   * lexically valid but unmodelled Bash syntax into a dependency graph. */
  static const char *const unmodelled_semantic_cases[] = {
      "[[ -f /tmp/x ]]",
      "(( count += 1 ))",
      "time -p echo x",
      "printf '%s' $\"localized\"",
      "echo $( [[ -f /tmp/x ]] )",
      "{ (( 1 )); }",
  };
  for (size_t i = 0; i < sizeof(unmodelled_semantic_cases) /
                             sizeof(unmodelled_semantic_cases[0]);
       i++) {
    const char *input = unmodelled_semantic_cases[i];
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), NULL, &fast);
    ASSERT(fast_status == SHELL_OK || fast_status == SHELL_EPARSE);
    memset(&supplied, 0, sizeof(supplied));
    ASSERT(shell_dep_graph_parse_with_fast(input, strlen(input), ".", NULL,
                                           &fast,
                                           &supplied) == SHELL_DEP_EPARSE);
    ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
           supplied.node_count == 0 && supplied.edge_count == 0);
  }
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
      {"cmd {trace}> trace.log", SHELL_EDGE_FD_OPEN, 1, 1, 1, "trace.log"},
      {"cmd {input}< input.log", SHELL_EDGE_FD_OPEN, 1, 1, 1, "input.log"},
      {"cmd {both}<> state.log", SHELL_EDGE_FD_OPEN, 1, 2, 1, "state.log"},
      {"cmd &> combined.log", SHELL_EDGE_WRITE, 1, 2, 1, "combined.log"},
      {"cmd &>> combined.log", SHELL_EDGE_APPEND, 1, 2, 1, "combined.log"},
      {"cmd >& combined.log", SHELL_EDGE_WRITE, 1, 2, 1, "combined.log"},
      {"cmd 1>& combined.log", SHELL_EDGE_WRITE, 1, 2, 1, "combined.log"},
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
      if (cases[i].edge_type == SHELL_EDGE_FD_OPEN)
        continue;
      if (cases[i].edge_type == SHELL_EDGE_READ) {
        ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_DOC);
        ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_CMD);
      } else {
        ASSERT(g.nodes[g.edges[j].from].type == SHELL_NODE_CMD);
        ASSERT(g.nodes[g.edges[j].to].type == SHELL_NODE_DOC);
      }
    }
    if (strstr(cases[i].command, "&>") != NULL ||
        strstr(cases[i].command, " >&") != NULL ||
        strstr(cases[i].command, " 1>&") != NULL) {
      bool stdout_seen = false;
      bool stderr_seen = false;
      for (uint32_t j = 0; j < g.edge_count; j++) {
        if (g.edges[j].type != cases[i].edge_type)
          continue;
        stdout_seen = stdout_seen || g.edges[j].source_fd == 1;
        stderr_seen = stderr_seen || g.edges[j].source_fd == 2;
      }
      ASSERT(stdout_seen && stderr_seen);
    }
    if (strstr(cases[i].command, "{trace}>") != NULL ||
        strstr(cases[i].command, "{input}<") != NULL ||
        strstr(cases[i].command, "{both}<>") != NULL) {
      bool named_seen = false;
      for (uint32_t j = 0; j < g.edge_count; j++)
        named_seen = named_seen || g.edges[j].source_fd == SHELL_DEP_FD_NAMED ||
                     g.edges[j].target_fd == SHELL_DEP_FD_NAMED;
      ASSERT(named_seen);
    }
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&g);
    ASSERT(validation.valid);
    ASSERT(validation.error_count == 0);
  }
  shell_dep_graph_t named;
  ASSERT(parse("cmd {fd}>&1", &named) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&named, SHELL_EDGE_FD_OPEN) == 1 &&
         named.edges[0].source_fd == 1 &&
         named.edges[0].target_fd == SHELL_DEP_FD_NAMED &&
         (named.edges[0].flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0 &&
         named.edges[0].target_fd_name_len == 2 &&
         memcmp(named.edges[0].target_fd_name, "fd", 2) == 0 &&
         shell_dep_graph_validate(&named).valid);
  ASSERT(parse("cmd {fd}<&0", &named) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&named, SHELL_EDGE_FD_OPEN) == 1 &&
         named.edges[0].source_fd == 0 &&
         named.edges[0].target_fd == SHELL_DEP_FD_NAMED &&
         shell_dep_graph_validate(&named).valid);
  /* Bash rejects a close before `{fd}` has allocated a descriptor. */
  ASSERT(parse("cmd {fd}>&-", &named) == SHELL_DEP_EPARSE);
  ASSERT(named.node_count == 0 && named.edge_count == 0 &&
         named.status == SHELL_DEP_STATUS_ERROR);
  pass_count++;
}

TEST(legacy_combined_output_redirects) {
  static const char *const accepted[] = {
      "cmd >&combined",
      "cmd >&$",
      "cmd >&$:",
      "cmd >&[",
      "cmd >&[]",
      "cmd >&file[part",
      "cmd >&{literal$}",
      "cmd 1>&combined",
      "cmd >&123file",
      "cmd >&\"quoted combined\"",
      "cmd >&\"-\"file",
      "cmd >&\\-file",
      "cmd >&$'-'file",
      "cmd >&foo{bar}",
      "cmd >&literal$destination",
      "cmd >&literal${destination}",
      "cmd >&literal$((1 + 2))",
      "cmd >&literal*.log",
      "cmd >&literal@(one|two)",
      "cmd >&foo{one,two}",
      "cmd >&foo{1..2}",
      "cmd >&*.log",
      "{ cmd; } >&combined",
  };
  for (uint32_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(accepted[i], &graph) == SHELL_DEP_OK);
    int document = find_doc(&graph, SHELL_DOC_FILE);
    ASSERT(document >= 0);
    bool stdout_seen = false;
    bool stderr_seen = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *item = &graph.edges[edge];
      if ((item->type == SHELL_EDGE_WRITE || item->type == SHELL_EDGE_APPEND) &&
          item->to == (uint32_t)document) {
        stdout_seen = stdout_seen || item->source_fd == 1;
        stderr_seen = stderr_seen || item->source_fd == 2;
      }
    }
    ASSERT(stdout_seen && stderr_seen &&
           shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t graph = {0};
  static const char *const descriptor_targets[] = {
      "cmd >&7",
      "cmd >&0000000000000000000000000000000000000001",
      "cmd >&$'0000000000000000000000000000000000000001'",
      "cmd >&-",
      "cmd >&\"7\"",
      "cmd >&$'7'",
      "cmd >&\"-\"",
  };
  for (uint32_t i = 0;
       i < sizeof(descriptor_targets) / sizeof(descriptor_targets[0]); i++) {
    ASSERT(parse(descriptor_targets[i], &graph) == SHELL_DEP_OK);
    ASSERT(count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("cmd >&-file", &graph) == SHELL_DEP_OK);
  int close_command = find_first_cmd(&graph);
  ASSERT(close_command >= 0 &&
         graph.nodes[close_command].cmd.token_count == 2 &&
         graph.nodes[close_command].cmd.token_lens[0] == 3 &&
         memcmp(graph.nodes[close_command].cmd.tokens[0], "cmd", 3) == 0 &&
         graph.nodes[close_command].cmd.token_lens[1] == 4 &&
         memcmp(graph.nodes[close_command].cmd.tokens[1], "file", 4) == 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_CLOSE, (uint32_t)close_command,
                      (uint32_t)close_command, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  static const char long_path[] = "abcdefghijklmnopqrstuvwxyzabcdefghi";
  char long_legacy[sizeof("cmd >&") + sizeof(long_path)] = "cmd >&";
  strcat(long_legacy, long_path);
  ASSERT(parse(long_legacy, &graph) == SHELL_DEP_OK);
  ASSERT(find_file_doc(&graph, long_path) >= 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cmd >&foo{bar}", &graph) == SHELL_DEP_OK);
  ASSERT(find_file_doc(&graph, "foo{bar}") >= 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* A bare dollar and unmatched bracket are literal pathname bytes. They must
   * not be promoted into dynamic filename nodes or descriptor duplication. */
  static const char *const literal_targets[] = {
      "$", "$:", "[", "[]", "file[part", "{literal$}",
  };
  for (uint32_t i = 0; i < sizeof(literal_targets) / sizeof(literal_targets[0]);
       i++) {
    char command_text[64];
    int written = snprintf(command_text, sizeof(command_text), "cmd >&%s",
                           literal_targets[i]);
    ASSERT(written > 0 && (size_t)written < sizeof(command_text));
    ASSERT(parse(command_text, &graph) == SHELL_DEP_OK);
    int literal_document = find_file_doc(&graph, literal_targets[i]);
    int literal_command = find_first_cmd(&graph);
    ASSERT(literal_document >= 0 && literal_command >= 0 &&
           (graph.nodes[literal_document].doc.flags &
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) == 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)literal_command,
                        (uint32_t)literal_document, 1, SHELL_DEP_FD_NONE) &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)literal_command,
                        (uint32_t)literal_document, 2, SHELL_DEP_FD_NONE) &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* An unmatched bracket is a literal pathname byte even when the remaining
   * word has runtime expansion. A complete bracket glob, by contrast, could
   * become a descriptor number and is rejected below. */
  static const char *const dynamic_literal_targets[] = {
      "[$fd",
      "[]$fd",
      "file[[:digit:]]",
  };
  for (uint32_t i = 0;
       i < sizeof(dynamic_literal_targets) / sizeof(dynamic_literal_targets[0]);
       i++) {
    char command_text[64];
    int written = snprintf(command_text, sizeof(command_text), "cmd >&%s",
                           dynamic_literal_targets[i]);
    ASSERT(written > 0 && (size_t)written < sizeof(command_text));
    ASSERT(parse(command_text, &graph) == SHELL_DEP_OK);
    int dynamic_document = find_file_doc(&graph, dynamic_literal_targets[i]);
    int dynamic_command = find_first_cmd(&graph);
    ASSERT(dynamic_document >= 0 && dynamic_command >= 0 &&
           (graph.nodes[dynamic_document].doc.flags &
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)dynamic_command,
                        (uint32_t)dynamic_document, 1, SHELL_DEP_FD_NONE) &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)dynamic_command,
                        (uint32_t)dynamic_document, 2, SHELL_DEP_FD_NONE) &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("cmd >& >(consumer)", &graph) == SHELL_DEP_OK);
  int endpoint = find_endpoint(&graph);
  int command = find_first_cmd(&graph);
  ASSERT(endpoint >= 0 && command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Both process-substitution directions yield a pathname.  Writing through
   * the pathname produced by `<(...)` is cross-directional, so retain the
   * producer but do not invent a byte-flow route to it. */
  static const char *const cross_direction_process_substitutions[] = {
      "cmd >& <(producer)",
      "cmd >&<(producer)",
      "{ cmd; } >& <(producer)",
  };
  for (uint32_t i = 0; i < sizeof(cross_direction_process_substitutions) /
                               sizeof(cross_direction_process_substitutions[0]);
       i++) {
    ASSERT(parse(cross_direction_process_substitutions[i], &graph) ==
           SHELL_DEP_OK);
    bool byte_route = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      byte_route = byte_route || graph.edges[edge].type == SHELL_EDGE_WRITE ||
                   graph.edges[edge].type == SHELL_EDGE_APPEND ||
                   graph.edges[edge].type == SHELL_EDGE_PIPE ||
                   graph.edges[edge].type == SHELL_EDGE_SUBST;
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
           count_doc_kind(&graph, SHELL_DOC_FILE) == 0 && !byte_route &&
           shell_dep_graph_validate(&graph).valid);
  }

  static const char *const rejected[] = {
      "cmd 2>&combined",
      "cmd {fd}>&combined",
      "cmd >&$destination",
      "cmd >&~",
      "cmd >&*",
      "cmd >&[[:digit:]]",
      "cmd >&[[=a=]]",
      "cmd >&[[.a.]]",
      "cmd >&?(one|two)",
      "cmd >&*(one|two)",
      "cmd >&+(one|two)",
      "cmd >&@(one|two)",
      "cmd >&!(one|two)",
      "cmd >&\\\n~",
      "cmd >&''",
      "cmd >&$'a\\0b'",
      "cmd >&2147483648",
      "cmd >&00000000000000000000000000000000002147483648",
      "cmd >&$'2147483648'",
      /* A command substitution may produce a descriptor number, `-`, or a
       * pathname. Do not claim the legacy combined-output topology for it. */
      "cmd >&$(printf 2)",
      "cmd >&`printf 2`",
      "cmd >&",
  };
  for (uint32_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
           graph.status == SHELL_DEP_STATUS_ERROR);
  }
  pass_count++;
}

/* A literal non-descriptor fragment proves that an expanded `>&word` remains
 * a pathname. Dynamic FILE nodes retain that fact for all expansion forms;
 * command substitutions additionally retain their producer. */
TEST(literal_brace_dynamic_redirect_paths) {
  static const struct {
    const char *command;
    const char *path;
    bool combined_output;
    bool has_producer;
    bool owner_is_group;
  } cases[] = {
      {"printf value >{$(printf /tmp/brace-output)}",
       "{$(printf /tmp/brace-output)}", false, true, false},
      {"printf value >&path-$(printf /tmp/brace-combined)",
       "path-$(printf /tmp/brace-combined)", true, true, false},
      {"printf value >&literal$destination", "literal$destination", true, false,
       false},
      {"printf value >&literal$((1 + 2))", "literal$((1 + 2))", true, false,
       false},
      {"{ printf value; } >&\"\"literal$(printf /tmp/quoted-combined)",
       "\"\"literal$(printf /tmp/quoted-combined)", true, true, true},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int redirect_owner = find_nth_cmd(&graph, 0);
    if (cases[i].owner_is_group) {
      redirect_owner = -1;
      for (uint32_t node = 0; node < graph.node_count; node++)
        if (graph.nodes[node].type == SHELL_NODE_GROUP) {
          redirect_owner = (int)node;
          break;
        }
    }
    int pathname_producer =
        cases[i].has_producer
            ? (cases[i].owner_is_group
                   ? find_cmd_tokens(&graph, "printf", "/tmp/quoted-combined")
                   : find_nth_cmd(&graph, 1))
            : -1;
    int document = find_file_doc(&graph, cases[i].path);
    ASSERT(redirect_owner >= 0 &&
           (!cases[i].has_producer || pathname_producer >= 0) && document >= 0);
    ASSERT((graph.nodes[document].doc.flags &
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0);

    bool dynamic_name_flow = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *current = &graph.edges[edge];
      dynamic_name_flow =
          dynamic_name_flow ||
          (current->type == SHELL_EDGE_SUBST &&
           current->from == (uint32_t)pathname_producer &&
           current->to == (uint32_t)document && current->source_fd == 1 &&
           current->target_fd == SHELL_DEP_FD_NONE &&
           (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0 &&
           (current->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) == 0);
    }
    ASSERT(!cases[i].has_producer || dynamic_name_flow);
    ASSERT(has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)redirect_owner,
                        (uint32_t)document, 1, SHELL_DEP_FD_NONE));
    ASSERT(!cases[i].combined_output ||
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)redirect_owner,
                        (uint32_t)document, 2, SHELL_DEP_FD_NONE));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(named_fd_redirect_topology) {
  static const struct {
    const char *command;
    shell_dep_node_type_t owner_type;
    bool has_input;
    bool has_output;
    bool append_output;
  } cases[] = {
      {"cmd {input}< input.log", SHELL_NODE_CMD, true, false, false},
      {"cmd {input}< '<(producer)'", SHELL_NODE_CMD, true, false, false},
      {"cmd {output}> output.log", SHELL_NODE_CMD, false, true, false},
      {"cmd {append}>> output.log", SHELL_NODE_CMD, false, true, true},
      {"cmd {both}<> state.log", SHELL_NODE_CMD, true, true, false},
      {"{ printf x; } {input}< input.log", SHELL_NODE_GROUP, true, false,
       false},
      {"{ printf x; } {output}> output.log", SHELL_NODE_GROUP, false, true,
       false},
      {"{ printf x; } {both}<> state.log", SHELL_NODE_GROUP, true, true, false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(cases[i].command, &g) == SHELL_DEP_OK);
    ASSERT(count_doc_kind(&g, SHELL_DOC_FILE) == 1);
    ASSERT(count_edge_type(&g, SHELL_EDGE_FD_OPEN) ==
           (uint32_t)cases[i].has_input + (uint32_t)cases[i].has_output);

    int document = find_doc(&g, SHELL_DOC_FILE);
    ASSERT(document >= 0);
    int owner = -1;
    for (uint32_t j = 0; j < g.node_count; j++) {
      if (g.nodes[j].type == cases[i].owner_type) {
        owner = (int)j;
        break;
      }
    }
    ASSERT(owner >= 0);
    if (cases[i].has_input)
      ASSERT(has_edge_fds(&g, SHELL_EDGE_FD_OPEN, (uint32_t)document,
                          (uint32_t)owner, SHELL_DEP_FD_NONE,
                          SHELL_DEP_FD_NAMED));
    if (cases[i].has_output)
      ASSERT(has_edge_fds(&g, SHELL_EDGE_FD_OPEN, (uint32_t)owner,
                          (uint32_t)document, SHELL_DEP_FD_NAMED,
                          SHELL_DEP_FD_NONE));
    bool append_seen = false;
    for (uint32_t edge = 0; edge < g.edge_count; edge++)
      append_seen =
          append_seen ||
          ((g.edges[edge].flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0);
    ASSERT(append_seen == cases[i].append_output);
    ASSERT(shell_dep_graph_validate(&g).valid);
  }
  pass_count++;
}

TEST(named_fd_symbolic_duplication_routes) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("printf bytes {out}> /tmp/out >&\"$out\"", &graph) ==
         SHELL_DEP_OK);
  int command = find_first_cmd(&graph);
  int document = find_doc(&graph, SHELL_DOC_FILE);
  bool setup = false;
  bool routed = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    setup = setup || (item->type == SHELL_EDGE_FD_OPEN &&
                      item->from == (uint32_t)command &&
                      item->to == (uint32_t)document &&
                      item->source_fd == SHELL_DEP_FD_NAMED &&
                      item->source_fd_name_len == 3 &&
                      memcmp(item->source_fd_name, "out", 3) == 0);
    routed = routed || (item->type == SHELL_EDGE_WRITE &&
                        item->from == (uint32_t)command &&
                        item->to == (uint32_t)document && item->source_fd == 1);
  }
  ASSERT(command >= 0 && document >= 0 && setup && routed &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf bytes {one}> /tmp/out {two}>&\"$one\" >&${two}",
               &graph) == SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  document = find_doc(&graph, SHELL_DOC_FILE);
  bool named_dup = false;
  routed = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    named_dup =
        named_dup ||
        (item->type == SHELL_EDGE_FD_OPEN &&
         (item->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0 &&
         item->source_fd == SHELL_DEP_FD_NAMED &&
         item->target_fd == SHELL_DEP_FD_NAMED &&
         item->source_fd_name_len == 3 && item->target_fd_name_len == 3 &&
         memcmp(item->source_fd_name, "one", 3) == 0 &&
         memcmp(item->target_fd_name, "two", 3) == 0);
    routed = routed || (item->type == SHELL_EDGE_WRITE &&
                        item->from == (uint32_t)command &&
                        item->to == (uint32_t)document && item->source_fd == 1);
  }
  ASSERT(command >= 0 && document >= 0 && named_dup && routed &&
         shell_dep_graph_validate(&graph).valid);

  /* Bash permits descriptor setup from the otherwise unavailable direction of
   * a named descriptor. It becomes meaningful only if a later command uses
   * that direction, so the graph records setup without inventing byte flow. */
  ASSERT(parse("exec {out}> /tmp/out; exec {copy}<&$out; printf bytes >&$copy",
               &graph) == SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 2);
  document = find_file_doc(&graph, "/tmp/out");
  ASSERT(command >= 0 && document >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {in}< /tmp/in; exec {copy}>&$in; cat <&$copy", &graph) ==
         SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 2);
  document = find_file_doc(&graph, "/tmp/in");
  ASSERT(command >= 0 && document >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)command, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A named self-dup resolves the old descriptor before the redirect assigns
   * its fresh descriptor value. The later write must still reach /tmp/out. */
  ASSERT(parse("exec {out}> /tmp/out; exec {out}>&$out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  command = find_nth_cmd(&graph, 2);
  document = find_file_doc(&graph, "/tmp/out");
  routed = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    routed = routed || (graph.edges[edge].type == SHELL_EDGE_WRITE &&
                        graph.edges[edge].from == (uint32_t)command &&
                        graph.edges[edge].to == (uint32_t)document &&
                        graph.edges[edge].source_fd == 1);
  ASSERT(command >= 0 && document >= 0 && routed &&
         shell_dep_graph_validate(&graph).valid);

  /* The suffix is a stable non-descriptor literal, so this is combined output
   * to a dynamic pathname rather than a named-FD duplication. */
  ASSERT(parse("printf bytes {out}> /tmp/out >&\"$out\"suffix", &graph) ==
         SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  document = find_file_doc(&graph, "\"$out\"suffix");
  ASSERT(command >= 0 && document >= 0 &&
         (graph.nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) !=
             0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)document, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  static const char *const rejected[] = {
      "printf bytes >&\"$missing\"",
      "printf bytes {out}> /tmp/out >&${out:-1}",
      "exec {out}> /tmp/out; exec {copy}<&$out; cat <&$copy",
      "exec {in}< /tmp/in; exec {copy}>&$in; printf bytes >&$copy",
  };
  for (uint32_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }
  pass_count++;
}

/* A named process-substitution descriptor remains a valid Bash descriptor
 * even if the nested command redirected away the stream it inherited from the
 * process-substitution pipe. Retain that pipe as setup-only endpoint state;
 * the later exact descriptor use is the first actual byte-flow relation. */
TEST(named_fd_unconnected_process_substitution_routes) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("exec {source}< <(printf payload >/tmp/named-source); "
               "cat <&\"$source\"",
               &graph) == SHELL_DEP_OK);
  int setup_owner = find_cmd_tokens(&graph, "exec", NULL);
  int payload = find_cmd_tokens(&graph, "printf", "payload");
  int consumer = find_cmd_tokens(&graph, "cat", NULL);
  int endpoint = find_endpoint(&graph);
  bool setup = false;
  bool flow = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    setup = setup || (item->type == SHELL_EDGE_FD_OPEN &&
                      item->from == (uint32_t)endpoint &&
                      item->to == (uint32_t)setup_owner &&
                      item->source_fd == SHELL_DEP_FD_NONE &&
                      item->target_fd == SHELL_DEP_FD_NAMED &&
                      item->target_fd_name_len == 6 &&
                      memcmp(item->target_fd_name, "source", 6) == 0);
    flow =
        flow ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)endpoint &&
         item->to == (uint32_t)consumer &&
         item->source_fd == SHELL_DEP_FD_NONE && item->target_fd == 0);
  }
  ASSERT(setup_owner >= 0 && payload >= 0 && consumer >= 0 && endpoint >= 0 &&
         graph.nodes[endpoint].endpoint.reserved != 0 && setup && flow &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {sink}> >(cat </tmp/named-sink); "
               "printf payload >&\"$sink\"",
               &graph) == SHELL_DEP_OK);
  setup_owner = find_cmd_tokens(&graph, "exec", NULL);
  int nested_consumer = find_cmd_tokens(&graph, "cat", NULL);
  int writer = find_cmd_tokens(&graph, "printf", "payload");
  endpoint = find_endpoint(&graph);
  setup = false;
  flow = false;
  uint32_t setup_edge = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    bool is_setup = item->type == SHELL_EDGE_FD_OPEN &&
                    item->from == (uint32_t)setup_owner &&
                    item->to == (uint32_t)endpoint &&
                    item->source_fd == SHELL_DEP_FD_NAMED &&
                    item->source_fd_name_len == 4 &&
                    memcmp(item->source_fd_name, "sink", 4) == 0 &&
                    item->target_fd == SHELL_DEP_FD_NONE;
    setup = setup || is_setup;
    if (is_setup)
      setup_edge = edge;
    flow = flow ||
           (item->type == SHELL_EDGE_WRITE && item->from == (uint32_t)writer &&
            item->to == (uint32_t)endpoint && item->source_fd == 1 &&
            item->target_fd == SHELL_DEP_FD_NONE);
  }
  ASSERT(setup_owner >= 0 && nested_consumer >= 0 && writer >= 0 &&
         endpoint >= 0 && graph.nodes[endpoint].endpoint.reserved != 0 &&
         setup && flow && shell_dep_graph_validate(&graph).valid);

  shell_dep_graph_t malformed = graph;
  ASSERT(setup_edge != UINT32_MAX);
  malformed.edges[setup_edge].type = SHELL_EDGE_WRITE;
  ASSERT(!shell_dep_graph_validate(&malformed).valid);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 2;
  shell_dep_graph_t limited = {0};
  const char *limited_input =
      "exec {source}< <(printf payload >/tmp/named-source)";
  ASSERT(shell_dep_graph_parse(limited_input, strlen(limited_input), ".",
                               &limits, &limited) == SHELL_DEP_ETRUNC);
  ASSERT((limited.status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
         limited.node_count <= limits.max_nodes &&
         shell_dep_graph_validate(&limited).valid);
  pass_count++;
}

/* Named descriptor spans retain their source spelling, but binding identity
 * must use the same escaped-physical-line-ending rules as syntax parsing.
 * Exercise every accepted spelling against a differently wrapped reference so
 * a local descriptor comparator cannot silently diverge from the parser. */
TEST(named_fd_continuation_identity) {
  static const struct {
    const char *command;
    const char *path;
  } cases[] = {
      {"exec {f\\\rd}>/tmp/bare-cr-declaration; printf bytes >&$fd",
       "/tmp/bare-cr-declaration"},
      {"exec {fd}>/tmp/bare-cr-reference; printf bytes >&$f\\\rd",
       "/tmp/bare-cr-reference"},
      {"exec {f\\\r\nd}>/tmp/crlf-declaration; printf bytes >&$fd",
       "/tmp/crlf-declaration"},
      {"exec {fd}>/tmp/crlf-reference; printf bytes >&\"${f\\\r\nd}\"",
       "/tmp/crlf-reference"},
      {"exec {fd}>/tmp/dollar-lf-reference; printf bytes >&$\\\n{fd}",
       "/tmp/dollar-lf-reference"},
      {"exec {fd}>/tmp/dollar-crlf-reference; printf bytes >&$\\\r\n{fd}",
       "/tmp/dollar-crlf-reference"},
      {"exec {fd}>/tmp/dollar-cr-reference; printf bytes >&$\\\r{fd}",
       "/tmp/dollar-cr-reference"},
      {"exec {fd}>/tmp/dollar-quoted-reference; printf bytes >&\"$\\\n{fd}\"",
       "/tmp/dollar-quoted-reference"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int document = find_file_doc(&graph, cases[i].path);
    int command = find_nth_cmd(&graph, 1);
    ASSERT(document >= 0 && command >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                        (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
           !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                         (uint32_t)document, 2, SHELL_DEP_FD_NONE) &&
           count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(named_fd_exec_scope_and_lifecycle) {
  shell_dep_graph_t graph = {0};
  const char *persistent = "exec {out}> /tmp/out; printf bytes >&\"$out\"";
  ASSERT(parse(persistent, &graph) == SHELL_DEP_OK);
  int document = find_doc(&graph, SHELL_DOC_FILE);
  int printf_command = find_nth_cmd(&graph, 1);
  bool routed = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    routed = routed || (graph.edges[edge].type == SHELL_EDGE_WRITE &&
                        graph.edges[edge].from == (uint32_t)printf_command &&
                        graph.edges[edge].to == (uint32_t)document &&
                        graph.edges[edge].source_fd == 1);
  ASSERT(document >= 0 && printf_command >= 0 && routed &&
         shell_dep_graph_validate(&graph).valid);

  /* Assignment prefixes are private to the command they decorate. Redirect
   * expansion must keep using the current-shell descriptor value, and the
   * prefix must not erase that value for the later command either. */
  ASSERT(parse("exec {out}> /tmp/prefix-out; out=shadow printf first >&$out; "
               "printf second >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/prefix-out");
  int prefixed_printf = find_nth_cmd(&graph, 1);
  int later_printf = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && prefixed_printf >= 0 && later_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)prefixed_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)later_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}> /tmp/prefix-append-out; "
               "out+=shadow printf first >&$out; printf second >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/prefix-append-out");
  prefixed_printf = find_nth_cmd(&graph, 1);
  later_printf = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && prefixed_printf >= 0 && later_printf >= 0 &&
         find_nth_cmd(&graph, 3) < 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)prefixed_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)later_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Command-word substitutions use that same pre-command descriptor state;
   * resolver snapshots must not treat their outer assignment prefix as a
   * persistent mutation. */
  ASSERT(parse("exec {input}< /tmp/prefix-in; input=shadow printf '%s' "
               "\"$(cat <&$input)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/prefix-in");
  int prefixed_nested_cat = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && prefixed_nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)prefixed_nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ exec {out}> /tmp/out; printf bytes >&$out; }", &graph) ==
         SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_FILE);
  bool brace_routed = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    brace_routed =
        brace_routed || (graph.edges[edge].type == SHELL_EDGE_WRITE &&
                         graph.edges[edge].to == (uint32_t)document &&
                         graph.edges[edge].source_fd == 1);
  ASSERT(document >= 0 && brace_routed &&
         shell_dep_graph_validate(&graph).valid);

  /* Every execution scope inherits descriptors that existed before it. A
   * brace group shares its parent state; subshell, pipeline, and background
   * scopes each receive a private snapshot. */
  static const char *const inherited[] = {
      "exec {out}> /tmp/out; { printf bytes >&$out; }",
      "exec {out}> /tmp/out; ( printf bytes >&$out )",
      "exec {out}> /tmp/out; printf source | cat >&$out",
      "exec {out}> /tmp/out; printf bytes >&$out &",
      "exec {f\\\nd}> /tmp/out; printf bytes >&$f\\\nd",
      "exec {out}> /tmp/out; true && printf bytes >&$out",
  };
  for (uint32_t i = 0; i < sizeof(inherited) / sizeof(inherited[0]); i++) {
    ASSERT(parse(inherited[i], &graph) == SHELL_DEP_OK);
    document = find_file_doc(&graph, "/tmp/out");
    bool child_write = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      child_write =
          child_write || (graph.edges[edge].type == SHELL_EDGE_WRITE &&
                          graph.edges[edge].to == (uint32_t)document &&
                          graph.edges[edge].source_fd == 1);
    ASSERT(document >= 0 && child_write &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("( exec {out}> /tmp/out; printf bytes >&$out )", &graph) ==
             SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid);

  /* Recursively parsed shell and process substitutions retain direct edges to
   * the parent resource; they neither reject a visible binding nor clone its
   * FILE/ENDPOINT node. */
  ASSERT(parse("exec {input}< /tmp/in; printf '%s' \"$(cat <&$input)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  int nested_cat_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_cat_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat_command, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {input}< /tmp/in; printf '%s' \"$(printf '%s' \"$(cat "
               "<&$input)\")\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  bool nested_import_read = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    nested_import_read =
        nested_import_read || (graph.edges[edge].type == SHELL_EDGE_READ &&
                               graph.edges[edge].from == (uint32_t)document &&
                               graph.edges[edge].target_fd == 0);
  ASSERT(document >= 0 && nested_import_read &&
         shell_dep_graph_validate(&graph).valid);

  /* `<>` retains both directions when the descriptor crosses a recursive
   * shell boundary; a one-way named allocation must not inherit its absent
   * direction from an earlier value of the shell variable. */
  ASSERT(parse("exec {state}<> /tmp/state; printf '%s' \"$(cat <&$state; "
               "printf bytes >&$state)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/state");
  int state_cat = find_nth_cmd(&graph, 2);
  int state_printf = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && state_cat >= 0 && state_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)state_cat, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)state_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {sink}> >(cat); printf '%s' \"$(printf bytes >&$sink)\"",
               &graph) == SHELL_DEP_OK);
  int nested_sink = find_endpoint(&graph);
  int nested_printf = find_nth_cmd(&graph, 3);
  ASSERT(nested_sink >= 0 && nested_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_printf,
                      (uint32_t)nested_sink, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {sink}> >(cat)", &graph) == SHELL_DEP_OK);
  int exec_command = find_nth_cmd(&graph, 0);
  int sink = find_endpoint(&graph);
  bool sink_setup = false;
  bool false_exec_write = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    sink_setup = sink_setup || (item->type == SHELL_EDGE_FD_OPEN &&
                                item->from == (uint32_t)exec_command &&
                                item->to == (uint32_t)sink &&
                                item->source_fd == SHELL_DEP_FD_NAMED &&
                                item->source_fd_name_len == 4 &&
                                memcmp(item->source_fd_name, "sink", 4) == 0);
    false_exec_write =
        false_exec_write ||
        (item->type == SHELL_EDGE_WRITE &&
         item->from == (uint32_t)exec_command && item->to == (uint32_t)sink);
  }
  ASSERT(exec_command >= 0 && sink >= 0 && sink_setup && !false_exec_write &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {sink}> >(cat); printf bytes >&\"$sink\"", &graph) ==
         SHELL_DEP_OK);
  sink = find_endpoint(&graph);
  printf_command = find_nth_cmd(&graph, 2);
  bool sink_write = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    sink_write =
        sink_write || (graph.edges[edge].type == SHELL_EDGE_WRITE &&
                       graph.edges[edge].from == (uint32_t)printf_command &&
                       graph.edges[edge].to == (uint32_t)sink &&
                       graph.edges[edge].source_fd == 1);
  ASSERT(sink >= 0 && printf_command >= 0 && sink_write &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {source}< <(printf bytes); cat <&\"${source}\"", &graph) ==
         SHELL_DEP_OK);
  int producer = find_nth_cmd(&graph, 1);
  int cat_command = find_nth_cmd(&graph, 2);
  bool source_setup = false;
  bool source_read = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    source_setup =
        source_setup ||
        (item->type == SHELL_EDGE_FD_OPEN && item->from == (uint32_t)producer &&
         item->target_fd == SHELL_DEP_FD_NAMED &&
         item->target_fd_name_len == 6 &&
         memcmp(item->target_fd_name, "source", 6) == 0);
    source_read =
        source_read ||
        (item->type == SHELL_EDGE_SUBST && item->from == (uint32_t)producer &&
         item->to == (uint32_t)cat_command && item->target_fd == 0);
  }
  ASSERT(producer >= 0 && cat_command >= 0 && source_setup && source_read &&
         shell_dep_graph_validate(&graph).valid);

  /* With Bash's default `varredir_close` behavior, a named descriptor opened
   * by an ordinary simple command remains available to later commands. A
   * redirect-only command is deliberately different and remains rejected. */
  ASSERT(parse(": {out}> /tmp/out; printf bytes >&$out", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A trailing group redirect has the same current-shell lifetime. */
  ASSERT(parse("{ :; } {out}> /tmp/out; printf bytes >&$out", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A bare `>&$name` after a completed group is a group redirect tail, not an
   * argv word or a separate redirect-only command. The group and later
   * command therefore share the previously persisted binding. */
  ASSERT(parse("exec {out}>/tmp/out; { :; } >&$out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && group >= 0 && printf_command >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 3 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A non-`exec` close is local under the default option, whereas an `exec`
   * close persists and makes the known later descriptor use invalid. */
  ASSERT(parse("exec {out}> /tmp/out; : {out}>&-; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A successful AND continuation necessarily observes setup performed by
   * its left side. Keep that state branch-local: the subsequent byte-flow
   * edge belongs to the consumer, while the setup remains visible on exec. */
  ASSERT(parse("exec {out}> /tmp/and-named && printf bytes >&$out", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-named");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, SHELL_DEP_FD_NAMED,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* `exec` is not special to the successful direct-AND visibility rule:
   * an ordinary current-shell command that allocates a named descriptor also
   * makes it available to its immediate right-hand continuation. */
  ASSERT(parse(": {out}> /tmp/and-ordinary && printf bytes >&$out", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-ordinary");
  int setup_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && setup_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)setup_command,
                      (uint32_t)document, SHELL_DEP_FD_NAMED,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/and-numeric && printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-numeric");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("true && exec {out}> /tmp/and-chain && printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-chain");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  static const char *const rejected[] = {
      "{out}> /tmp/out; printf bytes >&$out",
      "FOO=bar {out}> /tmp/out; printf bytes >&$out",
      "true && exec {out}> /tmp/out; printf bytes >&$out",
      "true || exec {out}> /tmp/out && printf bytes >&$out",
      "exec {out}> /tmp/out || : && printf bytes >&$out",
      "exec {out}> /tmp/out && :; printf bytes >&$out",
      "( exec {out}> /tmp/out; printf bytes >&$out ); printf bytes >&$out",
      "exec {out}> /tmp/out; exec {out}>&-; printf bytes >&$out",
      "exec {out}> /tmp/out; out=1; printf bytes >&$out",
      "exec {out}> /tmp/out; out+=shadow; printf bytes >&$out",
      "exec {o}> /tmp/one-char; o=shadow; printf bytes >&$o",
      "exec {out}> /tmp/out; o\\\nut=shadow; printf bytes >&$out",
      "exec {out}> /tmp/out; o\\\r\nut=shadow; printf bytes >&$out",
      "exec {out}> /tmp/out; o\\\nut+=shadow; printf bytes >&$out",
      "exec {out}> /tmp/out; o\\\r\nut+=shadow; printf bytes >&$out",
      "exec {out}> /tmp/out; unset out; printf bytes >&$out",
      "exec {out}> /tmp/out; un'set' out; printf bytes >&$out",
      "exec {out}> /tmp/out; un'set' 'out'; printf bytes >&$out",
      "exec {out}> /tmp/out; command unset out; printf bytes >&$out",
      "exec {out}> /tmp/out; builtin unset out; printf bytes >&$out",
      "exec {out}> /tmp/out; read out </dev/null; printf bytes >&$out",
      "exec {out}> /tmp/out; r'ead' out </dev/null; printf bytes >&$out",
      "exec {out}> /tmp/out; printf -v out 1; printf bytes >&$out",
      "exec {out}> /tmp/out; p'rintf' -v out 1; printf bytes >&$out",
      "exec {out}> /tmp/out; command printf -v out 1; printf bytes >&$out",
      "exec {out}> /tmp/out; export out=1; printf bytes >&$out",
      "exec {out}> /tmp/out; export out+=1; printf bytes >&$out",
      "exec {out}> /tmp/out; ex'port' out=1; printf bytes >&$out",
      "exec {out}> /tmp/out; declare out=1; printf bytes >&$out",
      "exec {out}> /tmp/out; declare out+=1; printf bytes >&$out",
      "exec {out}> /tmp/out; de'clare' out=1; printf bytes >&$out",
      "exec {out}> /tmp/out; declare 'out'=1; printf bytes >&$out",
      "exec {out}> /tmp/out; declare 'out'+=1; printf bytes >&$out",
      "exec {out}> /tmp/out; @(unset) out; printf bytes >&$out",
      "exec {out}> /tmp/out; eval 'out=1'; printf bytes >&$out",
      "exec {out}> /tmp/out; printf '%s' \"$(cat <&$out)\"",
      "exec {out}< /tmp/in; printf bytes >&$out",
      "exec {out}< /tmp/in; exec {out}> /tmp/out; "
      "printf '%s' \"$(cat <&$out)\"",
      "exec {out}> /tmp/out; exec {out}>&-; "
      "printf '%s' \"$(cat <&$out)\"",
      "shopt -s varredir_close; : {out}> /tmp/out; printf bytes >&$out",
      "x+=value shopt -s varredir_close; : {out}> /tmp/out; "
      "printf bytes >&$out",
      "x+\\\n=value shopt -u varredir_close; : {out}> /tmp/out; "
      "printf bytes >&$out",
      "sh'opt' '-s' varredir_close; : {out}> /tmp/out; printf bytes >&$out",
      "command shopt -u varredir_close; : {out}> /tmp/out; "
      "printf bytes >&$out",
      "shopt -s lastpipe; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "command shopt -u lastpipe; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "eval 'shopt -s lastpipe'; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      ". /tmp/shell-state; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "command source /tmp/shell-state; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "trap 'shopt -s lastpipe' DEBUG; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "alias change_scope='shopt -s lastpipe'; "
      "printf source | : {out}> /tmp/out; printf bytes >&$out",
      "shopt -s expand_aliases; printf source | : {out}> /tmp/out; "
      "printf bytes >&$out",
      "history -s 'shopt -s lastpipe'; fc -s -1; "
      "printf source | : {out}> /tmp/out; printf bytes >&$out",
      "enable -f /tmp/shell-state change_scope; "
      "printf source | : {out}> /tmp/out; printf bytes >&$out",
  };
  for (uint32_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }
  pass_count++;
}

/* A group redirect list is installed before that group's body runs. A brace
 * group shares its parent shell, while a subshell or a brace group isolated by
 * a pipeline/background relation keeps the named descriptor private. */
TEST(named_fd_group_execution_scopes) {
  shell_dep_graph_t graph = {0};

  ASSERT(parse("{ printf bytes >&$out; } {out}> /tmp/brace-out; "
               "printf later >&$out",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/brace-out");
  int first_printf = find_first_cmd(&graph);
  int later_printf = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && first_printf >= 0 && later_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)first_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)later_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* The redirect is visible inside the isolated group, but does not survive
   * in the caller's descriptor-variable state. */
  ASSERT(parse("( printf bytes >&$out ) {out}> /tmp/subshell-out", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/subshell-out");
  first_printf = find_first_cmd(&graph);
  ASSERT(document >= 0 && first_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)first_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  static const char *const nonexporting_groups[] = {
      "( : ) {out}> /tmp/subshell-out; printf bytes >&$out",
      "{ :; } {out}> /tmp/pipe-out | cat; printf bytes >&$out",
      "{ :; } {out}> /tmp/background-out & printf bytes >&$out",
  };
  for (uint32_t i = 0;
       i < sizeof(nonexporting_groups) / sizeof(nonexporting_groups[0]); i++) {
    ASSERT(parse(nonexporting_groups[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }

  /* A compound group's ordinary redirect list is restored before its direct
   * `&&` successor runs.  The success edge carries control, not the group's
   * temporary stdin document. */
  ASSERT(parse("{ cat; } <<< group-input && cat", &graph) == SHELL_DEP_OK);
  int group = -1;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_GROUP) {
      group = (int)node;
      break;
    }
  int tail = find_nth_cmd(&graph, 1);
  int here = -1;
  uint32_t reads = 0;
  bool group_read = false;
  bool tail_read = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (item->type != SHELL_EDGE_READ)
      continue;
    reads++;
    here = (int)item->from;
    group_read = group_read || item->to == (uint32_t)group;
    tail_read = tail_read || item->to == (uint32_t)tail;
  }
  ASSERT(group >= 0 && tail >= 0 && here >= 0 && reads == 1 && group_read &&
         !tail_read && graph.nodes[here].type == SHELL_NODE_DOC &&
         graph.nodes[here].doc.kind == SHELL_DOC_HERESTRING &&
         shell_dep_graph_validate(&graph).valid);

  /* Bash retains a `{name}` allocation from a non-isolated brace group, so
   * the proven success successor may resolve the symbolic descriptor even
   * though the group's ordinary redirect routes were discarded. */
  ASSERT(parse("{ printf inner >&$out; } {out}> /tmp/and-group-out && "
               "printf outer >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-group-out");
  first_printf = find_first_cmd(&graph);
  later_printf = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && first_printf >= 0 && later_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)first_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)later_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* All group-tail operations are installed before body substitutions. The
   * later dup must copy the opened stdin route, so nested command evaluation
   * reads the same file from fd 3. */
  ASSERT(parse("{ printf '%s' \"$(cat <&3)\"; } </tmp/group-mixed-in 3<&0",
               &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  document = find_file_doc(&graph, "/tmp/group-mixed-in");
  int nested_cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(group >= 0 && document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)group, SHELL_DEP_FD_NONE, 3) &&
         shell_dep_graph_validate(&graph).valid);

  /* The same source-order replay includes here-string and here-document
   * documents, not just file opens. */
  ASSERT(parse("{ printf '%s' \"$(cat <&3)\"; } <<< group-here 3<&0", &graph) ==
         SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_HERESTRING);
  nested_cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ printf '%s' \"$(cat <&3)\"; } <<EOF 3<&0\n"
               "group-doc\nEOF\n",
               &graph) == SHELL_DEP_OK);
  document = find_doc(&graph, SHELL_DOC_HEREDOC);
  nested_cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A process-substitution input followed by a dup is replayed before body
   * expansion too; no placeholder FILE path stands in for the pipe. */
  ASSERT(parse("{ printf '%s' \"$(cat <&3)\"; } < <(printf payload) 3<&0",
               &graph) == SHELL_DEP_OK);
  int process_producer = find_cmd_tokens(&graph, "printf", "payload");
  nested_cat = find_cmd_tokens(&graph, "cat", NULL);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(process_producer >= 0 && nested_cat >= 0 && group >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)process_producer,
                      (uint32_t)group, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)process_producer,
                      (uint32_t)nested_cat, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)process_producer,
                      (uint32_t)group, 1, 3) &&
         shell_dep_graph_validate(&graph).valid);

  /* The group's descriptor table is installed before its body starts, so a
   * nested command substitution inherits its named input descriptor too. */
  ASSERT(parse("{ printf '%s' \"$(cat <&$in)\"; } {in}</tmp/and-group-in && :",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-group-in");
  nested_cat = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* The same installation rule applies to ordinary descriptors. The
   * pre-body redirect must reach a nested shell even though its source text is
   * a trailing group list. */
  ASSERT(parse("{ printf '%s' \"$(cat <&0)\"; } </tmp/group-substitution-in",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/group-substitution-in");
  nested_cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(named_fd_group_body_replay) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("{ exec {fd}</tmp/inner; echo \"$(cat <&$fd)\"; }", &graph) ==
         SHELL_DEP_OK);
  int inner = find_file_doc(&graph, "/tmp/inner");
  int cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inner >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}</tmp/outer; { exec {fd}</tmp/inner; "
               "echo \"$(cat <&$fd)\"; }",
               &graph) == SHELL_DEP_OK);
  inner = find_file_doc(&graph, "/tmp/inner");
  int outer = find_file_doc(&graph, "/tmp/outer");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inner >= 0 && outer >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer, (uint32_t)cat,
                       SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}</tmp/outer; { exec {fd}</tmp/inner; cat <&$fd; }",
               &graph) == SHELL_DEP_OK);
  inner = find_file_doc(&graph, "/tmp/inner");
  outer = find_file_doc(&graph, "/tmp/outer");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inner >= 0 && outer >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer, (uint32_t)cat,
                       SHELL_DEP_FD_NONE, 0));

  static const char *const group_cases[] = {
      ("exec {fd}</tmp/outer; { exec {fd}</tmp/inner; cat <&$fd; } "
       "{tail}>/tmp/tail"),
      "exec {fd}</tmp/outer; { { exec {fd}</tmp/inner; cat <&$fd; }; }",
      "exec {fd}</tmp/outer; { exec {fd}</tmp/inner && cat <&$fd; }",
  };
  for (uint32_t i = 0; i < sizeof(group_cases) / sizeof(group_cases[0]); i++) {
    ASSERT(parse(group_cases[i], &graph) == SHELL_DEP_OK);
    inner = find_file_doc(&graph, "/tmp/inner");
    outer = find_file_doc(&graph, "/tmp/outer");
    cat = find_cmd_tokens(&graph, "cat", NULL);
    ASSERT(inner >= 0 && outer >= 0 && cat >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner, (uint32_t)cat,
                        SHELL_DEP_FD_NONE, 0) &&
           !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer,
                         (uint32_t)cat, SHELL_DEP_FD_NONE, 0) &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("{ exec {fd}</tmp/inner; cat <&$fd; } {fd}</tmp/outer",
               &graph) == SHELL_DEP_OK);
  inner = find_file_doc(&graph, "/tmp/inner");
  outer = find_file_doc(&graph, "/tmp/outer");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inner >= 0 && outer >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer, (uint32_t)cat,
                       SHELL_DEP_FD_NONE, 0));

  /* A subshell sees the rebind but must not publish it back to its parent. */
  ASSERT(parse("exec {fd}</tmp/outer; ( exec {fd}</tmp/inner; cat <&$fd ); "
               "cat <&$fd",
               &graph) == SHELL_DEP_OK);
  inner = find_file_doc(&graph, "/tmp/inner");
  outer = find_file_doc(&graph, "/tmp/outer");
  int local_cat = find_nth_cmd(&graph, 2);
  int parent_cat = find_nth_cmd(&graph, 3);
  ASSERT(inner >= 0 && outer >= 0 && local_cat >= 0 && parent_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inner,
                      (uint32_t)local_cat, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer,
                      (uint32_t)parent_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  static const char *const invalidated[] = {
      "exec {fd}</tmp/outer; unset fd; echo \"$(cat <&$fd)\"",
      "exec {fd}</tmp/outer; fd=shadow; echo \"$(cat <&$fd)\"",
      "exec {fd}</tmp/outer; { unset fd; echo \"$(cat <&$fd)\"; }",
      "exec {fd}</tmp/outer; { fd=shadow; echo \"$(cat <&$fd)\"; }",
  };
  for (uint32_t i = 0; i < sizeof(invalidated) / sizeof(invalidated[0]); i++)
    ASSERT(parse(invalidated[i], &graph) == SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(conditional_group_descriptor_replay) {
  shell_dep_graph_t graph = {0};
  static const char *const commented_connectors[] = {
      "{ exec {fd}</tmp/snapshot-input; } >/dev/null # && not a connector\n"
      "printf \"$(cat <&$fd)\"",
      "{ exec {fd}</tmp/snapshot-input; } >/dev/null # || not a connector\n"
      "printf \"$(cat <&$fd)\"",
      "{ exec {fd}</tmp/snapshot-input; } >\"/tmp/out # && literal\"; "
      "printf \"$(cat <&$fd)\"",
  };
  for (uint32_t i = 0;
       i < sizeof(commented_connectors) / sizeof(commented_connectors[0]);
       i++) {
    ASSERT(parse(commented_connectors[i], &graph) == SHELL_DEP_OK);
    int input = find_file_doc(&graph, "/tmp/snapshot-input");
    int nested = find_cmd_tokens(&graph, "cat", NULL);
    ASSERT(input >= 0 && nested >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)input,
                        (uint32_t)nested, SHELL_DEP_FD_NONE, 0) &&
           shell_dep_graph_validate(&graph).valid);
  }
  ASSERT(parse("false && { :; exec {fd}</tmp/skipped; }; "
               "echo \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(parse("true || { :; exec {fd}</tmp/skipped; }; "
               "echo \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(parse("{ :; exec {fd}</tmp/skipped; } && :; "
               "echo \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_EPARSE);

  ASSERT(parse("true && { exec {fd}</tmp/inside; "
               "echo \"$(cat <&$fd)\"; }",
               &graph) == SHELL_DEP_OK);
  int inside = find_file_doc(&graph, "/tmp/inside");
  int cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inside >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inside, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);
  ASSERT(parse("false || { exec {fd}</tmp/inside; "
               "echo \"$(cat <&$fd)\"; }",
               &graph) == SHELL_DEP_OK);
  inside = find_file_doc(&graph, "/tmp/inside");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inside >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inside, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0));

  ASSERT(parse("{ exec 3<&0; } </tmp/group-input; cat <&3", &graph) ==
         SHELL_DEP_OK);
  inside = find_file_doc(&graph, "/tmp/group-input");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inside >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inside, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);
  ASSERT(parse("{ cat <&3; } 3</tmp/group-input", &graph) == SHELL_DEP_OK);
  inside = find_file_doc(&graph, "/tmp/group-input");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inside >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inside, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3</tmp/outer; true && { exec 3</tmp/inner; "
               "{ cat <&3; }; }",
               &graph) == SHELL_DEP_OK);
  inside = find_file_doc(&graph, "/tmp/inner");
  int outer = find_file_doc(&graph, "/tmp/outer");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(inside >= 0 && outer >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)inside, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)outer, (uint32_t)cat,
                       SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}</tmp/outer; true && { unset fd; "
               "{ cat <&$fd; }; }",
               &graph) == SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(named_fd_builtin_mutation_follows_own_redirects) {
  shell_dep_graph_t graph = {0};
  static const char *const output_cases[] = {
      "exec {fd}>/tmp/before-mutation; unset fd >&$fd",
      "exec {fd}>/tmp/before-mutation; printf -v fd shadow >&$fd",
      "exec {fd}>/tmp/before-mutation; command unset fd >&$fd",
      "exec {fd}>/tmp/before-mutation; { unset fd >&$fd; }",
  };
  for (uint32_t i = 0; i < sizeof(output_cases) / sizeof(output_cases[0]);
       i++) {
    ASSERT(parse(output_cases[i], &graph) == SHELL_DEP_OK);
    int document = find_file_doc(&graph, "/tmp/before-mutation");
    int mutator = find_cmd_tokens(&graph,
                                  i == 1   ? "printf"
                                  : i == 2 ? "command"
                                           : "unset",
                                  NULL);
    ASSERT(document >= 0 && mutator >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)mutator,
                        (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("exec {fd}</tmp/before-read; read fd <&$fd", &graph) ==
         SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/before-read");
  int reader = find_cmd_tokens(&graph, "read", NULL);
  ASSERT(document >= 0 && reader >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)reader, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}</tmp/before-read; printf -v fd shadow "
               "> >(cat <&$fd)",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/before-read");
  reader = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(document >= 0 && reader >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)reader, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}</tmp/before-read; printf -v fd shadow "
               "\"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/before-read");
  reader = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(document >= 0 && reader >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)reader, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  static const char *const invalid_after[] = {
      "exec {fd}>/tmp/before-mutation; unset fd >&$fd; printf x >&$fd",
      "exec {fd}>/tmp/before-mutation; unset fd >&$fd && printf x >&$fd",
      "exec {fd}</tmp/before-read; read fd <&$fd; cat <&$fd",
      "exec {fd}>/tmp/before-mutation; fd=shadow >&$fd",
      "printf -v fd shadow {fd}>/tmp/before-mutation; printf x >&$fd",
      "printf -v fd shadow {fd}>/tmp/before-mutation && printf x >&$fd",
      "unset fd {fd}>/tmp/before-mutation; printf x >&$fd",
  };
  for (uint32_t i = 0; i < sizeof(invalid_after) / sizeof(invalid_after[0]);
       i++)
    ASSERT(parse(invalid_after[i], &graph) == SHELL_DEP_EPARSE &&
           graph.node_count == 0 && graph.edge_count == 0);
  pass_count++;
}

/* Redirect filenames and symbolic duplication operands belong to the shell,
 * not to the builtin's variable-argument list. */
TEST(named_fd_builtin_redirect_operands) {
  static const char *const surviving[] = {
      "exec {fd}>/tmp/route; unset unrelated >&$fd; printf x >&$fd",
      "exec {fd}>/tmp/route; unset unrelated >fd; printf x >&$fd",
      "exec {fd}>/tmp/route; command unset unrelated >other; printf x >&$fd",
      "exec {fd}>/tmp/route; export OTHER=1 >fd=shadow; printf x >&$fd",
      "exec {fd}>/tmp/route; declare OTHER=1 >fd=shadow; printf x >&$fd",
      "exec {fd}>/tmp/route; typeset OTHER=1 >fd=shadow; printf x >&$fd",
      "exec {fd}>/tmp/route; >fd=shadow export OTHER=1; printf x >&$fd",
      "exec {fd}>/tmp/route; printf '%s' x >&$fd; printf x >&$fd",
  };
  shell_dep_graph_t graph = {0};
  for (size_t i = 0; i < sizeof(surviving) / sizeof(surviving[0]); i++) {
    shell_dep_error_t parsed = parse(surviving[i], &graph);
    if (parsed != SHELL_DEP_OK)
      fprintf(stderr, "builtin redirect case %zu failed: %s (%d)\n", i,
              surviving[i], parsed);
    ASSERT(parsed == SHELL_DEP_OK);
    int document = find_file_doc(&graph, "/tmp/route");
    int writer = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
    ASSERT(document >= 0 && writer >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                        (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
           shell_dep_graph_validate(&graph).valid);
  }
  ASSERT(parse("exec {fd}>/tmp/route; unset fd >other; printf x >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(parse("exec {fd}>/tmp/route; export fd=shadow >other; "
               "printf x >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  pass_count++;
}

TEST(backtick_command_boundaries) {
  shell_dep_graph_t graph = {0};
  static const char *const commands[] = {
      "echo `printf x; printf y`; next",
      "echo `printf x | cat` && next",
      "echo `printf \\`quoted\\` | cat`; next",
  };
  for (uint32_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    ASSERT(parse(commands[i], &graph) == SHELL_DEP_OK);
    ASSERT(find_cmd_tokens(&graph, "echo", NULL) >= 0 &&
           find_cmd_tokens(&graph, "next", NULL) >= 0 &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* Nested shell evaluations receive the descriptor environment that the shell
 * would have at that exact expansion point.  In particular, ordinary command
 * words expand before their command's redirect list, while a redirect operand
 * and an expandable heredoc see only preceding entries in that list. */
TEST(named_fd_recursive_snapshot_timing) {
  shell_dep_graph_t graph = {0};

  static const char *const rejected[] = {
      "printf '%s' {fd}</tmp/in \"$(cat <&$fd)\"",
      "printf '%s' \"$(cat <&$fd)\" {fd}</tmp/in",
      "exec {fd}</tmp/in; exec {fd}<&-; printf '%s' \"$(cat <&$fd)\"",
      "false && exec {fd}</tmp/in; printf '%s' \"$(cat <&$fd)\"",
      "true || exec {fd}</tmp/in && printf '%s' \"$(cat <&$fd)\"",
      "printf > >(cat <&$fd) {fd}</tmp/in",
      "cat <<EOF {fd}</tmp/in\n$(cat <&$fd)\nEOF\n",
  };
  for (uint32_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }

  /* A preceding ordinary command persists its named allocation under the
   * default `varredir_close` setting. Its later command substitution receives
   * the exact descriptor state, rather than rediscovering raw source text. */
  ASSERT(parse("printf '%s' {fd}</tmp/in; printf '%s' \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/in");
  int nested_cat = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Recursive parsing asks for a snapshot before the enclosing graph has
   * emitted every control edge. A right-hand substitution still receives the
   * proven AND-success descriptor state, while an OR bypass above is rejected
   * by the matrix before this case. */
  ASSERT(parse("exec {fd}</tmp/and-in && printf '%s' \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/and-in");
  nested_cat = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Duplicating an inherited numeric descriptor is a valid named binding,
   * even though it has no document endpoint to materialize in this graph. */
  static const char *const inherited_numeric[] = {
      "exec {fd}<&0; printf '%s' \"$(cat <&$fd)\"",
      "exec {fd}>&1; printf '%s' \"$(printf bytes >&$fd)\"",
  };
  for (uint32_t i = 0;
       i < sizeof(inherited_numeric) / sizeof(inherited_numeric[0]); i++) {
    ASSERT(parse(inherited_numeric[i], &graph) == SHELL_DEP_OK);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("exec {source}</tmp/in; exec {copy}<&$source; printf '%s' "
               "\"$(cat <&$copy)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  nested_cat = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {source}>/tmp/out; exec {copy}<&$source; printf '%s' "
               "\"$(printf bytes >&$copy)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int nested_printf = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && nested_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf {fd}</tmp/in > >(cat <&$fd)", &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  ASSERT(document >= 0 && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat {fd}</tmp/in <<EOF\n$(cat <&$fd)\nEOF\n", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  ASSERT(document >= 0 && shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(group_entry_redirect_expansion_timing) {
  shell_dep_graph_t graph = {0};
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cd_as_cmd = true;
  const char *cwd_command = "cd /tmp; { :; } > >(pwd); pwd";
  ASSERT(shell_dep_graph_parse(cwd_command, strlen(cwd_command), "/workspace",
                               &limits, &graph) == SHELL_DEP_OK);
  int nested_pwd = find_cmd_tokens(&graph, "pwd", NULL);
  int body = find_cmd_tokens(&graph, ":", NULL);
  ASSERT(nested_pwd >= 0 && body >= 0 && nested_pwd < body &&
         graph.nodes[nested_pwd].cmd.cwd_known);
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[nested_pwd].cmd.cwd_offset),
                "/tmp");
  ASSERT(shell_dep_graph_validate(&graph).valid);

  static const char *const other_group_operands[] = {
      "cd /tmp; { :; } >$(pwd)",
      "cd /tmp; { :; } <<<$(pwd)",
      "cd /tmp; { :; } <<EOF\n$(pwd)\nEOF\n",
      "( cd /tmp; { :; } > >(pwd) ); pwd",
  };
  for (uint32_t i = 0;
       i < sizeof(other_group_operands) / sizeof(other_group_operands[0]);
       i++) {
    ASSERT(parse_cwd(other_group_operands[i], "/workspace", &graph) ==
           SHELL_DEP_OK);
    nested_pwd = find_cmd_tokens(&graph, "pwd", NULL);
    ASSERT(nested_pwd >= 0 && graph.nodes[nested_pwd].cmd.cwd_known);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[nested_pwd].cmd.cwd_offset),
                  "/tmp");
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  const char *isolated = "cd /tmp; ( { :; } > >(pwd) ); pwd";
  ASSERT(shell_dep_graph_parse(isolated, strlen(isolated), "/workspace",
                               &limits, &graph) == SHELL_DEP_OK);
  nested_pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(nested_pwd >= 0 && graph.nodes[nested_pwd].cmd.cwd_known);
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[nested_pwd].cmd.cwd_offset),
                "/tmp");
  ASSERT(shell_dep_graph_validate(&graph).valid);

  const char *uncertain = "cd \"$path\"; { :; } > >(pwd)";
  ASSERT(shell_dep_graph_parse(uncertain, strlen(uncertain), "/workspace",
                               &limits, &graph) == SHELL_DEP_OK);
  nested_pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(nested_pwd >= 0 && !graph.nodes[nested_pwd].cmd.cwd_known &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse_cwd("cd \"$path\"; echo \"$(pwd)\"", "/workspace", &graph) ==
         SHELL_DEP_OK);
  nested_pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(nested_pwd >= 0 && !graph.nodes[nested_pwd].cmd.cwd_known &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3</tmp/group-entry-in; { :; } <<<$(cat <&3)", &graph) ==
         SHELL_DEP_OK);
  int file = find_file_doc(&graph, "/tmp/group-entry-in");
  int cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(file >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)file, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {in}</tmp/group-entry-in && ! { :; } <<<$(cat <&$in)",
               &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "/tmp/group-entry-in");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(file >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)file, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {in}</tmp/group-entry-in; { :; } <<<$(cat <&$in)",
               &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "/tmp/group-entry-in");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(file >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)file, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {in}</tmp/group-entry-in && { :; } <<<$(cat <&$in)",
               &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "/tmp/group-entry-in");
  cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(file >= 0 && cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)file, (uint32_t)cat,
                      SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* The inner group is prebuilt but has not run when the outer redirect
   * operand expands. Its named descriptor must not leak backwards in time. */
  ASSERT(parse("{ { :; } {in}</tmp/later; } <<<$(cat <&$in)", &graph) ==
         SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("{ :; } {in}</tmp/earlier <<<$(cat <&$in)", &graph) ==
         SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  ASSERT(parse("{ :; } <<<$(cat <&$in) {in}</tmp/later", &graph) ==
         SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Prebuilt compound documents still honor graph bounds before any body or
   * operand expansion is allowed to publish a partial topology. */
  static const char *const bounded[] = {
      "{ :; } >/tmp/group-bound",
      "{ :; } <<<$(pwd)",
      "{ :; } <<EOF\n$(pwd)\nEOF\n",
  };
  shell_dep_limits_t bounded_limits = SHELL_DEP_LIMITS_DEFAULT;
  bounded_limits.max_nodes = 1;
  for (uint32_t i = 0; i < sizeof(bounded) / sizeof(bounded[0]); i++) {
    ASSERT(shell_dep_graph_parse(bounded[i], strlen(bounded[i]), ".",
                                 &bounded_limits, &graph) == SHELL_DEP_ETRUNC);
    ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0);
  }

  static const char *const quoted_substitutions[] = {
      "{ :; } <<<$(printf $'a)b')",
      "{ :; } > >(printf $'a)b')",
      "{ :; } >$(printf $'a)b')",
  };
  for (uint32_t i = 0;
       i < sizeof(quoted_substitutions) / sizeof(quoted_substitutions[0]);
       i++) {
    ASSERT(parse(quoted_substitutions[i], &graph) == SHELL_DEP_OK);
    ASSERT(find_cmd_tokens(&graph, "printf", NULL) >= 0 &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* A persistent `exec` redirect updates the current shell's numeric descriptor
 * table. It is setup, not byte flow: only a later command that duplicates the
 * descriptor onto stdin/stdout has a concrete edge to the resource. */
TEST(numeric_exec_descriptor_lifecycle) {
  shell_dep_graph_t graph = {0};

  ASSERT(parse("exec >/tmp/stdout; printf bytes", &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/stdout");
  int exec_command = find_nth_cmd(&graph, 0);
  int printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)exec_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("MODE=quiet exec 3>/tmp/prefixed; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/prefixed");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)exec_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec -cl 3>/tmp/options; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/options");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec -a label 3>/tmp/option-name; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/option-name");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec -- 3>/tmp/end-options; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/end-options");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec -alabel 3>/tmp/argv0; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/argv0");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec </tmp/stdin; cat", &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/stdin");
  exec_command = find_nth_cmd(&graph, 0);
  int cat_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && cat_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)document,
                      (uint32_t)exec_command, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)cat_command, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>>/tmp/append; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/append");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/out; printf bytes >&3", &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Shell roles use quote removal, not raw source spelling. These forms all
   * invoke a current-shell `exec` and must materialize the later route only
   * when stdout is duplicated onto the persistent descriptor. */
  ASSERT(parse("e'x'ec 3>/tmp/quoted-exec; printf bytes >&3", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/quoted-exec");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)exec_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("e\\xec '-c''l' 3>/tmp/escaped-exec; printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/escaped-exec");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* An auxiliary descriptor does not imply that an unrelated command writes
   * to it. The graph records the persistent setup but no speculative flow. */
  ASSERT(parse("exec 3>/tmp/out; printf bytes", &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && count_edge_type(&graph, SHELL_EDGE_FD_OPEN) == 1 &&
         printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/out; exec 4>&3; printf bytes >&4", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int duplicate_exec = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && duplicate_exec >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)duplicate_exec,
                      (uint32_t)duplicate_exec, 3, 4) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* The target word can remain quoted or be a distinct lexical token. It is
   * still a static descriptor target, never an argv or pathname operand. */
  ASSERT(parse("exec 3>/tmp/quoted-dup; exec 4>&\"3\"; printf bytes >&4",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/quoted-dup");
  duplicate_exec = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && duplicate_exec >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)duplicate_exec,
                      (uint32_t)duplicate_exec, 3, 4) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/bare-dup; exec 4>& 3; printf bytes >&4", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/bare-dup");
  duplicate_exec = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && duplicate_exec >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)duplicate_exec,
                      (uint32_t)duplicate_exec, 3, 4) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* `command` preserves execution for its `-p` form. A following `exec`
   * without a command operand therefore has the same current-shell descriptor
   * lifetime as direct exec, including numeric open and duplication state. */
  ASSERT(parse("command -p -- exec 3>/tmp/command-open; command exec 4>&3; "
               "printf bytes >&4",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/command-open");
  exec_command = find_nth_cmd(&graph, 0);
  duplicate_exec = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && exec_command >= 0 && duplicate_exec >= 0 &&
         printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)duplicate_exec,
                      (uint32_t)duplicate_exec, 3, 4) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("com'mand' '-p' '--' e'x'ec 3>/tmp/quoted-command; "
               "com'mand' e'x'ec 4>&3; printf bytes >&4",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/quoted-command");
  exec_command = find_nth_cmd(&graph, 0);
  duplicate_exec = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && exec_command >= 0 && duplicate_exec >= 0 &&
         printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)duplicate_exec,
                      (uint32_t)duplicate_exec, 3, 4) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A qualified exec close must replace an earlier named binding. The later
   * exact parameter reference is consequently not a usable route. */
  ASSERT(parse("command exec {fd}>/tmp/command-close; command exec {fd}>&-; "
               "printf bytes >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Inspection forms do not execute their argument and must not accidentally
   * promote the redirect into persistent descriptor state. */
  ASSERT(parse("command -v exec 3>/tmp/command-inspect; printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/command-inspect");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("builtin e'x'ec 3>/tmp/builtin-inspect; printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/builtin-inspect");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("com'mand' '-V' e'x'ec 3>/tmp/quoted-inspect; "
               "printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/quoted-inspect");
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/out; exec 3>&-; printf bytes", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  exec_command = find_nth_cmd(&graph, 1);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_CLOSE, (uint32_t)exec_command,
                      (uint32_t)exec_command, 3, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>/tmp/quoted-close; exec 3>&\"-\"; printf bytes >&3",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec 3>/tmp/bare-close; exec 3>& -; printf bytes >&3",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec 3>/tmp/out; exec 3>&-; printf bytes >&3", &graph) ==
         SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Nested command substitutions inherit persistent numeric descriptors, but
   * their captured stdout remains independent of the parent descriptor. */
  ASSERT(parse("exec 3>/tmp/out; printf '%s' \"$(printf bytes >&3)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int nested_printf = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A nested `exec 4>&3` is descriptor setup, not a write by the `exec`
   * builtin. Its later nested command is the one that materializes the
   * imported route. */
  ASSERT(parse("exec 3>/tmp/out; printf '%s' \"$(exec 4>&3; "
               "printf bytes >&4)\"",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int nested_exec = find_nth_cmd(&graph, 2);
  nested_printf = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && nested_exec >= 0 && nested_printf >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)nested_exec,
                      (uint32_t)nested_exec, 3, 4) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_exec,
                       (uint32_t)document, 4, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_printf,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3</tmp/in; printf '%s' \"$(cat <&3)\"", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/in");
  int nested_cat = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_cat >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                      (uint32_t)nested_cat, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Process substitutions receive the same persistent auxiliary descriptor
   * state, while their stdin remains the substitution stream. */
  ASSERT(parse("exec 3>/tmp/out; printf payload > >(cat >&3)", &graph) ==
         SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  int nested_consumer = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && nested_consumer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)nested_consumer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3> >(cat); printf bytes >&3", &graph) == SHELL_DEP_OK);
  int endpoint = find_endpoint(&graph);
  exec_command = find_nth_cmd(&graph, 0);
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(endpoint >= 0 && exec_command >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)exec_command,
                      (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)endpoint, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3< <(printf bytes); cat <&3", &graph) == SHELL_DEP_OK);
  exec_command = find_nth_cmd(&graph, 0);
  int producer = find_nth_cmd(&graph, 1);
  cat_command = find_nth_cmd(&graph, 2);
  ASSERT(exec_command >= 0 && producer >= 0 && cat_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)producer,
                      (uint32_t)exec_command, 1, 3) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)cat_command, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* Descriptor state follows the effective static builtin after quote removal.
 * Wrapper redirects are temporary, while a dynamic wrapper target can execute
 * an arbitrary assignment builtin and must therefore invalidate every named
 * route before a later symbolic descriptor use. */
TEST(static_builtin_descriptor_route_regressions) {
  shell_dep_graph_t graph = {0};

  /* `unset -f` and `unset -n` do not remove ordinary descriptor variables.
   * `-v` does, and conflicting function/variable options fail before changing
   * either namespace. */
  ASSERT(parse("exec {out}> /tmp/function; unset -f out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/function");
  int printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}> /tmp/nameref; unset '-n' out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/nameref");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}> /tmp/variable; unset -v out; printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/conflict; unset -fv out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/conflict");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}> /tmp/out; command >/tmp/log unset out; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/out; command -- unset out; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/out; builtin -- unset out; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Wrapper chains retain the final builtin's current-shell effect. A chain
   * that reaches unset, printf -v, or export must not leave a stale named-FD
   * route for a later descriptor expansion. */
  ASSERT(parse("exec {out}> /tmp/out; command builtin unset out; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/out; builtin command printf -v out value; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/out; command command export out=value; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("exec {out}> /tmp/out; command \"$target\"; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* `declare -p` only inspects state. It must not discard the named descriptor
   * route, unlike a declaration assignment. */
  ASSERT(parse("exec {out}> /tmp/declared; declare -p; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/declared");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* An invalid static printf assignment target fails before mutating its
   * variable, so it does not invalidate an unrelated descriptor binding. */
  ASSERT(parse("exec {out}> /tmp/out; printf -v 3 ignored; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("com'mand' '-pp' e'x'ec 3>/tmp/repeated-p; "
               "printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/repeated-p");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A chain of `command` wrappers preserves `exec`'s current-shell
   * descriptor lifetime. Introducing `builtin` does not: Bash scopes the
   * redirect to that wrapper invocation, so the later writer has no route. */
  ASSERT(parse("command command exec 3>/tmp/nested-command; printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/nested-command");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("command builtin exec 3>/tmp/nested-builtin; "
               "printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/nested-builtin");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("builtin command exec 3>/tmp/builtin-command; "
               "printf bytes >&3",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/builtin-command");
  printf_command = find_nth_cmd(&graph, 1);
  ASSERT(document >= 0 && printf_command >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                       (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* Descriptor variables are shell identifiers after quote removal. A static
 * mutation of `{left}` must not erase an independent `{right}` binding merely
 * because its operand was quoted or physically continued in source. */
TEST(quoted_named_fd_mutation_targets) {
  static const char *const mutations[] = {
      "unset 'left'",        "unset -v \"left\"",      "printf -v le'ft' value",
      "export 'left'=value", "declare le\"ft\"=value", "typeset $'left'=value",
  };
  shell_dep_graph_t graph = {0};
  for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
    char command[256];
    int written = snprintf(command, sizeof(command),
                           "exec {left}>/tmp/left; exec {right}>/tmp/right; "
                           "%s; printf bytes >&$right",
                           mutations[i]);
    ASSERT(written > 0 && (size_t)written < sizeof(command));
    shell_dep_error_t parsed = parse(command, &graph);
    if (parsed != SHELL_DEP_OK)
      fprintf(stderr, "quoted mutation %s returned %d\n", mutations[i], parsed);
    ASSERT(parsed == SHELL_DEP_OK);
    int document = find_file_doc(&graph, "/tmp/right");
    int printf_command = find_nth_cmd(&graph, 3);
    ASSERT(document >= 0 && printf_command >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                        (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* A plain declaration reads metadata without changing the descriptor
   * variable, even when its name contains quotes. */
  ASSERT(parse("exec {left}>/tmp/left; declare 'left'; "
               "printf bytes >&$left",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/left");
  int printf_command = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* The stored route and the static target both allow physical continuation.
   * Removing `right` must leave the independently named left route alive. */
  ASSERT(parse("exec {left}>/tmp/left; exec {ri\\\nght}>/tmp/right; "
               "unset ri\\\nght; printf bytes >&$left",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/left");
  printf_command = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && printf_command >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)printf_command,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Runtime, malformed, and invalid assignment targets remain conservative:
   * they could alter any descriptor variable, so no later symbolic route is
   * trusted. */
  static const char *const uncertain_mutations[] = {
      "unset \"$target\"",
      "printf -v \"$target\" value",
      "export \"$target\"=value",
      "declare 1left=value",
  };
  for (size_t i = 0;
       i < sizeof(uncertain_mutations) / sizeof(uncertain_mutations[0]); i++) {
    char command[256];
    int written = snprintf(command, sizeof(command),
                           "exec {left}>/tmp/left; exec {right}>/tmp/right; "
                           "%s; printf bytes >&$right",
                           uncertain_mutations[i]);
    ASSERT(written > 0 && (size_t)written < sizeof(command));
    ASSERT(parse(command, &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }
  pass_count++;
}

TEST(decoded_assignment_targets_and_env_docs) {
  shell_dep_graph_t graph = {0};
  static const char *const spellings[] = {
      "export \"NAME=$(printf data)\"",
      "export NA\"ME\"=value",
      "export $'NA\\x4dE'=value",
      "export N\\AME=value",
      "export 'NAME=value'",
      "export \"NAME+=value\"",
  };
  for (size_t i = 0; i < sizeof(spellings) / sizeof(spellings[0]); i++) {
    ASSERT(parse(spellings[i], &graph) == SHELL_DEP_OK);
    const shell_dep_doc_t *env = NULL;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_DOC &&
          graph.nodes[node].doc.kind == SHELL_DOC_ENVVAR)
        env = &graph.nodes[node].doc;
    ASSERT(env != NULL && count_doc_kind(&graph, SHELL_DOC_ENVVAR) == 1);
    ASSERT(((env->flags & SHELL_DEP_DOC_FLAG_ENVVAR_APPEND) != 0) == (i == 5));
    size_t length = 0;
    size_t written = SIZE_MAX;
    char name[8] = {0};
    ASSERT(shell_dep_doc_env_name_length(env, &length) && length == 4 &&
           shell_dep_doc_write_env_name(env, name, sizeof(name), &written) &&
           written == 4 && memcmp(name, "NAME", 4) == 0 &&
           shell_dep_doc_env_name_equals(env, "NAME", 4) &&
           !shell_dep_doc_env_name_equals(env, "OTHER", 5));
    written = SIZE_MAX;
    ASSERT(!shell_dep_doc_write_env_name(env, name, 3, &written) &&
           written == 0 && memcmp(name, "NAME", 4) == 0);
    ASSERT(shell_dep_graph_validate(&graph).valid);
    if (i == 0) {
      int command = find_cmd_tokens(&graph, "export", NULL);
      int producer = find_cmd_tokens(&graph, "printf", NULL);
      ASSERT(command >= 0 && producer >= 0 &&
             has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                      (uint32_t)command));
    }
  }
  shell_dep_doc_t non_env = {.kind = SHELL_DOC_FILE};
  size_t rejected_length = SIZE_MAX;
  size_t rejected_written = SIZE_MAX;
  char rejected_name[10] = "untouched";
  ASSERT(!shell_dep_doc_env_name_length(&non_env, &rejected_length) &&
         rejected_length == 0 &&
         !shell_dep_doc_write_env_name(&non_env, rejected_name,
                                       sizeof(rejected_name),
                                       &rejected_written) &&
         rejected_written == 0 &&
         memcmp(rejected_name, "untouched", sizeof(rejected_name)) == 0 &&
         !shell_dep_doc_env_name_equals(&non_env, "NAME", 4));
  ASSERT(parse("NAME+=value command", &graph) == SHELL_DEP_OK);
  bool leading_append = false;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_DOC &&
        graph.nodes[node].doc.kind == SHELL_DOC_ENVVAR)
      leading_append =
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_ENVVAR_APPEND) != 0;
  ASSERT(leading_append && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}>/tmp/route; export OTHER=$(printf data); "
               "printf x >&$fd",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/route");
  int writer = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE));
  ASSERT(parse("exec {fd}>/tmp/route; export \"OTHER=$(printf data)\"; "
               "printf x >&$fd",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/route");
  writer = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE));
  ASSERT(parse("exec {fd}>/tmp/route; declare OTHER=\"$(printf data)\"; "
               "printf x >&$fd",
               &graph) == SHELL_DEP_OK);
  int declaration = find_cmd_tokens(&graph, "declare", NULL);
  int producer = find_cmd_tokens(&graph, "printf", NULL);
  ASSERT(declaration >= 0 && producer >= 0 &&
         has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
                  (uint32_t)declaration));
  ASSERT(parse("exec {fd}>/tmp/route; export fd=$(printf data); "
               "printf x >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(parse("exec {fd}>/tmp/route; export \"fd=$(printf data)\"; "
               "printf x >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(parse("exec {left}>/tmp/left; exec {right}>/tmp/right; "
               "export \"left=$(printf data)\"; printf x >&$right",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/right");
  writer = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* Bash parses `printf` options only before its format operand. Keep literal
 * `-v` data from discarding a route, while attached `-vname` assignments must
 * retire exactly that route after quote removal. */
TEST(printf_v_named_fd_option_contract) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("exec {out}>/tmp/out; printf '%s' -v out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  int document = find_file_doc(&graph, "/tmp/out");
  int writer = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}>/tmp/out; printf -- -v out; printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  writer = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Static invalid destinations make Bash printf fail before assigning a
   * variable. They are not dynamic writers, so an existing route remains
   * available to the next command. */
  ASSERT(parse("exec {out}>/tmp/out; printf -v9 value; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  writer = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}>/tmp/out; printf -v 9 value; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/out");
  writer = find_nth_cmd(&graph, 2);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {left}>/tmp/left; exec {right}>/tmp/right; "
               "printf -v'left' value; printf bytes >&$right",
               &graph) == SHELL_DEP_OK);
  document = find_file_doc(&graph, "/tmp/right");
  writer = find_nth_cmd(&graph, 3);
  ASSERT(document >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)document, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {out}>/tmp/out; printf -vout value; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  ASSERT(parse("exec {out}>/tmp/out; printf \"$format\"; "
               "printf bytes >&$out",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  /* Bash treats `name[0]` as an array target, including the scalar element
   * zero. It must not be mistaken for printf's harmless invalid-target path:
   * accepting it would preserve the old {out} route after the variable value
   * changed. */
  static const char *const array_targets[] = {
      "printf -v out[0] value",
      "printf -vout[0] value",
      "printf -v 'out[0]' value",
      "printf -v $'out[0]' value",
  };
  for (size_t i = 0; i < sizeof(array_targets) / sizeof(array_targets[0]);
       i++) {
    char command[256];
    int written = snprintf(command, sizeof(command),
                           "exec {out}>/tmp/out; %s; printf bytes >&$out",
                           array_targets[i]);
    ASSERT(written > 0 && (size_t)written < sizeof(command));
    ASSERT(parse(command, &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }
  pass_count++;
}

/* Keep the persistent named-FD resolver exercised across the forms that share
 * one logical descriptor while changing quoting, direction, scope, and
 * declaration semantics. These are parser-only fixtures: every accepted row
 * must yield an internally consistent effective-I/O graph. */
TEST(named_fd_route_cross_product_matrix) {
  static const struct {
    const char *command;
    shell_dep_error_t expected;
  } cases[] = {
      {"exec {out}>/tmp/out; printf x >&${out}", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf x >&\"$out\"", SHELL_DEP_OK},
      {"exec {out}>>/tmp/out; printf x >&$out", SHELL_DEP_OK},
      {"exec {in}</tmp/in; exec {copy}<&$in; cat <&$copy", SHELL_DEP_OK},
      {"exec {both}<>/tmp/rw; cat <&$both; printf x >&$both", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; exec {copy}>&$out; printf x >&$copy",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; { printf x; } >&$out; printf y >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; ( printf x >&$out ); printf y >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; { printf x; } | cat; printf y >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf x >&$out | cat; printf y >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf \"$(printf nested >&$out)\"", SHELL_DEP_OK},
      {"exec {in}</tmp/in; printf \"$(cat <&$in)\"", SHELL_DEP_OK},
      {"exec {sink}> >(cat); printf \"$(printf nested >&$sink)\"",
       SHELL_DEP_OK},
      {"{ printf root; } > >(printf one; printf two)", SHELL_DEP_OK},
      {"{ printf root; } < <(printf one; printf two)", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; unset -f 'out'; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; unset -n 'out'; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; command -p unset -f out; printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; builtin unset -f out; printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; command -V unset; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; command -v unset; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; command -p -- unset -f out; printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; command >/tmp/log -- unset -f out; "
       "printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; builtin -p unset; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; declare 'out'; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; readonly -p; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; exec {copy}>&$out; unset copy; "
       "printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; exec {copy}>&$out; unset out; "
       "printf x >&$copy",
       SHELL_DEP_OK},
      {"exec {in}</tmp/in; exec {copy}<&$in; unset in; cat <&$copy",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; exec {out}>&$out; printf x >&$out", SHELL_DEP_OK},
      {"exec {out}>/tmp/out; { exec {copy}>&$out; printf x >&$copy; }; "
       "printf y >&$copy",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; ( exec {copy}>&$out; printf x >&$copy ); "
       "printf y >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf \"$(exec {copy}>&$out; "
       "printf x >&$copy)\"",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; exec {sink}> >(cat); printf x >&$sink",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf '%s' -v out; printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; printf -- -v out; printf x >&$out", SHELL_DEP_OK},
      {"exec {left}>/tmp/left; exec {right}>/tmp/right; printf -vleft value; "
       "printf x >&$right",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; unset -- 'out'; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; printf -v out value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; printf -vout value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; printf -v'o'ut value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; printf > /tmp/log -v out value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; printf \"$format\"; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; declare -n ref=out; ref=1; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/first; readonly out; exec {out}>/tmp/second; "
       "printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/first; declare -r out; exec {out}>/tmp/second; "
       "printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/first; typeset -r out; exec {out}>/tmp/second; "
       "printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/first; command -p readonly out; "
       "exec {out}>/tmp/second; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; set -o posix; out=1 export marker=1; "
       "printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; export out=value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; command -p unset out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; builtin unset out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; command -p printf -v out value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; builtin export out=value; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; command unset \"$target\"; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; command -- unset out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; builtin -- unset out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; { exec {copy}>&$out; printf x >&$copy; } | cat; "
       "printf y >&$copy",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; ( exec {copy}>&$out; printf x >&$copy ); "
       "printf y >&$copy",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; exec {missing}>&-; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; exec {out}>&-; printf x >&$out", SHELL_DEP_EPARSE},
  };
  shell_dep_graph_t graph = {0};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_error_t parsed = parse(cases[i].command, &graph);
    if (parsed != cases[i].expected)
      fprintf(stderr, "named FD matrix row %zu returned %d, expected %d: %s\n",
              i, parsed, cases[i].expected, cases[i].command);
    ASSERT(parsed == cases[i].expected);
    if (cases[i].expected == SHELL_DEP_OK) {
      shell_dep_graph_validation_t validation =
          shell_dep_graph_validate(&graph);
      if (!validation.valid)
        fprintf(stderr, "named FD matrix invalid row %zu: %s (%s)\n", i,
                cases[i].command, validation.errors[0].msg);
      ASSERT(validation.valid);
      if (strcmp(cases[i].command, "exec {out}>>/tmp/out; printf x >&$out") ==
          0) {
        bool append_setup = false;
        bool materialized_append = false;
        for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
          const shell_dep_edge_t *current = &graph.edges[edge];
          append_setup =
              append_setup ||
              (current->type == SHELL_EDGE_FD_OPEN &&
               (current->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0);
          materialized_append = materialized_append ||
                                (current->type == SHELL_EDGE_APPEND &&
                                 current->flags == SHELL_DEP_EDGE_FLAG_NONE);
        }
        ASSERT(append_setup && materialized_append);
      }
    } else
      ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
             graph.edge_count == 0);
  }
  pass_count++;
}

/* A named descriptor is dynamically addressed, so it has no numeric READ
 * route in the graph. Its inline document is nevertheless live: FD_OPEN is
 * the descriptor setup relation and must not be labelled as a document later
 * replaced by another redirect. */
TEST(named_fd_inline_documents_remain_live) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t kind;
    shell_dep_node_type_t owner_type;
  } cases[] = {
      {"cmd {fd}<<<payload", SHELL_DOC_HERESTRING, SHELL_NODE_CMD},
      {"cmd {fd}<<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC, SHELL_NODE_CMD},
      {"{ cat; } {fd}<<<payload", SHELL_DOC_HERESTRING, SHELL_NODE_GROUP},
      {"{ cat; } {fd}<<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC,
       SHELL_NODE_GROUP},
      {"{ cat; } {f\\\nd}<<<payload", SHELL_DOC_HERESTRING, SHELL_NODE_GROUP},
      {"{ cat; } {f\\\r\nd}\\\n<<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC,
       SHELL_NODE_GROUP},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int document = find_doc(&graph, cases[i].kind);
    int owner = -1;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == cases[i].owner_type) {
        owner = (int)node;
        break;
      }
    ASSERT(document >= 0 && owner >= 0);
    ASSERT((graph.nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) ==
           0);
    ASSERT(has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)document,
                        (uint32_t)owner, SHELL_DEP_FD_NONE,
                        SHELL_DEP_FD_NAMED));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* A named FD_OPEN records observable setup, but it is only a live setup while
 * the final current-shell descriptor table still reaches its document. A
 * persistent `exec` close or rebind must retire the old document without
 * confusing a separate alias or a command-local close for that transition. */
TEST(named_fd_retired_setup_documents) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("exec {fd}>out; exec {fd}>&-", &graph) == SHELL_DEP_OK);
  int out = find_file_doc(&graph, "out");
  int close = find_nth_cmd(&graph, 1);
  bool named_close = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &graph.edges[edge];
    named_close =
        named_close ||
        (current->type == SHELL_EDGE_FD_CLOSE &&
         current->from == (uint32_t)close && current->to == (uint32_t)close &&
         current->source_fd == SHELL_DEP_FD_NAMED &&
         current->target_fd == SHELL_DEP_FD_NONE &&
         current->source_fd_name_len == 2 &&
         memcmp(current->source_fd_name, "fd", 2) == 0);
  }
  ASSERT(out >= 0 && close >= 0 && named_close &&
         (graph.nodes[out].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* An alias is still a live reference to the original setup after the source
   * binding is persistently closed. */
  ASSERT(parse("exec {fd}>out; exec {copy}>&$fd; exec {fd}>&-", &graph) ==
         SHELL_DEP_OK);
  out = find_file_doc(&graph, "out");
  ASSERT(out >= 0 &&
         (graph.nodes[out].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}>old; exec {fd}>&-; exec {fd}>new", &graph) ==
         SHELL_DEP_OK);
  int old = find_file_doc(&graph, "old");
  int replacement = find_file_doc(&graph, "new");
  ASSERT(old >= 0 && replacement >= 0 &&
         (graph.nodes[old].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         (graph.nodes[replacement].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) ==
             0 &&
         shell_dep_graph_validate(&graph).valid);

  /* A close attached to an ordinary command is local under Bash's default
   * varredir_close behavior; it cannot retire the outer binding. */
  ASSERT(parse("exec {fd}>local; : {fd}>&-", &graph) == SHELL_DEP_OK);
  int local = find_file_doc(&graph, "local");
  ASSERT(local >= 0 &&
         (graph.nodes[local].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}<>state; exec {fd}>&-", &graph) == SHELL_DEP_OK);
  int state = find_file_doc(&graph, "state");
  ASSERT(state >= 0 &&
         (graph.nodes[state].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}<<<payload; exec {fd}>&-", &graph) == SHELL_DEP_OK);
  int here_string = find_doc(&graph, SHELL_DOC_HERESTRING);
  ASSERT(here_string >= 0 &&
         (graph.nodes[here_string].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) !=
             0 &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(named_fd_requires_complete_word_boundary) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t document_kind;
    bool named;
    const char *argument;
    uint32_t command_tokens;
  } cases[] = {
      {"cat $'x'{fd}>out", SHELL_DOC_FILE, false, "$'x'{fd}", 2},
      {"cat ''{fd}>out", SHELL_DOC_FILE, false, "''{fd}", 2},
      {"cat ${x}{fd}>out", SHELL_DOC_FILE, false, "${x}{fd}", 2},
      {"cat $(x){fd}>out", SHELL_DOC_FILE, false, "$(x){fd}", 2},
      {"cat {f\\\nd}>out", SHELL_DOC_FILE, true, NULL, 1},
      {"cat {f\\\r\nd}\\\n>out", SHELL_DOC_FILE, true, NULL, 1},
      {"cat {fd} >out", SHELL_DOC_FILE, false, "{fd}", 2},
      {"cat {fd}\t>out", SHELL_DOC_FILE, false, "{fd}", 2},
      {"cat {f d}>out", SHELL_DOC_FILE, false, "{f", 3},
      {"cat $'x'{fd}<<<body", SHELL_DOC_HERESTRING, false, "$'x'{fd}", 2},
      {"cat {f\\\nd}<<<body", SHELL_DOC_HERESTRING, true, NULL, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    int document = find_doc(&graph, cases[i].document_kind);
    ASSERT(command >= 0 && document >= 0);
    ASSERT(graph.nodes[command].cmd.token_count == cases[i].command_tokens);
    if (cases[i].argument)
      ASSERT_STRN_EQ(graph.nodes[command].cmd.tokens[1],
                     graph.nodes[command].cmd.token_lens[1], cases[i].argument);
    if (cases[i].named) {
      bool input = cases[i].document_kind == SHELL_DOC_HERESTRING;
      ASSERT(has_edge_fds(&graph, SHELL_EDGE_FD_OPEN,
                          input ? (uint32_t)document : (uint32_t)command,
                          input ? (uint32_t)command : (uint32_t)document,
                          input ? SHELL_DEP_FD_NONE : SHELL_DEP_FD_NAMED,
                          input ? SHELL_DEP_FD_NAMED : SHELL_DEP_FD_NONE));
    } else if (cases[i].document_kind == SHELL_DOC_HERESTRING) {
      ASSERT(has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                          (uint32_t)command, SHELL_DEP_FD_NONE, 0));
    } else {
      ASSERT(has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                          (uint32_t)document, 1, SHELL_DEP_FD_NONE));
    }
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* A physical list boundary before a redirect starts an I/O-only command.  It
 * must not retroactively attach that redirect to the preceding command or
 * compound group.  A shell line continuation is deliberately different: it
 * keeps the redirect in the preceding command's grammar production. */
TEST(redirect_only_command_boundary_ownership) {
  shell_dep_graph_t g;
  int echo, owner, group, document, endpoint, consumer;

  ASSERT(parse("echo\n>out", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_FILE);
  ASSERT(echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[echo].cmd.token_count == 1 &&
         g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge(&g, SHELL_EDGE_SEQ, (uint32_t)echo, (uint32_t)owner));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)owner, (uint32_t)document,
                      1, SHELL_DEP_FD_NONE));
  ASSERT(!has_edge(&g, SHELL_EDGE_WRITE, (uint32_t)echo, (uint32_t)document));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("echo | >out", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_FILE);
  ASSERT(echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(
      has_edge_fds(&g, SHELL_EDGE_PIPE, (uint32_t)echo, (uint32_t)owner, 1, 0));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)owner, (uint32_t)document,
                      1, SHELL_DEP_FD_NONE));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; }\n>out", &g) == SHELL_DEP_OK);
  group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_FILE);
  ASSERT(group >= 0 && echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge(&g, SHELL_EDGE_SEQ, (uint32_t)echo, (uint32_t)owner));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)owner, (uint32_t)document,
                      1, SHELL_DEP_FD_NONE));
  ASSERT(!has_edge(&g, SHELL_EDGE_WRITE, (uint32_t)group, (uint32_t)document));
  ASSERT(!has_edge(&g, SHELL_EDGE_WRITE, (uint32_t)echo, (uint32_t)document));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; } \\\n>out", &g) == SHELL_DEP_OK);
  group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  document = find_doc(&g, SHELL_DOC_FILE);
  ASSERT(group >= 0 && document >= 0 && count_type(&g, SHELL_NODE_CMD) == 1);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)group, (uint32_t)document,
                      1, SHELL_DEP_FD_NONE));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; }\n<<<payload", &g) == SHELL_DEP_OK);
  group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_HERESTRING);
  ASSERT(group >= 0 && echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge(&g, SHELL_EDGE_SEQ, (uint32_t)echo, (uint32_t)owner));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)owner,
                      SHELL_DEP_FD_NONE, 0));
  ASSERT(!has_edge(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)group));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; } \\\n<<<payload", &g) == SHELL_DEP_OK);
  group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  document = find_doc(&g, SHELL_DOC_HERESTRING);
  ASSERT(group >= 0 && document >= 0 && count_type(&g, SHELL_NODE_CMD) == 1);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)group,
                      SHELL_DEP_FD_NONE, 0));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; }\n<<EOF\npayload\nEOF\n", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_HEREDOC);
  ASSERT(echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge(&g, SHELL_EDGE_SEQ, (uint32_t)echo, (uint32_t)owner));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)owner,
                      SHELL_DEP_FD_NONE, 0));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; } \\\n<<EOF\npayload\nEOF\n", &g) == SHELL_DEP_OK);
  group = find_group(&g, SHELL_GROUP_BRACE, UINT32_MAX);
  document = find_doc(&g, SHELL_DOC_HEREDOC);
  ASSERT(group >= 0 && document >= 0 && count_type(&g, SHELL_NODE_CMD) == 1);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)group,
                      SHELL_DEP_FD_NONE, 0));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("echo\n<<<payload", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  document = find_doc(&g, SHELL_DOC_HERESTRING);
  ASSERT(echo >= 0 && owner >= 0 && document >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge(&g, SHELL_EDGE_SEQ, (uint32_t)echo, (uint32_t)owner));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)owner,
                      SHELL_DEP_FD_NONE, 0));
  ASSERT(shell_dep_graph_validate(&g).valid);

  /* An io_number immediately before a later here-string remains syntax after
   * another redirect and an escaped physical line ending; it is not an argv
   * word or a new redirect-only command. */
  ASSERT(parse("cmd >out \\\n3<<<data", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  int output = find_doc(&g, SHELL_DOC_FILE);
  document = find_doc(&g, SHELL_DOC_HERESTRING);
  ASSERT(echo >= 0 && output >= 0 && document >= 0 &&
         count_type(&g, SHELL_NODE_CMD) == 1);
  ASSERT(g.nodes[echo].cmd.token_count == 1);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)echo, (uint32_t)output, 1,
                      SHELL_DEP_FD_NONE));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)echo,
                      SHELL_DEP_FD_NONE, 3));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("cmd >out \\\r\n3<<<data", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  output = find_doc(&g, SHELL_DOC_FILE);
  document = find_doc(&g, SHELL_DOC_HERESTRING);
  ASSERT(echo >= 0 && output >= 0 && document >= 0 &&
         count_type(&g, SHELL_NODE_CMD) == 1);
  ASSERT(g.nodes[echo].cmd.token_count == 1);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)echo, (uint32_t)output, 1,
                      SHELL_DEP_FD_NONE));
  ASSERT(has_edge_fds(&g, SHELL_EDGE_READ, (uint32_t)document, (uint32_t)echo,
                      SHELL_DEP_FD_NONE, 3));
  ASSERT(shell_dep_graph_validate(&g).valid);

  ASSERT(parse("{ echo; }\n> >(cat)", &g) == SHELL_DEP_OK);
  echo = find_nth_cmd(&g, 0);
  owner = find_nth_cmd(&g, 1);
  consumer = find_nth_cmd(&g, 2);
  endpoint = find_endpoint(&g);
  ASSERT(echo >= 0 && owner >= 0 && consumer >= 0 && endpoint >= 0);
  ASSERT(g.nodes[owner].cmd.token_count == 0);
  ASSERT(has_edge_fds(&g, SHELL_EDGE_WRITE, (uint32_t)owner, (uint32_t)endpoint,
                      1, SHELL_DEP_FD_NONE));
  ASSERT(
      has_edge(&g, SHELL_EDGE_SUBST, (uint32_t)endpoint, (uint32_t)consumer));
  ASSERT(!has_edge(&g, SHELL_EDGE_WRITE, (uint32_t)echo, (uint32_t)endpoint));
  ASSERT(shell_dep_graph_validate(&g).valid);
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
      {"cd ../../foo && ls", "/home/user", "/foo"},
      {"cd /../../foo; pwd", "/home/user", "/foo"},
      {"cd /tmp//nested/../final && ls", "/home/user", "/tmp/final"},
      {"cd ..; pwd", ".", ".."},
      {"cd ../../foo; pwd", ".", "../../foo"},
      {"cd ./a/../..; pwd", ".", ".."},
      {"cd ./a/..; pwd", ".", "."},
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

TEST(cwd_decoded_operand_matrix) {
  static const struct {
    const char *command;
    const char *initial_cwd;
    const char *expected_cwd;
  } static_cases[] = {
      {"cd \"/tmp\"; pwd", "/home/user", "/tmp"},
      {"c'd' '/tmp'; pwd", "/home/user", "/tmp"},
      {"cd /tmp\\ dir; pwd", "/home/user", "/tmp dir"},
      {"cd /tmp$; pwd", "/home/user", "/tmp$"},
      {"cd /tmp[part; pwd", "/home/user", "/tmp[part"},
      {"cd /tmp{part}; pwd", "/home/user", "/tmp{part}"},
      {"cd $'\\x2ftmp'; pwd", "/home/user", "/tmp"},
      {"cd ~; pwd", "/home/user", "$HOME"},
      {"cd ~/project; pwd", "/home/user", "$HOME/project"},
      {"cd ~/project; cd ./child; pwd", "/home/user", "$HOME/project/child"},
      {"cd -e /tmp; pwd", "/home/user", "/tmp"},
      {"cd -PL /tmp; pwd", "/home/user", "/tmp"},
      {"cd /tmp > log; pwd", "/home/user", "/tmp"},
      {"cd /tmp >&log; pwd", "/home/user", "/tmp"},
      {"command cd /tmp; pwd", "/home/user", "/tmp"},
      {"command -p cd /tmp; pwd", "/home/user", "/tmp"},
      {"builtin cd /tmp; pwd", "/home/user", "/tmp"},
      {"command builtin cd /tmp; pwd", "/home/user", "/tmp"},
      {"CDPREFIX=1 command cd /tmp; pwd", "/home/user", "/tmp"},
  };
  for (size_t i = 0; i < sizeof(static_cases) / sizeof(static_cases[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse_cwd(static_cases[i].command, static_cases[i].initial_cwd,
                     &graph) == SHELL_DEP_OK);
    int pwd = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
    ASSERT(pwd >= 0);
    ASSERT(graph.nodes[pwd].cmd.cwd_known);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset),
                  static_cases[i].expected_cwd);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const char *const dynamic_cases[] = {
      "cd $HOME; pwd",
      "cd ${HOME}; pwd",
      "cd \"$HOME\"; pwd",
      "cd $(pwd); pwd",
      "cd `pwd`; pwd",
      "cd *.d; pwd",
      "cd /tmp[ab]; pwd",
      "cd /tmp{left,right}; pwd",
      "cd /tmp@(left|right); pwd",
      "cd ~other; pwd",
      "cd <(pwd); pwd",
      "cd -; pwd",
      "cd -P -; pwd",
      "cd -P /tmp; pwd",
      "cd -LP /tmp; pwd",
      "cd -Pe /tmp; pwd",
      "cd -@ /tmp; pwd",
      "cd \"$option\" /tmp; pwd",
      "cd project; pwd",
      "cd project/subdir; pwd",
      "cd relative\\ dir; pwd",
      "cd foo//bar; pwd",
      "cd -- -; pwd",
      "cd '$HOME'; pwd",
      "cd '$HOME/project'; pwd",
      "cd '$HOME-suffix'; pwd",
      "cd \\$HOME; pwd",
      "cd $'\\044HOME/project'; pwd",
  };
  for (size_t i = 0; i < sizeof(dynamic_cases) / sizeof(dynamic_cases[0]);
       i++) {
    shell_dep_graph_t graph;
    ASSERT(parse_cwd(dynamic_cases[i], "/home/user", &graph) == SHELL_DEP_OK);
    int pwd = find_nth_cmd(&graph, count_type(&graph, SHELL_NODE_CMD) - 1);
    ASSERT(pwd >= 0);
    ASSERT(!graph.nodes[pwd].cmd.cwd_known);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset),
                  "/home/user");
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const char *const failed_cd_cases[] = {
      "cd /tmp extra; pwd",
      "cd /tmp -P; pwd",
      "cd /tmp --; pwd",
      "cd -x; pwd",
  };
  for (size_t i = 0; i < sizeof(failed_cd_cases) / sizeof(failed_cd_cases[0]);
       i++) {
    shell_dep_graph_t graph;
    ASSERT(parse_cwd(failed_cd_cases[i], "/home/user", &graph) == SHELL_DEP_OK);
    int pwd = find_first_cmd(&graph);
    ASSERT(pwd >= 0);
    ASSERT(graph.nodes[pwd].cmd.cwd_known);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset),
                  "/home/user");
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t graph;
  shell_dep_limits_t small_cwd_limits = SHELL_DEP_LIMITS_DEFAULT;
  small_cwd_limits.cwd_buf_size = 12;
  memset(&graph, 0, sizeof(graph));
  ASSERT(shell_dep_graph_parse("cd /tmp; pwd", strlen("cd /tmp; pwd"),
                               "/home/user", &small_cwd_limits,
                               &graph) == SHELL_DEP_ETRUNC);
  int pwd = find_first_cmd(&graph);
  ASSERT(pwd >= 0);
  ASSERT(!graph.nodes[pwd].cmd.cwd_known);
  ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cd_as_cmd = true;
  memset(&graph, 0, sizeof(graph));
  ASSERT(shell_dep_graph_parse("cd $'\\x2ftmp'; pwd",
                               strlen("cd $'\\x2ftmp'; pwd"), "/home/user",
                               &limits, &graph) == SHELL_DEP_OK);
  int document = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(document >= 0);
  ASSERT_STRN_EQ(graph.nodes[document].doc.path,
                 graph.nodes[document].doc.path_len, "$'\\x2ftmp'");
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* cd's redirect setup and nested commands execute before its CWD transition.
 * Plain cd still needs no execution node with default limits. */
TEST(cd_graph_visible_effects) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse_cwd("cd /tmp", "/home/user", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 0);

  ASSERT(parse_cwd("printf before; cd /tmp >/tmp/redirect; pwd", "/home/user",
                   &graph) == SHELL_DEP_OK);
  int before = find_cmd_tokens(&graph, "printf", NULL);
  int cd = find_cmd_tokens(&graph, "cd", NULL);
  int pwd = find_cmd_tokens(&graph, "pwd", NULL);
  int redirect = find_file_doc(&graph, "/tmp/redirect");
  ASSERT(before >= 0 && cd >= 0 && pwd >= 0 && redirect >= 0);
  ASSERT(has_edge(&graph, SHELL_EDGE_SEQ, (uint32_t)before, (uint32_t)cd) &&
         has_edge(&graph, SHELL_EDGE_SEQ, (uint32_t)cd, (uint32_t)pwd) &&
         has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)cd, (uint32_t)redirect) &&
         !has_edge(&graph, SHELL_EDGE_ARG, (uint32_t)cd, (uint32_t)redirect));
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[cd].cmd.cwd_offset),
                "/home/user");
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset), "/tmp");
  ASSERT(shell_dep_graph_validate(&graph).valid);

  ASSERT(parse_cwd("printf before; cd /tmp \\\n>out; pwd", "/home/user",
                   &graph) == SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  pwd = find_cmd_tokens(&graph, "pwd", NULL);
  redirect = find_file_doc(&graph, "out");
  ASSERT(cd >= 0 && pwd >= 0 && redirect >= 0 &&
         has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)cd, (uint32_t)redirect) &&
         !has_edge(&graph, SHELL_EDGE_ARG, (uint32_t)cd, (uint32_t)redirect));
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[cd].cmd.cwd_offset),
                "/home/user");
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset), "/tmp");
  ASSERT(shell_dep_graph_validate(&graph).valid);

  ASSERT(parse_cwd("cd \"$(printf /tmp)\"; pwd", "/home/user", &graph) ==
         SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  int producer = find_cmd_tokens(&graph, "printf", NULL);
  pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(cd >= 0 && producer >= 0 && pwd >= 0 &&
         has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)producer, (uint32_t)cd) &&
         !graph.nodes[pwd].cmd.cwd_known &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse_cwd("cd /tmp > >(cat); pwd", "/home/user", &graph) ==
         SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  int consumer = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(cd >= 0 && consumer >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) != 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse_cwd("cd /tmp {fd}>out; printf x >&$fd", "/home/user", &graph) ==
         SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  int writer = find_cmd_tokens(&graph, "printf", NULL);
  redirect = find_file_doc(&graph, "out");
  ASSERT(cd >= 0 && writer >= 0 && redirect >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)redirect, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[cd].cmd.cwd_offset),
                "/home/user");
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[writer].cmd.cwd_offset),
                "/tmp");

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.cd_as_cmd = true;
  ASSERT(shell_dep_graph_parse("cd /tmp >/tmp/redirect",
                               strlen("cd /tmp >/tmp/redirect"), "/home/user",
                               &limits, &graph) == SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  redirect = find_file_doc(&graph, "/tmp/redirect");
  ASSERT(cd >= 0 && redirect >= 0 &&
         has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)cd, (uint32_t)redirect) &&
         !has_edge(&graph, SHELL_EDGE_ARG, (uint32_t)cd, (uint32_t)redirect) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(shell_dep_graph_parse("printf before; cd /tmp; pwd",
                               strlen("printf before; cd /tmp; pwd"),
                               "/home/user", &limits, &graph) == SHELL_DEP_OK);
  before = find_cmd_tokens(&graph, "printf", NULL);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(before >= 0 && cd >= 0 && pwd >= 0 &&
         has_edge(&graph, SHELL_EDGE_SEQ, (uint32_t)before, (uint32_t)cd) &&
         has_edge(&graph, SHELL_EDGE_SEQ, (uint32_t)cd, (uint32_t)pwd) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(wrapper_cwd_semantics) {
  static const char *const dynamic_command_cases[] = {
      "command \"$target\"; pwd",
      "builtin \"$target\"; pwd",
  };
  for (size_t i = 0;
       i < sizeof(dynamic_command_cases) / sizeof(dynamic_command_cases[0]);
       i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse_cwd(dynamic_command_cases[i], "/home/user", &graph) ==
           SHELL_DEP_OK);
    int pwd = find_nth_cmd(&graph, 1);
    ASSERT(pwd >= 0 && !graph.nodes[pwd].cmd.cwd_known);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[pwd].cmd.cwd_offset),
                  "/home/user");
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const char *const unsupported[] = {
      "pushd /tmp; pwd",
      "popd; pwd",
      "command pushd /tmp; pwd",
      "builtin popd; pwd",
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse_cwd(unsupported[i], "/home/user", &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
           graph.status == SHELL_DEP_STATUS_ERROR);
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

TEST(pipeline_negation_metadata) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("! false | cat", &graph) == SHELL_DEP_OK);
  int false_command = find_nth_cmd(&graph, 0);
  int cat_command = find_nth_cmd(&graph, 1);
  ASSERT(false_command >= 0 && cat_command >= 0 &&
         graph.nodes[false_command].cmd.pipeline_negated &&
         graph.nodes[cat_command].cmd.pipeline_negated &&
         graph.nodes[false_command].cmd.pipeline_negation_count == 1 &&
         graph.nodes[cat_command].cmd.pipeline_negation_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! ! false | cat", &graph) == SHELL_DEP_OK);
  false_command = find_nth_cmd(&graph, 0);
  cat_command = find_nth_cmd(&graph, 1);
  ASSERT(false_command >= 0 && cat_command >= 0 &&
         !graph.nodes[false_command].cmd.pipeline_negated &&
         !graph.nodes[cat_command].cmd.pipeline_negated &&
         graph.nodes[false_command].cmd.pipeline_negation_count == 2 &&
         graph.nodes[cat_command].cmd.pipeline_negation_count == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! { printf x; } | cat", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int group_member = find_nth_cmd(&graph, 0);
  cat_command = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && group_member >= 0 && cat_command >= 0 &&
         graph.nodes[group].group.pipeline_negated &&
         graph.nodes[group].group.pipeline_negation_count == 1 &&
         !graph.nodes[group_member].cmd.pipeline_negated &&
         graph.nodes[cat_command].cmd.pipeline_negated &&
         graph.nodes[cat_command].cmd.pipeline_negation_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! ! { printf x; } | cat", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  group_member = find_nth_cmd(&graph, 0);
  cat_command = find_nth_cmd(&graph, 1);
  ASSERT(group >= 0 && group_member >= 0 && cat_command >= 0 &&
         !graph.nodes[group].group.pipeline_negated &&
         graph.nodes[group].group.pipeline_negation_count == 2 &&
         !graph.nodes[group_member].cmd.pipeline_negated &&
         !graph.nodes[cat_command].cmd.pipeline_negated &&
         graph.nodes[cat_command].cmd.pipeline_negation_count == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! # note\nfalse | cat", &graph) == SHELL_DEP_EPARSE &&
         graph.node_count == 0 && graph.edge_count == 0);

  ASSERT(parse("{ ! false | cat; echo done; }", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0 && !graph.nodes[group].group.pipeline_negated &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("false | cat", &graph) == SHELL_DEP_OK);
  false_command = find_nth_cmd(&graph, 0);
  cat_command = find_nth_cmd(&graph, 1);
  ASSERT(false_command >= 0 && cat_command >= 0 &&
         !graph.nodes[false_command].cmd.pipeline_negated &&
         !graph.nodes[cat_command].cmd.pipeline_negated &&
         shell_dep_graph_validate(&graph).valid);
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

TEST(static_file_identity_and_effective_group_pipe_routes) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("cd /tmp/first; printf x >\"out\"; cat ./out; "
               "cd /tmp/second; cat ./out",
               &graph) == SHELL_DEP_OK);
  char identities[3][128] = {{0}};
  size_t lengths[3] = {0};
  bool absolute = false;
  uint32_t count = 0;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_FILE || count == 3)
      continue;
    ASSERT(shell_dep_doc_file_identity_write(
        &graph, &graph.nodes[node].doc, identities[count],
        sizeof(identities[count]), &lengths[count], &absolute));
    ASSERT(absolute);
    count++;
  }
  ASSERT(count == 3 && strcmp(identities[0], "/tmp/first/out") == 0 &&
         strcmp(identities[1], identities[0]) == 0 &&
         strcmp(identities[2], "/tmp/second/out") == 0);

  ASSERT(parse("printf x >out; cd /; cat ./out", &graph) == SHELL_DEP_OK);
  bool origin_absolute[2] = {false, false};
  uint32_t origin_count = 0;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_FILE || origin_count == 2)
      continue;
    ASSERT(shell_dep_doc_file_identity_write(
        &graph, &graph.nodes[node].doc, identities[origin_count],
        sizeof(identities[origin_count]), &lengths[origin_count],
        &origin_absolute[origin_count]));
    origin_count++;
  }
  ASSERT(origin_count == 2 && !origin_absolute[0] && origin_absolute[1] &&
         strcmp(identities[0], "out") == 0 &&
         strcmp(identities[1], "/out") == 0);

  ASSERT(parse("printf x >../out; cat ./out", &graph) == SHELL_DEP_OK);
  int parent_file = find_file_doc(&graph, "../out");
  int local_file = find_file_doc(&graph, "./out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(shell_dep_doc_file_identity_write(
             &graph, &graph.nodes[parent_file].doc, identities[0],
             sizeof(identities[0]), &lengths[0], &absolute) &&
         !absolute && strcmp(identities[0], "../out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &lengths[1], &absolute) &&
         !absolute && strcmp(identities[1], "out") == 0);

  ASSERT(parse("printf x >/var/run/../tmp/out; cat /var/tmp/out", &graph) ==
         SHELL_DEP_OK);
  parent_file = find_file_doc(&graph, "/var/run/../tmp/out");
  local_file = find_file_doc(&graph, "/var/tmp/out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(shell_dep_doc_file_identity_write(
             &graph, &graph.nodes[parent_file].doc, identities[0],
             sizeof(identities[0]), &lengths[0], &absolute) &&
         absolute && strcmp(identities[0], "/var/run/../tmp/out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &lengths[1], &absolute) &&
         absolute && strcmp(identities[1], "/var/tmp/out") == 0);

  ASSERT(parse("printf x >link/../out; cat ./out", &graph) == SHELL_DEP_OK);
  parent_file = find_file_doc(&graph, "link/../out");
  local_file = find_file_doc(&graph, "./out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(shell_dep_doc_file_identity_write(
             &graph, &graph.nodes[parent_file].doc, identities[0],
             sizeof(identities[0]), &lengths[0], &absolute) &&
         !absolute && strcmp(identities[0], "link/../out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &lengths[1], &absolute) &&
         !absolute && strcmp(identities[1], "out") == 0);

  ASSERT(parse("cd /tmp/first; printf x >\"out\"; cat ./out; "
               "cd /tmp/second; cat ./out",
               &graph) == SHELL_DEP_OK);
  char too_small[4] = {'x', 'x', 'x', 'x'};
  size_t written = SIZE_MAX;
  int file = find_file_doc(&graph, "\"out\"");
  ASSERT(file >= 0 &&
         !shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                            too_small, sizeof(too_small),
                                            &written, &absolute) &&
         written == 0 && too_small[0] == 'x');

  shell_dep_doc_t uncertain = graph.nodes[file].doc;
  uncertain.cwd_known = false;
  written = SIZE_MAX;
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]), &written,
                                            &absolute) &&
         written == 0);
  uncertain.path = "/tmp/absolute";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                           sizeof(identities[0]), &written,
                                           &absolute) &&
         absolute && strcmp(identities[0], "/tmp/absolute") == 0);
  uncertain.path = "$runtime";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]), &written,
                                            &absolute) &&
         written == 0);
  uncertain.path = "$'\\x00x'";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]), &written,
                                            &absolute) &&
         written == 0);
  ASSERT(!shell_dep_doc_file_identity_write(NULL, &uncertain, identities[0],
                                            sizeof(identities[0]), &written,
                                            &absolute) &&
         written == 0 && !absolute);
  shell_dep_graph_t malformed_cwd = {0};
  memcpy(malformed_cwd.cwd_buf.data, "invalid", 7);
  malformed_cwd.cwd_buf.len = 7;
  uncertain.path = "relative";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  uncertain.cwd_known = true;
  uncertain.cwd_offset = 0;
  ASSERT(!shell_dep_doc_file_identity_write(
             &malformed_cwd, &uncertain, identities[0], sizeof(identities[0]),
             &written, &absolute) &&
         written == 0 && !absolute);

  ASSERT(parse("cd /tmp/group; { printf x; } >out", &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "out");
  ASSERT(file >= 0 &&
         shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                           identities[0], sizeof(identities[0]),
                                           &written, &absolute) &&
         absolute && strcmp(identities[0], "/tmp/group/out") == 0);

  ASSERT(parse("echo $(cd /tmp/nested; cat ./file)", &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "./file");
  ASSERT(file >= 0 &&
         shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                           identities[0], sizeof(identities[0]),
                                           &written, &absolute) &&
         absolute && strcmp(identities[0], "/tmp/nested/file") == 0);

  ASSERT(parse("{ curl URL; } | { sh; }", &graph) == SHELL_DEP_OK);
  int curl = find_nth_cmd(&graph, 0);
  int sh = find_nth_cmd(&graph, 1);
  ASSERT(curl >= 0 && sh >= 0);
  uint32_t source_group = UINT32_MAX, target_group = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_PIPE) {
      source_group = graph.edges[edge].from;
      target_group = graph.edges[edge].to;
    }
  ASSERT(source_group != UINT32_MAX && target_group != UINT32_MAX &&
         graph.nodes[curl].cmd.pipe_stdout_target == target_group &&
         graph.nodes[sh].cmd.pipe_stdin_source == source_group &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ curl URL >/tmp/out; } | { sh </dev/null; }", &graph) ==
         SHELL_DEP_OK);
  curl = find_nth_cmd(&graph, 0);
  sh = find_nth_cmd(&graph, 1);
  ASSERT(curl >= 0 && sh >= 0 &&
         graph.nodes[curl].cmd.pipe_stdout_target == UINT32_MAX &&
         graph.nodes[sh].cmd.pipe_stdin_source == UINT32_MAX &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(effective_static_command_identity) {
  static const struct {
    const char *command;
    bool known;
    uint32_t token;
    shell_dep_command_wrapper_t wrapper;
  } cases[] = {
      {"curl URL", true, 0, SHELL_DEP_COMMAND_DIRECT},
      {"command -p curl URL", true, 2, SHELL_DEP_COMMAND_SEARCH},
      {"NAME=x command curl URL", true, 1, SHELL_DEP_COMMAND_SEARCH},
      {"com'mand' -p c'url' URL", true, 2, SHELL_DEP_COMMAND_SEARCH},
      {"builtin command curl URL", true, 2, SHELL_DEP_COMMAND_SEARCH},
      {"command builtin curl URL", true, 2, SHELL_DEP_COMMAND_BUILTIN},
      {"builtin curl URL", true, 1, SHELL_DEP_COMMAND_BUILTIN},
      {"exec curl URL", true, 1, SHELL_DEP_COMMAND_EXEC},
      {"exec -c curl URL", true, 2, SHELL_DEP_COMMAND_EXEC},
      {"exec -a alias curl URL", true, 3, SHELL_DEP_COMMAND_EXEC},
      {"exec -aalias curl URL", true, 2, SHELL_DEP_COMMAND_EXEC},
      {"exec -- curl URL", true, 2, SHELL_DEP_COMMAND_EXEC},
      {"command exec curl URL", true, 2, SHELL_DEP_COMMAND_EXEC},
      {"builtin exec curl URL", true, 2, SHELL_DEP_COMMAND_EXEC},
      {"exec 3>out", true, 0, SHELL_DEP_COMMAND_DIRECT},
      {"exec \"$runtime\" URL", false, 0, SHELL_DEP_COMMAND_DIRECT},
      {"exec -x curl URL", false, 0, SHELL_DEP_COMMAND_DIRECT},
      {"command -v curl", false, 0, SHELL_DEP_COMMAND_DIRECT},
      {"command \"$runtime\" URL", false, 0, SHELL_DEP_COMMAND_DIRECT},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    ASSERT(command >= 0);
    const shell_dep_cmd_t *result = &graph.nodes[command].cmd;
    ASSERT(result->effective_command_known == cases[i].known);
    if (cases[i].known)
      ASSERT(result->effective_command_token == cases[i].token &&
             result->effective_command_wrapper == cases[i].wrapper);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
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

TEST(compound_group_combined_and_named_redirects) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("{ echo one; } &> /tmp/all", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int file = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(group >= 0 && file >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group, (uint32_t)file,
                      1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group, (uint32_t)file,
                      2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("( echo one; ) &>> /tmp/all", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_SUBSHELL, UINT32_MAX);
  file = find_doc(&graph, SHELL_DOC_FILE);
  ASSERT(group >= 0 && file >= 0 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_APPEND) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)group,
                      (uint32_t)file, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)group,
                      (uint32_t)file, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ echo one; } {trace}> /tmp/trace {input}< /tmp/input "
               "{both}<> /tmp/state",
               &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  ASSERT(group >= 0 && count_doc_kind(&graph, SHELL_DOC_FILE) == 3 &&
         count_edge_type(&graph, SHELL_EDGE_FD_OPEN) == 4);
  bool named_read = false;
  bool named_write = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    named_read = named_read || (edge->type == SHELL_EDGE_FD_OPEN &&
                                edge->target_fd == SHELL_DEP_FD_NAMED);
    named_write = named_write || (edge->type == SHELL_EDGE_FD_OPEN &&
                                  edge->source_fd == SHELL_DEP_FD_NAMED);
  }
  ASSERT(named_read && named_write && shell_dep_graph_validate(&graph).valid);

  static const char *const invalid_combined_prefixes[] = {
      "{ echo one; } 2&> /tmp/all",
      "{ echo one; } 3&>> /tmp/all",
      "{ echo one; } {fd}&> /tmp/all",
  };
  for (size_t i = 0; i < sizeof(invalid_combined_prefixes) /
                             sizeof(invalid_combined_prefixes[0]);
       i++) {
    ASSERT(parse(invalid_combined_prefixes[i], &graph) == SHELL_DEP_EPARSE &&
           graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0);
  }
  pass_count++;
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
      {"{ cat; } <<$'EO\\x46'\nbody\nEOF\n", 1, 1, "$'EO\\x46'"},
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

  /* A physical continuation inside `||` must not turn the brace group into a
   * pipeline subshell. The group remains in the current shell, so its `cd`
   * reaches the right-hand side of the logical list. */
  memset(&g, 0, sizeof(g));
  const char *continued_or = "{ cd /tmp; } |\\\n| pwd";
  ASSERT(shell_dep_graph_parse(continued_or, strlen(continued_or), "/home/user",
                               &limits, &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT_STR_EQ(get_cwd_str(&g, g.nodes[find_nth_cmd(&g, 1)].cmd.cwd_offset),
                "/tmp");
  ASSERT(shell_dep_graph_validate(&g).valid);

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

TEST(export_graph_visible_effects) {
  static const char *const redirected[] = {
      "export VALUE=one >/tmp/export-output",
      ">/tmp/export-output export VALUE=one",
      "command export VALUE=one >/tmp/export-output",
  };
  shell_dep_graph_t graph = {0};
  for (size_t i = 0; i < sizeof(redirected) / sizeof(redirected[0]); i++) {
    ASSERT(parse(redirected[i], &graph) == SHELL_DEP_OK);
    int command = find_nth_cmd(&graph, 0);
    int output = find_file_doc(&graph, "/tmp/export-output");
    ASSERT(command >= 0 && output >= 0 &&
           count_doc_kind(&graph, SHELL_DOC_ENVVAR) == 1 &&
           has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                    (uint32_t)output) &&
           !has_edge(&graph, SHELL_EDGE_ARG, (uint32_t)command,
                     (uint32_t)output) &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("export VALUE=$(printf data) >/tmp/export-output", &graph) ==
         SHELL_DEP_OK);
  int command = find_cmd_tokens(&graph, "export", NULL);
  int producer = find_cmd_tokens(&graph, "printf", NULL);
  int output = find_file_doc(&graph, "/tmp/export-output");
  ASSERT(
      command >= 0 && producer >= 0 && output >= 0 &&
      count_doc_kind(&graph, SHELL_DOC_ENVVAR) == 1 &&
      has_edge(&graph, SHELL_EDGE_SUBST, (uint32_t)producer,
               (uint32_t)command) &&
      has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)command, (uint32_t)output) &&
      shell_dep_graph_validate(&graph).valid);
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
      {"rm -rf $'\\x2fetc'", 1, 1, "$'\\x2fetc'"},
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
      {"echo plain", 1, 0, 0},
      {"echo $(cat /etc/hosts)", 2, 1, 1},
      {"echo $(date) $(whoami)", 3, 2, 0},
      {"cat <(whoami)", 2, 1, 0},
      {"echo $(<file)", 1, 1, 1},
      {"echo $\\\n(whoami)", 2, 1, 0},
      {"cat <\\\r\n(whoami)", 2, 1, 0},
      {"printf bytes > \\\n>(cat)", 2, 1, 0},
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
              g.nodes[g.edges[j].from].doc.kind == SHELL_DOC_FILE) ||
             g.nodes[g.edges[j].from].type == SHELL_NODE_ENDPOINT);
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
      {"nested static arithmetic",
       "echo $((1 + $((2))))",
       {"echo"},
       {-1},
       1,
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

TEST(named_document_and_structural_stage_routing) {
  static const struct {
    const char *command;
    shell_dep_doc_kind_t kind;
  } named[] = {
      {"printf x {fd}<<<body", SHELL_DOC_HERESTRING},
      {"printf x {fd}<<EOF\nbody\nEOF\n", SHELL_DOC_HEREDOC},
      {"{ cat; } {fd}<<<body", SHELL_DOC_HERESTRING},
      {"{ cat; } {fd}<<EOF\nbody\nEOF\n", SHELL_DOC_HEREDOC},
  };
  for (size_t i = 0; i < sizeof(named) / sizeof(named[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(named[i].command, &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    int document = find_doc(&graph, named[i].kind);
    ASSERT(command >= 0 && document >= 0 &&
           count_type(&graph, SHELL_NODE_CMD) == 1);
    ASSERT(graph.nodes[command].cmd.token_count == (i < 2 ? 2 : 1));
    ASSERT_STRN_EQ(graph.nodes[command].cmd.tokens[0],
                   graph.nodes[command].cmd.token_lens[0],
                   i < 2 ? "printf" : "cat");
    int owner =
        i < 2 ? command : find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
    ASSERT(owner >= 0 && has_edge_fds(&graph, SHELL_EDGE_FD_OPEN,
                                      (uint32_t)document, (uint32_t)owner,
                                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NAMED));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const struct {
    const char *command;
    shell_dep_edge_type_t relation;
  } controls[] = {
      {"printf x && <<<body", SHELL_EDGE_AND},
      {"printf x || <<<body", SHELL_EDGE_OR},
      {"printf x & <<<body", SHELL_EDGE_BACKGROUND},
      {"printf x && <<EOF\nbody\nEOF\n", SHELL_EDGE_AND},
      {"printf x || <<EOF\nbody\nEOF\n", SHELL_EDGE_OR},
      {"printf x & <<EOF\nbody\nEOF\n", SHELL_EDGE_BACKGROUND},
  };
  for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(controls[i].command, &graph) == SHELL_DEP_OK);
    int first = find_nth_cmd(&graph, 0);
    int second = find_nth_cmd(&graph, 1);
    ASSERT(first >= 0 && second >= 0 &&
           has_edge(&graph, controls[i].relation, (uint32_t)first,
                    (uint32_t)second));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t cwd = {0};
  ASSERT(parse("cd /tmp && <<<body; pwd", &cwd) == SHELL_DEP_OK);
  int pwd = find_nth_cmd(&cwd, 1);
  ASSERT(pwd >= 0 && !cwd.nodes[pwd].cmd.cwd_known &&
         shell_dep_graph_validate(&cwd).valid);

  static const char *const negated[] = {
      "! <<<body",
      "! ! <<<body",
      "! <<EOF\nbody\nEOF\n",
      "! ! <<EOF\nbody\nEOF\n",
  };
  for (size_t i = 0; i < sizeof(negated) / sizeof(negated[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(negated[i], &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    ASSERT(command >= 0 && graph.nodes[command].cmd.token_count == 0 &&
           graph.nodes[command].cmd.pipeline_negation_count ==
               (i == 1 || i == 3 ? 2 : 1) &&
           shell_dep_graph_validate(&graph).valid);
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

TEST(document_writer_overlap_contract) {
  char heredoc_source[] = "\tX\n\tY";
  const char heredoc_original[] = "\tX\n\tY";
  shell_dep_doc_t heredoc = {
      .kind = SHELL_DOC_HEREDOC,
      .value = heredoc_source,
      .value_len = sizeof(heredoc_source) - 1,
      .flags = SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS,
  };
  size_t length = SIZE_MAX;
  size_t written = SIZE_MAX;
  ASSERT(shell_dep_doc_content_length(&heredoc, &length) && length == 3);
  ASSERT(!shell_dep_doc_write_content(&heredoc, heredoc_source + 2, length,
                                      &written) &&
         written == 0 &&
         memcmp(heredoc_source, heredoc_original, sizeof(heredoc_original)) ==
             0);
  char content[3];
  ASSERT(shell_dep_doc_write_content(&heredoc, content, sizeof(content),
                                     &written) &&
         written == sizeof(content) && memcmp(content, "X\nY", 3) == 0);

  char assignment_source[] = "a\\\nb=1";
  const char assignment_original[] = "a\\\nb=1";
  shell_dep_doc_t env = {
      .kind = SHELL_DOC_ENVVAR,
      .name = assignment_source,
      .name_len = 4,
      .value = assignment_source + 5,
      .value_len = 1,
  };
  ASSERT(shell_dep_doc_env_name_length(&env, &length) && length == 2);
  written = SIZE_MAX;
  ASSERT(!shell_dep_doc_write_env_name(&env, assignment_source + 1, length,
                                       &written) &&
         written == 0 &&
         memcmp(assignment_source, assignment_original,
                sizeof(assignment_original)) == 0);
  char name[2];
  ASSERT(shell_dep_doc_write_env_name(&env, name, sizeof(name), &written) &&
         written == sizeof(name) && memcmp(name, "ab", 2) == 0);
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

  static const char *const literal_delimiters[] = {
      "cat <<\\EOF\n$(id)\nEOF", "cat <<E\"OF\"\n$(id)\nEOF",
      "cat <<$'EOF'\n$(id)\nEOF", "cat <<$'EO\\x46'\n$(id)\nEOF"};
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
  /* The group tail closes fd 3 before trying to copy it to fd 4. Bash fails
   * setup with EBADF; a full inherited table must not invent a live route. */
  shell_dep_graph_t invalid;
  ASSERT(parse("{ cat <&4; } 3<<EOF 3>&- 4<&3\n$(id)\nEOF", &invalid) ==
         SHELL_DEP_EPARSE);
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

  /* Parameter operands are a separate quote scope. A quoted process-like
   * spelling is literal, while unquoted process and command substitutions
   * still contribute executable producers. */
  ASSERT(parse("echo \"${value:-\"<(printf hi)\"}\"", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0);
  ASSERT(parse("echo ${value:-<(printf hi)}", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  ASSERT(parse("echo ${value:-$(printf hi)}", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  pass_count++;
}

TEST(brace_group_process_substitution_routing) {
  shell_dep_graph_t graph;

  /* A process input attached to a compound group supplies the group boundary,
   * rather than being projected onto the first member command. */
  ASSERT(parse("{ cat; } < <(printf config)", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int consumer = find_cmd_tokens(&graph, "cat", NULL);
  int producer = find_cmd_tokens(&graph, "printf", "config");
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
  consumer = find_cmd_tokens(&graph, "cat", NULL);
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
  consumer = find_cmd_tokens(&graph, "cat", NULL);
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
  int source = find_cmd_tokens(&graph, "printf", "source");
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  producer = find_cmd_tokens(&graph, "printf", "config");
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
  int writer = find_cmd_tokens(&graph, "printf", "outer");
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  consumer = find_cmd_tokens(&graph, "cat", NULL);
  producer = find_cmd_tokens(&graph, "printf", "inner");
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
  consumer = find_cmd_tokens(&graph, "printf", "'%s'");
  producer = find_cmd_tokens(&graph, "id", NULL);
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

TEST(composite_process_substitution_redirects) {
  static const struct {
    const char *command;
    unsigned commands;
    unsigned substitutions;
  } cases[] = {
      {"cat < prefix<(echo)", 2, 0},
      {"cat > >(echo)suffix", 2, 0},
      {"cat >> prefix>(echo)", 2, 0},
      {"cat <> <(echo)suffix", 2, 0},
      {"cat &> prefix>(echo)", 2, 0},
      {"cat &>> >(echo)suffix", 2, 0},
      {"cat < <(echo)<(printf)", 3, 0},
      {"{ cat; } < prefix<(echo)", 2, 0},
      {"{ cat; } > >(echo)suffix", 2, 0},
      {"{ cat; } <> <(echo)suffix", 2, 0},
      {"echo $(<prefix<(printf))", 2, 1},
      {"echo $(< <(printf)suffix)", 2, 1},
      {"cat < prefix<(echo)$(printf path)", 3, 1},
      {"cat 3> >(echo)suffix 3>&-", 2, 0},
      {"{ cat; } > >(echo)suffix |& cat", 3, 0},
      {"cat >| >(echo)suffix", 2, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    ASSERT(shell_dep_graph_validate(&graph).valid);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == cases[i].commands);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == cases[i].substitutions);
    bool dynamic_file = false;
    uint32_t document = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++)
      if (graph.nodes[n].type == SHELL_NODE_DOC &&
          graph.nodes[n].doc.kind == SHELL_DOC_FILE &&
          (graph.nodes[n].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)) {
        dynamic_file = true;
        document = n;
      }
    ASSERT(dynamic_file);
    for (uint32_t e = 0; e < graph.edge_count; e++)
      if (graph.edges[e].type == SHELL_EDGE_SUBST)
        ASSERT(graph.edges[e].flags != SHELL_DEP_EDGE_FLAG_NONE);
    if (i == 0 || i == 1) {
      int owner = find_nth_cmd(&graph, 0);
      ASSERT(owner >= 0);
      ASSERT(has_edge(&graph, i == 0 ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                      i == 0 ? document : (uint32_t)owner,
                      i == 0 ? (uint32_t)owner : document));
      ASSERT_STRN_EQ(graph.nodes[document].doc.path,
                     graph.nodes[document].doc.path_len,
                     i == 0 ? "prefix<(echo)" : ">(echo)suffix");
    }
  }
  shell_dep_graph_t limited = {0};
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 2;
  const char *input = "cat < prefix<(echo)";
  ASSERT(shell_dep_graph_parse(input, strlen(input), ".", &limits, &limited) ==
         SHELL_DEP_ETRUNC);
  ASSERT(shell_dep_graph_validate(&limited).valid);
  char nested[1024] = "cat";
  for (unsigned depth = 0; depth < 17; depth++) {
    char next[sizeof(nested)];
    int length = snprintf(next, sizeof(next), "cat < prefix<(%s)", nested);
    ASSERT(length > 0 && (size_t)length < sizeof(next));
    memcpy(nested, next, (size_t)length + 1);
    shell_dep_error_t status = parse(nested, &limited);
    ASSERT(status == (depth < 16 ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
    if (depth < 16)
      ASSERT(shell_dep_graph_validate(&limited).valid);
    else
      ASSERT(limited.node_count == 0 && limited.edge_count == 0 &&
             limited.cwd_buf.len == 0);
  }
  pass_count++;
}

TEST(composite_redirect_group_metadata) {
  static const struct {
    const char *operand;
    shell_group_io_kind_t kind;
  } cases[] = {
      {"<(echo)", SHELL_GROUP_IO_PROCESS_SUB_IN},
      {"<(printf ')')", SHELL_GROUP_IO_PROCESS_SUB_IN},
      {"prefix<(echo)", SHELL_GROUP_IO_READ_FILE},
      {"<(echo)suffix", SHELL_GROUP_IO_READ_FILE},
      {"<(echo)<(printf)", SHELL_GROUP_IO_READ_FILE},
      {"'<(echo)'", SHELL_GROUP_IO_READ_FILE},
      {"\"<(echo)\"", SHELL_GROUP_IO_READ_FILE},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char input[128];
    int length =
        snprintf(input, sizeof(input), "{ cat; } < %s", cases[i].operand);
    ASSERT(length > 0 && (size_t)length < sizeof(input));
    shell_processed_commands_t result = {0};
    ASSERT(shell_process_commands(input, (size_t)length, NULL, &result) ==
           SHELL_PROCESS_OK);
    bool valid = result.group_io_op_count == 1;
    if (valid) {
      const shell_group_io_op_t *op = &result.group_io_ops[0];
      valid = op->kind == cases[i].kind && op->fd == 0 &&
              op->target_fd == SHELL_PROCESS_FD_NONE &&
              op->operand_end - op->operand_start == strlen(cases[i].operand) &&
              memcmp(input + op->operand_start, cases[i].operand,
                     strlen(cases[i].operand)) == 0;
    }
    shell_processed_commands_free(&result);
    ASSERT(valid);
  }
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
  int group = -1;
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

  ASSERT(parse("cat log &> >(sh)", &graph) == SHELL_DEP_OK);
  bool stdout_to_endpoint = false;
  bool stderr_to_endpoint = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->type != SHELL_EDGE_WRITE ||
        graph.nodes[edge->to].type != SHELL_NODE_ENDPOINT)
      continue;
    stdout_to_endpoint = stdout_to_endpoint || edge->source_fd == 1;
    stderr_to_endpoint = stderr_to_endpoint || edge->source_fd == 2;
  }
  ASSERT(stdout_to_endpoint && stderr_to_endpoint);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  /* A combined process-output redirect still creates independent fd routes.
   * Later redirects replace only the descriptor they name; retaining the
   * initial stdout collector edge here would falsely duplicate `log` into
   * the nested shell. */
  ASSERT(parse("cat log &> >(sh) >out", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  endpoint = find_endpoint(&graph);
  int out_file = find_file_doc(&graph, "out");
  ASSERT(writer >= 0 && endpoint >= 0 && out_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)out_file, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                       (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log &>> >(sh) 2>>err", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  endpoint = find_endpoint(&graph);
  int err_file = find_file_doc(&graph, "err");
  ASSERT(writer >= 0 && endpoint >= 0 && err_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)writer,
                      (uint32_t)err_file, 2, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                       (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log >& >(sh) 2>&-", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  endpoint = find_endpoint(&graph);
  ASSERT(writer >= 0 && endpoint >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                       (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_FD_CLOSE, (uint32_t)writer,
                      (uint32_t)writer, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log &> >(sh) >out 2>&1", &graph) == SHELL_DEP_OK);
  writer = find_nth_cmd(&graph, 0);
  out_file = find_file_doc(&graph, "out");
  bool stale_collector_route = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    stale_collector_route =
        stale_collector_route ||
        (edge->type == SHELL_EDGE_WRITE && edge->from == (uint32_t)writer &&
         graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT &&
         (edge->source_fd == 1 || edge->source_fd == 2));
  }
  ASSERT(writer >= 0 && out_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)out_file, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)out_file, 2, SHELL_DEP_FD_NONE) &&
         !stale_collector_route && shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ cat log; } &> >(sh) >out", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  out_file = find_file_doc(&graph, "out");
  ASSERT(group >= 0 && endpoint >= 0 && out_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)out_file, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                       (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* Combined output process substitutions need both descriptor edges. A
   * one-edge-short graph must report truncation rather than retaining only
   * stdout and appearing complete. */
  shell_dep_graph_t combined_complete = {0};
  ASSERT(shell_dep_graph_parse("cat log &> >(sh)", strlen("cat log &> >(sh)"),
                               ".", NULL, &combined_complete) == SHELL_DEP_OK);
  shell_dep_limits_t combined_limits = SHELL_DEP_LIMITS_DEFAULT;
  ASSERT(combined_complete.edge_count > 0);
  combined_limits.max_edges = combined_complete.edge_count - 1;
  shell_dep_graph_t combined_limited = {0};
  ASSERT(shell_dep_graph_parse("cat log &> >(sh)", strlen("cat log &> >(sh)"),
                               ".", &combined_limits,
                               &combined_limited) == SHELL_DEP_ETRUNC);
  ASSERT(combined_limited.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(combined_limited.edge_count <= combined_limits.max_edges);
  ASSERT(shell_dep_graph_validate(&combined_limited).valid);

  ASSERT(parse("{ printf payload; } 3>> >(cat)", &graph) == SHELL_DEP_OK);
  group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  endpoint = find_endpoint(&graph);
  consumer = find_cmd_tokens(&graph, "cat", NULL);
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

/* Recursive descriptor imports retain child-node indices until the parent
 * graph is assembled. Pruning an overridden process-output collector must
 * remap those indices before a later child redirect materializes its route. */
TEST(recursive_fd_import_survives_endpoint_pruning) {
  static const struct {
    const char *command;
    const char *path;
    const char *final_command;
    const char *final_argument;
    shell_dep_edge_type_t edge_type;
    uint32_t source_fd;
    uint32_t target_fd;
  } cases[] = {
      {"exec {fd}>/tmp/import-out; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; printf y >&$fd)\"",
       "/tmp/import-out", "printf", "y", SHELL_EDGE_WRITE, 1,
       SHELL_DEP_FD_NONE},
      {"exec 3>/tmp/import-out; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; printf y >&3)\"",
       "/tmp/import-out", "printf", "y", SHELL_EDGE_WRITE, 1,
       SHELL_DEP_FD_NONE},
      {"exec {fd}</tmp/import-in; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; cat <&$fd)\"",
       "/tmp/import-in", "cat", NULL, SHELL_EDGE_READ, SHELL_DEP_FD_NONE, 0},
      {"exec 3</tmp/import-in; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; cat <&3)\"",
       "/tmp/import-in", "cat", NULL, SHELL_EDGE_READ, SHELL_DEP_FD_NONE, 0},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].command, &graph) == SHELL_DEP_OK);
    int document = find_file_doc(&graph, cases[i].path);
    int final = find_cmd_tokens(&graph, cases[i].final_command,
                                cases[i].final_argument);
    int sink = find_cmd_tokens(&graph, "sink", NULL);
    bool stale_collector_substitution = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *current = &graph.edges[edge];
      stale_collector_substitution =
          stale_collector_substitution ||
          (current->type == SHELL_EDGE_SUBST && current->to == (uint32_t)sink);
    }
    ASSERT(document >= 0);
    ASSERT(final >= 0);
    ASSERT(sink >= 0);
    ASSERT(graph.status == SHELL_DEP_STATUS_OK);
    ASSERT(!stale_collector_substitution);
    if (cases[i].edge_type == SHELL_EDGE_READ)
      ASSERT(has_edge_fds(&graph, cases[i].edge_type, (uint32_t)document,
                          (uint32_t) final, cases[i].source_fd,
                          cases[i].target_fd));
    else
      ASSERT(has_edge_fds(&graph, cases[i].edge_type, (uint32_t) final,
                          (uint32_t)document, cases[i].source_fd,
                          cases[i].target_fd));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
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

  static const struct {
    const char *source;
    bool executes;
  } parameter_cases[] = {
      {"echo \"${x:-'$(printf hi)'}\"", true},
      {"echo \"${x:-$'$(printf hi)'}\"", true},
      {"echo \"${x:-'`printf hi`'}\"", true},
      {"echo \"${x:-'${y:-$(printf hi)}'}\"", true},
      {"echo ${x:-'$(printf hi)'}", false},
      {"echo ${x:-$'$(printf hi)'}", false},
      {"echo \"${x:-'\\$(printf hi)'}\"", false},
      {"echo \"${x:-'<(printf hi)'}\"", false},
      {"echo \"${x/a/'$(printf hi)'}\"", false},
      {"echo \"${x#'$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\\\$(printf hi)'}\"", true},
      {"echo \"${x^$(printf hi)}\"", true},
      {"echo \"${x:-$'\\x24'}\"", false},
      {"echo \"${x:-$'\\x3c'}\"", false},
  };
  for (size_t i = 0; i < sizeof(parameter_cases) / sizeof(parameter_cases[0]);
       i++) {
    ASSERT(parse(parameter_cases[i].source, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) ==
           (parameter_cases[i].executes ? 2u : 1u));
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) ==
           (parameter_cases[i].executes ? 1u : 0u));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const char *const unsafe_ansi[] = {
      "echo \"${x:-$'$(printf\\x20X)'}\"", "echo \"${x:-$'$(pr\\x69ntf X)'}\"",
      "echo \"${x:-$'\\\\'$(printf X)}\"", "echo \"${x:-$'\\\"$(printf X)'}\"",
      "echo \"${x:-$'\"$(printf X)'}\"",
  };
  for (size_t i = 0; i < sizeof(unsafe_ansi) / sizeof(unsafe_ansi[0]); i++) {
    ASSERT(parse(unsafe_ansi[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  }

  ASSERT(parse("echo \"${x/a/<(printf hi)}\"", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);

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
  producer = find_cmd_tokens(&graph, "printf", "value");
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
  int process_consumer = find_cmd_tokens(&graph, "cat", NULL);
  producer = find_cmd_tokens(&graph, "printf", "payload");
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
  producer = find_cmd_tokens(&graph, "printf", "live");
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
  producer = find_cmd_tokens(&graph, "id", NULL);
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

TEST(resolver_workspace_contract) {
  size_t required = 0;
  size_t alignment = shell_dep_workspace_alignment();
  ASSERT(alignment != 0 && (alignment & (alignment - 1)) == 0);
  ASSERT(shell_dep_workspace_size(NULL, &required));
  ASSERT(required != 0 && required <= sizeof(shellsplit_test_dep_workspace));
  shell_dep_limits_t small_limits = SHELL_DEP_LIMITS_DEFAULT;
  small_limits.max_nodes = 1;
  small_limits.max_edges = 1;
  small_limits.max_tokens_per_cmd = 1;
  size_t small_required = 0;
  ASSERT(shell_dep_workspace_size(&small_limits, &small_required));
  shell_dep_limits_t maximum_limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t maximum_required = 0;
  ASSERT(shell_dep_workspace_size(&maximum_limits, &maximum_required));
  ASSERT(small_required == required && maximum_required == required);

  shell_dep_graph_t graph;
  memset(&graph, 0xA5, sizeof(graph));
  ASSERT(raw_dep_graph_parse("printf x", strlen("printf x"), ".", NULL,
                             &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  ASSERT(raw_dep_graph_parse("echo $(id)", strlen("echo $(id)"), ".", NULL,
                             &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  static const char group_substitution[] = "{ echo $(id); } > /tmp/group.out";
  ASSERT(raw_dep_graph_parse(group_substitution, strlen(group_substitution),
                             ".", NULL, &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  ASSERT(raw_dep_graph_parse("echo \"", strlen("echo \""), ".", NULL, &graph) ==
         SHELL_DEP_EPARSE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  ASSERT(raw_dep_graph_parse(" \t\n", strlen(" \t\n"), ".", NULL, &graph) ==
         SHELL_DEP_OK);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_OK);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.workspace = shellsplit_test_dep_workspace;
  limits.workspace_size = required - 1;
  memset(&graph, 0xA5, sizeof(graph));
  ASSERT(raw_dep_graph_parse("printf x", strlen("printf x"), ".", &limits,
                             &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  limits.workspace = shellsplit_test_dep_workspace + 1;
  limits.workspace_size = sizeof(shellsplit_test_dep_workspace) - 1;
  memset(&graph, 0xA5, sizeof(graph));
  ASSERT(raw_dep_graph_parse("printf x", strlen("printf x"), ".", &limits,
                             &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);

  limits.workspace = shellsplit_test_dep_workspace;
  limits.workspace_size = sizeof(shellsplit_test_dep_workspace);
  ASSERT(raw_dep_graph_parse("printf x", strlen("printf x"), ".", &limits,
                             &graph) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  shell_parse_result_t fast;
  ASSERT(shell_parse_fast("printf x", strlen("printf x"), NULL, &fast) ==
         SHELL_OK);
  limits.workspace = NULL;
  limits.workspace_size = 0;
  ASSERT(raw_dep_graph_parse_with_fast("printf x", strlen("printf x"), ".",
                                       &limits, &fast,
                                       &graph) == SHELL_DEP_EWORKSPACE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
         graph.cwd_buf.len == 0 && graph.status == SHELL_DEP_STATUS_ERROR);
  pass_count++;
}

TEST(resolver_workspace_alias_contract) {
  const char command[] = "printf x";
  size_t required = 0;
  ASSERT(shell_dep_workspace_size(NULL, &required) && required != 0);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  shell_dep_graph_t graph;
  unsigned char graph_snapshot[sizeof(graph)];

  /* A workspace may be large in the public contract, but overlap is rejected
   * before it is touched. Keep both the command and graph sentinels intact. */
  char command_storage[sizeof(command)];
  memcpy(command_storage, command, sizeof(command));
  memset(&graph, 0xA5, sizeof(graph));
  memcpy(graph_snapshot, &graph, sizeof(graph));
  limits.workspace = command_storage;
  limits.workspace_size = required;
  ASSERT(raw_dep_graph_parse(command_storage, sizeof(command) - 1, ".", &limits,
                             &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(command_storage, command, sizeof(command)) == 0 &&
         memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  memset(&graph, 0xA5, sizeof(graph));
  memcpy(graph_snapshot, &graph, sizeof(graph));
  limits.workspace = command_storage + 1;
  limits.workspace_size = required;
  ASSERT(raw_dep_graph_parse(command_storage, sizeof(command) - 1, ".", &limits,
                             &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(command_storage, command, sizeof(command)) == 0 &&
         memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  /* Graph output and resolver scratch also have incompatible write
   * lifetimes, even when the graph object's alignment happens to suffice. */
  memset(&graph, 0xA5, sizeof(graph));
  memcpy(graph_snapshot, &graph, sizeof(graph));
  limits.workspace = &graph;
  limits.workspace_size = required;
  ASSERT(raw_dep_graph_parse(command, sizeof(command) - 1, ".", &limits,
                             &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  /* The output graph itself cannot alias borrowed command storage. */
  memset(&graph, 0xA5, sizeof(graph));
  memcpy(&graph, command, sizeof(command) - 1);
  memcpy(graph_snapshot, &graph, sizeof(graph));
  ASSERT(raw_dep_graph_parse((const char *)&graph, sizeof(command) - 1, ".",
                             NULL, &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  /* The initial CWD is a borrowed input too. Reject an output alias before
   * clearing the CWD buffer that contains it. */
  memset(&graph, 0xA5, sizeof(graph));
  strcpy(graph.cwd_buf.data, "/saved-cwd");
  graph.cwd_buf.len = strlen(graph.cwd_buf.data) + 1;
  memcpy(graph_snapshot, &graph, sizeof(graph));
  limits.workspace = shellsplit_test_dep_workspace;
  limits.workspace_size = sizeof(shellsplit_test_dep_workspace);
  ASSERT(raw_dep_graph_parse(command, sizeof(command) - 1, graph.cwd_buf.data,
                             &limits, &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  /* Resolver scratch is writable for the duration of parsing, so it cannot
   * also own the borrowed initial CWD string. */
  const char workspace_cwd[] = "/workspace-cwd";
  memcpy(shellsplit_test_dep_workspace, workspace_cwd, sizeof(workspace_cwd));
  memset(&graph, 0xA5, sizeof(graph));
  memcpy(graph_snapshot, &graph, sizeof(graph));
  ASSERT(raw_dep_graph_parse(command, sizeof(command) - 1,
                             (const char *)shellsplit_test_dep_workspace,
                             &limits, &graph) == SHELL_DEP_EINPUT);
  ASSERT(memcmp(shellsplit_test_dep_workspace, workspace_cwd,
                sizeof(workspace_cwd)) == 0 &&
         memcmp(&graph, graph_snapshot, sizeof(graph)) == 0);

  ASSERT(raw_dep_graph_parse(command, sizeof(command) - 1, "/valid-cwd",
                             &limits, &graph) == SHELL_DEP_OK);
  ASSERT(strcmp(graph.cwd_buf.data, "/valid-cwd") == 0 &&
         shell_dep_graph_validate(&graph).valid);

  /* Limits are borrowed at entry, but may live in either writable region.
   * A nested parse must retain its own copy after scratch has been reused. */
  const char nested[] = "echo $(printf nested); echo after";
  ASSERT(shell_dep_workspace_alignment() <= _Alignof(max_align_t));
  size_t allocation_size = required > sizeof(shell_dep_limits_t)
                               ? required
                               : sizeof(shell_dep_limits_t);
  shell_dep_limits_t *workspace_limits = malloc(allocation_size);
  ASSERT(workspace_limits != NULL);
  *workspace_limits = SHELL_DEP_LIMITS_DEFAULT;
  workspace_limits->workspace = workspace_limits;
  workspace_limits->workspace_size = required;
  ASSERT(raw_dep_graph_parse(nested, sizeof(nested) - 1, ".", workspace_limits,
                             &graph) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);

  union {
    shell_dep_limits_t limits;
    shell_dep_graph_t graph;
  } graph_alias;
  graph_alias.limits = SHELL_DEP_LIMITS_DEFAULT;
  graph_alias.limits.workspace = shellsplit_test_dep_workspace;
  graph_alias.limits.workspace_size = sizeof(shellsplit_test_dep_workspace);
  ASSERT(raw_dep_graph_parse(nested, sizeof(nested) - 1, ".",
                             &graph_alias.limits,
                             &graph_alias.graph) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph_alias.graph).valid);

  shell_parse_result_t nested_fast = {0};
  ASSERT(shell_parse_fast(nested, sizeof(nested) - 1, NULL, &nested_fast) ==
         SHELL_OK);
  *workspace_limits = SHELL_DEP_LIMITS_DEFAULT;
  workspace_limits->workspace = workspace_limits;
  workspace_limits->workspace_size = required;
  ASSERT(raw_dep_graph_parse_with_fast(nested, sizeof(nested) - 1, ".",
                                       workspace_limits, &nested_fast,
                                       &graph) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  free(workspace_limits);
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
      "(\\\n( count += 1 ))",
      "[\\\r[ -n value ]]",
      "[[\\\r\n -n value ]]",
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
      {"cmd1 ; cmd2", {1, 8, 8, 0, false, NULL, 0}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo hi > out.txt",
       {8, 0, 8, 0, false, NULL, 0},
       SHELL_DEP_ETRUNC,
       1,
       0,
       2},
      {"echo hello", {8, 8, 1, 0, false, NULL, 0}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"cd /tmp && ls",
       {8, 8, 8, 4, false, NULL, 0},
       SHELL_DEP_ETRUNC,
       1,
       0,
       1},
      {"echo $(cat /etc/hosts)",
       {2, 8, 8, 0, false, NULL, 0},
       SHELL_DEP_ETRUNC,
       1,
       0,
       2},
      {"c 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 "
       "24 25 26 27 28 29 30 31 32 33",
       {64, 64, SHELL_DEP_MAX_TOKENS, 0, false, NULL, 0},
       SHELL_DEP_ETRUNC,
       1,
       0,
       SHELL_DEP_MAX_TOKENS},
      {"echo hello",
       {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, false, NULL, 0},
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
    shell_dep_limits_t limits = {bounds[i].nodes,
                                 bounds[i].edges,
                                 bounds[i].tokens,
                                 bounds[i].cwd,
                                 false,
                                 NULL,
                                 0};
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

/* Named descriptor identity is carried beside the public sentinel. Validate
 * both sides of that contract explicitly, including the close edge emitted
 * when an allocated descriptor is released. These guards prevent a malformed
 * caller-owned graph from silently conflating unrelated named descriptors. */
TEST(validation_rejects_malformed_named_fd_metadata) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("exec {out}>/tmp/out; printf bytes >&$out", &graph) ==
         SHELL_DEP_OK);
  uint32_t named_edge = UINT32_MAX;
  bool source_name = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    if (graph.edges[edge].source_fd == SHELL_DEP_FD_NAMED) {
      named_edge = edge;
      source_name = true;
      break;
    }
    if (graph.edges[edge].target_fd == SHELL_DEP_FD_NAMED) {
      named_edge = edge;
      break;
    }
  }
  ASSERT(named_edge != UINT32_MAX);
  if (source_name) {
    graph.edges[named_edge].source_fd_name = NULL;
    graph.edges[named_edge].source_fd_name_len = 0;
  } else {
    graph.edges[named_edge].target_fd_name = NULL;
    graph.edges[named_edge].target_fd_name_len = 0;
  }
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "named descriptor") != NULL);

  ASSERT(parse("exec {out}>/tmp/out; exec {out}>&-", &graph) == SHELL_DEP_OK);
  uint32_t close_edge = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_FD_CLOSE) {
      close_edge = edge;
      break;
    }
  ASSERT(close_edge != UINT32_MAX);
  graph.edges[close_edge].target_fd = 0;
  validation = shell_dep_graph_validate(&graph);
  ASSERT(!validation.valid && validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);
  pass_count++;
}

TEST(validation_rejects_ambiguous_fd_open_forms) {
  /* Every ordinary setup topology must reject the duplication marker. The
   * marker changes how Shellgate interprets the relation, so accepting it on
   * a document or process-substitution edge would be contradictory. */
  static const char *const ordinary_setups[] = {
      "exec 3>/tmp/fd-open-output",
      "exec 3</tmp/fd-open-input",
      "exec 3> >(cat)",
      "exec 3< <(printf bytes)",
  };
  for (uint32_t i = 0; i < sizeof(ordinary_setups) / sizeof(ordinary_setups[0]);
       i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(ordinary_setups[i], &graph) == SHELL_DEP_OK);
    uint32_t setup = UINT32_MAX;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      if (graph.edges[edge].type == SHELL_EDGE_FD_OPEN &&
          (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) == 0) {
        setup = edge;
        break;
      }
    ASSERT(setup != UINT32_MAX);
    graph.edges[setup].flags |= SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP;
    ASSERT(!shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t graph = {0};
  ASSERT(parse("exec 3>/tmp/fd-open-dup; exec 4>&3", &graph) == SHELL_DEP_OK);
  uint32_t duplicate = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_FD_OPEN &&
        (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0) {
      duplicate = edge;
      break;
    }
  ASSERT(duplicate != UINT32_MAX);
  graph.edges[duplicate].flags = SHELL_DEP_EDGE_FLAG_NONE;
  ASSERT(!shell_dep_graph_validate(&graph).valid);
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
  ASSERT(parse("! { printf x; } > >(cat)", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("! ! false | cat", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec {sink}> >(cat); printf bytes >&\"$sink\"", &g) ==
         SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec {source}< <(printf bytes >/tmp/dump-source); "
               "cat <&\"$source\"",
               &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec {f\\\nd}> out; printf bytes >&$f\\\nd", &g) ==
         SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);

  ASSERT(fflush(output) == 0);
  ASSERT(fseek(output, 0, SEEK_SET) == 0);
  char text[16384];
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
  ASSERT(strstr(text, "GROUP span=\"{ printf x; }\"") != NULL);
  ASSERT(strstr(text, "source-name=\"sink\"") != NULL);
  ASSERT(strstr(text, "source-name=\"f"
                      "\\\\"
                      "\\"
                      "nd\"") != NULL);
  ASSERT(strstr(text, "GROUP[") != NULL);
  ASSERT(strstr(text, "ENDPOINT") != NULL);
  ASSERT(strstr(text, "unconnected-process-substitution") != NULL);
  ASSERT(strstr(text, "negation-count=2") != NULL);
  ASSERT(strstr(text, " negated") != NULL);
  ASSERT(fclose(output) == 0);
  pass_count++;
}

TEST(name_helpers) {
  static const char *edge_names[] = {"READ",  "WRITE",   "APPEND",
                                     "PIPE",  "ARG",     "ENV",
                                     "SUBST", "SEQ",     "AND",
                                     "OR",    "CWD",     "BACKGROUND",
                                     "GROUP", "FD_OPEN", "FD_CLOSE"},
                    *node_names[] = {"CMD", "DOC", "GROUP", "ENDPOINT"},
                    *doc_names[] = {"FILE", "HEREDOC", "HERESTRING", "ENVVAR"},
                    *error_names[] = {
                        "OK", "Invalid input", "Truncated (limits exceeded)",
                        "Parse error", "Resolver workspace unavailable"};
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

TEST(continued_list_operator_routing) {
  static const struct {
    const char *input;
    shell_pipe_mode_t mode;
    uint32_t pipe_count;
  } pipelines[] = {
      {"printf x |\ncat", SHELL_PIPE_MODE_STDOUT, 1},
      {"printf x | # note\ncat", SHELL_PIPE_MODE_STDOUT, 1},
      {"printf x |&\r\ncat", SHELL_PIPE_MODE_STDOUT_AND_STDERR, 2},
      {"printf x |& \\\r\ncat", SHELL_PIPE_MODE_STDOUT_AND_STDERR, 2},
  };
  for (size_t i = 0; i < sizeof(pipelines) / sizeof(pipelines[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_dep_graph_t graph = {0};
    ASSERT(shell_parse_fast(pipelines[i].input, strlen(pipelines[i].input),
                            NULL, &fast) == SHELL_OK &&
           fast.count == 2 && fast.cmds[1].type == SHELL_TYPE_PIPELINE &&
           fast.cmds[1].pipe_input_mode == pipelines[i].mode);
    ASSERT(shell_dep_graph_parse_with_fast(
               pipelines[i].input, strlen(pipelines[i].input), ".", NULL, &fast,
               &graph) == SHELL_DEP_OK);
    int source = find_nth_cmd(&graph, 0);
    int target = find_nth_cmd(&graph, 1);
    ASSERT(source >= 0 && target >= 0 &&
           count_edge_type(&graph, SHELL_EDGE_PIPE) ==
               pipelines[i].pipe_count &&
           has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                        (uint32_t)target, 1, 0) &&
           (pipelines[i].mode != SHELL_PIPE_MODE_STDOUT_AND_STDERR ||
            has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                         (uint32_t)target, 2, 0)) &&
           shell_dep_graph_validate(&graph).valid);
  }

  static const struct {
    const char *input;
    shell_dep_edge_type_t edge;
  } lists[] = {
      {"printf x &&\ncat", SHELL_EDGE_AND},
      {"printf x || # note\ncat", SHELL_EDGE_OR},
      {"printf x\ncat", SHELL_EDGE_SEQ},
  };
  for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(lists[i].input, &graph) == SHELL_DEP_OK &&
           count_edge_type(&graph, lists[i].edge) == 1 &&
           shell_dep_graph_validate(&graph).valid);
  }

  static const char grouped[] = "{ printf x; } |& # note\n{ cat; }";
  shell_parse_result_t fast = {0};
  shell_dep_graph_t graph = {0};
  ASSERT(shell_parse_fast(grouped, sizeof(grouped) - 1, NULL, &fast) ==
             SHELL_OK &&
         shell_dep_graph_parse_with_fast(grouped, sizeof(grouped) - 1, ".",
                                         NULL, &fast, &graph) == SHELL_DEP_OK);
  int source_group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int target_group = -1;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if ((int)i != source_group && graph.nodes[i].type == SHELL_NODE_GROUP &&
        graph.nodes[i].group.kind == SHELL_GROUP_BRACE &&
        graph.nodes[i].group.parent == UINT32_MAX) {
      target_group = (int)i;
      break;
    }
  ASSERT(source_group >= 0 && target_group >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 2, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* The physical line continuation belongs to the source group's trailing
   * pipeline operator, not to a separate shell list. */
  static const char continued_group[] = "{ printf x; } \\\r\n|& { cat; }";
  memset(&graph, 0, sizeof(graph));
  ASSERT(shell_dep_graph_parse(continued_group, sizeof(continued_group) - 1,
                               ".", NULL, &graph) == SHELL_DEP_OK);
  source_group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  target_group = -1;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if ((int)i != source_group && graph.nodes[i].type == SHELL_NODE_GROUP &&
        graph.nodes[i].group.kind == SHELL_GROUP_BRACE &&
        graph.nodes[i].group.parent == UINT32_MAX) {
      target_group = (int)i;
      break;
    }
  ASSERT(source_group >= 0 && target_group >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 2, 0) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(bash_pipe_both_descriptor_routing) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("printf x |& cat", &graph) == SHELL_DEP_OK);
  int source = find_nth_cmd(&graph, 0);
  int target = find_nth_cmd(&graph, 1);
  ASSERT(source >= 0 && target >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 2, 0) &&
         has_only_public_edge_flags(&graph) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x 2>/tmp/err |& cat", &graph) == SHELL_DEP_OK);
  source = find_nth_cmd(&graph, 0);
  target = find_nth_cmd(&graph, 1);
  int error_file = find_file_doc(&graph, "/tmp/err");
  ASSERT(source >= 0 && target >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 && error_file >= 0 &&
         (graph.nodes[error_file].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) !=
             0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)source,
                      (uint32_t)error_file, 2, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 2, 0) &&
         has_only_public_edge_flags(&graph) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x >/tmp/out |& cat", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x 2>&1 >/tmp/out |& cat", &graph) == SHELL_DEP_OK);
  ASSERT(count_edge_type(&graph, SHELL_EDGE_PIPE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 2 &&
         has_only_public_edge_flags(&graph) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("printf x 3>/tmp/trace |& cat", &graph) == SHELL_DEP_OK);
  source = find_nth_cmd(&graph, 0);
  target = find_nth_cmd(&graph, 1);
  ASSERT(source >= 0 && target >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 2, 0) &&
         has_only_public_edge_flags(&graph) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ printf x; } |& { cat; }", &graph) == SHELL_DEP_OK);
  int source_group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int target_group = -1;
  for (uint32_t i = 0; i < graph.node_count; i++)
    if ((int)i != source_group && graph.nodes[i].type == SHELL_NODE_GROUP &&
        graph.nodes[i].group.kind == SHELL_GROUP_BRACE &&
        graph.nodes[i].group.parent == UINT32_MAX) {
      target_group = (int)i;
      break;
    }
  ASSERT(source_group >= 0 && target_group >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source_group,
                      (uint32_t)target_group, 2, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! printf x |& cat | sort", &graph) == SHELL_DEP_OK);
  source = find_nth_cmd(&graph, 0);
  target = find_nth_cmd(&graph, 1);
  int final = find_nth_cmd(&graph, 2);
  ASSERT(source >= 0 && target >= 0 && final >= 0 &&
         graph.nodes[source].cmd.pipeline_negated &&
         graph.nodes[target].cmd.pipeline_negated &&
         graph.nodes[final].cmd.pipeline_negated &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 3 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 2, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)target,
                      (uint32_t) final, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! ! printf x |& cat | sort", &graph) == SHELL_DEP_OK);
  source = find_nth_cmd(&graph, 0);
  target = find_nth_cmd(&graph, 1);
  final = find_nth_cmd(&graph, 2);
  ASSERT(source >= 0 && target >= 0 && final >= 0 &&
         !graph.nodes[source].cmd.pipeline_negated &&
         !graph.nodes[target].cmd.pipeline_negated &&
         !graph.nodes[final].cmd.pipeline_negated &&
         graph.nodes[source].cmd.pipeline_negation_count == 2 &&
         graph.nodes[target].cmd.pipeline_negation_count == 2 &&
         graph.nodes[final].cmd.pipeline_negation_count == 2 &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 3 &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 1, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                      (uint32_t)target, 2, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)target,
                      (uint32_t) final, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* Redirect setup is observable shell behavior even when a later binding
 * replaces the descriptor before command execution. FD_OPEN keeps that setup
 * separate from the graph's effective byte-flow edges. */
TEST(replaced_file_redirect_setup_edges) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("cmd >first >second", &graph) == SHELL_DEP_OK);
  int command = find_first_cmd(&graph);
  int first = find_file_doc(&graph, "first");
  int second = find_file_doc(&graph, "second");
  ASSERT(command >= 0 && first >= 0 && second >= 0 &&
         (graph.nodes[first].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)command,
                      (uint32_t)first, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)second, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cmd <first <second", &graph) == SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  first = find_file_doc(&graph, "first");
  second = find_file_doc(&graph, "second");
  ASSERT(command >= 0 && first >= 0 && second >= 0 &&
         (graph.nodes[first].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)first,
                      (uint32_t)command, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)second,
                      (uint32_t)command, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cmd >>old >new", &graph) == SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  int old = find_file_doc(&graph, "old");
  int new_file = find_file_doc(&graph, "new");
  ASSERT(command >= 0 && old >= 0 && new_file >= 0);
  bool old_append_setup = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    old_append_setup =
        old_append_setup ||
        (graph.edges[edge].type == SHELL_EDGE_FD_OPEN &&
         graph.edges[edge].from == (uint32_t)command &&
         graph.edges[edge].to == (uint32_t)old &&
         graph.edges[edge].source_fd == 1 &&
         (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0);
  ASSERT(old_append_setup &&
         (graph.nodes[old].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)new_file, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cmd <>state 0>replacement", &graph) == SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  int state = find_file_doc(&graph, "state");
  int replacement = find_file_doc(&graph, "replacement");
  ASSERT(command >= 0 && state >= 0 && replacement >= 0 &&
         (graph.nodes[state].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)state,
                      (uint32_t)command, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)command,
                      (uint32_t)state, 0, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)command,
                      (uint32_t)replacement, 0, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cmd 3>trace 3>&-", &graph) == SHELL_DEP_OK);
  command = find_first_cmd(&graph);
  int trace = find_file_doc(&graph, "trace");
  ASSERT(command >= 0 && trace >= 0 &&
         (graph.nodes[trace].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0 &&
         has_edge_fds(&graph, SHELL_EDGE_FD_OPEN, (uint32_t)command,
                      (uint32_t)trace, 3, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* A redirect-only document stage is still the right-hand member of a pipeline.
 * Its fd-0 document overrides the pipe input, so the producer's route ends at
 * an endpoint rather than being misreported as an ordinary sequential edge. */
TEST(inline_document_pipeline_routing) {
  static const struct {
    const char *input;
    uint16_t marker_type;
    shell_pipe_mode_t mode;
    shell_dep_doc_kind_t doc_kind;
    uint32_t pipes;
  } cases[] = {
      {"printf x | <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC,
       SHELL_PIPE_MODE_STDOUT, SHELL_DOC_HEREDOC, 1},
      {"printf x | <<<body", SHELL_TYPE_HERESTRING, SHELL_PIPE_MODE_STDOUT,
       SHELL_DOC_HERESTRING, 1},
      {"printf x |& <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_DOC_HEREDOC, 2},
      {"printf x |& <<<body", SHELL_TYPE_HERESTRING,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_DOC_HERESTRING, 2},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    ASSERT(shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL,
                            &fast) == SHELL_OK &&
           fast.count == 2 && fast.cmds[1].type == cases[i].marker_type &&
           fast.cmds[1].pipe_input_mode == cases[i].mode);
    ASSERT(shell_process_commands(cases[i].input, strlen(cases[i].input), NULL,
                                  &processed) == SHELL_PROCESS_OK &&
           processed.command_count == 1 &&
           processed.commands[0].has_pipe_output &&
           processed.commands[0].pipe_output_mode == cases[i].mode);
    shell_processed_commands_free(&processed);
    ASSERT(shell_dep_graph_parse_with_fast(cases[i].input,
                                           strlen(cases[i].input), ".", NULL,
                                           &fast, &graph) == SHELL_DEP_OK);
    int source = find_nth_cmd(&graph, 0);
    int document_owner = find_nth_cmd(&graph, 1);
    int document = find_doc(&graph, cases[i].doc_kind);
    int endpoint = find_endpoint(&graph);
    ASSERT(source >= 0 && document_owner >= 0 && document >= 0 &&
           endpoint >= 0 && count_edge_type(&graph, SHELL_EDGE_SEQ) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_PIPE) == cases[i].pipes &&
           has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)document,
                        (uint32_t)document_owner, SHELL_DEP_FD_NONE, 0) &&
           has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                        (uint32_t)endpoint, 1, 0) &&
           (cases[i].pipes == 1 ||
            has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)source,
                         (uint32_t)endpoint, 2, 0)) &&
           shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t graph = {0};
  ASSERT(parse("printf x >/tmp/out |& <<EOF\nbody\nEOF\n", &graph) ==
             SHELL_DEP_OK &&
         count_edge_type(&graph, SHELL_EDGE_PIPE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 2 &&
         shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* Keep uncommon but supported execution forms in one declarative matrix. The
 * graph need not predict external command behaviour; it must faithfully retain
 * each shell-visible data route and reject neither adjacent redirections nor
 * compound-list ownership. */
TEST(structural_routing_regression_matrix) {
  static const char *const cases[] = {
      "VAR=value env cmd",
      "cd -- /tmp && pwd",
      "cmd 0<&3 1>&2 2>&-",
      "cmd 3<<<data",
      "cmd < <(producer)",
      "cmd > >(consumer)",
      "cmd <> >(consumer)",
      "cmd $(producer)",
      "cmd `producer`",
      "cmd $(cat <(nested))",
      "cmd > \"$(producer)\"",
      "cmd < \"$(producer)\"",
      "cmd \"$(cat file)\"",
      "cmd <<EOF\nbody\nEOF\n",
      "cmd <<EOF <<'END'\nfirst\nEOF\nsecond\nEND\n",
      "{ cmd; } >out",
      "{ cmd; } 2>err 3>&1",
      "( cd /tmp; cmd )",
      "cmd | { first; second; }",
      "{ first; second; } |& { third; fourth; }",
      "cmd && { next; }",
      "cmd || ( fallback; )",
      "cmd & { next; }",
      "! { first; } |& ( second; )",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i], &graph) == SHELL_DEP_OK);
    ASSERT(graph.node_count > 0);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* Exercise legal syntax combinations that are too sparse in the anonymized
 * command corpus to provide dependable routing coverage on their own. These
 * inputs remain parser-only fixtures; validation checks the public graph after
 * every descriptor, document, substitution, and composition combination. */
TEST(routing_feature_cross_product_matrix) {
  static const char *const cases[] = {
      "cmd 0<in 1>out 2>>err 3<>read-write 4>|clobber",
      "cmd 2>&1 1>&- 3<&0 4>&-",
      "cmd {input}<in {output}>out {append}>>log {both}<>rw",
      "cmd &>combined && cmd &>>combined",
      "cmd >\"$(printf out)\" <\"$(printf in)\"",
      "cmd > >(consumer) 2> >(logger)",
      "cmd < <(producer) 3< <(trace)",
      "cmd <> >(duplex)",
      "VAR=$(printf value) cmd ARG=$(printf ignored)",
      "export VAR=$(printf value) OTHER=plain",
      "cmd $(printf one)$(printf two)",
      "cmd $(<input) $(<\"$(printf dynamic)\")",
      "cmd `printf one` \"$(printf two)\"",
      "cmd $((1 + $((2))))",
      "cat <<EOF <<-'END'\nfirst\nEOF\n\tsecond\n\tEND\n",
      "cat <<<\"$(printf body)\"",
      "{ cmd; } <in >out 2>&1",
      "{ cmd; } > >(consumer) |& { next; }",
      "( cmd; ) < <(producer) | next",
      "! { left; } |& right | final",
      "cd /tmp; cd ./child; cmd",
      "cd ~; cmd",
      "cd -- -; cmd",
      "cd /tmp && cmd || fallback",
      "cd /tmp | cmd; pwd",
      "cmd & cd /tmp; pwd",
      "cmd; { cd /tmp; nested; }; pwd",
      "cmd \"quoted path\" ./relative ../parent ~/child",
      "cmd $'quoted\\tvalue' @(left|right)",
      "cmd >out |& next 3>>trace",
      "cmd 2>err |& next >out",
      "cmd 2>&1 |& next",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse_cwd(cases[i], "/work/base", &graph) == SHELL_DEP_OK);
    ASSERT(graph.node_count > 0);
    ASSERT((graph.status & SHELL_DEP_STATUS_ERROR) == 0);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* Dynamic source fragments are only safe to model when their nested shell
 * syntax is complete. Verify every input-bearing route rejects atomically
 * instead of retaining an outer command with a missing SUBST relation. */
TEST(dynamic_routing_parse_error_matrix) {
  static const char *const malformed[] = {
      "cmd $(unterminated",          "cmd `unterminated",
      "cmd > $(unterminated",        "cmd < $(unterminated",
      "cmd > >(unterminated",        "cmd < <(unterminated",
      "cmd <<<$(unterminated",       "cmd <<EOF\n$(unterminated\nEOF\n",
      "cmd $((1 + $(unterminated))", "cmd ${value:-$(unterminated}",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(malformed[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
    ASSERT((graph.status & SHELL_DEP_STATUS_ERROR) != 0);
  }
  pass_count++;
}

/* A nested command can be lexically complete while still using a control
 * compound that Shellclave intentionally does not model.  Every dynamic-input
 * surface must reject that unsupported nested program atomically; accepting
 * the outer command with a missing SUBST edge would hide shell data flow. */
TEST(nested_unsupported_syntax_fails_atomically) {
  static const char *const cases[] = {
      "cmd \"$(while true; do :; done)\"",
      "VALUE=$(while true; do :; done) cmd",
      "cmd > \"$(while true; do :; done)\"",
      "cmd < <(while true; do :; done)",
      "cmd > >(while true; do :; done)",
      "cmd <<<\"$(while true; do :; done)\"",
      "{ cmd; } <<<\"$(while true; do :; done)\"",
      "{ cmd; } > >(while true; do :; done)",
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
           graph.edge_count == 0 && graph.cwd_buf.len == 0);
  }
  pass_count++;
}

/* The validation API is also a corruption-safe diagnostic boundary. Exercise
 * each public shape class with deliberately malformed, bounded graphs so a
 * caller can rely on it before inspecting any node or edge payload. */
TEST(validation_defensive_diagnostics_matrix) {
  static const char group_span[] = "{ x; }";
  bool valid = true;
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(NULL);
  valid = valid && !validation.valid && validation.error_count == 1;

  shell_dep_graph_t graph = {0};
  graph.node_count = SHELL_DEP_MAX_NODES + 1;
  graph.edge_count = SHELL_DEP_MAX_EDGES + 1;
  graph.cwd_buf.len = SHELL_DEP_CWD_BUF_SIZE + 1;
  validation = shell_dep_graph_validate(&graph);
  valid = valid && !validation.valid && validation.error_count == 3;

  graph = (shell_dep_graph_t){0};
  graph.cwd_buf.data[0] = '.';
  graph.cwd_buf.data[1] = '\0';
  graph.cwd_buf.len = 2;
  graph.node_count = 2;
  graph.nodes[0].type = SHELL_NODE_CMD;
  graph.nodes[1].type = SHELL_NODE_CMD;
  graph.nodes[0].cmd.cwd_offset = 0;
  graph.nodes[1].cmd.cwd_offset = 0;

  shell_dep_graph_t malformed = graph;
  malformed.nodes[0].type = (shell_dep_node_type_t)99;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].cmd.cwd_offset = 2;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.cwd_buf.data[1] = '.';
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_DOC;
  malformed.nodes[0].doc.kind = SHELL_DOC_FILE;
  malformed.nodes[0].doc.path_len = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_GROUP;
  malformed.nodes[0].group.kind = 99;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_GROUP;
  malformed.nodes[0].group.kind = SHELL_GROUP_BRACE;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_GROUP;
  malformed.nodes[0].group.kind = SHELL_GROUP_BRACE;
  malformed.nodes[0].group.start = group_span;
  malformed.nodes[0].group.length = sizeof(group_span) - 1;
  malformed.nodes[0].group.parent = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_ENDPOINT;
  malformed.nodes[0].endpoint.reserved = UINT8_MAX;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_ENDPOINT;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;

  malformed = graph;
  malformed.edge_count = 1;
  malformed.edges[0] = (shell_dep_edge_t){
      .type = SHELL_EDGE_SEQ,
      .dir = SHELL_DIR_FORWARD,
      .from = 2,
      .to = 0,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.edges[0].from = 0;
  malformed.edges[0].to = 1;
  malformed.edges[0].type = (shell_dep_edge_type_t)99;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.edges[0].type = SHELL_EDGE_SEQ;
  malformed.edges[0].dir = (shell_dep_edge_dir_t)99;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.edges[0].dir = SHELL_DIR_FORWARD;
  malformed.edges[0].source_fd = SHELL_DEP_FD_MAX + 1u;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.edges[0].source_fd = SHELL_DEP_FD_NONE;
  malformed.edges[0].flags = UINT8_MAX;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;

  static const shell_dep_edge_type_t edge_types[] = {
      SHELL_EDGE_READ,  SHELL_EDGE_WRITE,   SHELL_EDGE_APPEND,
      SHELL_EDGE_PIPE,  SHELL_EDGE_ARG,     SHELL_EDGE_ENV,
      SHELL_EDGE_SUBST, SHELL_EDGE_SEQ,     SHELL_EDGE_AND,
      SHELL_EDGE_OR,    SHELL_EDGE_CWD,     SHELL_EDGE_BACKGROUND,
      SHELL_EDGE_GROUP, SHELL_EDGE_FD_OPEN,
  };
  for (size_t i = 0; i < sizeof(edge_types) / sizeof(edge_types[0]); i++) {
    malformed = graph;
    malformed.edge_count = 1;
    malformed.edges[0] = (shell_dep_edge_t){
        .type = edge_types[i],
        .dir = edge_types[i] == SHELL_EDGE_ARG ? SHELL_DIR_UNDIR
                                               : SHELL_DIR_FORWARD,
        .from = 0,
        .to = 1,
        .source_fd = edge_types[i] == SHELL_EDGE_PIPE ||
                             edge_types[i] == SHELL_EDGE_WRITE ||
                             edge_types[i] == SHELL_EDGE_APPEND ||
                             edge_types[i] == SHELL_EDGE_SUBST ||
                             edge_types[i] == SHELL_EDGE_FD_OPEN
                         ? 1
                         : SHELL_DEP_FD_NONE,
        .target_fd =
            edge_types[i] == SHELL_EDGE_PIPE || edge_types[i] == SHELL_EDGE_READ
                ? 0
                : SHELL_DEP_FD_NONE,
    };
    validation = shell_dep_graph_validate(&malformed);
    /* CMD→CMD legitimately represents pipeline, substitution, and control
     * flow; every other class must still produce a typed diagnostic. */
    bool expected_valid =
        edge_types[i] == SHELL_EDGE_PIPE || edge_types[i] == SHELL_EDGE_SUBST ||
        edge_types[i] == SHELL_EDGE_SEQ || edge_types[i] == SHELL_EDGE_AND ||
        edge_types[i] == SHELL_EDGE_OR || edge_types[i] == SHELL_EDGE_CWD ||
        edge_types[i] == SHELL_EDGE_BACKGROUND;
    valid = valid && validation.valid == expected_valid;
  }
  ASSERT(valid);
  pass_count++;
}

/* Exercise every storage budget against the syntax families that compete for
 * graph resources. A truncated graph is still required to be internally
 * consistent, regardless of which producer, document, endpoint, or group was
 * the first item that could not be retained. */
TEST(resource_limit_cross_product_matrix) {
  static const char *const commands[] = {
      "VAR=$(printf value) cmd ./path >out 2>>err <in",
      "{ producer; } |& { consumer; } > >(sink)",
      "cmd $(producer) < <(input) > >(output)",
      "export A=$(one) B=$(two); cmd <<EOF\n$(body)\nEOF\n",
      "cd /workspace/very/long/path; cmd ../relative /absolute",
  };
  static const uint32_t limits[] = {1, 2, 3, 4};
  for (size_t command = 0; command < sizeof(commands) / sizeof(commands[0]);
       command++) {
    for (size_t bound = 0; bound < sizeof(limits) / sizeof(limits[0]);
         bound++) {
      shell_dep_limits_t configured = SHELL_DEP_LIMITS_DEFAULT;
      configured.max_nodes = limits[bound];
      configured.max_edges = limits[bound];
      configured.max_tokens_per_cmd = limits[bound];
      configured.cwd_buf_size = limits[bound] == 1 ? 2 : 12;
      shell_dep_graph_t graph = {0};
      shell_dep_error_t status =
          shell_dep_graph_parse(commands[command], strlen(commands[command]),
                                "/work/base", &configured, &graph);
      ASSERT(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
      ASSERT((status == SHELL_DEP_ETRUNC) ==
             ((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0));
      ASSERT((graph.status & SHELL_DEP_STATUS_ERROR) == 0);
      ASSERT(shell_dep_graph_validate(&graph).valid);
    }
  }
  pass_count++;
}

/* Multiple documents after a group share the group's execution owner. Named
 * descriptor setup is represented explicitly, including duplicate and close
 * transitions, without inventing a byte route. */
TEST(group_document_and_named_fd_error_boundaries) {
  static const char grouped_documents[] =
      "{ cat; } <<FIRST <<SECOND\nfirst body\nFIRST\nsecond body\nSECOND\n";
  shell_dep_graph_t graph = {0};
  bool valid =
      shell_dep_graph_parse(grouped_documents, sizeof(grouped_documents) - 1,
                            ".", NULL, &graph) == SHELL_DEP_OK &&
      shell_dep_graph_validate(&graph).valid;
  shell_dep_graph_t named = {0};
  valid = valid &&
          shell_dep_graph_parse("cmd {fd}>&1", strlen("cmd {fd}>&1"), ".", NULL,
                                &named) == SHELL_DEP_OK &&
          count_edge_type(&named, SHELL_EDGE_FD_OPEN) == 1 &&
          shell_dep_graph_validate(&named).valid;
  shell_dep_graph_t closed_fd = {0};
  valid = valid &&
          shell_dep_graph_parse("printf x {fd}>&-", strlen("printf x {fd}>&-"),
                                ".", NULL, &closed_fd) == SHELL_DEP_EPARSE &&
          closed_fd.node_count == 0 && closed_fd.edge_count == 0 &&
          closed_fd.status == SHELL_DEP_STATUS_ERROR;
  ASSERT(valid);
  pass_count++;
}

/* Document readers and CWD tracking expose bounded, caller-visible state.
 * Cover tab stripping and the resource boundaries through the public graph
 * contract rather than depending on incidental parser storage. */
TEST(document_and_cwd_boundary_contract) {
  static const char content[] = "\tfirst\n\tsecond\n";
  shell_dep_doc_t document = {
      .kind = SHELL_DOC_HEREDOC,
      .value = content,
      .value_len = sizeof(content) - 1,
      .flags = SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS,
  };
  char stripped[sizeof(content)] = {0};
  size_t length = 0;
  bool valid =
      shell_dep_doc_content_length(&document, &length) &&
      length == strlen("first\nsecond\n") &&
      shell_dep_doc_write_content(&document, stripped, length, &length) &&
      length == strlen("first\nsecond\n") &&
      memcmp(stripped, "first\nsecond\n", length) == 0;
  document.value = NULL;
  document.value_len = 1;
  valid = valid && !shell_dep_doc_content_length(&document, &length) &&
          length == 0 &&
          !shell_dep_doc_write_content(&document, stripped, sizeof(stripped),
                                       &length) &&
          length == 0;

  shell_dep_graph_t normalized = {0};
  shell_dep_error_t normalized_status =
      shell_dep_graph_parse("pwd", 3, "a/..", NULL, &normalized);
  valid = valid && normalized_status == SHELL_DEP_OK &&
          normalized.node_count == 1 && normalized.cwd_buf.len == 2 &&
          strcmp(normalized.cwd_buf.data, ".") == 0 &&
          shell_dep_graph_validate(&normalized).valid;

  shell_dep_graph_t empty_initial_cwd = {0};
  valid = valid &&
          shell_dep_graph_parse("pwd", 3, "", NULL, &empty_initial_cwd) ==
              SHELL_DEP_OK &&
          empty_initial_cwd.cwd_buf.len == 1 &&
          empty_initial_cwd.cwd_buf.data[0] == '\0' &&
          shell_dep_graph_validate(&empty_initial_cwd).valid;

  char long_cd[320] = "cd /";
  size_t long_cd_prefix = strlen(long_cd);
  memset(long_cd + long_cd_prefix, 'x', sizeof(long_cd) - long_cd_prefix - 1);
  long_cd[sizeof(long_cd) - 1] = '\0';
  shell_dep_limits_t limited = SHELL_DEP_LIMITS_DEFAULT;
  limited.cd_as_cmd = true;
  limited.max_nodes = 2;
  limited.max_edges = 1;
  limited.max_tokens_per_cmd = 1;
  shell_dep_graph_t bounded = {0};
  shell_dep_error_t bounded_status =
      shell_dep_graph_parse(long_cd, strlen(long_cd), ".", &limited, &bounded);
  valid = valid && bounded_status == SHELL_DEP_ETRUNC &&
          (bounded.status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
          shell_dep_graph_validate(&bounded).valid;

  shell_dep_limits_t tiny_cwd = SHELL_DEP_LIMITS_DEFAULT;
  tiny_cwd.cwd_buf_size = 4;
  shell_dep_graph_t home_limited = {0};
  shell_dep_graph_t relative_limited = {0};
  valid = valid &&
          shell_dep_graph_parse("cd ~/x; pwd", strlen("cd ~/x; pwd"), ".",
                                &tiny_cwd, &home_limited) == SHELL_DEP_ETRUNC &&
          shell_dep_graph_validate(&home_limited).valid &&
          shell_dep_graph_parse("cd ./relative; pwd",
                                strlen("cd ./relative; pwd"), ".", &tiny_cwd,
                                &relative_limited) == SHELL_DEP_ETRUNC &&
          shell_dep_graph_validate(&relative_limited).valid;

  shell_dep_graph_t deduplicated = {0};
  valid =
      valid &&
      shell_dep_graph_parse("cd /tmp; cd /tmp; pwd",
                            strlen("cd /tmp; cd /tmp; pwd"), ".", NULL,
                            &deduplicated) == SHELL_DEP_OK &&
      deduplicated.node_count == 1 &&
      strcmp(deduplicated.cwd_buf.data + deduplicated.nodes[0].cmd.cwd_offset,
             "/tmp") == 0 &&
      shell_dep_graph_validate(&deduplicated).valid;

  shell_dep_graph_t dynamic_cwd = {0};
  shell_dep_graph_t cd_dash = {0};
  shell_dep_graph_t named_home = {0};
  shell_dep_graph_t invalid_cd = {0};
  shell_dep_graph_t dynamic_then_operand = {0};
  valid =
      valid &&
      shell_dep_graph_parse("cd \"$HOME\"; pwd", strlen("cd \"$HOME\"; pwd"),
                            ".", NULL, &dynamic_cwd) == SHELL_DEP_OK &&
      dynamic_cwd.node_count == 1 && !dynamic_cwd.nodes[0].cmd.cwd_known &&
      shell_dep_graph_validate(&dynamic_cwd).valid &&
      shell_dep_graph_parse("cd -; pwd", strlen("cd -; pwd"), ".", NULL,
                            &cd_dash) == SHELL_DEP_OK &&
      cd_dash.node_count == 1 && !cd_dash.nodes[0].cmd.cwd_known &&
      shell_dep_graph_validate(&cd_dash).valid &&
      shell_dep_graph_parse("cd ~other; pwd", strlen("cd ~other; pwd"), ".",
                            NULL, &named_home) == SHELL_DEP_OK &&
      named_home.node_count == 1 && !named_home.nodes[0].cmd.cwd_known &&
      shell_dep_graph_validate(&named_home).valid &&
      shell_dep_graph_parse("cd /tmp -; pwd", strlen("cd /tmp -; pwd"), ".",
                            NULL, &invalid_cd) == SHELL_DEP_OK &&
      invalid_cd.node_count == 1 && invalid_cd.nodes[0].cmd.cwd_known &&
      strcmp(invalid_cd.cwd_buf.data + invalid_cd.nodes[0].cmd.cwd_offset,
             ".") == 0 &&
      shell_dep_graph_validate(&invalid_cd).valid &&
      shell_dep_graph_parse("cd - /tmp; pwd", strlen("cd - /tmp; pwd"), ".",
                            NULL, &dynamic_then_operand) == SHELL_DEP_OK &&
      dynamic_then_operand.node_count == 1 &&
      dynamic_then_operand.nodes[0].cmd.cwd_known &&
      strcmp(dynamic_then_operand.cwd_buf.data +
                 dynamic_then_operand.nodes[0].cmd.cwd_offset,
             ".") == 0 &&
      shell_dep_graph_validate(&dynamic_then_operand).valid;

  shell_dep_limits_t group_edges = SHELL_DEP_LIMITS_DEFAULT;
  group_edges.max_edges = 1;
  shell_dep_graph_t nested = {0};
  shell_dep_error_t nested_status =
      shell_dep_graph_parse("{ { { :; }; }; }", strlen("{ { { :; }; }; }"), ".",
                            &group_edges, &nested);
  valid = valid && nested_status == SHELL_DEP_ETRUNC &&
          (nested.status & SHELL_DEP_STATUS_TRUNCATED) != 0 &&
          shell_dep_graph_validate(&nested).valid;
  ASSERT(valid);
  pass_count++;
}

/* A line continuation inside a process-substitution opener must not promote
 * the operand to a static pathname. Compare the complete graph shape with the
 * uninterrupted Bash spelling, including the CWD-unknown result after `cd`. */
TEST(continued_process_substitution_topology) {
  static const struct {
    const char *reference;
    const char *continued;
    bool checks_cwd;
  } cases[] = {
      {"cd <(printf input); pwd", "cd <\\\n(printf input); pwd", true},
      {"printf bytes > >(cat)", "printf bytes > >\\\n(cat)", false},
      {"printf bytes >prefix<(printf path)",
       "printf bytes >prefix<\\\n(printf path)", false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t reference = {0};
    shell_dep_graph_t continued = {0};
    ASSERT(parse(cases[i].reference, &reference) == SHELL_DEP_OK);
    ASSERT(parse(cases[i].continued, &continued) == SHELL_DEP_OK);
    ASSERT(shell_dep_graph_validate(&reference).valid &&
           shell_dep_graph_validate(&continued).valid);
    ASSERT(reference.node_count == continued.node_count &&
           reference.edge_count == continued.edge_count);
    for (uint32_t type = SHELL_EDGE_READ; type <= SHELL_EDGE_FD_CLOSE; type++)
      ASSERT(count_edge_type(&reference, (shell_dep_edge_type_t)type) ==
             count_edge_type(&continued, (shell_dep_edge_type_t)type));
    if (cases[i].checks_cwd) {
      int reference_pwd =
          find_nth_cmd(&reference, count_type(&reference, SHELL_NODE_CMD) - 1);
      int continued_pwd =
          find_nth_cmd(&continued, count_type(&continued, SHELL_NODE_CMD) - 1);
      ASSERT(reference_pwd >= 0 && continued_pwd >= 0 &&
             !reference.nodes[reference_pwd].cmd.cwd_known &&
             !continued.nodes[continued_pwd].cmd.cwd_known);
    }
  }
  pass_count++;
}

/* A redirect token retains a terminal physical continuation in its raw source
 * span. The continuation is removed before the following word is assigned to
 * the operator, so it must not turn the operator or its operand into argv. */
TEST(continued_terminal_redirect_topology) {
  static const struct {
    const char *command;
    const char *path;
    shell_dep_edge_type_t edge_type;
    uint32_t fd;
    bool file_is_source;
  } file_cases[] = {
      {"printf payload >\\\n/tmp/write", "/tmp/write", SHELL_EDGE_WRITE, 1,
       false},
      {"cat <\\\r/tmp/read", "/tmp/read", SHELL_EDGE_READ, 0, true},
      {"printf payload >>\\\r\n/tmp/append", "/tmp/append", SHELL_EDGE_APPEND,
       1, false},
      {"printf payload >|\\\n/tmp/clobber", "/tmp/clobber", SHELL_EDGE_WRITE, 1,
       false},
      {"printf payload &>\\\r/tmp/both", "/tmp/both", SHELL_EDGE_WRITE, 1,
       false},
      {"printf payload &>>\\\n/tmp/both-append", "/tmp/both-append",
       SHELL_EDGE_APPEND, 1, false},
  };

  for (size_t i = 0; i < sizeof(file_cases) / sizeof(file_cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(file_cases[i].command, &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    int file = find_file_doc(&graph, file_cases[i].path);
    uint32_t from =
        file_cases[i].file_is_source ? (uint32_t)file : (uint32_t)command;
    uint32_t to =
        file_cases[i].file_is_source ? (uint32_t)command : (uint32_t)file;
    uint32_t source_fd =
        file_cases[i].file_is_source ? SHELL_DEP_FD_NONE : file_cases[i].fd;
    uint32_t target_fd =
        file_cases[i].file_is_source ? file_cases[i].fd : SHELL_DEP_FD_NONE;
    ASSERT(command >= 0 && file >= 0 &&
           has_edge_fds(&graph, file_cases[i].edge_type, from, to, source_fd,
                        target_fd) &&
           shell_dep_graph_validate(&graph).valid);
  }

  shell_dep_graph_t graph = {0};
  ASSERT(parse("cat <>\\\n/tmp/read-write", &graph) == SHELL_DEP_OK);
  int read_write_command = find_first_cmd(&graph);
  int read_write_file = find_file_doc(&graph, "/tmp/read-write");
  ASSERT(read_write_command >= 0 && read_write_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)read_write_file,
                      (uint32_t)read_write_command, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)read_write_command,
                      (uint32_t)read_write_file, 0, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {fd}>\\\n/tmp/trace; printf payload >&$fd", &graph) ==
         SHELL_DEP_OK);
  int writer = find_cmd_tokens(&graph, "printf", "payload");
  int trace = find_file_doc(&graph, "/tmp/trace");
  ASSERT(writer >= 0 && trace >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)trace, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ echo one; } >\\\r\n/tmp/group", &graph) == SHELL_DEP_OK);
  int group = find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX);
  int group_file = find_file_doc(&graph, "/tmp/group");
  ASSERT(group >= 0 && group_file >= 0 &&
         count_type(&graph, SHELL_NODE_CMD) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)group,
                      (uint32_t)group_file, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat log >\\\n >(sh)", &graph) == SHELL_DEP_OK);
  int output_writer = find_nth_cmd(&graph, 0);
  int output_consumer = find_nth_cmd(&graph, 1);
  int endpoint = find_endpoint(&graph);
  ASSERT(output_writer >= 0 && output_consumer >= 0 && endpoint >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)output_writer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)output_consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  static const char continued_heredoc[] = "cat <<\\\nEOF\nbody\nEOF\n";
  ASSERT(parse(continued_heredoc, &graph) == SHELL_DEP_OK);
  int heredoc_consumer = find_first_cmd(&graph);
  int heredoc = find_doc(&graph, SHELL_DOC_HEREDOC);
  ASSERT(heredoc_consumer >= 0 && heredoc >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)heredoc,
                      (uint32_t)heredoc_consumer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* A closing parenthesis in a continued-heredoc body is data. It cannot
   * close the surrounding command or process substitution. */
  static const char continued_command_substitution[] =
      "echo \"$(cat <\\\n<EOF\n)\nEOF\n)\"";
  ASSERT(parse(continued_command_substitution, &graph) == SHELL_DEP_OK);
  int substitution_producer = find_cmd_tokens(&graph, "cat", NULL);
  int substitution_consumer = find_cmd_tokens(&graph, "echo", NULL);
  heredoc = find_doc(&graph, SHELL_DOC_HEREDOC);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         substitution_producer >= 0 && substitution_consumer >= 0 &&
         heredoc >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)heredoc,
                      (uint32_t)substitution_producer, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)substitution_producer,
                      (uint32_t)substitution_consumer, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  static const char continued_process_substitution[] =
      "cat < <(cat <\\\n<EOF\n)\nEOF\n)";
  ASSERT(parse(continued_process_substitution, &graph) == SHELL_DEP_OK);
  substitution_producer = find_nth_cmd(&graph, 1);
  substitution_consumer = find_nth_cmd(&graph, 0);
  heredoc = find_doc(&graph, SHELL_DOC_HEREDOC);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
         substitution_producer >= 0 && substitution_consumer >= 0 &&
         heredoc >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)heredoc,
                      (uint32_t)substitution_producer, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)substitution_producer,
                      (uint32_t)substitution_consumer, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  static const char shifted_locale_quote[] =
      ": $((1 << 2))\nprintf %s $\"localized\"";
  ASSERT(parse(shifted_locale_quote, &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);
  pass_count++;
}

/* --- MAIN --- */

TEST(ansi_nul_source_boundary) {
  static const char *const rejected[] = {
      "e$'val\\0x' 'printf bypass'",
      "export $'POSIXLY_CORRECT\\0X'=1",
      "printf $'a\\x00b'",
      "printf $(printf $'a\\u0000b')",
      "cat <<$'E\\0F'X\nbody\nEX\n",
      "cat <<A <<$'E\\0F'X\nfirst\nA\nsecond\nEX\n",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  }
  shell_dep_graph_t literal = {0};
  ASSERT(parse("cat <<EOF\n$'a\\0b'\nEOF\n", &literal) == SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&literal).valid);
}

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
  RUN(continued_list_operator_routing);
  RUN(bash_pipe_both_descriptor_routing);
  RUN(replaced_file_redirect_setup_edges);
  RUN(inline_document_pipeline_routing);
  RUN(structural_routing_regression_matrix);
  RUN(routing_feature_cross_product_matrix);
  RUN(dynamic_routing_parse_error_matrix);
  RUN(nested_unsupported_syntax_fails_atomically);

  printf("\nRedirects:\n");
  RUN(redirect_matrix);
  RUN(legacy_combined_output_redirects);
  RUN(literal_brace_dynamic_redirect_paths);
  RUN(named_fd_redirect_topology);
  RUN(named_fd_symbolic_duplication_routes);
  RUN(named_fd_unconnected_process_substitution_routes);
  RUN(named_fd_continuation_identity);
  RUN(named_fd_exec_scope_and_lifecycle);
  RUN(named_fd_group_execution_scopes);
  RUN(named_fd_group_body_replay);
  RUN(conditional_group_descriptor_replay);
  RUN(named_fd_builtin_mutation_follows_own_redirects);
  RUN(named_fd_builtin_redirect_operands);
  RUN(backtick_command_boundaries);
  RUN(named_fd_recursive_snapshot_timing);
  RUN(group_entry_redirect_expansion_timing);
  RUN(numeric_exec_descriptor_lifecycle);
  RUN(static_builtin_descriptor_route_regressions);
  RUN(quoted_named_fd_mutation_targets);
  RUN(decoded_assignment_targets_and_env_docs);
  RUN(printf_v_named_fd_option_contract);
  RUN(named_fd_route_cross_product_matrix);
  RUN(named_fd_inline_documents_remain_live);
  RUN(named_fd_retired_setup_documents);
  RUN(named_fd_requires_complete_word_boundary);
  RUN(redirect_only_command_boundary_ownership);

  printf("\nCWD Tracking:\n");
  RUN(cwd_matrix);
  RUN(cwd_decoded_operand_matrix);
  RUN(cd_graph_visible_effects);
  RUN(wrapper_cwd_semantics);
  RUN(continued_process_substitution_topology);
  RUN(continued_terminal_redirect_topology);
  RUN(composition_metadata_matrix);
  RUN(posix_brace_group_pipeline);
  RUN(pipeline_negation_metadata);
  RUN(posix_brace_group_input_and_redirect);
  RUN(compound_group_input_redirect_overrides_pipe);
  RUN(effective_descriptor_routing);
  RUN(sibling_brace_group_pipeline_endpoints);
  RUN(static_file_identity_and_effective_group_pipe_routes);
  RUN(effective_static_command_identity);
  RUN(nested_brace_group_pipeline_scope);
  RUN(internal_brace_group_pipeline_stays_internal);
  RUN(brace_group_redirect_list_scope);
  RUN(compound_group_combined_and_named_redirects);
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
  RUN(export_graph_visible_effects);

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
  RUN(named_document_and_structural_stage_routing);
  RUN(heredoc_content_writer_contract);
  RUN(document_content_api_error_contract);
  RUN(document_writer_overlap_contract);
  RUN(expandable_heredoc_substitution_matrix);
  RUN(heredoc_substitution_cross_product_matrix);
  RUN(group_heredoc_descriptor_substitution_routing);
  RUN(brace_group_substitution_boundary_matrix);
  RUN(brace_group_process_substitution_routing);
  RUN(process_substitution_stream_topology);
  RUN(recursive_fd_import_survives_endpoint_pruning);
  RUN(composite_process_substitution_redirects);
  RUN(composite_redirect_group_metadata);
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
  RUN(resolver_workspace_contract);
  RUN(resolver_workspace_alias_contract);
  RUN(adversarial_limits);
  RUN(parse_error);
  RUN(ansi_nul_source_boundary);
  RUN(dialect_boundary_matrix);
  RUN(nested_parse_error_matrix);
  RUN(limit_matrix);
  RUN(nested_limit_cross_product);

  printf("\nGraph Integrity:\n");
  RUN(validation_matrix);
  RUN(validation_rejects_malformed_endpoint_metadata);
  RUN(validation_rejects_malformed_named_fd_metadata);
  RUN(validation_rejects_ambiguous_fd_open_forms);
  RUN(validation_rejects_corrupt_counts_documents_and_endpoint_shapes);
  RUN(validation_rejects_malformed_group_metadata);
  RUN(validation_defensive_diagnostics_matrix);
  RUN(resource_limit_cross_product_matrix);
  RUN(group_document_and_named_fd_error_boundaries);
  RUN(document_and_cwd_boundary_contract);

  printf("\nComplex:\n");
  RUN(graph_dump_contract);
  RUN(name_helpers);

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
