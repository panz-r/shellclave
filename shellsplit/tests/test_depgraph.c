#include "../src/shell_depgraph_internal.h"
#include "depgraph_compare.h"
#include "depgraph_invariants.h"
#include "depgraph_test_workspace.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_source.h"
#include "shell_tokenizer.h"
#include "syntax_boundary_cases.h"
#include "word_expansion_cases.h"
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
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
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_STR_EQ(a, b)                                                    \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("    FAIL: expected '%s', got '%s' at %s:%d\n", (b), (a),         \
             __FILE__, __LINE__);                                              \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
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
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

/* SHELLCLAVE_TEST_ONLY=name runs only the case of that name; a name that
 * matches no case is a failure, not an empty green run. */
static unsigned selected_count;
static bool selected(const char *name) {
  const char *only = getenv("SHELLCLAVE_TEST_ONLY");
  bool match = !only || strcmp(only, name) == 0;
  selected_count += match;
  return match;
}
static bool selection_matched_nothing(void) {
  if (getenv("SHELLCLAVE_TEST_ONLY") && selected_count == 0) {
    fprintf(stderr, "SHELLCLAVE_TEST_ONLY=%s matches no test\n",
            getenv("SHELLCLAVE_TEST_ONLY"));
    return true;
  }
  return false;
}

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  if (selected(#name))                                                         \
    do {                                                                       \
      printf("  %s ... ", #name);                                              \
      int _previous_fail_count = fail_count;                                   \
      test_##name();                                                           \
      if (fail_count == _previous_fail_count) {                                \
        printf("PASS\n");                                                      \
      }                                                                        \
  } while (0)

/* --- HELPERS --- */

static SHELL_NONNULL(1,
                     2) bool internal_relation(const shell_dep_graph_t *graph,
                                               const shell_dep_edge_t *edge) {
  return graph->nodes[edge->from].type != SHELL_NODE_FD &&
         graph->nodes[edge->to].type != SHELL_NODE_FD;
}

/* Existing topology fixtures count in-graph relations independently of the
 * newly explicit external boundary. The boundary suite checks complete counts
 * and destinations; every suite still validates the complete returned graph. */
static uint32_t count_internal_nodes(const shell_dep_graph_t *g) {
  uint32_t count = 0;
  for (uint32_t i = 0; i < g->node_count; i++)
    count += g->nodes[i].type != SHELL_NODE_FD;
  return count;
}

static uint32_t count_internal_edges(const shell_dep_graph_t *g) {
  uint32_t count = 0;
  for (uint32_t i = 0; i < g->edge_count; i++)
    count += g->nodes[g->edges[i].from].type != SHELL_NODE_FD &&
             g->nodes[g->edges[i].to].type != SHELL_NODE_FD;
  return count;
}

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
    if (g->edges[i].type == type &&
        g->nodes[g->edges[i].from].type != SHELL_NODE_FD &&
        g->nodes[g->edges[i].to].type != SHELL_NODE_FD)
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

/* Compares the identities' fields. The structs carry padding, which an
 * assignment or a callee need not copy, so a byte comparison is not defined. */
static bool file_identity_equal(const shell_dep_file_identity_t *a,
                                const shell_dep_file_identity_t *b) {
  return a->length == b->length && a->absolute == b->absolute &&
         a->requires_directory == b->requires_directory;
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

static int find_time(const shell_dep_graph_t *g) {
  for (uint32_t i = 0; i < g->node_count; i++)
    if (g->nodes[i].type == SHELL_NODE_TIME)
      return (int)i;
  return -1;
}

static bool time_has_external_fd(const shell_dep_graph_t *g, int timer,
                                 uint32_t fd) {
  if (!g || timer < 0 || (uint32_t)timer >= g->node_count ||
      g->nodes[timer].type != SHELL_NODE_TIME)
    return false;
  for (uint32_t i = 0; i < g->nodes[timer].time.report_external_fd_count; i++)
    if (g->nodes[timer].time.report_external_fds[i] == fd)
      return true;
  return false;
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

/* --- BASIC COMMANDS --- */

TEST(supplied_fast_parser_contract) {
  const char *command = "cd /tmp && printf 'two words' >out | sed s/x/y/";
  const shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                                 .strict_mode = true};
  shell_parse_result_t fast = {0};
  ASSERT(shell_parse_fast(command, strlen(command), &strict, &fast) ==
         SHELL_OK);
  shell_parse_result_t original;
  memcpy(&original, &fast, sizeof(original));

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
  ASSERT(memcmp(&fast, &original, sizeof(fast)) == 0);

  /* Exercise real parser truncation rather than inventing partial metadata. */
  const shell_limits_t short_limits = {.max_subcommands = 1,
                                       .strict_mode = true};
  ASSERT(shell_parse_fast(command, strlen(command), &short_limits, &fast) ==
         SHELL_ETRUNC);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_ETRUNC);
  ASSERT(supplied.status & SHELL_DEP_STATUS_TRUNCATED);
  ASSERT(shell_dep_graph_validate(&supplied).valid);

  const char *invalid = "echo 'unterminated";
  ASSERT(shell_parse_fast(invalid, strlen(invalid), &strict, &fast) ==
         SHELL_EPARSE);
  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(invalid, strlen(invalid), ".", NULL,
                                         &fast, &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);

  memset(&supplied, 0, sizeof(supplied));
  ASSERT(shell_dep_graph_parse_with_fast(command, strlen(command), ".", NULL,
                                         NULL, &supplied) == SHELL_DEP_OK);
  ASSERT(supplied.node_count == regular.node_count &&
         supplied.edge_count == regular.edge_count);

  /* Unsupported source semantics are still rejected, even if lexical parsing
   * succeeds. Source support is separate from the trusted parse/source pair. */
  static const char *const unsupported[] = {
      SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"),
      "(( count += 1 ))",
      "printf '%s' $\"localized\"",
      "echo $( " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x") " )",
      "{ (( count )); }",
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    const char *source = unsupported[i];
    shell_error_t status =
        shell_parse_fast(source, strlen(source), &strict, &fast);
    ASSERT(status == SHELL_OK || status == SHELL_EPARSE);
    memset(&supplied, 0, sizeof(supplied));
    ASSERT(shell_dep_graph_parse_with_fast(source, strlen(source), ".", NULL,
                                           &fast,
                                           &supplied) == SHELL_DEP_EPARSE);
    ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
           supplied.node_count == 0 && supplied.edge_count == 0);
  }

  /* Keep the public recursive-analysis depth limit covered independently of
   * supplied metadata. */
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
  ASSERT(shell_dep_graph_parse(deep_substitution, deep_length, ".", NULL,
                               &supplied) == SHELL_DEP_EPARSE);
  ASSERT(supplied.status == SHELL_DEP_STATUS_ERROR &&
         supplied.node_count == 0 && supplied.edge_count == 0);
  pass_count++;
}

/* Every validation failure must leave a stored explanation, and a corrupt
 * graph with more faults than the fixed diagnostic array holds must saturate
 * it rather than overflow. */
TEST(validation_diagnostic_invariants) {
  shell_dep_graph_t graph;
  ASSERT(parse("a;b;c;d;e;f;g;h;i;j;k;l;m;n;o;p;q;r;s;t", &graph) ==
         SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  ASSERT(graph.node_count > SHELL_DEP_MAX_VALIDATE_ERRORS);
  for (uint32_t i = 0; i < graph.node_count; i++)
    graph.nodes[i].type = (shell_dep_node_type_t)250;
  shell_dep_graph_validation_t saturated = shell_dep_graph_validate(&graph);
  ASSERT(!saturated.valid);
  ASSERT(saturated.error_count == SHELL_DEP_MAX_VALIDATE_ERRORS);
  for (uint32_t i = 0; i < saturated.error_count; i++) {
    size_t length =
        strnlen(saturated.errors[i].msg, sizeof(saturated.errors[i].msg));
    ASSERT(length != 0 && length < sizeof(saturated.errors[i].msg));
  }

  /* Invalid and explained are the same fact for single faults of each kind. */
  for (unsigned fault = 0; fault < 4; fault++) {
    ASSERT(parse("! true", &graph) == SHELL_DEP_OK);
    uint32_t command = UINT32_MAX;
    for (uint32_t i = 0; i < graph.node_count; i++)
      if (graph.nodes[i].type == SHELL_NODE_CMD)
        command = i;
    ASSERT(command != UINT32_MAX);
    if (fault == 0)
      graph.nodes[command].cmd.pipeline_negated =
          !graph.nodes[command].cmd.pipeline_negated;
    else if (fault == 1)
      graph.nodes[command].cmd.token_count = SHELL_DEP_MAX_TOKENS + 1;
    else if (fault == 2)
      graph.cwd_buf.len = SHELL_DEP_CWD_BUF_SIZE + 1;
    else
      graph.node_count = SHELL_DEP_MAX_NODES + 1;
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
    ASSERT(!validation.valid && validation.error_count == 1);
  }

  /* An edge fault records which edge, distinct from node diagnostics. */
  ASSERT(parse("a | b | c", &graph) == SHELL_DEP_OK);
  ASSERT(graph.edge_count > 1);
  uint32_t edge = graph.edge_count - 1;
  graph.edges[edge].from = graph.node_count + 1;
  shell_dep_graph_validation_t edge_fault = shell_dep_graph_validate(&graph);
  ASSERT(!edge_fault.valid && edge_fault.error_count == 1);
  ASSERT(edge_fault.errors[0].edge_idx == edge);
  pass_count++;
}

TEST(graph_pipeline_negation_parity) {
  static const char *const sources[] = {"true", "{ true; }"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(sources[i], &graph) == SHELL_DEP_OK);
    uint32_t index = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++)
      if (graph.nodes[n].type == (i ? SHELL_NODE_GROUP : SHELL_NODE_CMD)) {
        index = n;
        break;
      }
    ASSERT(index != UINT32_MAX);
    for (unsigned truncated = 0; truncated < 2; truncated++) {
      graph.status =
          truncated ? SHELL_DEP_STATUS_TRUNCATED : SHELL_DEP_STATUS_OK;
      for (uint32_t count = 0; count <= 2; count++) {
        if (i) {
          graph.nodes[index].group.pipeline_negation_count = count;
          graph.nodes[index].group.pipeline_negated = (count & 1u) != 0;
        } else {
          graph.nodes[index].cmd.pipeline_negation_count = count;
          graph.nodes[index].cmd.pipeline_negated = (count & 1u) != 0;
        }
        ASSERT(shell_dep_graph_validate(&graph).valid);
        if (i)
          graph.nodes[index].group.pipeline_negated = (count & 1u) == 0;
        else
          graph.nodes[index].cmd.pipeline_negated = (count & 1u) == 0;
        shell_dep_graph_validation_t validation =
            shell_dep_graph_validate(&graph);
        ASSERT(!validation.valid && validation.error_count != 0);
      }
    }
  }
  pass_count++;
}

/* --- OPERATORS --- */

/* --- REDIRECTS --- */

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
      if (!internal_relation(&graph, item))
        continue;
      if ((item->type == SHELL_EDGE_WRITE || item->type == SHELL_EDGE_APPEND) &&
          item->to == (uint32_t)document) {
        stdout_seen = stdout_seen || item->source_fd == 1;
        stderr_seen = stderr_seen || item->source_fd == 2;
      }
    }
    ASSERT(stdout_seen && stderr_seen &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* Brace expansion yields several words, an "ambiguous redirect" (reference
   * Bash), which no graph models. */
  static const char *const ambiguous[] = {"cmd >&foo{one,two}",
                                          "cmd >&foo{1..2}"};
  for (uint32_t i = 0; i < sizeof(ambiguous) / sizeof(ambiguous[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(ambiguous[i], &graph) == SHELL_DEP_EUNMODELED);
  }

  shell_dep_graph_t graph = {0};
  static const char *const descriptor_targets[] = {
      "cmd >&2",
      "cmd >&0000000000000000000000000000000000000001",
      "cmd >&$'0000000000000000000000000000000000000001'",
      "cmd >&-",
      "cmd >&\"2\"",
      "cmd >&$'2'",
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
    int outer = find_first_cmd(&graph);
    int nested = find_nth_cmd(&graph, 1);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      byte_route = byte_route || (graph.edges[edge].from == (uint32_t)outer &&
                                  graph.edges[edge].to == (uint32_t)nested);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 2 &&
           count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
           count_doc_kind(&graph, SHELL_DOC_FILE) == 0 && !byte_route &&
           shell_dep_graph_validate(&graph).valid);
  }

  static const char *const rejected[] = {
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
  /* An empty combined-output pathname certainly fails: a shell-level error
   * which no dependency graph models. */
  static const char *const failed_empty[] = {
      "cmd >&''",
      "{ cmd; } >&\"\"",
  };
  for (uint32_t i = 0; i < sizeof(failed_empty) / sizeof(failed_empty[0]); i++)
    ASSERT(parse(failed_empty[i], &graph) == SHELL_DEP_EUNMODELED);
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
    if (!internal_relation(&graph, item))
      continue;
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
    if (!internal_relation(&graph, item))
      continue;
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

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#endif

TEST(named_fd_ifs_expansion_routes) {
  for (size_t i = 0; i < sizeof(shellsplit_test_ifs_routes) /
                             sizeof(shellsplit_test_ifs_routes[0]);
       i++) {
    const shellsplit_test_ifs_route_case_t *fixture =
        &shellsplit_test_ifs_routes[i];
    shell_dep_graph_t graph = {0};
    shell_dep_error_t status = parse(fixture->source, &graph);
    if (fixture->unmodeled) {
      ASSERT(status == SHELL_DEP_EUNMODELED);
      continue;
    }
    if (status != (fixture->supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE))
      fprintf(stderr, "IFS route case %zu: %s (%d)\n", i, fixture->source,
              status);
    ASSERT(status == (fixture->supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
    if (!fixture->supported) {
      ASSERT(graph.node_count == 0 && graph.edge_count == 0);
      continue;
    }
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int document = find_file_doc(&graph, "out");
    ASSERT(writer >= 0 && document >= 0);
    bool writes = has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                               (uint32_t)document, 1, SHELL_DEP_FD_NONE);
    if (writes != fixture->writes)
      fprintf(stderr, "IFS route mismatch %zu: %s\n", i, fixture->source);
    ASSERT(writes == fixture->writes && shell_dep_graph_validate(&graph).valid);
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

  /* Reading a closed allocation is a certain descriptor error: no model. */
  ASSERT(parse("exec {fd}</tmp/in; exec {fd}<&-; printf '%s' \"$(cat <&$fd)\"",
               &graph) == SHELL_DEP_EUNMODELED);

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
      {"exec {out}>/tmp/out; out=99 export out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 command export out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 builtin export out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 export o'u't; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; ou\\\nt=99 export ou\\\nt; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 declare -x out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 typeset +x -x out; printf x >&$out",
       SHELL_DEP_EPARSE},
      {"exec {out}>/tmp/out; out=99 export -n out; printf x >&$out",
       SHELL_DEP_OK},
      {"exec {out}>/tmp/out; out=99 declare -p -x out; printf x >&$out",
       SHELL_DEP_OK},
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
      /* Writing a closed allocation is a certain descriptor error. */
      {"exec {out}>/tmp/out; exec {out}>&-; printf x >&$out",
       SHELL_DEP_EUNMODELED},
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
          if (!internal_relation(&graph, current))
            continue;
          append_setup =
              append_setup ||
              (current->type == SHELL_EDGE_FD_OPEN &&
               (current->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0);
          /* The unhandled open must succeed for `>&$out` to be valid. */
          materialized_append =
              materialized_append ||
              (current->type == SHELL_EDGE_APPEND &&
               current->flags == SHELL_DEP_EDGE_FLAG_REQUIRED);
        }
        ASSERT(append_setup && materialized_append);
      }
    } else
      ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
             graph.edge_count == 0);
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
      {"cd && ls", "/home/user", NULL},
      {"cd .. && pwd", "/home/user/docs", "/home/user"},
      {"cd ./foo && ls", "/home/user", "/home/user/foo"},
      {"cd ../../foo && ls", "/home/user", "/foo"},
      {"cd /../../foo && pwd", "/home/user", "/foo"},
      {"cd /tmp//nested/../final && ls", "/home/user", "/tmp/final"},
      {"cd .. && pwd", ".", ".."},
      {"cd ../../foo && pwd", ".", "../../foo"},
      {"cd ./a/../.. && pwd", ".", ".."},
      {"cd ./a/.. && pwd", ".", "."},
      {"ls", ".", "."},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse_cwd(cases[i].command, cases[i].initial_cwd, &g) ==
           SHELL_DEP_OK);
    uint32_t expected_commands =
        i + 1 == sizeof(cases) / sizeof(cases[0]) ? 1u : 2u;
    ASSERT(count_type(&g, SHELL_NODE_CMD) == expected_commands);
    int command_index = find_nth_cmd(&g, expected_commands - 1);
    ASSERT(command_index >= 0);
    ASSERT(g.nodes[command_index].cmd.cwd_known ==
           (cases[i].expected_cwd != NULL));
    if (cases[i].expected_cwd)
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
      {"cd \"/tmp\" && pwd", "/home/user", "/tmp"},
      {"c'd' '/tmp' && pwd", "/home/user", "/tmp"},
      {"cd /tmp\\ dir && pwd", "/home/user", "/tmp dir"},
      {"cd /tmp$ && pwd", "/home/user", "/tmp$"},
      {"cd /tmp[part && pwd", "/home/user", "/tmp[part"},
      {"cd /tmp{part} && pwd", "/home/user", "/tmp{part}"},
      {"cd $'\\x2ftmp' && pwd", "/home/user", "/tmp"},
      {"cd -e /tmp && pwd", "/home/user", "/tmp"},
      {"cd -PL /tmp && pwd", "/home/user", "/tmp"},
      {"cd /tmp > log && pwd", "/home/user", "/tmp"},
      {"cd /tmp >&log && pwd", "/home/user", "/tmp"},
      {"command cd /tmp && pwd", "/home/user", "/tmp"},
      {"command -p cd /tmp && pwd", "/home/user", "/tmp"},
      {"builtin cd /tmp && pwd", "/home/user", "/tmp"},
      {"command builtin cd /tmp && pwd", "/home/user", "/tmp"},
      {"CDPREFIX=1 command cd /tmp && pwd", "/home/user", "/tmp"},
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
      "cd ~ && pwd",
      "cd ~/project && pwd",
      "cd && pwd",
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
      "cd - $MAYBE; pwd",
      "cd - \"$@\"; pwd",
      "cd - >output.txt; pwd",
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
      "cd - extra; pwd", "cd - \"$MAYBE\"; pwd", "cd /tmp extra; pwd",
      "cd /tmp -P; pwd", "cd /tmp --; pwd",      "cd -x; pwd",
      "cd ''; pwd",      "cd -- ''; pwd",        "cd --help; pwd",
  };
  for (size_t i = 0; i < sizeof(failed_cd_cases) / sizeof(failed_cd_cases[0]);
       i++) {
    shell_dep_graph_t graph;
    ASSERT(parse_cwd(failed_cd_cases[i], "/home/user", &graph) == SHELL_DEP_OK);
    int pwd = find_cmd_tokens(&graph, "pwd", NULL);
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
  int pwd = find_cmd_tokens(&graph, "pwd", NULL);
  ASSERT(pwd >= 0);
  ASSERT(!graph.nodes[pwd].cmd.cwd_known);
  ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
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

/* Every cd is a command. Its redirect setup and nested commands execute in
 * the incoming directory, before the tracked CWD transition. */
TEST(cd_graph_visible_effects) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse_cwd("cd /tmp", "/home/user", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_CWD) == 1);

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

  /* Redirect setup fails before `cd` executes. A certain failure is a
   * shell-level error which no dependency graph models; where the setup may
   * fail, the following command runs in either directory, so neither the
   * precomputed target nor the incoming directory is committed. */
  ASSERT(parse_cwd("cd /tmp 4>\"\"; printf x >out", "/home/user", &graph) ==
         SHELL_DEP_EUNMODELED);
  ASSERT(parse_cwd("cd /tmp 4>/missing/x; printf x >out", "/home/user",
                   &graph) == SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  writer = find_cmd_tokens(&graph, "printf", NULL);
  redirect = find_file_doc(&graph, "out");
  ASSERT(cd >= 0 && writer >= 0 && redirect >= 0 &&
         !graph.nodes[writer].cmd.cwd_known &&
         shell_dep_graph_validate(&graph).valid);

  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
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

  /* The incoming PWD binding supplies cd's own redirect. Its implicit write
   * happens later and must not erase that command's already installed I/O. */
  ASSERT(parse_cwd("exec {PWD}>/tmp/cd-route; cd / 1>&$PWD; printf x",
                   "/workspace", &graph) == SHELL_DEP_OK);
  cd = find_cmd_tokens(&graph, "cd", NULL);
  redirect = find_file_doc(&graph, "/tmp/cd-route");
  writer = find_cmd_tokens(&graph, "printf", NULL);
  ASSERT(cd >= 0 && redirect >= 0 && writer >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)cd,
                      (uint32_t)redirect, 1, SHELL_DEP_FD_NONE) &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                   (uint32_t)redirect));
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[cd].cmd.cwd_offset),
                "/workspace");
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[writer].cmd.cwd_offset), "/");
  ASSERT(shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

/* A trailing separator or terminal `.` keeps one lexical identity but makes
 * the lookup require a directory; the identity bytes must not change. */
TEST(file_identity_requires_directory) {
  static const struct {
    const char *source;
    const char *word;
    bool requires_directory;
  } cases[] = {
      {": >regular", "regular", false},
      {": >regular/", "regular/", true},
      {": >regular/.", "regular/.", true},
      {": >regular//", "regular//", true},
      {": >.", ".", true},
      {": >a/./b", "a/./b", false},
      {": >a/..", "a/..", false},
      {": >a..", "a..", false},
      {": >a.", "a.", false},
      {": >'a/'", "'a/'", true},
      {": >\\a\\/", "\\a\\/", true},
      {": >/", "/", true},
      {": >/tmp/regular//", "/tmp/regular//", true},
  };
  char baseline[SHELL_DEP_CWD_BUF_SIZE];
  shell_dep_file_identity_t base_identity;
  shell_dep_graph_t graph;
  ASSERT(parse_cwd(": >regular", "/tmp", &graph) == SHELL_DEP_OK);
  int plain = find_file_doc(&graph, "regular");
  ASSERT(plain >= 0 && shell_dep_doc_file_identity_write(
                           &graph, &graph.nodes[plain].doc, baseline,
                           sizeof(baseline), &base_identity));
  ASSERT(!base_identity.requires_directory && base_identity.absolute);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(parse_cwd(cases[i].source, "/tmp", &graph) == SHELL_DEP_OK);
    int file = find_file_doc(&graph, cases[i].word);
    ASSERT(file >= 0);
    char text[SHELL_DEP_CWD_BUF_SIZE];
    shell_dep_file_identity_t identity;
    ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                             text, sizeof(text), &identity));
    ASSERT(identity.requires_directory == cases[i].requires_directory);
    ASSERT(identity.length == strlen(text));
  }
  /* The three spellings of one name still share one identity. */
  static const char *const same[] = {": >regular/", ": >regular/.",
                                     ": >/tmp/regular//"};
  for (size_t i = 0; i < sizeof(same) / sizeof(same[0]); i++) {
    ASSERT(parse_cwd(same[i], "/tmp", &graph) == SHELL_DEP_OK);
    int file = -1;
    for (uint32_t n = 0; n < graph.node_count; n++)
      if (graph.nodes[n].type == SHELL_NODE_DOC &&
          graph.nodes[n].doc.kind == SHELL_DOC_FILE)
        file = (int)n;
    ASSERT(file >= 0);
    char text[SHELL_DEP_CWD_BUF_SIZE];
    shell_dep_file_identity_t identity;
    ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                             text, sizeof(text), &identity));
    ASSERT(identity.length == base_identity.length &&
           memcmp(text, baseline, identity.length) == 0 &&
           identity.absolute == base_identity.absolute &&
           identity.requires_directory);
  }
  /* Dynamic paths have no identity, so no facts either. */
  ASSERT(parse_cwd(": >$target/", "/tmp", &graph) == SHELL_DEP_OK);
  for (uint32_t n = 0; n < graph.node_count; n++) {
    char text[SHELL_DEP_CWD_BUF_SIZE];
    shell_dep_file_identity_t identity = {1, true, true};
    if (graph.nodes[n].type == SHELL_NODE_DOC &&
        graph.nodes[n].doc.kind == SHELL_DOC_FILE)
      ASSERT(!shell_dep_doc_file_identity_write(
                 &graph, &graph.nodes[n].doc, text, sizeof(text), &identity) &&
             identity.length == 0 && !identity.absolute &&
             !identity.requires_directory);
  }
  pass_count++;
}

/* The word after `>&` or `<&` is the NUMBER operand, so the operator that
 * touches it starts a fresh redirect: `2>&1>f` is `2>&1` and then `>f`, just as
 * with a space before `>f`. Reading `1>` as a descriptor prefix leaves `f` an
 * argument and, for a test builtin name, a command nothing inventoried. */
TEST(duplication_operand_does_not_take_the_next_redirect) {
  static const struct {
    const char *joined, *spaced;
  } pairs[] = {
      {"echo hi 2>&1>/dev/null", "echo hi 2>&1 >/dev/null"},
      {"echo hi >&2>f z", "echo hi >&2 >f z"},
      {"echo hi >&2>>f", "echo hi >&2 >>f"},
      {"echo hi <&0>f", "echo hi <&0 >f"},
      {"echo hi >&2<f", "echo hi >&2 <f"},
      {"echo hi >&1>f 2>g", "echo hi >&1 >f 2>g"},
      {"echo hi >&2>f>g", "echo hi >&2 >f >g"},
      {"echo hi >&2>&1>f", "echo hi >&2 >&1 >f"},
      {"echo hi 2>&1|cat", "echo hi 2>&1 |cat"},
      {">&2>x", ">&2 >x"},
      {">&2>test", ">&2 >test"},
      {">&2>[", ">&2 >["},
      {">&2>[ x ]", ">&2 >[ x ]"},
      {"2>&1>test", "2>&1 >test"},
      {"{ echo hi 2>&1>f; }", "{ echo hi 2>&1 >f; }"},
  };
  for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
    shell_dep_graph_t joined, spaced;
    ASSERT(parse(pairs[i].joined, &joined) == SHELL_DEP_OK);
    ASSERT(parse(pairs[i].spaced, &spaced) == SHELL_DEP_OK);
    bool same = joined.node_count == spaced.node_count &&
                joined.edge_count == spaced.edge_count;
    uint32_t commands = count_type(&joined, SHELL_NODE_CMD);
    same = same && commands == count_type(&spaced, SHELL_NODE_CMD);
    for (uint32_t c = 0; same && c < commands; c++) {
      const shell_dep_cmd_t *a = &joined.nodes[find_nth_cmd(&joined, c)].cmd;
      const shell_dep_cmd_t *b = &spaced.nodes[find_nth_cmd(&spaced, c)].cmd;
      same = a->token_count == b->token_count;
      for (uint32_t t = 0; same && t < a->token_count; t++)
        same = a->token_lens[t] == b->token_lens[t] &&
               !memcmp(a->tokens[t], b->tokens[t], a->token_lens[t]);
    }
    if (!same)
      printf("    %s differs from %s (nodes %u/%u, edges %u/%u)\n",
             pairs[i].joined, pairs[i].spaced, joined.node_count,
             spaced.node_count, joined.edge_count, spaced.edge_count);
    ASSERT(same);
  }
  /* The target is a redirect operand, not an argument or a command. */
  shell_dep_graph_t g;
  ASSERT(parse("echo hi 2>&1>/dev/null", &g) == SHELL_DEP_OK);
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.token_count == 2);
  ASSERT(parse(">&2>test", &g) == SHELL_DEP_OK);
  ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.token_count == 0);
  ASSERT(parse("echo $(echo hi 2>&1>f)", &g) == SHELL_DEP_OK);
  ASSERT(count_type(&g, SHELL_NODE_CMD) == 2);
  ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.token_count == 2);
  pass_count++;
}

/* The route journal sweeps change nodes nothing pins. A descriptor state that
 * is still read after a call which can collect must be a root of that call: the
 * failure outcomes and continuations of `read` setup, the pre-application state
 * a setup operation is materialized against, the versions a per-mode setup
 * selects from, and the roots a descriptor operation still has to apply.
 * Reading a swept node used to index the journal at -1. The sources below are
 * valid Bash that drive the journal into collection while such a state is live.
 */
TEST(live_route_states_survive_journal_collection) {
  static const struct {
    const char *source;
    uint32_t commands;
  } cases[] = {
      /* Descriptors above 2 start closed: each shape first opens the
       * descriptors its copies read. */
      {"exec 12<f; read >&-93>&-3<f<&12", 2},
      {"exec 12<f; read >&- 93>&- 3<f <&12", 2},
      {"exec 12<f; read >&-93>&-3<}<&12", 2},
      /* The here-document ends the second command; the redirects after it
       * are a third, wordless command. */
      {"exec 64>f 255>f; : 10>>f {x}>&64 >f <<E\nx\nE\n 10>&255- >f", 3},
      /* More shapes of the same fault, found by fuzzing read setup. */
      {"exec 63>f; read 9>>f3>>f4>&63 x", 2},
      {"exec 93<f; read>&0 {x}<f 9<&93 x", 2},
      {"read {x}<f 3>&- >f 12<f x", 1},
      {"command read <f 1000>>f 10<>f 1000>&- {x}>f x", 1},
      {"exec 3<f 4<f 64>f; read -u 3 >f <&4 {x}>&64 <<E\nx\nE\n {x}<f -z x", 3},
  };
  /* The original fuzzer shapes copy descriptors that are not open: certain
   * descriptor errors, rejected before route resolution. */
  static const char *const violations[] = {
      "read >&-93>&-3<f<&12",
      "read >&- 93>&- 3<f <&12",
      "read >&-93>&-3<}<&12",
      ": 10>>f {x}>&64 >f <<E\nx\nE\n 10>&255- >f",
      "read 9>>f3>>f4>&63 x",
      "read>&0 {x}<f 9<&93 x",
      "read 1000<&64 1000<<<y {x}<&64 &>f {x}>&12 -n",
      "read -u 3 >f <&4 {x}>&64 <<E\nx\nE\n {x}<f -z x",
  };
  for (size_t i = 0; i < sizeof(violations) / sizeof(violations[0]); i++) {
    shell_dep_graph_t g;
    ASSERT(parse(violations[i], &g) == SHELL_DEP_EUNMODELED);
  }
  /* With its descriptors open, this shape still ends in `-n` without an
   * operand: a reported read error with no dependency model. */
  shell_dep_graph_t missing_operand;
  ASSERT(parse("exec 64<f 12>f; read 1000<&64 1000<<<y {x}<&64 &>f "
               "{x}>&12 -n",
               &missing_operand) == SHELL_DEP_EUNMODELED);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t g;
    if (parse(cases[i].source, &g) != SHELL_DEP_OK)
      printf("    not accepted: %s\n", cases[i].source);
    ASSERT(parse(cases[i].source, &g) == SHELL_DEP_OK);
    if (count_type(&g, SHELL_NODE_CMD) != cases[i].commands)
      printf("    %s: %u commands, expected %u\n", cases[i].source,
             count_type(&g, SHELL_NODE_CMD), cases[i].commands);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == cases[i].commands);
  }
  pass_count++;
}

/* A complete source may end in a lone backslash, which is the literal word
 * `\`: `test \` is a one-argument test and true. The semantic traversal that
 * inventories test programs must read that word like any other, or the graph
 * looks up a program nothing recorded. The same word after a state-changing
 * builtin gets the verdict an ordinary operand gets. */
TEST(final_backslash_is_a_literal_word) {
  static const struct {
    const char *source;
    uint32_t tokens; /* argv words of the first command */
  } accepted[] = {
      {"test \\", 2},         {"[ \\", 2},         {"test a \\", 3},
      {"test ! \\", 3},       {"[ a \\", 3},       {"test -n \\", 3},
      {"test a = \\", 4},     {"test \\\\ \\", 3}, {"echo \\", 2},
      {"echo a; test \\", 2},
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    shell_dep_graph_t g;
    if (parse(accepted[i].source, &g) != SHELL_DEP_OK)
      printf("    not accepted: %s\n", accepted[i].source);
    ASSERT(parse(accepted[i].source, &g) == SHELL_DEP_OK);
    uint32_t last = count_type(&g, SHELL_NODE_CMD) - 1;
    uint32_t tokens = g.nodes[find_nth_cmd(&g, last)].cmd.token_count;
    if (tokens != accepted[i].tokens)
      printf("    %s: %u tokens, expected %u\n", accepted[i].source, tokens,
             accepted[i].tokens);
    ASSERT(tokens == accepted[i].tokens);
  }
  /* The backslash word is an operand like `x`, not a way past the check. */
  static const char *const operands[][2] = {
      {"declare -i \\", "declare -i x"},
      {"readonly \\", "readonly x"},
      {"set -e \\", "set -e x"},
      {"shopt -s nullglob \\", "shopt -s nullglob x"},
      {"eval \\", "eval x"},
      /* An indexed array assignment is unsupported whatever its value. */
      {"a[1]=\\", "a[1]=x"},
      {"a[1]=,\\", "a[1]=,x"},
  };
  for (size_t i = 0; i < sizeof(operands) / sizeof(operands[0]); i++) {
    shell_dep_graph_t with_backslash, with_word;
    shell_dep_error_t a = parse(operands[i][0], &with_backslash);
    shell_dep_error_t b = parse(operands[i][1], &with_word);
    if (a != b)
      printf("    %s -> %d but %s -> %d\n", operands[i][0], a, operands[i][1],
             b);
    ASSERT(a == b);
  }
  pass_count++;
}

/* `N<(cmd)` and `N>(cmd)` are one word holding a process substitution, as in
 * `echo 2>(:)` printing `2/dev/fd/63`; they are not a descriptor redirect
 * whose operand is `(cmd)`. Reading them as a redirect hid the substitution's
 * command from the graph even though Bash runs it. */
/* Whether the executed command reads its stdin as shell code follows the
 * reference Bash's invocation grammar (verified per case against the pinned
 * Bash by piping `echo` into each invocation). */
TEST(bash_stdin_code_invocation_grammar) {
  static const struct {
    const char *invocation;
    shell_dep_stdin_code_t code;
  } cases[] = {
      {"bash", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash --", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -r", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -is", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -s", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -x", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash +s", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -o posix", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -ox posix", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash +O extglob", SHELL_DEP_STDIN_CODE_EXECUTES},
      /* Without its operand, -o lists the options and still reads stdin. */
      {"bash -o", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash --norc -x", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash --rcfile /dev/null", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -s sfile", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -s -- a b", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"/bin/bash", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"rbash", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"command bash", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"exec bash", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -o \"$opt\"", SHELL_DEP_STDIN_CODE_EXECUTES},
      {"bash -n", SHELL_DEP_STDIN_CODE_PARSES},
      {"bash -D", SHELL_DEP_STDIN_CODE_PARSES},
      {"bash --dump-strings", SHELL_DEP_STDIN_CODE_PARSES},
      {"bash --pretty-print", SHELL_DEP_STDIN_CODE_PARSES},
      {"bash -c 'echo hello'", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -ic 'echo C'", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -sc 'echo C'", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -s -c 'echo C'", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -c \"$cmd\"", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -- script.sh", SHELL_DEP_STDIN_CODE_NONE},
      {"bash script.sh", SHELL_DEP_STDIN_CODE_NONE},
      {"bash - script.sh", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -n script.sh", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -- -s", SHELL_DEP_STDIN_CODE_NONE},
      /* Option errors and --help/--version exit before reading. */
      {"bash -x --norc", SHELL_DEP_STDIN_CODE_NONE},
      {"bash --rcfile", SHELL_DEP_STDIN_CODE_NONE},
      {"bash --rcfile=/dev/null", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -Z", SHELL_DEP_STDIN_CODE_NONE},
      {"bash -abc", SHELL_DEP_STDIN_CODE_NONE},
      {"bash --help", SHELL_DEP_STDIN_CODE_NONE},
      {"bash --version", SHELL_DEP_STDIN_CODE_NONE},
      {"cat", SHELL_DEP_STDIN_CODE_NONE},
      {"mybash", SHELL_DEP_STDIN_CODE_NONE},
      /* Only the reference Bash is modeled; dynamic words may change the
       * grammar's decision. */
      {"sh", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"/bin/sh -s", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"zsh", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"\"$shell\"", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"bash \"$script\"", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"bash $opts", SHELL_DEP_STDIN_CODE_UNKNOWN},
      {"bash -s \"$arg\"", SHELL_DEP_STDIN_CODE_UNKNOWN},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char source[256];
    int length =
        snprintf(source, sizeof(source), "curl https://example.com/s | %s",
                 cases[i].invocation);
    ASSERT(length > 0 && (size_t)length < sizeof(source));
    shell_dep_graph_t graph;
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int consumer = -1;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_CMD)
        consumer = (int)node;
    ASSERT(consumer >= 0);
    if (graph.nodes[consumer].cmd.stdin_code != cases[i].code)
      printf("\n    stdin code: %s => %d\n", source,
             graph.nodes[consumer].cmd.stdin_code);
    ASSERT(graph.nodes[consumer].cmd.stdin_code == cases[i].code);
    ASSERT(graph.nodes[0].type != SHELL_NODE_CMD ||
           graph.nodes[0].cmd.stdin_code == SHELL_DEP_STDIN_CODE_NONE ||
           consumer == 0);
  }
  pass_count++;
}

TEST(named_fd_prefixed_process_substitution_is_a_word) {
  /* Bash reads `{fd}<(cmd)` as the literal word `{fd}` joined to the process
   * substitution (`echo {fd}<(:)` prints `{fd}/dev/fd/63`); a named
   * descriptor needs a redirect operator that is not `<(` or `>(`. */
  static const struct {
    const char *source;
    uint32_t commands;      /* command nodes, nested ones included */
    uint32_t first_tokens;  /* argv words of the first command */
    uint32_t second_tokens; /* argv words of the substitution's command */
  } words[] = {
      {"echo {fd}<(touch y)z", 2, 2, 2},
      {"echo {fd}>(touch y)z", 2, 2, 2},
      {"echo {fd}<(touch y)", 2, 2, 2},
      {"echo {fd}>(touch y)", 2, 2, 2},
      {"cat {fd}<(touch y)", 2, 2, 2},
      {"echo a {fd}<(touch y) b", 2, 4, 2},
      {"echo {_a1}>(touch y)", 2, 2, 2},
      {"echo $(echo {fd}<(touch y))", 3, 2, 2},
      {"echo {fd}<\\\n(touch y)", 2, 2, 2},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    shell_parse_result_t fast;
    shell_dep_graph_t g;
    if (shell_parse_fast(words[i].source, strlen(words[i].source), NULL,
                         &fast) != SHELL_OK)
      printf("    fast parse rejects: %s\n", words[i].source);
    ASSERT(shell_parse_fast(words[i].source, strlen(words[i].source), NULL,
                            &fast) == SHELL_OK);
    shell_dep_error_t status = parse(words[i].source, &g);
    if (status != SHELL_DEP_OK)
      printf("    not accepted: %s\n", words[i].source);
    ASSERT(status == SHELL_DEP_OK);
    uint32_t commands = count_type(&g, SHELL_NODE_CMD);
    if (commands != words[i].commands)
      printf("    %s: %u commands, expected %u\n", words[i].source, commands,
             words[i].commands);
    ASSERT(commands == words[i].commands);
    ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.token_count ==
           words[i].first_tokens);
    ASSERT(g.nodes[find_nth_cmd(&g, 1)].cmd.token_count ==
           words[i].second_tokens);
  }
  /* A named descriptor before any other redirect operator is still one. */
  static const char *const redirects[] = {
      "echo {fd}>f",       "echo {fd}<f",  "echo {fd}>>f",
      "echo {fd}<<<x",     "echo {fd}<>f", "echo {fd}<&0",
      "echo {fd}>&2",      "exec {fd}>f",  "echo {fd}<<E\nx\nE\n",
      "echo {fd}<\\\n<<x",
  };
  for (size_t i = 0; i < sizeof(redirects) / sizeof(redirects[0]); i++) {
    shell_dep_graph_t g;
    shell_dep_error_t status = parse(redirects[i], &g);
    if (status != SHELL_DEP_OK)
      printf("    not accepted: %s\n", redirects[i]);
    ASSERT(status == SHELL_DEP_OK);
    ASSERT(count_type(&g, SHELL_NODE_CMD) == 1);
    if (g.nodes[find_nth_cmd(&g, 0)].cmd.token_count != 1)
      printf("    %s: %u argv words, expected 1\n", redirects[i],
             (unsigned)g.nodes[find_nth_cmd(&g, 0)].cmd.token_count);
    ASSERT(g.nodes[find_nth_cmd(&g, 0)].cmd.token_count == 1);
  }
  pass_count++;
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

TEST(predecoded_file_identity) {
  static const char *const sources[] = {
      "printf x >\"out\"",
      "printf x >/tmp//./out",
      "printf x >link/../out",
      "printf x >$'/tmp/se\\x63ret'",
      "cd \"$where\"; printf x >out",
  };
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(shell_dep_graph_parse(sources[i], strlen(sources[i]), "/workspace",
                                 NULL, &graph) == SHELL_DEP_OK);
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const shell_dep_node_t *item = &graph.nodes[node];
      if (item->type != SHELL_NODE_DOC || item->doc.kind != SHELL_DOC_FILE)
        continue;
      const shell_dep_doc_t *doc = &item->doc;
      char reference[128], decoded[128], identity[128];
      size_t decoded_length;
      shell_dep_file_identity_t reference_identity, decoded_identity;
      ASSERT(shell_write_decoded_word(doc->path, doc->path_len, decoded,
                                      sizeof(decoded),
                                      &decoded_length) == SHELL_PROCESS_OK);
      bool known = shell_dep_doc_file_identity_write(
          &graph, doc, reference, sizeof(reference), &reference_identity);
      memset(identity, 'x', sizeof(identity));
      ASSERT(shell_dep_doc_file_identity_from_decoded(
                 &graph, doc, decoded, decoded_length, identity,
                 sizeof(identity), &decoded_identity) == known);
      ASSERT(file_identity_equal(&decoded_identity, &reference_identity));
      if (known) {
        ASSERT(strcmp(identity, reference) == 0);
        /* Preflight must leave every byte unchanged on insufficient storage. */
        memset(identity, 'x', sizeof(identity));
        ASSERT(!shell_dep_doc_file_identity_from_decoded(
            &graph, doc, decoded, decoded_length, identity, 1,
            &decoded_identity));
        ASSERT(decoded_identity.length == 0 && !decoded_identity.absolute &&
               !decoded_identity.requires_directory);
        for (size_t j = 0; j < sizeof(identity); j++)
          ASSERT(identity[j] == 'x');
        /* In-place CWD insertion must not overwrite the decoded operand. */
        memcpy(identity, decoded, decoded_length);
        ASSERT(shell_dep_doc_file_identity_from_decoded(
            &graph, doc, identity, decoded_length, identity, sizeof(identity),
            &decoded_identity));
        ASSERT(strcmp(identity, reference) == 0 &&
               file_identity_equal(&decoded_identity, &reference_identity));
      } else {
        for (size_t j = 0; j < sizeof(identity); j++)
          ASSERT(identity[j] == 'x');
      }
    }
  }
  pass_count++;
}

TEST(static_file_identity_and_effective_group_pipe_routes) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("cd /tmp/first && printf x >\"out\" && cat ./out && "
               "cd /tmp/second && cat ./out",
               &graph) == SHELL_DEP_OK);
  char identities[3][128] = {{0}};
  shell_dep_file_identity_t facts[3] = {{0}};
  shell_dep_file_identity_t file_identity = {.length = SIZE_MAX};
  uint32_t count = 0;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_FILE ||
        graph.nodes[node].doc.path_len != 5 ||
        (memcmp(graph.nodes[node].doc.path, "\"out\"", 5) != 0 &&
         memcmp(graph.nodes[node].doc.path, "./out", 5) != 0))
      continue;
    ASSERT(count < 3);
    ASSERT(shell_dep_doc_file_identity_write(
        &graph, &graph.nodes[node].doc, identities[count],
        sizeof(identities[count]), &facts[count]));
    ASSERT(facts[count].absolute);
    count++;
  }
  ASSERT(count == 3 && strcmp(identities[0], "/tmp/first/out") == 0 &&
         strcmp(identities[1], identities[0]) == 0 &&
         strcmp(identities[2], "/tmp/second/out") == 0);

  ASSERT(parse("printf x >out; cd / && cat ./out", &graph) == SHELL_DEP_OK);
  uint32_t origin_count = 0;
  for (uint32_t node = 0; node < graph.node_count; node++) {
    if (graph.nodes[node].type != SHELL_NODE_DOC ||
        graph.nodes[node].doc.kind != SHELL_DOC_FILE ||
        !((graph.nodes[node].doc.path_len == 3 &&
           memcmp(graph.nodes[node].doc.path, "out", 3) == 0) ||
          (graph.nodes[node].doc.path_len == 5 &&
           memcmp(graph.nodes[node].doc.path, "./out", 5) == 0)))
      continue;
    ASSERT(origin_count < 2);
    ASSERT(shell_dep_doc_file_identity_write(
        &graph, &graph.nodes[node].doc, identities[origin_count],
        sizeof(identities[origin_count]), &facts[origin_count]));
    origin_count++;
  }
  ASSERT(origin_count == 2 && !facts[0].absolute && facts[1].absolute &&
         strcmp(identities[0], "out") == 0 &&
         strcmp(identities[1], "/out") == 0);

  ASSERT(parse("printf x >../out; cat ./out", &graph) == SHELL_DEP_OK);
  int parent_file = find_file_doc(&graph, "../out");
  int local_file = find_file_doc(&graph, "./out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(shell_dep_doc_file_identity_write(
             &graph, &graph.nodes[parent_file].doc, identities[0],
             sizeof(identities[0]), &facts[0]) &&
         !facts[0].absolute && strcmp(identities[0], "../out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &facts[1]) &&
         !facts[1].absolute && strcmp(identities[1], "out") == 0);

  ASSERT(parse("printf x >/var/run/../tmp/out; cat /var/tmp/out", &graph) ==
         SHELL_DEP_OK);
  parent_file = find_file_doc(&graph, "/var/run/../tmp/out");
  local_file = find_file_doc(&graph, "/var/tmp/out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(
      shell_dep_doc_file_identity_write(&graph, &graph.nodes[parent_file].doc,
                                        identities[0], sizeof(identities[0]),
                                        &facts[0]) &&
      facts[0].absolute && strcmp(identities[0], "/var/run/../tmp/out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &facts[1]) &&
         facts[1].absolute && strcmp(identities[1], "/var/tmp/out") == 0);

  ASSERT(parse("printf x >link/../out; cat ./out", &graph) == SHELL_DEP_OK);
  parent_file = find_file_doc(&graph, "link/../out");
  local_file = find_file_doc(&graph, "./out");
  ASSERT(parent_file >= 0 && local_file >= 0);
  ASSERT(shell_dep_doc_file_identity_write(
             &graph, &graph.nodes[parent_file].doc, identities[0],
             sizeof(identities[0]), &facts[0]) &&
         !facts[0].absolute && strcmp(identities[0], "link/../out") == 0);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[local_file].doc,
                                           identities[1], sizeof(identities[1]),
                                           &facts[1]) &&
         !facts[1].absolute && strcmp(identities[1], "out") == 0);

  ASSERT(parse("cd /tmp/first; printf x >\"out\"; cat ./out; "
               "cd /tmp/second; cat ./out",
               &graph) == SHELL_DEP_OK);
  char too_small[4] = {'x', 'x', 'x', 'x'};

  int file = find_file_doc(&graph, "\"out\"");
  ASSERT(file >= 0 &&
         !shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                            too_small, sizeof(too_small),
                                            &file_identity) &&
         file_identity.length == 0 && too_small[0] == 'x');

  shell_dep_doc_t uncertain = graph.nodes[file].doc;
  uncertain.cwd_known = false;
  file_identity.length = SIZE_MAX;
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]),
                                            &file_identity) &&
         file_identity.length == 0);
  uncertain.path = "/tmp/absolute";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                           sizeof(identities[0]),
                                           &file_identity) &&
         file_identity.absolute && strcmp(identities[0], "/tmp/absolute") == 0);
  uncertain.path = "$runtime";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]),
                                            &file_identity) &&
         file_identity.length == 0);
  uncertain.path = "$'\\x00x'";
  uncertain.path_len = (uint32_t)strlen(uncertain.path);
  ASSERT(!shell_dep_doc_file_identity_write(&graph, &uncertain, identities[0],
                                            sizeof(identities[0]),
                                            &file_identity) &&
         file_identity.length == 0);

  ASSERT(parse("cd /tmp/group && { printf x; } >out", &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "out");
  ASSERT(file >= 0 &&
         shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                           identities[0], sizeof(identities[0]),
                                           &file_identity) &&
         file_identity.absolute &&
         strcmp(identities[0], "/tmp/group/out") == 0);

  ASSERT(parse("echo $(cd /tmp/nested && cat ./file)", &graph) == SHELL_DEP_OK);
  file = find_file_doc(&graph, "./file");
  ASSERT(file >= 0 &&
         shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                           identities[0], sizeof(identities[0]),
                                           &file_identity) &&
         file_identity.absolute &&
         strcmp(identities[0], "/tmp/nested/file") == 0);

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

TEST(exec_prepared_outcome_contract) {
  for (size_t i = 0; i < sizeof(shellsplit_test_exec_continuations) /
                             sizeof(shellsplit_test_exec_continuations[0]);
       i++) {
    shell_dep_graph_t graph = {0};
    const char *source = shellsplit_test_exec_continuations[i].source;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int file = find_file_doc(&graph, "out");
    ASSERT(writer >= 0 && file >= 0);
    bool writes = has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                               (uint32_t)file, 1, SHELL_DEP_FD_NONE);
    if (writes != shellsplit_test_exec_continuations[i].writes)
      printf("    exec source: %s (writes %d)\n", source, writes);
    ASSERT(writes == shellsplit_test_exec_continuations[i].writes &&
           shell_dep_graph_validate(&graph).valid);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    ASSERT(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_EXEC_ANALYSIS) ==
           1);
#endif
  }
  static const struct {
    const char *source;
    const char *file;
  } routes[] = {
      {"exec 3>base; exec -z 3>new; printf payload >&3", "base"},
      {"exec 3>base; exec -a 3>new; printf payload >&3", "base"},
      {"exec 3>base; command exec -z 3>new || printf payload >&3", "base"},
      {"exec 3>base; builtin exec 3>new; printf payload >&3", "base"},
      {"exec 3>base; exec $target 3>new && printf payload >&3", "new"},
      {"exec 3>base; exec $target 3>new || printf payload >&3", "base"},
      {"exec {fd}>base && fd=99 read fd {fd}>new <<<x && printf payload >&$fd",
       "new"},
  };
  for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(routes[i].source, &graph) == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int file = find_file_doc(&graph, routes[i].file);
    ASSERT(writer >= 0 && file >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                        (uint32_t)file, 1, SHELL_DEP_FD_NONE));
    for (uint32_t e = 0; e < graph.edge_count; e++)
      ASSERT((graph.edges[e].type != SHELL_EDGE_WRITE ||
              !internal_relation(&graph, &graph.edges[e])) ||
             graph.edges[e].from != (uint32_t)writer ||
             graph.edges[e].source_fd != 1 ||
             graph.edges[e].to == (uint32_t)file);
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(prefix_binding_index_scaling) {
  for (unsigned count = 4; count <= 12; count += 4) {
    char source[2048];
    size_t used =
        (size_t)snprintf(source, sizeof(source), "exec {fd}>base; fd=99 ");
    for (unsigned i = 0; i < count; i++)
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "key%u=99 ", i);
    used += (size_t)snprintf(source + used, sizeof(source) - used, "read fd ");
    for (unsigned i = 0; i < count; i++)
      used +=
          (size_t)snprintf(source + used, sizeof(source) - used, "k'ey'%u ", i);
    snprintf(source + used, sizeof(source) - used,
             "<<<x; printf payload >&$fd");
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    shell_dep_graph_t graph = {0};
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int file = find_file_doc(&graph, "base");
    ASSERT(writer >= 0 && file >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                        (uint32_t)file, 1, SHELL_DEP_FD_NONE));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    unsigned height = 1;
    for (unsigned names = count + 1; names; names >>= 1)
      height++;
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_PREFIX_LOOKUP);
    ASSERT(work > 0 && work <= 2u * (count + 1) * height);
#endif
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
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
      {"{ cat; } << EOF <<-\"F\"\r\none\r\nEOF\n\ttwo\r\n\tF\r\n", 2, 1, "EOF"},
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
      if ((graph.edges[edge].type == SHELL_EDGE_READ &&
           internal_relation(&graph, &graph.edges[edge]))) {
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

TEST(adjacent_substitution_consumers) {
  static const struct {
    const char *source;
    bool dynamic_name;
  } cases[] = {
      {"VALUE=\"$(printf a)${value:-$(printf b)}\" echo ok", false},
      {"cat >\"$(printf a)${value:-$(printf b)}\"", true},
      {"{ cat; } >\"$(printf a)${value:-$(printf b)}\"", true},
      {"cat <<<\"$(printf a)${value:-$(printf b)}\"", false},
      {"cat <<EOF\n'$(printf a)'${value:-$(printf b)}\nEOF", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].source, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == 2);
    int first = find_cmd_tokens(&graph, "printf", "a");
    int second = find_cmd_tokens(&graph, "printf", "b");
    ASSERT(first >= 0 && second >= 0 && first != second);
    unsigned producers = 0;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *flow = &graph.edges[edge];
      if (!internal_relation(&graph, flow))
        continue;
      if (flow->type != SHELL_EDGE_SUBST)
        continue;
      ASSERT(flow->source_fd == 1);
      ASSERT(((flow->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ==
             cases[i].dynamic_name);
      if (flow->from == (uint32_t)first)
        producers |= 1;
      if (flow->from == (uint32_t)second)
        producers |= 2;
    }
    ASSERT(producers == 3 && shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

/* --- ENVIRONMENT VARIABLES --- */

/* --- FILE ARGUMENTS --- */

TEST(file_argument_positions) {
  static const struct {
    const char *source;
    const char *arguments[2];
  } cases[] = {
      {"/bin/echo hello", {NULL, NULL}},
      {"<() /bin/echo hello", {NULL, NULL}},
      {"X=x /bin/echo hello", {NULL, NULL}},
      {"</dev/null /bin/echo hello", {NULL, NULL}},
      {"X=x </dev/null <()>() /bin/echo hello", {NULL, NULL}},
      {"<(# comment\n) >() <() /bin/echo hello", {NULL, NULL}},
      {"/bin/echo /tmp/input", {"/tmp/input", NULL}},
      {"<() /bin/echo /tmp/input", {"/tmp/input", NULL}},
      {"X=x /bin/echo /tmp/input", {"/tmp/input", NULL}},
      {"</dev/null /bin/echo /tmp/input", {"/tmp/input", NULL}},
      {"X=x </dev/null <()>() /bin/echo /tmp/input", {"/tmp/input", NULL}},
      {"/bin/<()echo /tmp/input", {"/tmp/input", NULL}},
      {"\"$program\" /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"$(printf program) /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"\"$(printf program)\" /tmp/input", {"/tmp/input", NULL}},
      {"<(printf program) /tmp/input", {"/tmp/input", NULL}},
      {"command /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"command <() /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"builtin printf /tmp/input", {"/tmp/input", NULL}},
      {"exec <() /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
  };
  /* A statically empty command name certainly fails its lookup, a
   * shell-level error which no dependency graph models. */
  static const char *const empty_names[] = {
      "'' /bin/echo /tmp/input",
      "''<() /bin/echo /tmp/input",
  };
  for (size_t i = 0; i < sizeof(empty_names) / sizeof(empty_names[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(empty_names[i], &graph) == SHELL_DEP_EUNMODELED);
  }
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].source, &graph) == SHELL_DEP_OK);
    unsigned seen = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (edge->type != SHELL_EDGE_ARG)
        continue;
      ASSERT(seen < 2 && cases[i].arguments[seen] != NULL);
      ASSERT(edge->dir == SHELL_DIR_UNDIR &&
             graph.nodes[edge->to].type == SHELL_NODE_DOC &&
             graph.nodes[edge->to].doc.kind == SHELL_DOC_FILE);
      const shell_dep_doc_t *doc = &graph.nodes[edge->to].doc;
      ASSERT_STRN_EQ(doc->path, doc->path_len, cases[i].arguments[seen]);
      seen++;
    }
    ASSERT(seen == (unsigned)(cases[i].arguments[0] != NULL) +
                       (unsigned)(cases[i].arguments[1] != NULL));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  /* Token truncation cannot turn argv[0] into an argument or hide a later
   * pathname merely because its source word could not enter the public array.
   */
  static const uint32_t capacities[][3] = {{2, 2, 1}, {3, 3, 1},  {6, 5, 1},
                                           {6, 6, 2}, {8, 12, 1}, {8, 12, 3}};
  const char *source = "X=x </dev/null <() /bin/echo /tmp/input";
  for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); i++) {
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    limits.max_nodes = capacities[i][0];
    limits.max_edges = capacities[i][1];
    limits.max_tokens_per_cmd = capacities[i][2];
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = shell_dep_graph_parse(
        source, strlen(source), "/workspace", &limits, &graph);
    ASSERT(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC);
    ASSERT(graph.node_count <= limits.max_nodes &&
           graph.edge_count <= limits.max_edges &&
           find_file_doc(&graph, "/bin/echo") < 0 &&
           shell_dep_graph_validate(&graph).valid);
    if (i >= 4)
      ASSERT(find_file_doc(&graph, "/tmp/input") >= 0);
  }
  pass_count++;
}

/* --- SUBSHELLS --- */

/* --- HEREDOCS AND HERESTRINGS --- */

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

  ASSERT(!shell_dep_doc_content_length(&malformed_value, &length) &&
         length == 0);
  ASSERT(!shell_dep_doc_content_length(&malformed_flags, &length) &&
         length == 0);
  ASSERT(shell_dep_doc_content_length(&empty, &length) && length == 0);

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
    if (!internal_relation(&graph, item))
      continue;
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
        heredoc_read || ((graph.edges[edge].type == SHELL_EDGE_READ &&
                          internal_relation(&graph, &graph.edges[edge])) &&
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

  /* Static arithmetic is active in an unquoted heredoc without creating a
   * data-flow edge. Dynamic arithmetic retains the library-wide unsupported
   * semantic classification and fails closed. */
  ASSERT(parse("cat <<EOF\n$((1 + 2))\nEOF", &graph) == SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$((1 + $(id)))\nEOF", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

  ASSERT(parse("cat <<EOF\n$((1 + 2)\nEOF", &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
         graph.edge_count == 0);

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
   * replaces fd 0. The second document's substitution inherits the first
   * document as stdin; the final document alone feeds the outer command. */
  ASSERT(parse("cat <<A <<-B\n$(id)\nA\n\t$(pwd)\n\tB\n", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 3 &&
         count_doc_kind(&graph, SHELL_DOC_HEREDOC) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         count_edge_type(&graph, SHELL_EDGE_READ) == 2);
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
  ASSERT(transient_count == 0 && strip_tabs_count == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <<EOF\n$(</tmp/heredoc-input)\nEOF", &graph) ==
         SHELL_DEP_OK);
  ASSERT(count_type(&graph, SHELL_NODE_CMD) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1);
  bool file_to_document = false;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
    const shell_dep_edge_t *item = &graph.edges[edge];
    if (!internal_relation(&graph, item))
      continue;
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
    if (!internal_relation(&graph, current))
      continue;
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
    if (!internal_relation(&graph, edge))
      continue;
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
         /* The later stderr open can fail into the existing substitution. */
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
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
    if (!internal_relation(&graph, edge))
      continue;
    stale_collector_route =
        stale_collector_route ||
        (edge->type == SHELL_EDGE_WRITE && edge->from == (uint32_t)writer &&
         graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT &&
         edge->source_fd == 1);
  }
  ASSERT(writer >= 0 && out_file >= 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)out_file, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                      (uint32_t)out_file, 2, SHELL_DEP_FD_NONE) &&
         /* stdout is replaced; setup failure still emits stderr to the
          * existing collector before reaching the later 2>&1. */
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

  /* Cross-direction opens install a shared pipe with two readers or writers,
   * not a transfer between those peers. Do not invert that relation
   * or manufacture a file named after the process-substitution spelling. */
  ASSERT(parse("cat < >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)producer, SHELL_DEP_FD_NONE, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat > <(printf input)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)consumer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)producer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  /* A redirect need not be separated from its process-substitution operand.
   * `><(` is a compact cross-direction spelling, not the `<>` read/write
   * operator, and therefore creates no fabricated stream. */
  ASSERT(parse("cat><(printf input)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
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
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)producer,
                      (uint32_t)endpoint, 1, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                      (uint32_t)consumer, SHELL_DEP_FD_NONE, 0) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)consumer,
                      (uint32_t)endpoint, 0, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <> >(sh)", &graph) == SHELL_DEP_OK);
  consumer = find_nth_cmd(&graph, 0);
  producer = find_nth_cmd(&graph, 1);
  endpoint = find_endpoint(&graph);
  ASSERT(consumer >= 0 && producer >= 0 && endpoint >= 0 &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_doc_kind(&graph, SHELL_DOC_FILE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 2 &&
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
    if (!internal_relation(&graph, current))
      continue;
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
    if (!internal_relation(&graph, current))
      continue;
    final_file_write =
        final_file_write ||
        (current->type == SHELL_EDGE_WRITE &&
         current->from == (uint32_t)writer && current->source_fd == 0 &&
         graph.nodes[current->to].type == SHELL_NODE_DOC &&
         graph.nodes[current->to].doc.kind == SHELL_DOC_FILE);
  }
  ASSERT(writer >= 0 && consumer >= 0 && final_file_write &&
         count_type(&graph, SHELL_NODE_ENDPOINT) == 1 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                   (uint32_t)find_endpoint(&graph)) &&
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
    if (!internal_relation(&graph, current))
      continue;
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
TEST(recursive_fd_import_final_routes) {
  static const struct {
    const char *source;
    const char *command;
    const char *argument;
    const char *path;
    shell_dep_edge_type_t type;
    uint32_t fd;
    bool present;
  } cases[] = {
      {"exec 0<input; echo \"$(cat)\"", "cat", NULL, "input", SHELL_EDGE_READ,
       0, true},
      {"exec 2>errors; echo \"$(child)\"", "child", NULL, "errors",
       SHELL_EDGE_WRITE, 2, true},
      {"exec 3>old; echo \"$(printf child >&3 >new)\"", "printf", "child",
       "old", SHELL_EDGE_WRITE, 1, false},
      {"exec 3>old; echo \"$(printf child >&3 1>&-)\"", "printf", "child",
       "old", SHELL_EDGE_WRITE, 1, false},
      {"exec 3<input; echo \"$(cat <&3 <new)\"", "cat", NULL, "input",
       SHELL_EDGE_READ, 0, false},
      {"exec 3>old; echo \"$(exec 1>&3; printf child)\"", "printf", "child",
       "old", SHELL_EDGE_WRITE, 1, true},
      {"exec 3<input; echo \"$(exec 0<&3; cat)\"", "cat", NULL, "input",
       SHELL_EDGE_READ, 0, true},
      {"exec {fd}<>both; echo \"$(exec 0<&$fd 1>&$fd; child)\"", "child", NULL,
       "both", SHELL_EDGE_READ, 0, true},
      {"exec {fd}<>both; echo \"$(exec 0<&$fd 1>&$fd; child)\"", "child", NULL,
       "both", SHELL_EDGE_WRITE, 1, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(cases[i].source, &graph) == SHELL_DEP_OK);
    int command = find_cmd_tokens(&graph, cases[i].command, cases[i].argument);
    int document = find_file_doc(&graph, cases[i].path);
    ASSERT(command >= 0 && document >= 0);
    bool present =
        cases[i].type == SHELL_EDGE_READ
            ? has_edge_fds(&graph, cases[i].type, (uint32_t)document,
                           (uint32_t)command, SHELL_DEP_FD_NONE, cases[i].fd)
            : has_edge_fds(&graph, cases[i].type, (uint32_t)command,
                           (uint32_t)document, cases[i].fd, SHELL_DEP_FD_NONE);
    if (present != cases[i].present)
      printf("\n    import final-route case: %s\n", cases[i].source);
    ASSERT(present == cases[i].present &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(pipeline_group_scope_state) {
  static const char *const timed_sources[] = {
      "printf x | { exec 2>err && time true; }",
      "printf x |& { exec 2>err && time true; }",
      "printf x |\\\n{ exec 2>err && time true; }",
      "printf x |\n# next stage\n{ exec 2>err && time true; }",
      "printf x | { { exec 2>err; } && time true; }",
      "printf x | { exec 2>err && echo \"$(time true)\"; }",
      "printf x | { exec {fd}>err && exec 2>&$fd && time true; }",
      "printf x | { exec 2>err && time true; } | cat",
      "printf x |& { exec 2>err && time true; } |& cat",
      "{ exec 2>err && time true; } | cat",
      "printf x | { exec 2>err && time true; } &",
      "printf x | { exec 2>err && time true; } <<EOF\nbody\nEOF\n",
      "printf x | { <<EOF; exec 2>err && time true; }\nbody\nEOF\n",
  };
  for (size_t i = 0; i < sizeof(timed_sources) / sizeof(timed_sources[0]);
       i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t status = parse(timed_sources[i], &graph);
    if (status != SHELL_DEP_OK)
      printf("\n    pipeline scope: %s status=%d\n", timed_sources[i], status);
    ASSERT(status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid);
    int timer = find_time(&graph), document = find_file_doc(&graph, "err");
    ASSERT(timer >= 0 && document >= 0);
    ASSERT(graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH);
    ASSERT(has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                        (uint32_t)document, 2, SHELL_DEP_FD_NONE));
  }

  static const char *const alias_sources[] = {
      "printf x | { exec 3<&0 && echo \"$(cat <&3)\"; }",
      "printf x | { exec 3<&0 && exec <input && echo \"$(cat <&3)\"; }",
      "printf x | { exec {fd}<&0 && echo \"$(cat <&$fd)\"; }",
      "printf x |& { exec {fd}<&0 && echo \"$(cat <&$fd)\"; }",
      "printf x | { { exec 3<&0; }; echo \"$(cat <&3)\"; }",
  };
  for (size_t i = 0; i < sizeof(alias_sources) / sizeof(alias_sources[0]);
       i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(alias_sources[i], &graph) == SHELL_DEP_OK);
    int producer = find_cmd_tokens(&graph, "printf", "x");
    int consumer = find_cmd_tokens(&graph, "cat", NULL);
    ASSERT(producer >= 0 && consumer >= 0);
    ASSERT(has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)producer,
                        (uint32_t)consumer, 1, 0));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  static const char *const cwd_sources[] = {
      "printf x | { cd /tmp; echo inside; }; echo outside",
      "printf x | { true; cd /tmp; echo inside; }; echo outside",
      "printf x | { { cd /tmp; }; echo inside; }; echo outside",
      "printf x |& { cd /tmp; echo inside; }; echo outside",
      "printf x | { cd /tmp; echo inside; } | cat; echo outside",
      "{ cd /tmp; echo inside; } | cat; echo outside",
      "printf x | { cd /tmp; echo inside; } & echo outside",
  };
  for (size_t i = 0; i < sizeof(cwd_sources) / sizeof(cwd_sources[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse_cwd(cwd_sources[i], "/workspace", &graph) == SHELL_DEP_OK);
    int inside = find_cmd_tokens(&graph, "echo", "inside");
    int outside = find_cmd_tokens(&graph, "echo", "outside");
    ASSERT(inside >= 0 && outside >= 0);
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[inside].cmd.cwd_offset),
                  "/tmp");
    ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[outside].cmd.cwd_offset),
                  "/workspace");
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }

  /* Syntactic pipeline membership, not a live PIPE edge, defines isolation.
   * Conversely, an inner pipeline must not isolate its enclosing brace. */
  shell_dep_graph_t graph;
  ASSERT(parse("printf x | { exec {fd}>err && printf value >&$fd; }; "
               "printf later >&$fd",
               &graph) == SHELL_DEP_EPARSE);
  ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  ASSERT(parse_cwd("{ printf x | cat; cd /tmp; }; echo outside", "/workspace",
                   &graph) == SHELL_DEP_OK);
  int outside = find_cmd_tokens(&graph, "echo", "outside");
  ASSERT(outside >= 0);
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[outside].cmd.cwd_offset),
                "/tmp");
  ASSERT(parse_cwd("printf x | { cd /tmp; } <input; echo outside", "/workspace",
                   &graph) == SHELL_DEP_OK);
  outside = find_cmd_tokens(&graph, "echo", "outside");
  ASSERT(outside >= 0);
  ASSERT_STR_EQ(get_cwd_str(&graph, graph.nodes[outside].cmd.cwd_offset),
                "/workspace");
  pass_count++;
}

TEST(unconnected_process_redirect_replaces_descriptor) {
  static const struct {
    const char *source;
    const char *command;
    const char *argument;
    bool input;
    uint32_t fd;
    bool group;
  } cases[] = {
      {"cat outer <input < <(printf ignored >/dev/null)", "cat", "outer", true,
       0, false},
      {"cat outer <input < <(printf ignored >/dev/null) 3<&0 <&3", "cat",
       "outer", true, 0, false},
      {"cat outer <input < <(printf ignored >/dev/null) <<<\"$(cat nested)\"",
       "cat", "nested", true, 0, false},
      {"exec 0<input && exec 0< <(printf ignored >/dev/null) && cat outer",
       "cat", "outer", true, 0, false},
      {"exec {fd}<input && exec {fd}< <(printf ignored >/dev/null) && cat "
       "outer "
       "<&$fd",
       "cat", "outer", true, 0, false},
      {"{ cat outer; } <input < <(printf ignored >/dev/null)", "cat", "outer",
       true, 0, true},
      {"printf value >out > >(true </dev/null)", "printf", "value", false, 1,
       false},
      {"printf value >out > >(true 0<&-)", "printf", "value", false, 1, false},
      {"printf value >out > >(true </dev/null) 3>&1 >&3", "printf", "value",
       false, 1, false},
      {"printf value >out &> >(true </dev/null)", "printf", "value", false, 1,
       false},
      {"printf value >out &>> >(true </dev/null)", "printf", "value", false, 2,
       false},
      {"exec 1>out && exec 1> >(true </dev/null) && printf value", "printf",
       "value", false, 1, false},
      {"exec {fd}>out && exec {fd}> >(true </dev/null) && printf value >&$fd",
       "printf", "value", false, 1, false},
      {"{ printf value; } >out > >(true </dev/null)", "printf", "value", false,
       1, true},
      {"exec 2>out && exec 2> >(true </dev/null) && time true", NULL, NULL,
       false, 2, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t status = parse(cases[i].source, &graph);
    if (status != SHELL_DEP_OK)
      fprintf(stderr, "unconnected redirect parse: %s status=%d\n",
              cases[i].source, status);
    ASSERT(status == SHELL_DEP_OK);
    int owner =
        cases[i].group ? find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX)
        : cases[i].command
            ? find_cmd_tokens(&graph, cases[i].command, cases[i].argument)
            : find_time(&graph);
    int previous = find_file_doc(&graph, cases[i].input ? "input" : "out");
    bool installed = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *item = &graph.edges[edge];
      if (!internal_relation(&graph, item))
        continue;
      uint32_t endpoint = cases[i].input ? item->from : item->to;
      bool route = cases[i].input ? item->type == SHELL_EDGE_SUBST &&
                                        item->to == (uint32_t)owner &&
                                        item->target_fd == cases[i].fd
                                  : item->type == SHELL_EDGE_WRITE &&
                                        item->from == (uint32_t)owner &&
                                        item->source_fd == cases[i].fd;
      installed |= route && graph.nodes[endpoint].type == SHELL_NODE_ENDPOINT &&
                   graph.nodes[endpoint].endpoint.reserved == 2;
    }
    if (!installed)
      fprintf(stderr, "unconnected redirect: %s\n", cases[i].source);
    ASSERT(owner >= 0 && previous >= 0 && installed);
    ASSERT(cases[i].input
               ? !has_edge_fds(&graph, SHELL_EDGE_READ, (uint32_t)previous,
                               (uint32_t)owner, SHELL_DEP_FD_NONE, cases[i].fd)
               : !has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)owner,
                               (uint32_t)previous, cases[i].fd,
                               SHELL_DEP_FD_NONE));
    shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
    if (!validation.valid) {
      fprintf(stderr, "invalid unconnected route: %s\n", cases[i].source);
      shell_dep_graph_dump(&graph, stderr);
      for (uint32_t error = 0; error < validation.error_count; error++)
        fprintf(stderr, "%s\n", validation.errors[error].msg);
    }
    ASSERT(validation.valid);
  }
  shell_dep_graph_t graph;
  ASSERT(parse("cat < <(printf old) < <(printf ignored >/dev/null)", &graph) ==
         SHELL_DEP_OK);
  int previous = find_cmd_tokens(&graph, "printf", "old");
  int owner = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(previous >= 0 && owner >= 0 &&
         !has_edge_fds(&graph, SHELL_EDGE_SUBST, (uint32_t)previous,
                       (uint32_t)owner, 1, 0) &&
         shell_dep_graph_validate(&graph).valid);

  /* Both a connected pipe and an unconnected replacement reserve their entire
   * topology before joining. Truncated graphs must never promise a half-route.
   */
  static const char *const bounded[] = {
      "cat <input < <(printf ignored >/dev/null)",
      "printf value >out &> >(true </dev/null)",
      "exec 2>out && exec 2> >(true </dev/null) && time true",
  };
  for (size_t i = 0; i < sizeof(bounded) / sizeof(bounded[0]); i++) {
    shell_dep_graph_t full;
    ASSERT(parse(bounded[i], &full) == SHELL_DEP_OK);
    for (unsigned dimension = 0; dimension < 2; dimension++) {
      uint32_t count = dimension == 0 ? full.node_count : full.edge_count;
      for (uint32_t capacity = 0; capacity <= count; capacity++) {
        shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
        if (dimension == 0)
          limits.max_nodes = capacity;
        else
          limits.max_edges = capacity;
        shell_dep_error_t status = shell_dep_graph_parse(
            bounded[i], strlen(bounded[i]), ".", &limits, &graph);
        ASSERT(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        ASSERT(shellsplit_test_depgraph_invariants(
            bounded[i], strlen(bounded[i]), status, &graph, &limits));
      }
    }
  }
  pass_count++;
}

TEST(process_pipe_descriptor_installation) {
  static const struct {
    const char *source;
    const char *old_path;
    bool write;
    uint32_t fd;
    bool group;
    bool timer;
  } cases[] = {
      {"cat outer <input < >(true </dev/null)", "input", false, 0, false,
       false},
      {"printf value >out > <(printf ignored >/dev/null)", "out", true, 1,
       false, false},
      {"printf value >out &> <(printf ignored >/dev/null)", "out", true, 1,
       false, false},
      {"printf value >out &>> <(printf ignored >/dev/null)", "out", true, 2,
       false, false},
      {"exec 0<input && exec 0< >(true </dev/null) && cat outer", "input",
       false, 0, false, false},
      {"exec 1>out && exec 1> <(printf ignored >/dev/null) && printf value",
       "out", true, 1, false, false},
      {"{ cat outer; } <input < >(true </dev/null)", "input", false, 0, true,
       false},
      {"{ printf value; } >out > <(printf ignored >/dev/null)", "out", true, 1,
       true, false},
      {"exec {fd}< >(true </dev/null) && cat outer <&$fd", NULL, false, 0,
       false, false},
      {"exec {fd}> <(printf ignored >/dev/null) && printf value >&$fd", NULL,
       true, 1, false, false},
      {"exec {fd}<> <(printf input) && printf value >&$fd", NULL, true, 1,
       false, false},
      {"exec {fd}<> >(true </dev/null) && cat outer <&$fd", NULL, false, 0,
       false, false},
      {"exec {fd}<> <(printf input) && exec 3>&$fd && exec {fd}>&- && "
       "printf value >&3",
       NULL, true, 1, false, false},
      {"exec 2>out && exec 2> <(printf ignored >/dev/null) && time true", "out",
       true, 2, false, true},
      {"exec {fd}> <(printf ignored >/dev/null) && echo \"$(printf value "
       ">&$fd)\"",
       NULL, true, 1, false, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t status = parse(cases[i].source, &graph);
    if (status != SHELL_DEP_OK)
      fprintf(stderr, "process pipe case %zu: status=%d source=%s\n", i, status,
              cases[i].source);
    ASSERT(status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid);
    int owner = cases[i].group
                    ? find_group(&graph, SHELL_GROUP_BRACE, UINT32_MAX)
                : cases[i].timer ? find_time(&graph)
                : cases[i].write ? find_cmd_tokens(&graph, "printf", "value")
                                 : find_cmd_tokens(&graph, "cat", "outer");
    int pipe = find_endpoint(&graph);
    ASSERT(owner >= 0 && pipe >= 0);
    shell_dep_edge_type_t type =
        cases[i].write ? SHELL_EDGE_WRITE : SHELL_EDGE_SUBST;
    ASSERT(has_edge_fds(&graph, type, (uint32_t)(cases[i].write ? owner : pipe),
                        (uint32_t)(cases[i].write ? pipe : owner),
                        cases[i].write ? cases[i].fd : SHELL_DEP_FD_NONE,
                        cases[i].write ? SHELL_DEP_FD_NONE : cases[i].fd));
    if (cases[i].old_path) {
      int old = find_file_doc(&graph, cases[i].old_path);
      if (old >= 0) {
        ASSERT(
            !has_edge(&graph, SHELL_EDGE_READ, (uint32_t)old, (uint32_t)owner));
        ASSERT(!has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)owner,
                         (uint32_t)old));
        ASSERT(!has_edge(&graph, SHELL_EDGE_APPEND, (uint32_t)owner,
                         (uint32_t)old));
      }
    }
    /* A shared pipe is not a direct transfer between same-direction peers. */
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *item = &graph.edges[edge];
      if (!internal_relation(&graph, item))
        continue;
      if (item->type == SHELL_EDGE_SUBST && item->to == (uint32_t)owner &&
          item->target_fd == cases[i].fd)
        ASSERT(item->from == (uint32_t)pipe);
    }
    for (unsigned dimension = 0; dimension < 2; dimension++) {
      uint32_t count = dimension ? graph.edge_count : graph.node_count;
      for (uint32_t capacity = 0; capacity <= count; capacity++) {
        shell_dep_graph_t bounded;
        shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
        if (dimension)
          limits.max_edges = capacity;
        else
          limits.max_nodes = capacity;
        shell_dep_error_t error = shell_dep_graph_parse(
            cases[i].source, strlen(cases[i].source), ".", &limits, &bounded);
        ASSERT(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC ||
               error == SHELL_DEP_EPARSE);
        bool valid = shellsplit_test_depgraph_invariants(
            cases[i].source, strlen(cases[i].source), error, &bounded, &limits);
        if (!valid) {
          fprintf(
              stderr,
              "process pipe capacity: %s dimension=%u capacity=%u status=%d\n",
              cases[i].source, dimension, capacity, error);
          shell_dep_graph_dump(&bounded, stderr);
        }
        ASSERT(valid);
      }
    }
  }
  pass_count++;
}

TEST(descriptor_metadata_scaling) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  static const struct {
    const char *prefix;
    const char *unit;
    const char *suffix;
    shellsplit_test_metadata_kind_t kind;
    size_t maximum;
  } families[] = {
      {"", "cat < <(printf x); ", "", SHELLSPLIT_TEST_WORK_PROCESS_ROUTES, 32},
      {"", "cat < <(printf ignored >/dev/null); ", "",
       SHELLSPLIT_TEST_WORK_PROCESS_ROUTES, 16},
      {"", "cat < <(printf x) < <(printf ignored >/dev/null); ", "",
       SHELLSPLIT_TEST_WORK_PROCESS_ROUTES, 16},
      {"", "time true; ", "", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES, 32},
      {"", "time { true; }; ", "", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES, 32},
      {"", "time exec 2>&1; ", "", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES, 32},
      {"", "true && time true; ", "", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES, 16},
      {"", "true && time exec 2>&1; ", "", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES,
       16},
      {"exec 2>err; echo \"$(", "true; ", ")\"",
       SHELLSPLIT_TEST_WORK_IMPORT_USES, 32},
      {"exec 2>err; echo \"$(echo \"$(", "true; ", ")\")\"",
       SHELLSPLIT_TEST_WORK_IMPORT_USES, 32},
      {"echo \"$({ ", "true; ", "})\"", SHELLSPLIT_TEST_WORK_IMPORT_USES, 32},
      {"", "echo \"$(true)\" | ", "true", SHELLSPLIT_TEST_WORK_IMPORT_USES, 16},
      {"echo \"$(", "time true; ", ")\"", SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES,
       32},
  };
  for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
       family++) {
    size_t previous = 0;
    for (size_t count = 4; count <= families[family].maximum; count *= 2) {
      char source[4096];
      size_t used = strlen(families[family].prefix);
      memcpy(source, families[family].prefix, used);
      for (size_t i = 0; i < count; i++) {
        size_t length = strlen(families[family].unit);
        memcpy(source + used, families[family].unit, length);
        used += length;
      }
      size_t length = strlen(families[family].suffix);
      memcpy(source + used, families[family].suffix, length + 1);
      shellsplit_test_source_scan_reset();
      shell_dep_graph_t graph;
      shell_dep_error_t status = parse(source, &graph);
      size_t work = shellsplit_test_metadata_work(families[family].kind);
      bool valid = status == SHELL_DEP_OK && work != 0 && work <= 80 * count &&
                   (previous == 0 || work <= 3 * previous) &&
                   shell_dep_graph_validate(&graph).valid;
      if (!valid)
        fprintf(stderr,
                "metadata scaling: family=%zu count=%zu status=%d work=%zu "
                "previous=%zu\n",
                family, count, status, work, previous);
      previous = work;
      ASSERT(valid);
    }
  }
#endif
  pass_count++;
}

TEST(nested_capture_publication_scaling) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  static const char *units[] = {"true; ", "exec 3>&1; ", "unset unused; "};
  for (size_t family = 0; family < sizeof(units) / sizeof(units[0]); family++) {
    size_t previous_source = 0, previous_imports = 0, previous_publication = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[4096] = "echo \"$(";
      size_t used = strlen(source);
      for (unsigned i = 0; i < count; i++) {
        memcpy(source + used, "{ ", 2);
        used += 2;
      }
      for (unsigned i = 0; i < count; i++) {
        size_t length = strlen(units[family]);
        memcpy(source + used, units[family], length);
        used += length;
      }
      for (unsigned i = 0; i < count; i++) {
        memcpy(source + used, "}; ", 3);
        used += 3;
      }
      memcpy(source + used, ")\"", 3);
      used += 2;
      shellsplit_test_source_scan_reset();
      shell_dep_graph_t graph;
      shell_dep_error_t status = parse(source, &graph);
      size_t source_work = shellsplit_test_source_scan_work();
      size_t imports =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_IMPORT_USES);
      size_t publication =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
      bool valid =
          status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid &&
          source_work <= 512 * used && imports <= 128 * count &&
          publication <= 32 * count &&
          (!previous_source || source_work <= 3 * previous_source) &&
          (!previous_imports || imports <= 3 * previous_imports) &&
          (!previous_publication || publication <= 3 * previous_publication);
      if (!valid)
        fprintf(stderr,
                "nested scaling: family=%zu count=%u status=%d source=%zu "
                "imports=%zu publication=%zu previous=%zu/%zu/%zu\n",
                family, count, status, source_work, imports, publication,
                previous_source, previous_imports, previous_publication);
      ASSERT(valid);
      previous_source = source_work;
      previous_imports = imports;
      previous_publication = publication;
    }
  }
#endif
  pass_count++;
}

TEST(indexed_named_route_mutations) {
  static const char *mutations[] = {
      "unset 'f2' f0 f3; export 'f4=1'; printf -vf6 '%s' value; ",
      ("probe gate && { unset f2 f0 f3; export 'f4=1'; printf -vf6 '%s' value; "
       "}; "),
      "( unset f2 f0 f3; export 'f4=1'; printf -vf6 '%s' value ); ",
  };
  for (unsigned reverse = 0; reverse < 2; reverse++) {
    for (size_t variant = 0; variant < sizeof(mutations) / sizeof(mutations[0]);
         variant++) {
      char source[4096];
      size_t used = 0;
      for (unsigned i = 0; i < 8; i++) {
        unsigned fd = reverse ? 7 - i : i;
        int written = snprintf(source + used, sizeof(source) - used,
                               "exec {f%u}>base%u && ", fd, fd);
        ASSERT(written > 0 && (size_t)written < sizeof(source) - used);
        used += (size_t)written;
      }
      int written = snprintf(
          source + used, sizeof(source) - used,
          "{ %s exec {f0}>new0 {f2}>new2 {f3}>new3 {f4}>new4 {f6}>new6 && "
          "{ echo \"$(probe child >&$f7)\"; probe parent >&$f7; "
          "probe rebound >&$f2; }; }",
          mutations[variant]);
      ASSERT(written > 0 && (size_t)written < sizeof(source) - used);
      shell_dep_graph_t graph;
      ASSERT(parse(source, &graph) == SHELL_DEP_OK);
      int untouched = find_file_doc(&graph, "base7");
      int rebound = find_file_doc(&graph, "new2");
      int old = find_file_doc(&graph, "base2");
      ASSERT(untouched >= 0 && rebound >= 0 && old >= 0);
      static const char *labels[] = {"child", "parent", "rebound"};
      for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        int owner = find_cmd_tokens(&graph, "probe", labels[i]);
        ASSERT(owner >= 0 &&
               has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)owner,
                            (uint32_t)(i == 2 ? rebound : untouched), 1,
                            SHELL_DEP_FD_NONE));
        ASSERT(!has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)owner,
                             (uint32_t)old, 1, SHELL_DEP_FD_NONE));
      }
      ASSERT(shell_dep_graph_validate(&graph).valid);
    }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_delta = 0;
  for (unsigned count = 3; count <= 12; count *= 2) {
    size_t work[2] = {0};
    for (unsigned with_mutations = 0; with_mutations < 2; with_mutations++) {
      char source[4096] = "exec ";
      size_t used = strlen(source);
      for (unsigned i = 0; i < count; i++) {
        int written =
            snprintf(source + used, sizeof(source) - used, "{f%u}>base ", i);
        ASSERT(written > 0 && (size_t)written < sizeof(source) - used);
        used += (size_t)written;
      }
      memcpy(source + used, "|| exit; ", 9);
      used += 9;
      if (with_mutations)
        for (unsigned i = 0; i < count; i++) {
          memcpy(source + used, "unset unused; ", 14);
          used += 14;
        }
      memcpy(source + used, "true", 5);
      shellsplit_test_source_scan_reset();
      shell_dep_graph_t graph;
      ASSERT(parse(source, &graph) == SHELL_DEP_OK);
      ASSERT(shell_dep_graph_validate(&graph).valid);
      work[with_mutations] =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    }
    ASSERT(work[1] >= work[0]);
    size_t delta = work[1] - work[0];
    /* Each absent static target takes one indexed lookup in each outcome
     * journal. It must not visit every inherited descriptor binding. */
    /* IFS target recognition and the boundary key/emission projections add
     * constant-many indexed lookups, not a scan of inherited bindings. Include
     * the logarithmic comparison depth of both owner and proof-domain maps. */
    unsigned depth = 0;
    for (unsigned width = count; width; width >>= 1)
      depth++;
    size_t budget = 64u * count * (depth + 1);
    if (verbose || delta > budget ||
        (previous_delta && delta > 3 * previous_delta))
      printf("\n    indexed mutations: count=%u delta=%zu budget=%zu", count,
             delta, budget);
    ASSERT(delta <= budget && (!previous_delta || delta <= 3 * previous_delta));
    previous_delta = delta;
  }
#endif
  pass_count++;
}

TEST(conditional_named_binding_invalidation) {
  static const char *const rejected[] = {
      "exec 7>seven && exec {fd}>base && fd=7; "
      "{ exec {fd}>out && true; } >setup; printf payload >&$fd",
      "exec {fd}>base && unset fd; { exec {fd}>out && true; } >setup; "
      "echo \"$(printf payload >&$fd)\"",
      "exec {fd}>base && probe && unset fd; probe after >&$fd",
      "exec {fd}>base && probe || unset fd; probe after >&$fd",
      "exec {fd}>base && probe && { unset fd; }; probe after >&$fd",
      "exec {fd}>base && probe && { { unset fd; }; }; probe after >&$fd",
      "exec {fd}>base && probe && { probe && unset fd; }; probe after >&$fd",
      "exec {fd}>base && probe && fd=1; probe after >&$fd",
      "exec {fd}>base && probe && { fd=1; }; probe after >&$fd",
      "exec {fd}>base && probe && printf -v fd 1; probe after >&$fd",
      "exec {fd}>base && probe && builtin unset 'fd'; probe after >&$fd",
      "exec {fd}>base && probe && unset \"$target\"; probe after >&$fd",
      "exec {fd}<base && probe && { unset fd; }; echo \"$(probe after <&$fd)\"",
      "exec {fd}>base && probe && { unset fd; }; exec 2>&$fd && time true",
      "exec {fd}>base && true && { unset fd; }; probe after >&$fd",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(rejected[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0 &&
           graph.status == SHELL_DEP_STATUS_ERROR);
  }
  /* Where the open fails, the `||` branch unsets the name, which leaves the
   * operand empty. The analysis does not attribute that miss to the failed
   * open, so it conservatively reports no model. */
  shell_dep_graph_t unset_graph;
  ASSERT(parse("exec {fd}>base && true || { unset fd; }; probe after >&$fd",
               &unset_graph) == SHELL_DEP_EUNMODELED);
  static const struct {
    const char *source;
    const char *expected;
  } retained[] = {
      {"exec {fd}>base && false && { unset fd; }; probe after >&$fd", "base"},
      {"exec {fd}>base && probe && unset other; probe after >&$fd", "base"},
      {"exec {fd}>base && probe && { unset other; }; probe after >&$fd",
       "base"},
      {"exec {fd}>base && probe && (unset fd); probe after >&$fd", "base"},
      {"exec {fd}>base && probe && { unset fd; }; exec {fd}>new && probe after "
       ">&$fd",
       "new"},
      {"exec {fd}>base && probe && { unset fd; exec {fd}>new; }; exec "
       "{fd}>final && "
       "probe after >&$fd",
       "final"},
      {"exec {fd}>base && probe && { unset fd; }; exec {fd}>new && echo "
       "\"$(probe after >&$fd)\"",
       "new"},
      {"exec {fd}>base && probe && { unset fd; } && exec {fd}>new && probe "
       "after "
       ">&$fd",
       "new"},
  };
  for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(retained[i].source, &graph) == SHELL_DEP_OK);
    int after = find_cmd_tokens(&graph, "probe", "after");
    int file = find_file_doc(&graph, retained[i].expected);
    ASSERT(after >= 0 && file >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)after,
                        (uint32_t)file, 1, SHELL_DEP_FD_NONE));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(descriptor_import_identity_scaling) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned reverse = 0; reverse < 2; reverse++) {
    size_t previous = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[8192] = "";
      size_t used = 0;
      for (unsigned i = 0; i < count; i++) {
        unsigned fd = 3 + (reverse ? count - i - 1 : i);
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "exec %u>resource%u && ", fd, fd);
      }
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "echo \"$(echo \"$(");
      for (unsigned i = 0; i < count; i++) {
        unsigned fd = 3 + (reverse ? count - i - 1 : i);
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "probe resource%u %u>&%u; ", fd, fd, fd);
      }
      snprintf(source + used, sizeof(source) - used, ")\")\"");
      shellsplit_test_source_scan_reset();
      shell_dep_graph_t graph;
      shell_dep_error_t status = parse(source, &graph);
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_IMPORT_USES);
      if (status != SHELL_DEP_OK || work > 160 * count ||
          (previous && work > 3 * previous))
        fprintf(stderr,
                "import identity scaling: reverse=%u count=%u status=%d "
                "work=%zu previous=%zu\n",
                reverse, count, status, work, previous);
      ASSERT(status == SHELL_DEP_OK && work > 0 && work <= 160 * count &&
             (!previous || work <= 3 * previous) &&
             shell_dep_graph_validate(&graph).valid);
      previous = work;
      for (unsigned i = 0; i < count; i++) {
        char path[32];
        snprintf(path, sizeof(path), "resource%u", i + 3);
        int document = find_file_doc(&graph, path);
        int probe = find_cmd_tokens(&graph, "probe", path);
        ASSERT(document >= 0 && probe >= 0 &&
               has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)probe,
                            (uint32_t)document, i + 3, SHELL_DEP_FD_NONE));
      }
    }
  }
#endif
  pass_count++;
}

TEST(stream_resource_limit_contract) {
  static const char *const sources[] = {
      "echo \"$(exec 3>&1 >out; probe && exec >&3; printf value)\"",
      "{ echo \"$(time true)\"; } |& cat 3<&0",
      "printf source > >(printf '%s' \"$(cat)\")",
      "{ echo \"$(time true)\"; } |& cat <input",
      "echo \"$(exec 3>&1; echo \"$(time exec 2>&3)\")\"",
  };
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(sources[i], &graph) == SHELL_DEP_OK);
    uint32_t full_nodes = graph.node_count, full_edges = graph.edge_count;
    for (unsigned dimension = 0; dimension < 2; dimension++) {
      uint32_t full = dimension == 0 ? full_nodes : full_edges;
      for (uint32_t limit = 0; limit <= full; limit++) {
        shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
        if (dimension == 0)
          limits.max_nodes = limit;
        else
          limits.max_edges = limit;
        shell_dep_error_t status = shell_dep_graph_parse(
            sources[i], strlen(sources[i]), ".", &limits, &graph);
        bool accepted = status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC;
        bool valid = accepted && shell_dep_graph_validate(&graph).valid;
        if (!valid) {
          printf("\n    stream limit: %s, dimension=%u limit=%u status=%d\n",
                 sources[i], dimension, limit, status);
          shell_dep_graph_dump(&graph, stdout);
          shell_dep_graph_validation_t validation =
              shell_dep_graph_validate(&graph);
          for (uint32_t error = 0; error < validation.error_count; error++)
            printf("    validation: %s\n", validation.errors[error].msg);
        }
        ASSERT(valid);
        ASSERT(graph.node_count <= limits.max_nodes &&
               graph.edge_count <= limits.max_edges);
      }
    }
  }
  pass_count++;
}

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
      if (!internal_relation(&graph, current))
        continue;
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

/* --- ERROR HANDLING --- */

TEST(null_input) {
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

  /* cd is a real execution stage and requires the normal route workspace. */
  ASSERT(raw_dep_graph_parse("cd /tmp", strlen("cd /tmp"), ".", NULL, &graph) ==
         SHELL_DEP_EWORKSPACE);
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

/* The lists of an `if` are alternatives. `then` runs on the condition's
 * success and `else` on its failure, so the graph relates each list to the
 * condition, never one list to the other. */
TEST(if_lists_are_alternatives_of_the_condition) {
  shell_dep_graph_t graph;
  ASSERT(parse("if test -f file; then echo yes; else echo no; fi", &graph) ==
         SHELL_DEP_OK);
  ASSERT(graph.status == SHELL_DEP_STATUS_OK &&
         shell_dep_graph_validate(&graph).valid);
  int group = find_group(&graph, SHELL_GROUP_IF, UINT32_MAX);
  int condition = find_cmd_tokens(&graph, "test", "-f");
  int yes = find_cmd_tokens(&graph, "echo", "yes");
  int no = find_cmd_tokens(&graph, "echo", "no");
  ASSERT(group >= 0 && condition >= 0 && yes >= 0 && no >= 0);
  ASSERT(has_edge(&graph, SHELL_EDGE_AND, (uint32_t)condition, (uint32_t)yes));
  ASSERT(has_edge(&graph, SHELL_EDGE_OR, (uint32_t)condition, (uint32_t)no));
  for (shell_dep_edge_type_t type = SHELL_EDGE_SEQ; type <= SHELL_EDGE_OR;
       type++)
    ASSERT(!has_edge(&graph, type, (uint32_t)yes, (uint32_t)no) &&
           !has_edge(&graph, type, (uint32_t)no, (uint32_t)yes));

  /* An `elif` condition runs on the failure of the one before it. */
  ASSERT(parse("if a; then b; elif c; then d; else e; fi", &graph) ==
         SHELL_DEP_OK);
  ASSERT(shell_dep_graph_validate(&graph).valid);
  int a = find_cmd_tokens(&graph, "a", NULL),
      b = find_cmd_tokens(&graph, "b", NULL),
      c = find_cmd_tokens(&graph, "c", NULL),
      d = find_cmd_tokens(&graph, "d", NULL),
      e = find_cmd_tokens(&graph, "e", NULL);
  ASSERT(a >= 0 && b >= 0 && c >= 0 && d >= 0 && e >= 0);
  ASSERT(has_edge(&graph, SHELL_EDGE_AND, (uint32_t)a, (uint32_t)b));
  ASSERT(has_edge(&graph, SHELL_EDGE_OR, (uint32_t)a, (uint32_t)c));
  ASSERT(has_edge(&graph, SHELL_EDGE_AND, (uint32_t)c, (uint32_t)d));
  ASSERT(has_edge(&graph, SHELL_EDGE_OR, (uint32_t)c, (uint32_t)e));
  for (shell_dep_edge_type_t type = SHELL_EDGE_SEQ; type <= SHELL_EDGE_OR;
       type++)
    ASSERT(!has_edge(&graph, type, (uint32_t)b, (uint32_t)c));

  static const char *const accepted[] = {
      "if true; then :; elif false; then :; fi",
      "{ if test -f file; then echo yes; fi; }",
      "echo ok; if true; then :; fi; echo after",
      "if a; then if b; then c; else d; fi; else e; fi",
      "if a | b; then c; fi | d",
      "if a; then b; fi > out",
      "! if a; then b; fi",
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    ASSERT(parse(accepted[i], &graph) == SHELL_DEP_OK);
    ASSERT(graph.status == SHELL_DEP_STATUS_OK &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* The union memo may be too small for a source. The analysis then fails closed
 * as truncation, like an exhausted pool, and never decides differently: a
 * source with a smaller memo gets the answer of the full memo or ETRUNC. In
 * particular it is never admitted where the full memo refuses it. The last
 * two sources read fd 11 after seven opens and a named allocation: keeping
 * the exhausted merges' versions apart would admit them (soundly, and
 * correctly for Bash, given the opens succeed), which the full memo's merged
 * version refuses. */
TEST(union_memo_exhaustion_fails_closed) {
  static const char *const sources[] = {
      "if test -n \"$a\"; then exec 3<f; else exec 4<g; fi; cat <&3",
      "if exec 3<a; then if exec 4<b; then cat <&4; fi; cat <&3; fi",
      "exec 3<a; { exec 4<b; cat <&3; } || { exec 4<c; cat <&4; }",
      "exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null 7<>/dev/null "
      "8<>/dev/null 9<>/dev/null 10<&- 11<&-; read -u11 value {fd}</dev/null",
      "exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null 7<>/dev/null "
      "8<>/dev/null 9<>/dev/null 10<&- 11<&-; : {fd}<<<payload; read -u11 v",
      /* Named descriptors: the merge compares maps of overrides. */
      "if test -n \"$c\"; then exec {a}>f; else exec {b}>g; fi; cat <&$a",
      "if test -n \"$c\"; then exec {a}>f {b}>g; else exec {b}>h; fi; cat <&$b",
      "exec {a}>f; if test -n \"$c\"; then exec {b}>g; fi; exec {c}>h; cat "
      "<&$a",
  };
  static const uint32_t sizes[] = {2, 3, 8, 16, 64, 256, 1024};
  bool refused = false;
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    static shell_dep_graph_t full, small;
    shellsplit_test_set_union_memo_limit(0);
    shell_dep_error_t expected = parse(sources[i], &full);
    for (size_t j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
      shellsplit_test_set_union_memo_limit(sizes[j]);
      shell_dep_error_t got = parse(sources[i], &small);
      shellsplit_test_set_union_memo_limit(0);
      ASSERT(got == expected || got == SHELL_DEP_ETRUNC);
      refused |= got != expected;
      if (got != expected || got != SHELL_DEP_OK)
        continue;
      ASSERT(small.node_count == full.node_count &&
             small.edge_count == full.edge_count);
      for (uint32_t e = 0; e < full.edge_count; e++)
        ASSERT(small.edges[e].from == full.edges[e].from &&
               small.edges[e].to == full.edges[e].to &&
               small.edges[e].type == full.edges[e].type &&
               small.edges[e].flags == full.edges[e].flags &&
               small.edges[e].source_fd == full.edges[e].source_fd &&
               small.edges[e].target_fd == full.edges[e].target_fd);
    }
  }
  /* The sizes include ones no analysis fits in. */
  ASSERT(refused);
  pass_count++;
}
#endif

/* A source with more compounds than the parser keeps ranges for cannot be
 * given a graph: the parser disables the compounds it cut off, and each needs
 * an endpoint. It reports truncation, as it does for too many commands. */
TEST(compounds_past_the_parser_capacity_truncate) {
  static const char *const forms[] = {"{ c%u; echo a; }; ",
                                      "if c%u; then echo a; else echo b; fi; "};
  for (size_t form = 0; form < sizeof(forms) / sizeof(forms[0]); form++) {
    char source[8192];
    size_t length = 0;
    for (unsigned i = 0; i < 100; i++)
      length += (size_t)snprintf(source + length, sizeof(source) - length,
                                 forms[form], i);
    shell_dep_graph_t graph;
    ASSERT(parse(source, &graph) == SHELL_DEP_ETRUNC);
    ASSERT(graph.status & SHELL_DEP_STATUS_TRUNCATED);
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
      {"cmd1 ; cmd2", {1, 8, 8, 0, NULL, 0}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"echo hi > out.txt", {8, 0, 8, 0, NULL, 0}, SHELL_DEP_ETRUNC, 1, 0, 2},
      {"echo hello", {8, 8, 1, 0, NULL, 0}, SHELL_DEP_ETRUNC, 1, 0, 1},
      {"cd /tmp && ls", {8, 8, 8, 4, NULL, 0}, SHELL_DEP_ETRUNC, 3, 3, 2},
      {"echo $(cat /etc/hosts)",
       {2, 8, 8, 0, NULL, 0},
       SHELL_DEP_ETRUNC,
       0,
       0,
       0},
      {"c 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 "
       "24 25 26 27 28 29 30 31 32 33",
       {64, 64, 32, 0, NULL, 0},
       SHELL_DEP_ETRUNC,
       1,
       0,
       32},
      {"echo hello",
       {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, NULL, 0},
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
    if (count_internal_nodes(&g) != cases[i].node_count ||
        count_internal_edges(&g) != cases[i].edge_count)
      fprintf(stderr, "limit case %zu nodes=%u edges=%u first-tokens=%u\n", i,
              g.node_count, g.edge_count, g.nodes[0].cmd.token_count);
    ASSERT(count_internal_nodes(&g) == cases[i].node_count);
    ASSERT(count_internal_edges(&g) == cases[i].edge_count);
    if (error == SHELL_DEP_ETRUNC)
      ASSERT(g.status & SHELL_DEP_STATUS_TRUNCATED);
    if (error == SHELL_DEP_EPARSE)
      ASSERT(g.status == SHELL_DEP_STATUS_ERROR);
    if (cases[i].node_count > 0 && g.nodes[0].type == SHELL_NODE_CMD)
      ASSERT(g.nodes[0].cmd.token_count == cases[i].command_tokens);
    ASSERT(shell_dep_graph_validate(&g).valid);
  }

  shell_dep_limits_t cd_limits = SHELL_DEP_LIMITS_DEFAULT;
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
  ASSERT(count_internal_edges(&g) == 1);
  g.edges[0].source_fd = 0;
  g.edges[0].target_fd = SHELL_DEP_FD_NONE;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("echo $(id)", &g) == SHELL_DEP_OK);
  ASSERT(count_internal_edges(&g) == 1);
  g.edges[0].flags = SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "type mismatch") != NULL);

  ASSERT(parse("echo $(id)", &g) == SHELL_DEP_OK);
  ASSERT(count_internal_edges(&g) == 1);
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
  ASSERT(count_internal_edges(&g) == 1);
  g.edges[0].source_fd = SHELL_DEP_FD_MAX + 1u;
  validation = shell_dep_graph_validate(&g);
  ASSERT(!validation.valid);
  ASSERT(validation.error_count == 1);
  ASSERT(strstr(validation.errors[0].msg, "descriptor outside") != NULL);

  ASSERT(parse("cat < /tmp/input", &g) == SHELL_DEP_OK);
  ASSERT(count_internal_edges(&g) == 1);
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

/* ARG associates a command with a possible pathname and therefore only FILE
 * documents are valid endpoints. Preserve its intentionally undirected
 * orientation without permitting other document kinds to acquire path
 * semantics in a caller-supplied graph. */
TEST(validation_rejects_non_file_argument_documents) {
  static const struct {
    const char *source;
    shell_dep_doc_kind_t kind;
  } invalid[] = {
      {"NAME=value cmd", SHELL_DOC_ENVVAR},
      {"cat <<<payload", SHELL_DOC_HERESTRING},
      {"cat <<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC},
  };

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(invalid[i].source, &graph) == SHELL_DEP_OK);
    int command = find_first_cmd(&graph);
    int document = find_doc(&graph, invalid[i].kind);
    ASSERT(command >= 0 && document >= 0 &&
           graph.edge_count < SHELL_DEP_MAX_EDGES &&
           shell_dep_graph_validate(&graph).valid);
    for (unsigned reversed = 0; reversed < 2; reversed++) {
      shell_dep_graph_t malformed = graph;
      malformed.edges[malformed.edge_count++] = (shell_dep_edge_t){
          .type = SHELL_EDGE_ARG,
          .dir = SHELL_DIR_UNDIR,
          .from = reversed ? (uint32_t)document : (uint32_t)command,
          .to = reversed ? (uint32_t)command : (uint32_t)document,
          .source_fd = SHELL_DEP_FD_NONE,
          .target_fd = SHELL_DEP_FD_NONE,
      };
      shell_dep_graph_validation_t validation =
          shell_dep_graph_validate(&malformed);
      ASSERT(!validation.valid && validation.error_count >= 1);
    }
  }

  shell_dep_graph_t graph = {0};
  ASSERT(parse("cmd /tmp/argument", &graph) == SHELL_DEP_OK);
  uint32_t argument = UINT32_MAX;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_ARG) {
      argument = edge;
      break;
    }
  ASSERT(argument != UINT32_MAX && shell_dep_graph_validate(&graph).valid);
  uint32_t from = graph.edges[argument].from;
  graph.edges[argument].from = graph.edges[argument].to;
  graph.edges[argument].to = from;
  ASSERT(shell_dep_graph_validate(&graph).valid);
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

TEST(command_token_capacity) {
  static const unsigned counts[] = {32, 33, 47, 48, 49};
  shell_dep_graph_t *graph = malloc(sizeof(*graph));
  shell_source_result_t *draft = malloc(sizeof(*draft));
  ASSERT(graph && draft);
  for (unsigned c = 0; c < sizeof(counts) / sizeof(*counts); ++c) {
    char source[256] = "cmd";
    size_t length = 3;
    for (unsigned i = 1; i < counts[c]; ++i) {
      memcpy(source + length, " a", 2);
      length += 2;
    }
    source[length] = 0;
    bool fits = counts[c] <= SHELL_DEP_MAX_TOKENS;
    ASSERT(parse(source, graph) == (fits ? SHELL_DEP_OK : SHELL_DEP_ETRUNC));
    ASSERT(shell_dep_graph_validate(graph).valid);
    ASSERT(graph->nodes[0].cmd.token_count ==
           (fits ? counts[c] : SHELL_DEP_MAX_TOKENS));
    ASSERT(shell_parse_draft(source, length, NULL, draft) ==
           (fits ? SHELL_SOURCE_COMPLETE : SHELL_SOURCE_TRUNCATED));
    if (fits)
      ASSERT(draft->headers[0].word_count == counts[c]);
    shell_dep_limits_t smaller = SHELL_DEP_LIMITS_DEFAULT;
    smaller.max_tokens_per_cmd = 32;
    ASSERT(shell_dep_graph_parse(source, length, ".", &smaller, graph) ==
           (counts[c] == 32 ? SHELL_DEP_OK : SHELL_DEP_ETRUNC));
  }
  free(draft);
  free(graph);
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

/* Validation accepts caller-populated fixed graph storage specifically so it
 * can reject corruption safely. Endpoint topology must never dereference an
 * edge until both endpoints have passed the bounds boundary, and the control
 * topology consumed by Shellgate must remain acyclic. */
TEST(validation_rejects_oob_topology_and_control_cycles) {
  shell_dep_graph_t graph = {0};
  ASSERT(parse("printf value > >(true </dev/null)", &graph) == SHELL_DEP_OK);
  uint32_t process_endpoint = UINT32_MAX;
  uint32_t incoming = UINT32_MAX;
  for (uint32_t node = 0; node < graph.node_count; node++)
    if (graph.nodes[node].type == SHELL_NODE_ENDPOINT &&
        graph.nodes[node].endpoint.reserved == 2)
      process_endpoint = node;
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].to == process_endpoint &&
        (graph.edges[edge].type == SHELL_EDGE_WRITE &&
         internal_relation(&graph, &graph.edges[edge])))
      incoming = edge;
  ASSERT(process_endpoint != UINT32_MAX && incoming != UINT32_MAX);
  graph.edges[incoming].from = graph.node_count;
  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
  bool saw_oob = false;
  for (uint32_t error = 0; error < validation.error_count; error++)
    saw_oob = saw_oob || strstr(validation.errors[error].msg, "OOB") != NULL;
  ASSERT(!validation.valid && saw_oob);

  ASSERT(parse("true; false", &graph) == SHELL_DEP_OK);
  int first = find_nth_cmd(&graph, 0);
  int second = find_nth_cmd(&graph, 1);
  ASSERT(first >= 0 && second >= 0 && graph.edge_count < SHELL_DEP_MAX_EDGES);
  graph.edges[graph.edge_count++] = (shell_dep_edge_t){
      .type = SHELL_EDGE_SEQ,
      .dir = SHELL_DIR_FORWARD,
      .from = (uint32_t)second,
      .to = (uint32_t)first,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
  validation = shell_dep_graph_validate(&graph);
  bool saw_cycle = false;
  for (uint32_t error = 0; error < validation.error_count; error++)
    saw_cycle =
        saw_cycle || strstr(validation.errors[error].msg, "cycle") != NULL;
  ASSERT(!validation.valid && saw_cycle);
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
  ASSERT(parse("exec {sink}> >(cat) && printf bytes >&\"$sink\"", &g) ==
         SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec {source}< <(printf bytes >/tmp/dump-source) && "
               "cat <&\"$source\"",
               &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec {f\\\nd}> out && printf bytes >&$f\\\nd", &g) ==
         SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("time { printf x;\n} 2>err | cat", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("probe && exec 2>maybe; time -p true", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec 2>&- && time true", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);
  ASSERT(parse("exec 2>old && exec 2<input && time true", &g) == SHELL_DEP_OK);
  shell_dep_graph_dump(&g, output);

  static const char escaped_token[] = "\\\"\n\r\x01";
  static const char diagnostic_group[] = "{ diagnostic; }";
  g = (shell_dep_graph_t){0};
  memcpy(g.cwd_buf.data, ".", 2);
  g.cwd_buf.len = 2;
  g.node_count = 4;
  g.nodes[0] = (shell_dep_node_t){
      .type = SHELL_NODE_CMD,
      .cmd = {.cwd_offset = 0,
              .token_count = 1,
              .tokens = {escaped_token},
              .token_lens = {sizeof(escaped_token) - 1},
              .pipeline_negation_count = 1,
              .pipeline_negated = true,
              .pipeline_time_mode = SHELL_PIPE_TIME_POSIX},
  };
  g.nodes[1] = (shell_dep_node_t){
      .type = SHELL_NODE_GROUP,
      .group = {.start = diagnostic_group,
                .length = sizeof(diagnostic_group) - 1,
                .parent = UINT32_MAX,
                .kind = SHELL_GROUP_BRACE,
                .pipeline_negation_count = 2,
                .pipeline_time_mode = SHELL_PIPE_TIME_DEFAULT},
  };
  g.nodes[2] = (shell_dep_node_t){
      .type = SHELL_NODE_ENDPOINT,
      .endpoint = {.reserved = 1},
  };
  g.nodes[3] = (shell_dep_node_t){
      .type = SHELL_NODE_TIME,
      .time = {.start = diagnostic_group,
               .length = sizeof(diagnostic_group) - 1,
               .mode = SHELL_PIPE_TIME_DEFAULT,
               .report_fd = 2,
               .report_route = (shell_dep_time_report_route_t)99},
  };
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
  ASSERT(strstr(text, "DOC HEREDOC delim=\"EOF\" content=\"hello\\n\"") !=
         NULL);
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
  ASSERT(strstr(text, "process-substitution-pipe") != NULL);
  ASSERT(strstr(text, "negation-count=2") != NULL);
  ASSERT(strstr(text, " negated") != NULL);
  ASSERT(strstr(text, "TIME mode=default report-fd=2 route=external "
                      "target-fd=2 span=\"{ printf "
                      "x;\\n} 2>err | cat\"") != NULL);
  ASSERT(strstr(text, "TIME mode=posix report-fd=2 route=multiple "
                      "route-flags=0x3 external-fds=2 span=\"true\"") != NULL);
  ASSERT(strstr(text,
                "TIME mode=default report-fd=2 route=closed span=\"true\"") !=
         NULL);
  ASSERT(strstr(text, "TIME mode=default report-fd=2 route=unavailable "
                      "span=\"true\"") != NULL);
  ASSERT(strstr(text, "GROUP span=\"{ printf x;\\n}\"") != NULL);
  ASSERT(strstr(text, "tokens=[\"\\\\\\\"\\n\\r\\x01\"]") != NULL);
  ASSERT(strstr(text, "time-node=missing") != NULL);
  ASSERT(strstr(text, " terminal-pipe") != NULL);
  ASSERT(strstr(text, "route=invalid") != NULL);
  ASSERT(fclose(output) == 0);
  pass_count++;
}

TEST(name_helpers) {
  static const char *edge_names[] = {"READ",  "WRITE",    "APPEND",
                                     "PIPE",  "ARG",      "ENV",
                                     "SUBST", "SEQ",      "AND",
                                     "OR",    "CWD",      "BACKGROUND",
                                     "GROUP", "FD_OPEN",  "FD_CLOSE",
                                     "TIME",  "FILE_TEST"},
                    *node_names[] = {"CMD", "DOC", "GROUP", "ENDPOINT", "TIME"},
                    *doc_names[] = {"FILE", "HEREDOC", "HERESTRING", "ENVVAR"},
                    *error_names[] = {
                        "OK", "Invalid input", "Truncated (limits exceeded)",
                        "Parse error", "Dependency workspace unavailable"};
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

TEST(named_fd_allocation_cleanup) {
  const shellsplit_test_named_cleanup_case_t *cases =
      shellsplit_test_named_cleanup;
  for (size_t i = 0; i < sizeof(shellsplit_test_named_cleanup) /
                             sizeof(shellsplit_test_named_cleanup[0]);
       i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(cases[i].source, &graph);
    if (error != SHELL_DEP_OK)
      printf("    allocation source: %s (error %d)\n", cases[i].source, error);
    ASSERT(error == SHELL_DEP_OK);
    int writer = cases[i].timer
                     ? find_time(&graph)
                     : find_cmd_tokens(&graph, cases[i].read ? "cat" : "printf",
                                       cases[i].argument);
    int target = find_file_doc(&graph, cases[i].file);
    int alternative = find_file_doc(&graph, cases[i].alternative_file);
    ASSERT(writer >= 0 && target >= 0 &&
           (!cases[i].alternative_file || alternative >= 0));
    unsigned writes = 0;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      if ((cases[i].read ? graph.edges[edge].to : graph.edges[edge].from) ==
              (uint32_t)writer &&
          graph.edges[edge].type ==
              (cases[i].read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
          graph.nodes[cases[i].read ? graph.edges[edge].from
                                    : graph.edges[edge].to]
                  .type == SHELL_NODE_DOC) {
        uint32_t endpoint =
            cases[i].read ? graph.edges[edge].from : graph.edges[edge].to;
        if (endpoint != (uint32_t)target && endpoint != (uint32_t)alternative)
          printf("    allocation source: %s (unexpected target %u, wanted "
                 "%d/%d: %.*s)\n",
                 cases[i].source, endpoint, target, alternative,
                 (int)graph.nodes[endpoint].doc.path_len,
                 graph.nodes[endpoint].doc.path);
        ASSERT(endpoint == (uint32_t)target ||
               endpoint == (uint32_t)alternative);
        ASSERT((cases[i].read
                    ? graph.edges[edge].target_fd
                    : graph.edges[edge].source_fd) == (cases[i].timer  ? 2u
                                                       : cases[i].read ? 0u
                                                                       : 1u));
        writes++;
      }
    if (writes != 1u + (cases[i].alternative_file != NULL))
      printf("    allocation count case %zu (%s): %u\n", i,
             cases[i].argument ? cases[i].argument : "timer", writes);
    ASSERT(writes == 1u + (cases[i].alternative_file != NULL) &&
           shell_dep_graph_validate(&graph).valid);
  }
  /* Descriptor setup and close transitions are not byte use. Reusing the
   * closed numeric identity for a later named allocation must not invent an
   * owner READ/WRITE edge through that auxiliary descriptor. */
  shell_dep_graph_t setup;
  ASSERT(parse("exec 10>&-; true 10>&- {a}>one", &setup) == SHELL_DEP_OK);
  int setup_owner = find_cmd_tokens(&setup, "true", NULL);
  int setup_file = find_file_doc(&setup, "one");
  ASSERT(setup_owner >= 0 && setup_file >= 0 &&
         has_edge(&setup, SHELL_EDGE_FD_OPEN, (uint32_t)setup_owner,
                  (uint32_t)setup_file) &&
         !has_edge(&setup, SHELL_EDGE_WRITE, (uint32_t)setup_owner,
                   (uint32_t)setup_file));

  ASSERT(parse("exec 10<base || exit; cat 10<&- {a}<one", &setup) ==
         SHELL_DEP_OK);
  setup_owner = find_cmd_tokens(&setup, "cat", NULL);
  setup_file = find_file_doc(&setup, "one");
  ASSERT(setup_owner >= 0 && setup_file >= 0 &&
         has_edge(&setup, SHELL_EDGE_FD_OPEN, (uint32_t)setup_file,
                  (uint32_t)setup_owner) &&
         !has_edge(&setup, SHELL_EDGE_READ, (uint32_t)setup_file,
                   (uint32_t)setup_owner));

  ASSERT(parse("exec 10>&-; true 10>&- {a}> >(cat)", &setup) == SHELL_DEP_OK);
  setup_owner = find_cmd_tokens(&setup, "true", NULL);
  int consumer = find_cmd_tokens(&setup, "cat", NULL);
  int endpoint = find_endpoint(&setup);
  ASSERT(setup_owner >= 0 && consumer >= 0 && endpoint >= 0 &&
         !has_edge(&setup, SHELL_EDGE_WRITE, (uint32_t)setup_owner,
                   (uint32_t)endpoint) &&
         has_edge(&setup, SHELL_EDGE_SUBST, (uint32_t)endpoint,
                  (uint32_t)consumer) &&
         shell_dep_graph_validate(&setup).valid);
  const char *streams[] = {
      "{ exec 10>&-; true {a}>&1 && printf payload >&$a; } | cat",
      "exec 10>&-; true {a}> >(cat) && printf payload >&$a",
      "exec 10>&-; true {a}< <(printf input) && cat <&$a",
  };
  for (size_t i = 0; i < sizeof(streams) / sizeof(streams[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(streams[i], &graph) == SHELL_DEP_OK);
    bool used = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (!internal_relation(&graph, edge))
        continue;
      if (edge->type != SHELL_EDGE_PIPE && edge->type != SHELL_EDGE_WRITE &&
          edge->type != SHELL_EDGE_SUBST)
        continue;
      /* Only standard-stream duplication uses the allocated route; its
       * inferred fd 10 is never an additional byte-flow source or target. */
      ASSERT(edge->source_fd <= 2 || edge->source_fd == SHELL_DEP_FD_NONE);
      ASSERT(edge->target_fd <= 2 || edge->target_fd == SHELL_DEP_FD_NONE);
      used = true;
    }
    ASSERT(used && shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(scope_termination_descriptor_continuations) {
  for (size_t i = 0; i < sizeof(shellsplit_test_descriptor_outcomes) /
                             sizeof(shellsplit_test_descriptor_outcomes[0]);
       i++) {
    const char *source = shellsplit_test_descriptor_outcomes[i].source;
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = parse(source, &graph);
    if (error != SHELL_DEP_OK)
      printf("    descriptor outcome source: %s (error %d)\n", source, error);
    ASSERT(error == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    ASSERT(writer >= 0);
    bool base = false, out = false;
    unsigned writes = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (!internal_relation(&graph, edge))
        continue;
      if (edge->from != (uint32_t)writer || edge->type != SHELL_EDGE_WRITE ||
          edge->source_fd != 1 || graph.nodes[edge->to].type == SHELL_NODE_FD)
        continue;
      writes++;
      base |= (int)edge->to == find_file_doc(&graph, "base");
      out |= (int)edge->to == find_file_doc(&graph, "out");
    }
    if (base != shellsplit_test_descriptor_outcomes[i].base ||
        out != shellsplit_test_descriptor_outcomes[i].out)
      printf("    descriptor outcome source: %s (base %d out %d)\n", source,
             base, out);
    ASSERT(base == shellsplit_test_descriptor_outcomes[i].base &&
           out == shellsplit_test_descriptor_outcomes[i].out &&
           writes == (unsigned)base + (unsigned)out &&
           shell_dep_graph_validate(&graph).valid);
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_scope_outcomes) /
                             sizeof(shellsplit_test_scope_outcomes[0]);
       i++) {
    const char *source = shellsplit_test_scope_outcomes[i].source;
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = parse(source, &graph);
    if (error != SHELL_DEP_OK)
      printf("    scope outcome source: %s (error %d)\n", source, error);
    ASSERT(error == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int file = find_file_doc(&graph, "out");
    ASSERT(writer >= 0 && file >= 0);
    bool writes = has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                               (uint32_t)file, 1, SHELL_DEP_FD_NONE);
    if (writes != shellsplit_test_scope_outcomes[i].writes_to_out)
      printf("    outcome source: %s (writes %d)\n", source, writes);
    ASSERT(writes == shellsplit_test_scope_outcomes[i].writes_to_out &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(redirect_setup_outcome_substitutions) {
  static const struct {
    const char *prefix;
    bool executes;
  } cases[] = {
      {"false >setup &&", false},
      {"{ false; } >setup &&", false},
      {"{ exit 0; } >setup &&", false},
      {"! { false; } >setup ||", true},
      {"{ { false; }; } >setup &&", false},
      {"(exit 0) >setup ||", true},
      {"{ true; } >setup ||", true},
      {"! { exit 0; } >setup &&", false},
      {"! { true; } >setup &&", false},
      {"! (exit 0) >setup &&", false},
      /* A statically failing setup returns before a compound's `!` applies,
       * but a simple command's returning failure is negated. */
      {"! true >\"\" ||", false},
      {"! false >\"\" &&", true},
      {"! { :; } >\"\" ||", true},
      {"! ((1)) >\"\" ||", true},
      {"! ((0)) >\"\" &&", false},
      {"! [[ a ]] >\"\" ||", true},
      {"! [[ -z a ]] >\"\" &&", false},
      /* A pipeline stage runs in a child, so its failed setup is that stage's
       * exit status, which is the pipeline status for the last stage. The
       * child's status is inverted by `!` for every command kind. */
      {"true | : >\"\" ||", true},
      {"true | : >\"\" &&", false},
      {"true | : <\"\" ||", true},
      {"true | : 2>&bogus ||", true},
      {"true | true >\"\" ||", true},
      {"true | ((1)) >\"\" ||", true},
      {"true | { :; } >\"\" ||", true},
      {"! true | : >\"\" &&", true},
      {"! true | : >\"\" ||", false},
      {"! true | ((0)) >\"\" &&", true},
      {"! true | [[ a ]] >\"\" ||", false},
      {"true | : >\"\" | true ||", false},
      {": >\"\" | cat >\"\" ||", true},
      /* The same holds for a group stage, but a group in the current shell
       * returns its setup failure before its own `!` applies. */
      {"true | (:) >\"\" ||", true},
      {"true | { :; } >\"\" &&", false},
      {"! true | (:) >\"\" &&", true},
      {"! true | (:) >\"\" ||", false},
      {"! true | { :; } >\"\" &&", true},
      {"(:) >\"\" | true ||", false},
      {"! (:) >\"\" | true &&", false},
      {"! (:) >\"\" ||", true},
      {"! (:) >\"\" &&", false},
  };
  static const struct {
    const char *certain, *possible;
  } failing[] = {
      {">\"\"", ">/missing/x"},
      {"<\"\"", "</missing/x"},
      {"2>&bogus", "2>/missing/x"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    /* A certainly failing setup is a shell-level error which no dependency
     * graph models. Its status flow is checked on an open that may fail
     * instead: the successor runs when the failure path (`executes`) or the
     * success path, the same command without that setup, reaches it. */
    const char *body = " echo \"$(printf payload >out; printf marker)\"";
    char certain[256], possible[256] = "", succeeding[256] = "";
    snprintf(certain, sizeof(certain), "%s%s", cases[i].prefix, body);
    bool found = false;
    for (const char *at = cases[i].prefix; *at;) {
      size_t kind = 0;
      while (kind < sizeof(failing) / sizeof(failing[0]) &&
             strncmp(at, failing[kind].certain, strlen(failing[kind].certain)))
        kind++;
      if (kind == sizeof(failing) / sizeof(failing[0])) {
        strncat(possible, at, 1);
        strncat(succeeding, at++, 1);
        continue;
      }
      found = true;
      strcat(possible, failing[kind].possible);
      at += strlen(failing[kind].certain);
    }
    strcat(possible, body);
    strcat(succeeding, body);
    bool success_executes = false;
    if (found) {
      shell_dep_graph_t graph = {0};
      ASSERT(parse(certain, &graph) == SHELL_DEP_EUNMODELED);
      ASSERT(parse(succeeding, &graph) == SHELL_DEP_OK);
      int writer = find_cmd_tokens(&graph, "printf", "payload");
      int file = find_file_doc(&graph, "out");
      ASSERT(writer >= 0 && file >= 0);
      success_executes =
          has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                       (uint32_t)file, 1, SHELL_DEP_FD_NONE);
    }
    bool executes = cases[i].executes || success_executes;
    char source[256];
    int length = snprintf(source, sizeof(source), "%s", possible);
    ASSERT(length > 0 && (size_t)length < sizeof(source));
    shell_dep_graph_t graph = {0};
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int writer = find_cmd_tokens(&graph, "printf", "payload");
    int file = find_file_doc(&graph, "out");
    ASSERT(writer >= 0 && file >= 0 &&
           find_cmd_tokens(&graph, "printf", "marker") >= 0);
    if (has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer, (uint32_t)file,
                     1, SHELL_DEP_FD_NONE) != executes)
      printf("    setup outcome: %s\n", source);
    ASSERT(has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                        (uint32_t)file, 1, SHELL_DEP_FD_NONE) == executes);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_SUBST) == (executes ? 1u : 0u));
    ASSERT(shell_dep_graph_validate(&graph).valid);
    shell_parse_result_t fast = {0};
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    ASSERT(shell_parse_fast(source, (size_t)length, &strict, &fast) ==
           SHELL_OK);
    shell_dep_graph_t supplied = {0};
    ASSERT(shell_dep_graph_parse_with_fast(source, (size_t)length, ".", NULL,
                                           &fast, &supplied) == SHELL_DEP_OK);
    ASSERT(supplied.node_count == graph.node_count &&
           supplied.edge_count == graph.edge_count &&
           shellsplit_test_graph_equal(&supplied, &graph));
  }
  pass_count++;
}

TEST(reachability_cwd_transitions) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  for (size_t i = 0; i < sizeof(shellsplit_test_cwd_reachability) /
                             sizeof(shellsplit_test_cwd_reachability[0]);
       i++) {
    const char *source = shellsplit_test_cwd_reachability[i].source;
    const char *expected = shellsplit_test_cwd_reachability[i].identity;
    shell_dep_graph_t graph = {0};
    ASSERT(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                 &graph) == SHELL_DEP_OK);
    int file = find_file_doc(&graph, shellsplit_test_cwd_reachability[i].file);
    ASSERT(file >= 0);
    char identity[512];
    shell_dep_file_identity_t file_identity = {.length = 0, .absolute = false};

    bool known = shell_dep_doc_file_identity_write(
        &graph, &graph.nodes[file].doc, identity, sizeof(identity),
        &file_identity);
    if (known != (expected != NULL) ||
        (known && strcmp(identity, expected) != 0))
      printf("    CWD case %zu: %s (identity %s)\n", i, source,
             known ? identity : "unknown");
    ASSERT(known == (expected != NULL));
    if (known)
      ASSERT(file_identity.absolute &&
             file_identity.length == strlen(expected) &&
             strcmp(identity, expected) == 0);
    ASSERT(shell_dep_graph_validate(&graph).valid);
    shell_parse_result_t fast = {0};
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    ASSERT(shell_parse_fast(source, strlen(source), &strict, &fast) ==
           SHELL_OK);
    shell_dep_graph_t supplied = {0};
    ASSERT(shell_dep_graph_parse_with_fast(source, strlen(source), "/workspace",
                                           &limits, &fast,
                                           &supplied) == SHELL_DEP_OK);
    ASSERT(supplied.node_count == graph.node_count &&
           supplied.edge_count == graph.edge_count &&
           supplied.cwd_buf.len == graph.cwd_buf.len &&
           memcmp(supplied.cwd_buf.data, graph.cwd_buf.data,
                  graph.cwd_buf.len) == 0 &&
           shellsplit_test_graph_equal(&supplied, &graph));
  }
  limits.cwd_buf_size = sizeof("/workspace");
  static const char unreachable[] =
      "UID=0; cd /a/long/unreachable/destination\nprintf payload >out";
  shell_dep_graph_t graph = {0};
  ASSERT(shell_dep_graph_parse(unreachable, sizeof(unreachable) - 1,
                               "/workspace", &limits, &graph) == SHELL_DEP_OK);
  ASSERT(graph.cwd_buf.len == sizeof("/workspace") &&
         shell_dep_graph_validate(&graph).valid);
  static const char recovery[] = "cd \"$dir\"; cd / && printf payload >out";
  ASSERT(shell_dep_graph_parse(recovery, sizeof(recovery) - 1, "/workspace",
                               &limits, &graph) == SHELL_DEP_ETRUNC);
  ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0);
  limits.cwd_buf_size += sizeof("/");
  ASSERT(shell_dep_graph_parse(recovery, sizeof(recovery) - 1, "/workspace",
                               &limits, &graph) == SHELL_DEP_OK);
  int file = find_file_doc(&graph, "out");
  ASSERT(file >= 0);
  char identity[32];
  shell_dep_file_identity_t file_identity = {0};

  ASSERT(shell_dep_doc_file_identity_write(&graph, &graph.nodes[file].doc,
                                           identity, sizeof(identity),
                                           &file_identity));
  ASSERT(file_identity.absolute && strcmp(identity, "/out") == 0);
  pass_count++;
}

TEST(skipped_duplication_operand_syntax) {
  for (size_t i = 0; i < sizeof(shellsplit_test_skipped_dup_operands) /
                             sizeof(shellsplit_test_skipped_dup_operands[0]);
       i++) {
    const char *source = shellsplit_test_skipped_dup_operands[i].source;
    shell_dep_graph_t graph = {0};
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    ASSERT(count_type(&graph, SHELL_NODE_CMD) ==
           shellsplit_test_skipped_dup_operands[i].commands);
    ASSERT(find_cmd_tokens(&graph, "printf", "payload") >= 0);
    ASSERT(count_type(&graph, SHELL_NODE_ENDPOINT) == 0);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_READ) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_APPEND) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_FD_OPEN) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_FD_CLOSE) == 0);
    ASSERT(shell_dep_graph_validate(&graph).valid);
    shell_parse_result_t fast = {0};
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    ASSERT(shell_parse_fast(source, strlen(source), &strict, &fast) ==
           SHELL_OK);
    shell_dep_graph_t supplied = {0};
    ASSERT(shell_dep_graph_parse_with_fast(source, strlen(source), ".", NULL,
                                           &fast, &supplied) == SHELL_DEP_OK);
    ASSERT(supplied.node_count == graph.node_count &&
           supplied.edge_count == graph.edge_count &&
           shellsplit_test_graph_equal(&supplied, &graph));
  }
  static const char *const invalid[] = {
      "false && : >&$(echo \"unfinished)",
      "false && { :; } 2>&$(while true; do echo bad; done)",
      ": >&$(printf 1)",
      "{ :; } 2>&$(printf 1)",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(invalid[i], &graph) == SHELL_DEP_EPARSE);
    ASSERT(graph.node_count == 0 && graph.edge_count == 0);
  }
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.max_nodes = 2;
  shell_dep_graph_t graph = {0};
  static const char capacity[] = "false && : >&$(printf payload >out)";
  ASSERT(shell_dep_graph_parse(capacity, sizeof(capacity) - 1, ".", &limits,
                               &graph) == SHELL_DEP_ETRUNC);
  ASSERT((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0);
  pass_count++;
}

TEST(bash_pipeline_time_external_count_validation) {
  static const char source[] = "time true";
  shell_dep_graph_t graph = {0};
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  ASSERT(parse(source, &graph) == SHELL_DEP_OK);
  int timer = find_time(&graph);
  ASSERT(timer >= 0);
  graph.nodes[timer].time.report_route = SHELL_TIME_REPORT_MULTIPLE;
  graph.nodes[timer].time.report_target_fd = SHELL_DEP_FD_NONE;
  graph.nodes[timer].time.report_external_fd_count =
      SHELL_DEP_TIME_MAX_EXTERNAL_FDS;
  for (uint32_t fd = 0; fd < SHELL_DEP_TIME_MAX_EXTERNAL_FDS; fd++)
    graph.nodes[timer].time.report_external_fds[fd] = fd;
  /* External summaries are derived conveniences, so a valid fixture retains
   * a matching WRITE-to-FD relation for every declared alternative. */
  for (uint32_t fd = 0; fd < SHELL_DEP_TIME_MAX_EXTERNAL_FDS; fd++) {
    uint32_t endpoint = UINT32_MAX;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_FD &&
          graph.nodes[node].fd.number == fd)
        endpoint = node;
    if (endpoint == UINT32_MAX) {
      endpoint = graph.node_count++;
      graph.nodes[endpoint] =
          (shell_dep_node_t){.type = SHELL_NODE_FD, .fd = {.number = fd}};
    }
    if (fd != 2)
      graph.edges[graph.edge_count++] =
          (shell_dep_edge_t){.from = (uint32_t)timer,
                             .to = endpoint,
                             .type = SHELL_EDGE_WRITE,
                             .dir = SHELL_DIR_FORWARD,
                             .source_fd = 2,
                             .target_fd = SHELL_DEP_FD_NONE};
  }
  ASSERT(shell_dep_graph_validate(&graph).valid);
  ASSERT(shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                             SHELL_DEP_OK, &graph, &limits));
  static const uint32_t bad_counts[] = {SHELL_DEP_TIME_MAX_EXTERNAL_FDS + 1,
                                        UINT32_MAX};
  for (size_t i = 0; i < sizeof(bad_counts) / sizeof(bad_counts[0]); i++) {
    graph.nodes[timer].time.report_external_fd_count = bad_counts[i];
    ASSERT(!shell_dep_graph_validate(&graph).valid);
    ASSERT(!shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                                SHELL_DEP_OK, &graph, &limits));
  }
  graph.nodes[timer].time.report_external_fd_count =
      SHELL_DEP_TIME_MAX_EXTERNAL_FDS;
  graph.nodes[timer]
      .time.report_external_fds[SHELL_DEP_TIME_MAX_EXTERNAL_FDS - 1] =
      SHELL_DEP_FD_MAX + 1;
  ASSERT(!shell_dep_graph_validate(&graph).valid);
  graph.nodes[timer]
      .time.report_external_fds[SHELL_DEP_TIME_MAX_EXTERNAL_FDS - 1] = 0;
  ASSERT(!shell_dep_graph_validate(&graph).valid);
  pass_count++;
}

TEST(bash_pipeline_time_document_stages) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  static const struct {
    const char *source;
    const char *span;
    unsigned commands;
    unsigned groups;
  } cases[] = {
      {"time cat <<<body | cat", "cat <<<body | cat", 2, 0},
      {"time cat <<<body argument | cat", "cat <<<body argument | cat", 2, 0},
      {"time cat <<EOF | cat\nbody\nEOF\n", "cat <<EOF | cat", 2, 0},
      {"time cat <<<one 3<<<two | cat", "cat <<<one 3<<<two | cat", 2, 0},
      {"time cat <<<body |& cat", "cat <<<body |& cat", 2, 0},
      {"time cat | <<<body", "cat | <<<body", 2, 0},
      {"time cat | <<EOF\nbody\nEOF\n", "cat | <<EOF", 2, 0},
      {"time cat <<<body | { cat; }", "cat <<<body | { cat; }", 1, 1},
      {"time { cat; } | <<<body", "{ cat; } | <<<body", 1, 1},
      {"time <<<body | cat", "<<<body | cat", 2, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = parse(cases[i].source, &graph);
    if (error != SHELL_DEP_OK)
      printf("\n    document case: %s (error %d)\n", cases[i].source, error);
    ASSERT(error == SHELL_DEP_OK);
    int timer = find_time(&graph);
    ASSERT(timer >= 0 && count_type(&graph, SHELL_NODE_TIME) == 1);
    ASSERT_STRN_EQ(graph.nodes[timer].time.start,
                   graph.nodes[timer].time.length, cases[i].span);
    unsigned commands = 0, groups = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type == SHELL_NODE_CMD &&
          graph.nodes[node].cmd.pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
        commands++;
        ASSERT(graph.nodes[node].cmd.pipeline_time_id == (uint32_t)timer + 1);
      }
      if (graph.nodes[node].type == SHELL_NODE_GROUP &&
          graph.nodes[node].group.pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
        groups++;
        ASSERT(graph.nodes[node].group.pipeline_time_id == (uint32_t)timer + 1);
      }
    }
    ASSERT(commands == cases[i].commands && groups == cases[i].groups);
    ASSERT(shell_dep_graph_validate(&graph).valid);
    ASSERT(shellsplit_test_depgraph_invariants(
        cases[i].source, strlen(cases[i].source), error, &graph, &limits));
  }

  /* The document is a redirect adjunct, not a stage boundary: a piped exec
   * runs privately even though the fast parser exposes an intervening range. */
  static const char *const private_exec[] = {
      "time exec 2>new <<<body | cat; time true",
      "time exec 2>new <<EOF | cat\nbody\nEOF\ntime true",
      "time exec 2>new <<<body |& cat; time true",
      "{ time exec 2>new <<<body | cat; time true; }",
  };
  for (size_t i = 0; i < sizeof(private_exec) / sizeof(private_exec[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(private_exec[i], &graph) == SHELL_DEP_OK);
    int file = find_file_doc(&graph, "new");
    ASSERT(file >= 0 && count_type(&graph, SHELL_NODE_TIME) == 2);
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_TIME) {
        ASSERT(time_has_external_fd(&graph, (int)node, 2));
        ASSERT(!has_edge(&graph, SHELL_EDGE_WRITE, node, (uint32_t)file));
      }
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
}

typedef struct {
  const char *word;
  shell_dep_word_value_t failure;
  size_t calls;
  bool valid;
} dep_expansion_failure_t;

typedef struct {
  const char *word;
  shell_dep_word_value_t value;
  size_t calls;
} dep_argument_fixture_t;

/* The executor contract opens only 0, 1 and 2. A safe input never fails for
 * want of a descriptor: every copy/move source and `read -u` descriptor must
 * exist on every path reaching it (SHELL_DEP_EUNMODELED otherwise). */
TEST(descriptor_contract) {
  static const char *const violations[] = {
      "cat <&3",
      "true >f 6<&23",
      "exec 2>&-; echo x >&2",
      "exec 5<&4-",
      "read -u3 x",
      "cat <&3 | :",
      "x=$(cat <&3)",
      "exec 3<f; exec 3<&-; cat <&3",
      "probe && exec 3>&-; true && time exec 2>&3",
      "exec 2>base && exec 3>out && { probe && exec 3>&-; time exec 2>&3; }",
      /* Also a certain arithmetic error. */
      "(X=$((1/0)) true) || exec 3>out; printf \"$(printf payload >&3)\"",
      "exec 0<&- 10>base; printf payload >&10",
      "exec 3>base; exec 3>&- 4>&3 2>out && time true",
      "exec 3>&-; true \"$(printf early)\" 4>&3 && printf body >bodyout",
      /* An unhandled failing open, control flow, a conditional process
       * substitution or a possibly unbound name leaves one path without it. */
      "probe && exec 3>maybe; exec 2>&3",
      ("exec 2>old || exit; probe && exec 3>new; echo \"$(exec 2>&3; time "
       "true)\""),
      ": ${choice:+<(printf p)} \"$(read -u63 x)\"",
  };
  static const char *const valid[] = {
      /* A failed open is the only way to lose the source: it is required. */
      "exec 3<f; cat <&3",
      "exec 3<f; read -u3 x",
      "exec 3>&1 >f; echo x >&3",
      "exec {x}<f; cat <&$x",
      "exec 3<f || exit; cat <&3",
      "exec 3<f && cat <&3",
      "exec 3<&0; cat <&3",
      "cat 3>&-",
      "exec 3>f; exec 3>&-; exec 3>&-",
      "exec 10>f; exec 10>&-; exec 10>&-",
      "true 2>&1 >f",
      "exec 4<f || exit; exec 5<&4-; cat <&5",
      "exec 3<f || exit; read -u3 x",
      "exec {x}<f || exit; cat <&$x",
      "x=$(exec 3<f || exit; cat <&3)",
      "exec 3<f || exit; x=$(cat <&3)",
      "{ cat <&3; } 3<g",
      "{ exec 11>&-; echo in; } >g",
      "true >f 10>&-",
      "cat 3<f 4<&3",
      "echo x >&2",
      /* A close before a named allocation does not orphan the failed-open
       * cause: the guarded use still requires only the fallible opens. */
      "true 10>&- {f}>out 4>/missing/x || printf value >&$f",
      "true 11>&- {f}>out 4>/missing/x || printf value >&$f",
  };
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  for (size_t i = 0; i < sizeof(violations) / sizeof(violations[0]); i++) {
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = parse(violations[i], &graph);
    if (error != SHELL_DEP_EUNMODELED)
      printf("    violation: %s (error %d)\n", violations[i], error);
    ASSERT(error == SHELL_DEP_EUNMODELED &&
           shellsplit_test_depgraph_invariants(
               violations[i], strlen(violations[i]), error, &graph, &limits));
  }
  for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
    shell_dep_graph_t graph = {0};
    shell_dep_error_t error = parse(valid[i], &graph);
    if (error != SHELL_DEP_OK)
      printf("    within contract: %s (error %d)\n", valid[i], error);
    ASSERT(error == SHELL_DEP_OK &&
           shellsplit_test_depgraph_invariants(valid[i], strlen(valid[i]),
                                               error, &graph, &limits));
  }
  /* Graph capacity can omit the setup which opened a descriptor. A violation
   * cannot be established from that incomplete state. */
  static const char opened_before_capacity[] =
      "exec 11>b || exit; : \"$(echo next >&11)\"";
  shell_dep_limits_t limited = limits;
  limited.max_edges = 1;
  shell_dep_graph_t graph = {0};
  ASSERT(shell_dep_graph_parse(opened_before_capacity,
                               sizeof(opened_before_capacity) - 1, "/",
                               &limited, &graph) == SHELL_DEP_ETRUNC);
  ASSERT(parse(opened_before_capacity, &graph) == SHELL_DEP_OK);
  /* Requirements: the open whose failure would leave the source missing, and
   * only that one. A handled failure needs no requirement. */
  static const struct {
    const char *source;
    unsigned required;
  } requirements[] = {
      {"exec 3<f; cat <&3", 1},
      {"exec 3<f || exit; cat <&3", 0},
      {"exec 3<f; cat <g", 0},
      {"exec 3<f 4<g; cat <&3", 2},
      {"true 10>&- {f}>out 4>/missing/x || printf value >&$f", 2},
      {"true 11>&- {f}>out 4>/missing/x || printf value >&$f", 2},
  };
  for (size_t i = 0; i < sizeof(requirements) / sizeof(requirements[0]); i++) {
    shell_dep_graph_t graph = {0};
    ASSERT(parse(requirements[i].source, &graph) == SHELL_DEP_OK);
    unsigned required = 0;
    /* Count the documents whose open is required. */
    for (uint32_t node = 0; node < graph.node_count; node++) {
      bool flagged = false;
      for (uint32_t edge = 0; edge < graph.edge_count; edge++)
        flagged |=
            graph.nodes[node].type == SHELL_NODE_DOC &&
            (graph.edges[edge].from == node || graph.edges[edge].to == node) &&
            (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_REQUIRED);
      required += flagged;
    }
    if (required != requirements[i].required)
      printf("    requirements: %s (%u)\n", requirements[i].source, required);
    ASSERT(required == requirements[i].required &&
           shell_dep_graph_validate(&graph).valid);
  }
  /* After the failed setup, Bash keeps f=10. Undoing `10>&-` closes that
   * descriptor, so `>&$f` fails and printf never runs (verified: "$f: Bad
   * file descriptor"); undoing `11>&-` leaves it open on out, which printf
   * writes. */
  {
    shell_dep_graph_t closed = {0}, open = {0};
    ASSERT(parse(requirements[4].source, &closed) == SHELL_DEP_OK);
    int printf_node = find_cmd_tokens(&closed, "printf", "value");
    ASSERT(printf_node >= 0);
    for (uint32_t edge = 0; edge < closed.edge_count; edge++)
      ASSERT(closed.edges[edge].from != (uint32_t)printf_node ||
             closed.edges[edge].source_fd != 1);
    ASSERT(parse(requirements[5].source, &open) == SHELL_DEP_OK);
    printf_node = find_cmd_tokens(&open, "printf", "value");
    int out = find_file_doc(&open, "out");
    ASSERT(printf_node >= 0 && out >= 0 &&
           has_edge_fds(&open, SHELL_EDGE_WRITE, (uint32_t)printf_node,
                        (uint32_t)out, 1, SHELL_DEP_FD_NONE));
  }
  ASSERT(strcmp(shell_dep_error_string(SHELL_DEP_EUNMODELED),
                "No safe dependency model") == 0);
}

TEST(exit_operand_and_status_transfer) {
  static const struct {
    const char *exit_command;
    bool success;
  } numeric[] = {
      {"exit 2", false},
      {"exit -1", false},
      {"exit +0", true},
      {"exit 256", true},
      {"exit 000256", true},
      {"exit -256", true},
      {"exit 257", false},
      {"exit -- 256", true},
      {"command exit 2", false},
      {"command -p exit +0", true},
      {"builtin ex'it' -- -256", true},
      {"exit ' 256 '\t", true},
      {"exit $'\\t-256\\n'", true},
      {"exit 2\\\n56", true},
      {"exit 9223372036854775807", false},
      {"exit -9223372036854775808", true},
  };
  for (size_t i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++) {
    char source[256];
    shell_dep_graph_t graph;
    snprintf(source, sizeof(source), "%s; time true", numeric[i].exit_command);
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int timer = find_time(&graph);
    ASSERT(timer >= 0 && graph.nodes[timer].time.report_route ==
                             SHELL_TIME_REPORT_UNAVAILABLE);
    snprintf(source, sizeof(source), "(%s) %s time true",
             numeric[i].exit_command, numeric[i].success ? "||" : "&&");
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    ASSERT(timer >= 0 && graph.nodes[timer].time.report_route ==
                             SHELL_TIME_REPORT_UNAVAILABLE);
    snprintf(source, sizeof(source), "(%s) %s time true",
             numeric[i].exit_command, numeric[i].success ? "&&" : "||");
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    ASSERT(timer >= 0 &&
           graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
           shell_dep_graph_validate(&graph).valid);
  }

  static const char *const skipped[] = {
      "(false; exit) && time true",
      "(true; exit) || time true",
      "(false; exit --) && time true",
      "(true; command exit) || time true",
      "(false; builtin exit) && time true",
      "(true; ! exit) || time true",
      "(false || exit) && time true",
      "(true && exit) || time true",
      "(probe && exit; true) || time true",
      "(probe || exit; false) && time true",
      "false; (exit) && time true",
      "true; (exit --) || time true",
      "false; ( { exit; } ) && time true",
      "false; ({ exit; }) && time true",
      "true; ({(exit)}) || time true",
      "(false; exit <<< <(printf '%s' \"$(true)\")) && time true",
      "(true; exit <<< <(printf '%s' \"$(false)\")) || time true",
      "(false; exit <<< <(printf '%s' `true`)) && time true",
      "(true; exit <<< >(cat <<<\"$(false)\")) || time true",
      "(false; exit <<<prefix<(printf '%s' \"$(true)\")suffix) && time true",
      "(true; <<< <(printf '%s' \"$(false)\") exit) || time true",
      "true; ( (exit) ) || time true",
      "false; ! (exit) || time true",
      "true; ! { exit; }; time true",
      "(exit -- 2 2>&1) && time true",
  };
  for (size_t i = 0; i < sizeof(skipped) / sizeof(skipped[0]); i++) {
    shell_dep_graph_t graph;
    shell_dep_error_t error = parse(skipped[i], &graph);
    if (error != SHELL_DEP_OK)
      printf("\n    inherited exit parse: %s (error %d)\n", skipped[i], error);
    ASSERT(error == SHELL_DEP_OK);
    int timer = find_time(&graph);
    if (timer < 0 ||
        graph.nodes[timer].time.report_route != SHELL_TIME_REPORT_UNAVAILABLE)
      printf("\n    inherited exit case: %s\n", skipped[i]);
    ASSERT(timer >= 0 &&
           graph.nodes[timer].time.report_route ==
               SHELL_TIME_REPORT_UNAVAILABLE &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* Redirects are not exit operands. An open/setup failure may still return,
   * but its failure cannot turn a successful subshell into an AND successor.
   */
  shell_dep_graph_t graph;
  ASSERT(parse("(exit 2 >out) && time true", &graph) == SHELL_DEP_OK);
  int timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_UNAVAILABLE);
  ASSERT(parse("exit 2 2>/missing/x; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL);

  static const char *const unreachable[] = {
      "exit 2; printf x >out",
      "command exit -- 256; printf x >out",
      "exit -1; printf x >&\"$fd\"",
      "exit 2; echo \"$(printf nested)\"",
      "(false; exit) && echo \"$(printf nested)\"",
      "false; (exit) && printf x >&\"$fd\"",
  };
  for (size_t i = 0; i < sizeof(unreachable) / sizeof(unreachable[0]); i++) {
    ASSERT(parse(unreachable[i], &graph) == SHELL_DEP_OK);
    ASSERT(count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
           count_edge_type(&graph, SHELL_EDGE_SUBST) == 0 &&
           shell_dep_graph_validate(&graph).valid);
  }

  ASSERT(parse("(true; exit <<< <(printf '%s' \"$(false)\")) || printf x >out",
               &graph) == SHELL_DEP_OK);
  int skipped_writer = find_cmd_tokens(&graph, "printf", "x");
  ASSERT(skipped_writer >= 0 &&
         count_edge_type(&graph, SHELL_EDGE_WRITE) == 0 &&
         count_edge_type(&graph, SHELL_EDGE_SUBST) == 1 &&
         shell_dep_graph_validate(&graph).valid);
  for (uint32_t edge = 0; edge < graph.edge_count; edge++)
    if (graph.edges[edge].type == SHELL_EDGE_SUBST)
      ASSERT(graph.edges[edge].to != (uint32_t)skipped_writer);

  static const char *const retained[] = {
      "(false; exit) &&",         "(true; exit) ||",
      "(probe && exit; true) ||", "(probe || exit; false) &&",
      "false; (exit) &&",         "true; (exit) ||",
      "(exit -- 256) ||",         "(exit -1) &&",
  };
  for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "exec {fd}>out || exit; %s unset fd; printf x >&\"$fd\"",
             retained[i]);
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int output = find_file_doc(&graph, "out");
    int writer = find_cmd_tokens(&graph, "printf", "x");
    ASSERT(output >= 0 && writer >= 0 &&
           has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)writer,
                        (uint32_t)output, 1, SHELL_DEP_FD_NONE));

    snprintf(source, sizeof(source),
             "exec 2>base || exit; %s exec 2>other; time true", retained[i]);
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    int base = find_file_doc(&graph, "base");
    int other = find_file_doc(&graph, "other");
    ASSERT(
        timer >= 0 && base >= 0 && other >= 0 &&
        graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
        has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)base,
                     2, SHELL_DEP_FD_NONE) &&
        !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)other));

    snprintf(source, sizeof(source), "%s cd /private; cat ./file", retained[i]);
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    int reader = find_cmd_tokens(&graph, "cat", "./file");
    ASSERT(reader >= 0 && graph.nodes[reader].cmd.cwd_known &&
           strcmp(graph.cwd_buf.data + graph.nodes[reader].cmd.cwd_offset,
                  ".") == 0 &&
           shell_dep_graph_validate(&graph).valid);
  }

  /* Error behavior differs between Bash releases. Keep genuine returning
   * errors and dynamic argv separate from the statically numeric proof. */
  static const char *const uncertain[] = {
      "exit ''",
      "exit nonsense",
      "exit +",
      "exit 9223372036854775808",
      "exit -9223372036854775809",
      "exit 0 1",
      "exit -- --",
      "exit \"$status\"",
      "exit $status",
      "exit 256 $extra",
      "exit -- 256 $extra",
      "exit --help",
  };
  for (size_t i = 0; i < sizeof(uncertain) / sizeof(uncertain[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source), "%s; time true", uncertain[i]);
    ASSERT(parse(source, &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    ASSERT(timer >= 0 &&
           graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
           shell_dep_graph_validate(&graph).valid);
  }
  static const char *const expansion_status[] = {
      "(true; exit >\"$(printf /dev/null; false)\") || time true",
      "true; ( { exit; } >\"$(printf /dev/null; false)\" ) || time true",
      "false; ( { exit; } >\"$(printf /dev/null; true)\" ) && time true",
      "(true; X=\"$(false)\" exit) || time true",
      "(true; exit <<<\"$(false)\") || time true",
      "(true; <<<\"$(false)\" exit) || time true",
      "(true; exit <<<\"`false`\") || time true",
      "(true; exit <<< <(printf '%s' \"$(true)\") <<<\"$(false)\") || time "
      "true",
      "(true; exit <<<\"$(false)\" <<< <(printf '%s' \"$(true)\")) || time "
      "true",
      "(true; exit <<EOF\n$(false)\nEOF\n) || time true",
      ("false; ( { exit; } > >(cat) >\"$(printf /dev/null; true)\" ) && time "
       "true"),
  };
  for (size_t i = 0; i < sizeof(expansion_status) / sizeof(expansion_status[0]);
       i++) {
    ASSERT(parse(expansion_status[i], &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    if (timer < 0 ||
        graph.nodes[timer].time.report_route != SHELL_TIME_REPORT_EXTERNAL)
      printf("\n    expanded exit status: %s\n", expansion_status[i]);
    ASSERT(timer >= 0 &&
           graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
           shell_dep_graph_validate(&graph).valid);
  }
  /* A compound's document setup can fail before its body runs. That ordinary
   * failure remains possible regardless of substitutions in a process child;
   * adding the child must not change the parent's possible report routes. */
  static const char *const group_setup[] = {
      "true; ({ exit; } <<< <(printf x)) || time true",
      "true; ({ exit; } <<< <(printf '%s' \"$(false)\")) || time true",
  };
  for (size_t i = 0; i < sizeof(group_setup) / sizeof(group_setup[0]); i++) {
    ASSERT(parse(group_setup[i], &graph) == SHELL_DEP_OK);
    timer = find_time(&graph);
    ASSERT(timer >= 0 &&
           graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
           shell_dep_graph_validate(&graph).valid);
  }
  pass_count++;
}

TEST(bash_pipeline_time_report_routes) {
  shell_dep_graph_t graph = {0};
  /* Name enumeration is not indirect dereferencing and cannot contribute an
   * expansion-abort branch. A following unconditional exec owns the complete
   * timing-report route, including when enumeration is nested or in I/O. */
  for (size_t i = 0; i < sizeof(shellsplit_test_enumeration_time_routes) /
                             sizeof(shellsplit_test_enumeration_time_routes[0]);
       i++) {
    ASSERT(parse(shellsplit_test_enumeration_time_routes[i], &graph) ==
           SHELL_DEP_OK);
    unsigned timers = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type != SHELL_NODE_TIME)
        continue;
      const shell_dep_time_t *time = &graph.nodes[node].time;
      ASSERT(time->report_route == SHELL_TIME_REPORT_EXTERNAL &&
             time->report_target_fd == 1 &&
             time->report_route_flags == SHELL_TIME_REPORT_ROUTE_EXTERNAL &&
             !time_has_external_fd(&graph, (int)node, 2));
      timers++;
    }
    ASSERT(timers > 0 && shell_dep_graph_validate(&graph).valid);
  }
  ASSERT(parse("time true", &graph) == SHELL_DEP_OK);
  int timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         graph.nodes[timer].time.report_target_fd == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time>/tmp/timing printf value", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int source = find_first_cmd(&graph);
  int timing = find_file_doc(&graph, "/tmp/timing");
  ASSERT(
      timer >= 0 && source >= 0 && timing >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      graph.nodes[timer].time.report_target_fd == 2 &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)source, (uint32_t)timing,
                   1, SHELL_DEP_FD_NONE) &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)timing) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time true 2>local", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int local = find_file_doc(&graph, "local");
  ASSERT(
      timer >= 0 && local >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      graph.nodes[timer].time.report_target_fd == 2 &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)local) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time true 2>&-", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         graph.nodes[timer].time.report_target_fd == 2 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>persistent || exit; time { printf x >&2; } 2>local",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int persistent = find_file_doc(&graph, "persistent");
  local = find_file_doc(&graph, "local");
  ASSERT(
      timer >= 0 && persistent >= 0 && local >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)persistent, 2, SHELL_DEP_FD_NONE) &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)local) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ time true; } 2>outer", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int outer = find_file_doc(&graph, "outer");
  ASSERT(timer >= 0 && outer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)outer, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time exec 2>new", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time exec 2>new && true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time { exec 2>new; }", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time (exec 2>new)", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time exec 2>new | cat", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>>log && time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int log = find_file_doc(&graph, "log");
  ASSERT(timer >= 0 && log >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)timer, (uint32_t)log,
                      2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {log}>>named || exit; exec 2>&$log; time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int named = find_file_doc(&graph, "named");
  ASSERT(timer >= 0 && named >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_APPEND, (uint32_t)timer,
                      (uint32_t)named, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {log}>named || exit; time true 2>&$log", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  named = find_file_doc(&graph, "named");
  ASSERT(
      timer >= 0 && named >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      graph.nodes[timer].time.report_target_fd == 2 &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)named) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec {log}>named || exit; time exec 2>&$log", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  named = find_file_doc(&graph, "named");
  ASSERT(timer >= 0 && named >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)named, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>$(printf error-name) && time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int dynamic = find_file_doc(&graph, "$(printf error-name)");
  ASSERT(timer >= 0 && dynamic >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)dynamic, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>&1; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         graph.nodes[timer].time.report_target_fd == 1 &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>&-; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_CLOSED &&
         graph.nodes[timer].time.report_target_fd == SHELL_DEP_FD_NONE &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time exec 2>&-", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_CLOSED &&
         graph.nodes[timer].time.report_target_fd == SHELL_DEP_FD_NONE &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>old || exit; exec 2<input && time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route ==
             SHELL_TIME_REPORT_UNAVAILABLE &&
         graph.nodes[timer].time.report_route_flags ==
             SHELL_TIME_REPORT_ROUTE_UNAVAILABLE &&
         graph.nodes[timer].time.report_target_fd == SHELL_DEP_FD_NONE &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>old || exit; probe && exec 2<input; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int old = find_file_doc(&graph, "old");
  ASSERT(timer >= 0 && old >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_route_flags ==
             (SHELL_TIME_REPORT_ROUTE_GRAPH |
              SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) &&
         graph.nodes[timer].time.report_external_fd_count == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)old,
                      2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! false && exec 2>negated && time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int negated = find_file_doc(&graph, "negated");
  ASSERT(timer >= 0 && negated >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)negated, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("! true && exec 2>skipped; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int skipped = find_file_doc(&graph, "skipped");
  ASSERT(
      timer >= 0 && skipped >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      graph.nodes[timer].time.report_target_fd == 2 &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)skipped) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ time true; } |& cat", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int cat = find_cmd_tokens(&graph, "cat", NULL);
  ASSERT(timer >= 0 && cat >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_PIPE, (uint32_t)timer, (uint32_t)cat,
                      2, 0) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("{ time true; } 2> >(cat)", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int endpoint = find_endpoint(&graph);
  ASSERT(timer >= 0 && endpoint >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)endpoint, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 2>err && echo \"$(time true)\"", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int error_file = find_file_doc(&graph, "err");
  ASSERT(timer >= 0 && error_file >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)error_file, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("echo \"$(exec 2>&1; time true)\"", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int echo = find_cmd_tokens(&graph, "echo", NULL);
  bool timed_word_flow = false;
  for (uint32_t endpoint_node = 0; endpoint_node < graph.node_count;
       endpoint_node++) {
    if (graph.nodes[endpoint_node].type != SHELL_NODE_ENDPOINT)
      continue;
    timed_word_flow =
        timed_word_flow ||
        (has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, endpoint_node,
                      2, SHELL_DEP_FD_NONE) &&
         has_edge(&graph, SHELL_EDGE_SUBST, endpoint_node, (uint32_t)echo));
  }
  ASSERT(timer >= 0 && echo >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         !time_has_external_fd(&graph, timer, 1) && timed_word_flow &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("cat <(exec 2>&1; time true)", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int cat_subst = find_cmd_tokens(&graph, "cat", NULL);
  bool timed_process_flow = false;
  for (uint32_t endpoint_node = 0; endpoint_node < graph.node_count;
       endpoint_node++) {
    if (graph.nodes[endpoint_node].type != SHELL_NODE_ENDPOINT)
      continue;
    timed_process_flow =
        timed_process_flow ||
        (has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, endpoint_node,
                      2, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_SUBST, endpoint_node,
                      (uint32_t)cat_subst, SHELL_DEP_FD_NONE,
                      SHELL_DEP_FD_NONE));
  }
  ASSERT(timer >= 0 && cat_subst >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         !time_has_external_fd(&graph, timer, 1) && timed_process_flow &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time true; exec 2>later", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int later = find_file_doc(&graph, "later");
  ASSERT(
      timer >= 0 && later >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      graph.nodes[timer].time.report_target_fd == 2 &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)later) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time (true) 2>local", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  local = find_file_doc(&graph, "local");
  ASSERT(timer >= 0 && local >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)local, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time { true; } 2>local", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  local = find_file_doc(&graph, "local");
  ASSERT(
      timer >= 0 && local >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      time_has_external_fd(&graph, timer, 2) &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)local) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time (true) 2>local | cat", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  local = find_file_doc(&graph, "local");
  ASSERT(
      timer >= 0 && local >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)local) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time true 2>local &", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  local = find_file_doc(&graph, "local");
  ASSERT(
      timer >= 0 && local >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)local) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time { true; } 2>local &", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  local = find_file_doc(&graph, "local");
  ASSERT(timer >= 0 && local >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)local, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time exec 2>new &", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time { exec 2>new; } &", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time (exec 2>new) | cat", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("time { exec 2>new; } | cat", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 2>new; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_GRAPH) &&
      time_has_external_fd(&graph, timer, 2) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  /* `||` has the same unknown-status descriptor alternatives as `&&`: the
   * branch either preserves fd 2 or persistently replaces it before timing. */
  ASSERT(parse("probe || exec 2>or-new; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int or_replacement = find_file_doc(&graph, "or-new");
  ASSERT(
      timer >= 0 && or_replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_GRAPH) &&
      time_has_external_fd(&graph, timer, 2) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)or_replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  /* A later unconditional close resolves every prior OR alternative. */
  ASSERT(parse("probe || exec 2>or-closed; exec 2>&-; time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int or_closed = find_file_doc(&graph, "or-closed");
  ASSERT(timer >= 0 && or_closed >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_CLOSED &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)or_closed) &&
         shell_dep_graph_validate(&graph).valid);

  /* `&&` and `||` are left-associative. Either descriptor-changing branch
   * can be the final state of this mixed list. A redirect setup can itself
   * fail, so preserve the unchanged external fallback as well. */
  ASSERT(parse("probe && exec 2>and-new || exec 2>or-new; time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int and_replacement = find_file_doc(&graph, "and-new");
  or_replacement = find_file_doc(&graph, "or-new");
  ASSERT(
      timer >= 0 && and_replacement >= 0 && or_replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_GRAPH) &&
      time_has_external_fd(&graph, timer, 2) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)and_replacement, 2, SHELL_DEP_FD_NONE) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)or_replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  /* The copied descriptor must exist on every path: each branch replaces the
   * base open, and the copy never falls back to the external stderr. */
  ASSERT(parse("exec 3>base3 || exit; probe && exec 3>first3; "
               "probe && exec 3>second3; exec 2>&3; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int first3 = find_file_doc(&graph, "first3");
  int second3 = find_file_doc(&graph, "second3");
  ASSERT(timer >= 0 && first3 >= 0 && second3 >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_external_fd_count == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base3"), 2,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)first3, 2, SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)second3, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>base3 || exit; probe || exec 3>or-indirect; "
               "exec 2>&3; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int or_indirect = find_file_doc(&graph, "or-indirect");
  ASSERT(timer >= 0 && or_indirect >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_route_flags ==
             SHELL_TIME_REPORT_ROUTE_GRAPH &&
         graph.nodes[timer].time.report_external_fd_count == 0 &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base3"), 2,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)or_indirect, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>base3 || exit; probe && exec 3>shadowed3 3>final3; "
               "exec 2>&3; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int shadowed3 = find_file_doc(&graph, "shadowed3");
  int final3 = find_file_doc(&graph, "final3");
  ASSERT(timer >= 0 && shadowed3 >= 0 && final3 >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base3"), 2,
                      SHELL_DEP_FD_NONE) &&
         !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)shadowed3) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)final3, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

#define MANY_CONDITIONAL_DESCRIPTORS                                           \
  "probe && exec 3>f3; probe && exec 4>f4; "                                   \
  "probe && exec 5>f5; probe && exec 6>f6; "                                   \
  "probe && exec 7>f7; probe && exec 8>f8; "                                   \
  "probe && exec 9>f9; probe && exec 10>f10; "                                 \
  "probe && exec 11>f11; probe && exec 12>f12; "                               \
  "probe && exec 13>f13; probe && exec 14>f14; "                               \
  "probe && exec 15>f15; probe && exec 16>f16; "                               \
  "probe && exec 17>f17; probe && exec 18>f18; "                               \
  "probe && exec 19>f19; "
  ASSERT(parse(MANY_CONDITIONAL_DESCRIPTORS "time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
         graph.nodes[timer].time.report_target_fd == 2 &&
         time_has_external_fd(&graph, timer, 2) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 19>base19 || exit; " MANY_CONDITIONAL_DESCRIPTORS
               "exec 2>&19; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int nineteenth = find_file_doc(&graph, "f19");
  ASSERT(timer >= 0 && nineteenth >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_route_flags ==
             SHELL_TIME_REPORT_ROUTE_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base19"), 2,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)nineteenth, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse(MANY_CONDITIONAL_DESCRIPTORS
               "exec 19>final19 && exec 2>&19 && time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int final_nineteenth = find_file_doc(&graph, "final19");
  ASSERT(timer >= 0 && final_nineteenth >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         !time_has_external_fd(&graph, timer, 19) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)final_nineteenth, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
#undef MANY_CONDITIONAL_DESCRIPTORS

  /* Exercise the same overflow journal through OR alternatives.  Descriptor
   * choices beyond the inline route set must survive the later fd 2 import. */
#define MANY_OR_CONDITIONAL_DESCRIPTORS                                        \
  "probe || exec 3>o3; probe || exec 4>o4; "                                   \
  "probe || exec 5>o5; probe || exec 6>o6; "                                   \
  "probe || exec 7>o7; probe || exec 8>o8; "                                   \
  "probe || exec 9>o9; probe || exec 10>o10; "                                 \
  "probe || exec 11>o11; probe || exec 12>o12; "                               \
  "probe || exec 13>o13; probe || exec 14>o14; "                               \
  "probe || exec 15>o15; probe || exec 16>o16; "                               \
  "probe || exec 17>o17; probe || exec 18>o18; "                               \
  "probe || exec 19>o19; "
  ASSERT(parse("exec 19>base19 || exit; " MANY_OR_CONDITIONAL_DESCRIPTORS
               "exec 2>&19; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  nineteenth = find_file_doc(&graph, "o19");
  ASSERT(timer >= 0 && nineteenth >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_route_flags ==
             SHELL_TIME_REPORT_ROUTE_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base19"), 2,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)nineteenth, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);
#undef MANY_OR_CONDITIONAL_DESCRIPTORS

  ASSERT(parse("exec 3>base3 || exit; probe && exec 3>first; "
               "exec 4>&3 3>second || exit; exec 2>&4; time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  int first = find_file_doc(&graph, "first");
  int second = find_file_doc(&graph, "second");
  ASSERT(
      timer >= 0 && first >= 0 && second >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)find_file_doc(&graph, "base3"), 2,
                   SHELL_DEP_FD_NONE) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)first,
                   2, SHELL_DEP_FD_NONE) &&
      !has_edge(&graph, SHELL_EDGE_WRITE, (uint32_t)timer, (uint32_t)second) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("exec 3>base3 || exit; probe && exec 3>new; exec 2>&3; "
               "time true",
               &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)find_file_doc(&graph, "base3"), 2,
                      SHELL_DEP_FD_NONE) &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 2>new && time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 3>new && time exec 2>&3", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(timer >= 0 && replacement >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && time { exec 2>new; true; }", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  /* A descriptor-changing exec inside the timed foreground brace may be
   * skipped independently of the brace itself. The report belongs to the
   * containing shell, so retain both the unchanged and changed routes. */
  ASSERT(parse("time { probe && exec 2>new; true; }", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_GRAPH) &&
      time_has_external_fd(&graph, timer, 2) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 2>&-; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(
      timer >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_CLOSED) &&
      time_has_external_fd(&graph, timer, 2) &&
      shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 2>&1; time true", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  ASSERT(timer >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
         graph.nodes[timer].time.report_route_flags ==
             SHELL_TIME_REPORT_ROUTE_EXTERNAL &&
         time_has_external_fd(&graph, timer, 1) &&
         time_has_external_fd(&graph, timer, 2) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && exec 2>maybe; exec 2>final && time true", &graph) ==
         SHELL_DEP_OK);
  timer = find_time(&graph);
  int final = find_file_doc(&graph, "final");
  ASSERT(timer >= 0 && final >= 0 &&
         graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_GRAPH &&
         has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                      (uint32_t) final, 2, SHELL_DEP_FD_NONE) &&
         shell_dep_graph_validate(&graph).valid);

  ASSERT(parse("probe && time exec 2>new", &graph) == SHELL_DEP_OK);
  timer = find_time(&graph);
  replacement = find_file_doc(&graph, "new");
  ASSERT(
      timer >= 0 && replacement >= 0 &&
      graph.nodes[timer].time.report_route == SHELL_TIME_REPORT_MULTIPLE &&
      time_has_external_fd(&graph, timer, 2) &&
      graph.nodes[timer].time.report_route_flags ==
          (SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL) &&
      has_edge_fds(&graph, SHELL_EDGE_WRITE, (uint32_t)timer,
                   (uint32_t)replacement, 2, SHELL_DEP_FD_NONE) &&
      shell_dep_graph_validate(&graph).valid);

  static const char *const bounded_routes[] = {
      "{ time true; } 2>outer",
      "{ time true; } |& cat",
      "exec 2>err && echo \"$(time true)\"",
      "exec 3>base3 || exit; probe && exec 3>new; exec 2>&3; time true",
      "exec 2>base; probe && exec 2>new; time true",
  };
  for (size_t route = 0;
       route < sizeof(bounded_routes) / sizeof(bounded_routes[0]); route++) {
    ASSERT(parse(bounded_routes[route], &graph) == SHELL_DEP_OK);
    uint32_t full_edge_count = graph.edge_count;
    for (uint32_t edge_limit = 0; edge_limit <= full_edge_count; edge_limit++) {
      shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
      limits.max_edges = edge_limit;
      shell_dep_error_t status = shell_dep_graph_parse(
          bounded_routes[route], strlen(bounded_routes[route]), ".", &limits,
          &graph);
      ASSERT((status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC) &&
             shell_dep_graph_validate(&graph).valid);
    }
  }
  pass_count++;
}

/* The validation API is also a corruption-safe diagnostic boundary. Exercise
 * each public shape class with deliberately malformed, bounded graphs so a
 * caller can rely on it before inspecting any node or edge payload. */
TEST(validation_defensive_diagnostics_matrix) {
  static const char group_span[] = "{ x; }";
  bool valid = true;
  shell_dep_graph_validation_t validation;

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
  malformed.nodes[0].cmd.pipeline_time_mode =
      (shell_pipeline_time_mode_t)(SHELL_PIPE_TIME_POSIX + 1);
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].cmd.pipeline_time_id = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = graph;
  malformed.nodes[0].type = SHELL_NODE_GROUP;
  malformed.nodes[0].group.pipeline_time_mode =
      (shell_pipeline_time_mode_t)(SHELL_PIPE_TIME_POSIX + 1);
  valid = valid && !shell_dep_graph_validate(&malformed).valid;

  shell_dep_graph_t timed = graph;
  timed.node_count = 4;
  timed.nodes[0].cmd.pipeline_time_mode = SHELL_PIPE_TIME_DEFAULT;
  timed.nodes[0].cmd.pipeline_time_id = 3;
  timed.nodes[2] = (shell_dep_node_t){
      .type = SHELL_NODE_TIME,
      .time = {.start = group_span,
               .length = sizeof(group_span) - 1,
               .mode = SHELL_PIPE_TIME_DEFAULT,
               .report_fd = 2,
               .report_target_fd = 2,
               .report_route = SHELL_TIME_REPORT_EXTERNAL,
               .report_route_flags = SHELL_TIME_REPORT_ROUTE_EXTERNAL,
               .report_external_fd_count = 1,
               .report_external_fds = {2}},
  };
  timed.nodes[3] =
      (shell_dep_node_t){.type = SHELL_NODE_FD, .fd = {.number = 2}};
  timed.edge_count = 2;
  timed.edges[1] = (shell_dep_edge_t){.type = SHELL_EDGE_WRITE,
                                      .dir = SHELL_DIR_FORWARD,
                                      .from = 2,
                                      .to = 3,
                                      .source_fd = 2,
                                      .target_fd = SHELL_DEP_FD_NONE};
  timed.edges[0] = (shell_dep_edge_t){
      .type = SHELL_EDGE_TIME,
      .dir = SHELL_DIR_FORWARD,
      .from = 2,
      .to = 0,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
  valid = valid && shell_dep_graph_validate(&timed).valid;
  malformed = graph;
  malformed.nodes[0].cmd.pipeline_time_mode = SHELL_PIPE_TIME_DEFAULT;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.status = SHELL_DEP_STATUS_TRUNCATED;
  valid = valid && shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[0].cmd.pipeline_time_id = 2;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  shell_dep_graph_t timed_group = timed;
  timed_group.nodes[0] = (shell_dep_node_t){
      .type = SHELL_NODE_GROUP,
      .group = {.start = group_span,
                .length = sizeof(group_span) - 1,
                .parent = UINT32_MAX,
                .kind = SHELL_GROUP_BRACE,
                .pipeline_time_mode = SHELL_PIPE_TIME_DEFAULT,
                .pipeline_time_id = 3},
  };
  valid = valid && shell_dep_graph_validate(&timed_group).valid;
  malformed = timed_group;
  malformed.nodes[0].group.pipeline_time_id = 0;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.mode = SHELL_PIPE_TIME_NONE;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_fd = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_target_fd = SHELL_DEP_FD_NONE;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_route = SHELL_TIME_REPORT_CLOSED;
  malformed.nodes[2].time.report_target_fd = 2;
  malformed.nodes[2].time.report_route_flags = SHELL_TIME_REPORT_ROUTE_CLOSED;
  malformed.nodes[2].time.report_external_fd_count = 0;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  shell_dep_graph_t unavailable_time = timed;
  unavailable_time.nodes[2].time.report_route = SHELL_TIME_REPORT_UNAVAILABLE;
  unavailable_time.nodes[2].time.report_target_fd = SHELL_DEP_FD_NONE;
  unavailable_time.nodes[2].time.report_route_flags =
      SHELL_TIME_REPORT_ROUTE_UNAVAILABLE;
  unavailable_time.nodes[2].time.report_external_fd_count = 0;
  unavailable_time.node_count = 3;
  unavailable_time.edge_count = 1;
  valid = valid && shell_dep_graph_validate(&unavailable_time).valid;
  malformed = unavailable_time;
  malformed.nodes[2].time.report_route_flags = SHELL_TIME_REPORT_ROUTE_CLOSED;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_route = SHELL_TIME_REPORT_UNKNOWN;
  malformed.nodes[2].time.report_target_fd = SHELL_DEP_FD_NONE;
  malformed.nodes[2].time.report_route_flags = SHELL_TIME_REPORT_ROUTE_UNKNOWN;
  malformed.nodes[2].time.report_external_fd_count = 0;
  malformed.node_count = 3;
  malformed.edge_count = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed.status = SHELL_DEP_STATUS_TRUNCATED;
  valid = valid && shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_route = SHELL_TIME_REPORT_GRAPH;
  malformed.nodes[2].time.report_target_fd = SHELL_DEP_FD_NONE;
  malformed.nodes[2].time.report_route_flags = SHELL_TIME_REPORT_ROUTE_GRAPH;
  malformed.nodes[2].time.report_external_fd_count = 0;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  shell_dep_graph_t multiple_time = timed;
  multiple_time.nodes[2].time.report_route = SHELL_TIME_REPORT_MULTIPLE;
  multiple_time.nodes[2].time.report_target_fd = SHELL_DEP_FD_NONE;
  multiple_time.nodes[2].time.report_route_flags =
      SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_CLOSED;
  multiple_time.nodes[2].time.report_external_fd_count = 1;
  multiple_time.nodes[2].time.report_external_fds[0] = 2;
  valid = valid && shell_dep_graph_validate(&multiple_time).valid;
  malformed = multiple_time;
  malformed.nodes[2].time.report_external_fd_count = 2;
  malformed.nodes[2].time.report_external_fds[1] = 2;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = multiple_time;
  malformed.nodes[2].time.report_route_flags = SHELL_TIME_REPORT_ROUTE_EXTERNAL;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[2].time.report_route =
      (shell_dep_time_report_route_t)(SHELL_TIME_REPORT_MULTIPLE + 1);
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.nodes[0].cmd.pipeline_time_mode = SHELL_PIPE_TIME_POSIX;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.edge_count = 0;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.edges[0].dir = SHELL_DIR_UNDIR;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.edges[0].flags = SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.edge_count = 2;
  malformed.edges[1] = malformed.edges[0];
  malformed.edges[1].to = 1;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  /* TIME nodes are sources only: no timing edge may target a timer. */
  malformed = timed;
  malformed.node_count = 4;
  malformed.nodes[3] = malformed.nodes[2];
  malformed.edge_count = 2;
  malformed.edges[1] = malformed.edges[0];
  malformed.edges[1].from = 3;
  malformed.edges[1].to = 2;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  /* Two independent timers cannot own one measured pipeline target. */
  malformed = timed;
  malformed.node_count = 4;
  malformed.nodes[3] = malformed.nodes[2];
  malformed.edge_count = 2;
  malformed.edges[1] = malformed.edges[0];
  malformed.edges[1].from = 3;
  valid = valid && !shell_dep_graph_validate(&malformed).valid;
  malformed = timed;
  malformed.edge_count = 2;
  malformed.edges[1] = (shell_dep_edge_t){
      .type = SHELL_EDGE_SEQ,
      .dir = SHELL_DIR_FORWARD,
      .from = 0,
      .to = 2,
      .source_fd = SHELL_DEP_FD_NONE,
      .target_fd = SHELL_DEP_FD_NONE,
  };
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
      "exec 2>err; echo \"$(time true)\"",
      "time -p { producer; consumer; } |& sink",
      "time { cmd <<<\"$(producer)\"; } 2>report",
      "time { cat; } <<EOF\n$(producer)\nEOF\n",
      "time { cmd; } <<<\"$(producer)\" >\"$(path)\"",
      "time (time producer | consumer) >out 2>report",
      "time { >out; cmd; } | time sink",
      "time { producer; } > >(time sink)",
      "time { consumer; } < <(time producer)",
      "exec {fd}>out; time { cmd >&$fd; } 2>&$fd; exec {fd}>&-",
      "time true || { exec 2>fallback; }; time cmd",
      "time unknown && { exec 2>one; } || { exec 2>two; }; time cmd",
  };
  static const uint32_t limits[] = {1, 2, 3, 4};
  for (size_t command = 0; command < sizeof(commands) / sizeof(commands[0]);
       command++) {
    shell_dep_graph_t baseline = {0};
    ASSERT(shell_dep_graph_parse(commands[command], strlen(commands[command]),
                                 "/work/base", NULL,
                                 &baseline) == SHELL_DEP_OK &&
           shell_dep_graph_validate(&baseline).valid);
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
    /* Constrain one budget at a time: an early node truncation must not hide
     * the independent edge, token, and CWD boundaries later in construction. */
    static const uint32_t independent[] = {1, 2, 3, 4, 8, 16, 24};
    for (unsigned budget = 0; budget < 4; budget++) {
      for (size_t bound = 0;
           bound < sizeof(independent) / sizeof(independent[0]); bound++) {
        shell_dep_limits_t configured = SHELL_DEP_LIMITS_DEFAULT;
        uint32_t value = independent[bound];
        if (budget == 0)
          configured.max_nodes = value;
        else if (budget == 1)
          configured.max_edges = value;
        else if (budget == 2)
          configured.max_tokens_per_cmd = value;
        else
          configured.cwd_buf_size = value == 1 ? 2 : value;
        shell_dep_graph_t graph = {0};
        shell_dep_error_t status =
            shell_dep_graph_parse(commands[command], strlen(commands[command]),
                                  "/work/base", &configured, &graph);
        ASSERT(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        ASSERT((status == SHELL_DEP_ETRUNC) ==
               ((graph.status & SHELL_DEP_STATUS_TRUNCATED) != 0));
        ASSERT((graph.status & SHELL_DEP_STATUS_ERROR) == 0);
        ASSERT(graph.node_count <= configured.max_nodes &&
               graph.edge_count <= configured.max_edges);
        ASSERT(shell_dep_graph_validate(&graph).valid);
      }
    }
  }
  pass_count++;
}

/* Document readers and CWD tracking expose bounded, caller-visible state.
 * Cover tab stripping and the resource boundaries through the public graph
 * contract rather than depending on incidental parser storage. */
/* A document is transient when its setup was evaluated and no byte flows
 * through it. A command that never executes evaluates nothing and keeps no
 * setup edge, so its documents carry no flag. */
TEST(unreached_documents_are_not_transient) {
  static const struct {
    const char *source;
    bool transient;
  } cases[] = {
      {"exec 3<<<x", true},
      {"exec 3<<EOF\nx\nEOF", true},
      {"exec {fd}<<<x; exec {fd}<&-", true},
      {"true && exec 3<<<x", true},
      {"false && exec 3<<<x", false},
      {"false && exec 3<<EOF\nx\nEOF", false},
      {"false && cat <<EOF\nx\nEOF", false},
      {"true || cat <<<x", false},
      {"false && exec {fd}<<<x", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_graph_t graph;
    ASSERT(parse(cases[i].source, &graph) == SHELL_DEP_OK);
    uint32_t documents = 0, transient = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type != SHELL_NODE_DOC ||
          (graph.nodes[node].doc.kind != SHELL_DOC_HEREDOC &&
           graph.nodes[node].doc.kind != SHELL_DOC_HERESTRING))
        continue;
      documents++;
      transient +=
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0;
    }
    ASSERT(documents == 1 && transient == (cases[i].transient ? 1u : 0u));
    ASSERT(shell_dep_graph_validate(&graph).valid);
  }
}

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
          count_internal_nodes(&normalized) == 1 &&
          normalized.cwd_buf.len == 2 &&
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
                                &tiny_cwd, &home_limited) == SHELL_DEP_OK &&
          !home_limited.nodes[find_cmd_tokens(&home_limited, "pwd", NULL)]
               .cmd.cwd_known &&
          shell_dep_graph_validate(&home_limited).valid &&
          shell_dep_graph_parse("cd ./relative; pwd",
                                strlen("cd ./relative; pwd"), ".", &tiny_cwd,
                                &relative_limited) == SHELL_DEP_ETRUNC &&
          shell_dep_graph_validate(&relative_limited).valid;

  shell_dep_graph_t deduplicated = {0};
  valid =
      valid &&
      shell_dep_graph_parse("cd /tmp && cd /tmp && pwd",
                            strlen("cd /tmp && cd /tmp && pwd"), ".", NULL,
                            &deduplicated) == SHELL_DEP_OK &&
      count_type(&deduplicated, SHELL_NODE_CMD) == 3 &&
      strcmp(deduplicated.cwd_buf.data +
                 deduplicated.nodes[find_cmd_tokens(&deduplicated, "pwd", NULL)]
                     .cmd.cwd_offset,
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
      count_type(&dynamic_cwd, SHELL_NODE_CMD) == 2 &&
      !dynamic_cwd.nodes[find_cmd_tokens(&dynamic_cwd, "pwd", NULL)]
           .cmd.cwd_known &&
      shell_dep_graph_validate(&dynamic_cwd).valid &&
      shell_dep_graph_parse("cd -; pwd", strlen("cd -; pwd"), ".", NULL,
                            &cd_dash) == SHELL_DEP_OK &&
      count_type(&cd_dash, SHELL_NODE_CMD) == 2 &&
      !cd_dash.nodes[find_cmd_tokens(&cd_dash, "pwd", NULL)].cmd.cwd_known &&
      shell_dep_graph_validate(&cd_dash).valid &&
      shell_dep_graph_parse("cd ~other; pwd", strlen("cd ~other; pwd"), ".",
                            NULL, &named_home) == SHELL_DEP_OK &&
      count_type(&named_home, SHELL_NODE_CMD) == 2 &&
      !named_home.nodes[find_cmd_tokens(&named_home, "pwd", NULL)]
           .cmd.cwd_known &&
      shell_dep_graph_validate(&named_home).valid &&
      shell_dep_graph_parse("cd /tmp -; pwd", strlen("cd /tmp -; pwd"), ".",
                            NULL, &invalid_cd) == SHELL_DEP_OK &&
      count_type(&invalid_cd, SHELL_NODE_CMD) == 2 &&
      invalid_cd.nodes[0].cmd.cwd_known &&
      strcmp(invalid_cd.cwd_buf.data + invalid_cd.nodes[0].cmd.cwd_offset,
             ".") == 0 &&
      shell_dep_graph_validate(&invalid_cd).valid &&
      shell_dep_graph_parse("cd - /tmp; pwd", strlen("cd - /tmp; pwd"), ".",
                            NULL, &dynamic_then_operand) == SHELL_DEP_OK &&
      count_type(&dynamic_then_operand, SHELL_NODE_CMD) == 2 &&
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

/* --- MAIN --- */

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "-v") == 0)
    verbose = true;

  printf("Running depgraph tests...\n\n");

  printf("Basic Commands:\n");
  RUN(supplied_fast_parser_contract);
  RUN(graph_pipeline_negation_parity);
  RUN(validation_diagnostic_invariants);

  printf("\nOperators:\n");
  RUN(bash_pipeline_time_report_routes);
  RUN(bash_pipeline_time_document_stages);
  RUN(descriptor_contract);
  RUN(exit_operand_and_status_transfer);
  RUN(scope_termination_descriptor_continuations);
  RUN(named_fd_allocation_cleanup);
  RUN(redirect_setup_outcome_substitutions);
  RUN(reachability_cwd_transitions);
  RUN(skipped_duplication_operand_syntax);
  RUN(bash_pipeline_time_external_count_validation);

  printf("\nRedirects:\n");
  RUN(legacy_combined_output_redirects);
  RUN(named_fd_unconnected_process_substitution_routes);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#endif
  RUN(named_fd_ifs_expansion_routes);
  RUN(named_fd_recursive_snapshot_timing);
  RUN(decoded_assignment_targets_and_env_docs);
  RUN(named_fd_route_cross_product_matrix);

  printf("\nCWD Tracking:\n");
  RUN(cwd_matrix);
  RUN(cwd_decoded_operand_matrix);
  RUN(cd_graph_visible_effects);
  RUN(file_identity_requires_directory);
  RUN(duplication_operand_does_not_take_the_next_redirect);
  RUN(final_backslash_is_a_literal_word);
  RUN(live_route_states_survive_journal_collection);
  RUN(named_fd_prefixed_process_substitution_is_a_word);
  RUN(bash_stdin_code_invocation_grammar);
  RUN(posix_brace_group_input_and_redirect);
  RUN(static_file_identity_and_effective_group_pipe_routes);
  RUN(predecoded_file_identity);
  RUN(exec_prepared_outcome_contract);
  RUN(prefix_binding_index_scaling);
  RUN(canonical_heredoc_delimiter_contract);
  RUN(adjacent_substitution_consumers);

  printf("\nEnvironment Variables:\n");

  printf("\nFile Arguments:\n");
  RUN(file_argument_positions);

  printf("\nSubshells:\n");

  printf("\nHeredocs and herestrings:\n");
  RUN(document_content_api_error_contract);
  RUN(expandable_heredoc_substitution_matrix);
  RUN(process_substitution_stream_topology);
  RUN(recursive_fd_import_final_routes);
  RUN(pipeline_group_scope_state);
  RUN(unconnected_process_redirect_replaces_descriptor);
  RUN(descriptor_metadata_scaling);
  RUN(nested_capture_publication_scaling);
  RUN(indexed_named_route_mutations);
  RUN(conditional_named_binding_invalidation);
  RUN(descriptor_import_identity_scaling);
  RUN(process_pipe_descriptor_installation);
  RUN(stream_resource_limit_contract);
  RUN(recursive_fd_import_survives_endpoint_pruning);
  RUN(composite_process_substitution_redirects);
  RUN(brace_group_process_substitution_recursion_limit);

  printf("\nError Handling:\n");
  RUN(null_input);
  RUN(resolver_workspace_contract);
  RUN(adversarial_limits);
  RUN(if_lists_are_alternatives_of_the_condition);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  RUN(union_memo_exhaustion_fails_closed);
#endif
  RUN(compounds_past_the_parser_capacity_truncate);
  RUN(limit_matrix);

  printf("\nGraph Integrity:\n");
  RUN(validation_matrix);
  RUN(validation_rejects_non_file_argument_documents);
  RUN(validation_rejects_malformed_named_fd_metadata);
  RUN(validation_rejects_ambiguous_fd_open_forms);
  RUN(validation_rejects_corrupt_counts_documents_and_endpoint_shapes);
  RUN(command_token_capacity);
  RUN(validation_rejects_malformed_group_metadata);
  RUN(validation_rejects_oob_topology_and_control_cycles);
  RUN(validation_defensive_diagnostics_matrix);
  RUN(resource_limit_cross_product_matrix);
  RUN(document_and_cwd_boundary_contract);
  RUN(unreached_documents_are_not_transient);

  printf("\nComplex:\n");
  RUN(graph_dump_contract);
  RUN(name_helpers);

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 || selection_matched_nothing() ? 1 : 0;
}
