#include "depgraph_invariants.h"
#include "shell_depgraph.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "failed: %s at %d\n", #condition, __LINE__);             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

typedef struct {
  const char *source;
  const char *payload;
  size_t payload_length;
  shell_expand_status_t status;
  size_t calls, arguments, redirects, files;
  bool seen[256];
  bool expect_absolute_cwd;
} fixture_t;

static shell_expand_status_t
expand_word(const shell_expand_word_request_t *request, const char **netargv,
            size_t *length, void *context) {
  fixture_t *fixture = context;
  CHECK(request->source == fixture->source);
  CHECK(request->source_length == strlen(fixture->source));
  CHECK(request->word_offset < request->source_length &&
        request->word_length <= request->source_length - request->word_offset);
  CHECK(request->owner_offset <= request->word_offset &&
        request->owner_length <=
            request->source_length - request->owner_offset);
  CHECK(request->word_offset < sizeof(fixture->seen));
  CHECK(!fixture->seen[request->word_offset]);
  fixture->seen[request->word_offset] = true;
  fixture->calls++;
  fixture->arguments += request->purpose == SHELL_EXPAND_WORD_ARGUMENT;
  fixture->redirects += request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH;
  fixture->files +=
      request->purpose == SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH;
  if (fixture->expect_absolute_cwd)
    CHECK(request->cwd_known && request->cwd_absolute &&
          strcmp(request->cwd, "/workspace") == 0);
  *netargv = fixture->payload;
  *length = fixture->payload_length;
  return fixture->status;
}

static bool equal_span(const char *left, size_t left_length, const char *right,
                       size_t right_length) {
  return left_length == right_length &&
         (left_length == 0 || memcmp(left, right, left_length) == 0);
}

static void check_unresolved_equivalence(const shell_dep_graph_t *plain,
                                         const shell_dep_graph_t *resolved) {
  CHECK(plain->node_count == resolved->node_count &&
        plain->edge_count == resolved->edge_count);
  CHECK(equal_span(plain->cwd_buf.data, plain->cwd_buf.len,
                   resolved->cwd_buf.data, resolved->cwd_buf.len));
  for (uint32_t i = 0; i < plain->node_count; i++) {
    const shell_dep_node_t *a = &plain->nodes[i], *b = &resolved->nodes[i];
    CHECK(a->type == b->type);
    if (a->type == SHELL_NODE_CMD) {
      CHECK(a->cmd.token_count == b->cmd.token_count &&
            a->cmd.effective_command_known == b->cmd.effective_command_known &&
            a->cmd.effective_command_token == b->cmd.effective_command_token &&
            a->cmd.effective_command_wrapper ==
                b->cmd.effective_command_wrapper &&
            a->cmd.cwd_offset == b->cmd.cwd_offset &&
            a->cmd.cwd_known == b->cmd.cwd_known &&
            a->cmd.cwd_absolute == b->cmd.cwd_absolute &&
            a->cmd.group_depth == b->cmd.group_depth &&
            a->cmd.group_kinds == b->cmd.group_kinds &&
            a->cmd.backgrounded == b->cmd.backgrounded &&
            a->cmd.pipeline_negation_count == b->cmd.pipeline_negation_count &&
            a->cmd.pipeline_negated == b->cmd.pipeline_negated &&
            a->cmd.pipeline_time_mode == b->cmd.pipeline_time_mode &&
            a->cmd.pipeline_time_id == b->cmd.pipeline_time_id &&
            a->cmd.pipe_stdin_source == b->cmd.pipe_stdin_source &&
            a->cmd.pipe_stdin_target == b->cmd.pipe_stdin_target &&
            a->cmd.pipe_stdout_source == b->cmd.pipe_stdout_source &&
            a->cmd.pipe_stdout_target == b->cmd.pipe_stdout_target);
      for (uint32_t j = 0; j < a->cmd.token_count; j++)
        CHECK(equal_span(a->cmd.tokens[j], a->cmd.token_lens[j],
                         b->cmd.tokens[j], b->cmd.token_lens[j]));
    } else if (a->type == SHELL_NODE_DOC) {
      CHECK(a->doc.kind == b->doc.kind && a->doc.flags == b->doc.flags &&
            a->doc.cwd_offset == b->doc.cwd_offset &&
            a->doc.cwd_known == b->doc.cwd_known &&
            a->doc.cwd_absolute == b->doc.cwd_absolute);
      CHECK(equal_span(a->doc.path, a->doc.path_len, b->doc.path,
                       b->doc.path_len));
      CHECK(equal_span(a->doc.name, a->doc.name_len, b->doc.name,
                       b->doc.name_len));
      CHECK(equal_span(a->doc.value, a->doc.value_len, b->doc.value,
                       b->doc.value_len));
    } else if (a->type == SHELL_NODE_GROUP) {
      CHECK(equal_span(a->group.start, a->group.length, b->group.start,
                       b->group.length));
      CHECK(a->group.parent == b->group.parent &&
            a->group.kind == b->group.kind &&
            a->group.pipeline_negation_count ==
                b->group.pipeline_negation_count &&
            a->group.pipeline_negated == b->group.pipeline_negated &&
            a->group.pipeline_time_mode == b->group.pipeline_time_mode &&
            a->group.pipeline_time_id == b->group.pipeline_time_id);
    }
  }
  for (uint32_t i = 0; i < plain->edge_count; i++) {
    const shell_dep_edge_t *a = &plain->edges[i], *b = &resolved->edges[i];
    CHECK(a->from == b->from && a->to == b->to && a->type == b->type &&
          a->dir == b->dir && a->flags == b->flags &&
          a->source_fd == b->source_fd && a->target_fd == b->target_fd);
    CHECK(equal_span(a->source_fd_name, a->source_fd_name_len,
                     b->source_fd_name, b->source_fd_name_len));
    CHECK(equal_span(a->target_fd_name, a->target_fd_name_len,
                     b->target_fd_name, b->target_fd_name_len));
  }
}

static void test_nested_and_conditional_resolution(shell_dep_limits_t *limits,
                                                   shell_dep_graph_t *graph) {
  static const struct {
    const char *source;
    size_t arguments, redirects, files;
    size_t unresolved;
    bool substitution;
  } cases[] = {
      {"false && cat <\"$IN\"", 0, 0, 0, 0, false},
      {"true || cat <\"$IN\"", 0, 0, 0, 0, false},
      {"maybe && cat <\"$IN\"", 0, 1, 0, 1, false},
      {"echo \"$(cat <\"$IN\")\"", 1, 1, 0, 1, true},
      {"{ { cat; }; } <\"$IN\"", 0, 1, 0, 1, false},
      {"cat $(<\"$IN\") | cat", 1, 0, 1, 1, true},
      {"cat < <(cat <\"$IN\")", 0, 1, 0, 1, true},
  };
  shell_dep_graph_t *plain = malloc(sizeof(*plain));
  CHECK(plain != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    for (unsigned mode = 0; mode < 3; mode++) {
      fixture_t fixture = {.source = source,
                           .payload = "9:/tmp/path,",
                           .payload_length = 12,
                           .status = mode == 2 ? SHELL_EXPAND_RESOLVED
                                               : SHELL_EXPAND_UNRESOLVED};
      memset(unresolved, 0xff, sizeof(unresolved));
      shell_dep_error_t error = shell_dep_graph_parse_resolved(
          source, length, NULL, limits, graph, mode ? expand_word : NULL,
          &fixture, unresolved);
      CHECK(error == SHELL_DEP_OK);
      CHECK(shellsplit_test_depgraph_invariants(source, length, error, graph,
                                                limits));
      CHECK(fixture.arguments == (mode ? cases[i].arguments : 0) &&
            fixture.redirects == (mode ? cases[i].redirects : 0) &&
            fixture.files == (mode ? cases[i].files : 0));
      size_t flags = 0;
      bool substitution = false, borrowed = false;
      for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++) {
        CHECK(unresolved[node] <= 1);
        if (node >= graph->node_count)
          CHECK(unresolved[node] == 0);
        flags += unresolved[node];
        if (node < graph->node_count &&
            graph->nodes[node].type == SHELL_NODE_DOC &&
            (graph->nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)) {
          CHECK(graph->nodes[node].doc.value == fixture.payload + 2 &&
                graph->nodes[node].doc.value_len == 9);
          borrowed = true;
        }
      }
      CHECK(flags == (mode == 2 ? 0 : cases[i].unresolved));
      CHECK(borrowed == (mode == 2 && (cases[i].redirects || cases[i].files)));
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        substitution |= graph->edges[edge].type == SHELL_EDGE_SUBST;
      CHECK(substitution == cases[i].substitution);
      if (mode < 2) {
        CHECK(shell_dep_graph_parse(source, length, NULL, limits, plain) ==
              SHELL_DEP_OK);
        check_unresolved_equivalence(plain, graph);
      }
    }
  }
  free(plain);
}

int main(void) {
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t required;
  CHECK(shell_dep_resolved_workspace_size(256, NULL, &required));
  void *workspace = malloc(required + shell_dep_workspace_alignment());
  shell_dep_graph_t *graph = malloc(sizeof(*graph));
  CHECK(workspace && graph);
  limits.workspace = workspace;
  limits.workspace_size = required;
  test_nested_and_conditional_resolution(&limits, graph);
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  static const struct {
    const char *source;
    size_t arguments, redirects, files;
    bool absolute_cwd;
  } cases[] = {
      {"echo \"$V\"", 1, 0, 0, false},
      {"cd /workspace && { echo \"$V\"; } >\"$OUT\"", 1, 1, 0, true},
      {"cat $(<\"$IN\")", 1, 0, 1, false},
      {"exec \"$V\"", 0, 0, 0, false},
      {"cd \"$V\"", 0, 0, 0, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    fixture_t fixture = {.source = cases[i].source,
                         .payload = "15:/tmp/value file,",
                         .payload_length = 19,
                         .status = SHELL_EXPAND_RESOLVED,
                         .expect_absolute_cwd = cases[i].absolute_cwd};
    CHECK(shell_dep_graph_parse_resolved(fixture.source, strlen(fixture.source),
                                         NULL, &limits, graph, expand_word,
                                         &fixture, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.arguments == cases[i].arguments &&
          fixture.redirects == cases[i].redirects &&
          fixture.files == cases[i].files);
    CHECK(shell_dep_graph_validate(graph).valid);
    for (size_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
      CHECK(unresolved[node] == 0);
    if (cases[i].redirects || cases[i].files) {
      bool borrowed_path = false;
      for (uint32_t node = 0; node < graph->node_count; node++)
        if (graph->nodes[node].type == SHELL_NODE_DOC &&
            graph->nodes[node].doc.value == fixture.payload + 3)
          borrowed_path = true;
      CHECK(borrowed_path);
    }
  }

  const char *source = "echo \"$V\"";
  static const char binary[] = {'3', ':', 'a', 0, 'b', ','};
  static const struct {
    shell_expand_status_t status;
    const char *data;
    size_t length;
    shell_dep_error_t expected;
  } values[] = {
      {SHELL_EXPAND_RESOLVED, binary, sizeof(binary), SHELL_DEP_OK},
      {SHELL_EXPAND_RESOLVED, NULL, 0, SHELL_DEP_OK},
      {SHELL_EXPAND_RESOLVED, "0:,", 3, SHELL_DEP_OK},
      {SHELL_EXPAND_UNRESOLVED, NULL, 100, SHELL_DEP_OK},
      {SHELL_EXPAND_FAILED, NULL, 0, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, "01:x,", 5, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, "2:x,", 4, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, NULL, 1, SHELL_DEP_EEXPAND},
      {(shell_expand_status_t)7, NULL, 0, SHELL_DEP_EEXPAND},
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    fixture_t fixture = {.source = source,
                         .payload = values[i].data,
                         .payload_length = values[i].length,
                         .status = values[i].status};
    memset(unresolved, 0xff, sizeof(unresolved));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                         graph, expand_word, &fixture,
                                         unresolved) == values[i].expected);
    CHECK(fixture.calls == 1);
    if (values[i].expected != SHELL_DEP_OK)
      CHECK(graph->node_count == 0 && graph->edge_count == 0);
    for (size_t node = 0; node < sizeof(unresolved); node++)
      CHECK(unresolved[node] == 0);
  }

  source = "{ echo ok; } >\"$OUT\"";
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  size_t flags = 0;
  for (size_t node = 0; node < sizeof(unresolved); node++)
    flags += unresolved[node] != 0;
  CHECK(flags == 1);
  fixture_t fixture = {.source = source,
                       .payload = binary,
                       .payload_length = sizeof(binary),
                       .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_word, &fixture,
                                       NULL) == SHELL_DEP_EEXPAND);
  fixture = (fixture_t){.source = source, .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_word, &fixture, NULL) ==
        SHELL_DEP_OK); /* Empty expansion is shell redirection failure. */
  CHECK(shell_dep_graph_validate(graph).valid);

  source = "echo \"$V\"; if true; then echo no; fi";
  fixture = (fixture_t){.source = source, .status = SHELL_EXPAND_UNRESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_word, &fixture,
                                       unresolved) == SHELL_DEP_EPARSE);
  CHECK(fixture.calls == 0);
  source = "echo \"$V\"";
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  limits.max_nodes = 1;
  source = "echo \"$V\" | cat";
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  memset(unresolved, 0xff, sizeof(unresolved));
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count <= 1);
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source),
                                            SHELL_DEP_ETRUNC, graph, &limits));
  for (size_t node = 0; node < sizeof(unresolved); node++) {
    CHECK(unresolved[node] <= 1);
    if (node >= graph->node_count)
      CHECK(unresolved[node] == 0);
  }
  limits.max_nodes = SHELL_DEP_LIMITS_DEFAULT.max_nodes;
  source = "cat <\"$IN\"";
  fixture = (fixture_t){.source = source,
                        .payload = "1:a,1:b,",
                        .payload_length = 8,
                        .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_word, &fixture,
                                       unresolved) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  CHECK(fixture.calls == 1);
  CHECK(shell_dep_graph_parse_resolved("", 0, NULL, &limits, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_EINPUT);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, NULL,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_EWORKSPACE);
  limits.workspace_size = required - 1;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  limits.workspace_size = required;
  limits.workspace = (char *)workspace + 1;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  limits.workspace = NULL;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  CHECK(!shell_dep_resolved_workspace_size(SIZE_MAX, NULL, &required));
  CHECK(required == 0);
  CHECK(strcmp(shell_dep_error_string(SHELL_DEP_EEXPAND),
               "Word resolution failed") == 0);
  free(graph);
  free(workspace);
  puts("public word resolution tests passed");
  return 0;
}
