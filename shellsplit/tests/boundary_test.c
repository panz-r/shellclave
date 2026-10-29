#include "../src/shell_builtin_internal.h"
#include "../src/shell_depgraph_internal.h"
#include "../src/shell_pipeline_internal.h"
#include "depgraph_compare.h"
#include "depgraph_invariants.h"
#include "graph_fixture.h"
#include "shell_depgraph.h"
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static uint32_t command(const shell_dep_graph_t *graph, const char *name) {
  size_t length = strlen(name);
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD && node->cmd.token_count &&
        node->cmd.token_lens[0] == length &&
        !memcmp(node->cmd.tokens[0], name, length))
      return i;
  }
  return UINT32_MAX;
}

static bool route(const shell_dep_graph_t *graph, uint32_t owner, uint32_t fd,
                  bool input, uint32_t inherited) {
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    uint32_t endpoint = input ? edge->from : edge->to;
    if (edge->type == (input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
        (input ? edge->to : edge->from) == owner &&
        (input ? edge->target_fd : edge->source_fd) == fd &&
        graph->nodes[endpoint].type == SHELL_NODE_FD &&
        graph->nodes[endpoint].fd.number == inherited)
      return true;
  }
  return false;
}

static void parse(const char *source, shell_dep_limits_t *limits,
                  shell_dep_graph_t *graph) {
  shell_dep_error_t status =
      shell_dep_graph_parse(source, strlen(source), "/", limits, graph);
  if (status != SHELL_DEP_OK)
    fprintf(stderr, "source: %s\nstatus: %d\n", source, status);
  CHECK(status == SHELL_DEP_OK);
  /* The invariant helper validates successful graphs before inspecting them. */
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source), status,
                                            graph, limits));
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      for (uint32_t j = 0; j < i; j++)
        CHECK(graph->nodes[j].type != SHELL_NODE_FD ||
              graph->nodes[j].fd.number != graph->nodes[i].fd.number);
}

static uint32_t implicit_input(const shell_dep_graph_t *graph) {
  uint32_t result = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_DOC &&
        (graph->nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
      CHECK(result == UINT32_MAX);
      result = node;
      CHECK(graph->nodes[node].doc.kind == SHELL_DOC_FILE);
      CHECK(graph->nodes[node].doc.flags == SHELL_DEP_DOC_FLAG_IMPLICIT);
      CHECK(graph->nodes[node].doc.path_len == 9);
      CHECK(!memcmp(graph->nodes[node].doc.path, "/dev/null", 9));
      CHECK(graph->nodes[node].doc.value == NULL &&
            graph->nodes[node].doc.name == NULL);
      bool used = false;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
        CHECK(graph->edges[edge].to != node);
        if (graph->edges[edge].from == node) {
          CHECK(graph->edges[edge].type == SHELL_EDGE_READ);
          used = true;
        }
      }
      CHECK(used);
    }
  return result;
}

static bool reads_implicit(const shell_dep_graph_t *graph, uint32_t owner,
                           uint32_t fd) {
  uint32_t input = implicit_input(graph);
  for (;;) {
    uint32_t parent = UINT32_MAX;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type == SHELL_EDGE_READ && item->from == input &&
          item->to == owner && item->target_fd == fd)
        return true;
      if (item->type == SHELL_EDGE_GROUP && item->to == owner)
        parent = item->from;
    }
    if (parent == UINT32_MAX)
      return false;
    owner = parent;
  }
}

static void background_newlines(shell_dep_limits_t *limits,
                                shell_dep_graph_t *graph,
                                shell_dep_graph_t *other) {
  static const char *const separators[] = {" ", "\n", " # note\n", "\n\n"};
  static const struct {
    const char *source;
    bool implicit;
  } stages[] = {{"wc -c", true},          {"true | wc -c", false},
                {"true |& wc -c", false}, {"time wc -c", true},
                {"true && wc -c", true},  {"false || wc -c", true},
                {"{ wc -c; }", true},     {"(wc -c)", true}};
  for (size_t stage = 0; stage < sizeof(stages) / sizeof(stages[0]); stage++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), "%s &%swait", stages[stage].source,
               separators[separator]);
      parse(source, limits, graph);
      uint32_t wc = command(graph, "wc"), wait = command(graph, "wait");
      CHECK(wc != UINT32_MAX && wait != UINT32_MAX);
      CHECK(graph->nodes[wc].cmd.backgrounded &&
            !graph->nodes[wait].cmd.backgrounded);
      CHECK(implicit_input(graph) != UINT32_MAX);
      if (reads_implicit(graph, wc, 0) != stages[stage].implicit)
        fprintf(stderr, "background stdin case: %s\n", source);
      CHECK(reads_implicit(graph, wc, 0) == stages[stage].implicit);
      CHECK(!reads_implicit(graph, wait, 0) && route(graph, wait, 0, true, 0));
      unsigned backgrounds = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        if (graph->edges[edge].type == SHELL_EDGE_BACKGROUND) {
          CHECK(graph->edges[edge].to == wait);
          backgrounds++;
        }
      CHECK(backgrounds == 1);
      shell_parse_result_t fast;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                            &fast, other) == SHELL_DEP_OK);
      CHECK(shellsplit_test_graph_equal(graph, other));
    }

  static const char *const recursive[] = {
      "printf '%%s' \"$(wc -c &%swait)\"", "cat <(wc -c &%swait)",
      "{ wc -c &%swait; }", "(wc -c &%swait)"};
  for (size_t item = 0; item < sizeof(recursive) / sizeof(recursive[0]); item++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), recursive[item], separators[separator]);
      parse(source, limits, graph);
      CHECK(reads_implicit(graph, command(graph, "wc"), 0));
      uint32_t wait = command(graph, "wait");
      unsigned backgrounds = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        backgrounds += graph->edges[edge].type == SHELL_EDGE_BACKGROUND &&
                       graph->edges[edge].to == wait;
      CHECK(backgrounds == 1);
      shell_parse_result_t fast;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                            &fast, other) == SHELL_DEP_OK);
      CHECK(shellsplit_test_graph_equal(graph, other));
    }

  static const char *const tails[] = {"\n", " # end\n", "\n\n# end\n"};
  for (size_t tail = 0; tail < sizeof(tails) / sizeof(tails[0]); tail++) {
    char source[128];
    snprintf(source, sizeof(source), "wc -c &%s", tails[tail]);
    parse(source, limits, graph);
    CHECK(graph->nodes[command(graph, "wc")].cmd.backgrounded);
    CHECK(reads_implicit(graph, command(graph, "wc"), 0));
  }

  static const char *const documents[] = {"wc -c 3<<EOF &\nbody\nEOF\nwait",
                                          "wc -c 3<<<body & # note\n\nwait"};
  for (size_t item = 0; item < sizeof(documents) / sizeof(documents[0]);
       item++) {
    parse(documents[item], limits, graph);
    CHECK(!reads_implicit(graph, command(graph, "wc"), 0));
    uint32_t wait = command(graph, "wait");
    unsigned backgrounds = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      backgrounds += graph->edges[edge].type == SHELL_EDGE_BACKGROUND &&
                     graph->edges[edge].to == wait;
    CHECK(backgrounds == 1 && route(graph, wait, 0, true, 0));
  }

  static const char *const isolated[] = {
      "exec 0<&- && true &%scat", "false || exec 0<&- &%scat",
      "cd /tmp && true &%scat", "cd /tmp && exec 0<&- &%scat",
      "exec 0<&- && true &%scd /tmp && true &\ncat"};
  for (size_t item = 0; item < sizeof(isolated) / sizeof(isolated[0]); item++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), isolated[item], separators[separator]);
      parse(source, limits, graph);
      uint32_t cat = command(graph, "cat");
      CHECK(cat != UINT32_MAX && route(graph, cat, 0, true, 0));
      CHECK(!reads_implicit(graph, cat, 0));
      CHECK(
          graph->nodes[cat].cmd.cwd_known &&
          !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
    }

  /* A newline after `&` retains its source span but advances Bash's input
   * unit. Newlines after binary connectors remain in the current unit. */
  static const struct {
    const char *source;
    uint16_t connector;
    uint32_t input_unit;
  } connectors[] = {{"wc &\nwait", SHELL_TYPE_BACKGROUND, 1},
                    {"wc & # note\n\nwait", SHELL_TYPE_BACKGROUND, 2},
                    {"true |\nwc", SHELL_TYPE_PIPELINE, 0},
                    {"true |&\nwc", SHELL_TYPE_PIPELINE, 0},
                    {"true &&\nwc", SHELL_TYPE_AND, 0},
                    {"false ||\nwc", SHELL_TYPE_OR, 0}};
  for (size_t item = 0; item < sizeof(connectors) / sizeof(connectors[0]);
       item++) {
    shell_parse_result_t fast;
    shell_pipeline_index_t index;
    const char *source = connectors[item].source;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(fast.count == 2);
    shell_pipeline_index_connectors(source, strlen(source), &fast, &index);
    CHECK(index.range_successor[0] == connectors[item].connector);
    CHECK(index.range_connector[1] == connectors[item].connector);
    CHECK(index.range_input_unit[0] == 0 &&
          index.range_input_unit[1] == connectors[item].input_unit);
  }
  static const char group_source[] = "wc & # note\n\n{ wait; }";
  shell_parse_result_t fast;
  shell_pipeline_index_t index;
  CHECK(shell_parse_fast(group_source, sizeof(group_source) - 1, NULL, &fast) ==
        SHELL_OK);
  CHECK(fast.group_count == 1);
  shell_pipeline_index_connectors(group_source, sizeof(group_source) - 1, &fast,
                                  &index);
  CHECK(index.group_connector[0] == SHELL_TYPE_BACKGROUND &&
        index.group_connector_start[0] == 3 &&
        index.group_connector_end[0] == 4 && index.group_input_unit[0] == 2);
}

static void async_completion(shell_dep_limits_t *limits,
                             shell_dep_graph_t *graph,
                             shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool reached;
  } cases[] = {
      {"{ false & } || printf bad >out", false},
      {"{ true & } || printf bad >out", false},
      {"{ exit 1 & } || printf bad >out", false},
      {"{ false & } && printf good >out", true},
      {"{ false & } && true || printf bad >out", false},
      {"{ false && true & } || printf bad >out", false},
      {"{ false || true & } || printf bad >out", false},
      {"{ { false; } & } || printf bad >out", false},
      {"{ (false) & } || printf bad >out", false},
      {"{ false | true & } || printf bad >out", false},
      {"{ time false & } || printf bad >out", false},
      {"{ ! true & } || printf bad >out", false},
      {"(false &) || printf bad >out", false},
      {"(false &) && printf good >out", true},
      {"{ { false & }; } || printf bad >out", false},
      {"{ (false &); } || printf bad >out", false},
      {"! { false & } && printf bad >out", false},
      {"! { false & } || printf good >out", true},
      {"time { false & } || printf bad >out", false},
      {"{ false &\n} || printf bad >out", false},
      {"{ false & # note\n\n} || printf bad >out", false},
      {"{ false & } || { printf bad >out; }", false},
      {"echo \"$( { false & } || printf bad >out )\"", false},
      {"echo \"$( { false & } && printf good >out )\"", true},
      {"cat <({ false & } || printf bad >out)", false},
      {"{ false; } || printf good >out", true},
      {"{ true; } || printf bad >out", false},
      {"{ false & true; } || printf bad >out", false},
      {"{ true & false; } || printf good >out", true},
      {"exit 0; { false & } && printf bad >out", false},
      {"UID=1; { false & } && printf bad >out", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, limits, graph);
    uint32_t marker = command(graph, "printf");
    CHECK(marker != UINT32_MAX);
    bool effects = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if ((item->type == SHELL_EDGE_READ && item->to == marker) ||
          (item->type == SHELL_EDGE_WRITE && item->from == marker))
        effects = true;
    }
    if (effects != cases[i].reached) {
      fprintf(stderr, "asynchronous completion: %s\n", cases[i].source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(effects == cases[i].reached);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  parse("{ false & } || exec 0<&-; cat", limits, graph);
  CHECK(route(graph, command(graph, "cat"), 0, true, 0));
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    CHECK(graph->edges[edge].type != SHELL_EDGE_FD_CLOSE);
  parse("{ false & } || cd /tmp; cat", limits, graph);
  uint32_t cat = command(graph, "cat");
  CHECK(cat != UINT32_MAX && graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  parse("{ false & } || export MARK=value; cat", limits, graph);
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    CHECK(graph->edges[edge].type != SHELL_EDGE_ENV);
}

static void standard_directions(shell_dep_limits_t *limits,
                                shell_dep_graph_t *graph,
                                shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    uint32_t local_fd, inherited;
    bool input, group;
  } cases[] = {
      {"wc 0>&1", 0, 1, false, false},
      {"wc 1<&0", 1, 0, true, false},
      {"wc 2<&0", 2, 0, true, false},
      {"wc 0>&1 1>&-", 0, 1, false, false},
      {"wc 1<&0 0<&-", 1, 0, true, false},
      {"wc 0>&1 0>&-", 0, SHELL_DEP_FD_NONE, false, false},
      {"wc 1<&0 1<&-", 1, SHELL_DEP_FD_NONE, true, false},
      {"wc 0>&1 0>&2", 0, 2, false, false},
      {"wc 1<&0 1<&2", 1, 2, true, false},
      {"exec 0>&1; wc", 0, 1, false, false},
      {"exec 1<&0; wc", 1, 0, true, false},
      {"exec 3>&1; wc 0>&3-", 0, 1, false, false},
      /* A self move leaves the descriptor unchanged and needs no sparse use. */
      {"wc 0>&0-", 0, SHELL_DEP_FD_NONE, false, false},
      {"{ wc; } 0>&1", 0, 1, false, true},
      {"{ wc; } 1<&0", 1, 0, true, true},
      {"echo \"$(wc 1<&0)\"", 1, 0, true, false},
      {"cat <(wc 1<&0)", 1, 0, true, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, limits, graph);
    uint32_t owner = command(graph, "wc");
    CHECK(owner != UINT32_MAX);
    if (cases[i].group)
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        if (graph->edges[edge].type == SHELL_EDGE_GROUP &&
            graph->edges[edge].to == owner) {
          owner = graph->edges[edge].from;
          break;
        }
    unsigned count = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type != (cases[i].input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) ||
          (cases[i].input ? item->to : item->from) != owner ||
          (cases[i].input ? item->target_fd : item->source_fd) !=
              cases[i].local_fd)
        continue;
      const shell_dep_node_t *resource =
          &graph->nodes[cases[i].input ? item->from : item->to];
      CHECK(resource->type == SHELL_NODE_FD &&
            resource->fd.number == cases[i].inherited);
      count++;
    }
    if (count != (cases[i].inherited != SHELL_DEP_FD_NONE ? 1u : 0u)) {
      fprintf(stderr, "standard direction case: %s\n", cases[i].source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(count == (cases[i].inherited != SHELL_DEP_FD_NONE ? 1u : 0u));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *source;
    bool input;
    uint32_t fd;
  } files[] = {{"wc 0>out", false, 0},
               {"wc 1<input", true, 1},
               {"wc 2<input", true, 2},
               {"wc 0<input 1>&0", true, 1},
               {"wc 0<input 1<&0-", true, 1}};
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    parse(files[i].source, limits, graph);
    uint32_t owner = command(graph, "wc");
    unsigned count = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      /* Opening read-only stderr can itself fail before installing that
       * route. Its shell diagnostic still uses the inherited writable fd 2. */
      bool setup_diagnostic = files[i].fd == 2 &&
                              item->type == SHELL_EDGE_WRITE &&
                              item->from == owner && item->source_fd == 2 &&
                              graph->nodes[item->to].type == SHELL_NODE_FD;
      CHECK(setup_diagnostic ||
            !(item->type ==
                  (files[i].input ? SHELL_EDGE_WRITE : SHELL_EDGE_READ) &&
              (files[i].input ? item->from : item->to) == owner &&
              (files[i].input ? item->source_fd : item->target_fd) ==
                  files[i].fd));
      if (item->type == (files[i].input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
          (files[i].input ? item->to : item->from) == owner &&
          (files[i].input ? item->target_fd : item->source_fd) == files[i].fd) {
        CHECK(graph->nodes[files[i].input ? item->from : item->to].type ==
              SHELL_NODE_DOC);
        count++;
      }
    }
    CHECK(count == 1);
  }
  parse("wc 0>&1 | cat", limits, graph);
  uint32_t writer = command(graph, "wc"), reader = command(graph, "cat");
  unsigned copies = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_PIPE && item->from == writer &&
        item->to == reader && item->source_fd == 0 && item->target_fd == 0)
      copies++;
  }
  CHECK(copies == 1);
  parse("echo \"$(wc 0>&1)\"", limits, graph);
  writer = command(graph, "wc");
  copies = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->from == writer && item->source_fd == 0 &&
        (item->type == SHELL_EDGE_WRITE || item->type == SHELL_EDGE_SUBST))
      copies++;
  }
  CHECK(copies == 1);
}

static void async_inputs(shell_dep_limits_t *limits, shell_dep_graph_t *graph,
                         shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool implicit;
  } cases[] = {
      {"wc -c &", true},
      {"wc -c <&0 &", false},
      {"wc -c 3<&0 &", true},
      {"wc -c 3</dev/null &", false},
      {": 3<<<\"$(wc -c)\" &", false},
      {"{ wc -c; } 3<<<value &", false},
      {"wc -c 0>&0 &", true},
      {"wc -c 0>&- &", false},
      {"wc -c 3<&0 0<&3- &", true},
      {"wc -c 3<&0 0<&\"3\"- &", true},
      {"wc -c 3<&0 0<&3\\- &", true},
      {"{ wc -c <&0; } &", true},
      {"{ wc -c & } &", true},
      {"{ { wc -c; } & } &", true},
      {"{ wc -c; } <&0 &", false},
      {"{ wc -c & wait; } <&0", false},
      {"{ :; } <&0; wc -c &", false},
      {"{ :; } <&0\nwc -c &", false},
      {"{ :; } <&0; (true); wc -c &", false},
      {"{ :; } <&0; (wc -c & wait)", true},
      {"{ :; } <&0; { :; } 2>&1; wc -c &", true},
      {"cat | { wc -c & wait; }", false},
      {"{ :; } <&0; true | (true); wc -c &", false},
      {"cat <(wc -c)", false},
      {"printf '%s' \"$(wc -c)\" &", false},
      {"value=$(wc -c) &", false},
      {"! printf '%s' \"$(wc -c)\" &", false},
      {"printf '%s' \"$(wc -c)\" | cat &", false},
      {"time printf '%s' \"$(wc -c)\" &", true},
      {"true && printf '%s' \"$(wc -c)\" &", true},
      {"false || printf '%s' \"$(wc -c)\" &", true},
      {": 3>\"$(wc -c >&2; printf /dev/null)\" &", true},
      {"{ { printf '%s' \"$(wc -c)\"; }; } &", true},
      {"exec {fd}<&0; wc -c <&$fd &", false},
      {"UID=1\nwc -c & wait", true},
      {"UID=1\ntime wc -c & wait", true},
      {"UID=1\n{ wc -c; } & wait", true},
      {"UID=1\ntrue && wc -c & wait", true},
      {"UID=1\nfalse || wc -c & wait", true},
      {"UID=1\ntrue && printf '%s' \"$(wc -c)\" & wait", true},
      {"UID=1\nvalue=$(wc -c) & wait", false},
      {"UID=1\n: 3>\"$(wc -c >&2; printf /dev/null)\" & wait", true},
      {"UID=1; time wc -c & wait", false},
      {"UID=1; : &\nwc -c &\nwait", true},
      {"UID=1; : & # note\n\nwc -c &\nwait", true},
      {"UID=1; { :; } &\nwc -c &\nwait", true},
      {"UID=1; time : &\nwc -c &\nwait", true},
      {"UID=1; : &\ntrue && wc -c &\nwait", true},
      {"UID=1; : & wc -c &\nwait", false},
      {"exit 0; : &\nwc -c &\nwait", false},
      {"exit 0\ntime wc -c & wait", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, limits, graph);
    uint32_t wc = command(graph, "wc");
    CHECK(wc != UINT32_MAX);
    if (reads_implicit(graph, wc, 0) != cases[i].implicit)
      fprintf(stderr, "async case: %s\n", cases[i].source);
    CHECK(reads_implicit(graph, wc, 0) == cases[i].implicit);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  parse("wc -c &", limits, graph);
  uint32_t wc = command(graph, "wc");
  CHECK(route(graph, wc, 0, true, 0)); /* Nonfatal implicit-open failure. */
  CHECK(reads_implicit(graph, wc, 0));
  uint32_t implicit = implicit_input(graph);
  *other = *graph;
  other->nodes[implicit].doc.path = NULL;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[implicit].doc.flags |= SHELL_DEP_DOC_FLAG_TRANSIENT;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] = graph->nodes[implicit];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[other->edge_count - 1].type = SHELL_EDGE_WRITE;
  CHECK(!shell_dep_graph_validate(other).valid);
  parse("wc -c 3<&0 &", limits, graph);
  CHECK(reads_implicit(graph, command(graph, "wc"), 3));
  parse("wc -c & cat", limits, graph);
  CHECK(!reads_implicit(graph, command(graph, "cat"), 0));
  CHECK(route(graph, command(graph, "cat"), 0, true, 0));
  parse("true && exec 0<&- & cat", limits, graph);
  CHECK(route(graph, command(graph, "cat"), 0, true, 0));
  CHECK(!reads_implicit(graph, command(graph, "cat"), 0));
  parse("cd /tmp && true & cat", limits, graph);
  uint32_t cat = command(graph, "cat");
  CHECK(graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  parse("exec 0<before || exit; UID=1\n"
        "cd /tmp && true & cat",
        limits, graph);
  cat = command(graph, "cat");
  CHECK(graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  unsigned parent_reads = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_READ && item->to == cat &&
        item->target_fd == 0) {
      const shell_dep_node_t *resource = &graph->nodes[item->from];
      CHECK(resource->type == SHELL_NODE_DOC && resource->doc.path_len == 6 &&
            !memcmp(resource->doc.path, "before", 6));
      parent_reads++;
    }
  }
  CHECK(parent_reads == 1 && !reads_implicit(graph, cat, 0));
  parse("true || wc -c &", limits, graph);
  CHECK(implicit_input(graph) !=
        UINT32_MAX); /* true executes in the wrapper. */
  parse("false && { wc; } &", limits, graph);
  CHECK(!reads_implicit(graph, command(graph, "wc"), 0));
  parse("exec 0<&-; wc -c &", limits, graph);
  CHECK(reads_implicit(graph, command(graph, "wc"), 0));
  parse(">out &", limits, graph);
  CHECK(implicit_input(graph) == UINT32_MAX);
  parse("exec 2>&1 &", limits, graph);
  CHECK(implicit_input(graph) == UINT32_MAX);
  parse("time { exec 2<&0; wc; } &", limits, graph);
  CHECK(reads_implicit(graph, command(graph, "wc"), 0));
  bool unavailable = false;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_TIME)
      unavailable |= (graph->nodes[node].time.report_route_flags &
                      SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) != 0;
  CHECK(unavailable);
  parse("{ : >& }; wc; }", limits, graph);
  bool literal_closer = false;
  for (uint32_t node = 0; node < graph->node_count; node++)
    literal_closer |= graph->nodes[node].type == SHELL_NODE_DOC &&
                      graph->nodes[node].doc.kind == SHELL_DOC_FILE &&
                      graph->nodes[node].doc.path_len == 1 &&
                      graph->nodes[node].doc.path[0] == '}';
  CHECK(literal_closer);
  static const char malformed[] = "{ wc && }";
  CHECK(shell_dep_graph_parse(malformed, sizeof(malformed) - 1, "/", limits,
                              graph) == SHELL_DEP_EPARSE);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
}

static void timing_destinations(shell_dep_limits_t *limits,
                                shell_dep_graph_t *graph,
                                shell_dep_graph_t *other) {
  static const char source[] = "probe && exec 2>&1; time wc";
  parse(source, limits, graph);
  uint32_t timer = UINT32_MAX, first = UINT32_MAX, second = UINT32_MAX;
  uint32_t unused_destination = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type == SHELL_NODE_TIME)
      timer = node;
    if (graph->nodes[node].type == SHELL_NODE_FD &&
        graph->nodes[node].fd.number == 0)
      unused_destination = node;
  }
  CHECK(timer != UINT32_MAX && unused_destination != UINT32_MAX);
  CHECK(graph->nodes[timer].time.report_external_fd_count == 2);
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    if (graph->edges[edge].from == timer &&
        graph->edges[edge].type == SHELL_EDGE_WRITE &&
        graph->nodes[graph->edges[edge].to].type == SHELL_NODE_FD) {
      if (first == UINT32_MAX)
        first = edge;
      else {
        CHECK(second == UINT32_MAX);
        second = edge;
      }
    }
  CHECK(first != UINT32_MAX && second != UINT32_MAX);
  *other = *graph;
  other->edges[second].to = other->edges[first].to;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[second] = other->edges[--other->edge_count];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[second].to = unused_destination;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  shell_dep_time_t *time = &other->nodes[timer].time;
  uint32_t swap = time->report_external_fds[0];
  time->report_external_fds[0] = time->report_external_fds[1];
  time->report_external_fds[1] = swap;
  CHECK(shell_dep_graph_validate(other).valid);
  CHECK(shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                            SHELL_DEP_OK, other, limits));
  *other = *graph;
  other->edges[second] = other->edges[--other->edge_count];
  time = &other->nodes[timer].time;
  time->report_external_fd_count = 1;
  time->report_external_fds[0] = other->nodes[other->edges[first].to].fd.number;
  time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNKNOWN;
  other->status = SHELL_DEP_STATUS_TRUNCATED;
  CHECK(shell_dep_graph_validate(other).valid);
  CHECK(shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                            SHELL_DEP_ETRUNC, other, limits));
}

typedef struct {
  const char *word;
  unsigned calls;
} recovery_resolution_t;

static shell_expand_status_t
recovery_resolve(const shell_expand_word_request_t *request,
                 const char **netargv, size_t *length, void *context) {
  recovery_resolution_t *fixture = context;
  CHECK(request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH);
  CHECK(request->source + request->word_offset == fixture->word &&
        request->word_length == strlen("\"$(wc -c)\""));
  CHECK(request->cwd_known && request->cwd_absolute &&
        !strcmp(request->cwd, "/"));
  fixture->calls++;
  *netargv = "3:out,";
  *length = sizeof("3:out,") - 1;
  return SHELL_EXPAND_RESOLVED;
}

static void recovery_resolution(shell_dep_limits_t *limits,
                                shell_dep_graph_t *graph,
                                shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    unsigned calls;
    bool implicit;
  } cases[] = {
      {"UID=1\ntime : >\"$(wc -c)\" & cat", 1, true},
      {"UID=1\ntrue && : >\"$(wc -c)\" & cat", 1, true},
      {"{ false & } || : >\"$(wc -c)\"; cat", 0, false},
      {"(false &) || : >\"$(wc -c)\"; cat", 0, false},
      {"{ { false & }; } || : >\"$(wc -c)\"; cat", 0, false},
      {"{ false & } && : >\"$(wc -c)\"; cat", 1, false},
      {"! { false & } || : >\"$(wc -c)\"; cat", 1, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    recovery_resolution_t fixture = {strstr(source, "\"$(wc -c)\""), 0};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph, recovery_resolve, &fixture,
                                         unresolved) == SHELL_DEP_OK);
    CHECK(fixture.calls == cases[i].calls &&
          shell_dep_graph_validate(graph).valid);
    CHECK(reads_implicit(graph, command(graph, "wc"), 0) == cases[i].implicit);
    CHECK(!reads_implicit(graph, command(graph, "cat"), 0));
    if (!cases[i].calls)
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        CHECK(graph->edges[edge].type != SHELL_EDGE_SUBST);
    for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
      CHECK(unresolved[node] == 0);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    fixture.calls = 0;
    shell_expand_cache_t cache;
    shell_dep_limits_t graph_limits = *limits;
    CHECK(shell_expand_cache_init(
        recovery_resolve, &fixture, source, strlen(source), false,
        limits->workspace, limits->workspace_size, &cache,
        &graph_limits.workspace, &graph_limits.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &graph_limits, &fast, other,
              &resolver, unresolved) == SHELL_DEP_OK);
    CHECK(cache.error == SHELL_DEP_OK && fixture.calls == cases[i].calls &&
          shellsplit_test_graph_equal(graph, other));
  }
}

typedef struct {
  const char *netargv;
  shell_expand_status_t status;
  unsigned paths, later;
} diagnostic_resolution_t;

static shell_expand_status_t
diagnostic_resolve(const shell_expand_word_request_t *request,
                   const char **netargv, size_t *length, void *context) {
  diagnostic_resolution_t *fixture = context;
  if (request->purpose != SHELL_EXPAND_WORD_REDIRECT_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  const char *word = request->source + request->word_offset;
  if (request->word_length == 7 && !memcmp(word, "\"$path\"", 7)) {
    fixture->paths++;
    if (fixture->status == SHELL_EXPAND_RESOLVED) {
      *netargv = fixture->netargv;
      *length = strlen(*netargv);
    }
    return fixture->status;
  }
  CHECK(request->word_length == 8 && !memcmp(word, "\"$later\"", 8));
  fixture->later++;
  *netargv = "4:next,";
  *length = 7;
  return SHELL_EXPAND_RESOLVED;
}

static void diagnostic_resolution(shell_dep_limits_t *limits,
                                  shell_dep_graph_t *graph,
                                  shell_dep_graph_t *other) {
  static const struct {
    const char *value;
    shell_expand_status_t status;
    bool stopped;
  } cases[] = {{"", SHELL_EXPAND_RESOLVED, true},
               {"0:,", SHELL_EXPAND_RESOLVED, true},
               {"1:a,1:b,", SHELL_EXPAND_RESOLVED, true},
               {"3:out,", SHELL_EXPAND_RESOLVED, false},
               {NULL, SHELL_EXPAND_UNRESOLVED, false}};
  const char *source = "sh -c \"$(echo 2>&1 >\"$path\" >\"$later\")\"";
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    diagnostic_resolution_t fixture = {cases[i].value, cases[i].status, 0, 0};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph, diagnostic_resolve, &fixture,
                                         unresolved) == SHELL_DEP_OK);
    CHECK(fixture.paths == 1 && fixture.later == !cases[i].stopped);
    bool diagnostic = false, body = false;
    uint32_t echo = command(graph, "echo");
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      diagnostic |= edge->type == SHELL_EDGE_SUBST && edge->from == echo &&
                    edge->source_fd == 2;
      body |= edge->type == SHELL_EDGE_READ && edge->to == echo;
    }
    CHECK(diagnostic && body == !cases[i].stopped);
    CHECK(shell_dep_graph_validate(graph).valid);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    fixture.paths = fixture.later = 0;
    shell_expand_cache_t cache;
    shell_dep_limits_t graph_limits = *limits;
    CHECK(shell_expand_cache_init(
        diagnostic_resolve, &fixture, source, strlen(source), false,
        limits->workspace, limits->workspace_size, &cache,
        &graph_limits.workspace, &graph_limits.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &graph_limits, &fast, other,
              &resolver, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.paths == 1 && fixture.later == !cases[i].stopped);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  diagnostic_resolution_t failure = {NULL, SHELL_EXPAND_FAILED, 0, 0};
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                       graph, diagnostic_resolve, &failure,
                                       unresolved) == SHELL_DEP_EEXPAND);
  CHECK(failure.paths == 1 && failure.later == 0);
}

static void cd_commands(shell_dep_limits_t *limits, shell_dep_graph_t *graph,
                        shell_dep_graph_t *other) {
  static const struct {
    const char *source, *spelling, *cwd;
  } cases[] = {
      {"cd /tmp; pwd", "cd", NULL},
      {"c'd' /tmp; pwd", "c'd'", NULL},
      {"command cd /tmp; pwd", "command", NULL},
      {"builtin cd /tmp; pwd", "builtin", NULL},
      {"cd one two; pwd", "cd", "/"},
      {"false && cd /tmp; pwd", "cd", "/"},
      {"(cd /tmp); pwd", "cd", "/"},
      {"cd /tmp | true; pwd", "cd", "/"},
      {"cd /tmp & pwd", "cd", "/"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, limits, graph);
    uint32_t cd = command(graph, cases[i].spelling);
    uint32_t pwd = command(graph, "pwd");
    CHECK(cd != UINT32_MAX && pwd != UINT32_MAX);
    CHECK(graph->nodes[cd].cmd.cwd_known &&
          !strcmp(graph->cwd_buf.data + graph->nodes[cd].cmd.cwd_offset, "/"));
    CHECK(graph->nodes[pwd].cmd.cwd_known == (cases[i].cwd != NULL));
    if (cases[i].cwd)
      CHECK(!strcmp(graph->cwd_buf.data + graph->nodes[pwd].cmd.cwd_offset,
                    cases[i].cwd));
    bool cwd_edge = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      cwd_edge |= graph->edges[edge].type == SHELL_EDGE_CWD &&
                  graph->edges[edge].from == cd && graph->edges[edge].to == cd;
    CHECK(cwd_edge == (i != 5));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *source;
    bool capture;
  } captures[] = {
      {"sh -c \"$(exec 2>&1; cd one two)\"", true},
      {"sh -c \"$(cd /; cd -)\"", true},
      {"sh -c \"$({ exec 2>&1; cd one two; })\"", true},
      {"sh -c \"$(exec 2>&1; command cd one two)\"", true},
      {"sh -c \"$(exec 2>&1; builtin cd one two)\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; cd one two)\"", false},
      {"sh -c \"$(false >&- 2>&- && cd one two)\"", false},
  };
  for (size_t i = 0; i < sizeof(captures) / sizeof(captures[0]); i++) {
    const char *source = captures[i].source;
    parse(source, limits, graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      capture |= graph->edges[edge].type == SHELL_EDGE_SUBST;
    if (capture != captures[i].capture)
      fprintf(stderr, "cd capture: %s\n", source);
    CHECK(capture == captures[i].capture);
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }

  parse("exec 2>error; cd one two", limits, graph);
  uint32_t cd = command(graph, "cd");
  bool stderr_file = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    const shell_dep_node_t *to = &graph->nodes[item->to];
    stderr_file |= item->type == SHELL_EDGE_WRITE && item->from == cd &&
                   item->source_fd == 2 && to->type == SHELL_NODE_DOC &&
                   to->doc.path_len == 5 && !memcmp(to->doc.path, "error", 5);
  }
  CHECK(stderr_file);
}

static void owner_stream_inventory(shell_dep_limits_t *limits,
                                   shell_dep_graph_t *graph,
                                   shell_dep_graph_t *other) {
  static const char *const cases[] = {
      "exec 30>&1; printf data 31>&30 31>&- 31>&30",
      "exec 30>&1; printf data 31>&30 | cat",
      "exec 30>out; printf data 31>&30",
      "exec 30>&1; { printf data 31>&30; } 2>&1",
      "sh -c \"$(exec 30>&1; printf data 31>&30 31>&- 31>&30)\"",
      "exec {fd}>&1; printf data >&$fd",
      "exec 30>&1; printf data 0>&30 1<&0 2>&-",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i], limits, graph);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i], strlen(cases[i]), NULL, &fast) ==
          SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i], strlen(cases[i]), "/",
                                          limits, &fast,
                                          other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(cases[i], strlen(cases[i]), "/",
                                         limits, other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    uint32_t owner = command(graph, "printf");
    CHECK(owner != UINT32_MAX);
    if (i < 2 || i == 3)
      CHECK(route(graph, owner, 31, false, 1));
    if (i == 6)
      CHECK(route(graph, owner, 0, false, 1) &&
            route(graph, owner, 1, false, 1) &&
            !route(graph, owner, 2, false, 2));
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned family = 0; family < 2; family++) {
    size_t previous = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[2048] = "";
      size_t length = 0;
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(source + length, sizeof(source) - length,
                                   "exec %u>&1; %s", 30 + i,
                                   family == 0 ? ":; " : "");
      if (family == 1)
        for (unsigned i = 0; i < count; i++)
          strcat(source, ":; ");
      shellsplit_test_source_scan_reset();
      parse(source, limits, graph);
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_OWNER_STREAMS);
      CHECK(work > 0 && work <= 96 * count &&
            (!previous || work <= 3 * previous));
      previous = work;
    }
  }
#endif
}

static void assignment_effects(shell_dep_limits_t *limits,
                               shell_dep_graph_t *graph,
                               shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    uint32_t environments, substitutions;
  } cases[] = {
      {"UID=1 true", 0, 0},
      {"UID+=1 true", 0, 0},
      {"U\\\nID=1 true", 0, 0},
      {"UID=1 command true", 0, 0},
      {"UID=1 builtin true", 0, 0},
      {"first=ok UID=1 last=ok true", 2, 0},
      {"first=ok UID=1 last=ok", 1, 0},
      {"UID=1 EUID=2 true", 0, 0},
      {"x=$(printf data) UID=$(printf ignored) last=ok true", 2, 1},
      {"UID=$(printf skipped) true", 0, 0},
      {"UID=$(printf data) $missing", 0, 1},
      {"UID=$(printf data) $(true)", 0, 2},
      {"UID=$(printf marker >&2; printf data) $(true)", 0, 2},
      {"UID=$(printf data) $first $second", 0, 1},
      {"UID=$(printf data) \"$@\"", 0, 1},
      {"UID=$(printf data) \"${!prefix@}\"", 0, 1},
      {"UID=$(printf data) ${!prefix*}", 0, 1},
      {"UID=$(printf data) ${@:-}", 0, 1},
      {"UID=$(printf data) \"${@:+data}\"", 0, 1},
      {"UID=$(printf data) \"${@:99}\"", 0, 1},
      {"UID=$(printf skipped) \"${!prefix*}\"", 0, 0},
      {"UID=$(printf skipped) \"${!pre\\\nfix\\\n*}\"", 0, 0},
      {"UID=$(printf skipped) \"${@-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${@-}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-\"$@\"}\"", 0, 0},
      {"UID=$(printf skipped) \"${@?error}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:?error}\"", 0, 0},
      {"UID=$(printf skipped) \"${\\\n@:\\\n-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${!prefix@}\"suffix", 0, 0},
      {"UID=$(printf data) {,}", 0, 1},
      {"UID=$(printf skipped) ''", 0, 0},
      {"UID=$(printf skipped) \"$missing\"", 0, 0},
      {"UID=$(printf skipped) \"${missing:-}\"", 0, 0},
      {"UID=$(printf skipped) \"$(true)\"", 0, 1},
      {"UID=$(printf skipped) $missing true", 0, 0},
      {"UID=$(printf skipped) $missing \"\"", 0, 0},
      {"UID=$(printf skipped) \"$@\"\"\"", 0, 0},
      {"UID=$(printf skipped) literal$missing", 0, 0},
      {"UID=$(printf skipped) $missing-suffix", 0, 0},
      {"UID=$(printf skipped) $''", 0, 0},
      {"UID=$(printf skipped) *", 0, 0},
      {"UID=$(printf skipped) {,}suffix", 0, 0},
      {"UID=$(printf skipped) {a,b}", 0, 0},
      {"UID=$(printf skipped) {a,$missing}", 0, 0},
      {"UID=$(printf skipped) {\"\",}", 0, 0},
      {"x=$(printf first) UID=$(printf data) last=$(printf last) $maybe", 2, 3},
      {"UID=$(printf data) EUID=$(printf skipped) $maybe", 0, 1},
      {"UID=$(printf data) $maybe 3>$(printf /dev/null)", 0, 1},
      {"false && UID=$(printf skipped) $maybe", 0, 0},
      {"(UID=$(printf data) $maybe)", 0, 1},
      {"{ UID=$(printf data) $maybe; }", 0, 1},
      {"UID=$(printf data) $maybe | true", 0, 1},
      {"UID=$(printf data) $maybe & true", 0, 1},
      {"UID=${missing:?skipped} true; x=kept", 1, 0},
      {"UID=$(printf data) later=$(printf skipped)", 0, 1},
      {"export UID=$(printf data)", 0, 1},
      {"export -Z x=$(printf data)", 0, 1},
      {"export UID=1", 0, 0},
      {"export -p UID=1 x=2", 1, 0},
      {"export -- UID=1 EUID+=2 x=3", 1, 0},
      {"export 'U''ID=1' x=2", 1, 0},
      {"command export UID=1 x=2", 1, 0},
      {"builtin export UID=1 x=2", 1, 0},
      {"export -Z x=1", 0, 0},
      {"export -f UID=1 x=2", 0, 0},
      {"false && UID=1 true", 0, 0},
      {"false && export x=1", 0, 0},
      {"sh -c \"$(exec 2>&1; UID=$(printf skipped) true 1>&- 2>&-)\"", 0, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    parse(source, limits, graph);
    uint32_t environments = 0, substitutions = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      environments += graph->edges[edge].type == SHELL_EDGE_ENV;
      substitutions +=
          graph->edges[edge].type == SHELL_EDGE_SUBST &&
          (graph->edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
    }
    if (environments != cases[i].environments ||
        substitutions != cases[i].substitutions)
      fprintf(stderr, "assignment effects: %s (%u ENV, %u SUBST)\n", source,
              environments, substitutions);
    CHECK(environments == cases[i].environments &&
          substitutions == cases[i].substitutions);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }
}

static void assignment_streams(shell_dep_limits_t *limits,
                               shell_dep_graph_t *graph,
                               shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool captured, diagnostic;
  } cases[] = {
      {"sh -c \"$(x=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; x=1)\"", false, false},
      {"sh -c \"$(x=$(printf data))\"", false, false},
      {"sh -c \"$(<<<\"$(printf data)\")\"", false, true},
      {"sh -c \"$(UID=1)\"", false, true},
      {"sh -c \"$(UID=1 2>&1)\"", false, true},
      {"sh -c \"$(exec 2>&1; UID=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID+=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; U\\\nID=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1)\"", false, false},
      {"sh -c \"$(false >&- 2>&- && UID=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; UID=1 true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 command true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 builtin true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1 true 1>&- 2>&-)\"", false, false},
      {"sh -c \"$({ UID=1 true 1>&- 2>&-; } 2>&1)\"", true, true},
      {"sh -c \"$(>out 2>&1)\"", false, true},
      {"sh -c \"$(2>&1 >out)\"", true, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    parse(source, limits, graph);
    uint32_t shell = command(graph, "sh");
    bool captured = false, diagnostic = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      captured |= item->type == SHELL_EDGE_SUBST && item->to == shell &&
                  (item->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
      const shell_dep_node_t *owner = &graph->nodes[item->from];
      bool assignment_owner = owner->type == SHELL_NODE_GROUP;
      if (owner->type == SHELL_NODE_CMD) {
        const shell_dep_cmd_t *stage = &owner->cmd;
        assignment_owner = stage->token_count == 0 ||
                           (stage->token_lens[0] == 4 &&
                            !memcmp(stage->tokens[0], "true", 4)) ||
                           (stage->token_lens[0] == 7 &&
                            (!memcmp(stage->tokens[0], "command", 7) ||
                             !memcmp(stage->tokens[0], "builtin", 7)));
      }
      diagnostic |=
          item->source_fd == 2 &&
          (item->type == SHELL_EDGE_SUBST || item->type == SHELL_EDGE_WRITE) &&
          item->from != shell && assignment_owner;
    }
    if (captured != cases[i].captured || diagnostic != cases[i].diagnostic) {
      fprintf(stderr, "assignment stream: %s\n", source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(captured == cases[i].captured && diagnostic == cases[i].diagnostic);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }
  parse("UID=1", limits, graph);
  CHECK(route(graph, 0, 2, false, 2));
  CHECK(!route(graph, 0, 1, false, 1) && !route(graph, 0, 0, true, 0));
  parse("x=1", limits, graph);
  CHECK(graph->node_count == 2 && graph->edge_count == 1 &&
        graph->edges[0].type == SHELL_EDGE_ENV);
  parse("exec 2>error; UID=1", limits, graph);
  bool file_diagnostic = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    const shell_dep_node_t *target = &graph->nodes[item->to];
    file_diagnostic |= item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
                       graph->nodes[item->from].type == SHELL_NODE_CMD &&
                       graph->nodes[item->from].cmd.token_count == 0 &&
                       target->type == SHELL_NODE_DOC &&
                       target->doc.path_len == 5 &&
                       !memcmp(target->doc.path, "error", 5);
  }
  CHECK(file_diagnostic);
  static const struct {
    const char *source;
    bool capture;
  } process_setup[] = {
      {"< <(true)", false},
      {"> >(true)", false},
      /* Bash's file-command shortcut actually reads the process descriptor. */
      {"sh -c \"$(< <(true))\"", true},
      /* The consumer's own stdout still inherits the enclosing capture. */
      {"sh -c \"$(> >(true))\"", true}};
  for (size_t i = 0; i < sizeof(process_setup) / sizeof(process_setup[0]);
       i++) {
    parse(process_setup[i].source, limits, graph);
    bool setup = false, capture = false;
    uint32_t shell = command(graph, "sh");
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      setup |= item->type == SHELL_EDGE_FD_OPEN;
      capture |= item->type == SHELL_EDGE_SUBST && item->to == shell &&
                 (item->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
    }
    CHECK((setup || i == 2) && capture == process_setup[i].capture);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "UID=1 true;");
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned n = count; n; n >>= 1)
      height++;
    CHECK(work > 0 && work <= 64 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

typedef struct {
  unsigned arguments, paths;
  bool fail;
} nullable_resolution_t;

static shell_expand_status_t
nullable_resolve(const shell_expand_word_request_t *request,
                 const char **netargv, size_t *length, void *context) {
  nullable_resolution_t *fixture = context;
  const char *word = request->source + request->word_offset;
  if (request->purpose == SHELL_EXPAND_WORD_ARGUMENT) {
    CHECK(request->word_length == sizeof("\"$payload\"") - 1 &&
          !memcmp(word, "\"$payload\"", request->word_length));
    fixture->arguments++;
  } else {
    CHECK(request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH &&
          request->word_length == sizeof("\"$path\"") - 1 &&
          !memcmp(word, "\"$path\"", request->word_length));
    fixture->paths++;
  }
  *netargv = NULL;
  *length = 0;
  return fixture->fail ? SHELL_EXPAND_FAILED : SHELL_EXPAND_UNRESOLVED;
}

static void nullable_assignments(shell_dep_limits_t *limits,
                                 shell_dep_graph_t *graph,
                                 shell_dep_graph_t *other) {
  static const struct {
    const char *word;
    bool survives;
  } words[] = {
      {"$missing", false},
      {"${missing:-}", false},
      {"$(true)", false},
      {"`true`", false},
      {"$((1+2))", false},
      {"\"$@\"", false},
      {"\"${@}\"", false},
      {"\"${!prefix@}\"", false},
      {"${!prefix*}", false},
      {"${@:-}", false},
      {"\"${@+data}\"", false},
      {"\"${@:+data}\"", false},
      {"\"${@#prefix}\"", false},
      {"\"${@:99}\"", false},
      {"{,}", false},
      {"\\\n$missing\\\n", false},
      {"''", true},
      {"\"\"", true},
      {"$''", true},
      {"$'\\0'", true},
      {"\"$missing\"", true},
      {"\"${missing:-$@}\"", true},
      {"\"$(true)\"", true},
      {"\"`true`\"", true},
      {"\"$((1+2))\"", true},
      {"\"$*\"", true},
      {"\"${#@}\"", true},
      {"\"${!prefix*}\"", true},
      {"\"${!pre\\\nfix\\\n*}\"", true},
      {"\"${@-data}\"", true},
      {"\"${@:-data}\"", true},
      {"\"${@-}\"", true},
      {"\"${@:-}\"", true},
      {"\"${@:-\"$@\"}\"", true},
      {"\"${@?error}\"", true},
      {"\"${@:?error}\"", true},
      {"\"${\\\n@:\\\n-data}\"", true},
      {"\"${!prefix@}\"suffix", true},
      {"\"$@\"''", true},
      {"literal$missing", true},
      {"$missing-suffix", true},
      {"$missing\\ ", true},
      {"{,}suffix", true},
      {"{{literal}}", true},
      {"{{,},}", false},
      {"{a,b}", true},
      {"{a,$missing}", true},
      {"{\"\",}", true},
      {"{\"$@\",}", false},
      {"{{},}", true},
      {"*", true},
      {"[a]", true},
      {"~", true},
      {"<(true)", true},
      {"\\$missing", true},
      {"$", true},
  };
  for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); i++)
    CHECK(shell_builtin_word_guarantees_argument(
              words[i].word, strlen(words[i].word)) == words[i].survives);
  /* Nonempty lists need not be scalar: getopts still cannot prove which
   * expanded word supplies its destination. Keep its exact-word boundary. */
  const char *multiple = "getopts \"${@:-ab}\" option";
  CHECK(!shell_builtin_parameter_is_scalar("${@:-ab}", sizeof("${@:-ab}") - 1));
  CHECK(shell_dep_graph_parse(multiple, strlen(multiple), "/", limits, graph) ==
        SHELL_DEP_EPARSE);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  static const struct {
    const char *source;
    bool cwd_known;
  } continuation[] = {
      {"UID=${missing:?rhs} $maybe; printf after", false},
      {"UID=${missing:?rhs} $maybe && printf after", false},
      {"! UID=${missing:?rhs} $maybe || printf after", false},
      {"{ UID=${missing:?rhs} $maybe; } && printf after", false},
      {"(UID=${missing:?rhs} $maybe); printf after", true},
      {"UID=${missing:?rhs} $maybe & printf after", true},
      {"UID=$(printf data) $maybe 1>&- 2>&-; printf after", false},
      {"exec 3>&1; UID=${missing:?rhs} $maybe 3>&-; printf after >&3", false},
      {"IFS=0123456789 UID=1 $maybe 4>&- 5>&4\n"
       "exec {fd}>&1; printf after >&\"$fd\"",
       true},
  };
  for (unsigned i = 0; i < sizeof(continuation) / sizeof(continuation[0]);
       i++) {
    parse(continuation[i].source, limits, graph);
    uint32_t after = UINT32_MAX;
    for (uint32_t node = 0; node < graph->node_count; node++)
      if (graph->nodes[node].type == SHELL_NODE_CMD &&
          graph->nodes[node].cmd.token_count == 2 &&
          graph->nodes[node].cmd.token_lens[1] == 5 &&
          !memcmp(graph->nodes[node].cmd.tokens[1], "after", 5))
        after = node;
    CHECK(after != UINT32_MAX && route(graph, after, 1, false, 1));
    CHECK(graph->nodes[after].cmd.cwd_known == continuation[i].cwd_known);
  }

  /* A rejected RHS runs only on the null path, where preceding IFS commits
   * are visible. It still executes printf, but its ambiguous redirect cannot
   * supply captured stdout. */
  parse("IFS=0123456789 UID=$(exec {fd}>&1; printf rhs >&$fd) $maybe", limits,
        graph);
  CHECK(command(graph, "printf") != UINT32_MAX);
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    CHECK(!(graph->edges[edge].type == SHELL_EDGE_SUBST &&
            (graph->edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD)));

  /* A prefix committed before the readonly error invalidates its old named
   * descriptor proof. Mixed IFS/descriptor facts must not select the valid
   * executable alternative and silently discard the null one. */
  static const char *const unresolved[] = {
      "exec {fd}>out; fd=changed UID=$(printf rhs >&\"$fd\") $maybe",
      "IFS=0123456789 x=$(exec {fd}>&1; printf rhs >&$fd) UID=1 $maybe",
      ("IFS=0123456789 UID=1 $maybe 4>&- 5>&4\n"
       "exec {fd}>&1; printf after >&$fd"),
  };
  for (unsigned i = 0; i < sizeof(unresolved) / sizeof(unresolved[0]); i++) {
    CHECK(shell_dep_graph_parse(unresolved[i], strlen(unresolved[i]), "/",
                                limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }
  parse("exec {fd}>out; fd=changed UID=1 $maybe 4>&- 5>&4 || "
        "printf after >&\"$fd\"",
        limits, graph);
  uint32_t after = command(graph, "printf");
  CHECK(after != UINT32_MAX);
  bool writes_file = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    writes_file |= item->type == SHELL_EDGE_WRITE && item->from == after &&
                   graph->nodes[item->to].type == SHELL_NODE_DOC &&
                   graph->nodes[item->to].doc.path_len == 3 &&
                   !memcmp(graph->nodes[item->to].doc.path, "out", 3);
  }
  CHECK(writes_file); /* The abort-only prefix must not affect the OR path. */

  static const char *const resolved[] = {
      "UID=$(printf '%s' \"$payload\") $maybe >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"$maybe\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${!prefix*}\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${!prefix@}\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${@:-data}\" >\"$path\"",
  };
  for (unsigned i = 0; i < sizeof(resolved) / sizeof(resolved[0]); i++) {
    nullable_resolution_t fixture = {0};
    parse(resolved[i], limits, graph);
    CHECK(shell_dep_graph_parse_resolved(resolved[i], strlen(resolved[i]), "/",
                                         limits, other, nullable_resolve,
                                         &fixture, NULL) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
    CHECK(fixture.arguments == (i == 0 || i == 3 ? 1u : 0u) &&
          fixture.paths == 1);
  }
  nullable_resolution_t failure = {.fail = true};
  CHECK(shell_dep_graph_parse_resolved(resolved[0], strlen(resolved[0]), "/",
                                       limits, other, nullable_resolve,
                                       &failure, NULL) == SHELL_DEP_EEXPAND);
  CHECK(other->node_count == 0 && other->edge_count == 0);

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 32; count <= 256; count *= 2) {
    char source[4096] = "UID=$(printf data) ";
    for (unsigned word = 0; word < count; word++)
      strcat(source, "$missing\\\n");
    strcat(source, "$missing");
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work > 0 && work <= 256 * strlen(source) &&
          (!previous || work <= 3 * previous));
    CHECK(command(graph, "printf") != UINT32_MAX);
    previous = work;
  }
  previous = 0;
  for (unsigned count = 32; count <= 256; count *= 2) {
    char source[4096] = "UID=$(printf skipped) \"${!";
    for (unsigned byte = 0; byte < count; byte++)
      strcat(source, "p\\\n");
    strcat(source, "*}\"");
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work > 0 && work <= 256 * strlen(source) &&
          (!previous || work <= 3 * previous));
    CHECK(command(graph, "printf") == UINT32_MAX);
    previous = work;
  }
#endif
}

static void diagnostic_flows(shell_dep_limits_t *limits,
                             shell_dep_graph_t *graph,
                             shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool capture;
  } cases[] = {
      {"exec 3>&-; sh -c \"$(echo 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(echo >&3 2>&1)\"", false},
      {"exec 3>&-; sh -c \"$(echo >&3)\"", false},
      {"exec 3>&-; sh -c \"$(echo 2>&- >&3)\"", false},
      {"exec 3>&-; sh -c \"$(2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$({ echo body; } 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$( (echo body) 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(time echo 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(false && echo 2>&1 >&3)\"", false},
      {"exec 3>&-; sh -c \"$(true || echo 2>&1 >&3)\"", false},
      {"sh -c \"$(echo 2>&1 >'')\"", true},
      {"sh -c \"$(echo >'' 2>&1)\"", false},
      {"exec 3>&-; cat <(echo 2>&1 >&3)", true},
      {"exec 3>&-; cat <(echo >&3 2>&1)", false},
      {"exec 3>&-; sh -c \"$(echo 2>&1 1>&3-)\"", true},
      {"exec 3>&-; sh -c \"$(echo 2>&1 {fd}>&3)\"", true},
      {"sh -c \"$(exec 2>&1; echo ok &)\"", true},
      {"exec 10>&-; sh -c \"$({ exec 10>&-; } 2>&1)\"", true},
      {"exec 3>&- 10>&-; sh -c \"$(: 2>&1 10>&- 4>&3)\"", true},
      {"exec 3>&- 4>&- 63>&-; sh -c \"$(read -u63 -n0 probe; "
       "{ true 2>&1 5>left 6>right 7>&3; })\"",
       true},
      {"exec 3>&- 4>&- 63>&-; sh -c \"$(read -u63 -n0 probe; "
       "{ true 5>left 6>right 2>&- 7>&3; })\"",
       false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, limits, graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      capture |= item->type == SHELL_EDGE_SUBST && item->source_fd == 2;
      if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
          graph->nodes[item->to].type == SHELL_NODE_ENDPOINT)
        for (uint32_t out = 0; out < graph->edge_count; out++)
          capture |= graph->edges[out].type == SHELL_EDGE_SUBST &&
                     graph->edges[out].from == item->to;
      /* These bodies either fail setup or are skipped: no body stdin use. */
      if (i < 16 && graph->nodes[item->to].type == SHELL_NODE_CMD &&
          graph->nodes[item->to].cmd.token_count &&
          graph->nodes[item->to].cmd.token_lens[0] == 4 &&
          !memcmp(graph->nodes[item->to].cmd.tokens[0], "echo", 4))
        CHECK(item->type != SHELL_EDGE_READ);
    }
    if (capture != cases[i].capture)
      fprintf(stderr, "diagnostic capture: %s\n", cases[i].source);
    CHECK(capture == cases[i].capture);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_failure_cleanup_reference(true);
    parse(cases[i].source, limits, other);
    shellsplit_test_failure_cleanup_reference(false);
    CHECK(shellsplit_test_graph_equal(graph, other));
#endif
  }
  parse("exec 3>&-; echo 2>&1 >&3 | cat", limits, graph);
  uint32_t echo = command(graph, "echo"), cat = command(graph, "cat");
  bool piped = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    piped |= item->type == SHELL_EDGE_PIPE && item->from == echo &&
             item->to == cat && item->source_fd == 2 && item->target_fd == 0;
  }
  CHECK(piped);
  /* More than 16 distinct prefix sinks fit the graph. Split into three
   * owners to stay within the independent per-command lexical token bound. */
  char source[1024] = "exec 3>&-;";
  for (unsigned owner = 0; owner < 3; owner++) {
    strcat(source, " echo");
    for (unsigned i = 0; i < 8; i++) {
      char redirect[32];
      snprintf(redirect, sizeof(redirect), " 2>error%u", owner * 8 + i);
      strcat(source, redirect);
    }
    strcat(source, " >&3;");
  }
  parse(source, limits, graph);
  unsigned destinations = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE &&
        graph->nodes[item->from].type == SHELL_NODE_CMD &&
        item->source_fd == 2 && graph->nodes[item->to].type == SHELL_NODE_DOC)
      destinations++;
  }
  CHECK(destinations == 24);
  for (unsigned nodes = 0; nodes <= 8; nodes++)
    for (unsigned edges = 0; edges <= 12; edges++) {
      shell_dep_limits_t bounded = *limits;
      bounded.max_nodes = nodes;
      bounded.max_edges = edges;
      const char *limited_source = cases[0].source;
      shell_dep_error_t status = shell_dep_graph_parse(
          limited_source, strlen(limited_source), "/", &bounded, other);
      CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
      CHECK(other->node_count <= nodes && other->edge_count <= edges &&
            shell_dep_graph_validate(other).valid);
      if (status == SHELL_DEP_OK) {
        bool captured = false;
        for (uint32_t edge = 0; edge < other->edge_count; edge++)
          captured |= other->edges[edge].type == SHELL_EDGE_SUBST &&
                      other->edges[edge].source_fd == 2;
        CHECK(captured);
      }
    }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_failure_cleanup_reference(true);
  parse(source, limits, other);
  shellsplit_test_failure_cleanup_reference(false);
  CHECK(shellsplit_test_graph_equal(graph, other));
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    strcpy(source, "exec 3>&-;");
    for (unsigned i = 0; i < count; i++) {
      char stage[40];
      snprintf(stage, sizeof(stage), " echo 2>error%u >&3;", i);
      strcat(source, stage);
    }
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 64 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

/* UINT32_MAX selects any consumer. Index collectors once so exact-consumer
 * assertions do not rescan the edge stream for every diagnostic producer. */
static bool captured_stderr(const shell_dep_graph_t *graph, uint32_t consumer) {
  bool collectors[SHELL_DEP_MAX_NODES] = {false};
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type != SHELL_EDGE_SUBST ||
        (consumer != UINT32_MAX && item->to != consumer))
      continue;
    if (item->source_fd == 2)
      return true;
    collectors[item->from] = true;
  }
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
        graph->nodes[item->to].type == SHELL_NODE_ENDPOINT &&
        collectors[item->to])
      return true;
  }
  return false;
}

static void expansion_diagnostics(shell_dep_limits_t *limits,
                                  shell_dep_graph_t *graph,
                                  shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool capture;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"", true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)))\"", true},
      {"sh -c \"$(exec 2>&1; x=${value:1/0})\"", true},
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&1; : ${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)) true 1>&- 2>&-)\"", true},
      {"sh -c \"$(exec 2>&1; export x=${missing:?expansion-marker} 1>&- "
       "2>&-)\"",
       true},
      {"sh -c \"$(x=${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(exec 2>&-; x=${missing:?expansion-marker})\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && "
       "x=${missing:?expansion-marker})\"",
       false},
      {"sh -c \"$(exec 2>&1; true 1>&- 2>&- || x=$((1/0)))\"", false},
      {"sh -c \"$(exec 2>&1; UID=${missing:?expansion-marker} true 1>&- "
       "2>&-)\"",
       true},
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(exec 2>&1; x='${missing:?literal}')\"", false},
      {"sh -c \"$(: 2>&1 >${missing:?expansion-marker} 2>&-)\"", true},
      {"sh -c \"$(: >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(: 2>&- >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(exec 3>&-; : 2>&1 >&3 >${missing:?expansion-marker})\"",
       true},
      {"sh -c \"$(: 2>&1 <<<$((1/0)) 2>&-)\"", true},
      {"sh -c \"$(: <<<$((1/0)) 2>&1 1>&- 2>&-)\"", false},
      {"sh -c \"$(: 2>&1 <<EOF 2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
       true},
      {"sh -c \"$(: <<EOF 2>&1 1>&- "
       "2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
       false},
      {"sh -c \"$(: <<'EOF' 1>&- 2>&-\n${missing:?literal}\nEOF\n)\"", false},
      {"sh -c \"$(exec 2<input; x=${missing:?expansion-marker})\"", false},
      {"sh -c \"$({ :; } 2>&1 >${missing:?expansion-marker})\"", true},
      {"sh -c \"$({ :; } >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$( (x=${missing:?expansion-marker}) 2>&1)\"", true},
      {"cat <(exec 2>&1; x=$((1/0)))", true},
      {"sh -c \"$(exec 2>&1; x=$(exec 2>&1; y=$((1/0))))\"", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    parse(source, limits, graph);
    if (captured_stderr(graph, UINT32_MAX) != cases[i].capture)
      fprintf(stderr, "expansion diagnostic: %s\n", source);
    CHECK(captured_stderr(graph, UINT32_MAX) == cases[i].capture);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  /* A failed RHS is shell stderr, even when there is no executable argv.
   * Its incoming binding must survive the command's later close operations. */
  parse("exec 2>&1; x=$((1/0)) 1>&- 2>&-", limits, graph);
  uint32_t assignment = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_CMD &&
        !graph->nodes[node].cmd.token_count)
      assignment = node;
  CHECK(assignment != UINT32_MAX && route(graph, assignment, 2, false, 1));
  CHECK(!route(graph, assignment, 0, true, 0) &&
        !route(graph, assignment, 1, false, 1));

  parse("exec 2>errors; x=$((1/0)) 2>&-", limits, graph);
  bool written = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
        graph->nodes[item->to].type == SHELL_NODE_DOC &&
        graph->nodes[item->to].doc.path_len == 6 &&
        !memcmp(graph->nodes[item->to].doc.path, "errors", 6))
      written = true;
  }
  CHECK(written);
  parse("{ x=$((1/0)); } 2>&1 | cat", limits, graph);
  bool piped = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    piped |= item->type == SHELL_EDGE_PIPE && item->source_fd == 2 &&
             item->to == command(graph, "cat") && item->target_fd == 0;
  }
  CHECK(piped);

  static const char *const limited_sources[] = {
      "sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"",
      "sh -c \"$(exec 2>&1; x=$((1/0)))\"",
      "sh -c \"$(: 2>&1 >${missing:?expansion-marker} 2>&-)\"",
      "sh -c \"$(: 2>&1 <<<$((1/0)) 2>&-)\"",
      "sh -c \"$(: 2>&1 <<EOF 2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
  };
  for (size_t i = 0; i < sizeof(limited_sources) / sizeof(limited_sources[0]);
       i++) {
    const char *source = limited_sources[i];
    for (unsigned nodes = 0; nodes <= 12; nodes++)
      for (unsigned edges = 0; edges <= 18; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        CHECK(status != SHELL_DEP_OK || captured_stderr(other, UINT32_MAX));
      }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[4096] = "";
    for (unsigned i = 0; i < count; i++) {
      strcat(source, ": <<<$((1/0));");
    }
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 128 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

typedef struct {
  const char *value;
  shell_expand_status_t status;
  unsigned calls;
} file_diagnostic_resolution_t;

static shell_expand_status_t
file_diagnostic_resolve(const shell_expand_word_request_t *request,
                        const char **netargv, size_t *length, void *context) {
  file_diagnostic_resolution_t *fixture = context;
  if (request->purpose != SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  fixture->calls++;
  *netargv = fixture->value;
  *length = fixture->value ? strlen(fixture->value) : 0;
  return fixture->status;
}

static void file_diagnostics(shell_dep_limits_t *limits,
                             shell_dep_graph_t *graph,
                             shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool captured;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=$(<input))\"", true},
      {"sh -c \"$(x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&-; x=$(<input))\"", false},
      {"sh -c \"$(exec 2<input; x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&1; x=$(<input) 1>&- 2>&-)\"", true},
      {"sh -c \"$(x=$(<input) 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&1; x=$(< <(true 1>&- 2>&-)))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(<$(printf input)))\"", true},
      {"sh -c \"$(: 2>&1 >$(<input) 1>&- 2>&-)\"", true},
      {"sh -c \"$(: >$(<input) 2>&1 1>&- 2>&-)\"", false},
      {"sh -c \"$(: 2>&1 <<<\"$(<input)\" 1>&- 2>&-)\"", true},
      {"sh -c \"$({ :; } 2>&1 >$(<input))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(y=$(<input)))\"", true},
      {"sh -c \"$(x=$(exec 2>&1; y=$(<input)))\"", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    parse(source, limits, graph);
    uint32_t shell = command(graph, "sh");
    CHECK(shell != UINT32_MAX);
    if (captured_stderr(graph, shell) != cases[i].captured)
      fprintf(stderr, "file diagnostic receiver: %s\n", source);
    CHECK(captured_stderr(graph, shell) == cases[i].captured);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *word, *value;
    shell_expand_status_t status;
    bool failed;
  } values[] = {
      {"\"$FILE\"", "0:,", SHELL_EXPAND_RESOLVED, true},
      {"\"$@\"", NULL, SHELL_EXPAND_RESOLVED, true},
      {"\"$@\"", "1:a,1:b,", SHELL_EXPAND_RESOLVED, true},
      {"\"$FILE\"", "10:/tmp/input,", SHELL_EXPAND_RESOLVED, false},
      {"\"$FILE\"", NULL, SHELL_EXPAND_UNRESOLVED, false},
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    char source[128];
    snprintf(source, sizeof(source), "sh -c \"$(exec 2>&1; x=$(<%s))\"",
             values[i].word);
    file_diagnostic_resolution_t fixture = {values[i].value, values[i].status,
                                            0};
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph, file_diagnostic_resolve,
                                         &fixture, NULL) == SHELL_DEP_OK);
    CHECK(fixture.calls == 1 && shell_dep_graph_validate(graph).valid);
    uint32_t shell = command(graph, "sh");
    CHECK(shell != UINT32_MAX && captured_stderr(graph, shell));
    unsigned content = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      content += item->type == SHELL_EDGE_SUBST &&
                 graph->nodes[item->from].type == SHELL_NODE_DOC;
    }
    CHECK(content == !values[i].failed);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    shell_expand_cache_t cache;
    shell_dep_limits_t resolved = *limits;
    fixture.calls = 0;
    CHECK(shell_expand_cache_init(
        file_diagnostic_resolve, &fixture, source, strlen(source), false,
        limits->workspace, limits->workspace_size, &cache, &resolved.workspace,
        &resolved.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &resolved, &fast, other, &resolver,
              unresolved) == SHELL_DEP_OK);
    CHECK(fixture.calls == 1 && shellsplit_test_graph_equal(graph, other));
    for (unsigned nodes = 0; nodes <= 10; nodes++)
      for (unsigned edges = 0; edges <= 14; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        fixture.calls = 0;
        shell_dep_error_t error = shell_dep_graph_parse_resolved(
            source, strlen(source), "/", &bounded, other,
            file_diagnostic_resolve, &fixture, NULL);
        CHECK(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC);
        CHECK(fixture.calls <= 1 && other->node_count <= nodes &&
              other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        CHECK(error != SHELL_DEP_OK ||
              shellsplit_test_graph_equal(graph, other));
      }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[4096] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "x=$(<input);");
    shellsplit_test_source_scan_reset();
    parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 128 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

static void terminal_pipe_capacity(shell_dep_limits_t *limits,
                                   shell_dep_graph_t *graph,
                                   shell_dep_graph_t *other) {
  const char *regression = "exec 3>&-; echo 2>&1 >&3 | cat <input";
  shell_dep_limits_t bounded = *limits;
  bounded.max_nodes = 5;
  bounded.max_edges = 3;
  CHECK(shell_dep_graph_parse(regression, strlen(regression), "/", &bounded,
                              other) == SHELL_DEP_ETRUNC);
  CHECK(other->node_count <= 5 && other->edge_count <= 3 &&
        shell_dep_graph_validate(other).valid);

  static const struct {
    const char *source;
    uint32_t producers;
    bool diagnostic, timer_pipe;
  } cases[] = {
      {"exec 3>&-; echo 2>&1 >&3 | cat <input", 1, true, false},
      {"exec 3>&-; echo 2>&1 >&3 | cat <&-", 1, true, false},
      {"exec 3>&-; { echo 2>&1 >&3; } | cat <input", 2, true, false},
      {"exec 3>&-; (echo 2>&1 >&3) | cat <input", 2, true, false},
      {"exec 3>&-; time echo 2>&1 >&3 | cat <input", 1, true, false},
      {"echo | : <&-", 1, false, false},
      {"echo | cat <input", 1, false, false},
      {"{ echo one; echo two; } 2>&1 | cat <input", 2, false, false},
      {"{ time echo; } 2>&1 | cat <input", 3, false, true},
      {"exec 3>&-; printf '%s' \"$(echo 2>&1 >&3 | cat <input)\"", 1, true,
       false},
      {"exec 3>&-; cat <(echo 2>&1 >&3 | cat <input)", 1, true, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    parse(source, limits, graph);
    uint32_t terminal = UINT32_MAX;
    for (uint32_t node = 0; node < graph->node_count; node++)
      if (graph->nodes[node].type == SHELL_NODE_ENDPOINT) {
        CHECK(terminal == UINT32_MAX);
        terminal = node;
      }
    CHECK(terminal != UINT32_MAX);
    uint32_t producers = 0;
    uint32_t echo = command(graph, "echo");
    bool diagnostic_pipe = false, timer_pipe = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type == SHELL_EDGE_PIPE && item->to == terminal) {
        CHECK(item->target_fd == 0 && item->flags == 0);
        producers++;
        diagnostic_pipe |= item->from == echo && item->source_fd == 2;
        if (graph->nodes[item->from].type == SHELL_NODE_TIME) {
          const shell_dep_time_t *time = &graph->nodes[item->from].time;
          CHECK(item->source_fd == 2 &&
                time->report_route == SHELL_TIME_REPORT_GRAPH &&
                time->report_external_fd_count == 0);
          timer_pipe = true;
        }
      }
      if (cases[i].diagnostic) {
        CHECK(item->type != SHELL_EDGE_READ || item->to != echo);
        if (item->from == echo)
          CHECK(item->type != SHELL_EDGE_WRITE &&
                item->type != SHELL_EDGE_APPEND &&
                (item->type != SHELL_EDGE_PIPE || item->source_fd == 2));
      }
    }
    CHECK(producers == cases[i].producers &&
          timer_pipe == cases[i].timer_pipe &&
          (!cases[i].diagnostic || diagnostic_pipe));

    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
    for (uint32_t nodes = 0; nodes <= graph->node_count + 1; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count + 1; edges++) {
        bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        for (unsigned api = 0; api < 3; api++) {
          shell_dep_error_t status =
              api == 0
                  ? shell_dep_graph_parse(source, length, "/", &bounded, other)
              : api == 1
                  ? shell_dep_graph_parse_with_fast(source, length, "/",
                                                    &bounded, &fast, other)
                  : shell_dep_graph_parse_resolved(
                        source, length, "/", &bounded, other, NULL, NULL, NULL);
          bool valid =
              (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC) &&
              other->node_count <= nodes && other->edge_count <= edges &&
              shellsplit_test_depgraph_invariants(source, length, status, other,
                                                  &bounded);
          if (!valid)
            fprintf(stderr,
                    "terminal capacity: %s (api=%u nodes=%u edges=%u "
                    "status=%d)\n",
                    source, api, nodes, edges, status);
          CHECK(valid);
          if (status == SHELL_DEP_OK)
            CHECK(shellsplit_test_graph_equal(graph, other));
        }
      }
  }
}

int main(void) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_RESOLVED,
                                      4096, 2, false, 0));
  shell_dep_limits_t limits = fixture.limits;
  shell_dep_graph_t *graph = fixture.graph[0];
  shell_dep_graph_t *other = fixture.graph[1];
  background_newlines(&limits, graph, other);
  async_completion(&limits, graph, other);
  async_inputs(&limits, graph, other);
  standard_directions(&limits, graph, other);
  timing_destinations(&limits, graph, other);
  recovery_resolution(&limits, graph, other);
  cd_commands(&limits, graph, other);
  owner_stream_inventory(&limits, graph, other);
  assignment_effects(&limits, graph, other);
  assignment_streams(&limits, graph, other);
  nullable_assignments(&limits, graph, other);
  diagnostic_flows(&limits, graph, other);
  expansion_diagnostics(&limits, graph, other);
  file_diagnostics(&limits, graph, other);
  terminal_pipe_capacity(&limits, graph, other);
  diagnostic_resolution(&limits, graph, other);
  char exact[512] = "";
  for (unsigned i = 0; i < 64; i++)
    strcat(exact, i == 0 ? "wc" : ";wc");
  static const char *const trivia[] = {"", ";", " \n", "; \n# end\n"};
  size_t exact_length = strlen(exact);
  for (unsigned i = 0; i < sizeof(trivia) / sizeof(trivia[0]); i++) {
    strcpy(exact + exact_length, trivia[i]);
    parse(exact, &limits, graph);
    CHECK(graph->node_count == 67 && graph->edge_count == 255);
  }
  strcpy(exact + exact_length, ";wc");
  CHECK(shell_dep_graph_parse(exact, strlen(exact), "/", &limits, graph) ==
        SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 67 && graph->edge_count == 255 &&
        shell_dep_graph_validate(graph).valid);

  static const char *const async_capacity[] = {
      "wc &",
      "wc &\nwait",
      "exec 0<&- && true &\ncat",
      "{ wc; } &",
      "time wc &",
      "true && wc &",
      "printf '%s' \"$(wc)\" &",
      "wc 0>&1",
      "wc 1<&0",
      "UID=1\ntrue && wc & wait",
      "probe && exec 2>&1; time wc",
  };
  for (unsigned source = 0;
       source < sizeof(async_capacity) / sizeof(async_capacity[0]); source++)
    for (unsigned nodes = 0; nodes <= 8; nodes++)
      for (unsigned edges = 0; edges <= 15; edges++) {
        shell_dep_limits_t bounded = limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t error = shell_dep_graph_parse(
            async_capacity[source], strlen(async_capacity[source]), "/",
            &bounded, graph);
        CHECK(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= nodes && graph->edge_count <= edges &&
              shell_dep_graph_validate(graph).valid);
        (void)implicit_input(graph);
      }

  static const struct {
    const char *source;
    uint32_t stdout_fd, stderr_fd;
    const char *stdout_file, *stderr_file;
  } cases[] = {
      {"wc -l file.txt", 1, 2, NULL, NULL},
      {"wc -l file.txt 2>&1", 1, 1, NULL, NULL},
      {"wc -l file.txt 1>&2", 2, 2, NULL, NULL},
      {"wc -l file.txt 2>&1 >out", SHELL_DEP_FD_NONE, 1, "out", NULL},
      {"wc -l file.txt >out 2>&1", SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE, "out",
       "out"},
      {"wc -l file.txt 2>&-", 1, SHELL_DEP_FD_NONE, NULL, NULL},
      {"wc -l file.txt 2>&2-", 1, 2, NULL, NULL},
      {"exec 3>&1; wc -l file.txt 1>&3-", 1, 2, NULL, NULL},
      {"exec {fd}>&1; wc -l file.txt 2>&$fd", 1, 1, NULL, NULL},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    parse(cases[i].source, &limits, graph);
    uint32_t owner = command(graph, "wc");
    CHECK(owner != UINT32_MAX && route(graph, owner, 0, true, 0));
    for (uint32_t fd = 1; fd <= 2; fd++) {
      uint32_t inherited = fd == 1 ? cases[i].stdout_fd : cases[i].stderr_fd;
      const char *file = fd == 1 ? cases[i].stdout_file : cases[i].stderr_file;
      unsigned destinations = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
        const shell_dep_edge_t *item = &graph->edges[edge];
        if (item->type != SHELL_EDGE_WRITE || item->from != owner ||
            item->source_fd != fd)
          continue;
        const shell_dep_node_t *target = &graph->nodes[item->to];
        bool failed_open = i == 4 && fd == 2 && target->type == SHELL_NODE_FD &&
                           target->fd.number == 2;
        if (file && !failed_open)
          CHECK(target->type == SHELL_NODE_DOC &&
                target->doc.kind == SHELL_DOC_FILE &&
                target->doc.path_len == strlen(file) &&
                !memcmp(target->doc.path, file, strlen(file)));
        else if (!failed_open)
          CHECK(target->type == SHELL_NODE_FD &&
                target->fd.number == inherited);
        destinations++;
      }
      CHECK(destinations == (file || inherited != SHELL_DEP_FD_NONE ? 1u : 0u) +
                                (i == 4 && fd == 2 ? 1u : 0u));
    }
  }

  parse("wc -l file.txt", &limits, graph);
  CHECK(graph->node_count == 5 && graph->edge_count == 4);
  parse("wc -l file.txt 2>&1", &limits, graph);
  /* Both sparse stdout/stderr slots retain their available read/write halves.
   */
  CHECK(graph->node_count == 4 && graph->edge_count == 6);
  uint32_t external = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      external = i;
  CHECK(external != UINT32_MAX);
  *other = *graph;
  other->nodes[external].fd.number = SHELL_DEP_FD_NONE;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] = graph->nodes[external];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] =
      (shell_dep_node_t){.type = SHELL_NODE_FD, .fd = {.number = 3}};
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[other->edge_count - 1].type = SHELL_EDGE_PIPE;
  CHECK(!shell_dep_graph_validate(other).valid);
  parse("time wc", &limits, graph);
  *other = *graph;
  for (uint32_t i = 0; i < other->node_count; i++)
    if (other->nodes[i].type == SHELL_NODE_TIME)
      other->nodes[i].time.report_external_fds[0] = 1;
  CHECK(!shell_dep_graph_validate(other).valid);

  static const char *const scopes[] = {
      "{ wc -l file.txt; echo ok; } 2>&1",
      "( wc -l file.txt; echo ok ) 2>&1",
      "{ { wc -l file.txt; }; } 2>&1",
      "{ wc -l file.txt 2>&1; echo ok; }",
      "echo \"$(wc -l file.txt)\"",
      "echo \"$(wc -l file.txt 2>&1)\"",
      "echo `wc -l file.txt`",
      "cat <(wc -l file.txt)",
      "cat > >(wc -l file.txt)",
      "wc -l file.txt | cat",
      "wc -l file.txt |& cat",
      "probe && exec 2>&1; wc -l file.txt",
      "time wc -l file.txt",
      "echo \"$(exec 3>&2; time wc 2>&3)\"",
      "time { wc; } 2>&1",
      "echo \"$( { wc; } )\"",
      "true || wc -l file.txt",
      ">out",
      "exec 2>&1",
      "time",
  };
  for (size_t i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++) {
    parse(scopes[i], &limits, graph);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(scopes[i], strlen(scopes[i]), NULL, &fast) ==
          SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(scopes[i], strlen(scopes[i]), "/",
                                          &limits, &fast,
                                          other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  parse(" ", &limits, graph);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  parse("echo \"$(wc -l file.txt 2>&1)\"", &limits, graph);
  uint32_t owner = command(graph, "wc");
  CHECK(route(graph, owner, 0, true, 0));
  CHECK(!route(graph, owner, 1, false, 1) && !route(graph, owner, 2, false, 1));
  parse("probe && exec 2>&1; wc -l file.txt", &limits, graph);
  owner = command(graph, "wc");
  CHECK(route(graph, owner, 2, false, 1) && route(graph, owner, 2, false, 2));
  parse("true || wc -l file.txt", &limits, graph);
  owner = command(graph, "wc");
  CHECK(!route(graph, owner, 0, true, 0) && !route(graph, owner, 1, false, 1));
  parse("echo \"$( { wc; } )\"", &limits, graph);
  uint32_t child_group = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_GROUP)
      child_group = i;
  owner = command(graph, "wc");
  CHECK(child_group != UINT32_MAX && route(graph, child_group, 0, true, 0) &&
        route(graph, child_group, 2, false, 2));
  CHECK(!route(graph, owner, 0, true, 0) && !route(graph, owner, 2, false, 2));
  parse("{ >out; }", &limits, graph);
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      CHECK(graph->nodes[i].fd.number == 2);
  /* No body needs stdin/stdout. Only the possible open-error diagnostic has
   * an inherited stream relation. */
  unsigned diagnostic_boundaries = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (graph->nodes[edge->to].type == SHELL_NODE_FD) {
      CHECK(edge->type == SHELL_EDGE_WRITE && edge->source_fd == 2);
      diagnostic_boundaries++;
    }
    CHECK(graph->nodes[edge->from].type != SHELL_NODE_FD);
  }
  CHECK(diagnostic_boundaries == 1);

  /* Repeated nested exposures are coalesced before retained-edge budgeting. */
  char nested[512] = "";
  for (unsigned i = 0; i < 16; i++)
    strcat(nested, "{ ");
  strcat(nested, "wc;");
  for (unsigned i = 0; i < 16; i++)
    strcat(nested, " }; ");
  parse(nested, &limits, graph);
  uint32_t boundaries = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++)
    boundaries += graph->nodes[graph->edges[i].from].type == SHELL_NODE_FD ||
                  graph->nodes[graph->edges[i].to].type == SHELL_NODE_FD;
  CHECK(boundaries == 3);

  /* Many conditional routes shared by deeply nested groups must not consume
   * the public edge budget once per redundant intermediate exposure. */
  char alternatives[2048] = "";
  size_t used = 0;
  for (unsigned fd = 3; fd <= 9; fd++)
    used += (size_t)snprintf(alternatives + used, sizeof(alternatives) - used,
                             "probe && exec 2>&%u; ", fd);
  for (unsigned i = 0; i < 60; i++)
    strcat(alternatives, "{ ");
  strcat(alternatives, "wc;");
  for (unsigned i = 0; i < 60; i++)
    strcat(alternatives, " }; ");
  parse(alternatives, &limits, graph);
  uint32_t outer = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_GROUP &&
        graph->nodes[i].group.parent == UINT32_MAX) {
      CHECK(outer == UINT32_MAX);
      outer = i;
    }
  CHECK(outer != UINT32_MAX);
  CHECK(route(graph, outer, 0, true, 0) && route(graph, outer, 1, false, 1));
  for (unsigned fd = 2; fd <= 9; fd++)
    CHECK(route(graph, outer, 2, false, fd));

  for (uint32_t max_nodes = 1; max_nodes <= 4; max_nodes++)
    for (uint32_t max_edges = 0; max_edges <= 3; max_edges++) {
      shell_dep_limits_t bounded = limits;
      bounded.max_nodes = max_nodes;
      bounded.max_edges = max_edges;
      shell_dep_error_t status =
          shell_dep_graph_parse("wc", 2, "/", &bounded, graph);
      CHECK(status == ((max_nodes == 4 && max_edges == 3) ? SHELL_DEP_OK
                                                          : SHELL_DEP_ETRUNC));
      CHECK(graph->node_count <= max_nodes && graph->edge_count <= max_edges);
      CHECK(shell_dep_graph_validate(graph).valid);
    }
  static const char stopped_join[] =
      "exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
      "exec 10>&3 11>&- 12>&- 13>&-; exec 3>&10- 11>&4 10>&-; "
      ": \"$(echo next >&11)\"";
  shell_dep_limits_t limited = limits;
  limited.max_edges = 1;
  CHECK(shell_dep_graph_parse(stopped_join, sizeof(stopped_join) - 1, "/",
                              &limited, graph) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 0 && graph->edge_count == 0 &&
        shell_dep_graph_validate(graph).valid);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Completing nested compounds ending in background units projects each
   * final outcome once, rather than searching their prefixes or ancestors. */
  for (unsigned family = 0; family < 2; family++) {
    size_t previous_work = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[1024] = "";
      for (unsigned i = 0; i < count; i++)
        strcat(source, "{ ");
      strcat(source, "false &");
      for (unsigned i = 1; i < count; i++)
        strcat(source, family == 0 ? " };" : " } &");
      strcat(source, " } || printf bad >out");
      shellsplit_test_source_scan_reset();
      parse(source, &limits, graph);
      uint32_t marker = command(graph, "printf");
      CHECK(marker != UINT32_MAX);
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        CHECK(!((graph->edges[edge].type == SHELL_EDGE_READ &&
                 graph->edges[edge].to == marker) ||
                (graph->edges[edge].type == SHELL_EDGE_WRITE &&
                 graph->edges[edge].from == marker)));
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
      CHECK(work > 0 && work <= 256 * count &&
            (!previous_work || work <= 3 * previous_work));
      previous_work = work;
    }
  }
  /* Exercise the connector walk directly so route publication cannot mask a
   * repeated source scan. Both stage and trivia growth must remain linear. */
  for (unsigned family = 0; family < 2; family++) {
    size_t previous_work = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[1024] = "wc &\n";
      for (unsigned i = 1; i < count; i++)
        strcat(source, family == 0 ? "wc &\n\n# note\n" : "\n# note\n");
      strcat(source, "wait");
      shell_parse_result_t fast;
      shell_pipeline_index_t index;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      shellsplit_test_source_scan_reset();
      shell_pipeline_index_connectors(source, strlen(source), &fast, &index);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work > 0 && work <= 64 * strlen(source) &&
            (!previous_work || work <= 3 * previous_work));
      CHECK(index.range_successor[0] == SHELL_TYPE_BACKGROUND &&
            index.range_connector[fast.count - 1] == SHELL_TYPE_BACKGROUND);
      previous_work = work;
    }
  }
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "wc; ");
    shellsplit_test_source_scan_reset();
    parse(source, &limits, graph);
    size_t work = shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_BOUNDARY);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 96 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
  previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned group = 0; group < count; group++)
      strcat(source, "{ ");
    strcat(source, "wc;");
    for (unsigned group = 0; group < count; group++)
      strcat(source, " } &");
    shellsplit_test_source_scan_reset();
    parse(source, &limits, graph);
    CHECK(reads_implicit(graph, command(graph, "wc"), 0));
    size_t work = shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_BOUNDARY);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 120 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
  shellsplit_graph_fixture_destroy(&fixture);
  puts("inherited boundary graph tests passed");
  return 0;
}
