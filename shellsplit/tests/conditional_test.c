#include "../src/shell_token_regions_internal.h"
#include "conditional_cases.h"
#include "graph_fixture.h"
#include "shell_abstract.h"
#include "shell_sequence.h"
#include "shell_source.h"
#include "shell_transform.h"
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *current = "setup";
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #x, current);    \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static shell_dep_graph_t *graph;
static shell_source_result_t *draft;
static shell_dep_limits_t limits;

static void check_expansion_regions(void) {
  static const struct {
    const char *source;
    unsigned count;
    shell_token_region_context_t context;
    const char *words[2];
  } cases[] = {
      {"[[ -n '$literal' # $(|)\n]]",
       1,
       SHELL_TOKEN_REGION_CONDITIONAL,
       {"'$literal'"}},
      {"[[ \"$(printf left)\" == \"pre\"* # $ignored\n]]",
       2,
       SHELL_TOKEN_REGION_CONDITIONAL,
       {"\"$(printf left)\"", "\"pre\"*"}},
      {"[[ value == \"pre",
       2,
       SHELL_TOKEN_REGION_CONDITIONAL,
       {"value", "\"pre"}},
      {"[[ -n ", 0, SHELL_TOKEN_REGION_CONDITIONAL, {NULL}},
      {"[[ -n \"$left\" && -n \"$right",
       2,
       SHELL_TOKEN_REGION_CONDITIONAL,
       {"\"$left\"", "\"$right"}},
      {"(( 1 + (2) ))", 1, SHELL_TOKEN_REGION_ARITHMETIC, {" 1 + (2) "}},
      {"(( 1 +", 1, SHELL_TOKEN_REGION_ARITHMETIC, {" 1 +"}},
      {"value", 1, SHELL_TOKEN_REGION_WORD, {"value"}},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    const char *source = cases[i].source;
    current = source;
    shell_tokenizer_state_t state;
    CHECK(shell_tokenizer_init(&state, source, strlen(source), NULL));
    shell_token_t token;
    CHECK(shell_tokenizer_next(&state, &token));
    shell_token_regions_t regions =
        shell_token_regions(&token, !state.in_arithmetic);
    CHECK(regions.count == cases[i].count);
    for (unsigned j = 0; j < regions.count; ++j) {
      const shell_token_region_t *region = &regions.regions[j];
      CHECK(region->context == cases[i].context);
      CHECK(region->text >= source &&
            region->text + region->length <= source + strlen(source));
      CHECK(region->length == strlen(cases[i].words[j]));
      CHECK(!memcmp(region->text, cases[i].words[j], region->length));
    }
  }
}

static void check_partial_condition_regions(void) {
  static const struct {
    unsigned groups;
    const char *tail;
    bool close_groups;
    shell_conditional_frame_t frame;
    unsigned regions;
  } cases[] = {
      {49, "", false, SHELL_CONDITIONAL_INCOMPLETE, 98},
      {50, "", false, SHELL_CONDITIONAL_INCOMPLETE, 100},
      {SHELL_CONDITIONAL_MAX_NODES, "", false, SHELL_CONDITIONAL_INCOMPLETE,
       2 * SHELL_CONDITIONAL_MAX_NODES},
      {SHELL_CONDITIONAL_MAX_NODES + 1, "", false, SHELL_CONDITIONAL_LIMIT,
       2 * SHELL_CONDITIONAL_MAX_NODES},
      {SHELL_CONDITIONAL_MAX_NODES - 1, "pending -nt \"unfinished", false,
       SHELL_CONDITIONAL_INCOMPLETE, 2 * SHELL_CONDITIONAL_MAX_NODES},
      {50, "last -ef end", true, SHELL_CONDITIONAL_LIMIT, 102},
      {47, "last -ef end", true, SHELL_CONDITIONAL_COMPLETE, 96},
  };
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    char source[4096] = "[[ ";
    shell_token_region_t expected[2 * (SHELL_CONDITIONAL_MAX_NODES + 2)];
    unsigned count = 0;
    size_t used = strlen(source);
    for (unsigned i = 0; i < cases[c].groups; ++i) {
      expected[count++] = (shell_token_region_t){
          source + used, 1, SHELL_TOKEN_REGION_CONDITIONAL};
      expected[count++] = (shell_token_region_t){
          source + used + 6, 1, SHELL_TOKEN_REGION_CONDITIONAL};
      strcpy(source + used, "l -nt r && (");
      used += strlen("l -nt r && (");
    }
    if (*cases[c].tail) {
      bool pending = !cases[c].close_groups;
      expected[count++] = (shell_token_region_t){
          source + used, pending ? 7 : 4, SHELL_TOKEN_REGION_CONDITIONAL};
      expected[count++] = (shell_token_region_t){
          source + used + (pending ? 12 : 9),
          pending ? strlen("\"unfinished") : 3, SHELL_TOKEN_REGION_CONDITIONAL};
      strcpy(source + used, cases[c].tail);
      used += strlen(cases[c].tail);
    }
    if (cases[c].close_groups) {
      for (unsigned i = 0; i < cases[c].groups; ++i)
        source[used++] = ')';
      strcpy(source + used, " ]]");
      used += strlen(" ]]");
    }
    current = source;
    shell_conditional_t condition = shell_conditional_parse(source, used, 0);
    CHECK(condition.frame == cases[c].frame);
    shell_token_regions_t regions =
        shell_conditional_regions(source, &condition);
    CHECK(regions.count == cases[c].regions && regions.count <= count);
    for (unsigned i = 0; i < regions.count; ++i) {
      CHECK(regions.regions[i].text == expected[i].text);
      CHECK(regions.regions[i].length == expected[i].length);
      CHECK(regions.regions[i].context == SHELL_TOKEN_REGION_CONDITIONAL);
      CHECK(regions.regions[i].text + regions.regions[i].length <=
            source + used);
    }
    shell_source_status_t status =
        cases[c].frame == SHELL_CONDITIONAL_LIMIT ? SHELL_SOURCE_TRUNCATED
        : cases[c].frame == SHELL_CONDITIONAL_COMPLETE
            ? SHELL_SOURCE_COMPLETE
            : SHELL_SOURCE_INCOMPLETE;
    CHECK(shell_parse_draft(source, used, NULL, draft) == status);
  }

  char source[4096] = "printf before; [[ ";
  for (unsigned i = 0; i < 50; ++i)
    strcat(source, "l -nt r && (");
  strcat(source, "-n \"$(printf child)\"");
  current = source;
  CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(draft->prefix_length == strlen("printf before;") &&
        draft->prefix.count == 1);
  CHECK(draft->header_count == 3 && !draft->headers[1].complete &&
        draft->headers[2].complete);
}

static void parse(const char *source) {
  current = source;
  shell_dep_error_t e = shell_dep_graph_parse(source, strlen(source),
                                              "/workspace", &limits, graph);
  if (e != SHELL_DEP_OK)
    fprintf(stderr, "graph error %d\n", e);
  CHECK(e == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

static unsigned condition_node(void) {
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_CMD &&
        graph->nodes[i].cmd.kind == SHELL_COMMAND_CONDITIONAL)
      return i;
  CHECK(false);
  return 0;
}

static unsigned file_node(const char *name) {
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_DOC &&
        graph->nodes[i].doc.kind == SHELL_DOC_FILE &&
        graph->nodes[i].doc.path_len == strlen(name) &&
        !memcmp(graph->nodes[i].doc.path, name, strlen(name)))
      return i;
  CHECK(false);
  return 0;
}

static void check_file_predicates(void) {
  static const struct {
    const char *source, *path;
    unsigned flag;
  } cases[] = {
      {"[[ -e config.json ]]", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"[[ -f config.json ]]", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR},
      {"[[ -d output ]]", "output", SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY},
      {"[[ -L current ]]", "current", SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK},
      {"[[ -h current ]]", "current", SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK},
      {"[[ -a target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"test -a target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"[ -a target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"[[ -s target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY},
      {"test -s target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY},
      {"[ -s target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY},
      {"[[ -b target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK},
      {"test -b target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK},
      {"[ -b target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK},
      {"[[ -c target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER},
      {"test -c target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER},
      {"[ -c target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER},
      {"[[ -p target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO},
      {"test -p target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO},
      {"[ -p target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO},
      {"[[ -S target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET},
      {"test -S target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET},
      {"[ -S target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET},
      {"[[ -r target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE},
      {"test -r target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE},
      {"[ -r target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE},
      {"[[ -w target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE},
      {"test -w target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE},
      {"[ -w target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE},
      {"[[ -x target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE},
      {"test -x target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE},
      {"[ -x target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE},
      {"[[ -u target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID},
      {"test -u target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID},
      {"[ -u target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID},
      {"[[ -g target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID},
      {"test -g target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID},
      {"[ -g target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID},
      {"[[ -k target ]]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY},
      {"test -k target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY},
      {"[ -k target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY},
      {"[[ -O target ]]", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER},
      {"test -O target", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER},
      {"[ -O target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER},
      {"[[ -G target ]]", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP},
      {"test -G target", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP},
      {"[ -G target ]", "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP},
      {"[[ -N target ]]", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ},
      {"test -N target", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ},
      {"[ -N target ]", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ},
      {"{ [[ -N target ]]; }", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ},
      {"printf '%s' \"$( [[ -N target ]] && printf yes )\"", "target",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ},
      {"test -e config.json", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"test -a config.json", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"command test -e config.json", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
      {"[ -f config.json ]", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR},
      {"test -d output", "output", SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY},
      {"test '-f' config.json", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR},
      {"[ -h current ]", "current", SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK},
      {"{ [[ -f config.json ]]; }", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR},
      {"printf '%s' \"$( [[ -f config.json ]] && printf yes )\"", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR},
      {"printf '%s' \"$( test -e config.json && printf yes )\"", "config.json",
       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    parse(cases[i].source);
    unsigned found = 0;
    for (unsigned j = 0; j < graph->edge_count; ++j) {
      const shell_dep_edge_t *edge = &graph->edges[j];
      if (edge->type != SHELL_EDGE_FILE_TEST)
        continue;
      const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
      CHECK(edge->flags == cases[i].flag);
      CHECK(doc->path_len == strlen(cases[i].path));
      CHECK(!memcmp(doc->path, cases[i].path, doc->path_len));
      CHECK(doc->cwd_known && doc->cwd_absolute);
      for (unsigned k = 0; k < graph->edge_count; ++k)
        CHECK(graph->edges[k].type != SHELL_EDGE_READ ||
              graph->edges[k].from != edge->to);
      ++found;
    }
    CHECK(found == 1);
    for (unsigned j = 0; j < graph->edge_count; ++j) {
      shell_dep_edge_t *edge = &graph->edges[j];
      if (edge->type == SHELL_EDGE_FILE_TEST) {
        unsigned saved = edge->flags;
        edge->flags = 0;
        CHECK(!shell_dep_graph_validate(graph).valid);
        edge->flags = UINT32_C(1) << 31;
        CHECK(!shell_dep_graph_validate(graph).valid);
        edge->flags = saved;
      }
    }
  }
  static const char *const operators[] = {
      "-e", "-a", "-f", "-d", "-L", "-h", "-s", "-b", "-c", "-p",
      "-S", "-r", "-w", "-x", "-u", "-g", "-k", "-O", "-G", "-N"};
  for (unsigned i = 0; i < sizeof(operators) / sizeof(*operators); ++i) {
    char source[96];
    for (unsigned negate = 0; negate < 2; ++negate) {
      snprintf(source, sizeof(source), "[[ %s%s '' ]]", negate ? "! " : "",
               operators[i]);
      parse(source);
      CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
            (negate ? SHELL_CONDITIONAL_TRUE : SHELL_CONDITIONAL_FALSE));
      for (unsigned edge = 0; edge < graph->edge_count; ++edge)
        CHECK(graph->edges[edge].type != SHELL_EDGE_FILE_TEST);
      /* Three-argument ! -a '' selects binary conjunction before unary
       * negation; the explicit conditional grammar instead selects -a. */
      for (unsigned bracket = 0; bracket < 2; ++bracket) {
        snprintf(source, sizeof(source), "%s %s%s ''%s %s cat <unreachable",
                 bracket ? "[" : "test", negate ? "! " : "", operators[i],
                 bracket ? " ]" : "",
                 negate && strcmp(operators[i], "-a") ? "||" : "&&");
        parse(source);
        for (unsigned edge = 0; edge < graph->edge_count; ++edge)
          CHECK(graph->edges[edge].type != SHELL_EDGE_FILE_TEST &&
                (graph->edges[edge].type != SHELL_EDGE_READ ||
                 graph->nodes[graph->edges[edge].from].type != SHELL_NODE_DOC));
      }
    }
  }
  parse("[[ -e '' ]]");
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_FALSE);
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("exec 99<&-; [[ -e config.json ]] <&99");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("exec 99<&-; test -e config.json <&99");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("test \"$operator\" target");
  bool possible_target = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != SHELL_EDGE_FILE_TEST)
      continue;
    const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
    if (doc->path_len == 6 && !memcmp(doc->path, "target", 6)) {
      CHECK(edge->flags == (SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP |
                            SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ));
      possible_target = true;
    }
  }
  CHECK(possible_target);
  parse("[[ -f * ]]");
  unsigned literal_star = file_node("*");
  CHECK(!(graph->nodes[literal_star].doc.flags &
          SHELL_DEP_DOC_FLAG_DYNAMIC_NAME));
  parse("test -e = x"); /* Three-argument binary comparison, not -e x. */
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("test 1 -eq 1");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("test x -a y");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  parse("test -e a -a -d b");
  unsigned combined = 0, count = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_FILE_TEST) {
      combined |= graph->edges[i].flags;
      ++count;
    }
  CHECK(combined == (SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS |
                     SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY));
  CHECK(count == 2);
  /* Connector roles must remain separate from the expanded predicate mask;
   * builtin evaluation records both queries even when a true operand decides
   * the enclosing Boolean expression. */
  parse("test x -o -N first -a -G second");
  combined = count = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_FILE_TEST) {
      combined |= graph->edges[i].flags;
      ++count;
    }
  CHECK(combined == (SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ |
                     SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP));
  CHECK(count == 2);
  parse("test -f '' && cat /unreachable");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_READ ||
          graph->nodes[graph->edges[i].from].type != SHELL_NODE_DOC);
  parse("cd sub && [[ -N config.json ]]");
  unsigned file = file_node("config.json");
  CHECK(!graph->nodes[file].doc.cwd_known);
  parse("cd /src && [[ -N config.json ]]");
  file = file_node("config.json");
  CHECK(graph->nodes[file].doc.cwd_known);
  CHECK(
      !strcmp(graph->cwd_buf.data + graph->nodes[file].doc.cwd_offset, "/src"));
}

static void check_body_setup(void) {
  parse("[[ -n $(printf side >&2; printf value) ]] 2>report");
  unsigned owner = condition_node(), report = file_node("report");
  bool routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    routed |= edge->type == SHELL_EDGE_WRITE && edge->to == report &&
              edge->source_fd == 2 && edge->from != owner;
  }
  CHECK(routed && graph->nodes[owner].cmd.has_redirections);
  parse("[[ -n $(read -r value; printf '%s' \"$value\") ]] <<<hello");
  owner = condition_node();
  bool read_document = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    read_document |= edge->type == SHELL_EDGE_READ && edge->to != owner &&
                     graph->nodes[edge->from].type == SHELL_NODE_DOC &&
                     graph->nodes[edge->from].doc.kind == SHELL_DOC_HERESTRING;
  }
  CHECK(read_document);
  parse("exec 99<&-; [[ -n $(cat body-input) ]] <&99");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_READ);
  parse("[[ -n x ]] {fd}>report; printf x >&$fd");
  report = file_node("report");
  routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    routed |= graph->edges[i].type == SHELL_EDGE_WRITE &&
              graph->edges[i].to == report && graph->edges[i].source_fd == 1;
  CHECK(routed);
  parse("[[ -n <(cat) ]] <parent-input");
  unsigned input = file_node("parent-input");
  owner = condition_node();
  routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    routed |= edge->type == SHELL_EDGE_READ && edge->from == input &&
              edge->to != owner;
    CHECK(!(edge->type == SHELL_EDGE_READ && edge->to == owner));
  }
  CHECK(routed);
  parse("exec 0<&-; [[ -n <(cat)$(read -u0 value) ]] 0<&-");
  parse("time ! { [[ -z '' ]]; } | cat");
  parse("( [[ -n x ]] & ); printf tail");
}

static const char *resolved_value;
static size_t resolved_length;
static unsigned calls;
static SHELL_NONNULL(1, 2, 3) shell_expand_status_t
    resolve(const shell_expand_word_request_t *request, const char **value,
            size_t *length, void *context) {
  (void)context;
  CHECK(request->purpose == SHELL_EXPAND_WORD_CONDITIONAL);
  CHECK(request->cwd_known);
  ++calls;
  *value = resolved_value;
  *length = resolved_length ? resolved_length : strlen(resolved_value);
  return SHELL_EXPAND_RESOLVED;
}

static void check_file_predicate_resolution(void) {
  current = "[[ -N \"$path\" ]]";
  resolved_value = "4:path,";
  resolved_length = 0;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  bool found = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != SHELL_EDGE_FILE_TEST)
      continue;
    const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
    CHECK(doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH);
    CHECK(doc->value_len == 4 && !memcmp(doc->value, "path", 4));
    found = true;
  }
  CHECK(found);
  resolved_value = "0:,";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_OK);
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_FALSE);
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
}

static SHELL_NONNULL(1, 2, 3) shell_expand_status_t
    resolve_nul_argument(const shell_expand_word_request_t *request,
                         const char **value, size_t *length, void *context) {
  (void)context;
  if (request->purpose != SHELL_EXPAND_WORD_ARGUMENT)
    return SHELL_EXPAND_UNRESOLVED;
  static const char encoded[] = {'3', ':', 'a', 0, 'b', ','};
  *value = encoded;
  *length = sizeof(encoded);
  return SHELL_EXPAND_RESOLVED;
}

static void check_file_predicate_nul_argument(void) {
  current = "test -N \"$path\"";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_nul_argument,
                                       NULL, NULL) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  bool found = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type == SHELL_EDGE_FILE_TEST) {
      CHECK(graph->nodes[edge->to].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME);
      found = true;
    }
  }
  CHECK(found);
  current = "test \"$left\" -ef \"$right\"";
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_nul_argument,
                                       NULL, unresolved) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid && unresolved[0]);
  unsigned operands = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    if (graph->edges[e].type == SHELL_EDGE_FILE_LEFT ||
        graph->edges[e].type == SHELL_EDGE_FILE_RIGHT) {
      const shell_dep_doc_t *doc = &graph->nodes[graph->edges[e].to].doc;
      CHECK(doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME);
      ++operands;
    }
  CHECK(operands == 2);
}

static SHELL_NONNULL(1, 2, 3) shell_expand_status_t
    resolve_predicate_path(const shell_expand_word_request_t *request,
                           const char **value, size_t *length, void *context) {
  (void)request;
  if (!context)
    return SHELL_EXPAND_UNRESOLVED;
  *value = context;
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
}

static void check_comparison_operand_contexts(void) {
  static const struct {
    const char *word, *literal;
    bool argument_dynamic, conditional_dynamic, empty;
  } cases[] = {
      {"*", "*", true, false, false},
      {"file?.c", "file?.c", true, false, false},
      {"[ab]", "[ab]", true, false, false},
      {"{a,b}", "{a,b}", true, false, false},
      {"@(a|b)", "@(a|b)", true, false, false},
      {"'*'", "*", false, false, false},
      {"\\*", "*", false, false, false},
      {"'{a,b}'", "{a,b}", false, false, false},
      {"\"$path\"", NULL, true, true, false},
      {"''", "", false, false, true},
  };
  const char *const operators[] = {"-nt", "-ot", "-ef"};
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c)
    for (unsigned form = 0; form < 3; ++form)
      for (unsigned op = 0; op < 3; ++op)
        for (unsigned side = 0; side < 2; ++side)
          for (unsigned mode = 0; mode < 5; ++mode) {
            char source[256];
            int n = snprintf(source, sizeof(source), "%s %s %s %s %s",
                             form == 0   ? "[["
                             : form == 1 ? "test"
                                         : "[",
                             side ? "other" : cases[c].word, operators[op],
                             side ? cases[c].word : "other",
                             form == 0   ? "]]"
                             : form == 1 ? ""
                                         : "]");
            CHECK(n > 0 && (size_t)n < sizeof(source));
            current = source;
            bool unsupported = form && cases[c].argument_dynamic &&
                               !cases[c].conditional_dynamic;
            shell_dep_error_t error;
            if (!mode)
              error = shell_dep_graph_parse(source, (size_t)n, "/workspace",
                                            &limits, graph);
            else
              error = shell_dep_graph_parse_resolved(
                  source, (size_t)n, "/workspace", &limits, graph,
                  mode == 1 ? NULL : resolve_predicate_path,
                  mode == 3   ? (void *)"6:actual,"
                  : mode == 4 ? (void *)"0:,"
                              : NULL,
                  unresolved);
            if (unsupported) {
              /* Builtin admission requires a stable argv cardinality, before
               * callback resolution or comparison attachment. */
              CHECK(error == SHELL_DEP_EPARSE && !graph->node_count &&
                    !graph->edge_count);
              if (mode)
                for (unsigned i = 0; i < SHELL_DEP_MAX_NODES; ++i)
                  CHECK(!unresolved[i]);
              continue;
            }
            CHECK(error == SHELL_DEP_OK);
            CHECK(shell_dep_graph_validate(graph).valid);
            bool dynamic =
                form ? cases[c].argument_dynamic : cases[c].conditional_dynamic;
            bool resolved = dynamic && mode >= 3;
            bool empty = cases[c].empty || (dynamic && mode == 4);
            if (!form) {
              const shell_dep_cmd_t *command =
                  &graph->nodes[condition_node()].cmd;
              bool false_result = empty && (op == 2 || op == side);
              CHECK(command->conditional_truth ==
                    (false_result ? SHELL_CONDITIONAL_FALSE
                                  : SHELL_CONDITIONAL_UNKNOWN));
              CHECK(command->conditional_unresolved == (dynamic && !resolved));
            }
            unsigned count = 0, flagged = 0;
            for (unsigned i = 0; mode && i < SHELL_DEP_MAX_NODES; ++i)
              flagged += unresolved[i] != 0;
            if (mode)
              CHECK(flagged == (unsigned)(dynamic && !resolved));
            for (unsigned e = 0; e < graph->edge_count; ++e) {
              const shell_dep_edge_t *edge = &graph->edges[e];
              if (edge->type !=
                  (side ? SHELL_EDGE_FILE_RIGHT : SHELL_EDGE_FILE_LEFT))
                continue;
              ++count;
              CHECK(graph->nodes[edge->from].file_comparison.empty_operands ==
                    (unsigned)(empty ? 1u << side : 0));
              const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
              CHECK(doc->flags == (resolved && !empty
                                       ? SHELL_DEP_DOC_FLAG_RESOLVED_PATH
                                   : dynamic ? SHELL_DEP_DOC_FLAG_DYNAMIC_NAME
                                             : 0));
              char identity[256] = "unchanged", expected[256];
              size_t written = 17;
              bool absolute = false;
              bool identified = shell_dep_doc_file_identity_write(
                  graph, doc, identity, sizeof(identity), &written, &absolute);
              CHECK(identified == (!empty && (!dynamic || resolved)));
              if (identified) {
                n = snprintf(expected, sizeof(expected), "/workspace/%s",
                             resolved ? "actual" : cases[c].literal);
                CHECK(n > 0 && (size_t)n < sizeof(expected));
                CHECK(absolute && written == (size_t)n &&
                      !strcmp(identity, expected));
              } else
                CHECK(!written && !absolute && !strcmp(identity, "unchanged"));
            }
            CHECK(count == 1);
          }

  const char *const nested[] = {
      "printf '%s' \"$(test \"$path\" -nt other)\"",
      "cat <([ other -ot \"$path\" ])",
  };
  for (unsigned i = 0; i < sizeof(nested) / sizeof(*nested); ++i) {
    current = nested[i];
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, NULL, NULL,
                                         unresolved) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
    unsigned flagged = 0;
    for (unsigned n = 0; n < SHELL_DEP_MAX_NODES; ++n)
      flagged += unresolved[n] != 0;
    CHECK(flagged == 1);
  }
  current = "[[ x || * -nt other ]]";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  for (unsigned i = 0; i < graph->node_count; ++i) {
    CHECK(graph->nodes[i].type != SHELL_NODE_FILE_COMPARISON && !unresolved[i]);
  }
  current = "printf '%s' \"$( [[ * -nt other ]] )\"";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  unsigned literal_operands = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_FILE_LEFT) {
      const shell_dep_doc_t *doc = &graph->nodes[graph->edges[i].to].doc;
      char identity[64];
      size_t written;
      bool absolute;
      CHECK(!doc->flags &&
            shell_dep_doc_file_identity_write(
                graph, doc, identity, sizeof(identity), &written, &absolute));
      CHECK(absolute && written == strlen("/workspace/*") &&
            !strcmp(identity, "/workspace/*"));
      ++literal_operands;
    }
  CHECK(literal_operands == 1);
  current = "test \"$path\" -nt other";
  shell_dep_limits_t truncated = limits;
  truncated.max_nodes = 1;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &truncated, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 1 && unresolved[0] &&
        shell_dep_graph_validate(graph).valid);
  for (unsigned i = graph->node_count; i < SHELL_DEP_MAX_NODES; ++i)
    CHECK(!unresolved[i]);
}

static void check_file_predicate_unresolved_paths(void) {
  static const struct {
    const char *source, *value;
    unsigned flagged;
  } cases[] = {
      {"[[ -N \"$path\" ]]", NULL, 1},
      {"test -N \"$path\"", NULL, 1},
      {"[ -N \"$path\" ]", NULL, 1},
      {"printf '%s' \"$( [[ -N \"$path\" ]] )\"", NULL, 1},
      {"printf '%s' \"$( test -N \"$path\" )\"", NULL, 1},
      {"{ [[ -N \"$path\" ]]; }", NULL, 1},
      {"[[ -N \"$path\" ]]", "4:path,", 0},
      {"test -N \"$path\"", "4:path,", 0},
      {"[[ -N \"$path\" ]]", "0:,", 0},
      {"test -N \"$path\"", "0:,", 0},
      {"[[ -N '' ]]", NULL, 0},
      {"test -N config.json", NULL, 0},
      {"false && [[ -N \"$path\" ]]", NULL, 0},
      {"false && test -N \"$path\"", NULL, 0},
      {"exec 99<&-; [[ -N \"$path\" ]] <&99", NULL, 0},
      {"exec 99<&-; test -N \"$path\" <&99", NULL, 0},
      {"test -n \"$path\"", NULL, 0},
  };
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    current = cases[c].source;
    memset(unresolved, 0xff, sizeof(unresolved));
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, resolve_predicate_path,
                                         (void *)cases[c].value,
                                         unresolved) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
    unsigned flagged = 0;
    for (unsigned i = 0; i < SHELL_DEP_MAX_NODES; ++i) {
      if (!unresolved[i])
        continue;
      CHECK(i < graph->node_count);
      CHECK(graph->nodes[i].type == SHELL_NODE_CMD);
      bool owns_predicate = false;
      for (unsigned e = 0; e < graph->edge_count; ++e)
        owns_predicate |= graph->edges[e].type == SHELL_EDGE_FILE_TEST &&
                          graph->edges[e].from == i;
      CHECK(owns_predicate);
      ++flagged;
    }
    CHECK(flagged == cases[c].flagged);
  }
  current = "test -N \"$path\"";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_nul_argument,
                                       NULL, unresolved) == SHELL_DEP_OK);
  unsigned flagged = 0;
  for (unsigned i = 0; i < graph->node_count; ++i)
    flagged += unresolved[i] != 0;
  CHECK(flagged == 1);

  /* Keep the command owner while denying capacity for its FILE document.
   * The public uncertainty result must survive that output truncation. */
  current = "[[ -N \"$path\" ]]";
  shell_dep_limits_t truncated = limits;
  truncated.max_nodes = 1;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &truncated, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 1 && unresolved[0] == 1);
  for (unsigned i = graph->node_count; i < SHELL_DEP_MAX_NODES; ++i)
    CHECK(unresolved[i] == 0);
}

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    resolve_test_operator(const shell_expand_word_request_t *request,
                          const char **value, size_t *length, void *context) {
  if (request->purpose != SHELL_EXPAND_WORD_ARGUMENT)
    return SHELL_EXPAND_UNRESOLVED;
  *value = context;
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
}

static void parse_test_operator(const char *source, const char *encoded) {
  current = source;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                       &limits, graph, resolve_test_operator,
                                       (void *)encoded, NULL) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

static unsigned predicate_edges(const char *path, unsigned mask) {
  unsigned found = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != SHELL_EDGE_FILE_TEST)
      continue;
    const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
    CHECK(doc->path_len == strlen(path));
    CHECK(!memcmp(doc->path, path, doc->path_len));
    if (edge->flags != mask)
      fprintf(stderr, "predicate flags %#x, expected %#x\n", edge->flags, mask);
    CHECK(edge->flags == mask);
    ++found;
  }
  return found;
}

static bool has_document_read(void) {
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_READ &&
        graph->nodes[graph->edges[i].from].type == SHELL_NODE_DOC)
      return true;
  return false;
}

static void check_test_grammar_refinement(void) {
  const unsigned all = SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_NONEMPTY |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_BLOCK |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_CHARACTER |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_FIFO |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_READABLE |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_WRITABLE |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_EXECUTABLE |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_SETUID |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_SETGID |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_STICKY |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_USER |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP |
                       SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ;
  parse("test -e \"$op\" -e -a -f target && cat <effect");
  CHECK(predicate_edges("target", SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR) == 1);
  CHECK(has_document_read());
  static const struct {
    const char *expression;
    unsigned files;
    bool succeeds;
  } boundaries[] = {
      {"-e \"$op\" x -a -e =", 1, false},
      {"-e \"$op\" -e -o ! -e", 0, true},
      {"-e \"$op\" x -a '(' x -a -e = ')'", 0, false},
      {"-e \"$op\" -e -a '(' x -o ! -e ')'", 0, false},
      {"-e \"$op\" x -a '(' x -a x -a -e = ')'", 0, false},
      {"-e \"$op\" x -a '(' x -a x -o ! -e ')'", 0, false},
  };
  for (unsigned i = 0; i < sizeof(boundaries) / sizeof(*boundaries); ++i)
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char source[256];
      snprintf(source, sizeof(source), "%s %s%s %s cat <effect",
               bracket ? "[" : "test", boundaries[i].expression,
               bracket ? " ]" : "", boundaries[i].succeeds ? "&&" : "||");
      parse(source);
      CHECK(predicate_edges("=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) ==
            boundaries[i].files);
      CHECK(has_document_read());
      parse_test_operator(source, "1:=,");
      CHECK(predicate_edges("=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) ==
            boundaries[i].files);
      CHECK(has_document_read());
    }
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    char source[128];
    snprintf(source, sizeof(source), "%s -e \"$op\" x -a -e =%s && cat <effect",
             bracket ? "[" : "test", bracket ? " ]" : "");
    parse(source);
    CHECK(has_document_read());
    CHECK(predicate_edges("=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
    parse_test_operator(source, "2:!=,");
    CHECK(has_document_read());
    CHECK(predicate_edges("=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
  }
  parse_test_operator("test -e \"$op\" -e -a -f target && cat <effect", "1:=,");
  CHECK(predicate_edges("target", SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR) == 1);
  CHECK(has_document_read());
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    const char *source = bracket ? "[ \"$op\" target ]" : "test \"$op\" target";
    parse(source);
    CHECK(predicate_edges("target", all) == 1);
    parse_test_operator(source, "2:-n,");
    CHECK(predicate_edges("target", 0) == 0);
    parse_test_operator(source, "2:-e,");
    CHECK(predicate_edges("target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
    parse_test_operator(source, "2:-S,");
    CHECK(predicate_edges("target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET) == 1);
    parse_test_operator(source, "2:-N,");
    CHECK(predicate_edges("target",
                          SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ) ==
          1);
  }
  parse_test_operator("test \"$op\" target || cat <unreachable", "2:-n,");
  CHECK(!has_document_read());
  parse_test_operator("test \"$op\" target && cat <input", "2:-n,");
  CHECK(has_document_read());
  parse_test_operator("test \"$op\" target && cat <unreachable", "2:-z,");
  CHECK(!has_document_read());
  parse_test_operator("unset CONFIG; test \"$op\" CONFIG && cat <unreachable",
                      "2:-v,");
  CHECK(!has_document_read());
  CHECK(predicate_edges("CONFIG", 0) == 0);
  parse_test_operator("CONFIG=; test \"$op\" CONFIG && cat <input", "2:-v,");
  CHECK(has_document_read());
  CHECK(predicate_edges("CONFIG", 0) == 0);
  parse_test_operator(
      "unset CONFIG; test -e \"$op\" -e -a -v CONFIG && cat <unreachable",
      "1:=,");
  CHECK(!has_document_read());
  parse_test_operator("CONFIG=; test -e \"$op\" -e -a -v CONFIG && cat <input",
                      "1:=,");
  CHECK(has_document_read());
  current = "test -e \"$op\" -e -a -v 'a[$(printf marker)]'";
  CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &limits,
                              graph) == SHELL_DEP_EPARSE);
  CHECK(!graph->node_count && !graph->edge_count);
  char source[512] = "test -e \"$op\" -e -a -f target";
  unsigned tokens = 7;
  for (; tokens + 3 <= SHELL_DEP_MAX_TOKENS; tokens += 3)
    strcat(source, " -a -f target");
  if (tokens + 2 == SHELL_DEP_MAX_TOKENS)
    strcat(source, " -o x");
  size_t fixed, tail, previous = limits.workspace_size;
  CHECK(shell_dep_workspace_size(NULL, &fixed));
  CHECK(shell_source_workspace_size(strlen(source), &tail));
  limits.workspace_size = fixed + tail;
  parse(source);
  limits.workspace_size = previous;
}

typedef struct {
  const char *values[2];
  const char *words[2];
  bool unresolved[2];
  unsigned calls;
  size_t offsets[2];
} comparison_resolver_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    resolve_comparison(const shell_expand_word_request_t *request,
                       const char **value, size_t *length, void *context) {
  comparison_resolver_t *resolver = context;
  /* Nested executable children can query their own argv independently. */
  if (request->purpose != SHELL_EXPAND_WORD_CONDITIONAL &&
      request->purpose != SHELL_EXPAND_WORD_CONDITIONAL_ARITHMETIC)
    return SHELL_EXPAND_UNRESOLVED;
  CHECK(resolver->calls < 2);
  unsigned index = resolver->calls++;
  resolver->offsets[index] = request->word_offset;
  if (resolver->words[index]) {
    CHECK(request->word_length == strlen(resolver->words[index]));
    CHECK(!memcmp(request->source + request->word_offset,
                  resolver->words[index], request->word_length));
  }
  if (index)
    CHECK(resolver->offsets[0] < resolver->offsets[1]);
  if (resolver->unresolved[index])
    return SHELL_EXPAND_UNRESOLVED;
  *value = resolver->values[index];
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
}

static SHELL_NONNULL(1) bool reads_file(const char *path) {
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *node = &graph->nodes[edge->from];
    if (edge->type == SHELL_EDGE_READ && node->type == SHELL_NODE_DOC &&
        node->doc.kind == SHELL_DOC_FILE &&
        node->doc.path_len == strlen(path) &&
        !memcmp(node->doc.path, path, node->doc.path_len))
      return true;
  }
  return false;
}

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    observe_comparison_branch(const shell_expand_word_request_t *request,
                              const char **value, size_t *length,
                              void *context) {
  (void)value;
  (void)length;
  const char branch[] = "\"$(cat <important.txt)\"";
  if (request->purpose == SHELL_EXPAND_WORD_CONDITIONAL &&
      request->word_length == sizeof(branch) - 1 &&
      !memcmp(request->source + request->word_offset, branch,
              sizeof(branch) - 1))
    ++*(unsigned *)context;
  return SHELL_EXPAND_UNRESOLVED;
}

static void check_conditional_observation_order(void) {
  static const struct {
    const char *prefix;
    bool reaches_suffix;
  } cases[] = {
      {"-e probe && -n \"$(printf x)\"", true},
      {"! ( -e probe && -n \"$(printf x)\" )", true},
      {"-e probe && ( -e other && -n \"$(printf x)\" )", true},
      {"( -e probe && -n \"$(printf x)\" ) || "
       "( -e other && -n \"$(printf y)\" )",
       true},
      {"-e probe && ( -z x && -n \"$(printf skipped)\" )", true},
      {"-e probe && ( -n x || -n \"$(printf skipped)\" )", true},
      {"-n x && -z x", true},
      {"-z x && -n \"$(printf skipped)\"", true},
      {"-n x || -n \"$(printf skipped)\"", false},
  };
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    char source[1024];
    int length = snprintf(source, sizeof(source),
                          "exec 63<<<seed 62<&-; [[ ( %s ) || "
                          "-n \"$(read -r -u63 -n1 before)\"<(printf pipe)"
                          "\"$(read -r -u62 -n1 after)\" ]]",
                          cases[c].prefix);
    CHECK(length > 0 && (size_t)length < sizeof(source));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    parse(source);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    CHECK(shellsplit_test_observation_order_errors() == 0);
#endif
    /* The first read observes the persistent here-string. Only the later read
     * can use the newly allocated process descriptor. Skipped operands retain
     * source nodes but must not acquire either route. */
    unsigned before = UINT32_MAX, after = UINT32_MAX, producer = UINT32_MAX;
    for (unsigned n = 0; n < graph->node_count; ++n) {
      const shell_dep_node_t *node = &graph->nodes[n];
      if (node->type != SHELL_NODE_CMD || !node->cmd.token_count)
        continue;
      unsigned last = node->cmd.token_count - 1;
      const char *word = node->cmd.tokens[last];
      unsigned size = node->cmd.token_lens[last];
      if (size == 6 && !memcmp(word, "before", 6))
        before = n;
      if (size == 5 && !memcmp(word, "after", 5))
        after = n;
      if (size == 4 && !memcmp(word, "pipe", 4))
        producer = n;
    }
    CHECK(before != UINT32_MAX && after != UINT32_MAX &&
          producer != UINT32_MAX);
    bool reads_document = false, reads_process = false;
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      const shell_dep_node_t *origin = &graph->nodes[edge->from];
      reads_document |= edge->type == SHELL_EDGE_READ && edge->to == before &&
                        edge->target_fd == 63 &&
                        origin->type == SHELL_NODE_DOC &&
                        origin->doc.kind == SHELL_DOC_HERESTRING;
      reads_process |= edge->type == SHELL_EDGE_SUBST &&
                       edge->from == producer && edge->to == after &&
                       edge->source_fd == 1 && edge->target_fd == 62;
      CHECK(!(edge->type == SHELL_EDGE_SUBST && edge->from == producer &&
              edge->to == before));
    }
    CHECK(reads_document == cases[c].reaches_suffix);
    CHECK(reads_process == cases[c].reaches_suffix);
  }
}

/* Numeric builtin arguments are decimal integers, unlike arithmetic operands
 * in [[ ... ]]. Verify their effects through the public graph continuation. */
static void count_arithmetic_reference(const char *name, size_t length,
                                       void *context) {
  CHECK(length == 5 && !memcmp(name, "count", length));
  ++*(unsigned *)context;
}

static void check_scalar_arithmetic_boundary(void) {
  unsigned references = 0;
  const char expression[] = "count + 2 * 3";
  shell_arithmetic_scalar_result_t scalar =
      shell_arithmetic_analyze_scalar(expression, sizeof(expression) - 1,
                                      count_arithmetic_reference, &references);
  CHECK(scalar.result.supported && !scalar.result.known && scalar.references);
  CHECK(references == 1);
  CHECK(
      !shell_arithmetic_analyze(expression, sizeof(expression) - 1).supported);
  static const char *const rejected[] = {"count=1", "count[0]"};
  for (unsigned i = 0; i < sizeof(rejected) / sizeof(*rejected); ++i) {
    scalar = shell_arithmetic_analyze_scalar(rejected[i], strlen(rejected[i]),
                                             NULL, NULL);
    CHECK(!scalar.result.supported);
  }
  scalar = shell_arithmetic_analyze_scalar("2#10 + 3", 8, NULL, NULL);
  CHECK(scalar.result.supported && scalar.result.known &&
        scalar.result.value == 5 && !scalar.references);
  static const char *const mutations[] = {
      "++count",   "--count",   "++ count",   "--\tcount",  "count++",
      "count--",   "count++1",  "count--1",   "count ++ 1", "!++count",
      "- --count", "++++count", "0&&++count", "1||count--", "0?++count:1",
  };
  for (unsigned i = 0; i < sizeof(mutations) / sizeof(*mutations); ++i) {
    scalar = shell_arithmetic_analyze_scalar(mutations[i], strlen(mutations[i]),
                                             NULL, NULL);
    CHECK(!scalar.result.supported && scalar.mutation);
  }
  static const char *const pure[] = {
      "1--2",     "++2",      "--2",       "count + +1", "count - -1",
      "+ +count", "- -count", "--(count)", "++(count)",  "1||count",
  };
  for (unsigned i = 0; i < sizeof(pure) / sizeof(*pure); ++i) {
    scalar =
        shell_arithmetic_analyze_scalar(pure[i], strlen(pure[i]), NULL, NULL);
    CHECK(scalar.result.supported && !scalar.mutation);
  }
}

static void check_arithmetic_mutation_rejection(void) {
  static const char *const operands[] = {
      "++count",     "--count",      "'++ count'",        "'count++1'",
      "'! --count'", "'0&&++count'", "'1||count--'",      "'0?++count:1'",
      "'+'+count",   "+\\\n+count",  "\"++count\"$((0))", "'count'$((0))++1",
  };
  for (unsigned i = 0; i < sizeof(operands) / sizeof(*operands); ++i)
    for (unsigned side = 0; side < 2; ++side) {
      char source[256];
      snprintf(source, sizeof(source),
               "cat <before; [[ %s -eq %s ]]; cat <after",
               side ? "0" : operands[i], side ? operands[i] : "0");
      current = source;
      CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                  graph) == SHELL_DEP_EPARSE);
      CHECK(graph->status == SHELL_DEP_STATUS_ERROR && !graph->node_count &&
            !graph->edge_count && !graph->cwd_buf.len);
    }
  /* Pure scalar operators still publish direct reads and coverage status. */
  parse("[[ 'count + +1' -eq 0 ]]");
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  unsigned reads = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    if (graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ) {
      CHECK(shell_dep_doc_env_name_equals(
          &graph->nodes[graph->edges[e].from].doc, "count", 5));
      ++reads;
    }
  CHECK(reads == 1);
}

static void check_numeric_conditional_contract(void) {
  static const struct {
    const char *source;
    shell_conditional_truth_t truth;
  } cases[] = {
      {"[[ 2 -eq 2 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 2 -ne 2 ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ -2 -lt 1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 2 -le 1 ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ 3 -gt 2 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 3 -ge 3 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '2+3' -eq 5 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '1--2' -eq 3 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ ++2 -eq 2 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ --2 -eq 2 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 010 -eq 8 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '' -eq 0 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '0&&count' -eq 0 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '1||count' -eq 1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '0?count:1' -eq 1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 2#10 -eq 2 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '~+0' -eq -1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ \\~+0 -eq -1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ ~+0'' -eq -1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ ~''+0 -eq -1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ \"$((~0))\" -eq -1 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ $((2+3)) -eq 5 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ 1$((2)) -eq 12 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ \"$((2+3))\" -eq 5 ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -t -0 ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -t 0 ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -t -1 ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ -t 2147483648 ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ -t invalid ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ ! -t invalid ]]", SHELL_CONDITIONAL_TRUE},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    parse(cases[i].source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          cases[i].truth);
    CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
    for (unsigned e = 0; e < graph->edge_count; ++e)
      CHECK(graph->edges[e].type != SHELL_EDGE_READ);
  }
  static const char *const protected_sources[] = {
      "[[ '$((1))' -eq 1 ]]",
      "[[ \"\\$((1))\" -eq 1 ]]",
      "[[ '$((1))'+\"$((0))\" -eq 1 ]]",
      "[[ $'\\x24((1))' -eq 1 ]]",
      "[[ '1\\\n+2' -eq 3 ]]",
  };
  for (unsigned i = 0;
       i < sizeof(protected_sources) / sizeof(*protected_sources); ++i) {
    CHECK(shell_parse_draft(protected_sources[i], strlen(protected_sources[i]),
                            NULL, draft) == SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(protected_sources[i],
                                strlen(protected_sources[i]), NULL, &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0);
  }
  size_t fixed;
  CHECK(shell_dep_workspace_size(&limits, &fixed));
  shell_dep_limits_t small = limits;
  small.workspace_size = fixed;
  CHECK(shell_dep_graph_parse("[[ count -eq 0 ]]", strlen("[[ count -eq 0 ]]"),
                              NULL, &small, graph) == SHELL_DEP_EWORKSPACE);
  CHECK(graph->node_count == 0);
  parse("[[ count -eq 0 ]]");
  shell_dep_graph_t *saved = malloc(sizeof(*saved));
  CHECK(saved != NULL);
  memcpy(saved, graph, sizeof(*saved));
  shell_source_result_t other;
  CHECK(shell_parse_draft("[[ '12345678' -eq 1 ]]",
                          strlen("[[ '12345678' -eq 1 ]]"), NULL,
                          &other) == SHELL_SOURCE_COMPLETE);
  for (unsigned e = 0; e < saved->edge_count; ++e)
    if (saved->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ)
      CHECK(shell_dep_doc_env_name_equals(
          &saved->nodes[saved->edges[e].from].doc, "count", 5));
  free(saved);
  static const char *const tildes[] = {
      "~",     "~+0",     "~-0",    "~+0/$((1))", "~+0/$value",
      "~user", "~+\\\n0", "name=~", "name=x:~",
  };
  static const char *const numeric_ops[] = {"-eq", "-ne", "-lt",
                                            "-le", "-gt", "-ge"};
  /* Prefix classification precedes comparison. Exercise all operators with
   * one prefix, and every prefix spelling on both sides with equality. */
  for (unsigned t = 0; t < sizeof(tildes) / sizeof(*tildes); ++t)
    for (unsigned op = 0; op < (t == 0 ? 6u : 1u); ++op)
      for (unsigned side = 0; side < 2; ++side) {
        char source[256];
        snprintf(source, sizeof(source), "[[ ! %s %s %s ]] || cat <fallback",
                 side ? "-1" : tildes[t], numeric_ops[op],
                 side ? tildes[t] : "-1");
        parse(source);
        CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
              SHELL_CONDITIONAL_UNKNOWN);
        CHECK(graph->nodes[condition_node()].cmd.conditional_unresolved);
        CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
        for (unsigned e = 0; e < graph->edge_count; ++e)
          if (graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ)
            CHECK(shell_dep_doc_env_name_equals(
                &graph->nodes[graph->edges[e].from].doc, "value", 5));
      }
  for (unsigned unresolved = 0; unresolved < 2; ++unresolved) {
    comparison_resolver_t resolver = {
        .values = {"1:3,"}, .words = {"~"}, .unresolved = {unresolved}};
    const char *source = "[[ ~ -eq -1 ]] || cat <fallback";
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                         &limits, graph, resolve_comparison,
                                         &resolver, NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 1);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          (unresolved ? SHELL_CONDITIONAL_UNKNOWN : SHELL_CONDITIONAL_FALSE));
    CHECK(!!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC) ==
          !!unresolved);
    CHECK(reads_file("fallback") == !unresolved);
  }
  parse("[[ -z x && ~+0 -eq -1 ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  static const char *const operands[] = {"count", "\"$count\"", "\"${count}\""};
  for (unsigned i = 0; i < sizeof(operands) / sizeof(*operands); ++i) {
    char source[256];
    snprintf(source, sizeof(source), "cat <before; [[ %s -gt 0 ]]; cat <after",
             operands[i]);
    parse(source);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(graph->nodes[condition_node()].cmd.conditional_arithmetic_unresolved);
    CHECK(reads_file("before"));
    CHECK(!reads_file("after"));
    bool dependency = false, later = false;
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (edge->type == SHELL_EDGE_ENV &&
          edge->flags == SHELL_DEP_EDGE_FLAG_ENV_READ) {
        const shell_dep_doc_t *doc = &graph->nodes[edge->from].doc;
        CHECK(doc->value == NULL && doc->value_len == 0);
        CHECK(shell_dep_doc_env_name_equals(doc, "count", 5));
        char name[5];
        size_t written;
        CHECK(shell_dep_doc_write_env_name(doc, name, sizeof(name), &written));
        CHECK(written == 5 && !memcmp(name, "count", 5));
        dependency = true;
      }
    }
    for (unsigned n = condition_node() + 1; n < graph->node_count; ++n)
      if (graph->nodes[n].type == SHELL_NODE_CMD) {
        CHECK(!graph->nodes[n].cmd.cwd_known);
        later = true;
      }
    CHECK(dependency && later);
  }
  static const char *const parameter_sources[] = {
      "[[ \"${count:-$fallback}\" -gt 0 ]]",
      "[[ \"${count:-'$fallback'}\" -gt 0 ]]",
      "test \"$count\" -gt \"$fallback\"",
  };
  for (unsigned i = 0;
       i < sizeof(parameter_sources) / sizeof(*parameter_sources); ++i) {
    parse(parameter_sources[i]);
    bool count_read = false, fallback_read = false;
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (edge->type == SHELL_EDGE_ENV &&
          edge->flags == SHELL_DEP_EDGE_FLAG_ENV_READ) {
        const shell_dep_doc_t *doc = &graph->nodes[edge->from].doc;
        count_read |= shell_dep_doc_env_name_equals(doc, "count", 5);
        fallback_read |= shell_dep_doc_env_name_equals(doc, "fallback", 8);
      }
    }
    CHECK(count_read && fallback_read);
  }
  parse("[[ count -eq 0 ]]; { cat; } <relative-after");
  for (unsigned n = 0; n < graph->node_count; ++n)
    if (graph->nodes[n].type == SHELL_NODE_DOC &&
        graph->nodes[n].doc.kind == SHELL_DOC_FILE)
      CHECK(!graph->nodes[n].doc.cwd_known);
  parse("[[ count -eq 0 ]]; time printf after");
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  parse("[[ co$((1)) -eq 0 ]]");
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  for (unsigned e = 0; e < graph->edge_count; ++e)
    if (graph->edges[e].type == SHELL_EDGE_ENV)
      CHECK(shell_dep_doc_env_name_equals(
          &graph->nodes[graph->edges[e].from].doc, "co1", 3));
  parse("unset later; [[ count -eq 0 && -v later ]]");
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  parse("[[ -z x && count -gt 0 ]] && cat <skipped");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  CHECK(!reads_file("skipped"));
}

static void check_nested_arithmetic_coverage(void) {
  static const char *const sources[] = {
      "cat < <( [[ count -eq 0 ]]; cat <inchild ); cat <after",
      "printf \"%s\" \"$(< <( [[ count -eq 0 ]]; cat <inchild ))\"; cat <after",
      "printf \"$( [[ count -eq 0 ]]; cat <inchild )\"; cat <after",
  };
  for (unsigned i = 0; i < sizeof(sources) / sizeof(*sources); ++i) {
    parse(sources[i]);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(!reads_file("inchild"));
    CHECK(!reads_file("after"));
  }
  parse("[[ -z x && $( [[ count -eq 0 ]] ) -eq 0 ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
}

static void check_conditional_coverage_barrier(void) {
  static const char *const tails[] = {
      "count -eq 0 && \"$path\" -nt other",
      "count -eq 0 || literal -ef other",
      "count -eq 0 && ! ( -f \"$path\" || -d literal )",
      "count -eq 0 || ( -v present && -e literal )",
      "\"$( [[ count -eq 0 ]] )\" -nt other",
      "-f \"$( [[ count -eq 0 ]] )\"",
      "-n \"$( [[ count -eq 0 ]] )\" && -d literal",
  };
  for (unsigned i = 0; i < sizeof(tails) / sizeof(*tails); ++i) {
    char source[512];
    snprintf(source, sizeof(source),
             "present=; [[ -e before && ( %s ) ]]; cat <after", tails[i]);
    parse(source);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_UNKNOWN);
    unsigned observations = 0;
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      CHECK(edge->type != SHELL_EDGE_FILE_COMPARE);
      if (edge->type == SHELL_EDGE_FILE_TEST) {
        const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
        CHECK(doc->path_len == 6 && !memcmp(doc->path, "before", 6));
        ++observations;
      }
    }
    CHECK(observations == 1 && !reads_file("after"));
  }
  parse("[[ -z x && count -eq 0 || -f literal ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  unsigned tests = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    tests += graph->edges[e].type == SHELL_EDGE_FILE_TEST;
  CHECK(tests == 1);

  current = "[[ count -eq 0 && \"$path\" -nt other ]]";
  comparison_resolver_t resolver = {.values = {"1:0,", "6:target,"},
                                    .words = {"count", "\"$path\""}};
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_comparison,
                                       &resolver, NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2 && graph->status == SHELL_DEP_STATUS_OK);
  unsigned comparisons = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    comparisons += graph->edges[e].type == SHELL_EDGE_FILE_COMPARE;
  CHECK(comparisons == 1 && shell_dep_graph_validate(graph).valid);
}

static void check_parameter_operand_dependencies(void) {
  static const struct {
    const char *word;
    bool fallback, count, builtin_scalar;
  } cases[] = {
      {"\"${count#${count:-$'$fallback'}}\"", true, true, false},
      {"\"${1:-$fallback}\"", true, false, false},
      {"\"${10:-${count:-$fallback}}\"", true, true, false},
      {"\"${@:-$fallback}\"", true, false, false},
      {"\"${*:-$fallback}\"", true, false, false},
      {"\"${?:-$fallback}\"", true, false, false},
      {"\"${-:-$fallback}\"", true, false, false},
      {"\"${##$fallback}\"", true, false, false},
      {"\"${?##$fallback}\"", true, false, false},
      {"\"${?\\\n##$fallback}\"", true, false, false},
      {"\"${1:-'$fallback'}\"", true, false, false},
      {"${1:-'$fallback'}", false, false, false},
      {"\"${1#'$fallback'}\"", false, false, false},
      {"\"${#count}\"", false, true, true},
      {"\"${#1}\"", false, false, true},
      {"\"${#?}\"", false, false, true},
      {"\"${#}\"", false, false, true},
      {"\"${!}\"", false, false, true},
      {"\"${!prefix*}\"", false, false, false},
      {"\"${1\\\n0:-$fallback}\"", true, false, false},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
    for (unsigned form = 0; form < 4; ++form) {
      char source[512];
      snprintf(source, sizeof(source),
               form == 0   ? "[[ %s -eq 0 ]]"
               : form == 1 ? "test %s -eq 0"
               : form == 2 ? "[ %s -eq 0 ]"
                           : "[[ -t %s ]]",
               cases[i].word);
      current = source;
      /* Builtin admission deliberately rejects complex parameter operators
       * whose argv cardinality it cannot establish. Keep that boundary. */
      if ((form == 1 || form == 2) && !cases[i].builtin_scalar) {
        CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace",
                                    &limits, graph) == SHELL_DEP_EPARSE);
        continue;
      }
      parse(source);
      for (unsigned resolved = 0; resolved < (form == 0 ? 2u : 1u);
           ++resolved) {
        if (resolved) {
          comparison_resolver_t resolver = {.values = {"1:0,"},
                                            .words = {cases[i].word}};
          CHECK(shell_dep_graph_parse_resolved(
                    source, strlen(source), "/workspace", &limits, graph,
                    resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
          CHECK(resolver.calls == 1);
          CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
        }
        bool fallback = false, count = false;
        for (unsigned e = 0; e < graph->edge_count; ++e)
          if (graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ) {
            const shell_dep_doc_t *doc =
                &graph->nodes[graph->edges[e].from].doc;
            bool f = shell_dep_doc_env_name_equals(doc, "fallback", 8);
            bool c = shell_dep_doc_env_name_equals(doc, "count", 5);
            CHECK(f || c);
            CHECK(!doc->value && !doc->value_len);
            fallback |= f;
            count |= c;
          }
        CHECK(fallback == cases[i].fallback && count == cases[i].count);
      }
    }
  parse("[[ -z x && ${1:-$fallback} -eq 0 ]]");
  for (unsigned e = 0; e < graph->edge_count; ++e)
    CHECK(graph->edges[e].flags != SHELL_DEP_EDGE_FLAG_ENV_READ);
  parse("test x -o \"$fallback\" -eq 0");
  bool read = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    read |= graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ;
  CHECK(read);
}

static void check_builtin_argument_read_phase(void) {
  static const struct {
    const char *source;
    unsigned reads;
  } cases[] = {
      {"test \"$count\" -eq 0", 1},
      {"test \"$count\" -eq 0 1>&- 2>&1", 1},
      {"[ \"$count\" -eq 0 ] 1>&- 2>&1", 1},
      {"1>&- 2>&1 test \"$count\" -eq 0", 1},
      {"test \"$count\" -eq \"$fallback\" 1>&- 2>&1", 2},
      {"test x -o \"$count\" -eq invalid 1>&- 2>&1", 1},
      {"false && test \"$count\" -eq 0", 0},
      {"{ test \"$count\" -eq 0; } 1>&- 2>&1", 0},
      {"test -f \"$count\" 1>&- 2>&1", 1},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    for (unsigned resolved = 0; resolved < 2; ++resolved) {
      if (resolved)
        parse_test_operator(cases[i].source, "1:0,");
      else
        parse(cases[i].source);
      unsigned reads = 0;
      for (unsigned e = 0; e < graph->edge_count; ++e) {
        const shell_dep_edge_t *edge = &graph->edges[e];
        if (edge->flags == SHELL_DEP_EDGE_FLAG_ENV_READ) {
          const shell_dep_doc_t *doc = &graph->nodes[edge->from].doc;
          CHECK(shell_dep_doc_env_name_equals(doc, "count", 5) ||
                shell_dep_doc_env_name_equals(doc, "fallback", 8));
          ++reads;
        }
        CHECK(edge->type != SHELL_EDGE_FILE_TEST);
      }
      CHECK(reads == cases[i].reads);
    }
  }
}

static void check_builtin_integer_comparisons(void) {
  static const struct {
    const char *expression;
    bool success;
  } cases[] = {
      {"2 -eq 2", true},
      {"2 -eq 3", false},
      {"2 -ne 3", true},
      {"2 -ne 2", false},
      {"-2 -lt 1", true},
      {"2 -lt 1", false},
      {"2 -le 2", true},
      {"3 -le 2", false},
      {"3 -gt 2", true},
      {"2 -gt 3", false},
      {"3 -ge 3", true},
      {"2 -ge 3", false},
      {"010 -eq 10", true},
      {"' +10 ' -eq 10", true},
      {"-9223372036854775808 -lt 0", true},
      {"9223372036854775807 -gt 0", true},
      {"9223372036854775808 -eq 0", false},
      {"'' -eq 0", false},
      {"invalid -ne 0", false},
      {"x -o 1 -eq invalid", false},
      {"! 1 -eq invalid", false},
      {"-t -1", false},
      {"-t 2147483648", false},
      {"! -t -1", true},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char source[256];
      snprintf(source, sizeof(source), "%s %s%s && cat <numeric-success",
               bracket ? "[" : "test", cases[i].expression,
               bracket ? " ]" : "");
      parse(source);
      CHECK(reads_file("numeric-success") == cases[i].success);
    }
}

static void check_file_comparison_continuations(void) {
  /* Ordinary executable arguments retain ARG relations; an active cat also
   * has a possible stdin route. Explicit redirects below test file READs. */
  parse("[[ \"$path\" -ef reference ]] && cat important.txt");
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_UNKNOWN);
  bool cat_reads = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *target = &graph->nodes[edge->to];
    cat_reads |= edge->type == SHELL_EDGE_READ &&
                 target->type == SHELL_NODE_CMD && target->cmd.token_count &&
                 target->cmd.token_lens[0] == 3 &&
                 !memcmp(target->cmd.tokens[0], "cat", 3);
  }
  CHECK(cat_reads);

  /* Expected false-kind masks are independent of the evaluator. In particular,
   * unknown operands do not prevent an empty counterpart from proving false. */
  static const struct {
    const char *left, *right;
    unsigned false_kinds, empty_operands;
  } cases[] = {
      {"\"$path\"", "reference", 0, 0},
      {"reference", "\"$path\"", 0, 0},
      {"\"$left\"", "\"$right\"", 0, 0},
      {"''", "\"$path\"", SHELL_FILE_COMPARE_NEWER | SHELL_FILE_COMPARE_SAME,
       1},
      {"\"$path\"", "''", SHELL_FILE_COMPARE_OLDER | SHELL_FILE_COMPARE_SAME,
       2},
      {"''", "''", 7, 3},
  };
  const char *const operators[] = {"-nt", "-ot", "-ef"};
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c)
    for (unsigned op = 0; op < 3; ++op)
      for (unsigned negated = 0; negated < 2; ++negated)
        for (unsigned join = 0; join < 2; ++join) {
          bool known = (cases[c].false_kinds & (1u << op)) != 0;
          shell_conditional_truth_t truth = !known ? SHELL_CONDITIONAL_UNKNOWN
                                            : negated ? SHELL_CONDITIONAL_TRUE
                                                      : SHELL_CONDITIONAL_FALSE;
          bool reached = join ? truth != SHELL_CONDITIONAL_TRUE
                              : truth != SHELL_CONDITIONAL_FALSE;
          for (unsigned form = 0; form < 3; ++form) {
            char source[256];
            snprintf(source, sizeof(source),
                     "%s %s%s %s %s %s %s cat <important.txt",
                     form == 0   ? "[["
                     : form == 1 ? "test"
                                 : "[",
                     negated ? "! " : "", cases[c].left, operators[op],
                     cases[c].right,
                     form == 0   ? "]]"
                     : form == 1 ? ""
                                 : "]",
                     join ? "||" : "&&");
            parse(source);
            CHECK(reads_file("important.txt") == reached);
            unsigned comparisons = 0;
            for (unsigned i = 0; i < graph->node_count; ++i)
              if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON) {
                ++comparisons;
                CHECK(graph->nodes[i].file_comparison.empty_operands ==
                      cases[c].empty_operands);
              }
            CHECK(comparisons == 1);
            if (!form) {
              const shell_dep_cmd_t *command =
                  &graph->nodes[condition_node()].cmd;
              CHECK(command->conditional_truth == truth);
              CHECK(command->conditional_unresolved ==
                    (cases[c].empty_operands != 3));
            }
          }

          char source[256];
          snprintf(source, sizeof(source),
                   "[[ %s( %s %s %s ) %s -n \"$(cat <important.txt)\" ]]",
                   negated ? "! " : "", cases[c].left, operators[op],
                   cases[c].right, join ? "||" : "&&");
          current = source;
          unsigned requests = 0;
          uint8_t unresolved[SHELL_DEP_MAX_NODES];
          CHECK(shell_dep_graph_parse_resolved(
                    source, strlen(source), "/workspace", &limits, graph,
                    observe_comparison_branch, &requests,
                    unresolved) == SHELL_DEP_OK);
          CHECK(shell_dep_graph_validate(graph).valid);
          CHECK(requests == (unsigned)reached);
          CHECK(reads_file("important.txt") == reached);
          unsigned owner = condition_node();
          CHECK(unresolved[owner] == (cases[c].empty_operands != 3));
          CHECK(graph->nodes[owner].cmd.conditional_unresolved ==
                (cases[c].empty_operands != 3 || reached));
        }

  /* Captured emptiness and absent values must remain distinct when both source
   * operands are dynamic. Nonempty captured paths still have unknown metadata.
   */
  static const struct {
    const char *values[2];
    unsigned false_kinds, empty_operands;
  } captured[] = {
      {{NULL, NULL}, 0, 0},
      {{"0:,", NULL}, SHELL_FILE_COMPARE_NEWER | SHELL_FILE_COMPARE_SAME, 1},
      {{NULL, "0:,"}, SHELL_FILE_COMPARE_OLDER | SHELL_FILE_COMPARE_SAME, 2},
      {{"6:actual,", NULL}, 0, 0},
      {{NULL, "6:actual,"}, 0, 0},
      {{"0:,", "0:,"}, 7, 3},
      {{"6:actual,", "6:actual,"}, 0, 0},
  };
  for (unsigned c = 0; c < sizeof(captured) / sizeof(*captured); ++c)
    for (unsigned op = 0; op < 3; ++op) {
      char source[128];
      snprintf(source, sizeof(source),
               "[[ \"$left\" %s \"$right\" ]] && cat <important.txt",
               operators[op]);
      current = source;
      comparison_resolver_t resolver = {
          .values = {captured[c].values[0], captured[c].values[1]},
          .unresolved = {!captured[c].values[0], !captured[c].values[1]}};
      uint8_t unresolved[SHELL_DEP_MAX_NODES];
      CHECK(shell_dep_graph_parse_resolved(
                source, strlen(source), "/workspace", &limits, graph,
                resolve_comparison, &resolver, unresolved) == SHELL_DEP_OK);
      CHECK(resolver.calls == 2 && shell_dep_graph_validate(graph).valid);
      bool known_false = (captured[c].false_kinds & (1u << op)) != 0;
      const shell_dep_cmd_t *command = &graph->nodes[condition_node()].cmd;
      CHECK(
          command->conditional_truth ==
          (known_false ? SHELL_CONDITIONAL_FALSE : SHELL_CONDITIONAL_UNKNOWN));
      CHECK(reads_file("important.txt") == !known_false);
      CHECK(command->conditional_unresolved ==
            (resolver.unresolved[0] || resolver.unresolved[1]));
      CHECK(unresolved[condition_node()] == command->conditional_unresolved);
      for (unsigned i = 0; i < graph->node_count; ++i)
        if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON)
          CHECK(graph->nodes[i].file_comparison.empty_operands ==
                captured[c].empty_operands);
    }
}

static void check_comparisons(void) {
  current = "[[ ! 'left' != \"right\" ]]";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_COMPLETE);
  shell_source_header_t *header = &draft->headers[0];
  CHECK(header->conditional_operand_count == 2);
  CHECK(header->conditional_predicate == SHELL_CONDITIONAL_STRING_NOT_EQUAL);
  CHECK(header->conditional_negated);
  CHECK(header->conditional_operands[0].length == 6 &&
        header->conditional_operands[1].length == 7);
  parse(current);
  const shell_dep_cmd_t *condition = &graph->nodes[condition_node()].cmd;
  CHECK(condition->conditional_operand_count == 2);
  CHECK(condition->conditional_predicate == header->conditional_predicate);
  CHECK(condition->conditional_negated == header->conditional_negated);
  CHECK(condition->conditional_truth == SHELL_CONDITIONAL_FALSE);
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(current, strlen(current), NULL, &processed) ==
        SHELL_PROCESS_OK);
  const shell_command_info_t *owned = &processed.commands[0];
  CHECK(owned->conditional_operand_count == 2);
  CHECK(owned->conditional_predicate == condition->conditional_predicate);
  CHECK(owned->conditional_negated);
  for (unsigned i = 0; i < 2; ++i) {
    CHECK(owned->conditional_operand_lengths[i] ==
          condition->conditional_operand_lengths[i]);
    CHECK(owned->conditional_operands[i] >= owned->original_command);
    CHECK(owned->conditional_operands[i] +
              owned->conditional_operand_lengths[i] <=
          owned->original_command + strlen(owned->original_command));
    CHECK(!memcmp(owned->conditional_operands[i],
                  condition->conditional_operands[i],
                  owned->conditional_operand_lengths[i]));
  }
  shell_processed_commands_free(&processed);

  for (unsigned unequal = 0; unequal < 2; ++unequal)
    for (unsigned unresolved = 0; unresolved < 4; ++unresolved) {
      current = "[[ \"$left\" == \"$right\" ]]";
      comparison_resolver_t resolver = {
          .values = {"1:x,", unequal ? "1:y," : "1:x,"},
          .unresolved = {unresolved & 1, unresolved & 2}};
      CHECK(shell_dep_graph_parse_resolved(
                current, strlen(current), "/workspace", &limits, graph,
                resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
      CHECK(resolver.calls == 2);
      CHECK(shell_dep_graph_validate(graph).valid);
      CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
            (unresolved ? SHELL_CONDITIONAL_UNKNOWN
             : unequal  ? SHELL_CONDITIONAL_FALSE
                        : SHELL_CONDITIONAL_TRUE));
    }
  static const char *const mixed[] = {"[[ x == \"$right\" ]]",
                                      "[[ $left == \"x\" ]]"};
  for (unsigned i = 0; i < 2; ++i) {
    current = mixed[i];
    comparison_resolver_t resolver = {.values = {"1:x,"}};
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, resolve_comparison,
                                         &resolver, NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 1);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_TRUE);
  }
  static const char *const malformed[] = {"", "0:,1:x,", "1:x"};
  for (unsigned side = 0; side < 2; ++side)
    for (unsigned i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
      current = "[[ $left == \"$right\" ]]";
      comparison_resolver_t resolver = {.values = {"1:x,", "1:x,"}};
      resolver.values[side] = malformed[i];
      CHECK(shell_dep_graph_parse_resolved(
                current, strlen(current), "/workspace", &limits, graph,
                resolve_comparison, &resolver, NULL) == SHELL_DEP_EEXPAND);
      CHECK(!graph->node_count && !graph->edge_count);
    }

  parse("[[ <(printf x) == \"$(read -r -u63 value)\" ]]");
  bool read_process = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    read_process |=
        graph->edges[e].type == SHELL_EDGE_SUBST &&
        graph->edges[e].source_fd == 1 && graph->edges[e].target_fd == 63 &&
        graph->nodes[graph->edges[e].to].type == SHELL_NODE_CMD &&
        graph->nodes[graph->edges[e].to].cmd.token_count &&
        graph->nodes[graph->edges[e].to].cmd.token_lens[0] == 4 &&
        !memcmp(graph->nodes[graph->edges[e].to].cmd.tokens[0], "read", 4);
  CHECK(read_process);
  parse("[[ x == \"$(cat)\" ]] <<<payload");
  bool read_document = false;
  for (unsigned e = 0; e < graph->edge_count; ++e) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    read_document |= edge->type == SHELL_EDGE_READ &&
                     graph->nodes[edge->from].type == SHELL_NODE_DOC &&
                     graph->nodes[edge->from].doc.kind == SHELL_DOC_HERESTRING;
  }
  CHECK(read_document);
  parse("exec 99<&-; [[ $(cat left-file) == \"$(cat right-file)\" ]] <&99");
  for (unsigned e = 0; e < graph->edge_count; ++e)
    CHECK(graph->edges[e].type != SHELL_EDGE_READ);
  /* A producer's failed return status does not stop comparison expansion. */
  current = "[[ $(false) == \"$(cat right-file)\" ]]";
  comparison_resolver_t resolver = {.values = {"0:,", "1:x,"}};
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_comparison,
                                       &resolver, NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2);
  bool right_read = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    right_read |= graph->edges[e].type == SHELL_EDGE_READ;
  CHECK(right_read);

  for (unsigned truth = 0; truth < 2; ++truth) {
    parse(truth ? "[[ x == \"x\" ]] && cat reached"
                : "[[ x != \"x\" ]] && cat reached");
    unsigned reads = 0;
    for (unsigned e = 0; e < graph->edge_count; ++e)
      reads += graph->edges[e].type == SHELL_EDGE_READ;
    CHECK((reads != 0) == (truth != 0));
  }
  current = "printf before; [[ $(printf left) == \"$(printf right)\"";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(draft->prefix_length == strlen("printf before;"));
  CHECK(draft->header_count == 4 &&
        draft->headers[1].conditional_operand_count == 2);
  CHECK(draft->headers[2].complete && draft->headers[3].complete);
}

static const shell_source_header_t *retained_condition(void) {
  for (unsigned h = 0; h < draft->header_count; ++h)
    if (draft->headers[h].kind == SHELL_COMMAND_CONDITIONAL)
      return &draft->headers[h];
  CHECK(false);
  return NULL;
}

static void check_grouped_draft_summaries(void) {
  static const struct {
    const char *primary, *operands[2];
    shell_conditional_predicate_t predicate;
    unsigned children;
  } cases[] = {
      {"-n value", {"value", NULL}, SHELL_CONDITIONAL_STRING_NONEMPTY, 0},
      {"left -nt right", {"left", "right"}, SHELL_CONDITIONAL_FILE_NEWER, 0},
      {"-v CONFIG", {"CONFIG", NULL}, SHELL_CONDITIONAL_VARIABLE_SET, 0},
      {"-n \"$(printf child)\"",
       {"\"$(printf child)\"", NULL},
       SHELL_CONDITIONAL_STRING_NONEMPTY,
       1},
  };
  static const char *const tails[] = {"",   " \\",  " ]",  " ]\\", " ]\\\n",
                                      " &", " |\\", " ]]", " ]]\\"};
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c)
    for (unsigned groups = 0; groups <= 3; ++groups)
      for (unsigned mask = 0; mask < (1u << (groups + 1)); ++mask)
        for (unsigned closed = 0; closed <= groups; ++closed)
          for (unsigned tail = 0; tail < sizeof(tails) / sizeof(*tails);
               ++tail) {
            char source[512] = "printf before; [[ ";
            bool negated = false;
            for (unsigned level = 0; level <= groups; ++level) {
              if (mask & (1u << level)) {
                strcat(source, "! ");
                negated = !negated;
              }
              if (level < groups)
                strcat(source, "( ");
            }
            size_t primary_start = strlen(source);
            strcat(source, cases[c].primary);
            for (unsigned level = 0; level < closed; ++level)
              strcat(source, " )");
            strcat(source, tails[tail]);
            current = source;
            bool invalid = closed < groups && strchr(tails[tail], ']');
            bool complete = !invalid && !strcmp(tails[tail], " ]]");
            CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
                  (invalid    ? SHELL_SOURCE_INVALID
                   : complete ? SHELL_SOURCE_COMPLETE
                              : SHELL_SOURCE_INCOMPLETE));
            if (invalid) {
              CHECK(!draft->prefix_length && !draft->prefix.count);
              continue;
            }
            const shell_source_header_t *header = retained_condition();
            CHECK(header->complete == complete);
            CHECK(header->conditional_predicate == cases[c].predicate);
            CHECK(header->conditional_negated == negated);
            unsigned operands = cases[c].operands[1] ? 2 : 1;
            CHECK(header->conditional_operand_count == operands);
            for (unsigned i = 0; i < operands; ++i) {
              shell_source_span_t word = header->conditional_operands[i];
              CHECK(word.start == (size_t)(strstr(source + primary_start,
                                                  cases[c].operands[i]) -
                                           source));
              CHECK(word.length == strlen(cases[c].operands[i]));
            }
            CHECK(draft->header_count == 2 + cases[c].children);
            if (cases[c].children)
              CHECK(draft->headers[2].complete);
            if (!complete) {
              CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
              CHECK(draft->prefix_length == strlen("printf before;") &&
                    draft->prefix.count == 1);
            }
          }

  static const struct {
    const char *source;
    shell_conditional_predicate_t predicate;
    const char *operands[2];
    bool negated;
  } unfinished_words[] = {
      {"[[ ! ( -n \"value]",
       SHELL_CONDITIONAL_STRING_NONEMPTY,
       {"\"value]", NULL},
       true},
      {"[[ ! ( -n \"value",
       SHELL_CONDITIONAL_STRING_NONEMPTY,
       {"\"value", NULL},
       true},
      {"[[ ! ( ! ( left -nt \"right",
       SHELL_CONDITIONAL_FILE_NEWER,
       {"left", "\"right"},
       false},
      {"[[ ! ( -n \"$(printf child",
       SHELL_CONDITIONAL_STRING_NONEMPTY,
       {"\"$(printf child", NULL},
       true},
  };
  for (unsigned c = 0; c < sizeof(unfinished_words) / sizeof(*unfinished_words);
       ++c) {
    current = unfinished_words[c].source;
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    const shell_source_header_t *header = retained_condition();
    CHECK(header->conditional_predicate == unfinished_words[c].predicate);
    CHECK(header->conditional_negated == unfinished_words[c].negated);
    unsigned count = unfinished_words[c].operands[1] ? 2 : 1;
    CHECK(header->conditional_operand_count == count);
    for (unsigned i = 0; i < count; ++i) {
      shell_source_span_t span = header->conditional_operands[i];
      const char *word = unfinished_words[c].operands[i];
      CHECK(span.length == strlen(word));
      CHECK(!memcmp(current + span.start, word, span.length));
    }
  }

  /* A committed connector makes the summary compound even if its right term
   * has not arrived. Lexical children remain available through their headers.
   */
  static const char *const compounds[] = {
      "[[ -n value &&",
      "[[ ( -n value ) ||",
      "[[ ! ( -n value && -n \"$(printf child)\"",
      "[[ ! ( -n value || ! ( -n child ) ) ]",
  };
  for (unsigned i = 0; i < sizeof(compounds) / sizeof(*compounds); ++i) {
    current = compounds[i];
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    const shell_source_header_t *header = retained_condition();
    CHECK(header->conditional_predicate == SHELL_CONDITIONAL_PREDICATE_NONE);
    CHECK(!header->conditional_operand_count && !header->conditional_negated);
    CHECK(draft->header_count == (strstr(current, "$(") ? 2u : 1u));
  }
}

static void check_mixed_literal_comparisons(void) {
  static const struct {
    const char *word, *value;
  } cases[] = {
      {"\"$right\".txt", "a*?[()].txt"},
      {"release-\"$right\"", "release-"},
      {"pre\"$right\"post", "prea bpost"},
      {"\"$right\"\"${other:-fallback}\".txt", "afallback.txt"},
      {"\"$(printf '%s' \"$right\")\".txt", "value.txt"},
      {"\"${right#x*}\".txt", "value.txt"},
      {"\"$right\"\\*.txt", "value*.txt"},
      {"\"$right\"'?[()]'", "value?[()]"},
      {"~\"$right\"", "~value"},
      {"name=~\"$right\"", "name=~value"},
      {"name=prefix:~\"$right\"", "name=prefix:~value"},
      {"$'\\0discard'\"$right\".txt", "value.txt"},
      {"pre\\\n\"$right\".txt", "prevalue.txt"},
      {"日本\"$right\".txt", "日本語.txt"},
      {"\"$right\"$'\\xff'", "value\xff"},
      {"\"$@\".txt", "one two.txt"},
  };
  static const char *const operators[] = {"=", "==", "!="};
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    for (unsigned op = 0; op < 3; ++op)
      for (unsigned negate = 0; negate < 2; ++negate)
        for (unsigned unequal = 0; unequal < 2; ++unequal)
          for (unsigned unresolved = 0; unresolved < 4; ++unresolved) {
            char source[256], left[128], right[128];
            snprintf(source, sizeof(source), "[[ %s\"$left\" %s %s ]]",
                     negate ? "! " : "", operators[op], cases[i].word);
            snprintf(left, sizeof(left), "%zu:%s%s,",
                     strlen(cases[i].value) + unequal, cases[i].value,
                     unequal ? "!" : "");
            snprintf(right, sizeof(right), "%zu:%s,", strlen(cases[i].value),
                     cases[i].value);
            current = source;
            comparison_resolver_t resolver = {
                .values = {left, right},
                .words = {"\"$left\"", cases[i].word},
                .unresolved = {unresolved & 1, unresolved & 2}};
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 2);
            const shell_dep_cmd_t *condition =
                &graph->nodes[condition_node()].cmd;
            CHECK(condition->conditional_predicate ==
                  (op == 2 ? SHELL_CONDITIONAL_STRING_NOT_EQUAL
                           : SHELL_CONDITIONAL_STRING_EQUAL));
            bool truth = (unequal == (op == 2)) != (negate != 0);
            CHECK(condition->conditional_truth ==
                  (unresolved ? SHELL_CONDITIONAL_UNKNOWN
                   : truth    ? SHELL_CONDITIONAL_TRUE
                              : SHELL_CONDITIONAL_FALSE));
            CHECK(shell_dep_graph_validate(graph).valid);
          }

  /* Each callback receives a complete word; both child input routes survive. */
  current = "[[ \"$(cat <left-file)\" == pre\"$(cat <right-file)\"post ]]";
  comparison_resolver_t resolver = {
      .values = {"8:preapost,", "8:preapost,"},
      .words = {"\"$(cat <left-file)\"", "pre\"$(cat <right-file)\"post"}};
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve_comparison,
                                       &resolver, NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2);
  file_node("left-file");
  file_node("right-file");

  /* Left process allocation precedes the right operand's read from its fd. */
  parse("[[ <(printf x) == pre\"$(read -r -u63 value)\"post ]]");
  bool read_process = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    read_process |= graph->edges[e].type == SHELL_EDGE_SUBST &&
                    graph->edges[e].source_fd == 1 &&
                    graph->edges[e].target_fd == 63;
  CHECK(read_process);

  for (unsigned mode = 0; mode < 3; ++mode) {
    current = "[[ \"$left\" == pre\"$right\".txt ]] && cat reached";
    resolver = (comparison_resolver_t){
        .values = {mode == 0 ? "8:prex.txt," : "5:other,", "8:prex.txt,"},
        .unresolved = {mode == 2, false}};
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, resolve_comparison,
                                         &resolver, NULL) == SHELL_DEP_OK);
    bool read = false;
    for (unsigned e = 0; e < graph->edge_count; ++e)
      read |= graph->edges[e].type == SHELL_EDGE_READ;
    CHECK(read == (mode != 1));
  }
}

static void check_tilde_comparisons(void) {
  static const struct {
    const char *word, *value;
    bool dynamic;
  } cases[] = {
      {"name=~", "name=/model-home", true},
      {"name+=~", "name+=/model-home", true},
      {"name=prefix:~", "name=prefix:/model-home", true},
      {"name='prefix':~", "name=prefix:/model-home", true},
      {"arr[0]=~", "arr[0]=/model-home", true},
      {"arr['0']+=~", "arr[0]+=/model-home", true},
      {"a[:~/x]=~", "a[:/model-home/x]=/model-home", true},
      {"a[=~/x]=~", "a[=/model-home/x]=~", true},
      {"na\\\nme=\\\n~", "name=/model-home", true},
      {"name=prefix:\\\n~", "name=prefix:/model-home", true},
      {"name='~'", "name=~", false},
      {"name=\"~\"", "name=~", false},
      {"name=\\~", "name=~", false},
      {"name=~''", "name=~", false},
      {"name=~\"\"/x", "name=~/x", false},
      {"~''", "~", false},
      {"name\\=~", "name=~", false},
      {"1name=~", "1name=~", false},
      {"name:~", "name:~", false},
      {"name=x=~", "name=x=~", false},
      {"*", "*", false},
      {"{a,b}", "{a,b}", false},
      {"@(a|b)", "@(a|b)", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char source[256], record[128];
    snprintf(source, sizeof(source), "[[ %s == '%s' ]]", cases[i].word,
             cases[i].value);
    snprintf(record, sizeof(record), "%zu:%s,", strlen(cases[i].value),
             cases[i].value);
    parse(source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          (cases[i].dynamic ? SHELL_CONDITIONAL_UNKNOWN
                            : SHELL_CONDITIONAL_TRUE));
    for (unsigned unresolved = 0; unresolved < 2; ++unresolved) {
      comparison_resolver_t resolver = {.values = {record},
                                        .unresolved = {unresolved}};
      CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                           &limits, graph, resolve_comparison,
                                           &resolver, NULL) == SHELL_DEP_OK);
      CHECK(resolver.calls == cases[i].dynamic);
      CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
            (unresolved && cases[i].dynamic ? SHELL_CONDITIONAL_UNKNOWN
                                            : SHELL_CONDITIONAL_TRUE));
      CHECK(shell_dep_graph_validate(graph).valid);
    }
  }

  /* Before resolution both continuations are possible. After expansion the
   * operand differs from its spelling, so equality must take the false path. */
  static const char *const operators[] = {"=", "==", "!="};
  for (unsigned op = 0; op < 3; ++op)
    for (unsigned negate = 0; negate < 2; ++negate)
      for (unsigned failure = 0; failure < 2; ++failure)
        for (unsigned mode = 0; mode < 3; ++mode) {
          char source[128];
          snprintf(source, sizeof(source),
                   "[[ %sname=~ %s 'name=~' ]] %s cat reached",
                   negate ? "! " : "", operators[op], failure ? "||" : "&&");
          current = source;
          comparison_resolver_t resolver = {.values = {"16:name=/model-home,"},
                                            .unresolved = {mode == 1}};
          if (mode == 0)
            parse(source);
          else {
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 1);
          }
          bool truth = (op == 2) != (negate != 0);
          CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
                (mode != 2 ? SHELL_CONDITIONAL_UNKNOWN
                 : truth   ? SHELL_CONDITIONAL_TRUE
                           : SHELL_CONDITIONAL_FALSE));
          bool reads = false;
          for (unsigned e = 0; e < graph->edge_count; ++e)
            reads |= graph->edges[e].type == SHELL_EDGE_READ;
          CHECK(reads == (mode != 2 || truth != (failure != 0)));
        }
}

static void check_patterns(void) {
  static const struct {
    const char *source;
    shell_conditional_predicate_t predicate;
  } forms[] = {
      {"[[ x == x ]]", SHELL_CONDITIONAL_STRING_EQUAL},
      {"[[ '*' == \\* ]]", SHELL_CONDITIONAL_STRING_EQUAL},
      {"[[ x == '*' ]]", SHELL_CONDITIONAL_STRING_EQUAL},
      {"[[ x == * ]]", SHELL_CONDITIONAL_PATTERN_MATCH},
      {"[[ x != x* ]]", SHELL_CONDITIONAL_PATTERN_NOT_MATCH},
      {"[[ x == \"\"* ]]", SHELL_CONDITIONAL_PATTERN_MATCH},
      {"[[ -v UID ]]", SHELL_CONDITIONAL_VARIABLE_SET},
      {"[[ -e config.json ]]", SHELL_CONDITIONAL_FILE_EXISTS},
      {"[[ -f config.json ]]", SHELL_CONDITIONAL_FILE_REGULAR},
      {"[[ -d output ]]", SHELL_CONDITIONAL_FILE_DIRECTORY},
      {"[[ -L current ]]", SHELL_CONDITIONAL_FILE_SYMLINK},
      {"[[ -h current ]]", SHELL_CONDITIONAL_FILE_SYMLINK},
      {"[[ -a current ]]", SHELL_CONDITIONAL_FILE_EXISTS},
      {"[[ -s current ]]", SHELL_CONDITIONAL_FILE_NONEMPTY},
      {"[[ -b current ]]", SHELL_CONDITIONAL_FILE_BLOCK},
      {"[[ -c current ]]", SHELL_CONDITIONAL_FILE_CHARACTER},
      {"[[ -p current ]]", SHELL_CONDITIONAL_FILE_FIFO},
      {"[[ -S current ]]", SHELL_CONDITIONAL_FILE_SOCKET},
      {"[[ -r current ]]", SHELL_CONDITIONAL_FILE_READABLE},
      {"[[ -w current ]]", SHELL_CONDITIONAL_FILE_WRITABLE},
      {"[[ -x current ]]", SHELL_CONDITIONAL_FILE_EXECUTABLE},
      {"[[ -u current ]]", SHELL_CONDITIONAL_FILE_SETUID},
      {"[[ -g current ]]", SHELL_CONDITIONAL_FILE_SETGID},
      {"[[ -k current ]]", SHELL_CONDITIONAL_FILE_STICKY},
      {"[[ -O current ]]", SHELL_CONDITIONAL_FILE_OWNED_BY_USER},
      {"[[ -G current ]]", SHELL_CONDITIONAL_FILE_OWNED_BY_GROUP},
      {"[[ -N current ]]", SHELL_CONDITIONAL_FILE_MODIFIED_SINCE_READ},
  };
  for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
    parse(forms[i].source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_predicate ==
          forms[i].predicate);
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft->headers[0].conditional_predicate == forms[i].predicate);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(current, strlen(current), NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.commands[0].conditional_predicate == forms[i].predicate);
    shell_processed_commands_free(&processed);
  }
  static const char *const operators[] = {"=", "==", "!="};
  for (unsigned op = 0; op < 3; ++op)
    for (unsigned negate = 0; negate < 2; ++negate)
      for (unsigned matches = 0; matches < 2; ++matches)
        for (unsigned failure = 0; failure < 2; ++failure)
          for (unsigned unresolved = 0; unresolved < 2; ++unresolved) {
            char source[128];
            snprintf(source, sizeof(source),
                     "[[ %s$value %s \"file\"* ]] %s cat reached",
                     negate ? "! " : "", operators[op], failure ? "||" : "&&");
            current = source;
            comparison_resolver_t resolver = {
                .values = {matches ? "8:file.txt," : "6:xfile*,"},
                .unresolved = {unresolved}};
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 1);
            bool truth = (matches != (op == 2)) != (negate != 0);
            CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
                  (unresolved ? SHELL_CONDITIONAL_UNKNOWN
                   : truth    ? SHELL_CONDITIONAL_TRUE
                              : SHELL_CONDITIONAL_FALSE));
            bool reads = false;
            for (unsigned e = 0; e < graph->edge_count; ++e)
              reads |= graph->edges[e].type == SHELL_EDGE_READ;
            CHECK(reads == (unresolved || truth != (failure != 0)));
          }

  size_t fixed, previous_size = limits.workspace_size;
  CHECK(shell_dep_workspace_size(NULL, &fixed));
  limits.workspace_size = fixed;
  char large_pattern[128] = "[[ x == *";
  size_t offset = strlen(large_pattern);
  memset(large_pattern + offset, 'x', 64);
  strcpy(large_pattern + offset + 64, "* ]]");
  current = large_pattern;
  CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &limits,
                              graph) == SHELL_DEP_EWORKSPACE);
  CHECK(!graph->node_count && !graph->edge_count);
  limits.workspace_size = previous_size;
  parse(large_pattern);
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_FALSE);
}

static void check_token_prefixes(void) {
  for (size_t i = 0; i < sizeof(conditional_prefix_cases) /
                             sizeof(conditional_prefix_cases[0]);
       ++i) {
    const char *tail = conditional_prefix_cases[i].source;
    current = tail;
    CHECK(shell_parse_draft(tail, strlen(tail), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(!draft->prefix_length && !draft->prefix.count);
    const shell_source_header_t *header = retained_condition();
    CHECK(!header->complete);
    CHECK(header->conditional_operand_count ==
          conditional_prefix_cases[i].operands);
    for (unsigned operand = 0; operand < header->conditional_operand_count;
         ++operand) {
      shell_source_span_t word = header->conditional_operands[operand];
      CHECK(word.length > 0 && word.start + word.length <= strlen(tail));
    }
    CHECK(header->conditional_operands[0].start +
              header->conditional_operands[0].length <
          strlen(tail));
    CHECK(shell_dep_graph_parse(tail, strlen(tail), "/workspace", &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(!graph->node_count && !graph->edge_count);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(tail, strlen(tail), NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(!processed.commands && !processed.command_count);
    char source[512];
    snprintf(source, sizeof(source), "printf before; %s", tail);
    current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(draft->prefix_length == strlen("printf before;") &&
          draft->prefix.count == 1);
    CHECK(!retained_condition()->complete);

    snprintf(source, sizeof(source), "printf before; { %s", tail);
    current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->prefix_length == strlen("printf before;") &&
          draft->prefix.count == 1);
    CHECK(!retained_condition()->complete);

    /* A still-open child permits extension, while its outer source owns the
     * missing-substitution diagnostic. A closed child commits the same bytes.
     */
    snprintf(source, sizeof(source), "printf before; printf $(%s", tail);
    current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_SUBSTITUTION ||
          draft->need == SHELL_SOURCE_NEEDS_ESCAPE);
    CHECK(draft->prefix_length == strlen("printf before;"));
    CHECK(!retained_condition()->complete);
    static const char *const wrappers[] = {"printf before; printf $(%s)",
                                           "printf before; cat <(%s)",
                                           "printf before; printf `%s`"};
    /* A final escape immediately before a wrapper closer would quote that
     * closer. Use a nonescaping token prefix for these closed-child cases. */
    if (tail[strlen(tail) - 1] != '\\')
      for (unsigned wrapper = 0;
           wrapper < sizeof(wrappers) / sizeof(wrappers[0]); ++wrapper) {
        /* Backticks needing an escape-decoding layer remain unsupported. */
        if (wrapper == 2 && strchr(tail, '\\'))
          continue;
        snprintf(source, sizeof(source), wrappers[wrapper], tail);
        current = source;
        CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
              SHELL_SOURCE_INVALID);
        CHECK(!draft->prefix_length && !draft->prefix.count);
      }
    snprintf(source, sizeof(source), "%s%s", tail,
             conditional_prefix_cases[i].completion);
    current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(retained_condition()->complete);
    parse(source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          (shell_conditional_truth_t)conditional_prefix_cases[i].truth);
  }
}

static void check_binary_and_compound_conditions(void) {
  static const char *const comparisons[] = {"-nt", "-ot", "-ef"};
  for (unsigned kind = 0; kind < 3; ++kind)
    for (unsigned form = 0; form < 3; ++form) {
      char source[160];
      snprintf(source, sizeof(source), "%s left %s right %s",
               form == 0   ? "[["
               : form == 1 ? "test"
                           : "[",
               comparisons[kind],
               form == 0   ? "]]"
               : form == 1 ? ""
                           : "]");
      parse(source);
      unsigned count = 0;
      for (unsigned i = 0; i < graph->node_count; ++i) {
        if (graph->nodes[i].type != SHELL_NODE_FILE_COMPARISON)
          continue;
        ++count;
        CHECK(graph->nodes[i].file_comparison.predicates == (1u << kind));
        CHECK(graph->nodes[i].file_comparison.empty_operands == 0);
        unsigned left = 0, right = 0, owner = 0;
        for (unsigned e = 0; e < graph->edge_count; ++e) {
          const shell_dep_edge_t *edge = &graph->edges[e];
          owner += edge->type == SHELL_EDGE_FILE_COMPARE && edge->to == i;
          if (edge->from != i)
            continue;
          const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
          if (edge->type == SHELL_EDGE_FILE_LEFT) {
            CHECK(doc->path_len == 4 && !memcmp(doc->path, "left", 4));
            ++left;
          } else if (edge->type == SHELL_EDGE_FILE_RIGHT) {
            CHECK(doc->path_len == 5 && !memcmp(doc->path, "right", 5));
            ++right;
          }
        }
        CHECK(left == 1 && right == 1 && owner == 1);
      }
      CHECK(count == 1);
    }
  static const struct {
    const char *source;
    shell_conditional_truth_t truth;
  } cases[] = {
      {"[[ x && y ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '' || y ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ x || '' && '' ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ ( x || '' ) && '' ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ ! ( x && '' ) ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ !(x) ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ ! (x) ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ !<() ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '' -nt path ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ path -ot '' ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ '' -ef path ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ path -nt '' ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ '' -ot path ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ path -ef path ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -f path && -r path ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"[[ x || -n $(cat skipped) ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ '' && -n $(cat skipped) ]]", SHELL_CONDITIONAL_FALSE},
      {"unset item; [[ -v item && -n $(cat skipped) ]]",
       SHELL_CONDITIONAL_FALSE},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    parse(cases[i].source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          cases[i].truth);
    if (strstr(cases[i].source, "skipped"))
      for (unsigned e = 0; e < graph->edge_count; ++e)
        CHECK(graph->edges[e].type != SHELL_EDGE_SUBST);
  }
  parse("echo \"$( [[ first -ef second || -r third ]] )\"");
  parse("test left \"$operator\" right");
  unsigned comparisons_count = 0;
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON) {
      ++comparisons_count;
      CHECK(graph->nodes[i].file_comparison.predicates == 7);
    }
  CHECK(comparisons_count == 1);
  current = "[[ -n \"$left\" && -n \"$right";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->headers[0].conditional_predicate ==
            SHELL_CONDITIONAL_PREDICATE_NONE &&
        draft->headers[0].conditional_operand_count == 0);
  static const char *const join_prefixes[] = {
      "[[ x &",     "[[ -n x |",   "[[ (x) &", "[[ ( -n x && x ) |",
      "[[ (x) &\\", "[[ (x) |\\\n"};
  for (unsigned i = 0; i < sizeof(join_prefixes) / sizeof(*join_prefixes);
       ++i) {
    char source[128];
    snprintf(source, sizeof(source), "printf before; %s", join_prefixes[i]);
    current = source;
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(draft->prefix_length == strlen("printf before;"));
    CHECK(draft->prefix.count == 1);
  }
  current = "[[ \"$left\" -ef \"$right\" ]]";
  resolved_value = "0:,";
  resolved_length = 0;
  calls = 0;
  uint8_t empty_unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       empty_unresolved) == SHELL_DEP_OK);
  CHECK(calls == 2 && graph->nodes[condition_node()].cmd.conditional_truth ==
                          SHELL_CONDITIONAL_FALSE);
  CHECK(!empty_unresolved[condition_node()]);
  CHECK(!graph->nodes[condition_node()].cmd.conditional_unresolved);
  unsigned comparison_node = UINT32_MAX;
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON) {
      comparison_node = i;
      CHECK(graph->nodes[i].file_comparison.empty_operands == 3);
    }
  CHECK(comparison_node != UINT32_MAX);
  unsigned empty_documents = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->from != comparison_node || (edge->type != SHELL_EDGE_FILE_LEFT &&
                                          edge->type != SHELL_EDGE_FILE_RIGHT))
      continue;
    const shell_dep_doc_t *doc = &graph->nodes[edge->to].doc;
    const char *spelling =
        edge->type == SHELL_EDGE_FILE_LEFT ? "\"$left\"" : "\"$right\"";
    CHECK(doc->path_len == strlen(spelling));
    CHECK(!memcmp(doc->path, spelling, doc->path_len));
    CHECK(doc->flags == SHELL_DEP_DOC_FLAG_DYNAMIC_NAME);
    char identity[64];
    size_t written;
    bool absolute;
    CHECK(!shell_dep_doc_file_identity_write(
        graph, doc, identity, sizeof(identity), &written, &absolute));
    empty_documents++;
  }
  CHECK(empty_documents == 2);
  CHECK(shell_dep_graph_validate(graph).valid);
  graph->nodes[comparison_node].file_comparison.predicates = 0;
  CHECK(!shell_dep_graph_validate(graph).valid);
  graph->nodes[comparison_node].file_comparison.predicates =
      SHELL_FILE_COMPARE_SAME;
  unsigned edges = graph->edge_count;
  graph->edge_count = 1;
  CHECK(!shell_dep_graph_validate(graph).valid);
  graph->edge_count = edges;
  CHECK(shell_dep_graph_validate(graph).valid);
  shell_dep_limits_t small = limits;
  small.max_nodes = 2;
  current = "[[ first -nt second ]]";
  CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &small,
                              graph) == SHELL_DEP_ETRUNC);
  CHECK(shell_dep_graph_validate(graph).valid);
  char deep[512] = "[[ ";
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES / 2; ++i)
    strcat(deep, "x && ");
  strcat(deep, "x ]]");
  current = deep;
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_TRUNCATED);
}

/* A syntax resource stop has no qualified prefix, even when complete commands
 * precede it. Check each public consumer rather than only the private frame. */
static void check_syntax_resource_stop(const char *source) {
  current = source;
  size_t length = strlen(source);
  CHECK(shell_parse_draft(source, length, NULL, draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft->prefix_length && !draft->prefix.count);
  for (unsigned i = 0; i < draft->header_count; ++i)
    CHECK(!draft->headers[i].complete);
  shell_parse_result_t fast;
  for (unsigned strict = 0; strict < 2; ++strict) {
    shell_limits_t options = SHELL_LIMITS_DEFAULT;
    options.strict_mode = strict != 0;
    CHECK(shell_parse_fast(source, length, &options, &fast) == SHELL_ETRUNC);
    CHECK(fast.status == SHELL_STATUS_TRUNCATED && !fast.count &&
          !fast.group_count);
  }
  CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits, graph) ==
        SHELL_DEP_ETRUNC);
  CHECK(graph->status == SHELL_DEP_STATUS_TRUNCATED && !graph->node_count &&
        !graph->edge_count && !graph->cwd_buf.len);
  CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                        &fast, graph) == SHELL_DEP_ETRUNC);
  CHECK(graph->status == SHELL_DEP_STATUS_TRUNCATED && !graph->node_count &&
        !graph->edge_count && !graph->cwd_buf.len);
  shell_command_t *commands = NULL;
  size_t count = 0;
  CHECK(shell_tokenize_commands(source, length, &commands, &count) ==
        SHELL_TOKENIZE_EOVERFLOW);
  CHECK(!commands && !count);
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(source, length, NULL, &processed) ==
        SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(!processed.commands && !processed.command_count);
  shell_abstract_command_t *abstract = NULL;
  CHECK(shell_abstract_command_parse(source, length, &abstract) ==
        SHELL_ABSTRACT_EOVERFLOW);
  CHECK(!abstract);
  shell_transformed_command_t **transformed = NULL;
  CHECK(shell_transform_command_line(source, length, NULL, &transformed,
                                     &count) == SHELL_TRANSFORM_EOVERFLOW);
  CHECK(!transformed && !count);
}

static void check_syntax_resource_outcomes(void) {
  char condition[2048] = "[[ ! ";
  for (unsigned i = 0; i < 47; ++i)
    strcat(condition, "x && ");
  strcat(condition, "x ]]");
  /* 48 primaries + 47 joins + one NOT fills all 96 nodes. */
  CHECK(shell_conditional_parse(condition, strlen(condition), 0).count == 96);
  parse(condition);
  strcpy(condition, "[[ ");
  for (unsigned i = 0; i < 48; ++i)
    strcat(condition, "x && ");
  strcat(condition, "x ]]");
  static const char *const wrappers[] = {
      "%s",        "printf before; %s",       "printf '%%s' \"$(%s)\"",
      "cat <(%s)", "cat <<EOF\n$(%s)\nEOF\n", "printf '%%s' `%s`"};
  for (unsigned i = 0; i < sizeof(wrappers) / sizeof(*wrappers); ++i) {
    char source[4096];
    int n = snprintf(source, sizeof(source), wrappers[i], condition);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    check_syntax_resource_stop(source);
  }
  strcpy(condition, "[[ ");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES - 1; ++i)
    strcat(condition, "(");
  strcat(condition, "x");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES - 1; ++i)
    strcat(condition, ")");
  strcat(condition, " ]]");
  parse(condition);
  char deep[4096];
  strcpy(deep, "[[ ");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES; ++i)
    strcat(deep, "(");
  strcat(deep, "x");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES; ++i)
    strcat(deep, ")");
  strcat(deep, " ]]");
  check_syntax_resource_stop(deep);
  /* Shared list-group capacity is a resource stop too. */
  strcpy(deep, "");
  for (unsigned i = 0; i <= SHELL_MAX_GROUPS; ++i)
    strcat(deep, "{ ");
  strcat(deep, "printf x;");
  for (unsigned i = 0; i <= SHELL_MAX_GROUPS; ++i)
    strcat(deep, " };");
  check_syntax_resource_stop(deep);
  /* Syntax errors still precede range-output limits when validation finishes.
   */
  shell_limits_t small = SHELL_LIMITS_DEFAULT;
  small.max_subcommands = 1;
  small.strict_mode = true;
  current = "printf first; printf second; [[ x && ]]";
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(current, strlen(current), &small, &fast) ==
        SHELL_EPARSE);
  CHECK(fast.status == SHELL_STATUS_ERROR);
}

int main(int argc, char **argv) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 8192,
                                      1, true, 0));
  limits = fixture.limits;
  graph = fixture.graph[0];
  draft = malloc(sizeof(*draft));
  CHECK(draft);
  /* Conformance probe: both operands are dynamic; arguments supply their
   * complete final strings, not individual expansion-fragment values. */
  if (argc == 5 && !strcmp(argv[1], "--resolved")) {
    current = argv[2];
    char records[2][256];
    for (unsigned i = 0; i < 2; ++i) {
      int used = snprintf(records[i], sizeof(records[i]), "%zu:%s,",
                          strlen(argv[3 + i]), argv[3 + i]);
      CHECK(used >= 0 && (size_t)used < sizeof(records[i]));
    }
    comparison_resolver_t resolver = {.values = {records[0], records[1]}};
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, resolve_comparison,
                                         &resolver, NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 2);
    printf("%d\n", graph->nodes[condition_node()].cmd.conditional_truth);
    goto done;
  }
  if (argc == 3) {
    current = argv[2];
    if (!strcmp(argv[1], "--status"))
      printf("%d\n", shell_parse_draft(current, strlen(current), NULL, draft));
    else {
      parse(current);
      if (!strcmp(argv[1], "--dump"))
        shell_dep_graph_dump(graph, stdout);
      else
        printf("%d\n", graph->nodes[condition_node()].cmd.conditional_truth);
    }
    goto done;
  }
  check_conditional_observation_order();
  check_body_setup();
  check_binary_and_compound_conditions();
  check_syntax_resource_outcomes();
  check_file_predicates();
  check_file_predicate_resolution();
  check_file_predicate_nul_argument();
  check_file_predicate_unresolved_paths();
  check_comparison_operand_contexts();
  check_scalar_arithmetic_boundary();
  check_arithmetic_mutation_rejection();
  check_numeric_conditional_contract();
  check_builtin_argument_read_phase();
  check_builtin_integer_comparisons();
  check_nested_arithmetic_coverage();
  check_conditional_coverage_barrier();
  check_parameter_operand_dependencies();
  check_file_comparison_continuations();
  check_test_grammar_refinement();
  check_expansion_regions();
  check_partial_condition_regions();
  check_comparisons();
  check_grouped_draft_summaries();
  check_mixed_literal_comparisons();
  check_tilde_comparisons();
  check_patterns();
  check_token_prefixes();
  for (size_t i = 0;
       i < sizeof(conditional_cases) / sizeof(conditional_cases[0]); ++i) {
    current = conditional_cases[i].source;
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft->headers[0].kind == SHELL_COMMAND_CONDITIONAL);
    CHECK(draft->headers[0].word_count == 0 && draft->headers[0].compound);
    CHECK(draft->headers[0].conditional_operands[0].length > 0);
    shell_limits_t syntax_limits = SHELL_LIMITS_DEFAULT;
    syntax_limits.strict_mode = true;
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(current, strlen(current), &syntax_limits, &fast) ==
          SHELL_OK);
    CHECK(fast.count == 1 && fast.cmds[0].kind == SHELL_COMMAND_CONDITIONAL);
    if (conditional_cases[i].truth != 0) {
      CHECK(draft->header_count == 1);
      CHECK(!(fast.cmds[0].features &
              (SHELL_FEAT_VARS | SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL |
               SHELL_FEAT_PROCESS_SUB)));
    }
    parse(current);
    unsigned owner = condition_node();
    bool pattern = graph->nodes[owner].cmd.conditional_predicate ==
                       SHELL_CONDITIONAL_PATTERN_MATCH ||
                   graph->nodes[owner].cmd.conditional_predicate ==
                       SHELL_CONDITIONAL_PATTERN_NOT_MATCH;
    CHECK(((fast.cmds[0].features & SHELL_FEAT_GLOBS) != 0) == pattern);
    CHECK(graph->nodes[owner].cmd.conditional_truth ==
          (shell_conditional_truth_t)conditional_cases[i].truth);
    CHECK(!graph->nodes[owner].cmd.token_count);
    shell_command_t *commands = NULL;
    size_t command_count;
    CHECK(shell_tokenize_commands(current, strlen(current), &commands,
                                  &command_count) == SHELL_TOKENIZE_OK);
    CHECK(command_count == 1 && commands[0].has_conditionals &&
          commands[0].has_globs == pattern);
    /* These sentinel spellings occur in the owner's own operands. Variables
     * inside executable children are covered by the mixed-word tests above. */
    if (strstr(current, "$value"))
      CHECK(commands[0].has_variables);
    if (strstr(current, "$(printf"))
      CHECK(commands[0].has_subshells);
    if (strstr(current, "$((1))"))
      CHECK(commands[0].has_arithmetic);
    shell_commands_free(commands, command_count);
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      if (conditional_cases[i].truth != 0)
        CHECK(graph->edges[e].type != SHELL_EDGE_SUBST);
      CHECK(!(graph->edges[e].type == SHELL_EDGE_READ &&
              graph->edges[e].to == owner));
      CHECK(!(graph->edges[e].type == SHELL_EDGE_WRITE &&
              graph->edges[e].from == owner && graph->edges[e].source_fd == 1));
      CHECK(graph->edges[e].type != SHELL_EDGE_ARG);
    }
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(current, strlen(current), NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1 &&
          processed.commands[0].kind == SHELL_COMMAND_CONDITIONAL);
    CHECK(!processed.commands[0].command_token_count);
    CHECK(processed.commands[0].conditional_operand_lengths[0] > 0);
    shell_processed_commands_free(&processed);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(current, strlen(current), &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(abstract->element_count == 1 &&
          abstract->elements[0]->type == SHELL_ABSTRACT_CT);
    CHECK(abstract->has_globs == pattern);
    shell_abstract_command_free(abstract);
    shell_netstring_buffer_t raw = {0}, typed = {0};
    size_t stages;
    CHECK(shell_build_anomaly_netseqs_buffer(current, strlen(current), NULL,
                                             &raw, &typed,
                                             &stages) == SHELL_PROCESS_OK);
    CHECK(stages > 0 && typed.length >= 11 &&
          !memcmp(typed.data + typed.length - 11, "8:0:,2:CT,,", 11));
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
  }
  current = "printf '%s' \"$([[ -n x # $(|)\n]])\"";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft->header_count == 2);
  parse(current);
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_TRUE);
  current = "[[ # ' comment\n-n $(printf value) # $(|)\n]]";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft->header_count == 2);
  parse(current);
  CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_UNKNOWN);
  bool real_substitution = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    real_substitution |= graph->edges[e].type == SHELL_EDGE_SUBST;
  CHECK(real_substitution);
  for (size_t i = 0;
       i < sizeof(conditional_invalid) / sizeof(conditional_invalid[0]); ++i) {
    current = conditional_invalid[i];
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft->prefix.count && !draft->prefix_length);
    CHECK(shell_dep_graph_parse(current, strlen(current), ".", &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(!graph->node_count && !graph->edge_count && !graph->cwd_buf.len);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(current, strlen(current), NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(!processed.commands && !processed.command_count);
    shell_processed_commands_free(&processed);
    char prefixed[256];
    CHECK(strlen(current) + sizeof("printf before; ") <= sizeof(prefixed));
    strcpy(prefixed, "printf before; ");
    strcat(prefixed, current);
    CHECK(shell_parse_draft(prefixed, strlen(prefixed), NULL, draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft->prefix.count && !draft->prefix_length);
  }
  static const char *const repairable[] = {
      "[[ x == ",
      "[[ x == \"",
      "[[ x == \"$(printf x",
      "[[ x == pre\"$value",
      "[[ x == pre\"$(printf x",
      "[[ x == \"x\" # $(|)",
      "[[ x ",
      "[[ ! x ",
      "[[ -n x\n",
      "[[ -z '' # note\n",
      "[[ -n x # note",
      "[[ # $(|)",
      "[[ ! # $(|)",
      "[[ -n x # $(|)",
      "[[ -n x # $(|)\n",
  };
  for (size_t i = 0; i < sizeof(repairable) / sizeof(repairable[0]); ++i) {
    char source[256];
    current = repairable[i];
    strcpy(source, "printf before; ");
    strcat(source, current);
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(draft->prefix_length == strlen("printf before;"));
    CHECK(draft->prefix.count == 1);
  }
  for (size_t i = 0;
       i < sizeof(conditional_unsupported) / sizeof(conditional_unsupported[0]);
       ++i) {
    current = conditional_unsupported[i];
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_UNSUPPORTED);
    CHECK(shell_dep_graph_parse(current, strlen(current), ".", &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(!graph->node_count && !graph->edge_count);
  }
  current = "printf before; [[ -n \"$(printf 日本";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(draft->prefix_length == strlen("printf before;"));
  parse("[[ '' ]] && cat unreachable; cat reachable");
  unsigned reads = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    reads += graph->edges[i].type == SHELL_EDGE_READ;
  CHECK(reads == 1);
  current = "[[ -z $value ]]";
  resolved_value = "0:,";
  calls = 0;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_OK);
  CHECK(calls == 1 && graph->nodes[condition_node()].cmd.conditional_truth ==
                          SHELL_CONDITIONAL_TRUE);
  resolved_value = "1:x,";
  calls = 0;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_OK);
  CHECK(calls == 1 && graph->nodes[condition_node()].cmd.conditional_truth ==
                          SHELL_CONDITIONAL_FALSE);
  /* Predicate truth controls continuation even when the output producer's
   * status has the opposite truth value. */
  for (unsigned nonempty = 0; nonempty < 2; ++nonempty) {
    current = nonempty ? "[[ -n $(false)x ]] && printf ok >reached"
                       : "[[ -n $(printf '') ]] && printf wrong >reached";
    resolved_value = nonempty ? "1:x," : "0:,";
    calls = 0;
    CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                         &limits, graph, resolve, NULL,
                                         NULL) == SHELL_DEP_OK);
    CHECK(calls == 1 && shell_dep_graph_validate(graph).valid);
    bool reached = false;
    for (unsigned e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (edge->type != SHELL_EDGE_WRITE)
        continue;
      const shell_dep_node_t *target = &graph->nodes[edge->to];
      reached |= target->type == SHELL_NODE_DOC &&
                 target->doc.kind == SHELL_DOC_FILE &&
                 target->doc.path_len == 7 &&
                 !memcmp(target->doc.path, "reached", 7);
    }
    CHECK(reached == (nonempty != 0));
  }
  current = "[[ -z $value ]]";
  resolved_value = "";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_EEXPAND);
  CHECK(!graph->node_count && !graph->edge_count);
  resolved_value = "0:,1:x,";
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_EEXPAND);
  resolved_value = "1:\0,";
  resolved_length = 4;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, resolve, NULL,
                                       NULL) == SHELL_DEP_EEXPAND);
  CHECK(!graph->node_count && !graph->edge_count);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_work = 0;
  /* A long near-match inside stars must not retry the literal run at every
   * subject position. Both input and pattern grow, exposing quadratic search.
   */
  for (size_t length = 16; length <= 1024; length *= 2) {
    char source[4096];
    char *p = source;
    memcpy(p, "[[ '", 4);
    p += 4;
    memset(p, 'a', length);
    p += length;
    memcpy(p, "' == *", 6);
    p += 6;
    memset(p, 'a', length / 2);
    p += length / 2;
    memcpy(p, "b* ]]", 6);
    current = source;
    size_t fixed, tail;
    CHECK(shell_dep_workspace_size(NULL, &fixed));
    CHECK(shell_source_workspace_size(strlen(source), &tail));
    size_t previous_size = limits.workspace_size;
    limits.workspace_size = fixed + tail;
    shellsplit_test_source_scan_reset();
    parse(source);
    limits.workspace_size = previous_size;
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_FALSE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
  previous_work = 0;
  for (size_t terms = 16; terms <= 1024; terms *= 2) {
    char source[4096] = "[[ ";
    for (size_t i = 0; i < terms; ++i)
      memcpy(source + 3 + i * 2, "! ", 2);
    strcpy(source + 3 + terms * 2, "-n x ]]");
    current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
  previous_work = 0;
  /* Many quoted fragments must not trigger repeated prefix scans when their
   * static neighbors make the RHS eligible for literal comparison. */
  for (size_t terms = 16; terms <= 256; terms *= 2) {
    char source[8192] = "[[ x == ";
    const char fragment[] = "p\"${right:-value}\"";
    size_t end = strlen(source);
    for (size_t i = 0; i < terms; ++i) {
      memcpy(source + end, fragment, sizeof(fragment) - 1);
      end += sizeof(fragment) - 1;
    }
    strcpy(source + end, " ]]");
    current = source;
    shellsplit_test_source_scan_reset();
    parse(source);
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_UNKNOWN);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
  previous_work = 0;
  for (size_t continuations = 16; continuations <= 1024; continuations *= 2) {
    char source[4096] = "[[ x !";
    size_t end = strlen(source);
    for (size_t i = 0; i < continuations; ++i) {
      source[end++] = '\\';
      source[end++] = '\n';
    }
    source[end++] = '\\';
    source[end] = 0;
    current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, end, NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(retained_condition()->conditional_operand_count == 1);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
  previous_work = 0;
  for (size_t length = 16; length <= 1024; length *= 2) {
    char source[4096];
    char *out = source;
    memcpy(out, "[[ '", 4);
    out += 4;
    memset(out, 'a', length);
    out += length;
    memcpy(out, "' == \"", 6);
    out += 6;
    memset(out, 'a', length);
    out += length;
    strcpy(out, "\" ]]");
    current = source;
    size_t fixed, tail;
    CHECK(shell_dep_workspace_size(NULL, &fixed));
    CHECK(shell_source_workspace_size(strlen(source), &tail));
    size_t previous_size = limits.workspace_size;
    limits.workspace_size = fixed + tail;
    shellsplit_test_source_scan_reset();
    parse(source);
    limits.workspace_size = previous_size;
    CHECK(graph->nodes[condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_TRUE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
#endif
done:
  free(draft);
  shellsplit_graph_fixture_destroy(&fixture);
  return 0;
}
