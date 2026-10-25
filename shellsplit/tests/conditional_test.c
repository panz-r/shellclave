#include "conditional_cases.h"
#include "shell_abstract.h"
#include "shell_sequence.h"
#include "shell_source.h"
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

typedef struct {
  const char *values[2];
  bool unresolved[2];
  unsigned calls;
  size_t offsets[2];
} comparison_resolver_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    resolve_comparison(const shell_expand_word_request_t *request,
                       const char **value, size_t *length, void *context) {
  comparison_resolver_t *resolver = context;
  CHECK(request->purpose == SHELL_EXPAND_WORD_CONDITIONAL);
  CHECK(resolver->calls < 2);
  unsigned index = resolver->calls++;
  resolver->offsets[index] = request->word_offset;
  if (index)
    CHECK(resolver->offsets[0] < resolver->offsets[1]);
  if (resolver->unresolved[index])
    return SHELL_EXPAND_UNRESOLVED;
  *value = resolver->values[index];
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
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

int main(int argc, char **argv) {
  graph = malloc(sizeof(*graph));
  draft = malloc(sizeof(*draft));
  CHECK(graph && draft);
  limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t bytes, scratch;
  CHECK(shell_dep_workspace_size(NULL, &bytes));
  CHECK(shell_source_workspace_size(8192, &scratch));
  bytes += scratch;
  size_t alignment = shell_dep_workspace_alignment();
  bytes = (bytes + alignment - 1) / alignment * alignment;
  void *workspace = aligned_alloc(alignment, bytes);
  CHECK(workspace);
  limits.workspace = workspace;
  limits.workspace_size = bytes;
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
  check_body_setup();
  check_comparisons();
  check_tilde_comparisons();
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
    CHECK(graph->nodes[owner].cmd.conditional_truth ==
          (shell_conditional_truth_t)conditional_cases[i].truth);
    CHECK(!graph->nodes[owner].cmd.token_count);
    shell_command_t *commands = NULL;
    size_t command_count;
    CHECK(shell_tokenize_commands(current, strlen(current), &commands,
                                  &command_count) == SHELL_TOKENIZE_OK);
    CHECK(command_count == 1 && commands[0].has_conditionals &&
          !commands[0].has_globs);
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
    CHECK(!abstract->has_globs);
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
  free(workspace);
  free(graph);
  free(draft);
  return 0;
}
