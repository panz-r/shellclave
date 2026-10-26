#include "../src/shell_semantics_internal.h"
#include "../src/shell_test_internal.h"
#include "shell_depgraph.h"
#include "shell_source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *current;
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #test, current); \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static shell_dep_graph_t *graph;
static shell_dep_limits_t limits;

static shell_conditional_truth_t truth(const char *source) {
  current = source;
  CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                              graph) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  for (uint32_t i = graph->node_count; i-- > 0;)
    if (graph->nodes[i].type == SHELL_NODE_CMD &&
        graph->nodes[i].cmd.kind == SHELL_COMMAND_CONDITIONAL)
      return graph->nodes[i].cmd.conditional_truth;
  CHECK(false);
  return SHELL_CONDITIONAL_UNKNOWN;
}

static shell_conditional_truth_t test_truth(const char *source) {
  /* Graph spans and failure diagnostics borrow this source until the next
   * probe, including assertions made after this helper returns. */
  static char combined[4096];
  int n = snprintf(
      combined, sizeof(combined),
      "unset __shellclave_presence_probe; { %s; } && "
      "__shellclave_presence_probe=; [[ -v __shellclave_presence_probe ]]",
      source);
  CHECK(n >= 0 && (size_t)n < sizeof(combined));
  return truth(combined);
}

static void observe_token(const shell_token_t *token, void *context) {
  (void)token;
  (void)context;
}
static void observe_read(const char *word, uint32_t fd, unsigned kind,
                         const char *parameter, size_t length, bool identity,
                         void *context) {
  (void)word;
  (void)fd;
  (void)kind;
  (void)parameter;
  (void)length;
  (void)identity;
  (void)context;
}
static void observe_process(const char *word, size_t length, void *context) {
  (void)word;
  (void)length;
  (void)context;
}
typedef struct {
  unsigned queries, programs;
} observed_test_t;
static void observe_name(const char *name, size_t length, void *context) {
  CHECK(length == 6 && !memcmp(name, "CONFIG", 6));
  ++((observed_test_t *)context)->queries;
}
static void observe_test(const char *command,
                         const shell_test_program_t *program, void *context) {
  CHECK(*command == '[' || !memcmp(command, "test", 4));
  CHECK(program && program->active);
  ++((observed_test_t *)context)->programs;
}

static void check_observation_roles(void) {
  static const struct {
    const char *source;
    unsigned queries, programs;
  } cases[] = {
      {"test CONFIG", 0, 1},
      {"test -v = CONFIG", 0, 1},
      {"test -v -a CONFIG", 0, 1},
      {"[ -v CONFIG", 0, 1},
      {"test '(' -v CONFIG extra ')'", 0, 1},
      {"test -v CONFIG", 1, 1},
      {"[ -v 'CON'\"FIG\" ]", 1, 1},
      {"test '(' -v CONFIG ')'", 1, 1},
      {"test x -o -v CONFIG", 1, 1},
      {"test -v CONFIG -o ! -v CONFIG", 2, 1},
      {"[[ -v CONFIG ]]", 1, 0},
      {"test -n \"$(test -v CONFIG)\"", 1, 2},
      {"test '' -o '(' CONFIG ')'", 0, 1},
      {"[ x -a '(' -v ')' ]", 0, 1},
      {"command builtin test '(' -t -o ')' -o -v CONFIG", 1, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    current = cases[i].source;
    size_t length = strlen(current), bytes;
    CHECK(shell_source_workspace_size(length, &bytes));
    void *scratch = malloc(bytes);
    CHECK(scratch);
    for (unsigned observers = 0; observers < 4; ++observers) {
      observed_test_t observed = {0};
      shell_source_operation_begin(current, length);
      shell_source_workspace_scope_t previous =
          shell_source_workspace_begin(current, length, scratch, bytes);
      CHECK(shell_tokenizer_inspect_semantics(
                current, length, observe_token, observe_read, observe_process,
                observers & 1 ? observe_name : NULL,
                observers & 2 ? observe_test : NULL,
                &observed) == SHELL_SEMANTIC_OK);
      CHECK(!shell_source_scratch_exhausted());
      CHECK(observed.queries == (observers & 1 ? cases[i].queries : 0));
      CHECK(observed.programs == (observers & 2 ? cases[i].programs : 0));
      shell_source_workspace_end(previous);
      shell_source_operation_end();
    }
    free(scratch);
  }
}

static void check_inspection_outcomes(void) {
  char source[1024] = "test x";
  for (unsigned i = 0; i < 20; ++i)
    strcat(source, " -o x");
  strcat(source, "; test -v CONFIG");
  for (unsigned unsupported = 0; unsupported < 2; ++unsupported) {
    if (unsupported)
      strcat(source, "; test -v 'a[$(printf marker)]'");
    current = source;
    size_t bytes, length = strlen(source);
    CHECK(shell_source_workspace_size(length, &bytes));
    void *scratch = malloc(bytes);
    CHECK(scratch);
    for (unsigned observers = 0; observers < 4; ++observers) {
      for (unsigned exhaust = 0; exhaust < 2; ++exhaust) {
        observed_test_t observed = {0};
        shell_source_operation_begin(source, length);
        shell_source_workspace_scope_t previous =
            shell_source_workspace_begin(source, length, scratch, bytes);
        if (exhaust)
          CHECK(shell_source_scratch_take(bytes));
        shell_semantic_result_t result = shell_tokenizer_inspect_semantics(
            source, length, observe_token, observe_read, observe_process,
            observers & 1 ? observe_name : NULL,
            observers & 2 ? observe_test : NULL, &observed);
        CHECK(result == (observers && exhaust ? SHELL_SEMANTIC_EWORKSPACE
                         : unsupported        ? SHELL_SEMANTIC_UNSUPPORTED
                         : observers          ? SHELL_SEMANTIC_TRUNCATED
                                              : SHELL_SEMANTIC_OK));
        shell_source_workspace_end(previous);
        shell_source_operation_end();
      }
    }
    free(scratch);
  }
  current = "test -v CONFIG";
  size_t length = strlen(current), bytes;
  CHECK(shell_source_workspace_size(length, &bytes));
  void *scratch = malloc(bytes);
  CHECK(scratch);
  for (unsigned observers = 1; observers < 4; ++observers) {
    observed_test_t observed = {0};
    shell_source_operation_begin(current, length);
    shell_source_workspace_scope_t previous =
        shell_source_workspace_begin(current, length, scratch, bytes);
    CHECK(shell_source_scratch_take(bytes));
    CHECK(shell_tokenizer_inspect_semantics(
              current, length, observe_token, observe_read, observe_process,
              observers & 1 ? observe_name : NULL,
              observers & 2 ? observe_test : NULL,
              &observed) == SHELL_SEMANTIC_EWORKSPACE);
    CHECK(!observed.queries && !observed.programs);
    shell_source_workspace_end(previous);
    shell_source_operation_end();
  }
  free(scratch);
}

static void check_observation_capacity(void) {
  char source[8192];
  for (unsigned lookup = 0; lookup < 2; ++lookup) {
    size_t used = 0;
    for (unsigned command = 0; command < 33; ++command) {
      int n = snprintf(source + used, sizeof(source) - used, "test x");
      CHECK(n >= 0 && (size_t)n < sizeof(source) - used);
      used += (size_t)n;
      for (unsigned operand = 0; operand < 9; ++operand) {
        n = snprintf(source + used, sizeof(source) - used,
                     lookup ? " -o -v name_%u_%u" : " -a name_%u_%u", command,
                     operand);
        CHECK(n >= 0 && (size_t)n < sizeof(source) - used);
        used += (size_t)n;
      }
      CHECK(used + 2 < sizeof(source));
      source[used++] = ';';
      source[used++] = ' ';
    }
    source[used] = 0;
    current = source;
    CHECK(shell_dep_graph_parse(source, used, "/workspace", &limits, graph) ==
          SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void check_recursive_routes(void) {
  static const char *const selections[] = {
      "test x",
      "! test ''",
      "test '' || :",
      "result=$( [[ -v MODE ]] ) || :",
      "read -n0 VALUE",
      "read -n0 VALUE <<<\"$( [[ -v MODE ]] )\"",
      "result=$( [[ -v MODE ]] ); read -n0 VALUE",
      "( [[ -v MODE ]] ) || :; read -n0 VALUE"};
  for (size_t i = 0; i < sizeof(selections) / sizeof(*selections); ++i) {
    char source[1024];
    int n = snprintf(source, sizeof(source),
                     "exec 4<was-set 5<was-unset && { "
                     "[[ -v MODE ]] && exec 3<&4 || exec 3<&5; %s; "
                     "echo \"$( [[ -v MODE ]] && cat set <&3; "
                     "[[ ! -v MODE ]] && cat unset <&3 )\"; }; [[ -v UID ]]",
                     selections[i]);
    CHECK(n >= 0 && (size_t)n < sizeof(source));
    CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
    bool seen[2] = {false};
    for (uint32_t e = 0; e < graph->edge_count; ++e) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      const shell_dep_node_t *from = &graph->nodes[edge->from],
                             *to = &graph->nodes[edge->to];
      if (edge->type != SHELL_EDGE_READ || from->type != SHELL_NODE_DOC ||
          from->doc.kind != SHELL_DOC_FILE || to->type != SHELL_NODE_CMD ||
          to->cmd.token_count != 2 || to->cmd.token_lens[0] != 3 ||
          memcmp(to->cmd.tokens[0], "cat", 3))
        continue;
      bool set =
          to->cmd.token_lens[1] == 3 && !memcmp(to->cmd.tokens[1], "set", 3);
      const char *expected = set ? "was-set" : "was-unset";
      CHECK(from->doc.path_len == strlen(expected) &&
            !memcmp(from->doc.path, expected, from->doc.path_len));
      seen[set] = true;
    }
    CHECK(seen[0] && seen[1]);
  }
}

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    no_presence_callback(const shell_expand_word_request_t *request,
                         const char **value, size_t *length, void *context) {
  (void)request;
  (void)value;
  (void)length;
  ++*(unsigned *)context;
  return SHELL_EXPAND_UNRESOLVED;
}

static SHELL_NONNULL(1) bool has_file_read(const char *path) {
  size_t length = strlen(path);
  for (uint32_t i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *from = &graph->nodes[edge->from];
    if (edge->type == SHELL_EDGE_READ && from->type == SHELL_NODE_DOC &&
        from->doc.kind == SHELL_DOC_FILE && from->doc.path_len == length &&
        !memcmp(from->doc.path, path, length))
      return true;
  }
  return false;
}

static void check_nonassignable_variables(void) {
  static const char *const names[] = {"FUNCNAME",    "GROUPS",
                                      "BASH_ARGC",   "BASH_ARGV",
                                      "BASH_SOURCE", "BASH_LINENO"};
  static const char *const writers[] = {"%s=value",
                                        "declare %s=value",
                                        "export %s=value",
                                        "printf -v %s %%s value",
                                        "printf -v%s %%s value",
                                        "printf '%%n' %s",
                                        "read -n0 %s",
                                        "getopts a %s -a"};
  for (size_t n = 0; n < sizeof(names) / sizeof(*names); ++n) {
    for (size_t w = 0; w < sizeof(writers) / sizeof(*writers); ++w) {
      char write[128], source[512];
      int used = snprintf(write, sizeof(write), writers[w], names[n]);
      CHECK(used >= 0 && (size_t)used < sizeof(write));
      used =
          snprintf(source, sizeof(source), "%s; [[ -v %s ]]", write, names[n]);
      CHECK(used >= 0 && (size_t)used < sizeof(source));
      CHECK(truth(source) == SHELL_CONDITIONAL_UNKNOWN);
      /* Unknown initial presence stays unknown. A previously observed absence
       * also survives the rejected write, so its failure route remains live. */
      used = snprintf(
          source, sizeof(source),
          "[[ ! -v %s ]] && { %s; [[ -v %s ]] || cat <important.txt; }; "
          "[[ -v UID ]]",
          names[n], write, names[n]);
      CHECK(used >= 0 && (size_t)used < sizeof(source));
      CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
      CHECK(has_file_read("important.txt"));
      if (n < 2) {
        used = snprintf(source, sizeof(source), "unset %s; %s; [[ -v %s ]]",
                        names[n], write, names[n]);
        CHECK(used >= 0 && (size_t)used < sizeof(source));
        CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
      }
    }
    char source[512];
    int used = snprintf(source, sizeof(source),
                        "[[ ! -v %s ]] && { %s=value test -v %s || "
                        "cat <important.txt; }; [[ -v UID ]]",
                        names[n], names[n], names[n]);
    CHECK(used >= 0 && (size_t)used < sizeof(source));
    CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt"));
    used = snprintf(source, sizeof(source),
                    "[[ ! -v %s ]] && { %s=value result=$( [[ -v %s ]] ) || "
                    "cat <important.txt; }; [[ -v UID ]]",
                    names[n], names[n], names[n]);
    CHECK(used >= 0 && (size_t)used < sizeof(source));
    CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt"));
  }
  CHECK(truth("printf -v FUNCNAME %s value; [[ -v FUNCNAME ]] || "
              "cat <important.txt") == SHELL_CONDITIONAL_UNKNOWN);
  CHECK(has_file_read("important.txt"));
  CHECK(truth("unset first IFS last; read first FUNCNAME IFS last <<<payload; "
              "[[ -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset first IFS last; read -n0 first FUNCNAME IFS last; "
              "[[ -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(
      truth(
          "unset first IFS last; read -t0 first FUNCNAME IFS last <<<payload; "
          "[[ ! -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
      SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset count; printf -v FUNCNAME '%n' count; [[ -v count ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(
      truth("unset output; printf -v output '%n' FUNCNAME; [[ -v output ]]") ==
      SHELL_CONDITIONAL_TRUE);
  CHECK(truth("OPTARG=; getopts a FUNCNAME -a; [[ -v OPTIND ]]") ==
        SHELL_CONDITIONAL_TRUE);
  /* Option scanning remains abstract: its independent OPTARG update can
   * either clear or assign the previous value despite destination rejection. */
  CHECK(truth("OPTARG=; getopts a FUNCNAME -a; [[ -v OPTARG ]]") ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(truth("[[ ! -v FUNCNAME ]] && { (unset FUNCNAME); "
              "read -n0 FUNCNAME; [[ -v FUNCNAME ]]; }") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(truth("[[ ! -v FUNCNAME ]] && { result=$(unset FUNCNAME); "
              "read -n0 FUNCNAME; [[ -v FUNCNAME ]]; }") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(truth("{ unset FUNCNAME; }; read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset FUNCNAME; unset FUNCNAME; "
              "FUNCNAME=value result=$( [[ -v FUNCNAME ]] ); "
              "[[ -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset FUNCNAME; FUNCNAME=value test -v FUNCNAME && "
              "[[ ! -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(truth("test -d /maybe && unset FUNCNAME; "
              "read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(
      truth("unset BASH_SOURCE; read -n0 BASH_SOURCE; [[ -v BASH_SOURCE ]]") ==
      SHELL_CONDITIONAL_UNKNOWN);
}

static SHELL_NONNULL(1, 3) unsigned unexpected_test_lookup(const char *name,
                                                           size_t length,
                                                           void *context) {
  (void)name;
  (void)length;
  (void)context;
  CHECK(false);
  return 0;
}

static void check_opaque_unsets(void) {
  static const struct {
    const char *source;
    bool reads;
  } cases[] = {
      {"name=unused; unset \"$name\" FUNCNAME; "
       "read -n0 FUNCNAME && cat <important.txt",
       true},
      {"name=unused; unset FUNCNAME \"$name\"; "
       "read -n0 FUNCNAME && cat <important.txt",
       true},
      {"FUNCNAME=value unset FUNCNAME; "
       "read -n0 FUNCNAME && cat <important.txt",
       true},
      {"GROUPS=value unset GROUPS; read -n0 GROUPS && cat <important.txt",
       true},
      {"unset FUNCNAME; FUNCNAME=value unset FUNCNAME; "
       "read -n0 FUNCNAME && cat <important.txt",
       true},
      {"unset \"$name\"; read -n0 FUNCNAME && cat <important.txt", true},
      {"unset \"$name\"; read -n0 FUNCNAME || cat <important.txt", true},
      {"unset \"$name\"; read -n0 FUNCNAME && "
       "{ [[ ! -v FUNCNAME ]] && cat <important.txt; }",
       false},
      {"printf -- \"$format\" value; "
       "read -n0 FUNCNAME && cat <important.txt",
       false},
      {"read -n0 -- \"$name\"; read -n0 FUNCNAME && cat <important.txt", false},
      {"(FUNCNAME=value unset FUNCNAME); "
       "read -n0 FUNCNAME && cat <important.txt",
       false},
      {"{ FUNCNAME=value unset FUNCNAME; }; "
       "read -n0 FUNCNAME && cat <important.txt",
       true},
      {"unset \"$name\"; result=$(read -n0 FUNCNAME && cat <important.txt)",
       true},
      {"FUNCNAME=value unset FUNCNAME; exec {FUNCNAME}<important.txt && "
       "cat <&$FUNCNAME",
       true},
      {"unset \"$name\" BASH_SOURCE; "
       "read -n0 BASH_SOURCE && cat <important.txt",
       false},
      {"unset \"$name\"; FUNCNAME=value test -v FUNCNAME && cat <important.txt",
       true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    char source[768];
    int n = snprintf(source, sizeof(source), "%s; after=; [[ -v after ]]",
                     cases[i].source);
    CHECK(n >= 0 && (size_t)n < sizeof(source));
    CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt") == cases[i].reads);
  }
  CHECK(truth("unset -- \"$name\" FUNCNAME; printf -v FUNCNAME %s value; "
              "[[ -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset -- \"$name\" GROUPS; GROUPS=value; [[ -v GROUPS ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(truth("unset \"$name\"; read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(truth("unset CONFIG; CONFIG=value unset \"$name\" CONFIG; "
              "[[ -v CONFIG ]]") == SHELL_CONDITIONAL_FALSE);
}

static void check_prepared_test_values(void) {
  static const char *const operands[] = {"-n", "\"$VALUE\"", "-a", "'('",
                                         "''", "')'",        "]"};
  static const char *const values[] = {NULL, "", "x"};
  current = "prepared parenthesized test values";
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    for (unsigned value = 0; value < 3; ++value) {
      shell_source_operation_begin(current, strlen(current));
      char scratch[4096];
      shell_source_workspace_scope_t previous = shell_source_workspace_begin(
          current, strlen(current), scratch, sizeof(scratch));
      shell_test_value_t words[7];
      size_t count = bracket ? 7 : 6;
      for (size_t word = 0; word < count; ++word)
        CHECK(shell_test_prepare_value(operands[word], strlen(operands[word]),
                                       &words[word]));
      shell_test_program_t program;
      CHECK(shell_test_compile(words, count, bracket, &program));
      /* Refine data without recompiling or rebasing the nested dispatch. */
      if (values[value])
        shell_test_set_value(&words[1], values[value], strlen(values[value]));
      CHECK(shell_test_evaluate(&program, unexpected_test_lookup, &program) ==
            (value == 0   ? SHELL_TEST_FALSE | SHELL_TEST_TRUE
             : value == 1 ? SHELL_TEST_FALSE
                          : SHELL_TEST_TRUE));
      shell_source_workspace_end(previous);
      shell_source_operation_end();
    }
  }
}

static void check_parenthesized_tests(void) {
  static const struct {
    const char *expression;
    bool succeeds;
  } cases[] = {
      {"'' -o '(' x ')'", false},
      {"x -a '(' '' ')'", true},
      {"'' -o '(' x ')' -o '(' x ')'", false},
      {"x -a '(' '' ')' -a '(' '' ')'", true},
      {"x -a '(' '' -o '(' '' ')' ')'", true},
      {"'' -o '(' x -a '(' x ')' ')'", false},
      {"'(' '' ')'", false},
      {"'(' x ')'", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char command[512];
      int n =
          snprintf(command, sizeof(command), "%s %s%s", bracket ? "[" : "test",
                   cases[i].expression, bracket ? " ]" : "");
      CHECK(n >= 0 && (size_t)n < sizeof(command));
      CHECK(test_truth(command) == (cases[i].succeeds
                                        ? SHELL_CONDITIONAL_TRUE
                                        : SHELL_CONDITIONAL_FALSE));
      for (unsigned negated = 0; negated < 2; ++negated) {
        for (unsigned on_failure = 0; on_failure < 2; ++on_failure) {
          char source[768];
          n = snprintf(source, sizeof(source),
                       "%s%s %s cat <important.txt; [[ -v UID ]]",
                       negated ? "! " : "", command, on_failure ? "||" : "&&");
          CHECK(n >= 0 && (size_t)n < sizeof(source));
          CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
          bool succeeds = cases[i].succeeds != (bool)negated;
          CHECK(has_file_read("important.txt") ==
                (on_failure ? !succeeds : succeeds));
        }
      }
    }
  }
  static const char source[] =
      "test -n \"$VALUE\" -a '(' '' ')' && cat <important.txt; [[ -v UID ]]";
  CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
  CHECK(has_file_read("important.txt"));
  check_prepared_test_values();
}

static void check_parenthesized_admission(void) {
  static const char *const failures[] = {
      "'(' -t -o ')' -o -v 'a[$(printf marker >&2)]'",
      "'(' -t -a ')' -o -v 'a[$(printf marker >&2)]'",
      "! '(' -t -o ')' -a -v 'a[$(printf marker >&2)]'",
      "x -a '(' -t -o ')' -o -v 'a[$(printf marker >&2)]'",
      "'(' '(' -t -o ')' ')' -o -v 'a[$(printf marker >&2)]'",
      "'(' -v 'a[$(printf marker >&2)]' extra ')' -o -v CONFIG",
      "'(' '(' -v 'a[$(printf marker >&2)]' ')' ')'",
      "'(' -t invalid ')' -o -v 'a[$(printf marker >&2)]'",
      "'(' -t -o ')' -o -v \"a[$(printf expansion-marker >&2)]\"",
      "-t \"$FD\" '(' -v 'a[$(printf marker >&2)]' extra ')'",
      "-t \"$FD\" '(' -v 'a[$(printf marker >&2)]' extra ')' -o "
      "\"$(printf expansion-marker >&2)\"",
  };
  for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char command[512];
      int n =
          snprintf(command, sizeof(command), "%s %s%s", bracket ? "[" : "test",
                   failures[i], bracket ? " ]" : "");
      CHECK(n >= 0 && (size_t)n < sizeof(command));
      CHECK(test_truth(command) == SHELL_CONDITIONAL_FALSE);
      bool expanded = false;
      for (uint32_t node = 0; node < graph->node_count; ++node) {
        const shell_dep_node_t *child = &graph->nodes[node];
        if (child->type == SHELL_NODE_CMD && child->cmd.token_count >= 2 &&
            child->cmd.token_lens[0] == 6 &&
            !memcmp(child->cmd.tokens[0], "printf", 6)) {
          CHECK(child->cmd.token_lens[1] == 16 &&
                !memcmp(child->cmd.tokens[1], "expansion-marker", 16));
          expanded = true;
        }
      }
      CHECK(expanded == (strstr(failures[i], "expansion-marker") != NULL));
      for (unsigned negated = 0; negated < 2; ++negated) {
        for (unsigned on_failure = 0; on_failure < 2; ++on_failure) {
          char source[768];
          n = snprintf(source, sizeof(source),
                       "CONFIG=; %s%s %s cat <important.txt; [[ -v UID ]]",
                       negated ? "! " : "", command, on_failure ? "||" : "&&");
          CHECK(n >= 0 && (size_t)n < sizeof(source));
          CHECK(truth(source) == SHELL_CONDITIONAL_TRUE);
          CHECK(has_file_read("important.txt") == (on_failure != negated));
        }
      }
    }
  }
}

int main(int argc, char **argv) {
  current = "setup";
  graph = malloc(sizeof(*graph));
  CHECK(graph);
  limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t bytes, scratch;
  CHECK(shell_dep_workspace_size(&limits, &bytes));
  CHECK(shell_source_workspace_size(8192, &scratch));
  bytes += scratch;
  size_t alignment = shell_dep_workspace_alignment();
  bytes = (bytes + alignment - 1) / alignment * alignment;
  void *workspace = aligned_alloc(alignment, bytes);
  CHECK(workspace);
  limits.workspace = workspace;
  limits.workspace_size = bytes;
  if (argc == 3) {
    printf("%d\n",
           !strcmp(argv[1], "--test") ? test_truth(argv[2]) : truth(argv[2]));
    free(workspace);
    free(graph);
    return 0;
  }
  check_observation_roles();
  check_inspection_outcomes();
  check_observation_capacity();
  check_recursive_routes();
  check_parenthesized_tests();
  check_parenthesized_admission();
  check_nonassignable_variables();
  check_opaque_unsets();
  static const struct {
    const char *source;
    shell_conditional_truth_t expected;
  } cases[] = {
      {"[[ -v ordinary_inherited ]]", SHELL_CONDITIONAL_UNKNOWN},
      {"unset CONFIG; [[ -v CONFIG ]]", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; [[ -v CONFIG ]]", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=value; [[ ! -v CONFIG ]]", SHELL_CONDITIONAL_FALSE},
      {"unset CONFIG; declare CONFIG; [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset CONFIG; export CONFIG; [[ -v CONFIG ]]", SHELL_CONDITIONAL_FALSE},
      {"export CONFIG=; [[ -v CONFIG ]]", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; unset CONFIG; [[ -v 'CON'\"FIG\" ]]", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; [[ -v $'CONFIG\\0discard' ]]", SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; CONFIG= test -v CONFIG && [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; ( unset CONFIG ); [[ -v CONFIG ]]", SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; { CONFIG=; }; [[ -v CONFIG ]]", SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; CONFIG= & [[ -v CONFIG ]]", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; : \"$(unset CONFIG)\"; [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; : \"$( [[ -v CONFIG ]] )\"; [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; printf -v CONFIG %s value; [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; read -t0 CONFIG; [[ -v CONFIG ]]", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; read -n-invalid CONFIG; [[ -v CONFIG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"exec {fd}>&1 && { exec {fd}>&-; [[ -v fd ]]; }",
       SHELL_CONDITIONAL_TRUE},
      {"exec {fd}>&1 && { unset fd; [[ -v fd ]]; }", SHELL_CONDITIONAL_FALSE},
      {"unset PWD OLDPWD; cd / && [[ -v OLDPWD ]]", SHELL_CONDITIONAL_FALSE},
      {"PWD=; cd / && [[ -v OLDPWD ]]", SHELL_CONDITIONAL_TRUE},
      {"unset PWD OLDPWD; PWD= cd / && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_TRUE},
      /* A PWD write can make entry alternatives identical. OLDPWD must
       * retain their old presence before completed mutations are merged. */
      {"unset PWD OLDPWD; choose && PWD=; cd / && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset PWD OLDPWD MARK; choose && { PWD=; MARK=; }; "
       "choose2 && PWD=; cd / && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset PWD OLDPWD MARK; choose && { PWD=; MARK=; }; "
       "choose2 && PWD=; cd / && [[ -v MARK ]] && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset PWD OLDPWD MARK; choose && { PWD=; MARK=; }; "
       "choose2 && PWD=; cd / && [[ ! -v OLDPWD ]] && [[ -v MARK ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset PWD OLDPWD; choose && PWD=; PWD= cd / && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset PWD OLDPWD; choose && PWD=; "
       "{ cd / && [[ -v OLDPWD ]]; } && [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset PWD OLDPWD; choose && PWD=; "
       "( cd / && [[ -v OLDPWD ]] ) && [[ -v PWD ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset PWD OLDPWD; choose && PWD=; "
       "( cd / && [[ ! -v OLDPWD ]] ) && [[ -v PWD ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset PWD OLDPWD; choose && PWD=; "
       "result=$( cd / && [[ -v OLDPWD ]] ) && [[ -v PWD ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset PWD OLDPWD; choose && PWD=; "
       "result=$( cd / && [[ ! -v OLDPWD ]] ) && [[ -v PWD ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset PWD OLDPWD; choose && PWD=; "
       "result=$( cd / && [[ -v OLDPWD ]] )",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset PWD OLDPWD; choose && PWD=; "
       "result=$( cd / && [[ -v OLDPWD ]] ); [[ -v OLDPWD ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset PWD; OLDPWD=; cd '' || [[ -v OLDPWD ]]", SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts a result; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts a OPTARG -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts a OPTARG; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts a: OPTARG -a value; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts a OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"OPTARG=; getopts a: OPTARG -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts '' OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts :a OPTARG -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts :a: OPTARG -a ''; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts :a OPTARG; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts :a OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts :a: OPTARG -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts -- :a 'OPT'\"ARG\" -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts a $'OPTARG' -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts :a OPT\\\nARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts \"a$spec\" OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset OPTARG; getopts \":$spec\" OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; command builtin getopts :a OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; OPTARG= getopts :a OPTARG -b; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; ( getopts :a OPTARG -b ); [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset OPTARG; { getopts :a OPTARG -b; }; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts -x :a OPTARG; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_FALSE},
      {"OPTARG=; getopts -x :a OPTARG; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts :a OPTARG -b 9>&- 0<&9; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset DEST; getopts a DEST -b; [[ -v DEST ]]", SHELL_CONDITIONAL_TRUE},
      {"unset DEST; getopts a: DEST -a; [[ -v DEST ]]", SHELL_CONDITIONAL_TRUE},
      {"unset DEST; getopts a DEST; [[ -v DEST ]]", SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; spec=-x; getopts \"$spec\" OPTARG -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset DEST; spec=-x; getopts \"$spec\" DEST -a; [[ -v DEST ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"DEST=; spec=-x; getopts \"$spec\" DEST -a; [[ -v DEST ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset DEST; getopts \"a$spec\" DEST -a; [[ -v DEST ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset OPTARG; getopts a invalid-name -a; [[ -v OPTARG ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset fd; true {fd}>out 9>&- 1>&9 || [[ -v fd ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset fd; true {fd}>&1 9>&- 1>&9 || [[ -v fd ]]",
       SHELL_CONDITIONAL_TRUE},
      {"unset fd; true 9>&- 1>&9 {fd}>out || [[ -v fd ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset fd; ( true {fd}>out 9>&- 1>&9 ); [[ -v fd ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset fd; { true; } {fd}>&1 9>&- 1>&9 || [[ -v fd ]]",
       SHELL_CONDITIONAL_TRUE},
      {"[[ -v UID ]]", SHELL_CONDITIONAL_TRUE},
      {"unset UID; [[ -v UID ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v LC_ALL ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v POSIXLY_CORRECT ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ -v EUID ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v PPID ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v SHELLOPTS ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v BASHOPTS ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v BASH_COMPAT ]]", SHELL_CONDITIONAL_FALSE},
      {"[[ -v BASH_XTRACEFD ]]", SHELL_CONDITIONAL_FALSE},
      {"( [[ -v unknown ]] ) && [[ -v unknown ]]", SHELL_CONDITIONAL_TRUE},
      {"( [[ ! -v unknown ]] ) && [[ -v unknown ]]", SHELL_CONDITIONAL_FALSE},
      {"( unknown=; [[ -v unknown ]] ) && [[ -v unknown ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"( unset unknown; [[ ! -v unknown ]] ) && [[ -v unknown ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset A B; A= B=$( [[ -v A ]] ) && [[ -v B ]]", SHELL_CONDITIONAL_TRUE},
      {"unset A; A= : \"$( [[ -v A ]] )\"; [[ -v A ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset A; read -n0 A; [[ -v A ]]", SHELL_CONDITIONAL_TRUE},
      {"unset A; read -r A <<<payload; [[ -v A ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v unknown ]] && [[ -v unknown ]]", SHELL_CONDITIONAL_TRUE},
      {"[[ -v unknown ]] || [[ -v unknown ]]", SHELL_CONDITIONAL_FALSE},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
    CHECK(truth(cases[i].source) == cases[i].expected);
  static const struct {
    const char *source;
    shell_conditional_truth_t expected;
  } tests[] = {
      {"unset CONFIG; test -v CONFIG", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; test '-v' CONFIG", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; [ -v CONFIG ]", SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; command builtin test ! -v CONFIG",
       SHELL_CONDITIONAL_TRUE},
      {"unset A; B=; test -v A -o -v B", SHELL_CONDITIONAL_TRUE},
      {"unset A; B=; [ -v A -a -v B ]", SHELL_CONDITIONAL_FALSE},
      {"unset A; B=; test '(' -v A -o -v B ')' -a ! -v A",
       SHELL_CONDITIONAL_TRUE},
      {"unset A; B=; test -v A -a -v B -o ! -v A", SHELL_CONDITIONAL_TRUE},
      {"test '(' '!' ')'", SHELL_CONDITIONAL_TRUE},
      {"test '(' '(' -v = x ')' ')'", SHELL_CONDITIONAL_FALSE},
      {"test -v", SHELL_CONDITIONAL_TRUE},
      {"test -v = -v", SHELL_CONDITIONAL_TRUE},
      {"test -v -a nonempty", SHELL_CONDITIONAL_TRUE},
      {"[ -v CONFIG", SHELL_CONDITIONAL_FALSE},
      {"[ ]", SHELL_CONDITIONAL_FALSE},
      {"test", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; test -t -o -v CONFIG", SHELL_CONDITIONAL_TRUE},
      {"unset CONFIG; test -t -a -v CONFIG", SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; [ -t -o -v CONFIG ]", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; test -t invalid -o -v CONFIG", SHELL_CONDITIONAL_FALSE},
      {"unset MARK; CONFIG=; test -t invalid -o -v CONFIG && MARK=; [[ -v MARK "
       "]]",
       SHELL_CONDITIONAL_FALSE},
      {"CONFIG=; test -t '' -o -v CONFIG", SHELL_CONDITIONAL_FALSE},
      {"test x -o -t invalid", SHELL_CONDITIONAL_FALSE},
      {"test -t 999999999999999999999999999999999999999999",
       SHELL_CONDITIONAL_FALSE},
      {"test -t 1 -o x", SHELL_CONDITIONAL_TRUE},
      {"test -t ' +01 ' -o x", SHELL_CONDITIONAL_TRUE},
      {"test -t -1 -o x", SHELL_CONDITIONAL_TRUE},
      {"test '(' -t -o ')'", SHELL_CONDITIONAL_FALSE},
      {"test -t -o x", SHELL_CONDITIONAL_TRUE},
      {"CONFIG=; test '(' -t -o -v CONFIG ')'", SHELL_CONDITIONAL_TRUE},
      {"test x -o 1 -eq invalid", SHELL_CONDITIONAL_UNKNOWN},
      {"test -v inherited_unknown", SHELL_CONDITIONAL_UNKNOWN},
      {"test -v inherited_unknown -o ! -v inherited_unknown",
       SHELL_CONDITIONAL_TRUE},
      {"test -v inherited_unknown -a ! -v inherited_unknown",
       SHELL_CONDITIONAL_FALSE},
      {"test x -o -v inherited_unknown", SHELL_CONDITIONAL_TRUE},
      {"test '' -a -v inherited_unknown", SHELL_CONDITIONAL_FALSE},
      {"test -f external_path -a -v inherited_unknown",
       SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -v inherited_unknown ]] || :; test x; "
       "result=$( [[ -v inherited_unknown ]] )",
       SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -v inherited_unknown ]] || :; test ''; "
       "result=$( [[ ! -v inherited_unknown ]] )",
       SHELL_CONDITIONAL_UNKNOWN},
      {"[[ -v inherited_unknown ]] || :; ! test ''; "
       "result=$( [[ -v inherited_unknown ]] )",
       SHELL_CONDITIONAL_UNKNOWN},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); ++i)
    CHECK(test_truth(tests[i].source) == tests[i].expected);

  CHECK(truth("unset PWD OLDPWD; choose && PWD=; cd / && { "
              "[[ -v OLDPWD ]] && cat <was-set; "
              "[[ ! -v OLDPWD ]] && cat <was-unset; }") ==
        SHELL_CONDITIONAL_UNKNOWN);
  bool read_set = false, read_unset = false;
  for (uint32_t i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *node = &graph->nodes[edge->from];
    if (edge->type != SHELL_EDGE_READ || node->type != SHELL_NODE_DOC ||
        node->doc.kind != SHELL_DOC_FILE)
      continue;
    read_set |=
        node->doc.path_len == 7 && !memcmp(node->doc.path, "was-set", 7);
    read_unset |=
        node->doc.path_len == 9 && !memcmp(node->doc.path, "was-unset", 9);
  }
  CHECK(read_set && read_unset);

  CHECK(truth("unset OPTARG; getopts a OPTARG -b; "
              "[[ -v OPTARG ]] || cat <important.txt") ==
        SHELL_CONDITIONAL_UNKNOWN);
  bool read_important = false;
  for (uint32_t i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *from = &graph->nodes[edge->from];
    const shell_dep_node_t *to = &graph->nodes[edge->to];
    if (edge->type == SHELL_EDGE_READ && from->type == SHELL_NODE_DOC &&
        from->doc.kind == SHELL_DOC_FILE && from->doc.path_len == 13 &&
        !memcmp(from->doc.path, "important.txt", 13) &&
        to->type == SHELL_NODE_CMD && to->cmd.token_count == 1 &&
        to->cmd.token_lens[0] == 3 && !memcmp(to->cmd.tokens[0], "cat", 3))
      read_important = true;
  }
  CHECK(read_important);

  CHECK(truth("test -v CONFIG <input >output; [[ -v UID ]]") ==
        SHELL_CONDITIONAL_TRUE);
  for (uint32_t i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *e = &graph->edges[i];
    CHECK(!(e->type == SHELL_EDGE_READ && e->to == 0));
    CHECK(!((e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND) &&
            e->from == 0 && e->source_fd != 2));
  }
  static const char *const unsupported[] = {
      "[[ -v \"$name\" ]]", "[[ -v 1 ]]",
      "[[ -v 'a[0]' ]]",    "[[ -v 'a[$(printf marker)]' ]]",
      "[[ -R name ]]",      "[[ -v name && -v other ]]",
  };
  shell_source_result_t *draft = malloc(sizeof(*draft));
  CHECK(draft);
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i) {
    current = unsupported[i];
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_UNSUPPORTED);
    CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &limits,
                                graph) == SHELL_DEP_EPARSE);
  }
  static const char *const unsafe_tests[] = {
      "test -t -o -v 'a[$(printf marker)]'",
      "[ -t -o -v 'a[$(printf marker)]' ]",
      "test '(' -t -o -v 'a[$(printf marker)]' ')'",
      "test -t \"$FD\" -v 'a[$(printf marker)]'",
      "test -t \"$FD\" '(' -v 'a[$(printf marker)]' ')'",
      "[ -t \"$FD\" '(' -v 'a[$(printf marker)]' ')' ]",
  };
  for (size_t i = 0; i < sizeof(unsafe_tests) / sizeof(*unsafe_tests); ++i) {
    current = unsafe_tests[i];
    /* Drafts establish shell grammar; graph admission checks builtin effects.
     */
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &limits,
                                graph) == SHELL_DEP_EPARSE);
  }
  current = "[[ -v ordinary_inherited ]]";
  unsigned calls = 0;
  CHECK(shell_dep_graph_parse_resolved(current, strlen(current), "/workspace",
                                       &limits, graph, no_presence_callback,
                                       &calls, NULL) == SHELL_DEP_OK);
  CHECK(calls == 0 &&
        graph->nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_UNKNOWN);
  static const char *const prefixes[] = {"[[ -v", "[[ -v ", "[[ -v CON",
                                         "[[ -v 'CON"};
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(*prefixes); ++i) {
    current = prefixes[i];
    CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
          SHELL_SOURCE_INCOMPLETE);
  }
  char long_name[1024] = "[[ -v ";
  memset(long_name + 6, 'a', sizeof(long_name) - 10);
  memcpy(long_name + sizeof(long_name) - 4, " ]]", 4);
  CHECK(truth(long_name) == SHELL_CONDITIONAL_UNKNOWN);
  size_t full = limits.workspace_size;
  CHECK(shell_dep_workspace_size(NULL, &limits.workspace_size));
  current = long_name;
  CHECK(shell_dep_graph_parse(current, strlen(current), "/workspace", &limits,
                              graph) == SHELL_DEP_EWORKSPACE);
  CHECK(!graph->node_count && !graph->edge_count);
  limits.workspace_size = full;
  free(draft);
  free(workspace);
  free(graph);
  puts("scalar presence tests passed");
  return 0;
}
