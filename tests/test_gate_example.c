/* Test the compiled example and the result-reporting excerpt in the README. */
#define main gate_example_main
#include "../examples/gate_policy.c"
#undef main
#include <shell_depgraph.h>

static shell_expand_status_t
fail_expansion(const shell_expand_word_request_t *request, const char **netargv,
               size_t *length, void *context) {
  (void)request;
  (void)netargv;
  (void)length;
  (void)context;
  return SHELL_EXPAND_FAILED;
}

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "example check failed at line %d: %s\n", __LINE__,       \
              #condition);                                                     \
      return EXIT_FAILURE;                                                     \
    }                                                                          \
  } while (0)

/* Both strings are NUL-terminated; result metadata is initialized for SG_OK
 * only. The temporary stream is closed and removed on every return path. */
static SHELL_NONNULL(1, 3, 4) bool report_is(const char *source,
                                             sg_error_t error,
                                             const sg_result_t *result,
                                             const char *expected) {
  FILE *output = tmpfile();
  if (!output)
    return false;
  report_analysis(output, source, error, result);
  bool valid = fflush(output) == 0 && fseek(output, 0, SEEK_SET) == 0;
  char actual[2048];
  size_t length = valid ? fread(actual, 1, sizeof(actual), output) : 0;
  valid = valid && !ferror(output);
  size_t source_length = strlen(source), expected_length = strlen(expected);
  valid = valid && length == source_length + 2 + expected_length &&
          !memcmp(actual, source, source_length) &&
          !memcmp(actual + source_length, ": ", 2) &&
          !memcmp(actual + source_length + 2, expected, expected_length);
  if (!valid)
    fprintf(stderr, "report mismatch for %s: %.*s\n", source, (int)length,
            actual);
  if (fclose(output) != 0)
    valid = false;
  return valid;
}

static int quoted_policy_bytes(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *allow = context ? st_policy_new(context) : NULL;
  st_policy_t *deny = allow ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  CHECK(deny && add_rule(allow, "printf %s 日本") &&
        add_rule(allow, "printf %s é") &&
        add_rule(allow, "printf %s \x80\xff"));
  sg_gate_t *gate = sg_gate_new_with_policies_owned(allow, deny);
  CHECK(gate && sg_gate_set_stop_mode(gate, SG_EVAL_ALL) == SG_OK);
  static const struct {
    const char *source;
    sg_verdict_t verdict;
  } cases[] = {
      {"printf %s '日本'", SG_VERDICT_ALLOW},
      {"printf %s 日本", SG_VERDICT_ALLOW},
      {"printf %s \"日本\"", SG_VERDICT_ALLOW},
      {"printf %s 'é'", SG_VERDICT_ALLOW},
      {"printf %s é", SG_VERDICT_ALLOW},
      {"printf %s 'é'", SG_VERDICT_UNDETERMINED},
      {"printf %s é", SG_VERDICT_UNDETERMINED},
      {"printf %s '\x80\xff'", SG_VERDICT_ALLOW},
      {"printf %s \x80\xff", SG_VERDICT_ALLOW},
      {"printf %s '\x80\xfe'", SG_VERDICT_UNDETERMINED},
      {"printf %s \x80\xfe", SG_VERDICT_UNDETERMINED},
  };
  size_t size = sg_gate_evaluate_size_hint(256);
  CHECK(size != SIZE_MAX);
  char *buffer = malloc(size);
  CHECK(buffer);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    sg_result_t result;
    CHECK(sg_gate_evaluate(gate, cases[i].source, strlen(cases[i].source),
                           buffer, size, &result) == SG_OK);
    CHECK(result.verdict == cases[i].verdict && !result.truncated &&
          !result.short_circuited && !result.unresolved_expansion_flags);
  }
  free(buffer);
  sg_gate_free(gate);
  return EXIT_SUCCESS;
}

static int graph_example(void) {
  const char source[] = "git status --short >report.txt";
  static shell_dep_graph_t graph;
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  CHECK(shell_dep_workspace_size(NULL, &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace != NULL);
  shell_dep_error_t error = shell_dep_graph_parse(
      source, sizeof(source) - 1, "/workspace", &limits, &graph);
  free(limits.workspace);
  CHECK(error == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid);
  CHECK(graph.node_count == 4 && graph.edge_count == 3);
  uint32_t command = UINT32_MAX, file = UINT32_MAX, input = UINT32_MAX,
           diagnostic = UINT32_MAX;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    const shell_dep_node_t *node = &graph.nodes[i];
    if (node->type == SHELL_NODE_CMD)
      command = i;
    else if (node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_FILE &&
             node->doc.path_len == 10 &&
             !memcmp(node->doc.path, "report.txt", 10))
      file = i;
    else if (node->type == SHELL_NODE_FD && node->fd.number == 0)
      input = i;
    else if (node->type == SHELL_NODE_FD && node->fd.number == 2)
      diagnostic = i;
  }
  CHECK(command != UINT32_MAX && file != UINT32_MAX && input != UINT32_MAX &&
        diagnostic != UINT32_MAX);
  bool stdin_route = false, stdout_route = false, stderr_route = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    CHECK(edge->dir == SHELL_DIR_FORWARD);
    stdin_route |= edge->type == SHELL_EDGE_READ && edge->from == input &&
                   edge->to == command && edge->target_fd == 0 &&
                   edge->source_fd == SHELL_DEP_FD_NONE;
    stdout_route |= edge->type == SHELL_EDGE_WRITE && edge->from == command &&
                    edge->to == file && edge->source_fd == 1 &&
                    edge->target_fd == SHELL_DEP_FD_NONE;
    stderr_route |= edge->type == SHELL_EDGE_WRITE && edge->from == command &&
                    edge->to == diagnostic && edge->source_fd == 2 &&
                    edge->target_fd == SHELL_DEP_FD_NONE;
  }
  CHECK(stdin_route && stdout_route && stderr_route);
  return EXIT_SUCCESS;
}

int main(void) {
  CHECK(quoted_policy_bytes() == EXIT_SUCCESS);
  CHECK(gate_example_main() == EXIT_SUCCESS);
  sg_gate_t *gate = example_gate();
  CHECK(gate != NULL);
  CHECK(sg_gate_set_reject_mask(gate, 0) == SG_OK);
  size_t arithmetic_size = sg_gate_evaluate_size_hint(128);
  char *arithmetic_buffer = malloc(arithmetic_size);
  CHECK(arithmetic_buffer);
  sg_result_t arithmetic_result;
  const char arithmetic_source[] = "[[ count -eq 0 ]]";
  CHECK(sg_gate_evaluate(gate, arithmetic_source, sizeof(arithmetic_source) - 1,
                         arithmetic_buffer, arithmetic_size,
                         &arithmetic_result) == SG_OK);
  CHECK(report_is(arithmetic_source, SG_OK, &arithmetic_result,
                  "argv policy UNDETERMINED; unresolved arithmetic\n"));
  free(arithmetic_buffer);
  CHECK(sg_gate_set_reject_mask(gate, SG_REJECT_MASK_DEFAULT) == SG_OK);
  static const char word_conditions[] =
      "argv policy ALLOW_CONDITIONAL; substitution inspection required; "
      "unresolved argv; dynamic substitution I/O present\n";
  static const char combined_conditions[] =
      "argv policy ALLOW_CONDITIONAL; substitution inspection required; "
      "unresolved argv; unresolved pathname; dynamic substitution I/O "
      "present\n";
  static const struct {
    const char *source;
    sg_verdict_t verdict;
    uint32_t commands, unresolved;
    bool inspect, dynamic_io;
    const char *report;
  } cases[] = {
      {"git status --short", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"git status --short # 日本 if while case $(false) >phantom",
       SG_VERDICT_ALLOW, 1, 0, false, false, "argv policy ALLOW\n"},
      {"# \x80\xff\ngit status --short", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"git status --short >report.txt", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"VALUE=example git status --short", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"whoami", SG_VERDICT_ALLOW, 1, 0, false, false, "argv policy ALLOW\n"},
      {"cd /tmp", SG_VERDICT_UNDETERMINED, 1, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"echo \"\"", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo '日本'", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo 日本if", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo 日本''if", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo 日本.if", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo '日本.if'", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo 日本-while", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo 日本.in", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo '\x80\xff'", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo '日本' >'résumé.txt'", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
      {"echo one two", SG_VERDICT_UNDETERMINED, 1, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"git reset --hard", SG_VERDICT_DENY, 1, 0, false, false,
       "argv policy DENY\n"},
      {"git reset --hard # 日本", SG_VERDICT_DENY, 1, 0, false, false,
       "argv policy DENY\n"},
      {"git log --oneline", SG_VERDICT_UNDETERMINED, 1, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"if true; then :; fi", SG_VERDICT_REJECT, 1, 0, false, false,
       "argv policy REJECT\n"},
      {"while false; do :; done", SG_VERDICT_REJECT, 1, 0, false, false,
       "argv policy REJECT\n"},
      {"case x in x) :;; esac", SG_VERDICT_REJECT, 1, 0, false, false,
       "argv policy REJECT\n"},
      {"echo \"$(whoami)\"", SG_VERDICT_ALLOW_CONDITIONAL, 2,
       SG_EXPANSION_UNRESOLVED_ARGV, true, true, word_conditions},
      {"echo \"`whoami`\"", SG_VERDICT_ALLOW_CONDITIONAL, 2,
       SG_EXPANSION_UNRESOLVED_ARGV, true, true, word_conditions},
      {"echo \"$(whoami)\" >\"$OUT\"", SG_VERDICT_ALLOW_CONDITIONAL, 2,
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH, true, true,
       combined_conditions},
      {"echo ok < <(whoami)", SG_VERDICT_ALLOW, 2, 0, false, true,
       "argv policy ALLOW; dynamic substitution I/O present\n"},
      {"echo \"$(<report.txt)\"", SG_VERDICT_ALLOW_CONDITIONAL, 1,
       SG_EXPANSION_UNRESOLVED_ARGV, true, true, word_conditions},
      {"echo \"$VALUE\"", SG_VERDICT_ALLOW, 1, SG_EXPANSION_UNRESOLVED_ARGV,
       false, false, "argv policy ALLOW; unresolved argv\n"},
      {"echo ok >\"$OUT\"", SG_VERDICT_ALLOW, 1, SG_EXPANSION_UNRESOLVED_PATH,
       false, false, "argv policy ALLOW; unresolved pathname\n"},
      {"echo 日本$VALUE >ré$OUT", SG_VERDICT_ALLOW, 1,
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH, false,
       false, "argv policy ALLOW; unresolved argv; unresolved pathname\n"},
      {"echo 日本* >ré*", SG_VERDICT_ALLOW, 1,
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH, false,
       false, "argv policy ALLOW; unresolved argv; unresolved pathname\n"},
      {"echo ok; >out", SG_VERDICT_UNDETERMINED, 1, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"echo ok; VALUE=example", SG_VERDICT_UNDETERMINED, 1, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"git reset --hard; >out", SG_VERDICT_DENY, 1, 0, false, false,
       "argv policy DENY\n"},
      {">out", SG_VERDICT_UNDETERMINED, 0, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"VALUE=example", SG_VERDICT_UNDETERMINED, 0, 0, false, false,
       "argv policy UNDETERMINED\n"},
      {"# comment", SG_VERDICT_ALLOW, 0, 0, false, false,
       "argv policy ALLOW\n"},
      {"# 日本 if while case $(whoami) >phantom", SG_VERDICT_ALLOW, 0, 0, false,
       false, "argv policy ALLOW\n"},
      {"time", SG_VERDICT_ALLOW, 0, 0, false, false, "argv policy ALLOW\n"},
      {"{ whoami; }", SG_VERDICT_ALLOW, 1, 0, false, false,
       "argv policy ALLOW\n"},
  };
  size_t size = sg_gate_evaluate_size_hint(2048);
  CHECK(size != SIZE_MAX);
  char *buffer = malloc(size);
  CHECK(buffer != NULL);
  sg_result_t result = {.verdict = SG_VERDICT_UNDETERMINED};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    sg_error_t error = sg_gate_evaluate(
        gate, cases[i].source, strlen(cases[i].source), buffer, size, &result);
    CHECK(error == SG_OK && result.verdict == cases[i].verdict);
    if (result.subcommand_count != cases[i].commands ||
        result.unresolved_expansion_flags != cases[i].unresolved ||
        result.requires_substitution_evaluation != cases[i].inspect ||
        result.has_dynamic_substitution_io != cases[i].dynamic_io)
      fprintf(stderr,
              "source: %s; commands=%u unresolved=%u inspect=%d dynamic=%d\n",
              cases[i].source, result.subcommand_count,
              result.unresolved_expansion_flags,
              result.requires_substitution_evaluation,
              result.has_dynamic_substitution_io);
    CHECK(result.subcommand_count == cases[i].commands &&
          result.unresolved_expansion_flags == cases[i].unresolved &&
          result.requires_substitution_evaluation == cases[i].inspect &&
          result.has_dynamic_substitution_io == cases[i].dynamic_io);
    CHECK(!result.truncated && !result.short_circuited);
    CHECK(report_is(cases[i].source, error, &result, cases[i].report));
    if (strcmp(cases[i].source, "VALUE=example git status --short") == 0 ||
        strcmp(cases[i].source, "git status --short >report.txt") == 0)
      CHECK(result.subcommands[0].netargv_length ==
                strlen("3:git,6:status,7:--short,") &&
            !memcmp(result.subcommands[0].netargv, "3:git,6:status,7:--short,",
                    result.subcommands[0].netargv_length));
  }

  /* A deny match wins even when the allow policy contains the same rule. */
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *allow = context ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  CHECK(allow && add_rule(allow, "git reset --hard") &&
        add_rule(allow, "cd *"));
  sg_gate_set_allow_policy_owned(gate, allow);
  const char denied[] = "git reset --hard";
  CHECK(sg_gate_evaluate(gate, denied, sizeof(denied) - 1, buffer, size,
                         &result) == SG_OK);
  CHECK(result.verdict == SG_VERDICT_DENY);
  CHECK(report_is(denied, SG_OK, &result, "argv policy DENY\n"));
  const char builtin[] = "cd /tmp";
  CHECK(sg_gate_evaluate(gate, builtin, sizeof(builtin) - 1, buffer, size,
                         &result) == SG_OK);
  CHECK(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  CHECK(report_is(builtin, SG_OK, &result, "argv policy ALLOW\n"));
  sg_gate_free(gate);
  gate = example_gate();
  CHECK(gate != NULL);

  const char short_circuit[] = "git status --short; git reset --hard";
  CHECK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_ALLOW) == SG_OK);
  CHECK(sg_gate_evaluate(gate, short_circuit, sizeof(short_circuit) - 1, buffer,
                         size, &result) == SG_OK);
  CHECK(result.verdict == SG_VERDICT_ALLOW && result.short_circuited);
  CHECK(report_is(short_circuit, SG_OK, &result,
                  "incomplete evaluation; reported argv policy ALLOW\n"));
  CHECK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL) == SG_OK);

  const char ordinary[] = "git status --short";
  sg_error_t error = sg_gate_evaluate(gate, ordinary, sizeof(ordinary) - 1,
                                      buffer, SG_DIAGNOSTIC_BUF_MIN, &result);
  CHECK(error == SG_ERR_MEMORY);
  CHECK(report_is(ordinary, error, &result, "evaluation failed (-2)\n"));
  error = sg_gate_evaluate(gate, ordinary, sizeof(ordinary) - 1, buffer, size,
                           &result);
  CHECK(error == SG_OK && result.verdict == SG_VERDICT_ALLOW);
  CHECK(report_is(ordinary, error, &result, "argv policy ALLOW\n"));

  const char malformed[] = "echo 'unfinished";
  error = sg_gate_evaluate(gate, malformed, sizeof(malformed) - 1, buffer, 1,
                           &result);
  CHECK(error == SG_ERR_TRUNC && result.truncated);
  CHECK(report_is(malformed, error, &result, "evaluation failed (-4)\n"));
  error = sg_gate_evaluate(gate, malformed, sizeof(malformed) - 1, buffer, size,
                           &result);
  CHECK(error == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT);
  CHECK(report_is(malformed, error, &result, "evaluation failed (-3)\n"));

  char many[(SG_MAX_SUBCOMMAND_RESULTS + 1) * 8 + 1] = {0};
  for (size_t i = 0; i < SG_MAX_SUBCOMMAND_RESULTS + 1; ++i)
    memcpy(many + i * 8, "echo ok;", 8);
  error = sg_gate_evaluate(gate, many, strlen(many), buffer, size, &result);
  CHECK(error == SG_ERR_TRUNC && result.truncated);
  CHECK(report_is(many, error, &result, "evaluation failed (-4)\n"));

  CHECK(sg_gate_set_expand_word_netargv(gate, fail_expansion, NULL) == SG_OK);
  const char dynamic[] = "echo \"$VALUE\"";
  error = sg_gate_evaluate(gate, dynamic, sizeof(dynamic) - 1, buffer, size,
                           &result);
  CHECK(error == SG_ERR_EXPAND);
  CHECK(report_is(dynamic, error, &result, "evaluation failed (-6)\n"));

  const char empty[] = "";
  error = sg_gate_evaluate(gate, empty, 0, buffer, size, &result);
  CHECK(error == SG_ERR_INVALID);
  CHECK(report_is(empty, error, &result, "evaluation failed (-1)\n"));

  /* Result metadata is usable only after a successful operation. */
  static const sg_error_t failures[] = {SG_ERR_INVALID, SG_ERR_MEMORY,
                                        SG_ERR_PARSE,   SG_ERR_TRUNC,
                                        SG_ERR_IO,      SG_ERR_EXPAND};
  sg_result_t unused_metadata = {.verdict = SG_VERDICT_UNDETERMINED};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
    char expected[64];
    snprintf(expected, sizeof(expected), "evaluation failed (%d)\n",
             failures[i]);
    CHECK(report_is("failed input", failures[i], &unused_metadata, expected));
  }
  free(buffer);
  sg_gate_free(gate);
  CHECK(graph_example() == EXIT_SUCCESS);
  return EXIT_SUCCESS;
}
