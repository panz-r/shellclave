#include <env_screener.h>
#include <shell_depgraph.h>
#include <shell_sequence.h>
#include <shell_source.h>
#include <shell_tokenizer.h>
#include <shellgate.h>
#include <shelltype.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef SG_BUF_MIN
#error "SG_BUF_MIN must not be exposed by the current public API"
#endif
#ifndef SG_DIAGNOSTIC_BUF_MIN
#error "SG_DIAGNOSTIC_BUF_MIN must remain available for diagnostic buffers"
#endif

static bool count_token(const st_token_view_t *token, void *user_ctx) {
  size_t *count = user_ctx;
  if (!token || !count)
    return false;
  (*count)++;
  return true;
}

static bool count_policy_match(st_netpattern_view_t netpattern,
                               void *user_ctx) {
  size_t *count = user_ctx;
  if (!netpattern.data || !count)
    return false;
  (*count)++;
  return true;
}

static bool count_policy_diff(st_policy_diff_kind_t kind,
                              st_netpattern_view_t netpattern, void *user_ctx) {
  size_t *count = user_ctx;
  if (kind != ST_POLICY_DIFF_ADDED || !netpattern.data || !count)
    return false;
  (*count)++;
  return true;
}

static bool check_policy_view_apis(st_netargv_view_t netargv) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_t *empty = ctx ? st_policy_new(ctx) : NULL;
  st_netpattern_t netpattern = {0};
  st_netpattern_view_t *all_matches = NULL;
  size_t all_count = 0;
  size_t visited_count = 0;
  size_t diff_count = 0;
  st_eval_result_t eval = {0};
  st_token_array_t validated = {0};
  bool matches = false;
  bool ok =
      ctx && policy && empty &&
      st_netpattern_from_cpl_owned("echo hello", &netpattern) == ST_OK &&
      st_netpattern_validate_view(
          (st_netpattern_view_t){(const char *)netpattern.data,
                                 netpattern.length},
          &validated) == ST_OK &&
      validated.count == 2 && validated.tokens[1].text_length == 5 &&
      memcmp(validated.tokens[1].text, "hello", 5) == 0 &&
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){(const char *)netpattern.data,
                                         netpattern.length}) == ST_OK &&
      st_policy_eval_view(policy, netargv, &eval) == ST_OK && eval.matches &&
      st_policy_match_view(policy, netargv, &matches) == ST_OK && matches &&
      st_policy_verify_all_view(policy, netargv, &all_matches, &all_count) ==
          ST_OK &&
      all_count == 1 && all_matches[0].length == netpattern.length &&
      memcmp(all_matches[0].data, netpattern.data, all_matches[0].length) ==
          0 &&
      st_policy_visit_matches_view(policy, netargv, count_policy_match,
                                   &visited_count, &visited_count) == ST_OK &&
      visited_count == 1 &&
      st_policy_visit_diff(empty, policy, count_policy_diff, &diff_count,
                           &diff_count) == ST_OK &&
      diff_count == 1;

  st_policy_matches_free(all_matches);
  st_token_array_free(&validated);
  st_netpattern_free(&netpattern);
  st_policy_free(empty);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return ok;
}

/* Exercise the changed canonical signatures with binary, unterminated input. */
static bool check_gate_netpattern_apis(void) {
  st_netpattern_t pattern = {0};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *allow = context ? st_policy_new(context) : NULL;
  st_policy_t *deny = allow ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  sg_gate_t *gate = NULL;
  bool ok = deny && st_netpattern_from_cpl_owned("printf \"a\\x00b\"",
                                                 &pattern) == ST_OK;
  char *bytes = ok ? malloc(pattern.length) : NULL;
  ok = ok && bytes != NULL;
  if (ok) {
    memcpy(bytes, pattern.data, pattern.length);
    st_netpattern_view_t view = {bytes, pattern.length};
    st_netpattern_view_t batch[] = {view, view};
    ok = memchr(view.data, '\0', view.length) != NULL &&
         st_policy_add_netpattern_view(allow, view) == ST_OK &&
         st_policy_batch_add_netpattern_views(allow, batch, 2) == ST_OK &&
         st_policy_add_netpattern_view(deny, view) == ST_OK &&
         st_policy_batch_add_netpattern_views(deny, batch, 2) == ST_OK;
    if (ok) {
      gate = sg_gate_new_with_policies_owned(allow, deny);
      if (gate) {
        allow = deny = NULL;
        ok = st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)) == 1 &&
             st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)) == 1;
      } else
        ok = false;
    }
  }
  free(bytes);
  st_netpattern_free(&pattern);
  sg_gate_free(gate);
  st_policy_free(allow);
  st_policy_free(deny);
  return ok;
}

/* Exercise the installed caller-owned dependency-graph workspace contract,
 * including its declared alignment, without relying on test-only adapters. */
static shell_expand_status_t
resolve_input(const shell_expand_word_request_t *request, const char **netargv,
              size_t *length, void *context) {
  (void)context;
  if (request->purpose != SHELL_EXPAND_WORD_REDIRECT_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  *netargv = "10:/tmp/input,";
  *length = sizeof("10:/tmp/input,") - 1;
  return SHELL_EXPAND_RESOLVED;
}

static bool check_depgraph_workspace_api(void) {
  size_t workspace_size = 0;
  size_t alignment = shell_dep_workspace_alignment();
  if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
      !shell_dep_resolved_workspace_size(256, NULL, &workspace_size) ||
      workspace_size == 0 || workspace_size > SIZE_MAX - (alignment - 1))
    return false;

  unsigned char *raw = malloc(workspace_size + alignment - 1);
  if (!raw)
    return false;
  uintptr_t address = (uintptr_t)(void *)raw;
  size_t padding = (size_t)((alignment - address % alignment) % alignment);
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  limits.workspace = raw + padding;
  limits.workspace_size = workspace_size;
  shell_dep_graph_t graph = {0};
  bool ok = shell_dep_graph_parse("echo hello", strlen("echo hello"), ".",
                                  &limits, &graph) == SHELL_DEP_OK &&
            shell_dep_graph_validate(&graph).valid;
  if (ok) {
    static const char timed[] = "time -p echo hello | cat";
    ok = shell_dep_graph_parse(timed, sizeof(timed) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    uint32_t timers = 0;
    uint32_t timed_commands = 0;
    for (uint32_t i = 0; ok && i < graph.node_count; i++) {
      if (graph.nodes[i].type == SHELL_NODE_TIME) {
        timers++;
        ok = graph.nodes[i].time.mode == SHELL_PIPE_TIME_POSIX &&
             graph.nodes[i].time.report_route == SHELL_TIME_REPORT_EXTERNAL &&
             graph.nodes[i].time.report_target_fd == 2 &&
             graph.nodes[i].time.report_route_flags ==
                 SHELL_TIME_REPORT_ROUTE_EXTERNAL &&
             graph.nodes[i].time.report_external_fd_count == 1 &&
             graph.nodes[i].time.report_external_fds[0] == 2;
      } else if (graph.nodes[i].type == SHELL_NODE_CMD) {
        ok = graph.nodes[i].cmd.pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
             graph.nodes[i].cmd.pipeline_time_id != 0;
        timed_commands++;
      }
    }
    ok = ok && timers == 1 && timed_commands == 2;
  }
  if (ok) {
    static const char resolved[] = "cat <\"$INPUT\"";
    ok = shell_dep_graph_parse_resolved(resolved, sizeof(resolved) - 1, ".",
                                        &limits, &graph, resolve_input, NULL,
                                        NULL) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
  }
  if (ok) {
    static const char redirected[] = "wc -l file.txt 2>&1";
    ok = shell_dep_graph_parse(redirected, sizeof(redirected) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK;
    bool stderr_to_stdout = false;
    for (uint32_t i = 0; ok && i < graph.edge_count; i++) {
      const shell_dep_edge_t *edge = &graph.edges[i];
      stderr_to_stdout |= edge->type == SHELL_EDGE_WRITE &&
                          edge->source_fd == 2 &&
                          graph.nodes[edge->to].type == SHELL_NODE_FD &&
                          graph.nodes[edge->to].fd.number == 1;
    }
    ok = ok && stderr_to_stdout && shell_dep_graph_validate(&graph).valid;
  }
  if (ok) {
    static const char directory[] = "cd /tmp && pwd";
    ok = shell_dep_graph_parse(directory, sizeof(directory) - 1, "/", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    unsigned commands = 0, cwd_edges = 0;
    for (uint32_t i = 0; ok && i < graph.node_count; i++)
      if (graph.nodes[i].type == SHELL_NODE_CMD) {
        const shell_dep_cmd_t *command = &graph.nodes[i].cmd;
        ok = command->cwd_known &&
             strcmp(graph.cwd_buf.data + command->cwd_offset,
                    commands == 0 ? "/" : "/tmp") == 0;
        commands++;
      }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      cwd_edges += graph.edges[i].type == SHELL_EDGE_CWD;
    ok = ok && commands == 2 && cwd_edges == 1;
  }
  if (ok) {
    static const char background[] = "wc -c &";
    ok = shell_dep_graph_parse(background, sizeof(background) - 1, ".", &limits,
                               &graph) == SHELL_DEP_OK &&
         shell_dep_graph_validate(&graph).valid;
    unsigned implicit = 0;
    for (uint32_t i = 0; ok && i < graph.node_count; ++i)
      if (graph.nodes[i].type == SHELL_NODE_DOC &&
          (graph.nodes[i].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
        ++implicit;
        char path[10];
        size_t written;
        bool absolute;
        ok = shell_dep_doc_file_identity_write(&graph, &graph.nodes[i].doc,
                                               path, sizeof(path), &written,
                                               &absolute) &&
             absolute && written == 9 && strcmp(path, "/dev/null") == 0;
      }
    ok = ok && implicit == 1;
  }
  if (ok) {
    static const char source[] = "echo before\ncat >target <<'EOF'\nalpha\n";
    shell_source_result_t *draft = malloc(sizeof(*draft));
    ok = draft &&
         shell_parse_draft(source, sizeof(source) - 1, NULL, draft) ==
             SHELL_SOURCE_INCOMPLETE &&
         draft->prefix_length == sizeof("echo before\n") - 1 &&
         draft->heredoc_count == 1 && draft->heredocs[0].content.value_len == 6;
    if (ok)
      ok = shell_dep_graph_parse_with_fast(source, draft->prefix_length, "/",
                                           &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK;
    if (ok) {
      static const char quoted[] = "printf '%s' '日本'";
      static const char unquoted[] = "printf '%s' 日本";
      static const char ansi[] = "printf '%s' $'日本'";
      static const char unsupported[] = "if true; then :; fi";
      static const char malformed[] = "cat <<\n";
      static const char nul[] = "echo\0x";
      static const char nul_word[] = "pre$'a\\0b'post";
      static const char arithmetic[] = "((2 + 3))";
      size_t effective_length = 0, binary_length = 0;
      ok = shell_parse_draft(quoted, sizeof(quoted) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           shell_parse_draft(unquoted, sizeof(unquoted) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           shell_parse_draft(ansi, sizeof(ansi) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           shell_parse_draft(unsupported, sizeof(unsupported) - 1, NULL,
                             draft) == SHELL_SOURCE_UNSUPPORTED &&
           shell_parse_draft(malformed, sizeof(malformed) - 1, NULL, draft) ==
               SHELL_SOURCE_INVALID &&
           shell_parse_draft(nul, sizeof(nul) - 1, NULL, draft) ==
               SHELL_SOURCE_INVALID_INPUT &&
           shell_visit_static_word(nul_word, sizeof(nul_word) - 1, NULL, NULL,
                                   &effective_length) &&
           effective_length == 8 &&
           shell_measure_decoded_word(nul_word, sizeof(nul_word) - 1,
                                      &binary_length) == SHELL_PROCESS_OK &&
           binary_length == 10 &&
           shell_parse_draft(arithmetic, sizeof(arithmetic) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->header_count == 1 &&
           draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
           shell_dep_graph_parse_with_fast(arithmetic, sizeof(arithmetic) - 1,
                                           ".", &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.kind == SHELL_COMMAND_ARITHMETIC &&
           graph.nodes[0].cmd.arithmetic_truth == SHELL_ARITHMETIC_NONZERO;
      const char condition[] = "[[ 'file.txt' == *.txt ]]";
      ok = ok &&
           shell_parse_draft(condition, sizeof(condition) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].kind == SHELL_COMMAND_CONDITIONAL &&
           shell_dep_graph_parse_with_fast(condition, sizeof(condition) - 1,
                                           ".", &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.kind == SHELL_COMMAND_CONDITIONAL &&
           graph.nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_TRUE &&
           graph.nodes[0].cmd.conditional_operand_count == 2 &&
           graph.nodes[0].cmd.conditional_predicate ==
               SHELL_CONDITIONAL_PATTERN_MATCH &&
           draft->headers[0].conditional_operand_count == 2 &&
           graph.nodes[0].cmd.conditional_operand_lengths[1] == 5 &&
           graph.nodes[0].cmd.token_count == 0;
      const char presence[] = "[[ -v UID ]]";
      ok = ok &&
           shell_parse_draft(presence, sizeof(presence) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].conditional_predicate ==
               SHELL_CONDITIONAL_VARIABLE_SET &&
           shell_dep_graph_parse_with_fast(presence, sizeof(presence) - 1, ".",
                                           &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.conditional_predicate ==
               SHELL_CONDITIONAL_VARIABLE_SET &&
           graph.nodes[0].cmd.conditional_operand_count == 1 &&
           graph.nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_TRUE;
      const char file_test[] = "[[ -N config.json ]]";
      ok = ok &&
           shell_parse_draft(file_test, sizeof(file_test) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].conditional_predicate ==
               SHELL_CONDITIONAL_FILE_MODIFIED_SINCE_READ &&
           shell_dep_graph_parse_with_fast(file_test, sizeof(file_test) - 1,
                                           ".", &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.conditional_predicate ==
               SHELL_CONDITIONAL_FILE_MODIFIED_SINCE_READ &&
           graph.nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_UNKNOWN;
      unsigned file_checks = 0;
      for (uint32_t i = 0; ok && i < graph.edge_count; ++i) {
        const shell_dep_edge_t *edge = &graph.edges[i];
        if (edge->type != SHELL_EDGE_FILE_TEST)
          continue;
        const shell_dep_doc_t *doc = &graph.nodes[edge->to].doc;
        ok = edge->from == 0 && edge->dir == SHELL_DIR_FORWARD &&
             graph.nodes[edge->to].type == SHELL_NODE_DOC &&
             doc->kind == SHELL_DOC_FILE &&
             edge->flags == SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ &&
             edge->source_fd == SHELL_DEP_FD_NONE &&
             edge->target_fd == SHELL_DEP_FD_NONE && doc->path_len == 11 &&
             !memcmp(doc->path, "config.json", 11);
        ++file_checks;
      }
      ok = ok && file_checks == 1;
      const char compound[] = "[[ first -nt second && -r first ]]";
      ok = ok &&
           shell_parse_draft(compound, sizeof(compound) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].conditional_predicate ==
               SHELL_CONDITIONAL_PREDICATE_NONE &&
           draft->headers[0].conditional_operand_count == 0 &&
           shell_dep_graph_parse_with_fast(compound, sizeof(compound) - 1, ".",
                                           &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_UNKNOWN &&
           shell_dep_graph_validate(&graph).valid;
      unsigned comparisons = 0;
      for (unsigned i = 0; ok && i < graph.node_count; ++i)
        if (graph.nodes[i].type == SHELL_NODE_FILE_COMPARISON) {
          ++comparisons;
          ok = graph.nodes[i].file_comparison.predicates ==
               SHELL_FILE_COMPARE_NEWER;
        }
      ok = ok && comparisons == 1;
      const char numeric[] = "[[ '2+3' -eq 5 ]]";
      ok = ok &&
           shell_parse_draft(numeric, sizeof(numeric) - 1, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].conditional_predicate ==
               SHELL_CONDITIONAL_NUMERIC_EQUAL &&
           shell_dep_graph_parse_with_fast(numeric, sizeof(numeric) - 1, ".",
                                           &limits, &draft->prefix,
                                           &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_TRUE;
      const char dependent[] = "[[ count -gt 0 ]]";
      ok = ok &&
           shell_dep_graph_parse(dependent, sizeof(dependent) - 1, ".", &limits,
                                 &graph) == SHELL_DEP_OK &&
           (graph.status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC) &&
           graph.nodes[0].cmd.conditional_arithmetic_unresolved &&
           shell_dep_graph_validate(&graph).valid;
      unsigned env_reads = 0;
      for (unsigned i = 0; ok && i < graph.edge_count; ++i) {
        const shell_dep_edge_t *edge = &graph.edges[i];
        if (edge->type != SHELL_EDGE_ENV ||
            edge->flags != SHELL_DEP_EDGE_FLAG_ENV_READ)
          continue;
        const shell_dep_doc_t *doc = &graph.nodes[edge->from].doc;
        ok = ok && doc->value == NULL && doc->value_len == 0 &&
             shell_dep_doc_env_name_equals(doc, "count", 5);
        ++env_reads;
      }
      ok = ok && env_reads == 1;

      char many_words[SHELL_DEP_MAX_TOKENS * 2 + 4] = "cmd";
      size_t many_length = 3;
      for (unsigned i = 1; i < SHELL_DEP_MAX_TOKENS; ++i) {
        memcpy(many_words + many_length, " a", 2);
        many_length += 2;
      }
      many_words[many_length] = 0;
      ok = ok &&
           shell_dep_graph_parse(many_words, many_length, ".", &limits,
                                 &graph) == SHELL_DEP_OK &&
           graph.nodes[0].cmd.token_count == SHELL_DEP_MAX_TOKENS &&
           shell_parse_draft(many_words, many_length, NULL, draft) ==
               SHELL_SOURCE_COMPLETE &&
           draft->headers[0].word_count == SHELL_DEP_MAX_TOKENS;
    }
    free(draft);
  }
  free(raw);
  return ok;
}

int main(void) {
  const char exact_token[] = {'4', '2', '\0', 'x'};
  if (st_token_classify(exact_token, 2) != ST_TYPE_NUMBER ||
      st_token_classify(exact_token, sizeof(exact_token)) != ST_TYPE_LITERAL ||
      st_token_classify(NULL, 0) != ST_TYPE_LITERAL)
    return 20;
  static const char command[] = "echo hello && printf done";
  shell_parse_result_t parsed = {0};
  shell_error_t error =
      shell_parse_fast(command, strlen(command), NULL, &parsed);
  if (error != SHELL_OK || parsed.status != SHELL_STATUS_OK ||
      parsed.count != 2 || parsed.cmds[0].start != 0 ||
      parsed.cmds[0].len != strlen("echo hello") ||
      parsed.cmds[1].type != SHELL_TYPE_AND ||
      parsed.cmds[1].start != strlen("echo hello && ") ||
      parsed.cmds[1].len != strlen("printf done"))
    return 1;

  shell_netstring_buffer_t command_netseq = {0};
  shell_netstring_buffer_t type_netseq = {0};
  size_t subcommand_count = 0;
  if (shell_build_anomaly_netseqs_buffer(
          command, strlen(command), NULL, &command_netseq, &type_netseq,
          &subcommand_count) != SHELL_PROCESS_OK ||
      subcommand_count != 2) {
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    return 2;
  }
  shell_netstring_buffer_free(&command_netseq);
  shell_netstring_buffer_free(&type_netseq);

  size_t environment_indices[1] = {0};
  size_t environment_count = 0;
  (void)shell_env_screener_scan(environment_indices,
                                sizeof(environment_indices) /
                                    sizeof(environment_indices[0]),
                                &environment_count, 0.5, 1);

  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.01,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  static const char netargv_data[] = "4:echo,5:hello,unframed trailer";
  st_netargv_view_t netargv = {
      .data = netargv_data,
      .length = strlen("4:echo,5:hello,"),
  };
  if (!learner || st_learner_feed_netargv_view(learner, netargv) != ST_OK) {
    st_learner_free(learner);
    return 3;
  }
  size_t visited_count = 0;
  if (st_netargv_visit_view(netargv, count_token, &visited_count, NULL) !=
          ST_OK ||
      visited_count != 2) {
    st_learner_free(learner);
    return 4;
  }
  if (!check_policy_view_apis(netargv)) {
    st_learner_free(learner);
    return 5;
  }
  size_t suggestion_count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &suggestion_count);
  char *suggestion_cpl = NULL;
  if (suggestions && suggestion_count == 1)
    (void)st_netpattern_to_cpl_view(
        (st_netpattern_view_t){suggestions[0].pattern,
                               suggestions[0].pattern_length},
        &suggestion_cpl);
  if (!suggestions || suggestion_count != 1 || !suggestion_cpl ||
      strcmp(suggestion_cpl, "echo hello") != 0 || suggestions[0].count != 1 ||
      suggestions[0].confidence != 1.0) {
    free(suggestion_cpl);
    st_suggestion_list_free(suggestions, suggestion_count);
    st_learner_free(learner);
    return 6;
  }
  free(suggestion_cpl);
  st_suggestion_list_free(suggestions, suggestion_count);
  st_learner_free(learner);

  if (!check_depgraph_workspace_api() || !check_gate_netpattern_apis())
    return 7;

  sg_gate_t *gate = sg_gate_new();
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  st_policy_ctx_release(context);
  st_netpattern_t pattern = {0};
  if (!gate || !policy ||
      st_netpattern_from_cpl_owned("echo hello", &pattern) != ST_OK ||
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){pattern.data, pattern.length}) !=
          ST_OK) {
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    sg_gate_free(gate);
    return 7;
  }
  st_netpattern_free(&pattern);
  sg_gate_set_allow_policy_owned(gate, policy);
  size_t buffer_size = sg_gate_evaluate_size_hint(strlen("echo hello"));
  char *buffer = buffer_size == SIZE_MAX ? NULL : malloc(buffer_size);
  sg_result_t result;
  sg_error_t gate_error =
      buffer ? sg_gate_evaluate(gate, "echo hello", strlen("echo hello"),
                                buffer, buffer_size, &result)
             : SG_ERR_MEMORY;
  free(buffer);
  sg_gate_free(gate);
  return gate_error == SG_OK && result.verdict == SG_VERDICT_ALLOW ? 0 : 8;
}
