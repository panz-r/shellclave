#include "../src/shell_arithmetic_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "arithmetic_cases.h"
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

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #condition,      \
              current);                                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const char *current = "setup";
static shell_dep_graph_t *graph;
static shell_source_result_t *draft;
static shell_dep_limits_t limits;
static void *workspace;

static void parse(const char *source) {
  current = source;
  shell_dep_error_t error = shell_dep_graph_parse(source, strlen(source),
                                                  "/workspace", &limits, graph);
  if (error != SHELL_DEP_OK)
    fprintf(stderr, "graph error %d\n", error);
  CHECK(error == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

static void check_semantic_rejection(const char *source) {
  current = source;
  size_t length = strlen(source);
  CHECK(shell_parse_draft(source, length, NULL, draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(shell_dep_graph_parse(source, length, ".", &limits, graph) ==
        SHELL_DEP_EPARSE);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  shell_netstring_buffer_t argv = {0}, raw = {0}, typed = {0};
  size_t count;
  bool features;
  CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &argv, &count,
                                            &features) == SHELL_PROCESS_EPARSE);
  CHECK(argv.data == NULL && argv.length == 0);
  CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw, &typed,
                                           &count) == SHELL_PROCESS_EPARSE);
  CHECK(raw.data == NULL && raw.length == 0 && typed.data == NULL &&
        typed.length == 0 && count == 0);
}

static void check_source_byte_domains(void) {
  for (size_t i = 0; i < sizeof(shellsplit_arithmetic_source_cases) /
                             sizeof(shellsplit_arithmetic_source_cases[0]);
       ++i) {
    current = shellsplit_arithmetic_source_cases[i].source;
    size_t length = strlen(current);
    shell_source_status_t expected =
        shellsplit_arithmetic_source_cases[i].status;
    if (expected == SHELL_SOURCE_COMPLETE) {
      check_semantic_rejection(current);
      CHECK(draft->header_count >= 2 &&
            draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
            draft->headers[0].source.start == 0 &&
            draft->headers[0].source.length == length &&
            draft->headers[0].arithmetic_expression.start == 2 &&
            draft->headers[0].arithmetic_expression.length == length - 4);
      const shell_source_header_t *child = &draft->headers[1];
      CHECK(child->kind == SHELL_COMMAND_SIMPLE && child->complete &&
            child->word_count > 0 &&
            child->source.start ==
                (size_t)(strstr(current, "printf") - current) &&
            child->source.start + child->source.length <= length &&
            child->words[0].start == child->source.start &&
            child->words[0].length == 6);
    } else {
      CHECK(shell_parse_draft(current, length, NULL, draft) == expected);
      CHECK(draft->prefix_length == 0 && draft->prefix.count == 0);
      if (expected == SHELL_SOURCE_INCOMPLETE) {
        CHECK(draft->header_count >= 2 &&
              draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
              !draft->headers[0].complete &&
              draft->headers[0].arithmetic_expression.start == 2 &&
              draft->headers[0].arithmetic_expression.length == length - 2 &&
              draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
      } else {
        for (uint32_t h = 0; h < draft->header_count; ++h)
          CHECK(!draft->headers[h].complete);
      }
    }
  }
  current = "printf before; (( $(printf 日本";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
  CHECK(draft->prefix_length == strlen("printf before;"));
  CHECK(draft->prefix.count == 1 && draft->header_count == 3);
  CHECK(draft->headers[0].complete);
  CHECK(draft->headers[1].kind == SHELL_COMMAND_ARITHMETIC &&
        !draft->headers[1].complete);
  /* The child's local command grammar is complete before its closing ')'. */
  CHECK(draft->headers[2].complete);
}

static void check_substring_whitespace(void) {
  /* Whitespace-only operands exercise substring's empty-operand handling
   * directly, without the parentheses used by the general expression matrix. */
  static const char *const contexts[] = {
      "echo \"${value:%s}\"",
      "echo \"${value:%s:1}\"",
      "echo \"${value:0:%s}\"",
  };
  static const char *const valid[] = {" ", "\t", "\n", "\\\n "};
  static const char *const invalid[] = {"\r", "\v", "\f"};
  for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]); ++c) {
    char source[64];
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
      snprintf(source, sizeof(source), contexts[c], valid[i]);
      parse(source);
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
      snprintf(source, sizeof(source), contexts[c], invalid[i]);
      check_semantic_rejection(source);
    }
  }
}

static bool setup_file(const char *name) {
  for (uint32_t i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *e = &graph->edges[i];
    uint32_t doc =
        graph->nodes[e->from].type == SHELL_NODE_DOC ? e->from : e->to;
    const shell_dep_node_t *n = &graph->nodes[doc];
    if ((e->type == SHELL_EDGE_FD_OPEN || e->type == SHELL_EDGE_READ ||
         e->type == SHELL_EDGE_WRITE) &&
        n->type == SHELL_NODE_DOC && n->doc.kind == SHELL_DOC_FILE &&
        n->doc.path_len == strlen(name) &&
        memcmp(n->doc.path, name, strlen(name)) == 0)
      return true;
  }
  return false;
}

static void check_expression_views(void) {
  static const struct {
    const char *source, *content;
    bool complete;
  } cases[] = {
      {"((1<<(2)))", "1<<(2)", true},
      {"(\\\n(1<\\\n(2)))", "1<\\\n(2)", true},
      {"((", "", false},
      {"((1<(2)", "1<(2)", false},
      {"$((1<<(2)))", "1<<(2)", true},
      {"$\\\n(\\\n(1)\\\n)", "1", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    current = cases[i].source;
    shell_tokenizer_state_t lexer;
    CHECK(shell_tokenizer_init(&lexer, current, strlen(current), NULL));
    shell_token_t token;
    CHECK(shell_tokenizer_next(&lexer, &token));
    CHECK((token.type == SHELL_TOKEN_ARITHMETIC ||
           token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) &&
          token.length == strlen(current));
    const char *content;
    size_t length;
    shell_tokenizer_arithmetic_content(&token, cases[i].complete, &content,
                                       &length);
    CHECK(length == strlen(cases[i].content) &&
          memcmp(content, cases[i].content, length) == 0);
  }
}

static void check_mixed_sequences(void) {
  static const struct {
    const char *source;
    size_t count;
    const char *names[4];
    bool has_substitution;
  } cases[] = {
      {"printf before; ((1<<(2))); cat < <(printf child)",
       4,
       {"printf", "", "printf", "cat"},
       true},
      {"((8>>(1))); cat <(printf child)", 3, {"", "printf", "cat"}, true},
      {"printf '%s' \"$((1<<(2)))\"", 1, {"printf"}, false},
      {"printf %s $\\\n(\\\n(1)\\\n)", 1, {"printf"}, false},
      {"printf >$((1))suffix$(printf path)", 2, {"printf", "printf"}, true},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
    current = cases[c].source;
    shell_netstring_buffer_t raw = {0}, typed = {0}, raw_only = {0},
                             typed_only = {0};
    size_t count, raw_count, typed_count;
    CHECK(shell_build_anomaly_netseqs_buffer(current, strlen(current), NULL,
                                             &raw, &typed,
                                             &count) == SHELL_PROCESS_OK);
    CHECK(count == cases[c].count);
    shell_netstring_iter_t items;
    shell_netstring_view_t item;
    CHECK(shell_netstring_iter_init(&items, raw.data, raw.length) ==
          SHELL_NETSTRING_OK);
    for (size_t i = 0; i < count; ++i) {
      CHECK(shell_netstring_iter_next(&items, &item) == SHELL_NETSTRING_OK);
      CHECK(item.payload_length == strlen(cases[c].names[i]) &&
            memcmp(item.payload, cases[c].names[i], item.payload_length) == 0);
    }
    CHECK(shell_netstring_iter_next(&items, &item) == SHELL_NETSTRING_DONE);
    CHECK(shell_build_command_netseq_buffer(current, strlen(current), NULL,
                                            &raw_only,
                                            &raw_count) == SHELL_PROCESS_OK);
    CHECK(shell_build_type_netseq_buffer(current, strlen(current), NULL,
                                         &typed_only,
                                         &typed_count) == SHELL_PROCESS_OK);
    CHECK(raw_count == count && typed_count == count &&
          raw_only.length == raw.length && typed_only.length == typed.length &&
          memcmp(raw_only.data, raw.data, raw.length) == 0 &&
          memcmp(typed_only.data, typed.data, typed.length) == 0);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&raw_only);
    shell_netstring_buffer_free(&typed_only);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(current, strlen(current), &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(abstract->has_cmd_subst == cases[c].has_substitution);
    shell_abstract_command_free(abstract);
  }
}

int main(int argc, char **argv) {
  graph = malloc(sizeof(*graph));
  draft = malloc(sizeof(*draft));
  CHECK(graph && draft);
  limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t bytes, source_bytes;
  CHECK(shell_dep_workspace_size(&limits, &bytes));
  CHECK(shell_source_workspace_size(16384, &source_bytes));
  bytes += source_bytes;
  workspace = malloc(bytes);
  CHECK(workspace != NULL);
  limits.workspace = workspace;
  limits.workspace_size = bytes;
  if (argc == 3 && strcmp(argv[1], "--truth") == 0) {
    parse(argv[2]);
    printf("%u\n", (unsigned)graph->nodes[0].cmd.arithmetic_truth);
    free(workspace);
    free(draft);
    free(graph);
    return 0;
  }

  check_expression_views();
  check_source_byte_domains();
  check_substring_whitespace();
  check_mixed_sequences();
  for (size_t c = 0; c < sizeof(shellsplit_arithmetic_cases) /
                             sizeof(shellsplit_arithmetic_cases[0]);
       ++c) {
    const char *expression = shellsplit_arithmetic_cases[c].expression;
    current = expression;
    shell_arithmetic_result_t fact =
        shell_arithmetic_analyze(expression, strlen(expression));
    int truth = shellsplit_arithmetic_cases[c].truth;
    CHECK(fact.supported && fact.known == (truth >= 0));
    if (fact.known)
      CHECK((fact.value != 0) == (truth != 0));
    char source[512];
    snprintf(source, sizeof(source), "((%s))", expression);
    current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft->header_count == 1 && draft->headers[0].compound &&
          draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
          draft->headers[0].word_count == 0 &&
          draft->headers[0].arithmetic_expression.length == strlen(expression));
    CHECK(draft->prefix.count == 1 &&
          draft->prefix.cmds[0].kind == SHELL_COMMAND_ARITHMETIC);
    parse(source);
    CHECK(graph->node_count >= 1 && graph->nodes[0].type == SHELL_NODE_CMD &&
          graph->nodes[0].cmd.kind == SHELL_COMMAND_ARITHMETIC &&
          graph->nodes[0].cmd.token_count == 0 &&
          graph->nodes[0].cmd.arithmetic_expression_length ==
              strlen(expression));
    CHECK(graph->nodes[0].cmd.arithmetic_truth ==
          (truth < 0 ? SHELL_ARITHMETIC_UNKNOWN
           : truth   ? SHELL_ARITHMETIC_NONZERO
                     : SHELL_ARITHMETIC_ZERO));
    for (uint32_t e = 0; e < graph->edge_count; ++e) {
      CHECK(graph->edges[e].type != SHELL_EDGE_READ);
      if (graph->edges[e].type == SHELL_EDGE_WRITE)
        CHECK(truth < 0 && graph->edges[e].source_fd == 2);
    }
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1 &&
          processed.commands[0].kind == SHELL_COMMAND_ARITHMETIC &&
          processed.commands[0].command_token_count == 0 &&
          processed.commands[0].arithmetic_expression_length ==
              strlen(expression));
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_t argv = {0}, raw = {0}, typed = {0},
                             typed_only = {0};
    size_t count;
    bool features;
    CHECK(shell_build_netargv_sequence_buffer(source, strlen(source), NULL,
                                              &argv, &count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(count == 0 && argv.length == 0 && features);
    CHECK(shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL, &raw,
                                             &typed,
                                             &count) == SHELL_PROCESS_OK);
    CHECK(count == 1 && raw.length == 3 && memcmp(raw.data, "0:,", 3) == 0 &&
          typed.length == 11 && memcmp(typed.data, "8:0:,2:AR,,", 11) == 0);
    CHECK(shell_build_type_netseq_buffer(source, strlen(source), NULL,
                                         &typed_only,
                                         &count) == SHELL_PROCESS_OK);
    CHECK(typed_only.length == typed.length &&
          memcmp(typed_only.data, typed.data, typed.length) == 0);
    shell_netstring_buffer_free(&argv);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&typed_only);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, strlen(source), &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(abstract->has_arithmetic && !abstract->has_cmd_subst);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count;
    CHECK(shell_transform_command_line(source, strlen(source), NULL,
                                       &transformed, &transformed_count) ==
          SHELL_TRANSFORM_OK);
    CHECK(transformed_count == 1 && transformed[0]->has_shell_syntax);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  for (size_t c = 0; c < sizeof(shellsplit_arithmetic_unsupported) /
                             sizeof(shellsplit_arithmetic_unsupported[0]);
       ++c) {
    const char *expression = shellsplit_arithmetic_unsupported[c];
    current = expression;
    CHECK(!shell_arithmetic_analyze(expression, strlen(expression)).supported);
    /* Parentheses distinguish substring operands from :+ and :- operators. */
    static const char *const contexts[] = {
        "((%s))",
        "echo $((%s))",
        "echo \"${value:(%s)}\"",
        "echo \"${value:0:(%s)}\"",
        "cat <<EOF\n$((%s))\nEOF\n",
        "((%s)) || cat <input",
        "((%s)) && cat <input",
        "echo before; ((%s)) || cat <input",
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
      char source[256];
      snprintf(source, sizeof(source), contexts[i], expression);
      check_semantic_rejection(source);
    }
  }
  parse("((0)) && cat <never || cat <yes");
  CHECK(!setup_file("never") && setup_file("yes"));
  parse("! ((1)) && cat <never || cat <yes");
  CHECK(!setup_file("never") && setup_file("yes"));
  parse("value=$( ((0)) ) && cat <never || cat <yes");
  CHECK(!setup_file("never") && setup_file("yes"));
  parse("((0)) | ((1)) && cat <yes");
  CHECK(setup_file("yes"));
  parse("((1)) <\"\" && cat <never");
  CHECK(!setup_file("never"));
  parse("cd /tmp && ((1)) && cat <input");
  for (uint32_t n = 0; n < graph->node_count; ++n)
    if (graph->nodes[n].type == SHELL_NODE_CMD &&
        graph->nodes[n].cmd.kind == SHELL_COMMAND_ARITHMETIC)
      CHECK(graph->nodes[n].cmd.cwd_known &&
            strcmp(graph->cwd_buf.data + graph->nodes[n].cmd.cwd_offset,
                   "/tmp") == 0);
  parse("((1)) >output <input");
  CHECK(setup_file("output") && setup_file("input"));
  for (uint32_t e = 0; e < graph->edge_count; ++e) {
    if (graph->edges[e].type == SHELL_EDGE_READ ||
        (graph->edges[e].type == SHELL_EDGE_WRITE &&
         graph->edges[e].source_fd != 2))
      fprintf(stderr, "unexpected route %s %u -> %u fd %u/%u\n",
              shell_dep_edge_type_name(graph->edges[e].type),
              graph->edges[e].from, graph->edges[e].to,
              graph->edges[e].source_fd, graph->edges[e].target_fd);
    CHECK(graph->edges[e].type != SHELL_EDGE_READ &&
          (graph->edges[e].type != SHELL_EDGE_WRITE ||
           graph->edges[e].source_fd == 2));
  }
  const char *incomplete = "printf before; ((1+";
  current = incomplete;
  CHECK(shell_parse_draft(incomplete, strlen(incomplete), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC &&
        draft->prefix_length == strlen("printf before;"));
  current = "(( $x + $(printf 1)";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
  shell_parse_result_t partial;
  CHECK(shell_parse_fast(current, strlen(current), NULL, &partial) == SHELL_OK);
  uint32_t expected = SHELL_FEAT_ARITH | SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL;
  CHECK(partial.count == 1 &&
        (partial.cmds[0].features & expected) == expected);
  current = "(( $(echo &&) ))";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_INVALID);
  current = "(( $(printf 1) ))";
  CHECK(shell_parse_draft(current, strlen(current), NULL, draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft->header_count == 2 &&
        draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC);
  parse("((printf ok); printf tail)");
  parse("( (printf ok) )");
  parse("{ ((1)); } | cat");
  parse("printf %s \"$( ((1<<2)); printf ok)\"");
  parse("cat <<EOF\n$( ((1<<2)); printf ok)\nEOF\n");
  parse("((1)) <<<payload");
  CHECK(graph->nodes[0].cmd.arithmetic_has_redirections);
  parse("((1)) {fd}>output; printf value >&$fd");
  parse("time ((1)) & cat <input");
  const char *two = "((1)); ((0))";
  shell_limits_t short_limits = SHELL_LIMITS_DEFAULT;
  short_limits.max_subcommands = 1;
  short_limits.strict_mode = true;
  shell_parse_result_t short_parse;
  current = two;
  CHECK(shell_parse_fast(two, strlen(two), &short_limits, &short_parse) ==
        SHELL_ETRUNC);
  CHECK(short_parse.count == 1 &&
        short_parse.cmds[0].kind == SHELL_COMMAND_ARITHMETIC);
  CHECK(shell_dep_graph_parse_with_fast(two, strlen(two), ".", &limits,
                                        &short_parse,
                                        graph) == SHELL_DEP_ETRUNC);
  CHECK(shell_dep_graph_validate(graph).valid);
  shell_netstring_buffer_t raw = {0}, typed = {0};
  size_t limited_count = 7;
  shell_process_limits_t output_limit = {10, 100, 0};
  CHECK(shell_build_anomaly_netseqs_buffer("((1))", 5, &output_limit, &raw,
                                           &typed, &limited_count) ==
        SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(!raw.data && !typed.data && limited_count == 0);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  static const struct {
    char digit;
    const char *suffix;
  } invalid_numbers[] = {{'0', "2#1))"}, {'9', "#1))"}, {'0', "8))"}};
  for (size_t c = 0; c < sizeof(invalid_numbers) / sizeof(invalid_numbers[0]);
       ++c) {
    size_t previous_work = 0;
    for (size_t digits = 16; digits <= 512; digits *= 2) {
      char source[1024] = "((";
      memset(source + 2, invalid_numbers[c].digit, digits);
      strcpy(source + 2 + digits, invalid_numbers[c].suffix);
      current = source;
      shellsplit_test_source_scan_reset();
      CHECK(shell_parse_draft(source, strlen(source), NULL, draft) ==
            SHELL_SOURCE_COMPLETE);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(!previous_work || work <= previous_work * 3);
      previous_work = work;
    }
  }
  size_t previous = 0;
  for (size_t terms = 16; terms <= 1024; terms *= 2) {
    char source[8192];
    size_t used = 0;
    memcpy(source, "((", 2);
    used = 2;
    for (size_t i = 0; i < terms; ++i) {
      memcpy(source + used, "- ", 2);
      used += 2;
    }
    memcpy(source + used, "1))", 4);
    used += 3;
    current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, used, NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous || work <= previous * 3);
    previous = work;
  }
  previous = 0;
  for (size_t depth = 8; depth <= 32; depth *= 2) {
    char source[256];
    size_t used = 0;
    for (size_t i = 0; i < depth; ++i)
      source[used++] = '(';
    memcpy(source + used, ":)", 2);
    used += 2;
    for (size_t i = 1; i < depth; ++i) {
      memcpy(source + used, ";:)", 3);
      used += 3;
    }
    source[used] = '\0';
    current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, used, NULL, draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous || work <= previous * 3);
    previous = work;
  }
#endif
  free(workspace);
  free(draft);
  free(graph);
  return 0;
}
