/* Evaluation: the truth of arithmetic commands, conditional commands and
 * variable-presence tests, as the analysis decides them. The Bash qualification
 * drivers name the section to query. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#include "../src/shell_arithmetic_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_source_runtime_internal.h"
#include "../src/shell_test_internal.h"
#include "../src/shell_token_regions_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "arithmetic_cases.h"
#include "conditional_cases.h"
#include "graph_fixture.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_sequence.h"
#include "shell_source.h"
#include "shell_transform.h"

/* --- arithmetic (from arithmetic_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #condition,      \
              arithmetic_current);                                             \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const char *arithmetic_current = "setup";
static shell_dep_graph_t *graph;
static shell_source_result_t *arithmetic_draft;
static shell_dep_limits_t limits;

static void arithmetic_parse(const char *source) {
  arithmetic_current = source;
  shell_dep_error_t error = shell_dep_graph_parse(source, strlen(source),
                                                  "/workspace", &limits, graph);
  if (error != SHELL_DEP_OK)
    fprintf(stderr, "graph error %d\n", error);
  CHECK(error == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

static void arithmetic_check_semantic_rejection(const char *source) {
  arithmetic_current = source;
  size_t length = strlen(source);
  CHECK(shell_parse_draft(source, length, NULL, arithmetic_draft) ==
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

static void arithmetic_check_source_byte_domains(void) {
  for (size_t i = 0; i < sizeof(shellsplit_arithmetic_source_cases) /
                             sizeof(shellsplit_arithmetic_source_cases[0]);
       ++i) {
    arithmetic_current = shellsplit_arithmetic_source_cases[i].source;
    size_t length = strlen(arithmetic_current);
    shell_source_status_t expected =
        shellsplit_arithmetic_source_cases[i].status;
    if (expected == SHELL_SOURCE_COMPLETE) {
      arithmetic_check_semantic_rejection(arithmetic_current);
      CHECK(arithmetic_draft->header_count >= 2 &&
            arithmetic_draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
            arithmetic_draft->headers[0].source.start == 0 &&
            arithmetic_draft->headers[0].source.length == length &&
            arithmetic_draft->headers[0].arithmetic_expression.start == 2 &&
            arithmetic_draft->headers[0].arithmetic_expression.length ==
                length - 4);
      const shell_source_header_t *child = &arithmetic_draft->headers[1];
      CHECK(child->kind == SHELL_COMMAND_SIMPLE && child->complete &&
            child->word_count > 0 &&
            child->source.start ==
                (size_t)(strstr(arithmetic_current, "printf") -
                         arithmetic_current) &&
            child->source.start + child->source.length <= length &&
            child->words[0].start == child->source.start &&
            child->words[0].length == 6);
    } else {
      CHECK(shell_parse_draft(arithmetic_current, length, NULL,
                              arithmetic_draft) == expected);
      CHECK(arithmetic_draft->prefix_length == 0 &&
            arithmetic_draft->prefix.count == 0);
      if (expected == SHELL_SOURCE_INCOMPLETE) {
        CHECK(arithmetic_draft->header_count >= 2 &&
              arithmetic_draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
              !arithmetic_draft->headers[0].complete &&
              arithmetic_draft->headers[0].arithmetic_expression.start == 2 &&
              arithmetic_draft->headers[0].arithmetic_expression.length ==
                  length - 2 &&
              arithmetic_draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
      } else {
        for (uint32_t h = 0; h < arithmetic_draft->header_count; ++h)
          CHECK(!arithmetic_draft->headers[h].complete);
      }
    }
  }
  arithmetic_current = "printf before; (( $(printf 日本";
  CHECK(shell_parse_draft(arithmetic_current, strlen(arithmetic_current), NULL,
                          arithmetic_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(arithmetic_draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
  CHECK(arithmetic_draft->prefix_length == strlen("printf before;"));
  CHECK(arithmetic_draft->prefix.count == 1 &&
        arithmetic_draft->header_count == 3);
  CHECK(arithmetic_draft->headers[0].complete);
  CHECK(arithmetic_draft->headers[1].kind == SHELL_COMMAND_ARITHMETIC &&
        !arithmetic_draft->headers[1].complete);
  /* The child's local command grammar is complete before its closing ')'. */
  CHECK(arithmetic_draft->headers[2].complete);
}

static void arithmetic_check_substring_whitespace(void) {
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
      arithmetic_parse(source);
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
      snprintf(source, sizeof(source), contexts[c], invalid[i]);
      arithmetic_check_semantic_rejection(source);
    }
  }
}

static bool arithmetic_setup_file(const char *name) {
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

static void arithmetic_check_expression_views(void) {
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
    arithmetic_current = cases[i].source;
    shell_tokenizer_state_t lexer;
    CHECK(shell_tokenizer_init(&lexer, arithmetic_current,
                               strlen(arithmetic_current), NULL));
    shell_token_t token;
    CHECK(shell_tokenizer_next(&lexer, &token));
    CHECK((token.type == SHELL_TOKEN_ARITHMETIC ||
           token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) &&
          token.length == strlen(arithmetic_current));
    const char *content;
    size_t length;
    shell_tokenizer_arithmetic_content(&token, cases[i].complete, &content,
                                       &length);
    CHECK(length == strlen(cases[i].content) &&
          memcmp(content, cases[i].content, length) == 0);
  }
}

static void arithmetic_check_mixed_sequences(void) {
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
    arithmetic_current = cases[c].source;
    shell_netstring_buffer_t raw = {0}, typed = {0}, raw_only = {0},
                             typed_only = {0};
    size_t count, raw_count, typed_count;
    CHECK(shell_build_anomaly_netseqs_buffer(
              arithmetic_current, strlen(arithmetic_current), NULL, &raw,
              &typed, &count) == SHELL_PROCESS_OK);
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
    CHECK(shell_build_command_netseq_buffer(
              arithmetic_current, strlen(arithmetic_current), NULL, &raw_only,
              &raw_count) == SHELL_PROCESS_OK);
    CHECK(shell_build_type_netseq_buffer(
              arithmetic_current, strlen(arithmetic_current), NULL, &typed_only,
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
    CHECK(shell_abstract_command_parse(arithmetic_current,
                                       strlen(arithmetic_current),
                                       &abstract) == SHELL_ABSTRACT_OK);
    CHECK(abstract->has_cmd_subst == cases[c].has_substitution);
    shell_abstract_command_free(abstract);
  }
}

static int run_arithmetic(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE,
                                      16384, 1, false, 0));
  limits = fixture.limits;
  graph = fixture.graph[0];
  arithmetic_draft = malloc(sizeof(*arithmetic_draft));
  CHECK(arithmetic_draft);
  if (argc == 3 && strcmp(argv[1], "--truth") == 0) {
    arithmetic_parse(argv[2]);
    printf("%u\n", (unsigned)graph->nodes[0].cmd.arithmetic_truth);
    free(arithmetic_draft);
    shellsplit_graph_fixture_destroy(&fixture);
    return 0;
  }

  arithmetic_check_expression_views();
  arithmetic_check_source_byte_domains();
  arithmetic_check_substring_whitespace();
  arithmetic_check_mixed_sequences();
  for (size_t c = 0; c < sizeof(shellsplit_arithmetic_cases) /
                             sizeof(shellsplit_arithmetic_cases[0]);
       ++c) {
    const char *expression = shellsplit_arithmetic_cases[c].expression;
    arithmetic_current = expression;
    shell_arithmetic_result_t fact =
        shell_arithmetic_analyze(expression, strlen(expression));
    int truth = shellsplit_arithmetic_cases[c].truth;
    CHECK(fact.supported && fact.known == (truth >= 0));
    if (fact.known)
      CHECK((fact.value != 0) == (truth != 0));
    char source[512];
    snprintf(source, sizeof(source), "((%s))", expression);
    arithmetic_current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, arithmetic_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(arithmetic_draft->header_count == 1 &&
          arithmetic_draft->headers[0].compound &&
          arithmetic_draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC &&
          arithmetic_draft->headers[0].word_count == 0 &&
          arithmetic_draft->headers[0].arithmetic_expression.length ==
              strlen(expression));
    CHECK(arithmetic_draft->prefix.count == 1 &&
          arithmetic_draft->prefix.cmds[0].kind == SHELL_COMMAND_ARITHMETIC);
    arithmetic_parse(source);
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
    arithmetic_current = expression;
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
      arithmetic_check_semantic_rejection(source);
    }
  }
  arithmetic_parse("((0)) && cat <never || cat <yes");
  CHECK(!arithmetic_setup_file("never") && arithmetic_setup_file("yes"));
  arithmetic_parse("! ((1)) && cat <never || cat <yes");
  CHECK(!arithmetic_setup_file("never") && arithmetic_setup_file("yes"));
  arithmetic_parse("value=$( ((0)) ) && cat <never || cat <yes");
  CHECK(!arithmetic_setup_file("never") && arithmetic_setup_file("yes"));
  arithmetic_parse("((0)) | ((1)) && cat <yes");
  CHECK(arithmetic_setup_file("yes"));
  /* A setup which certainly fails is a shell-level error: no model. */
  arithmetic_current = "((1)) <\"\" && cat <never";
  CHECK(shell_dep_graph_parse(arithmetic_current, strlen(arithmetic_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
  arithmetic_parse("cd /tmp && ((1)) && cat <input");
  for (uint32_t n = 0; n < graph->node_count; ++n)
    if (graph->nodes[n].type == SHELL_NODE_CMD &&
        graph->nodes[n].cmd.kind == SHELL_COMMAND_ARITHMETIC)
      CHECK(graph->nodes[n].cmd.cwd_known &&
            strcmp(graph->cwd_buf.data + graph->nodes[n].cmd.cwd_offset,
                   "/tmp") == 0);
  arithmetic_parse("((1)) >output <input");
  CHECK(arithmetic_setup_file("output") && arithmetic_setup_file("input"));
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
  arithmetic_current = incomplete;
  CHECK(shell_parse_draft(incomplete, strlen(incomplete), NULL,
                          arithmetic_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(arithmetic_draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC &&
        arithmetic_draft->prefix_length == strlen("printf before;"));
  arithmetic_current = "(( $x + $(printf 1)";
  CHECK(shell_parse_draft(arithmetic_current, strlen(arithmetic_current), NULL,
                          arithmetic_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(arithmetic_draft->need == SHELL_SOURCE_NEEDS_ARITHMETIC);
  shell_parse_result_t partial;
  CHECK(shell_parse_fast(arithmetic_current, strlen(arithmetic_current), NULL,
                         &partial) == SHELL_OK);
  uint32_t expected = SHELL_FEAT_ARITH | SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL;
  CHECK(partial.count == 1 &&
        (partial.cmds[0].features & expected) == expected);
  arithmetic_current = "(( $(echo &&) ))";
  CHECK(shell_parse_draft(arithmetic_current, strlen(arithmetic_current), NULL,
                          arithmetic_draft) == SHELL_SOURCE_INVALID);
  arithmetic_current = "(( $(printf 1) ))";
  CHECK(shell_parse_draft(arithmetic_current, strlen(arithmetic_current), NULL,
                          arithmetic_draft) == SHELL_SOURCE_COMPLETE);
  CHECK(arithmetic_draft->header_count == 2 &&
        arithmetic_draft->headers[0].kind == SHELL_COMMAND_ARITHMETIC);
  arithmetic_parse("((printf ok); printf tail)");
  arithmetic_parse("( (printf ok) )");
  /* Without a closing `))` after the first balanced interior, `((` opens two
   * subshells. The fast parser frames it exactly as the spaced spelling. */
  static const struct {
    const char *nested, *spaced;
    const char *executable;
  } subshells[] = {
      {"((printf ok); printf tail)", "( (printf ok); printf tail )", "printf"},
      {"((cat secret.txt) 3>&1)", "( (cat secret.txt) 3>&1 )", "cat"},
      {"((true) >out) && printf x", "( (true) >out ) && printf x", "true"},
      {"x; ((cat) ); y", "x; ( (cat) ); y", "cat"},
  };
  for (size_t i = 0; i < sizeof(subshells) / sizeof(subshells[0]); i++) {
    shell_parse_result_t nested, spaced;
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    arithmetic_current = subshells[i].nested;
    CHECK(shell_parse_fast(subshells[i].nested, strlen(subshells[i].nested),
                           &strict, &nested) == SHELL_OK);
    CHECK(shell_parse_fast(subshells[i].spaced, strlen(subshells[i].spaced),
                           &strict, &spaced) == SHELL_OK);
    CHECK(nested.group_count == 2 && nested.group_count == spaced.group_count &&
          nested.count == spaced.count);
    for (size_t command = 0; command < nested.count; command++)
      CHECK(nested.cmds[command].kind == SHELL_COMMAND_SIMPLE);
    arithmetic_parse(subshells[i].nested);
    uint32_t nested_nodes = graph->node_count, nested_edges = graph->edge_count;
    bool found = false;
    for (uint32_t node = 0; node < nested_nodes; node++)
      found |=
          graph->nodes[node].type == SHELL_NODE_CMD &&
          graph->nodes[node].cmd.token_count &&
          graph->nodes[node].cmd.token_lens[0] ==
              strlen(subshells[i].executable) &&
          !memcmp(graph->nodes[node].cmd.tokens[0], subshells[i].executable,
                  strlen(subshells[i].executable));
    CHECK(found);
    arithmetic_parse(subshells[i].spaced);
    CHECK(graph->node_count == nested_nodes &&
          graph->edge_count == nested_edges);
  }
  /* A closing `))` still frames arithmetic, including with nested parens. */
  arithmetic_parse("((1)) && ((0))");
  arithmetic_parse("(( (1) + (2) ))");
  arithmetic_parse("{ ((1)); } | cat");
  arithmetic_parse("printf %s \"$( ((1<<2)); printf ok)\"");
  arithmetic_parse("cat <<EOF\n$( ((1<<2)); printf ok)\nEOF\n");
  arithmetic_parse("((1)) <<<payload");
  CHECK(graph->nodes[0].cmd.has_redirections);
  arithmetic_parse("((1)) {fd}>output; printf value >&$fd");
  arithmetic_parse("time ((1)) & cat <input");
  const char *two = "((1)); ((0))";
  shell_limits_t short_limits = SHELL_LIMITS_DEFAULT;
  short_limits.max_subcommands = 1;
  short_limits.strict_mode = true;
  shell_parse_result_t short_parse;
  arithmetic_current = two;
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
      arithmetic_current = source;
      shellsplit_test_source_scan_reset();
      CHECK(shell_parse_draft(source, strlen(source), NULL, arithmetic_draft) ==
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
    arithmetic_current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, used, NULL, arithmetic_draft) ==
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
    arithmetic_current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, used, NULL, arithmetic_draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous || work <= previous * 3);
    previous = work;
  }
#endif
  free(arithmetic_draft);
  shellsplit_graph_fixture_destroy(&fixture);
  return 0;
}
#undef CHECK

/* --- conditional (from conditional_test.c) --- */
static const char *conditional_current = "setup";
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #x,              \
              conditional_current);                                            \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static shell_dep_graph_t *graph;
static shell_source_result_t *conditional_draft;
static shell_dep_limits_t limits;

static void conditional_check_expansion_regions(void) {
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
    conditional_current = source;
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

static void conditional_check_partial_condition_regions(void) {
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
    conditional_current = source;
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
    CHECK(shell_parse_draft(source, used, NULL, conditional_draft) == status);
  }

  char source[4096] = "printf before; [[ ";
  for (unsigned i = 0; i < 50; ++i)
    strcat(source, "l -nt r && (");
  strcat(source, "-n \"$(printf child)\"");
  conditional_current = source;
  CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(conditional_draft->prefix_length == strlen("printf before;") &&
        conditional_draft->prefix.count == 1);
  CHECK(conditional_draft->header_count == 3 &&
        !conditional_draft->headers[1].complete &&
        conditional_draft->headers[2].complete);
}

static void conditional_parse(const char *source) {
  conditional_current = source;
  shell_dep_error_t e = shell_dep_graph_parse(source, strlen(source),
                                              "/workspace", &limits, graph);
  if (e != SHELL_DEP_OK)
    fprintf(stderr, "graph error %d\n", e);
  CHECK(e == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

/* A reached setup which certainly fails is a shell-level error: no model. */
static void conditional_reject(const char *source) {
  conditional_current = source;
  CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
}

static unsigned conditional_condition_node(void) {
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_CMD &&
        graph->nodes[i].cmd.kind == SHELL_COMMAND_CONDITIONAL)
      return i;
  CHECK(false);
  return 0;
}

static unsigned conditional_file_node(const char *name) {
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_DOC &&
        graph->nodes[i].doc.kind == SHELL_DOC_FILE &&
        graph->nodes[i].doc.path_len == strlen(name) &&
        !memcmp(graph->nodes[i].doc.path, name, strlen(name)))
      return i;
  CHECK(false);
  return 0;
}

static void conditional_check_file_predicates(void) {
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
    conditional_parse(cases[i].source);
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
      conditional_parse(source);
      CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
        conditional_parse(source);
        for (unsigned edge = 0; edge < graph->edge_count; ++edge)
          CHECK(graph->edges[edge].type != SHELL_EDGE_FILE_TEST &&
                (graph->edges[edge].type != SHELL_EDGE_READ ||
                 graph->nodes[graph->edges[edge].from].type != SHELL_NODE_DOC));
      }
    }
  }
  conditional_parse("[[ -e '' ]]");
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_FALSE);
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  conditional_reject("[[ -e config.json ]] <\"\"");
  conditional_reject("test -e config.json <\"\"");
  conditional_parse("test \"$operator\" target");
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
  conditional_parse("[[ -f * ]]");
  unsigned literal_star = conditional_file_node("*");
  CHECK(!(graph->nodes[literal_star].doc.flags &
          SHELL_DEP_DOC_FLAG_DYNAMIC_NAME));
  conditional_parse(
      "test -e = x"); /* Three-argument binary comparison, not -e x. */
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  conditional_parse("test 1 -eq 1");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  conditional_parse("test x -a y");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_FILE_TEST);
  conditional_parse("test -e a -a -d b");
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
  conditional_parse("test x -o -N first -a -G second");
  combined = count = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_FILE_TEST) {
      combined |= graph->edges[i].flags;
      ++count;
    }
  CHECK(combined == (SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ |
                     SHELL_DEP_EDGE_FLAG_FILE_TEST_OWNED_BY_GROUP));
  CHECK(count == 2);
  conditional_parse("test -f '' && cat /unreachable");
  for (unsigned i = 0; i < graph->edge_count; ++i)
    CHECK(graph->edges[i].type != SHELL_EDGE_READ ||
          graph->nodes[graph->edges[i].from].type != SHELL_NODE_DOC);
  conditional_parse("cd sub && [[ -N config.json ]]");
  unsigned file = conditional_file_node("config.json");
  CHECK(!graph->nodes[file].doc.cwd_known);
  conditional_parse("cd /src && [[ -N config.json ]]");
  file = conditional_file_node("config.json");
  CHECK(graph->nodes[file].doc.cwd_known);
  CHECK(
      !strcmp(graph->cwd_buf.data + graph->nodes[file].doc.cwd_offset, "/src"));
}

static void conditional_check_body_setup(void) {
  conditional_parse("[[ -n $(printf side >&2; printf value) ]] 2>report");
  unsigned owner = conditional_condition_node(),
           report = conditional_file_node("report");
  bool routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    routed |= edge->type == SHELL_EDGE_WRITE && edge->to == report &&
              edge->source_fd == 2 && edge->from != owner;
  }
  CHECK(routed && graph->nodes[owner].cmd.has_redirections);
  conditional_parse(
      "[[ -n $(read -r value; printf '%s' \"$value\") ]] <<<hello");
  owner = conditional_condition_node();
  bool read_document = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    read_document |= edge->type == SHELL_EDGE_READ && edge->to != owner &&
                     graph->nodes[edge->from].type == SHELL_NODE_DOC &&
                     graph->nodes[edge->from].doc.kind == SHELL_DOC_HERESTRING;
  }
  CHECK(read_document);
  conditional_reject("[[ -n $(cat body-input) ]] <\"\"");
  conditional_parse("[[ -n x ]] {fd}>report; printf x >&$fd");
  report = conditional_file_node("report");
  routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    routed |= graph->edges[i].type == SHELL_EDGE_WRITE &&
              graph->edges[i].to == report && graph->edges[i].source_fd == 1;
  CHECK(routed);
  conditional_parse("[[ -n <(cat) ]] <parent-input");
  unsigned input = conditional_file_node("parent-input");
  owner = conditional_condition_node();
  routed = false;
  for (unsigned i = 0; i < graph->edge_count; ++i) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    routed |= edge->type == SHELL_EDGE_READ && edge->from == input &&
              edge->to != owner;
    CHECK(!(edge->type == SHELL_EDGE_READ && edge->to == owner));
  }
  CHECK(routed);
  /* stdin is closed for the conditional's operands: `read -u0` certainly
   * fails, a descriptor contract violation. */
  conditional_current = "exec 0<&-; [[ -n <(cat)$(read -u0 value) ]] 0<&-";
  CHECK(shell_dep_graph_parse(conditional_current, strlen(conditional_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
  conditional_parse("exec 0<&-; [[ -n <(cat) ]] 0<&-");
  conditional_parse("time ! { [[ -z '' ]]; } | cat");
  conditional_parse("( [[ -n x ]] & ); printf tail");
}

static const char *conditional_resolved_value;
static size_t conditional_resolved_length;
static unsigned calls;
static SHELL_NONNULL(1, 2, 3) shell_expand_status_t
    resolve(const shell_expand_word_request_t *request, const char **value,
            size_t *length, void *context) {
  (void)context;
  CHECK(request->purpose == SHELL_EXPAND_WORD_CONDITIONAL);
  CHECK(request->cwd_known);
  ++calls;
  *value = conditional_resolved_value;
  *length = conditional_resolved_length ? conditional_resolved_length
                                        : strlen(conditional_resolved_value);
  return SHELL_EXPAND_RESOLVED;
}

static void conditional_check_file_predicate_resolution(void) {
  conditional_current = "[[ -N \"$path\" ]]";
  conditional_resolved_value = "4:path,";
  conditional_resolved_length = 0;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_OK);
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
  conditional_resolved_value = "0:,";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_OK);
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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

static void conditional_check_file_predicate_nul_argument(void) {
  conditional_current = "test -N \"$path\"";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_nul_argument, NULL, NULL) == SHELL_DEP_OK);
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
  conditional_current = "test \"$left\" -ef \"$right\"";
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_nul_argument, NULL,
            unresolved) == SHELL_DEP_OK);
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

static void conditional_check_comparison_operand_contexts(void) {
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
            conditional_current = source;
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
                  &graph->nodes[conditional_condition_node()].cmd;
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
              shell_dep_file_identity_t file_identity = {.length = 17,
                                                         .absolute = false};

              bool identified = shell_dep_doc_file_identity_write(
                  graph, doc, identity, sizeof(identity), &file_identity);
              CHECK(identified == (!empty && (!dynamic || resolved)));
              if (identified) {
                n = snprintf(expected, sizeof(expected), "/workspace/%s",
                             resolved ? "actual" : cases[c].literal);
                CHECK(n > 0 && (size_t)n < sizeof(expected));
                CHECK(file_identity.absolute &&
                      file_identity.length == (size_t)n &&
                      !strcmp(identity, expected));
              } else
                CHECK(!file_identity.length && !file_identity.absolute &&
                      !strcmp(identity, "unchanged"));
            }
            CHECK(count == 1);
          }

  const char *const nested[] = {
      "printf '%s' \"$(test \"$path\" -nt other)\"",
      "cat <([ other -ot \"$path\" ])",
  };
  for (unsigned i = 0; i < sizeof(nested) / sizeof(*nested); ++i) {
    conditional_current = nested[i];
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, NULL, NULL, unresolved) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
    unsigned flagged = 0;
    for (unsigned n = 0; n < SHELL_DEP_MAX_NODES; ++n)
      flagged += unresolved[n] != 0;
    CHECK(flagged == 1);
  }
  conditional_current = "[[ x || * -nt other ]]";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, NULL, NULL, unresolved) == SHELL_DEP_OK);
  for (unsigned i = 0; i < graph->node_count; ++i) {
    CHECK(graph->nodes[i].type != SHELL_NODE_FILE_COMPARISON && !unresolved[i]);
  }
  conditional_current = "printf '%s' \"$( [[ * -nt other ]] )\"";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, NULL, NULL, unresolved) == SHELL_DEP_OK);
  unsigned literal_operands = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_FILE_LEFT) {
      const shell_dep_doc_t *doc = &graph->nodes[graph->edges[i].to].doc;
      char identity[64];
      shell_dep_file_identity_t file_identity = {0};

      CHECK(!doc->flags &&
            shell_dep_doc_file_identity_write(
                graph, doc, identity, sizeof(identity), &file_identity));
      CHECK(file_identity.absolute &&
            file_identity.length == strlen("/workspace/*") &&
            !strcmp(identity, "/workspace/*"));
      ++literal_operands;
    }
  CHECK(literal_operands == 1);
  conditional_current = "test \"$path\" -nt other";
  shell_dep_limits_t truncated = limits;
  truncated.max_nodes = 1;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &truncated, graph, NULL, NULL, unresolved) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 1 && unresolved[0] &&
        shell_dep_graph_validate(graph).valid);
  for (unsigned i = graph->node_count; i < SHELL_DEP_MAX_NODES; ++i)
    CHECK(!unresolved[i]);
}

static void conditional_check_file_predicate_unresolved_paths(void) {
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
      {"test -n \"$path\"", NULL, 0},
  };
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    conditional_current = cases[c].source;
    memset(unresolved, 0xff, sizeof(unresolved));
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, resolve_predicate_path, (void *)cases[c].value,
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
  conditional_current = "test -N \"$path\"";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_nul_argument, NULL,
            unresolved) == SHELL_DEP_OK);
  unsigned flagged = 0;
  for (unsigned i = 0; i < graph->node_count; ++i)
    flagged += unresolved[i] != 0;
  CHECK(flagged == 1);

  /* Keep the command owner while denying capacity for its FILE document.
   * The public uncertainty result must survive that output truncation. */
  conditional_current = "[[ -N \"$path\" ]]";
  shell_dep_limits_t truncated = limits;
  truncated.max_nodes = 1;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &truncated, graph, NULL, NULL, unresolved) == SHELL_DEP_ETRUNC);
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

static void conditional_parse_test_operator(const char *source,
                                            const char *encoded) {
  conditional_current = source;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                       &limits, graph, resolve_test_operator,
                                       (void *)encoded, NULL) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
}

static unsigned conditional_predicate_edges(const char *path, unsigned mask) {
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

static bool conditional_has_document_read(void) {
  for (unsigned i = 0; i < graph->edge_count; ++i)
    if (graph->edges[i].type == SHELL_EDGE_READ &&
        graph->nodes[graph->edges[i].from].type == SHELL_NODE_DOC)
      return true;
  return false;
}

static void conditional_check_test_grammar_refinement(void) {
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
  conditional_parse("test -e \"$op\" -e -a -f target && cat <effect");
  CHECK(conditional_predicate_edges(
            "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR) == 1);
  CHECK(conditional_has_document_read());
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
      conditional_parse(source);
      CHECK(conditional_predicate_edges("=",
                                        SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) ==
            boundaries[i].files);
      CHECK(conditional_has_document_read());
      conditional_parse_test_operator(source, "1:=,");
      CHECK(conditional_predicate_edges("=",
                                        SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) ==
            boundaries[i].files);
      CHECK(conditional_has_document_read());
    }
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    char source[128];
    snprintf(source, sizeof(source), "%s -e \"$op\" x -a -e =%s && cat <effect",
             bracket ? "[" : "test", bracket ? " ]" : "");
    conditional_parse(source);
    CHECK(conditional_has_document_read());
    CHECK(conditional_predicate_edges(
              "=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
    conditional_parse_test_operator(source, "2:!=,");
    CHECK(conditional_has_document_read());
    CHECK(conditional_predicate_edges(
              "=", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
  }
  conditional_parse_test_operator(
      "test -e \"$op\" -e -a -f target && cat <effect", "1:=,");
  CHECK(conditional_predicate_edges(
            "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR) == 1);
  CHECK(conditional_has_document_read());
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    const char *source = bracket ? "[ \"$op\" target ]" : "test \"$op\" target";
    conditional_parse(source);
    CHECK(conditional_predicate_edges("target", all) == 1);
    conditional_parse_test_operator(source, "2:-n,");
    CHECK(conditional_predicate_edges("target", 0) == 0);
    conditional_parse_test_operator(source, "2:-e,");
    CHECK(conditional_predicate_edges(
              "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS) == 1);
    conditional_parse_test_operator(source, "2:-S,");
    CHECK(conditional_predicate_edges(
              "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_SOCKET) == 1);
    conditional_parse_test_operator(source, "2:-N,");
    CHECK(conditional_predicate_edges(
              "target", SHELL_DEP_EDGE_FLAG_FILE_TEST_MODIFIED_SINCE_READ) ==
          1);
  }
  conditional_parse_test_operator("test \"$op\" target || cat <unreachable",
                                  "2:-n,");
  CHECK(!conditional_has_document_read());
  conditional_parse_test_operator("test \"$op\" target && cat <input", "2:-n,");
  CHECK(conditional_has_document_read());
  conditional_parse_test_operator("test \"$op\" target && cat <unreachable",
                                  "2:-z,");
  CHECK(!conditional_has_document_read());
  conditional_parse_test_operator(
      "unset CONFIG; test \"$op\" CONFIG && cat <unreachable", "2:-v,");
  CHECK(!conditional_has_document_read());
  CHECK(conditional_predicate_edges("CONFIG", 0) == 0);
  conditional_parse_test_operator("CONFIG=; test \"$op\" CONFIG && cat <input",
                                  "2:-v,");
  CHECK(conditional_has_document_read());
  CHECK(conditional_predicate_edges("CONFIG", 0) == 0);
  conditional_parse_test_operator(
      "unset CONFIG; test -e \"$op\" -e -a -v CONFIG && cat <unreachable",
      "1:=,");
  CHECK(!conditional_has_document_read());
  conditional_parse_test_operator(
      "CONFIG=; test -e \"$op\" -e -a -v CONFIG && cat <input", "1:=,");
  CHECK(conditional_has_document_read());
  conditional_current = "test -e \"$op\" -e -a -v 'a[$(printf marker)]'";
  CHECK(shell_dep_graph_parse(conditional_current, strlen(conditional_current),
                              "/workspace", &limits,
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
  conditional_parse(source);
  limits.workspace_size = previous;
}

typedef struct {
  const char *values[2];
  const char *words[2];
  bool unresolved[2];
  unsigned calls;
  size_t offsets[2];
} conditional_comparison_resolver_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    resolve_comparison(const shell_expand_word_request_t *request,
                       const char **value, size_t *length, void *context) {
  conditional_comparison_resolver_t *resolver = context;
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

static void conditional_check_conditional_observation_order(void) {
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
                          "exec 63<<<seed 62<&- || exit; [[ ( %s ) || "
                          "-n \"$(read -r -u63 -n1 before)\"<(printf pipe)"
                          "\"$(read -r -u62 -n1 after)\" ]]",
                          cases[c].prefix);
    CHECK(length > 0 && (size_t)length < sizeof(source));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    conditional_parse(source);
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
static void conditional_count_arithmetic_reference(const char *name,
                                                   size_t length,
                                                   void *context) {
  CHECK(length == 5 && !memcmp(name, "count", length));
  ++*(unsigned *)context;
}

static void conditional_check_scalar_arithmetic_boundary(void) {
  unsigned references = 0;
  const char expression[] = "count + 2 * 3";
  shell_arithmetic_scalar_result_t scalar = shell_arithmetic_analyze_scalar(
      expression, sizeof(expression) - 1,
      conditional_count_arithmetic_reference, &references);
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

static void conditional_check_arithmetic_mutation_rejection(void) {
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
      conditional_current = source;
      CHECK(shell_parse_draft(source, strlen(source), NULL,
                              conditional_draft) == SHELL_SOURCE_COMPLETE);
      CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                  graph) == SHELL_DEP_EPARSE);
      CHECK(graph->status == SHELL_DEP_STATUS_ERROR && !graph->node_count &&
            !graph->edge_count && !graph->cwd_buf.len);
    }
  /* Pure scalar operators still publish direct reads and coverage status. */
  conditional_parse("[[ 'count + +1' -eq 0 ]]");
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

static void conditional_check_numeric_conditional_contract(void) {
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
    conditional_parse(cases[i].source);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
                            NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
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
  conditional_parse("[[ count -eq 0 ]]");
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
        conditional_parse(source);
        CHECK(
            graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
            SHELL_CONDITIONAL_UNKNOWN);
        CHECK(graph->nodes[conditional_condition_node()]
                  .cmd.conditional_unresolved);
        CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
        for (unsigned e = 0; e < graph->edge_count; ++e)
          if (graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ)
            CHECK(shell_dep_doc_env_name_equals(
                &graph->nodes[graph->edges[e].from].doc, "value", 5));
      }
  for (unsigned unresolved = 0; unresolved < 2; ++unresolved) {
    conditional_comparison_resolver_t resolver = {
        .values = {"1:3,"}, .words = {"~"}, .unresolved = {unresolved}};
    const char *source = "[[ ~ -eq -1 ]] || cat <fallback";
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                         &limits, graph, resolve_comparison,
                                         &resolver, NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 1);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          (unresolved ? SHELL_CONDITIONAL_UNKNOWN : SHELL_CONDITIONAL_FALSE));
    CHECK(!!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC) ==
          !!unresolved);
    CHECK(reads_file("fallback") == !unresolved);
  }
  conditional_parse("[[ -z x && ~+0 -eq -1 ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  static const char *const operands[] = {"count", "\"$count\"", "\"${count}\""};
  for (unsigned i = 0; i < sizeof(operands) / sizeof(*operands); ++i) {
    char source[256];
    snprintf(source, sizeof(source), "cat <before; [[ %s -gt 0 ]]; cat <after",
             operands[i]);
    conditional_parse(source);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(graph->nodes[conditional_condition_node()]
              .cmd.conditional_arithmetic_unresolved);
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
    for (unsigned n = conditional_condition_node() + 1; n < graph->node_count;
         ++n)
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
    conditional_parse(parameter_sources[i]);
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
  conditional_parse("[[ count -eq 0 ]]; { cat; } <relative-after");
  for (unsigned n = 0; n < graph->node_count; ++n)
    if (graph->nodes[n].type == SHELL_NODE_DOC &&
        graph->nodes[n].doc.kind == SHELL_DOC_FILE)
      CHECK(!graph->nodes[n].doc.cwd_known);
  conditional_parse("[[ count -eq 0 ]]; time printf after");
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  conditional_parse("[[ co$((1)) -eq 0 ]]");
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  for (unsigned e = 0; e < graph->edge_count; ++e)
    if (graph->edges[e].type == SHELL_EDGE_ENV)
      CHECK(shell_dep_doc_env_name_equals(
          &graph->nodes[graph->edges[e].from].doc, "co1", 3));
  conditional_parse("unset later; [[ count -eq 0 && -v later ]]");
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
  conditional_parse("[[ -z x && count -gt 0 ]] && cat <skipped");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  CHECK(!reads_file("skipped"));
}

static void conditional_check_nested_arithmetic_coverage(void) {
  static const char *const sources[] = {
      "cat < <( [[ count -eq 0 ]]; cat <inchild ); cat <after",
      "printf \"%s\" \"$(< <( [[ count -eq 0 ]]; cat <inchild ))\"; cat <after",
      "printf \"$( [[ count -eq 0 ]]; cat <inchild )\"; cat <after",
  };
  for (unsigned i = 0; i < sizeof(sources) / sizeof(*sources); ++i) {
    conditional_parse(sources[i]);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(!reads_file("inchild"));
    CHECK(!reads_file("after"));
  }
  conditional_parse("[[ -z x && $( [[ count -eq 0 ]] ) -eq 0 ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
}

static void conditional_check_conditional_coverage_barrier(void) {
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
    conditional_parse(source);
    CHECK(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
  conditional_parse("[[ -z x && count -eq 0 || -f literal ]]");
  CHECK(!(graph->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC));
  unsigned tests = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    tests += graph->edges[e].type == SHELL_EDGE_FILE_TEST;
  CHECK(tests == 1);

  conditional_current = "[[ count -eq 0 && \"$path\" -nt other ]]";
  conditional_comparison_resolver_t resolver = {
      .values = {"1:0,", "6:target,"}, .words = {"count", "\"$path\""}};
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_comparison, &resolver,
            NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2 && graph->status == SHELL_DEP_STATUS_OK);
  unsigned comparisons = 0;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    comparisons += graph->edges[e].type == SHELL_EDGE_FILE_COMPARE;
  CHECK(comparisons == 1 && shell_dep_graph_validate(graph).valid);
}

static void conditional_check_parameter_operand_dependencies(void) {
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
      conditional_current = source;
      /* Builtin admission deliberately rejects complex parameter operators
       * whose argv cardinality it cannot establish. Keep that boundary. */
      if ((form == 1 || form == 2) && !cases[i].builtin_scalar) {
        CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace",
                                    &limits, graph) == SHELL_DEP_EPARSE);
        continue;
      }
      conditional_parse(source);
      for (unsigned resolved = 0; resolved < (form == 0 ? 2u : 1u);
           ++resolved) {
        if (resolved) {
          conditional_comparison_resolver_t resolver = {
              .values = {"1:0,"}, .words = {cases[i].word}};
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
  conditional_parse("[[ -z x && ${1:-$fallback} -eq 0 ]]");
  for (unsigned e = 0; e < graph->edge_count; ++e)
    CHECK(graph->edges[e].flags != SHELL_DEP_EDGE_FLAG_ENV_READ);
  conditional_parse("test x -o \"$fallback\" -eq 0");
  bool read = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    read |= graph->edges[e].flags == SHELL_DEP_EDGE_FLAG_ENV_READ;
  CHECK(read);
}

static void conditional_check_builtin_argument_read_phase(void) {
  static const struct {
    const char *source;
    unsigned reads;
  } cases[] = {
      {"test \"$count\" -eq 0", 1},
      {"test \"$count\" -eq 0 1>fail", 1},
      {"[ \"$count\" -eq 0 ] 1>fail", 1},
      {"1>fail test \"$count\" -eq 0", 1},
      {"test \"$count\" -eq \"$fallback\" 1>fail", 2},
      {"test x -o \"$count\" -eq invalid 1>fail", 1},
      {"false && test \"$count\" -eq 0", 0},
  };
  conditional_reject("{ test \"$count\" -eq 0; } 1>\"\"");
  conditional_reject("test -f \"$count\" 1>\"\"");
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    for (unsigned resolved = 0; resolved < 2; ++resolved) {
      if (resolved)
        conditional_parse_test_operator(cases[i].source, "1:0,");
      else
        conditional_parse(cases[i].source);
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

static void conditional_check_builtin_integer_comparisons(void) {
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
      conditional_parse(source);
      CHECK(reads_file("numeric-success") == cases[i].success);
    }
}

static void conditional_check_file_comparison_continuations(void) {
  /* Ordinary executable arguments retain ARG relations; an active cat also
   * has a possible stdin route. Explicit redirects below test file READs. */
  conditional_parse("[[ \"$path\" -ef reference ]] && cat important.txt");
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
            conditional_parse(source);
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
                  &graph->nodes[conditional_condition_node()].cmd;
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
          conditional_current = source;
          unsigned requests = 0;
          uint8_t unresolved[SHELL_DEP_MAX_NODES];
          CHECK(shell_dep_graph_parse_resolved(
                    source, strlen(source), "/workspace", &limits, graph,
                    observe_comparison_branch, &requests,
                    unresolved) == SHELL_DEP_OK);
          CHECK(shell_dep_graph_validate(graph).valid);
          CHECK(requests == (unsigned)reached);
          CHECK(reads_file("important.txt") == reached);
          unsigned owner = conditional_condition_node();
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
      conditional_current = source;
      conditional_comparison_resolver_t resolver = {
          .values = {captured[c].values[0], captured[c].values[1]},
          .unresolved = {!captured[c].values[0], !captured[c].values[1]}};
      uint8_t unresolved[SHELL_DEP_MAX_NODES];
      CHECK(shell_dep_graph_parse_resolved(
                source, strlen(source), "/workspace", &limits, graph,
                resolve_comparison, &resolver, unresolved) == SHELL_DEP_OK);
      CHECK(resolver.calls == 2 && shell_dep_graph_validate(graph).valid);
      bool known_false = (captured[c].false_kinds & (1u << op)) != 0;
      const shell_dep_cmd_t *command =
          &graph->nodes[conditional_condition_node()].cmd;
      CHECK(
          command->conditional_truth ==
          (known_false ? SHELL_CONDITIONAL_FALSE : SHELL_CONDITIONAL_UNKNOWN));
      CHECK(reads_file("important.txt") == !known_false);
      CHECK(command->conditional_unresolved ==
            (resolver.unresolved[0] || resolver.unresolved[1]));
      CHECK(unresolved[conditional_condition_node()] ==
            command->conditional_unresolved);
      for (unsigned i = 0; i < graph->node_count; ++i)
        if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON)
          CHECK(graph->nodes[i].file_comparison.empty_operands ==
                captured[c].empty_operands);
    }
}

static void conditional_check_comparisons(void) {
  conditional_current = "[[ ! 'left' != \"right\" ]]";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
  shell_source_header_t *header = &conditional_draft->headers[0];
  CHECK(header->conditional_operand_count == 2);
  CHECK(header->conditional_predicate == SHELL_CONDITIONAL_STRING_NOT_EQUAL);
  CHECK(header->conditional_negated);
  CHECK(header->conditional_operands[0].length == 6 &&
        header->conditional_operands[1].length == 7);
  conditional_parse(conditional_current);
  const shell_dep_cmd_t *condition =
      &graph->nodes[conditional_condition_node()].cmd;
  CHECK(condition->conditional_operand_count == 2);
  CHECK(condition->conditional_predicate == header->conditional_predicate);
  CHECK(condition->conditional_negated == header->conditional_negated);
  CHECK(condition->conditional_truth == SHELL_CONDITIONAL_FALSE);
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(conditional_current, strlen(conditional_current),
                               NULL, &processed) == SHELL_PROCESS_OK);
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
      conditional_current = "[[ \"$left\" == \"$right\" ]]";
      conditional_comparison_resolver_t resolver = {
          .values = {"1:x,", unequal ? "1:y," : "1:x,"},
          .unresolved = {unresolved & 1, unresolved & 2}};
      CHECK(shell_dep_graph_parse_resolved(
                conditional_current, strlen(conditional_current), "/workspace",
                &limits, graph, resolve_comparison, &resolver,
                NULL) == SHELL_DEP_OK);
      CHECK(resolver.calls == 2);
      CHECK(shell_dep_graph_validate(graph).valid);
      CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
            (unresolved ? SHELL_CONDITIONAL_UNKNOWN
             : unequal  ? SHELL_CONDITIONAL_FALSE
                        : SHELL_CONDITIONAL_TRUE));
    }
  static const char *const mixed[] = {"[[ x == \"$right\" ]]",
                                      "[[ $left == \"x\" ]]"};
  for (unsigned i = 0; i < 2; ++i) {
    conditional_current = mixed[i];
    conditional_comparison_resolver_t resolver = {.values = {"1:x,"}};
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, resolve_comparison, &resolver,
              NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 1);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_TRUE);
  }
  static const char *const malformed[] = {"", "0:,1:x,", "1:x"};
  for (unsigned side = 0; side < 2; ++side)
    for (unsigned i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
      conditional_current = "[[ $left == \"$right\" ]]";
      conditional_comparison_resolver_t resolver = {.values = {"1:x,", "1:x,"}};
      resolver.values[side] = malformed[i];
      CHECK(shell_dep_graph_parse_resolved(
                conditional_current, strlen(conditional_current), "/workspace",
                &limits, graph, resolve_comparison, &resolver,
                NULL) == SHELL_DEP_EEXPAND);
      CHECK(!graph->node_count && !graph->edge_count);
    }

  conditional_parse("[[ <(printf x) == \"$(read -r -u63 value)\" ]]");
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
  conditional_parse("[[ x == \"$(cat)\" ]] <<<payload");
  bool read_document = false;
  for (unsigned e = 0; e < graph->edge_count; ++e) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    read_document |= edge->type == SHELL_EDGE_READ &&
                     graph->nodes[edge->from].type == SHELL_NODE_DOC &&
                     graph->nodes[edge->from].doc.kind == SHELL_DOC_HERESTRING;
  }
  CHECK(read_document);
  conditional_reject("[[ $(cat left-file) == \"$(cat right-file)\" ]] <\"\"");
  /* A producer's failed return status does not stop comparison expansion. */
  conditional_current = "[[ $(false) == \"$(cat right-file)\" ]]";
  conditional_comparison_resolver_t resolver = {.values = {"0:,", "1:x,"}};
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_comparison, &resolver,
            NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2);
  bool right_read = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    right_read |= graph->edges[e].type == SHELL_EDGE_READ;
  CHECK(right_read);

  for (unsigned truth = 0; truth < 2; ++truth) {
    conditional_parse(truth ? "[[ x == \"x\" ]] && cat reached"
                            : "[[ x != \"x\" ]] && cat reached");
    unsigned reads = 0;
    for (unsigned e = 0; e < graph->edge_count; ++e)
      reads += graph->edges[e].type == SHELL_EDGE_READ;
    CHECK((reads != 0) == (truth != 0));
  }
  conditional_current =
      "printf before; [[ $(printf left) == \"$(printf right)\"";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(conditional_draft->prefix_length == strlen("printf before;"));
  CHECK(conditional_draft->header_count == 4 &&
        conditional_draft->headers[1].conditional_operand_count == 2);
  CHECK(conditional_draft->headers[2].complete &&
        conditional_draft->headers[3].complete);
}

static const shell_source_header_t *conditional_retained_condition(void) {
  for (unsigned h = 0; h < conditional_draft->header_count; ++h)
    if (conditional_draft->headers[h].kind == SHELL_COMMAND_CONDITIONAL)
      return &conditional_draft->headers[h];
  CHECK(false);
  return NULL;
}

static void conditional_check_grouped_draft_summaries(void) {
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
            conditional_current = source;
            bool invalid = closed < groups && strchr(tails[tail], ']');
            bool complete = !invalid && !strcmp(tails[tail], " ]]");
            CHECK(shell_parse_draft(source, strlen(source), NULL,
                                    conditional_draft) ==
                  (invalid    ? SHELL_SOURCE_INVALID
                   : complete ? SHELL_SOURCE_COMPLETE
                              : SHELL_SOURCE_INCOMPLETE));
            if (invalid) {
              CHECK(!conditional_draft->prefix_length &&
                    !conditional_draft->prefix.count);
              continue;
            }
            const shell_source_header_t *header =
                conditional_retained_condition();
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
            CHECK(conditional_draft->header_count == 2 + cases[c].children);
            if (cases[c].children)
              CHECK(conditional_draft->headers[2].complete);
            if (!complete) {
              CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
              CHECK(conditional_draft->prefix_length ==
                        strlen("printf before;") &&
                    conditional_draft->prefix.count == 1);
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
    conditional_current = unfinished_words[c].source;
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL,
                            conditional_draft) == SHELL_SOURCE_INCOMPLETE);
    const shell_source_header_t *header = conditional_retained_condition();
    CHECK(header->conditional_predicate == unfinished_words[c].predicate);
    CHECK(header->conditional_negated == unfinished_words[c].negated);
    unsigned count = unfinished_words[c].operands[1] ? 2 : 1;
    CHECK(header->conditional_operand_count == count);
    for (unsigned i = 0; i < count; ++i) {
      shell_source_span_t span = header->conditional_operands[i];
      const char *word = unfinished_words[c].operands[i];
      CHECK(span.length == strlen(word));
      CHECK(!memcmp(conditional_current + span.start, word, span.length));
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
    conditional_current = compounds[i];
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL,
                            conditional_draft) == SHELL_SOURCE_INCOMPLETE);
    const shell_source_header_t *header = conditional_retained_condition();
    CHECK(header->conditional_predicate == SHELL_CONDITIONAL_PREDICATE_NONE);
    CHECK(!header->conditional_operand_count && !header->conditional_negated);
    CHECK(conditional_draft->header_count ==
          (strstr(conditional_current, "$(") ? 2u : 1u));
  }
}

static void conditional_check_mixed_literal_comparisons(void) {
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
            conditional_current = source;
            conditional_comparison_resolver_t resolver = {
                .values = {left, right},
                .words = {"\"$left\"", cases[i].word},
                .unresolved = {unresolved & 1, unresolved & 2}};
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 2);
            const shell_dep_cmd_t *condition =
                &graph->nodes[conditional_condition_node()].cmd;
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
  conditional_current =
      "[[ \"$(cat <left-file)\" == pre\"$(cat <right-file)\"post ]]";
  conditional_comparison_resolver_t resolver = {
      .values = {"8:preapost,", "8:preapost,"},
      .words = {"\"$(cat <left-file)\"", "pre\"$(cat <right-file)\"post"}};
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve_comparison, &resolver,
            NULL) == SHELL_DEP_OK);
  CHECK(resolver.calls == 2);
  conditional_file_node("left-file");
  conditional_file_node("right-file");

  /* Left process allocation precedes the right operand's read from its fd. */
  conditional_parse("[[ <(printf x) == pre\"$(read -r -u63 value)\"post ]]");
  bool read_process = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    read_process |= graph->edges[e].type == SHELL_EDGE_SUBST &&
                    graph->edges[e].source_fd == 1 &&
                    graph->edges[e].target_fd == 63;
  CHECK(read_process);

  for (unsigned mode = 0; mode < 3; ++mode) {
    conditional_current = "[[ \"$left\" == pre\"$right\".txt ]] && cat reached";
    resolver = (conditional_comparison_resolver_t){
        .values = {mode == 0 ? "8:prex.txt," : "5:other,", "8:prex.txt,"},
        .unresolved = {mode == 2, false}};
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, resolve_comparison, &resolver,
              NULL) == SHELL_DEP_OK);
    bool read = false;
    for (unsigned e = 0; e < graph->edge_count; ++e)
      read |= graph->edges[e].type == SHELL_EDGE_READ;
    CHECK(read == (mode != 1));
  }
}

static void conditional_check_tilde_comparisons(void) {
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
    conditional_parse(source);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          (cases[i].dynamic ? SHELL_CONDITIONAL_UNKNOWN
                            : SHELL_CONDITIONAL_TRUE));
    for (unsigned unresolved = 0; unresolved < 2; ++unresolved) {
      conditional_comparison_resolver_t resolver = {.values = {record},
                                                    .unresolved = {unresolved}};
      CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/workspace",
                                           &limits, graph, resolve_comparison,
                                           &resolver, NULL) == SHELL_DEP_OK);
      CHECK(resolver.calls == cases[i].dynamic);
      CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
          conditional_current = source;
          conditional_comparison_resolver_t resolver = {
              .values = {"16:name=/model-home,"}, .unresolved = {mode == 1}};
          if (mode == 0)
            conditional_parse(source);
          else {
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 1);
          }
          bool truth = (op == 2) != (negate != 0);
          CHECK(graph->nodes[conditional_condition_node()]
                    .cmd.conditional_truth ==
                (mode != 2 ? SHELL_CONDITIONAL_UNKNOWN
                 : truth   ? SHELL_CONDITIONAL_TRUE
                           : SHELL_CONDITIONAL_FALSE));
          bool reads = false;
          for (unsigned e = 0; e < graph->edge_count; ++e)
            reads |= graph->edges[e].type == SHELL_EDGE_READ;
          CHECK(reads == (mode != 2 || truth != (failure != 0)));
        }
}

static void conditional_check_patterns(void) {
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
    conditional_parse(forms[i].source);
    CHECK(
        graph->nodes[conditional_condition_node()].cmd.conditional_predicate ==
        forms[i].predicate);
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(conditional_draft->headers[0].conditional_predicate ==
          forms[i].predicate);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(conditional_current,
                                 strlen(conditional_current), NULL,
                                 &processed) == SHELL_PROCESS_OK);
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
            conditional_current = source;
            conditional_comparison_resolver_t resolver = {
                .values = {matches ? "8:file.txt," : "6:xfile*,"},
                .unresolved = {unresolved}};
            CHECK(shell_dep_graph_parse_resolved(
                      source, strlen(source), "/workspace", &limits, graph,
                      resolve_comparison, &resolver, NULL) == SHELL_DEP_OK);
            CHECK(resolver.calls == 1);
            bool truth = (matches != (op == 2)) != (negate != 0);
            CHECK(graph->nodes[conditional_condition_node()]
                      .cmd.conditional_truth ==
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
  conditional_current = large_pattern;
  CHECK(shell_dep_graph_parse(conditional_current, strlen(conditional_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EWORKSPACE);
  CHECK(!graph->node_count && !graph->edge_count);
  limits.workspace_size = previous_size;
  conditional_parse(large_pattern);
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_FALSE);
}

static void conditional_check_token_prefixes(void) {
  for (size_t i = 0; i < sizeof(conditional_prefix_cases) /
                             sizeof(conditional_prefix_cases[0]);
       ++i) {
    const char *tail = conditional_prefix_cases[i].source;
    conditional_current = tail;
    CHECK(shell_parse_draft(tail, strlen(tail), NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(!conditional_draft->prefix_length &&
          !conditional_draft->prefix.count);
    const shell_source_header_t *header = conditional_retained_condition();
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
    conditional_current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(conditional_draft->prefix_length == strlen("printf before;") &&
          conditional_draft->prefix.count == 1);
    CHECK(!conditional_retained_condition()->complete);

    snprintf(source, sizeof(source), "printf before; { %s", tail);
    conditional_current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->prefix_length == strlen("printf before;") &&
          conditional_draft->prefix.count == 1);
    CHECK(!conditional_retained_condition()->complete);

    /* A still-open child permits extension, while its outer source owns the
     * missing-substitution diagnostic. A closed child commits the same bytes.
     */
    snprintf(source, sizeof(source), "printf before; printf $(%s", tail);
    conditional_current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_SUBSTITUTION ||
          conditional_draft->need == SHELL_SOURCE_NEEDS_ESCAPE);
    CHECK(conditional_draft->prefix_length == strlen("printf before;"));
    CHECK(!conditional_retained_condition()->complete);
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
        conditional_current = source;
        CHECK(shell_parse_draft(source, strlen(source), NULL,
                                conditional_draft) == SHELL_SOURCE_INVALID);
        CHECK(!conditional_draft->prefix_length &&
              !conditional_draft->prefix.count);
      }
    snprintf(source, sizeof(source), "%s%s", tail,
             conditional_prefix_cases[i].completion);
    conditional_current = source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(conditional_retained_condition()->complete);
    conditional_parse(source);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          (shell_conditional_truth_t)conditional_prefix_cases[i].truth);
  }
}

static void conditional_check_binary_and_compound_conditions(void) {
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
      conditional_parse(source);
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
    conditional_parse(cases[i].source);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          cases[i].truth);
    if (strstr(cases[i].source, "skipped"))
      for (unsigned e = 0; e < graph->edge_count; ++e)
        CHECK(graph->edges[e].type != SHELL_EDGE_SUBST);
  }
  conditional_parse("echo \"$( [[ first -ef second || -r third ]] )\"");
  conditional_parse("test left \"$operator\" right");
  unsigned comparisons_count = 0;
  for (unsigned i = 0; i < graph->node_count; ++i)
    if (graph->nodes[i].type == SHELL_NODE_FILE_COMPARISON) {
      ++comparisons_count;
      CHECK(graph->nodes[i].file_comparison.predicates == 7);
    }
  CHECK(comparisons_count == 1);
  conditional_current = "[[ -n \"$left\" && -n \"$right";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(conditional_draft->headers[0].conditional_predicate ==
            SHELL_CONDITIONAL_PREDICATE_NONE &&
        conditional_draft->headers[0].conditional_operand_count == 0);
  static const char *const join_prefixes[] = {
      "[[ x &",     "[[ -n x |",   "[[ (x) &", "[[ ( -n x && x ) |",
      "[[ (x) &\\", "[[ (x) |\\\n"};
  for (unsigned i = 0; i < sizeof(join_prefixes) / sizeof(*join_prefixes);
       ++i) {
    char source[128];
    snprintf(source, sizeof(source), "printf before; %s", join_prefixes[i]);
    conditional_current = source;
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL,
                            conditional_draft) == SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(conditional_draft->prefix_length == strlen("printf before;"));
    CHECK(conditional_draft->prefix.count == 1);
  }
  conditional_current = "[[ \"$left\" -ef \"$right\" ]]";
  conditional_resolved_value = "0:,";
  conditional_resolved_length = 0;
  calls = 0;
  uint8_t empty_unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, empty_unresolved) == SHELL_DEP_OK);
  CHECK(calls == 2 &&
        graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
            SHELL_CONDITIONAL_FALSE);
  CHECK(!empty_unresolved[conditional_condition_node()]);
  CHECK(!graph->nodes[conditional_condition_node()].cmd.conditional_unresolved);
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
    shell_dep_file_identity_t file_identity = {0};

    CHECK(!shell_dep_doc_file_identity_write(graph, doc, identity,
                                             sizeof(identity), &file_identity));
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
  conditional_current = "[[ first -nt second ]]";
  CHECK(shell_dep_graph_parse(conditional_current, strlen(conditional_current),
                              "/workspace", &small, graph) == SHELL_DEP_ETRUNC);
  CHECK(shell_dep_graph_validate(graph).valid);
  char deep[512] = "[[ ";
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES / 2; ++i)
    strcat(deep, "x && ");
  strcat(deep, "x ]]");
  conditional_current = deep;
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_TRUNCATED);
}

/* A syntax resource stop has no qualified prefix, even when complete commands
 * precede it. Check each public consumer rather than only the private frame. */
static void conditional_check_syntax_resource_stop(const char *source) {
  conditional_current = source;
  size_t length = strlen(source);
  CHECK(shell_parse_draft(source, length, NULL, conditional_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!conditional_draft->prefix_length && !conditional_draft->prefix.count);
  for (unsigned i = 0; i < conditional_draft->header_count; ++i)
    CHECK(!conditional_draft->headers[i].complete);
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

static void conditional_check_syntax_resource_outcomes(void) {
  char condition[2048] = "[[ ! ";
  for (unsigned i = 0; i < 47; ++i)
    strcat(condition, "x && ");
  strcat(condition, "x ]]");
  /* 48 primaries + 47 joins + one NOT fills all 96 nodes. */
  CHECK(shell_conditional_parse(condition, strlen(condition), 0).count == 96);
  conditional_parse(condition);
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
    conditional_check_syntax_resource_stop(source);
  }
  strcpy(condition, "[[ ");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES - 1; ++i)
    strcat(condition, "(");
  strcat(condition, "x");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES - 1; ++i)
    strcat(condition, ")");
  strcat(condition, " ]]");
  conditional_parse(condition);
  char deep[4096];
  strcpy(deep, "[[ ");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES; ++i)
    strcat(deep, "(");
  strcat(deep, "x");
  for (unsigned i = 0; i < SHELL_CONDITIONAL_MAX_NODES; ++i)
    strcat(deep, ")");
  strcat(deep, " ]]");
  conditional_check_syntax_resource_stop(deep);
  /* Shared list-group capacity is a resource stop too. */
  strcpy(deep, "");
  for (unsigned i = 0; i <= SHELL_MAX_GROUPS; ++i)
    strcat(deep, "{ ");
  strcat(deep, "printf x;");
  for (unsigned i = 0; i <= SHELL_MAX_GROUPS; ++i)
    strcat(deep, " };");
  conditional_check_syntax_resource_stop(deep);
  /* Syntax errors still precede range-output limits when validation finishes.
   */
  shell_limits_t small = SHELL_LIMITS_DEFAULT;
  small.max_subcommands = 1;
  small.strict_mode = true;
  conditional_current = "printf first; printf second; [[ x && ]]";
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(conditional_current, strlen(conditional_current),
                         &small, &fast) == SHELL_EPARSE);
  CHECK(fast.status == SHELL_STATUS_ERROR);
}

static int run_conditional(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 8192,
                                      1, true, 0));
  limits = fixture.limits;
  graph = fixture.graph[0];
  conditional_draft = malloc(sizeof(*conditional_draft));
  CHECK(conditional_draft);
  /* Conformance probe: both operands are dynamic; arguments supply their
   * complete final strings, not individual expansion-fragment values. */
  if (argc == 5 && !strcmp(argv[1], "--resolved")) {
    conditional_current = argv[2];
    char records[2][256];
    for (unsigned i = 0; i < 2; ++i) {
      int used = snprintf(records[i], sizeof(records[i]), "%zu:%s,",
                          strlen(argv[3 + i]), argv[3 + i]);
      CHECK(used >= 0 && (size_t)used < sizeof(records[i]));
    }
    conditional_comparison_resolver_t resolver = {
        .values = {records[0], records[1]}};
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, resolve_comparison, &resolver,
              NULL) == SHELL_DEP_OK);
    CHECK(resolver.calls == 2);
    printf("%d\n",
           graph->nodes[conditional_condition_node()].cmd.conditional_truth);
    goto done;
  }
  if (argc == 3) {
    conditional_current = argv[2];
    if (!strcmp(argv[1], "--status"))
      printf("%d\n",
             shell_parse_draft(conditional_current, strlen(conditional_current),
                               NULL, conditional_draft));
    else {
      conditional_parse(conditional_current);
      if (!strcmp(argv[1], "--dump"))
        shell_dep_graph_dump(graph, stdout);
      else
        printf(
            "%d\n",
            graph->nodes[conditional_condition_node()].cmd.conditional_truth);
    }
    goto done;
  }
  conditional_check_conditional_observation_order();
  conditional_check_body_setup();
  conditional_check_binary_and_compound_conditions();
  conditional_check_syntax_resource_outcomes();
  conditional_check_file_predicates();
  conditional_check_file_predicate_resolution();
  conditional_check_file_predicate_nul_argument();
  conditional_check_file_predicate_unresolved_paths();
  conditional_check_comparison_operand_contexts();
  conditional_check_scalar_arithmetic_boundary();
  conditional_check_arithmetic_mutation_rejection();
  conditional_check_numeric_conditional_contract();
  conditional_check_builtin_argument_read_phase();
  conditional_check_builtin_integer_comparisons();
  conditional_check_nested_arithmetic_coverage();
  conditional_check_conditional_coverage_barrier();
  conditional_check_parameter_operand_dependencies();
  conditional_check_file_comparison_continuations();
  conditional_check_test_grammar_refinement();
  conditional_check_expansion_regions();
  conditional_check_partial_condition_regions();
  conditional_check_comparisons();
  conditional_check_grouped_draft_summaries();
  conditional_check_mixed_literal_comparisons();
  conditional_check_tilde_comparisons();
  conditional_check_patterns();
  conditional_check_token_prefixes();
  for (size_t i = 0;
       i < sizeof(conditional_cases) / sizeof(conditional_cases[0]); ++i) {
    conditional_current = conditional_cases[i].source;
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(conditional_draft->headers[0].kind == SHELL_COMMAND_CONDITIONAL);
    CHECK(conditional_draft->headers[0].word_count == 0 &&
          conditional_draft->headers[0].compound);
    CHECK(conditional_draft->headers[0].conditional_operands[0].length > 0);
    shell_limits_t syntax_limits = SHELL_LIMITS_DEFAULT;
    syntax_limits.strict_mode = true;
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(conditional_current, strlen(conditional_current),
                           &syntax_limits, &fast) == SHELL_OK);
    CHECK(fast.count == 1 && fast.cmds[0].kind == SHELL_COMMAND_CONDITIONAL);
    if (conditional_cases[i].truth != 0) {
      CHECK(conditional_draft->header_count == 1);
      CHECK(!(fast.cmds[0].features &
              (SHELL_FEAT_VARS | SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL |
               SHELL_FEAT_PROCESS_SUB)));
    }
    conditional_parse(conditional_current);
    unsigned owner = conditional_condition_node();
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
    CHECK(shell_tokenize_commands(conditional_current,
                                  strlen(conditional_current), &commands,
                                  &command_count) == SHELL_TOKENIZE_OK);
    CHECK(command_count == 1 && commands[0].has_conditionals &&
          commands[0].has_globs == pattern);
    /* These sentinel spellings occur in the owner's own operands. Variables
     * inside executable children are covered by the mixed-word tests above. */
    if (strstr(conditional_current, "$value"))
      CHECK(commands[0].has_variables);
    if (strstr(conditional_current, "$(printf"))
      CHECK(commands[0].has_subshells);
    if (strstr(conditional_current, "$((1))"))
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
    CHECK(shell_process_commands(conditional_current,
                                 strlen(conditional_current), NULL,
                                 &processed) == SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1 &&
          processed.commands[0].kind == SHELL_COMMAND_CONDITIONAL);
    CHECK(!processed.commands[0].command_token_count);
    CHECK(processed.commands[0].conditional_operand_lengths[0] > 0);
    shell_processed_commands_free(&processed);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(conditional_current,
                                       strlen(conditional_current),
                                       &abstract) == SHELL_ABSTRACT_OK);
    CHECK(abstract->element_count == 1 &&
          abstract->elements[0]->type == SHELL_ABSTRACT_CT);
    CHECK(abstract->has_globs == pattern);
    shell_abstract_command_free(abstract);
    shell_netstring_buffer_t raw = {0}, typed = {0};
    size_t stages;
    CHECK(shell_build_anomaly_netseqs_buffer(
              conditional_current, strlen(conditional_current), NULL, &raw,
              &typed, &stages) == SHELL_PROCESS_OK);
    CHECK(stages > 0 && typed.length >= 11 &&
          !memcmp(typed.data + typed.length - 11, "8:0:,2:CT,,", 11));
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
  }
  conditional_current = "printf '%s' \"$([[ -n x # $(|)\n]])\"";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
  CHECK(conditional_draft->header_count == 2);
  conditional_parse(conditional_current);
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_TRUE);
  conditional_current = "[[ # ' comment\n-n $(printf value) # $(|)\n]]";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_COMPLETE);
  CHECK(conditional_draft->header_count == 2);
  conditional_parse(conditional_current);
  CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
        SHELL_CONDITIONAL_UNKNOWN);
  bool real_substitution = false;
  for (unsigned e = 0; e < graph->edge_count; ++e)
    real_substitution |= graph->edges[e].type == SHELL_EDGE_SUBST;
  CHECK(real_substitution);
  for (size_t i = 0;
       i < sizeof(conditional_invalid) / sizeof(conditional_invalid[0]); ++i) {
    conditional_current = conditional_invalid[i];
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL, conditional_draft) == SHELL_SOURCE_INVALID);
    CHECK(!conditional_draft->prefix.count &&
          !conditional_draft->prefix_length);
    CHECK(shell_dep_graph_parse(conditional_current,
                                strlen(conditional_current), ".", &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(!graph->node_count && !graph->edge_count && !graph->cwd_buf.len);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(conditional_current,
                                 strlen(conditional_current), NULL,
                                 &processed) == SHELL_PROCESS_EPARSE);
    CHECK(!processed.commands && !processed.command_count);
    shell_processed_commands_free(&processed);
    char prefixed[256];
    CHECK(strlen(conditional_current) + sizeof("printf before; ") <=
          sizeof(prefixed));
    strcpy(prefixed, "printf before; ");
    strcat(prefixed, conditional_current);
    CHECK(shell_parse_draft(prefixed, strlen(prefixed), NULL,
                            conditional_draft) == SHELL_SOURCE_INVALID);
    CHECK(!conditional_draft->prefix.count &&
          !conditional_draft->prefix_length);
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
    conditional_current = repairable[i];
    strcpy(source, "printf before; ");
    strcat(source, conditional_current);
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(conditional_draft->prefix_length == strlen("printf before;"));
    CHECK(conditional_draft->prefix.count == 1);
  }
  for (size_t i = 0;
       i < sizeof(conditional_unsupported) / sizeof(conditional_unsupported[0]);
       ++i) {
    conditional_current = conditional_unsupported[i];
    CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                            NULL,
                            conditional_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(shell_dep_graph_parse(conditional_current,
                                strlen(conditional_current), ".", &limits,
                                graph) == SHELL_DEP_EPARSE);
    CHECK(!graph->node_count && !graph->edge_count);
  }
  conditional_current = "printf before; [[ -n \"$(printf 日本";
  CHECK(shell_parse_draft(conditional_current, strlen(conditional_current),
                          NULL, conditional_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
  CHECK(conditional_draft->prefix_length == strlen("printf before;"));
  conditional_parse("[[ '' ]] && cat unreachable; cat reachable");
  unsigned reads = 0;
  for (unsigned i = 0; i < graph->edge_count; ++i)
    reads += graph->edges[i].type == SHELL_EDGE_READ;
  CHECK(reads == 1);
  conditional_current = "[[ -z $value ]]";
  conditional_resolved_value = "0:,";
  calls = 0;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_OK);
  CHECK(calls == 1 &&
        graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
            SHELL_CONDITIONAL_TRUE);
  conditional_resolved_value = "1:x,";
  calls = 0;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_OK);
  CHECK(calls == 1 &&
        graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
            SHELL_CONDITIONAL_FALSE);
  /* Predicate truth controls continuation even when the output producer's
   * status has the opposite truth value. */
  for (unsigned nonempty = 0; nonempty < 2; ++nonempty) {
    conditional_current =
        nonempty ? "[[ -n $(false)x ]] && printf ok >reached"
                 : "[[ -n $(printf '') ]] && printf wrong >reached";
    conditional_resolved_value = nonempty ? "1:x," : "0:,";
    calls = 0;
    CHECK(shell_dep_graph_parse_resolved(
              conditional_current, strlen(conditional_current), "/workspace",
              &limits, graph, resolve, NULL, NULL) == SHELL_DEP_OK);
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
  conditional_current = "[[ -z $value ]]";
  conditional_resolved_value = "";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_EEXPAND);
  CHECK(!graph->node_count && !graph->edge_count);
  conditional_resolved_value = "0:,1:x,";
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_EEXPAND);
  conditional_resolved_value = "1:\0,";
  conditional_resolved_length = 4;
  CHECK(shell_dep_graph_parse_resolved(
            conditional_current, strlen(conditional_current), "/workspace",
            &limits, graph, resolve, NULL, NULL) == SHELL_DEP_EEXPAND);
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
    conditional_current = source;
    size_t fixed, tail;
    CHECK(shell_dep_workspace_size(NULL, &fixed));
    CHECK(shell_source_workspace_size(strlen(source), &tail));
    size_t previous_size = limits.workspace_size;
    limits.workspace_size = fixed + tail;
    shellsplit_test_source_scan_reset();
    conditional_parse(source);
    limits.workspace_size = previous_size;
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
    conditional_current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, strlen(source), NULL, conditional_draft) ==
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
    conditional_current = source;
    shellsplit_test_source_scan_reset();
    conditional_parse(source);
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
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
    conditional_current = source;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, end, NULL, conditional_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(conditional_draft->need == SHELL_SOURCE_NEEDS_CONDITIONAL);
    CHECK(conditional_retained_condition()->conditional_operand_count == 1);
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
    conditional_current = source;
    size_t fixed, tail;
    CHECK(shell_dep_workspace_size(NULL, &fixed));
    CHECK(shell_source_workspace_size(strlen(source), &tail));
    size_t previous_size = limits.workspace_size;
    limits.workspace_size = fixed + tail;
    shellsplit_test_source_scan_reset();
    conditional_parse(source);
    limits.workspace_size = previous_size;
    CHECK(graph->nodes[conditional_condition_node()].cmd.conditional_truth ==
          SHELL_CONDITIONAL_TRUE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_work || work <= previous_work * 3);
    previous_work = work;
  }
#endif
done:
  free(conditional_draft);
  shellsplit_graph_fixture_destroy(&fixture);
  return 0;
}
#undef CHECK

/* --- presence (from presence_test.c) --- */
static const char *presence_current;
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #test,           \
              presence_current);                                               \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static shell_dep_graph_t *graph;
static shell_dep_limits_t limits;

static shell_conditional_truth_t presence_truth(const char *source) {
  presence_current = source;
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

static shell_conditional_truth_t presence_test_truth(const char *source) {
  /* Graph spans and failure diagnostics borrow this source until the next
   * probe, including assertions made after this helper returns. */
  static char combined[4096];
  int n = snprintf(
      combined, sizeof(combined),
      "unset __shellclave_presence_probe; { %s; } && "
      "__shellclave_presence_probe=; [[ -v __shellclave_presence_probe ]]",
      source);
  CHECK(n >= 0 && (size_t)n < sizeof(combined));
  return presence_truth(combined);
}

static void presence_observe_token(const shell_token_t *token, void *context) {
  (void)token;
  (void)context;
}
static void presence_observe_read(const char *word, uint32_t fd, unsigned kind,
                                  const char *parameter, size_t length,
                                  bool identity, void *context) {
  (void)word;
  (void)fd;
  (void)kind;
  (void)parameter;
  (void)length;
  (void)identity;
  (void)context;
}
static void presence_observe_process(const char *word, size_t length,
                                     void *context) {
  (void)word;
  (void)length;
  (void)context;
}
typedef struct {
  unsigned queries, programs;
} presence_observed_test_t;
static void presence_observe_name(const char *name, size_t length,
                                  void *context) {
  CHECK(length == 6 && !memcmp(name, "CONFIG", 6));
  ++((presence_observed_test_t *)context)->queries;
}
static void presence_observe_test(const char *command,
                                  const shell_test_program_t *program,
                                  void *context) {
  CHECK(*command == '[' || !memcmp(command, "test", 4));
  CHECK(program && program->active);
  ++((presence_observed_test_t *)context)->programs;
}

static void presence_check_observation_roles(void) {
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
      {"command builtin test '(' -t -o ')' -o -v CONFIG", 0, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    presence_current = cases[i].source;
    size_t length = strlen(presence_current), bytes;
    CHECK(shell_source_workspace_size(length, &bytes));
    void *scratch = malloc(bytes);
    CHECK(scratch);
    for (unsigned observers = 0; observers < 4; ++observers) {
      presence_observed_test_t observed = {0};
      shell_source_operation_begin(presence_current, length);
      shell_source_workspace_scope_t previous = shell_source_workspace_begin(
          presence_current, length, scratch, bytes);
      CHECK(shell_tokenizer_inspect_semantics(
                presence_current, length, presence_observe_token,
                presence_observe_read, presence_observe_process,
                observers & 1 ? presence_observe_name : NULL,
                observers & 2 ? presence_observe_test : NULL,
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

static void presence_check_inspection_outcomes(void) {
  char source[1024] = "test x";
  for (unsigned i = 0; i < SHELL_DEP_MAX_TOKENS / 2; ++i)
    strcat(source, " -o x");
  strcat(source, "; test -v CONFIG");
  for (unsigned unsupported = 0; unsupported < 2; ++unsupported) {
    if (unsupported)
      strcat(source, "; test -v 'a[$(printf marker)]'");
    presence_current = source;
    size_t bytes, length = strlen(source);
    CHECK(shell_source_workspace_size(length, &bytes));
    void *scratch = malloc(bytes);
    CHECK(scratch);
    for (unsigned observers = 0; observers < 4; ++observers) {
      for (unsigned exhaust = 0; exhaust < 2; ++exhaust) {
        presence_observed_test_t observed = {0};
        shell_source_operation_begin(source, length);
        shell_source_workspace_scope_t previous =
            shell_source_workspace_begin(source, length, scratch, bytes);
        if (exhaust)
          CHECK(shell_source_scratch_take(bytes));
        shell_semantic_result_t result = shell_tokenizer_inspect_semantics(
            source, length, presence_observe_token, presence_observe_read,
            presence_observe_process,
            observers & 1 ? presence_observe_name : NULL,
            observers & 2 ? presence_observe_test : NULL, &observed);
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
  presence_current = "test -v CONFIG";
  size_t length = strlen(presence_current), bytes;
  CHECK(shell_source_workspace_size(length, &bytes));
  void *scratch = malloc(bytes);
  CHECK(scratch);
  for (unsigned observers = 1; observers < 4; ++observers) {
    presence_observed_test_t observed = {0};
    shell_source_operation_begin(presence_current, length);
    shell_source_workspace_scope_t previous =
        shell_source_workspace_begin(presence_current, length, scratch, bytes);
    CHECK(shell_source_scratch_take(bytes));
    CHECK(shell_tokenizer_inspect_semantics(
              presence_current, length, presence_observe_token,
              presence_observe_read, presence_observe_process,
              observers & 1 ? presence_observe_name : NULL,
              observers & 2 ? presence_observe_test : NULL,
              &observed) == SHELL_SEMANTIC_EWORKSPACE);
    CHECK(!observed.queries && !observed.programs);
    shell_source_workspace_end(previous);
    shell_source_operation_end();
  }
  free(scratch);
}

static void presence_check_observation_capacity(void) {
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
    presence_current = source;
    CHECK(shell_dep_graph_parse(source, used, "/workspace", &limits, graph) ==
          SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void presence_check_recursive_routes(void) {
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
    CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
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

static void presence_check_nonassignable_variables(void) {
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
      CHECK(presence_truth(source) == SHELL_CONDITIONAL_UNKNOWN);
      /* Unknown initial presence stays unknown. A previously observed absence
       * also survives the rejected write, so its failure route remains live. */
      used = snprintf(
          source, sizeof(source),
          "[[ ! -v %s ]] && { %s; [[ -v %s ]] || cat <important.txt; }; "
          "[[ -v UID ]]",
          names[n], write, names[n]);
      CHECK(used >= 0 && (size_t)used < sizeof(source));
      CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
      CHECK(has_file_read("important.txt"));
      if (n < 2) {
        used = snprintf(source, sizeof(source), "unset %s; %s; [[ -v %s ]]",
                        names[n], write, names[n]);
        CHECK(used >= 0 && (size_t)used < sizeof(source));
        CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
      }
    }
    char source[512];
    int used = snprintf(source, sizeof(source),
                        "[[ ! -v %s ]] && { %s=value test -v %s || "
                        "cat <important.txt; }; [[ -v UID ]]",
                        names[n], names[n], names[n]);
    CHECK(used >= 0 && (size_t)used < sizeof(source));
    CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt"));
    used = snprintf(source, sizeof(source),
                    "[[ ! -v %s ]] && { %s=value result=$( [[ -v %s ]] ) || "
                    "cat <important.txt; }; [[ -v UID ]]",
                    names[n], names[n], names[n]);
    CHECK(used >= 0 && (size_t)used < sizeof(source));
    CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt"));
  }
  CHECK(presence_truth("printf -v FUNCNAME %s value; [[ -v FUNCNAME ]] || "
                       "cat <important.txt") == SHELL_CONDITIONAL_UNKNOWN);
  CHECK(has_file_read("important.txt"));
  CHECK(presence_truth(
            "unset first IFS last; read first FUNCNAME IFS last <<<payload; "
            "[[ -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(
      presence_truth("unset first IFS last; read -n0 first FUNCNAME IFS last; "
                     "[[ -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
      SHELL_CONDITIONAL_TRUE);
  CHECK(
      presence_truth(
          "unset first IFS last; read -t0 first FUNCNAME IFS last <<<payload; "
          "[[ ! -v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]") ==
      SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth(
            "unset count; printf -v FUNCNAME '%n' count; [[ -v count ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth(
            "unset output; printf -v output '%n' FUNCNAME; [[ -v output ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("OPTARG=; getopts a FUNCNAME -a; [[ -v OPTIND ]]") ==
        SHELL_CONDITIONAL_TRUE);
  /* Option scanning remains abstract: its independent OPTARG update can
   * either clear or assign the previous value despite destination rejection. */
  CHECK(presence_truth("OPTARG=; getopts a FUNCNAME -a; [[ -v OPTARG ]]") ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(presence_truth("[[ ! -v FUNCNAME ]] && { (unset FUNCNAME); "
                       "read -n0 FUNCNAME; [[ -v FUNCNAME ]]; }") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(presence_truth("[[ ! -v FUNCNAME ]] && { result=$(unset FUNCNAME); "
                       "read -n0 FUNCNAME; [[ -v FUNCNAME ]]; }") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(presence_truth(
            "{ unset FUNCNAME; }; read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("unset FUNCNAME; unset FUNCNAME; "
                       "FUNCNAME=value result=$( [[ -v FUNCNAME ]] ); "
                       "[[ -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("unset FUNCNAME; FUNCNAME=value test -v FUNCNAME && "
                       "[[ ! -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("test -d /maybe && unset FUNCNAME; "
                       "read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
        SHELL_CONDITIONAL_UNKNOWN);
  CHECK(presence_truth(
            "unset BASH_SOURCE; read -n0 BASH_SOURCE; [[ -v BASH_SOURCE ]]") ==
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

static void presence_check_opaque_unsets(void) {
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
    CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
    CHECK(has_file_read("important.txt") == cases[i].reads);
  }
  /* An invalid read count is a reported read error: no dependency model. */
  presence_current = "CONFIG=; read -n-invalid CONFIG; [[ -v CONFIG ]]";
  CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
  /* A dynamic read target name may be invalid: no dependency model. */
  presence_current = "read -n0 -- \"$name\"; read -n0 FUNCNAME";
  CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
  CHECK(presence_truth(
            "unset -- \"$name\" FUNCNAME; printf -v FUNCNAME %s value; "
            "[[ -v FUNCNAME ]]") == SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth(
            "unset -- \"$name\" GROUPS; GROUPS=value; [[ -v GROUPS ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(
      presence_truth("unset \"$name\"; read -n0 FUNCNAME; [[ -v FUNCNAME ]]") ==
      SHELL_CONDITIONAL_UNKNOWN);
  CHECK(presence_truth("unset CONFIG; CONFIG=value unset \"$name\" CONFIG; "
                       "[[ -v CONFIG ]]") == SHELL_CONDITIONAL_FALSE);
}

static void presence_check_prepared_test_values(void) {
  static const char *const operands[] = {"-n", "\"$VALUE\"", "-a", "'('",
                                         "''", "')'",        "]"};
  static const char *const values[] = {NULL, "", "x"};
  presence_current = "prepared parenthesized test values";
  for (unsigned bracket = 0; bracket < 2; ++bracket) {
    for (unsigned value = 0; value < 3; ++value) {
      shell_source_operation_begin(presence_current, strlen(presence_current));
      char scratch[4096];
      shell_source_workspace_scope_t previous = shell_source_workspace_begin(
          presence_current, strlen(presence_current), scratch, sizeof(scratch));
      shell_test_value_t words[7];
      size_t count = bracket ? 7 : 6;
      for (size_t word = 0; word < count; ++word)
        CHECK(shell_test_prepare_value(operands[word], strlen(operands[word]),
                                       &words[word]));
      shell_test_program_t program;
      CHECK(shell_test_compile(words, count, bracket, &program));
      /* Captured values can change operator roles as well as string truth.
       * Refresh in reserved storage, preserving global counted dispatch. */
      if (values[value]) {
        shell_test_set_value(&words[1], values[value], strlen(values[value]));
        CHECK(shell_test_refresh(&program));
      }
      CHECK(shell_test_evaluate(&program, unexpected_test_lookup, &program) ==
            (value == 0
                 ? SHELL_TEST_FALSE | SHELL_TEST_TRUE | SHELL_TEST_ERROR_RESULT
             : value == 1 ? SHELL_TEST_FALSE
                          : SHELL_TEST_TRUE));
      shell_source_workspace_end(previous);
      shell_source_operation_end();
    }
  }
}

typedef struct {
  const shell_test_value_t *words;
  unsigned masks[SHELL_DEP_MAX_TOKENS];
} presence_projected_files_t;

static SHELL_NONNULL(1, 3) void capture_projected_file(
    const shell_test_value_t *word, unsigned mask, void *context) {
  presence_projected_files_t *files = context;
  files->masks[word - files->words] |= mask;
}

static SHELL_NONNULL(1, 3) unsigned unknown_test_lookup(const char *name,
                                                        size_t length,
                                                        void *context) {
  (void)name;
  (void)length;
  (void)context;
  return SHELL_TEST_FALSE | SHELL_TEST_TRUE;
}

static void presence_check_projected_test_alternatives(void) {
  static const struct {
    unsigned count;
    const char *words[12]; /* NULL selects the one unresolved operator. */
  } cases[] = {
      {2, {NULL, "target"}},
      {3, {"!", NULL, "target"}},
      {4, {"(", NULL, "target", ")"}},
      {4, {"x", NULL, "-e", "target"}},
      {5, {"-t", NULL, "-o", "-f", "target"}},
      {6, {"-e", NULL, "-e", "-a", "-f", "target"}},
      {6, {"-n", NULL, "-a", "(", "''", ")"}},
      {7, {"(", NULL, "target", ")", "-a", "-e", "other"}},
      {8, {"(", "-e", NULL, "-e", "-a", "-f", "target", ")"}},
      {6, {"-e", NULL, "x", "-a", "-e", "="}},
      {6, {"-e", NULL, "-e", "-o", "!", "-e"}},
      {10, {"-e", NULL, "x", "-a", "(", "x", "-a", "-e", "=", ")"}},
      {10, {"-e", NULL, "x", "-a", "(", "x", "-o", "!", "-e", ")"}},
      {12, {"-e", NULL, "x", "-a", "(", "x", "-a", "x", "-a", "-e", "=", ")"}},
      {12, {"-e", NULL, "x", "-a", "(", "x", "-a", "x", "-o", "!", "-e", ")"}},
  };
  static const char *const values[] = {"",   "x",  "0",  "1",  "!",  "(",  ")",
                                       "=",  "!=", "-a", "-o", "-n", "-z", "-e",
                                       "-f", "-d", "-h", "-L", "-v", "-t"};
  static const char *const vocabulary[] = {
      "x", "-e", "-f", "-n", "-t", "(", ")", "!", "-a", "-o", "=", "target"};
  uint32_t generator = UINT32_C(0x94138427);
  unsigned named_cases = sizeof(cases) / sizeof(*cases);
  /* Exercise interactions of grouping/precedence with one unknown slot.
   * Concrete prepared programs are the differential oracle for the projected
   * grammar's status and operand coverage, independently of runtime strings. */
  for (unsigned c = 0; c < named_cases + 128; ++c) {
    const char *generated[8];
    unsigned word_count = c < named_cases ? cases[c].count : 5 + c % 4;
    const char *const *words_source =
        c < named_cases ? cases[c].words : generated;
    if (c >= named_cases) {
      for (unsigned i = 0; i < word_count; ++i) {
        generator ^= generator << 13;
        generator ^= generator >> 17;
        generator ^= generator << 5;
        generated[i] =
            vocabulary[generator % (sizeof(vocabulary) / sizeof(*vocabulary))];
      }
      generated[c % word_count] = NULL;
    }
    for (unsigned bracket = 0; bracket < 2; ++bracket)
      for (unsigned v = 0; v < sizeof(values) / sizeof(*values); ++v) {
        presence_current = "projected test grammar alternatives";
        shell_source_operation_begin(presence_current,
                                     strlen(presence_current));
        unsigned char scratch[32768];
        shell_source_workspace_scope_t previous = shell_source_workspace_begin(
            presence_current, strlen(presence_current), scratch,
            sizeof(scratch));
        shell_test_value_t abstract_words[13], concrete_words[13];
        unsigned count = word_count + bracket;
        for (unsigned i = 0; i < count; ++i) {
          const char *source = i == word_count ? "]" : words_source[i];
          bool dynamic = source == NULL;
          if (dynamic)
            source = "\"$op\"";
          CHECK(shell_test_prepare_value(source, strlen(source),
                                         &abstract_words[i]));
          concrete_words[i] = abstract_words[i];
          if (dynamic)
            shell_test_set_value(&concrete_words[i], values[v],
                                 strlen(values[v]));
        }
        shell_test_program_t abstract, concrete;
        CHECK(shell_test_compile(abstract_words, count, bracket, &abstract));
        CHECK(shell_test_compile(concrete_words, count, bracket, &concrete));
        unsigned result =
            shell_test_evaluate(&concrete, unknown_test_lookup, &concrete);
        if (result & (SHELL_TEST_FALSE | SHELL_TEST_TRUE)) {
          unsigned projected =
              shell_test_evaluate(&abstract, unknown_test_lookup, &abstract);
          if ((result & projected) != result)
            fprintf(stderr,
                    "case %u bracket %u value '%s': actual %#x projected %#x\n",
                    c, bracket, values[v], result, projected);
          CHECK((result & projected) == result);
          presence_projected_files_t a = {.words = abstract_words},
                                     b = {.words = concrete_words};
          shell_test_observe_files(&abstract, capture_projected_file, &a);
          shell_test_observe_files(&concrete, capture_projected_file, &b);
          for (unsigned i = 0; i < count; ++i) {
            if ((a.masks[i] & b.masks[i]) != b.masks[i])
              fprintf(stderr,
                      "case %u bracket %u value '%s' word %u: actual %#x "
                      "projected %#x\n",
                      c, bracket, values[v], i, b.masks[i], a.masks[i]);
            CHECK((a.masks[i] & b.masks[i]) == b.masks[i]);
          }
        }
        /* Refresh the same canonical program after capturing the unknown
         * value. A prior projection must not leave a false error proof. */
        for (unsigned i = 0; i < count; ++i)
          if (!abstract_words[i].known)
            shell_test_set_value(&abstract_words[i], values[v],
                                 strlen(values[v]));
        CHECK(shell_test_refresh(&abstract));
        CHECK(shell_test_evaluate(&abstract, unknown_test_lookup, &abstract) ==
              result);
        presence_projected_files_t refreshed = {.words = abstract_words},
                                   exact = {.words = concrete_words};
        shell_test_observe_files(&abstract, capture_projected_file, &refreshed);
        shell_test_observe_files(&concrete, capture_projected_file, &exact);
        for (unsigned i = 0; i < count; ++i) {
          if ((result & (SHELL_TEST_FALSE | SHELL_TEST_TRUE)) &&
              refreshed.masks[i] != exact.masks[i])
            fprintf(
                stderr,
                "refresh case %u bracket %u value '%s' word %u: %#x vs %#x\n",
                c, bracket, values[v], i, refreshed.masks[i], exact.masks[i]);
          if (result & (SHELL_TEST_FALSE | SHELL_TEST_TRUE))
            CHECK(refreshed.masks[i] == exact.masks[i]);
        }
        shell_source_workspace_end(previous);
        shell_source_operation_end();
      }
  }
  presence_current = "bounded test projection scratch exhaustion";
  shell_source_operation_begin(presence_current, strlen(presence_current));
  unsigned char scratch[512];
  shell_source_workspace_scope_t previous = shell_source_workspace_begin(
      presence_current, strlen(presence_current), scratch, sizeof(scratch));
  CHECK(shell_source_scratch_take(384) != NULL);
  static const char *const source[] = {"-e", "\"$op\"", "-e",
                                       "-a", "-f",      "target"};
  shell_test_value_t words[6];
  for (unsigned i = 0; i < 6; ++i)
    CHECK(shell_test_prepare_value(source[i], strlen(source[i]), &words[i]));
  shell_test_program_t program;
  CHECK(!shell_test_compile(words, 6, false, &program));
  CHECK(shell_source_scratch_exhausted());
  shell_source_workspace_end(previous);
  shell_source_operation_end();
}

static void presence_check_parenthesized_tests(void) {
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
      CHECK(presence_test_truth(command) == (cases[i].succeeds
                                                 ? SHELL_CONDITIONAL_TRUE
                                                 : SHELL_CONDITIONAL_FALSE));
      for (unsigned negated = 0; negated < 2; ++negated) {
        for (unsigned on_failure = 0; on_failure < 2; ++on_failure) {
          char source[768];
          n = snprintf(source, sizeof(source),
                       "%s%s %s cat <important.txt; [[ -v UID ]]",
                       negated ? "! " : "", command, on_failure ? "||" : "&&");
          CHECK(n >= 0 && (size_t)n < sizeof(source));
          CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
          bool succeeds = cases[i].succeeds != (bool)negated;
          CHECK(has_file_read("important.txt") ==
                (on_failure ? !succeeds : succeeds));
        }
      }
    }
  }
  static const char source[] =
      "test -n \"$VALUE\" -a '(' '' ')' && cat <important.txt; [[ -v UID ]]";
  CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
  CHECK(has_file_read("important.txt"));
  presence_check_prepared_test_values();
  presence_check_projected_test_alternatives();
}

static void presence_check_chained_group_progress(void) {
  static const char *const group[] = {"(", "x", "-a", "-e", "=", ")", "-a"};
  for (unsigned groups = 1; groups <= 6; ++groups)
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char source[1024];
      size_t used = (size_t)snprintf(source, sizeof(source), "%s ",
                                     bracket ? "[" : "test");
      for (unsigned i = 0; i < groups; ++i)
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "'(' x -a -e = ')' -a ");
      snprintf(source + used, sizeof(source) - used, "-e tail%s",
               bracket ? " ]" : "");
      CHECK(presence_test_truth(source) == SHELL_CONDITIONAL_FALSE);

      presence_current = "chained group compilation and refresh";
      shell_source_operation_begin(presence_current, strlen(presence_current));
      unsigned char scratch[32768];
      shell_source_workspace_scope_t previous = shell_source_workspace_begin(
          presence_current, strlen(presence_current), scratch, sizeof(scratch));
      shell_test_value_t words[SHELL_DEP_MAX_TOKENS];
      unsigned count = groups * 7 + 2 + bracket;
      unsigned dynamic = (groups - 1) * 7 + 4;
      for (unsigned i = 0; i < count; ++i) {
        const char *word = i < groups * 7        ? group[i % 7]
                           : i == groups * 7     ? "-e"
                           : i == groups * 7 + 1 ? "tail"
                                                 : "]";
        CHECK(shell_test_prepare_value(word, strlen(word), &words[i]));
      }
      shell_test_program_t exact;
      CHECK(shell_test_compile(words, count, bracket, &exact));
      CHECK(exact.count <= count * 2 + 2);
      CHECK(shell_test_evaluate(&exact, unknown_test_lookup, &exact) ==
            SHELL_TEST_ERROR_RESULT);
      CHECK(shell_test_prepare_value("\"$op\"", 5, &words[dynamic]));
      shell_test_program_t captured;
      CHECK(shell_test_compile(words, count, bracket, &captured));
      CHECK(captured.count <= count * 2 + 2);
      shell_test_set_value(&words[dynamic], "=", 1);
      CHECK(shell_test_refresh(&captured));
      CHECK(captured.count <= count * 2 + 2);
      CHECK(shell_test_evaluate(&captured, unknown_test_lookup, &captured) ==
            SHELL_TEST_ERROR_RESULT);
      shell_source_workspace_end(previous);
      shell_source_operation_end();
    }
  /* A consumed candidate ')' can be data; the actual later ')' still closes
   * the group. Preserving the real cursor must accept these valid neighbors. */
  CHECK(presence_test_truth("test '(' x -a -e = ')' ')'") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(presence_test_truth("test '(' x -a -e != ')' ')'") ==
        SHELL_CONDITIONAL_TRUE);
}

static void presence_check_high_read_targets(void) {
  static const unsigned target_positions[] = {31, 32, 46};
  for (unsigned t = 0; t < sizeof(target_positions) / sizeof(*target_positions);
       ++t) {
    char source[1024] = "unset pad CONFIG REPLY; read -n0";
    size_t used = strlen(source);
    for (unsigned i = 1; i < target_positions[t]; ++i)
      used += (size_t)snprintf(source + used, sizeof(source) - used, " pad");
    snprintf(source + used, sizeof(source) - used,
             " CONFIG; [[ -v CONFIG ]] && [[ ! -v REPLY ]]");
    CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
  }
  char source[1024] = "unset pad CONFIG IFS REPLY; read -n0";
  size_t used = strlen(source);
  for (unsigned i = 0; i < 32; ++i)
    used += (size_t)snprintf(source + used, sizeof(source) - used, " pad");
  snprintf(source + used, sizeof(source) - used,
           " CONFIG FUNCNAME IFS; [[ -v CONFIG ]] && [[ ! -v IFS ]] && [[ ! -v "
           "REPLY ]]");
  CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("unset REPLY; read -n0; [[ -v REPLY ]]") ==
        SHELL_CONDITIONAL_TRUE);
}

static void presence_check_sparse_read_targets(void) {
  static const struct {
    unsigned first;
    const char *suffix;
    bool tail_set, failed;
  } cases[] = {{1, "", false, false},
               {14, "", false, false},
               {1, " tail", true, false},
               {1, " bad-name tail", false, true}};
  for (unsigned c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    char source[2048] = "unset gap first last tail REPLY; { read -n0";
    size_t used = strlen(source);
    for (unsigned i = 1; i < cases[c].first; ++i)
      used += (size_t)snprintf(source + used, sizeof(source) - used, " -r");
    used += (size_t)snprintf(source + used, sizeof(source) - used, " first");
    /* Elided words still occupy prepared argument slots. Targets separated
     * by 32 slots produce equal low/high mask words, including at capacity. */
    for (unsigned i = 0; i < 31; ++i)
      used += (size_t)snprintf(source + used, sizeof(source) - used, " $gap");
    used += (size_t)snprintf(source + used, sizeof(source) - used, " last%s",
                             cases[c].suffix);
    for (unsigned on_failure = 0; on_failure < 2; ++on_failure) {
      int n = snprintf(source + used, sizeof(source) - used,
                       " %s cat <continued.txt; [[ -v first ]] && "
                       "[[ -v last ]] && [[ %s-v tail ]] && [[ ! -v REPLY ]] "
                       "&& cat <present.txt; [[ -v last ]]; } <<<payload",
                       on_failure ? "||" : "&&", cases[c].tail_set ? "" : "! ");
      CHECK(n >= 0 && (size_t)n < sizeof(source) - used);
      CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
      CHECK(has_file_read("continued.txt") == (on_failure == cases[c].failed));
      CHECK(has_file_read("present.txt"));
      for (uint32_t i = 0; i < graph->edge_count; ++i) {
        const shell_dep_edge_t *edge = &graph->edges[i];
        const shell_dep_node_t *to = &graph->nodes[edge->to];
        CHECK(!(edge->type == SHELL_EDGE_READ && to->type == SHELL_NODE_CMD &&
                to->cmd.token_count && to->cmd.token_lens[0] == 4 &&
                !memcmp(to->cmd.tokens[0], "read", 4)));
      }
    }
  }
}

static void presence_check_parenthesized_admission(void) {
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
      ("-t \"$FD\" '(' -v 'a[$(printf marker >&2)]' extra ')' -o "
       "\"$(printf expansion-marker >&2)\""),
  };
  for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
    for (unsigned bracket = 0; bracket < 2; ++bracket) {
      char command[512];
      int n =
          snprintf(command, sizeof(command), "%s %s%s", bracket ? "[" : "test",
                   failures[i], bracket ? " ]" : "");
      CHECK(n >= 0 && (size_t)n < sizeof(command));
      CHECK(presence_test_truth(command) == SHELL_CONDITIONAL_FALSE);
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
          CHECK(presence_truth(source) == SHELL_CONDITIONAL_TRUE);
          CHECK(has_file_read("important.txt") == (on_failure != negated));
        }
      }
    }
  }
}

static int run_presence(int argc, char **argv) {
  (void)argc;
  (void)argv;
  presence_current = "setup";
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 8192,
                                      1, true, 0));
  limits = fixture.limits;
  graph = fixture.graph[0];
  if (argc == 3) {
    if (!strcmp(argv[1], "--status"))
      printf("%d\n", shell_dep_graph_parse(argv[2], strlen(argv[2]),
                                           "/workspace", &limits, graph));
    else
      printf("%d\n", !strcmp(argv[1], "--test") ? presence_test_truth(argv[2])
                                                : presence_truth(argv[2]));
    shellsplit_graph_fixture_destroy(&fixture);
    return 0;
  }
  presence_check_observation_roles();
  presence_check_inspection_outcomes();
  presence_check_observation_capacity();
  presence_check_recursive_routes();
  presence_check_parenthesized_tests();
  presence_check_chained_group_progress();
  presence_check_high_read_targets();
  presence_check_sparse_read_targets();
  presence_check_parenthesized_admission();
  presence_check_nonassignable_variables();
  presence_check_opaque_unsets();
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
      {"unset fd; true {fd}>out 1>fail || [[ -v fd ]]",
       SHELL_CONDITIONAL_UNKNOWN},
      {"unset fd; true {fd}>&1 1>fail || [[ -v fd ]]", SHELL_CONDITIONAL_TRUE},
      {"unset fd; true 1>fail {fd}>out || [[ -v fd ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset fd; ( true {fd}>out 1>fail ); [[ -v fd ]]",
       SHELL_CONDITIONAL_FALSE},
      {"unset fd; { true; } {fd}>&1 1>fail || [[ -v fd ]]",
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
    CHECK(presence_truth(cases[i].source) == cases[i].expected);
  /* A setup which certainly fails is a shell-level error: no model. */
  presence_current =
      "unset OPTARG; getopts :a OPTARG -b 0<\"\"; [[ -v OPTARG ]]";
  CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EUNMODELED);
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
      {"test x -o 1 -eq invalid", SHELL_CONDITIONAL_FALSE},
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
    CHECK(presence_test_truth(tests[i].source) == tests[i].expected);

  CHECK(presence_truth("unset PWD OLDPWD; choose && PWD=; cd / && { "
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

  CHECK(presence_truth("unset OPTARG; getopts a OPTARG -b; "
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

  CHECK(presence_truth("test -v CONFIG <input >output; [[ -v UID ]]") ==
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
      "[[ -R name ]]",
  };
  CHECK(presence_truth("unset name other; [[ -v name && -v other ]]") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(presence_truth("name=; other=; [[ -v name && -v other ]]") ==
        SHELL_CONDITIONAL_TRUE);
  CHECK(presence_truth("[[ -v name && -v other ]] && [[ ! -v name ]]") ==
        SHELL_CONDITIONAL_FALSE);
  CHECK(presence_truth("[[ ! ( -v name || -v other ) ]] && [[ -v other ]]") ==
        SHELL_CONDITIONAL_FALSE);
  shell_source_result_t *draft = malloc(sizeof(*draft));
  CHECK(draft);
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i) {
    presence_current = unsupported[i];
    CHECK(shell_parse_draft(presence_current, strlen(presence_current), NULL,
                            draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                                "/workspace", &limits,
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
    presence_current = unsafe_tests[i];
    /* Drafts establish shell grammar; graph admission checks builtin effects.
     */
    CHECK(shell_parse_draft(presence_current, strlen(presence_current), NULL,
                            draft) == SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                                "/workspace", &limits,
                                graph) == SHELL_DEP_EPARSE);
  }
  presence_current = "[[ -v ordinary_inherited ]]";
  unsigned calls = 0;
  CHECK(shell_dep_graph_parse_resolved(
            presence_current, strlen(presence_current), "/workspace", &limits,
            graph, no_presence_callback, &calls, NULL) == SHELL_DEP_OK);
  CHECK(calls == 0 &&
        graph->nodes[0].cmd.conditional_truth == SHELL_CONDITIONAL_UNKNOWN);
  static const char *const prefixes[] = {"[[ -v", "[[ -v ", "[[ -v CON",
                                         "[[ -v 'CON"};
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(*prefixes); ++i) {
    presence_current = prefixes[i];
    CHECK(shell_parse_draft(presence_current, strlen(presence_current), NULL,
                            draft) == SHELL_SOURCE_INCOMPLETE);
  }
  char long_name[1024] = "[[ -v ";
  memset(long_name + 6, 'a', sizeof(long_name) - 10);
  memcpy(long_name + sizeof(long_name) - 4, " ]]", 4);
  CHECK(presence_truth(long_name) == SHELL_CONDITIONAL_UNKNOWN);
  size_t full = limits.workspace_size;
  CHECK(shell_dep_workspace_size(NULL, &limits.workspace_size));
  presence_current = long_name;
  CHECK(shell_dep_graph_parse(presence_current, strlen(presence_current),
                              "/workspace", &limits,
                              graph) == SHELL_DEP_EWORKSPACE);
  CHECK(!graph->node_count && !graph->edge_count);
  limits.workspace_size = full;
  free(draft);
  shellsplit_graph_fixture_destroy(&fixture);
  puts("scalar presence tests passed");
  return 0;
}
#undef CHECK

int main(int argc, char **argv) {
  static const struct {
    const char *name;
    int (*run)(int, char **);
  } sections[] = {{"arithmetic", run_arithmetic},
                  {"conditional", run_conditional},
                  {"presence", run_presence}};
  /* A qualification driver names the section; its flags follow. */
  if (argc >= 2)
    for (unsigned i = 0; i < sizeof(sections) / sizeof(sections[0]); i++)
      if (!strcmp(argv[1], sections[i].name))
        return sections[i].run(argc - 1, argv + 1);
  int status = 0;
  for (unsigned i = 0; i < sizeof(sections) / sizeof(sections[0]); i++)
    status |= sections[i].run(1, argv);
  return status != 0;
}
