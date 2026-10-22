#include "../shellsplit/tests/word_byte_cases.h"
#include "shell_abstract.h"
#include "shell_ascii.h"
#include "shell_depgraph.h"
#include "shell_sequence.h"
#include "shell_source.h"
#include "shell_transform.h"
#include "shellgate.h"

#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static shell_dep_graph_t graph;
static shell_source_result_t draft;
static shell_dep_limits_t limits;

static void byte_predicates(void) {
  const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char lower[] = "abcdefghijklmnopqrstuvwxyz";
  const char digits[] = "0123456789";
  const char hex[] = "0123456789ABCDEFabcdef";
  const char spaces[] = " \t\n\v\f\r";
  for (unsigned i = 0; i < 256; ++i) {
    unsigned char byte = (unsigned char)i;
    bool alpha = memchr(upper, byte, 26) || memchr(lower, byte, 26);
    bool digit = memchr(digits, byte, 10) != NULL;
    CHECK(shell_ascii_alpha(byte) == alpha);
    CHECK(shell_ascii_digit(byte) == digit);
    CHECK(shell_ascii_alnum(byte) == (alpha || digit));
    CHECK(shell_ascii_xdigit(byte) == (memchr(hex, byte, 22) != NULL));
    CHECK(shell_ascii_lower(byte) == (memchr(lower, byte, 26) != NULL));
    CHECK(shell_ascii_space(byte) == (memchr(spaces, byte, 6) != NULL));
    CHECK(shell_ascii_print(byte) == (i >= 32 && i <= 126));
    const char *capital = memchr(upper, byte, 26);
    unsigned char folded =
        capital ? (unsigned char)lower[capital - upper] : byte;
    CHECK(shell_ascii_fold(byte) == folded);
    char left[] = {(char)byte, '\0', (char)byte};
    char right[] = {(char)folded, '\0', (char)folded};
    CHECK(shell_ascii_equal_ci(left, right, sizeof(left)));
    right[2] = (char)(folded ^ 0x80u);
    CHECK(!shell_ascii_equal_ci(left, right, sizeof(left)));
  }
}

static void word_literals(void) {
  for (size_t i = 0; i < sizeof(shellsplit_test_word_bytes) /
                             sizeof(shellsplit_test_word_bytes[0]);
       ++i) {
    const char *word = shellsplit_test_word_bytes[i].word;
    const char *value = shellsplit_test_word_bytes[i].value;
    char source[256], expected[256];
    int length = snprintf(source, sizeof(source), "printf %%s %s", word);
    int encoded = snprintf(expected, sizeof(expected), "6:printf,2:%%s,%zu:%s,",
                           strlen(value), value);
    CHECK(length > 0 && (size_t)length < sizeof(source) && encoded > 0 &&
          (size_t)encoded < sizeof(expected));
    CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.prefix.count == 1 &&
          !(draft.prefix.cmds[0].features &
            (SHELL_FEAT_CONDITIONALS | SHELL_FEAT_LOOPS | SHELL_FEAT_CASE)));
    shell_netstring_buffer_t sequence = {0};
    size_t count;
    bool features;
    CHECK(shell_build_netargv_sequence_buffer(source, (size_t)length, NULL,
                                              &sequence, &count,
                                              &features) == SHELL_PROCESS_OK);
    shell_netstring_iter_t records;
    shell_netstring_view_t record;
    CHECK(count == 1 &&
          shell_netstring_iter_init(&records, sequence.data, sequence.length) ==
              SHELL_NETSTRING_OK);
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK &&
          record.payload_length == (size_t)encoded &&
          !memcmp(record.payload, expected, (size_t)encoded));
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_DONE);
    char decoded[256];
    size_t measured, written;
    CHECK(shell_measure_decoded_word(word, strlen(word), &measured) ==
              SHELL_PROCESS_OK &&
          measured == strlen(value));
    CHECK(shell_write_decoded_word(word, strlen(word), decoded, sizeof(decoded),
                                   &written) == SHELL_PROCESS_OK &&
          written == measured && !memcmp(decoded, value, written));
    CHECK(measured &&
          shell_write_decoded_word(word, strlen(word), decoded, measured - 1,
                                   &written) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          !written);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, (size_t)length, &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(!abstract->has_variables && !abstract->has_cmd_subst);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    CHECK(shell_transform_command_line(source, (size_t)length, NULL,
                                       &transformed,
                                       &count) == SHELL_TRANSFORM_OK);
    CHECK(count == 1 && transformed[0]->token_count >= 3 &&
          !strcmp(transformed[0]->original_command, source));
    /* Diagnostic tokens retain lexical fragments, not canonical argv words. */
    size_t offset = 0;
    for (size_t t = 2; t < transformed[0]->token_count; t++) {
      const char *fragment = transformed[0]->tokens[t].original;
      size_t size = strlen(fragment);
      CHECK(size <= strlen(word) - offset &&
            !memcmp(fragment, word + offset, size));
      offset += size;
    }
    CHECK(offset == strlen(word));
    shell_transformed_command_list_free(transformed, count);
    printf("word[%zu]=%s\n", i, expected);
    shell_netstring_buffer_free(&sequence);
  }
  static const char *const names[] = {"if日本",   "日本if",     "while日本",
                                      "日本case", "time日本",   "exec日本",
                                      "cd日本",   "日本=value", "\x80\xff"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char source[64];
    int length = snprintf(source, sizeof(source), "%s argument", names[i]);
    CHECK(length > 0 && (size_t)length < sizeof(source));
    CHECK(shell_dep_graph_parse(source, (size_t)length, "/workspace", &limits,
                                &graph) == SHELL_DEP_OK);
    unsigned commands = 0;
    for (uint32_t n = 0; n < graph.node_count; ++n)
      if (graph.nodes[n].type == SHELL_NODE_CMD) {
        CHECK(
            graph.nodes[n].cmd.token_count == 2 &&
            graph.nodes[n].cmd.token_lens[0] == strlen(names[i]) &&
            !memcmp(graph.nodes[n].cmd.tokens[0], names[i], strlen(names[i])));
        ++commands;
      }
    CHECK(commands == 1 && shell_dep_graph_validate(&graph).valid);
  }
}

static void quoted_lists(void) {
  static const struct {
    const char *source;
    unsigned count;
    const char *arguments[3];
  } cases[] = {
      {"printf 'é\\'; printf 'a\\'", 2, {"é\\", "a\\"}},
      {"printf 'é\\' ; cat file ; printf 'a\\'", 3, {"é\\", "file", "a\\"}},
      {"printf '\xe9\\'\ncat file\nprintf 'a\\'", 3, {"\xe9\\", "file", "a\\"}},
      {"printf pre'é\\'\".txt\"; cat file; printf 'a\\'",
       3,
       {"preé\\.txt", "file", "a\\"}},
      {"printf $'日本\\t語'; cat $'résumé.txt'; printf $'é\\\\'",
       3,
       {"日本\t語", "résumé.txt", "é\\"}},
  };
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == cases[c].count);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, &strict, &fast) == SHELL_OK);
    CHECK(fast.count == cases[c].count);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == cases[c].count);
    shell_transformed_command_t **transformed = NULL;
    size_t count = 0;
    CHECK(shell_transform_command_line(source, length, NULL, &transformed,
                                       &count) == SHELL_TRANSFORM_OK);
    CHECK(count == cases[c].count);
    shell_netstring_buffer_t sequence = {0};
    bool features;
    CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &sequence,
                                              &count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(count == cases[c].count);
    shell_netstring_iter_t records;
    shell_netstring_view_t record;
    CHECK(shell_netstring_iter_init(&records, sequence.data, sequence.length) ==
          SHELL_NETSTRING_OK);
    for (unsigned i = 0; i < cases[c].count; ++i) {
      const char *name = cases[c].count == 3 && i == 1 ? "cat" : "printf";
      char expected[256];
      int n =
          snprintf(expected, sizeof(expected), "%zu:%s,%zu:%s,", strlen(name),
                   name, strlen(cases[c].arguments[i]), cases[c].arguments[i]);
      CHECK(n > 0 && (size_t)n < sizeof(expected));
      CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK);
      CHECK(record.payload_length == (size_t)n &&
            !memcmp(record.payload, expected, (size_t)n));
      shell_netstring_buffer_t argv = {0};
      CHECK(shell_render_netargv_buffer(&processed.commands[i], NULL, &argv) ==
            SHELL_PROCESS_OK);
      CHECK(argv.length == (size_t)n &&
            !memcmp(argv.data, expected, argv.length));
      shell_netstring_buffer_free(&argv);
      CHECK(processed.commands[i].command_token_count == 2);
      CHECK(transformed[i]->token_count == 2 + (i + 1 < cases[c].count) &&
            !strcmp(transformed[i]->tokens[0].original, name));
      if (i + 1 < cases[c].count)
        CHECK(transformed[i]->tokens[2].is_shell_construct &&
              (!strcmp(transformed[i]->tokens[2].original, ";") ||
               !strcmp(transformed[i]->tokens[2].original, "\n")));
      const shell_source_span_t *word = &draft.headers[i].words[1];
      CHECK(word->start >= fast.cmds[i].start &&
            word->start + word->length <=
                fast.cmds[i].start + fast.cmds[i].len);
      CHECK(strlen(transformed[i]->tokens[1].original) == word->length &&
            !memcmp(transformed[i]->tokens[1].original, source + word->start,
                    word->length));
    }
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_DONE);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &fast, &graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    unsigned commands = 0;
    for (uint32_t i = 0; i < graph.node_count; ++i)
      if (graph.nodes[i].type == SHELL_NODE_CMD) {
        CHECK(graph.nodes[i].cmd.token_count == 2);
        ++commands;
      }
    CHECK(commands == cases[c].count);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, length, &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(!abstract->has_variables && !abstract->has_cmd_subst);
    printf("list[%zu]=%s\n", c, abstract->display_text);
    shell_abstract_command_free(abstract);
    shell_dep_graph_dump(&graph, stdout);
    shell_netstring_buffer_free(&sequence);
    shell_transformed_command_list_free(transformed, count);
    shell_processed_commands_free(&processed);
  }
  static const char *const unfinished[] = {
      "printf 'é\\",
      "printf 'é\\' ; printf 'unfinished\\",
      "printf \"é\\\"",
      "printf 'é\\' &&",
  };
  for (size_t i = 0; i < sizeof(unfinished) / sizeof(unfinished[0]); ++i) {
    CHECK(shell_parse_draft(unfinished[i], strlen(unfinished[i]), NULL,
                            &draft) == SHELL_SOURCE_INCOMPLETE);
    shell_transformed_command_t **transformed = NULL;
    size_t count = 0;
    CHECK(shell_transform_command_line(unfinished[i], strlen(unfinished[i]),
                                       NULL, &transformed,
                                       &count) == SHELL_TRANSFORM_EPARSE);
    CHECK(!transformed && !count);
  }
}

static void invalid_read_targets(void) {
  static const char *const sources[] = {
      "read '\xe9' fd <<<payload && printf wrong >unexpected || printf "
      "fallback",
      "read -n'\xe9' value <<<payload && printf wrong >unexpected || printf "
      "fallback",
      "exec {fd}>/dev/null; read '\xe9' IFS fd <<<payload; printf data >&$fd",
      "read \xe9 fd <<<payload && printf wrong >unexpected || printf fallback",
      "read -n\xe9 value <<<payload && printf wrong >unexpected || printf "
      "fallback",
      "exec {fd}>/dev/null; read \xe9 IFS fd <<<payload; printf data >&$fd",
      "read $'\xe9' fd <<<payload && printf wrong >unexpected || printf "
      "fallback",
      "read -n$'\xe9' value <<<payload && printf wrong >unexpected || printf "
      "fallback",
      "exec {fd}>/dev/null; read $'\xe9' IFS fd <<<payload; printf data >&$fd",
  };
  for (size_t c = 0; c < sizeof(sources) / sizeof(sources[0]); ++c) {
    const char *source = sources[c];
    CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                &graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    uint32_t payload = UINT32_MAX, output = UINT32_MAX, printing = UINT32_MAX,
             unexpected = UINT32_MAX;
    for (uint32_t i = 0; i < graph.node_count; ++i) {
      const shell_dep_node_t *node = &graph.nodes[i];
      if (node->type == SHELL_NODE_DOC) {
        if (node->doc.kind == SHELL_DOC_HERESTRING)
          payload = i;
        if (node->doc.kind == SHELL_DOC_FILE && node->doc.path_len == 9 &&
            !memcmp(node->doc.path, "/dev/null", 9))
          output = i;
        if (node->doc.kind == SHELL_DOC_FILE && node->doc.path_len == 10 &&
            !memcmp(node->doc.path, "unexpected", 10))
          unexpected = i;
      } else if (node->type == SHELL_NODE_CMD && node->cmd.token_lens[0] == 6 &&
                 !memcmp(node->cmd.tokens[0], "printf", 6))
        printing = i;
    }
    CHECK(payload != UINT32_MAX && printing != UINT32_MAX);
    bool preserved = false;
    bool fallback = false;
    for (uint32_t i = 0; i < graph.edge_count; ++i) {
      const shell_dep_edge_t *edge = &graph.edges[i];
      CHECK(edge->type != SHELL_EDGE_READ || edge->from != payload);
      CHECK((edge->type != SHELL_EDGE_WRITE &&
             edge->type != SHELL_EDGE_FD_OPEN) ||
            edge->to != unexpected);
      preserved |= edge->type == SHELL_EDGE_WRITE && edge->from == printing &&
                   edge->to == output && edge->source_fd == 1;
      fallback |= edge->type == SHELL_EDGE_WRITE && edge->from == printing &&
                  edge->source_fd == 1;
    }
    CHECK(c % 3 != 2 || preserved);
    CHECK(c % 3 == 2 || (unexpected != UINT32_MAX && fallback));
    shell_dep_graph_dump(&graph, stdout);
  }
}

static void classification_and_policy(void) {
  static const char *const tokens[] = {
      "\xe9", "\xe9name", "--\xe9", "~\xe9", "é", "日本", "SIGINT", "KIB",
  };
  for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i)
    printf("type[%zu]=%u\n", i,
           (unsigned)st_token_classify(tokens[i], strlen(tokens[i])));
  st_policy_ctx_t *context = st_policy_ctx_new();
  CHECK(context);
  st_policy_t *allow = st_policy_new(context), *deny = st_policy_new(context);
  st_policy_ctx_release(context);
  CHECK(allow && deny);
  const char *rules[] = {"printf \xe9", "id #user", "echo *"};
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); ++i) {
    st_netpattern_t rule = {0};
    CHECK(st_netpattern_from_cpl_owned(rules[i], &rule) == ST_OK);
    CHECK(st_policy_add_netpattern_view(
              allow, (st_netpattern_view_t){rule.data, rule.length}) == ST_OK);
    st_netpattern_free(&rule);
  }
  sg_gate_t *gate = sg_gate_new_with_policies_owned(allow, deny);
  CHECK(gate && sg_gate_set_stop_mode(gate, SG_EVAL_ALL) == SG_OK);
  static const struct {
    const char *source;
    sg_verdict_t verdict;
  } cases[] = {
      {"printf '\xe9'", SG_VERDICT_ALLOW},
      {"printf \xe9", SG_VERDICT_ALLOW},
      {"printf $'\xe9'", SG_VERDICT_ALLOW},
      {"printf $'\xe8'", SG_VERDICT_UNDETERMINED},
      {"printf \xe9 # 日本 if while case $(false) >phantom", SG_VERDICT_ALLOW},
      {"# \x80\xff\n printf '\xe9'", SG_VERDICT_ALLOW},
      {"# 日本 if while case", SG_VERDICT_ALLOW},
      {"printf '\xe8'", SG_VERDICT_UNDETERMINED},
      {"id root", SG_VERDICT_ALLOW},
      {"id '\xe9name'", SG_VERDICT_UNDETERMINED},
      {"id \xe9name", SG_VERDICT_UNDETERMINED},
      {"id \xe9name # 日本", SG_VERDICT_UNDETERMINED},
      {"echo 日本if", SG_VERDICT_ALLOW},
      {"echo 日本''if", SG_VERDICT_ALLOW},
      {"echo 日本.if", SG_VERDICT_ALLOW},
      {"echo '日本.if'", SG_VERDICT_ALLOW},
      {"echo $'日本.if'", SG_VERDICT_ALLOW},
      {"echo 日本-while", SG_VERDICT_ALLOW},
      {"echo 日本.in", SG_VERDICT_ALLOW},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    size_t size = sg_gate_evaluate_size_hint(strlen(cases[i].source));
    CHECK(size != SIZE_MAX);
    char *buffer = malloc(size);
    CHECK(buffer);
    sg_result_t result;
    CHECK(sg_gate_evaluate(gate, cases[i].source, strlen(cases[i].source),
                           buffer, size, &result) == SG_OK);
    CHECK(result.verdict == cases[i].verdict && !result.truncated &&
          !result.short_circuited && !result.unresolved_expansion_flags);
    printf("policy[%zu]=%u\n", i, (unsigned)result.verdict);
    free(buffer);
  }
  sg_gate_free(gate);
}

int main(int argc, char **argv) {
  CHECK(argc == 2);
  CHECK(setlocale(LC_CTYPE, argv[1]));
  CHECK((isalpha(0xe9) != 0) == (strcmp(argv[1], "en_US.ISO8859-1") == 0));
  char *host_locale = strdup(setlocale(LC_CTYPE, NULL));
  CHECK(host_locale);
  byte_predicates();
  limits = SHELL_DEP_LIMITS_DEFAULT;
  CHECK(shell_dep_workspace_size(&limits, &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace);
  word_literals();
  quoted_lists();
  invalid_read_targets();
  classification_and_policy();
  CHECK(!strcmp(host_locale, setlocale(LC_CTYPE, NULL)));
  free(host_locale);
  free(limits.workspace);
  return EXIT_SUCCESS;
}
